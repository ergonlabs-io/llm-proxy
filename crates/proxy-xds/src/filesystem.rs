//! Filesystem xDS source.
//!
//! A source reads one complete `DiscoveryResponse` from disk and exposes a
//! polling watcher for atomic file replacement. Reading happens only when a
//! reload is requested; callers can parse and apply the returned response
//! before publishing it, so request workers never perform filesystem I/O.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use prost::Message;
use prost_reflect::{DeserializeOptions, DynamicMessage};
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;

const RESPONSE_TYPE: &str = "envoy.service.discovery.v3.DiscoveryResponse";

/// A filesystem-backed xDS response source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSource {
    path: PathBuf,
    type_url: String,
}

impl FileSource {
    /// Construct source for one resource type. `type_url` is checked on every
    /// load, preventing a file intended for one subscription from being
    /// applied to another.
    pub fn new(path: impl Into<PathBuf>, type_url: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            type_url: type_url.into(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn type_url(&self) -> &str {
        &self.type_url
    }

    /// Read and parse one response. The file is read into one byte buffer,
    /// which gives atomic rename-based updates either old or new contents.
    pub fn load(&self) -> Result<DiscoveryResponse, FileSourceError> {
        let bytes = std::fs::read(&self.path).map_err(|source| FileSourceError::Io {
            path: self.path.display().to_string(),
            source,
        })?;
        let response = parse_response(&self.path, &bytes)?;
        if response.type_url != self.type_url {
            return Err(FileSourceError::TypeMismatch {
                path: self.path.display().to_string(),
                expected: self.type_url.clone(),
                actual: response.type_url,
            });
        }
        Ok(response)
    }

    pub fn watcher(&self) -> FileWatcher {
        FileWatcher::new(self.path.clone())
    }
}

/// Metadata-based watcher. A caller polls it from its control-plane task and
/// calls [`FileSource::load`] only after it returns true.
#[derive(Debug, Clone)]
pub struct FileWatcher {
    path: PathBuf,
    observed: Option<FileStamp>,
}

impl FileWatcher {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            observed: None,
        }
    }

    /// Return true once for each file replacement/change. Missing files are
    /// errors, not removals: keeping last-good config is safer than silently
    /// deleting a live resource because a deployment moved a file briefly.
    pub fn changed(&mut self) -> Result<bool, FileSourceError> {
        let stamp = FileStamp::read(&self.path)?;
        if self.observed == Some(stamp) {
            return Ok(false);
        }
        self.observed = Some(stamp);
        Ok(true)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
}

impl FileStamp {
    fn read(path: &Path) -> Result<Self, FileSourceError> {
        let metadata = std::fs::metadata(path).map_err(|source| FileSourceError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self {
            modified: metadata.modified().ok(),
            len: metadata.len(),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FileSourceError {
    #[error("failed to read filesystem xDS source `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse filesystem xDS source `{path}`: {reason}")]
    Parse { path: String, reason: String },
    #[error("filesystem xDS source `{path}` has type_url `{actual}`, expected `{expected}`")]
    TypeMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}

fn parse_response(path: &Path, bytes: &[u8]) -> Result<DiscoveryResponse, FileSourceError> {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("pb") => DiscoveryResponse::decode(bytes).map_err(|source| FileSourceError::Parse {
            path: path.display().to_string(),
            reason: format!("invalid DiscoveryResponse protobuf: {source}"),
        }),
        Some("yaml" | "yml" | "json") => parse_text(path, bytes),
        _ => Err(FileSourceError::Parse {
            path: path.display().to_string(),
            reason: "expected .yaml, .yml, .json, or .pb".to_string(),
        }),
    }
}

fn parse_text(path: &Path, bytes: &[u8]) -> Result<DiscoveryResponse, FileSourceError> {
    let text = std::str::from_utf8(bytes).map_err(|source| FileSourceError::Parse {
        path: path.display().to_string(),
        reason: format!("invalid UTF-8: {source}"),
    })?;
    let value: serde_json::Value = if path.extension().and_then(|e| e.to_str()) == Some("json") {
        serde_json::from_str(text).map_err(|source| FileSourceError::Parse {
            path: path.display().to_string(),
            reason: format!("invalid JSON: {source}"),
        })?
    } else {
        serde_yaml::from_str(text).map_err(|source| FileSourceError::Parse {
            path: path.display().to_string(),
            reason: format!("invalid YAML: {source}"),
        })?
    };
    let descriptor = proxy_api::descriptor_pool()
        .get_message_by_name(RESPONSE_TYPE)
        .expect("DiscoveryResponse is embedded in proxy-api descriptor pool");
    let options = DeserializeOptions::new().deny_unknown_fields(true);
    let json = serde_json::to_string(&value).map_err(|source| FileSourceError::Parse {
        path: path.display().to_string(),
        reason: format!("cannot normalize document: {source}"),
    })?;
    let mut deserializer = serde_json::Deserializer::from_str(&json);
    let dynamic: DynamicMessage =
        DynamicMessage::deserialize_with_options(descriptor, &mut deserializer, &options).map_err(
            |source| FileSourceError::Parse {
                path: path.display().to_string(),
                reason: source.to_string(),
            },
        )?;
    let response: DiscoveryResponse =
        dynamic
            .transcode_to()
            .map_err(|source: prost::DecodeError| FileSourceError::Parse {
                path: path.display().to_string(),
                reason: format!("internal DiscoveryResponse transcode failure: {source}"),
            })?;
    Ok(response)
}
