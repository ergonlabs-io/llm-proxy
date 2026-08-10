//! WP-03: bootstrap loading — Envoy config files into typed protos.
//!
//! Pipeline (ADR-0002): bytes -> (YAML|JSON) -> `serde_json::Value` ->
//! prost-reflect proto3-JSON deserialize against the embedded Envoy descriptor
//! pool (unknown fields denied) -> typed [`Bootstrap`]. `.pb` files decode the
//! protobuf directly. The same pipeline will serve xDS resources (WP-20), which
//! arrive as protobuf `Any` rather than files.
//!
//! Error quality is a product feature here (PLAN.md Part 7.1): every failure
//! carries the full dotted field path, produced by threading the deserializer
//! through `serde_path_to_error`.

use std::path::Path;

use prost_reflect::{DeserializeOptions, DynamicMessage, MessageDescriptor};
use proxy_api::envoy::config::bootstrap::v3::Bootstrap;

use crate::error::{ConfigError, ConfigFrontEnd, ConfigWarning};
use crate::StrictMode;

/// Fully-qualified name of the bootstrap root message.
pub const BOOTSTRAP_TYPE: &str = "envoy.config.bootstrap.v3.Bootstrap";

/// Cap on permissive-mode strip-and-retry iterations, so a pathological config
/// cannot loop forever.
const MAX_PERMISSIVE_RETRIES: usize = 500;

/// Config file formats we accept, keyed by extension (Envoy-compatible set,
/// minus `.pb_text` which prost has no parser for — rejected explicitly).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Yaml,
    Json,
    ProtoBinary,
}

impl ConfigFormat {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("yaml" | "yml") => Ok(Self::Yaml),
            Some("json") => Ok(Self::Json),
            Some("pb") => Ok(Self::ProtoBinary),
            Some("pb_text") => Err(ConfigError::Unimplemented {
                field_path: path.display().to_string(),
                reason: "pb_text bootstrap files; use .yaml, .json or .pb".to_string(),
            }),
            other => Err(ConfigError::Parse(format!(
                "unrecognized config extension {other:?} for `{}`; expected .yaml/.yml/.json/.pb",
                path.display()
            ))),
        }
    }
}

/// A successfully loaded bootstrap: the typed message for WP-05 IR conversion,
/// the dynamic (reflective) view for validation/config_dump, and any
/// permissive-mode warnings.
#[derive(Debug)]
pub struct LoadedBootstrap {
    pub bootstrap: Bootstrap,
    pub dynamic: DynamicMessage,
    pub warnings: Vec<ConfigWarning>,
}

/// Load a bootstrap config file, inferring the format from its extension.
pub fn load_bootstrap_file(path: &Path, mode: StrictMode) -> Result<LoadedBootstrap, ConfigError> {
    let format = ConfigFormat::from_path(path)?;
    let bytes = std::fs::read(path).map_err(|e| ConfigError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    parse_bootstrap(&bytes, format, mode)
}

/// Parse bootstrap config bytes in the given format.
pub fn parse_bootstrap(
    bytes: &[u8],
    format: ConfigFormat,
    mode: StrictMode,
) -> Result<LoadedBootstrap, ConfigError> {
    let desc = bootstrap_descriptor();
    match format {
        ConfigFormat::ProtoBinary => {
            let dynamic = DynamicMessage::decode(desc, bytes)
                .map_err(|e| ConfigError::Parse(format!("invalid Bootstrap protobuf: {e}")))?;
            crate::validate::validate_message(&dynamic)?;
            let bootstrap = transcode(&dynamic)?;
            Ok(LoadedBootstrap {
                bootstrap,
                dynamic,
                warnings: Vec::new(),
            })
        }
        ConfigFormat::Yaml | ConfigFormat::Json => {
            let text = std::str::from_utf8(bytes)
                .map_err(|e| ConfigError::Parse(format!("config is not valid UTF-8: {e}")))?;
            let value: serde_json::Value = match format {
                ConfigFormat::Yaml => serde_yaml::from_str(text)
                    .map_err(|e| ConfigError::Parse(format!("invalid YAML: {e}")))?,
                _ => serde_json::from_str(text)
                    .map_err(|e| ConfigError::Parse(format!("invalid JSON: {e}")))?,
            };
            parse_json_value(value, mode)
        }
    }
}

fn bootstrap_descriptor() -> MessageDescriptor {
    proxy_api::descriptor_pool()
        .get_message_by_name(BOOTSTRAP_TYPE)
        .expect("Bootstrap is always in the embedded descriptor pool (WP-02 test)")
}

fn transcode(dynamic: &DynamicMessage) -> Result<Bootstrap, ConfigError> {
    dynamic
        .transcode_to::<Bootstrap>()
        .map_err(|e| ConfigError::Parse(format!("internal transcode failure: {e}")))
}

/// Deserialize a JSON value as Bootstrap. In [`StrictMode::Permissive`],
/// unknown fields are stripped one at a time (strict parse -> on unknown-field
/// error, remove that node, record a warning, retry) so we can report *exactly*
/// which fields were ignored — prost-reflect's lenient mode would drop them
/// silently, which ground rule #2 forbids.
fn parse_json_value(
    mut value: serde_json::Value,
    mode: StrictMode,
) -> Result<LoadedBootstrap, ConfigError> {
    let desc = bootstrap_descriptor();
    let options = DeserializeOptions::new().deny_unknown_fields(true);
    let mut warnings = Vec::new();

    for _ in 0..MAX_PERMISSIVE_RETRIES {
        // Rust note: `serde_path_to_error` wraps the deserializer and records
        // the path (e.g. `static_resources.listeners[0].address`) at which
        // deserialization failed — that path is our error currency.
        let mut track = serde_path_to_error::Track::new();
        let traced = serde_path_to_error::Deserializer::new(&value, &mut track);

        match DynamicMessage::deserialize_with_options(desc.clone(), traced, &options) {
            Ok(dynamic) => {
                // WP-04: parsing proved the fields exist; validation proves the
                // values satisfy Envoy's PGV constraints. Both modes enforce it
                // — permissive only relaxes UNKNOWN fields, never bad values.
                crate::validate::validate_message(&dynamic)?;
                let bootstrap = transcode(&dynamic)?;
                return Ok(LoadedBootstrap {
                    bootstrap,
                    dynamic,
                    warnings,
                });
            }
            Err(err) => {
                let path = track.path().to_string();
                let unknown_field = extract_unknown_field(&err.to_string());
                let full_path = join_path(&path, unknown_field.as_deref());

                match (mode, &unknown_field) {
                    (StrictMode::Permissive, Some(field))
                        if remove_field(&mut value, &path, field) =>
                    {
                        warnings.push(ConfigWarning {
                            field_path: full_path,
                            message: "unknown field ignored (permissive mode)".to_string(),
                        });
                        continue;
                    }
                    _ if unknown_field.is_some() => {
                        return Err(ConfigError::UnknownField {
                            field_path: full_path,
                            front_end: ConfigFrontEnd::Bootstrap,
                        });
                    }
                    _ => {
                        return Err(ConfigError::InvalidValue {
                            field_path: full_path,
                            reason: err.to_string(),
                        });
                    }
                }
            }
        }
    }
    Err(ConfigError::Parse(format!(
        "gave up after ignoring {MAX_PERMISSIVE_RETRIES} unknown fields — is this an Envoy config?"
    )))
}

/// Pull the field name out of an unknown-field error message. Two spellings
/// exist: prost-reflect's `unrecognized field name 'x'` and serde's canonical
/// `unknown field \`x\`, expected ...`. Returns `None` for every other error
/// kind (type errors, bad enums, ...), which callers treat as hard failures.
fn extract_unknown_field(message: &str) -> Option<String> {
    if let Some(pos) = message.find("unrecognized field name '") {
        let rest = &message[pos + "unrecognized field name '".len()..];
        return Some(rest[..rest.find('\'')?].to_string());
    }
    if let Some(rest) = message.strip_prefix("unknown field `") {
        return Some(rest[..rest.find('`')?].to_string());
    }
    None
}

/// `parent` path + unknown field name -> full dotted path.
fn join_path(parent: &str, field: Option<&str>) -> String {
    match (parent, field) {
        // serde_path_to_error renders an empty path as "."
        ("." | "", Some(f)) => f.to_string(),
        ("." | "", None) => "<root>".to_string(),
        (p, Some(f)) => format!("{p}.{f}"),
        (p, None) => p.to_string(),
    }
}

/// Navigate `value` down `path` (dotted segments, `[n]` list indices) and
/// remove `field` from the map found there. Returns false if the shape doesn't
/// match (caller then falls back to a hard error).
fn remove_field(value: &mut serde_json::Value, path: &str, field: &str) -> bool {
    let mut current = value;
    if path != "." && !path.is_empty() {
        for segment in path.split('.') {
            // Each dotted segment may carry trailing indices: `listeners[0][1]`.
            let (key, indices) = match segment.find('[') {
                Some(pos) => (&segment[..pos], &segment[pos..]),
                None => (segment, ""),
            };
            if !key.is_empty() {
                match current.get_mut(key) {
                    Some(next) => current = next,
                    None => return false,
                }
            }
            for idx in indices.trim_end_matches(']').split("[").skip(1) {
                let Ok(i) = idx.trim_end_matches(']').parse::<usize>() else {
                    return false;
                };
                match current.get_mut(i) {
                    Some(next) => current = next,
                    None => return false,
                }
            }
        }
    }
    match current.as_object_mut() {
        Some(map) => map.remove(field).is_some(),
        None => false,
    }
}
