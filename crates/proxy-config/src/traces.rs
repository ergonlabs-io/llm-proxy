//! Strict decoder for `node.metadata["io.llmproxy.traces"]`, trace export
//! (ADR-0008). Process-level and boot-scoped like the ledger beside it, so it
//! sits on the bootstrap `node`.
//!
//! `google.protobuf.Struct` is opaque to the reflective surface walk, so
//! AGENTS.md invariant 1 is enforced here by hand: every unknown key and
//! every bad value fails with its full dotted path. The block is ours, not
//! Envoy's, so `--permissive` does not relax it: these errors come from
//! lowering, after the permissive strip-and-retry stage has finished.
//!
//! Error reasons are static text and never echo a configured value, so a
//! credential cannot reach a log through a config error.

use crate::error::ConfigError;
use prost_types::{value::Kind, Struct, Value};
use proxy_observability::traces::config::{
    valid_bucket, valid_endpoint, valid_prefix, S3Credentials, S3Destination, TraceCodec,
    TraceExportConfig, BODY_BYTES_RANGE, DEFAULT_MAX_MEMORY_BYTES, DEFAULT_MAX_OPEN_SEGMENTS,
    DEFAULT_MAX_QUEUED_TRACES, DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_MAX_RESPONSE_BODY_BYTES,
    DEFAULT_SEGMENT_MAX_AGE, DEFAULT_SEGMENT_MAX_BYTES, DEFAULT_UPLOAD_TIMEOUT,
    DEFAULT_ZSTD_WINDOW_LOG, MAX_DISK_BYTES_RANGE, MAX_MEMORY_BYTES_RANGE, MAX_OPEN_SEGMENTS_RANGE,
    MAX_QUEUED_TRACES_RANGE, SEGMENT_MAX_AGE_RANGE_SECS, SEGMENT_MAX_BYTES_RANGE,
    UPLOAD_TIMEOUT_RANGE_SECS, ZSTD_WINDOW_LOG_RANGE,
};
use std::path::PathBuf;
use std::time::Duration;

pub(crate) const TRACES_METADATA_KEY: &str = "io.llmproxy.traces";

/// Ten years: past this a `max_age` is a typo, not a retention policy.
const MAX_AGE_LIMIT_SECS: f64 = 10.0 * 365.0 * 24.0 * 3600.0;

const FIELDS: &[&str] = &[
    "directory",
    "max_disk_bytes",
    "max_age",
    "codec",
    "zstd_window_log",
    "max_request_body_bytes",
    "max_response_body_bytes",
    "max_memory_bytes",
    "max_queued_traces",
    "segment_max_bytes",
    "segment_max_age",
    "max_open_segments",
    "s3",
];

const S3_FIELDS: &[&str] = &[
    "bucket",
    "region",
    "endpoint",
    "path_style",
    "prefix",
    "access_key_id",
    "secret_access_key",
    "session_token",
    "upload_timeout",
];

fn invalid(path: impl Into<String>, reason: &str) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: path.into(),
        reason: reason.into(),
    }
}

fn object<'a>(value: &'a Value, path: &str, keys: &[&str]) -> Result<&'a Struct, ConfigError> {
    let Some(Kind::StructValue(s)) = &value.kind else {
        return Err(invalid(path, "must be an object"));
    };
    // Rust note: `Struct::fields` is a `HashMap`; sort so the reported key
    // is the same on every run.
    let mut unknown: Vec<_> = s
        .fields
        .keys()
        .filter(|k| !keys.contains(&k.as_str()))
        .collect();
    unknown.sort();
    if let Some(k) = unknown.first() {
        return Err(ConfigError::UnsupportedField {
            field_path: format!("{path}.{k}"),
            reason: format!(
                "unsupported trace export field; supported: {}",
                keys.join(", ")
            ),
        });
    }
    Ok(s)
}

fn string<'a>(s: &'a Struct, key: &str, path: &str) -> Result<Option<&'a str>, ConfigError> {
    match s.fields.get(key).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::StringValue(v)) if v.is_empty() => {
            Err(invalid(format!("{path}.{key}"), "must not be empty"))
        }
        Some(Kind::StringValue(v)) => Ok(Some(v)),
        Some(_) => Err(invalid(format!("{path}.{key}"), "must be a string")),
    }
}

fn required_string<'a>(s: &'a Struct, key: &str, path: &str) -> Result<&'a str, ConfigError> {
    string(s, key, path)?.ok_or_else(|| invalid(format!("{path}.{key}"), "is required"))
}

fn absolute_path(s: &Struct, key: &str, path: &str) -> Result<PathBuf, ConfigError> {
    let value = PathBuf::from(required_string(s, key, path)?);
    if !value.is_absolute() {
        return Err(invalid(format!("{path}.{key}"), "must be an absolute path"));
    }
    Ok(value)
}

fn boolean(s: &Struct, key: &str, path: &str) -> Result<Option<bool>, ConfigError> {
    match s.fields.get(key).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::BoolValue(b)) => Ok(Some(*b)),
        Some(_) => Err(invalid(format!("{path}.{key}"), "must be a boolean")),
    }
}

fn integer(
    s: &Struct,
    key: &str,
    path: &str,
    range: &std::ops::RangeInclusive<u64>,
) -> Result<Option<u64>, ConfigError> {
    let p = format!("{path}.{key}");
    let Some(kind) = s.fields.get(key).and_then(|v| v.kind.as_ref()) else {
        return Ok(None);
    };
    let Kind::NumberValue(n) = *kind else {
        return Err(invalid(p, "must be an integer"));
    };
    // 2^53: the largest integer a JSON number carries exactly.
    if !n.is_finite() || n.fract() != 0.0 || n < 0.0 || n > 9_007_199_254_740_992.0 {
        return Err(invalid(p, "must be an integer"));
    }
    let n = n as u64;
    if !range.contains(&n) {
        return Err(invalid(
            p,
            &format!("must be between {} and {}", range.start(), range.end()),
        ));
    }
    Ok(Some(n))
}

/// A duration given as numeric seconds, bounded by `range`.
fn seconds(
    s: &Struct,
    key: &str,
    path: &str,
    range: &std::ops::RangeInclusive<f64>,
) -> Result<Option<Duration>, ConfigError> {
    let p = format!("{path}.{key}");
    match s.fields.get(key).and_then(|v| v.kind.as_ref()) {
        None => Ok(None),
        Some(Kind::NumberValue(n)) if n.is_finite() && range.contains(n) => {
            Ok(Some(Duration::from_secs_f64(*n)))
        }
        Some(Kind::NumberValue(_)) => Err(invalid(
            p,
            &format!(
                "must be between {} and {} seconds",
                range.start(),
                range.end()
            ),
        )),
        Some(_) => Err(invalid(p, "must be a number of seconds")),
    }
}

fn s3(value: &Value, path: &str) -> Result<S3Destination, ConfigError> {
    let s = object(value, path, S3_FIELDS)?;

    let bucket = required_string(s, "bucket", path)?;
    if !valid_bucket(bucket) {
        return Err(invalid(
            format!("{path}.bucket"),
            "must be 3-63 bytes of lowercase letters, digits, '.' and '-', starting and ending \
             with a letter or digit",
        ));
    }
    let region = required_string(s, "region", path)?;
    if region.len() > 64
        || !region
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
    {
        return Err(invalid(
            format!("{path}.region"),
            "must be at most 64 bytes of lowercase letters, digits and '-'",
        ));
    }
    let endpoint = match string(s, "endpoint", path)? {
        None => None,
        Some(e) if valid_endpoint(e) => Some(e.to_owned()),
        Some(_) => {
            return Err(invalid(
                format!("{path}.endpoint"),
                "must be http(s)://host[:port] with no path, query, userinfo or trailing '/'",
            ))
        }
    };
    let path_style = boolean(s, "path_style", path)?.unwrap_or(false);
    let prefix = string(s, "prefix", path)?.unwrap_or("");
    if !valid_prefix(prefix) {
        return Err(invalid(
            format!("{path}.prefix"),
            "must not start or end with '/' and must not contain '//', '.' or '..' segments",
        ));
    }
    let credentials = S3Credentials {
        access_key_id: required_string(s, "access_key_id", path)?.to_owned(),
        secret_access_key: required_string(s, "secret_access_key", path)?.to_owned(),
        session_token: string(s, "session_token", path)?.map(str::to_owned),
    };
    let upload_timeout = seconds(s, "upload_timeout", path, &UPLOAD_TIMEOUT_RANGE_SECS)?
        .unwrap_or(DEFAULT_UPLOAD_TIMEOUT);

    Ok(S3Destination {
        bucket: bucket.to_owned(),
        region: region.to_owned(),
        endpoint,
        path_style,
        prefix: prefix.to_owned(),
        credentials,
        upload_timeout,
    })
}

/// Read `node.metadata["io.llmproxy.traces"]`. `None` when absent: no trace
/// export.
pub(crate) fn convert(
    node: Option<&proxy_api::envoy::config::core::v3::Node>,
    path: &str,
) -> Result<Option<TraceExportConfig>, ConfigError> {
    let Some(value) = node
        .and_then(|n| n.metadata.as_ref())
        .and_then(|m| m.fields.get(TRACES_METADATA_KEY))
    else {
        return Ok(None);
    };
    let root = format!("{path}.metadata[\"{TRACES_METADATA_KEY}\"]");
    let s = object(value, &root, FIELDS)?;

    let directory = absolute_path(s, "directory", &root)?;
    let max_disk_bytes = integer(s, "max_disk_bytes", &root, &MAX_DISK_BYTES_RANGE)?
        .ok_or_else(|| invalid(format!("{root}.max_disk_bytes"), "is required"))?;
    let max_age = seconds(
        s,
        "max_age",
        &root,
        &(f64::MIN_POSITIVE..=MAX_AGE_LIMIT_SECS),
    )?;

    let window_log = integer(s, "zstd_window_log", &root, &ZSTD_WINDOW_LOG_RANGE)?;
    let codec = match string(s, "codec", &root)? {
        None | Some("gzip") => {
            if window_log.is_some() {
                return Err(invalid(
                    format!("{root}.zstd_window_log"),
                    "is only valid with codec zstd",
                ));
            }
            TraceCodec::Gzip
        }
        Some("zstd") => TraceCodec::Zstd {
            window_log: window_log.map_or(DEFAULT_ZSTD_WINDOW_LOG, |n| n as u8),
        },
        Some(_) => return Err(invalid(format!("{root}.codec"), "must be `gzip` or `zstd`")),
    };

    let max_request_body_bytes = integer(s, "max_request_body_bytes", &root, &BODY_BYTES_RANGE)?
        .map_or(DEFAULT_MAX_REQUEST_BODY_BYTES, |n| n as usize);
    let max_response_body_bytes = integer(s, "max_response_body_bytes", &root, &BODY_BYTES_RANGE)?
        .map_or(DEFAULT_MAX_RESPONSE_BODY_BYTES, |n| n as usize);
    let max_memory_bytes = integer(s, "max_memory_bytes", &root, &MAX_MEMORY_BYTES_RANGE)?
        .map_or(DEFAULT_MAX_MEMORY_BYTES, |n| n as usize);
    let max_queued_traces = integer(s, "max_queued_traces", &root, &MAX_QUEUED_TRACES_RANGE)?
        .map_or(DEFAULT_MAX_QUEUED_TRACES, |n| n as usize);
    let segment_max_bytes = integer(s, "segment_max_bytes", &root, &SEGMENT_MAX_BYTES_RANGE)?
        .unwrap_or(DEFAULT_SEGMENT_MAX_BYTES);
    let segment_max_age = seconds(s, "segment_max_age", &root, &SEGMENT_MAX_AGE_RANGE_SECS)?
        .unwrap_or(DEFAULT_SEGMENT_MAX_AGE);
    let max_open_segments = integer(s, "max_open_segments", &root, &MAX_OPEN_SEGMENTS_RANGE)?
        .map_or(DEFAULT_MAX_OPEN_SEGMENTS, |n| n as usize);

    let s3 = s
        .fields
        .get("s3")
        .map(|v| s3(v, &format!("{root}.s3")))
        .transpose()?;

    let config = TraceExportConfig {
        directory,
        max_disk_bytes,
        max_age,
        codec,
        max_request_body_bytes,
        max_response_body_bytes,
        max_memory_bytes,
        max_queued_traces,
        segment_max_bytes,
        segment_max_age,
        max_open_segments,
        s3,
    };
    config
        .validate()
        .map_err(|(field, reason)| invalid(format!("{root}.{field}"), &reason))?;
    Ok(Some(config))
}
