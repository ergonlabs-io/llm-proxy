//! Stable access-log capture comparison for WP-24/WP-26.
//!
//! Envoy and llm-proxy emit the same semantic access-log fields, but timing,
//! byte counts, and connection-local addresses vary between runs. This module
//! parses JSON access-log lines, masks only explicitly volatile fields, and
//! reports field-level differences for the side-by-side harness.

use std::collections::BTreeMap;

use serde_json::Value;

/// A normalized JSON access-log object suitable for comparison.
pub type NormalizedAccessLog = BTreeMap<String, Value>;

/// Fields whose values are inherently run-specific and must not make a
/// deterministic lifecycle comparison fail.
pub const DEFAULT_VOLATILE_FIELDS: &[&str] = &[
    "start_time",
    "duration",
    "request_duration",
    "response_duration",
    "downstream_remote_address",
    "upstream_host",
    "bytes_received",
    "bytes_sent",
];

/// Parse and normalize one JSON access-log line.
pub fn normalize_json_line(
    line: &str,
    volatile_fields: &[&str],
) -> Result<NormalizedAccessLog, AccessLogDiffError> {
    let value: Value = serde_json::from_str(line.trim())
        .map_err(|source| AccessLogDiffError::InvalidJson { source })?;
    let object = value.as_object().ok_or(AccessLogDiffError::NotAnObject)?;
    let mut normalized = BTreeMap::new();
    for (key, value) in object {
        normalized.insert(
            key.clone(),
            if volatile_fields.contains(&key.as_str()) {
                Value::String("<volatile>".to_string())
            } else {
                value.clone()
            },
        );
    }
    Ok(normalized)
}

/// Compare two normalized access-log lines and return field-level changes.
pub fn compare_json_lines(
    expected: &str,
    actual: &str,
    volatile_fields: &[&str],
) -> Result<(), AccessLogDiffError> {
    let expected = normalize_json_line(expected, volatile_fields)?;
    let actual = normalize_json_line(actual, volatile_fields)?;
    if expected == actual {
        return Ok(());
    }

    let mut differences = Vec::new();
    for key in expected.keys().chain(actual.keys()) {
        if differences.iter().any(|seen| seen == key) {
            continue;
        }
        let left = expected.get(key);
        let right = actual.get(key);
        if left != right {
            differences.push(key.clone());
        }
    }
    Err(AccessLogDiffError::FieldMismatch {
        fields: differences,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum AccessLogDiffError {
    #[error("access-log line is not valid JSON: {source}")]
    InvalidJson { source: serde_json::Error },
    #[error("access-log JSON value must be an object")]
    NotAnObject,
    #[error("access-log fields differ: {fields:?}")]
    FieldMismatch { fields: Vec<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_only_declared_volatile_fields() {
        let envoy = r#"{"start_time":"2026-09-20T12:00:00Z","response_code":200,"response_flags":"-","duration":12,"path":"/v1/chat"}"#;
        let proxy = r#"{"start_time":"2026-09-20T12:00:01Z","response_code":200,"response_flags":"-","duration":99,"path":"/v1/chat"}"#;
        compare_json_lines(envoy, proxy, DEFAULT_VOLATILE_FIELDS)
            .expect("volatile timing fields should not differ");
    }

    #[test]
    fn reports_semantic_field_differences() {
        let envoy = r#"{"response_code":200,"response_flags":"-"}"#;
        let proxy = r#"{"response_code":503,"response_flags":"UH"}"#;
        let err = compare_json_lines(envoy, proxy, &[]).expect_err("status and flags must differ");
        assert!(matches!(
            err,
            AccessLogDiffError::FieldMismatch { ref fields }
                if fields == &["response_code", "response_flags"]
        ));
    }

    #[test]
    fn rejects_non_object_json() {
        let err = normalize_json_line("[]", &[]).expect_err("array is not an access-log object");
        assert!(matches!(err, AccessLogDiffError::NotAnObject));
    }
}
