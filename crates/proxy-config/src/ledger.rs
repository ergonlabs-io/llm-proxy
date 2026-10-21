//! Strict decoder for `node.metadata["io.llmproxy.ledger"]`, the billing
//! ledger (ADR-0009). Process-level, like the tracing and metrics
//! namespaces beside it: there is one ledger writer per process, so it sits
//! on the bootstrap `node`, not on a listener or HCM.
//!
//! `google.protobuf.Struct` is opaque to the reflective surface walk, so
//! AGENTS.md invariant 1 is enforced here by hand: every unknown key and
//! every bad value fails with its full dotted path.

use crate::error::ConfigError;
use prost_types::{value::Kind, Struct, Value};
use proxy_observability::ledger::{
    LedgerConfig, LedgerKeyFile, OnUnavailable, DEFAULT_GROUP_COMMIT_INTERVAL,
    DEFAULT_GROUP_COMMIT_MAX_ENTRIES, DEFAULT_MAX_RESERVATIONS, MAX_GROUP_COMMIT_ENTRIES,
    MAX_RESERVATIONS,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

pub(crate) const LEDGER_METADATA_KEY: &str = "io.llmproxy.ledger";

/// The spool's own floor: database metadata plus commit headroom.
const MIN_DISK_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DISK_BYTES: u64 = 1 << 40;
/// The spool holds at most 32 keys, the active one included.
const MAX_PREVIOUS_KEYS: usize = 31;

const FIELDS: &[&str] = &[
    "directory",
    "encryption_key_file",
    "encryption_key_id",
    "previous_keys",
    "max_disk_bytes",
    "max_reservations",
    "group_commit_max_entries",
    "group_commit_interval",
    "on_unavailable",
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
            reason: format!("unsupported ledger field; supported: {}", keys.join(", ")),
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

fn key_id(s: &Struct, key: &str, path: &str) -> Result<String, ConfigError> {
    let id = required_string(s, key, path)?;
    if id.len() > 128 || id.chars().any(char::is_control) {
        return Err(invalid(
            format!("{path}.{key}"),
            "must be 1-128 bytes without control characters",
        ));
    }
    Ok(id.to_owned())
}

fn integer(
    s: &Struct,
    key: &str,
    path: &str,
    range: std::ops::RangeInclusive<u64>,
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

/// Read `node.metadata["io.llmproxy.ledger"]`. `None` when absent: no
/// ledger, and admission reserves nothing.
pub(crate) fn convert(
    node: Option<&proxy_api::envoy::config::core::v3::Node>,
    path: &str,
) -> Result<Option<LedgerConfig>, ConfigError> {
    let Some(value) = node
        .and_then(|n| n.metadata.as_ref())
        .and_then(|m| m.fields.get(LEDGER_METADATA_KEY))
    else {
        return Ok(None);
    };
    let root = format!("{path}.metadata[\"{LEDGER_METADATA_KEY}\"]");
    let s = object(value, &root, FIELDS)?;

    let directory = absolute_path(s, "directory", &root)?;
    let encryption_key = LedgerKeyFile {
        file: absolute_path(s, "encryption_key_file", &root)?,
        id: key_id(s, "encryption_key_id", &root)?,
    };
    let mut ids = BTreeSet::from([encryption_key.id.clone()]);
    let mut previous_keys = Vec::new();
    if let Some(list) = s.fields.get("previous_keys") {
        let list_path = format!("{root}.previous_keys");
        let Some(Kind::ListValue(list)) = &list.kind else {
            return Err(invalid(list_path, "must be a list"));
        };
        if list.values.len() > MAX_PREVIOUS_KEYS {
            return Err(invalid(list_path, "at most 31 previous keys"));
        }
        for (i, entry) in list.values.iter().enumerate() {
            let entry_path = format!("{list_path}[{i}]");
            let e = object(entry, &entry_path, &["id", "file"])?;
            let key = LedgerKeyFile {
                id: key_id(e, "id", &entry_path)?,
                file: absolute_path(e, "file", &entry_path)?,
            };
            if !ids.insert(key.id.clone()) {
                return Err(invalid(
                    format!("{entry_path}.id"),
                    "must differ from encryption_key_id and every other previous key id",
                ));
            }
            previous_keys.push(key);
        }
    }

    let max_disk_bytes = integer(s, "max_disk_bytes", &root, MIN_DISK_BYTES..=MAX_DISK_BYTES)?
        .ok_or_else(|| invalid(format!("{root}.max_disk_bytes"), "is required"))?;
    let max_reservations = integer(s, "max_reservations", &root, 1..=MAX_RESERVATIONS as u64)?
        .map_or(DEFAULT_MAX_RESERVATIONS, |n| n as usize);
    let group_commit_max_entries = integer(
        s,
        "group_commit_max_entries",
        &root,
        1..=MAX_GROUP_COMMIT_ENTRIES as u64,
    )?
    .map_or(DEFAULT_GROUP_COMMIT_MAX_ENTRIES, |n| n as usize);

    let interval_path = format!("{root}.group_commit_interval");
    let group_commit_interval = match s
        .fields
        .get("group_commit_interval")
        .and_then(|v| v.kind.as_ref())
    {
        None => DEFAULT_GROUP_COMMIT_INTERVAL,
        Some(Kind::NumberValue(n)) if n.is_finite() && (0.001..=1.0).contains(n) => {
            Duration::from_secs_f64(*n)
        }
        Some(Kind::NumberValue(_)) => {
            return Err(invalid(
                interval_path,
                "must be between 0.001 and 1 seconds",
            ))
        }
        Some(_) => return Err(invalid(interval_path, "must be a number of seconds")),
    };

    let on_unavailable = match string(s, "on_unavailable", &root)? {
        // Unset means reject (ADR-0009 decision 5).
        None | Some("reject") => OnUnavailable::Reject,
        Some("admit") => OnUnavailable::Admit,
        Some(_) => {
            return Err(invalid(
                format!("{root}.on_unavailable"),
                "must be `reject` or `admit`",
            ))
        }
    };

    Ok(Some(LedgerConfig {
        directory,
        encryption_key,
        previous_keys,
        max_disk_bytes,
        max_reservations,
        group_commit_max_entries,
        group_commit_interval,
        on_unavailable,
    }))
}
