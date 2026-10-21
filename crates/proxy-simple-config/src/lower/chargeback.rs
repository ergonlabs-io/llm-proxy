//! `auth.chargeback_tags` -> `Authentication.chargeback_tags`, and
//! `auth.keys[].tags` -> `VirtualKey.tags`. The filter checks the same rules
//! again on the proto (`proxy_observability::chargeback`); they are repeated
//! here so errors name dialect paths, because this crate does not depend on
//! the data plane. `tests/chargeback.rs` pins both sets of rules together.

use std::collections::{BTreeMap, HashSet};

use proxy_config::ConfigError;
use serde_json::{json, Value};

use crate::model::ChargebackTagsDef;

/// Must equal `proxy_observability::chargeback::MAX_KEY_BYTES`.
const MAX_KEY_BYTES: usize = 64;
/// Must equal `proxy_observability::chargeback::MAX_TAGS_CEILING`.
const MAX_TAGS_CEILING: u32 = 32;
/// Must equal `proxy_observability::chargeback::MAX_VALUE_BYTES_CEILING`.
const MAX_VALUE_BYTES_CEILING: u32 = 256;
/// Must equal `proxy_observability::chargeback::DEFAULT_MAX_VALUE_BYTES`.
const DEFAULT_MAX_VALUE_BYTES: u32 = 64;

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

pub(super) fn check_key(key: &str, path: &str) -> Result<(), ConfigError> {
    let mut bytes = key.bytes();
    let well_formed = (1..=MAX_KEY_BYTES).contains(&key.len())
        && bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b));
    if well_formed {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!(
                "tag key `{key}` must be 1 to {MAX_KEY_BYTES} bytes of lowercase letters, \
                 digits, `_`, `.` and `-`, starting with a letter"
            ),
        ))
    }
}

fn check_value(value: &str, max_bytes: u32, path: &str) -> Result<(), ConfigError> {
    let well_formed = (1..=max_bytes as usize).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:/@+-".contains(&b));
    if well_formed {
        Ok(())
    } else {
        Err(invalid(
            path,
            format!(
                "tag value `{value}` must be 1 to {max_bytes} bytes of ASCII letters, digits, \
                 `_`, `.`, `:`, `/`, `@`, `+` and `-`"
            ),
        ))
    }
}

/// Lowers `auth.chargeback_tags`.
pub(super) fn lower_policy(def: &ChargebackTagsDef) -> Result<Value, ConfigError> {
    const BASE: &str = "auth.chargeback_tags";
    for (field, value) in [
        ("max_tags", def.max_tags.map(|v| (v, MAX_TAGS_CEILING))),
        (
            "max_value_bytes",
            def.max_value_bytes.map(|v| (v, MAX_VALUE_BYTES_CEILING)),
        ),
    ] {
        if let Some((value, ceiling)) = value {
            if !(1..=ceiling).contains(&value) {
                return Err(invalid(
                    format!("{BASE}.{field}"),
                    format!("must be 1 to {ceiling}, got {value}"),
                ));
            }
        }
    }
    let max_value_bytes = def.max_value_bytes.unwrap_or(DEFAULT_MAX_VALUE_BYTES);
    if def.allowed.is_empty() {
        return Err(invalid(
            format!("{BASE}.allowed"),
            "must name at least one tag key",
        ));
    }
    let mut seen = HashSet::new();
    let mut allowed = Vec::with_capacity(def.allowed.len());
    for (i, entry) in def.allowed.iter().enumerate() {
        let path = format!("{BASE}.allowed[{i}]");
        check_key(&entry.key, &format!("{path}.key"))?;
        if !seen.insert(entry.key.as_str()) {
            return Err(invalid(
                format!("{path}.key"),
                format!("duplicate tag key `{}`", entry.key),
            ));
        }
        let mut lowered = json!({ "key": entry.key });
        if let Some(values) = &entry.values {
            if values.is_empty() {
                return Err(invalid(
                    format!("{path}.values"),
                    "must not be empty; omit it to allow any value",
                ));
            }
            for (j, value) in values.iter().enumerate() {
                check_value(value, max_value_bytes, &format!("{path}.values[{j}]"))?;
            }
            lowered["values"] = json!(values);
        }
        allowed.push(lowered);
    }
    let mut out = json!({ "allowed": allowed, "from_header": def.from_header });
    if let Some(max_tags) = def.max_tags {
        out["max_tags"] = json!(max_tags);
    }
    if let Some(max_value_bytes) = def.max_value_bytes {
        out["max_value_bytes"] = json!(max_value_bytes);
    }
    Ok(out)
}

/// Checks `auth.keys[i].tags` (`path` is `auth.keys[i].tags`).
pub(super) fn check_key_tags(
    tags: &BTreeMap<String, String>,
    path: &str,
) -> Result<(), ConfigError> {
    if tags.len() > MAX_TAGS_CEILING as usize {
        return Err(invalid(
            path,
            format!("at most {MAX_TAGS_CEILING} tags, got {}", tags.len()),
        ));
    }
    for (key, value) in tags {
        check_key(key, path)?;
        check_value(value, MAX_VALUE_BYTES_CEILING, &format!("{path}.{key}"))?;
    }
    Ok(())
}
