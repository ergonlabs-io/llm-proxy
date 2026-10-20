//! The auth filter's chargeback-tag step: config parsing for
//! `Authentication.chargeback_tags` and `VirtualKey.tags`, and the per-request
//! resolution the filter runs after authentication. The tag rules themselves
//! are in `proxy_observability::chargeback`.

use std::sync::Arc;

use http::HeaderMap;
use prost_reflect::DynamicMessage;
use proxy_config::ConfigError;
use proxy_observability::chargeback::{
    validate_key_tags, ChargebackTags, DropReason, TagPolicy, HEADER,
};
use proxy_observability::stats::{Handle, Instrument, InstrumentKind, Registry, WorkerId};

/// Tags dropped, by reason. `reason` is the only label and has five values;
/// tag keys and values are never labels, so no request can add a series.
pub static DROPPED: Instrument = Instrument {
    name: "llmproxy_chargeback_tags_dropped_total",
    kind: InstrumentKind::Counter,
    unit: "{tag}",
    attribute_keys: &["reason"],
    buckets: None,
};

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

/// Reads `typed_config.chargeback_tags`. `None` when unset: no tags are
/// attributed and the header is never read.
pub(crate) fn parse_policy(config: &DynamicMessage) -> Result<Option<TagPolicy>, ConfigError> {
    const BASE: &str = "typed_config.chargeback_tags";
    if !config.has_field_by_name("chargeback_tags") {
        return Ok(None);
    }
    let Some(msg) = config
        .get_field_by_name("chargeback_tags")
        .and_then(|v| v.as_message().cloned())
    else {
        return Err(invalid(BASE, "must be a message"));
    };
    let entries: Vec<prost_reflect::Value> = msg
        .get_field_by_name("allowed")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();
    let mut allowed = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let entry = entry
            .as_message()
            .ok_or_else(|| invalid(format!("{BASE}.allowed[{i}]"), "must be a message"))?;
        let key = entry
            .get_field_by_name("key")
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        let values: Vec<String> = entry
            .get_field_by_name("values")
            .and_then(|v| {
                v.as_list().map(|l| {
                    l.iter()
                        .filter_map(|v| v.as_str().map(str::to_owned))
                        .collect()
                })
            })
            .unwrap_or_default();
        // Proto3 cannot tell an empty list from an absent one; empty means
        // any value, as the proto documents.
        allowed.push((key, (!values.is_empty()).then_some(values)));
    }
    let from_header = msg
        .get_field_by_name("from_header")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let cap = |field: &str| {
        msg.get_field_by_name(field)
            .and_then(|v| v.as_u32())
            .filter(|n| *n != 0)
            .map(|n| n as usize)
    };
    TagPolicy::new(
        allowed,
        from_header,
        cap("max_tags"),
        cap("max_value_bytes"),
    )
    .map(Some)
    .map_err(|reason| {
        // `TagPolicy::new` names the part (`allowed[0].key: ...`); move
        // the part into the dotted path when it leads the reason.
        match reason.split_once(": ") {
            Some((part, rest)) if part.starts_with("allowed[") => {
                invalid(format!("{BASE}.{part}"), rest)
            }
            _ => match reason.split_once(' ') {
                Some((field, _)) if matches!(field, "max_tags" | "max_value_bytes" | "allowed") => {
                    invalid(format!("{BASE}.{field}"), reason)
                }
                _ => invalid(BASE, reason),
            },
        }
    })
}

/// Reads `typed_config.virtual_keys[i].tags`.
pub(crate) fn parse_key_tags(
    msg: &DynamicMessage,
    base: &str,
) -> Result<ChargebackTags, ConfigError> {
    let path = format!("{base}.tags");
    let Some(map) = msg
        .get_field_by_name("tags")
        .and_then(|v| v.as_map().cloned())
    else {
        return Ok(ChargebackTags::new());
    };
    let mut tags = ChargebackTags::new();
    for (key, value) in map.iter() {
        let (prost_reflect::MapKey::String(key), prost_reflect::Value::String(value)) =
            (key, value)
        else {
            return Err(invalid(path, "map keys and values must be strings"));
        };
        tags.insert(key.clone(), value.clone());
    }
    validate_key_tags(&tags).map_err(|reason| invalid(path, reason))?;
    Ok(tags)
}

/// The policy plus its drop counters, shared by every stream of one chain.
pub(crate) struct Tagging {
    policy: TagPolicy,
    exported: Option<(Arc<Registry>, [Handle; 5])>,
}

impl Tagging {
    pub(crate) fn new(policy: TagPolicy, registry: Option<Arc<Registry>>) -> Self {
        let exported = registry.map(|registry| {
            let handles = DropReason::ALL.map(|reason| {
                registry.resolve_capped(
                    &DROPPED,
                    &[("reason", reason.as_str())],
                    8,
                    &[("reason", "overflow")],
                )
            });
            (registry, handles)
        });
        Self { policy, exported }
    }

    /// Resolves the request's tags from the key's metadata and, when the
    /// policy enables it, the [`HEADER`], counting every drop. The header is
    /// removed when the policy reads it, so it never reaches the provider;
    /// otherwise it is not touched.
    pub(crate) fn resolve(
        &self,
        key_tags: &ChargebackTags,
        headers: &mut HeaderMap,
    ) -> ChargebackTags {
        let resolved = if self.policy.from_header() {
            let values: Vec<&[u8]> = headers
                .get_all(HEADER)
                .iter()
                .map(|v| v.as_bytes())
                .collect();
            let resolved = self.policy.resolve(key_tags, &values);
            headers.remove(HEADER);
            resolved
        } else {
            self.policy.resolve(key_tags, &[])
        };
        if let Some((registry, handles)) = &self.exported {
            for (reason, count) in resolved.dropped.iter() {
                let index = DropReason::ALL
                    .iter()
                    .position(|r| *r == reason)
                    .expect("ALL lists every reason");
                registry.incr(WorkerId(0), handles[index], count);
            }
        }
        resolved.tags
    }
}
