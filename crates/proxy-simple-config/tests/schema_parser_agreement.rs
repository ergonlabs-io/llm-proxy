//! The schema and the parser accept the same field names and enum values.
//!
//! The normative schema and strict parser must accept the same fields and enum
//! values. The parser's accepted names come from serde errors; completeness
//! checks ensure every schema object and strict model type is compared.

mod schema_support;

use proxy_simple_config::model::*;
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;

/// A key no schema property or Rust field could ever be named.
const PROBE: &str = "\u{1}probe";

/// The field names `T` accepts, from serde's unknown-field error.
fn parser_fields<T: DeserializeOwned>() -> BTreeSet<String> {
    let err = match serde_json::from_value::<T>(serde_json::json!({ PROBE: null })) {
        Ok(_) => panic!("{} accepted an unknown field", std::any::type_name::<T>()),
        Err(e) => e.to_string(),
    };
    expected_names(&err, "unknown field", std::any::type_name::<T>())
}

/// The string values the unit enum `T` accepts, from serde's unknown-variant
/// error.
fn parser_variants<T: DeserializeOwned>() -> BTreeSet<String> {
    let err = match serde_json::from_value::<T>(serde_json::json!(PROBE)) {
        Ok(_) => panic!("{} accepted an unknown variant", std::any::type_name::<T>()),
        Err(e) => e.to_string(),
    };
    expected_names(&err, "unknown variant", std::any::type_name::<T>())
}

/// Parses serde's `unknown field `x`, expected one of `a`, `b`` (also the
/// `expected `a` or `b`` and `there are no fields` forms): every backticked
/// name after the probe itself.
fn expected_names(err: &str, kind: &str, type_name: &str) -> BTreeSet<String> {
    assert!(
        err.starts_with(kind),
        "{type_name}: expected a serde `{kind}` error, got: {err}"
    );
    err.split('`')
        .skip(1)
        .step_by(2)
        .skip(1)
        .map(str::to_owned)
        .collect()
}

type FieldProbe = fn() -> BTreeSet<String>;

/// Every closed schema object, paired with the model struct that parses it.
fn object_table() -> Vec<(&'static str, &'static str, FieldProbe)> {
    vec![
        ("#", "SimpleConfig", parser_fields::<SimpleConfig>),
        ("#/$defs/AutoModel", "AutoModel", parser_fields::<AutoModel>),
        (
            "#/$defs/Listener",
            "ListenerSpec",
            parser_fields::<ListenerSpec>,
        ),
        (
            "#/$defs/Listener/properties/tls",
            "ListenTls",
            parser_fields::<ListenTls>,
        ),
        ("#/$defs/Auth", "Auth", parser_fields::<Auth>),
        (
            "#/$defs/AuthEnforce",
            "AuthEnforce",
            parser_fields::<AuthEnforce>,
        ),
        ("#/$defs/AuthStore", "AuthStore", parser_fields::<AuthStore>),
        (
            "#/$defs/AuthStore/properties/in_memory",
            "InMemoryStore",
            parser_fields::<InMemoryStore>,
        ),
        (
            "#/$defs/AuthStorePersistent",
            "PersistentStore",
            parser_fields::<PersistentStore>,
        ),
        (
            "#/$defs/AuthStoreShared",
            "SharedStore",
            parser_fields::<SharedStore>,
        ),
        (
            "#/$defs/AuthTenantCredentials",
            "TenantCredentials",
            parser_fields::<TenantCredentials>,
        ),
        (
            "#/$defs/AuthTenantCredentialKey",
            "PreviousCredentialKey",
            parser_fields::<PreviousCredentialKey>,
        ),
        ("#/$defs/AuthKey", "AuthKey", parser_fields::<AuthKey>),
        ("#/$defs/Provider", "Provider", parser_fields::<Provider>),
        (
            "#/$defs/Provider/properties/request_fields",
            "RequestFields",
            parser_fields::<RequestFields>,
        ),
        ("#/$defs/ModelDef", "ModelDef", parser_fields::<ModelDef>),
        (
            "#/$defs/ModelProvider",
            "ModelProvider",
            parser_fields::<ModelProvider>,
        ),
        ("#/$defs/Route", "RouteRule", parser_fields::<RouteRule>),
        (
            "#/$defs/Route/properties/retries",
            "Retries",
            parser_fields::<Retries>,
        ),
        ("#/$defs/Limit", "Limit", parser_fields::<Limit>),
        (
            "#/$defs/Observability",
            "Observability",
            parser_fields::<Observability>,
        ),
        (
            "#/$defs/Observability/properties/access_logs",
            "AccessLogs",
            parser_fields::<AccessLogs>,
        ),
        (
            "#/$defs/Observability/properties/metrics",
            "Metrics",
            parser_fields::<Metrics>,
        ),
        (
            "#/$defs/Observability/properties/tracing",
            "Tracing",
            parser_fields::<Tracing>,
        ),
        ("#/$defs/Pricing", "Pricing", parser_fields::<Pricing>),
        (
            "#/$defs/PriceList",
            "PriceListDef",
            parser_fields::<PriceListDef>,
        ),
        (
            "#/$defs/PriceEntry",
            "PriceEntryDef",
            parser_fields::<PriceEntryDef>,
        ),
        ("#/$defs/PricingTier", "TierDef", parser_fields::<TierDef>),
        ("#/$defs/Ledger", "Ledger", parser_fields::<Ledger>),
        (
            "#/$defs/LedgerKey",
            "PreviousCredentialKey",
            parser_fields::<PreviousCredentialKey>,
        ),
    ]
}

/// Every schema `enum`, paired with the unit enum that parses it.
fn enum_table() -> Vec<(&'static str, &'static str, FieldProbe)> {
    vec![
        (
            "#/$defs/AuthEnforce/properties/tenants_without_policy",
            "TenantsWithoutPolicy",
            parser_variants::<TenantsWithoutPolicy>,
        ),
        (
            "#/$defs/Provider/properties/type",
            "ProviderType",
            parser_variants::<ProviderType>,
        ),
        (
            "#/$defs/Provider/properties/protocol",
            "UpstreamProtocol",
            parser_variants::<UpstreamProtocol>,
        ),
        (
            "#/$defs/ModelProvider/properties/dialect",
            "Dialect",
            parser_variants::<Dialect>,
        ),
        (
            "#/$defs/Route/properties/streaming",
            "StreamingMode",
            parser_variants::<StreamingMode>,
        ),
        (
            "#/$defs/PriceEntry/properties/tier_mode",
            "TierModeDef",
            parser_variants::<TierModeDef>,
        ),
        (
            "#/$defs/Ledger/properties/on_unavailable",
            "LedgerOnUnavailable",
            parser_variants::<LedgerOnUnavailable>,
        ),
        (
            "#/$defs/Observability/properties/access_logs/properties/format",
            "LogFormat",
            parser_variants::<LogFormat>,
        ),
    ]
}

/// Resolves a `#/a/b` pointer into the schema.
fn at<'a>(schema: &'a serde_json::Value, pointer: &str) -> &'a serde_json::Value {
    schema
        .pointer(pointer.trim_start_matches('#'))
        .unwrap_or_else(|| panic!("schema has no {pointer}"))
}

/// Pointers to closed schema objects and enums, excluding keyed maps and open
/// helper objects inside conditionals.
fn schema_locations(schema: &serde_json::Value) -> (BTreeSet<String>, BTreeSet<String>) {
    fn walk(
        node: &serde_json::Value,
        ptr: String,
        objects: &mut BTreeSet<String>,
        enums: &mut BTreeSet<String>,
    ) {
        match node {
            serde_json::Value::Object(map) => {
                // A keyed map (`providers`, `models`) is closed too, but by a
                // key pattern rather than a field list; its key grammar is
                // checked by `schema_and_parser_agree_on_map_key_names`.
                if map.get("additionalProperties") == Some(&serde_json::Value::Bool(false))
                    && !map.contains_key("patternProperties")
                {
                    objects.insert(ptr.clone());
                }
                if map.contains_key("enum") {
                    enums.insert(ptr.clone());
                }
                for (k, v) in map {
                    // Literal instance data, not subschemas.
                    if matches!(k.as_str(), "examples" | "default" | "const" | "enum") {
                        continue;
                    }
                    walk(v, format!("{ptr}/{k}"), objects, enums);
                }
            }
            serde_json::Value::Array(items) => {
                for (i, v) in items.iter().enumerate() {
                    walk(v, format!("{ptr}/{i}"), objects, enums);
                }
            }
            _ => {}
        }
    }
    let (mut objects, mut enums) = (BTreeSet::new(), BTreeSet::new());
    walk(schema, "#".into(), &mut objects, &mut enums);
    (objects, enums)
}

fn schema_properties(schema: &serde_json::Value, pointer: &str) -> BTreeSet<String> {
    at(schema, pointer)
        .get("properties")
        .and_then(|p| p.as_object())
        .map(|p| p.keys().cloned().collect())
        .unwrap_or_default()
}

fn schema_enum(schema: &serde_json::Value, pointer: &str) -> BTreeSet<String> {
    at(schema, pointer)["enum"]
        .as_array()
        .unwrap_or_else(|| panic!("{pointer} has no enum array"))
        .iter()
        .map(|v| v.as_str().expect("string enum").to_owned())
        .collect()
}

/// Reports both directions of a set difference, or nothing when equal.
fn diff(
    pointer: &str,
    rust: &str,
    schema: &BTreeSet<String>,
    parser: &BTreeSet<String>,
) -> Option<String> {
    let only_schema: Vec<_> = schema.difference(parser).collect();
    let only_parser: Vec<_> = parser.difference(schema).collect();
    (!only_schema.is_empty() || !only_parser.is_empty()).then(|| {
        format!("{pointer} vs {rust}: schema only {only_schema:?}, parser only {only_parser:?}")
    })
}

#[test]
fn schema_and_parser_accept_the_same_field_names() {
    let schema = schema_support::schema();
    let failures: Vec<String> = object_table()
        .into_iter()
        .filter_map(|(ptr, rust, probe)| {
            diff(ptr, rust, &schema_properties(&schema, ptr), &probe())
        })
        .collect();
    assert!(
        failures.is_empty(),
        "field-name drift:\n{}",
        failures.join("\n")
    );
}

#[test]
fn schema_and_parser_accept_the_same_enum_values() {
    let schema = schema_support::schema();
    let failures: Vec<String> = enum_table()
        .into_iter()
        .filter_map(|(ptr, rust, probe)| diff(ptr, rust, &schema_enum(&schema, ptr), &probe()))
        .collect();
    assert!(
        failures.is_empty(),
        "enum-value drift:\n{}",
        failures.join("\n")
    );
}

/// Every closed schema object and enum must have a comparison-table entry.
#[test]
fn every_schema_object_and_enum_is_paired_with_a_model_type() {
    let (objects, enums) = schema_locations(&schema_support::schema());
    let paired_objects: BTreeSet<String> =
        object_table().iter().map(|(p, ..)| p.to_string()).collect();
    let paired_enums: BTreeSet<String> = enum_table().iter().map(|(p, ..)| p.to_string()).collect();
    assert_eq!(
        objects, paired_objects,
        "closed schema objects vs object_table()"
    );
    assert_eq!(enums, paired_enums, "schema enums vs enum_table()");
}

/// Every strict model struct and unit enum must have a table entry; Rust has
/// no reflection over module types, so the source is scanned.
#[test]
fn every_strict_model_type_is_paired_with_a_schema_location() {
    let source = include_str!("../src/model.rs");
    let lines: Vec<&str> = source.lines().collect();
    let type_name = |line: &str| {
        line.trim_start_matches("pub ")
            .trim_start_matches("struct ")
            .trim_start_matches("enum ")
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .next()
            .unwrap_or_default()
            .to_owned()
    };
    let mut structs = BTreeSet::new();
    let mut enums = BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        let attr = line.trim();
        // The attribute sits directly above the item, possibly after other
        // attributes; take the first item line below it.
        let is_struct_marker = attr == "#[serde(deny_unknown_fields)]";
        let is_enum_marker = attr.starts_with("#[serde(rename_all");
        if !is_struct_marker && !is_enum_marker {
            continue;
        }
        let item = lines[i + 1..]
            .iter()
            .find(|l| l.starts_with("pub struct") || l.starts_with("pub enum"))
            .expect("an item follows the attribute");
        if is_struct_marker {
            structs.insert(type_name(item));
        } else if item.starts_with("pub enum") {
            enums.insert(type_name(item));
        }
    }
    let paired_structs: BTreeSet<String> = object_table()
        .iter()
        .map(|(_, r, _)| r.to_string())
        .collect();
    let paired_enums: BTreeSet<String> =
        enum_table().iter().map(|(_, r, _)| r.to_string()).collect();
    assert_eq!(
        structs, paired_structs,
        "deny_unknown_fields structs vs object_table()"
    );
    assert_eq!(enums, paired_enums, "rename_all enums vs enum_table()");
}

/// The probe must read the real accepted set: a known struct's fields come
/// back exactly, so a change in serde's message format fails loudly here
/// rather than turning the comparison into one of empty sets.
#[test]
fn the_probe_reads_serdes_accepted_field_list() {
    assert_eq!(
        parser_fields::<Retries>(),
        BTreeSet::from(["attempts".to_owned()])
    );
    assert_eq!(parser_fields::<InMemoryStore>(), BTreeSet::new());
    assert_eq!(
        parser_variants::<UpstreamProtocol>(),
        BTreeSet::from(["http1".to_owned(), "http2".to_owned()])
    );
}

/// The keyed maps' name grammar: for each candidate key, the schema and the
/// parser give the same verdict. A key the schema rejects but the parser
/// takes (or the reverse) is drift that no field list can show.
/// Builds a whole config that uses the candidate key.
type ConfigForKey<'a> = &'a dyn Fn(&str) -> serde_json::Value;

#[test]
fn schema_and_parser_agree_on_map_key_names() {
    let schema = schema_support::schema();
    let validator = schema_support::validator(&schema);
    let provider_config = |key: &str| {
        serde_json::json!({
            "version": 0,
            // The key is referenced nowhere else, so only the map's key
            // grammar decides (a route reference has its own pattern).
            "providers": { "openai": {}, key: { "base_url": "http://127.0.0.1:1" } },
            "routes": [{ "model": "*", "provider": "openai" }],
        })
    };
    let model_config = |key: &str| {
        serde_json::json!({
            "version": 0,
            "providers": { "openai": {} },
            "models": { key: { "providers": ["openai"] } },
            // `routes` may be empty when `models` has an entry.
            "routes": [],
        })
    };
    let cases: [(&str, ConfigForKey, &[&str]); 2] = [
        (
            "providers",
            &provider_config,
            &[
                "openai",
                "my-vllm",
                "0x",
                "-lead",
                "Upper",
                "under_score",
                "dot.ted",
                "",
            ],
        ),
        (
            "models",
            &model_config,
            &[
                "gpt-4o",
                "gpt-4*",
                "*",
                "*-mini",
                "gpt-*-mini",
                "a**",
                "**",
                "claude 3",
                "",
            ],
        ),
    ];
    let mut failures = Vec::new();
    for (map, build, keys) in cases {
        let mut verdicts = BTreeSet::new();
        for key in keys {
            let config = build(key);
            let schema_ok = schema_support::validation_errors(&validator, &config).is_empty();
            let parser_ok = proxy_simple_config::parse_simple_config(&config.to_string()).is_ok();
            verdicts.insert(schema_ok);
            if schema_ok != parser_ok {
                failures.push(format!(
                    "{map} key {key:?}: schema {}, parser {}",
                    verdict(schema_ok),
                    verdict(parser_ok)
                ));
            }
        }
        // Both verdicts must occur, or the base config is broken and every
        // key fails for an unrelated reason.
        assert_eq!(
            verdicts.len(),
            2,
            "{map}: every candidate key got the same verdict"
        );
    }
    assert!(
        failures.is_empty(),
        "map-key drift:\n{}",
        failures.join("\n")
    );
}

fn verdict(ok: bool) -> &'static str {
    if ok {
        "accepts"
    } else {
        "rejects"
    }
}
