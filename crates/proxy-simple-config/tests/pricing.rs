use proxy_config::ConfigError;
use proxy_simple_config::{lower, parse_simple_config, SimpleConfig};

const BASE: &str = r#"
version: 0
providers:
  openai: { api_key: test }
routes:
  - model: "*"
    provider: openai
pricing:
  price_list:
    version: 2026-09
    effective_from: "2026-09-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-5
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 1250
            cached_input_nanodollars_per_token: 125
            cache_write_nanodollars_per_token: 1560
            output_nanodollars_per_token: 10000
"#;

fn parse(text: &str) -> SimpleConfig {
    parse_simple_config(text).expect("config parses")
}

#[test]
fn valid_inline_price_list_lowers() {
    let lowered = lower(&parse(BASE)).expect("rate card validates");
    assert!(lowered
        .warnings
        .iter()
        .all(|warning| !warning.field_path.starts_with("pricing")));
}

#[test]
fn rate_card_reaches_the_listener_usage_filter_with_actual_provider_map() {
    let lowered = lower(&parse(BASE)).expect("rate card validates");
    let typed_config = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["http_filters"]
        .as_array()
        .expect("filters")
        .iter()
        .find(|filter| filter["name"] == "llmproxy.usage")
        .expect("usage filter")["typed_config"]
        .clone();
    assert_eq!(typed_config["@type"], proxy_filters::usage_filter::TYPE_URL);
    assert_eq!(typed_config["dialect"], "openai");
    let carrier: serde_json::Value = serde_json::from_str(
        typed_config["pricing_json"]
            .as_str()
            .expect("rate card carrier"),
    )
    .expect("strict JSON carrier");
    assert_eq!(carrier["price_list"]["version"], "2026-09");
    assert_eq!(carrier["providers"]["provider:openai"], "openai");
}

#[test]
fn tier_mode_is_required_with_a_precise_path() {
    let config = BASE.replace("        tier_mode: whole_request\n", "");
    let error = lower(&parse(&config)).expect_err("must not guess money semantics");
    let ConfigError::InvalidValue { field_path, .. } = error else {
        panic!("expected invalid value")
    };
    assert_eq!(field_path, "pricing.price_list.entries[0].tier_mode");
}

#[test]
fn invalid_tier_ladder_is_rejected_at_load() {
    let config = BASE.replace(
        "          - input_nanodollars_per_token: 1250",
        "          - up_to: 200\n            input_nanodollars_per_token: 1250",
    );
    let error = lower(&parse(&config)).expect_err("a final finite tier leaves a hole");
    let ConfigError::InvalidValue { field_path, .. } = error else {
        panic!("expected invalid value")
    };
    assert_eq!(field_path, "pricing.price_list.entries[0].tiers");
}

#[test]
fn file_and_inline_sources_are_mutually_exclusive() {
    let config = BASE.replace(
        "  price_list:\n",
        "  price_list_file: /tmp/prices.yaml\n  price_list:\n",
    );
    let error = lower(&parse(&config)).expect_err("two sources must never have precedence");
    let ConfigError::InvalidValue { field_path, .. } = error else {
        panic!("expected invalid value")
    };
    assert_eq!(field_path, "pricing");
}

#[test]
fn tier_selector_is_not_configurable_away_from_total_input_context() {
    let config = BASE.replace(
        "        tier_mode: whole_request\n",
        "        tier_basis: output_tokens\n        tier_mode: whole_request\n",
    );
    let error = parse_simple_config(&config).expect_err("only total input context selects tiers");
    let ConfigError::UnknownField { field_path, .. } = error else {
        panic!("expected unknown field")
    };
    assert_eq!(field_path, "pricing.price_list.entries[0].tier_basis");
}

#[test]
fn unknown_cache_rates_and_source_metadata_survive_lowering() {
    let config = BASE.replace("pricing:\n", "pricing:\n  catalog: { source: openrouter, models: [] }\n")
        .replace("        tier_mode: whole_request", "        cached_input_unpriced: true\n        cache_write_unpriced: true\n        tier_mode: whole_request");
    let lowered = lower(&parse(&config)).unwrap();
    let filters = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["http_filters"]
        .as_array()
        .unwrap();
    let carrier: serde_json::Value = serde_json::from_str(
        filters
            .iter()
            .find(|filter| filter["name"] == "llmproxy.usage")
            .unwrap()["typed_config"]["pricing_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(carrier["catalog"]["source"], "openrouter");
    assert_eq!(
        carrier["price_list"]["entries"][0]["cached_input_unpriced"],
        true
    );
    assert_eq!(
        carrier["price_list"]["entries"][0]["cache_write_unpriced"],
        true
    );
}

// ---- rate-card basis (images) and per-modality tier rates ----

mod schema_support;

fn carrier(config: &str) -> serde_json::Value {
    let lowered = lower(&parse(config)).expect("rate card validates");
    let filters = lowered.bootstrap["static_resources"]["listeners"][0]["filter_chains"][0]
        ["filters"][0]["typed_config"]["http_filters"]
        .as_array()
        .expect("filters")
        .clone();
    let text = filters
        .iter()
        .find(|filter| filter["name"] == "llmproxy.usage")
        .expect("usage filter")["typed_config"]["pricing_json"]
        .as_str()
        .expect("rate card carrier")
        .to_string();
    serde_json::from_str(&text).expect("strict JSON carrier")
}

fn error_path(config: &str) -> String {
    match lower(&parse(config)).expect_err("must be rejected") {
        ConfigError::InvalidValue { field_path, .. } => field_path,
        other => panic!("expected invalid value, got {other:?}"),
    }
}

const IMAGES_ENTRY: &str = r#"
      - provider_type: openai
        model: image-model
        basis: images
        image_prices:
          - size: 1024x1024
            quality: high
            nanodollars_per_image: 100
          - size: 1024x1024
            nanodollars_per_image: 50
          - nanodollars_per_image: 10
"#;

/// An existing token card must lower to exactly this JSON: the card's version
/// hash is computed over it, so any new key would change every stored version.
#[test]
fn token_card_lowers_to_the_pinned_json() {
    let entry = &carrier(BASE)["price_list"]["entries"][0];
    assert_eq!(
        entry.to_string(),
        r#"{"cache_write_unpriced":false,"cached_input_unpriced":false,"model":"gpt-5","provider_type":"openai","tier_mode":"whole_request","tiers":[{"cache_write_nanodollars_per_token":1560,"cached_input_nanodollars_per_token":125,"input_nanodollars_per_token":1250,"output_nanodollars_per_token":10000,"up_to":null}]}"#
    );
}

#[test]
fn images_entry_lowers_without_token_keys() {
    let config = format!("{BASE}{IMAGES_ENTRY}");
    let entry = &carrier(&config)["price_list"]["entries"][1];
    assert_eq!(
        entry,
        &serde_json::json!({
            "cached_input_unpriced": false,
            "cache_write_unpriced": false,
            "provider_type": "openai",
            "model": "image-model",
            "basis": "images",
            "image_prices": [
                {"size": "1024x1024", "quality": "high", "nanodollars_per_image": 100},
                {"size": "1024x1024", "nanodollars_per_image": 50},
                {"nanodollars_per_image": 10},
            ],
        })
    );
    assert!(entry.get("tier_mode").is_none() && entry.get("tiers").is_none());
}

#[test]
fn explicit_tokens_basis_lowers_like_the_default() {
    let config = BASE.replace(
        "        tier_mode: whole_request",
        "        basis: tokens\n        tier_mode: whole_request",
    );
    assert_eq!(carrier(&config), carrier(BASE));
}

#[test]
fn modality_rates_lower_only_when_set() {
    let config = BASE.replace(
        "            output_nanodollars_per_token: 10000",
        "            output_nanodollars_per_token: 10000\n            image_input_nanodollars_per_token: 7\n            audio_output_nanodollars_per_token: 0",
    );
    let tier = &carrier(&config)["price_list"]["entries"][0]["tiers"][0];
    assert_eq!(tier["image_input_nanodollars_per_token"], 7);
    assert_eq!(tier["audio_output_nanodollars_per_token"], 0);
    assert!(tier.get("image_output_nanodollars_per_token").is_none());
    assert!(tier.get("audio_input_nanodollars_per_token").is_none());
}

#[test]
fn modality_rate_must_be_on_every_tier_or_none() {
    let config = BASE
        .replace(
            "          - input_nanodollars_per_token: 1250",
            "          - up_to: 200\n            input_nanodollars_per_token: 1250",
        )
        .replace(
            "            output_nanodollars_per_token: 10000",
            "            output_nanodollars_per_token: 10000\n            image_input_nanodollars_per_token: 7\n          - input_nanodollars_per_token: 1\n            cached_input_nanodollars_per_token: 1\n            cache_write_nanodollars_per_token: 1\n            output_nanodollars_per_token: 1",
        );
    assert_eq!(
        error_path(&config),
        "pricing.price_list.entries[0].tiers[1].image_input_nanodollars_per_token"
    );
}

#[test]
fn image_prices_on_a_tokens_entry_is_rejected() {
    let config = BASE.replace(
        "        tier_mode: whole_request",
        "        image_prices:\n          - nanodollars_per_image: 1\n        tier_mode: whole_request",
    );
    assert_eq!(
        error_path(&config),
        "pricing.price_list.entries[0].image_prices"
    );
}

fn images_card(entry_body: &str) -> String {
    let head = BASE.split("      - provider_type").next().unwrap();
    format!(
        "{head}      - provider_type: openai\n        model: image-model\n        basis: images\n{entry_body}"
    )
}

#[test]
fn images_entry_requires_image_prices() {
    assert_eq!(
        error_path(&images_card("")),
        "pricing.price_list.entries[0].image_prices"
    );
    assert_eq!(
        error_path(&images_card("        image_prices: []\n")),
        "pricing.price_list.entries[0].image_prices"
    );
}

#[test]
fn images_entry_rejects_token_fields_and_unpriced_flags() {
    let rows = "        image_prices:\n          - nanodollars_per_image: 1\n";
    for (extra, field) in [
        ("        tier_mode: graduated\n", "tier_mode"),
        (
            "        tiers:\n          - input_nanodollars_per_token: 1\n            cached_input_nanodollars_per_token: 1\n            cache_write_nanodollars_per_token: 1\n            output_nanodollars_per_token: 1\n",
            "tiers",
        ),
        ("        cached_input_unpriced: true\n", "cached_input_unpriced"),
        ("        cache_write_unpriced: true\n", "cache_write_unpriced"),
    ] {
        assert_eq!(
            error_path(&images_card(&format!("{rows}{extra}"))),
            format!("pricing.price_list.entries[0].{field}")
        );
    }
    // An explicit false is the default, so it is accepted.
    lower(&parse(&images_card(&format!(
        "{rows}        cached_input_unpriced: false\n"
    ))))
    .expect("false flags are the default");
}

#[test]
fn ambiguous_image_rows_name_the_later_row_and_the_earlier_index() {
    let cases = [
        // Identical pairs.
        "          - { size: a, quality: b, nanodollars_per_image: 1 }\n          - { size: a, quality: b, nanodollars_per_image: 2 }\n",
        // Two catch-alls.
        "          - { nanodollars_per_image: 1 }\n          - { nanodollars_per_image: 2 }\n",
        // Size-only beside quality-only, in either order.
        "          - { size: a, nanodollars_per_image: 1 }\n          - { quality: b, nanodollars_per_image: 2 }\n",
        "          - { quality: b, nanodollars_per_image: 1 }\n          - { size: a, nanodollars_per_image: 2 }\n",
    ];
    for rows in cases {
        let config = images_card(&format!("        image_prices:\n{rows}"));
        let ConfigError::InvalidValue { field_path, reason } =
            lower(&parse(&config)).expect_err("ambiguous")
        else {
            panic!("expected invalid value")
        };
        assert_eq!(field_path, "pricing.price_list.entries[0].image_prices[1]");
        assert!(reason.contains("image_prices[0]"), "{reason}");
    }
}

#[test]
fn distinct_specificity_and_distinct_values_are_not_ambiguous() {
    let rows = "        image_prices:\n          - { size: a, quality: b, nanodollars_per_image: 1 }\n          - { size: a, nanodollars_per_image: 2 }\n          - { size: c, nanodollars_per_image: 3 }\n          - { quality: b, nanodollars_per_image: 4 }\n";
    // size-only and quality-only rows clash even with different values, so
    // only the size-only/quality-only pair here is the ambiguity.
    assert_eq!(
        error_path(&images_card(rows)),
        "pricing.price_list.entries[0].image_prices[3]"
    );
    let ok = "        image_prices:\n          - { size: a, quality: b, nanodollars_per_image: 1 }\n          - { size: a, quality: c, nanodollars_per_image: 2 }\n          - { size: a, nanodollars_per_image: 3 }\n          - { size: b, nanodollars_per_image: 4 }\n          - { nanodollars_per_image: 5 }\n";
    lower(&parse(&images_card(ok))).expect("distinct rows are fine");
}

#[test]
fn empty_size_or_quality_is_rejected() {
    let config = images_card(
        "        image_prices:\n          - { size: \"\", nanodollars_per_image: 1 }\n",
    );
    assert_eq!(
        error_path(&config),
        "pricing.price_list.entries[0].image_prices[0].size"
    );
}

#[test]
fn phase_three_bases_and_unknown_image_price_keys_fail_to_parse() {
    for basis in ["characters", "audio_seconds"] {
        let config = BASE.replace(
            "        tier_mode: whole_request",
            &format!("        basis: {basis}\n        tier_mode: whole_request"),
        );
        let error = parse_simple_config(&config).expect_err("not accepted yet");
        assert!(error.to_string().contains("basis"), "{error}");
    }
    let config = images_card(
        "        image_prices:\n          - { nanodollars_per_image: 1, resolution: x }\n",
    );
    let error = parse_simple_config(&config).expect_err("strict row");
    assert!(error.to_string().contains("resolution"), "{error}");
}

fn schema_errors(config: &str) -> Vec<(String, String)> {
    let schema = schema_support::schema();
    let validator = schema_support::validator(&schema);
    let instance: serde_json::Value = serde_yaml::from_str(config).expect("yaml");
    schema_support::validation_errors(&validator, &instance)
}

#[test]
fn schema_accepts_valid_rate_card_shapes_and_rejects_invalid_ones() {
    assert_eq!(schema_errors(BASE), vec![]);
    assert_eq!(schema_errors(&format!("{BASE}{IMAGES_ENTRY}")), vec![]);
    let with_modality = BASE.replace(
        "            output_nanodollars_per_token: 10000",
        "            output_nanodollars_per_token: 10000\n            audio_input_nanodollars_per_token: 3",
    );
    assert_eq!(schema_errors(&with_modality), vec![]);

    let rows = "        image_prices:\n          - nanodollars_per_image: 1\n";
    let invalid = [
        // tokens entry without tiers
        BASE.replace("        tier_mode: whole_request\n", ""),
        // images entry without image_prices
        images_card(""),
        images_card("        image_prices: []\n"),
        // images entry with token fields
        images_card(&format!("{rows}        tier_mode: graduated\n")),
        // image_prices on tokens
        BASE.replace(
            "        tier_mode: whole_request",
            &format!("{rows}        tier_mode: whole_request"),
        ),
        // unknown / phase-3 basis
        BASE.replace(
            "        tier_mode: whole_request",
            "        basis: characters\n        tier_mode: whole_request",
        ),
        // strict row, empty attribute, negative price
        images_card("        image_prices:\n          - { nanodollars_per_image: 1, other: x }\n"),
        images_card("        image_prices:\n          - { size: \"\", nanodollars_per_image: 1 }\n"),
        images_card("        image_prices:\n          - { nanodollars_per_image: -1 }\n"),
        BASE.replace(
            "            output_nanodollars_per_token: 10000",
            "            output_nanodollars_per_token: 10000\n            image_input_nanodollars_per_token: -1",
        ),
    ];
    for (index, config) in invalid.iter().enumerate() {
        assert!(
            !schema_errors(config).is_empty(),
            "invalid case {index} was accepted by the schema:\n{config}"
        );
    }
}
