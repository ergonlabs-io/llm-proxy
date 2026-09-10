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
