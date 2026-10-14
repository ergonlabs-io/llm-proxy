//! The simple LLM-native config dialect.
//!
//! **Normative schema: `schema/llmproxy-v0.schema.json`** — the single source
//! of truth for the dialect. User docs, editor autocomplete, and the validator
//! are all generated from that file; this crate implements it, never extends it.
//!
//! Architecture: this is a FRONT-END, not a parallel config system. The
//! dialect lowers to standard Envoy resources (providers -> clusters + TLS
//! contexts, routes -> a route table on one listener/HCM), which then flow
//! through the identical `proxy-config` strict-parse -> PGV-validate -> IR
//! pipeline as Envoy bootstrap mode. `llm-proxy --mode translate` prints the
//! lowered Envoy bootstrap. Dialect rule: a capability must exist in the
//! Envoy-mode surface before the dialect may expose it.
//!
//! LLM-tuned defaults live here (no total timeout, idle-based guards,
//! never-retry-after-first-byte); Envoy bootstrap mode keeps Envoy's defaults
//! for parity.
//!
//! `SAMPLE_CONFIG` / `sample_config()` expose the shipped example for docs
//! and tests.

pub mod lower;
pub mod model;
pub mod parse;

pub use lower::{
    has_inline_secrets, lower, lower_to_loaded, to_envoy_yaml, to_envoy_yaml_with_secrets, Lowered,
    MODEL_HEADER, REDACTED,
};
pub use model::SimpleConfig;
pub use parse::{
    load_simple_config_file, looks_like_envoy_bootstrap, looks_like_simple_config,
    parse_simple_config, parse_simple_config_with_env,
};

/// The annotated sample config shipped as `examples/llmproxy.yaml` — the
/// "2-minute experience" file users copy from. Embedded here so docs,
/// doctests, and tests all exercise the exact file users see, instead of a
/// second copy that can drift out of sync.
// Rust note: `include_str!` reads the file's contents at *compile* time and
// inlines them as a `&'static str`; the path is resolved relative to this
// source file, not the crate root or the working directory.
pub const SAMPLE_CONFIG: &str = include_str!("../../../examples/llmproxy.yaml");

/// Parse [`SAMPLE_CONFIG`], resolving every `${VAR}` reference to a
/// deterministic placeholder (`sk-sample-<name>`) so the sample never
/// requires real environment variables.
///
/// This cannot panic in practice: the dialect test suite parses and lowers
/// `SAMPLE_CONFIG` end to end, so any change that would break parsing fails
/// CI before it reaches this helper.
///
/// ```
/// let config = proxy_simple_config::sample_config();
/// let lowered = proxy_simple_config::lower(&config).expect("sample lowers");
/// assert!(lowered.bootstrap["static_resources"]["clusters"].is_array());
/// ```
pub fn sample_config() -> SimpleConfig {
    let resolver = |name: &str| Some(format!("sk-sample-{}", name.to_ascii_lowercase()));
    parse::parse_simple_config_with_env(SAMPLE_CONFIG, &resolver)
        .expect("SAMPLE_CONFIG must parse — kept green by the dialect test suite")
}
