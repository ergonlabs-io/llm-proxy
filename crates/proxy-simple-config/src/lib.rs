//! The simple LLM-native config dialect.
//!
//! The dialect follows the normative schema and lowers to standard Envoy
//! resources, then uses the same strict parse, PGV, and IR pipeline as Envoy
//! bootstrap mode. A capability must already exist in Envoy mode before the
//! dialect exposes it. LLM-tuned timeout and retry defaults are applied here.

pub mod lower;
pub mod model;
pub mod parse;

// Compiled under `test` too, so `make tq` keeps the seam building even though
// only the nightly-only fuzz crate enables the feature.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;

pub use lower::{
    has_inline_secrets, lower, lower_to_loaded, require_service_node, to_envoy_yaml,
    to_envoy_yaml_with_secrets, Lowered, MODEL_HEADER, REDACTED,
};
pub use model::SimpleConfig;
pub use parse::{
    load_simple_config_file, looks_like_envoy_bootstrap, looks_like_simple_config,
    parse_simple_config, parse_simple_config_with_env,
};

/// The shipped example embedded so docs, doctests, and tests share one copy.
// Rust note: `include_str!` reads the file's contents at *compile* time and
// inlines them as a `&'static str`; the path is resolved relative to this
// source file, not the crate root or the working directory.
pub const SAMPLE_CONFIG: &str = include_str!("../../../examples/llmproxy.yaml");

/// Parse [`SAMPLE_CONFIG`], resolving every `${VAR}` reference to a
/// deterministic placeholder (`sk-sample-<name>`) so the sample never
/// requires real environment variables.
///
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
