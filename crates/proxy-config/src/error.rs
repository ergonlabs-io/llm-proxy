//! Config error type shared by bootstrap loading (WP-03), validation (WP-04),
//! IR conversion (WP-05) and xDS NACKs (WP-20).

/// A configuration error. `field_path` is always the full dotted path into the
/// Envoy proto, e.g. `static_resources.listeners[0].filter_chains[0].filters[0].typed_config`.
/// xDS NACK `error_detail` messages are built from `Display` of this type.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(
        "unsupported field `{field_path}`: {reason} (strict mode; see docs/envoy-divergences.md)"
    )]
    UnsupportedField { field_path: String, reason: String },

    #[error("invalid value at `{field_path}`: {reason}")]
    InvalidValue { field_path: String, reason: String },

    #[error("validation failed at `{field_path}`: {rule}")]
    Validation { field_path: String, rule: String },

    #[error("unknown extension type URL `{type_url}` at `{field_path}`")]
    UnknownTypeUrl {
        field_path: String,
        type_url: String,
    },

    #[error("failed to parse config: {0}")]
    Parse(String),

    #[error("not yet implemented ({work_package})")]
    Unimplemented { work_package: &'static str },
}
