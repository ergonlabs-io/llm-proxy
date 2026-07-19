//! Config error type shared by bootstrap loading (WP-03), validation (WP-04),
//! IR conversion (WP-05) and xDS NACKs (WP-20).

/// A configuration error. `field_path` is always the full dotted path into the
/// Envoy proto, e.g. `static_resources.listeners[0].filter_chains[0].filters[0].typed_config`.
/// For errors scoped to a whole file rather than a proto field (e.g. an
/// unimplemented bootstrap format), `field_path` is the file path instead —
/// every strict-mode rejection names *where* (ground rule #2), whatever kind
/// of "where" applies. xDS NACK `error_detail` messages are built from
/// `Display` of this type.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unknown field at `{field_path}`: not a recognized Envoy field at this position (strict mode; run with --permissive to ignore)")]
    UnknownField { field_path: String },

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

    #[error("failed to read `{path}`: {reason}")]
    Io { path: String, reason: String },

    #[error("failed to parse config: {0}")]
    Parse(String),

    #[error("not yet implemented at `{field_path}`: {reason}")]
    Unimplemented { field_path: String, reason: String },
}

/// A non-fatal finding from permissive-mode loading, surfaced on stderr and
/// (later) via the admin endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// Full dotted path of the field the warning is about.
    pub field_path: String,
    pub message: String,
}
