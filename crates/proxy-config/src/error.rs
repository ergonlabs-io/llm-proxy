//! Config error type shared by bootstrap loading, validation,
//! IR conversion and xDS NACKs.

/// A configuration error. `field_path` is always the full dotted path into the
/// Envoy proto, e.g. `static_resources.listeners[0].filter_chains[0].filters[0].typed_config`.
/// For errors scoped to a whole file rather than a proto field (e.g. an
/// unimplemented bootstrap format), `field_path` is the file path instead —
/// every strict-mode rejection names *where* (AGENTS.md invariant 1), whatever kind
/// of "where" applies. xDS NACK `error_detail` messages are built from
/// `Display` of this type.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    // Rust note: thiserror's `#[error(...)]` accepts any expression that's
    // valid inside `write!`'s argument list, not just bare field
    // interpolation -- `front_end.unknown_field_hint()` is a method call on
    // one of this variant's own fields, in scope because thiserror
    // destructures the variant before running the format string. That's how
    // one variant renders two genuinely different messages depending on
    // which front end (bootstrap vs. dialect) hit it, without a hand-written
    // `Display` impl for the whole enum.
    #[error("unknown field at `{field_path}`: {}", front_end.unknown_field_hint())]
    UnknownField {
        field_path: String,
        front_end: ConfigFrontEnd,
    },

    #[error(
        "unsupported field `{field_path}`: {reason} (strict mode; see https://ergonlabs.io/docs/llm-proxy/help/limitations/)"
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

/// Which config front end produced an [`ConfigError::UnknownField`] — the
/// two need genuinely different advice, not just a relabeled brand name:
/// `--permissive` is a real escape hatch on one and a no-op on the other, and
/// the authority for "what's valid here" is a different document. User-facing
/// text must not say "Envoy" (owner decision 2026-08-09); this is what lets
/// the bootstrap message stay accurate without using the word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFrontEnd {
    /// `-c`/`--config-path`: the bootstrap configuration format. Loaded with
    /// `deny_unknown_fields`, but `--permissive` genuinely relaxes
    /// that at boot, so the hint pointing at it is true here.
    Bootstrap,
    /// `--config`: the llm-proxy dialect (`schema/llmproxy-v0.schema.json`).
    /// Always strict — `--permissive` has no effect on it, so the message
    /// must not suggest it.
    Dialect,
}

/// Fixed tail of the bootstrap front end's unknown-field message. Public so
/// tests pin the real string instead of retyping it (a retyped copy proves
/// nothing about what the code actually emits).
pub const UNKNOWN_FIELD_BOOTSTRAP_HINT: &str =
    "not a recognized field in the bootstrap configuration at this position \
     (strict mode; run with --permissive to ignore)";

/// Fixed tail of the dialect front end's unknown-field message. Names the
/// schema instead of a flag, because the flag does nothing here.
pub const UNKNOWN_FIELD_DIALECT_HINT: &str =
    "not a recognized llm-proxy configuration field at this position \
     (the configuration is always strict; see schema/llmproxy-v0.schema.json for valid fields)";

impl ConfigFrontEnd {
    /// The fixed tail of this front end's unknown-field message.
    pub fn unknown_field_hint(self) -> &'static str {
        match self {
            ConfigFrontEnd::Bootstrap => UNKNOWN_FIELD_BOOTSTRAP_HINT,
            ConfigFrontEnd::Dialect => UNKNOWN_FIELD_DIALECT_HINT,
        }
    }
}

/// A non-fatal finding from permissive-mode loading, surfaced on stderr and
/// (later) via the admin endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// Full dotted path of the field the warning is about.
    pub field_path: String,
    pub message: String,
}
