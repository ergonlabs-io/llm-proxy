//! Configuration pipeline: bootstrap loading (WP-03), PGV validation (WP-04),
//! and the proto -> internal IR conversion (WP-05).
//!
//! Ground rule #3 (IMPLEMENTATION_PLAN.md): protobuf types do not escape this crate
//! (and `proxy-xds`). The rest of the system consumes the IR in [`ir`].
//!
//! Ground rule #2: strict mode is the default. Every Envoy config field is either
//! mapped to IR or rejected with its full field path — never silently ignored.

pub mod error;
pub mod ir;

pub use error::ConfigError;
pub use ir::ConfigSnapshot;

/// How to treat config fields we do not (yet) implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrictMode {
    /// Unsupported field => hard error (static config) / NACK (xDS). The default.
    #[default]
    Strict,
    /// Unsupported field => structured warning, surfaced via admin. Opt-in only.
    Permissive,
}

/// Load an Envoy bootstrap file (`.yaml`/`.json`/`.pb`/`.pb_text`) into a validated
/// [`ConfigSnapshot`].
///
/// Pipeline (WP-03): bytes -> serde value -> prost-reflect proto3-JSON deserialize
/// against `envoy.config.bootstrap.v3.Bootstrap` (deny unknown fields in strict mode)
/// -> PGV validation (WP-04) -> IR conversion (WP-05).
pub fn load_bootstrap(
    _path: &std::path::Path,
    _mode: StrictMode,
) -> Result<ConfigSnapshot, ConfigError> {
    Err(ConfigError::Unimplemented {
        work_package: "WP-03",
    })
}
