//! Configuration pipeline: bootstrap loading, PGV validation,
//! and the proto -> internal IR conversion.
//!
//! AGENTS.md invariant 2: protobuf types do not escape this crate (and
//! `proxy-xds`) — except through [`loader::LoadedBootstrap`], which lowering
//! consumes to build the IR the data plane actually runs on.
//!
//! AGENTS.md invariant 1: strict mode is the default. Every Envoy config field is
//! either mapped or rejected with its full field path — never silently ignored.

pub mod authorization;
mod capture;
pub mod error;
pub mod ir;
pub mod loader;
pub mod lower;
pub mod validate;

pub use error::{
    ConfigError, ConfigFrontEnd, ConfigWarning, UNKNOWN_FIELD_BOOTSTRAP_HINT,
    UNKNOWN_FIELD_DIALECT_HINT,
};
pub use ir::ConfigSnapshot;
pub use loader::{load_bootstrap_file, parse_bootstrap, ConfigFormat, LoadedBootstrap};
pub use lower::{
    build_snapshot, lower_dynamic_cluster, lower_dynamic_endpoints, lower_dynamic_listener,
    lower_dynamic_route, tenant_credential_verify_path_problem,
};
pub use validate::validate_message;

/// How to treat config fields we do not (yet) implement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrictMode {
    /// Unsupported field => hard error (static config) / NACK (xDS). The default.
    #[default]
    Strict,
    /// Unsupported field => structured warning, surfaced via admin. Opt-in only.
    Permissive,
}
