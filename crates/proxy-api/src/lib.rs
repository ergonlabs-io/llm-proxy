//! Generated Envoy v3 API protos + embedded `FileDescriptorSet`.
//!
//! This crate is the ONLY place Envoy protos are generated. It pins the Envoy
//! API version for the whole project (AGENTS.md invariant 9);
//! the vendored `.proto` sources and their dependency pins live in `vendor/`,
//! maintained by `scripts/vendor-protos.sh`.
//!
//! Two things are exported:
//! - The generated Rust types and tonic service stubs, under their proto
//!   package paths (e.g. [`envoy::config::bootstrap::v3::Bootstrap`]).
//! - [`descriptor_pool`], a reflection view of every compiled proto. This is
//!   what lets `proxy-config` parse Envoy YAML/JSON (the proto3 JSON mapping,
//!   including `Any` by type URL) and detect unknown fields for strict mode.
//!
//! Rust note: the generated code is produced by `build.rs` at compile time into
//! `OUT_DIR`; `include!` splices that file into this crate as if written here.

// The generated module tree is large and machine-written; skip lints we cannot
// fix without editing tonic/prost output. `result_large_err` fires on generated
// gRPC clients because `tonic::Status` itself is 176 bytes — boxing it would
// mean forking the generator. `async_trait` adds `must_use` to futures already
// marked must-use; newer Clippy versions flag this in generated service traits.
#[allow(
    missing_docs,
    rustdoc::invalid_html_tags,
    rustdoc::bare_urls,
    clippy::doc_markdown,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items,
    clippy::large_enum_variant,
    clippy::enum_variant_names,
    clippy::len_without_is_empty,
    clippy::result_large_err,
    clippy::double_must_use
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}

pub use generated::*;

use std::sync::OnceLock;

use prost_reflect::DescriptorPool;

/// The pinned Envoy API release this build targets. Bump only via a dedicated
/// proto-upgrade change that re-runs the exhaustive field checklists.
pub const PINNED_ENVOY_API_TAG: &str = "v1.38.0";

/// The serialized `FileDescriptorSet` for every vendored proto we compile
/// (roots + transitive imports). Embedded at build time.
pub const FILE_DESCRIPTOR_SET: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/descriptor.bin"));

/// Descriptor pool over [`FILE_DESCRIPTOR_SET`]. Resolves every
/// `type.googleapis.com/envoy.*` type URL this build supports.
///
/// Rust note: `OnceLock` is the standard lazy-init-once primitive — the pool is
/// decoded on first call, then every caller shares the same `'static` reference.
pub fn descriptor_pool() -> &'static DescriptorPool {
    static POOL: OnceLock<DescriptorPool> = OnceLock::new();
    POOL.get_or_init(|| {
        DescriptorPool::decode(FILE_DESCRIPTOR_SET)
            .expect("embedded FileDescriptorSet must decode; regenerate with a clean build")
    })
}
