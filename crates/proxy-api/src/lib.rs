//! Generated Envoy v3 API protos + embedded `FileDescriptorSet` (WP-02).
//!
//! This crate is the ONLY place Envoy protos are generated. It pins the Envoy API
//! version for the whole project (see IMPLEMENTATION_PLAN.md Part 0, rule 1).
//!
//! WP-02 deliverables:
//! - Vendored `envoyproxy/envoy` API protos at the pinned release tag.
//! - `prost-build`/`tonic-build` generation for: bootstrap, listener, cluster, route,
//!   endpoint, tls, HCM, router, and the ADS/SDS/ALS/ext_authz/ratelimit services.
//! - An embedded `FileDescriptorSet` powering `descriptor_pool()`, used by
//!   `proxy-config` for proto3-JSON parsing (YAML bootstrap) and strict-mode
//!   unknown-field detection.

use prost_reflect::DescriptorPool;

/// The pinned Envoy API release this build targets. Bump only via a dedicated
/// "proto upgrade" change that re-runs the WP-05 exhaustive field checklists.
pub const PINNED_ENVOY_API_TAG: &str = "v1.38.0";

/// Descriptor pool for all vendored Envoy protos.
///
/// TODO(WP-02): embed the real `FileDescriptorSet` produced at build time.
pub fn descriptor_pool() -> &'static DescriptorPool {
    unimplemented!("WP-02: generate protos and embed the FileDescriptorSet")
}
