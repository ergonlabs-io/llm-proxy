//! Generates Rust types + tonic service stubs from the vendored Envoy protos
//! (see `scripts/vendor-protos.sh` for the pins) and emits the
//! `FileDescriptorSet` that powers `proxy_api::descriptor_pool()`.
//!
//! We list only the ROOT protos we consume; protoc pulls their transitive
//! imports automatically, and prost generates code for everything in the
//! resulting descriptor set. Adding a new Envoy extension type = add its root
//! here.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vendor = PathBuf::from("vendor");

    let roots = [
        // Core resource types (bootstrap pulls listener/cluster/secret/etc.).
        "envoy/config/bootstrap/v3/bootstrap.proto",
        "envoy/config/route/v3/route.proto",
        "envoy/config/endpoint/v3/endpoint.proto",
        // xDS services.
        "envoy/service/discovery/v3/ads.proto",
        "envoy/service/discovery/v3/discovery.proto",
        "envoy/service/secret/v3/sds.proto",
        // Extensions we implement (their type URLs must resolve — WP-02 gate).
        "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto",
        "envoy/extensions/filters/http/router/v3/router.proto",
        "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto",
        "envoy/extensions/transport_sockets/tls/v3/tls.proto",
        "envoy/extensions/upstreams/http/v3/http_protocol_options.proto",
    ];

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let root_paths: Vec<PathBuf> = roots.iter().map(|r| vendor.join(r)).collect();

    tonic_build::configure()
        .build_client(true)
        .build_server(true) // servers are reused by the testing/controlplane harness
        .file_descriptor_set_path(out_dir.join("descriptor.bin"))
        // Emit one `generated.rs` containing the whole module tree, so lib.rs
        // includes a single file instead of one include! per proto package.
        .include_file("generated.rs")
        .compile_protos(&root_paths, &[vendor])?;

    Ok(())
}
