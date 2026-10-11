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
        // Extensions we implement (their type URLs must resolve).
        "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto",
        "envoy/extensions/filters/http/router/v3/router.proto",
        // Route-scoped CORS policy and local HTTP token buckets. These
        // must be roots, not merely vendored files: the descriptor pool is
        // what lets strict lowering decode their Any payloads.
        "envoy/extensions/filters/http/cors/v3/cors.proto",
        "envoy/extensions/filters/http/ext_authz/v3/ext_authz.proto",
        "envoy/service/auth/v3/external_auth.proto",
        "envoy/extensions/filters/http/local_ratelimit/v3/local_rate_limit.proto",
        "envoy/extensions/filters/network/tcp_proxy/v3/tcp_proxy.proto",
        "envoy/extensions/filters/listener/tls_inspector/v3/tls_inspector.proto",
        "envoy/extensions/transport_sockets/tls/v3/tls.proto",
        "envoy/extensions/upstreams/http/v3/http_protocol_options.proto",
        // Aggregate clusters (provider fallback): the type URL under a
        // `Cluster.cluster_type.typed_config` must resolve for the surface
        // walk to see inside it.
        "envoy/extensions/clusters/aggregate/v3/cluster.proto",
        // The built-in retry host predicate. Its empty
        // typed config still has to be in the descriptor pool so strict
        // bootstrap parsing can distinguish it from an unknown extension.
        "envoy/extensions/retry/host/previous_hosts/v3/previous_hosts.proto",
        // Access logging: common AccessLog/AccessLogFilter types plus
        // the two logger extensions we implement (file, stdout/stderr).
        "envoy/config/accesslog/v3/accesslog.proto",
        "envoy/extensions/access_loggers/file/v3/file.proto",
        "envoy/extensions/access_loggers/stream/v3/stream.proto",
        // LLM extensions we define ourselves, rather than borrowing an
        // unrelated Envoy message -- the auth filter. Note this is the only
        // root NOT under `vendor/envoy`: `scripts/vendor-protos.sh` does not
        // manage it, because it is ours and is not re-fetched on a proto bump.
        "llmproxy/filters/v0/auth.proto",
        // Owned token-budget configuration.  The legacy
        // Envoy RateLimitSettings decoder remains registered for one release,
        // but new configs lower to this message.
        "llmproxy/filters/v0/token_limit.proto",
        // Owned usage dialect and pricing carrier. The
        // legacy DataSource decoder remains registered for one release.
        "llmproxy/filters/v0/usage.proto",
        // Owned body-rewrite configuration. The legacy
        // RuntimeFeatureFlag decoder remains registered for one release.
        "llmproxy/filters/v0/body_rewrite.proto",
        // Per-tenant model allow-lists.
        "llmproxy/filters/v0/model_authz.proto",
        // The spend-budget filter's (cluster, model)
        // price table.
        "llmproxy/filters/v0/spend.proto",
        // OTLP export. The collector gRPC services; protoc
        // pulls the transitive trace/metrics/common/resource messages. We
        // hand-roll the exporter over these (build_client) and the in-test
        // mock collector over the generated servers (build_server), rather
        // than pulling in the opentelemetry SDK crates --
        // the SDK's Send+Sync async providers fight the !Send data
        // plane (ADR-0003); these plain prost/tonic types do not.
        "opentelemetry/proto/collector/trace/v1/trace_service.proto",
        "opentelemetry/proto/collector/metrics/v1/metrics_service.proto",
    ];

    let out_dir = PathBuf::from(std::env::var("OUT_DIR")?);
    let root_paths: Vec<PathBuf> = roots.iter().map(|r| vendor.join(r)).collect();

    // Tell cargo exactly what this script depends on.
    //
    // Without at least one `rerun-if-changed`, cargo falls back to re-running
    // the build script whenever ANY file in the package changes -- and every
    // rerun rewrites the generated tree in OUT_DIR with fresh mtimes, which
    // invalidates `proxy-api` and therefore every crate in the workspace,
    // since they all depend on it. Declaring the inputs turns that into "rerun
    // only when a vendored proto or this script actually changes".
    //
    // `vendor/` is watched as a directory rather than file-by-file: protoc
    // pulls transitive imports we never name in `roots`, so listing only the
    // roots would miss a change to an imported proto and silently serve stale
    // generated code -- the worse failure of the two.
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", vendor.display());

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
