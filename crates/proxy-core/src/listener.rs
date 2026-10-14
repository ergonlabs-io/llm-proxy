//! Per-worker listener manager: each worker binds its own
//! socket per listener, accepts connections, matches them against the
//! listener's filter chains (`crate::filter_chain`), and dispatches to the
//! matched chain's terminal L4 network filter -- `tcp_proxy`
//! (`crate::tcp_proxy`) or the HTTP connection manager.
//!
//! ## Platform divergence: `SO_REUSEPORT` accept balancing
//!
//! Every worker binds its own socket to the *same* listener address with
//! `SO_REUSEPORT`. On Linux the kernel load-balances incoming connections
//! across every socket bound this way -- that's the production path, and it's
//! what makes the share-nothing worker design (ADR-0003) able to accept
//! without a central accept thread handing sockets off to workers. On macOS,
//! `SO_REUSEPORT` allows the bind but does **not** balance accepts across the
//! duplicate sockets (in practice, whichever socket was bound most recently
//! tends to receive most/all new connections); this is a dev-only caveat --
//! fine for local development and tests, not representative of production
//! (Linux) accept distribution.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use proxy_cluster::manager::ClusterManager;
use proxy_config::ir::{
    CodecType, HttpConnectionManagerConfig, ListenerConfig, ListenerFilterSpec, ListenerName,
    NetworkFilterSpec, SnapshotVersion,
};
use proxy_config::ConfigSnapshot;
use proxy_http::codec::{serve_http1, serve_http2, Http1Options};
use proxy_http::filter::{
    FactoryContext, FilterRegistry, SharedFactoryState, TerminalFilterInstanceFactory,
};
use proxy_http::filter_manager::{ConfiguredHttpFilter, FilterChainHandler};
use proxy_http::handler::{DownstreamInfo, StreamHandler};
use proxy_http::router::RouterFilterFactory;
use proxy_http::stat_handles::{DownstreamStats, GenAiLatencyStats, GenAiTokenStats, RouterStats};
use proxy_observability::trace::SpanSink;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::drain::{drain_started, ConnectionRegistry, DrainState};
use crate::filter_chain::{select_filter_chain, ConnectionProperties};
use crate::header_mutation_filter::HeaderMutationFactory;
use crate::lifecycle::LifecycleState;
use crate::tcp_proxy::{self, TcpProxyParams};
use crate::tls::{DownstreamTlsFactory, SdsSecretRegistry, TlsBuildError};
use crate::tls_inspector::inspect_client_hello;
use crate::WorkerConfigHandle;

/// The shared [`FilterRegistry`]: every worker's listeners look up HTTP
/// filter factories by `type_url` against the same registered set, built
/// exactly once ("construct it once and share it, do not build a registry per
/// connection").
///
/// Rust note: `std::sync::OnceLock` is the safe, `std`-only way to build a
/// value lazily on first access and share it thereafter -- no `unsafe`, and
/// no extra crate dependency for something this simple. Registration happens
/// exactly once (the first caller to reach `get_or_init` blocks any
/// concurrent caller until it's done), so [`FilterRegistry::register`]'s
/// "called twice for the same type_url" assertion can never fire here.
fn filter_registry() -> &'static Arc<FilterRegistry> {
    static REGISTRY: std::sync::OnceLock<Arc<FilterRegistry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = FilterRegistry::default();
        registry.register(Arc::new(HeaderMutationFactory));
        registry.register(Arc::new(proxy_filters::ext_authz::ExtAuthzFactory));
        // CORS policies live on the route through
        // `typed_per_filter_config`; registration only makes a configured
        // policy buildable, never enables CORS on an unrelated route.
        registry.register(Arc::new(proxy_filters::cors::CorsFilterFactory));
        // Local rate limits keep their process-wide buckets in the
        // factory's shared state. Registration alone consumes no requests;
        // a listener must configure this type URL to enforce a limit.
        registry.register(Arc::new(
            proxy_filters::local_ratelimit::LocalRateLimitFilterFactory,
        ));
        // The usage/token filter. Registered unconditionally
        // -- it only does anything on a route that configures it, and a filter
        // that isn't in the registry is a hard config error at load time.
        registry.register(Arc::new(proxy_filters::usage_filter::UsageFilterFactory));
        // Migration compatibility: hand-written bootstraps using the
        // borrowed DataSource carrier continue to load for one release.
        // Its factory emits a deprecation warning and preserves old field
        // semantics while new configs use the owned Usage message.
        registry.register(Arc::new(
            proxy_filters::usage_filter::LegacyUsageFilterFactory,
        ));
        // The request-body rewrite filter
        // (forced `stream_options.include_usage` for OpenAI-dialect
        // streaming requests). Also registered unconditionally, same
        // reasoning as the usage filter above.
        registry.register(Arc::new(
            proxy_filters::body_rewrite_filter::BodyRewriteFilterFactory,
        ));
        // Migration compatibility: hand-written bootstraps using the
        // borrowed RuntimeFeatureFlag carrier continue to load for one
        // release. Its factory emits a deprecation warning and preserves old
        // field semantics while new configs use BodyRewrite.
        registry.register(Arc::new(
            proxy_filters::body_rewrite_filter::LegacyBodyRewriteFilterFactory,
        ));
        // The token-budget limiter. Must be
        // configured BEFORE `llmproxy.usage` in any listener's `http_filters`
        // list for its encode-side `record` to observe usage the usage
        // filter wrote (S2.1: encode runs in reverse config order) -- see
        // `token_limit_filter`'s module doc. Also registered unconditionally,
        // same reasoning as the filters above.
        registry.register(Arc::new(
            proxy_filters::token_limit_filter::TokenLimitFilterFactory,
        ));
        // Migration compatibility: hand-written bootstraps using the
        // borrowed Envoy RateLimitSettings continue to load for one release.
        // Its factory emits a deprecation warning and has the same runtime
        // semantics as the owned TokenLimit message above.
        registry.register(Arc::new(
            proxy_filters::token_limit_filter::LegacyTokenLimitFilterFactory,
        ));
        // Downstream authentication. Must be
        // configured BEFORE `llmproxy.token_limit` in any listener's
        // `http_filters` list -- decode callbacks run in FORWARD config order
        // (S2.1), and the limiter buckets on the tenant this filter resolves.
        // Unlike the two ordering notes above, that one is ENFORCED:
        // `proxy_config::lower::check_lane_h_filter_order` rejects the wrong
        // order at load time, because getting it wrong silently drops the
        // limiter back to bucketing on a client-supplied header. Registered
        // unconditionally, same reasoning as the filters above -- and note
        // that registering it does NOT enable authentication anywhere; only a
        // listener that configures the filter authenticates.
        registry.register(Arc::new(proxy_filters::auth_filter::AuthFilterFactory));
        // Per-tenant model allow-lists. Must be
        // configured AFTER BOTH `llmproxy.auth` (needs the tenant) and
        // `llmproxy.body_rewrite` (needs the extracted model) in any
        // listener's `http_filters` list -- `proxy_config::lower::
        // check_lane_h_filter_order` enforces both at config load. Also
        // registered unconditionally, same reasoning as the filters above:
        // registering it does NOT enable model authorization anywhere; only
        // a listener that configures the filter enforces an allow-list.
        registry.register(Arc::new(
            proxy_filters::model_authz_filter::ModelAuthzFilterFactory,
        ));
        // Resolution of the reserved `auto` model. Must be configured AFTER
        // `llmproxy.auth` and `llmproxy.body_rewrite` and BEFORE
        // `llmproxy.model_authz`; `check_lane_h_filter_order` enforces all
        // three. Registering it resolves nothing until a listener configures it.
        registry.register(Arc::new(
            proxy_filters::model_resolver_filter::ModelResolverFilterFactory,
        ));
        // Per-tenant spend-budget
        // enforcement. Decode-check + encode-record, exactly like
        // `llmproxy.token_limit` above -- must be configured AFTER
        // `llmproxy.auth` (needs the tenant) and BEFORE `llmproxy.usage`
        // (needs the usage filter's encode-side write) in any listener's
        // `http_filters` list. `proxy_config::lower::check_lane_h_filter_order`
        // enforces both at config load. Also registered unconditionally,
        // same reasoning as the filters above: registering it does NOT
        // enable spend enforcement anywhere; only a listener that configures
        // the filter enforces a ceiling.
        registry.register(Arc::new(
            proxy_filters::spend_limit_filter::SpendLimitFilterFactory,
        ));
        Arc::new(registry)
    })
}

/// Compiled downstream TLS factories for one listener's filter chains,
/// aligned by index with `ListenerConfig.filter_chains`,
/// plus the `default_filter_chain`. `None` in a slot means that chain has no
/// `transport_socket` (plaintext) -- or, only after a failed *runtime*
/// rebuild (see `spawn_accept_loop`), that its factory couldn't be rebuilt.
///
/// Rust note: these factories hold live `rustls` state (cert resolvers,
/// crypto providers) so they can't live in `ConfigSnapshot` -- `proxy-config`
/// can't depend on `proxy-core`'s TLS types (AGENTS.md invariant 2:
/// protos and generated types stay out of the data plane). Instead each
/// accept loop keeps its own `ListenerTls`, built once at bind time and
/// rebuilt lazily whenever it notices the snapshot version changed.
struct ListenerTls {
    chain_factories: Vec<Option<Arc<DownstreamTlsFactory>>>,
    default_factory: Option<Arc<DownstreamTlsFactory>>,
}

impl ListenerTls {
    /// An "everything resets" placeholder used when a runtime rebuild fails:
    /// every chain that needs TLS gets `None` (see the `(true, None)` arm in
    /// `spawn_accept_loop`), so connections matching a TLS chain are reset
    /// rather than silently served in the clear.
    fn empty_for(listener: &ListenerConfig) -> Self {
        Self {
            chain_factories: vec![None; listener.filter_chains.len()],
            default_factory: None,
        }
    }
}

/// Handshake deadline applied when a chain leaves
/// `transport_socket_connect_timeout` unset. Envoy applies none; this proxy
/// holds a connection admission slot for the whole handshake, so an unbounded
/// one lets stalled clients exhaust `max_downstream_connections`
/// (`internal-docs/envoy-divergences.md`).
const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The handshake deadline for `chain`: its configured value, the default when
/// unset, and `None` (no deadline) for an explicit `0s`.
fn tls_handshake_deadline(chain: &proxy_config::ir::FilterChainSpec) -> Option<Duration> {
    match chain.transport_socket_connect_timeout {
        None => Some(DEFAULT_TLS_HANDSHAKE_TIMEOUT),
        Some(d) if d.is_zero() => None,
        Some(d) => Some(d),
    }
}

/// An explicit `0s` removes the handshake bound, so a stalled client holds an
/// admission slot indefinitely. The owner chose availability; say so loudly
/// (AGENTS.md "Fail-open controls"). Called once per chain per TLS build.
fn warn_if_handshake_unbounded(chain: &proxy_config::ir::FilterChainSpec, context: &str) {
    if chain.transport_socket.is_some() && tls_handshake_deadline(chain).is_none() {
        tracing::warn!(
            "{context}: transport_socket_connect_timeout is 0s, so the TLS handshake is unbounded \
             and a stalled client holds a connection slot until it disconnects"
        );
    }
}

/// Build the compiled TLS factories for every `filter_chains[i]` (and the
/// `default_filter_chain`) of `listener` whose `transport_socket` is
/// configured. `None` transport_socket -> `None` slot (plaintext); a build
/// error names the listener + chain in its `TlsBuildError::context` and
/// propagates, letting the caller decide fatal-vs-log-and-skip.
///
/// Any chain whose `transport_socket` names SDS secrets
/// (`certificate_sds_names` non-empty -- `DownstreamTlsFactory::build` builds
/// it with an empty cert set in that case, deliberately, since the cert
/// hasn't arrived yet) is registered with `secret_registry` so a later --
/// or, per the registry's own doc, already-delivered -- secret reaches this
/// factory. A registration failure (a cached secret this factory's crypto
/// provider can't load) is a `TlsBuildError`, same as a build failure, since
/// it means this chain still can't actually serve TLS.
fn build_listener_tls(
    listener: &ListenerConfig,
    secret_registry: &Arc<SdsSecretRegistry>,
) -> Result<ListenerTls, TlsBuildError> {
    let mut chain_factories = Vec::with_capacity(listener.filter_chains.len());
    for (i, chain) in listener.filter_chains.iter().enumerate() {
        let factory = match &chain.transport_socket {
            Some(spec) => {
                let context = format!("listener '{}' filter_chains[{i}]", listener.name);
                warn_if_handshake_unbounded(chain, &context);
                let factory = Arc::new(DownstreamTlsFactory::build(spec, &context)?);
                if !spec.certificate_sds_names.is_empty() {
                    secret_registry.register(&spec.certificate_sds_names, &factory, &context)?;
                }
                if let Some(name) = &spec.validation_sds_name {
                    secret_registry.register_validation_context(name, &factory, &context)?;
                }
                Some(factory)
            }
            None => None,
        };
        chain_factories.push(factory);
    }
    let default_factory = match listener
        .default_filter_chain
        .as_ref()
        .and_then(|c| c.transport_socket.as_ref())
    {
        Some(spec) => {
            let context = format!("listener '{}' default_filter_chain", listener.name);
            if let Some(chain) = &listener.default_filter_chain {
                warn_if_handshake_unbounded(chain, &context);
            }
            let factory = Arc::new(DownstreamTlsFactory::build(spec, &context)?);
            if !spec.certificate_sds_names.is_empty() {
                secret_registry.register(&spec.certificate_sds_names, &factory, &context)?;
            }
            if let Some(name) = &spec.validation_sds_name {
                secret_registry.register_validation_context(name, &factory, &context)?;
            }
            Some(factory)
        }
        None => None,
    };
    Ok(ListenerTls {
        chain_factories,
        default_factory,
    })
}

/// A listener's HTTP filter chain (`http_filters`) failed to build for one
/// HCM terminal filter -- a `type_url` with no registered
/// [`proxy_http::filter::HttpFilterFactory`], or a filter's `typed_config`
/// failing that factory's own validation. Same fatal-at-[`initial_bind`] /
/// logged-and-skip-at-reconcile treatment as [`TlsBuildError`] (see
/// [`InitialBindError`]'s doc comment): this is a startup error, never a
/// silent skip of a configured filter (AGENTS.md invariant 1).
#[derive(Debug, thiserror::Error)]
#[error("{context}: {reason}")]
pub struct HttpFilterChainBuildError {
    context: String,
    reason: String,
}

/// Compiled HTTP filter-chain handlers for one listener's filter chains
/// aligned by index with
/// `ListenerConfig.filter_chains`, plus the `default_filter_chain` -- the HCM
/// counterpart to [`ListenerTls`], built and rebuilt on the same cadence
/// (bind time, then whenever the accept loop notices the snapshot version
/// changed). `None` in a slot means that chain's terminal filter isn't an
/// HTTP connection manager at all (e.g. a plain `tcp_proxy`) -- or, only
/// after a failed *runtime* rebuild, that its handler couldn't be rebuilt.
struct ListenerHcm {
    chain_handlers: Vec<Option<Rc<dyn StreamHandler>>>,
    default_handler: Option<Rc<dyn StreamHandler>>,
}

/// Shared runtime dependencies for every HCM filter-chain in one listener.
/// Keeping this bundle explicit prevents new instrumentation from quietly
/// growing `build_hcm_handler`'s positional interface again.
struct HcmRuntime<'a> {
    snapshot_version: SnapshotVersion,
    routes: &'a HashMap<String, Arc<proxy_config::ir::RouteTable>>,
    cluster_manager: &'a Arc<ClusterManager>,
    router_stats: &'a Arc<RouterStats>,
    token_stats: &'a Arc<GenAiTokenStats>,
    latency_stats: &'a Arc<GenAiLatencyStats>,
    tracing_handles: Option<&'a TracingHandles>,
    metadata: Option<&'a Arc<dyn proxy_observability::records::RequestRecordSink>>,
    factory_state: &'a Arc<SharedFactoryState>,
}

impl ListenerHcm {
    /// Same "everything resets" placeholder as [`ListenerTls::empty_for`],
    /// used when a runtime rebuild fails.
    fn empty_for(listener: &ListenerConfig) -> Self {
        Self {
            chain_handlers: vec![None; listener.filter_chains.len()],
            default_handler: None,
        }
    }
}

/// Build the compiled HTTP filter-chain handler for every `filter_chains[i]`
/// (and the `default_filter_chain`) of `listener` whose terminal network
/// filter is an HTTP connection manager. A chain whose terminal filter isn't
/// an HCM (or has no filters at all) gets a `None` slot -- mirrors
/// `build_listener_tls`'s shape exactly.
fn build_listener_hcm(
    listener: &ListenerConfig,
    runtime: &HcmRuntime<'_>,
) -> Result<ListenerHcm, HttpFilterChainBuildError> {
    let mut chain_handlers = Vec::with_capacity(listener.filter_chains.len());
    for (i, chain) in listener.filter_chains.iter().enumerate() {
        let handler = match chain.filters.last() {
            Some(NetworkFilterSpec::HttpConnectionManager(hcm)) => {
                let context = format!("listener '{}' filter_chains[{i}]", listener.name);
                Some(build_hcm_handler(
                    hcm,
                    runtime.routes,
                    &context,
                    listener.per_connection_buffer_limit_bytes,
                    runtime,
                )?)
            }
            _ => None,
        };
        chain_handlers.push(handler);
    }
    let default_handler = match listener
        .default_filter_chain
        .as_ref()
        .and_then(|c| c.filters.last())
    {
        Some(NetworkFilterSpec::HttpConnectionManager(hcm)) => {
            let context = format!("listener '{}' default_filter_chain", listener.name);
            Some(build_hcm_handler(
                hcm,
                runtime.routes,
                &context,
                listener.per_connection_buffer_limit_bytes,
                runtime,
            )?)
        }
        _ => None,
    };
    Ok(ListenerHcm {
        chain_handlers,
        default_handler,
    })
}

/// One listener this worker currently has bound: its address (so we can tell
/// "address changed" from "just a chain update" on the next config ping) and
/// the accept-loop task driving it.
///
/// Rust note: `pub` (it's the value type of the map `initial_bind` hands to
/// `run_listener_manager`, both public API) but its fields stay private --
/// callers outside this module only ever pass the whole map through, never
/// inspect one listener's bookkeeping directly.
pub struct BoundListener {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

/// A listener failed to bind (or have its TLS termination configured)
/// during [`initial_bind`] -- fatal, unlike reconcile-time failures (see
/// `reconcile`'s doc comment). Two causes, same fatal treatment: a socket
/// that won't bind, or a filter chain's `transport_socket` whose certs won't
/// load (Envoy parity: both fail a static listener's warm-up).
///
/// Rust note: `#[error(transparent)]` on `Tls` forwards straight to
/// `TlsBuildError`'s own `Display` (which already names the listener +
/// chain via its `context` field), so there's no need to duplicate that
/// context here.
#[derive(Debug, thiserror::Error)]
pub enum InitialBindError {
    #[error("listener '{name}' failed to bind {addr}: {source}")]
    Bind {
        name: ListenerName,
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error(transparent)]
    Tls(#[from] TlsBuildError),
    #[error(transparent)]
    Http(#[from] HttpFilterChainBuildError),
}

/// Bind a `socket2` socket for `listener` and hand it to tokio.
///
/// Rust note: `socket2` gives us access to `SO_REUSEADDR`/`SO_REUSEPORT`,
/// which `std`/`tokio` don't expose directly. Converting it into a
/// `tokio::net::TcpListener` goes through `std::net::TcpListener` as an
/// intermediate step -- `Socket: Into<std::net::TcpListener>` on unix, and
/// `TcpListener::from_std` just registers an already-bind/listen()'d,
/// already-nonblocking std socket with tokio's reactor. No `unsafe` needed;
/// the raw-fd handoff is entirely inside these safe abstractions.
fn bind_listener(listener: &ListenerConfig) -> io::Result<TcpListener> {
    let addr = listener.address;
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    // Rust note: `SO_REUSEPORT` is a unix-only socket option; `socket2` only
    // exposes `set_reuse_port` when compiled for unix targets, so this crate
    // (like the rest of llm-proxy) is unix-only for now.
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    let backlog = listener.tcp_backlog_size.unwrap_or(128) as i32;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// The three worker-scoped stats recorders [`initial_bind`]/[`reconcile`]/
/// [`run_listener_manager`] all need -- bundled into one struct purely to
/// keep THOSE functions' own argument counts under clippy's
/// `too_many_arguments` threshold, same motivation [`WorkerShared`]/
/// [`ListenerCaches`] document for their own bundling one layer down.
/// Unpacked back into [`WorkerShared`]'s three separate fields wherever one
/// is built -- `WorkerShared` keeps them separate because it predates this
/// bundle and its own field count was never close to
/// the threshold.
///
/// `tracing` rides along in this same bundle rather than
/// as a fifth threaded parameter, for the identical reason the other three
/// are bundled here -- it reaches [`build_hcm_handler`] on the exact same
/// path (`initial_bind`/`reconcile` -> [`WorkerShared`] -> `spawn_bound` ->
/// [`build_listener_hcm`]) that `token` already does.
pub struct StatsRecorders {
    pub router: Arc<RouterStats>,
    pub downstream: Arc<DownstreamStats>,
    pub token: Arc<GenAiTokenStats>,
    pub latency: Arc<GenAiLatencyStats>,
    /// This worker's span sink + head-sampling ratio, if
    /// `ConfigSnapshot::tracing` is `Some` -- `None` (tracing off) means
    /// [`build_hcm_handler`] never calls `FilterChainHandler::with_tracing`/
    /// `RouterFilterFactory::with_tracing` at all, so every handler it
    /// builds costs nothing extra per request (see those methods' own docs).
    pub tracing: Option<TracingHandles>,
    pub metadata: Option<Arc<dyn proxy_observability::records::RequestRecordSink>>,
    /// The process-wide downstream connection counter shared by every
    /// worker's accept loops. Not a stats recorder, but it rides in this
    /// bundle for the same argument-count reason the recorders do.
    pub connection_limiter: crate::admission::ConnectionLimiter,
}

/// [`StatsRecorders::tracing`]'s payload: a span sink plus the head-sampling
/// ratio a newly minted root span must apply (`TracingConfig::sample_ratio`,
/// `proxy-config`) -- always set (or unset) together, so this is one
/// `Option<TracingHandles>` rather than two independently-`Option` fields.
///
/// Rust note: `#[derive(Clone)]`, not `Copy` -- `SpanSink` wraps a
/// `tokio::sync::mpsc::Sender` (not `Copy`), so neither can this. Cloning is
/// cheap either way (a channel handle + an `Arc<AtomicU64>`, same as cloning
/// the `SpanSink` alone).
#[derive(Clone)]
pub struct TracingHandles {
    pub sink: SpanSink,
    pub sample_ratio: f64,
}

/// Bind `listener_ir` and spawn its accept loop, returning the [`BoundListener`]
/// on success. The one place that actually calls `bind_listener` +
/// `spawn_accept_loop` together; [`initial_bind`] and reconcile-time binding
/// (`bind_and_spawn`) each decide what to do with the `Err` case differently.
/// Bundles the per-worker state every bind/accept function below needs
/// (config handle, connection registry, drain signal, cluster manager,
/// the stats recorder) -- purely to keep
/// `spawn_bound`/`bind_and_spawn`'s argument count under clippy's
/// `too_many_arguments` threshold, the same motivation [`ListenerCaches`]
/// documents for the per-listener build outputs. [`initial_bind`]/[`reconcile`]
/// (the public-ish entry points) keep their separate parameters -- this
/// bundle is purely an internal plumbing convenience built once at their top
/// and threaded down by reference.
struct WorkerShared<'a> {
    config: &'a Arc<WorkerConfigHandle>,
    registry: &'a ConnectionRegistry,
    shutdown: &'a watch::Receiver<bool>,
    /// Handed to every connection so its HTTP codec can start a graceful
    /// shutdown at drain start instead of waiting for `shutdown`.
    drain: &'a watch::Receiver<DrainState>,
    cluster_manager: &'a Arc<ClusterManager>,
    /// This worker's `upstream_rq`/`upstream_rq_time` recorder -- built once
    /// per worker (it carries that worker's own `WorkerId`) in
    /// `crates/proxy/src/main.rs`'s `worker_main`, threaded down to
    /// [`RouterFilterFactory`] exactly like `cluster_manager` is.
    router_stats: &'a Arc<RouterStats>,
    /// This worker's `downstream_cx_total` recorder --
    /// same per-worker cadence and construction site as `router_stats`
    /// above, threaded down to [`spawn_accept_loop`] instead of a filter
    /// factory since the instrument it records is about the accept loop
    /// itself, not routing.
    downstream_stats: &'a Arc<DownstreamStats>,
    /// The process-wide downstream connection counter; see
    /// [`StatsRecorders::connection_limiter`].
    connection_limiter: &'a crate::admission::ConnectionLimiter,
    /// This worker's `llm.client.token.usage` recorder -- same per-worker
    /// cadence and construction site as `router_stats`, threaded down to
    /// [`build_hcm_handler`], which wires it into the built
    /// `FilterChainHandler` via
    /// [`proxy_http::filter_manager::FilterChainHandler::with_token_stats`].
    token_stats: &'a Arc<GenAiTokenStats>,
    latency_stats: &'a Arc<GenAiLatencyStats>,
    /// This worker's span sink + head-sampling ratio, if
    /// `ConfigSnapshot::tracing` is `Some` -- same per-worker cadence as
    /// `token_stats` above, threaded down to [`build_hcm_handler`], which
    /// wires it into both the `FilterChainHandler` (SERVER span) and the
    /// `RouterFilterFactory` (CLIENT spans) it builds.
    tracing: &'a Option<TracingHandles>,
    metadata: &'a Option<Arc<dyn proxy_observability::records::RequestRecordSink>>,
    /// The ONE per-serve [`SharedFactoryState`] slot,
    /// shared across every worker's filter-factory build -- same cadence and
    /// construction site (`crates/proxy/src/main.rs`'s `run_serve`) as
    /// `cluster_manager` above. Threaded down to [`build_hcm_handler`], which
    /// hands it to every `HttpFilterFactory::create` via `FactoryContext`.
    factory_state: &'a Arc<SharedFactoryState>,
    /// The one per-serve [`SdsSecretRegistry`] slot --
    /// same cadence and construction site as `factory_state` above
    /// (`crates/proxy/src/main.rs`'s `run_serve`). Threaded down to
    /// [`build_listener_tls`], which registers every SDS-named chain it
    /// builds against it.
    secret_registry: &'a Arc<SdsSecretRegistry>,
}

fn spawn_bound(
    name: &ListenerName,
    listener_ir: &Arc<ListenerConfig>,
    routes: &HashMap<String, Arc<proxy_config::ir::RouteTable>>,
    version: SnapshotVersion,
    shared: &WorkerShared<'_>,
) -> Result<BoundListener, InitialBindError> {
    // Built before the socket bind: no point opening a listening socket for a
    // filter chain whose certs won't load, or whose HTTP filter chain
    // references an unregistered filter.
    let tls = build_listener_tls(listener_ir, shared.secret_registry)?;
    let hcm_runtime = HcmRuntime {
        snapshot_version: version,
        routes,
        cluster_manager: shared.cluster_manager,
        router_stats: shared.router_stats,
        token_stats: shared.token_stats,
        latency_stats: shared.latency_stats,
        tracing_handles: shared.tracing.as_ref(),
        metadata: shared.metadata.as_ref(),
        factory_state: shared.factory_state,
    };
    let hcm = build_listener_hcm(listener_ir, &hcm_runtime)?;
    let tcp_listener = bind_listener(listener_ir).map_err(|source| InitialBindError::Bind {
        name: name.clone(),
        addr: listener_ir.address,
        source,
    })?;
    let addr = listener_ir.address;
    tracing::info!(listener = %name, %addr, "listener bound");
    let task = spawn_accept_loop(
        name.clone(),
        tcp_listener,
        addr,
        version,
        ListenerCaches { tls, hcm },
        AcceptLoopShared {
            config: shared.config.clone(),
            registry: shared.registry.clone(),
            shutdown: shared.shutdown.clone(),
            drain: shared.drain.clone(),
            cluster_manager: shared.cluster_manager.clone(),
            router_stats: shared.router_stats.clone(),
            downstream_stats: shared.downstream_stats.clone(),
            connection_limiter: shared.connection_limiter.clone(),
            token_stats: shared.token_stats.clone(),
            latency_stats: shared.latency_stats.clone(),
            tracing_handles: shared.tracing.clone(),
            metadata: shared.metadata.clone(),
            factory_state: shared.factory_state.clone(),
            secret_registry: shared.secret_registry.clone(),
        },
    );
    Ok(BoundListener { addr, task })
}

/// Bind `listener_ir` and spawn its accept loop, inserting the result into
/// `bound`. Reconcile-time only: bind failures here are logged and the
/// listener is skipped (rather than panicking the worker) -- a later config
/// push or manual intervention is the recovery path, matching how Envoy
/// itself degrades a single bad listener update. Contrast [`initial_bind`],
/// where a bind failure is fatal.
fn bind_and_spawn(
    name: ListenerName,
    listener_ir: &Arc<ListenerConfig>,
    routes: &HashMap<String, Arc<proxy_config::ir::RouteTable>>,
    version: SnapshotVersion,
    bound: &mut HashMap<ListenerName, BoundListener>,
    shared: &WorkerShared<'_>,
) {
    match spawn_bound(&name, listener_ir, routes, version, shared) {
        Ok(b) => {
            bound.insert(name, b);
        }
        Err(err) => {
            tracing::error!(listener = %name, address = %listener_ir.address, error = %err, "failed to bind listener; skipping");
        }
    }
}

/// Bind every `bind_to_port` listener in `snapshot` for the very first time.
///
/// Unlike reconcile-time binds, a failure here is fatal (returns `Err`
/// instead of logging and skipping): Envoy itself fails startup when a
/// static bootstrap listener can't bind, and starting the worker with fewer
/// listeners than configured -- silently serving a subset -- is exactly the
/// silent degradation AGENTS.md invariant 1 forbids. On error, any listeners this
/// call already bound are unwound (their accept-loop tasks aborted) before
/// returning, so a failed `initial_bind` leaves nothing running.
///
/// On success, hand the returned map to [`run_listener_manager`], which picks
/// up reconciliation against subsequent config pushes from there.
// `secret_registry` tips this over clippy's 7-arg
// ceiling, same reasoning as `reconcile`'s own `#[allow]` (it is a distinct
// per-serve shared handle, not a stats recorder, so it doesn't fold into
// `stats`).
#[allow(clippy::too_many_arguments)]
pub fn initial_bind(
    snapshot: &Arc<ConfigSnapshot>,
    config: &Arc<WorkerConfigHandle>,
    registry: &ConnectionRegistry,
    shutdown: &watch::Receiver<bool>,
    drain: &watch::Receiver<DrainState>,
    cluster_manager: &Arc<ClusterManager>,
    stats: &StatsRecorders,
    factory_state: &Arc<SharedFactoryState>,
    secret_registry: &Arc<SdsSecretRegistry>,
) -> Result<HashMap<ListenerName, BoundListener>, InitialBindError> {
    let shared = WorkerShared {
        config,
        registry,
        shutdown,
        drain,
        cluster_manager,
        router_stats: &stats.router,
        downstream_stats: &stats.downstream,
        connection_limiter: &stats.connection_limiter,
        token_stats: &stats.token,
        latency_stats: &stats.latency,
        tracing: &stats.tracing,
        metadata: &stats.metadata,
        factory_state,
        secret_registry,
    };
    let mut bound: HashMap<ListenerName, BoundListener> = HashMap::new();
    for (name, listener_ir) in snapshot.listeners.iter() {
        if !listener_ir.bind_to_port {
            tracing::debug!(listener = %name, "bind_to_port=false; not binding");
            continue;
        }
        if !listener_ir.routes_are_warmed(&snapshot.routes) {
            tracing::info!(listener = %name, "listener waits for RDS route configuration before binding");
            continue;
        }
        match spawn_bound(
            name,
            listener_ir,
            &snapshot.routes,
            snapshot.version,
            &shared,
        ) {
            Ok(b) => {
                bound.insert(name.clone(), b);
            }
            Err(err) => {
                for (_, b) in bound.drain() {
                    b.task.abort();
                }
                return Err(err);
            }
        }
    }
    Ok(bound)
}

/// The two per-listener caches [`spawn_accept_loop`] seeds its accept loop
/// with and keeps refreshed on every snapshot version change -- bundled into
/// one type purely to keep `spawn_accept_loop`'s argument count down
/// (clippy's `too_many_arguments`); see [`build_listener_tls`] and
/// [`build_listener_hcm`] for how each half is built.
struct ListenerCaches {
    tls: ListenerTls,
    hcm: ListenerHcm,
}

/// The owned counterpart to [`WorkerShared`] -- `spawn_accept_loop`'s task is
/// `'static`, so it needs owned clones (cheap: `Arc`/`ConnectionRegistry`/
/// `watch::Receiver` are all handle types) rather than borrows.
struct AcceptLoopShared {
    config: Arc<WorkerConfigHandle>,
    registry: ConnectionRegistry,
    shutdown: watch::Receiver<bool>,
    drain: watch::Receiver<DrainState>,
    cluster_manager: Arc<ClusterManager>,
    router_stats: Arc<RouterStats>,
    /// This worker's `downstream_cx_total` recorder --
    /// see [`WorkerShared::downstream_stats`].
    downstream_stats: Arc<DownstreamStats>,
    /// See [`WorkerShared::connection_limiter`].
    connection_limiter: crate::admission::ConnectionLimiter,
    /// This worker's `llm.client.token.usage` recorder -- see
    /// [`WorkerShared::token_stats`]; needed here (not just at
    /// [`spawn_bound`] time) because the accept loop's own runtime HCM
    /// rebuild (on a snapshot version change) calls [`build_listener_hcm`]
    /// again directly.
    token_stats: Arc<GenAiTokenStats>,
    latency_stats: Arc<GenAiLatencyStats>,
    /// This worker's span sink + head-sampling ratio -- see
    /// [`WorkerShared::tracing`]; needed here for the identical reason
    /// `token_stats` is (the runtime HCM rebuild below). Named
    /// `tracing_handles`, not `tracing`, so destructuring this struct below
    /// doesn't shadow the `tracing` crate this whole module logs through
    /// (`tracing::warn!` a few lines below the destructure).
    tracing_handles: Option<TracingHandles>,
    metadata: Option<Arc<dyn proxy_observability::records::RequestRecordSink>>,
    /// This worker's [`SharedFactoryState`] handle -- see
    /// [`WorkerShared::factory_state`]; needed here (not just at
    /// [`spawn_bound`] time) for the identical reason `token_stats` is (the
    /// runtime HCM rebuild below).
    factory_state: Arc<SharedFactoryState>,
    /// This worker's [`SdsSecretRegistry`] handle -- see
    /// [`WorkerShared::secret_registry`]; needed here (not just at
    /// [`spawn_bound`] time) because the accept loop's own runtime TLS
    /// rebuild below calls [`build_listener_tls`] again directly.
    secret_registry: Arc<SdsSecretRegistry>,
}

/// One accept loop per bound listener, spawned with `spawn_local` (this
/// module is worker-local / `!Send` per ADR-0003, same as the rest of
/// `proxy-core`).
fn spawn_accept_loop(
    name: ListenerName,
    tcp_listener: TcpListener,
    addr: SocketAddr,
    initial_version: SnapshotVersion,
    initial: ListenerCaches,
    shared: AcceptLoopShared,
) -> JoinHandle<()> {
    let ListenerCaches {
        tls: initial_tls,
        hcm: initial_hcm,
    } = initial;
    let AcceptLoopShared {
        config,
        registry,
        mut shutdown,
        drain,
        cluster_manager,
        router_stats,
        downstream_stats,
        connection_limiter,
        token_stats,
        latency_stats,
        tracing_handles,
        metadata,
        factory_state,
        secret_registry,
    } = shared;
    tokio::task::spawn_local(async move {
        // Rust note: `mut` locals, not behind a lock -- this whole task is
        // single-threaded (`spawn_local` on a `!Send` `LocalSet`, ADR-0003),
        // so nothing else can observe or race these between `.await` points.
        // `tls_cache`/`hcm_cache` are `Rc`s so each accepted connection's task
        // gets a cheap clone of the same compiled factories/handlers (pointer
        // bump, no rebuild).
        let mut name = name;
        let mut tls_version = initial_version;
        let mut tls_cache = Rc::new(initial_tls);
        let mut hcm_cache = Rc::new(initial_hcm);
        loop {
            let (stream, peer) = tokio::select! {
                accepted = tcp_listener.accept() => match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(listener = %name, error = %err, "accept() failed");
                        // Back off before retrying: when accept() fails
                        // persistently (EMFILE/ENFILE at fd exhaustion) the
                        // listener stays readable, so an immediate retry
                        // would spin this worker at 100% CPU. Shutdown still
                        // interrupts the pause.
                        tokio::select! {
                            _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                            _ = shutdown.changed() => return,
                        }
                        continue;
                    }
                },
                _ = shutdown.changed() => {
                    return;
                }
            };

            // Rust note: the snapshot is reloaded here, once per *accepted
            // connection*, not once for the whole lifetime of this accept
            // loop. That is deliberate: it's what lets `run_listener_manager`
            // leave an accept loop running untouched when a listener's
            // filter chains change but its address doesn't (see its doc
            // comment) -- the next connection simply sees the new snapshot.
            let snapshot = config.load();

            // Global downstream connection limit, taken before any other
            // per-connection work so an over-limit connection costs one
            // accept and one close. Envoy accepts and then closes too, and
            // does not count the rejected socket in `downstream_cx_total`.
            // The limit and the listener's `ignore_global_conn_limit` come
            // from the snapshot loaded just above, so a reload applies to the
            // next accept.
            let current = current_listener(&snapshot, &name, addr);
            let exempt = current.is_some_and(|(_, l)| l.ignore_global_conn_limit);
            let Some(connection_slot) =
                connection_limiter.try_acquire(snapshot.max_downstream_connections, exempt)
            else {
                let stat_name = current.map_or(name.as_str(), |(n, _)| n.as_str());
                downstream_stats.record_global_cx_overflow(stat_name);
                tracing::debug!(listener = %stat_name, peer = %peer, "global downstream connection limit reached; closing connection");
                drop(stream);
                continue;
            };

            // Counted once per successfully accepted and admitted
            // connection, and only here -- the `Err(err)` arm above already
            // `continue`d before reaching this line, so a failed `accept()`
            // never contributes to `downstream_cx_total`.
            downstream_stats.record_connection_accepted(&name);

            // The accept loop's own TLS factory cache goes stale exactly when
            // the snapshot version does: a chain-only config
            // change takes effect for new connections without a rebind (see
            // the "Rust note" above `spawn_accept_loop`'s doc), so a new
            // `transport_socket` or rotated cert on an existing chain needs a
            // rebuild here, not a new bind. A rebuild failure is logged and
            // treated as "no TLS factories for this listener" rather than
            // fatal -- reconcile-time failures already degrade this way, and
            // a runtime cert typo shouldn't take an established listener
            // down. Rust note: this is a *whole-listener* fallback (every
            // chain's factory reset to `None`) rather than a per-chain retry
            // of just the changed chain -- simpler, at the cost of briefly
            // resetting TLS connections on chains that didn't actually
            // change alongside the one that broke. This rebuild is the only
            // per-connection work done *inline* in the accept loop; it's
            // synchronous (no `.await`), so it can't stall new accepts.
            if snapshot.version != tls_version {
                if let Some((current_name, l)) = current {
                    let current_name = current_name.clone();
                    if name != current_name {
                        tracing::info!(old_listener = %name, new_listener = %current_name, %addr, "accept loop adopted renamed listener");
                        name = current_name;
                    }
                    match build_listener_tls(l, &secret_registry) {
                        Ok(rebuilt) => tls_cache = Rc::new(rebuilt),
                        Err(err) => {
                            tracing::warn!(listener = %name, error = %err, "failed to rebuild TLS factories after config change; TLS-requiring chains on this listener will reset connections until fixed");
                            tls_cache = Rc::new(ListenerTls::empty_for(l));
                        }
                    }
                    // Same rebuild cadence and same "whole-listener fallback"
                    // tradeoff as the TLS cache just above, for the HTTP
                    // filter-chain handlers.
                    let hcm_runtime = HcmRuntime {
                        snapshot_version: snapshot.version,
                        routes: &snapshot.routes,
                        cluster_manager: &cluster_manager,
                        router_stats: &router_stats,
                        token_stats: &token_stats,
                        latency_stats: &latency_stats,
                        tracing_handles: tracing_handles.as_ref(),
                        metadata: metadata.as_ref(),
                        factory_state: &factory_state,
                    };
                    match build_listener_hcm(l, &hcm_runtime) {
                        Ok(rebuilt) => hcm_cache = Rc::new(rebuilt),
                        Err(err) => {
                            tracing::warn!(listener = %name, error = %err, "failed to rebuild HTTP filter chain after config change; HCM chains on this listener will reset connections until fixed");
                            hcm_cache = Rc::new(ListenerHcm::empty_for(l));
                        }
                    }
                }
                tls_version = snapshot.version;
            }

            // Everything after the accept -- the ClientHello peek, filter-chain
            // matching, the TLS handshake, and the connection handler -- runs
            // in its own task, NOT inline in the accept loop. Rust note: this
            // is load-bearing. The `tls_inspector` peek and `factory.wrap`
            // handshake both `.await` on the client (they wait for its bytes);
            // doing them inline would let one slow or stalled client block
            // every other new connection on this worker's listener (a trivial
            // per-worker denial of service, bounded only by the inspector
            // timeout). Spawning per connection keeps the accept loop doing
            // nothing but `accept()` + the synchronous cache refresh above.
            tokio::task::spawn_local(serve_connection(ServeConnection {
                stream,
                peer,
                listener_name: name.clone(),
                snapshot,
                tls: tls_cache.clone(),
                hcm: hcm_cache.clone(),
                registry: registry.clone(),
                shutdown: shutdown.clone(),
                drain: drain.clone(),
                downstream_stats: downstream_stats.clone(),
                _connection_slot: connection_slot,
            }));
        }
    })
}

/// `request_headers_timeout` is enforced for HTTP/1 only (hyper's h2 server
/// exposes no per-stream header progress). Say so once per process when an
/// HTTP/2 connection meets a listener that configured it, so the gap is
/// visible rather than silent (AGENTS.md invariant 1).
fn warn_h2_header_timeout_not_enforced_once(listener: &str) {
    // Rust note: `Once::call_once` runs its closure exactly once per process
    // across all threads, with no lock on the later fast path.
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(%listener, "request_headers_timeout is not enforced on HTTP/2 connections; it applies to HTTP/1 only (internal-docs/envoy-divergences.md)");
    });
}

/// How long an accept loop pauses after `accept()` fails, so a persistent
/// error such as fd exhaustion does not become a hot loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// The listener this accept loop currently serves, by name first, then by
/// bound address (a rename at an unchanged address keeps the same socket).
fn current_listener<'a>(
    snapshot: &'a ConfigSnapshot,
    name: &ListenerName,
    addr: SocketAddr,
) -> Option<(&'a ListenerName, &'a Arc<ListenerConfig>)> {
    snapshot.listeners.get_key_value(name).or_else(|| {
        snapshot
            .listeners
            .iter()
            .find(|(_, listener)| listener.bind_to_port && listener.address == addr)
    })
}

/// Everything one accepted connection needs to be served, moved into its own
/// task off the accept loop (see the "load-bearing" Rust note in
/// `spawn_accept_loop`). Grouped into a struct only to keep the argument list
/// readable -- Rust note: none of these are `Send` (`Rc<ListenerTls>`,
/// `Arc<ConfigSnapshot>` handlers), which is fine because the whole listener
/// manager runs on a single-threaded `LocalSet` per ADR-0003.
struct ServeConnection {
    stream: TcpStream,
    peer: SocketAddr,
    listener_name: ListenerName,
    /// The snapshot this connection matched under; held for the connection's
    /// whole lifetime, which is exactly the passive-drain seam (config the
    /// control runtime has since replaced stays alive as long as connections
    /// accepted under it).
    snapshot: Arc<ConfigSnapshot>,
    /// TLS factories compiled from `snapshot` -- built consistently with it in
    /// the accept loop before this task was spawned.
    tls: Rc<ListenerTls>,
    /// HTTP filter-chain handlers compiled from `snapshot`, same cadence as
    /// `tls` above.
    hcm: Rc<ListenerHcm>,
    registry: ConnectionRegistry,
    shutdown: watch::Receiver<bool>,
    drain: watch::Receiver<DrainState>,
    /// Counts a handshake that misses its deadline.
    downstream_stats: Arc<DownstreamStats>,
    /// Held for the connection task's whole life; dropping it (on any exit
    /// path) frees the global connection-limit slot.
    _connection_slot: crate::admission::ConnectionSlot,
}

/// Run `handshake` under `deadline`; a `None` deadline means unbounded.
/// Returns `None` when the deadline expired.
async fn handshake_with_deadline<F: std::future::Future>(
    deadline: Option<Duration>,
    handshake: F,
) -> Option<F::Output> {
    match deadline {
        Some(d) => tokio::time::timeout(d, handshake).await.ok(),
        None => Some(handshake.await),
    }
}

async fn serve_connection(conn: ServeConnection) {
    let ServeConnection {
        stream,
        peer,
        listener_name: name,
        snapshot,
        tls,
        hcm,
        registry,
        shutdown,
        drain,
        downstream_stats,
        _connection_slot,
    } = conn;

    let local_addr = stream.local_addr().unwrap_or(peer);
    let listener_ir = snapshot.listeners.get(&name);

    // If this listener has a `tls_inspector` listener filter, peek the
    // ClientHello (without consuming it) before filter-chain matching so
    // `server_names`/`application_protocols`/`transport_protocol` criteria can
    // key on it.
    //
    // Rust note: `ListenerFilterSpec` currently has only one variant, so
    // destructuring it directly in the closure param (instead of a `match`) is
    // an *irrefutable* pattern -- if a second variant is ever added, this line
    // stops compiling until it's handled here too, which is exactly
    // AGENTS.md invariant 1 (never silently drop a config field) enforced by the type
    // checker.
    let mut server_name = None;
    let mut transport_protocol = "raw_buffer".to_string();
    let mut application_protocols = vec![];
    let tls_inspector_cfg = listener_ir
        .and_then(|l| l.listener_filters.first())
        .map(|ListenerFilterSpec::TlsInspector(cfg)| *cfg);
    if let Some(cfg) = tls_inspector_cfg {
        match inspect_client_hello(&stream, cfg.max_client_hello_size).await {
            Ok(Some(tls)) => {
                transport_protocol = "tls".to_string();
                server_name = tls.server_name;
                application_protocols = tls.application_protocols;
            }
            Ok(None) => {
                // Not TLS, or the ClientHello couldn't be parsed within
                // limits: treat as plaintext, same as if tls_inspector weren't
                // configured at all.
            }
            Err(err) => {
                // A real socket error, not a parse failure -- log and fall
                // back to plaintext; the connection will most likely fail
                // shortly after anyway, but the inspector itself must not be
                // fatal.
                tracing::debug!(listener = %name, peer = %peer, error = %err, "tls_inspector: socket error while peeking ClientHello");
            }
        }
    }

    let props = ConnectionProperties {
        destination_addr: local_addr,
        source_addr: peer,
        direct_source_addr: peer,
        server_name,
        transport_protocol,
        application_protocols,
    };

    let Some(matched) = listener_ir.and_then(|l| select_filter_chain(&props, l)) else {
        tracing::debug!(listener = %name, peer = %peer, "no filter chain matched; resetting connection");
        // Rust note: `SO_LINGER(0)` makes the kernel send a TCP RST instead of
        // the usual FIN close handshake once the socket is dropped -- this is
        // what Envoy does on a `filter_chain_match` miss, rather than a clean
        // close.
        reset(&stream, &name);
        return;
    };

    let buffer_limit = listener_ir
        .map(|l| l.per_connection_buffer_limit_bytes)
        .unwrap_or(1024 * 1024);

    // Which cache slot corresponds to `matched`: its index in `filter_chains`,
    // or the `default_filter_chain` slot if it isn't found there (Rust note:
    // `ptr::eq` on references into the immutable, `Arc`'d snapshot is valid and
    // needs no `unsafe` -- see `filter_chain`'s own property test for the same
    // technique). Looked up once and reused for both the TLS factory and the
    // HCM handler caches below, which are aligned the same way.
    let chain_idx = listener_ir.and_then(|l| {
        l.filter_chains
            .iter()
            .position(|c| std::ptr::eq(c, matched))
    });

    // Extracted before the stream is moved into either branch below: the
    // matched chain's terminal (and, today, only) network filter, turned into
    // cheap owned params/handle. A chain with no filters can't happen
    // (lowering rejects empty `filters`), but `None` here is handled
    // defensively. The HCM handler itself was built once at bind time (see
    // `build_listener_hcm`), not per connection -- this just looks up the
    // slot `matched` corresponds to.
    let hcm_handler = match chain_idx {
        Some(idx) => hcm.chain_handlers.get(idx).cloned().flatten(),
        None => hcm.default_handler.clone(),
    };
    let filter = terminal_filter(matched, buffer_limit, hcm_handler);

    // The configured `codec_type` for `matched`'s terminal filter, if
    // it has one (a `tcp_proxy` chain has no HCM and so no codec to pick --
    // `Auto` there is inert, never read, since the `(false, _)` arm below
    // only consults it when `filter` is actually `TerminalFilter::Http`).
    let (codec_type, request_headers_timeout) = match matched.filters.last() {
        Some(NetworkFilterSpec::HttpConnectionManager(hcm)) => {
            (hcm.codec_type, hcm.request_headers_timeout)
        }
        Some(NetworkFilterSpec::TcpProxy(_)) | None => (CodecType::Auto, None),
    };

    let factory = matched
        .transport_socket
        .as_ref()
        .and_then(|_| match chain_idx {
            Some(idx) => tls.chain_factories.get(idx).cloned().flatten(),
            None => tls.default_factory.clone(),
        });

    match (matched.transport_socket.is_some(), factory) {
        (true, Some(factory)) => {
            match handshake_with_deadline(tls_handshake_deadline(matched), factory.wrap(stream))
                .await
            {
                // Rust note: the outer `Option` is "did the deadline expire"
                // (`None`); the inner `Result` is the handshake's own outcome.
                None => {
                    // Returning drops the stream and, with it, the admission slot.
                    downstream_stats.record_transport_socket_connect_timeout(&name);
                    tracing::debug!(listener = %name, peer = %peer, "TLS handshake timed out; closing connection");
                }
                Some(Ok(tls_stream)) => {
                    // An explicit `codec_type` (`Http1`/`Http2`) is
                    // unconditional -- the operator has said what the client
                    // speaks, so there's nothing to negotiate. Only `Auto` (the
                    // Envoy default) falls back to reading what ALPN actually
                    // negotiated -- see `downstream_codec_for_alpn`'s doc comment
                    // for why that has to happen *here* (post-handshake) rather
                    // than be assumed from config.
                    let codec = match codec_type {
                        CodecType::Http1 => DownstreamCodec::Http1,
                        CodecType::Http2 => DownstreamCodec::Http2,
                        CodecType::Auto => downstream_codec_for_alpn(&tls_stream),
                    };
                    // Can't `reset` (SO_LINGER) a `TlsStream` the way we can a
                    // bare `TcpStream` -- `run_terminal_filter` hands the stream
                    // back on the no-op paths so the *unimplemented*/no-filter
                    // cases just drop it and let the close be a clean FIN.
                    let downstream = DownstreamInfo {
                        remote: peer,
                        is_tls: true,
                    };
                    let _ = run_terminal_filter(
                        tls_stream,
                        filter,
                        snapshot,
                        RunTerminalFilterCtx {
                            registry: &registry,
                            shutdown,
                            drain,
                            name: &name,
                            downstream,
                            codec,
                            request_headers_timeout,
                        },
                    )
                    .await;
                }
                Some(Err(err)) => {
                    tracing::debug!(listener = %name, peer = %peer, error = %err, "TLS handshake failed; dropping connection");
                }
            }
        }
        (true, None) => {
            // The matched chain needs TLS termination but no factory is
            // available (a runtime rebuild failed -- see `spawn_accept_loop`);
            // can't serve this chain, so reset rather than silently run it in
            // the clear.
            tracing::warn!(listener = %name, peer = %peer, "matched chain requires TLS but no factory is available; resetting connection");
            reset(&stream, &name);
        }
        (false, _) => {
            // Plaintext (or TLS-passthrough, if `matched` was selected via SNI
            // but configures no `transport_socket`): dispatch straight to the
            // terminal L4 filter on `stream`. No ALPN exists over plaintext,
            // so `codec_type` (`Auto` unless the operator overrode it) is
            // resolved by peeking for the h2 client connection preface
            // instead -- see `resolve_plaintext_codec`. The h1 `Upgrade: h2c`
            // dance is still out of scope (see `downstream_codec_for_alpn`'s
            // doc comment); this only covers h2 prior-knowledge.
            let downstream = DownstreamInfo {
                remote: peer,
                is_tls: false,
            };
            // Only worth resolving when there's an HTTP codec to pick at all
            // -- a `tcp_proxy` (or no-filter) chain ignores `codec` entirely
            // (see `RunTerminalFilterCtx::codec`'s doc), so skip the peek and
            // its potential wait rather than delaying those connections for
            // no reason.
            let codec = match &filter {
                Some(TerminalFilter::Http(_)) => resolve_plaintext_codec(codec_type, &stream).await,
                _ => DownstreamCodec::Http1,
            };
            if let Some(stream) = run_terminal_filter(
                stream,
                filter,
                snapshot,
                RunTerminalFilterCtx {
                    registry: &registry,
                    shutdown,
                    drain,
                    name: &name,
                    downstream,
                    codec,
                    request_headers_timeout,
                },
            )
            .await
            {
                reset(&stream, &name);
            }
        }
    }
}

/// Which HTTP codec serves a **TLS** downstream connection: negotiated ALPN,
/// read post-handshake -- **this used to be a live bug**:
/// `server_config.alpn_protocols` (set from `spec.alpn_protocols` in
/// `crates/proxy-core/src/tls/mod.rs`) already let an operator configure
/// `alpn_protocols: ["h2"]` on a downstream listener, rustls would happily
/// negotiate `h2` with the client during `factory.wrap`, and this module then
/// unconditionally called `serve_http1` on the result -- a config field
/// accepted and then silently not honored (AGENTS.md invariant 1), and a protocol
/// violation from the client's point of view (it believes it's speaking h2
/// framing to us; we read h1 framing off the same bytes). This function is
/// the fix: read what rustls actually negotiated, post-handshake, rather than
/// assuming h1.
///
/// Only `h2` selects [`DownstreamCodec::Http2`]; anything else (`http/1.1`,
/// no ALPN negotiated at all, e.g. `alpn_protocols` left empty in config) is
/// h1. Only called for `codec_type: Auto` (the Envoy default) -- the call
/// site handles an explicit `Http1`/`Http2` itself, unconditionally, without
/// consulting ALPN at all. See [`resolve_plaintext_codec`] for the plaintext
/// side, where there's no ALPN to read and the `Auto` case peeks for the h2
/// client preface instead. The h1 `Upgrade: h2c` mechanism remains out of
/// scope either way (see `serve_http2`'s and `proxy_http::codec`'s module
/// doc).
fn downstream_codec_for_alpn<IO>(
    tls_stream: &tokio_rustls::server::TlsStream<IO>,
) -> DownstreamCodec {
    // Rust note: `get_ref()` on a `tokio_rustls::server::TlsStream` returns
    // `(&IO, &rustls::ServerConnection)` (via `Deref` to `CommonState`) --
    // the underlying I/O plus the live rustls session state, which is where
    // the post-handshake negotiated ALPN protocol lives (`alpn_protocol()`
    // returns `None` before the handshake completes or when neither side
    // negotiated one).
    match tls_stream.get_ref().1.alpn_protocol() {
        Some(b"h2") => DownstreamCodec::Http2,
        _ => DownstreamCodec::Http1,
    }
}

/// See [`downstream_codec_for_alpn`]. `Copy` so it threads through
/// `run_terminal_filter`'s already-long parameter list as cheaply as
/// `DownstreamInfo` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownstreamCodec {
    Http1,
    Http2,
}

/// The HTTP/2 client connection preface (RFC 9113 S3.4): the exact 24 bytes
/// a client speaking h2 "prior knowledge" (no ALPN, no `Upgrade` -- it just
/// starts sending h2 framing) sends before anything else. This is the only
/// signal available to tell such a client apart from an ordinary h1 request
/// on a **plaintext** connection, which has no ALPN to consult at all.
const H2_CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Wall-clock bound on [`resolve_plaintext_codec`]'s preface peek -- same
/// reasoning as `tls_inspector::INSPECT_TIMEOUT`: a client that sends fewer
/// than 24 bytes and then goes quiet must not hang this connection forever
/// waiting to see whether the rest of the preface ever arrives.
const H2_PREFACE_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Backoff applied when a peek returns exactly as many bytes as the previous
/// one and the preface is still incomplete -- see the Rust note in
/// `tls_inspector::peek_client_hello` for why this is necessary:
/// `TcpStream::peek` is level-triggered on "there is unread data", so
/// re-`.await`ing it with no new bytes on the wire can return instantly with
/// the same stale peek instead of waiting for more to arrive.
const H2_PREFACE_STALL_BACKOFF: Duration = Duration::from_millis(5);

/// Which codec serves a **plaintext** HTTP connection manager
/// connection, given its configured `codec_type`. `Http1`/`Http2` are
/// unconditional -- the operator has said what the client speaks. `Auto`
/// (the Envoy default) has no ALPN to consult over plaintext (unlike
/// [`downstream_codec_for_alpn`]'s TLS case), so it peeks -- without
/// consuming, same as `tls_inspector` -- for the [`H2_CLIENT_PREFACE`]: a
/// match means h2 prior-knowledge, anything else (including "never
/// resolved within the timeout") is treated as h1.
async fn resolve_plaintext_codec(codec_type: CodecType, stream: &TcpStream) -> DownstreamCodec {
    match codec_type {
        CodecType::Http1 => DownstreamCodec::Http1,
        CodecType::Http2 => DownstreamCodec::Http2,
        CodecType::Auto => {
            match tokio::time::timeout(H2_PREFACE_PEEK_TIMEOUT, peek_for_h2_preface(stream)).await {
                Ok(true) => DownstreamCodec::Http2,
                // `Ok(false)`: the peeked bytes definitely aren't the preface.
                // `Err(_elapsed)`: never resolved either way in time -- same
                // "collapse to the non-TLS/h1 default" fallback
                // `tls_inspector::inspect_client_hello` uses for its own
                // timeout, and for the same reason (a stalled *client* must
                // not become a stalled *codec choice*).
                Ok(false) | Err(_) => DownstreamCodec::Http1,
            }
        }
    }
}

/// The actual peek loop, run under [`resolve_plaintext_codec`]'s timeout.
/// Returns `true` only once all 24 preface bytes have arrived and match
/// exactly; returns `false` as soon as an arrived byte diverges from
/// [`H2_CLIENT_PREFACE`] -- an h1 request line and the h2 preface disagree
/// within the first couple of bytes in every real case (`GET`/`POST`/... vs
/// `PRI *`), so this discriminates promptly rather than always waiting for
/// the full 24 bytes.
async fn peek_for_h2_preface(stream: &TcpStream) -> bool {
    let mut buf = [0u8; H2_CLIENT_PREFACE.len()];
    // Tracks the byte count from the previous iteration, so a peek that
    // returns the exact same (incomplete) prefix as last time -- no new
    // bytes arrived -- can be told apart from real progress; see
    // `H2_PREFACE_STALL_BACKOFF`'s doc.
    let mut last_n: Option<usize> = None;
    loop {
        // Rust note: like `tls_inspector::peek_client_hello`, `TcpStream::
        // peek` reads from the front of the kernel receive buffer *without*
        // draining it -- every byte looked at here is still there for
        // `serve_http1`/`serve_http2` to read again once dispatch decides.
        let n = match stream.peek(&mut buf).await {
            Ok(n) => n,
            // A real socket error: let the chosen codec's own read surface
            // it rather than treating it as a signal about the preface.
            Err(_) => return false,
        };
        if n == 0 {
            return false; // peer closed before sending anything
        }
        if buf[..n] != H2_CLIENT_PREFACE[..n] {
            return false;
        }
        if n == H2_CLIENT_PREFACE.len() {
            return true;
        }
        if last_n == Some(n) {
            tokio::time::sleep(H2_PREFACE_STALL_BACKOFF).await;
        } else {
            last_n = Some(n);
        }
    }
}

/// The matched chain's terminal network filter, resolved into cheap owned
/// data ahead of the stream move (see the call site in `serve_connection`).
/// `filters.last()` and `.first()` are the same slot today -- lowering only
/// ever produces exactly one filter per chain -- but `.last()` is what
/// matches Envoy's "the terminal filter is the last one in the chain"
/// semantics for when a second, non-terminal L4 filter exists (see
/// `net_filter`'s module doc).
enum TerminalFilter {
    TcpProxy(TcpProxyParams),
    /// HTTP connection manager: the codec-facing `StreamHandler` -- built
    /// once at bind time (see `build_listener_hcm`/`build_hcm_handler`), not
    /// per connection; `terminal_filter` just clones the `Rc` handed to it.
    Http(Rc<dyn StreamHandler>),
}

/// `hcm_handler` is the (already-built) handler for the slot `matched`
/// occupies in this worker's `ListenerHcm` cache -- see the call site in
/// `serve_connection`, which looks it up the same way it looks up the TLS
/// factory. `None` there just means `matched`'s terminal filter isn't an HCM
/// (or, on a failed runtime rebuild, that it couldn't be rebuilt), same as a
/// missing TLS factory.
fn terminal_filter(
    matched: &proxy_config::ir::FilterChainSpec,
    buffer_limit: u32,
    hcm_handler: Option<Rc<dyn StreamHandler>>,
) -> Option<TerminalFilter> {
    match matched.filters.last()? {
        NetworkFilterSpec::TcpProxy(tp) => Some(TerminalFilter::TcpProxy(TcpProxyParams {
            cluster: tp.cluster.clone(),
            idle_timeout: tp.idle_timeout,
            max_connect_attempts: tp.max_connect_attempts,
            buffer_limit,
        })),
        NetworkFilterSpec::HttpConnectionManager(_) => hcm_handler.map(TerminalFilter::Http),
    }
}

/// Build the `StreamHandler` the downstream h1 codec (`proxy_http::codec`)
/// drives for one HTTP connection manager terminal filter: every non-router
/// `http_filters` entry becomes one `FilterInstanceFactory` (config order),
/// looked up in the shared [`filter_registry`] by `type_url`; a `type_url`
/// with no registered factory is a startup error (`context` names the
/// listener/chain), never a silent skip (AGENTS.md invariant 1). The router itself
/// (`envoy.filters.http.router`, `is_router: true`) is the terminal --
/// [`proxy_http::router::RouterHandler`] -- not one of these chain filters.
fn build_hcm_handler(
    hcm: &HttpConnectionManagerConfig,
    routes: &HashMap<String, Arc<proxy_config::ir::RouteTable>>,
    context: &str,
    buffer_limit_bytes: u32,
    runtime: &HcmRuntime<'_>,
) -> Result<Rc<dyn StreamHandler>, HttpFilterChainBuildError> {
    let registry = filter_registry();
    // `context` is this chain's identity (the same string this function's own
    // error messages use) -- it becomes `FactoryContext::scope`, so every
    // filter factory `create`d below shares one scope for this chain, and a
    // sibling chain built through a later call gets a different one. See
    // `SharedFactoryState`'s doc for why this must not collide across chains.
    let factory_ctx = FactoryContext {
        shared: runtime.factory_state.clone(),
        scope: context.to_string(),
        // The HCM's own operator-supplied `stat_prefix` (this
        // function already holds `hcm`) becomes the chain's external name --
        // see `FactoryContext`'s doc for why this is a second field, not a
        // rename of `scope`.
        stat_prefix: hcm.stat_prefix.clone(),
    };
    // Filters built from a `DynamicMessage` have no other way to reach the
    // stats registry, so seed it where `FactoryContext` consumers can find it.
    runtime
        .factory_state
        .get_or_try_init(
            "",
            "",
            proxy_filters::usage_filter::STATS_REGISTRY_KEY,
            || Ok(runtime.router_stats.registry() as Arc<dyn std::any::Any + Send + Sync>),
        )
        .map_err(|e| HttpFilterChainBuildError {
            context: context.to_string(),
            reason: format!("stats registry: {e}"),
        })?;
    let mut filters: Vec<ConfiguredHttpFilter> = Vec::with_capacity(hcm.http_filters.len());
    for f in &hcm.http_filters {
        if f.is_router {
            continue;
        }
        let factory = registry
            .get(&f.type_url)
            .ok_or_else(|| HttpFilterChainBuildError {
                context: context.to_string(),
                reason: format!(
                    "http filter '{}' (type_url `{}`) has no registered factory",
                    f.name, f.type_url
                ),
            })?;
        // Invariant enforced by `proxy-config`'s lowering: `config` is `None`
        // only for the router filter, which the `continue` above already
        // skipped -- every other entry carries a decoded `typed_config`.
        if let Some(config) = &f.ext_authz {
            let endpoint = config.endpoint.ok_or_else(|| HttpFilterChainBuildError {
                context: context.to_string(),
                reason: format!(
                    "{}.grpc_service: authorization endpoint was not validated",
                    config.field_path
                ),
            })?;
            let client = Arc::new(proxy_xds::authorization::GrpcAuthorizationClient::new(
                endpoint,
                config.timeout,
                config.connect_timeout,
            ));
            let scope = if config.stat_prefix.is_empty() {
                format!("{}.ext_authz", hcm.stat_prefix)
            } else {
                format!("{}.ext_authz.{}", hcm.stat_prefix, config.stat_prefix)
            };
            // Every worker and every config rebuild runs this function, so the
            // stats (and their warn-once fail-open flag) live in the process-wide
            // factory state, keyed by stat scope. A per-build instance would log
            // the bypass again per worker and per update (AGENTS.md "Fail-open
            // controls": suppress repeats). Chains that share a scope already
            // share its counters.
            let stats = runtime
                .factory_state
                .get_or_try_init(
                    &scope,
                    &scope,
                    proxy_config::authorization::TYPE_URL,
                    || {
                        Ok(Arc::new(proxy_filters::ext_authz::ExtAuthzStats::new(
                            runtime.router_stats.registry(),
                            &scope,
                        ))
                            as Arc<dyn std::any::Any + Send + Sync>)
                    },
                )
                .map_err(|e| HttpFilterChainBuildError {
                    context: context.to_string(),
                    reason: format!("http filter '{}': {e}", f.name),
                })?
                .downcast::<proxy_filters::ext_authz::ExtAuthzStats>()
                .expect("ext_authz stats singleton is always ExtAuthzStats");
            filters.push(ConfiguredHttpFilter {
                name: f.name.clone(),
                instance_factory: Arc::new(proxy_filters::ext_authz::ExtAuthzInstanceFactory {
                    config: config.clone(),
                    client,
                    stats,
                }),
                factory: factory.clone(),
            });
            continue;
        }
        let config = f
            .config
            .as_ref()
            .expect("lowering only leaves `config: None` on the router filter");
        let instance_factory =
            factory
                .create(config, &factory_ctx)
                .map_err(|e| HttpFilterChainBuildError {
                    context: context.to_string(),
                    reason: format!("http filter '{}': {e}", f.name),
                })?;
        filters.push(ConfiguredHttpFilter {
            name: f.name.clone(),
            instance_factory: Arc::from(instance_factory),
            // ADR-0004 step 4: kept alongside the instance
            // factory -- `FilterChainHandler::new_with_filters` needs the
            // registered `HttpFilterFactory` (not just the per-stream
            // instance factory) once, at construction, to resolve any
            // `typed_per_filter_config` entry naming this filter through
            // `HttpFilterFactory::parse_per_route`.
            factory: factory.clone(),
        });
    }

    // `.with_tracing` on the router factory whenever
    // tracing is on -- every attempt this HCM's router dispatches gets a
    // CLIENT span sink to emit through (see `RouterFilterFactory::with_tracing`'s
    // doc). `None` costs nothing; see this function's own `.with_tracing`
    // call below for the FilterChainHandler half of the same wiring.
    let mut router_factory = RouterFilterFactory::new(
        runtime.cluster_manager.clone(),
        runtime.router_stats.clone(),
    )
    .with_config_context(context.to_string(), runtime.snapshot_version.0);
    if let Some(t) = runtime.tracing_handles {
        router_factory = router_factory.with_tracing(t.sink.clone());
    }
    // S10: thread this HCM's `upgrade_configs` into
    // the router -- empty is the common case (no upgrades configured) and
    // costs nothing beyond an empty `HashMap`; see
    // `RouterFilterFactory::with_upgrade_configs`'s doc.
    router_factory = router_factory.with_upgrade_configs(hcm.upgrade_configs.clone());
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(router_factory);

    // `access_logs` sinks are opened here, at the same
    // bind/rebuild cadence as everything else in this function (a fresh
    // `FilterChainHandler` -- and so a fresh set of loggers/sinks -- is built
    // every time `build_listener_hcm` rebuilds this chain, mirroring
    // `build_listener_tls`'s cadence for certs). A sink that can't be opened
    // (e.g. an unwritable file path) is a startup/config error, same
    // fatal-at-`initial_bind`/logged-and-skip-at-reconcile treatment as an
    // unregistered filter or a bad cert.
    //
    // Access logging now lives on `FilterChainHandler`, not `RouterHandler`
    // -- see `proxy_http::filter_manager`'s and `proxy_http::access_logging`'s
    // module docs for why (the router sits INSIDE the encode filter chain,
    // so logging from there can never observe what an encode filter does at
    // end-of-stream).
    //
    // ADR-0004 step 4: `new_with_filters_and_access_logs` (not
    // plain `new_with_access_logs`) -- `filters` carries each entry's Envoy
    // name and registered factory, needed to resolve `typed_per_filter_config`
    // against the real chain once, here, rather than never (AGENTS.md invariant 1).
    // `.with_token_stats` on every real HCM build --
    // `FilterChainHandler::with_token_stats`'s own doc says this is exactly
    // what this function is supposed to do; before this, the field it sets
    // was wired end to end everywhere except here, so `token_stats` was
    // always `None` and `llm.client.token.usage` was never recorded no
    // matter what a route configured.
    let route_table = match &hcm.rds_route_config_name {
        Some(name) => routes
            .get(name)
            .cloned()
            .ok_or_else(|| HttpFilterChainBuildError {
                context: context.to_string(),
                reason: format!("RDS route configuration `{name}` is not warmed"),
            })?,
        None => hcm.route_table.clone(),
    };
    let mut handler = FilterChainHandler::new_with_filters_and_access_logs(
        filters,
        terminal_factory,
        route_table,
        hcm.generate_request_id,
        hcm.use_remote_address,
        hcm.xff_num_trusted_hops,
        &hcm.access_logs,
    )
    .map_err(|e| HttpFilterChainBuildError {
        context: context.to_string(),
        reason: format!("failed to build filter chain: {e}"),
    })?
    .with_token_stats(runtime.token_stats.clone())
    // The listener's `per_connection_buffer_limit_bytes` (Envoy default 1 MiB,
    // applied at lowering) caps request-body collection for every HTTP request,
    // before any filter runs, as well as filter buffering. A larger body gets a
    // 413 (`decode_buffer_overflow`).
    .with_buffer_limit(buffer_limit_bytes as usize)
    .with_request_timeout(hcm.request_timeout);
    handler = handler.with_gen_ai_latency_stats(runtime.latency_stats.clone());
    if let Some(sink) = runtime.metadata {
        handler = handler.with_request_record_sink(sink.clone());
    }
    // `.with_tracing` on the FilterChainHandler half of
    // this build -- see the `router_factory` one above for the other half
    // (the CLIENT-span-emitting router terminal); this half is what mints
    // the SERVER span and joins/propagates an inbound `traceparent`.
    if let Some(t) = runtime.tracing_handles {
        handler = handler.with_tracing(t.sink.clone(), t.sample_ratio);
    }
    Ok(Rc::new(handler))
}

/// Everything [`run_terminal_filter`] needs beyond `stream`/`filter`/
/// `snapshot` -- the `codec` field is what pushed the plain
/// parameter list over clippy's `too_many_arguments` threshold; bundled here
/// rather than adding an 8th positional parameter (same motivation
/// [`WorkerShared`]/[`ListenerCaches`] document for their own bundling).
struct RunTerminalFilterCtx<'a> {
    registry: &'a ConnectionRegistry,
    shutdown: watch::Receiver<bool>,
    /// Starts the HTTP codecs' graceful shutdown; TCP proxy connections ignore
    /// it and run until `shutdown`.
    drain: watch::Receiver<DrainState>,
    name: &'a ListenerName,
    // Rust note: `Copy`, so it threads cheaply -- also doubles as `peer` for
    // the tracing calls below via `downstream.remote`.
    downstream: DownstreamInfo,
    // Which codec to drive the `Http` terminal filter with --
    // always `Http1` on the plaintext call site, ALPN-derived on the TLS one
    // (see `downstream_codec_for_alpn`). Ignored by the `TcpProxy`/`None`
    // arms below, which have no HTTP codec to pick.
    codec: DownstreamCodec,
    /// The matched HCM's `request_headers_timeout`. Applied to HTTP/1 only;
    /// hyper's h2 server exposes no per-stream header progress, so it is not
    /// enforced there (internal-docs/envoy-divergences.md).
    request_headers_timeout: Option<Duration>,
}

/// Dispatch to the matched chain's terminal L4 filter. On the `TcpProxy` and
/// `Http` paths this registers the connection guard and runs to completion,
/// consuming `stream` and returning `None`. On the no-filter path it logs and
/// hands `stream` back so the caller can decide how to close it (a plaintext
/// `TcpStream` can be `reset`; a `TlsStream` is just dropped -- see the call
/// sites).
async fn run_terminal_filter<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: IO,
    filter: Option<TerminalFilter>,
    snapshot: Arc<ConfigSnapshot>,
    ctx: RunTerminalFilterCtx<'_>,
) -> Option<IO> {
    let RunTerminalFilterCtx {
        registry,
        mut shutdown,
        mut drain,
        name,
        downstream,
        codec,
        request_headers_timeout,
    } = ctx;
    let peer = downstream.remote;
    match filter {
        Some(TerminalFilter::TcpProxy(params)) => {
            let guard = registry.register();
            tcp_proxy::proxy_connection(stream, snapshot, params, guard, shutdown).await;
            None
        }
        Some(TerminalFilter::Http(handler)) => {
            // Held for the whole HTTP connection's lifetime -- same role as
            // `tcp_proxy`'s guard above -- so drain accounting sees this
            // connection as live until the codec returns. The codecs return
            // only after any upgrade tunnel they spawned has closed, so this
            // also covers upgraded streams (envoy-semantics.md S10.5).
            let _guard = registry.register();

            // Rust note: `serve_http1` wants an `impl Future<Output = ()>`,
            // not a `watch::Receiver` directly (it's decoupled from
            // proxy-core's drain machinery on purpose -- see its doc
            // comment). Hyper's graceful shutdown must start at whichever
            // comes first: drain start (idle keep-alive connections close now,
            // in-flight requests finish, then `Connection: close` on HTTP/1
            // or GOAWAY on HTTP/2) or the final `shutdown` signal.
            // Hook: a realtime/WebSocket session would send Close 1001 when
            // `drain_started` resolves.
            let shutdown_fut = async move {
                let shutdown_signal = async {
                    if *shutdown.borrow() {
                        return;
                    }
                    // `changed()` only ever resolves once in practice (the
                    // sender flips `false` -> `true` exactly once), but the
                    // loop guards against spurious/duplicate notifications
                    // rather than assuming that.
                    while shutdown.changed().await.is_ok() {
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                };
                tokio::select! {
                    _ = drain_started(&mut drain) => {}
                    _ = shutdown_signal => {}
                }
            };

            match codec {
                DownstreamCodec::Http1 => {
                    let options = Http1Options {
                        keep_alive: true,
                        header_read_timeout: request_headers_timeout,
                    };
                    if let Err(err) =
                        serve_http1(stream, handler, options, shutdown_fut, downstream).await
                    {
                        tracing::debug!(listener = %name, peer = %peer, error = %err, "http/1.1 connection ended with an error");
                    }
                }
                DownstreamCodec::Http2 => {
                    if request_headers_timeout.is_some() {
                        warn_h2_header_timeout_not_enforced_once(name);
                    }
                    if let Err(err) = serve_http2(stream, handler, shutdown_fut, downstream).await {
                        tracing::debug!(listener = %name, peer = %peer, error = %err, "http/2 connection ended with an error");
                    }
                }
            }
            None
        }
        None => {
            tracing::debug!(listener = %name, peer = %peer, "matched chain has no terminal filter; resetting connection");
            Some(stream)
        }
    }
}

/// Reset a connection with a TCP RST (via `SO_LINGER(0)`) instead of a clean
/// FIN close -- Envoy's behavior on a `filter_chain_match` miss or an
/// un-serviceable TLS chain.
fn reset(stream: &TcpStream, listener: &str) {
    if let Err(err) = SockRef::from(stream).set_linger(Some(Duration::ZERO)) {
        tracing::warn!(listener = %listener, error = %err, "failed to set SO_LINGER for reset-close");
    }
    // `stream` is dropped by the caller (it owns it); the linger option we
    // just set is what turns that drop into an RST.
}

/// Reconcile `bound` against `snapshot`: bind new listeners, warm a replacement
/// before stopping an address-changed listener, leave unchanged ones alone, and
/// stop accepting on ones that were removed.
// `factory_state` is the 8th argument, tipping this over
// clippy's 7-arg ceiling -- it can't fold into `stats` (a `&StatsRecorders`,
// already a bundle of the actual per-worker *stats recorders*; `factory_state`
// is a different kind of shared handle) without muddying that bundle's own
// documented purpose, so this leaf allows the extra arg instead, same
// tradeoff `crates/proxy/src/main.rs`'s `worker_main` already made for
// `tracing_handles`. `secret_registry` rides along the
// same way, for the same reason.
#[allow(clippy::too_many_arguments)]
fn reconcile(
    snapshot: &Arc<ConfigSnapshot>,
    bound: &mut HashMap<ListenerName, BoundListener>,
    config: &Arc<WorkerConfigHandle>,
    registry: &ConnectionRegistry,
    shutdown: &watch::Receiver<bool>,
    drain: &watch::Receiver<DrainState>,
    cluster_manager: &Arc<ClusterManager>,
    stats: &StatsRecorders,
    factory_state: &Arc<SharedFactoryState>,
    secret_registry: &Arc<SdsSecretRegistry>,
) {
    let shared = WorkerShared {
        config,
        registry,
        shutdown,
        drain,
        cluster_manager,
        router_stats: &stats.router,
        downstream_stats: &stats.downstream,
        connection_limiter: &stats.connection_limiter,
        token_stats: &stats.token,
        latency_stats: &stats.latency,
        tracing: &stats.tracing,
        metadata: &stats.metadata,
        factory_state,
        secret_registry,
    };
    // A listener rename at an unchanged address keeps the existing socket and
    // accept loop. The loop resolves its logical name from the next snapshot
    // before accepting again, so the rename cannot create a `SO_REUSEPORT`
    // accept race or leave an old handler pointed at a removed cluster.
    let renames: Vec<(ListenerName, ListenerName)> = snapshot
        .listeners
        .iter()
        .filter(|(name, _)| !bound.contains_key(*name))
        .filter_map(|(new_name, listener_ir)| {
            bound
                .iter()
                .find(|(old_name, existing)| {
                    !snapshot.listeners.contains_key(*old_name)
                        && existing.addr == listener_ir.address
                })
                .map(|(old_name, _)| (old_name.clone(), new_name.clone()))
        })
        .collect();
    for (old_name, new_name) in renames {
        let existing = bound
            .remove(&old_name)
            .expect("rename source must remain bound until re-keyed");
        tracing::info!(old_listener = %old_name, new_listener = %new_name, addr = %existing.addr, "listener renamed in place");
        bound.insert(new_name, existing);
    }

    // Warm every desired listener before retiring names absent from the new
    // snapshot. A rename at the same address is a replacement, not a remove
    // followed by a bind: aborting the old accept loop first leaves a socket
    // gap and drops connections queued during that gap.
    for (name, listener_ir) in snapshot.listeners.iter() {
        if !listener_ir.bind_to_port {
            // Envoy only uses such listeners via internal redirection
            // (`internal_listener`); we don't implement that, so we simply
            // never bind or accept for them.
            tracing::debug!(listener = %name, "bind_to_port=false; not binding");
            continue;
        }
        if !listener_ir.routes_are_warmed(&snapshot.routes) {
            tracing::info!(listener = %name, "listener waits for RDS route configuration before binding");
            continue;
        }

        match bound.get(name) {
            Some(existing) if existing.addr == listener_ir.address => {
                // Unchanged address: leave the accept loop running. It
                // reloads the snapshot per accepted connection (see
                // `spawn_accept_loop`), so filter-chain changes on this
                // listener take effect for new connections without a rebind.
            }
            Some(existing) => {
                let old_addr = existing.addr;
                tracing::info!(listener = %name, %old_addr, new_addr = %listener_ir.address, "listener address changed; warming replacement before drain");
                match spawn_bound(
                    name,
                    listener_ir,
                    &snapshot.routes,
                    snapshot.version,
                    &shared,
                ) {
                    Ok(replacement) => {
                        // The replacement has completed every bind-time warm-up
                        // (TLS and HTTP filter construction plus socket bind) before
                        // this point. Only now stop the old accept loop. Its already
                        // accepted connection tasks own their snapshots and drain
                        // independently.
                        let old = bound
                            .insert(name.clone(), replacement)
                            .expect("address-changed listener must still be bound");
                        old.task.abort();
                    }
                    Err(err) => {
                        // Keep the old map entry and accept loop intact. A failed
                        // replacement must never turn a live listener update into an
                        // outage; later snapshots can retry this warm-up.
                        tracing::error!(listener = %name, address = %listener_ir.address, error = %err, "failed to warm replacement listener; keeping previous listener active");
                    }
                }
            }
            None => {
                bind_and_spawn(
                    name.clone(),
                    listener_ir,
                    &snapshot.routes,
                    snapshot.version,
                    bound,
                    &shared,
                );
            }
        }
    }

    let desired_addrs: HashSet<SocketAddr> = snapshot
        .listeners
        .values()
        .filter(|listener| listener.bind_to_port && listener.routes_are_warmed(&snapshot.routes))
        .map(|listener| listener.address)
        .collect();
    let active_addrs: HashSet<SocketAddr> = bound
        .iter()
        .filter(|(name, _)| snapshot.listeners.contains_key(*name))
        .map(|(_, listener)| listener.addr)
        .collect();
    let removed: Vec<ListenerName> = bound
        .keys()
        .filter(|name| !snapshot.listeners.contains_key(*name))
        .cloned()
        .collect();
    for name in removed {
        let addr = bound
            .get(&name)
            .expect("removed listener must still be bound")
            .addr;
        if desired_addrs.contains(&addr) && !active_addrs.contains(&addr) {
            // A same-address rename whose replacement failed to warm must
            // leave the last-good listener accepting until a later snapshot
            // can retry it.
            tracing::error!(listener = %name, %addr, "replacement listener failed to bind; keeping previous listener active");
            continue;
        }
        if let Some(b) = bound.remove(&name) {
            tracing::info!(listener = %name, "listener removed from config after replacements warmed; existing connections drain independently");
            b.task.abort();
        }
    }
}

/// Runs for the rest of a worker's lifetime: reconciles `bound` (already
/// populated by a prior, fallible [`initial_bind`] call) against each new
/// snapshot the control runtime publishes (`config_ping`), until `drain` or
/// `shutdown` fires.
///
/// At drain start every accept loop is aborted and awaited, which drops its
/// `TcpListener`: new connections are refused from then on, and no later
/// snapshot (SIGHUP, xDS) can bind a listener again. Established connections
/// are untouched here; they own their tasks and react to `drain` themselves.
/// `lifecycle.mark_listener_bound()` runs after each reconcile that leaves a
/// listener bound, so `/ready` also turns live for listeners that arrive
/// later through LDS.
///
/// Rust note: the split between `initial_bind` (fallible, run first, can
/// report a fatal startup error) and this function (infallible from here on
/// -- reconcile-time bind failures are logged and skipped, not fatal) is
/// deliberate. Callers that care about startup failing loudly (`crates/proxy`
/// `serve()`) call `initial_bind` themselves and only reach this function on
/// success.
///
/// Established connections are unaffected by any of this: they hold their
/// own `Arc<ConfigSnapshot>` and their own task, independent of the accept
/// loop that spawned them.
// `factory_state` tips this over clippy's 7-arg ceiling,
// same reasoning as `reconcile`'s own `#[allow]` just above (this function's
// only job with it is forwarding it there every reconcile). `secret_registry`
// rides along the same way.
#[allow(clippy::too_many_arguments)]
pub async fn run_listener_manager(
    mut bound: HashMap<ListenerName, BoundListener>,
    config: Arc<WorkerConfigHandle>,
    mut config_ping: watch::Receiver<SnapshotVersion>,
    mut shutdown: watch::Receiver<bool>,
    mut drain: watch::Receiver<DrainState>,
    lifecycle: Arc<LifecycleState>,
    registry: ConnectionRegistry,
    cluster_manager: Arc<ClusterManager>,
    stats: StatsRecorders,
    factory_state: Arc<SharedFactoryState>,
    secret_registry: Arc<SdsSecretRegistry>,
) {
    loop {
        // Rust note: `biased;` makes `select!` poll branches in source order
        // instead of randomly. Drain is first so a snapshot published in the
        // same instant as the drain can never rebind a listener.
        tokio::select! {
            biased;
            _ = drain_started(&mut drain) => {
                tracing::info!("drain started: closing listening sockets, no further binds");
                break;
            }
            _ = shutdown.changed() => {
                break;
            }
            changed = config_ping.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = config.load();
                reconcile(
                    &snapshot,
                    &mut bound,
                    &config,
                    &registry,
                    &shutdown,
                    &drain,
                    &cluster_manager,
                    &stats,
                    &factory_state,
                    &secret_registry,
                );
                if !bound.is_empty() {
                    lifecycle.mark_listener_bound();
                }
            }
        }
    }

    // Aborting only schedules the cancellation; awaiting each handle is what
    // guarantees the `TcpListener` is dropped (the port refuses connections)
    // before this returns.
    let tasks: Vec<JoinHandle<()>> = bound.drain().map(|(_, b)| b.task).collect();
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
}

#[cfg(test)]
#[path = "listener_ext_authz_tests.rs"]
mod ext_authz_tests;

#[cfg(test)]
#[path = "listener_admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "listener_body_cap_tests.rs"]
mod body_cap_tests;

#[cfg(test)]
#[path = "listener_drain_tests.rs"]
mod drain_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::run_local;
    use proxy_config::ir::{
        FilterChainMatch, FilterChainSpec, ListenerConfig as IrListenerConfig, SourceType,
    };
    use std::collections::BTreeMap;
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::net::TcpStream;

    use crate::tls::UpstreamTlsFactory;
    use proxy_config::ir::{
        ClusterConfig, ClusterKind, DataSourceIR, DiscoveryType, DownstreamTlsSpec, EndpointIR,
        LbPolicy, TcpProxyConfig, TlsCertificateIR, TlsParametersIR, TlsVersion, UpstreamTlsSpec,
    };
    use rcgen::{CertificateParams, DnType, KeyPair};

    /// Rust note: standard "reserve an ephemeral port, then reuse the
    /// number" technique for tests that need a fixed port ahead of time --
    /// bind on port 0, read back whatever the OS assigned, then drop the
    /// listener so the port is free again. There's a small window where
    /// another process could grab it first; acceptable for tests.
    async fn free_port() -> u16 {
        let l = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        drop(l);
        port
    }

    /// A connected `TcpStream` pair over loopback -- for tests that exercise
    /// [`peek_for_h2_preface`]/[`resolve_plaintext_codec`] directly, without
    /// going through a whole listener/`spawn_manager` harness (same
    /// motivation as `tls_inspector::tests::loopback_pair`, which this
    /// mirrors).
    async fn tcp_loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    // --- `codec_type` peek/dispatch on a plaintext connection --------

    /// Sanity check: a preface delivered in a single write is recognized.
    #[test]
    fn peek_for_h2_preface_true_for_a_complete_preface_in_one_write() {
        run_local(async {
            let (mut client, server) = tcp_loopback_pair().await;
            client.write_all(H2_CLIENT_PREFACE).await.unwrap();
            let result = tokio::time::timeout(Duration::from_secs(2), peek_for_h2_preface(&server))
                .await
                .expect("should resolve promptly");
            assert!(result, "a complete, correct preface must be recognized");
        });
    }

    /// A request that diverges from the preface at its very first byte (an
    /// ordinary h1 method) must be rejected promptly -- it should not need to
    /// wait anywhere near `H2_PREFACE_PEEK_TIMEOUT` to decide, the same
    /// "discriminate on the bytes actually seen, don't wait for more than
    /// necessary" property `tls_inspector::non_tls_first_byte_returns_none_promptly`
    /// checks for the TLS ClientHello peek.
    #[test]
    fn peek_for_h2_preface_false_promptly_for_a_mismatched_first_byte() {
        run_local(async {
            let (mut client, server) = tcp_loopback_pair().await;
            client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            let result =
                tokio::time::timeout(Duration::from_millis(500), peek_for_h2_preface(&server))
                    .await
                    .expect(
                        "a first-byte mismatch should resolve promptly, not wait for the timeout",
                    );
            assert!(!result, "an ordinary h1 request line is not the h2 preface");
        });
    }

    /// "A connection that sends 23 bytes of a
    /// valid preface then more must still work" -- the peek loop must keep
    /// waiting across a slow, split write of an otherwise-valid preface, not
    /// bail out (or misread the split as a mismatch) on the first incomplete
    /// read.
    #[test]
    fn peek_for_h2_preface_handles_a_slow_split_write_of_an_otherwise_valid_preface() {
        run_local(async {
            let (mut client, server) = tcp_loopback_pair().await;
            client
                .write_all(&H2_CLIENT_PREFACE[..H2_CLIENT_PREFACE.len() - 1])
                .await
                .unwrap();

            let peek = tokio::task::spawn_local(async move {
                tokio::time::timeout(Duration::from_secs(2), peek_for_h2_preface(&server))
                    .await
                    .expect("should resolve once the rest of the preface arrives")
            });

            tokio::time::sleep(Duration::from_millis(50)).await;
            client
                .write_all(&H2_CLIENT_PREFACE[H2_CLIENT_PREFACE.len() - 1..])
                .await
                .unwrap();

            assert!(
                peek.await.expect("peek task should not panic"),
                "a preface split across a slow write must still be recognized, not misread as h1"
            );
        });
    }

    /// "A connection sending fewer than 24 bytes
    /// and then waiting must not hang forever" -- a client that sends a valid
    /// preface *prefix* and then goes quiet forever must still resolve,
    /// falling back to h1 once `H2_PREFACE_PEEK_TIMEOUT` elapses rather than
    /// blocking the connection indefinitely. The outer `tokio::time::timeout`
    /// here is the test's own safety net (so a regression that removes the
    /// bound fails this test instead of hanging the suite); the inner bound
    /// is `resolve_plaintext_codec`'s real one.
    #[test]
    fn resolve_plaintext_codec_auto_falls_back_to_http1_when_a_partial_preface_never_completes() {
        run_local(async {
            let (mut client, server) = tcp_loopback_pair().await;
            client.write_all(&H2_CLIENT_PREFACE[..10]).await.unwrap();
            // Never sends the rest, and never closes -- `server` must give up
            // on its own rather than wait on `client` forever.

            let codec = tokio::time::timeout(
                H2_PREFACE_PEEK_TIMEOUT + Duration::from_secs(2),
                resolve_plaintext_codec(CodecType::Auto, &server),
            )
            .await
            .expect("resolve_plaintext_codec must give up on its own bound, not hang forever");
            assert_eq!(
                codec,
                DownstreamCodec::Http1,
                "an incomplete preface that never completes should fall back to h1"
            );
        });
    }

    /// A `tcp_proxy` filter targeting `cluster`, no idle timeout, a single
    /// connect attempt -- the minimal filter every "held open" fixture below
    /// needs now that empty filter lists no longer hold a connection open
    /// (a chain with no terminal filter is reset, matching Envoy/the
    /// lowering-time non-empty-filters invariant).
    fn tcp_proxy_filter(cluster: &str) -> NetworkFilterSpec {
        tcp_proxy_filter_with_idle(cluster, None)
    }

    fn tcp_proxy_filter_with_idle(
        cluster: &str,
        idle_timeout: Option<Duration>,
    ) -> NetworkFilterSpec {
        NetworkFilterSpec::TcpProxy(TcpProxyConfig {
            stat_prefix: "test".to_string(),
            cluster: cluster.to_string(),
            idle_timeout,
            max_connect_attempts: 1,
        })
    }

    /// A minimal `http_connection_manager` filter -- an empty route table (no
    /// virtual hosts) and no http_filters. The terminal is a
    /// real [`proxy_http::router::RouterHandler`], so a request against this
    /// empty table always takes the `NoVirtualHost` path (404) -- see
    /// `hcm_terminal_filter_serves_http_over_the_real_socket`, which exists
    /// to prove HTTP is served over the real socket at all, not any
    /// particular route outcome.
    fn hcm_filter() -> NetworkFilterSpec {
        NetworkFilterSpec::HttpConnectionManager(proxy_config::ir::HttpConnectionManagerConfig {
            stat_prefix: "test".to_string(),
            route_table: Arc::new(
                proxy_config::ir::RouteTable::new(
                    "test-routes".to_string(),
                    vec![],
                    BTreeMap::new(),
                )
                .expect("empty route table can't have duplicate domains"),
            ),
            rds_route_config_name: None,
            http_filters: vec![],
            codec_type: proxy_config::ir::CodecType::Auto,
            generate_request_id: true,
            use_remote_address: false,
            xff_num_trusted_hops: 0,
            access_logs: vec![],
            upgrade_configs: vec![],
            request_headers_timeout: None,
            request_timeout: None,
        })
    }

    /// A one-vhost, one-route table matching every request (`*` domain,
    /// empty-prefix path) with a `DirectResponse` action -- the router
    /// terminal synthesizes this response itself, no cluster/upstream
    /// involved. Used by `hcm_filter_chain_mutates_headers_over_the_real_socket`
    /// to prove the header-mutation filter's mutation survives the real
    /// router terminal (as opposed to the router-forwarding test below, which
    /// proves the `Forward` path to a real upstream).
    fn direct_response_route_table(status: u16) -> Arc<proxy_config::ir::RouteTable> {
        use proxy_config::ir::{
            PathMatch, RouteActionIR, RouteEntry, RouteMatcher, RouteTable, VirtualHostIR,
        };
        Arc::new(
            RouteTable::new(
                "test-routes".to_string(),
                vec![VirtualHostIR {
                    name: "vh".to_string(),
                    domains: vec!["*".to_string()],
                    routes: vec![Arc::new(RouteEntry {
                        name: None,
                        matcher: RouteMatcher {
                            path: PathMatch::Prefix(String::new()),
                            case_sensitive: true,
                            headers: vec![],
                        },
                        action: RouteActionIR::DirectResponse { status, body: None },
                        request_headers_to_add: vec![],
                        streaming_strict: false,
                        typed_per_filter_config: BTreeMap::new(),
                        route_index: 0,
                        include_request_attempt_count: false,
                        include_attempt_count_in_response: false,
                    })],
                    typed_per_filter_config: BTreeMap::new(),
                }],
                BTreeMap::new(),
            )
            .expect("single vhost can't have duplicate domains"),
        )
    }

    /// An `http_connection_manager` filter whose `http_filters` chain is the
    /// built-in [`crate::header_mutation_filter`] followed by the terminal
    /// router -- what actually exercises the `FilterRegistry` ->
    /// `FilterChainHandler` wiring end to end (see
    /// `hcm_filter_chain_mutates_headers_over_the_real_socket` below). The
    /// route table is [`direct_response_route_table`] (200), so the real
    /// router terminal produces a response for the header-mutation encode
    /// filter to mutate (the terminal used to be a fixed-200 stub).
    fn hcm_filter_with_header_mutation(header_name: &str, header_value: &str) -> NetworkFilterSpec {
        use crate::header_mutation_filter::{header_value_option, TYPE_URL};
        NetworkFilterSpec::HttpConnectionManager(proxy_config::ir::HttpConnectionManagerConfig {
            stat_prefix: "test".to_string(),
            route_table: direct_response_route_table(200),
            rds_route_config_name: None,
            http_filters: vec![
                proxy_config::ir::HttpFilterSpec {
                    ext_authz: None,
                    name: "llmproxy.header_mutation".to_string(),
                    type_url: TYPE_URL.to_string(),
                    config: Some(header_value_option(header_name, header_value)),
                    is_router: false,
                },
                proxy_config::ir::HttpFilterSpec {
                    ext_authz: None,
                    name: "envoy.filters.http.router".to_string(),
                    type_url: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                        .to_string(),
                    config: None,
                    is_router: true,
                },
            ],
            codec_type: proxy_config::ir::CodecType::Auto,
            generate_request_id: true,
            use_remote_address: false,
            xff_num_trusted_hops: 0,
            access_logs: vec![],
            upgrade_configs: vec![],
            request_headers_timeout: None,
            request_timeout: None,
        })
    }

    /// A single match-all-chain listener whose sole filter is `filter` --
    /// the general form [`match_all_listener`] delegates to for the common
    /// (idle-timeout-less `tcp_proxy`) case.
    fn match_all_listener_with_filter(
        name: &str,
        addr: SocketAddr,
        filter: NetworkFilterSpec,
    ) -> IrListenerConfig {
        IrListenerConfig {
            name: name.to_string(),
            address: addr,
            filter_chains: vec![FilterChainSpec {
                transport_socket_connect_timeout: None,
                name: Some("default".to_string()),
                match_criteria: FilterChainMatch::default(),
                transport_socket: None,
                filters: vec![filter],
            }],
            default_filter_chain: None,
            listener_filters: vec![],
            per_connection_buffer_limit_bytes: 1024 * 1024,
            tcp_backlog_size: None,
            bind_to_port: true,
            ignore_global_conn_limit: false,
        }
    }

    /// A STATIC cluster with a single priority-0 endpoint at `addr`.
    fn static_cluster(name: &str, addr: SocketAddr) -> ClusterConfig {
        ClusterConfig {
            // Non-EDS fixture: hosts come from `endpoints`/`discovery`.
            eds: None,
            name: name.to_string(),
            discovery: DiscoveryType::Static,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints: vec![EndpointIR {
                metadata: Default::default(),
                host: addr.ip().to_string(),
                port: addr.port(),
                weight: 1,
                priority: 0,
            }],
            kind: ClusterKind::Endpoints,
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1024 * 1024,
            circuit_breakers: Default::default(),
            upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
            request_headers_to_add: Vec::new(),
            usage_dialect: None,
            request_path_rewrite: None,
            provider_runtime: None,
            health_check: None,
            outlier_detection: None,
        }
    }

    /// Accept connections on an ephemeral port forever and hold each one open
    /// without reading or writing -- a stand-in upstream for tests that only
    /// care whether the *downstream* side of a `tcp_proxy`'d connection stays
    /// open (matching the old drain-and-discard stub's observable behavior),
    /// not about what flows over the wire.
    async fn spawn_holding_upstream() -> SocketAddr {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn_local(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        tokio::task::spawn_local(async move {
                            let _stream = stream; // held for the task's lifetime
                            std::future::pending::<()>().await;
                        });
                    }
                    Err(_) => return,
                }
            }
        });
        addr
    }

    /// Accept connections forever and echo back whatever's read, byte for
    /// byte, until the peer closes -- the default upstream fixture for
    /// tests that actually push data through the pump.
    async fn spawn_echo_upstream() -> SocketAddr {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn_local(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::task::spawn_local(async move {
                    let mut buf = [0u8; 8192];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    fn snapshot_with(listener: IrListenerConfig, version: u64) -> Arc<ConfigSnapshot> {
        Arc::new(ConfigSnapshot {
            listeners: HashMap::from([(listener.name.clone(), Arc::new(listener))]),
            version: SnapshotVersion(version),
            ..Default::default()
        })
    }

    /// Like [`snapshot_with`], plus a cluster map -- needed by any fixture
    /// whose matched chain actually dispatches to `tcp_proxy` at runtime.
    fn snapshot_with_cluster(
        listener: IrListenerConfig,
        cluster: ClusterConfig,
        version: u64,
    ) -> Arc<ConfigSnapshot> {
        Arc::new(ConfigSnapshot {
            listeners: HashMap::from([(listener.name.clone(), Arc::new(listener))]),
            clusters: HashMap::from([(cluster.name.clone(), Arc::new(cluster))]),
            version: SnapshotVersion(version),
            ..Default::default()
        })
    }

    fn match_all_listener(name: &str, addr: SocketAddr, cluster: &str) -> IrListenerConfig {
        match_all_listener_with_filter(name, addr, tcp_proxy_filter(cluster))
    }

    fn sni_only_listener(name: &str, addr: SocketAddr, cluster: &str) -> IrListenerConfig {
        IrListenerConfig {
            name: name.to_string(),
            address: addr,
            filter_chains: vec![FilterChainSpec {
                transport_socket_connect_timeout: None,
                name: Some("sni-only".to_string()),
                match_criteria: FilterChainMatch {
                    server_names: vec!["example.com".to_string()],
                    source_type: SourceType::Any,
                    ..Default::default()
                },
                transport_socket: None,
                filters: vec![tcp_proxy_filter(cluster)],
            }],
            default_filter_chain: None,
            listener_filters: vec![],
            per_connection_buffer_limit_bytes: 1024 * 1024,
            tcp_backlog_size: None,
            bind_to_port: true,
            ignore_global_conn_limit: false,
        }
    }

    /// Same match criteria as [`sni_only_listener`], but with a `tls_inspector`
    /// listener filter -- the only thing that lets `server_names` matching
    /// actually see the ClientHello's SNI.
    fn sni_only_listener_with_tls_inspector(
        name: &str,
        addr: SocketAddr,
        cluster: &str,
    ) -> IrListenerConfig {
        IrListenerConfig {
            listener_filters: vec![proxy_config::ir::ListenerFilterSpec::TlsInspector(
                proxy_config::ir::TlsInspectorConfig::default(),
            )],
            ..sni_only_listener(name, addr, cluster)
        }
    }

    /// Drive a `rustls::ClientConnection` far enough to produce its first
    /// flight (the ClientHello) without touching the network, and hand back
    /// the raw bytes it would have written to the wire. Same technique as
    /// `tls_inspector`'s own unit tests.
    fn client_hello_bytes(server_name: &str) -> Vec<u8> {
        let root_store = rustls::RootCertStore::empty();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let server_name: rustls::pki_types::ServerName<'static> =
            server_name.to_string().try_into().unwrap();
        let mut conn =
            rustls::ClientConnection::new(std::sync::Arc::new(config), server_name).unwrap();
        let mut bytes = Vec::new();
        conn.write_tls(&mut bytes).unwrap();
        bytes
    }

    struct Harness {
        config: Arc<WorkerConfigHandle>,
        config_tx: watch::Sender<SnapshotVersion>,
        shutdown_tx: watch::Sender<bool>,
        registry: ConnectionRegistry,
        manager: tokio::task::JoinHandle<()>,
        stats_control: proxy_observability::stats::StatsControl,
    }

    /// Builds a [`ClusterManager`] populated (and force-initialized, so
    /// `pick_host` never has to wait on real DNS) from `snapshot`'s cluster
    /// map -- the same manager both the `tcp_proxy` fixtures' listener wiring
    /// and the HTTP router's `RouterHandler` see.
    async fn cluster_manager_for(snapshot: &ConfigSnapshot) -> Arc<ClusterManager> {
        let manager = Arc::new(ClusterManager::new(
            Arc::new(proxy_cluster::resolver::TokioResolver),
            crate::tls::transport_socket_builder(),
        ));
        manager.update_from_snapshot(&snapshot.clusters).await;
        for name in snapshot.clusters.keys() {
            manager.force_initialize(name);
        }
        manager
    }

    /// A fresh, single-worker [`RouterStats`] resolved
    /// for every cluster in `snapshot` -- what `crates/proxy/src/main.rs`
    /// builds once at boot from the real config snapshot; these tests need
    /// the same shape so `RouterFilterFactory` (built deep inside
    /// `initial_bind`/`build_listener_hcm`) has somewhere to record into.
    ///
    /// Takes `control` by reference rather than building its own, and so do
    /// [`downstream_stats_for`]/[`token_stats_for`] below -- all three
    /// recorders must share the SAME [`proxy_observability::stats::StatsControl`]
    /// (and so the same underlying `Registry`), exactly like
    /// `crates/proxy/src/main.rs`'s `run_serve` shares one `stats_control`
    /// across `stat_handles`/`downstream_stat_handles`/
    /// `token_usage_stat_handles`. A [`Handle`](proxy_observability::stats::Handle)
    /// is just an index into its resolving control's registry; handing one
    /// recorder a handle resolved from a DIFFERENT, unrelated control's
    /// registry is exactly the bug this shape prevents (found by these
    /// tests panicking with "index out of bounds" the first time
    /// `downstream_stats_for`/`token_stats_for` each built their own private
    /// `StatsControl`).
    pub(super) fn router_stats_for(
        control: &proxy_observability::stats::StatsControl,
        snapshot: &ConfigSnapshot,
    ) -> Arc<RouterStats> {
        let handles = Arc::new(proxy_http::stat_handles::StatHandles::build(
            control,
            snapshot.clusters.keys().map(String::as_str),
        ));
        Arc::new(RouterStats::new(
            control.registry(),
            handles,
            proxy_observability::stats::WorkerId(0),
        ))
    }

    /// [`router_stats_for`]'s counterpart for `downstream_cx_total` -- see
    /// that function's doc for why this shares `control` rather than
    /// building its own.
    fn downstream_stats_for(
        control: &proxy_observability::stats::StatsControl,
        snapshot: &ConfigSnapshot,
    ) -> Arc<DownstreamStats> {
        let handles = Arc::new(proxy_http::stat_handles::DownstreamStatHandles::build(
            control,
            snapshot.listeners.keys().map(String::as_str),
        ));
        Arc::new(DownstreamStats::new(
            control.registry(),
            handles,
            proxy_observability::stats::WorkerId(0),
        ))
    }

    /// [`router_stats_for`]'s counterpart for `llm.client.token.usage` --
    /// see that function's doc for why this shares `control` rather than
    /// building its own. Resolved for every cluster (= provider,
    /// AGENTS.md invariant 6) in `snapshot`.
    pub(super) fn token_stats_for(
        control: &proxy_observability::stats::StatsControl,
        snapshot: &ConfigSnapshot,
    ) -> Arc<GenAiTokenStats> {
        let handles = Arc::new(proxy_http::stat_handles::TokenUsageStatHandles::build(
            control,
            snapshot.clusters.keys().map(String::as_str),
        ));
        Arc::new(GenAiTokenStats::new(
            control.registry(),
            handles,
            proxy_observability::stats::WorkerId(0),
        ))
    }

    pub(super) fn latency_stats_for(
        control: &proxy_observability::stats::StatsControl,
    ) -> Arc<GenAiLatencyStats> {
        Arc::new(GenAiLatencyStats::new(
            control.registry(),
            proxy_observability::stats::WorkerId(0),
        ))
    }

    async fn spawn_manager(initial: Arc<ConfigSnapshot>) -> Harness {
        let config = Arc::new(WorkerConfigHandle::new(initial.clone()));
        let (config_tx, config_rx) = watch::channel(initial.version);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Dropping the sender makes `drain_started` pend forever, which is
        // what these non-drain tests want; the drain tests own their own harness.
        let (_drain_tx, drain_rx) = watch::channel(DrainState::NotDraining);
        let registry = ConnectionRegistry::new();
        let cluster_manager = cluster_manager_for(&initial).await;
        let stats_control = proxy_observability::stats::StatsControl::new(1);
        let stats = StatsRecorders {
            router: router_stats_for(&stats_control, &initial),
            downstream: downstream_stats_for(&stats_control, &initial),
            token: token_stats_for(&stats_control, &initial),
            latency: latency_stats_for(&stats_control),
            tracing: None,
            metadata: None,
            connection_limiter: crate::admission::ConnectionLimiter::default(),
        };
        let factory_state = Arc::new(SharedFactoryState::default());
        let secret_registry = Arc::new(SdsSecretRegistry::new());

        let bound = initial_bind(
            &initial,
            &config,
            &registry,
            &shutdown_rx,
            &drain_rx,
            &cluster_manager,
            &stats,
            &factory_state,
            &secret_registry,
        )
        .expect("initial_bind should succeed in tests");

        let manager = tokio::task::spawn_local(run_listener_manager(
            bound,
            config.clone(),
            config_rx,
            shutdown_rx,
            drain_rx,
            Arc::new(LifecycleState::new()),
            registry.clone(),
            cluster_manager,
            stats,
            factory_state,
            secret_registry,
        ));

        Harness {
            config,
            config_tx,
            shutdown_tx,
            registry,
            manager,
            stats_control,
        }
    }

    impl Harness {
        /// The Envoy `/stats` text for everything this harness's workers recorded.
        fn stats(&self) -> String {
            proxy_observability::stats::envoy_render::render(&self.stats_control.registry())
        }

        /// The value `stats()` renders for `name`, or `None` if absent.
        fn counter(&self, name: &str) -> Option<u64> {
            let prefix = format!("{name}: ");
            self.stats()
                .lines()
                .find_map(|line| line.strip_prefix(prefix.as_str())?.parse().ok())
        }

        fn publish(&self, snapshot: Arc<ConfigSnapshot>) {
            self.config.store(snapshot.clone());
            let _ = self.config_tx.send(snapshot.version);
        }

        async fn shutdown(self) {
            let _ = self.shutdown_tx.send(true);
            self.manager.await.expect("listener manager task panicked");
        }
    }

    #[test]
    fn accept_and_match_keeps_connection_open() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let listener_ir = match_all_listener("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            // Give the accept loop a moment to actually bind.
            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            stream.write_all(b"hello").await.unwrap();

            // No EOF within ~100ms: the connection is being held open by the
            // stub handler, not immediately closed.
            let mut buf = [0u8; 8];
            let result =
                tokio::time::timeout(Duration::from_millis(100), stream.read(&mut buf)).await;
            assert!(
                result.is_err(),
                "expected read to time out (connection held open), got {result:?}"
            );

            harness.shutdown().await;
        });
    }

    #[test]
    fn no_match_closes_with_reset() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = sni_only_listener("l1", addr, "unused");
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");

            let mut buf = [0u8; 8];
            let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) => {} // clean EOF is acceptable too, platform-dependent
                Ok(Err(err)) => {
                    assert!(
                        matches!(err.kind(), ErrorKind::ConnectionReset | ErrorKind::Other)
                            || err.raw_os_error().is_some(),
                        "expected a reset-ish error, got {err:?}"
                    );
                }
                other => panic!("expected immediate EOF/reset, got {other:?}"),
            }

            harness.shutdown().await;
        });
    }

    #[test]
    fn tls_inspector_sni_match_keeps_connection_open() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let listener_ir = sni_only_listener_with_tls_inspector("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            let hello = client_hello_bytes("example.com");
            stream.write_all(&hello).await.unwrap();

            // Matched (SNI == example.com): held open by the stub handler.
            let mut buf = [0u8; 8];
            let result =
                tokio::time::timeout(Duration::from_millis(200), stream.read(&mut buf)).await;
            assert!(
                result.is_err(),
                "expected read to time out (connection held open on SNI match), got {result:?}"
            );

            harness.shutdown().await;
        });
    }

    #[test]
    fn tls_inspector_sni_mismatch_closes_with_reset() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = sni_only_listener_with_tls_inspector("l1", addr, "unused");
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            let hello = client_hello_bytes("other.com");
            stream.write_all(&hello).await.unwrap();

            let mut buf = [0u8; 8];
            let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) => {} // clean EOF is acceptable too, platform-dependent
                Ok(Err(err)) => {
                    assert!(
                        matches!(err.kind(), ErrorKind::ConnectionReset | ErrorKind::Other)
                            || err.raw_os_error().is_some(),
                        "expected a reset-ish error, got {err:?}"
                    );
                }
                other => panic!("expected immediate EOF/reset, got {other:?}"),
            }

            harness.shutdown().await;
        });
    }

    #[test]
    fn tls_inspector_plaintext_connection_closes_with_reset() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = sni_only_listener_with_tls_inspector("l1", addr, "unused");
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

            // Not TLS at all, so tls_inspector reports it as plaintext --
            // the sni-only chain never matches raw_buffer connections.
            let mut buf = [0u8; 8];
            let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) => {}
                Ok(Err(err)) => {
                    assert!(
                        matches!(err.kind(), ErrorKind::ConnectionReset | ErrorKind::Other)
                            || err.raw_os_error().is_some(),
                        "expected a reset-ish error, got {err:?}"
                    );
                }
                other => panic!("expected immediate EOF/reset, got {other:?}"),
            }

            harness.shutdown().await;
        });
    }

    #[test]
    fn chain_update_without_rebind_applies_to_new_connections_only() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let v1 = match_all_listener("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                v1,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            // Held connection under v1 (match-all chain).
            let mut held = TcpStream::connect(addr)
                .await
                .expect("connect should succeed under v1");

            // Give the accept loop a chance to actually accept and match
            // this connection *before* publishing v2 below -- otherwise the
            // server-side accept (which runs on this same executor) could be
            // scheduled after the config swap and match under v2 instead,
            // which is not what this test is exercising.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                harness.registry.live(),
                1,
                "held connection should be registered"
            );

            // Publish v2: same name/address, but now the only chain requires
            // SNI -- so it never matches a raw connection. No rebind should
            // happen (v1's accept loop keeps running).
            let v2 = sni_only_listener("l1", addr, "unused");
            harness.publish(snapshot_with(v2, 2));
            tokio::time::sleep(Duration::from_millis(50)).await;

            // The connection held from before the config change stays open
            // (it matched under v1's snapshot and its handler doesn't
            // re-evaluate the match).
            let mut buf = [0u8; 8];
            let result =
                tokio::time::timeout(Duration::from_millis(100), held.read(&mut buf)).await;
            assert!(result.is_err(), "pre-existing connection should stay open");

            // A brand new connection now observes v2's behavior: no match,
            // closed immediately.
            let mut fresh = TcpStream::connect(addr)
                .await
                .expect("connect should still succeed (socket still bound)");
            let result = tokio::time::timeout(Duration::from_secs(1), fresh.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => {
                    panic!("expected new connection to observe v2's no-match close, got {other:?}")
                }
            }

            harness.shutdown().await;
        });
    }

    #[test]
    fn address_replacement_serves_new_listener_and_drains_existing_connection() {
        run_local(async {
            let old_port = free_port().await;
            let old_addr: SocketAddr = format!("127.0.0.1:{old_port}").parse().unwrap();
            let new_port = free_port().await;
            let new_addr: SocketAddr = format!("127.0.0.1:{new_port}").parse().unwrap();
            let upstream_addr = spawn_echo_upstream().await;
            let harness = spawn_manager(snapshot_with_cluster(
                match_all_listener("l1", old_addr, "up"),
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut held = TcpStream::connect(old_addr)
                .await
                .expect("old listener should accept before replacement");
            held.write_all(b"before").await.unwrap();
            let mut before = [0_u8; 6];
            held.read_exact(&mut before).await.unwrap();
            assert_eq!(&before, b"before");

            harness.publish(snapshot_with_cluster(
                match_all_listener("l1", new_addr, "up"),
                static_cluster("up", upstream_addr),
                2,
            ));
            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut fresh = TcpStream::connect(new_addr)
                .await
                .expect("warmed replacement listener should accept");
            fresh.write_all(b"new").await.unwrap();
            let mut new_response = [0_u8; 3];
            fresh.read_exact(&mut new_response).await.unwrap();
            assert_eq!(&new_response, b"new");

            // Replacing the accept loop must not abort a connection it handed
            // off before the swap.
            held.write_all(b"drained").await.unwrap();
            let mut drained = [0_u8; 7];
            held.read_exact(&mut drained).await.unwrap();
            assert_eq!(&drained, b"drained");

            harness.shutdown().await;
        });
    }

    #[test]
    fn same_address_listener_rename_warms_replacement_before_retiring_old_name() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_echo_upstream().await;
            let harness = spawn_manager(snapshot_with_cluster(
                match_all_listener("old-name", addr, "up"),
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;
            harness.publish(snapshot_with_cluster(
                match_all_listener("new-name", addr, "up"),
                static_cluster("up", upstream_addr),
                2,
            ));
            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut fresh = TcpStream::connect(addr)
                .await
                .expect("same-address renamed listener should accept");
            fresh.write_all(b"renamed").await.unwrap();
            let mut response = [0_u8; 7];
            fresh.read_exact(&mut response).await.unwrap();
            assert_eq!(&response, b"renamed");

            harness.shutdown().await;
        });
    }

    #[test]
    fn failed_address_replacement_keeps_previous_listener_accepting() {
        run_local(async {
            let old_port = free_port().await;
            let old_addr: SocketAddr = format!("127.0.0.1:{old_port}").parse().unwrap();
            // A plain Tokio listener does not opt into SO_REUSEPORT, so it
            // makes the replacement address unavailable to proxy-core's
            // SO_REUSEPORT listener socket.
            let occupied = TokioTcpListener::bind("127.0.0.1:0")
                .await
                .expect("occupy replacement address");
            let occupied_addr = occupied.local_addr().unwrap();
            let upstream_addr = spawn_echo_upstream().await;
            let harness = spawn_manager(snapshot_with_cluster(
                match_all_listener("l1", old_addr, "up"),
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;
            harness.publish(snapshot_with_cluster(
                match_all_listener("l1", occupied_addr, "up"),
                static_cluster("up", upstream_addr),
                2,
            ));
            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut old = TcpStream::connect(old_addr)
                .await
                .expect("old listener must remain after replacement warm-up failure");
            old.write_all(b"still-live").await.unwrap();
            let mut echoed = [0_u8; 10];
            old.read_exact(&mut echoed).await.unwrap();
            assert_eq!(&echoed, b"still-live");

            drop(occupied);
            harness.shutdown().await;
        });
    }

    #[test]
    fn listener_removal_stops_new_accepts_but_keeps_existing_open() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let v1 = match_all_listener("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                v1,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut held = TcpStream::connect(addr)
                .await
                .expect("connect should succeed before removal");

            // See the equivalent comment in
            // `chain_update_without_rebind_applies_to_new_connections_only`:
            // give the accept loop a chance to accept+match this connection
            // before the listener is removed out from under it.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                harness.registry.live(),
                1,
                "held connection should be registered"
            );

            // Publish a snapshot with no listeners at all.
            let snapshot_v2 = Arc::new(ConfigSnapshot {
                version: SnapshotVersion(2),
                ..Default::default()
            });
            harness.publish(snapshot_v2);
            tokio::time::sleep(Duration::from_millis(50)).await;

            // New connect attempts fail: nothing is listening anymore.
            let connect_result =
                tokio::time::timeout(Duration::from_millis(200), TcpStream::connect(addr)).await;
            match connect_result {
                Ok(Err(_)) => {} // refused, as expected
                Err(_) => {}     // timed out trying to connect -- also fine
                Ok(Ok(_)) => panic!("expected connect to fail after listener removal"),
            }

            // The pre-existing connection is untouched.
            let mut buf = [0u8; 8];
            let result =
                tokio::time::timeout(Duration::from_millis(100), held.read(&mut buf)).await;
            assert!(result.is_err(), "pre-existing connection should stay open");

            harness.shutdown().await;
        });
    }

    // --- downstream TLS termination in the accept path -----

    fn tls_params() -> TlsParametersIR {
        TlsParametersIR {
            min_version: TlsVersion::V1_2,
            max_version: TlsVersion::V1_3,
            cipher_suites: vec![],
            ecdh_curves: vec![],
        }
    }

    fn tls_cert_ir(cert: &rcgen::Certificate, key: &KeyPair) -> TlsCertificateIR {
        TlsCertificateIR {
            cert_chain: DataSourceIR::Inline(cert.pem()),
            private_key: DataSourceIR::Inline(key.serialize_pem()),
        }
    }

    /// Mint a self-signed leaf for `name` -- good enough for these tests,
    /// which check that the *right* factory served the connection (matching
    /// cert bytes / a completed handshake), not chain-of-trust validation
    /// (already covered by `proxy-core/tests/tls.rs`).
    fn mint_self_signed(name: &str) -> (rcgen::Certificate, KeyPair) {
        let key = KeyPair::generate().expect("ecdsa keygen");
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.self_signed(&key).expect("self-sign");
        (cert, key)
    }

    fn downstream_tls_spec(cert: &rcgen::Certificate, key: &KeyPair) -> DownstreamTlsSpec {
        DownstreamTlsSpec {
            certificate_sds_names: Vec::new(),
            certificates: vec![tls_cert_ir(cert, key)],
            params: tls_params(),
            alpn_protocols: vec![],
            validation: None,
            validation_sds_name: None,
            require_client_certificate: false,
            disable_stateless_session_resumption: false,
        }
    }

    /// A single-chain listener (match-all) whose `transport_socket`
    /// terminates TLS with a freshly minted self-signed cert for `cn`, plus
    /// the `tls_inspector` listener filter (needed for chains that key on
    /// SNI; harmless for the match-all case too).
    fn tls_chain_listener(
        name: &str,
        addr: SocketAddr,
        cn: &str,
        cluster: &str,
    ) -> (IrListenerConfig, rcgen::Certificate) {
        let (cert, key) = mint_self_signed(cn);
        let listener = IrListenerConfig {
            listener_filters: vec![proxy_config::ir::ListenerFilterSpec::TlsInspector(
                proxy_config::ir::TlsInspectorConfig::default(),
            )],
            filter_chains: vec![FilterChainSpec {
                transport_socket_connect_timeout: None,
                name: Some("tls".to_string()),
                match_criteria: FilterChainMatch::default(),
                transport_socket: Some(downstream_tls_spec(&cert, &key)),
                filters: vec![tcp_proxy_filter(cluster)],
            }],
            ..match_all_listener(name, addr, cluster)
        };
        (listener, cert)
    }

    /// Two chains, each matching on a different SNI and terminating with its
    /// own cert.
    fn tls_dual_sni_listener(
        name: &str,
        addr: SocketAddr,
        host_a: &str,
        host_b: &str,
    ) -> (IrListenerConfig, rcgen::Certificate, rcgen::Certificate) {
        let (cert_a, key_a) = mint_self_signed(host_a);
        let (cert_b, key_b) = mint_self_signed(host_b);
        // No cluster backs either chain -- this fixture is only used to check
        // "which cert got served"/handshake completion, which is settled
        // before `tcp_proxy` even looks at the (nonexistent) cluster.
        let listener = IrListenerConfig {
            listener_filters: vec![proxy_config::ir::ListenerFilterSpec::TlsInspector(
                proxy_config::ir::TlsInspectorConfig::default(),
            )],
            filter_chains: vec![
                FilterChainSpec {
                    transport_socket_connect_timeout: None,
                    name: Some("a".to_string()),
                    match_criteria: FilterChainMatch {
                        server_names: vec![host_a.to_string()],
                        ..Default::default()
                    },
                    transport_socket: Some(downstream_tls_spec(&cert_a, &key_a)),
                    filters: vec![tcp_proxy_filter("unused")],
                },
                FilterChainSpec {
                    transport_socket_connect_timeout: None,
                    name: Some("b".to_string()),
                    match_criteria: FilterChainMatch {
                        server_names: vec![host_b.to_string()],
                        ..Default::default()
                    },
                    transport_socket: Some(downstream_tls_spec(&cert_b, &key_b)),
                    filters: vec![tcp_proxy_filter("unused")],
                },
            ],
            ..match_all_listener(name, addr, "unused")
        };
        (listener, cert_a, cert_b)
    }

    /// A bare client-side TLS factory that sends `sni` as its SNI extension
    /// and does no server-cert validation (these tests check "which cert got
    /// served"/"did the handshake complete", not chain-of-trust -- that's
    /// `proxy-core/tests/tls.rs`'s job).
    fn client_factory_with_sni(sni: &str) -> UpstreamTlsFactory {
        UpstreamTlsFactory::build(
            &UpstreamTlsSpec {
                sni: Some(sni.to_string()),
                params: tls_params(),
                alpn_protocols: vec![],
                client_certificate: None,
                validation: None,
            },
            "test client",
        )
        .expect("client factory should build")
    }

    /// Like [`client_factory_with_sni`], but with an explicit ALPN offer --
    /// the h2 dispatch test below needs to control exactly which
    /// protocol the client proposes (rather than none at all), unlike every
    /// pre-h2 TLS test in this module.
    fn client_factory_with_alpn(sni: &str, alpns: &[&str]) -> UpstreamTlsFactory {
        UpstreamTlsFactory::build(
            &UpstreamTlsSpec {
                sni: Some(sni.to_string()),
                params: tls_params(),
                alpn_protocols: alpns.iter().map(|s| s.to_string()).collect(),
                client_certificate: None,
                validation: None,
            },
            "test client",
        )
        .expect("client factory should build")
    }

    /// An `http_connection_manager` filter whose route table always returns a
    /// fixed-status `DirectResponse` -- the h2 dispatch tests below only
    /// care "did the right codec (h1 vs h2) serve this connection", not
    /// about routing, so this is deliberately simpler than
    /// [`hcm_filter_with_header_mutation`]. `codec_type` defaults to `Auto`
    /// (Envoy's default); see [`hcm_filter_direct_response_with_codec`] for
    /// the plaintext `codec_type` dispatch tests, which need to set it
    /// explicitly.
    fn hcm_filter_direct_response(status: u16) -> NetworkFilterSpec {
        hcm_filter_direct_response_with_codec(status, proxy_config::ir::CodecType::Auto)
    }

    /// See [`hcm_filter_direct_response`].
    fn hcm_filter_direct_response_with_codec(
        status: u16,
        codec_type: proxy_config::ir::CodecType,
    ) -> NetworkFilterSpec {
        NetworkFilterSpec::HttpConnectionManager(proxy_config::ir::HttpConnectionManagerConfig {
            stat_prefix: "test".to_string(),
            route_table: direct_response_route_table(status),
            rds_route_config_name: None,
            http_filters: vec![],
            codec_type,
            generate_request_id: true,
            use_remote_address: false,
            xff_num_trusted_hops: 0,
            access_logs: vec![],
            upgrade_configs: vec![],
            request_headers_timeout: None,
            request_timeout: None,
        })
    }

    /// The ALPN dispatch test, and the regression test for the
    /// bug [`downstream_codec_for_alpn`]'s doc comment describes: before that
    /// function existed, this listener unconditionally called `serve_http1`
    /// regardless of what ALPN negotiated, so an operator configuring
    /// `alpn_protocols: ["h2", ...]` on a downstream listener got a silent
    /// protocol violation (h2 negotiated with the client, h1 framing spoken
    /// on the wire).
    ///
    /// Verified at the wire-framing level rather than through a real h2
    /// client library: `proxy-core` deliberately carries no `hyper`/
    /// `http-body-util` dependency (see `spawn_http_upstream_chunked_json`'s
    /// doc comment for the established reasoning, which applies here too),
    /// so the h2 side of this test hand-writes the client connection preface
    /// (RFC 7540 S3.5: the `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` magic plus an
    /// empty SETTINGS frame) and asserts the server's first frame back is
    /// itself a SETTINGS frame at stream id 0 -- something only a real h2
    /// codec produces. `serve_http1`'s h1 parser has no notion of that
    /// framing at all (it would either error out on the `PRI * HTTP/2.0`
    /// request line or hang waiting for `\r\n\r\n`-terminated headers that
    /// never come in that shape), so this genuinely discriminates the two
    /// codecs rather than merely checking a config field was read.
    #[test]
    fn alpn_negotiated_protocol_selects_the_serving_codec() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let (cert, key) = mint_self_signed("alpn.example.com");
            let mut tls_spec = downstream_tls_spec(&cert, &key);
            tls_spec.alpn_protocols = vec!["h2".to_string(), "http/1.1".to_string()];
            let listener_ir = IrListenerConfig {
                filter_chains: vec![FilterChainSpec {
                    transport_socket_connect_timeout: None,
                    name: Some("tls-hcm".to_string()),
                    match_criteria: FilterChainMatch::default(),
                    transport_socket: Some(tls_spec),
                    filters: vec![hcm_filter_direct_response(200)],
                }],
                ..match_all_listener_with_filter("l1", addr, hcm_filter_direct_response(200))
            };
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            // -- h2 side: ALPN offers only "h2".
            let tcp = TcpStream::connect(addr).await.expect("h2 connect");
            let client_h2 = client_factory_with_alpn("alpn.example.com", &["h2"]);
            let mut tls_h2 = client_h2
                .wrap(tcp, "alpn.example.com")
                .await
                .expect("h2 ALPN handshake should complete");
            assert_eq!(
                tls_h2.get_ref().1.alpn_protocol(),
                Some(&b"h2"[..]),
                "client should have negotiated h2"
            );

            let mut preface = Vec::from(&b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"[..]);
            // An empty SETTINGS frame: 3-byte length (0), 1-byte type (0x4),
            // 1-byte flags (0x0), 4-byte stream id (0) -- RFC 7540 S4.1/S6.5.
            preface.extend_from_slice(&[0, 0, 0, 0x4, 0x0, 0, 0, 0, 0]);
            tls_h2
                .write_all(&preface)
                .await
                .expect("write h2 client preface");

            let mut frame_header = [0u8; 9];
            tokio::time::timeout(Duration::from_secs(2), tls_h2.read_exact(&mut frame_header))
                .await
                .expect("server should respond with its own frame before the timeout")
                .expect("read server's first frame header");
            assert_eq!(
                frame_header[3], 0x4,
                "server's first frame should be its own SETTINGS frame (h2 served), got: {frame_header:?}"
            );
            assert_eq!(
                &frame_header[5..9],
                &[0, 0, 0, 0],
                "SETTINGS is a connection-level frame (stream id 0), got: {frame_header:?}"
            );

            // -- h1 side: ALPN offers only "http/1.1".
            let tcp = TcpStream::connect(addr).await.expect("h1 connect");
            let client_h1 = client_factory_with_alpn("alpn.example.com", &["http/1.1"]);
            let mut tls_h1 = client_h1
                .wrap(tcp, "alpn.example.com")
                .await
                .expect("http/1.1 ALPN handshake should complete");
            assert_eq!(
                tls_h1.get_ref().1.alpn_protocol(),
                Some(&b"http/1.1"[..]),
                "client should have negotiated http/1.1"
            );

            tls_h1
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), tls_h1.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");
            let response = String::from_utf8(response).expect("response should be valid utf8");
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "expected an ordinary h1 status line (http/1.1 served), got: {response:?}"
            );

            harness.shutdown().await;
        });
    }

    /// The `h2` frame-body of an empty SETTINGS frame -- 3-byte length (0),
    /// 1-byte type (0x4), 1-byte flags (0x0), 4-byte stream id (0), per RFC
    /// 9113 S4.1/S6.5. Paired with [`H2_CLIENT_PREFACE`], this is a complete,
    /// valid client connection preface (RFC 9113 S3.4) -- shared by the
    /// plaintext dispatch tests below, same bytes
    /// `alpn_negotiated_protocol_selects_the_serving_codec` hand-writes
    /// inline for the TLS/ALPN case.
    const EMPTY_SETTINGS_FRAME: [u8; 9] = [0, 0, 0, 0x4, 0x0, 0, 0, 0, 0];

    /// `true` if `frame_header` (the first 9 bytes read back from a
    /// connection) is itself a SETTINGS frame at stream id 0 -- something
    /// only a real h2 codec produces as its first frame. Shared by the
    /// plaintext dispatch tests below.
    fn looks_like_a_settings_frame_at_stream_zero(frame_header: &[u8]) -> bool {
        frame_header.len() >= 9 && frame_header[3] == 0x4 && frame_header[5..9] == [0, 0, 0, 0]
    }

    /// Read whatever arrives on `stream` within `wait`, or an empty `Vec` if
    /// nothing does (EOF, a reset, or the bound elapsing first) -- for
    /// dispatch tests that need to assert a *negative* ("this was not served
    /// as h1"/"this was not served as h2"), where the failure mode on the
    /// wrong codec is usually a closed connection or a protocol-level error
    /// frame rather than a clean, parseable response.
    async fn read_whatever_arrives(stream: &mut TcpStream, wait: Duration) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        match tokio::time::timeout(wait, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => Vec::new(),
            Ok(Ok(n)) => buf[..n].to_vec(),
            Ok(Err(_)) => Vec::new(),
        }
    }

    /// `codec_type: AUTO` (the default) on a **plaintext** connection
    /// has no ALPN to consult -- see [`resolve_plaintext_codec`]'s doc. This
    /// is the plaintext counterpart of
    /// `alpn_negotiated_protocol_selects_the_serving_codec`: same
    /// discrimination technique (an h2 client preface for one connection, an
    /// ordinary h1 request line for the other, on the SAME listener), just
    /// without TLS/ALPN in the picture at all.
    #[test]
    fn plaintext_codec_auto_detects_h2_prior_knowledge_and_an_ordinary_h1_request() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = match_all_listener_with_filter(
                "l1",
                addr,
                hcm_filter_direct_response_with_codec(200, CodecType::Auto),
            );
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            // -- h2 side: prior-knowledge preface, no ALPN/TLS involved.
            let mut stream = TcpStream::connect(addr).await.expect("h2 connect");
            let mut preface = Vec::from(&H2_CLIENT_PREFACE[..]);
            preface.extend_from_slice(&EMPTY_SETTINGS_FRAME);
            stream.write_all(&preface).await.expect("write preface");

            let mut frame_header = [0u8; 9];
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut frame_header))
                .await
                .expect("server should respond with its own frame before the timeout")
                .expect("read server's first frame header");
            assert!(
                looks_like_a_settings_frame_at_stream_zero(&frame_header),
                "server's first frame should be its own SETTINGS frame (h2 served), got: {frame_header:?}"
            );

            // -- h1 side: an ordinary request line, same listener.
            let mut stream = TcpStream::connect(addr).await.expect("h1 connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");
            let response = String::from_utf8(response).expect("response should be valid utf8");
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "expected an ordinary h1 status line (http/1.1 served), got: {response:?}"
            );

            harness.shutdown().await;
        });
    }

    /// `codec_type: HTTP2` is unconditional -- `serve_http2` is used
    /// even for a request that, under `AUTO`, would have been detected as h1
    /// (see `plaintext_codec_auto_detects_h2_prior_knowledge_and_an_ordinary_h1_request`'s
    /// h1 side, which sends the exact same bytes against the same fixture
    /// and gets a clean 200). This is the test that would catch a regression
    /// where an explicit `codec_type` silently fell back to `AUTO`'s peek
    /// instead of skipping it.
    #[test]
    fn plaintext_codec_type_http2_serves_h2_unconditionally() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = match_all_listener_with_filter(
                "l1",
                addr,
                hcm_filter_direct_response_with_codec(200, CodecType::Http2),
            );
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            // -- positive: a real h2 client (real preface) is served h2.
            let mut stream = TcpStream::connect(addr).await.expect("h2 connect");
            let mut preface = Vec::from(&H2_CLIENT_PREFACE[..]);
            preface.extend_from_slice(&EMPTY_SETTINGS_FRAME);
            stream.write_all(&preface).await.expect("write preface");
            let mut frame_header = [0u8; 9];
            tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut frame_header))
                .await
                .expect("server should respond with its own frame before the timeout")
                .expect("read server's first frame header");
            assert!(
                looks_like_a_settings_frame_at_stream_zero(&frame_header),
                "codec_type: HTTP2 should serve a real h2 client as h2, got: {frame_header:?}"
            );

            // -- discriminating: an ordinary h1 request line must NOT get an
            // ordinary h1 response -- `AUTO` would have peeked, seen no
            // preface, and answered "HTTP/1.1 200"; an unconditional HTTP2
            // must not.
            let mut stream = TcpStream::connect(addr).await.expect("h1 connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let response = read_whatever_arrives(&mut stream, Duration::from_millis(500)).await;
            assert!(
                !response.starts_with(b"HTTP/1.1"),
                "codec_type: HTTP2 must not serve an h1-shaped request as h1, got: {response:?}"
            );

            harness.shutdown().await;
        });
    }

    /// `codec_type: HTTP1` is unconditional -- `serve_http1` is used
    /// "even when a preface is present" (Envoy's wording for an explicit codec).
    /// Mirrors `plaintext_codec_type_http2_serves_h2_unconditionally`, with
    /// the codec and the discriminating payload swapped.
    #[test]
    fn plaintext_codec_type_http1_serves_h1_unconditionally() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = match_all_listener_with_filter(
                "l1",
                addr,
                hcm_filter_direct_response_with_codec(200, CodecType::Http1),
            );
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            // -- positive: an ordinary h1 request is served h1.
            let mut stream = TcpStream::connect(addr).await.expect("h1 connect");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");
            let response = String::from_utf8(response).expect("response should be valid utf8");
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "expected an ordinary h1 status line, got: {response:?}"
            );

            // -- discriminating: a full, valid h2 client preface must NOT get
            // an h2 SETTINGS frame back -- `AUTO` would have peeked, seen the
            // preface, and answered with its own SETTINGS frame; an
            // unconditional HTTP1 must not.
            let mut stream = TcpStream::connect(addr).await.expect("h2-shaped connect");
            let mut preface = Vec::from(&H2_CLIENT_PREFACE[..]);
            preface.extend_from_slice(&EMPTY_SETTINGS_FRAME);
            stream.write_all(&preface).await.expect("write preface");
            let response = read_whatever_arrives(&mut stream, Duration::from_millis(500)).await;
            assert!(
                !looks_like_a_settings_frame_at_stream_zero(&response),
                "codec_type: HTTP1 must not serve a preface-bearing connection as h2, got: {response:?}"
            );

            harness.shutdown().await;
        });
    }

    #[test]
    fn tls_termination_handshake_completes_and_holds_connection() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let (listener_ir, _cert) = tls_chain_listener("l1", addr, "server.example.com", "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let tcp = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            let client = client_factory_with_sni("server.example.com");
            let mut tls = client
                .wrap(tcp, "server.example.com")
                .await
                .expect("TLS handshake should complete");

            tls.write_all(b"hello").await.unwrap();

            // No EOF within ~200ms: the handshake completed and the
            // connection is held open by the stub handler underneath the
            // TLS layer, exactly like the plaintext case.
            let mut buf = [0u8; 8];
            let result = tokio::time::timeout(Duration::from_millis(200), tls.read(&mut buf)).await;
            assert!(
                result.is_err(),
                "expected read to time out (connection held open after TLS termination), got {result:?}"
            );

            harness.shutdown().await;
        });
    }

    /// A match-all TLS listener on `addr` with the handshake deadline
    /// `timeout`, and a connection cap of one. The `tls_inspector` is dropped
    /// so a client that sends nothing stalls in the handshake itself.
    fn capped_tls_snapshot(
        addr: SocketAddr,
        upstream_addr: SocketAddr,
        timeout: Option<Duration>,
    ) -> Arc<ConfigSnapshot> {
        let (mut listener_ir, _cert) = tls_chain_listener("l1", addr, "server.example.com", "up");
        listener_ir.listener_filters.clear();
        listener_ir.filter_chains[0].transport_socket_connect_timeout = timeout;
        let cluster = static_cluster("up", upstream_addr);
        Arc::new(ConfigSnapshot {
            listeners: HashMap::from([(listener_ir.name.clone(), Arc::new(listener_ir))]),
            clusters: HashMap::from([(cluster.name.clone(), Arc::new(cluster))]),
            version: SnapshotVersion(1),
            max_downstream_connections: Some(1),
            ..Default::default()
        })
    }

    /// True once the peer has closed `stream` (EOF or reset), bounded so a
    /// connection that is never closed fails the test instead of hanging it.
    async fn closed_within(stream: &mut TcpStream, bound: Duration) -> bool {
        let mut buf = [0u8; 8];
        match tokio::time::timeout(bound, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => true,
            Ok(Ok(_)) | Err(_) => false,
        }
    }

    const HANDSHAKE_TIMEOUT_STAT: &str =
        "listener.l1.downstream_cx_transport_socket_connect_timeout";

    #[test]
    fn stalled_tls_handshake_is_closed_at_the_deadline_and_frees_the_slot() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let harness = spawn_manager(capped_tls_snapshot(
                addr,
                upstream_addr,
                Some(Duration::from_secs(1)),
            ))
            .await;
            tokio::time::sleep(Duration::from_millis(50)).await;

            // A client that connects and never sends a byte holds the only slot.
            let mut stalled = TcpStream::connect(addr).await.expect("connect");
            tokio::time::sleep(Duration::from_millis(100)).await;

            // The cap is full, so a second connection is closed on accept.
            let mut overflow = TcpStream::connect(addr).await.expect("connect");
            assert!(
                closed_within(&mut overflow, Duration::from_millis(500)).await,
                "the second connection should be refused while the first holds the slot"
            );

            // The proxy, not the client, ends the stalled handshake, and
            // counts it once. The overflow connection never reached a
            // handshake, so it is not counted.
            assert!(
                closed_within(&mut stalled, Duration::from_secs(5)).await,
                "a stalled TLS handshake must be closed by the handshake deadline"
            );
            assert_eq!(harness.counter(HANDSHAKE_TIMEOUT_STAT), Some(1));

            // The slot is free again: a real TLS client completes a handshake.
            let tcp = TcpStream::connect(addr).await.expect("connect");
            let client = client_factory_with_sni("server.example.com");
            tokio::time::timeout(
                Duration::from_secs(5),
                client.wrap(tcp, "server.example.com"),
            )
            .await
            .expect("handshake should not stall")
            .expect("TLS handshake should complete after the slot is freed");

            harness.shutdown().await;
        });
    }

    #[test]
    fn handshake_deadline_does_not_apply_after_the_handshake_completes() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let harness = spawn_manager(capped_tls_snapshot(
                addr,
                upstream_addr,
                Some(Duration::from_millis(300)),
            ))
            .await;
            tokio::time::sleep(Duration::from_millis(50)).await;

            let tcp = TcpStream::connect(addr).await.expect("connect");
            let client = client_factory_with_sni("server.example.com");
            let mut tls = tokio::time::timeout(
                Duration::from_secs(5),
                client.wrap(tcp, "server.example.com"),
            )
            .await
            .expect("handshake should not stall")
            .expect("TLS handshake should complete");

            // Stay connected well past the handshake deadline: the open
            // session must not be cut by it.
            let mut buf = [0u8; 8];
            let held = tokio::time::timeout(Duration::from_millis(900), tls.read(&mut buf)).await;
            assert!(
                held.is_err(),
                "a completed handshake must outlive the handshake deadline, got {held:?}"
            );
            assert_eq!(harness.counter(HANDSHAKE_TIMEOUT_STAT), Some(0));

            harness.shutdown().await;
        });
    }

    #[test]
    fn handshake_deadline_defaults_when_unset_and_zero_disables_it() {
        let mut chain = FilterChainSpec {
            transport_socket_connect_timeout: None,
            name: None,
            match_criteria: FilterChainMatch::default(),
            transport_socket: None,
            filters: vec![],
        };
        assert_eq!(
            tls_handshake_deadline(&chain),
            Some(DEFAULT_TLS_HANDSHAKE_TIMEOUT)
        );
        chain.transport_socket_connect_timeout = Some(Duration::from_secs(3));
        assert_eq!(tls_handshake_deadline(&chain), Some(Duration::from_secs(3)));
        chain.transport_socket_connect_timeout = Some(Duration::ZERO);
        assert_eq!(tls_handshake_deadline(&chain), None);
    }

    #[test]
    fn sni_selects_matching_chain_and_serves_its_certificate() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let (listener_ir, cert_a, cert_b) =
                tls_dual_sni_listener("l1", addr, "host-a.example.com", "host-b.example.com");
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let tcp_a = TcpStream::connect(addr).await.expect("connect (a) failed");
            let client_a = client_factory_with_sni("host-a.example.com");
            let tls_a = client_a
                .wrap(tcp_a, "host-a.example.com")
                .await
                .expect("handshake for host-a should complete");
            let peer_a = tls_a
                .get_ref()
                .1
                .peer_certificates()
                .expect("peer certs present")[0]
                .as_ref()
                .to_vec();
            assert_eq!(
                peer_a,
                cert_a.der().as_ref(),
                "SNI host-a should be served cert A"
            );

            let tcp_b = TcpStream::connect(addr).await.expect("connect (b) failed");
            let client_b = client_factory_with_sni("host-b.example.com");
            let tls_b = client_b
                .wrap(tcp_b, "host-b.example.com")
                .await
                .expect("handshake for host-b should complete");
            let peer_b = tls_b
                .get_ref()
                .1
                .peer_certificates()
                .expect("peer certs present")[0]
                .as_ref()
                .to_vec();
            assert_eq!(
                peer_b,
                cert_b.der().as_ref(),
                "SNI host-b should be served cert B"
            );

            harness.shutdown().await;
        });
    }

    #[test]
    fn build_listener_tls_fails_for_bad_cert() {
        let mut listener_ir = match_all_listener(
            "bad-cert-listener",
            "127.0.0.1:0".parse().unwrap(),
            "unused",
        );
        listener_ir.filter_chains[0].transport_socket = Some(DownstreamTlsSpec {
            certificate_sds_names: Vec::new(),
            certificates: vec![TlsCertificateIR {
                cert_chain: DataSourceIR::Inline("not a certificate".to_string()),
                private_key: DataSourceIR::Inline("not a key".to_string()),
            }],
            params: tls_params(),
            alpn_protocols: vec![],
            validation: None,
            validation_sds_name: None,
            require_client_certificate: false,
            disable_stateless_session_resumption: false,
        });

        let secret_registry = Arc::new(SdsSecretRegistry::new());
        let err = match build_listener_tls(&listener_ir, &secret_registry) {
            Ok(_) => panic!("garbage PEM must fail to build"),
            Err(err) => err,
        };
        assert!(
            err.context.contains("bad-cert-listener"),
            "error should name the listener that failed: {err}"
        );
    }

    #[test]
    fn initial_bind_propagates_a_tls_build_failure_as_fatal() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let mut listener_ir = match_all_listener("l1", addr, "unused");
            listener_ir.filter_chains[0].transport_socket = Some(DownstreamTlsSpec {
                certificate_sds_names: Vec::new(),
                certificates: vec![TlsCertificateIR {
                    cert_chain: DataSourceIR::Inline("garbage".to_string()),
                    private_key: DataSourceIR::Inline("garbage".to_string()),
                }],
                params: tls_params(),
                alpn_protocols: vec![],
                validation: None,
                validation_sds_name: None,
                require_client_certificate: false,
                disable_stateless_session_resumption: false,
            });

            let snapshot = snapshot_with(listener_ir, 1);
            let config = Arc::new(WorkerConfigHandle::new(snapshot.clone()));
            let registry = ConnectionRegistry::new();
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            let (_drain_tx, drain_rx) = watch::channel(DrainState::NotDraining);
            let cluster_manager = cluster_manager_for(&snapshot).await;
            let stats_control = proxy_observability::stats::StatsControl::new(1);
            let stats = StatsRecorders {
                router: router_stats_for(&stats_control, &snapshot),
                downstream: downstream_stats_for(&stats_control, &snapshot),
                token: token_stats_for(&stats_control, &snapshot),
                latency: latency_stats_for(&stats_control),
                tracing: None,
                metadata: None,
                connection_limiter: crate::admission::ConnectionLimiter::default(),
            };
            let factory_state = Arc::new(SharedFactoryState::default());
            let secret_registry = Arc::new(SdsSecretRegistry::new());

            let result = initial_bind(
                &snapshot,
                &config,
                &registry,
                &shutdown_rx,
                &drain_rx,
                &cluster_manager,
                &stats,
                &factory_state,
                &secret_registry,
            );
            match result {
                Err(err @ InitialBindError::Tls(_)) => {
                    // Also asserts `Display` works end to end -- this is
                    // exactly what `crates/proxy`'s startup path prints.
                    assert!(err.to_string().contains("TLS config error"));
                }
                Err(InitialBindError::Bind { .. }) => {
                    panic!("expected a TLS build failure, got a bind failure instead")
                }
                Err(InitialBindError::Http(err)) => {
                    panic!("expected a TLS build failure, got an HTTP filter chain build failure instead: {err}")
                }
                Ok(_) => panic!("a bad cert must fail initial_bind, not silently bind plaintext"),
            }
        });
    }

    // --- tcp_proxy runtime ------------------------------------------

    #[test]
    fn tcp_proxy_bidirectional_round_trip() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_echo_upstream().await;
            let listener_ir = match_all_listener("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");

            // A multi-KB payload, larger than a single TCP segment/read, to
            // exercise the pump across several read/write cycles.
            let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
            stream.write_all(&payload).await.unwrap();

            let mut echoed = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
                .await
                .expect("read should not time out")
                .expect("read_exact should succeed");
            assert_eq!(echoed, payload, "echoed bytes should match exactly");

            harness.shutdown().await;
        });
    }

    #[test]
    fn tcp_proxy_large_bidirectional_transfer_does_not_deadlock() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_echo_upstream().await;
            let listener_ir = match_all_listener("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");

            // A payload much larger than any socket send/recv buffer, so BOTH
            // directions apply backpressure at once (the client is pushing 8
            // MiB up while the echo pushes 8 MiB back). A pump that serializes
            // read+write within one direction deadlocks here -- we're parked
            // writing to the upstream while never draining its echo, and it's
            // parked writing the echo while never draining us. The client must
            // therefore also read and write concurrently (split halves), or it
            // would deadlock itself the same way.
            let payload: Vec<u8> = (0..8 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
            let (mut read_half, mut write_half) = stream.into_split();

            let writer = {
                let payload = payload.clone();
                tokio::task::spawn_local(async move {
                    write_half.write_all(&payload).await.unwrap();
                    // FIN so the echo upstream sees EOF and stops after the
                    // last byte comes back.
                    write_half.shutdown().await.unwrap();
                })
            };

            let mut echoed = vec![0u8; payload.len()];
            // Generous ceiling: a deadlock manifests as this timing out.
            tokio::time::timeout(Duration::from_secs(20), read_half.read_exact(&mut echoed))
                .await
                .expect("large bidirectional transfer should not deadlock")
                .expect("read_exact should succeed");
            writer.await.unwrap();
            assert_eq!(echoed, payload, "all 8 MiB should round-trip byte-exact");

            harness.shutdown().await;
        });
    }

    #[test]
    fn tcp_proxy_upstream_to_downstream_independent_of_client_writes() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

            // A dedicated upstream that speaks first, unprompted -- proves
            // the upstream -> downstream direction works on its own, not
            // just as an echo of what the client sent.
            let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_addr = listener.local_addr().unwrap();
            tokio::task::spawn_local(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let _ = stream.write_all(b"hello from upstream").await;
                    std::future::pending::<()>().await;
                }
            });

            let listener_ir = match_all_listener("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");

            let mut buf = [0u8; 32];
            let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                .await
                .expect("read should not time out")
                .expect("read should succeed");
            assert_eq!(&buf[..n], b"hello from upstream");

            harness.shutdown().await;
        });
    }

    #[test]
    fn tcp_proxy_half_close_propagates_fin_without_killing_other_direction() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();

            let (eof_tx, eof_rx) = tokio::sync::oneshot::channel();
            let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_addr = listener.local_addr().unwrap();
            tokio::task::spawn_local(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = [0u8; 1024];
                    let mut received = Vec::new();
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => received.extend_from_slice(&buf[..n]),
                            Err(_) => break,
                        }
                    }
                    // Downstream's write half is closed (FIN seen): report
                    // it, then prove the reverse direction is still usable by
                    // sending a reply before this end closes too.
                    let _ = eof_tx.send(received);
                    let _ = stream.write_all(b"bye").await;
                }
            });

            let listener_ir = match_all_listener("l1", addr, "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            stream.write_all(b"hello upstream").await.unwrap();
            stream.shutdown().await.unwrap();

            let received = tokio::time::timeout(Duration::from_secs(2), eof_rx)
                .await
                .expect("upstream should observe EOF promptly")
                .expect("sender should not be dropped");
            assert_eq!(received, b"hello upstream");

            // The reverse direction is still open even though downstream's
            // write half is closed: the client should still receive
            // upstream's reply.
            let mut buf = [0u8; 8];
            let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                .await
                .expect("read should not time out")
                .expect("read should succeed");
            assert_eq!(&buf[..n], b"bye");

            harness.shutdown().await;
        });
    }

    #[test]
    fn tcp_proxy_idle_timeout_closes_connection_after_inactivity() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_holding_upstream().await;
            let listener_ir = match_all_listener_with_filter(
                "l1",
                addr,
                tcp_proxy_filter_with_idle("up", Some(Duration::from_millis(200))),
            );
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");

            // No traffic at all: the idle timer should close the connection
            // well within a couple of timeout windows.
            let mut buf = [0u8; 8];
            let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => panic!("expected the connection to close after idling, got {other:?}"),
            }

            harness.shutdown().await;
        });
    }

    #[test]
    fn tcp_proxy_idle_timeout_does_not_close_connection_with_active_traffic() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_echo_upstream().await;
            let listener_ir = match_all_listener_with_filter(
                "l1",
                addr,
                tcp_proxy_filter_with_idle("up", Some(Duration::from_millis(200))),
            );
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");

            // Ping-pong well past the idle timeout window; each round trip
            // resets the idle clock, so the connection must stay open the
            // whole time.
            for _ in 0..6 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                stream.write_all(b"ping").await.unwrap();
                let mut buf = [0u8; 4];
                tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut buf))
                    .await
                    .expect("read should not time out while traffic is active")
                    .expect("read_exact should succeed");
                assert_eq!(&buf, b"ping");
            }

            harness.shutdown().await;
        });
    }

    #[test]
    fn tcp_proxy_missing_cluster_closes_connection_promptly() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            // No cluster in the snapshot at all: `nonexistent` never resolves.
            let listener_ir = match_all_listener("l1", addr, "nonexistent");
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed (the downstream accept happens regardless)");

            let mut buf = [0u8; 8];
            let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
            match result {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                other => panic!("expected a prompt close for a missing cluster, got {other:?}"),
            }

            harness.shutdown().await;
        });
    }

    #[test]
    fn tcp_proxy_over_downstream_tls_round_trips() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_addr = spawn_echo_upstream().await;
            let (listener_ir, _cert) = tls_chain_listener("l1", addr, "server.example.com", "up");
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let tcp = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            let client = client_factory_with_sni("server.example.com");
            let mut tls = client
                .wrap(tcp, "server.example.com")
                .await
                .expect("TLS handshake should complete");

            let payload = b"hello over tls tcp_proxy";
            tls.write_all(payload).await.unwrap();

            let mut echoed = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(2), tls.read_exact(&mut echoed))
                .await
                .expect("read should not time out")
                .expect("read_exact should succeed");
            assert_eq!(echoed, payload);

            harness.shutdown().await;
        });
    }

    // --- HCM terminal filter wired to the h1 codec ----

    /// `build_hcm_handler`'s terminal is a real
    /// `proxy_http::router::RouterHandler`, not a fixed-200 stub -- an empty
    /// route table (`hcm_filter`) means every request takes the
    /// `NoVirtualHost` path, a 404. This test now proves HTTP is served over
    /// the real socket *at all* (request parsed, response written back) --
    /// see `hcm_filter_chain_mutates_headers_over_the_real_socket` for a
    /// route that actually matches, and the router-forwarding test below for
    /// a route that forwards to a real upstream.
    #[test]
    fn hcm_terminal_filter_serves_http_over_the_real_socket() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = match_all_listener_with_filter("l1", addr, hcm_filter());
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            // `Connection: close` so the server (keep-alive is on by default)
            // closes after this response instead of idling open -- lets this
            // test read to EOF rather than needing to parse a Content-Length.
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");

            let response = String::from_utf8(response).expect("response should be valid utf8");
            assert!(
                response.starts_with("HTTP/1.1 404"),
                "expected a 404 status line (empty route table -> NoVirtualHost), got: {response:?}"
            );

            harness.shutdown().await;
        });
    }

    /// A listener whose HCM `http_filters` chain runs the built-in
    /// header-mutation filter (in config order, ahead of the terminal
    /// router) must show that filter's mutation in the actual response
    /// bytes over a real socket -- proof that `build_hcm_handler` builds a
    /// real `FilterChainHandler` against the shared `FilterRegistry`, with
    /// the real `RouterHandler` (not a stub) as its terminal.
    #[test]
    fn hcm_filter_chain_mutates_headers_over_the_real_socket() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = match_all_listener_with_filter(
                "l1",
                addr,
                hcm_filter_with_header_mutation("x-mutated-by-filter", "yes"),
            );
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");

            let response = String::from_utf8(response).expect("response should be valid utf8");
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "expected a 200 status line, got: {response:?}"
            );
            assert!(
                response
                    .to_ascii_lowercase()
                    .contains("x-mutated-by-filter: yes"),
                "expected the header-mutation filter's header in the response, got: {response:?}"
            );

            harness.shutdown().await;
        });
    }

    // --- router terminal + cluster-manager wiring -------------------

    /// A one-vhost, one-route table matching every request (`*` domain,
    /// empty-prefix path) with a `Forward` action targeting `cluster` --
    /// the counterpart to [`direct_response_route_table`] that actually
    /// exercises `RouterHandler::apply_forward`'s cluster-manager/pool path.
    fn forward_route_table(cluster: &str) -> Arc<proxy_config::ir::RouteTable> {
        use proxy_config::ir::{
            ForwardAction, ForwardTarget, PathMatch, RouteActionIR, RouteEntry, RouteMatcher,
            RouteTable, VirtualHostIR,
        };
        Arc::new(
            RouteTable::new(
                "test-routes".to_string(),
                vec![VirtualHostIR {
                    name: "vh".to_string(),
                    domains: vec!["*".to_string()],
                    routes: vec![Arc::new(RouteEntry {
                        name: None,
                        matcher: RouteMatcher {
                            path: PathMatch::Prefix(String::new()),
                            case_sensitive: true,
                            headers: vec![],
                        },
                        action: RouteActionIR::Forward(ForwardAction {
                            target: ForwardTarget::Cluster(cluster.to_string()),
                            timeout: None,
                            idle_timeout: None,
                            retry_policy: None,
                            host_rewrite_literal: None,
                            prefix_rewrite: None,
                        }),
                        request_headers_to_add: vec![],
                        streaming_strict: false,
                        typed_per_filter_config: BTreeMap::new(),
                        route_index: 0,
                        include_request_attempt_count: false,
                        include_attempt_count_in_response: false,
                    })],
                    typed_per_filter_config: BTreeMap::new(),
                }],
                BTreeMap::new(),
            )
            .expect("single vhost can't have duplicate domains"),
        )
    }

    /// Same shape as [`hcm_filter_with_header_mutation`], but its route table
    /// forwards to a real cluster instead of synthesizing a `DirectResponse`
    /// -- proving the router terminal actually dials an upstream, not just
    /// that the encode filter chain runs.
    fn hcm_filter_forward_with_header_mutation(
        header_name: &str,
        header_value: &str,
        cluster: &str,
    ) -> NetworkFilterSpec {
        use crate::header_mutation_filter::{header_value_option, TYPE_URL};
        NetworkFilterSpec::HttpConnectionManager(proxy_config::ir::HttpConnectionManagerConfig {
            stat_prefix: "test".to_string(),
            route_table: forward_route_table(cluster),
            rds_route_config_name: None,
            http_filters: vec![
                proxy_config::ir::HttpFilterSpec {
                    ext_authz: None,
                    name: "llmproxy.header_mutation".to_string(),
                    type_url: TYPE_URL.to_string(),
                    config: Some(header_value_option(header_name, header_value)),
                    is_router: false,
                },
                proxy_config::ir::HttpFilterSpec {
                    ext_authz: None,
                    name: "envoy.filters.http.router".to_string(),
                    type_url: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                        .to_string(),
                    config: None,
                    is_router: true,
                },
            ],
            codec_type: proxy_config::ir::CodecType::Auto,
            generate_request_id: true,
            use_remote_address: false,
            xff_num_trusted_hops: 0,
            access_logs: vec![],
            upgrade_configs: vec![],
            request_headers_timeout: None,
            request_timeout: None,
        })
    }

    /// Serve a fixed 200 response (a known body, no extra headers) over real
    /// HTTP/1.1 on a fresh ephemeral-port `TcpListener`, forever -- the "real
    /// upstream" fixture for the router-forwarding test below. Reuses
    /// `proxy_http`'s own downstream codec + `FixedResponseHandler` stub
    /// (exactly what `proxy-http`'s own tests use to fake an origin), so this
    /// isn't hand-rolled wire parsing.
    async fn spawn_http_upstream(body: &'static [u8]) -> SocketAddr {
        use proxy_http::handler::stub::FixedResponseHandler;
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn_local(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::task::spawn_local(async move {
                    let handler: Rc<dyn StreamHandler> = Rc::new(FixedResponseHandler {
                        status: http::StatusCode::OK,
                        headers: http::HeaderMap::new(),
                        body: bytes::Bytes::from_static(body),
                    });
                    let _ = serve_http1(
                        stream,
                        handler,
                        Http1Options {
                            keep_alive: false,
                            header_read_timeout: None,
                        },
                        std::future::pending(),
                        DownstreamInfo::loopback(),
                    )
                    .await;
                });
            }
        });
        addr
    }

    /// Like [`spawn_http_upstream`], but hand-writes a **chunked**
    /// `content-type: application/json` response over the raw socket instead
    /// of going through `serve_http1`/`FixedResponseHandler`.
    ///
    /// Rust note: this exists (rather than reusing `FixedResponseHandler`,
    /// whose body is an `http_body_util::Full` -- an exact-length body) for a
    /// load-bearing reason, not style: `Full`'s exact `size_hint()` makes
    /// hyper stamp an explicit `content-length` on *this* fixture's own
    /// response, which `RouterHandler` then forwards verbatim onto the
    /// downstream response. Once that header is on the wire, hyper's h1
    /// write-dispatcher (`Conn::can_write_body()`) stops polling our
    /// `StreamingEncoder` the instant it has written that many bytes -- it
    /// never issues the final empty `end_stream=true` frame the filter
    /// manager relies on to call `finalize()`. A chunked body (no
    /// content-length anywhere) doesn't hit that early-stop path, so the
    /// usage filter's end-of-stream write actually happens, which is the
    /// thing this whole test exists to observe. Writing raw chunked bytes by
    /// hand (rather than adding a `hyper`/`http-body` dependency to build a
    /// custom `Body` impl) keeps this fixture inside `proxy-core`'s existing
    /// dependency set.
    async fn spawn_http_upstream_chunked_json(body: &'static [u8]) -> SocketAddr {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn_local(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::task::spawn_local(async move {
                    // Drain the request up to the header/body separator --
                    // we don't care about its contents, just don't want a
                    // half-read request left sitting in the kernel buffer.
                    let mut buf = [0u8; 8192];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
                        body.len(),
                        String::from_utf8_lossy(body),
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    /// Acceptance test: a real HTTP request is routed (via the
    /// router terminal + `ClusterManager`) to a real upstream over HTTP/1.1,
    /// and the response still flows back through the encode filter chain --
    /// proving all three pieces (route match -> cluster/host pick -> upstream
    /// codec -> encode filters) work together over real sockets.
    ///
    /// Mutation-tested: reverting `build_hcm_handler`'s terminal to
    /// `FixedResponseHandler` (the earlier fixed-response stub) makes this fail, since the
    /// stub never contacts `upstream_addr` and never emits its body.
    #[test]
    fn router_forwards_a_real_request_to_a_real_upstream_over_http1() {
        run_local(async {
            let port = free_port().await;
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let upstream_body: &'static [u8] = b"hello from upstream";
            let upstream_addr = spawn_http_upstream(upstream_body).await;

            let listener_ir = match_all_listener_with_filter(
                "l1",
                addr,
                hcm_filter_forward_with_header_mutation("x-mutated-by-filter", "yes", "up"),
            );
            let harness = spawn_manager(snapshot_with_cluster(
                listener_ir,
                static_cluster("up", upstream_addr),
                1,
            ))
            .await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");

            let response = String::from_utf8(response).expect("response should be valid utf8");
            assert!(
                response.starts_with("HTTP/1.1 200"),
                "expected a 200 status line, got: {response:?}"
            );
            assert!(
                response.contains("hello from upstream"),
                "expected the real upstream's body in the response, got: {response:?}"
            );
            assert!(
                response
                    .to_ascii_lowercase()
                    .contains("x-mutated-by-filter: yes"),
                "expected the header-mutation filter's header in the response, got: {response:?}"
            );

            harness.shutdown().await;
        });
    }

    // --- usage filter over a real socket ---------------------------

    /// Undo HTTP/1.1 chunked transfer-coding: `<hex-len>\r\n<chunk>\r\n`
    /// repeated, terminated by a `0\r\n\r\n` end chunk (no trailers in this
    /// fixture). Just enough of RFC 9112 section 7.1 to unwrap what
    /// [`spawn_http_upstream_chunked_json`] -- and, transitively, the proxy's
    /// own re-encoded response -- produce; not a general-purpose decoder.
    fn dechunk(mut data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let line_end = data
                .windows(2)
                .position(|w| w == b"\r\n")
                .expect("chunk size line must end in CRLF");
            let size_str =
                std::str::from_utf8(&data[..line_end]).expect("chunk size must be ascii");
            let size = usize::from_str_radix(size_str.trim(), 16).expect("chunk size must be hex");
            data = &data[line_end + 2..];
            if size == 0 {
                break;
            }
            out.extend_from_slice(&data[..size]);
            data = &data[size + 2..]; // skip the chunk's trailing CRLF too
        }
        out
    }

    /// Acceptance test: a **YAML-shaped** bootstrap (not
    /// hand-built IR) wires the `type.llmproxy.dev/envoy.config.core.v3.DataSource`
    /// usage filter and a file access logger into one HCM, `build_snapshot`
    /// lowers it exactly the way `proxy_config::load_bootstrap_file` would for
    /// a real deployment, and the whole stack runs over real `TcpStream`s: a
    /// real upstream emits an OpenAI-shaped JSON body, the proxy forwards it
    /// unmodified to a real client socket, and the usage filter's extracted
    /// token counts land in a real rendered access-log line on disk.
    ///
    /// Four distinct numbers (`input=20, cached=80, cache_creation=0,
    /// output=20, total=120`) are asserted so a filter that reads the wrong
    /// JSON field, or the extractor's cached-tokens-out-of-prompt-tokens
    /// arithmetic regressing, cannot accidentally pass.
    ///
    /// Mutation-tested: see the task notes -- either dropping the
    /// `UsageFilterFactory` registration or making `classify_body` treat
    /// `application/json` as `Inert` makes this fail (no line is ever
    /// written, so the bounded poll below times out).
    #[test]
    fn usage_filter_records_tokens_from_a_real_upstream_response() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        run_local(async {
            let proxy_port = free_port().await;
            let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

            let upstream_body: &'static [u8] = br#"{"id":"x","usage":{"prompt_tokens":100,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":80}}}"#;
            let upstream_addr = spawn_http_upstream_chunked_json(upstream_body).await;

            let log_path = std::env::temp_dir().join(format!(
                "llm-proxy-usage-filter-test-{}-{}.log",
                std::process::id(),
                proxy_port
            ));
            // Rust note: `Path::display()` (rather than `to_str().unwrap()`)
            // so this doesn't panic on a hypothetical non-UTF8 temp dir --
            // the resulting YAML string just needs *a* path, not a lossless
            // round trip of the OS path type.
            let log_path_str = log_path.display().to_string();

            let yaml = format!(
                r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {proxy_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: llmproxy.usage
                    typed_config:
                      "@type": type.llmproxy.dev/envoy.config.core.v3.DataSource
                      inline_string: openai
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: up }}
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: {log_path_str}
                      log_format:
                        text_format: "%LLM_INPUT_TOKENS% %LLM_CACHED_TOKENS% %LLM_CACHE_CREATION_TOKENS% %LLM_OUTPUT_TOKENS% %LLM_TOTAL_TOKENS% %LLM_TTFT%\n"
  clusters:
    - name: up
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: up
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
                proxy_port = proxy_port,
                log_path_str = log_path_str,
                upstream_ip = upstream_addr.ip(),
                upstream_port = upstream_addr.port(),
            );

            let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
                .expect("bootstrap YAML must parse");
            let snapshot = Arc::new(build_snapshot(&loaded).expect("bootstrap YAML must lower"));

            let harness = spawn_manager(snapshot).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(proxy_addr)
                .await
                .expect("connect should succeed");
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();

            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");

            let header_end = response
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("response must have a header/body separator");
            let status_line = String::from_utf8(response[..header_end].to_vec())
                .expect("headers should be valid utf8");
            assert!(
                status_line.starts_with("HTTP/1.1 200"),
                "expected a 200 status line, got: {status_line:?}"
            );
            let raw_body = &response[header_end + 4..];
            // The proxy's own response is chunked too (nothing downstream of
            // the filter chain re-adds a `content-length`, for the same
            // reason `spawn_http_upstream_chunked_json` sends one upstream),
            // so unwrap the chunk framing before comparing against the
            // upstream's raw body.
            let response_body = dechunk(raw_body);
            assert_eq!(
                response_body, upstream_body,
                "the usage filter observes the body -- it must never alter or truncate it"
            );

            harness.shutdown().await;

            // FileSink flushes per line, but the write races the harness
            // shutdown returning, so poll briefly instead of asserting on
            // the first read.
            let mut logged = String::new();
            for attempt in 0..20 {
                logged = std::fs::read_to_string(&log_path).unwrap_or_default();
                if !logged.trim().is_empty() {
                    break;
                }
                assert!(
                    attempt < 19,
                    "access-log file at {log_path_str} was never written"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }

            let line = logged.trim();
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(
                fields.len(),
                6,
                "expected 6 space-separated fields, got: {line:?}"
            );
            // input=20, cached=80, cache_creation=0, output=20, total=120 --
            // four distinct values, so a wrong-field extraction bug can't
            // accidentally pass.
            assert_eq!(&fields[0..5], &["20", "80", "0", "20", "120"]);
            assert_ne!(
                fields[5], "-",
                "time-to-first-byte must be populated for a real streamed response"
            );

            let _ = std::fs::remove_file(&log_path);
        });
    }

    /// An invalid per-route usage dialect must
    /// be a build error, even when the `typed_per_filter_config` entry is
    /// wrapped `is_optional: true`. `is_optional` only tolerates a filter
    /// that has *no* per-route config at all (`ConfigError::Unimplemented`,
    /// the `HttpFilterFactory::parse_per_route` default) -- see
    /// `filter_manager::resolve_per_filter_row`. A malformed dialect string
    /// is a different failure (`ConfigError::InvalidValue`) and must not be
    /// swallowed, or a typo'd per-route dialect would silently fall back to
    /// the listener-level one and meter with the wrong dialect.
    ///
    /// This test builds the bootstrap YAML with `parse_bootstrap` +
    /// `build_snapshot` exactly like
    /// `usage_filter_records_tokens_from_a_real_upstream_response` above --
    /// `build_snapshot` accepts the config (the dialect string is opaque at
    /// lowering time; `PerFilterConfig` just carries the decoded `Any`
    /// verbatim). The rejection only happens when the filter chain is built
    /// against the real registered factories, so this test drives
    /// `build_listener_hcm` directly instead of spawning a listener over a
    /// real socket -- no `run_local`, no network, no upstream, no access log.
    ///
    /// Mutation-tested: changing `filter_manager::resolve_per_filter_row`'s
    /// `Err(ConfigError::Unimplemented { .. }) if cfg.is_optional => continue`
    /// arm to `Err(_) if cfg.is_optional => continue` turns this test red
    /// (the build wrongly succeeds instead of erroring) -- see the task notes
    /// for the exact mutation and restore procedure.
    #[test]
    fn an_invalid_per_route_usage_dialect_fails_the_build_even_when_optional() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        let yaml = r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 127.0.0.1, port_value: 0 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: llmproxy.usage
                    typed_config:
                      "@type": type.llmproxy.dev/envoy.config.core.v3.DataSource
                      inline_string: openai
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: up }
                          typed_per_filter_config:
                            llmproxy.usage:
                              "@type": type.googleapis.com/envoy.config.route.v3.FilterConfig
                              is_optional: true
                              config:
                                "@type": type.llmproxy.dev/envoy.config.core.v3.DataSource
                                inline_string: gemini
  clusters:
    - name: up
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: up
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 127.0.0.1, port_value: 1 }
"#;

        let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
            .expect("bootstrap YAML must parse");
        let snapshot = build_snapshot(&loaded)
            .expect("bootstrap YAML must lower -- the dialect string is opaque at this stage");

        let listener_ir = snapshot.listeners.get("l1").expect("listener l1");
        // No clusters need to be registered for the filter chain to build --
        // route -> cluster resolution happens per-request, not at build time.
        let cluster_manager = Arc::new(ClusterManager::new(
            Arc::new(proxy_cluster::resolver::TokioResolver),
            crate::tls::transport_socket_builder(),
        ));
        let stats_control = proxy_observability::stats::StatsControl::new(1);
        let router_stats = router_stats_for(&stats_control, &snapshot);
        let token_stats = token_stats_for(&stats_control, &snapshot);
        let latency_stats = latency_stats_for(&stats_control);
        let factory_state = Arc::new(SharedFactoryState::default());

        let hcm_runtime = HcmRuntime {
            snapshot_version: snapshot.version,
            routes: &snapshot.routes,
            cluster_manager: &cluster_manager,
            router_stats: &router_stats,
            token_stats: &token_stats,
            latency_stats: &latency_stats,
            tracing_handles: None,
            metadata: None,
            factory_state: &factory_state,
        };
        let err = match build_listener_hcm(listener_ir, &hcm_runtime) {
            Ok(_) => {
                panic!("an invalid per-route dialect must fail the build, is_optional or not")
            }
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("typed_config.inline_string") || msg.contains("gemini"),
            "error should name the invalid dialect field/value, got: {msg}"
        );
    }

    // --- SharedFactoryState scope fix: two listeners must not collide ----------

    /// The `build_hcm_handler`-level half of the regression: two listeners,
    /// each configuring `llmproxy.auth` with its own `hmac_secret`, built
    /// through `build_listener_hcm` against the SAME `SharedFactoryState` --
    /// exactly the shape `initial_bind`/`spawn_bound` produce for a real
    /// multi-listener config. Each listener's own `context` string
    /// (`"listener '<name>' filter_chains[0]"`) must become a DIFFERENT
    /// `FactoryContext::scope`, so each gets its own `ControlPlane` singleton
    /// rather than colliding on `llmproxy.auth`'s shared `type_url`.
    ///
    /// This only proves the two registered under different scopes (via
    /// `get_across_scopes` reporting the collision as `Err` with both scope
    /// names) -- `auth_filter`'s own
    /// `two_scopes_over_one_shared_state_get_independent_control_planes` is
    /// the test that proves the two `ControlPlane`s actually enforce
    /// independently (a real request over each filter). Driving that same
    /// proof through a real socket here would mean standing up two full
    /// listeners end to end purely to re-demonstrate what `SharedFactoryState`
    /// itself already guarantees once the scopes differ -- not cheap enough
    /// to be worth duplicating.
    #[test]
    fn two_listeners_each_configuring_auth_get_independent_singleton_scopes() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        let yaml = r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 127.0.0.1, port_value: 0 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: l1
                http_filters:
                  - name: llmproxy.auth
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
                      hmac_secret:
                        inline_string: listener-l1-secret
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc1
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: up }
    - name: l2
      address:
        socket_address: { address: 127.0.0.1, port_value: 0 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: l2
                http_filters:
                  - name: llmproxy.auth
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
                      hmac_secret:
                        inline_string: listener-l2-secret
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc2
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: { prefix: "/" }
                          route: { cluster: up }
  clusters:
    - name: up
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: up
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 127.0.0.1, port_value: 1 }
"#;

        let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
            .expect("bootstrap YAML must parse");
        let snapshot = build_snapshot(&loaded).expect("bootstrap YAML must lower");

        let l1 = snapshot.listeners.get("l1").expect("listener l1");
        let l2 = snapshot.listeners.get("l2").expect("listener l2");
        let cluster_manager = Arc::new(ClusterManager::new(
            Arc::new(proxy_cluster::resolver::TokioResolver),
            crate::tls::transport_socket_builder(),
        ));
        let stats_control = proxy_observability::stats::StatsControl::new(1);
        let router_stats = router_stats_for(&stats_control, &snapshot);
        let token_stats = token_stats_for(&stats_control, &snapshot);
        let latency_stats = latency_stats_for(&stats_control);
        let factory_state = Arc::new(SharedFactoryState::default());

        let hcm_runtime = HcmRuntime {
            snapshot_version: snapshot.version,
            routes: &snapshot.routes,
            cluster_manager: &cluster_manager,
            router_stats: &router_stats,
            token_stats: &token_stats,
            latency_stats: &latency_stats,
            tracing_handles: None,
            metadata: None,
            factory_state: &factory_state,
        };
        build_listener_hcm(l1, &hcm_runtime).expect("listener l1's filter chain must build");
        build_listener_hcm(l2, &hcm_runtime).expect("listener l2's filter chain must build");

        let scopes = factory_state
            .get_across_scopes(proxy_filters::auth_filter::TYPE_URL)
            .expect_err(
                "two listeners each configuring llmproxy.auth must register TWO distinct \
                 scopes -- before the scope fix, l2's build would have silently reused l1's \
                 slot instead, leaving exactly one",
            );
        assert_eq!(
            scopes.len(),
            2,
            "expected exactly two scopes (one per listener), got: {scopes:?}"
        );
        assert!(
            scopes.iter().any(|s| s.contains("listener 'l1'"))
                && scopes.iter().any(|s| s.contains("listener 'l2'")),
            "each scope must be traceable back to the listener that registered it, got: {scopes:?}"
        );
    }

    // --- body-rewrite filter over a real socket -----------

    /// A real upstream that reads a raw HTTP/1.1 request by hand, echoes the
    /// request body back as its own response body, and reports two numbers
    /// as response headers: the `content-length` the request DECLARED, and
    /// the number of body bytes it actually READ off the wire. The
    /// point of the body-rewrite filter is that those two numbers must agree after
    /// the body-rewrite filter splices bytes in and grows `content-length`
    /// to match -- a unit test can't observe that, since it never puts real
    /// bytes on a real socket with real HTTP/1.1 framing.
    async fn spawn_http_upstream_echoing_request_body() -> SocketAddr {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::task::spawn_local(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::task::spawn_local(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let header_end = loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                    break pos;
                                }
                            }
                        }
                    };
                    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
                    let declared_content_length: usize = header_str
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            if name.trim().eq_ignore_ascii_case("content-length") {
                                value.trim().parse::<usize>().ok()
                            } else {
                                None
                            }
                        })
                        .expect(
                            "this fixture only serves the content-length code path -- \
                             the request must declare one",
                        );

                    let mut body = buf[header_end + 4..].to_vec();
                    while body.len() < declared_content_length {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => body.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let actual_body_length = body.len();

                    // Per HTTP/1.1 framing this fixture stops reading the
                    // instant it's read exactly `declared_content_length`
                    // bytes -- that's the correct, honest behavior of a real
                    // upstream. If the proxy actually put MORE bytes on the
                    // wire than it declared (the exact failure mode of
                    // skipping the content-length fix-up after an
                    // injection), those extra bytes are still sitting
                    // unread in the kernel receive buffer right now. A short
                    // bounded probe surfaces them as `leftover_bytes`; a
                    // healthy request always has zero.
                    let mut leftover = Vec::new();
                    loop {
                        match tokio::time::timeout(
                            Duration::from_millis(100),
                            stream.read(&mut chunk),
                        )
                        .await
                        {
                            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                            Ok(Ok(n)) => leftover.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let leftover_bytes = leftover.len();

                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nx-received-content-length: {declared_content_length}\r\nx-actual-body-length: {actual_body_length}\r\nx-leftover-bytes: {leftover_bytes}\r\nconnection: close\r\n\r\n",
                        body.len(),
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    /// Acceptance test: a bootstrap YAML wires the
    /// `type.llmproxy.dev/llmproxy.filters.v0.BodyRewrite`
    /// body-rewrite filter ahead of the router, a streaming OpenAI request
    /// WITHOUT `stream_options` is sent over a real socket, and the request
    /// the upstream actually received on the wire is asserted to (a) equal
    /// the original body with `stream_options` spliced in, byte for byte,
    /// and (b) leave nothing unread on the wire (`x-leftover-bytes: 0`) --
    /// proving the splice and the `modify_decoded_headers` content-length
    /// fix-up landed together, not just that the scanner/splice logic is
    /// correct in isolation (that's `body_rewrite_filter`'s own unit tests).
    ///
    /// Mutation-tested: skipping the `modify_decoded_headers` call (so
    /// `content-length` stays at the pre-injection length while the actual
    /// body sent is longer) turns this red -- the fixture, obeying real
    /// HTTP/1.1 framing, stops reading at the stale (too-small) declared
    /// length, so the extra injected bytes are left sitting unread
    /// (`x-leftover-bytes` > 0) and the echoed body no longer matches the
    /// expected spliced body. A first version of this test only compared
    /// `x-received-content-length` against how many bytes the fixture itself
    /// chose to read up to that same declared length -- trivially equal by
    /// construction, so it never actually caught this mutation; the
    /// `x-leftover-bytes` probe and the exact-body comparison below are what
    /// make it load-bearing.
    #[test]
    fn body_rewrite_filter_injects_and_fixes_content_length_over_a_real_upstream() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        run_local(async {
            let proxy_port = free_port().await;
            let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

            let upstream_addr = spawn_http_upstream_echoing_request_body().await;

            let request_body =
                br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;

            let yaml = format!(
                r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {proxy_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: llmproxy.body_rewrite
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.BodyRewrite
                      enabled: true
                      dialect: openai
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: up }}
  clusters:
    - name: up
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: up
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
                proxy_port = proxy_port,
                upstream_ip = upstream_addr.ip(),
                upstream_port = upstream_addr.port(),
            );

            let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
                .expect("bootstrap YAML must parse");
            let snapshot = Arc::new(build_snapshot(&loaded).expect("bootstrap YAML must lower"));

            let harness = spawn_manager(snapshot).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(proxy_addr)
                .await
                .expect("connect should succeed");
            let request = format!(
                "POST / HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                request_body.len(),
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            stream.write_all(request_body).await.unwrap();

            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                .await
                .expect("read should not time out")
                .expect("read should succeed");

            let header_end = response
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .expect("response must have a header/body separator");
            let status_line_and_headers =
                String::from_utf8(response[..header_end].to_vec()).expect("headers valid utf8");
            assert!(
                status_line_and_headers.starts_with("HTTP/1.1 200"),
                "expected a 200 status line, got: {status_line_and_headers:?}"
            );

            let header_value = |name: &str| -> usize {
                status_line_and_headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        if key.trim().eq_ignore_ascii_case(name) {
                            value.trim().parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| panic!("upstream must report {name}"))
            };
            let received_content_length = header_value("x-received-content-length");
            let actual_body_length = header_value("x-actual-body-length");
            let leftover_bytes = header_value("x-leftover-bytes");

            assert_eq!(
                received_content_length, actual_body_length,
                "the upstream's declared content-length must match the body bytes it actually read \
                 up to that length (this alone is true by construction -- see the doc comment on \
                 why the assertions below are the ones that actually catch a broken fix-up)"
            );
            assert_eq!(
                leftover_bytes, 0,
                "no bytes should be left unread on the wire past the declared content-length -- \
                 a nonzero count means the proxy put more bytes on the wire than it declared"
            );

            let echoed_body = &response[header_end + 4..];
            let inject = r#""stream_options":{"include_usage":true},"#;
            let mut expected_body = Vec::with_capacity(request_body.len() + inject.len());
            expected_body.extend_from_slice(&request_body[..1]);
            expected_body.extend_from_slice(inject.as_bytes());
            expected_body.extend_from_slice(&request_body[1..]);
            assert_eq!(
                echoed_body, expected_body,
                "the upstream must have received the original body with stream_options spliced \
                 in right after the opening `{{`, byte for byte"
            );

            harness.shutdown().await;
        });
    }

    // --- token limiter over real sockets ------------------

    /// Acceptance test: a bootstrap wires
    /// `llmproxy.token_limit` BEFORE `llmproxy.usage` (see
    /// `token_limit_filter`'s module doc for why the order matters), a real
    /// upstream reports a fixed, known token usage on every response, and a
    /// tiny budget (100 tokens) is exhausted by the first request's actual
    /// 120-token usage. Two sequential requests, each its own real socket:
    /// the first gets 200 (the budget starts empty), the second gets 429
    /// with the rate-limit headers -- proving the second is refused *because
    /// of tokens the first actually spent*, which is the whole feature and
    /// something no unit test (which drives `BudgetStore` or the filter
    /// callbacks directly, never a real end-to-end usage->record->check
    /// loop through two independent HTTP exchanges) can prove.
    ///
    /// Mutation-tested: see the task notes -- reordering the two filters (so
    /// `llmproxy.usage` runs before `llmproxy.token_limit` in config order)
    /// makes this fail (both requests come back 200, since the limiter's
    /// encode callback then runs before the usage filter's and never
    /// observes the usage it's supposed to record).
    #[test]
    fn token_limit_filter_denies_the_second_request_after_the_first_spends_its_budget() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        run_local(async {
            let proxy_port = free_port().await;
            let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

            // input=20 (100 prompt - 80 cached), cached=80, cache_creation=0,
            // output=20 -- total=120, same fixture shape as
            // `usage_filter_records_tokens_from_a_real_upstream_response`.
            let upstream_body: &'static [u8] = br#"{"id":"x","usage":{"prompt_tokens":100,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":80}}}"#;
            let upstream_addr = spawn_http_upstream_chunked_json(upstream_body).await;

            let yaml = format!(
                r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {proxy_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: test
                http_filters:
                  - name: llmproxy.token_limit
                    typed_config:
                      "@type": type.llmproxy.dev/llmproxy.filters.v0.TokenLimit
                      max_tokens: 100
                      fill_rate: 0.001
                  - name: llmproxy.usage
                    typed_config:
                      "@type": type.llmproxy.dev/envoy.config.core.v3.DataSource
                      inline_string: openai
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: up }}
  clusters:
    - name: up
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: up
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
                proxy_port = proxy_port,
                upstream_ip = upstream_addr.ip(),
                upstream_port = upstream_addr.port(),
            );

            let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
                .expect("bootstrap YAML must parse");
            let snapshot = Arc::new(build_snapshot(&loaded).expect("bootstrap YAML must lower"));

            let harness = spawn_manager(snapshot).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            async fn send_request(proxy_addr: SocketAddr) -> (u16, HashMap<String, String>) {
                let mut stream = TcpStream::connect(proxy_addr)
                    .await
                    .expect("connect should succeed");
                stream
                    .write_all(
                        b"GET / HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer sk-e2e\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();

                let mut response = Vec::new();
                tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
                    .await
                    .expect("read should not time out")
                    .expect("read should succeed");

                let header_end = response
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .expect("response must have a header/body separator");
                let head = String::from_utf8(response[..header_end].to_vec())
                    .expect("headers should be valid utf8");
                let mut lines = head.lines();
                let status_line = lines.next().expect("a status line");
                let status: u16 = status_line
                    .split_whitespace()
                    .nth(1)
                    .expect("status line has a code")
                    .parse()
                    .expect("status code is numeric");
                let headers: HashMap<String, String> = lines
                    .filter_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
                    })
                    .collect();
                (status, headers)
            }

            // First request: the budget starts empty (100 tokens allowed),
            // so this is admitted. Its response reports 120 actual tokens
            // used, which is what exhausts the budget for the request after
            // it -- not this one.
            let (first_status, _first_headers) = send_request(proxy_addr).await;
            assert_eq!(
                first_status, 200,
                "the first request must be admitted -- the budget starts empty"
            );

            // FileSink-style eventual consistency isn't a factor here (the
            // store's `record` is synchronous, in-process), but give the
            // harness a moment to fully tear down the first connection's
            // stream state before opening the second.
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Second request, same credential/route: the first request's
            // 120 actual tokens are now recorded against a 100-token
            // budget, so this one must be denied.
            let (second_status, second_headers) = send_request(proxy_addr).await;
            assert_eq!(
                second_status, 429,
                "the second request must be denied -- the first request's actual usage (120) \
                 exceeded the 100-token budget"
            );
            for name in [
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
                "retry-after",
            ] {
                assert!(
                    second_headers.contains_key(name),
                    "expected header `{name}` on the 429, got: {second_headers:?}"
                );
            }
            assert_eq!(
                second_headers.get("x-ratelimit-limit").map(String::as_str),
                Some("100")
            );
            assert_eq!(
                second_headers
                    .get("x-ratelimit-remaining")
                    .map(String::as_str),
                Some("0")
            );

            harness.shutdown().await;
        });
    }
}
