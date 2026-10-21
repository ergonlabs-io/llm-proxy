//! Per-worker listener manager. Each worker binds its own socket per listener, accepts
//! connections, matches them against the listener's filter chains (`crate::filter_chain`), and
//! dispatches to the matched chain's terminal L4 network filter (`crate::tcp_proxy` or the HTTP
//! connection manager).
//!
//! ## Platform divergence: `SO_REUSEPORT` accept balancing
//!
//! Each worker binds the same listener address with `SO_REUSEPORT`. On Linux the kernel balances
//! accepts across those sockets, which is what lets the share-nothing worker design (ADR-0003)
//! accept without a central accept thread. On macOS the bind succeeds but accepts are not
//! balanced, so macOS is for development and tests only.

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
use proxy_http::codec::{serve_http1, serve_http2, Http1Options, RequestHeadLimits};
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

/// The shared [`FilterRegistry`], built exactly once and shared by every worker, so
/// `FilterRegistry::register` never sees a duplicate `type_url`.
///
/// Rust note: `std::sync::OnceLock` builds a value lazily on first access and shares it after
/// that, with no `unsafe` and no extra dependency. The first caller to reach `get_or_init` runs
/// registration; concurrent callers wait for it.
fn filter_registry() -> &'static Arc<FilterRegistry> {
    static REGISTRY: std::sync::OnceLock<Arc<FilterRegistry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut registry = FilterRegistry::default();
        registry.register(Arc::new(HeaderMutationFactory));
        registry.register(Arc::new(proxy_filters::ext_authz::ExtAuthzFactory));
        // Registration only makes a CORS policy buildable; a route opts in through
        // `typed_per_filter_config`.
        registry.register(Arc::new(proxy_filters::cors::CorsFilterFactory));
        // Registration alone consumes no requests; a listener must configure this type URL to
        // enforce a limit.
        registry.register(Arc::new(
            proxy_filters::local_ratelimit::LocalRateLimitFilterFactory,
        ));
        // Registered unconditionally: it only acts on routes that configure it, and an
        // unregistered filter is a hard config error at load time.
        registry.register(Arc::new(proxy_filters::usage_filter::UsageFilterFactory));
        // Deprecated alias for the borrowed DataSource carrier. Its factory warns and keeps the
        // old field semantics; new configs use the owned Usage message.
        registry.register(Arc::new(
            proxy_filters::usage_filter::LegacyUsageFilterFactory,
        ));
        // Request-body rewrite (forced `stream_options.include_usage` for OpenAI-dialect streaming).
        // Registered unconditionally, like the usage filter.
        registry.register(Arc::new(
            proxy_filters::body_rewrite_filter::BodyRewriteFilterFactory,
        ));
        // Deprecated alias for the borrowed RuntimeFeatureFlag carrier. Its factory warns and keeps
        // the old semantics; new configs use BodyRewrite.
        registry.register(Arc::new(
            proxy_filters::body_rewrite_filter::LegacyBodyRewriteFilterFactory,
        ));
        // Token-budget limiter. Must come BEFORE `llmproxy.usage` in `http_filters`: encode runs in
        // reverse config order (S2.1), so its encode-side `record` sees the usage the usage filter
        // wrote. Registered unconditionally.
        registry.register(Arc::new(
            proxy_filters::token_limit_filter::TokenLimitFilterFactory,
        ));
        // Deprecated alias for Envoy's RateLimitSettings. Its factory warns and has the same runtime
        // semantics as the owned TokenLimit message.
        registry.register(Arc::new(
            proxy_filters::token_limit_filter::LegacyTokenLimitFilterFactory,
        ));
        // Downstream authentication. Must come BEFORE `llmproxy.token_limit`: decode runs in forward
        // config order (S2.1), and the limiter buckets on the tenant this filter resolves.
        // `proxy_config::lower::check_lane_h_filter_order` enforces the order at load, because the
        // wrong order silently falls back to a client-supplied header. Registering it enables
        // nothing; only a listener that configures it authenticates.
        registry.register(Arc::new(proxy_filters::auth_filter::AuthFilterFactory));
        // Per-tenant model allow-lists. Must come AFTER `llmproxy.auth` and `llmproxy.body_rewrite`
        // (enforced by `check_lane_h_filter_order`). Registering it enables nothing; only a listener
        // that configures it enforces an allow-list.
        registry.register(Arc::new(
            proxy_filters::model_authz_filter::ModelAuthzFilterFactory,
        ));
        // Resolves the reserved `auto` model. Must come AFTER `llmproxy.auth` and
        // `llmproxy.body_rewrite`, and BEFORE `llmproxy.model_authz` (enforced by
        // `check_lane_h_filter_order`).
        registry.register(Arc::new(
            proxy_filters::model_resolver_filter::ModelResolverFilterFactory,
        ));
        // Body-aware request guardrails. Must come AFTER `llmproxy.auth`, `llmproxy.body_rewrite`,
        // `llmproxy.model_resolver` and `llmproxy.model_authz`, and BEFORE `llmproxy.token_limit`,
        // `llmproxy.spend_limit` and `llmproxy.usage` (enforced by `check_lane_h_filter_order`).
        registry.register(Arc::new(
            proxy_filters::guardrail_filter::GuardrailFilterFactory,
        ));
        // Tenant ownership of provider object IDs (files, batches). Must come
        // AFTER `llmproxy.auth` (enforced by `check_lane_h_filter_order`).
        registry.register(Arc::new(
            proxy_filters::object_ownership_filter::ObjectOwnershipFilterFactory,
        ));
        // Per-tenant spend-budget enforcement: decode-check and encode-record, like
        // `llmproxy.token_limit`. Must come AFTER `llmproxy.auth` and BEFORE `llmproxy.usage`
        // (enforced by `check_lane_h_filter_order`). Registering it enables nothing; only a listener
        // that configures it enforces a ceiling.
        registry.register(Arc::new(
            proxy_filters::spend_limit_filter::SpendLimitFilterFactory,
        ));
        Arc::new(registry)
    })
}

/// Compiled downstream TLS factories for one listener, indexed like
/// `ListenerConfig.filter_chains` plus the `default_filter_chain`. `None` means a plaintext chain,
/// or a TLS chain whose factory could not be rebuilt after a failed runtime rebuild.
///
/// Rust note: `rustls` state (cert resolvers, crypto providers) cannot live in `ConfigSnapshot`,
/// because `proxy-config` cannot depend on `proxy-core`'s TLS types (AGENTS.md invariant 2). Each
/// accept loop keeps its own `ListenerTls`, built at bind time and rebuilt when it sees the
/// snapshot version change.
struct ListenerTls {
    chain_factories: Vec<Option<Arc<DownstreamTlsFactory>>>,
    default_factory: Option<Arc<DownstreamTlsFactory>>,
}

impl ListenerTls {
    /// Placeholder used when a runtime rebuild fails: every TLS chain gets `None`, so matching
    /// connections are reset rather than served in the clear (see `spawn_accept_loop`).
    fn empty_for(listener: &ListenerConfig) -> Self {
        Self {
            chain_factories: vec![None; listener.filter_chains.len()],
            default_factory: None,
        }
    }
}

/// Handshake deadline when a chain leaves `transport_socket_connect_timeout` unset. Envoy applies
/// none, but this proxy holds an admission slot for the whole handshake, so an unbounded one lets
/// stalled clients exhaust `max_downstream_connections` (`internal-docs/envoy-divergences.md`).
const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Handshake deadline for `chain`: the configured value, the default when unset, or `None` for an
/// explicit `0s`.
fn tls_handshake_deadline(chain: &proxy_config::ir::FilterChainSpec) -> Option<Duration> {
    match chain.transport_socket_connect_timeout {
        None => Some(DEFAULT_TLS_HANDSHAKE_TIMEOUT),
        Some(d) if d.is_zero() => None,
        Some(d) => Some(d),
    }
}

/// An explicit `0s` removes the handshake bound, so a stalled client can hold an admission slot
/// indefinitely. Log loudly: the owner chose availability (AGENTS.md "Fail-open controls").
fn warn_if_handshake_unbounded(chain: &proxy_config::ir::FilterChainSpec, context: &str) {
    if chain.transport_socket.is_some() && tls_handshake_deadline(chain).is_none() {
        tracing::warn!(
            "{context}: transport_socket_connect_timeout is 0s, so the TLS handshake is unbounded \
             and a stalled client holds a connection slot until it disconnects"
        );
    }
}

/// Build the compiled TLS factories for every configured `transport_socket` in `listener`
/// (`filter_chains[i]` and `default_filter_chain`). A chain without one gets a `None` slot. A
/// build error names the listener and chain in `TlsBuildError::context` and propagates; the caller
/// decides whether it is fatal.
///
/// A chain whose `transport_socket` names SDS secrets is built with an empty cert set (the cert
/// has not arrived yet) and registered with `secret_registry`, so a later secret reaches it. A
/// registration failure is a `TlsBuildError`, since the chain still cannot serve TLS.
fn build_listener_tls(
    listener: &ListenerConfig,
    secret_registry: &Arc<SdsSecretRegistry>,
) -> Result<ListenerTls, TlsBuildError> {
    let mut chain_factories = Vec::with_capacity(listener.filter_chains.len());
    for (i, chain) in listener.filter_chains.iter().enumerate() {
        let factory = match &chain.transport_socket {
            Some(spec) => {
                let context = chain_context(&listener.name, Some(i));
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
            let context = chain_context(&listener.name, None);
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

/// An HCM terminal filter failed to build: an unregistered `type_url`, or a `typed_config` that
/// its factory rejected. Fatal in [`initial_bind`], logged and skipped at reconcile (see
/// [`InitialBindError`]). Never a silent skip of a configured filter (AGENTS.md invariant 1).
#[derive(Debug, thiserror::Error)]
#[error("{context}: {reason}")]
pub struct HttpFilterChainBuildError {
    context: String,
    reason: String,
}

/// Compiled HTTP filter-chain handlers, indexed like [`ListenerTls`] and built on the same
/// cadence. `None` means the chain's terminal filter is not an HTTP connection manager (for
/// example `tcp_proxy`), or a failed runtime rebuild.
struct ListenerHcm {
    chain_handlers: Vec<Option<Rc<dyn StreamHandler>>>,
    default_handler: Option<Rc<dyn StreamHandler>>,
}

/// Runtime dependencies shared by every HCM filter chain in one listener. Bundled so new
/// instrumentation does not grow `build_hcm_handler`'s positional arguments.
struct HcmRuntime<'a> {
    snapshot_version: SnapshotVersion,
    routes: &'a HashMap<String, Arc<proxy_config::ir::RouteTable>>,
    cluster_manager: &'a Arc<ClusterManager>,
    router_stats: &'a Arc<RouterStats>,
    token_stats: &'a Arc<GenAiTokenStats>,
    latency_stats: &'a Arc<GenAiLatencyStats>,
    tracing_handles: Option<&'a TracingHandles>,
    metadata: Option<&'a Arc<dyn proxy_observability::records::RequestRecordSink>>,
    ledger: Option<&'a Arc<proxy_observability::ledger::Ledger>>,
    traces: Option<&'a Arc<proxy_observability::traces::capture::TraceAdmission>>,
    factory_state: &'a Arc<SharedFactoryState>,
}

impl ListenerHcm {
    /// Same placeholder as [`ListenerTls::empty_for`], used when a runtime rebuild fails.
    fn empty_for(listener: &ListenerConfig) -> Self {
        Self {
            chain_handlers: vec![None; listener.filter_chains.len()],
            default_handler: None,
        }
    }
}

/// A chain's identity: its error context and its `FactoryContext::scope`.
/// `None` is the listener's `default_filter_chain`.
fn chain_context(listener: &str, index: Option<usize>) -> String {
    match index {
        Some(i) => format!("listener '{listener}' filter_chains[{i}]"),
        None => format!("listener '{listener}' default_filter_chain"),
    }
}

/// Refuses `snapshot` when an HTTP filter on a chain that is already built
/// would change state that filter fixed at its first build, so the reload or
/// xDS update is rejected before publish instead of failing per worker as
/// connection resets. Only `llmproxy.auth` has such state today (see
/// `proxy_filters::auth_filter::check_reload`). Every refusal is returned,
/// sorted, as `<chain>: http filter '<name>': <field>: <reason>`.
pub fn check_reload_compatible(
    snapshot: &ConfigSnapshot,
    factory_state: &SharedFactoryState,
) -> Result<(), String> {
    let mut refusals = Vec::new();
    for listener in snapshot.listeners.values() {
        let chains = listener
            .filter_chains
            .iter()
            .enumerate()
            .map(|(i, chain)| (Some(i), chain))
            .chain(
                listener
                    .default_filter_chain
                    .iter()
                    .map(|chain| (None, chain)),
            );
        for (index, chain) in chains {
            let Some(NetworkFilterSpec::HttpConnectionManager(hcm)) = chain.filters.last() else {
                continue;
            };
            let context = chain_context(&listener.name, index);
            for f in &hcm.http_filters {
                if f.type_url != proxy_filters::auth_filter::TYPE_URL {
                    continue;
                }
                let Some(config) = &f.config else { continue };
                if let Err(e) =
                    proxy_filters::auth_filter::check_reload(config, &context, factory_state)
                {
                    refusals.push(format!("{context}: http filter '{}': {e}", f.name));
                }
            }
        }
    }
    if refusals.is_empty() {
        return Ok(());
    }
    refusals.sort();
    Err(refusals.join("; "))
}

/// Build the compiled HTTP handler for every chain (`filter_chains[i]` and
/// `default_filter_chain`) whose terminal filter is an HCM. Other chains get a `None` slot,
/// mirroring `build_listener_tls`.
fn build_listener_hcm(
    listener: &ListenerConfig,
    runtime: &HcmRuntime<'_>,
) -> Result<ListenerHcm, HttpFilterChainBuildError> {
    let mut chain_handlers = Vec::with_capacity(listener.filter_chains.len());
    for (i, chain) in listener.filter_chains.iter().enumerate() {
        let handler = match chain.filters.last() {
            Some(NetworkFilterSpec::HttpConnectionManager(hcm)) => {
                let context = chain_context(&listener.name, Some(i));
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
            let context = chain_context(&listener.name, None);
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

/// A listener this worker has bound: its address (to tell an address change from a chain-only
/// update) and the accept-loop task driving it.
///
/// Rust note: `pub` because `initial_bind` returns a map of these, but the fields stay private;
/// outside callers only pass the map through.
pub struct BoundListener {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

/// A listener failed to bind or to configure TLS during [`initial_bind`]. Fatal, unlike
/// reconcile-time failures (see `reconcile`). Covers a socket that will not bind, or a chain
/// whose certs will not load (Envoy parity: both fail a static listener's warm-up).
///
/// Rust note: `#[error(transparent)]` on `Tls` forwards to `TlsBuildError`'s `Display`, which
/// already names the listener and chain.
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
/// Rust note: `socket2` exposes `SO_REUSEADDR` and `SO_REUSEPORT`, which `std` and `tokio` do not.
/// The socket converts to `std::net::TcpListener`, then to tokio with `from_std`. No `unsafe`.
fn bind_listener(listener: &ListenerConfig) -> io::Result<TcpListener> {
    let addr = listener.address;
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    // Rust note: `SO_REUSEPORT` is unix-only in `socket2`, so this crate is unix-only for now.
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    let backlog = listener.tcp_backlog_size.unwrap_or(128) as i32;
    socket.listen(backlog)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

/// The three worker-scoped stats recorders that [`initial_bind`], [`reconcile`], and
/// [`run_listener_manager`] all need. Bundled to keep their argument counts under clippy's
/// `too_many_arguments` threshold. `tracing` rides along for the same reason: it reaches
/// [`build_hcm_handler`] on the same path as the token recorder.
pub struct StatsRecorders {
    pub router: Arc<RouterStats>,
    pub downstream: Arc<DownstreamStats>,
    pub token: Arc<GenAiTokenStats>,
    pub latency: Arc<GenAiLatencyStats>,
    /// This worker's span sink and head-sampling ratio, if `ConfigSnapshot::tracing` is set. `None`
    /// means [`build_hcm_handler`] never enables tracing, so handlers pay nothing extra.
    pub tracing: Option<TracingHandles>,
    pub metadata: Option<Arc<dyn proxy_observability::records::RequestRecordSink>>,
    /// The billing ledger (ADR-0009). `None` when no ledger is configured. Every worker shares
    /// the one `Ledger`: admission slots are process-wide, and its single writer numbers
    /// entries, so `seq` is gapless across the instance.
    pub ledger: Option<Arc<proxy_observability::ledger::Ledger>>,
    /// Trace export admission (ADR-0008). `None` when export is off. Shared
    /// by every worker: its slot and byte budgets are process-wide.
    pub traces: Option<Arc<proxy_observability::traces::capture::TraceAdmission>>,
    /// The process-wide downstream connection counter. Not a recorder, but bundled for the same
    /// argument-count reason.
    pub connection_limiter: crate::admission::ConnectionLimiter,
}

/// [`StatsRecorders::tracing`]'s payload: a span sink plus the head-sampling ratio for new root
/// spans (`TracingConfig::sample_ratio`). Always set or unset together, hence one `Option`.
///
/// Rust note: `Clone` but not `Copy`, because `SpanSink` wraps an mpsc `Sender`. Cloning is cheap.
#[derive(Clone)]
pub struct TracingHandles {
    pub sink: SpanSink,
    pub sample_ratio: f64,
}

/// Bind `listener_ir` and spawn its accept loop, returning the [`BoundListener`]. The one place
/// that calls `bind_listener` and `spawn_accept_loop` together. Callers decide what an `Err`
/// means: [`initial_bind`] fails, reconcile logs and skips. [`WorkerShared`] bundles the
/// per-worker state for argument-count reasons.
struct WorkerShared<'a> {
    config: &'a Arc<WorkerConfigHandle>,
    registry: &'a ConnectionRegistry,
    shutdown: &'a watch::Receiver<bool>,
    /// Lets each connection's HTTP codec start graceful shutdown when drain starts.
    drain: &'a watch::Receiver<DrainState>,
    cluster_manager: &'a Arc<ClusterManager>,
    /// This worker's `upstream_rq` recorder. Built per worker in `worker_main` and threaded to
    /// [`RouterFilterFactory`] like `cluster_manager`.
    router_stats: &'a Arc<RouterStats>,
    /// This worker's `downstream_cx_total` recorder, threaded to [`spawn_accept_loop`].
    downstream_stats: &'a Arc<DownstreamStats>,
    /// The process-wide connection counter; see [`StatsRecorders::connection_limiter`].
    connection_limiter: &'a crate::admission::ConnectionLimiter,
    /// This worker's token-usage recorder, threaded to [`build_hcm_handler`] and wired in with
    /// `FilterChainHandler::with_token_stats`.
    token_stats: &'a Arc<GenAiTokenStats>,
    latency_stats: &'a Arc<GenAiLatencyStats>,
    /// Span sink and head-sampling ratio; see [`StatsRecorders::tracing`].
    tracing: &'a Option<TracingHandles>,
    metadata: &'a Option<Arc<dyn proxy_observability::records::RequestRecordSink>>,
    ledger: &'a Option<Arc<proxy_observability::ledger::Ledger>>,
    traces: &'a Option<Arc<proxy_observability::traces::capture::TraceAdmission>>,
    /// The per-serve [`SharedFactoryState`], shared by every worker's filter-factory build. Passed
    /// to each `HttpFilterFactory::create` through `FactoryContext`.
    factory_state: &'a Arc<SharedFactoryState>,
    /// The per-serve [`SdsSecretRegistry`]. Threaded to [`build_listener_tls`], which registers
    /// every SDS-named chain against it.
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
        ledger: shared.ledger.as_ref(),
        traces: shared.traces.as_ref(),
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
            ledger: shared.ledger.clone(),
            traces: shared.traces.clone(),
            factory_state: shared.factory_state.clone(),
            secret_registry: shared.secret_registry.clone(),
        },
    );
    Ok(BoundListener { addr, task })
}

/// Reconcile-time variant of the per-listener bind in [`initial_bind`]. Failures are logged and
/// the listener is skipped, not fatal: a later config push or manual intervention is the recovery
/// path, as Envoy degrades a single bad listener update.
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

/// Bind every `bind_to_port` listener in `snapshot` for the first time. Failure is fatal: Envoy
/// fails startup when a static listener cannot bind, and serving a subset of the configured
/// listeners is the silent degradation AGENTS.md invariant 1 forbids. On error, listeners this
/// call already bound are unwound before returning. On success, hand the map to
/// [`run_listener_manager`].
// `secret_registry` tips this over clippy's 7-argument ceiling, like `reconcile`'s own
// `#[allow]`. It is a per-serve handle, not a stats recorder.
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
        ledger: &stats.ledger,
        traces: &stats.traces,
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
    ledger: Option<Arc<proxy_observability::ledger::Ledger>>,
    traces: Option<Arc<proxy_observability::traces::capture::TraceAdmission>>,
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
        ledger,
        traces,
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
                accepted = accept_downstream(&tcp_listener, &name) => match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(listener = %name, error = %err, "accept() failed");
                        // Back off after a failed accept: a persistent error (EMFILE/ENFILE) leaves the
                        // listener readable, so an immediate retry would spin this worker. Shutdown
                        // still interrupts the pause.
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

            // Rust note: the snapshot is reloaded once per accepted connection, not once per accept
            // loop. That lets `run_listener_manager` leave this loop running when only a listener's
            // filter chains change (see its doc comment); the next connection sees the new snapshot.
            let snapshot = config.load();

            // Global downstream connection limit, checked before any other per-connection work so an
            // over-limit connection costs one accept and one close. Envoy also closes such a socket
            // without counting it in `downstream_cx_total`. The limit and `ignore_global_conn_limit`
            // come from the snapshot loaded above, so a reload applies to the next accept.
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

            // Counted only for admitted connections; the `Err` arm above `continue`s before this line.
            downstream_stats.record_connection_accepted(&name);

            // The TLS factory cache goes stale when the snapshot version does, so a chain-only change
            // (a new `transport_socket` or a rotated cert) is picked up here without a rebind. A rebuild
            // failure is logged and degrades the listener to "no TLS factories", as reconcile does, so a
            // runtime cert typo does not take the listener down.
            // Rust note: the fallback is whole-listener (every chain resets to `None`), not per chain.
            // It is simpler, at the cost of resetting unchanged TLS chains too. The rebuild is
            // synchronous, so it cannot stall new accepts.
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
                    // Same cadence and whole-listener fallback as the TLS cache above, for the HTTP handlers.
                    let hcm_runtime = HcmRuntime {
                        snapshot_version: snapshot.version,
                        routes: &snapshot.routes,
                        cluster_manager: &cluster_manager,
                        router_stats: &router_stats,
                        token_stats: &token_stats,
                        latency_stats: &latency_stats,
                        tracing_handles: tracing_handles.as_ref(),
                        metadata: metadata.as_ref(),
                        ledger: ledger.as_ref(),
                        traces: traces.as_ref(),
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

            // Everything after the accept (the ClientHello peek, filter-chain matching, the TLS handshake,
            // and the connection handler) runs in its own task. Rust note: this is load-bearing. The
            // peek and the handshake `.await` on the client, so inline they would let one stalled client
            // block every new connection on this listener. Spawning keeps the accept loop to `accept()`
            // plus the synchronous cache refresh above.
            tokio::task::spawn_local(serve_connection(ServeConnection {
                stream,
                peer,
                listener_name: name.clone(),
                published: config.subscribe(),
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

/// `request_headers_timeout` is enforced for HTTP/1 only (hyper's h2 server exposes no per-stream
/// header progress). Warn once per process when an HTTP/2 connection meets a listener that set it,
/// so the gap is visible (AGENTS.md invariant 1).
fn warn_h2_header_timeout_not_enforced_once(listener: &str) {
    // Rust note: `Once::call_once` runs its closure once per process, with no lock on later calls.
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(%listener, "request_headers_timeout is not enforced on HTTP/2 connections; it applies to HTTP/1 only (internal-docs/envoy-divergences.md)");
    });
}

/// Accept one downstream connection and set `TCP_NODELAY` on it, as Envoy does on every accepted
/// socket. Without it, Nagle holds a small response write until the client's delayed ACK arrives,
/// which adds tens of milliseconds per request. Failing to set the option is logged and the
/// connection is still served, matching the upstream dial in `tcp_proxy`.
async fn accept_downstream(
    tcp_listener: &TcpListener,
    listener: &ListenerName,
) -> std::io::Result<(TcpStream, SocketAddr)> {
    let (stream, peer) = tcp_listener.accept().await?;
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(%listener, %peer, error = %err, "failed to set TCP_NODELAY on downstream socket");
    }
    Ok((stream, peer))
}

/// Pause after a failed `accept()`, so a persistent error such as fd exhaustion does not spin.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// The listener this accept loop serves: matched by name first, then by bound address, so a rename
/// at an unchanged address keeps the socket.
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

/// Everything one accepted connection needs, moved into its own task (see the "load-bearing" Rust
/// note in `spawn_accept_loop`). Rust note: none of these fields are `Send`, which is fine because
/// the listener manager runs on a single-threaded `LocalSet` per ADR-0003.
struct ServeConnection {
    stream: TcpStream,
    peer: SocketAddr,
    listener_name: ListenerName,
    /// The snapshot this connection matched under, held for its lifetime. This is the passive-drain
    /// seam: replaced config stays alive as long as connections accepted under it.
    snapshot: Arc<ConfigSnapshot>,
    /// The worker's published snapshot version. An HTTP connection closes gracefully once it moves past
    /// `snapshot.version`; see `run_terminal_filter`.
    published: watch::Receiver<SnapshotVersion>,
    /// TLS factories built from `snapshot` in the accept loop, before this task was spawned.
    tls: Rc<ListenerTls>,
    /// HTTP filter-chain handlers built from `snapshot`, same cadence as `tls`.
    hcm: Rc<ListenerHcm>,
    registry: ConnectionRegistry,
    shutdown: watch::Receiver<bool>,
    drain: watch::Receiver<DrainState>,
    /// Counts a handshake that misses its deadline.
    downstream_stats: Arc<DownstreamStats>,
    /// Held for the task's lifetime; dropping it on any exit path frees the global connection slot.
    _connection_slot: crate::admission::ConnectionSlot,
}

/// Run `handshake` under `deadline`; `None` means unbounded. Returns `None` if the deadline expired.
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
        published,
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

    // If this listener has a `tls_inspector` filter, peek the ClientHello (without consuming it)
    // before filter-chain matching, so `server_names`, `application_protocols`, and
    // `transport_protocol` criteria can key on it.
    //
    // Rust note: `ListenerFilterSpec` has one variant today, so destructuring it in the closure
    // parameter is an irrefutable pattern. A second variant stops this line compiling until it is
    // handled here too, which enforces AGENTS.md invariant 1 at the type level.
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
                // Not TLS, or the ClientHello did not parse within limits: treat as plaintext.
            }
            Err(err) => {
                // A socket error, not a parse failure. Fall back to plaintext; the inspector must not be fatal.
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
        // Rust note: `SO_LINGER(0)` makes the kernel send a TCP RST on drop instead of a FIN. Envoy
        // does this on a `filter_chain_match` miss.
        reset(&stream, &name);
        return;
    };

    let buffer_limit = listener_ir
        .map(|l| l.per_connection_buffer_limit_bytes)
        .unwrap_or(1024 * 1024);

    // The cache slot for `matched`: its index in `filter_chains`, or the `default_filter_chain` slot.
    // Rust note: `ptr::eq` on references into the immutable `Arc`'d snapshot is valid and needs no
    // `unsafe` (see `filter_chain`'s property test). Looked up once for both the TLS and HCM caches,
    // which are aligned the same way.
    let chain_idx = listener_ir.and_then(|l| {
        l.filter_chains
            .iter()
            .position(|c| std::ptr::eq(c, matched))
    });

    // Extracted before the stream moves into either branch: the matched chain's terminal network
    // filter, as cheap owned params. A chain with no filters cannot occur (lowering rejects empty
    // `filters`), but `None` is handled defensively. The HCM handler was built at bind time (see
    // `build_listener_hcm`); this only looks up the slot.
    let hcm_handler = match chain_idx {
        Some(idx) => hcm.chain_handlers.get(idx).cloned().flatten(),
        None => hcm.default_handler.clone(),
    };
    let filter = terminal_filter(matched, buffer_limit, hcm_handler);

    // The configured `codec_type` for `matched`'s terminal filter. A `tcp_proxy` chain has no codec,
    // so `Auto` is inert there: the `(false, _)` arm reads it only for `TerminalFilter::Http`.
    let (codec_type, request_headers_timeout, request_head_limits) = match matched.filters.last() {
        Some(NetworkFilterSpec::HttpConnectionManager(hcm)) => (
            hcm.codec_type,
            hcm.request_headers_timeout,
            RequestHeadLimits {
                max_bytes: hcm.max_request_headers_kb as usize * 1024,
                max_headers: hcm.max_headers_count as usize,
            },
        ),
        Some(NetworkFilterSpec::TcpProxy(_)) | None => {
            (CodecType::Auto, None, RequestHeadLimits::default())
        }
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
                // Rust note: the outer `Option` is the deadline (`None` means it expired); the inner
                // `Result` is the handshake's own outcome.
                None => {
                    // Returning drops the stream and, with it, the admission slot.
                    downstream_stats.record_transport_socket_connect_timeout(&name);
                    tracing::debug!(listener = %name, peer = %peer, "TLS handshake timed out; closing connection");
                }
                Some(Ok(tls_stream)) => {
                    // An explicit `codec_type` (`Http1`/`Http2`) is unconditional: the operator said what
                    // the client speaks. Only `Auto` (the Envoy default) reads the negotiated ALPN, and that
                    // must happen here, post-handshake. See `downstream_codec_for_alpn`.
                    let codec = match codec_type {
                        CodecType::Http1 => DownstreamCodec::Http1,
                        CodecType::Http2 => DownstreamCodec::Http2,
                        CodecType::Auto => downstream_codec_for_alpn(&tls_stream),
                    };
                    // A `TlsStream` cannot be `reset` (SO_LINGER) like a bare `TcpStream`, so the no-op
                    // paths drop it and the close is a clean FIN.
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
                            published,
                            name: &name,
                            downstream,
                            codec,
                            request_headers_timeout,
                            request_head_limits,
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
            // The chain needs TLS but no factory exists (a runtime rebuild failed; see
            // `spawn_accept_loop`). Reset rather than run it in the clear.
            tracing::warn!(listener = %name, peer = %peer, "matched chain requires TLS but no factory is available; resetting connection");
            reset(&stream, &name);
        }
        (false, _) => {
            // Plaintext, or TLS passthrough (`matched` selected by SNI with no `transport_socket`):
            // dispatch to the terminal L4 filter on `stream`. No ALPN exists over plaintext, so `Auto`
            // resolves by peeking for the h2 client preface (see `resolve_plaintext_codec`).
            let downstream = DownstreamInfo {
                remote: peer,
                is_tls: false,
            };
            // Only resolve the codec when there is an HTTP codec to pick. A `tcp_proxy` chain ignores
            // `codec`, so skip the peek rather than delay those connections.
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
                    published,
                    name: &name,
                    downstream,
                    codec,
                    request_headers_timeout,
                    request_head_limits,
                },
            )
            .await
            {
                reset(&stream, &name);
            }
        }
    }
}

/// Which HTTP codec serves a **TLS** downstream connection: the negotiated ALPN, read post-handshake.
/// Only `h2` selects [`DownstreamCodec::Http2`]; anything else, including no ALPN at all, is h1.
/// Only called for `codec_type: Auto`; an explicit `Http1`/`Http2` is honored without consulting
/// ALPN. For plaintext see [`resolve_plaintext_codec`]. The h1 `Upgrade: h2c` path is out of scope
/// (see `serve_http2` and `proxy_http::codec`).
fn downstream_codec_for_alpn<IO>(
    tls_stream: &tokio_rustls::server::TlsStream<IO>,
) -> DownstreamCodec {
    // Rust note: `get_ref()` returns `(&IO, &rustls::ServerConnection)`. The negotiated ALPN lives in
    // the rustls session; `alpn_protocol()` is `None` before the handshake completes or when neither
    // side negotiated one.
    match tls_stream.get_ref().1.alpn_protocol() {
        Some(b"h2") => DownstreamCodec::Http2,
        _ => DownstreamCodec::Http1,
    }
}

/// See [`downstream_codec_for_alpn`]. `Copy`, so it threads through `run_terminal_filter`'s long
/// parameter list cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DownstreamCodec {
    Http1,
    Http2,
}

/// The HTTP/2 client connection preface (RFC 9113 S3.4): the 24 bytes a prior-knowledge h2 client
/// sends first. A plaintext connection has no ALPN, so this is the only signal that tells such a
/// client apart from an h1 request.
const H2_CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Wall-clock bound on [`resolve_plaintext_codec`]'s peek. A client that sends fewer than 24 bytes
/// and then stalls must not hang the connection (see `tls_inspector::INSPECT_TIMEOUT`).
const H2_PREFACE_PEEK_TIMEOUT: Duration = Duration::from_secs(5);

/// Backoff when a peek returns the same incomplete prefix as before. `TcpStream::peek` is
/// level-triggered on unread data, so re-awaiting it with no new bytes can return instantly. See
/// `tls_inspector::peek_client_hello`.
const H2_PREFACE_STALL_BACKOFF: Duration = Duration::from_millis(5);

/// Codec for a **plaintext** HTTP connection manager connection. `Http1`/`Http2` are unconditional.
/// `Auto` has no ALPN to read, so it peeks (without consuming) for [`H2_CLIENT_PREFACE`]: a match
/// is h2; anything else, including a timeout, is h1.
async fn resolve_plaintext_codec(codec_type: CodecType, stream: &TcpStream) -> DownstreamCodec {
    match codec_type {
        CodecType::Http1 => DownstreamCodec::Http1,
        CodecType::Http2 => DownstreamCodec::Http2,
        CodecType::Auto => {
            match tokio::time::timeout(H2_PREFACE_PEEK_TIMEOUT, peek_for_h2_preface(stream)).await {
                Ok(true) => DownstreamCodec::Http2,
                // `Ok(false)`: the bytes are not the preface. `Err(_)`: timed out. Both collapse to h1.
                Ok(false) | Err(_) => DownstreamCodec::Http1,
            }
        }
    }
}

/// The peek loop, run under [`resolve_plaintext_codec`]'s timeout. Returns `true` once all 24 bytes
/// match, and `false` as soon as one diverges. An h1 request line and the preface differ within the
/// first bytes (`GET` vs `PRI *`), so this decides promptly.
async fn peek_for_h2_preface(stream: &TcpStream) -> bool {
    let mut buf = [0u8; H2_CLIENT_PREFACE.len()];
    // The byte count from the previous iteration, so a peek that returns the same incomplete prefix
    // is not mistaken for progress. See `H2_PREFACE_STALL_BACKOFF`.
    let mut last_n: Option<usize> = None;
    loop {
        // Rust note: like `tls_inspector::peek_client_hello`, `TcpStream::peek` reads without draining
        // the kernel buffer, so the bytes remain for `serve_http1`/`serve_http2` after dispatch.
        let n = match stream.peek(&mut buf).await {
            Ok(n) => n,
            // A real socket error: let the chosen codec's own read surface it.
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
    // The token limiter's shared-store `GET /v1/usage` reads one store row
    // per route, so it needs this chain's route names. Published before the
    // filters are built, and on every build, so an RDS update reaches it.
    runtime
        .factory_state
        .get_or_try_init(
            context,
            "",
            proxy_control::window_usage::ROUTE_NAMES_KEY,
            || {
                Ok(
                    Arc::new(proxy_control::window_usage::ChainRouteNames::default())
                        as Arc<dyn std::any::Any + Send + Sync>,
                )
            },
        )
        .map_err(|e| HttpFilterChainBuildError {
            context: context.to_string(),
            reason: format!("route names: {e}"),
        })?
        .downcast::<proxy_control::window_usage::ChainRouteNames>()
        .expect("the route-names singleton is always ChainRouteNames")
        .publish_from(&route_table);
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
        // Lowering guarantees `config` is `None` only for the router filter, which `continue` skipped.
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
            // Stats live in the process-wide factory state, keyed by stat scope, so a rebuild does not log
            // the fail-open bypass again per worker and per update (AGENTS.md "Fail-open controls").
            // Chains that share a scope share its counters.
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
            // Kept beside the instance factory: `new_with_filters` needs the registered
            // `HttpFilterFactory` once, at construction, to resolve `typed_per_filter_config` through
            // `parse_per_route` (ADR-0004 step 4).
            factory: factory.clone(),
        });
    }

    // envoy-semantics.md S10.2: no filter that can hold response bytes on an HCM that upgrades.
    {
        let names: Vec<String> = filters.iter().map(|f| f.name.clone()).collect();
        let factories: Vec<_> = filters.iter().map(|f| f.factory.clone()).collect();
        proxy_http::filter_manager::check_upgrade_filters(&hcm.upgrade_configs, &names, &factories)
            .map_err(|e| HttpFilterChainBuildError {
                context: context.to_string(),
                reason: e.to_string(),
            })?;
    }

    // With tracing on, the router gets a CLIENT span sink so every dispatched attempt can emit a
    // span (see `RouterFilterFactory::with_tracing`). `None` costs nothing.
    let mut router_factory = RouterFilterFactory::new(
        runtime.cluster_manager.clone(),
        runtime.router_stats.clone(),
    )
    .with_config_context(context.to_string(), runtime.snapshot_version.0);
    if let Some(t) = runtime.tracing_handles {
        router_factory = router_factory.with_tracing(t.sink.clone());
    }
    // Thread this HCM's `upgrade_configs` into the router. Empty is the common case and costs nothing.
    router_factory = router_factory.with_upgrade_configs(hcm.upgrade_configs.clone());
    let terminal_factory: Arc<dyn TerminalFilterInstanceFactory> = Arc::new(router_factory);

    // `access_logs` sinks open here, at the same bind/rebuild cadence as the rest of this function.
    // A sink that cannot open (for example an unwritable path) is a config error: fatal at
    // `initial_bind`, logged and skipped at reconcile, like an unregistered filter or a bad cert.
    //
    // Access logging lives on `FilterChainHandler`, not `RouterHandler`: the router sits inside the
    // encode filter chain and cannot observe what an encode filter does at end of stream (see
    // `proxy_http::filter_manager`).
    //
    // `new_with_filters_and_access_logs` (ADR-0004 step 4) resolves `typed_per_filter_config` against
    // the real chain once, here (AGENTS.md invariant 1). `.with_token_stats` is applied on every real
    // HCM build; without it `llm.client.token.usage` is never recorded, whatever the route configures.
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
    // The listener's `per_connection_buffer_limit_bytes` (Envoy default 1 MiB, applied at lowering)
    // caps request-body collection for every HTTP request, before any filter runs. A larger body gets
    // a 413 (`decode_buffer_overflow`).
    .with_buffer_limit(buffer_limit_bytes as usize)
    .with_request_timeout(hcm.request_timeout)
    .with_stream_timeouts(hcm.stream_idle_timeout, hcm.max_stream_duration);
    handler = handler.with_gen_ai_latency_stats(runtime.latency_stats.clone());
    if let Some(sink) = runtime.metadata {
        handler = handler.with_request_record_sink(sink.clone());
    }
    if let Some(ledger) = runtime.ledger {
        handler = handler.with_ledger(ledger.clone());
    }
    if let Some(traces) = runtime.traces {
        handler = handler.with_traces(traces.clone());
    }
    // `.with_tracing` on the FilterChainHandler half: it mints the SERVER span and joins or propagates
    // an inbound `traceparent`. The CLIENT-span half is on the router above.
    if let Some(t) = runtime.tracing_handles {
        handler = handler.with_tracing(t.sink.clone(), t.sample_ratio);
    }
    let active = proxy_http::active_requests::ActiveRequests::new(
        runtime.router_stats.registry(),
        runtime.router_stats.worker(),
        &hcm.stat_prefix,
    );
    Ok(Rc::new(
        proxy_http::active_requests::ActiveRequestHandler::new(Rc::new(handler), active),
    ))
}

/// Everything [`run_terminal_filter`] needs beyond `stream`, `filter`, and `snapshot`. Bundled so the
/// argument list stays under clippy's `too_many_arguments` threshold.
struct RunTerminalFilterCtx<'a> {
    registry: &'a ConnectionRegistry,
    shutdown: watch::Receiver<bool>,
    /// Starts the HTTP codecs' graceful shutdown. TCP proxy connections ignore it and run until `shutdown`.
    drain: watch::Receiver<DrainState>,
    /// See [`ServeConnection::published`]. TCP proxy connections ignore it.
    published: watch::Receiver<SnapshotVersion>,
    name: &'a ListenerName,
    // Rust note: `Copy`, so it threads cheaply. It also serves as `peer` for tracing via `downstream.remote`.
    downstream: DownstreamInfo,
    // Codec for the `Http` terminal filter: always `Http1` on plaintext, ALPN-derived on TLS (see
    // `downstream_codec_for_alpn`). The `TcpProxy` and `None` arms ignore it.
    codec: DownstreamCodec,
    /// The matched HCM's `request_headers_timeout`. Enforced for HTTP/1 only, because hyper's h2 server
    /// exposes no per-stream header progress (internal-docs/envoy-divergences.md).
    request_headers_timeout: Option<Duration>,
    /// The matched HCM's `max_request_headers_kb` and `max_headers_count`, enforced by both codecs.
    request_head_limits: RequestHeadLimits,
}

/// Dispatch to the matched chain's terminal L4 filter. The `TcpProxy` and `Http` paths register the
/// connection guard and run to completion, returning `None`. The no-filter path hands `stream` back
/// so the caller can close it: a `TcpStream` can be `reset`, while a `TlsStream` is just dropped.
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
        mut published,
        name,
        downstream,
        codec,
        request_headers_timeout,
        request_head_limits,
    } = ctx;
    let peer = downstream.remote;
    match filter {
        Some(TerminalFilter::TcpProxy(params)) => {
            let guard = registry.register();
            tcp_proxy::proxy_connection(stream, snapshot, params, guard, shutdown).await;
            None
        }
        Some(TerminalFilter::Http(handler)) => {
            // Held for the whole HTTP connection, like `tcp_proxy`'s guard, so drain accounting sees it
            // live until the codec returns. That also covers upgraded streams (envoy-semantics.md S10.5).
            let _guard = registry.register();

            // Rust note: `serve_http1` takes an `impl Future`, not a `watch::Receiver`, so it stays
            // decoupled from drain. Graceful shutdown starts at whichever comes first: drain start
            // (idle keep-alives close, in-flight requests finish, then `Connection: close` or GOAWAY) or
            // the final `shutdown`.
            // The codec hands the same signal to its upgrade tunnels: a WebSocket tunnel sends Close 1001.
            //
            // A reload starts the same graceful shutdown. This connection's handler, routes and cluster view
            // (and so its provider credentials) belong to `snapshot`. Without this a kept-alive connection would
            // keep sending a rotated or revoked provider key until the client closed it. Requests already in
            // flight finish on their own generation, so a retry never mixes generations
            // (internal-docs/envoy-divergences.md).
            let accepted = snapshot.version;
            let listener = name.clone();
            let superseded = async move {
                // `wait_for` checks the current value first, so a publish between the accept loop's `load` and
                // its `subscribe` is not missed. A dropped sender means the worker is going away: never fires.
                if published.wait_for(|v| *v != accepted).await.is_err() {
                    std::future::pending::<()>().await;
                }
                tracing::debug!(listener = %listener, peer = %peer, "config replaced; closing connection after in-flight requests");
            };
            let shutdown_fut = async move {
                let shutdown_signal = async {
                    if *shutdown.borrow() {
                        return;
                    }
                    // `changed()` resolves once in practice, but the loop tolerates spurious notifications.
                    while shutdown.changed().await.is_ok() {
                        if *shutdown.borrow() {
                            return;
                        }
                    }
                };
                tokio::select! {
                    _ = drain_started(&mut drain) => {}
                    _ = shutdown_signal => {}
                    _ = superseded => {}
                }
            };

            match codec {
                DownstreamCodec::Http1 => {
                    let options = Http1Options {
                        keep_alive: true,
                        header_read_timeout: request_headers_timeout,
                        request_head_limits,
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
                    if let Err(err) = serve_http2(
                        stream,
                        handler,
                        request_head_limits,
                        shutdown_fut,
                        downstream,
                    )
                    .await
                    {
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

/// Reset a connection with a TCP RST (`SO_LINGER(0)`) instead of a clean FIN. Envoy does this on a
/// `filter_chain_match` miss or an unserviceable TLS chain.
fn reset(stream: &TcpStream, listener: &str) {
    if let Err(err) = SockRef::from(stream).set_linger(Some(Duration::ZERO)) {
        tracing::warn!(listener = %listener, error = %err, "failed to set SO_LINGER for reset-close");
    }
    // The caller drops `stream`; the linger option set above turns that drop into an RST.
}

/// Reconcile `bound` against `snapshot`: bind new listeners, warm a replacement before stopping an
/// address-changed listener, leave unchanged ones alone, and stop accepting on removed ones.
// `factory_state` and `secret_registry` push this past clippy's 7-argument ceiling. They are not
// stats recorders, so they stay out of `StatsRecorders`; this leaf allows the extra arguments instead
// (the same tradeoff `worker_main` makes for `tracing_handles`).
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
        ledger: &stats.ledger,
        traces: &stats.traces,
        factory_state,
        secret_registry,
    };
    // A rename at an unchanged address keeps the socket and accept loop. The loop resolves its name
    // from the next snapshot before accepting, so a rename cannot race `SO_REUSEPORT` or leave a
    // handler pointing at a removed cluster.
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

    // Warm every desired listener before retiring names absent from the new snapshot. A same-address
    // rename is a replacement, not a remove-then-bind: aborting the old loop first would open a socket
    // gap and drop queued connections.
    for (name, listener_ir) in snapshot.listeners.iter() {
        if !listener_ir.bind_to_port {
            // Envoy reaches such listeners only through internal redirection (`internal_listener`), which
            // is not implemented here. Never bind or accept on them.
            tracing::debug!(listener = %name, "bind_to_port=false; not binding");
            continue;
        }
        if !listener_ir.routes_are_warmed(&snapshot.routes) {
            tracing::info!(listener = %name, "listener waits for RDS route configuration before binding");
            continue;
        }

        match bound.get(name) {
            Some(existing) if existing.addr == listener_ir.address => {
                // Unchanged address: leave the accept loop running. It reloads the snapshot per accepted
                // connection, so filter-chain changes take effect without a rebind.
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
                        // Every bind-time warm-up (TLS, HTTP filters, socket bind) has completed. Only now stop
                        // the old loop. Accepted connections own their snapshots and drain on their own.
                        let old = bound
                            .insert(name.clone(), replacement)
                            .expect("address-changed listener must still be bound");
                        old.task.abort();
                    }
                    Err(err) => {
                        // Keep the old map entry and accept loop. A failed replacement must not turn a live
                        // update into an outage; a later snapshot retries the warm-up.
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
            // A same-address rename whose replacement failed to warm keeps the last-good listener
            // accepting until a later snapshot retries.
            tracing::error!(listener = %name, %addr, "replacement listener failed to bind; keeping previous listener active");
            continue;
        }
        if let Some(b) = bound.remove(&name) {
            tracing::info!(listener = %name, "listener removed from config after replacements warmed; existing connections drain independently");
            b.task.abort();
        }
    }
}

/// Runs for the rest of a worker's lifetime: reconciles `bound` (from a prior [`initial_bind`]) against
/// each snapshot published on `config_ping`, until `drain` or `shutdown` fires.
///
/// At drain start every accept loop is aborted and awaited, dropping its `TcpListener`: new
/// connections are refused and no later snapshot can rebind. Established connections are untouched;
/// they own their tasks. `lifecycle.mark_listener_bound()` runs after each reconcile that leaves a
/// listener bound, so `/ready` turns live for listeners that arrive later through LDS.
///
/// Rust note: `initial_bind` is fallible and runs first, so startup failures are loud. This function
/// is infallible from there: reconcile-time bind failures are logged and skipped.
// `factory_state` tips this past clippy's 7-argument ceiling, like `reconcile`'s own `#[allow]`.
// `secret_registry` rides along the same way.
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
        // Rust note: `biased;` polls branches in source order. Drain comes first, so a snapshot published
        // at the same instant as a drain cannot rebind a listener.
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

    // Aborting only schedules cancellation. Awaiting each handle is what guarantees the `TcpListener`
    // is dropped before this returns.
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
#[path = "listener_ledger_tests.rs"]
mod ledger_tests;

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
    use crate::test_ports::free_port;
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

    /// The accept loop's accept sets `TCP_NODELAY`, so a small response write is not held for the
    /// client's delayed ACK. The client side of the same connection is left at the kernel default,
    /// which shows the option is not on by default here.
    #[test]
    fn accept_downstream_sets_nodelay() {
        run_local(async {
            let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let name = ListenerName::from("nodelay");
            let (accepted, _peer) =
                tokio::time::timeout(Duration::from_secs(5), accept_downstream(&listener, &name))
                    .await
                    .expect("accept should resolve promptly")
                    .unwrap();
            assert!(
                !client.nodelay().unwrap(),
                "kernel default must be Nagle on"
            );
            assert!(
                accepted.nodelay().unwrap(),
                "accepted socket must have TCP_NODELAY"
            );
        });
    }

    /// A connected loopback `TcpStream` pair, for testing [`peek_for_h2_preface`] and
    /// [`resolve_plaintext_codec`] without a full listener harness. Mirrors `tls_inspector::tests::loopback_pair`.
    async fn tcp_loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    // --- `codec_type` peek/dispatch on a plaintext connection --------

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

    /// An ordinary h1 method must be rejected at its first byte, not after waiting out the preface
    /// timeout. Same property as `tls_inspector::non_tls_first_byte_returns_none_promptly`.
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

    /// A valid preface split across a slow write must keep being read, not rejected at the first
    /// short read.
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

    /// A client that sends a partial preface and then goes quiet must still resolve, falling back to
    /// h1 once `H2_PREFACE_PEEK_TIMEOUT` elapses. The outer `tokio::time::timeout` is the test's own
    /// safety net, so a regression fails instead of hanging.
    #[test]
    fn resolve_plaintext_codec_auto_falls_back_to_http1_when_a_partial_preface_never_completes() {
        run_local(async {
            let (mut client, server) = tcp_loopback_pair().await;
            client.write_all(&H2_CLIENT_PREFACE[..10]).await.unwrap();
            // Never sends the rest and never closes, so `server` must give up on its own.

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

    /// A minimal `tcp_proxy` filter targeting `cluster`: no idle timeout, one connect attempt. Empty
    /// filter lists are rejected at lowering, so each held-open fixture needs a terminal filter.
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
            stream_idle_timeout: None,
            max_stream_duration: None,
            max_request_headers_kb: 60,
            max_headers_count: 100,
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

    /// An `http_connection_manager` whose `http_filters` are the built-in [`crate::header_mutation_filter`]
    /// followed by the terminal router. This exercises the `FilterRegistry` -> `FilterChainHandler`
    /// wiring end to end (see `hcm_filter_chain_mutates_headers_over_the_real_socket`). The route table
    /// is [`direct_response_route_table`], so the router produces a real 200 for the encode filter to mutate.
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
            stream_idle_timeout: None,
            max_stream_duration: None,
            max_request_headers_kb: 60,
            max_headers_count: 100,
        })
    }

    /// A single match-all-chain listener whose sole filter is `filter`. [`match_all_listener`]
    /// delegates here for the idle-timeout-less `tcp_proxy` case.
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

    /// Accept forever and hold each connection open without reading or writing. A stand-in upstream
    /// for tests that only check the downstream side stays open.
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

    /// Accept forever and echo bytes back until the peer closes. The default upstream for tests that
    /// push data through the pump.
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

    /// Like [`snapshot_with`], plus a cluster map, for fixtures whose chain dispatches to `tcp_proxy`.
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

    /// Same match criteria as [`sni_only_listener`], plus a `tls_inspector` listener filter so
    /// `server_names` can see the ClientHello's SNI.
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

    /// Drive a `rustls::ClientConnection` to its first flight (the ClientHello) and return those bytes,
    /// without touching the network. Same technique as `tls_inspector`'s unit tests.
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

    /// Build a [`ClusterManager`] from `snapshot`'s clusters, force-initialized so `pick_host` never
    /// waits on real DNS. The listener wiring and the HTTP router share this manager.
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

    /// A fresh single-worker [`RouterStats`] for every cluster in `snapshot`. `RouterFilterFactory`
    /// records into it.
    ///
    /// Takes `control` by reference, as do [`downstream_stats_for`] and [`token_stats_for`]: all three
    /// recorders must share one [`proxy_observability::stats::StatsControl`]. A
    /// [`Handle`](proxy_observability::stats::Handle) indexes its resolving control's registry, so a
    /// handle from a different control panics with "index out of bounds".
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

    /// [`router_stats_for`]'s counterpart for `downstream_cx_total`. Shares `control` for the same reason.
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

    /// [`router_stats_for`]'s counterpart for `llm.client.token.usage`, resolved for every cluster
    /// (= provider, AGENTS.md invariant 6) in `snapshot`.
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
        // Dropping the sender makes `drain_started` pend forever, as these non-drain tests want.
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
            ledger: None,
            traces: None,
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
            let port = free_port();
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
            let port = free_port();
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
            let port = free_port();
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
            let port = free_port();
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
            let port = free_port();
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = sni_only_listener_with_tls_inspector("l1", addr, "unused");
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

            // Not TLS, so tls_inspector reports plaintext, and the sni-only chain never matches it.
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
            let port = free_port();
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

            // Let the accept loop accept and match this connection before v2 is published. Otherwise it
            // could match under v2, which is not what this test exercises.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert_eq!(
                harness.registry.live(),
                1,
                "held connection should be registered"
            );

            // Publish v2: same name and address, but the only chain requires SNI and never matches a raw
            // connection. No rebind should happen.
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
            let old_port = free_port();
            let old_addr: SocketAddr = format!("127.0.0.1:{old_port}").parse().unwrap();
            let new_port = free_port();
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

            // Replacing the accept loop must not abort a connection already handed off.
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
            let port = free_port();
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
            let old_port = free_port();
            let old_addr: SocketAddr = format!("127.0.0.1:{old_port}").parse().unwrap();
            // A plain Tokio listener does not opt into SO_REUSEPORT, so it blocks the replacement address.
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
            let port = free_port();
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

            // As in `chain_update_without_rebind_applies_to_new_connections_only`: let the accept loop match
            // this connection before the listener is removed.
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

    /// Mint a self-signed leaf for `name`. Enough to check which factory served the connection; not
    /// chain-of-trust, which `proxy-core/tests/tls.rs` covers.
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

    /// A match-all listener whose `transport_socket` terminates TLS with a self-signed cert for `cn`.
    /// Includes the `tls_inspector` filter, so SNI-keyed chains work too.
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
        // No cluster backs either chain: the test checks only which cert was served, which settles before
        // `tcp_proxy` looks up the cluster.
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

    /// A client-side TLS factory that sends `sni` and skips server-cert validation. Tests check which cert
    /// was served, not chain-of-trust.
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

    /// Like [`client_factory_with_sni`], with an explicit ALPN offer, so the h2 test controls the protocol
    /// the client proposes.
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

    /// An `http_connection_manager` filter whose route always returns a fixed-status `DirectResponse`. The
    /// h2 dispatch tests only check which codec served the connection. `codec_type` defaults to `Auto`;
    /// see [`hcm_filter_direct_response_with_codec`] for explicit codecs.
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
            stream_idle_timeout: None,
            max_stream_duration: None,
            max_request_headers_kb: 60,
            max_headers_count: 100,
        })
    }

    /// Covers the ALPN dispatch in [`downstream_codec_for_alpn`]: an `alpn_protocols: ["h2", ...]` listener
    /// must serve h2 framing, not h1.
    ///
    /// Checked at the wire-framing level, since `proxy-core` carries no `hyper` dependency (see
    /// `spawn_http_upstream_chunked_json`). The h2 side hand-writes the client preface (RFC 7540 S3.5) and
    /// expects a SETTINGS frame back at stream 0, which only a real h2 codec produces. `serve_http1` would
    /// fail on the `PRI *` request line, so this discriminates the two codecs.
    #[test]
    fn alpn_negotiated_protocol_selects_the_serving_codec() {
        run_local(async {
            let port = free_port();
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
            // Empty SETTINGS frame: length 0, type 0x4, flags 0, stream id 0 (RFC 7540 S4.1/S6.5).
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

    /// An empty SETTINGS frame (RFC 9113 S4.1/S6.5). With [`H2_CLIENT_PREFACE`] it forms a complete client
    /// connection preface (RFC 9113 S3.4). Shared by the plaintext dispatch tests.
    const EMPTY_SETTINGS_FRAME: [u8; 9] = [0, 0, 0, 0x4, 0x0, 0, 0, 0, 0];

    /// True if `frame_header` (the first 9 bytes read back) is a SETTINGS frame at stream 0, which only a
    /// real h2 codec sends first.
    fn looks_like_a_settings_frame_at_stream_zero(frame_header: &[u8]) -> bool {
        frame_header.len() >= 9 && frame_header[3] == 0x4 && frame_header[5..9] == [0, 0, 0, 0]
    }

    /// Reads whatever arrives on `stream` within `wait`, or an empty `Vec` on EOF, reset, or timeout. Used
    /// to assert a negative: the wrong codec usually closes the connection or sends an error frame.
    async fn read_whatever_arrives(stream: &mut TcpStream, wait: Duration) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        match tokio::time::timeout(wait, stream.read(&mut buf)).await {
            Ok(Ok(0)) | Err(_) => Vec::new(),
            Ok(Ok(n)) => buf[..n].to_vec(),
            Ok(Err(_)) => Vec::new(),
        }
    }

    /// `codec_type: AUTO` on a **plaintext** connection peeks for the h2 preface, since there is no ALPN
    /// (see [`resolve_plaintext_codec`]). The plaintext counterpart of
    /// `alpn_negotiated_protocol_selects_the_serving_codec`, on the same listener.
    #[test]
    fn plaintext_codec_auto_detects_h2_prior_knowledge_and_an_ordinary_h1_request() {
        run_local(async {
            let port = free_port();
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

    /// `codec_type: HTTP2` is unconditional: an ordinary h1 request that `AUTO` would serve as h1 must not
    /// get h1 back. This catches an explicit codec silently falling back to `AUTO`'s peek.
    #[test]
    fn plaintext_codec_type_http2_serves_h2_unconditionally() {
        run_local(async {
            let port = free_port();
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

            // -- discriminating: `AUTO` would answer this h1 request with "HTTP/1.1 200"; unconditional HTTP2
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

    /// `codec_type: HTTP1` is unconditional, even when a preface is present. Mirror of
    /// `plaintext_codec_type_http2_serves_h2_unconditionally`.
    #[test]
    fn plaintext_codec_type_http1_serves_h1_unconditionally() {
        run_local(async {
            let port = free_port();
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

            // -- discriminating: a valid h2 preface must not get a SETTINGS frame back. `AUTO` would answer
            // with one; unconditional HTTP1 must not.
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
            let port = free_port();
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

            // No EOF within ~200ms: the handshake completed and the stub handler holds the connection open
            // under the TLS layer.
            let mut buf = [0u8; 8];
            let result = tokio::time::timeout(Duration::from_millis(200), tls.read(&mut buf)).await;
            assert!(
                result.is_err(),
                "expected read to time out (connection held open after TLS termination), got {result:?}"
            );

            harness.shutdown().await;
        });
    }

    /// A match-all TLS listener on `addr` with handshake deadline `timeout` and a connection cap of one.
    /// No `tls_inspector`, so a client that sends nothing stalls in the handshake itself.
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
            let port = free_port();
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
            let port = free_port();
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
            let port = free_port();
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
            let port = free_port();
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
                ledger: None,
                traces: None,
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
                    // Also checks `Display` end to end: the text `crates/proxy`'s startup path prints.
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
            let port = free_port();
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
            let port = free_port();
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

            // Larger than any socket buffer, so BOTH directions apply backpressure at once. A pump that
            // serializes read and write within one direction deadlocks here, so the client must also read
            // and write concurrently (split halves).
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
            let port = free_port();
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
            let port = free_port();
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
                    // Downstream's write half is closed (FIN seen): report it, then prove the reverse
                    // direction still works by sending a reply.
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

            // The reverse direction stays open after downstream's write half closes: the client should
            // still get upstream's reply.
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
            let port = free_port();
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
            let port = free_port();
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

            // Ping-pong past the idle timeout. Each round trip resets the idle clock, so the connection must
            // stay open throughout.
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
            let port = free_port();
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
            let port = free_port();
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

    /// The HCM terminal is a real `RouterHandler`, not a fixed-200 stub. An empty route table means every
    /// request takes the `NoVirtualHost` path (404). This proves HTTP is served over the real socket; see
    /// `hcm_filter_chain_mutates_headers_over_the_real_socket` for a route that matches.
    #[test]
    fn hcm_terminal_filter_serves_http_over_the_real_socket() {
        run_local(async {
            let port = free_port();
            let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
            let listener_ir = match_all_listener_with_filter("l1", addr, hcm_filter());
            let harness = spawn_manager(snapshot_with(listener_ir, 1)).await;

            tokio::time::sleep(Duration::from_millis(50)).await;

            let mut stream = TcpStream::connect(addr)
                .await
                .expect("connect should succeed");
            // `Connection: close` so the server closes after this response, letting the test read to EOF.
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

    /// A listener whose HCM chain runs the built-in header-mutation filter ahead of the terminal router.
    /// The mutation must show in the response bytes over a real socket. That proves `build_hcm_handler`
    /// builds a real `FilterChainHandler` on the shared `FilterRegistry`, with the real router as terminal.
    #[test]
    fn hcm_filter_chain_mutates_headers_over_the_real_socket() {
        run_local(async {
            let port = free_port();
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

    /// A one-vhost, one-route table matching every request (`*` domain, empty prefix) with a `Forward` to
    /// `cluster`. Counterpart to [`direct_response_route_table`] that exercises `RouterHandler::apply_forward`'s
    /// cluster-manager and pool path.
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

    /// Like [`hcm_filter_with_header_mutation`], but the route forwards to a real cluster instead of a
    /// `DirectResponse`. The router must dial an upstream, not just run the encode chain.
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
            stream_idle_timeout: None,
            max_stream_duration: None,
            max_request_headers_kb: 60,
            max_headers_count: 100,
        })
    }

    /// Serve a fixed 200 over real HTTP/1.1 on an ephemeral port, forever: the "real upstream" for the
    /// router-forwarding test. Uses `proxy_http`'s own codec and `FixedResponseHandler`, the same stub
    /// `proxy-http`'s tests use to fake an origin.
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
                            request_head_limits: Default::default(),
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

    /// Like [`spawn_http_upstream`], but writes a **chunked** `application/json` response by hand over the
    /// raw socket.
    ///
    /// Rust note: this must not reuse `FixedResponseHandler`. Its `Full` body has an exact size hint, so
    /// hyper stamps a `content-length` on the response and `RouterHandler` forwards it. Hyper then stops
    /// polling the encoder once that many bytes are written, so the final end-of-stream frame never
    /// arrives and the usage filter's `finalize()` never runs. A chunked body avoids that path. Raw
    /// chunked bytes keep this fixture inside `proxy-core`'s existing dependencies.
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
                    // Drain the request up to the header/body separator, so no half-read request is left in
                    // the kernel buffer.
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

    /// Acceptance test: a real HTTP request is routed (route match, then cluster and host pick, then
    /// upstream codec, then encode filters) to a real upstream over HTTP/1.1, and the response flows back
    /// through the encode chain.
    ///
    /// Mutation-tested: reverting `build_hcm_handler`'s terminal to `FixedResponseHandler` makes this
    /// fail, since the stub never contacts `upstream_addr`.
    #[test]
    fn router_forwards_a_real_request_to_a_real_upstream_over_http1() {
        run_local(async {
            let port = free_port();
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
    /// Mutation-tested: dropping the `UsageFilterFactory` registration, or making `classify_body` treat
    /// `application/json` as `Inert`, makes this fail. No line is ever written, so the bounded poll below times out.
    #[test]
    fn usage_filter_records_tokens_from_a_real_upstream_response() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        run_local(async {
            let proxy_port = free_port();
            let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

            let upstream_body: &'static [u8] = br#"{"id":"x","usage":{"prompt_tokens":100,"completion_tokens":20,"prompt_tokens_details":{"cached_tokens":80}}}"#;
            let upstream_addr = spawn_http_upstream_chunked_json(upstream_body).await;

            let log_path = std::env::temp_dir().join(format!(
                "llm-proxy-usage-filter-test-{}-{}.log",
                std::process::id(),
                proxy_port
            ));
            // Rust note: `Path::display()` rather than `to_str().unwrap()`, so a non-UTF8 temp dir cannot
            // panic. The YAML only needs a path, not a lossless round trip of the OS path type.
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
            // The proxy's own response is chunked too (nothing downstream re-adds a `content-length`), so
            // unwrap the framing before comparing with the upstream's raw body.
            let response_body = dechunk(raw_body);
            assert_eq!(
                response_body, upstream_body,
                "the usage filter observes the body -- it must never alter or truncate it"
            );

            harness.shutdown().await;

            // `FileSink` flushes per line, but the write can race harness shutdown, so poll briefly.
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
            // Four distinct values, so a wrong-field extraction cannot pass.
            assert_eq!(&fields[0..5], &["20", "80", "0", "20", "120"]);
            assert_ne!(
                fields[5], "-",
                "time-to-first-byte must be populated for a real streamed response"
            );

            let _ = std::fs::remove_file(&log_path);
        });
    }

    /// An invalid per-route usage dialect must be a build error, even under `is_optional: true`.
    /// `is_optional` tolerates only a filter with no per-route config (`ConfigError::Unimplemented`; see
    /// `filter_manager::resolve_per_filter_row`). A malformed dialect (`ConfigError::InvalidValue`) must
    /// not be swallowed, or a typo would silently meter with the listener-level dialect.
    ///
    /// The rejection only happens when the chain is built against the real factories, so this drives
    /// `build_listener_hcm` directly, with no socket.
    ///
    /// Mutation-tested: changing `resolve_per_filter_row`'s `Unimplemented` arm to `Err(_) if
    /// cfg.is_optional` makes this fail.
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
        // No clusters are needed to build the chain: route to cluster resolution happens per request.
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
            ledger: None,
            traces: None,
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

    /// The `build_hcm_handler` half of the regression: two listeners each configure `llmproxy.auth` with
    /// their own `hmac_secret`, built through `build_listener_hcm` against one `SharedFactoryState`, as
    /// `initial_bind` does for a real multi-listener config. Each listener's `context` must become a
    /// different `FactoryContext::scope`, so each gets its own `ControlPlane` singleton instead of
    /// colliding on `llmproxy.auth`'s shared `type_url`.
    ///
    /// This proves only that the scopes differ (`get_across_scopes` reports a collision as `Err`).
    /// `auth_filter`'s `two_scopes_over_one_shared_state_get_independent_control_planes` proves the two
    /// enforce independently.
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
            ledger: None,
            traces: None,
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

    // --- route names for the token limiter's usage read ----------------------

    /// A one-listener bootstrap whose route table holds `routes` (YAML route
    /// entries, already indented), for the route-names tests below.
    fn bootstrap_with_routes(routes: &str) -> String {
        format!(
            r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 127.0.0.1, port_value: 0 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: l1
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc1
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
{routes}
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
                    socket_address: {{ address: 127.0.0.1, port_value: 1 }}
"#
        )
    }

    /// Build `yaml`'s listener `l1` against `factory_state` and return the
    /// route names its chain published.
    fn published_route_names(yaml: &str, factory_state: &Arc<SharedFactoryState>) -> Vec<String> {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
            .expect("bootstrap YAML must parse");
        let snapshot = build_snapshot(&loaded).expect("bootstrap YAML must lower");
        let cluster_manager = Arc::new(ClusterManager::new(
            Arc::new(proxy_cluster::resolver::TokioResolver),
            crate::tls::transport_socket_builder(),
        ));
        let stats_control = proxy_observability::stats::StatsControl::new(1);
        let router_stats = router_stats_for(&stats_control, &snapshot);
        let token_stats = token_stats_for(&stats_control, &snapshot);
        let latency_stats = latency_stats_for(&stats_control);
        let hcm_runtime = HcmRuntime {
            snapshot_version: snapshot.version,
            routes: &snapshot.routes,
            cluster_manager: &cluster_manager,
            router_stats: &router_stats,
            token_stats: &token_stats,
            latency_stats: &latency_stats,
            tracing_handles: None,
            metadata: None,
            ledger: None,
            traces: None,
            factory_state,
        };
        build_listener_hcm(
            snapshot.listeners.get("l1").expect("listener l1"),
            &hcm_runtime,
        )
        .expect("the chain must build");
        factory_state
            .get(
                "listener 'l1' filter_chains[0]",
                proxy_control::window_usage::ROUTE_NAMES_KEY,
            )
            .expect("the chain publishes its route names")
            .downcast::<proxy_control::window_usage::ChainRouteNames>()
            .expect("the route-names singleton is always ChainRouteNames")
            .load()
            .as_ref()
            .clone()
    }

    /// A shared-store `GET /v1/usage` reads one store row per route, so the chain must publish every route
    /// name (an unnamed route under the empty name, as the token limiter buckets it). A rebuild must
    /// replace the list, or a new route stays out of every tenant's usage.
    #[test]
    fn a_chain_build_publishes_its_route_names_and_a_rebuild_replaces_them() {
        let factory_state = Arc::new(SharedFactoryState::default());
        let first = bootstrap_with_routes(
            r#"                        - name: images
                          match: { prefix: "/v1/images" }
                          route: { cluster: up }
                        - name: chat
                          match: { prefix: "/v1/chat" }
                          route: { cluster: up }
                        - match: { prefix: "/" }
                          route: { cluster: up }"#,
        );
        assert_eq!(
            published_route_names(&first, &factory_state),
            ["", "chat", "images"]
        );

        let updated = bootstrap_with_routes(
            r#"                        - name: embeddings
                          match: { prefix: "/v1/embeddings" }
                          route: { cluster: up }"#,
        );
        assert_eq!(
            published_route_names(&updated, &factory_state),
            ["embeddings"]
        );
    }

    // --- body-rewrite filter over a real socket -----------

    /// A real upstream that reads a raw HTTP/1.1 request by hand, echoes the body back, and reports as
    /// headers the `content-length` the request declared and the body bytes it actually read. The
    /// body-rewrite filter must keep those equal after it splices bytes in and grows `content-length`. A
    /// unit test cannot observe that, because it never uses real framing on a real socket.
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

                    // This fixture stops reading at the declared length, as a real upstream does. Any extra
                    // bytes the proxy put on the wire stay in the kernel buffer; a short bounded probe reports
                    // them as `leftover_bytes`. A healthy request always has zero.
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

    /// Acceptance test: a bootstrap wires `type.llmproxy.dev/llmproxy.filters.v0.BodyRewrite` ahead of the
    /// router. A streaming OpenAI request without `stream_options` goes over a real socket, and the upstream
    /// must receive the original body with `stream_options` spliced in, byte for byte, and nothing left
    /// unread (`x-leftover-bytes: 0`). That proves the splice and the `modify_decoded_headers`
    /// content-length fix-up landed together.
    ///
    /// Mutation-tested: skipping the `modify_decoded_headers` call makes this fail. The fixture stops at
    /// the stale length and leaves injected bytes unread (`x-leftover-bytes` > 0). The exact-body
    /// comparison and the leftover-bytes probe are what make the test load-bearing.
    #[test]
    fn body_rewrite_filter_injects_and_fixes_content_length_over_a_real_upstream() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        run_local(async {
            let proxy_port = free_port();
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

    /// Acceptance test: `llmproxy.token_limit` is configured BEFORE `llmproxy.usage` (order matters; see
    /// `token_limit_filter`'s module doc). A real upstream reports 120 tokens per response against a
    /// 100-token budget. Two sequential requests, each on its own socket: the first gets 200, and the
    /// second gets 429 with rate-limit headers. The second is refused because of tokens the first spent,
    /// which no unit test covers, since none runs a real usage-record-check loop across two HTTP exchanges.
    ///
    /// Mutation-tested: running `llmproxy.usage` before `llmproxy.token_limit` makes this fail, since both
    /// requests return 200.
    #[test]
    fn token_limit_filter_denies_the_second_request_after_the_first_spends_its_budget() {
        use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

        run_local(async {
            let proxy_port = free_port();
            let proxy_addr: SocketAddr = format!("127.0.0.1:{proxy_port}").parse().unwrap();

            // input=20 (100 prompt - 80 cached), cached=80, cache_creation=0, output=20: total 120, as in
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
                        // A token limit admits only endpoints whose tokens it can count
                        // (ADR-0010 decision 1), so this is chat, not `GET /`.
                        b"POST /v1/chat/completions HTTP/1.1\r\nHost: t\r\nAuthorization: Bearer sk-e2e\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
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

            // First request: the budget starts empty, so it is admitted. Its 120 actual tokens exhaust the
            // budget for the next request.
            let (first_status, _first_headers) = send_request(proxy_addr).await;
            assert_eq!(
                first_status, 200,
                "the first request must be admitted -- the budget starts empty"
            );

            // The store's `record` is synchronous, but give the harness a moment to tear down the first
            // connection before opening the second.
            tokio::time::sleep(Duration::from_millis(20)).await;

            // Second request: the first's 120 tokens are now recorded against a 100-token budget, so this
            // one must be denied.
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
