//! Per-worker listener manager (WP-07 chunk C): each worker binds its own
//! socket per listener, accepts connections, matches them against the
//! listener's filter chains (`crate::filter_chain`), and dispatches to the
//! matched chain's terminal L4 network filter -- `tcp_proxy` (WP-09,
//! `crate::tcp_proxy`) today; HTTP connection manager L4 entry is WP-10/11.
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

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use proxy_cluster::manager::ClusterManager;
use proxy_config::ir::{
    HttpConnectionManagerConfig, ListenerConfig, ListenerFilterSpec, ListenerName,
    NetworkFilterSpec, SnapshotVersion,
};
use proxy_config::ConfigSnapshot;
use proxy_http::codec::{serve_http1, Http1Options};
use proxy_http::filter::{FactoryContext, FilterInstanceFactory, FilterRegistry};
use proxy_http::filter_manager::FilterChainHandler;
use proxy_http::handler::{DownstreamInfo, StreamHandler};
use proxy_http::router::RouterHandler;
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::drain::ConnectionRegistry;
use crate::filter_chain::{select_filter_chain, ConnectionProperties};
use crate::header_mutation_filter::HeaderMutationFactory;
use crate::tcp_proxy::{self, TcpProxyParams};
use crate::tls::{DownstreamTlsFactory, TlsBuildError};
use crate::tls_inspector::inspect_client_hello;
use crate::WorkerConfigHandle;

/// The shared [`FilterRegistry`]: every worker's listeners look up HTTP
/// filter factories by `type_url` against the same registered set, built
/// exactly once (ground rule from WP-11's wiring task: "construct it once
/// and share it, do not build a registry per connection").
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
        Arc::new(registry)
    })
}

/// Compiled downstream TLS factories for one listener's filter chains
/// (WP-08 chunk C3), aligned by index with `ListenerConfig.filter_chains`,
/// plus the `default_filter_chain`. `None` in a slot means that chain has no
/// `transport_socket` (plaintext) -- or, only after a failed *runtime*
/// rebuild (see `spawn_accept_loop`), that its factory couldn't be rebuilt.
///
/// Rust note: these factories hold live `rustls` state (cert resolvers,
/// crypto providers) so they can't live in `ConfigSnapshot` -- `proxy-config`
/// can't depend on `proxy-core`'s TLS types (ground rule #2). Instead each
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

/// Build the compiled TLS factories for every `filter_chains[i]` (and the
/// `default_filter_chain`) of `listener` whose `transport_socket` is
/// configured. `None` transport_socket -> `None` slot (plaintext); a build
/// error names the listener + chain in its `TlsBuildError::context` and
/// propagates, letting the caller decide fatal-vs-log-and-skip.
fn build_listener_tls(listener: &ListenerConfig) -> Result<ListenerTls, TlsBuildError> {
    let mut chain_factories = Vec::with_capacity(listener.filter_chains.len());
    for (i, chain) in listener.filter_chains.iter().enumerate() {
        let factory = match &chain.transport_socket {
            Some(spec) => {
                let context = format!("listener '{}' filter_chains[{i}]", listener.name);
                Some(Arc::new(DownstreamTlsFactory::build(spec, &context)?))
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
            Some(Arc::new(DownstreamTlsFactory::build(spec, &context)?))
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
/// silent skip of a configured filter (ground rule #1).
#[derive(Debug, thiserror::Error)]
#[error("{context}: {reason}")]
pub struct HttpFilterChainBuildError {
    context: String,
    reason: String,
}

/// Compiled HTTP filter-chain handlers for one listener's filter chains
/// (this WP-11 wiring task), aligned by index with
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
    cluster_manager: &Arc<ClusterManager>,
) -> Result<ListenerHcm, HttpFilterChainBuildError> {
    let mut chain_handlers = Vec::with_capacity(listener.filter_chains.len());
    for (i, chain) in listener.filter_chains.iter().enumerate() {
        let handler = match chain.filters.last() {
            Some(NetworkFilterSpec::HttpConnectionManager(hcm)) => {
                let context = format!("listener '{}' filter_chains[{i}]", listener.name);
                Some(build_hcm_handler(hcm, &context, cluster_manager)?)
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
            Some(build_hcm_handler(hcm, &context, cluster_manager)?)
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

/// Bind `listener_ir` and spawn its accept loop, returning the [`BoundListener`]
/// on success. The one place that actually calls `bind_listener` +
/// `spawn_accept_loop` together; [`initial_bind`] and reconcile-time binding
/// (`bind_and_spawn`) each decide what to do with the `Err` case differently.
/// Bundles the per-worker state every bind/accept function below needs
/// (config handle, connection registry, drain signal, cluster manager) --
/// purely to keep `spawn_bound`/`bind_and_spawn`'s argument count under
/// clippy's `too_many_arguments` threshold, the same motivation
/// [`ListenerCaches`] documents for the per-listener build outputs.
/// [`initial_bind`]/[`reconcile`] (the public-ish entry points) keep their
/// four separate parameters -- this bundle is purely an internal plumbing
/// convenience built once at their top and threaded down by reference.
struct WorkerShared<'a> {
    config: &'a Arc<WorkerConfigHandle>,
    registry: &'a ConnectionRegistry,
    shutdown: &'a watch::Receiver<bool>,
    cluster_manager: &'a Arc<ClusterManager>,
}

fn spawn_bound(
    name: &ListenerName,
    listener_ir: &Arc<ListenerConfig>,
    version: SnapshotVersion,
    shared: &WorkerShared<'_>,
) -> Result<BoundListener, InitialBindError> {
    // Built before the socket bind: no point opening a listening socket for a
    // filter chain whose certs won't load, or whose HTTP filter chain
    // references an unregistered filter.
    let tls = build_listener_tls(listener_ir)?;
    let hcm = build_listener_hcm(listener_ir, shared.cluster_manager)?;
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
        version,
        ListenerCaches { tls, hcm },
        AcceptLoopShared {
            config: shared.config.clone(),
            registry: shared.registry.clone(),
            shutdown: shared.shutdown.clone(),
            cluster_manager: shared.cluster_manager.clone(),
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
    version: SnapshotVersion,
    bound: &mut HashMap<ListenerName, BoundListener>,
    shared: &WorkerShared<'_>,
) {
    match spawn_bound(&name, listener_ir, version, shared) {
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
/// silent degradation ground rule #1 forbids. On error, any listeners this
/// call already bound are unwound (their accept-loop tasks aborted) before
/// returning, so a failed `initial_bind` leaves nothing running.
///
/// On success, hand the returned map to [`run_listener_manager`], which picks
/// up reconciliation against subsequent config pushes from there.
pub fn initial_bind(
    snapshot: &Arc<ConfigSnapshot>,
    config: &Arc<WorkerConfigHandle>,
    registry: &ConnectionRegistry,
    shutdown: &watch::Receiver<bool>,
    cluster_manager: &Arc<ClusterManager>,
) -> Result<HashMap<ListenerName, BoundListener>, InitialBindError> {
    let shared = WorkerShared {
        config,
        registry,
        shutdown,
        cluster_manager,
    };
    let mut bound: HashMap<ListenerName, BoundListener> = HashMap::new();
    for (name, listener_ir) in snapshot.listeners.iter() {
        if !listener_ir.bind_to_port {
            tracing::debug!(listener = %name, "bind_to_port=false; not binding");
            continue;
        }
        match spawn_bound(name, listener_ir, snapshot.version, &shared) {
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
    cluster_manager: Arc<ClusterManager>,
}

/// One accept loop per bound listener, spawned with `spawn_local` (this
/// module is worker-local / `!Send` per ADR-0003, same as the rest of
/// `proxy-core`).
fn spawn_accept_loop(
    name: ListenerName,
    tcp_listener: TcpListener,
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
        cluster_manager,
    } = shared;
    tokio::task::spawn_local(async move {
        // Rust note: `mut` locals, not behind a lock -- this whole task is
        // single-threaded (`spawn_local` on a `!Send` `LocalSet`, ADR-0003),
        // so nothing else can observe or race these between `.await` points.
        // `tls_cache`/`hcm_cache` are `Rc`s so each accepted connection's task
        // gets a cheap clone of the same compiled factories/handlers (pointer
        // bump, no rebuild).
        let mut tls_version = initial_version;
        let mut tls_cache = Rc::new(initial_tls);
        let mut hcm_cache = Rc::new(initial_hcm);
        loop {
            let (stream, peer) = tokio::select! {
                accepted = tcp_listener.accept() => match accepted {
                    Ok(pair) => pair,
                    Err(err) => {
                        tracing::warn!(listener = %name, error = %err, "accept() failed");
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

            // The accept loop's own TLS factory cache goes stale exactly when
            // the snapshot version does (WP-08 chunk C3): a chain-only config
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
                if let Some(l) = snapshot.listeners.get(&name) {
                    match build_listener_tls(l) {
                        Ok(rebuilt) => tls_cache = Rc::new(rebuilt),
                        Err(err) => {
                            tracing::warn!(listener = %name, error = %err, "failed to rebuild TLS factories after config change; TLS-requiring chains on this listener will reset connections until fixed");
                            tls_cache = Rc::new(ListenerTls::empty_for(l));
                        }
                    }
                    // Same rebuild cadence and same "whole-listener fallback"
                    // tradeoff as the TLS cache just above, for the HTTP
                    // filter-chain handlers.
                    match build_listener_hcm(l, &cluster_manager) {
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
            }));
        }
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
    // stops compiling until it's handled here too, which is exactly ground
    // rule #1 (never silently drop a config field) enforced by the type
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

    let factory = matched
        .transport_socket
        .as_ref()
        .and_then(|_| match chain_idx {
            Some(idx) => tls.chain_factories.get(idx).cloned().flatten(),
            None => tls.default_factory.clone(),
        });

    match (matched.transport_socket.is_some(), factory) {
        (true, Some(factory)) => match factory.wrap(stream).await {
            Ok(tls_stream) => {
                // Can't `reset` (SO_LINGER) a `TlsStream` the way we can a
                // bare `TcpStream` -- `run_terminal_filter` hands the stream
                // back on the no-op paths so the *unimplemented*/no-filter
                // cases just drop it and let the close be a clean FIN.
                let downstream = DownstreamInfo {
                    remote: peer,
                    is_tls: true,
                };
                let _ = run_terminal_filter(
                    tls_stream, filter, snapshot, &registry, shutdown, &name, downstream,
                )
                .await;
            }
            Err(err) => {
                tracing::debug!(listener = %name, peer = %peer, error = %err, "TLS handshake failed; dropping connection");
            }
        },
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
            // terminal L4 filter on `stream`.
            let downstream = DownstreamInfo {
                remote: peer,
                is_tls: false,
            };
            if let Some(stream) = run_terminal_filter(
                stream, filter, snapshot, &registry, shutdown, &name, downstream,
            )
            .await
            {
                reset(&stream, &name);
            }
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
/// listener/chain), never a silent skip (ground rule #1). The router itself
/// (`envoy.filters.http.router`, `is_router: true`) is the terminal --
/// [`proxy_http::router::RouterHandler`] -- not one of these chain filters
/// (WP-13).
fn build_hcm_handler(
    hcm: &HttpConnectionManagerConfig,
    context: &str,
    cluster_manager: &Arc<ClusterManager>,
) -> Result<Rc<dyn StreamHandler>, HttpFilterChainBuildError> {
    let registry = filter_registry();
    let factory_ctx = FactoryContext {};
    let mut factories: Vec<Arc<dyn FilterInstanceFactory>> =
        Vec::with_capacity(hcm.http_filters.len());
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
        factories.push(Arc::from(instance_factory));
    }

    let terminal: Rc<dyn StreamHandler> = Rc::new(RouterHandler::new(
        hcm.route_table.clone(),
        cluster_manager.clone(),
    ));

    Ok(Rc::new(FilterChainHandler::new(
        factories,
        terminal,
        hcm.generate_request_id,
        hcm.use_remote_address,
        hcm.xff_num_trusted_hops,
    )))
}

/// Dispatch to the matched chain's terminal L4 filter. On the `TcpProxy` and
/// `Http` paths this registers the connection guard and runs to completion,
/// consuming `stream` and returning `None`. On the no-filter path it logs and
/// hands `stream` back so the caller can decide how to close it (a plaintext
/// `TcpStream` can be `reset`; a `TlsStream` is just dropped -- see the call
/// sites).
async fn run_terminal_filter<IO: AsyncRead + AsyncWrite + Unpin + 'static>(
    stream: IO,
    filter: Option<TerminalFilter>,
    snapshot: Arc<ConfigSnapshot>,
    registry: &ConnectionRegistry,
    mut shutdown: watch::Receiver<bool>,
    name: &ListenerName,
    // Rust note: bundled into one `Copy` struct (rather than a bare
    // `SocketAddr` + `bool`) so this already-long parameter list doesn't grow
    // by two for S9 -- also doubles as `peer` for the tracing calls below via
    // `downstream.remote`.
    downstream: DownstreamInfo,
) -> Option<IO> {
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
            // connection as live until the codec returns.
            let _guard = registry.register();

            // Rust note: `serve_http1` wants an `impl Future<Output = ()>`,
            // not a `watch::Receiver` directly (it's decoupled from
            // proxy-core's drain machinery on purpose -- see its doc
            // comment). `changed()` only ever resolves once in practice (the
            // sender flips `false` -> `true` exactly once, at drain time),
            // but the loop guards against spurious/duplicate notifications
            // rather than assuming that.
            let shutdown_fut = async move {
                if *shutdown.borrow() {
                    return;
                }
                while shutdown.changed().await.is_ok() {
                    if *shutdown.borrow() {
                        return;
                    }
                }
            };

            let options = Http1Options { keep_alive: true };
            if let Err(err) = serve_http1(stream, handler, options, shutdown_fut, downstream).await
            {
                tracing::debug!(listener = %name, peer = %peer, error = %err, "http/1.1 connection ended with an error");
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

/// Reconcile `bound` against `snapshot`: bind new listeners, rebind ones
/// whose address changed, leave unchanged ones alone, and stop accepting on
/// ones that were removed.
fn reconcile(
    snapshot: &Arc<ConfigSnapshot>,
    bound: &mut HashMap<ListenerName, BoundListener>,
    config: &Arc<WorkerConfigHandle>,
    registry: &ConnectionRegistry,
    shutdown: &watch::Receiver<bool>,
    cluster_manager: &Arc<ClusterManager>,
) {
    let shared = WorkerShared {
        config,
        registry,
        shutdown,
        cluster_manager,
    };
    // Removed: present in `bound`, absent from the new snapshot. Stop
    // accepting; established connections under the old listener keep their
    // own `Arc<ConfigSnapshot>` clone and drain independently (v1 "full
    // listener replace + drain" semantics -- no partial in-place chain
    // surgery on live connections).
    let removed: Vec<ListenerName> = bound
        .keys()
        .filter(|name| !snapshot.listeners.contains_key(*name))
        .cloned()
        .collect();
    for name in removed {
        if let Some(b) = bound.remove(&name) {
            tracing::info!(listener = %name, "listener removed from config; no longer accepting (existing connections drain independently)");
            b.task.abort();
        }
    }

    for (name, listener_ir) in snapshot.listeners.iter() {
        if !listener_ir.bind_to_port {
            // Envoy only uses such listeners via internal redirection
            // (`internal_listener`); we don't implement that, so we simply
            // never bind or accept for them.
            tracing::debug!(listener = %name, "bind_to_port=false; not binding");
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
                tracing::info!(listener = %name, old_addr = %existing.addr, new_addr = %listener_ir.address, "listener address changed; rebinding");
                existing.task.abort();
                bind_and_spawn(name.clone(), listener_ir, snapshot.version, bound, &shared);
            }
            None => {
                bind_and_spawn(name.clone(), listener_ir, snapshot.version, bound, &shared);
            }
        }
    }
}

/// Runs for the rest of a worker's lifetime: reconciles `bound` (already
/// populated by a prior, fallible [`initial_bind`] call) against each new
/// snapshot the control runtime publishes (`config_ping`), until `shutdown`
/// fires -- at which point every accept loop is aborted and this returns.
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
pub async fn run_listener_manager(
    mut bound: HashMap<ListenerName, BoundListener>,
    config: Arc<WorkerConfigHandle>,
    mut config_ping: watch::Receiver<SnapshotVersion>,
    mut shutdown: watch::Receiver<bool>,
    registry: ConnectionRegistry,
    cluster_manager: Arc<ClusterManager>,
) {
    loop {
        tokio::select! {
            changed = config_ping.changed() => {
                if changed.is_err() {
                    break;
                }
                let snapshot = config.load();
                reconcile(&snapshot, &mut bound, &config, &registry, &shutdown, &cluster_manager);
            }
            _ = shutdown.changed() => {
                break;
            }
        }
    }

    for (_, bound_listener) in bound.drain() {
        bound_listener.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::run_local;
    use proxy_config::ir::{
        FilterChainMatch, FilterChainSpec, ListenerConfig as IrListenerConfig, SourceType,
    };
    use std::io::ErrorKind;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;
    use tokio::net::TcpStream;

    use crate::tls::UpstreamTlsFactory;
    use proxy_config::ir::{
        ClusterConfig, DataSourceIR, DiscoveryType, DownstreamTlsSpec, EndpointIR, LbPolicy,
        TcpProxyConfig, TlsCertificateIR, TlsParametersIR, TlsVersion, UpstreamTlsSpec,
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

    /// A `tcp_proxy` filter targeting `cluster`, no idle timeout, a single
    /// connect attempt -- the minimal filter every "held open" fixture below
    /// needs now that empty filter lists no longer hold a connection open
    /// (WP-09: a chain with no terminal filter is reset, matching Envoy/the
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
    /// virtual hosts) and no http_filters. Since WP-13, the terminal is a
    /// real [`proxy_http::router::RouterHandler`], so a request against this
    /// empty table always takes the `NoVirtualHost` path (404) -- see
    /// `hcm_terminal_filter_serves_http_over_the_real_socket`, which exists
    /// to prove HTTP is served over the real socket at all, not any
    /// particular route outcome.
    fn hcm_filter() -> NetworkFilterSpec {
        NetworkFilterSpec::HttpConnectionManager(proxy_config::ir::HttpConnectionManagerConfig {
            stat_prefix: "test".to_string(),
            route_table: Arc::new(
                proxy_config::ir::RouteTable::new("test-routes".to_string(), vec![])
                    .expect("empty route table can't have duplicate domains"),
            ),
            http_filters: vec![],
            generate_request_id: true,
            use_remote_address: false,
            xff_num_trusted_hops: 0,
        })
    }

    /// A one-vhost, one-route table matching every request (`*` domain,
    /// empty-prefix path) with a `DirectResponse` action -- the router
    /// terminal synthesizes this response itself, no cluster/upstream
    /// involved. Used by `hcm_filter_chain_mutates_headers_over_the_real_socket`
    /// to prove the header-mutation filter's mutation survives the real
    /// router terminal (as opposed to the WP-13 acceptance test below, which
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
                    })],
                }],
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
    /// filter to mutate -- WP-13 replaced the fixed-200 stub this used to
    /// exercise.
    fn hcm_filter_with_header_mutation(header_name: &str, header_value: &str) -> NetworkFilterSpec {
        use crate::header_mutation_filter::{header_value_option, TYPE_URL};
        NetworkFilterSpec::HttpConnectionManager(proxy_config::ir::HttpConnectionManagerConfig {
            stat_prefix: "test".to_string(),
            route_table: direct_response_route_table(200),
            http_filters: vec![
                proxy_config::ir::HttpFilterSpec {
                    name: "llmproxy.header_mutation".to_string(),
                    type_url: TYPE_URL.to_string(),
                    config: Some(header_value_option(header_name, header_value)),
                    is_router: false,
                },
                proxy_config::ir::HttpFilterSpec {
                    name: "envoy.filters.http.router".to_string(),
                    type_url: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                        .to_string(),
                    config: None,
                    is_router: true,
                },
            ],
            generate_request_id: true,
            use_remote_address: false,
            xff_num_trusted_hops: 0,
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
        }
    }

    /// A STATIC cluster with a single priority-0 endpoint at `addr`.
    fn static_cluster(name: &str, addr: SocketAddr) -> ClusterConfig {
        ClusterConfig {
            name: name.to_string(),
            discovery: DiscoveryType::Static,
            lb_policy: LbPolicy::RoundRobin,
            connect_timeout: Duration::from_secs(5),
            endpoints: vec![EndpointIR {
                host: addr.ip().to_string(),
                port: addr.port(),
                weight: 1,
                priority: 0,
            }],
            transport_socket: None,
            per_connection_buffer_limit_bytes: 1024 * 1024,
            circuit_breakers: Default::default(),
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
    /// byte, until the peer closes -- the default WP-09 upstream fixture for
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
        }
    }

    /// Same match criteria as [`sni_only_listener`], but with a `tls_inspector`
    /// listener filter -- the only thing that lets `server_names` matching
    /// actually see the ClientHello's SNI (WP-08 chunk C2).
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
    }

    /// Builds a [`ClusterManager`] populated (and force-initialized, so
    /// `pick_host` never has to wait on real DNS) from `snapshot`'s cluster
    /// map -- the same manager both the `tcp_proxy` fixtures' listener wiring
    /// and (WP-13) the HTTP router's `RouterHandler` see.
    async fn cluster_manager_for(snapshot: &ConfigSnapshot) -> Arc<ClusterManager> {
        let manager = Arc::new(ClusterManager::new(Arc::new(
            proxy_cluster::resolver::TokioResolver,
        )));
        manager.update_from_snapshot(&snapshot.clusters).await;
        for name in snapshot.clusters.keys() {
            manager.force_initialize(name);
        }
        manager
    }

    async fn spawn_manager(initial: Arc<ConfigSnapshot>) -> Harness {
        let config = Arc::new(WorkerConfigHandle::new(initial.clone()));
        let (config_tx, config_rx) = watch::channel(initial.version);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let registry = ConnectionRegistry::new();
        let cluster_manager = cluster_manager_for(&initial).await;

        let bound = initial_bind(&initial, &config, &registry, &shutdown_rx, &cluster_manager)
            .expect("initial_bind should succeed in tests");

        let manager = tokio::task::spawn_local(run_listener_manager(
            bound,
            config.clone(),
            config_rx,
            shutdown_rx,
            registry.clone(),
            cluster_manager,
        ));

        Harness {
            config,
            config_tx,
            shutdown_tx,
            registry,
            manager,
        }
    }

    impl Harness {
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

    // --- WP-08 chunk C3: downstream TLS termination in the accept path -----

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
            certificates: vec![tls_cert_ir(cert, key)],
            params: tls_params(),
            alpn_protocols: vec![],
            validation: None,
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
                    name: Some("a".to_string()),
                    match_criteria: FilterChainMatch {
                        server_names: vec![host_a.to_string()],
                        ..Default::default()
                    },
                    transport_socket: Some(downstream_tls_spec(&cert_a, &key_a)),
                    filters: vec![tcp_proxy_filter("unused")],
                },
                FilterChainSpec {
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
            certificates: vec![TlsCertificateIR {
                cert_chain: DataSourceIR::Inline("not a certificate".to_string()),
                private_key: DataSourceIR::Inline("not a key".to_string()),
            }],
            params: tls_params(),
            alpn_protocols: vec![],
            validation: None,
            require_client_certificate: false,
            disable_stateless_session_resumption: false,
        });

        let err = match build_listener_tls(&listener_ir) {
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
                certificates: vec![TlsCertificateIR {
                    cert_chain: DataSourceIR::Inline("garbage".to_string()),
                    private_key: DataSourceIR::Inline("garbage".to_string()),
                }],
                params: tls_params(),
                alpn_protocols: vec![],
                validation: None,
                require_client_certificate: false,
                disable_stateless_session_resumption: false,
            });

            let snapshot = snapshot_with(listener_ir, 1);
            let config = Arc::new(WorkerConfigHandle::new(snapshot.clone()));
            let registry = ConnectionRegistry::new();
            let (_shutdown_tx, shutdown_rx) = watch::channel(false);
            let cluster_manager = cluster_manager_for(&snapshot).await;

            let result = initial_bind(
                &snapshot,
                &config,
                &registry,
                &shutdown_rx,
                &cluster_manager,
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

    // --- WP-09: tcp_proxy runtime ------------------------------------------

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

    // --- WP-10 deferred chunk: HCM terminal filter wired to the h1 codec ----

    /// Since WP-13, `build_hcm_handler`'s terminal is a real
    /// `proxy_http::router::RouterHandler`, not a fixed-200 stub -- an empty
    /// route table (`hcm_filter`) means every request takes the
    /// `NoVirtualHost` path, a 404. This test now proves HTTP is served over
    /// the real socket *at all* (request parsed, response written back) --
    /// see `hcm_filter_chain_mutates_headers_over_the_real_socket` for a
    /// route that actually matches, and the WP-13 acceptance test below for
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

    // --- WP-13: router terminal + cluster-manager wiring -------------------

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
                    })],
                }],
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
            http_filters: vec![
                proxy_config::ir::HttpFilterSpec {
                    name: "llmproxy.header_mutation".to_string(),
                    type_url: TYPE_URL.to_string(),
                    config: Some(header_value_option(header_name, header_value)),
                    is_router: false,
                },
                proxy_config::ir::HttpFilterSpec {
                    name: "envoy.filters.http.router".to_string(),
                    type_url: "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                        .to_string(),
                    config: None,
                    is_router: true,
                },
            ],
            generate_request_id: true,
            use_remote_address: false,
            xff_num_trusted_hops: 0,
        })
    }

    /// Serve a fixed 200 response (a known body, no extra headers) over real
    /// HTTP/1.1 on a fresh ephemeral-port `TcpListener`, forever -- the "real
    /// upstream" fixture for the WP-13 acceptance test below. Reuses
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
                        Http1Options { keep_alive: false },
                        std::future::pending(),
                        DownstreamInfo::loopback(),
                    )
                    .await;
                });
            }
        });
        addr
    }

    /// The WP-13 acceptance test: a real HTTP request is routed (via the
    /// router terminal + `ClusterManager`) to a real upstream over HTTP/1.1,
    /// and the response still flows back through the encode filter chain --
    /// proving all three pieces (route match -> cluster/host pick -> upstream
    /// codec -> encode filters) work together over real sockets.
    ///
    /// Mutation-tested: reverting `build_hcm_handler`'s terminal to
    /// `FixedResponseHandler` (the pre-WP-13 stub) makes this fail, since the
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
}
