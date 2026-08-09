//! The `llm-proxy` binary.
//!
//! Implemented: Envoy bootstrap loading (`-c`, WP-03), PGV validation (WP-04),
//! IR building (WP-05), the simple dialect (`--config`, WP-38), `--mode
//! validate` / `--mode translate`, `--mode keygen` (WP-50 increment 2a-iv,
//! see `keygen`), serve mode's control runtime, worker pool, SIGTERM/SIGINT
//! drain sequence (WP-06 chunk C), and the per-worker listener manager
//! (WP-07 chunk C) that binds sockets and accepts connections. The L4
//! network filter chain (`tcp_proxy` etc.) is still a stub -- see
//! `proxy_core::listener`'s `TODO(WP-09)`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use proxy_config::{
    build_snapshot, load_bootstrap_file, ConfigSnapshot, LoadedBootstrap, StrictMode,
};
use proxy_core::drain::{
    drain_worker, graceful_shutdown, ConnectionRegistry, DrainStrategy as CoreDrainStrategy,
};
use proxy_core::listener::{initial_bind, run_listener_manager};
use proxy_core::runtime::{WorkerContext, WorkerId, WorkerPool, WorkerPoolConfig};
use proxy_core::WorkerConfigHandle;
use tokio::sync::mpsc;

mod keygen;

#[derive(Parser)]
#[command(name = "llm-proxy", version, about = "Proxy for LLM inference APIs")]
// Rust note: no `.required(true)` here any more -- `--mode keygen` needs
// neither `-c`/`--config-path` nor `--config`, so "at least one" can no
// longer be a blanket clap-level rule. The group still enforces "not both"
// (its `multiple` flag defaults to `false`); "at least one, unless keygen"
// is checked by hand in `main()`, right where `--mode translate`'s own extra
// requirement already is.
#[command(group(clap::ArgGroup::new("input").args(["config_path", "config"])))]
struct Args {
    /// Path to an Envoy bootstrap config (.yaml / .yml / .json / .pb).
    /// Required for `serve`/`validate`/`translate`; unused by `keygen`.
    #[arg(short = 'c', long = "config-path", value_name = "PATH")]
    config_path: Option<PathBuf>,

    /// Path to a simple llm-proxy config (schema/llmproxy-v0.schema.json).
    /// Required for `serve`/`validate`/`translate`; unused by `keygen`.
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// `validate` checks the config and exits; `translate` prints the Envoy
    /// bootstrap generated from a `--config` dialect file; `serve` runs;
    /// `keygen` prints a fresh virtual key and its digest and needs no
    /// config at all -- see `--tenant`/`--key-id`/`--hmac-secret-file`.
    #[arg(long, value_enum, default_value_t = Mode::Serve)]
    mode: Mode,

    /// `--mode keygen`: the tenant the generated key authenticates as.
    /// Required for `keygen`; unused otherwise.
    #[arg(long, value_name = "TENANT")]
    tenant: Option<String>,

    /// `--mode keygen`: names this credential in audit logs
    /// (`auth.keys[].id`). Defaults to an obvious placeholder the operator
    /// is expected to replace before deploying the printed config fragment.
    #[arg(long = "key-id", value_name = "ID", default_value = "REPLACE_ME")]
    key_id: String,

    /// `--mode keygen`: derive the digest's HMAC secret from this file
    /// (matches the dialect's `auth.hmac_secret_file`). Takes precedence
    /// over `$LLMPROXY_AUTH_SECRET` if both are set.
    #[arg(long = "hmac-secret-file", value_name = "PATH")]
    hmac_secret_file: Option<PathBuf>,

    /// Warn on unknown Envoy config fields instead of failing (default:
    /// strict). Has no effect on `--config` dialect files, which are always
    /// strict.
    #[arg(long)]
    permissive: bool,

    /// Number of worker runtimes (serve mode only). Envoy calls this
    /// `--concurrency`; default is the number of available cores.
    #[arg(long, value_name = "N", default_value_t = default_concurrency())]
    concurrency: usize,

    /// How long the drain sequence waits for connections to close before
    /// forcing worker shutdown (serve mode only). Matches Envoy's
    /// `--drain-time-s`.
    #[arg(
        long = "drain-time-s",
        value_name = "SECS",
        default_value_t = proxy_core::drain::DEFAULT_DRAIN_TIME.as_secs()
    )]
    drain_time_s: u64,

    /// How aggressively in-flight requests are encouraged to close during a
    /// drain. Matches Envoy's `--drain-strategy`.
    #[arg(long = "drain-strategy", value_enum, default_value_t = DrainStrategyArg::Gradual)]
    drain_strategy: DrainStrategyArg,

    /// Envoy hot-restart base id. Accepted for CLI compatibility only: we
    /// have no hot-restart implementation, so this is parsed and ignored.
    #[arg(long = "base-id", value_name = "N")]
    base_id: Option<u32>,

    /// Log verbosity. Matches Envoy's levels; `critical` is mapped to `error`
    /// (we don't distinguish the two).
    #[arg(short = 'l', long = "log-level", value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    /// xDS node id (carried into the `Node` proto once WP-20 lands).
    #[arg(long = "service-node", value_name = "NAME")]
    service_node: Option<String>,

    /// xDS node cluster (carried into the `Node` proto once WP-20 lands).
    #[arg(long = "service-cluster", value_name = "NAME")]
    service_cluster: Option<String>,
}

// Rust note: `default_value_t` needs a plain expression it can call while
// building the `clap::Command` -- a free function works fine, and keeps this
// in one place with `WorkerPoolConfig::default()`'s identical fallback.
fn default_concurrency() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Mode {
    Serve,
    Validate,
    Translate,
    /// WP-50 increment 2a-iv: generate a virtual key + digest. The one mode
    /// that touches no config at all -- see `run_keygen`.
    Keygen,
}

/// CLI-facing drain strategy. Rust note: `proxy_core::drain::DrainStrategy`
/// lives in another crate, so it can't derive `clap::ValueEnum` here -- this
/// mirrors it and converts via `From` below.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DrainStrategyArg {
    Gradual,
    Immediate,
}

impl From<DrainStrategyArg> for CoreDrainStrategy {
    fn from(value: DrainStrategyArg) -> Self {
        match value {
            DrainStrategyArg::Gradual => CoreDrainStrategy::Gradual,
            DrainStrategyArg::Immediate => CoreDrainStrategy::Immediate,
        }
    }
}

/// Envoy's `--log-level` values.
#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
    Off,
}

impl LogLevel {
    /// The `tracing_subscriber::EnvFilter` directive this level maps to.
    /// Envoy's `critical` has no `tracing` equivalent, so it collapses to
    /// `error` per the task's mapping.
    fn filter_directive(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error | LogLevel::Critical => "error",
            LogLevel::Off => "off",
        }
    }
}

/// Set up the global `tracing` subscriber. Called for every mode (not just
/// `serve`) so `tracing::warn!`/`error!` calls anywhere in the load path are
/// visible; logs always go to stderr so stdout's validate/translate contract
/// is untouched.
fn init_tracing(level: LogLevel) {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(level.filter_directive()))
        .with_writer(std::io::stderr)
        .init();
}

fn main() -> ExitCode {
    let args = Args::parse();
    init_tracing(args.log_level);

    // `keygen` needs no config -- and, unlike every other mode, must never
    // reach `load`/`build_snapshot` below. Handled first and returns
    // unconditionally.
    if args.mode == Mode::Keygen {
        return run_keygen(&args);
    }

    // The `input` ArgGroup (see `Args`'s doc) only forbids passing BOTH
    // `-c`/`--config-path` and `--config` now; "at least one, for every mode
    // except keygen" has to be checked here instead. Getting this wrong in
    // either direction is exactly the regression this task guards against
    // with a test: silently letting `serve` through with no config would
    // mean a "config required" invariant that used to be enforced by clap
    // quietly stops being enforced at all.
    if args.config_path.is_none() && args.config.is_none() {
        eprintln!(
            "a config is required: pass -c/--config-path or --config \
             (only --mode keygen runs without one)"
        );
        return ExitCode::FAILURE;
    }

    // `translate` only makes sense for the dialect: Envoy config IS the output.
    if args.mode == Mode::Translate && args.config.is_none() {
        eprintln!("--mode translate requires a --config dialect file (-c files already are Envoy configs)");
        return ExitCode::FAILURE;
    }

    let (path, loaded) = match load(&args) {
        Ok(ok) => ok,
        Err((path, err)) => {
            eprintln!("configuration '{path}' INVALID");
            eprintln!("  {err}");
            return ExitCode::FAILURE;
        }
    };

    for warning in &loaded.warnings {
        eprintln!("warning: `{}`: {}", warning.field_path, warning.message);
    }

    // Every mode builds the IR: a config that parses but cannot lower is
    // invalid — validate must reject exactly what serve would.
    let snapshot = match build_snapshot(&loaded) {
        Ok(s) => s,
        Err(err) => {
            eprintln!("configuration '{path}' INVALID");
            eprintln!("  {err}");
            return ExitCode::FAILURE;
        }
    };

    match args.mode {
        Mode::Translate => {
            // Printed in load(); reaching here means it already succeeded.
            ExitCode::SUCCESS
        }
        Mode::Validate => {
            println!(
                "configuration '{path}' OK ({} listener(s), {} cluster(s), {} warning(s))",
                snapshot.listeners.len(),
                snapshot.clusters.len(),
                loaded.warnings.len()
            );
            ExitCode::SUCCESS
        }
        Mode::Serve => serve(args, snapshot),
        // `main` returns via `run_keygen` before this point is ever reached
        // for `Mode::Keygen` (see the early `if args.mode == Mode::Keygen`
        // check) -- an explicit arm rather than a wildcard so a future new
        // `Mode` variant still fails to compile here instead of silently
        // falling through.
        Mode::Keygen => unreachable!("--mode keygen returns from main() before this match"),
    }
}

/// `--mode keygen`: validates `--tenant` (the one option this mode requires
/// that clap can't enforce for it alone, since `Args` has no per-mode
/// required flags -- see the doc on `Args::tenant`), then delegates to
/// `keygen::run`, which resolves the secret, generates the key, and prints
/// the paste-ready fragment. Returns before `load`/`build_snapshot` are ever
/// reached; this mode touches no config.
fn run_keygen(args: &Args) -> ExitCode {
    let Some(tenant) = args.tenant.as_deref().filter(|t| !t.trim().is_empty()) else {
        eprintln!("--mode keygen requires --tenant <TENANT>");
        return ExitCode::FAILURE;
    };
    match keygen::run(tenant, &args.key_id, args.hmac_secret_file.as_ref()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::FAILURE
        }
    }
}

/// Load whichever config style was given; returns (display path, loaded).
fn load(args: &Args) -> Result<(String, LoadedBootstrap), (String, String)> {
    if let Some(path) = &args.config_path {
        let display = path.display().to_string();
        // Helpful cross-mode hint before the real (confusing) parse error.
        if let Ok(text) = std::fs::read_to_string(path) {
            if proxy_simple_config::looks_like_simple_config(&text)
                && !proxy_simple_config::looks_like_envoy_bootstrap(&text)
            {
                return Err((
                    display,
                    "this looks like a simple llm-proxy config; use --config instead of -c"
                        .to_string(),
                ));
            }
        }
        let mode = if args.permissive {
            StrictMode::Permissive
        } else {
            StrictMode::Strict
        };
        let loaded =
            load_bootstrap_file(path, mode).map_err(|e| (display.clone(), e.to_string()))?;
        return Ok((display, loaded));
    }

    let path = args.config.as_ref().expect("clap group guarantees one");
    let display = path.display().to_string();
    if let Ok(text) = std::fs::read_to_string(path) {
        if proxy_simple_config::looks_like_envoy_bootstrap(&text) {
            return Err((
                display,
                "this looks like an Envoy bootstrap; use -c instead of --config".to_string(),
            ));
        }
    }
    let config = proxy_simple_config::load_simple_config_file(path)
        .map_err(|e| (display.clone(), e.to_string()))?;

    if args.mode == Mode::Translate {
        let (yaml, warnings) = proxy_simple_config::to_envoy_yaml(&config)
            .map_err(|e| (display.clone(), e.to_string()))?;
        for warning in &warnings {
            eprintln!("warning: `{}`: {}", warning.field_path, warning.message);
        }
        print!("{yaml}");
    }

    let loaded = proxy_simple_config::lower_to_loaded(&config)
        .map_err(|e| (display.clone(), e.to_string()))?;
    Ok((display, loaded))
}

/// Serve mode: build the control runtime, spawn the worker pool, wait for
/// SIGTERM/SIGINT, then run the graceful shutdown sequence.
fn serve(args: Args, snapshot: ConfigSnapshot) -> ExitCode {
    if let Some(base_id) = args.base_id {
        tracing::warn!(
            base_id,
            "--base-id ignored: it namespaces Envoy's shared-memory hot-restart regions, \
             which llm-proxy does not have (restarts are SO_REUSEPORT process overlap, \
             ADR-0001); multiple instances per host are safe without it"
        );
    }

    let drain_time = Duration::from_secs(args.drain_time_s);
    let strategy: CoreDrainStrategy = args.drain_strategy.into();

    // Rust note: the control runtime is a separate, ordinary multi-thread
    // tokio runtime (2 worker threads per WP-06) -- distinct from the
    // per-worker `current_thread` runtimes `WorkerPool::spawn` builds. Only
    // the control runtime ever touches the `ConfigPublisher`/signal seam;
    // workers only see it via the channels in `WorkerContext`.
    let control_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("failed to build control runtime");

    control_rt.block_on(run_serve(
        args.concurrency,
        drain_time,
        strategy,
        args.service_node,
        args.service_cluster,
        Arc::new(snapshot),
    ))
}

/// How long `run_serve` waits for every worker to report its initial listener
/// bind outcome before giving up and treating startup as failed. Generous:
/// binding a handful of sockets should take microseconds, but a heavily
/// loaded CI box scheduling `concurrency` OS threads is not something to cut
/// close.
const INITIAL_BIND_TIMEOUT: Duration = Duration::from_secs(10);

async fn run_serve(
    concurrency: usize,
    drain_time: Duration,
    strategy: CoreDrainStrategy,
    service_node: Option<String>,
    service_cluster: Option<String>,
    snapshot: Arc<ConfigSnapshot>,
) -> ExitCode {
    // Collected before `snapshot` moves into `WorkerPool::spawn` purely so
    // the startup log line below can name what got bound; each worker binds
    // its own copy of these sockets independently (WP-07 chunk C).
    let listener_summary: Vec<String> = snapshot
        .listeners
        .values()
        .filter(|l| l.bind_to_port)
        .map(|l| format!("{}@{}", l.name, l.address))
        .collect();

    // WP-13: one `ClusterManager` shared across every worker -- control
    // computes (discovery, EDS updates land here), workers only ever read
    // through `ClusterEntry`/`HttpConnPool`, exactly like Envoy's own
    // cluster manager. Built and populated here, before `WorkerPool::spawn`,
    // so every worker's first `initial_bind` sees a manager that already
    // knows about the snapshot's clusters.
    let cluster_manager = Arc::new(proxy_cluster::manager::ClusterManager::new(
        Arc::new(proxy_cluster::resolver::TokioResolver),
        proxy_core::tls::transport_socket_builder(),
    ));
    let rejected = cluster_manager
        .update_from_snapshot(&snapshot.clusters)
        .await;
    if !rejected.is_empty() {
        // A rejected cluster (unimplemented `lb_policy`, or a
        // `transport_socket` that fails to build -- e.g. bad TLS config) is
        // fatal at startup, same as a bad listener certificate
        // (`InitialBindError` below): ground rule #1 forbids leaving the
        // proxy up serving 503s for a misconfigured cluster with no
        // diagnostic.
        for (name, err) in &rejected {
            tracing::error!(cluster = %name, error = %err, "cluster rejected at startup");
        }
        return ExitCode::FAILURE;
    }

    // WP-50 increment 1: the read-only admin surface. Opt-in -- only binds
    // when the config names an `admin` address -- and, like a listener's
    // `initial_bind`, a bind failure here is a startup error, not a silent
    // skip (see `start_admin`'s doc comment). Started before the worker pool
    // so a bad admin port fails fast instead of after workers are already
    // accepting traffic.
    let admin_server = match start_admin(
        snapshot.admin,
        snapshot.clone(),
        concurrency,
        Instant::now(),
    )
    .await
    {
        Ok(server) => server,
        Err(err) => {
            eprintln!("failed to start admin server: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(server) = &admin_server {
        tracing::info!(addr = %server.local_addr(), "admin server listening");
    }

    // Rust note: `WorkerPool::spawn` takes `worker_main` by value and clones
    // it once per worker thread (see its doc comment), so `bind_tx` -- an
    // `mpsc::UnboundedSender`, itself `Clone` -- gets captured once here and
    // is cloned again per worker inside the closure. This is how initial-bind
    // status gets back to the control runtime without changing
    // `WorkerPool`'s public API: it's plumbed entirely through the closure's
    // capture, not through `WorkerContext`.
    // Install the shutdown handlers BEFORE spawning any worker. Workers begin
    // binding listeners as soon as they start, so installing after the spawn
    // would leave a window in which the proxy is already accepting connections
    // while a SIGTERM would still kill it outright with no drain -- see
    // `ShutdownSignals`'s doc comment. Nothing is listening yet at this point,
    // so there is nothing to tear down if installation fails.
    let mut shutdown_signals = match ShutdownSignals::install() {
        Ok(signals) => signals,
        Err(err) => {
            eprintln!("failed to install shutdown signal handlers: {err}");
            return ExitCode::FAILURE;
        }
    };

    let (bind_tx, mut bind_rx) = mpsc::unbounded_channel::<(WorkerId, Result<(), String>)>();

    let publisher = WorkerPool::spawn(
        WorkerPoolConfig {
            concurrency,
            pin_cores: true,
        },
        snapshot,
        move |ctx: WorkerContext| {
            let bind_tx = bind_tx.clone();
            worker_main(ctx, bind_tx, cluster_manager.clone())
        },
    );

    tracing::info!(
        workers = concurrency,
        drain_time_s = drain_time.as_secs(),
        drain_strategy = ?strategy,
        service_node = service_node.as_deref().unwrap_or("-"),
        service_cluster = service_cluster.as_deref().unwrap_or("-"),
        listeners = %listener_summary.join(", "),
        "llm-proxy started, waiting for SIGTERM/SIGINT"
    );

    // Startup gate: every worker must report a successful initial bind
    // before we consider ourselves "up". A single failed listener is fatal
    // at startup (ground rule #1 -- see `proxy_core::listener::initial_bind`'s
    // doc comment), so on the first failure (or a timeout) we tear the pool
    // down and exit nonzero instead of proceeding to the signal-wait loop.
    if let Err(message) = wait_for_initial_binds(&mut bind_rx, concurrency).await {
        eprintln!("{message}");
        publisher.shutdown();
        publisher.join();
        return ExitCode::FAILURE;
    }

    shutdown_signals.recv().await;

    let outcome = graceful_shutdown(publisher, drain_time, strategy).await;
    tracing::info!(?outcome, "drain sequence finished, exiting");
    ExitCode::SUCCESS
}

/// Waits for `expected` workers to each report `Ok(())` over `bind_rx`, or
/// returns the first failure (a worker's bind error, or a timeout) as a
/// ready-to-print message.
async fn wait_for_initial_binds(
    bind_rx: &mut mpsc::UnboundedReceiver<(WorkerId, Result<(), String>)>,
    expected: usize,
) -> Result<(), String> {
    let mut remaining = expected;
    while remaining > 0 {
        match tokio::time::timeout(INITIAL_BIND_TIMEOUT, bind_rx.recv()).await {
            Ok(Some((_, Ok(())))) => remaining -= 1,
            Ok(Some((id, Err(err)))) => {
                return Err(format!("worker {}: {err}", id.0));
            }
            Ok(None) => {
                return Err(
                    "all workers exited before reporting their initial listener bind status"
                        .to_string(),
                );
            }
            Err(_) => {
                return Err(format!(
                    "timed out after {}s waiting for workers to bind their listeners",
                    INITIAL_BIND_TIMEOUT.as_secs()
                ));
            }
        }
    }
    Ok(())
}

/// Starts the read-only admin server (`proxy-admin`, WP-50 increment 1) when
/// `admin` names a bind address; binds nothing and returns `Ok(None)`
/// otherwise -- the admin surface is opt-in, never automatic.
///
/// The admin server gets its own [`WorkerConfigHandle`], separate from the
/// ones [`WorkerPool::spawn`] hands to workers: it reads `snapshot` as it
/// was at startup. Nothing in this binary republishes into it today (dynamic
/// config updates are WP-20/21/22, not yet wired), so `/config_dump` shows
/// the snapshot the process booted with -- true for the whole process
/// lifetime today, but stated here rather than left to be discovered.
///
/// `concurrency` sizes the WP-23 stats [`Registry`](proxy_observability::stats::Registry)
/// this hands to the admin server for `/stats` -- the same worker count
/// `WorkerPoolConfig` uses, since a registry's shard count is fixed at
/// construction (see the registry's own module doc). No instrument is
/// resolved against it here: WP-23 increment 5 (the cluster/listener/HTTP
/// call sites that actually record traffic) hasn't landed yet, so `/stats`
/// answers `200` with a correctly-rendered but empty body until it does --
/// not a fabricated non-empty reading, and not the honest-404 case, which is
/// reserved for a server that was never handed a registry at all (see
/// `proxy-admin::server`'s `/stats` route).
///
/// A bind failure is returned as an `Err`, not swallowed: `run_serve` turns
/// it into a startup failure, holding the admin port to the same standard
/// `initial_bind` holds every listener port to.
async fn start_admin(
    admin: Option<SocketAddr>,
    snapshot: Arc<ConfigSnapshot>,
    concurrency: usize,
    started_at: Instant,
) -> Result<Option<proxy_admin::AdminServer>, String> {
    let Some(addr) = admin else {
        return Ok(None);
    };
    let config = Arc::new(WorkerConfigHandle::new(snapshot));
    let registry = Arc::new(proxy_observability::stats::Registry::new(concurrency));
    let server = proxy_admin::serve(addr, config, Some(registry), started_at)
        .await
        .map_err(|err| err.to_string())?;
    Ok(Some(server))
}

/// Each worker composes three concurrent seams over one shared
/// `ConnectionRegistry` (WP-07 chunk C): the listener manager (binds
/// sockets, accepts, matches filter chains), the drain routine (reports back
/// once the registry empties or the drain deadline passes), and a final wait
/// on the plain shutdown signal so the worker thread doesn't exit before the
/// control runtime calls `ConfigPublisher::shutdown`.
///
/// The very first thing this does is bind every listener in the initial
/// snapshot (`initial_bind`) and report the outcome over `bind_tx` --
/// `run_serve` blocks on every worker doing so before it starts waiting for
/// SIGTERM/SIGINT. A bind failure here is fatal (see `initial_bind`'s doc
/// comment), so this worker does nothing further but wait for the control
/// runtime's `shutdown` signal, which `run_serve` sends promptly once it
/// sees the failure.
async fn worker_main(
    ctx: WorkerContext,
    bind_tx: mpsc::UnboundedSender<(WorkerId, Result<(), String>)>,
    cluster_manager: Arc<proxy_cluster::manager::ClusterManager>,
) {
    let registry = ConnectionRegistry::new();

    let bound = match initial_bind(
        &ctx.config.load(),
        &ctx.config,
        &registry,
        &ctx.shutdown,
        &cluster_manager,
    ) {
        Ok(bound) => {
            let _ = bind_tx.send((ctx.id, Ok(())));
            bound
        }
        Err(err) => {
            let _ = bind_tx.send((ctx.id, Err(err.to_string())));
            let mut shutdown = ctx.shutdown;
            let _ = shutdown.changed().await;
            return;
        }
    };

    // Rust note: `spawn_local` (not a plain `.await`) because the listener
    // manager runs for the worker's whole life -- it needs to keep reacting
    // to `config_ping` while `drain_worker` below also runs concurrently on
    // the same `LocalSet`.
    let listener_manager = tokio::task::spawn_local(run_listener_manager(
        bound,
        ctx.config,
        ctx.config_ping,
        ctx.shutdown.clone(),
        registry.clone(),
        cluster_manager.clone(),
    ));

    drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;

    let mut shutdown = ctx.shutdown;
    let _ = shutdown.changed().await;

    // `run_listener_manager` also watches `shutdown` and aborts its accept
    // loops on the same signal; wait for it so the thread doesn't tear down
    // mid-abort.
    let _ = listener_manager.await;
}

/// SIGTERM and SIGINT, with their handlers already **installed**.
///
/// The distinction that matters: `tokio::signal::unix::signal()` registers the
/// handler with the OS when it is *called*, not when the returned stream is
/// first polled. Installing both up front — before we announce readiness and
/// before the initial-bind gate — is what makes the announcement true. If the
/// handler were installed only at the point we start awaiting it (as this used
/// to do), any signal arriving between "started" and that await would be
/// handled by the **default disposition**: immediate termination by signal, no
/// drain, live connections dropped. That window is small but entirely real —
/// an orchestrator terminating a pod during a fast rollout or a scale-down
/// race lands squarely in it.
///
/// Rust note: SIGINT is taken as a `Signal` stream rather than via
/// `tokio::signal::ctrl_c()` for exactly the same reason — `ctrl_c()` is a
/// future that installs its handler on first poll, which would reintroduce the
/// gap for SIGINT alone.
struct ShutdownSignals {
    sigterm: tokio::signal::unix::Signal,
    sigint: tokio::signal::unix::Signal,
}

impl ShutdownSignals {
    /// Installs both handlers. Failing to install one is a startup failure,
    /// not something to discover at shutdown time.
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            sigterm: signal(SignalKind::terminate())?,
            sigint: signal(SignalKind::interrupt())?,
        })
    }

    /// Resolves on the first of either signal. We only care about the first,
    /// so racing the two streams in a `select!` is enough.
    async fn recv(&mut self) {
        tokio::select! {
            _ = self.sigterm.recv() => {}
            _ = self.sigint.recv() => {}
        }
    }
}

/// Wiring tests for `start_admin` -- the decision of *whether* to bind the
/// admin port lives in this binary (`proxy-admin` itself always binds when
/// asked), so it's tested here against a real socket rather than by
/// inspecting `proxy-admin` in isolation.
#[cfg(test)]
mod tests {
    use super::*;

    fn empty_snapshot() -> Arc<ConfigSnapshot> {
        Arc::new(ConfigSnapshot::default())
    }

    #[tokio::test]
    async fn admin_none_binds_nothing() {
        // Reserve a port, release it, then prove `start_admin(None, ..)`
        // never touches it -- "no server started" has to be checked from
        // the outside (a real connect attempt), not just by reading the
        // `None` arm's code.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
        let port = probe.local_addr().expect("local_addr").port();
        drop(probe);

        let result = start_admin(None, empty_snapshot(), 1, Instant::now())
            .await
            .expect("start_admin(None, ..) must not fail");
        assert!(
            result.is_none(),
            "admin: None must not start a server (bind-only-when-configured)"
        );

        let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        assert!(
            tokio::net::TcpStream::connect(addr).await.is_err(),
            "nothing should be listening on {addr}: admin was never configured"
        );
    }

    #[tokio::test]
    async fn admin_some_binds_and_serves() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let server = start_admin(Some(addr), empty_snapshot(), 1, Instant::now())
            .await
            .expect("start_admin should succeed on an available port")
            .expect("admin: Some(_) must start a server");

        let bound = server.local_addr();
        tokio::net::TcpStream::connect(bound)
            .await
            .expect("the admin port should be connectable once start_admin has bound it");
    }
}
