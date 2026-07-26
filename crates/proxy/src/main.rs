//! The `llm-proxy` binary.
//!
//! Implemented: Envoy bootstrap loading (`-c`, WP-03), PGV validation (WP-04),
//! IR building (WP-05), the simple dialect (`--config`, WP-38), `--mode
//! validate` / `--mode translate`, serve mode's control runtime, worker pool,
//! SIGTERM/SIGINT drain sequence (WP-06 chunk C), and the per-worker listener
//! manager (WP-07 chunk C) that binds sockets and accepts connections. The L4
//! network filter chain (`tcp_proxy` etc.) is still a stub -- see
//! `proxy_core::listener`'s `TODO(WP-09)`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use proxy_config::{
    build_snapshot, load_bootstrap_file, ConfigSnapshot, LoadedBootstrap, StrictMode,
};
use proxy_core::drain::{
    drain_worker, graceful_shutdown, ConnectionRegistry, DrainStrategy as CoreDrainStrategy,
};
use proxy_core::listener::{initial_bind, run_listener_manager};
use proxy_core::runtime::{WorkerContext, WorkerId, WorkerPool, WorkerPoolConfig};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "llm-proxy", version, about = "Proxy for LLM inference APIs")]
#[command(group(clap::ArgGroup::new("input").required(true).args(["config_path", "config"])))]
struct Args {
    /// Path to an Envoy bootstrap config (.yaml / .yml / .json / .pb).
    #[arg(short = 'c', long = "config-path", value_name = "PATH")]
    config_path: Option<PathBuf>,

    /// Path to a simple llm-proxy config (schema/llmproxy-v0.schema.json).
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// `validate` checks the config and exits; `translate` prints the Envoy
    /// bootstrap generated from a `--config` dialect file; `serve` runs.
    #[arg(long, value_enum, default_value_t = Mode::Serve)]
    mode: Mode,

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

    // Rust note: `WorkerPool::spawn` takes `worker_main` by value and clones
    // it once per worker thread (see its doc comment), so `bind_tx` -- an
    // `mpsc::UnboundedSender`, itself `Clone` -- gets captured once here and
    // is cloned again per worker inside the closure. This is how initial-bind
    // status gets back to the control runtime without changing
    // `WorkerPool`'s public API: it's plumbed entirely through the closure's
    // capture, not through `WorkerContext`.
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

    wait_for_shutdown_signal().await;

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

/// Waits for either SIGTERM or SIGINT (Ctrl-C). Rust note:
/// `tokio::signal::unix::signal` returns a `Signal` stream we can `.recv()`
/// repeatedly; we only care about the first one, so `select!` racing it
/// against `ctrl_c()` is enough.
async fn wait_for_shutdown_signal() {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = sigterm.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}
