//! The `llm-proxy` binary.
//!
//! Loads Envoy and simple-dialect configuration, then runs the proxy binary
//! modes and serves HTTP and L4 traffic through `proxy_core`.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand, ValueEnum};
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::{DeltaDiscoveryResponse, DiscoveryResponse};
use proxy_config::ir::{AdsProtocol, DiscoverySource, NodeIdentity, SnapshotVersion};
use proxy_config::{
    build_snapshot, load_bootstrap_file, ConfigSnapshot, LoadedBootstrap, StrictMode,
};
use proxy_core::ads_transport::AdsTransport;
use proxy_core::drain::{drain_worker, ConnectionRegistry};
use proxy_core::lifecycle::LifecycleState;
use proxy_core::listener::{initial_bind, run_listener_manager};
use proxy_core::runtime::{SnapshotHandles, WorkerContext, WorkerId, WorkerPool, WorkerPoolConfig};
use proxy_core::tls::SdsSecretRegistry;
use proxy_xds::apply::SecretUpdate;
use proxy_xds::subscription::Verdict;
use proxy_xds::{
    AdsClient, DeltaAdsClient, DeltaResponseHandler, DeltaSubscriptionState, FileSource,
    InitializationEvent, InitializationSink, Publish, PublishEndpoints, PublishSecrets, Reconnect,
    ResourceApplier, ResponseHandler, Subscription, SubscriptionState,
};
use tokio::sync::{mpsc, oneshot, Notify};

mod init;
mod keygen;

// Opt-in (`--features mimalloc`): glibc malloc/free show up as about a tenth
// of proxy CPU in profiles at 5k rps, but mimalloc costs resident memory.
// The trade is measured in internal-docs/capacity/2026-10-21-allocator-ab.md.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "llm-proxy", version, about = "Proxy for LLM inference APIs")]
// Rust note: no `.required(true)`, because `--mode keygen` takes neither
// input. The group still rejects "both"; "at least one, unless keygen" is
// checked by hand in `main()`.
#[command(group(clap::ArgGroup::new("input").args(["config_path", "config"])))]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to a bootstrap configuration (.yaml / .yml / .json / .pb).
    /// `serve` and `validate` need exactly one of this or `--config`;
    /// `translate` needs `--config`. Unused by `keygen` and `init`.
    #[arg(short = 'c', long = "config-path", value_name = "PATH")]
    config_path: Option<PathBuf>,

    /// Path to a simple llm-proxy config (schema/llmproxy-v0.schema.json).
    /// `serve` and `validate` need exactly one of this or `-c`/`--config-path`;
    /// `translate` needs this one. Unused by `keygen` and `init`.
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// `validate` checks the config and exits; `translate` prints the
    /// bootstrap configuration generated from a `--config` file; `serve`
    /// runs; `keygen` prints a fresh virtual key and its digest and needs no
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
    /// (matches `auth.hmac_secret_file` in the configuration). Takes
    /// precedence over `$LLMPROXY_AUTH_SECRET` if both are set.
    #[arg(long = "hmac-secret-file", value_name = "PATH")]
    hmac_secret_file: Option<PathBuf>,

    /// `--mode translate`: print provider keys, the auth HMAC secret and the
    /// store URL as configured. Without it they print as `[REDACTED]`.
    #[arg(long = "reveal-secrets")]
    reveal_secrets: bool,

    /// Warn on unknown fields in the bootstrap configuration instead of
    /// failing (default: strict). Has no effect on `--config` files, which
    /// are always strict.
    #[arg(long)]
    permissive: bool,

    /// Number of worker runtimes (serve mode only); default is the number
    /// of available cores.
    #[arg(long, value_name = "N", default_value_t = default_concurrency())]
    concurrency: usize,

    /// Opt-in end-user metadata JSONL collector. Contains identities and model
    /// history; configure access and retention on the destination file.
    #[arg(long, value_name = "PATH")]
    request_records_file: Option<PathBuf>,
    /// Maximum retained attempt records per request. Excess attempts are
    /// explicitly reported as truncated; forwarding retry policy is unchanged.
    #[arg(long, requires = "request_records_file", value_parser = clap::value_parser!(u16).range(1..=64))]
    request_record_max_attempts: Option<u16>,
    /// How long the drain sequence waits for connections to close before
    /// forcing worker shutdown (serve mode only).
    #[arg(
        long = "drain-time-s",
        value_name = "SECS",
        default_value_t = proxy_core::drain::DEFAULT_DRAIN_TIME.as_secs()
    )]
    drain_time_s: u64,

    /// When, inside the drain window, each HTTP connection is told to close:
    /// `immediate` (the default) at drain start, `gradual` spread over the
    /// window, as Envoy does (serve mode only).
    #[arg(long = "drain-strategy", value_enum, default_value_t = DrainStrategyArg::Immediate)]
    drain_strategy: DrainStrategyArg,

    /// Hot-restart base id. Accepted for CLI compatibility only: we have no
    /// hot-restart implementation, so this is parsed and ignored.
    #[arg(long = "base-id", value_name = "N")]
    base_id: Option<u32>,

    /// Log verbosity; `critical` is mapped to `error` (we don't distinguish
    /// the two).
    #[arg(short = 'l', long = "log-level", value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    /// Node id of this instance. Overrides the bootstrap `node.id`; the
    /// result identifies the proxy to the xDS control plane and to
    /// node-scoped filter state.
    #[arg(long = "service-node", value_name = "NAME")]
    service_node: Option<String>,

    /// Cluster of this instance. Overrides the bootstrap `node.cluster`;
    /// the result identifies the proxy to the xDS control plane.
    #[arg(long = "service-cluster", value_name = "NAME")]
    service_cluster: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Create a starter config, authentication secret, and default-tenant key.
    Init {
        /// Directory to initialize.
        #[arg(value_name = "DIRECTORY", default_value = ".")]
        directory: PathBuf,
    },
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
    /// Generates a fresh virtual key and its digest for downstream
    /// authentication. The one mode that touches no config at all.
    Keygen,
}

/// CLI-facing `--drain-strategy`, Envoy's two values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DrainStrategyArg {
    Gradual,
    Immediate,
}

impl From<DrainStrategyArg> for proxy_core::drain::DrainStrategy {
    fn from(arg: DrainStrategyArg) -> Self {
        match arg {
            DrainStrategyArg::Gradual => Self::Gradual,
            DrainStrategyArg::Immediate => Self::Immediate,
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

    if let Some(Command::Init { directory }) = &args.command {
        return match init::run(directory) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("{err}");
                ExitCode::FAILURE
            }
        };
    }

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
    // Translate only prints the lowering; validate and serve run as a
    // replica, which needs a node id with a shared store or a spend journal.
    if args.mode != Mode::Translate {
        proxy_simple_config::require_service_node(&config, args.service_node.as_deref())
            .map_err(|e| (display.clone(), e.to_string()))?;
    }

    if args.mode == Mode::Translate {
        // Secrets are redacted unless asked for.
        let translated = if args.reveal_secrets {
            proxy_simple_config::to_envoy_yaml_with_secrets(&config)
        } else {
            proxy_simple_config::to_envoy_yaml(&config)
        };
        let (yaml, warnings) = translated.map_err(|e| (display.clone(), e.to_string()))?;
        for warning in &warnings {
            eprintln!("warning: `{}`: {}", warning.field_path, warning.message);
        }
        if !args.reveal_secrets && proxy_simple_config::has_inline_secrets(&config) {
            eprintln!(
                "note: secrets print as {}; pass --reveal-secrets to print them",
                proxy_simple_config::REDACTED
            );
        }
        print!("{yaml}");
    }

    let loaded = proxy_simple_config::lower_to_loaded(&config)
        .map_err(|e| (display.clone(), e.to_string()))?;
    Ok((display, loaded))
}

/// The config front-end and file that `serve` started with. It is captured
/// once after argument parsing and passed to the SIGHUP reload path. A reload
/// therefore always uses the same loader the process booted with.
#[derive(Debug, Clone)]
enum ConfigSource {
    /// `-c`/`--config-path`: an Envoy bootstrap file, loaded with `strict`
    /// (mirrors `--permissive` at boot; a reload keeps the same strictness
    /// the process booted with).
    Bootstrap { path: PathBuf, strict: StrictMode },
    /// `--config`: the simple llm-proxy dialect (schema/llmproxy-v0.schema.json).
    Dialect { path: PathBuf },
}

impl ConfigSource {
    /// Derives the source from the same `Args` fields `load` above reads,
    /// once, right after the clap parse that guarantees exactly one of
    /// `config_path`/`config` is set.
    fn from_args(args: &Args) -> Self {
        if let Some(path) = &args.config_path {
            let strict = if args.permissive {
                StrictMode::Permissive
            } else {
                StrictMode::Strict
            };
            ConfigSource::Bootstrap {
                path: path.clone(),
                strict,
            }
        } else {
            let path = args
                .config
                .clone()
                .expect("clap group guarantees one of config_path/config is set");
            ConfigSource::Dialect { path }
        }
    }

    /// Re-parses this source's file from scratch with the same library calls
    /// as boot. It omits the CLI-only output (hints and translate printing).
    /// Warnings go through `tracing`, because this runs from the signal loop.
    fn load(&self) -> Result<ConfigSnapshot, String> {
        let loaded = match self {
            ConfigSource::Bootstrap { path, strict } => {
                load_bootstrap_file(path, *strict).map_err(|e| e.to_string())?
            }
            ConfigSource::Dialect { path } => {
                let config = proxy_simple_config::load_simple_config_file(path)
                    .map_err(|e| e.to_string())?;
                proxy_simple_config::lower_to_loaded(&config).map_err(|e| e.to_string())?
            }
        };
        for warning in &loaded.warnings {
            tracing::warn!(field_path = %warning.field_path, message = %warning.message, "config reload warning");
        }
        build_snapshot(&loaded).map_err(|e| e.to_string())
    }
}

/// Serve mode: build the control runtime, spawn the worker pool, wait for
/// SIGTERM/SIGINT/SIGHUP, then run the graceful shutdown sequence.
fn serve(args: Args, snapshot: ConfigSnapshot) -> ExitCode {
    // Captured before anything below moves out of `args` -- see
    // `ConfigSource`'s doc for why a reload has to be pinned to this, rather
    // than re-deriving it from `Args` each time SIGHUP arrives.
    let config_source = ConfigSource::from_args(&args);

    if let Some(base_id) = args.base_id {
        tracing::warn!(
            base_id,
            "--base-id ignored: it namespaces Envoy's shared-memory hot-restart regions, \
             which llm-proxy does not have (restarts are SO_REUSEPORT process overlap, \
             ADR-0001); multiple instances per host are safe without it"
        );
    }

    let drain_time = Duration::from_secs(args.drain_time_s);
    let drain_strategy = args.drain_strategy.into();

    // Rust note: the control runtime is a separate, ordinary multi-thread
    // tokio runtime (2 worker threads) -- distinct from the
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
        drain_strategy,
        args.service_node,
        args.service_cluster,
        Arc::new(snapshot),
        config_source,
        args.request_records_file,
        args.request_record_max_attempts.unwrap_or(64),
    ))
}

/// How long `run_serve` waits for every worker to report its initial listener
/// bind outcome before giving up and treating startup as failed. Generous:
/// binding a handful of sockets should take microseconds, but a heavily
/// loaded CI box scheduling `concurrency` OS threads is not something to cut
/// close.
const INITIAL_BIND_TIMEOUT: Duration = Duration::from_secs(10);

/// How many finished spans [`proxy_observability::trace::SpanSink`]
/// buffers between the exporter's batches before [`proxy_observability::trace::SpanSink::emit`]
/// starts dropping. Generous relative to `otlp::MAX_BATCH` (512) -- several
/// batches' worth of headroom for a slow or momentarily unreachable
/// collector, without holding an unbounded amount of memory.
const SPAN_SINK_CAPACITY: usize = 4096;

/// Env var carrying the admin write API's bearer
/// token, mirroring `keygen`'s own `SECRET_ENV_VAR` (`LLMPROXY_AUTH_SECRET`)
/// convention -- an operator-supplied credential lives in the environment,
/// never in the bootstrap config, so a config dump or a checked-in file can
/// never leak it. `start_admin` reads this exactly once and passes the
/// result into `proxy_admin::serve` as a plain parameter rather than letting
/// that crate read the environment itself -- see `serve`'s own doc for why
/// (`std::env::set_var` is process-global and racy across parallel tests).
const ADMIN_TOKEN_ENV_VAR: &str = "LLMPROXY_ADMIN_TOKEN";

/// Env var pointing at the `make ui-build` output directory
/// (`admin-ui/dist/`). When set, the admin server loads the single-page admin
/// UI into memory once at startup and serves it same-origin under `/ui` --
/// no CORS, no extra port. Unset (or pointing at a dir without an
/// `index.html`) keeps the API-only behavior: `/ui` 404s with a hint. A
/// broken dir is a warning, not a startup error -- the API surface is the
/// contract, the UI is convenience, and refusing to serve traffic over a
/// missing bundle would invert that priority.
const ADMIN_UI_DIR_ENV_VAR: &str = "LLMPROXY_ADMIN_UI_DIR";

#[allow(clippy::too_many_arguments)]
async fn run_serve(
    concurrency: usize,
    drain_time: Duration,
    drain_strategy: proxy_core::drain::DrainStrategy,
    service_node: Option<String>,
    service_cluster: Option<String>,
    snapshot: Arc<ConfigSnapshot>,
    config_source: ConfigSource,
    request_records_file: Option<PathBuf>,
    request_record_max_attempts: u16,
) -> ExitCode {
    // Collected before `snapshot` moves into `WorkerPool::spawn` purely so
    // the startup log line below can name what got bound; each worker binds
    // its own copy of these sockets independently.
    let listener_summary: Vec<String> = snapshot
        .listeners
        .values()
        .filter(|l| l.bind_to_port)
        .map(|l| format!("{}@{}", l.name, l.address))
        .collect();

    // One `ClusterManager` shared across every worker -- control
    // computes (discovery, EDS updates land here), workers only ever read
    // through `ClusterEntry`/`HttpConnPool`, exactly like Envoy's own
    // cluster manager. Built and populated here, before `WorkerPool::spawn`,
    // so every worker's first `initial_bind` sees a manager that already
    // knows about the snapshot's clusters.
    let cluster_manager = Arc::new(proxy_cluster::manager::ClusterManager::new(
        Arc::new(proxy_cluster::resolver::TokioResolver),
        proxy_core::tls::transport_socket_builder(),
    ));
    // ADR-0006 §2: the effective node id, computed
    // ONCE here so both `factory_state` below and `start_ads` further down
    // use the exact same value -- see `effective_node`'s own doc for the
    // override rule. The bootstrap side of that rule is `snapshot.ads`'s own
    // `node` field, the only place today's IR carries the bootstrap `node`
    // proto field (`convert_dynamic_resources`, `proxy-config`); a fully
    // static bootstrap (no `dynamic_resources`) has none, so this falls back
    // to `NodeIdentity::default()` -- an empty id, matching
    // `SharedFactoryState::node_id`'s own "empty means unconfigured"
    // contract rather than inventing a second meaning for "no bootstrap
    // node" here.
    let bootstrap_node = snapshot
        .ads
        .as_ref()
        .map(|ads| ads.node.clone())
        .unwrap_or_default();
    let node = effective_node(
        &bootstrap_node,
        service_node.as_deref(),
        service_cluster.as_deref(),
    );

    // One `SharedFactoryState` shared across every
    // worker, same "control builds it once, workers get a clone of the same
    // instance" shape as `cluster_manager` above. The HTTP filter chain is
    // rebuilt PER WORKER (`proxy_core::listener::build_hcm_handler` runs on
    // each worker's own `LocalSet`, ADR-0003), so a filter factory that needs
    // ONE process-wide singleton registers it in this slot on its first
    // `create()` call and every other worker's `create()` for the same
    // filter reads the same instance back. It also carries
    // this process's effective node id (`node.id` above), so a filter that
    // needs to disambiguate itself across replicas (the spend flush token,
    // ADR-0006 §2) can reach it via `FactoryContext::node_id()`.
    let factory_state = Arc::new(proxy_http::filter::SharedFactoryState::for_node(
        node.id.clone(),
    ));
    // The one per-serve `SdsSecretRegistry`, same "control
    // builds it once, workers/`start_ads` get a clone of the same instance"
    // shape as `factory_state` just above -- see `proxy_core::tls::
    // SdsSecretRegistry`'s own doc for what it does. Every worker's
    // `build_listener_tls` registers its SDS-named chains against this one
    // instance (via `run_listener_manager`), and `start_ads`'s secret sink
    // publishes into it whenever the control plane delivers a named secret.
    let secret_registry = Arc::new(SdsSecretRegistry::new());
    let rejected = cluster_manager
        .update_from_snapshot(&snapshot.clusters)
        .await;
    if !rejected.is_empty() {
        // A rejected cluster (unimplemented `lb_policy`, or a
        // `transport_socket` that fails to build -- e.g. bad TLS config) is
        // fatal at startup, same as a bad listener certificate
        // (`InitialBindError` below): AGENTS.md invariant 1 forbids leaving the
        // proxy up serving 503s for a misconfigured cluster with no
        // diagnostic.
        for (name, err) in &rejected {
            tracing::error!(cluster = %name, error = %err, "cluster rejected at startup");
        }
        return ExitCode::FAILURE;
    }

    // One `StatsControl`/`Registry` shared across every
    // worker, same "control computes, workers `load`" shape as
    // `cluster_manager` above -- and a `StatHandles` table resolved, once,
    // for every cluster this boot snapshot names. `StatsControl` itself
    // (the only thing that can `resolve` a NEW handle) never leaves this
    // function -- but unlike before the SIGHUP reload path landed, it does
    // not go out of scope either: the signal loop below holds onto it (and
    // a clone of `stat_handles`) so `reload` can extend the SAME table for
    // a cluster a later config only introduces then, via
    // `StatHandles::resolve_missing`. `registry` (a plain `Arc<Registry>`
    // clone) is what both the admin server and every worker's `RouterStats`
    // actually hold. See `proxy_observability::stats`'s module doc for
    // why the two are split.
    let stats_control = proxy_observability::stats::StatsControl::new(concurrency);
    // Count access-log lines dropped by a full queue; see
    // `proxy_observability::sink::register_dropped_lines_counter`.
    proxy_observability::sink::register_dropped_lines_counter(&stats_control);
    let stat_handles = Arc::new(proxy_http::stat_handles::StatHandles::build(
        &stats_control,
        snapshot.clusters.keys().map(String::as_str),
    ));
    // `DownstreamStatHandles`'s counterpart to
    // `stat_handles` above, resolved once at boot for every listener this
    // boot snapshot names (rather than every cluster) -- see
    // `proxy_http::stat_handles`'s module doc for why the two tables mirror
    // each other's shape, and `reload` below for why a listener a later
    // SIGHUP introduces still gets a handle resolved for it.
    let downstream_stat_handles = Arc::new(proxy_http::stat_handles::DownstreamStatHandles::build(
        &stats_control,
        snapshot.listeners.keys().map(String::as_str),
    ));
    // `TokenUsageStatHandles`'s counterpart to
    // `stat_handles` above -- resolved once at boot for every cluster (a
    // provider, per AGENTS.md invariant 6, is a cluster, never a route), same
    // cadence as `stat_handles`. `FilterChainHandler::with_token_stats`'s doc
    // names `crate-core`'s `build_hcm_handler` as the one real call site this
    // feeds -- see that function for the missing half of the wiring this
    // finishes.
    let token_usage_stat_handles =
        Arc::new(proxy_http::stat_handles::TokenUsageStatHandles::build(
            &stats_control,
            snapshot.clusters.keys().map(String::as_str),
        ));
    let registry = stats_control.registry();
    // Request-record delivery is an independent best-effort pipeline. Resolve
    // its finite operational series even when no file collector is configured
    // so Prometheus and OTLP show explicit zeroes rather than an absent signal.
    let metadata_stats = proxy_observability::stats::MetadataDeliveryStats::resolve(&stats_control);
    // The JSONL file sink is the only request-record destination. With no
    // `--request-records-file` there is no sink at all.
    let collector = request_records_file.map(|path| {
        proxy_observability::metadata::MetadataDelivery::start(&path, 1024, metadata_stats)
    });
    let (metadata_sink, metadata_delivery) = match collector {
        Some(Ok((sink, delivery))) => (
            Some(
                Arc::new(sink.with_max_attempts(request_record_max_attempts))
                    as Arc<dyn proxy_observability::records::RequestRecordSink>,
            ),
            Some(delivery),
        ),
        Some(Err(err)) => {
            eprintln!("cannot start metadata collector: {err}");
            return ExitCode::FAILURE;
        }
        None => (None, None),
    };

    // ADR-0009: the billing ledger, opened before any worker starts so the
    // first request already reserves. A ledger that cannot open stops startup:
    // with the default `on_unavailable: reject` it would refuse every request.
    let running_ledger = snapshot.ledger.clone();
    let (ledger, ledger_writer) = match &snapshot.ledger {
        None => (None, None),
        Some(config) => match open_ledger(config, &node.id, &stats_control) {
            Ok((ledger, writer)) => (Some(ledger), Some(writer)),
            Err(message) => {
                eprintln!("{message}");
                return ExitCode::FAILURE;
            }
        },
    };

    // ADR-0008: trace export, opened before any worker starts. A directory
    // that cannot be locked or written stops startup rather than accepting a
    // block that records nothing (AGENTS.md invariant 1).
    let running_traces = snapshot.traces.clone();
    // OTLP export starts once below and never restarts; `reload` refuses a
    // change to either block.
    let running_otlp = (snapshot.tracing.clone(), snapshot.metrics.clone());
    let (trace_admission, trace_gate, trace_exporter) = match &snapshot.traces {
        None => (None, None, None),
        Some(config) => match open_traces(config, &node.id, &stats_control) {
            Ok((admission, gate, exporter)) => (Some(admission), Some(gate), Some(exporter)),
            Err(message) => {
                eprintln!("{message}");
                return ExitCode::FAILURE;
            }
        },
    };

    // Resolve operational health series even when exporters are disabled.
    // Only configured tracing creates a channel; its sender is owned by workers
    // so joining them closes the channel and triggers the final trace flush.
    let trace_channel = snapshot
        .tracing
        .as_ref()
        .map(|_| proxy_observability::trace::SpanSink::new(SPAN_SINK_CAPACITY));
    let trace_counters = proxy_observability::otlp::ExportCounters::resolve(
        &stats_control,
        trace_channel.as_ref().map(|(sink, _)| sink.drop_counter()),
    );
    let mut trace_export_shutdown: Option<(tokio::task::JoinHandle<()>, Duration)> = None;
    let mut metric_export_shutdown: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
        Duration,
    )> = None;

    let tracing_handles =
        snapshot
            .tracing
            .as_ref()
            .zip(trace_channel)
            .map(|(cfg, (sink, spans_rx))| {
                tracing::info!(
                    otlp_endpoint = %cfg.otlp_endpoint,
                    service_name = %cfg.service_name,
                    sample_ratio = cfg.sample_ratio,
                    export_deadline_ms = cfg.export_deadline.as_millis() as u64,
                    "OTLP trace export enabled"
                );
                let handle = tokio::spawn(proxy_observability::otlp::run_trace_exporter(
                    spans_rx,
                    cfg.otlp_endpoint.clone(),
                    cfg.service_name.clone(),
                    registry.clone(),
                    trace_counters.clone(),
                    cfg.export_deadline,
                ));
                // Bound total shutdown work as well as individual RPCs. A prolonged
                // outage can leave several batches queued; do not wait for all of them
                // indefinitely before exiting.
                trace_export_shutdown =
                    Some((handle, cfg.export_deadline * 2 + Duration::from_secs(1)));
                proxy_core::listener::TracingHandles {
                    sink,
                    sample_ratio: cfg.sample_ratio,
                }
            });

    // Metric export runs as its own task, separate from the trace exporter, so
    // a slow trace export cannot delay a metric snapshot. It is reachable even
    // when `snapshot.tracing` is `None`. The failure series is resolved
    // unconditionally, so `llmproxy_otel_export_failures{signal="metrics"}`
    // reads zero from the first scrape rather than being absent. Span drops are
    // not resolved here. They belong to the trace exporter's `ExportCounters`.
    let metric_health = proxy_observability::otlp::MetricExportHealth::resolve(&stats_control);
    if let Some(cfg) = snapshot.metrics.as_ref() {
        tracing::info!(
            otlp_endpoint = %cfg.otlp_endpoint,
            service_name = %cfg.service_name,
            export_interval_ms = cfg.export_interval.as_millis() as u64,
            export_deadline_ms = cfg.export_deadline.as_millis() as u64,
            "OTLP metric export enabled"
        );
        // The `oneshot` sender and the task handle are retained so the drain
        // sequence can ask for a final snapshot and wait for it; with metrics
        // off there is no task and nothing to signal.
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(proxy_observability::otlp::run_metric_exporter(
            registry.clone(),
            cfg.otlp_endpoint.clone(),
            cfg.service_name.clone(),
            cfg.export_interval,
            cfg.export_deadline,
            metric_health,
            shutdown_rx,
        ));
        // The shutdown budget is TWO deadlines plus slack, not one: the signal can
        // arrive while an ordinary tick's snapshot is mid-export (up to one
        // deadline), and the final snapshot it then sends is itself bounded by
        // another. A one-deadline budget is a coin flip against the in-flight
        // export -- this exact shape was caught in review with a slow
        // collector: the budget expired while the final snapshot was
        // legitimately still on the wire and the runtime dropped the task with
        // the data aboard. Both bounds derive from the operator's own
        // `export_deadline`, so the worst-case exit latency is chosen, not
        // imposed.
        let final_snapshot_budget = cfg.export_deadline * 2 + Duration::from_secs(1);
        metric_export_shutdown = Some((shutdown_tx, handle, final_snapshot_budget));
    }

    // Every consumer that must observe a SIGHUP-published snapshot registers
    // its `WorkerConfigHandle` into this ONE registry -- the admin server
    // just below, and every worker `WorkerPool::spawn` creates further down.
    // Created here, before either, precisely so it can be handed to both
    // without reordering when they start (see `start_admin`'s doc comment for
    // why the admin server still has to come first). `ConfigPublisher::publish`
    // (via `SnapshotHandles::store_all`) is what makes registering here enough
    // -- see that type's doc in `proxy-core`'s `runtime.rs`.
    let snapshot_handles = Arc::new(SnapshotHandles::new());

    // `/ready`'s readiness probe, built here (not inside
    // `start_admin`) because it needs `cluster_manager`, which `start_admin`
    // deliberately has no dependency on -- `proxy-admin` only ever sees the
    // `proxy_admin::ReadinessProbe` seam, never `proxy-cluster` itself (see
    // that type's doc). `timeout` follows `AdsConfig::initial_fetch_timeout`
    // when the bootstrap set one, else the same default Envoy itself uses;
    // `Instant::now()` here doubles as the warming deadline's start AND is
    // close enough to true process start for that purpose -- `run_serve` has
    // done no blocking I/O of note before this line.
    let readiness_timeout = snapshot
        .ads
        .as_ref()
        .and_then(|ads| ads.initial_fetch_timeout)
        .unwrap_or(proxy_cluster::discovery::DEFAULT_INITIAL_FETCH_TIMEOUT);
    // The ONE lifecycle state: `/ready`, the admin drain and health-check
    // endpoints, every worker, and the signal loop below all read or write
    // this, so they cannot disagree about whether the process is out of
    // rotation.
    let lifecycle = Arc::new(LifecycleState::new());
    let readiness = build_readiness_probe(
        cluster_manager.clone(),
        readiness_timeout,
        Instant::now(),
        lifecycle.clone(),
    );

    // proxy-admin stays free of data-plane/proto dependencies: this
    // binary is the narrow adapter from ClusterManager's plain runtime view
    // to the admin crate's equally plain input view. The manager filters by
    // the exact config snapshot passed by `/clusters`, so manager-first
    // reload installation cannot leak a future host set into an old config
    // response.
    let cluster_manager_for_admin = cluster_manager.clone();
    let cluster_state: proxy_admin::ClusterStateProvider = Arc::new(move |snapshot| {
        cluster_manager_for_admin
            .live_clusters_for(&snapshot.clusters)
            .into_iter()
            .map(|cluster| proxy_admin::LiveCluster {
                name: cluster.name,
                initialized: cluster.initialized,
                endpoints: cluster
                    .endpoints
                    .into_iter()
                    .map(|endpoint| proxy_admin::LiveEndpoint {
                        host: endpoint.address.ip().to_string(),
                        port: endpoint.address.port(),
                        hostname: endpoint.hostname,
                        weight: endpoint.weight,
                        priority: endpoint.priority,
                        health_flags: endpoint.health_flags,
                        metadata: endpoint.metadata,
                    })
                    .collect(),
            })
            .collect()
    });

    // The read-only admin surface. Opt-in -- only binds
    // when the config names an `admin` address -- and, like a listener's
    // `initial_bind`, a bind failure here is a startup error, not a silent
    // skip (see `start_admin`'s doc comment). Started before the worker pool
    // so a bad admin port fails fast instead of after workers are already
    // accepting traffic.
    let admin_server = match start_admin(
        snapshot.admin,
        AdminStartRuntime {
            snapshot: snapshot.clone(),
            registry: registry.clone(),
            started_at: Instant::now(),
            snapshot_handles: &snapshot_handles,
            factory_state: factory_state.clone(),
            readiness: Some(readiness),
            cluster_state: Some(cluster_state),
            credential_probe: Some(Arc::new(
                proxy_http::credential_probe::ClusterCredentialProbe::new(cluster_manager.clone()),
            )),
            lifecycle: lifecycle.clone(),
            ledger: ledger.clone(),
            trace_gate: trace_gate.clone(),
        },
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
    // Install the shutdown/reload handlers BEFORE spawning any worker. Workers
    // begin binding listeners as soon as they start, so installing after the
    // spawn would leave a window in which the proxy is already accepting
    // connections while a SIGTERM would still kill it outright with no drain
    // -- see `ControlSignals`'s doc comment. Nothing is listening yet at this
    // point, so there is nothing to tear down if installation fails.
    let mut control_signals = match ControlSignals::install() {
        Ok(signals) => signals,
        Err(err) => {
            eprintln!("failed to install shutdown/reload signal handlers: {err}");
            return ExitCode::FAILURE;
        }
    };

    let (bind_tx, mut bind_rx) = mpsc::unbounded_channel::<(WorkerId, Result<(), String>)>();

    // Cloned before `cluster_manager`/`stat_handles` move into the
    // `WorkerPool::spawn` closure below (which needs its own copies, one per
    // worker) -- these are what `reload` uses to apply a SIGHUP'd snapshot to
    // the SAME cluster manager and stats table every worker already reads
    // through.
    let cluster_manager_for_reload = cluster_manager.clone();
    let stat_handle_tables_for_reload = StatHandleTables {
        router: stat_handles.clone(),
        downstream: downstream_stat_handles.clone(),
        token_usage: token_usage_stat_handles.clone(),
    };
    let mut current_version = snapshot.version;
    // Keyed on the bootstrap, not on whether a client actually started: the
    // reload would break the same contract either way, and an operator
    // should not find SIGHUP's behavior depending on control-plane wiring.
    let dynamic_resources_configured = snapshot.ads.is_some();

    // Build the ADS client, if bootstrap
    // `dynamic_resources` asks for one, from this same boot snapshot --
    // before `snapshot` moves into `WorkerPool::spawn` just below. `None`
    // means nothing was started; see `start_ads`'s own doc for the three
    // (non-fatal) ways that happens. The receiver is read from inside the
    // `select!` in this function's own signal loop, further down.
    let mut init_manager = InitManager::new(&snapshot);
    let startup_gate = Arc::new(StartupGate::new());
    let ads_channels = start_ads(&snapshot, &node, &cluster_manager, &secret_registry);
    let (mut ads_apply_rx, mut init_rx) = ads_channels
        .map(|(apply, init)| (Some(apply), Some(init)))
        .unwrap_or((None, None));
    let initial_fetch_timeout = snapshot
        .ads
        .as_ref()
        .and_then(|ads| ads.initial_fetch_timeout)
        .unwrap_or(proxy_cluster::discovery::DEFAULT_INITIAL_FETCH_TIMEOUT);
    if init_manager.ready() {
        startup_gate.release();
    }

    let startup_gate_for_workers = startup_gate.clone();
    let lifecycle_for_workers = lifecycle.clone();
    // The control loop checks reloads against the singletons workers build.
    let factory_state_for_reload = factory_state.clone();
    let mut publisher = WorkerPool::spawn(
        WorkerPoolConfig {
            concurrency,
            pin_cores: true,
        },
        snapshot,
        snapshot_handles,
        move |ctx: WorkerContext| {
            let bind_tx = bind_tx.clone();
            let startup_gate = startup_gate_for_workers.clone();
            worker_main(
                ctx,
                bind_tx,
                startup_gate,
                lifecycle_for_workers.clone(),
                cluster_manager.clone(),
                registry.clone(),
                stat_handles.clone(),
                downstream_stat_handles.clone(),
                token_usage_stat_handles.clone(),
                tracing_handles.clone(),
                metadata_sink.clone(),
                ledger.clone(),
                trace_admission.clone(),
                factory_state.clone(),
                secret_registry.clone(),
            )
        },
    );

    tracing::info!(
        workers = concurrency,
        drain_time_s = drain_time.as_secs(),
        drain_strategy = ?drain_strategy,
        service_node = service_node.as_deref().unwrap_or("-"),
        service_cluster = service_cluster.as_deref().unwrap_or("-"),
        listeners = %listener_summary.join(", "),
        "llm-proxy started, waiting for SIGTERM/SIGINT/SIGHUP/SIGUSR1"
    );

    let records_reopen = metadata_delivery
        .as_ref()
        .map(proxy_observability::metadata::MetadataDelivery::reopen_handle);
    let mut startup = Startup::Running;

    // Startup gate: consume initial xDS responses before allowing workers to
    // bind. A timeout releases this gate without marking unresolved resources
    // initialized; request admission continues to distinguish warming.
    // SIGTERM here stops the proxy at once: the initial fetch can wait out a
    // long `initial_fetch_timeout` on a control plane that never answers.
    let init_deadline = Instant::now() + initial_fetch_timeout;
    while !init_manager.ready() {
        let remaining = init_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            tracing::warn!(
                "initial xDS fetch timeout expired; starting workers with last-good configuration"
            );
            startup_gate.release();
            break;
        }
        tokio::select! {
            event = recv_init_event(&mut init_rx) => {
                if let Some(event) = event {
                    init_manager.accept(event);
                    if init_manager.ready() {
                        startup_gate.release();
                    }
                } else {
                    init_rx = None;
                }
            }
            ads_msg = recv_ads_apply(&mut ads_apply_rx) => {
                if let Some((ads_snapshot, reply)) = ads_msg {
                    if let Some(version) = apply_ads_snapshot(
                        ads_snapshot,
                        reply,
                        current_version,
                        &publisher,
                        &cluster_manager_for_reload,
                        &stats_control,
                        &stat_handle_tables_for_reload,
                        &factory_state_for_reload,
                    ).await {
                        current_version = version;
                    }
                } else {
                    ads_apply_rx = None;
                }
            }
            signal = control_signals.recv_during_startup() => match signal {
                ControlSignal::Shutdown => {
                    startup = Startup::StoppedBeforeBind;
                    break;
                }
                ControlSignal::ReopenLogs => reopen_logs(records_reopen.as_ref()).await,
                ControlSignal::Reload => {}
            },
            _ = tokio::time::sleep(remaining) => {}
        }
    }

    // Startup gate: every worker must report a successful initial bind
    // before we consider ourselves "up". A single failed listener is fatal
    // at startup (AGENTS.md invariant 1 -- see `proxy_core::listener::initial_bind`'s
    // doc comment), so on the first failure (or a timeout) we tear the pool
    // down and exit nonzero instead of proceeding to the signal-wait loop.
    let binds = async {
        if matches!(startup, Startup::StoppedBeforeBind) {
            return Ok(());
        }
        let binds = wait_for_initial_binds(&mut bind_rx, concurrency);
        tokio::pin!(binds);
        loop {
            tokio::select! {
                result = &mut binds => return result,
                // Workers bind quickly, but a SIGTERM here must not wait out
                // `INITIAL_BIND_TIMEOUT`. Listeners already bound drain like
                // any other.
                signal = control_signals.recv_during_startup() => match signal {
                    ControlSignal::Shutdown => {
                        startup = Startup::StoppedDuringBind;
                        return Ok(());
                    }
                    ControlSignal::ReopenLogs => reopen_logs(records_reopen.as_ref()).await,
                    ControlSignal::Reload => {}
                },
            }
        }
    };
    if let Err(message) = binds.await {
        eprintln!("{message}");
        publisher.shutdown();
        publisher.join_async().await;
        if let Some(delivery) = metadata_delivery {
            delivery
                .shutdown(Duration::from_secs(5))
                .await
                .log("listener startup failure");
        }
        return ExitCode::FAILURE;
    }

    // Runs until a shutdown signal arrives; a SIGHUP along the way triggers a
    // config reload, and an ADS-applied snapshot
    // does likewise, and both loop back to waiting, exactly like Envoy's own
    // hot-reload trigger. An admin `POST /drain_listeners` also starts the
    // drain from inside this loop, but the process keeps running (SIGHUP and
    // ADS still apply; workers no longer bind) until a signal arrives. See `reload`'s doc for what "reload" does and does
    // not apply, and requirement 1's test (`sighup_with_a_broken_config_...`
    // in `tests/reload.rs`) for why a failed reload must never reach the
    // `break` below.
    //
    // Rust note: `tokio::select!` picks whichever branch is ready first, so
    // this is what turns two independent producers of "apply a new snapshot"
    // (SIGHUP and ADS) into one control loop that never applies both at once.
    if !matches!(startup, Startup::Running) {
        tracing::info!(
            "termination signal while starting: stopping before the proxy finished starting"
        );
    }
    let mut drain_deadline: Option<Instant> = None;
    if matches!(startup, Startup::Running) {
        loop {
            tokio::select! {
                signal = control_signals.recv() => match signal {
                    ControlSignal::Shutdown => break,
                    ControlSignal::ReopenLogs => reopen_logs(records_reopen.as_ref()).await,
                    // Review C4: the reloaded file yields a static-only snapshot,
                    // which would drop every xDS-delivered resource, and the
                    // applier's static base would bring the boot-time file back
                    // on its next publish. Refused instead; see
                    // internal-docs/envoy-divergences.md "SIGHUP with dynamic_resources".
                    ControlSignal::Reload if dynamic_resources_configured => {
                        tracing::error!(
                            "SIGHUP ignored: this bootstrap configures dynamic_resources, so the \
                             control plane owns the dynamic configuration and a file reload would \
                             replace it; the running configuration is unchanged. Restart the \
                             process to apply bootstrap changes"
                        );
                    }
                    ControlSignal::Reload => {
                        if let Some(new_version) = reload(
                            &config_source,
                            current_version,
                            &publisher,
                            &cluster_manager_for_reload,
                            &stats_control,
                            &stat_handle_tables_for_reload,
                            running_ledger.as_ref(),
                            running_traces.as_ref(),
                            &running_otlp,
                            &factory_state_for_reload,
                        )
                        .await
                        {
                            current_version = new_version;
                        }
                    }
                },
                // Rust note: the `if` guard disables this branch once the drain
                // has started, so a later `Notify` permit cannot start it twice.
                _ = lifecycle.drain_requested(), if drain_deadline.is_none() => {
                    drain_deadline = Some(begin_drain(
                        &lifecycle,
                        &publisher,
                        drain_time,
                        drain_strategy,
                        "POST /drain_listeners",
                    ));
                }
                ads_msg = recv_ads_apply(&mut ads_apply_rx) => match ads_msg {
                    Some((ads_snapshot, reply)) => {
                        if let Some(version) = apply_ads_snapshot(
                            ads_snapshot,
                            reply,
                            current_version,
                            &publisher,
                            &cluster_manager_for_reload,
                            &stats_control,
                            &stat_handle_tables_for_reload,
                            &factory_state_for_reload,
                        )
                        .await
                        {
                            current_version = version;
                        }
                    }
                    None => {
                        // Reachable ONLY when the ADS task dropped its sender,
                        // which should never happen: `AdsClient::run` is `-> !`,
                        // so the task ends only if it panics. (The "no ADS client
                        // was started" case does NOT arrive here -- there
                        // `ads_apply_rx` is already `None` and `recv_ads_apply`
                        // pends forever, so this arm is simply never ready.)
                        // Setting it to `None` stops selecting on a channel that
                        // would otherwise resolve to `None` again immediately,
                        // turning this loop into a spin.
                        tracing::error!(
                            "the ADS client task ended, which it should not be able to do;                          continuing to serve the last-good config with no control-plane                          connection"
                        );
                        ads_apply_rx = None;
                    }
                },
            }
        }
    }

    // A signal that arrives before any admin drain starts the drain now; after
    // an admin drain it keeps the ORIGINAL deadline, so the window is
    // `--drain-time-s` from the first drain trigger, not from the signal.
    let deadline = match drain_deadline {
        Some(deadline) => deadline,
        None => begin_drain(&lifecycle, &publisher, drain_time, drain_strategy, "signal"),
    };

    // Wait for every worker to report its connections gone (or the deadline),
    // while still listening for a second SIGTERM/SIGINT, which means "stop
    // waiting". Rust note: the wait future is pinned OUTSIDE the loop so a
    // SIGHUP iteration does not restart it and lose the workers that already
    // reported; the block ends its `&mut publisher` borrow.
    let drain_result = if matches!(startup, Startup::StoppedBeforeBind) {
        // Every worker is still parked at the startup gate: nothing is bound
        // and nothing is in flight, so there is nothing to wait for.
        Some(proxy_core::drain::DrainOutcome::Completed)
    } else {
        let wait = publisher.wait_drained(deadline);
        tokio::pin!(wait);
        loop {
            tokio::select! {
                outcome = &mut wait => break Some(outcome),
                signal = control_signals.recv() => match signal {
                    ControlSignal::Shutdown => break None,
                    ControlSignal::Reload => tracing::warn!(
                        "SIGHUP ignored: the proxy is draining and will not bind new listeners"
                    ),
                    ControlSignal::ReopenLogs => reopen_logs(records_reopen.as_ref()).await,
                },
            }
        }
    };
    let fast_exit = drain_result.is_none();
    if fast_exit {
        tracing::error!(
            "second termination signal during drain: cutting in-flight requests and exiting now"
        );
    }

    // Stopping the workers drops every connection still open: this is the
    // deadline cut (or the fast exit). Workers that already drained exit at once.
    // Marked first, so a stream cut here is recorded as cut by this process
    // (ADR-0011 decision 1).
    proxy_http::access_logging::mark_process_cut();
    publisher.shutdown();
    publisher.join_async().await;

    // Access-log lines are written by background threads, so a process that
    // exits right after the workers would lose whatever is still queued.
    // Workers are gone, so nothing can add more; bounded so a stuck
    // destination (a blocked stdout pipe) cannot hang exit.
    let log_flush_budget = if fast_exit {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(5)
    };
    if !proxy_observability::sink::flush_all_queued(log_flush_budget) {
        tracing::warn!(
            budget_ms = log_flush_budget.as_millis() as u64,
            "access-log writers did not drain before the shutdown budget; queued lines are lost"
        );
    }

    // Workers are gone, so no entry can be handed over any more: commit what
    // the writer holds. Bounded, so a stuck disk cannot hang exit.
    if let Some(writer) = ledger_writer {
        let budget = if fast_exit {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(5)
        };
        let finished = tokio::task::spawn_blocking(move || writer.shutdown(budget))
            .await
            .unwrap_or(false);
        if finished {
            tracing::info!("billing ledger writer committed its queue and stopped");
        } else {
            tracing::error!(
                budget_ms = budget.as_millis() as u64,
                "billing ledger writer did not finish before the shutdown budget; entries not yet \
                 committed are lost"
            );
        }
    }

    // Workers are gone, so nothing more is handed over: write what is queued
    // and seal every open segment, bounded like the ledger.
    if let Some(exporter) = trace_exporter {
        let budget = if fast_exit {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(5)
        };
        let finished = tokio::task::spawn_blocking(move || exporter.shutdown(budget))
            .await
            .unwrap_or(false);
        if finished {
            tracing::info!("trace exporter wrote its queue and sealed its segments");
        } else {
            tracing::error!(
                budget_ms = budget.as_millis() as u64,
                "trace exporter did not finish before the shutdown budget; open segments are \
                 removed at the next start and counted lost"
            );
        }
    }

    tracing::info!("drain finished: flushing metadata, trace and metric exports");

    // Rust note: the whole flush sequence is one future so it can be raced
    // against `control_signals.recv()` below. Our handlers replaced the default
    // SIGTERM action, so without that race a second signal during a slow
    // flush would be swallowed and every budget below waited out.
    let flush = async {
        // A fast exit bounds each flush to one second and skips the final metric
        // snapshot (its budget is derived from the exporter deadline and can be
        // tens of seconds): the operator asked for "now", but records for requests
        // that already finished are still worth a moment.
        let fast_flush_cap = Duration::from_secs(1);
        if let Some(delivery) = metadata_delivery {
            let budget = if fast_exit {
                fast_flush_cap
            } else {
                Duration::from_secs(5)
            };
            delivery.shutdown(budget).await.log("shutdown");
        }

        // Workers have dropped their senders. Flush remaining traces before taking
        // the final metric snapshot so export failures and drops are included.
        if let Some((mut handle, budget)) = trace_export_shutdown.take() {
            let budget = if fast_exit {
                budget.min(fast_flush_cap)
            } else {
                budget
            };
            match tokio::time::timeout(budget, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => tracing::warn!(error = %err, "trace exporter stopped unexpectedly"),
                Err(_) => {
                    handle.abort();
                    let _ = handle.await;
                    tracing::warn!(
                        budget_ms = budget.as_millis() as u64,
                        "trace exporter exceeded the shutdown budget; pending spans may be lost"
                    );
                }
            }
        }

        // Ask the metric exporter for one last snapshot, AFTER the drain, so the
        // final cumulative figures include drain-period traffic. The wait is
        // bounded by the exporter's deadline, so an unreachable collector cannot
        // hang exit. This proves delivery at the collector's ACK level only.
        //
        // Each `send`/`await` result is ignored on purpose. A closed channel means
        // the exporter is already gone, and nothing can be done about it at exit.
        if fast_exit {
            // Dropping the sender and handle without waiting: see the fast-exit
            // comment above.
            drop(metric_export_shutdown.take());
        } else if let Some((tx, handle, final_snapshot_budget)) = metric_export_shutdown.take() {
            let _ = tx.send(());
            if tokio::time::timeout(final_snapshot_budget, handle)
                .await
                .is_err()
            {
                tracing::warn!(
                    budget_ms = final_snapshot_budget.as_millis() as u64,
                    "metric exporter did not finish its final snapshot before the shutdown budget \
                 expired; the last cumulative figures may not reach the collector"
                );
            }
        }
    };
    tokio::pin!(flush);
    let abandoned = loop {
        tokio::select! {
            () = &mut flush => break false,
            signal = control_signals.recv() => match signal {
                ControlSignal::Shutdown => {
                    tracing::error!(
                        "termination signal while flushing telemetry: abandoning the remaining \
                         flushes and exiting now"
                    );
                    break true;
                }
                ControlSignal::Reload => tracing::warn!(
                    "SIGHUP ignored: the proxy is shutting down and will not reload"
                ),
                ControlSignal::ReopenLogs => tracing::warn!(
                    "SIGUSR1 ignored: the proxy is flushing its logs and exiting"
                ),
            },
        }
    };
    if abandoned {
        return ExitCode::FAILURE;
    }

    match drain_result {
        Some(outcome) => {
            tracing::info!(?outcome, "drain sequence finished, exiting");
            ExitCode::SUCCESS
        }
        None => ExitCode::FAILURE,
    }
}

/// Starts the one drain: flips `/ready` to DRAINING first (so load balancers
/// stop sending before sockets close), then broadcasts the drain to every
/// worker. Returns the deadline that bounds the whole drain. Idempotent on the
/// lifecycle side (`request_drain` reports whether it was first), but callers
/// invoke it once: SIGTERM/SIGINT or an admin request, whichever comes first.
fn begin_drain(
    lifecycle: &LifecycleState,
    publisher: &proxy_core::runtime::ConfigPublisher,
    drain_time: Duration,
    strategy: proxy_core::drain::DrainStrategy,
    trigger: &str,
) -> Instant {
    lifecycle.request_drain();
    let deadline = publisher.start_drain(drain_time, strategy);
    let closes = match strategy {
        proxy_core::drain::DrainStrategy::Immediate => "idle connections close now",
        proxy_core::drain::DrainStrategy::Gradual => {
            "connections close spread over the first quarter of the window, or sooner per request"
        }
    };
    tracing::info!(
        trigger,
        drain_time_s = drain_time.as_secs(),
        drain_strategy = ?strategy,
        "drain started: /ready now answers DRAINING, listeners are closing, {closes}, \
         in-flight requests may finish until the deadline"
    );
    deadline
}

/// The SIGHUP config-reload path: re-reads `source`'s file through the exact
/// front-end it was booted with ([`ConfigSource::load`]), and on success
/// republishes a fresh snapshot -- on failure, logs and leaves every piece of
/// running state untouched.
///
/// Order of operations on success: stat handles are resolved first, so a new
/// cluster has a handle before traffic can reach it. Then
/// `update_from_snapshot` runs, the same call `run_serve` makes at boot. Then
/// [`ConfigPublisher::publish`] runs last, so no listener routes to a cluster
/// the manager does not know yet.
///
/// A cluster the manager rejects is logged at `error` and left out of the live
/// set. Unlike at boot it is not fatal, because a reload must never take the
/// process down.
///
/// The boot-resolved stat-handle tables that `reload` extends when a SIGHUP
/// introduces a new listener or cluster. They are bundled to keep `reload`'s
/// argument count down.
struct StatHandleTables {
    router: Arc<proxy_http::stat_handles::StatHandles>,
    downstream: Arc<proxy_http::stat_handles::DownstreamStatHandles>,
    token_usage: Arc<proxy_http::stat_handles::TokenUsageStatHandles>,
}

/// Proof that a snapshot's clusters are already installed in the shared
/// [`proxy_cluster::manager::ClusterManager`].
///
/// Rust note: a "receipt" type. [`install_clusters`] is the only code that can
/// produce one, and [`publish_to_workers`] takes it by value. That makes
/// publish-before-install inexpressible, so the order is checked by the
/// compiler rather than a comment. See [`apply_snapshot`]'s doc.
///
/// It carries the clusters the new snapshot dropped. They stay installed until
/// [`retire_clusters`] runs.
#[must_use = "publishing without installing clusters first is the bug this type exists to prevent"]
struct ClustersInstalled(proxy_cluster::manager::PendingRemoval);

/// Proof that workers have been handed the snapshot, so the clusters it
/// dropped can leave the registry. Same receipt technique as
/// [`ClustersInstalled`], for the other end of the window.
#[must_use = "dropped clusters stay installed until this is passed to `retire_clusters`"]
struct SnapshotPublished(proxy_cluster::manager::PendingRemoval);

type RejectedClusters = Vec<(
    proxy_config::ir::ClusterName,
    proxy_cluster::manager::ClusterBuildError,
)>;

/// Step 4: teach the shared cluster manager about this snapshot's built
/// clusters, returning the receipt [`publish_to_workers`] needs plus any
/// clusters it rejected. Clusters the snapshot dropped stay installed.
async fn install_clusters(
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    staged: proxy_cluster::manager::StagedClusters,
) -> (ClustersInstalled, RejectedClusters) {
    let (pending, rejected) = cluster_manager.install(staged).await;
    (ClustersInstalled(pending), rejected)
}

/// Step 5: make the snapshot visible to workers. Takes the
/// [`ClustersInstalled`] receipt by value so this cannot run before step 4.
fn publish_to_workers(
    publisher: &proxy_core::runtime::ConfigPublisher,
    snapshot: ConfigSnapshot,
    installed: ClustersInstalled,
) -> (SnapshotVersion, SnapshotPublished) {
    let version = snapshot.version;
    publisher.publish(Arc::new(snapshot));
    (version, SnapshotPublished(installed.0))
}

/// Step 6: drop the clusters the published snapshot no longer names. A
/// worker that has not yet woken for the new snapshot builds new connections
/// from the latest one, because `publish` stores before it pings.
fn retire_clusters(
    cluster_manager: &proxy_cluster::manager::ClusterManager,
    published: SnapshotPublished,
) {
    cluster_manager.retire(published.0);
}

/// What a snapshot producer wants done when the cluster manager cannot build
/// one of its clusters.
#[derive(Clone, Copy, PartialEq, Eq)]
enum OnClusterRejection {
    /// SIGHUP: leave the cluster out and apply the rest, so a reload never
    /// takes the process down.
    LeaveOut,
    /// xDS: refuse the whole snapshot so the response is NACKed and
    /// last-good state keeps serving (S8 all-or-nothing).
    RefuseSnapshot,
}

/// The NACK `error_detail` for clusters the cluster manager could not build,
/// as dotted paths in the same `cds.clusters[<name>]` form lowering errors use.
fn cluster_rejection_detail(rejected: &RejectedClusters) -> String {
    let mut parts: Vec<String> = rejected
        .iter()
        .map(|(name, err)| {
            let field = match err {
                proxy_cluster::manager::ClusterBuildError::Lb(_) => "lb_policy",
                proxy_cluster::manager::ClusterBuildError::TransportSocket(_) => "transport_socket",
            };
            format!("cds.clusters[{name}].{field}: {err}")
        })
        .collect();
    parts.sort();
    parts.join("; ")
}

/// The names `snapshot` still configures, as the stats registry's live scope.
/// Clusters and listeners are restricted to the snapshot's own; tenants and
/// models stay unrestricted because no snapshot field names them (they come
/// from credentials and request bodies), so restricting them here would hide
/// live series.
fn live_scope_for(snapshot: &ConfigSnapshot) -> proxy_observability::stats::LiveScope {
    proxy_observability::stats::LiveScope {
        clusters: Some(snapshot.clusters.keys().cloned().collect()),
        listeners: Some(snapshot.listeners.keys().cloned().collect()),
        tenants: None,
        models: None,
    }
}

/// Applies an already-built [`ConfigSnapshot`] to all running state, in the
/// one safe order. This is the shared apply path for the SIGHUP `reload` and
/// the ADS client. Both call this function rather than publishing on their own.
///
/// Before any step, [`proxy_cluster::manager::ClusterManager::stage`] builds
/// new and changed clusters without installing them. A rejected cluster is
/// handled per `on_rejection`: [`OnClusterRejection::RefuseSnapshot`] returns
/// `Err` with nothing touched (the ADS caller NACKs), and
/// [`OnClusterRejection::LeaveOut`] applies the rest.
///
/// 0. [`proxy_observability::stats::StatsControl::set_live_scope`] drains the
///    series of removed clusters and listeners. The grace period is one
///    published snapshot. Heartbeats and identical re-sends never count.
/// 1. Stat handles are resolved for new cluster keys before traffic can reach
///    them. Steps 2 and 3 do the same for listeners and token usage.
/// 4. [`proxy_cluster::manager::ClusterManager::install`] makes added and
///    changed clusters visible to every worker's router.
/// 5. [`proxy_core::runtime::ConfigPublisher::publish`] makes the snapshot
///    visible to workers. It must not run before step 4, or a worker could
///    route to a cluster the manager does not know yet.
/// 6. [`proxy_cluster::manager::ClusterManager::retire`] runs last, removing
///    dropped clusters only after workers have the snapshot that no longer
///    routes to them (make-before-break).
///
/// The order of steps 4 to 6 is enforced by the type system, not by a test.
/// The damage window is microseconds, and no black-box test lands inside it.
/// [`install_clusters`] returns a [`ClustersInstalled`] receipt that
/// [`publish_to_workers`] takes by value. [`publish_to_workers`] returns a
/// [`SnapshotPublished`] receipt that [`retire_clusters`] takes. Reordering
/// the statements below does not compile.
async fn apply_snapshot(
    snapshot: ConfigSnapshot,
    on_rejection: OnClusterRejection,
    publisher: &proxy_core::runtime::ConfigPublisher,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    stats_control: &proxy_observability::stats::StatsControl,
    tables: &StatHandleTables,
) -> Result<(SnapshotVersion, RejectedClusters), RejectedClusters> {
    let staged = cluster_manager.stage(&snapshot.clusters);
    if on_rejection == OnClusterRejection::RefuseSnapshot && !staged.rejected().is_empty() {
        // Dropping `staged` discards every cluster it built; nothing below
        // has run, so stats scope, registry and workers are all unchanged.
        return Err(staged.into_rejected());
    }

    // Hide the series of clusters and listeners this snapshot no longer
    // names, and let one that returns after a single absent snapshot
    // reappear with its old value, BEFORE the resolves below so their cap
    // accounting sees the new scope and they can replace drained handles.
    // Tenants and models stay unrestricted: no snapshot field names them
    // (they come from credentials and request bodies), so hiding them here
    // would hide live series. A series absent from two consecutive snapshots
    // is drained and its slot reused; see the stats module doc's "Series are
    // retired, drained, then reused".
    stats_control.set_live_scope(live_scope_for(&snapshot));
    tables
        .router
        .resolve_missing(stats_control, snapshot.clusters.keys().map(String::as_str));
    tables
        .downstream
        .resolve_missing(stats_control, snapshot.listeners.keys().map(String::as_str));
    tables
        .token_usage
        .resolve_missing(stats_control, snapshot.clusters.keys().map(String::as_str));

    let (installed, rejected) = install_clusters(cluster_manager, staged).await;
    // `installed` is consumed here, and it cannot exist before the line above
    // -- that is what makes the order a compile error rather than a comment.
    let (version, published) = publish_to_workers(publisher, snapshot, installed);
    retire_clusters(cluster_manager, published);

    Ok((version, rejected))
}

/// Applies one snapshot the dynamic-resource applier assembled and answers its
/// reply: `Ok` lets the response be ACKed, `Err` NACKs it with the clusters'
/// dotted paths (S8). Returns the new version, or `None` when the snapshot
/// was refused and last-good keeps serving.
// Same shape as `reload`, which takes the same running state.
#[allow(clippy::too_many_arguments)]
async fn apply_ads_snapshot(
    mut snapshot: ConfigSnapshot,
    reply: oneshot::Sender<Result<(), String>>,
    current_version: SnapshotVersion,
    publisher: &proxy_core::runtime::ConfigPublisher,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    stats_control: &proxy_observability::stats::StatsControl,
    tables: &StatHandleTables,
    factory_state: &proxy_http::filter::SharedFactoryState,
) -> Option<SnapshotVersion> {
    // Rust note: authoritative version stamping happens HERE, not inside
    // `ResourceApplier`. Two producers stamp a version: `reload` (SIGHUP) does
    // the same overwrite before its own `apply_snapshot` call;
    // `ResourceApplier::assemble_snapshot`'s internal version is advisory
    // only and is discarded here.
    snapshot.version = SnapshotVersion(current_version.0 + 1);
    // A listener update that would change an auth chain's startup-fixed
    // inputs is NACKed whole, like an unbuildable cluster (S8).
    if let Err(detail) = proxy_core::listener::check_reload_compatible(&snapshot, factory_state) {
        tracing::error!(
            %detail,
            "xDS: a listener in the discovery response changes state fixed at startup; \
             rejecting the response and keeping the last-good configuration"
        );
        let _ = reply.send(Err(detail));
        return None;
    }
    let applied = apply_snapshot(
        snapshot,
        OnClusterRejection::RefuseSnapshot,
        publisher,
        cluster_manager,
        stats_control,
        tables,
    )
    .await;
    let (outcome, version) = match applied {
        Ok((version, _)) => (Ok(()), Some(version)),
        Err(rejected) => {
            let detail = cluster_rejection_detail(&rejected);
            tracing::error!(
                %detail,
                "xDS: a cluster in the discovery response could not be built; rejecting the \
                 response and keeping the last-good configuration"
            );
            (Err(detail), None)
        }
    };
    // A dropped receiver (the ADS task's `Publish` future was cancelled, e.g.
    // mid-shutdown) must not panic this loop -- `send` returning `Err` just
    // means nobody is waiting for the reply any more.
    let _ = reply.send(outcome);
    version
}

/// Returns the new [`SnapshotVersion`] on success so the caller can advance
/// `current_version` for the *next* reload, or `None` on any failure (old
/// snapshot, old version, old cluster set: all still serving).
// The boot-scoped inputs (ledger, traces, OTLP, auth) are each checked against the
// reloaded snapshot here, where it is loaded; bundling them only for the lint
// would hide which one refused a reload.
#[allow(clippy::too_many_arguments)]
async fn reload(
    source: &ConfigSource,
    current_version: SnapshotVersion,
    publisher: &proxy_core::runtime::ConfigPublisher,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    stats_control: &proxy_observability::stats::StatsControl,
    tables: &StatHandleTables,
    running_ledger: Option<&proxy_observability::ledger::LedgerConfig>,
    running_traces: Option<&proxy_observability::traces::config::TraceExportConfig>,
    running_otlp: &(
        Option<proxy_config::ir::TracingConfig>,
        Option<proxy_config::ir::MetricsExportConfig>,
    ),
    factory_state: &proxy_http::filter::SharedFactoryState,
) -> Option<SnapshotVersion> {
    // The parse and lowering are blocking file I/O and CPU work. Run inline,
    // they would hold a worker of the 2-thread control runtime that also
    // serves the admin API and ADS.
    let loaded = {
        let source = source.clone();
        tokio::task::spawn_blocking(move || source.load())
            .await
            .unwrap_or_else(|err| Err(format!("config reload task failed: {err}")))
    };
    let mut snapshot = match loaded {
        Ok(snapshot) => snapshot,
        Err(err) => {
            // Requirement 1: this is the one log line an operator's typo has
            // to produce. `err` is a `ConfigError`/`proxy-simple-config`
            // error `Display`, which already carries the full dotted field
            // path (AGENTS.md invariant 1) -- the same detail the boot-time
            // `eprintln!("{err}")` in `main()` shows, just routed through
            // `tracing` instead since this runs mid-serve.
            tracing::error!(
                error = %err,
                "SIGHUP: config reload failed; continuing to serve the previous snapshot"
            );
            return None;
        }
    };

    // `build_snapshot` always stamps a freshly loaded config as version 1
    // (it has no notion of "this is a reload") -- requirement 3 is that the
    // version strictly advances across reloads, so this overwrites it with
    // the next number in the sequence this process has been handing out
    // since boot (`current_version`, threaded in by the caller). This stays
    // here, not in `apply_snapshot`, because the ADS producer landing next
    // stamps its own versions differently (from the discovery response, not
    // from a local counter) -- versioning is producer-specific, applying is not.
    snapshot.version = SnapshotVersion(current_version.0 + 1);
    // The ledger writer is opened once at boot; a reload cannot move its
    // spool, keys or admission policy. Refusing the whole reload is the only
    // way the change is not silently ignored (AGENTS.md invariant 1).
    if snapshot.ledger.as_ref() != running_ledger {
        tracing::error!(
            "SIGHUP: node.metadata[\"io.llmproxy.ledger\"] (the dialect's `ledger`) cannot change \
             on reload; restart the process to apply it. Continuing to serve the previous snapshot"
        );
        return None;
    }
    // Trace export is boot-scoped like the ledger: its directory lock, codec
    // and destination are fixed once opened.
    if snapshot.traces.as_ref() != running_traces {
        tracing::error!(
            "SIGHUP: node.metadata[\"io.llmproxy.traces\"] (the dialect's `observability.traces`) \
             cannot change on reload; restart the process to apply it. Continuing to serve the \
             previous snapshot"
        );
        return None;
    }
    // OTLP trace and metric export start once at boot (see `run_serve`).
    if snapshot.tracing != running_otlp.0 {
        tracing::error!(
            "SIGHUP: node.metadata[\"io.llmproxy.tracing\"] (the dialect's \
             `observability.tracing`) cannot change on reload; restart the process to apply it. \
             Continuing to serve the previous snapshot"
        );
        return None;
    }
    if snapshot.metrics != running_otlp.1 {
        tracing::error!(
            "SIGHUP: node.metadata[\"io.llmproxy.metrics\"] (the dialect's \
             `observability.metrics`) cannot change on reload; restart the process to apply it. \
             Continuing to serve the previous snapshot"
        );
        return None;
    }
    // The auth control plane is built once per chain and reused across a
    // reload; a reload that would change its secret, bootstrap keys, store,
    // poll interval or key ring is refused here, before workers see it.
    if let Err(detail) = proxy_core::listener::check_reload_compatible(&snapshot, factory_state) {
        tracing::error!(
            %detail,
            "SIGHUP: config reload refused; continuing to serve the previous snapshot"
        );
        return None;
    }

    // Captured before `snapshot` moves into `apply_snapshot` below, purely so
    // the success log line further down can still report them.
    let listeners = snapshot.listeners.len();
    let clusters = snapshot.clusters.len();

    let applied = apply_snapshot(
        snapshot,
        OnClusterRejection::LeaveOut,
        publisher,
        cluster_manager,
        stats_control,
        tables,
    )
    .await;
    // `LeaveOut` never refuses the snapshot; the arm exists so a future change
    // to that rule fails loudly instead of being ignored.
    let (version, rejected) = match applied {
        Ok(applied) => applied,
        Err(rejected) => {
            tracing::error!(
                detail = %cluster_rejection_detail(&rejected),
                "SIGHUP: config reload refused; continuing to serve the previous snapshot"
            );
            return None;
        }
    };

    for (name, err) in &rejected {
        tracing::error!(
            cluster = %name,
            error = %err,
            "SIGHUP: cluster rejected during reload; it is not part of the live cluster set \
             (a request routed to it will fail until this is fixed and reloaded again)"
        );
    }

    tracing::info!(
        version = version.0,
        listeners,
        clusters,
        rejected_clusters = rejected.len(),
        "SIGHUP: config reload succeeded"
    );
    Some(version)
}

// --------------------------------------------------------------------- ads --
//
// The ADS client is the *second* producer of
// `Arc<ConfigSnapshot>` `apply_snapshot`'s doc comment predicted -- everything
// below is what actually constructs it from bootstrap `dynamic_resources` and
// wires its output back into `run_serve`'s own control loop, instead of
// reaching around `apply_snapshot`/`ConfigPublisher` to publish on its own.

/// Full `type_url` a CDS `DiscoveryRequest` subscribes to. Duplicated from
/// `proxy_xds::apply`'s own (private) constant of the same value rather than
/// making that one `pub` -- see this task's own brief for why.
const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
/// Full `type_url` an LDS `DiscoveryRequest` subscribes to.
const LDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.listener.v3.Listener";
/// Full `type_url` an RDS `DiscoveryRequest` subscribes to.
const RDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.route.v3.RouteConfiguration";
/// Full `type_url` an EDS `DiscoveryRequest` subscribes to. Same duplication
/// as [`CDS_TYPE_URL`]/[`LDS_TYPE_URL`], and the same reason.
const EDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment";
/// Full `type_url` an SDS `DiscoveryRequest` subscribes to. Same duplication
/// as [`CDS_TYPE_URL`]/[`LDS_TYPE_URL`], and the same reason.
const SDS_TYPE_URL: &str = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret";

/// What `ResourceApplier`'s `Publish` callback sends to `run_serve`'s control
/// loop for one accepted `DiscoveryResponse`: an owned snapshot to apply, and
/// the oneshot half the loop replies on once it actually has (see
/// `start_ads`'s doc for why the callback awaits the reply before resolving).
///
/// The reply is the apply outcome: `Err` carries the NACK `error_detail` for
/// a snapshot the control loop refused to install (S8 keeps last-good).
type AdsApplyMsg = (ConfigSnapshot, oneshot::Sender<Result<(), String>>);

/// The NACK detail for a response the control loop never answered. A loop
/// that went away (shutdown) did not apply the snapshot, so the response must
/// not be ACKed.
const CONTROL_LOOP_GONE: &str = "the proxy's control loop stopped before applying this response";

/// What a dynamic-resource publish resolves to once the control loop has
/// answered.
async fn await_apply_reply(reply_rx: oneshot::Receiver<Result<(), String>>) -> Result<(), String> {
    reply_rx
        .await
        .unwrap_or_else(|_| Err(CONTROL_LOOP_GONE.to_string()))
}

/// Tracks Envoy's initial dependency chain. A deadline releases workers from
/// startup gating, but never changes any cluster's initialization state.
#[derive(Debug)]
struct InitManager {
    cds_required: bool,
    lds_required: bool,
    cds_received: bool,
    lds_received: bool,
    required_eds: std::collections::BTreeSet<String>,
    received_eds: std::collections::BTreeSet<String>,
    required_rds: std::collections::BTreeSet<String>,
    received_rds: std::collections::BTreeSet<String>,
}

struct StartupGate {
    released: AtomicBool,
    notify: Notify,
}

impl StartupGate {
    fn new() -> Self {
        Self {
            released: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        while !self.released.load(Ordering::Acquire) {
            self.notify.notified().await;
        }
    }
}

impl InitManager {
    fn new(snapshot: &ConfigSnapshot) -> Self {
        let (cds_required, lds_required) = snapshot
            .ads
            .as_ref()
            .map(|ads| (ads.cds, ads.lds))
            .unwrap_or((false, false));
        let required_eds = snapshot
            .clusters
            .values()
            .filter_map(|cluster| cluster.eds.as_ref().map(|eds| eds.service_name.clone()))
            .collect();
        let required_rds = snapshot
            .listeners
            .values()
            .flat_map(|listener| listener.rds_route_config_names().cloned())
            .collect();
        Self {
            cds_required,
            lds_required,
            cds_received: false,
            lds_received: false,
            required_eds,
            received_eds: Default::default(),
            required_rds,
            received_rds: Default::default(),
        }
    }

    fn accept(&mut self, event: InitializationEvent) {
        self.cds_required = event.cds_required;
        self.lds_required = event.lds_required;
        self.required_eds = event.required_eds;
        self.received_eds = event.received_eds;
        self.required_rds = event.required_rds;
        self.received_rds = event.received_rds;
        match event.accepted_type_url.as_str() {
            CDS_TYPE_URL => self.cds_received = true,
            LDS_TYPE_URL => self.lds_received = true,
            _ => {}
        }
    }

    fn ready(&self) -> bool {
        (!self.cds_required || self.cds_received)
            && (!self.lds_required || self.lds_received)
            && self.required_eds.is_subset(&self.received_eds)
            && self.required_rds.is_subset(&self.received_rds)
    }
}

/// `--service-node`/`--service-cluster` override the corresponding field of
/// bootstrap `node` when present -- Envoy gives its own flags of the same
/// name the identical relationship to its bootstrap `node`. A pure function,
/// deliberately, so this rule is unit-testable without an `AdsClient`, a
/// channel, or a control plane (see the `effective_node_*` tests below).
///
/// An explicitly-empty override (`--service-node ''`, i.e. `Some("")`) still
/// overrides the bootstrap value with an empty string. The signal this reads
/// is `Some` vs `None` -- whether the flag was passed at all, which is
/// exactly what `clap` surfaces on `Args::service_node`/`service_cluster` --
/// not whether the value it carries happens to be non-empty. Treating an
/// empty override as "ignore it" would mean an operator who deliberately
/// wants an empty node id (unusual, but not this function's business to
/// forbid) silently keeps the bootstrap's instead, with no way to tell it
/// happened short of reading the ADS wire traffic.
fn effective_node(
    bootstrap: &NodeIdentity,
    service_node: Option<&str>,
    service_cluster: Option<&str>,
) -> NodeIdentity {
    NodeIdentity {
        id: service_node
            .map(str::to_string)
            .unwrap_or_else(|| bootstrap.id.clone()),
        cluster: service_cluster
            .map(str::to_string)
            .unwrap_or_else(|| bootstrap.cluster.clone()),
    }
}

/// Opens trace export (ADR-0008): the emergency gate (closed when a disable
/// was persisted), admission, and the exporter thread, which locks the
/// directory and raises the epoch mark. The node id names every segment, so
/// it is required and must be unique per replica. Errors start with the
/// namespace path.
type OpenedTraces = (
    Arc<proxy_observability::traces::capture::TraceAdmission>,
    Arc<proxy_observability::traces::gate::TraceGate>,
    proxy_observability::traces::exporter::TraceExporter,
);

fn open_traces(
    config: &proxy_observability::traces::config::TraceExportConfig,
    node_id: &str,
    stats: &proxy_observability::stats::StatsControl,
) -> Result<OpenedTraces, String> {
    use proxy_observability::traces::{capture, exporter, gate};
    const ROOT: &str = "node.metadata[\"io.llmproxy.traces\"]";
    let gate = Arc::new(gate::TraceGate::open(&config.directory));
    let trace_stats = capture::TraceStats::resolve(stats);
    let (admission, traces) = capture::TraceAdmission::new(config, Arc::clone(&gate), trace_stats);
    let exporter =
        exporter::TraceExporter::spawn(config, node_id, Arc::clone(&admission), traces, stats)
            .map_err(|e| match e {
                proxy_observability::traces::segment::OpenError::NodeId => format!(
                    "{ROOT}: trace export requires a node id (--service-node or node.id): {e}"
                ),
                other => format!("{ROOT}.directory: {other}"),
            })?;
    if gate.status().disabled {
        tracing::warn!(
            "trace capture starts DISABLED: a disable was persisted in the trace directory; \
             POST /traces/capture enables it"
        );
    }
    Ok((admission, gate, exporter))
}

/// Opens the billing ledger (ADR-0009). Its `instance_id` is the node id,
/// under the shared spend store's rule (ADR-0006 addendum): configured,
/// unique to this replica and stable across its restarts. A per-boot id
/// would start a new instance on every restart, and two replicas sharing one
/// would interleave sequences no consumer can tell apart.
fn open_ledger(
    config: &proxy_observability::ledger::LedgerConfig,
    node_id: &str,
    stats: &proxy_observability::stats::StatsControl,
) -> Result<
    (
        Arc<proxy_observability::ledger::Ledger>,
        proxy_observability::ledger::LedgerWriter,
    ),
    String,
> {
    const ROOT: &str = "node.metadata[\"io.llmproxy.ledger\"]";
    if node_id.is_empty() || node_id == "-" || node_id.len() > 128 {
        return Err(format!(
            "{ROOT}: the ledger requires a configured node id of at most 128 bytes, unique to \
             this replica and stable across its restarts: pass --service-node <name> (or set \
             the bootstrap node.id); it becomes every entry's instance_id"
        ));
    }
    proxy_observability::ledger::open(config, node_id, stats).map_err(|e| match e {
        proxy_observability::ledger::LedgerOpenError::Thread(_) => format!("{ROOT}: {e}"),
        _ => format!("{ROOT}.{e}"),
    })
}

/// Builds and spawns the dynamic-resource client tasks when `snapshot.ads`
/// asks for one. Sources may be ADS, filesystem, or a mixture of both.
///
/// Returns `None` -- and starts nothing -- in three cases, none of them
/// fatal to `run_serve` (architecture.md §12.2 rule 5: keep serving last-good/static config):
/// - `snapshot.ads` is `None`: no `dynamic_resources` in the bootstrap.
/// - none of `lds`, `cds`, or a statically-declared EDS cluster asks for
///   anything: nothing to subscribe to, logged at `info!`. EDS has no
///   bootstrap flag of its own -- Envoy expresses it per cluster, via
///   `eds_cluster_config.eds_config.ads`, already lowered into
///   `ClusterConfig.eds` -- so this gate also starts an ADS client for a
///   bootstrap that enables neither `lds` nor `cds` but declares a `Cluster`
///   whose membership comes over EDS.
/// - an ADS-backed source has no usable cluster endpoint, or its channel
///   cannot be built (`proxy_core::ads_transport::ads_channel`: a bad
///   `transport_socket`, or plaintext to a remote control plane without the
///   opt-in): a config error, logged at `error!` with the
///   cluster name. Filesystem-only sources do not
///   need an ADS cluster and are handled by the local watcher above.
///
/// The `Channel` is built with `connect_lazy`, not an eager `connect().await`:
/// a control plane that is not up yet at boot must not stop the proxy from
/// serving. [`AdsClient::run`] reconnects forever with a jittered backoff (see
/// its own doc comment), and a lazy channel is what lets the FIRST attempt
/// fail into that loop instead of into a startup error here.
///
/// `node` is the ALREADY-RESOLVED [`effective_node`] result -- `run_serve`
/// computes it once, before this call, so it can also hand the same value to
/// `SharedFactoryState::for_node`; this function no longer calls
/// `effective_node` itself, to keep that a single call site (see `run_serve`'s
/// own comment on `node`).
fn start_filesystem_ads(
    snapshot: &Arc<ConfigSnapshot>,
    _cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    _secret_registry: &Arc<SdsSecretRegistry>,
) -> Option<(
    mpsc::Receiver<AdsApplyMsg>,
    mpsc::Receiver<InitializationEvent>,
)> {
    let ads = snapshot.ads.as_ref()?;
    let mut sources = Vec::new();
    if let Some(DiscoverySource::Filesystem(path)) = &ads.lds_source {
        sources.push(FileSource::new(
            path.clone(),
            "type.googleapis.com/envoy.config.listener.v3.Listener",
        ));
    }
    if let Some(DiscoverySource::Filesystem(path)) = &ads.cds_source {
        sources.push(FileSource::new(
            path.clone(),
            "type.googleapis.com/envoy.config.cluster.v3.Cluster",
        ));
    }
    if sources.is_empty() {
        return None;
    }
    let (apply_tx, apply_rx) = mpsc::channel::<AdsApplyMsg>(1);
    let (init_tx, init_rx) = mpsc::channel::<InitializationEvent>(16);
    let publish: Publish = Box::new(move |snapshot: Arc<ConfigSnapshot>| {
        let apply_tx = apply_tx.clone();
        Box::pin(async move {
            let owned = snapshot.with_dynamic_resources(
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                snapshot.version,
            );
            let (reply_tx, reply_rx) = oneshot::channel();
            if apply_tx.send((owned, reply_tx)).await.is_err() {
                return Err(CONTROL_LOOP_GONE.to_string());
            }
            await_apply_reply(reply_rx).await
        })
    });
    let initialization_sink: InitializationSink = Box::new(move |event| {
        let init_tx = init_tx.clone();
        Box::pin(async move {
            let _ = init_tx.send(event).await;
        })
    });
    let mut applier = ResourceApplier::new(Arc::clone(snapshot), publish)
        .with_initialization_sink(initialization_sink);
    tokio::spawn(async move {
        let mut watchers: Vec<_> = sources.iter().map(FileSource::watcher).collect();
        loop {
            for (source, watcher) in sources.iter().zip(watchers.iter_mut()) {
                match watcher.changed() {
                    Ok(true) => match source.load() {
                        Ok(response) => {
                            let verdict = applier.on_response(&response).await;
                            tracing::info!(type_url = %response.type_url, ?verdict, "filesystem xDS response applied");
                        }
                        Err(error) => {
                            tracing::error!(%error, "filesystem xDS response rejected; retaining last-good state")
                        }
                    },
                    Ok(false) => {}
                    Err(error) => {
                        tracing::warn!(%error, "filesystem xDS source unavailable; retaining last-good state")
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    });
    Some((apply_rx, init_rx))
}

#[derive(Clone)]
struct SharedApplier {
    inner: Arc<tokio::sync::Mutex<ResourceApplier>>,
    desired: Arc<std::sync::RwLock<HashMap<String, BTreeSet<String>>>>,
}

impl SharedApplier {
    fn new(applier: ResourceApplier) -> Self {
        let mut desired_map = HashMap::new();
        for type_url in [
            "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
            "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
            "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
        ] {
            if let Some(names) = ResponseHandler::desired_names(&applier, type_url) {
                desired_map.insert(type_url.to_string(), names);
            }
        }
        Self {
            inner: Arc::new(tokio::sync::Mutex::new(applier)),
            desired: Arc::new(std::sync::RwLock::new(desired_map)),
        }
    }

    async fn apply_sotw(&self, response: DiscoveryResponse) -> Verdict {
        let mut applier = self.inner.lock().await;
        let verdict = applier.on_response(&response).await;
        self.refresh_desired(&applier);
        verdict
    }

    async fn apply_delta(&self, response: DeltaDiscoveryResponse) -> Verdict {
        let mut applier = self.inner.lock().await;
        let verdict = applier.on_delta_response(&response).await;
        self.refresh_desired(&applier);
        verdict
    }

    fn refresh_desired(&self, applier: &ResourceApplier) {
        let mut desired = self.desired.write().expect("desired names lock poisoned");
        for type_url in [
            "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
            "type.googleapis.com/envoy.config.route.v3.RouteConfiguration",
            "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.Secret",
        ] {
            if let Some(names) = ResponseHandler::desired_names(applier, type_url) {
                desired.insert(type_url.to_string(), names);
            }
        }
    }
}

impl ResponseHandler for SharedApplier {
    fn handle(
        &mut self,
        response: &DiscoveryResponse,
    ) -> impl std::future::Future<Output = Verdict> + Send {
        let this = self.clone();
        let response = response.clone();
        async move { this.apply_sotw(response).await }
    }

    fn desired_names(&self, type_url: &str) -> Option<BTreeSet<String>> {
        self.desired
            .read()
            .expect("desired names lock poisoned")
            .get(type_url)
            .cloned()
    }
}

impl DeltaResponseHandler for SharedApplier {
    fn handle(
        &mut self,
        response: &DeltaDiscoveryResponse,
    ) -> impl std::future::Future<Output = Verdict> + Send {
        let this = self.clone();
        let response = response.clone();
        async move { this.apply_delta(response).await }
    }

    fn desired_names(&self, type_url: &str) -> Option<BTreeSet<String>> {
        <Self as ResponseHandler>::desired_names(self, type_url)
    }
}

fn start_ads(
    snapshot: &Arc<ConfigSnapshot>,
    node: &NodeIdentity,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    secret_registry: &Arc<SdsSecretRegistry>,
) -> Option<(
    mpsc::Receiver<AdsApplyMsg>,
    mpsc::Receiver<InitializationEvent>,
)> {
    let ads = snapshot.ads.as_ref()?;
    if ads.cluster.is_none() {
        return start_filesystem_ads(snapshot, cluster_manager, secret_registry);
    }
    let ads_cluster = ads.cluster.as_ref()?;

    let has_static_eds_cluster = snapshot.clusters.values().any(|c| c.eds.is_some());
    let has_static_rds_listener = snapshot
        .listeners
        .values()
        .any(|listener| listener.rds_route_config_names().next().is_some());
    if !ads.lds && !ads.cds && !has_static_eds_cluster && !has_static_rds_listener {
        tracing::info!(
            cluster = %ads_cluster,
            "ADS configured but none of `lds`, `cds`, or a statically-declared EDS cluster asks \
             for anything; nothing to subscribe to, not starting an ADS client"
        );
        return None;
    }

    // `ads.cluster` names a cluster lowering has already checked exists in
    // `static_resources`; a missing one is treated like "no endpoints":
    // loud, never fatal to the process (architecture.md section 12.2 rule 5).
    let Some(cluster) = snapshot.clusters.get(ads_cluster) else {
        tracing::error!(
            cluster = %ads_cluster,
            "ADS cluster does not exist; not starting an ADS client"
        );
        return None;
    };
    let ads_channel = match proxy_core::ads_transport::ads_channel(cluster, ads) {
        Ok(ads_channel) => ads_channel,
        Err(error) => {
            tracing::error!(
                cluster = %ads_cluster,
                %error,
                "cannot build the ADS channel; not starting an ADS client"
            );
            return None;
        }
    };
    let target = &ads_channel.target;
    match ads_channel.transport {
        AdsTransport::Tls {
            server_verified: true,
        } => tracing::info!(cluster = %ads_cluster, %target, "ADS channel uses TLS"),
        // Envoy parity: no validation_context means any server certificate
        // is accepted. Encrypted but unauthenticated, so say so.
        AdsTransport::Tls {
            server_verified: false,
        } => tracing::warn!(
            cluster = %ads_cluster,
            %target,
            "ADS channel uses TLS without a validation_context: the control plane's \
             certificate is NOT verified"
        ),
        AdsTransport::PlaintextLoopback => {
            tracing::info!(cluster = %ads_cluster, %target, "ADS channel is plaintext on loopback")
        }
        // The fail-open path of AGENTS.md "Fail-open controls": the operator
        // chose a plaintext remote control plane, so log it loudly.
        AdsTransport::PlaintextAllowed => tracing::warn!(
            cluster = %ads_cluster,
            %target,
            "ADS channel is PLAINTEXT to a non-loopback control plane \
             (io.llmproxy.ads.allow_plaintext): provider credentials it delivers are \
             readable on the network"
        ),
    }
    let channel = ads_channel.channel;
    let mut grpc_client = AggregatedDiscoveryServiceClient::new(channel);

    // Bounded at 1: `ResourceApplier` (via `AdsClient::run_once`) applies one
    // `DiscoveryResponse` at a time and its `Publish` future awaits the
    // oneshot reply below before resolving, so at most one message is ever in
    // flight on this channel.
    let (apply_tx, apply_rx) = mpsc::channel::<AdsApplyMsg>(1);
    let (init_tx, init_rx) = mpsc::channel::<InitializationEvent>(16);
    let publish: Publish = Box::new(move |snapshot: Arc<ConfigSnapshot>| {
        let apply_tx = apply_tx.clone();
        Box::pin(async move {
            // Rust note: `ConfigSnapshot` has no `Clone` impl (deliberately --
            // see `crates/proxy-config/tests/ir_readership.rs`'s module doc),
            // so this is the one place this wiring needs to turn the
            // `Arc<ConfigSnapshot>` `ResourceApplier` hands back into an
            // owned one to send down the channel. `with_dynamic_resources`
            // (its own public constructor) is reused for exactly that,
            // rather than a struct literal here naming every field -- see
            // that method's own doc for why a struct literal in a runtime
            // crate is the shape `ir_readership.rs` exists to catch. Passing
            // empty dynamic maps means every listener/cluster is carried
            // over unchanged; the version passed through is a placeholder --
            // `run_serve`'s control loop is the authoritative stamper (see
            // its own comment on `current_version`) and overwrites it before
            // this ever reaches `apply_snapshot`.
            let owned = snapshot.with_dynamic_resources(
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                snapshot.version,
            );
            let (reply_tx, reply_rx) = oneshot::channel();
            if apply_tx.send((owned, reply_tx)).await.is_err() {
                // The control loop only ever drops its receiver by falling
                // out of `run_serve`'s select loop at shutdown -- if this
                // fires, the process is already on its way down and nothing
                // was applied, so the response is not ACKed.
                return Err(CONTROL_LOOP_GONE.to_string());
            }
            // Apply-then-ACK (S8): this future does not resolve until the
            // control loop has actually applied the snapshot --
            // `AdsClient::run_once` does not send this response's ACK until
            // THIS future resolves.
            //
            // Nothing in the tests catches the loss of this `.await`. Observing
            // the ACK costs a round trip, so the racing apply nearly always
            // wins (see `tests/ads_e2e.rs`). The seam is pinned one layer down
            // by `proxy-xds`'s
            // `the_ack_does_not_reach_the_wire_until_the_handler_future_resolves`.
            // This closure's use of it is not pinned. The harm is bounded: the
            // control plane believes config is live slightly early, which is an
            // S8 conformance point, not a serving defect.
            await_apply_reply(reply_rx).await
        })
    });

    // An accepted EDS endpoint update calls `ClusterManager::accept_eds_update`
    // directly. It skips the `apply_tx` channel, which exists for CDS/LDS
    // sequencing. The cluster is already live and no worker-visible snapshot
    // needs publishing.
    let cluster_manager = Arc::clone(cluster_manager);
    let endpoint_sink: PublishEndpoints = Box::new(move |name, endpoints| {
        let cluster_manager = Arc::clone(&cluster_manager);
        Box::pin(async move {
            cluster_manager
                .accept_eds_update(&name, &endpoints)
                .map(|_diff| ())
                .map_err(|err| err.to_string())
        })
    });

    // An accepted SDS secret goes straight to `SdsSecretRegistry`, for the
    // same reason as `endpoint_sink`. Validation contexts rebuild and swap the
    // ServerConfig, because rustls bakes the trust anchors into it. An invalid
    // CA is NACKed while the prior config keeps serving.
    let secret_registry = Arc::clone(secret_registry);
    let secret_sink: PublishSecrets = Box::new(move |update| {
        let secret_registry = Arc::clone(&secret_registry);
        Box::pin(async move {
            match update {
                SecretUpdate::Upsert { name, secret } => match secret.tls_certificate_ir() {
                    Ok(Some(ir)) => secret_registry.publish(&name, vec![ir]),
                    Ok(None) => match secret.validation_context_ir() {
                        Ok(Some(validation)) => {
                            secret_registry.publish_validation_context(&name, validation)
                        }
                        Ok(None) => {
                            Err(format!("secret `{name}` has no supported SDS TLS payload"))
                        }
                        Err(err) => Err(err.to_string()),
                    },
                    Err(err) => Err(err.to_string()),
                },
                SecretUpdate::Remove { name } => secret_registry.remove(&name),
            }
        })
    });

    let initialization_sink: InitializationSink = Box::new(move |event| {
        let init_tx = init_tx.clone();
        Box::pin(async move {
            let _ = init_tx.send(event).await;
        })
    });
    let applier = ResourceApplier::new(Arc::clone(snapshot), publish)
        .with_endpoint_sink(endpoint_sink)
        .with_secret_sink(secret_sink)
        .with_initialization_sink(initialization_sink);

    let mut states = Vec::new();
    if matches!(ads.cds_source, Some(DiscoverySource::Ads)) {
        states.push(SubscriptionState::new(CDS_TYPE_URL, Subscription::Wildcard));
    }
    if matches!(ads.lds_source, Some(DiscoverySource::Ads)) {
        states.push(SubscriptionState::new(LDS_TYPE_URL, Subscription::Wildcard));
    }
    // RDS is by-name like EDS. Register it even when empty so an LDS response
    // can widen this subscription after it introduces an RDS listener.
    states.push(SubscriptionState::new(
        RDS_TYPE_URL,
        Subscription::Names(applier.rds_resource_names()),
    ));
    // Seeded from the applier's OWN view of the boot snapshot, not left to
    // populate itself after the first response arrives. `ResponseHandler::
    // desired_names` (which `client.rs`'s pump calls) is only consulted
    // AFTER a response, so without this seed a bootstrap that declares a
    // static EDS cluster against a control plane that serves only EDS (never
    // any CDS/LDS response to trigger a `desired_names` call) would never
    // send an initial EDS subscription at all and sit there forever. Built
    // as `Subscription::Names`, never `Subscription::Wildcard` -- EDS is a
    // by-name subscription (S8), and an empty name set renders identically
    // to a wildcard on the wire (`SubscriptionState::has_nothing_to_request`'s
    // own doc), which would ask for every EDS resource the control plane has
    // instead of none.
    states.push(SubscriptionState::new(
        EDS_TYPE_URL,
        Subscription::Names(applier.eds_resource_names()),
    ));
    // Seeded for the same reason as EDS above, plus one that is not about
    // subscribing at all: `client.rs`'s pump resolves an incoming response's
    // `type_url` against THIS list, and a response whose type_url is absent
    // returns `AdsError::UnknownTypeUrl`, which propagates out of the pump
    // and tears down the WHOLE ADS stream -- CDS and LDS with it, not just
    // the secret. So the state is pushed unconditionally, even when the boot
    // snapshot names no SDS secrets at all: an empty `Names` set sends no
    // initial request (`SubscriptionState::has_nothing_to_request`), but it
    // still makes an SDS response the proxy did not ask for a NACK instead of
    // a disconnect. `Names`, never `Wildcard` -- SDS is by-name like EDS (S8).
    states.push(SubscriptionState::new(
        SDS_TYPE_URL,
        Subscription::Names(applier.sds_resource_names()),
    ));

    let file_sources: Vec<_> = [
        (
            ads.lds_source.as_ref(),
            "type.googleapis.com/envoy.config.listener.v3.Listener",
        ),
        (
            ads.cds_source.as_ref(),
            "type.googleapis.com/envoy.config.cluster.v3.Cluster",
        ),
    ]
    .into_iter()
    .filter_map(|(source, type_url)| match source {
        Some(DiscoverySource::Filesystem(path)) => Some(FileSource::new(path.clone(), type_url)),
        _ => None,
    })
    .collect();
    let shared = SharedApplier::new(applier);
    if !file_sources.is_empty() {
        let file_handler = shared.clone();
        tokio::spawn(async move {
            let mut watchers: Vec<_> = file_sources.iter().map(FileSource::watcher).collect();
            loop {
                for (source, watcher) in file_sources.iter().zip(watchers.iter_mut()) {
                    match watcher.changed() {
                        Ok(true) => match source.load() {
                            Ok(response) => {
                                let verdict = file_handler.apply_sotw(response).await;
                                tracing::info!(?verdict, "filesystem xDS response applied");
                            }
                            Err(error) => {
                                tracing::error!(%error, "filesystem xDS response rejected; retaining last-good state")
                            }
                        },
                        Ok(false) => {}
                        Err(error) => {
                            tracing::warn!(%error, "filesystem xDS source unavailable; retaining last-good state")
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        });
    }

    match ads.protocol {
        AdsProtocol::Sotw => {
            let mut client = AdsClient::new(states).with_node(node.clone());
            let handler = shared.clone();
            tokio::spawn(async move {
                client
                    .run(&mut grpc_client, handler, Reconnect::real())
                    .await;
            });
        }
        AdsProtocol::Delta => {
            let delta_states = states
                .into_iter()
                .map(|state| {
                    DeltaSubscriptionState::new(
                        state.type_url(),
                        if state.has_nothing_to_request() {
                            Subscription::Names(Default::default())
                        } else if let Some(names) =
                            DeltaResponseHandler::desired_names(&shared, state.type_url())
                        {
                            Subscription::Names(names)
                        } else {
                            Subscription::Wildcard
                        },
                    )
                })
                .collect();
            let mut client = DeltaAdsClient::new(delta_states).with_node(node.clone());
            let handler = shared.clone();
            tokio::spawn(async move {
                client
                    .run(&mut grpc_client, handler, Reconnect::real())
                    .await;
            });
        }
    }

    Some((apply_rx, init_rx))
}

/// Polls `rx` if `Some`, otherwise never resolves. This is what lets
/// `run_serve`'s `tokio::select!` include the ADS-apply channel as one of its
/// arms even when no ADS client was ever started (`rx` is `None`) without
/// that arm spinning in a tight loop on an instantly-ready `None` -- an `mpsc`
/// receiver whose sender was simply never created still resolves `recv()` to
/// `None` immediately, same as one whose sender was dropped.
async fn recv_ads_apply(rx: &mut Option<mpsc::Receiver<AdsApplyMsg>>) -> Option<AdsApplyMsg> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
}

async fn recv_init_event(
    rx: &mut Option<mpsc::Receiver<InitializationEvent>>,
) -> Option<InitializationEvent> {
    match rx {
        Some(rx) => rx.recv().await,
        None => std::future::pending().await,
    }
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

/// Builds the `/ready` readiness probe `run_serve` wires
/// into [`start_admin`], which passes it straight through to
/// `proxy_admin::serve`. Checked in this order on every call:
///
/// 1. `lifecycle.out_of_rotation()` (SIGTERM, `POST /drain_listeners`, or
///    `/healthcheck/fail`) answers [`proxy_admin::Readiness::Draining`].
/// 2. No worker has bound a listener yet answers
///    [`proxy_admin::Readiness::Initializing`] with whatever is warming (maybe
///    nothing). There is deliberately no deadline here: a proxy that never
///    receives LDS has nothing to serve and must stay not-ready.
/// 3. Otherwise the warming rule below.
///
/// The warming rule reads [`proxy_cluster::manager::ClusterManager::warming_clusters`]
/// fresh on every call -- no caching, since the whole point is that warming
/// state can change between polls -- and reports [`proxy_admin::Readiness::Initializing`]
/// for as long as it is non-empty AND `deadline_started_at.elapsed()` is
/// under `timeout`; past the deadline it reports [`proxy_admin::Readiness::Live`]
/// instead.
///
/// **This only changes what `/ready` says -- it never calls
/// `ClusterManager::force_initialize` and never touches `is_initialized`.**
/// A cluster that never resolved stays un-initialized forever; the deadline
/// only stops that fact from gating readiness. The router refuses an
/// un-initialized cluster before host selection, which is what makes a request
/// to a still-warming cluster behave differently from one to a cluster whose
/// hosts are all ejected; it needs `is_initialized` to keep telling those two
/// states apart -- see this crate's [`run_serve`] doc for where `timeout`
/// itself is resolved (`AdsConfig::initial_fetch_timeout`, falling back to
/// [`proxy_cluster::discovery::DEFAULT_INITIAL_FETCH_TIMEOUT`]).
///
/// Logs once, at `warn!`, the first probe call that observes the deadline
/// has passed with clusters still warming, naming them -- never on every
/// call. `/ready` is polled by orchestrators on a tight loop; logging on
/// every poll would become the incident (AGENTS.md "Fail-open controls"'s "keep the
/// suppression off the healthy hot path" reasoning, applied to a warning
/// rather than a security control).
///
/// Rust note: `warned` is a plain `AtomicBool`, not `Arc<AtomicBool>` --
/// it is captured BY the closure (moved in), not shared with anything
/// outside it, so a bare value works: every call to the returned `Fn`
/// receives `&self` over the closure's own captures, which is enough shared
/// access for `AtomicBool`'s interior mutability. No `Arc` needed for
/// something with exactly one owner.
fn build_readiness_probe(
    cluster_manager: Arc<proxy_cluster::manager::ClusterManager>,
    timeout: Duration,
    deadline_started_at: Instant,
    lifecycle: Arc<LifecycleState>,
) -> proxy_admin::ReadinessProbe {
    let warned = AtomicBool::new(false);
    Arc::new(move || {
        if lifecycle.out_of_rotation() {
            return proxy_admin::Readiness::Draining;
        }
        let warming = cluster_manager.warming_clusters();
        if !lifecycle.listener_bound() {
            return proxy_admin::Readiness::Initializing { warming };
        }
        if warming.is_empty() {
            return proxy_admin::Readiness::Live;
        }
        if deadline_started_at.elapsed() < timeout {
            return proxy_admin::Readiness::Initializing { warming };
        }
        if !warned.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                clusters = ?warming,
                timeout_s = timeout.as_secs(),
                "cluster warming deadline (initial_fetch_timeout) expired with clusters still \
                 unresolved; /ready now reports LIVE for them, but ClusterManager::is_initialized \
                 stays false because the deadline only stops warming from gating readiness"
            );
        }
        proxy_admin::Readiness::Live
    })
}

/// Starts the read-only admin server when `admin` names a bind address. It
/// binds nothing and returns `Ok(None)` otherwise. The admin surface is opt-in.
///
/// The admin handle comes from the same [`SnapshotHandles`] registry that
/// `ConfigPublisher::publish` walks. That is what makes `/config_dump` and
/// `/clusters` follow a SIGHUP reload. A private handle outside the registry
/// would keep serving the boot snapshot.
///
/// A bind failure is returned as `Err`, so `run_serve` treats it as a startup
/// failure. `ADMIN_TOKEN_ENV_VAR` is read once here and passed to
/// `proxy_admin::serve` as a plain parameter.
struct AdminStartRuntime<'a> {
    snapshot: Arc<ConfigSnapshot>,
    registry: Arc<proxy_observability::stats::Registry>,
    started_at: Instant,
    snapshot_handles: &'a SnapshotHandles,
    factory_state: Arc<proxy_http::filter::SharedFactoryState>,
    readiness: Option<proxy_admin::ReadinessProbe>,
    cluster_state: Option<proxy_admin::ClusterStateProvider>,
    credential_probe: Option<Arc<dyn proxy_http::credential_probe::TenantCredentialProbe>>,
    lifecycle: Arc<LifecycleState>,
    ledger: Option<Arc<proxy_observability::ledger::Ledger>>,
    trace_gate: Option<Arc<proxy_observability::traces::gate::TraceGate>>,
}

async fn start_admin(
    admin: Option<SocketAddr>,
    runtime: AdminStartRuntime<'_>,
) -> Result<Option<proxy_admin::AdminServer>, String> {
    let Some(addr) = admin else {
        return Ok(None);
    };
    let tls = runtime.snapshot.admin_tls.is_some();
    let config = runtime.snapshot_handles.register(runtime.snapshot);
    let admin_token = std::env::var(ADMIN_TOKEN_ENV_VAR).ok();
    let token_set = admin_token
        .as_deref()
        .is_some_and(|token| !token.trim().is_empty());
    let ui = std::env::var(ADMIN_UI_DIR_ENV_VAR)
        .ok()
        .filter(|dir| !dir.trim().is_empty())
        .and_then(
            |dir| match proxy_admin::UiAssets::load_from_dir(std::path::Path::new(&dir)) {
                Ok(assets) => {
                    tracing::info!(dir = %dir, "admin UI loaded, serving under /ui");
                    Some(Arc::new(assets))
                }
                Err(err) => {
                    tracing::warn!(
                        dir = %dir,
                        error = %err,
                        "admin UI not loaded, /ui will 404; API surface unaffected"
                    );
                    None
                }
            },
        );
    let ui_loaded = ui.is_some();
    let server = proxy_admin::serve(
        addr,
        proxy_admin::AdminRuntime {
            config,
            registry: Some(runtime.registry),
            started_at: runtime.started_at,
            factory_state: runtime.factory_state,
            admin_token,
            readiness: runtime.readiness,
            cluster_state: runtime.cluster_state,
            ui,
            lifecycle: Some(runtime.lifecycle),
            credential_probe: runtime.credential_probe,
            ledger: runtime.ledger,
            trace_gate: runtime.trace_gate,
        },
    )
    .await
    .map_err(|err| err.to_string())?;
    let notes = admin_startup_notes(server.local_addr(), tls, ui_loaded, token_set);
    if let Some(info) = notes.ui {
        tracing::info!("{info}");
    }
    if let Some(warning) = notes.token {
        tracing::warn!("{warning}");
    }
    Ok(Some(server))
}

/// What the operator needs to hear about the admin server at startup: where the UI is, and whether its writes can
/// work. The admin gate already refuses every write with 403 when the token is unset; without this line a new user
/// first learns that from a failed click.
struct AdminStartupNotes {
    ui: Option<String>,
    token: Option<String>,
}

fn admin_startup_notes(
    addr: SocketAddr,
    tls: bool,
    ui_loaded: bool,
    token_set: bool,
) -> AdminStartupNotes {
    let scheme = if tls { "https" } else { "http" };
    let ui = if ui_loaded {
        Some(format!("admin UI: {scheme}://{addr}/ui/"))
    } else {
        Some(format!(
            "admin UI not loaded: set {ADMIN_UI_DIR_ENV_VAR} to the UI bundle (the release archive's admin-ui-dist) \
             to serve it at {scheme}://{addr}/ui/"
        ))
    };
    let token = (!token_set).then(|| {
        format!(
            "{ADMIN_TOKEN_ENV_VAR} is not set: admin writes (keys, tenants, budgets, pricing) and key and spend \
             reads are refused with 403, in the admin UI too"
        )
    });
    AdminStartupNotes { ui, token }
}

/// Each worker composes three concurrent seams over one shared
/// `ConnectionRegistry`: the listener manager (binds
/// sockets, accepts, matches filter chains), the drain routine (reports back
/// once the registry empties or the drain deadline passes), and a final wait
/// on the plain shutdown signal so the worker thread doesn't exit before the
/// control runtime calls `ConfigPublisher::shutdown`. At drain start the
/// listener manager closes the listening sockets and HTTP connections begin
/// their graceful shutdown; `shutdown` is also watched during the drain so a
/// fast exit does not wait for the deadline.
///
/// The very first thing this does is bind every listener in the initial
/// snapshot (`initial_bind`) and report the outcome over `bind_tx` --
/// `run_serve` blocks on every worker doing so before it starts waiting for
/// SIGTERM/SIGINT. A bind failure here is fatal (see `initial_bind`'s doc
/// comment), so this worker does nothing further but wait for the control
/// runtime's `shutdown` signal, which `run_serve` sends promptly once it
/// sees the failure.
// Rust note: a spawn entrypoint handed one worker every boot-resolved
// dependency it needs. It already sat at clippy's 7-arg ceiling;
// the optional `tracing_handles` (8th) tips it over. These are each a
// distinct per-worker handle with no shared identity to bundle under -- the
// three stat tables are already bundled for `reload` via `StatHandleTables`,
// and re-bundling them here purely to dodge the lint would fragment that one
// owner -- so this leaf allows the extra arg rather than inventing a bag type.
#[allow(clippy::too_many_arguments)]
async fn worker_main(
    ctx: WorkerContext,
    bind_tx: mpsc::UnboundedSender<(WorkerId, Result<(), String>)>,
    startup_gate: Arc<StartupGate>,
    lifecycle: Arc<LifecycleState>,
    cluster_manager: Arc<proxy_cluster::manager::ClusterManager>,
    stats_registry: Arc<proxy_observability::stats::Registry>,
    stat_handles: Arc<proxy_http::stat_handles::StatHandles>,
    downstream_stat_handles: Arc<proxy_http::stat_handles::DownstreamStatHandles>,
    token_usage_stat_handles: Arc<proxy_http::stat_handles::TokenUsageStatHandles>,
    tracing_handles: Option<proxy_core::listener::TracingHandles>,
    metadata_sink: Option<Arc<dyn proxy_observability::records::RequestRecordSink>>,
    ledger: Option<Arc<proxy_observability::ledger::Ledger>>,
    traces: Option<Arc<proxy_observability::traces::capture::TraceAdmission>>,
    // This worker's clone of the ONE per-serve
    // `SharedFactoryState` -- see `run_serve`'s own comment on the Arc this
    // is cloned from.
    factory_state: Arc<proxy_http::filter::SharedFactoryState>,
    // This worker's clone of the ONE per-serve
    // `SdsSecretRegistry` -- see `run_serve`'s own comment on the Arc this is
    // cloned from.
    secret_registry: Arc<SdsSecretRegistry>,
) {
    // A shutdown while the gate is still closed (SIGTERM during the initial
    // xDS fetch) ends the worker here, or joining it would hang.
    let mut shutdown = ctx.shutdown.clone();
    tokio::select! {
        () = startup_gate.wait() => {}
        _ = shutdown.wait_for(|stop| *stop) => return,
    }
    // The upstream pool's sweep closes idle connections to endpoints that
    // left their cluster, so a replaced DNS or EDS endpoint does not hold
    // `max_connections` slots until the idle timeout. The caches are
    // per-worker thread locals, so each worker installs its own oracle.
    {
        let cluster_manager = Arc::clone(&cluster_manager);
        proxy_http::upstream_pool::set_worker_membership(std::rc::Rc::new(
            move |cluster: &str, addr: std::net::SocketAddr| {
                cluster_manager.has_host(cluster, addr)
            },
        ));
    }
    let registry = ConnectionRegistry::new();
    // Built fresh per worker -- `stats_registry`/
    // `stat_handles` are the SAME shared, config-scoped state every worker
    // gets (plain `Arc` clones), but `WorkerId` is this worker's own, so
    // `RouterStats` (which bakes a `WorkerId` in at construction, see its
    // doc) can't be shared across workers the way `cluster_manager` is.
    //
    // Rust note: `proxy_core::runtime::WorkerId` and
    // `proxy_observability::stats::WorkerId` are deliberately two distinct
    // types (see the latter's doc comment for why reusing one would close a
    // dependency cycle) -- `.0` is the conversion at this boundary, exactly
    // where that comment says it belongs.
    let router_stats = Arc::new(proxy_http::stat_handles::RouterStats::new(
        stats_registry.clone(),
        stat_handles,
        proxy_observability::stats::WorkerId(ctx.id.0),
    ));
    // `DownstreamStats`'s counterpart to `router_stats`
    // above, same per-worker `WorkerId` and same shared `stats_registry` --
    // this is what `crate::listener::spawn_accept_loop` calls once per
    // accepted connection.
    let downstream_stats = Arc::new(proxy_http::stat_handles::DownstreamStats::new(
        stats_registry.clone(),
        downstream_stat_handles,
        proxy_observability::stats::WorkerId(ctx.id.0),
    ));
    // `GenAiTokenStats`'s counterpart to `router_stats`
    // above -- this is what `crate::listener::build_hcm_handler` wires into
    // every real `FilterChainHandler` it builds, via `.with_token_stats`.
    let token_stats = Arc::new(proxy_http::stat_handles::GenAiTokenStats::new(
        stats_registry.clone(),
        token_usage_stat_handles,
        proxy_observability::stats::WorkerId(ctx.id.0),
    ));
    let latency_stats = Arc::new(proxy_http::stat_handles::GenAiLatencyStats::new(
        stats_registry,
        proxy_observability::stats::WorkerId(ctx.id.0),
    ));

    let stats = proxy_core::listener::StatsRecorders {
        router: router_stats,
        downstream: downstream_stats,
        token: token_stats,
        latency: latency_stats,
        tracing: tracing_handles,
        metadata: metadata_sink,
        // One shared handle: admission is process-wide (ADR-0009 decision 5).
        ledger,
        traces,
        connection_limiter: ctx.connection_limiter.clone(),
    };

    let bound = match initial_bind(
        &ctx.config.load(),
        &ctx.config,
        &registry,
        &ctx.shutdown,
        &ctx.drain,
        &cluster_manager,
        &stats,
        &factory_state,
        &secret_registry,
    ) {
        Ok(bound) => {
            // `/ready` stays INITIALIZING until a socket is actually listening;
            // a worker whose snapshot has no bindable listener (yet) leaves it so.
            if !bound.is_empty() {
                lifecycle.mark_listener_bound();
            }
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
        ctx.drain.clone(),
        lifecycle,
        registry.clone(),
        cluster_manager.clone(),
        stats,
        factory_state,
        secret_registry,
    ));

    // `drain_worker` only returns once the registry empties or the drain
    // deadline passes, so shutdown must also be watched while it runs: a
    // second termination signal stops the workers mid-drain and must not wait
    // for the deadline.
    let mut shutdown = ctx.shutdown;
    tokio::select! {
        _ = drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry) => {
            let _ = shutdown.changed().await;
        }
        _ = shutdown.changed() => {}
    }

    // `run_listener_manager` also watches `shutdown` and aborts its accept
    // loops on the same signal; wait for it so the thread doesn't tear down
    // mid-abort.
    let _ = listener_manager.await;
}

/// SIGUSR1: reopen every access-log file and the request-records file at
/// their configured paths, as Envoy reopens its access logs on SIGUSR1, so
/// logrotate's `postrotate kill -USR1` works. Lines queued before the signal
/// still go to the old file. The records file reopens before its next record.
async fn reopen_logs(records: Option<&proxy_observability::metadata::ReopenHandle>) {
    if let Some(records) = records {
        records.request();
    }
    // Bounded, so a destination stuck in a kernel write cannot hold the
    // signal loop for longer than this.
    let budget = Duration::from_secs(5);
    match tokio::task::spawn_blocking(move || proxy_observability::sink::reopen_all_queued(budget))
        .await
    {
        Ok((reopened, failed)) => {
            for (destination, error) in &failed {
                tracing::error!(
                    %destination,
                    %error,
                    "SIGUSR1: cannot reopen access log; lines keep going to the file already open"
                );
            }
            tracing::info!(
                access_logs_reopened = reopened,
                access_logs_failed = failed.len(),
                request_records = records.is_some(),
                "SIGUSR1: reopened log files"
            );
        }
        Err(err) => tracing::error!(error = %err, "SIGUSR1: the log reopen task failed"),
    }
}

/// How far startup got before the signal loop.
enum Startup {
    /// Startup finished; the signal loop runs.
    Running,
    /// SIGTERM or SIGINT while workers waited at the startup gate: no
    /// listener was bound.
    StoppedBeforeBind,
    /// SIGTERM or SIGINT while workers bound their listeners: some may serve,
    /// so they drain.
    StoppedDuringBind,
}

/// What [`ControlSignals::recv`] resolved on -- either begin the drain
/// sequence, or run a config reload and keep serving.
enum ControlSignal {
    /// SIGTERM or SIGINT.
    Shutdown,
    /// SIGHUP: see [`reload`].
    Reload,
    /// SIGUSR1: see [`reopen_logs`].
    ReopenLogs,
}

/// SIGTERM, SIGINT, SIGHUP, and SIGUSR1, with their handlers already
/// **installed**.
///
/// The distinction that matters: `tokio::signal::unix::signal()` registers the
/// handler with the OS when it is *called*, not when the returned stream is
/// first polled. Installing all three up front — before we announce readiness
/// and before the initial-bind gate — is what makes the announcement true. If
/// the handler were installed only at the point we start awaiting it (as this
/// used to do, for SIGTERM/SIGINT, before SIGHUP existed here), any signal
/// arriving between "started" and that await would be handled by the
/// **default disposition**: for SIGTERM/SIGINT that's immediate termination by
/// signal, no drain, live connections dropped; for SIGHUP it's process
/// termination too (SIGHUP's default disposition is "terminate", not
/// "ignore" — the opposite of what a reload trigger wants). That window is
/// small but entirely real — an orchestrator terminating a pod during a fast
/// rollout or a scale-down race lands squarely in it.
///
/// Rust note: SIGINT is taken as a `Signal` stream rather than via
/// `tokio::signal::ctrl_c()` for exactly the same reason — `ctrl_c()` is a
/// future that installs its handler on first poll, which would reintroduce the
/// gap for SIGINT alone.
struct ControlSignals {
    sigterm: tokio::signal::unix::Signal,
    sigint: tokio::signal::unix::Signal,
    sighup: tokio::signal::unix::Signal,
    sigusr1: tokio::signal::unix::Signal,
}

impl ControlSignals {
    /// Installs every handler. Failing to install one is a startup
    /// failure, not something to discover at shutdown/reload time. SIGUSR1's
    /// default disposition also terminates, so logrotate's
    /// `postrotate kill -USR1` would otherwise kill the proxy.
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            sigterm: signal(SignalKind::terminate())?,
            sigint: signal(SignalKind::interrupt())?,
            sighup: signal(SignalKind::hangup())?,
            sigusr1: signal(SignalKind::user_defined1())?,
        })
    }

    /// Resolves on the first signal, and says which kind it was so the
    /// caller's loop can tell a reload from a shutdown.
    async fn recv(&mut self) -> ControlSignal {
        tokio::select! {
            _ = self.sigterm.recv() => ControlSignal::Shutdown,
            _ = self.sigint.recv() => ControlSignal::Shutdown,
            _ = self.sighup.recv() => ControlSignal::Reload,
            _ = self.sigusr1.recv() => ControlSignal::ReopenLogs,
        }
    }

    /// As [`Self::recv`], but SIGHUP stays pending: a reload asked for while
    /// the proxy starts runs once the signal loop is up, as it did before
    /// startup listened for signals.
    async fn recv_during_startup(&mut self) -> ControlSignal {
        tokio::select! {
            _ = self.sigterm.recv() => ControlSignal::Shutdown,
            _ = self.sigint.recv() => ControlSignal::Shutdown,
            _ = self.sigusr1.recv() => ControlSignal::ReopenLogs,
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

    #[test]
    fn admin_startup_notes_name_the_ui_and_warn_only_without_a_token() {
        let addr: SocketAddr = "127.0.0.1:53422".parse().unwrap();

        let ready = admin_startup_notes(
            addr, /* tls */ false, /* ui_loaded */ true, /* token_set */ true,
        );
        assert_eq!(
            ready.ui.as_deref(),
            Some("admin UI: http://127.0.0.1:53422/ui/")
        );
        assert!(ready.token.is_none(), "a set token must not warn");
        let tls = admin_startup_notes(
            addr, /* tls */ true, /* ui_loaded */ true, /* token_set */ true,
        );
        assert_eq!(
            tls.ui.as_deref(),
            Some("admin UI: https://127.0.0.1:53422/ui/"),
            "a TLS admin port must not be advertised as http"
        );

        let bare = admin_startup_notes(
            addr, /* tls */ false, /* ui_loaded */ false, /* token_set */ false,
        );
        let ui = bare.ui.expect("an unloaded UI says how to load it");
        assert!(
            ui.contains(ADMIN_UI_DIR_ENV_VAR) && ui.contains("admin-ui-dist"),
            "{ui}"
        );
        let warning = bare.token.expect("an unset token warns");
        assert!(
            warning.contains(ADMIN_TOKEN_ENV_VAR) && warning.contains("403"),
            "{warning}"
        );
    }

    fn empty_snapshot() -> Arc<ConfigSnapshot> {
        Arc::new(ConfigSnapshot::default())
    }

    fn test_registry() -> Arc<proxy_observability::stats::Registry> {
        proxy_observability::stats::StatsControl::new(1).registry()
    }

    #[test]
    fn init_manager_waits_for_required_resources() {
        let mut manager = InitManager {
            cds_required: true,
            lds_required: true,
            cds_received: false,
            lds_received: false,
            required_eds: ["cluster-endpoints".to_string()].into_iter().collect(),
            received_eds: Default::default(),
            required_rds: ["routes".to_string()].into_iter().collect(),
            received_rds: Default::default(),
        };

        assert!(!manager.ready());
        manager.accept(InitializationEvent {
            accepted_type_url: CDS_TYPE_URL.to_string(),
            cds_required: true,
            lds_required: true,
            required_eds: ["cluster-endpoints".to_string()].into_iter().collect(),
            received_eds: ["cluster-endpoints".to_string()].into_iter().collect(),
            required_rds: ["routes".to_string()].into_iter().collect(),
            received_rds: Default::default(),
        });
        assert!(!manager.ready(), "LDS and RDS still have to arrive");

        manager.accept(InitializationEvent {
            accepted_type_url: LDS_TYPE_URL.to_string(),
            cds_required: true,
            lds_required: true,
            required_eds: ["cluster-endpoints".to_string()].into_iter().collect(),
            received_eds: ["cluster-endpoints".to_string()].into_iter().collect(),
            required_rds: ["routes".to_string()].into_iter().collect(),
            received_rds: ["routes".to_string()].into_iter().collect(),
        });
        assert!(manager.ready());
    }

    #[test]
    fn init_manager_empty_bootstrap_is_ready() {
        assert!(InitManager::new(&ConfigSnapshot::default()).ready());
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

        let result = start_admin(
            None,
            AdminStartRuntime {
                snapshot: empty_snapshot(),
                registry: test_registry(),
                started_at: Instant::now(),
                snapshot_handles: &SnapshotHandles::new(),
                factory_state: Arc::new(proxy_http::filter::SharedFactoryState::default()),
                readiness: None,
                cluster_state: None,
                credential_probe: None,
                lifecycle: Arc::new(LifecycleState::new()),
                ledger: None,
                trace_gate: None,
            },
        )
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
        let server = start_admin(
            Some(addr),
            AdminStartRuntime {
                snapshot: empty_snapshot(),
                registry: test_registry(),
                started_at: Instant::now(),
                snapshot_handles: &SnapshotHandles::new(),
                factory_state: Arc::new(proxy_http::filter::SharedFactoryState::default()),
                readiness: None,
                cluster_state: None,
                credential_probe: None,
                lifecycle: Arc::new(LifecycleState::new()),
                ledger: None,
                trace_gate: None,
            },
        )
        .await
        .expect("start_admin should succeed on an available port")
        .expect("admin: Some(_) must start a server");

        let bound = server.local_addr();
        tokio::net::TcpStream::connect(bound)
            .await
            .expect("the admin port should be connectable once start_admin has bound it");
    }

    /// Defect 1's regression guard, one level up from `runtime.rs`'s own
    /// `publish_updates_a_handle_registered_outside_spawn`: `start_admin`
    /// itself must obtain its handle through `SnapshotHandles::register`
    /// (not build one directly), so a snapshot published later into the same
    /// registry reaches the admin server too. Exercised via the registry
    /// directly rather than a real reload, since `run_serve`'s SIGHUP path is
    /// what `tests/reload.rs` already drives end to end against the real
    /// binary.
    #[tokio::test]
    async fn start_admin_registers_its_handle_into_the_shared_registry() {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let snapshot_handles = SnapshotHandles::new();
        let server = start_admin(
            Some(addr),
            AdminStartRuntime {
                snapshot: empty_snapshot(),
                registry: test_registry(),
                started_at: Instant::now(),
                snapshot_handles: &snapshot_handles,
                factory_state: Arc::new(proxy_http::filter::SharedFactoryState::default()),
                readiness: None,
                cluster_state: None,
                credential_probe: None,
                lifecycle: Arc::new(LifecycleState::new()),
                ledger: None,
                trace_gate: None,
            },
        )
        .await
        .expect("start_admin should succeed on an available port")
        .expect("admin: Some(_) must start a server");

        // A snapshot with a distinct version, published straight through the
        // registry `start_admin` was handed -- exactly what
        // `ConfigPublisher::publish` does on a real SIGHUP -- must be visible
        // over the admin server's own HTTP surface afterward.
        let updated = Arc::new(ConfigSnapshot {
            version: SnapshotVersion(7),
            ..ConfigSnapshot::default()
        });
        snapshot_handles.store_all(&updated);

        let mut stream = tokio::net::TcpStream::connect(server.local_addr())
            .await
            .expect("connect to admin server");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream
            .write_all(b"GET /config_dump HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
            .await
            .expect("write request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read response to EOF");
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.contains("\"version\":7"),
            "expected /config_dump to reflect the snapshot published through the shared \
             registry, got:\n{response}"
        );
    }

    /// A `ClusterManager` carrying one cluster that has never resolved --
    /// what every [`build_readiness_probe`] test below drives against,
    /// avoiding any real DNS/EDS traffic. An EDS cluster is the shape that
    /// stays unresolved for free: `resolve_cluster` short-circuits on
    /// `DiscoveryType::Eds` (membership arrives through
    /// `ClusterManager::accept_eds_update`, which this never calls), so the
    /// cluster is registered and `is_initialized` stays false with no I/O.
    async fn manager_with_one_never_fed_cluster() -> Arc<proxy_cluster::manager::ClusterManager> {
        let manager = proxy_cluster::manager::ClusterManager::with_default_transport(Arc::new(
            proxy_cluster::resolver::TokioResolver,
        ));
        let mut snapshot = HashMap::new();
        snapshot.insert(
            "never-fed".to_string(),
            Arc::new(proxy_config::ir::ClusterConfig {
                name: "never-fed".to_string(),
                discovery: proxy_config::ir::DiscoveryType::Eds,
                eds: Some(proxy_config::ir::EdsClusterConfig {
                    service_name: "never-fed".to_string(),
                }),
                lb_policy: proxy_config::ir::LbPolicy::RoundRobin,
                connect_timeout: Duration::from_secs(5),
                endpoints: Vec::new(),
                kind: proxy_config::ir::ClusterKind::Endpoints,
                transport_socket: None,
                per_connection_buffer_limit_bytes: 1 << 20,
                circuit_breakers: Default::default(),
                upstream_protocol: proxy_config::ir::UpstreamProtocol::Http1,
                request_headers_to_add: Vec::new(),
                request_path_rewrite: None,
                provider_runtime: None,
                usage_dialect: None,
                health_check: None,
                outlier_detection: None,
            }),
        );
        manager.update_from_snapshot(&snapshot).await;
        Arc::new(manager)
    }

    #[test]
    fn the_live_scope_restricts_clusters_and_listeners_but_not_tenants_or_models() {
        let scope = live_scope_for(&ConfigSnapshot::default());
        assert_eq!(scope.clusters, Some(Default::default()));
        assert_eq!(scope.listeners, Some(Default::default()));
        assert_eq!(scope.tenants, None);
        assert_eq!(scope.models, None);
    }

    fn bound_lifecycle() -> Arc<LifecycleState> {
        let lifecycle = Arc::new(LifecycleState::new());
        lifecycle.mark_listener_bound();
        lifecycle
    }

    /// A cluster manager with nothing warming: isolates the lifecycle checks
    /// from the warming rule.
    fn idle_manager() -> Arc<proxy_cluster::manager::ClusterManager> {
        Arc::new(
            proxy_cluster::manager::ClusterManager::with_default_transport(Arc::new(
                proxy_cluster::resolver::TokioResolver,
            )),
        )
    }

    /// M6: with no cluster warming at all, `/ready` still must not be LIVE
    /// until a worker has bound a listener, and a backdated deadline must not
    /// release it (a proxy that never receives LDS has nothing to serve).
    #[test]
    fn readiness_probe_is_initializing_until_a_listener_is_bound() {
        let lifecycle = Arc::new(LifecycleState::new());
        let probe = build_readiness_probe(
            idle_manager(),
            Duration::from_secs(1),
            Instant::now() - Duration::from_secs(60),
            lifecycle.clone(),
        );
        assert_eq!(
            probe(),
            proxy_admin::Readiness::Initializing { warming: vec![] }
        );
        lifecycle.mark_listener_bound();
        assert_eq!(probe(), proxy_admin::Readiness::Live);
    }

    /// Drain and a failed health check win over every other state, including
    /// warming clusters and a bound listener; `/healthcheck/ok` restores
    /// readiness but a drain never reverses.
    #[test]
    fn readiness_probe_reports_draining_before_anything_else() {
        let lifecycle = bound_lifecycle();
        let probe = build_readiness_probe(
            idle_manager(),
            Duration::from_secs(60),
            Instant::now(),
            lifecycle.clone(),
        );
        assert_eq!(probe(), proxy_admin::Readiness::Live);
        lifecycle.fail_health_check();
        assert_eq!(probe(), proxy_admin::Readiness::Draining);
        lifecycle.restore_health_check();
        assert_eq!(probe(), proxy_admin::Readiness::Live);
        lifecycle.request_drain();
        lifecycle.restore_health_check();
        assert_eq!(probe(), proxy_admin::Readiness::Draining);

        // Draining also beats "no listener bound yet".
        let unbound = Arc::new(LifecycleState::new());
        unbound.request_drain();
        let probe = build_readiness_probe(
            idle_manager(),
            Duration::from_secs(60),
            Instant::now(),
            unbound,
        );
        assert_eq!(probe(), proxy_admin::Readiness::Draining);
    }

    // ---- The readiness probe's deadline -----------------
    //
    // Both tests drive `build_readiness_probe` directly (per the task's own
    // acceptance note) rather than sleeping past a real timeout -- the
    // deadline is just `Instant` subtraction, so backdating
    // `deadline_started_at` proves the "past the deadline" branch
    // deterministically and instantly.

    #[tokio::test]
    async fn readiness_probe_reports_initializing_before_the_deadline() {
        let manager = manager_with_one_never_fed_cluster().await;
        let probe = build_readiness_probe(
            manager.clone(),
            Duration::from_secs(60),
            Instant::now(),
            bound_lifecycle(),
        );
        match probe() {
            proxy_admin::Readiness::Initializing { warming } => {
                assert_eq!(warming, vec!["never-fed".to_string()]);
            }
            other => panic!("expected Initializing before the deadline, got {other:?}"),
        }
        assert!(!manager.is_initialized("never-fed"));
    }

    /// The important assertion, per the task: past the deadline `/ready`
    /// reports `Live` for a cluster that never resolved, but
    /// `ClusterManager::is_initialized` stays `false` for it -- the deadline
    /// gates readiness, it does not call `force_initialize`. This is what
    /// stops someone "simplifying" `build_readiness_probe` into a
    /// `force_initialize` call later: that change would still make this
    /// test pass on `Readiness::Live` but fail on `is_initialized`.
    #[tokio::test]
    async fn readiness_probe_reports_live_past_the_deadline_but_leaves_is_initialized_false() {
        let manager = manager_with_one_never_fed_cluster().await;
        // Backdated, not slept-past: the deadline already elapsed before the
        // first call.
        let deadline_started_at = Instant::now() - Duration::from_secs(60);
        let probe = build_readiness_probe(
            manager.clone(),
            Duration::from_secs(1),
            deadline_started_at,
            bound_lifecycle(),
        );

        assert_eq!(probe(), proxy_admin::Readiness::Live);
        assert!(
            !manager.is_initialized("never-fed"),
            "the warming deadline must gate /ready only -- it must never mark a cluster \
             initialized (the router's request-time `is_initialized` check depends on that)"
        );
    }

    // ---- ConfigSource: front-end pinning (requirement 2) ------------------
    //
    // These are unit tests against the private `ConfigSource`/`Args` types
    // rather than a spawned-binary integration test -- the property under
    // test ("a `-c` process can only ever reload via the bootstrap loader,
    // a `--config` one only via the dialect loader") is a fact about which
    // Rust code path runs, which a `match` arm proves directly and a log
    // scrape over a real process could only prove indirectly. The SIGHUP
    // *end-to-end* behavior (a reload actually taking effect, a broken one
    // not taking the process down) is `tests/reload.rs`, which does spawn
    // the real binary.

    /// Builds an `Args` with every field beyond the three under test set to
    /// its CLI default, so a new required field added to `Args` later fails
    /// this to compile rather than silently getting an arbitrary value.
    fn test_args(config_path: Option<PathBuf>, config: Option<PathBuf>, permissive: bool) -> Args {
        Args {
            command: None,
            config_path,
            config,
            mode: Mode::Serve,
            tenant: None,
            key_id: "REPLACE_ME".to_string(),
            hmac_secret_file: None,
            reveal_secrets: false,
            permissive,
            concurrency: 1,
            request_records_file: None,
            request_record_max_attempts: None,
            drain_time_s: proxy_core::drain::DEFAULT_DRAIN_TIME.as_secs(),
            drain_strategy: DrainStrategyArg::Immediate,
            base_id: None,
            log_level: LogLevel::Info,
            service_node: None,
            service_cluster: None,
        }
    }

    #[test]
    fn drain_strategy_defaults_to_immediate_and_maps_gradual() {
        let default = Args::try_parse_from(["llm-proxy", "-c", "x.yaml"]).expect("parses");
        assert_eq!(
            proxy_core::drain::DrainStrategy::from(default.drain_strategy),
            proxy_core::drain::DrainStrategy::Immediate
        );

        let gradual =
            Args::try_parse_from(["llm-proxy", "-c", "x.yaml", "--drain-strategy", "gradual"])
                .expect("parses");
        assert_eq!(
            proxy_core::drain::DrainStrategy::from(gradual.drain_strategy),
            proxy_core::drain::DrainStrategy::Gradual
        );
    }

    #[test]
    fn config_source_from_args_picks_bootstrap_for_dash_c() {
        let path = PathBuf::from("/tmp/whatever-bootstrap.yaml");
        let args = test_args(Some(path.clone()), None, false);
        match ConfigSource::from_args(&args) {
            ConfigSource::Bootstrap {
                path: got,
                strict: StrictMode::Strict,
            } => assert_eq!(got, path),
            other => {
                panic!("-c must produce ConfigSource::Bootstrap{{strict: Strict}}, not {other:?}")
            }
        }
    }

    #[test]
    fn config_source_from_args_carries_permissive_through_to_strict_mode() {
        let args = test_args(Some(PathBuf::from("/tmp/whatever.yaml")), None, true);
        match ConfigSource::from_args(&args) {
            ConfigSource::Bootstrap {
                strict: StrictMode::Permissive,
                ..
            } => {}
            other => {
                panic!("--permissive must carry through as StrictMode::Permissive, not {other:?}")
            }
        }
    }

    #[test]
    fn config_source_from_args_picks_dialect_for_dash_dash_config() {
        let path = PathBuf::from("/tmp/whatever-dialect.yaml");
        let args = test_args(None, Some(path.clone()), false);
        match ConfigSource::from_args(&args) {
            ConfigSource::Dialect { path: got } => assert_eq!(got, path),
            other => panic!("--config must produce ConfigSource::Dialect, not {other:?}"),
        }
    }

    const BOOTSTRAP_ONE_LISTENER_YAML: &str = r#"
static_resources:
  listeners:
    - name: ingress_tcp
      address:
        socket_address: { address: 127.0.0.1, port_value: 19999 }
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: ingress_tcp
                cluster: backend
  clusters:
    - name: backend
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: 127.0.0.1, port_value: 8081 }
"#;

    const DIALECT_ONE_ROUTE_YAML: &str = r#"
version: 0
listen: 127.0.0.1:19999
providers:
  local-vllm:
    base_url: http://127.0.0.1:8081
routes:
  - model: "*"
    provider: local-vllm
"#;

    /// Rust note: `write` + `remove_file` here (no shared "with a temp file"
    /// helper) matches the rest of this crate's tests
    /// (`crates/proxy/tests/*.rs`) -- each writes and cleans up its own,
    /// since there's no `tempfile` dependency in this crate.
    fn write_temp(name_hint: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "llm-proxy-configsource-test-{name_hint}-{}-{}.yaml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, contents).expect("failed to write temp config");
        path
    }

    #[test]
    fn config_source_load_bootstrap_reflects_the_file_on_disk() {
        let path = write_temp("bootstrap-ok", BOOTSTRAP_ONE_LISTENER_YAML);
        let source = ConfigSource::Bootstrap {
            path: path.clone(),
            strict: StrictMode::Strict,
        };
        let snapshot = source.load().expect("a valid bootstrap file must load");
        assert_eq!(snapshot.listeners.len(), 1);
        assert_eq!(snapshot.clusters.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_source_load_dialect_reflects_the_file_on_disk() {
        let path = write_temp("dialect-ok", DIALECT_ONE_ROUTE_YAML);
        let source = ConfigSource::Dialect { path: path.clone() };
        let snapshot = source.load().expect("a valid dialect file must load");
        assert_eq!(snapshot.listeners.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_source_load_reports_a_parse_error_without_panicking() {
        // Requirement 1's other half, at the unit level: `ConfigSource::load`
        // must return `Err`, never panic, on a config that fails to parse --
        // `reload`'s caller depends on this to keep the old snapshot.
        let path = write_temp("bootstrap-broken", "not: valid: yaml: [");
        let source = ConfigSource::Bootstrap {
            path: path.clone(),
            strict: StrictMode::Strict,
        };
        let err = source
            .load()
            .expect_err("malformed YAML must be an Err, not a panic or a lossy Ok");
        assert!(!err.is_empty(), "error message should not be empty");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn config_source_load_dialect_is_never_confused_with_bootstrap() {
        // Requirement 2, at the unit level: pointing the BOOTSTRAP loader at
        // a dialect file (or vice versa) must fail cleanly, not silently
        // half-parse -- this is what makes "impossible by construction" an
        // actual guarantee rather than a description of the happy path.
        let path = write_temp("dialect-via-bootstrap", DIALECT_ONE_ROUTE_YAML);
        let source = ConfigSource::Bootstrap {
            path: path.clone(),
            strict: StrictMode::Strict,
        };
        assert!(
            source.load().is_err(),
            "a dialect file loaded through the Bootstrap front-end must not succeed"
        );
        let _ = std::fs::remove_file(&path);
    }

    // ---- effective_node: --service-node/--service-cluster overrides -------
    //
    // These two flags feed the effective node id. Covered here as unit tests
    // against the pure function rather than a spawned-process test, same
    // reasoning as `ConfigSource`'s tests above.

    fn node(id: &str, cluster: &str) -> NodeIdentity {
        NodeIdentity {
            id: id.to_string(),
            cluster: cluster.to_string(),
        }
    }

    #[test]
    fn effective_node_with_neither_override_keeps_bootstrap() {
        let bootstrap = node("bootstrap-id", "bootstrap-cluster");
        assert_eq!(effective_node(&bootstrap, None, None), bootstrap);
    }

    #[test]
    fn effective_node_service_node_alone_overrides_only_id() {
        let bootstrap = node("bootstrap-id", "bootstrap-cluster");
        assert_eq!(
            effective_node(&bootstrap, Some("cli-id"), None),
            node("cli-id", "bootstrap-cluster")
        );
    }

    #[test]
    fn effective_node_service_cluster_alone_overrides_only_cluster() {
        let bootstrap = node("bootstrap-id", "bootstrap-cluster");
        assert_eq!(
            effective_node(&bootstrap, None, Some("cli-cluster")),
            node("bootstrap-id", "cli-cluster")
        );
    }

    #[test]
    fn effective_node_both_overrides_replace_both_fields() {
        let bootstrap = node("bootstrap-id", "bootstrap-cluster");
        assert_eq!(
            effective_node(&bootstrap, Some("cli-id"), Some("cli-cluster")),
            node("cli-id", "cli-cluster")
        );
    }

    #[test]
    fn effective_node_explicitly_empty_override_still_overrides() {
        // `Some("")` -- the flag was passed with an empty value -- must
        // still replace the bootstrap value: presence of the flag is the
        // signal, not whether its content is non-empty (see
        // `effective_node`'s own doc comment for why).
        let bootstrap = node("bootstrap-id", "bootstrap-cluster");
        assert_eq!(
            effective_node(&bootstrap, Some(""), None),
            node("", "bootstrap-cluster")
        );
    }

    // ---- ADR-0006 §2: node id reaches
    // `SharedFactoryState` ---------------------------------------------------
    //
    // Mirrors `run_serve`'s own three-step pipeline (bootstrap node id ->
    // `effective_node` -> `SharedFactoryState::for_node`) at unit-test
    // granularity, rather than booting a whole serve to prove it -- see
    // `effective_node`'s tests above for the same reasoning, and the
    // `AGENTS.md "Running The Product"` rule against a test binding a port.

    #[test]
    fn service_node_override_reaches_shared_factory_state() {
        let bootstrap = node("bootstrap-id", "bootstrap-cluster");
        let effective = effective_node(&bootstrap, Some("cli-id"), None);
        let state = proxy_http::filter::SharedFactoryState::for_node(effective.id.clone());
        assert_eq!(state.node_id(), "cli-id");
    }

    #[test]
    fn bootstrap_node_id_reaches_shared_factory_state_with_no_override() {
        let bootstrap = node("bootstrap-id", "bootstrap-cluster");
        let effective = effective_node(&bootstrap, None, None);
        let state = proxy_http::filter::SharedFactoryState::for_node(effective.id.clone());
        assert_eq!(state.node_id(), "bootstrap-id");
    }
}
