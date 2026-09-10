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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_config::ir::{NodeIdentity, SnapshotVersion};
use proxy_config::{
    build_snapshot, load_bootstrap_file, ConfigSnapshot, LoadedBootstrap, StrictMode,
};
use proxy_core::drain::{
    drain_worker, graceful_shutdown, ConnectionRegistry, DrainStrategy as CoreDrainStrategy,
};
use proxy_core::listener::{initial_bind, run_listener_manager};
use proxy_core::runtime::{SnapshotHandles, WorkerContext, WorkerId, WorkerPool, WorkerPoolConfig};
use proxy_core::tls::SdsSecretRegistry;
use proxy_xds::{
    AdsClient, DynamicSecret, Publish, PublishEndpoints, PublishSecrets, Reconnect,
    ResourceApplier, Subscription, SubscriptionState,
};
use tokio::sync::{mpsc, oneshot};
use tonic::transport::Channel;

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
    /// Path to a bootstrap configuration (.yaml / .yml / .json / .pb).
    /// Required for `serve`/`validate`/`translate`; unused by `keygen`.
    #[arg(short = 'c', long = "config-path", value_name = "PATH")]
    config_path: Option<PathBuf>,

    /// Path to a simple llm-proxy config (schema/llmproxy-v0.schema.json).
    /// Required for `serve`/`validate`/`translate`; unused by `keygen`.
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

    /// Warn on unknown fields in the bootstrap configuration instead of
    /// failing (default: strict). Has no effect on `--config` files, which
    /// are always strict.
    #[arg(long)]
    permissive: bool,

    /// Number of worker runtimes (serve mode only); default is the number
    /// of available cores.
    #[arg(long, value_name = "N", default_value_t = default_concurrency())]
    concurrency: usize,

    /// How long the drain sequence waits for connections to close before
    /// forcing worker shutdown (serve mode only).
    #[arg(
        long = "drain-time-s",
        value_name = "SECS",
        default_value_t = proxy_core::drain::DEFAULT_DRAIN_TIME.as_secs()
    )]
    drain_time_s: u64,

    /// How aggressively in-flight requests are encouraged to close during a
    /// drain.
    #[arg(long = "drain-strategy", value_enum, default_value_t = DrainStrategyArg::Gradual)]
    drain_strategy: DrainStrategyArg,

    /// Hot-restart base id. Accepted for CLI compatibility only: we have no
    /// hot-restart implementation, so this is parsed and ignored.
    #[arg(long = "base-id", value_name = "N")]
    base_id: Option<u32>,

    /// Log verbosity; `critical` is mapped to `error` (we don't distinguish
    /// the two).
    #[arg(short = 'l', long = "log-level", value_enum, default_value_t = LogLevel::Info)]
    log_level: LogLevel,

    /// Identifies this instance to an xDS control plane. Accepted but not
    /// yet used: dynamic configuration is not implemented.
    #[arg(long = "service-node", value_name = "NAME")]
    service_node: Option<String>,

    /// Identifies this instance's cluster to an xDS control plane. Accepted
    /// but not yet used: dynamic configuration is not implemented.
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
    /// Generates a fresh virtual key and its digest for downstream
    /// authentication. The one mode that touches no config at all.
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

/// Which config front-end (`-c`/`--config-path` Envoy bootstrap, or
/// `--config` dialect) and file `serve` was started with -- captured once,
/// right after argument parsing, and threaded down into the SIGHUP reload
/// path (see [`reload`]) instead of a reload re-deriving it from `Args`
/// itself.
///
/// This is what makes "a reload goes through the SAME front-end it booted
/// with" true by construction rather than by care: a `Bootstrap`-sourced
/// process can only ever call `load_bootstrap_file` again on SIGHUP, and a
/// `Dialect`-sourced one can only ever call `load_simple_config_file` again
/// -- there is no code path that lets one call into the other's loader,
/// unlike re-inspecting `Args` on every reload, which would silently start
/// working from whatever `Args` happens to hold this time.
#[derive(Debug)]
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

    /// Re-parses and re-lowers this source's file from scratch: the exact
    /// same library calls `load`/`build_snapshot` make at boot, minus
    /// `load`'s two CLI-only conveniences (the cross-mode hint text and
    /// `--mode translate`'s stdout side effect) -- a SIGHUP reload has
    /// neither a terminal to hint at nor a reason to print an Envoy YAML
    /// translation. Warnings are logged via `tracing` rather than
    /// `eprintln!`, since this runs from the serve-mode signal loop, not the
    /// startup path.
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
    let strategy: CoreDrainStrategy = args.drain_strategy.into();

    // `DrainState::drain_close_probability` (proxy-core's `drain.rs`) is the
    // seam a per-response close decision was BUILT to consult, but nothing
    // calls it: the drain sequence (`graceful_shutdown`) only ever waits for
    // the connection registry to empty or the drain deadline to pass, then
    // flips the plain shutdown signal hyper's `graceful_shutdown()` reacts
    // to. Neither step reads `strategy` at all, so `gradual` and `immediate`
    // are byte-identical today. The CLI flag policy
    // (`internal-docs/envoy-divergences.md`) requires that to be loud rather than
    // silently accepted -- wiring it properly means teaching the HTTP codecs
    // (`proxy-http`) to consult a per-response close probability, which is
    // its own work package, not a one-line fix here.
    tracing::warn!(
        drain_strategy = ?strategy,
        "--drain-strategy is accepted but not enforced during drain: connections are not \
         proactively closed until the drain deadline passes or every connection ends on its \
         own, regardless of `gradual` vs `immediate` (see internal-docs/envoy-divergences.md, \
         \"Drain strategy\")"
    );

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
        config_source,
    ))
}

/// How long `run_serve` waits for every worker to report its initial listener
/// bind outcome before giving up and treating startup as failed. Generous:
/// binding a handful of sockets should take microseconds, but a heavily
/// loaded CI box scheduling `concurrency` OS threads is not something to cut
/// close.
const INITIAL_BIND_TIMEOUT: Duration = Duration::from_secs(10);

/// WP-51 increment 3a: how many finished spans [`proxy_observability::trace::SpanSink`]
/// buffers between the exporter's batches before [`proxy_observability::trace::SpanSink::emit`]
/// starts dropping. Generous relative to `otlp::MAX_BATCH` (512) -- several
/// batches' worth of headroom for a slow or momentarily unreachable
/// collector, without holding an unbounded amount of memory.
const SPAN_SINK_CAPACITY: usize = 4096;

/// WP-50 increment 3b-ii, W4: env var carrying the admin write API's bearer
/// token, mirroring `keygen`'s own `SECRET_ENV_VAR` (`LLMPROXY_AUTH_SECRET`)
/// convention -- an operator-supplied credential lives in the environment,
/// never in the bootstrap config, so a config dump or a checked-in file can
/// never leak it. `start_admin` reads this exactly once and passes the
/// result into `proxy_admin::serve` as a plain parameter rather than letting
/// that crate read the environment itself -- see `serve`'s own doc for why
/// (`std::env::set_var` is process-global and racy across parallel tests).
const ADMIN_TOKEN_ENV_VAR: &str = "LLMPROXY_ADMIN_TOKEN";

async fn run_serve(
    concurrency: usize,
    drain_time: Duration,
    strategy: CoreDrainStrategy,
    service_node: Option<String>,
    service_cluster: Option<String>,
    snapshot: Arc<ConfigSnapshot>,
    config_source: ConfigSource,
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
    // ADR-0006 §2 / WP-60 prerequisite: the effective node id, computed
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

    // WP-50 3b-ii part B: one `SharedFactoryState` shared across every
    // worker, same "control builds it once, workers get a clone of the same
    // instance" shape as `cluster_manager` above. The HTTP filter chain is
    // rebuilt PER WORKER (`proxy_core::listener::build_hcm_handler` runs on
    // each worker's own `LocalSet`, ADR-0003), so a filter factory that needs
    // ONE process-wide singleton registers it in this slot on its first
    // `create()` call and every other worker's `create()` for the same
    // filter reads the same instance back. WP-60 prerequisite: also carries
    // this process's effective node id (`node.id` above), so a filter that
    // needs to disambiguate itself across replicas (the spend flush token,
    // ADR-0006 §2) can reach it via `FactoryContext::node_id()`.
    let factory_state = Arc::new(proxy_http::filter::SharedFactoryState::for_node(
        node.id.clone(),
    ));
    // WP-22 increment 2b: the one per-serve `SdsSecretRegistry`, same "control
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
        // (`InitialBindError` below): ground rule #1 forbids leaving the
        // proxy up serving 503s for a misconfigured cluster with no
        // diagnostic.
        for (name, err) in &rejected {
            tracing::error!(cluster = %name, error = %err, "cluster rejected at startup");
        }
        return ExitCode::FAILURE;
    }

    // WP-23 increment 6a: one `StatsControl`/`Registry` shared across every
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
    // actually hold. See `proxy_observability::stats`'s module doc,
    // "Increment 5", for why the two are split.
    let stats_control = proxy_observability::stats::StatsControl::new(concurrency);
    let stat_handles = Arc::new(proxy_http::stat_handles::StatHandles::build(
        &stats_control,
        snapshot.clusters.keys().map(String::as_str),
    ));
    // WP-23 increment 6b: `DownstreamStatHandles`'s counterpart to
    // `stat_handles` above, resolved once at boot for every listener this
    // boot snapshot names (rather than every cluster) -- see
    // `proxy_http::stat_handles`'s module doc for why the two tables mirror
    // each other's shape, and `reload` below for why a listener a later
    // SIGHUP introduces still gets a handle resolved for it.
    let downstream_stat_handles = Arc::new(proxy_http::stat_handles::DownstreamStatHandles::build(
        &stats_control,
        snapshot.listeners.keys().map(String::as_str),
    ));
    // WP-23 increment 6b: `TokenUsageStatHandles`'s counterpart to
    // `stat_handles` above -- resolved once at boot for every cluster (a
    // provider, per ground rule #6, is a cluster, never a route), same
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

    // WP-51 increment 2+3a: one `SpanSink` shared across every worker, same
    // "control computes, workers get a cheap handle" shape as `registry`
    // just above -- built (and its exporter task spawned) only when the boot
    // snapshot's `tracing` is `Some`. `None` means no sink is ever
    // constructed and no exporter task ever runs: every `FilterChainHandler`/
    // `RouterFilterFactory` `proxy-core`'s `build_hcm_handler` builds gets
    // `tracing_handles: None`, so tracing-off costs nothing beyond the one
    // `is_none` check each of those already documents.
    //
    // The exporter task is spawned with a plain `tokio::spawn`, not
    // `tokio::task::spawn_local` -- it holds no `!Send` data-plane state
    // (ADR-0003 governs workers, not this control-runtime-only task), and
    // `run_serve` itself is already running ON the control runtime (this
    // function is `control_rt.block_on`'d from `main`), so `tokio::spawn`
    // here lands the task on that same runtime, alongside the config
    // reload/signal loop below -- never on a worker's `LocalSet`.
    let tracing_handles = snapshot.tracing.as_ref().map(|cfg| {
        let (sink, spans_rx) = proxy_observability::trace::SpanSink::new(SPAN_SINK_CAPACITY);
        tracing::info!(
            otlp_endpoint = %cfg.otlp_endpoint,
            service_name = %cfg.service_name,
            sample_ratio = cfg.sample_ratio,
            "OTLP trace export enabled"
        );
        tokio::spawn(proxy_observability::otlp::run_exporter(
            spans_rx,
            cfg.otlp_endpoint.clone(),
            cfg.service_name.clone(),
            registry.clone(),
        ));
        proxy_core::listener::TracingHandles {
            sink,
            sample_ratio: cfg.sample_ratio,
        }
    });

    // Every consumer that must observe a SIGHUP-published snapshot registers
    // its `WorkerConfigHandle` into this ONE registry -- the admin server
    // just below, and every worker `WorkerPool::spawn` creates further down.
    // Created here, before either, precisely so it can be handed to both
    // without reordering when they start (see `start_admin`'s doc comment for
    // why the admin server still has to come first). `ConfigPublisher::publish`
    // (via `SnapshotHandles::store_all`) is what makes registering here enough
    // -- see that type's doc in `proxy-core`'s `runtime.rs`.
    let snapshot_handles = Arc::new(SnapshotHandles::new());

    // WP-21 increment 3: `/ready`'s readiness probe, built here (not inside
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
    let readiness =
        build_readiness_probe(cluster_manager.clone(), readiness_timeout, Instant::now());

    // WP-50 increment 1: the read-only admin surface. Opt-in -- only binds
    // when the config names an `admin` address -- and, like a listener's
    // `initial_bind`, a bind failure here is a startup error, not a silent
    // skip (see `start_admin`'s doc comment). Started before the worker pool
    // so a bad admin port fails fast instead of after workers are already
    // accepting traffic.
    let admin_server = match start_admin(
        snapshot.admin,
        snapshot.clone(),
        registry.clone(),
        Instant::now(),
        &snapshot_handles,
        factory_state.clone(),
        Some(readiness),
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

    // WP-20 increment 4d-iii: build the ADS client, if bootstrap
    // `dynamic_resources` asks for one, from this same boot snapshot --
    // before `snapshot` moves into `WorkerPool::spawn` just below. `None`
    // means nothing was started; see `start_ads`'s own doc for the three
    // (non-fatal) ways that happens. The receiver is read from inside the
    // `select!` in this function's own signal loop, further down.
    let mut ads_apply_rx = start_ads(&snapshot, &node, &cluster_manager, &secret_registry);

    let publisher = WorkerPool::spawn(
        WorkerPoolConfig {
            concurrency,
            pin_cores: true,
        },
        snapshot,
        snapshot_handles,
        move |ctx: WorkerContext| {
            let bind_tx = bind_tx.clone();
            worker_main(
                ctx,
                bind_tx,
                cluster_manager.clone(),
                registry.clone(),
                stat_handles.clone(),
                downstream_stat_handles.clone(),
                token_usage_stat_handles.clone(),
                tracing_handles.clone(),
                factory_state.clone(),
                secret_registry.clone(),
            )
        },
    );

    tracing::info!(
        workers = concurrency,
        drain_time_s = drain_time.as_secs(),
        drain_strategy = ?strategy,
        service_node = service_node.as_deref().unwrap_or("-"),
        service_cluster = service_cluster.as_deref().unwrap_or("-"),
        listeners = %listener_summary.join(", "),
        "llm-proxy started, waiting for SIGTERM/SIGINT/SIGHUP"
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

    // Runs until a shutdown signal arrives; a SIGHUP along the way triggers a
    // config reload, and an ADS-applied snapshot (WP-20 increment 4d-iii)
    // does likewise, and both loop back to waiting, exactly like Envoy's own
    // hot-reload trigger. See `reload`'s doc for what "reload" does and does
    // not apply, and requirement 1's test (`sighup_with_a_broken_config_...`
    // in `tests/reload.rs`) for why a failed reload must never reach the
    // `break` below.
    //
    // Rust note: `tokio::select!` picks whichever branch is ready first, so
    // this is what turns two independent producers of "apply a new snapshot"
    // (SIGHUP and ADS) into one control loop that never applies both at once.
    loop {
        tokio::select! {
            signal = control_signals.recv() => match signal {
                ControlSignal::Shutdown => break,
                ControlSignal::Reload => {
                    if let Some(new_version) = reload(
                        &config_source,
                        current_version,
                        &publisher,
                        &cluster_manager_for_reload,
                        &stats_control,
                        &stat_handle_tables_for_reload,
                    )
                    .await
                    {
                        current_version = new_version;
                    }
                }
            },
            ads_msg = recv_ads_apply(&mut ads_apply_rx) => match ads_msg {
                Some((mut ads_snapshot, reply)) => {
                    // Rust note: authoritative version stamping happens HERE,
                    // not inside `ResourceApplier` -- see the comment on
                    // `apply_snapshot`'s own doc and on `current_version`
                    // above. Two producers stamp a version: `reload` (SIGHUP)
                    // does the same overwrite right before its own
                    // `apply_snapshot` call; `ResourceApplier::assemble_snapshot`'s
                    // internal version is advisory only and is discarded here.
                    ads_snapshot.version = SnapshotVersion(current_version.0 + 1);
                    let (version, rejected) = apply_snapshot(
                        ads_snapshot,
                        &publisher,
                        &cluster_manager_for_reload,
                        &stats_control,
                        &stat_handle_tables_for_reload,
                    )
                    .await;
                    current_version = version;
                    for (name, err) in &rejected {
                        tracing::error!(
                            cluster = %name,
                            error = %err,
                            "ADS: cluster rejected while applying a discovery response; it is \
                             not part of the live cluster set (a request routed to it will fail \
                             until the control plane sends a working definition)"
                        );
                    }
                    // A dropped receiver (the ADS task's `Publish` future was
                    // cancelled, e.g. mid-shutdown) must not panic this loop
                    // -- `send` returning `Err` just means nobody is waiting
                    // for the reply any more.
                    let _ = reply.send(());
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

    let outcome = graceful_shutdown(publisher, drain_time, strategy).await;
    tracing::info!(?outcome, "drain sequence finished, exiting");
    ExitCode::SUCCESS
}

/// The SIGHUP config-reload path: re-reads `source`'s file through the exact
/// front-end it was booted with ([`ConfigSource::load`]), and on success
/// republishes a fresh snapshot -- on failure, logs and leaves every piece of
/// running state untouched.
///
/// Order of operations on success, and why: [`proxy_http::stat_handles::StatHandles::resolve_missing`]
/// runs first so a cluster this table has never seen has a handle resolved
/// *before* traffic can possibly reach it; [`proxy_cluster::manager::ClusterManager::update_from_snapshot`]
/// runs next, exactly the call `run_serve` makes at boot, so the shared
/// cluster manager every worker's router reads through picks up added,
/// removed, or changed clusters; [`ConfigPublisher::publish`] runs last, so
/// listeners (via each worker's `config_ping` -> `reconcile`, already
/// covered by `proxy-core`'s own tests) never start routing to a cluster the
/// manager doesn't know about yet.
///
/// A cluster `update_from_snapshot` rejects (unimplemented `lb_policy`, a
/// bad `transport_socket`, ...) is logged at `error` and left out of the
/// live cluster set -- unlike at boot, where the same rejection is fatal,
/// here it cannot be: requirement 1 is that a reload never takes the process
/// down, and that has to hold even for a failure `build_snapshot` itself
/// has no way to catch.
///
/// The three boot-resolved stat-handle tables [`reload`] must extend when a
/// SIGHUP introduces a listener or cluster the boot snapshot never named.
/// Bundled purely to keep `reload`'s own argument count under clippy's
/// `too_many_arguments` threshold -- the same motivation, one layer up, that
/// [`proxy_core::listener::StatsRecorders`] documents for bundling the three
/// *recorders* these tables feed.
struct StatHandleTables {
    router: Arc<proxy_http::stat_handles::StatHandles>,
    downstream: Arc<proxy_http::stat_handles::DownstreamStatHandles>,
    token_usage: Arc<proxy_http::stat_handles::TokenUsageStatHandles>,
}

/// Proof that a snapshot's clusters are already installed in the shared
/// [`proxy_cluster::manager::ClusterManager`].
///
/// Rust note: a zero-sized "receipt" (or witness) type. It carries no data --
/// its whole job is that [`install_clusters`] is the only thing that can
/// produce one and [`publish_to_workers`] demands one by value, so the
/// dangerous order (publish first, install second) is not expressible. This
/// is the cheapest way to turn "a comment says do these in order" into "the
/// compiler says so", and it exists because two separate attempts to catch
/// the wrong order with a test both failed -- see [`apply_snapshot`]'s doc.
#[must_use = "publishing without installing clusters first is the bug this type exists to prevent"]
struct ClustersInstalled;

/// Step 4: teach the shared cluster manager about this snapshot's clusters,
/// returning the receipt [`publish_to_workers`] needs plus any clusters it
/// rejected.
async fn install_clusters(
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    clusters: &std::collections::HashMap<
        proxy_config::ir::ClusterName,
        Arc<proxy_config::ir::ClusterConfig>,
    >,
) -> (
    ClustersInstalled,
    Vec<(
        proxy_config::ir::ClusterName,
        proxy_cluster::manager::ClusterBuildError,
    )>,
) {
    let rejected = cluster_manager.update_from_snapshot(clusters).await;
    (ClustersInstalled, rejected)
}

/// Step 5: make the snapshot visible to workers. Takes the
/// [`ClustersInstalled`] receipt by value so this cannot run before step 4.
fn publish_to_workers(
    publisher: &proxy_core::runtime::ConfigPublisher,
    snapshot: ConfigSnapshot,
    _installed: ClustersInstalled,
) -> SnapshotVersion {
    let version = snapshot.version;
    publisher.publish(Arc::new(snapshot));
    version
}

/// Applies an already-built [`ConfigSnapshot`] to every piece of running
/// state, in the one order that is safe. This is the shared tail end WP-20's
/// design brief requires: `reload` below (the SIGHUP producer) is the first
/// caller, and the ADS client -- the *second* producer of `Arc<ConfigSnapshot>`,
/// landing next -- calls this SAME function rather than reaching around it to
/// publish on its own (`internal-docs/wp-20-design-brief.md`, "The apply path
/// is solved, and xDS must not invent a second one").
///
/// Order of operations, and why -- unchanged from what used to be inline in
/// `reload`, just no longer duplicated for a second caller:
/// 1. [`proxy_http::stat_handles::StatHandles::resolve_missing`] over the
///    cluster keys, so a cluster this table has never seen has a handle
///    resolved *before* traffic can possibly reach it.
/// 2. [`proxy_http::stat_handles::DownstreamStatHandles::resolve_missing`]
///    over the listener keys, so a listener this snapshot introduces has a
///    `downstream_cx_total` handle resolved before its accept loop can
///    possibly see a connection.
/// 3. [`proxy_http::stat_handles::TokenUsageStatHandles::resolve_missing`]
///    over the cluster keys, so a cluster this snapshot introduces has its
///    four `llm.client.token.usage` handles resolved before it can dial its
///    first request.
/// 4. [`proxy_cluster::manager::ClusterManager::update_from_snapshot`] --
///    exactly the call `run_serve` makes at boot -- so the shared cluster
///    manager every worker's router reads through picks up added, removed, or
///    changed clusters. A rejected cluster (unimplemented `lb_policy`, a bad
///    `transport_socket`, ...) is left out of the live cluster set; the
///    name+error pairs are *returned* rather than logged here, since the two
///    callers want different things done with them (`reload` logs a
///    SIGHUP-specific message below; the ADS caller will want to NACK the
///    discovery response, not just log).
/// 5. [`proxy_core::runtime::ConfigPublisher::publish`], LAST: this is what
///    makes the snapshot visible to workers (via each worker's `config_ping`
///    -> `reconcile`, already covered by `proxy-core`'s own tests), so it must
///    not run until step 4 has already taught the cluster manager about every
///    cluster the new snapshot's routes can reach -- otherwise a worker could
///    start routing to a cluster the manager doesn't know about yet.
///
/// **The ordering of steps 4 and 5 is enforced by the TYPE SYSTEM, not by a
/// test, and that is a deliberate choice made after two measured failures.**
///
/// First (2026-09-06) a plain mutation showed no unit test caught a
/// reordering. Then an end-to-end test was written for exactly this -- boot
/// the binary, have a control plane introduce a cluster, drive real traffic --
/// and a mutation showed *it did not catch the reordering either*
/// (`tests/ads_e2e.rs`, see its module doc). The reason is structural: the
/// damage window is the microseconds between `publish` storing the snapshot
/// and `update_from_snapshot` storing the cluster map, which it does
/// synchronously before its per-cluster `refresh_cluster().await` loop. No
/// black-box observer can reliably land inside it, and CLAUDE.md rule 14's
/// lesson is that an instrument which lies is worse than none.
///
/// So the order is a compile-time property instead: [`install_clusters`]
/// returns a [`ClustersInstalled`] receipt that [`publish_to_workers`]
/// requires by value. Swapping the two statements below does not typecheck --
/// the receipt would be used before it exists. That is a stronger guarantee
/// than the test that could not be written, and it costs one zero-sized type.
async fn apply_snapshot(
    snapshot: ConfigSnapshot,
    publisher: &proxy_core::runtime::ConfigPublisher,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    stats_control: &proxy_observability::stats::StatsControl,
    tables: &StatHandleTables,
) -> (
    SnapshotVersion,
    Vec<(
        proxy_config::ir::ClusterName,
        proxy_cluster::manager::ClusterBuildError,
    )>,
) {
    tables
        .router
        .resolve_missing(stats_control, snapshot.clusters.keys().map(String::as_str));
    tables
        .downstream
        .resolve_missing(stats_control, snapshot.listeners.keys().map(String::as_str));
    tables
        .token_usage
        .resolve_missing(stats_control, snapshot.clusters.keys().map(String::as_str));

    let (installed, rejected) = install_clusters(cluster_manager, &snapshot.clusters).await;
    // `installed` is consumed here, and it cannot exist before the line above
    // -- that is what makes the order a compile error rather than a comment.
    let version = publish_to_workers(publisher, snapshot, installed);

    (version, rejected)
}

/// Returns the new [`SnapshotVersion`] on success so the caller can advance
/// `current_version` for the *next* reload, or `None` on any failure (old
/// snapshot, old version, old cluster set: all still serving).
async fn reload(
    source: &ConfigSource,
    current_version: SnapshotVersion,
    publisher: &proxy_core::runtime::ConfigPublisher,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    stats_control: &proxy_observability::stats::StatsControl,
    tables: &StatHandleTables,
) -> Option<SnapshotVersion> {
    let mut snapshot = match source.load() {
        Ok(snapshot) => snapshot,
        Err(err) => {
            // Requirement 1: this is the one log line an operator's typo has
            // to produce. `err` is a `ConfigError`/`proxy-simple-config`
            // error `Display`, which already carries the full dotted field
            // path (ground rule #1) -- the same detail the boot-time
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

    // Captured before `snapshot` moves into `apply_snapshot` below, purely so
    // the success log line further down can still report them.
    let listeners = snapshot.listeners.len();
    let clusters = snapshot.clusters.len();

    let (version, rejected) =
        apply_snapshot(snapshot, publisher, cluster_manager, stats_control, tables).await;

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
// WP-20 increment 4d-iii: the ADS client is the *second* producer of
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
type AdsApplyMsg = (ConfigSnapshot, oneshot::Sender<()>);

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

/// Builds and spawns the ADS client task when `snapshot.ads` asks for one.
///
/// Returns `None` -- and starts nothing -- in three cases, none of them
/// fatal to `run_serve` (PLAN.md 8.5: keep serving last-good/static config):
/// - `snapshot.ads` is `None`: no `dynamic_resources` in bootstrap, today's
///   behavior for every release through v0.2.0, untouched by this increment.
/// - none of `lds`, `cds`, or a statically-declared EDS cluster asks for
///   anything: nothing to subscribe to, logged at `info!`. EDS has no
///   bootstrap flag of its own -- Envoy expresses it per cluster, via
///   `eds_cluster_config.eds_config.ads`, already lowered into
///   `ClusterConfig.eds` -- so this gate also starts an ADS client for a
///   bootstrap that enables neither `lds` nor `cds` but declares a `Cluster`
///   whose membership comes over EDS.
/// - the named ADS cluster has no endpoints: a config error, logged at
///   `error!` with the cluster name -- config lowering already guarantees the
///   cluster itself exists in `static_resources` (`AdsConfig`'s own doc), so
///   this is the one thing left for this function to check.
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
fn start_ads(
    snapshot: &Arc<ConfigSnapshot>,
    node: &NodeIdentity,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    secret_registry: &Arc<SdsSecretRegistry>,
) -> Option<mpsc::Receiver<AdsApplyMsg>> {
    let ads = snapshot.ads.as_ref()?;

    let has_static_eds_cluster = snapshot.clusters.values().any(|c| c.eds.is_some());
    if !ads.lds && !ads.cds && !has_static_eds_cluster {
        tracing::info!(
            cluster = %ads.cluster,
            "ADS configured but none of `lds`, `cds`, or a statically-declared EDS cluster asks \
             for anything; nothing to subscribe to, not starting an ADS client"
        );
        return None;
    }

    // Rust note: `?` above already returned on `ads.is_none()`; from here on
    // `ads.cluster` is a name config lowering has already checked exists in
    // `static_resources`, so a missing entry here would be that guarantee
    // breaking, not an operator mistake -- treated the same as "no
    // endpoints" below rather than a panic, per ground rule #1's spirit
    // (loud, not silent -- but never fatal to the process here, see PLAN.md
    // 8.5).
    let endpoint = match snapshot
        .clusters
        .get(&ads.cluster)
        .and_then(|c| c.endpoints.first())
    {
        Some(endpoint) => endpoint,
        None => {
            tracing::error!(
                cluster = %ads.cluster,
                "ADS cluster has no endpoints (or does not exist); not starting an ADS client"
            );
            return None;
        }
    };
    let uri = format!("http://{}:{}", endpoint.host, endpoint.port);

    let channel = match Channel::from_shared(uri.clone()) {
        Ok(endpoint) => endpoint.connect_lazy(),
        Err(err) => {
            tracing::error!(
                cluster = %ads.cluster,
                uri,
                error = %err,
                "ADS cluster address is not a valid URI; not starting an ADS client"
            );
            return None;
        }
    };
    let mut grpc_client = AggregatedDiscoveryServiceClient::new(channel);

    // Bounded at 1: `ResourceApplier` (via `AdsClient::run_once`) applies one
    // `DiscoveryResponse` at a time and its `Publish` future awaits the
    // oneshot reply below before resolving, so at most one message is ever in
    // flight on this channel.
    let (apply_tx, apply_rx) = mpsc::channel::<AdsApplyMsg>(1);
    let publish: Publish = Box::new(move |snapshot: Arc<ConfigSnapshot>| {
        let apply_tx = apply_tx.clone();
        Box::pin(async move {
            // Rust note: `ConfigSnapshot` has no `Clone` impl (deliberately --
            // see `crates/proxy-config/tests/ir_readership.rs`'s module doc),
            // so this is the one place this increment needs to turn the
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
            let owned =
                snapshot.with_dynamic_resources(HashMap::new(), HashMap::new(), snapshot.version);
            let (reply_tx, reply_rx) = oneshot::channel();
            if apply_tx.send((owned, reply_tx)).await.is_err() {
                // The control loop only ever drops its receiver by falling
                // out of `run_serve`'s select loop at shutdown -- if this
                // fires, the process is already on its way down and there is
                // nothing left to apply.
                return;
            }
            // Apply-then-ACK (S8): this future does not resolve until the
            // control loop has actually applied the snapshot --
            // `AdsClient::run_once` does not send this response's ACK until
            // THIS future resolves.
            //
            // **NOTHING CATCHES THE LOSS OF THIS `.await`, and an
            // end-to-end attempt to fix that FAILED -- measured twice.**
            // Deleting it leaves this crate's unit tests green (2026-09-06),
            // and it also leaves all three of `tests/ads_e2e.rs`'s
            // real-binary-against-a-real-control-plane tests green. The
            // reason is in that file's module doc: observing the ACK costs a
            // network round trip, orders of magnitude longer than the window
            // this bug opens, so the racing apply always wins.
            //
            // The seam itself IS pinned, one layer down, by `proxy-xds`'s
            // `the_ack_does_not_reach_the_wire_until_the_handler_future_resolves`
            // -- what is unpinned is that THIS closure uses it. The sibling
            // step-4/step-5 ordering was in the same position and got solved
            // structurally instead (see `apply_snapshot`'s `ClustersInstalled`
            // receipt); the same trick does not reach across this channel,
            // because the reply arrives at runtime rather than as a value the
            // compiler can require. Left open deliberately, and the harm is
            // bounded: a control plane believes config is live fractionally
            // early, which is an S8 conformance point, not a serving defect.
            let _ = reply_rx.await;
        })
    });

    // WP-21 increment 2b-iii: an accepted EDS endpoint update goes straight
    // to `ClusterManager::accept_eds_update` -- an `arc_swap` store on the
    // cluster's own `HostSet`, nothing more -- rather than through the
    // `apply_tx`/`Publish` channel above. That channel exists because a
    // CDS/LDS response runs the WHOLE `apply_snapshot` sequence (install
    // clusters into `cluster_manager`, THEN publish to every worker), and
    // `Publish`'s own doc comment is what explains why that sequencing needs
    // a round trip through this function's control loop. Installing
    // endpoints into a cluster that already exists needs none of that -- the
    // cluster is already live, and there is no worker-visible snapshot to
    // publish -- so this sink calls `accept_eds_update` directly on the
    // `Arc<ClusterManager>` this closure closes over, instead of inventing a
    // second channel back to the same loop.
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

    // WP-22 increment 2b: an accepted SDS secret goes straight to
    // `SdsSecretRegistry::publish` -- same "no round trip through this
    // function's control loop" shape as `endpoint_sink` just above, and for
    // the same reason: the registry is already live shared state (an
    // `Arc<SdsSecretRegistry>`, not a worker-visible `ConfigSnapshot`), so
    // there is nothing for `apply_snapshot`'s sequencing to add.
    //
    // Certificate and validation-context secrets use distinct live TLS
    // seams. The latter rebuilds then atomically swaps ServerConfig because
    // rustls bakes the client verifier (trust anchors) into it; an invalid CA
    // is returned here as an SDS NACK while the prior config keeps serving.
    let secret_registry = Arc::clone(secret_registry);
    let secret_sink: PublishSecrets = Box::new(move |name, secret: Arc<DynamicSecret>| {
        let secret_registry = Arc::clone(&secret_registry);
        Box::pin(async move {
            match secret.tls_certificate_ir() {
                Ok(Some(ir)) => secret_registry.publish(&name, vec![ir]),
                Ok(None) => match secret.validation_context_ir() {
                    Ok(Some(validation)) => {
                        secret_registry.publish_validation_context(&name, validation)
                    }
                    Ok(None) => Err(format!("secret `{name}` has no supported SDS TLS payload")),
                    Err(err) => Err(err.to_string()),
                },
                Err(err) => Err(err.to_string()),
            }
        })
    });

    let applier = ResourceApplier::new(Arc::clone(snapshot), publish)
        .with_endpoint_sink(endpoint_sink)
        .with_secret_sink(secret_sink);

    let mut states = Vec::new();
    if ads.cds {
        states.push(SubscriptionState::new(CDS_TYPE_URL, Subscription::Wildcard));
    }
    if ads.lds {
        states.push(SubscriptionState::new(LDS_TYPE_URL, Subscription::Wildcard));
    }
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

    let mut client = AdsClient::new(states).with_node(node.clone());
    let reconnect = Reconnect::real();

    // Rust note: spawned and the `JoinHandle` dropped -- `AdsClient::run`
    // never returns (`-> !`), so there is nothing to join, only to abandon at
    // shutdown. This lands on the control runtime `run_serve` is already
    // `block_on`'d on (see the OTLP exporter's own `tokio::spawn` above for
    // the same reasoning): a plain `tokio::spawn`, not `spawn_local`, since
    // neither the client nor the applier holds any `!Send` worker-local state
    // (ADR-0003 governs workers, not this control-runtime-only task).
    tokio::spawn(async move {
        client.run(&mut grpc_client, applier, reconnect).await;
    });

    Some(apply_rx)
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

/// WP-21 increment 3: builds the `/ready` readiness probe `run_serve` wires
/// into [`start_admin`], which passes it straight through to
/// `proxy_admin::serve`. Reads [`proxy_cluster::manager::ClusterManager::warming_clusters`]
/// fresh on every call -- no caching, since the whole point is that warming
/// state can change between polls -- and reports [`proxy_admin::Readiness::Initializing`]
/// for as long as it is non-empty AND `deadline_started_at.elapsed()` is
/// under `timeout`; past the deadline it reports [`proxy_admin::Readiness::Live`]
/// instead.
///
/// **This only changes what `/ready` says -- it never calls
/// `ClusterManager::force_initialize` and never touches `is_initialized`.**
/// A cluster that never resolved stays un-initialized forever; the deadline
/// only stops that fact from gating readiness. WP-58 is what makes a request
/// to a still-warming cluster behave differently from one to a cluster whose
/// hosts are all ejected, and it needs `is_initialized` to keep telling those
/// two states apart -- see this crate's [`run_serve`] doc for where `timeout`
/// itself is resolved (`AdsConfig::initial_fetch_timeout`, falling back to
/// [`proxy_cluster::discovery::DEFAULT_INITIAL_FETCH_TIMEOUT`]).
///
/// Logs once, at `warn!`, the first probe call that observes the deadline
/// has passed with clusters still warming, naming them -- never on every
/// call. `/ready` is polled by orchestrators on a tight loop; logging on
/// every poll would become the incident (CLAUDE.md rule 17's "keep the
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
) -> proxy_admin::ReadinessProbe {
    let warned = AtomicBool::new(false);
    Arc::new(move || {
        let warming = cluster_manager.warming_clusters();
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
                 stays false -- see WP-58"
            );
        }
        proxy_admin::Readiness::Live
    })
}

/// Starts the read-only admin server (`proxy-admin`, WP-50 increment 1) when
/// `admin` names a bind address; binds nothing and returns `Ok(None)`
/// otherwise -- the admin surface is opt-in, never automatic.
///
/// The admin server's [`WorkerConfigHandle`](proxy_core::WorkerConfigHandle) is obtained from
/// `snapshot_handles` -- the SAME [`SnapshotHandles`] registry
/// [`WorkerPool::spawn`] enrolls every worker's handle into, further down in
/// `run_serve`. That is what makes `/config_dump` and `/clusters` track a
/// SIGHUP reload: `reload`'s call to `ConfigPublisher::publish` walks the
/// registry, not a hand-picked list of workers, so the admin handle gets the
/// new snapshot in the same store as everyone else's. (Before this, the admin
/// server built its own private `WorkerConfigHandle` here, outside that
/// registry entirely -- `publish` had no way to reach it, so `/config_dump`
/// kept serving the boot snapshot forever.)
///
/// `registry` is the same [`proxy_observability::stats::Registry`]
/// `run_serve` hands to every worker's [`RouterStats`](proxy_http::stat_handles::RouterStats)
/// -- built once, from a single [`StatsControl`](proxy_observability::stats::StatsControl),
/// in `run_serve` itself (not here any more, since increment 6a's workers
/// need the exact same registry, not a second, disconnected one). As of
/// WP-23 increment 6a, `/stats` reports real `upstream_rq`/`upstream_rq_time`
/// traffic for every cluster the boot snapshot named, and `reload`'s call to
/// `StatHandles::resolve_missing` keeps that true for a cluster a later
/// config reload introduces too -- see `proxy_http::stat_handles`'s module
/// doc for the two instruments' call sites.
///
/// A bind failure is returned as an `Err`, not swallowed: `run_serve` turns
/// it into a startup failure, holding the admin port to the same standard
/// `initial_bind` holds every listener port to.
///
/// `factory_state` is `run_serve`'s ONE per-serve [`proxy_http::filter::SharedFactoryState`]
/// -- the admin write API resolves its `ControlPlane` out of it per request
/// (see `proxy_admin::server`'s module doc for why that resolution can't
/// happen here or at `serve()` time: this function runs before the worker
/// pool spawns, so nothing has registered into the slot yet). This function
/// also reads [`ADMIN_TOKEN_ENV_VAR`] once and passes the result to
/// `proxy_admin::serve` as a plain parameter, per that function's own doc on
/// why it never reads the environment itself.
async fn start_admin(
    admin: Option<SocketAddr>,
    snapshot: Arc<ConfigSnapshot>,
    registry: Arc<proxy_observability::stats::Registry>,
    started_at: Instant,
    snapshot_handles: &SnapshotHandles,
    factory_state: Arc<proxy_http::filter::SharedFactoryState>,
    readiness: Option<proxy_admin::ReadinessProbe>,
) -> Result<Option<proxy_admin::AdminServer>, String> {
    let Some(addr) = admin else {
        return Ok(None);
    };
    let config = snapshot_handles.register(snapshot);
    let admin_token = std::env::var(ADMIN_TOKEN_ENV_VAR).ok();
    let server = proxy_admin::serve(
        addr,
        config,
        Some(registry),
        started_at,
        factory_state,
        admin_token,
        readiness,
    )
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
// Rust note: a spawn entrypoint handed one worker every boot-resolved
// dependency it needs. It already sat at clippy's 7-arg ceiling before WP-51;
// the optional `tracing_handles` (8th) tips it over. These are each a
// distinct per-worker handle with no shared identity to bundle under -- the
// three stat tables are already bundled for `reload` via `StatHandleTables`,
// and re-bundling them here purely to dodge the lint would fragment that one
// owner -- so this leaf allows the extra arg rather than inventing a bag type.
#[allow(clippy::too_many_arguments)]
async fn worker_main(
    ctx: WorkerContext,
    bind_tx: mpsc::UnboundedSender<(WorkerId, Result<(), String>)>,
    cluster_manager: Arc<proxy_cluster::manager::ClusterManager>,
    stats_registry: Arc<proxy_observability::stats::Registry>,
    stat_handles: Arc<proxy_http::stat_handles::StatHandles>,
    downstream_stat_handles: Arc<proxy_http::stat_handles::DownstreamStatHandles>,
    token_usage_stat_handles: Arc<proxy_http::stat_handles::TokenUsageStatHandles>,
    tracing_handles: Option<proxy_core::listener::TracingHandles>,
    // WP-50 3b-ii part B: this worker's clone of the ONE per-serve
    // `SharedFactoryState` -- see `run_serve`'s own comment on the Arc this
    // is cloned from.
    factory_state: Arc<proxy_http::filter::SharedFactoryState>,
    // WP-22 increment 2b: this worker's clone of the ONE per-serve
    // `SdsSecretRegistry` -- see `run_serve`'s own comment on the Arc this is
    // cloned from.
    secret_registry: Arc<SdsSecretRegistry>,
) {
    let registry = ConnectionRegistry::new();
    // WP-23 increment 6a: built fresh per worker -- `stats_registry`/
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
    // WP-23 increment 6b: `DownstreamStats`'s counterpart to `router_stats`
    // above, same per-worker `WorkerId` and same shared `stats_registry` --
    // this is what `crate::listener::spawn_accept_loop` calls once per
    // accepted connection.
    let downstream_stats = Arc::new(proxy_http::stat_handles::DownstreamStats::new(
        stats_registry.clone(),
        downstream_stat_handles,
        proxy_observability::stats::WorkerId(ctx.id.0),
    ));
    // WP-23 increment 6b: `GenAiTokenStats`'s counterpart to `router_stats`
    // above -- this is what `crate::listener::build_hcm_handler` wires into
    // every real `FilterChainHandler` it builds, via `.with_token_stats`.
    let token_stats = Arc::new(proxy_http::stat_handles::GenAiTokenStats::new(
        stats_registry,
        token_usage_stat_handles,
        proxy_observability::stats::WorkerId(ctx.id.0),
    ));

    let stats = proxy_core::listener::StatsRecorders {
        router: router_stats,
        downstream: downstream_stats,
        token: token_stats,
        tracing: tracing_handles,
    };

    let bound = match initial_bind(
        &ctx.config.load(),
        &ctx.config,
        &registry,
        &ctx.shutdown,
        &cluster_manager,
        &stats,
        &factory_state,
        &secret_registry,
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
        stats,
        factory_state,
        secret_registry,
    ));

    drain_worker(ctx.id, ctx.drain, ctx.drain_done, registry).await;

    let mut shutdown = ctx.shutdown;
    let _ = shutdown.changed().await;

    // `run_listener_manager` also watches `shutdown` and aborts its accept
    // loops on the same signal; wait for it so the thread doesn't tear down
    // mid-abort.
    let _ = listener_manager.await;
}

/// What [`ControlSignals::recv`] resolved on -- either begin the drain
/// sequence, or run a config reload and keep serving.
enum ControlSignal {
    /// SIGTERM or SIGINT.
    Shutdown,
    /// SIGHUP: see [`reload`].
    Reload,
}

/// SIGTERM, SIGINT, and SIGHUP, with their handlers already **installed**.
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
}

impl ControlSignals {
    /// Installs all three handlers. Failing to install one is a startup
    /// failure, not something to discover at shutdown/reload time.
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            sigterm: signal(SignalKind::terminate())?,
            sigint: signal(SignalKind::interrupt())?,
            sighup: signal(SignalKind::hangup())?,
        })
    }

    /// Resolves on the first of the three signals, and says which kind it
    /// was so the caller's loop can tell a reload from a shutdown.
    async fn recv(&mut self) -> ControlSignal {
        tokio::select! {
            _ = self.sigterm.recv() => ControlSignal::Shutdown,
            _ = self.sigint.recv() => ControlSignal::Shutdown,
            _ = self.sighup.recv() => ControlSignal::Reload,
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

    fn test_registry() -> Arc<proxy_observability::stats::Registry> {
        proxy_observability::stats::StatsControl::new(1).registry()
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
            empty_snapshot(),
            test_registry(),
            Instant::now(),
            &SnapshotHandles::new(),
            Arc::new(proxy_http::filter::SharedFactoryState::default()),
            None,
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
            empty_snapshot(),
            test_registry(),
            Instant::now(),
            &SnapshotHandles::new(),
            Arc::new(proxy_http::filter::SharedFactoryState::default()),
            None,
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
            empty_snapshot(),
            test_registry(),
            Instant::now(),
            &snapshot_handles,
            Arc::new(proxy_http::filter::SharedFactoryState::default()),
            None,
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
                usage_dialect: None,
                health_check: None,
                outlier_detection: None,
            }),
        );
        manager.update_from_snapshot(&snapshot).await;
        Arc::new(manager)
    }

    // ---- WP-21 increment 3: the readiness probe's deadline -----------------
    //
    // Both tests drive `build_readiness_probe` directly (per the task's own
    // acceptance note) rather than sleeping past a real timeout -- the
    // deadline is just `Instant` subtraction, so backdating
    // `deadline_started_at` proves the "past the deadline" branch
    // deterministically and instantly.

    #[tokio::test]
    async fn readiness_probe_reports_initializing_before_the_deadline() {
        let manager = manager_with_one_never_fed_cluster().await;
        let probe = build_readiness_probe(manager.clone(), Duration::from_secs(60), Instant::now());
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
        let probe =
            build_readiness_probe(manager.clone(), Duration::from_secs(1), deadline_started_at);

        assert_eq!(probe(), proxy_admin::Readiness::Live);
        assert!(
            !manager.is_initialized("never-fed"),
            "the warming deadline must gate /ready only -- it must never mark a cluster \
             initialized (that stays WP-58's job, at request time)"
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
            config_path,
            config,
            mode: Mode::Serve,
            tenant: None,
            key_id: "REPLACE_ME".to_string(),
            hmac_secret_file: None,
            permissive,
            concurrency: 1,
            drain_time_s: proxy_core::drain::DEFAULT_DRAIN_TIME.as_secs(),
            drain_strategy: DrainStrategyArg::Gradual,
            base_id: None,
            log_level: LogLevel::Info,
            service_node: None,
            service_cluster: None,
        }
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
    // WP-20 increment 4d-iii closes the ⚠️ outstanding item on the plan's
    // WP-20 checklist: these two flags used to reach only the startup log
    // line. Covered here as unit tests against the pure function rather than
    // a spawned-process test, same reasoning as `ConfigSource`'s tests above.

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

    // ---- ADR-0006 §2 / WP-60 prerequisite: node id reaches
    // `SharedFactoryState` ---------------------------------------------------
    //
    // Mirrors `run_serve`'s own three-step pipeline (bootstrap node id ->
    // `effective_node` -> `SharedFactoryState::for_node`) at unit-test
    // granularity, rather than booting a whole serve to prove it -- see
    // `effective_node`'s tests above for the same reasoning, and CLAUDE.md's
    // rule against a test binding a port.

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
