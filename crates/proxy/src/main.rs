//! The `llm-proxy` binary.
//!
//! Implemented: Envoy bootstrap loading (`-c`), PGV validation, IR building,
//! the simple dialect (`--config`), `--mode validate` / `--mode translate`,
//! `--mode keygen` (see `keygen`), `init`, serve mode's control runtime, worker
//! pool, SIGTERM/SIGINT drain sequence, and the per-worker listener manager
//! that binds sockets and accepts connections. The L4 network filter chain
//! (`tcp_proxy` etc.) lives in `proxy_core` (`tcp_proxy`, `net_filter`).

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

#[derive(Parser)]
#[command(name = "llm-proxy", version, about = "Proxy for LLM inference APIs")]
// Rust note: no `.required(true)` here any more -- `--mode keygen` needs
// neither `-c`/`--config-path` nor `--config`, so "at least one" can no
// longer be a blanket clap-level rule. The group still enforces "not both"
// (its `multiple` flag defaults to `false`); "at least one, unless keygen"
// is checked by hand in `main()`, right where `--mode translate`'s own extra
// requirement already is.
#[command(group(clap::ArgGroup::new("input").args(["config_path", "config"])))]
#[command(group(clap::ArgGroup::new("capture_destination").args(["request_records_file", "request_records_agent"])))]
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
    #[arg(long, value_name = "PATH", conflicts_with = "request_records_agent")]
    request_records_file: Option<PathBuf>,
    /// Opt-in Unix metadata agent. Delivery success requires a durable local ACK.
    #[arg(long, value_name = "SOCKET", requires_all = ["request_records_agent_uid", "request_records_agent_node", "request_records_producer"])]
    request_records_agent: Option<PathBuf>,
    /// Expected OS UID of the local metadata agent.
    #[arg(long, requires = "request_records_agent")]
    request_records_agent_uid: Option<u32>,
    /// Expected agent spool node identity, checked on handshake and receipts.
    #[arg(long, requires = "request_records_agent")]
    request_records_agent_node: Option<String>,
    /// Deployment producer ID bound to this proxy's OS UID in agent grants.
    #[arg(long, requires = "request_records_agent")]
    request_records_producer: Option<String>,
    /// Maximum retained attempt records per request. Excess attempts are
    /// explicitly reported as truncated; forwarding retry policy is unchanged.
    #[arg(long, requires="capture_destination", value_parser = clap::value_parser!(u16).range(1..=64))]
    request_record_max_attempts: Option<u16>,
    /// Milliseconds between capture-agent spool polls; the first poll waits one
    /// period. A parameter so integration tests need not sleep the default.
    #[arg(
        long = "capture-spool-poll-interval-ms",
        hide = true,
        value_name = "MS",
        default_value_t = CAPTURE_SPOOL_POLL_INTERVAL.as_millis() as u64,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    capture_spool_poll_interval_ms: u64,

    /// How long the drain sequence waits for connections to close before
    /// forcing worker shutdown (serve mode only).
    #[arg(
        long = "drain-time-s",
        value_name = "SECS",
        default_value_t = proxy_core::drain::DEFAULT_DRAIN_TIME.as_secs()
    )]
    drain_time_s: u64,

    /// Accepted for Envoy CLI compatibility. Both values behave as Envoy's
    /// `immediate`: the startup warning fires only when this flag is given;
    /// see the docs.
    #[arg(long = "drain-strategy", value_enum)]
    drain_strategy: Option<DrainStrategyArg>,

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

/// CLI-facing drain strategy. Both values are accepted so Envoy command lines
/// keep working, and both behave as `immediate` (see the startup warning in
/// `main`); nothing in the data plane reads the choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DrainStrategyArg {
    Gradual,
    Immediate,
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

    if snapshot.end_user_capture_configured
        && (args.request_records_file.is_some()
            || args.request_records_agent.is_some()
            || args.request_record_max_attempts.is_some())
    {
        eprintln!(
            "node.metadata[\"io.llmproxy.capture\"]: cannot combine declarative and CLI capture"
        );
        return ExitCode::FAILURE;
    }
    if snapshot.end_user_capture.is_some() && args.concurrency > 8 {
        eprintln!("node.metadata[\"io.llmproxy.capture\"].budgets.max_capture_memory_bytes: concurrency {} exceeds eight scratch owners",args.concurrency);
        return ExitCode::FAILURE;
    }
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
        // Secrets are redacted unless asked for (review M9).
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

/// The flag is accepted so Envoy command lines keep working, but it has no
/// effect: every drain is `immediate` (internal-docs/envoy-divergences.md,
/// "Drain strategy"). Loud on purpose, so an operator who chose `gradual`
/// learns that idle and finished connections close at drain start. Warns only
/// when the flag was given, so a default start is silent. Returns whether it
/// warned, for the unit test.
fn warn_drain_strategy_ignored(strategy: Option<DrainStrategyArg>) -> bool {
    let Some(strategy) = strategy else {
        return false;
    };
    tracing::warn!(
        drain_strategy = ?strategy,
        "--drain-strategy has no effect: `gradual` and `immediate` both behave as immediate. \
         At drain start the proxy stops accepting, closes idle keep-alive connections, and lets \
         in-flight requests finish before closing their connection (Connection: close on \
         HTTP/1, GOAWAY on HTTP/2); connections still open at --drain-time-s are cut \
         (see internal-docs/envoy-divergences.md, \"Drain strategy\")"
    );
    true
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
    warn_drain_strategy_ignored(args.drain_strategy);

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
        args.service_node,
        args.service_cluster,
        Arc::new(snapshot),
        config_source,
        args.request_records_file,
        args.request_record_max_attempts.unwrap_or(64),
        args.request_records_agent.map(|socket_path| {
            proxy_observability::capture_transport::AgentTransportConfig {
                socket_path,
                expected_agent_uid: args.request_records_agent_uid.unwrap(),
                expected_node_id: args.request_records_agent_node.unwrap(),
                producer_id: args.request_records_producer.unwrap(),
            }
        }),
        Duration::from_millis(args.capture_spool_poll_interval_ms),
    ))
}

/// How often the spool poller asks the capture agent for its counters.
const CAPTURE_SPOOL_POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Per-poll budget; a slower agent counts as unreachable for that tick.
const CAPTURE_SPOOL_POLL_DEADLINE: Duration = Duration::from_secs(2);

/// What the poller last learned about the agent, so a log line is written on a
/// change and never on every tick (AGENTS.md "Fail-open controls": suppress
/// repeats, or the log becomes the incident).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentLink {
    /// No successful or failed poll yet, or no endpoint configured.
    Unknown,
    Up,
    Down,
}

#[derive(Debug, PartialEq, Eq)]
enum LinkEvent {
    WentDown,
    Recovered,
}

/// Unknown then down still warns: an agent that was never reachable is the
/// loudest case. Unknown then up is silent because nothing changed for the
/// operator.
fn advance_link(prev: AgentLink, reachable: bool) -> (AgentLink, Option<LinkEvent>) {
    match (prev, reachable) {
        (AgentLink::Up, true) | (AgentLink::Unknown, true) => (AgentLink::Up, None),
        (AgentLink::Down, true) => (AgentLink::Up, Some(LinkEvent::Recovered)),
        (AgentLink::Down, false) => (AgentLink::Down, None),
        (AgentLink::Up, false) | (AgentLink::Unknown, false) => {
            (AgentLink::Down, Some(LinkEvent::WentDown))
        }
    }
}

/// Poller memory between ticks: reachability, plus which "agent answered but
/// gave no stats" cause was already logged (cleared when stats return).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PollState {
    link: AgentLink,
    stats_notice: Option<proxy_observability::capture_transport::InspectError>,
}

impl PollState {
    const START: Self = Self {
        link: AgentLink::Unknown,
        stats_notice: None,
    };
}

#[derive(Debug, PartialEq, Eq)]
enum NoticeEvent {
    Announce(proxy_observability::capture_transport::InspectError),
    Cleared,
}

/// Decides when to log "agent answered but gave no stats". A cause is announced
/// once; the same cause on later ticks is silent; a transport outage keeps the
/// remembered cause so a flap does not repeat it; returning stats clears it.
fn advance_stats_notice(
    prev: Option<proxy_observability::capture_transport::InspectError>,
    result: Result<(), proxy_observability::capture_transport::InspectError>,
) -> (
    Option<proxy_observability::capture_transport::InspectError>,
    Option<NoticeEvent>,
) {
    use proxy_observability::capture_transport::InspectError;
    match result {
        Ok(()) => (None, prev.map(|_| NoticeEvent::Cleared)),
        Err(InspectError::Unreachable) => (prev, None),
        Err(error) if prev == Some(error) => (prev, None),
        Err(error) => (Some(error), Some(NoticeEvent::Announce(error))),
    }
}

/// Pure core of a poll's bookkeeping. Only a transport failure moves the link
/// down: an agent that answers with a refusal or an unsupported-query close is
/// reachable (record delivery works) and gets a one-time stats notice instead.
fn advance_poll(
    state: PollState,
    result: Result<(), proxy_observability::capture_transport::InspectError>,
) -> (PollState, Option<LinkEvent>, Option<NoticeEvent>) {
    use proxy_observability::capture_transport::InspectError;
    let reachable = !matches!(result, Err(InspectError::Unreachable));
    let (link, link_event) = advance_link(state.link, reachable);
    let (stats_notice, notice_event) = advance_stats_notice(state.stats_notice, result);
    (PollState { link, stats_notice }, link_event, notice_event)
}

/// One poll: queries the agent, publishes the gauges, logs on transitions.
/// Fail-open by design: the proxy keeps serving while the agent is down; the
/// `llmproxy_capture_agent_reachable` gauge and the transition logs make that
/// visible. A transport failure is "unreachable"; an agent that answers but
/// cannot give stats (grant without `"inspect": true`, an older agent) is
/// reachable, because record delivery works, and is logged once per cause.
/// Logged errors are fixed phrases, never record contents.
async fn poll_capture_spool_once(
    stats: &proxy_observability::stats::CaptureSpoolStats,
    endpoint: Option<proxy_observability::capture_transport::AgentTransportConfig>,
    state: PollState,
) -> PollState {
    use proxy_observability::capture_transport::InspectError;
    let Some(config) = endpoint else {
        stats.publish(Err(InspectError::Unreachable));
        return PollState::START;
    };
    let result = proxy_observability::capture_transport::query_spool_stats(
        &config,
        CAPTURE_SPOOL_POLL_DEADLINE,
    )
    .await;
    stats.publish(result.as_ref().map_err(|error| *error));
    let (next, event, notice_event) =
        advance_poll(state, result.as_ref().map(|_| ()).map_err(|e| *e));
    match (event, &result) {
        (Some(LinkEvent::WentDown), Err(error)) => tracing::warn!(
            %error,
            "capture agent unreachable: spool gauges are stale and \
             llmproxy_capture_agent_reachable is 0; request handling continues"
        ),
        (Some(LinkEvent::Recovered), _) => tracing::info!("capture agent reachable again"),
        _ => {}
    }
    match notice_event {
        Some(NoticeEvent::Announce(InspectError::Unauthorized)) => tracing::info!(
            "capture agent spool stats are off: the producer grant lacks \"inspect\": true; \
             set it on the producer grant to enable them (record delivery is unaffected)"
        ),
        Some(NoticeEvent::Announce(InspectError::Unsupported)) => tracing::info!(
            "capture agent spool stats are off: the agent closed on the inspection query, so \
             it predates spool inspection; upgrade the capture agent (record delivery is \
             unaffected)"
        ),
        Some(NoticeEvent::Announce(other)) => tracing::warn!(
            error = %other,
            "capture agent answered the spool stats query with an error; spool gauges are \
             stale (record delivery is unaffected)"
        ),
        Some(NoticeEvent::Cleared) => tracing::info!("capture agent spool stats available again"),
        None => {}
    }
    next
}

async fn run_capture_spool_poller(
    stats: proxy_observability::stats::CaptureSpoolStats,
    endpoint: proxy_admin::CaptureAgentProvider,
    period: Duration,
) {
    // First poll one period after boot, so an agent that starts just after the
    // proxy does not produce a down/up log pair.
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    // A slow poll must not queue a burst of catch-up polls behind it.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut state = PollState::START;
    loop {
        ticker.tick().await;
        state = poll_capture_spool_once(&stats, endpoint(), state).await;
    }
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
    service_node: Option<String>,
    service_cluster: Option<String>,
    snapshot: Arc<ConfigSnapshot>,
    config_source: ConfigSource,
    request_records_file: Option<PathBuf>,
    request_record_max_attempts: u16,
    request_records_agent: Option<proxy_observability::capture_transport::AgentTransportConfig>,
    capture_spool_poll_interval: Duration,
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
    // Request-record capture is an independent best-effort pipeline. Resolve
    // its finite operational series even when no file collector is configured
    // so Prometheus and OTLP show explicit zeroes rather than an absent signal.
    let metadata_stats = proxy_observability::stats::MetadataDeliveryStats::resolve(&stats_control);
    let legacy_capture = request_records_file.is_some() || request_records_agent.is_some();
    if legacy_capture && snapshot.end_user_capture_configured {
        eprintln!(
            "node.metadata[\"io.llmproxy.capture\"]: cannot combine declarative and CLI capture"
        );
        return ExitCode::FAILURE;
    }
    let (capture_supervisor, capture_delivery) = if legacy_capture {
        (None, None)
    } else {
        match proxy_observability::capture::CaptureSupervisor::start(metadata_stats.clone()) {
            Ok((supervisor, delivery)) => {
                if let Err(error) =
                    supervisor.configure(snapshot.end_user_capture.clone(), concurrency)
                {
                    eprintln!("{error}");
                    let _ = delivery.shutdown(Duration::from_secs(1)).await;
                    return ExitCode::FAILURE;
                }
                (Some(supervisor), Some(delivery))
            }
            Err(error) => {
                eprintln!("cannot start capture supervisor: {error}");
                return ExitCode::FAILURE;
            }
        }
    };
    // Delivery to the capture agent's spool is experimental (review M7): the
    // agent has no reader, acknowledgement, retention or replay dedup, and
    // stops when its disk limit is reached. Say so where the operator will
    // see it; the JSONL file sink is the supported destination.
    if request_records_agent.is_some() || snapshot.end_user_capture_configured {
        tracing::warn!(
            "request capture to the llm-capture-agent spool is EXPERIMENTAL: acknowledged records \
             are never removed, there is no retention or replay deduplication, and capture stops \
             when the spool reaches its disk limit; use --request-records-file for supported delivery"
        );
    }
    let legacy_agent = request_records_agent.clone();
    let collector = match (request_records_file, request_records_agent) {
        (Some(path), None) => Some(proxy_observability::metadata::MetadataDelivery::start(
            &path,
            1024,
            metadata_stats,
        )),
        (None, Some(agent)) => Some(
            proxy_observability::metadata::MetadataDelivery::start_agent(
                agent,
                1024,
                metadata_stats,
            ),
        ),
        (None, None) => None,
        (Some(_), Some(_)) => {
            eprintln!("metadata file and agent modes are mutually exclusive");
            return ExitCode::FAILURE;
        }
    };
    let (metadata_sink, metadata_delivery) = match collector {
        Some(result) => match result {
            Ok((sink, delivery)) => (
                Some(
                    Arc::new(sink.with_max_attempts(request_record_max_attempts))
                        as Arc<dyn proxy_observability::records::RequestRecordSink>,
                ),
                Some(delivery),
            ),
            Err(err) => {
                eprintln!("cannot start metadata collector: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => (
            capture_supervisor.as_ref().map(|s| {
                Arc::new(s.clone()) as Arc<dyn proxy_observability::records::RequestRecordSink>
            }),
            None,
        ),
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

    // Metric export, spawned INDEPENDENTLY of the trace
    // exporter above. `snapshot.metrics` is a separate IR field precisely so
    // this block is reachable with `snapshot.tracing` set to `None` -- before
    // the split, a config with no `tracing` block exported no OTLP metrics at
    // all, even though the registry they are read from is always populated
    // (`docs/telemetry-design.md` §5.3). Separate task, separate ticker,
    // separate deadline, separate `Endpoint`: a slow or failing trace export
    // cannot delay a metric snapshot.
    //
    // Built and then conditionally MOVED into a task -- not built inside the
    // `if`. Resolving the failure series unconditionally is what makes
    // `llmproxy_otel_export_failures{signal="metrics"}` visible on
    // `/stats/prometheus` from the very first scrape of a process with no
    // metric export at all: a dashboard that only grows a series once something
    // has gone wrong cannot tell "zero failures" from "not instrumented", and
    // the design doc's failure matrix leans on these counters being dependable.
    // Span drops are deliberately NOT resolved here -- they are trace-path
    // facts owned by the trace exporter (see `ExportCounters`' doc), and
    // resolving them from this side is exactly the cross-domain coupling the
    // review rejected: a Prometheus-only deployment would otherwise have
    // reported zero span drops forever.
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

    // The capture agent endpoint, resolved fresh by the admin endpoints and the
    // spool poller. The CLI endpoint is fixed for the process; the declarative
    // one is read from a live config handle so a reload that moves the agent
    // is followed without a restart.
    let capture_endpoint: proxy_admin::CaptureAgentProvider = match legacy_agent.clone() {
        Some(config) => Arc::new(move || Some(config.clone())),
        None => {
            let live = snapshot_handles.register(snapshot.clone());
            Arc::new(move || {
                live.load()
                    .end_user_capture
                    .as_ref()
                    .map(|capture| capture.endpoint.clone())
            })
        }
    };

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
            capture_agent: Some(capture_endpoint.clone()),
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

    // Mirror the capture agent's spool counters into gauges. Started only when
    // an agent endpoint exists at boot; a reload that first introduces one is
    // not polled until restart (the admin endpoints do follow it).
    let capture_spool_poller = (legacy_agent.is_some() || snapshot.end_user_capture.is_some())
        .then(|| {
            tokio::spawn(run_capture_spool_poller(
                proxy_observability::stats::CaptureSpoolStats::resolve(&stats_control),
                capture_endpoint.clone(),
                capture_spool_poll_interval,
            ))
        });

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
                factory_state.clone(),
                secret_registry.clone(),
            )
        },
    );

    tracing::info!(
        workers = concurrency,
        drain_time_s = drain_time.as_secs(),
        service_node = service_node.as_deref().unwrap_or("-"),
        service_cluster = service_cluster.as_deref().unwrap_or("-"),
        listeners = %listener_summary.join(", "),
        "llm-proxy started, waiting for SIGTERM/SIGINT/SIGHUP"
    );

    // Startup gate: consume initial xDS responses before allowing workers to
    // bind. A timeout releases this gate without marking unresolved resources
    // initialized; request admission continues to distinguish warming.
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
                    ).await {
                        current_version = version;
                    }
                } else {
                    ads_apply_rx = None;
                }
            }
            _ = tokio::time::sleep(remaining) => {}
        }
    }

    // Startup gate: every worker must report a successful initial bind
    // before we consider ourselves "up". A single failed listener is fatal
    // at startup (AGENTS.md invariant 1 -- see `proxy_core::listener::initial_bind`'s
    // doc comment), so on the first failure (or a timeout) we tear the pool
    // down and exit nonzero instead of proceeding to the signal-wait loop.
    if let Err(message) = wait_for_initial_binds(&mut bind_rx, concurrency).await {
        eprintln!("{message}");
        publisher.shutdown();
        publisher.join_async().await;
        if let Some(delivery) = metadata_delivery {
            let summary = delivery.shutdown(Duration::from_secs(5)).await;
            tracing::warn!(
                ?summary,
                "metadata delivery stopped after listener startup failure"
            );
        }
        if let Some(delivery) = capture_delivery {
            let _ = delivery.shutdown(Duration::from_secs(1)).await;
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
    let mut drain_deadline: Option<Instant> = None;
    loop {
        tokio::select! {
            signal = control_signals.recv() => match signal {
                ControlSignal::Shutdown => break,
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
                        capture_supervisor.as_ref().map(|s|(s,concurrency)),
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

    // A signal that arrives before any admin drain starts the drain now; after
    // an admin drain it keeps the ORIGINAL deadline, so the window is
    // `--drain-time-s` from the first drain trigger, not from the signal.
    let deadline = match drain_deadline {
        Some(deadline) => deadline,
        None => begin_drain(&lifecycle, &publisher, drain_time, "signal"),
    };

    // Wait for every worker to report its connections gone (or the deadline),
    // while still listening for a second SIGTERM/SIGINT, which means "stop
    // waiting". Rust note: the wait future is pinned OUTSIDE the loop so a
    // SIGHUP iteration does not restart it and lose the workers that already
    // reported; the block ends its `&mut publisher` borrow.
    let drain_result = {
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

    // Capture admissions close only now, after the drain, so a request that
    // completed inside the drain window was still admitted and recorded;
    // stopping them first dropped every record from the window.
    if let Some(supervisor) = &capture_supervisor {
        supervisor.stop_admissions();
    }
    if let Some(poller) = &capture_spool_poller {
        poller.abort();
    }

    tracing::info!("drain finished: flushing capture, metadata, trace and metric exports");

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
        if let Some(delivery) = capture_delivery {
            let configured = capture_supervisor
                .as_ref()
                .map(|s| s.drain_deadline())
                .unwrap_or(Duration::from_secs(5));
            let deadline = if fast_exit {
                configured.min(fast_flush_cap)
            } else {
                configured
            };
            let timed_out = delivery.shutdown(deadline).await;
            tracing::info!(timed_out, "local capture delivery stopped");
        }
        if let Some(delivery) = metadata_delivery {
            let budget = if fast_exit {
                fast_flush_cap
            } else {
                Duration::from_secs(5)
            };
            let summary = delivery.shutdown(budget).await;
            tracing::info!(
                ?summary,
                "metadata delivery stopped; file writes do not imply durability"
            );
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

        // Ask the metric exporter for one last snapshot and WAIT
        // for it, AFTER the drain has finished -- so the final
        // cumulative figures include everything the drain period itself served, and
        // so a slow collector's deadline can never delay the drain. An earlier
        // revision fired this before the drain and was corrected in review on both
        // counts: drain-period traffic was missing from the "final" snapshot, and
        // the pre-drain await added up to one export deadline of latency to every
        // shutdown for no benefit.
        //
        // Design doc §13's other half still holds: this proves delivery of the
        // last snapshot at the collector's ACK level and nothing more, and the
        // wait is bounded (the exporter's deadline plus slack, captured at spawn)
        // so an unreachable collector cannot hang exit -- the process was already
        // done serving when this starts, so the only cost here is exit latency,
        // and it is one bounded RPC, not a reconnect loop.
        //
        // Each `send`/`await` result is deliberately ignored rather than unwrapped:
        // a closed channel or a panicked task means the exporter was already gone
        // (or never started), and there is no useful recovery for either at this
        // point in shutdown. The proxy is exiting; a missing final metric snapshot
        // must not change its exit behavior.
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
    trigger: &str,
) -> Instant {
    lifecycle.request_drain();
    let deadline = publisher.start_drain(drain_time);
    tracing::info!(
        trigger,
        drain_time_s = drain_time.as_secs(),
        "drain started: /ready now answers DRAINING, listeners are closing, idle connections \
         close now, in-flight requests may finish until the deadline"
    );
    deadline
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
///
/// It carries the clusters the new snapshot dropped, which stay installed
/// until [`retire_clusters`] runs (review M5: removal is two-phase).
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

/// Applies an already-built [`ConfigSnapshot`] to every piece of running
/// state, in the one order that is safe. This is the shared apply path:
/// `reload` below (the SIGHUP producer) is the first
/// caller, and the ADS client -- the *second* producer of `Arc<ConfigSnapshot>`,
/// landing next -- calls this SAME function rather than reaching around it to
/// publish on its own.
///
/// Order of operations, and why -- unchanged from what used to be inline in
/// `reload`, just no longer duplicated for a second caller.
///
/// Before any step, [`proxy_cluster::manager::ClusterManager::stage`] builds
/// the snapshot's new and changed clusters without installing them. A
/// cluster it rejects (unimplemented `lb_policy`, a bad `transport_socket`,
/// ...) is handled per `on_rejection`: [`OnClusterRejection::RefuseSnapshot`]
/// returns `Err` with nothing touched (the ADS caller NACKs, review H1);
/// [`OnClusterRejection::LeaveOut`] applies the rest (`reload` logs).
///
/// 0.[`proxy_observability::stats::StatsControl::set_live_scope`] with the
///    snapshot's cluster and listener names, so series of removed ones stop
///    being emitted and stop counting against their caps, and series absent
///    from this snapshot and the previous one are drained for reuse. The
///    grace period is one published snapshot, not a span of time: the xDS
///    applier publishes only when the listener, cluster or route set changed
///    (`proxy_xds::apply::same_published_resources`), so heartbeats, EDS
///    updates and re-sent identical resources never count toward it.
/// 1. [`proxy_http::stat_handles::StatHandles::resolve_missing`] over the
///    cluster keys, so a cluster this table has never seen has a handle
///    resolved *before* traffic can possibly reach it, and an entry step 0
///    drained is dropped or re-resolved. Steps 2 and 3 do the same.
/// 2. [`proxy_http::stat_handles::DownstreamStatHandles::resolve_missing`]
///    over the listener keys, so a listener this snapshot introduces has a
///    `downstream_cx_total` handle resolved before its accept loop can
///    possibly see a connection.
/// 3. [`proxy_http::stat_handles::TokenUsageStatHandles::resolve_missing`]
///    over the cluster keys, so a cluster this snapshot introduces has its
///    four `llm.client.token.usage` handles resolved before it can dial its
///    first request.
/// 4. [`proxy_cluster::manager::ClusterManager::install`] so the shared
///    cluster manager every worker's router reads through picks up added and
///    changed clusters. Clusters the snapshot dropped stay installed.
/// 5. [`proxy_core::runtime::ConfigPublisher::publish`]: this is what
///    makes the snapshot visible to workers (via each worker's `config_ping`
///    -> `reconcile`, already covered by `proxy-core`'s own tests), so it must
///    not run until step 4 has already taught the cluster manager about every
///    cluster the new snapshot's routes can reach -- otherwise a worker could
///    start routing to a cluster the manager doesn't know about yet.
/// 6. [`proxy_cluster::manager::ClusterManager::retire`], LAST: removes the
///    dropped clusters only once workers have the snapshot whose routes no
///    longer reach them (make-before-break, review M5).
///
/// **The ordering of steps 4, 5 and 6 is enforced by the TYPE SYSTEM, not by
/// a test, and that is a deliberate choice made after two measured failures.**
///
/// First (2026-09-06) a plain mutation showed no unit test caught a
/// reordering. Then an end-to-end test was written for exactly this -- boot
/// the binary, have a control plane introduce a cluster, drive real traffic --
/// and a mutation showed *it did not catch the reordering either*
/// (`tests/ads_e2e.rs`, see its module doc). The reason is structural: the
/// damage window is the microseconds between `publish` storing the snapshot
/// and `update_from_snapshot` storing the cluster map, which it does
/// synchronously before it resolves each new cluster's discovery. No
/// black-box observer can reliably land inside it, and AGENTS.md "Build And Test"'s
/// lesson is that an instrument which lies is worse than none.
///
/// So the order is a compile-time property instead: [`install_clusters`]
/// returns a [`ClustersInstalled`] receipt that [`publish_to_workers`]
/// requires by value, and [`publish_to_workers`] returns the
/// [`SnapshotPublished`] receipt [`retire_clusters`] requires. Reordering the
/// statements below does not typecheck -- a receipt would be used before it
/// exists. That is a stronger guarantee than the test that could not be
/// written.
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
async fn apply_ads_snapshot(
    mut snapshot: ConfigSnapshot,
    reply: oneshot::Sender<Result<(), String>>,
    current_version: SnapshotVersion,
    publisher: &proxy_core::runtime::ConfigPublisher,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    stats_control: &proxy_observability::stats::StatsControl,
    tables: &StatHandleTables,
) -> Option<SnapshotVersion> {
    // Rust note: authoritative version stamping happens HERE, not inside
    // `ResourceApplier`. Two producers stamp a version: `reload` (SIGHUP) does
    // the same overwrite before its own `apply_snapshot` call;
    // `ResourceApplier::assemble_snapshot`'s internal version is advisory
    // only and is discarded here.
    snapshot.version = SnapshotVersion(current_version.0 + 1);
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
async fn reload(
    source: &ConfigSource,
    current_version: SnapshotVersion,
    publisher: &proxy_core::runtime::ConfigPublisher,
    cluster_manager: &Arc<proxy_cluster::manager::ClusterManager>,
    stats_control: &proxy_observability::stats::StatsControl,
    tables: &StatHandleTables,
    capture: Option<(&proxy_observability::capture::CaptureSupervisor, usize)>,
) -> Option<SnapshotVersion> {
    let mut snapshot = match source.load() {
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
    if let Some((capture, concurrency)) = capture {
        if let Err(error) = capture.configure(snapshot.end_user_capture.clone(), concurrency) {
            tracing::error!(%error,"SIGHUP: capture reload rejected; retaining previous snapshot");
            return None;
        }
    } else if snapshot.end_user_capture_configured {
        tracing::error!(
            "node.metadata[\"io.llmproxy.capture\"]: cannot combine declarative and CLI capture"
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

/// Builds and spawns the dynamic-resource client tasks when `snapshot.ads`
/// asks for one. Sources may be ADS, filesystem, or a mixture of both.
///
/// Returns `None` -- and starts nothing -- in three cases, none of them
/// fatal to `run_serve` (architecture.md §12.2 rule 5: keep serving last-good/static config):
/// - `snapshot.ads` is `None`: no `dynamic_resources` in bootstrap, today's
///   behavior for every release through v0.2.0, untouched by this wiring.
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
            await_apply_reply(reply_rx).await
        })
    });

    // An accepted EDS endpoint update goes straight
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

    // An accepted SDS secret goes straight to
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

/// Starts the read-only admin server (`proxy-admin`) when
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
/// in `run_serve` itself, because the workers need the exact same registry,
/// not a second, disconnected one. `/stats` reports real `upstream_rq`/`upstream_rq_time`
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
    capture_agent: Option<proxy_admin::CaptureAgentProvider>,
}

async fn start_admin(
    admin: Option<SocketAddr>,
    runtime: AdminStartRuntime<'_>,
) -> Result<Option<proxy_admin::AdminServer>, String> {
    let Some(addr) = admin else {
        return Ok(None);
    };
    let config = runtime.snapshot_handles.register(runtime.snapshot);
    let admin_token = std::env::var(ADMIN_TOKEN_ENV_VAR).ok();
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
            capture_agent: runtime.capture_agent,
        },
    )
    .await
    .map_err(|err| err.to_string())?;
    Ok(Some(server))
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
    // This worker's clone of the ONE per-serve
    // `SharedFactoryState` -- see `run_serve`'s own comment on the Arc this
    // is cloned from.
    factory_state: Arc<proxy_http::filter::SharedFactoryState>,
    // This worker's clone of the ONE per-serve
    // `SdsSecretRegistry` -- see `run_serve`'s own comment on the Arc this is
    // cloned from.
    secret_registry: Arc<SdsSecretRegistry>,
) {
    startup_gate.wait().await;
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

    #[test]
    fn agent_link_logs_only_on_transitions() {
        use super::{advance_link as step, AgentLink::*, LinkEvent::*};
        assert_eq!(step(Unknown, false), (Down, Some(WentDown)));
        assert_eq!(step(Unknown, true), (Up, None));
        assert_eq!(step(Up, false), (Down, Some(WentDown)));
        assert_eq!(step(Down, false), (Down, None), "repeats are suppressed");
        assert_eq!(step(Down, true), (Up, Some(Recovered)));
        assert_eq!(step(Up, true), (Up, None));
    }

    #[test]
    fn an_answering_agent_without_stats_is_reachable_and_noticed_once() {
        use super::{advance_poll as step, AgentLink, NoticeEvent, PollState};
        use proxy_observability::capture_transport::InspectError::*;
        let up = PollState {
            link: AgentLink::Up,
            stats_notice: None,
        };
        for cause in [Unauthorized, Unsupported] {
            let (state, link_event, notice) = step(up, Err(cause));
            assert_eq!(state.link, AgentLink::Up, "{cause:?} must not read as down");
            assert_eq!(link_event, None, "{cause:?} must not warn about an outage");
            assert_eq!(notice, Some(NoticeEvent::Announce(cause)));
            let (again, link_event, notice) = step(state, Err(cause));
            assert_eq!((again, link_event, notice), (state, None, None));
        }
        let (down, link_event, _) = step(up, Err(Unreachable));
        assert_eq!(down.link, AgentLink::Down);
        assert_eq!(link_event, Some(super::LinkEvent::WentDown));
    }

    #[test]
    fn stats_notice_is_logged_once_per_cause() {
        use super::{advance_stats_notice as step, NoticeEvent::*};
        use proxy_observability::capture_transport::InspectError::*;
        assert_eq!(
            step(None, Err(Unauthorized)),
            (Some(Unauthorized), Some(Announce(Unauthorized)))
        );
        assert_eq!(
            step(Some(Unauthorized), Err(Unauthorized)),
            (Some(Unauthorized), None)
        );
        assert_eq!(
            step(Some(Unauthorized), Err(Unreachable)),
            (Some(Unauthorized), None)
        );
        assert_eq!(step(None, Err(Unreachable)), (None, None));
        assert_eq!(
            step(Some(Unauthorized), Err(Unsupported)),
            (Some(Unsupported), Some(Announce(Unsupported)))
        );
        assert_eq!(step(Some(Unsupported), Ok(())), (None, Some(Cleared)));
        assert_eq!(step(None, Ok(())), (None, None));
    }

    #[tokio::test]
    async fn spool_poll_of_an_absent_agent_marks_it_unreachable_and_warns_once() {
        let control = proxy_observability::stats::StatsControl::new(1);
        let stats = proxy_observability::stats::CaptureSpoolStats::resolve(&control);
        let dir = tempfile::tempdir().unwrap();
        let endpoint = proxy_observability::capture_transport::AgentTransportConfig {
            socket_path: dir.path().join("absent.sock"),
            expected_agent_uid: 0,
            expected_node_id: "node".into(),
            producer_id: "proxy".into(),
        };
        let link = tokio::time::timeout(
            Duration::from_secs(10),
            super::poll_capture_spool_once(
                &stats,
                Some(endpoint),
                super::PollState {
                    link: super::AgentLink::Up,
                    stats_notice: None,
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(link.link, super::AgentLink::Down);
        let scrape = proxy_observability::stats::prometheus_render::render(&control.registry());
        assert!(
            scrape.contains("envoy_llmproxy_capture_agent_reachable 0")
                && scrape.contains("envoy_llmproxy_capture_spool_stats_available 0"),
            "{scrape}"
        );
    }
    use super::*;

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
                capture_agent: None,
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
                capture_agent: None,
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
                capture_agent: None,
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
            request_records_agent: None,
            request_records_agent_uid: None,
            request_records_agent_node: None,
            request_records_producer: None,
            request_record_max_attempts: None,
            capture_spool_poll_interval_ms: 10_000,
            drain_time_s: proxy_core::drain::DEFAULT_DRAIN_TIME.as_secs(),
            drain_strategy: None,
            base_id: None,
            log_level: LogLevel::Info,
            service_node: None,
            service_cluster: None,
        }
    }

    #[test]
    fn drain_strategy_is_none_without_the_flag_and_some_with_it() {
        let none = Args::try_parse_from(["llm-proxy", "-c", "x.yaml"]).expect("parses");
        assert_eq!(none.drain_strategy, None);
        assert!(!warn_drain_strategy_ignored(none.drain_strategy));

        let some =
            Args::try_parse_from(["llm-proxy", "-c", "x.yaml", "--drain-strategy", "gradual"])
                .expect("parses");
        assert_eq!(some.drain_strategy, Some(DrainStrategyArg::Gradual));
        assert!(warn_drain_strategy_ignored(some.drain_strategy));
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
