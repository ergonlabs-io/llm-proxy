//! `mock-upstream`: the standalone mock LLM provider binary. See the
//! `mockupstream` crate doc (`src/lib.rs`) for why this exists as its own
//! process instead of reusing `testing/diffrig`'s in-process mocks.
//!
//! This file is deliberately thin: CLI parsing, binding the listener, and
//! picking a downstream protocol builder per connection. Everything that
//! decides what a request gets back lives in `mockupstream::handler` and
//! `mockupstream::frames`.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

use mockupstream::frames::StreamConfig;
use mockupstream::handler::{self, AppState};
use mockupstream::profiles::{Dist, Profile, ProfileFile, ProfileSet, DEFAULT_PROFILE};
use mockupstream::stats;

/// Which downstream HTTP protocol builder to use for every accepted
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Protocol {
    Http1,
    Http2,
    /// h2 prior-knowledge detection over plaintext (h2c), falling back to
    /// http/1.1 -- see `serve` below. This is the point of `--protocol`:
    /// the proxy dials plaintext h2c whenever a cluster sets
    /// `http2_protocol_options`, and this mock needs to answer that the
    /// same way a real provider's load balancer would.
    Auto,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Protocol::Http1 => "http1",
            Protocol::Http2 => "http2",
            Protocol::Auto => "auto",
        };
        f.write_str(s)
    }
}

/// A lean, standalone mock LLM provider for capacity/load testing.
/// Speaks the OpenAI Chat Completions and Anthropic Messages wire shapes,
/// streaming and non-streaming, with configurable per-token timing.
#[derive(Parser)]
#[command(name = "mock-upstream")]
struct Cli {
    /// Address to bind. Defaults to an ephemeral loopback port; the actual
    /// bound port is printed on the first stdout line (see `main`'s doc).
    #[arg(long, default_value = "127.0.0.1:0")]
    listen: String,

    /// Downstream HTTP protocol. `auto` detects h2c prior-knowledge over
    /// plaintext and falls back to http/1.1; `http1`/`http2` force one.
    #[arg(long, value_enum, default_value_t = Protocol::Auto)]
    protocol: Protocol,

    /// Fixed TTFT, in ms, for the `default` profile -- the response shape
    /// used when a request's `model` names none of the built-in or
    /// `--profiles`-file profiles (see `mockupstream::profiles`). Every
    /// *named* profile (`mock-fast-short`/`mock-medium`/`mock-slow-long`)
    /// draws its own TTFT from its own range regardless of this flag.
    #[arg(long = "ttft-ms", default_value_t = 0)]
    ttft_ms: u64,

    /// Fixed inter-token delay, in ms, for the `default` profile. See
    /// `--ttft-ms`.
    #[arg(long = "inter-token-ms", default_value_t = 0)]
    inter_token_ms: u64,

    /// Fixed streamed content-chunk count (and reported `output_tokens`)
    /// for the `default` profile. See `--ttft-ms`.
    #[arg(long, default_value_t = 16)]
    tokens: u32,

    /// Reported input token count -- shared by every profile; only output
    /// length/timing vary per profile.
    #[arg(long = "prompt-tokens", default_value_t = 10)]
    prompt_tokens: u32,

    /// Optional JSON file of named profiles to add to (or override in,
    /// including `"default"`) the built-in `mock-fast-short`/`mock-medium`/
    /// `mock-slow-long` set. See `mockupstream::profiles::ProfileFile`.
    #[arg(long = "profiles")]
    profiles: Option<std::path::PathBuf>,

    /// Print served-request counters to stderr on this interval, in
    /// seconds. 0 (the default) disables the printer.
    #[arg(long = "stats-interval-secs", default_value_t = 0)]
    stats_interval_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let addr: SocketAddr = cli
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --listen {:?}: {e}", cli.listen))?;
    let listener = TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;

    // The driver script that spawns this process reads the port off this
    // exact line, so it must be the *first* stdout line and must be
    // flushed before we start serving -- an `eprintln!`/log line racing
    // ahead of it, or output sitting in a buffer, would make the driver
    // block forever waiting for a port that already exists.
    println!(
        "mock-upstream listening on {local_addr} protocol={}",
        cli.protocol
    );
    std::io::stdout().flush()?;

    let cfg = StreamConfig {
        prompt_tokens: cli.prompt_tokens,
    };
    let default_profile = Profile {
        name: DEFAULT_PROFILE.to_string(),
        ttft_ms: Dist::fixed(cli.ttft_ms),
        inter_token_ms: Dist::fixed(cli.inter_token_ms),
        length: Dist::fixed(cli.tokens as u64),
    };
    let mut profiles = ProfileSet::with_builtins(default_profile);
    if let Some(path) = &cli.profiles {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading --profiles {path:?}: {e}"))?;
        let file: ProfileFile = serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("parsing --profiles {path:?}: {e}"))?;
        profiles.merge_file(file);
    }
    let state = Arc::new(AppState::new(cfg, profiles));
    stats::spawn_printer(
        state.stats.clone(),
        Duration::from_secs(cli.stats_interval_secs),
    );

    loop {
        let (stream, _peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();
        let protocol = cli.protocol;
        // Rust note: multi-threaded tokio (the crate doc's runtime
        // requirement), so this task can land on any worker thread -- no
        // `spawn_local`/`LocalSet` needed anywhere in this crate, unlike
        // `proxy-http`'s downstream codec (see its module doc), because our
        // response bodies never need to be `!Send`.
        tokio::spawn(serve(io, state, protocol));
    }
}

/// Drive one accepted connection to completion. A connection-level error
/// (a client disconnecting mid-request, a malformed frame) is logged and
/// dropped -- it ends that one connection, not the process.
async fn serve(io: TokioIo<tokio::net::TcpStream>, state: Arc<AppState>, protocol: Protocol) {
    // Rust note: `service_fn` needs an `Fn`, since hyper calls it once per
    // request and a connection may carry many requests (h1 keep-alive, h2
    // multiplexing). The closure only ever *borrows* `state` (via
    // `Arc::clone`) rather than consuming it, which is what makes it `Fn`
    // instead of `FnOnce`.
    let service = service_fn(move |req| {
        let state = Arc::clone(&state);
        async move { Ok::<_, std::convert::Infallible>(handler::handle(req, state).await) }
    });

    let result = match protocol {
        Protocol::Http1 => hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await
            .map_err(|e| e.to_string()),
        Protocol::Http2 => hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await
            .map_err(|e| e.to_string()),
        Protocol::Auto => {
            // Rust note: `auto::Builder` peeks the first bytes off the wire
            // for HTTP/2's connection preface before deciding which codec
            // to hand the connection to -- that's how it tells h2c
            // prior-knowledge apart from plaintext http/1.1 without either
            // side sending an `Upgrade` header. `TokioExecutor` is what lets
            // it spawn each h2 stream as its own task the same way
            // `hyper::server::conn::http2::Builder` does directly above.
            auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, service)
                .await
                .map_err(|e| e.to_string())
        }
    };
    if let Err(err) = result {
        eprintln!("mock-upstream: connection error: {err}");
    }
}
