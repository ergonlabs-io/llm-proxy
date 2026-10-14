use clap::Parser;
use proxy_capture_agent::{config::Config, Agent};
use std::{path::PathBuf, process::ExitCode, sync::atomic::Ordering};

#[derive(Parser)]
struct Args {
    /// Strict JSON deployment configuration. No backend or transcript support.
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let args = Args::parse();
    let config = match Config::load(&args.config) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("invalid capture agent configuration: {error}");
            return ExitCode::FAILURE;
        }
    };
    eprintln!(
        "warning: llm-capture-agent is EXPERIMENTAL: acknowledged records are never removed, \
         there is no retention or replay deduplication, and capture stops when the spool \
         reaches its disk limit"
    );
    let agent = match Agent::start(config) {
        Ok(agent) => agent,
        Err(error) => {
            eprintln!("cannot start capture agent: {error}");
            return ExitCode::FAILURE;
        }
    };
    let health = agent.health.clone();
    let result = agent
        .run(async {
            #[cfg(unix)]
            {
                if let Ok(mut term) =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                {
                    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
                    return;
                }
            }
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    eprintln!(
        "metadata agent: durable={}, rejected={}, failures={}",
        health.durable.load(Ordering::Relaxed),
        health.rejected.load(Ordering::Relaxed),
        health.failures.load(Ordering::Relaxed)
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("capture agent stopped: {error}");
            ExitCode::FAILURE
        }
    }
}
