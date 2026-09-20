//! Scenario request replay for WP-26.
//!
//! The process topology is owned by the caller (Docker Envoy and llm-proxy
//! can be started independently), while this module guarantees that each
//! scripted request is sent to both targets in the same order and compared
//! through the shared capture model.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::access_log_diff::{compare_captures, normalize_json_line, HttpCapture};
use crate::harness::send_json_optional;
use crate::scenario::{Scenario, ScriptedRequest};

/// Replay every request in a scenario against two already-running targets.
pub async fn replay_scenario(
    scenario: &Scenario,
    left: SocketAddr,
    right: SocketAddr,
    left_log: Option<&Path>,
    right_log: Option<&Path>,
) -> Result<(), ReplayError> {
    for (index, request) in scenario.requests.iter().enumerate() {
        let left_capture = capture_request(left, request, left_log, index).await;
        let right_capture = capture_request(right, request, right_log, index).await;
        compare_captures(&left_capture, &right_capture).map_err(|source| {
            ReplayError::Mismatch {
                request_index: index,
                source,
            }
        })?;
    }
    Ok(())
}

/// Run a scenario while owning both target processes. The Envoy container uses
/// published-port networking so the caller's scenario can name each listener.
pub async fn replay_managed(
    scenario: &Scenario,
    config: &ManagedReplayConfig,
) -> Result<(), ReplayError> {
    let _proxy = ManagedTarget::proxy(&config.proxy_bin, &config.proxy_config, &config.proxy_log)?;
    let _envoy = ManagedTarget::envoy(
        &config.envoy_image,
        &config.envoy_config,
        &config.envoy_log,
        config.right.port(),
    )?;
    wait_until_ready(config.left, &config.proxy_log)?;
    wait_until_ready(config.right, &config.envoy_log)?;
    // The readiness probe only proves one listener socket accepted a connect;
    // give all worker threads and Envoy's listener workers a short settling
    // window before the first replay request.
    tokio::time::sleep(Duration::from_millis(100)).await;
    replay_scenario(
        scenario,
        config.left,
        config.right,
        Some(&config.proxy_log),
        Some(&config.envoy_log),
    )
    .await
}

/// Process and endpoint configuration for a managed replay.
pub struct ManagedReplayConfig {
    pub proxy_bin: std::path::PathBuf,
    pub proxy_config: std::path::PathBuf,
    pub envoy_image: String,
    pub envoy_config: std::path::PathBuf,
    pub left: SocketAddr,
    pub right: SocketAddr,
    pub proxy_log: std::path::PathBuf,
    pub envoy_log: std::path::PathBuf,
}

struct ManagedTarget {
    child: Child,
}

impl ManagedTarget {
    fn proxy(bin: &Path, config: &Path, log: &Path) -> Result<Self, ReplayError> {
        let out = std::fs::File::create(log).map_err(|source| ReplayError::Io {
            action: "create proxy log",
            source,
        })?;
        let err = out.try_clone().map_err(|source| ReplayError::Io {
            action: "clone proxy log",
            source,
        })?;
        let child = Command::new(bin)
            .args(["-c", &config.to_string_lossy()])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .map_err(|source| ReplayError::Spawn {
                target: "llm-proxy",
                source,
            })?;
        Ok(Self { child })
    }

    fn envoy(
        image: &str,
        config: &Path,
        log: &Path,
        listener_port: u16,
    ) -> Result<Self, ReplayError> {
        let out = std::fs::File::create(log).map_err(|source| ReplayError::Io {
            action: "create Envoy log",
            source,
        })?;
        let err = out.try_clone().map_err(|source| ReplayError::Io {
            action: "clone Envoy log",
            source,
        })?;
        let config = std::fs::canonicalize(config).map_err(|source| ReplayError::Io {
            action: "resolve Envoy bootstrap path",
            source,
        })?;
        let mount = format!("{}:/etc/envoy/bootstrap.yaml:ro", config.display());
        let child = Command::new("docker")
            .args([
                "run",
                "--rm",
                "-p",
                &format!("{listener_port}:{listener_port}"),
                "--add-host",
                "host.docker.internal:host-gateway",
                "-v",
                &mount,
                image,
                "-c",
                "/etc/envoy/bootstrap.yaml",
            ])
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .map_err(|source| ReplayError::Spawn {
                target: "Envoy",
                source,
            })?;
        Ok(Self { child })
    }
}

impl Drop for ManagedTarget {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_until_ready(address: SocketAddr, log: &Path) -> Result<(), ReplayError> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(ReplayError::NotReady {
        address,
        log: std::fs::read_to_string(log).unwrap_or_default(),
    })
}

async fn capture_request(
    address: SocketAddr,
    request: &ScriptedRequest,
    access_log: Option<&Path>,
    request_index: usize,
) -> HttpCapture {
    let body = request
        .body
        .as_deref()
        .and_then(|body| serde_json::from_str(body).ok());
    let mut owned_headers: Vec<(String, String)> = request
        .headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect();
    if !owned_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        owned_headers.push((String::from("host"), String::from("replay.local")));
    }
    let headers: Vec<(&str, &str)> = owned_headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let response = send_json_optional(
        address,
        &request.method,
        &request.path,
        &headers,
        body.as_ref(),
    )
    .await;
    let response_headers = response
        .headers
        .into_iter()
        .filter(|(name, _)| !matches!(name.to_ascii_lowercase().as_str(), "date" | "server"))
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect::<BTreeMap<_, _>>();
    let access_log = access_log.and_then(|path| {
        let lines = std::fs::read_to_string(path).ok()?;
        lines
            .lines()
            .filter(|line| !line.trim().is_empty())
            .nth(request_index)
            .and_then(|line| {
                normalize_json_line(line, crate::access_log_diff::DEFAULT_VOLATILE_FIELDS).ok()
            })
    });
    HttpCapture {
        status: response.status,
        headers: response_headers,
        body: response.body,
        access_log,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("request {request_index} differs: {source}")]
    Mismatch {
        request_index: usize,
        source: crate::access_log_diff::CaptureDiff,
    },
    #[error("failed to spawn {target}: {source}")]
    Spawn {
        target: &'static str,
        source: std::io::Error,
    },
    #[error("failed to {action}: {source}")]
    Io {
        action: &'static str,
        source: std::io::Error,
    },
    #[error("target at {address} did not become ready; log: {log}")]
    NotReady { address: SocketAddr, log: String },
}
