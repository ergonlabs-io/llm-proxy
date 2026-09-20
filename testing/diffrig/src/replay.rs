//! Scenario request replay for WP-26.
//!
//! The process topology is owned by the caller (Docker Envoy and llm-proxy
//! can be started independently), while this module guarantees that each
//! scripted request is sent to both targets in the same order and compared
//! through the shared capture model.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;

use crate::access_log_diff::{compare_captures, normalize_json_line, HttpCapture};
use crate::harness::send_json;
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

async fn capture_request(
    address: SocketAddr,
    request: &ScriptedRequest,
    access_log: Option<&Path>,
    request_index: usize,
) -> HttpCapture {
    let body = request
        .body
        .as_deref()
        .and_then(|body| serde_json::from_str(body).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    let headers: Vec<(&str, &str)> = request
        .headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    let response = send_json(address, &request.method, &request.path, &headers, &body).await;
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
}
