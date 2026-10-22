//! ADR-0016 decision 1, against real Envoy: one bootstrap with a weighted
//! route, `use_hash_policy: true` and a header `hash_policy` over two plain
//! upstream clusters, run by the pinned Envoy v1.38 image and by llm-proxy in
//! Envoy mode. Both share the upstreams and the route table (same members,
//! order and weights), so the comparison is purely the pick: for every
//! session value, both must dial the same upstream.
//!
//! Docker is explicit, as in `ext_authz_e2e.rs`: `#[ignore]`d, run with
//! `cargo test -p diffrig --test session_affinity_envoy_diff -- --ignored`.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, ProxyProcess, ScratchDir, READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::json;

const ENVOY: &str =
    "envoyproxy/envoy@sha256:8146b97ee61a42cd216514709e4e3198af75f014974e3d9f310aef9c901fcbdf";

struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        if std::thread::panicking() {
            if let Ok(logs) = std::process::Command::new("docker")
                .args(["logs", &self.0])
                .output()
            {
                eprintln!(
                    "container logs: {}{}",
                    String::from_utf8_lossy(&logs.stdout),
                    String::from_utf8_lossy(&logs.stderr)
                );
            }
        }
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.0])
            .output();
    }
}

fn bootstrap(
    listen_address: &str,
    listen_port: u16,
    upstream_host: &str,
    ports: [u16; 2],
    dns: &str,
) -> String {
    let cluster = |name: &str, port: u16| {
        format!(
            r#"
    - name: {name}
      type: {dns}
      connect_timeout: 1s
      load_assignment:
        cluster_name: {name}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_host}, port_value: {port} }}"#
        )
    };
    format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: {listen_address}, port_value: {listen_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: http
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: rc
                  virtual_hosts:
                    - name: vh
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route:
                            timeout: 5s
                            hash_policy: [{{ header: {{ header_name: x-session-affinity }} }}]
                            weighted_clusters:
                              use_hash_policy: true
                              clusters:
                                - {{ name: a, weight: 3 }}
                                - {{ name: b, weight: 2 }}
  clusters:{}{}
"#,
        cluster("a", ports[0]),
        cluster("b", ports[1]),
    )
}

/// Docker's port forward accepts TCP before Envoy listens, so readiness is
/// Envoy's own log line, as in `ext_authz_e2e.rs`.
async fn wait_for_envoy(container: &str) {
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let logs = std::process::Command::new("docker")
                .args(["logs", container])
                .output()
                .unwrap();
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&logs.stdout),
                String::from_utf8_lossy(&logs.stderr)
            );
            if text.contains("starting main dispatch loop") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("Envoy did not start");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker and the pinned Envoy image"]
async fn envoy_v138_and_llm_proxy_pick_the_same_member_per_session() {
    let upstream = |text: &str| OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: text.to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: None,
        forced_error: None,
        cached_tokens: 0,
    };
    let a = OpenAiUpstream::spawn(upstream("a")).await.unwrap();
    let b = OpenAiUpstream::spawn(upstream("b")).await.unwrap();
    let ports = [a.port(), b.port()];
    let scratch = ScratchDir::new("affinity-envoy-diff");

    let ours_port = free_port();
    let ours_config = scratch.write(
        "ours.yaml",
        &bootstrap("127.0.0.1", ours_port, "127.0.0.1", ports, "STATIC"),
    );
    let mut ours = ProxyProcess::spawn_envoy(
        &resolve_llm_proxy_bin(),
        &ours_config,
        &scratch.path().join("ours.log"),
    );
    let ours_addr = format!("127.0.0.1:{ours_port}").parse().unwrap();
    ours.wait_until_ready(ours_addr, READY_TIMEOUT);

    let envoy_port = free_port();
    let envoy_config = scratch.write(
        "envoy.yaml",
        &bootstrap(
            "0.0.0.0",
            envoy_port,
            "host.docker.internal",
            ports,
            "STRICT_DNS",
        ),
    );
    let output = std::process::Command::new("docker")
        .args([
            "run".to_string(),
            "-d".to_string(),
            "--add-host".to_string(),
            "host.docker.internal:host-gateway".to_string(),
            "-p".to_string(),
            format!("127.0.0.1:{envoy_port}:{envoy_port}"),
            "-v".to_string(),
            format!("{}:/etc/envoy/bootstrap.yaml:ro", envoy_config.display()),
            ENVOY.to_string(),
            "-c".to_string(),
            "/etc/envoy/bootstrap.yaml".to_string(),
            "--concurrency".to_string(),
            "1".to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let _envoy = Container(String::from_utf8(output.stdout).unwrap().trim().to_owned());
    let envoy_addr = format!("127.0.0.1:{envoy_port}").parse().unwrap();
    wait_for_envoy(&_envoy.0).await;

    // Which upstream served one request through `addr`, read from the
    // upstreams' own logs rather than from either proxy.
    let dialled = |addr, session: String| {
        let (a, b) = (&a, &b);
        async move {
            let before = (a.log.requests().len(), b.log.requests().len());
            let res = tokio::time::timeout(
                Duration::from_secs(10),
                send_json(
                    addr,
                    "POST",
                    "/v1/chat/completions",
                    &[("host", "affinity"), ("x-session-affinity", session.as_str())],
                    &json!({ "model": "gpt-mock", "messages": [{ "role": "user", "content": "hi" }] }),
                ),
            )
            .await
            .expect("request timed out");
            assert_eq!(res.status, 200, "{session}: {}", res.body);
            let after = (a.log.requests().len(), b.log.requests().len());
            match (after.0 - before.0, after.1 - before.1) {
                (1, 0) => "a",
                (0, 1) => "b",
                other => panic!("{session}: one request dialled {other:?}"),
            }
        }
    };

    // Envoy may answer 503 for a moment while STRICT_DNS resolves.
    let mut last = (0, String::new());
    let probe = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let res = send_json(
                envoy_addr,
                "POST",
                "/v1/chat/completions",
                &[("host", "affinity")],
                &json!({ "model": "gpt-mock", "messages": [{ "role": "user", "content": "hi" }] }),
            )
            .await;
            last = (res.status, format!("{:?} {}", res.headers, res.body));
            if res.status == 200 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(
        probe.is_ok(),
        "Envoy never reached the upstreams; last answer {last:?}"
    );

    let mut members = std::collections::BTreeSet::new();
    for i in 0..40 {
        let session = format!("conversation-{i}");
        let theirs = dialled(envoy_addr, session.clone()).await;
        let ours_pick = dialled(ours_addr, session.clone()).await;
        assert_eq!(ours_pick, theirs, "{session}");
        members.insert(theirs);
    }
    assert_eq!(members.len(), 2, "both members were picked");

    drop(ours);
    a.shutdown().await;
    b.shutdown().await;
}
