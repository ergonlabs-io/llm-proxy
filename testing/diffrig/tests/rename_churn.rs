//! WP-21 acceptance drill: repeated listener and cluster renames while the
//! real proxy carries an open-loop 5,000 request/second stream.
//!
//! Every bootstrap is an ordinary Envoy-mode document (the same shape used by
//! the Envoy config validator). The route target and listener name change on
//! each SIGHUP, while the listener socket stays fixed. A deliberately invalid
//! generation is also attempted; the previous good generation must continue
//! serving instead of turning the request path into a 5xx storm.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use diffrig::harness::{free_port, resolve_llm_proxy_bin, ScratchDir};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use loadgen::dialect::Endpoint;
use loadgen::driver::{
    run_closed_loop, run_open_loop, DownstreamMode, RunConfig, Target, TransportConfig,
};

const RATE: f64 = 5_000.0;
const LOAD_DURATION: Duration = Duration::from_secs(3);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CHURN_INTERVAL: Duration = Duration::from_millis(250);

fn envoy_config(
    listener_port: u16,
    listener_name: &str,
    cluster_name: &str,
    upstream: SocketAddr,
) -> String {
    format!(
        r#"static_resources:
  listeners:
    - name: {listener_name}
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: {listener_name}
                route_config:
                  name: route-{listener_name}
                  virtual_hosts:
                    - name: vhost-{listener_name}
                      domains: ["*"]
                      routes:
                        - match: {{ prefix: "/" }}
                          route: {{ cluster: {cluster_name} }}
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
  clusters:
    - name: {cluster_name}
      type: STATIC
      connect_timeout: 1s
      load_assignment:
        cluster_name: {cluster_name}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
        upstream_ip = upstream.ip(),
        upstream_port = upstream.port(),
    )
}

struct RunningProxy {
    child: Child,
}

impl RunningProxy {
    fn spawn(bin: &Path, config: &Path, log: &Path, listener: SocketAddr) -> Self {
        let output = std::fs::File::create(log).expect("create proxy log");
        let error = output.try_clone().expect("clone proxy log");
        let child = Command::new(bin)
            .args(["-c", config.to_str().expect("config path")])
            .stdout(Stdio::from(output))
            .stderr(Stdio::from(error))
            .spawn()
            .expect("spawn llm-proxy");
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while std::net::TcpStream::connect_timeout(&listener, Duration::from_millis(50)).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "proxy never opened {listener}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self { child }
    }

    fn reload(&self) {
        let status = Command::new("kill")
            .args(["-HUP", &self.child.id().to_string()])
            .status()
            .expect("send SIGHUP");
        assert!(status.success(), "SIGHUP failed");
    }
}

impl Drop for RunningProxy {
    fn drop(&mut self) {
        let _ = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status();
        let _ = self.child.wait();
    }
}

async fn reload_probe(listener_port: u16) {
    // Long-lived keep-alive connections retain the listener generation that
    // accepted them. Open a fresh, short-lived connection after each SIGHUP
    // to prove the replacement generation routes traffic as intended.
    let summary = run_closed_loop(
        Arc::new(RunConfig {
            targets: vec![Target {
                tls: false,
                host: "127.0.0.1".to_string(),
                port: listener_port,
            }],
            endpoint: Endpoint::Chat,
            model: "rename-churn".to_string(),
            prompt: "reload probe".to_string(),
            max_tokens: 1,
            api_key: None,
            stream: false,
            timeout: REQUEST_TIMEOUT,
            transport: Default::default(),
        }),
        1,
        Duration::from_millis(50),
        Duration::ZERO,
    )
    .await;
    assert_eq!(
        summary.transport_errors, 0,
        "reload probe failed: {summary:?}"
    );
    assert!(
        summary.http_errors.is_empty(),
        "reload probe failed: {summary:?}"
    );
    assert!(
        summary.success > 0,
        "reload probe got no response: {summary:?}"
    );
}

#[ignore = "5k-rps acceptance; run on a dedicated capacity host"]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn rename_churn_at_5k_rps_keeps_last_good_generation_live() {
    // A lower diagnostic rate can reproduce reload failures on a workstation;
    // the release gate always uses the 5k default.
    let rate = std::env::var("RENAME_CHURN_DIAGNOSTIC_RPS")
        .ok()
        .map(|value| value.parse::<f64>().expect("valid diagnostic rps"))
        .unwrap_or(RATE);
    let upstream_a = OpenAiUpstream::spawn(OpenAiConfig {
        model: "rename-churn".to_string(),
        response_text: "a".to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: None,
        forced_error: None,
        cached_tokens: 0,
    })
    .await
    .expect("spawn upstream a");
    let upstream_b = OpenAiUpstream::spawn(OpenAiConfig {
        model: "rename-churn".to_string(),
        response_text: "b".to_string(),
        ttft: Duration::from_millis(1),
        inter_token_delay: Duration::from_millis(1),
        require_api_key: None,
        forced_error: None,
        cached_tokens: 0,
    })
    .await
    .expect("spawn upstream b");

    let scratch = ScratchDir::new("rename-churn");
    let listener_port = free_port();
    let listener = SocketAddr::from(([127, 0, 0, 1], listener_port));
    let config_path = scratch.write(
        "bootstrap.yaml",
        &envoy_config(listener_port, "listener-0", "cluster-0", upstream_a.addr()),
    );
    let log_path = scratch.path().join("proxy.log");
    let proxy = RunningProxy::spawn(&resolve_llm_proxy_bin(), &config_path, &log_path, listener);

    let load_config = Arc::new(RunConfig {
        targets: vec![Target {
            tls: false,
            host: "127.0.0.1".to_string(),
            port: listener_port,
        }],
        endpoint: Endpoint::Chat,
        model: "rename-churn".to_string(),
        prompt: "hello".to_string(),
        max_tokens: 1,
        api_key: None,
        stream: false,
        timeout: REQUEST_TIMEOUT,
        // This is a request-path churn drill, not a short-connection capacity
        // drill. Reuse a bounded set of downstream HTTP/1.1 connections so
        // connection setup cannot mask reload failures at 5k RPS.
        transport: TransportConfig {
            mode: DownstreamMode::H1Pool,
            h1_pool_size: 64,
            ca_file: None,
        },
    });
    let load = tokio::spawn(run_open_loop(
        load_config,
        rate,
        LOAD_DURATION,
        Duration::ZERO,
    ));

    for generation in 1..=8u16 {
        tokio::time::sleep(CHURN_INTERVAL).await;
        let (cluster, listener_name, upstream) = if generation % 2 == 0 {
            (
                format!("cluster-b-{generation}"),
                format!("listener-b-{generation}"),
                upstream_b.addr(),
            )
        } else {
            (
                format!("cluster-a-{generation}"),
                format!("listener-a-{generation}"),
                upstream_a.addr(),
            )
        };
        std::fs::write(
            &config_path,
            envoy_config(listener_port, &listener_name, &cluster, upstream),
        )
        .expect("write renamed generation");
        proxy.reload();
        reload_probe(listener_port).await;
    }

    // Invalid replacement must leave last-good generation serving.
    tokio::time::sleep(CHURN_INTERVAL).await;
    std::fs::write(&config_path, "static_resources:\n  listeners: [broken")
        .expect("write invalid generation");
    proxy.reload();
    reload_probe(listener_port).await;

    let (summary, stats) = load.await.expect("load task panicked");
    let failure_logs = std::fs::read_to_string(&log_path)
        .unwrap_or_default()
        .lines()
        .filter(|line| {
            line.contains("local 503 response")
                || line.contains("upstream connection attempt failed without retry")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !stats.driver_saturated,
        "load driver saturated: {stats:?}; responses: {summary:?}\nlocal 503s:\n{failure_logs}"
    );
    assert_eq!(summary.transport_errors, 0, "transport errors: {summary:?}");
    assert_eq!(summary.timeouts, 0, "timeouts: {summary:?}");
    assert_eq!(summary.truncated, 0, "truncated responses: {summary:?}");
    assert!(
        summary.http_errors.is_empty(),
        "5xx/non-2xx responses: {summary:?}\nlocal 503s:\n{failure_logs}"
    );
    assert!(summary.success > 0, "no successful requests: {summary:?}");
    assert!(
        !upstream_a.log.requests().is_empty(),
        "upstream A saw no traffic"
    );
    assert!(
        !upstream_b.log.requests().is_empty(),
        "upstream B saw no traffic"
    );

    drop(proxy);
    upstream_a.shutdown().await;
    upstream_b.shutdown().await;
}
