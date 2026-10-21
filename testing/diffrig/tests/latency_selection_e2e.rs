//! Health- and latency-aware selection among a weighted route's members,
//! through the real binary.
//!
//! Ejection is driven through real 5xx responses from a mock upstream, and
//! latency through fixed mock delays far apart, so no assertion depends on a
//! wall-clock window.

use std::net::SocketAddr;
use std::time::Duration;

use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json, ProxyProcess, RawResponse, ScratchDir,
    READY_TIMEOUT,
};
use diffrig::upstreams::{OpenAiConfig, OpenAiUpstream};
use serde_json::json;

/// Bounds each client wait so a stalled request fails the test instead of
/// hanging the suite. Not an assertion on timing.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

fn upstream(text: &str, ttft: Duration, forced_error: Option<u16>) -> OpenAiConfig {
    OpenAiConfig {
        model: "gpt-mock".to_string(),
        response_text: text.to_string(),
        ttft,
        inter_token_delay: Duration::from_millis(1),
        require_api_key: None,
        forced_error: forced_error.map(|status| (status, "mock upstream failure".to_string())),
        cached_tokens: 0,
    }
}

async fn spawn_upstream(text: &str, ttft: Duration, forced_error: Option<u16>) -> OpenAiUpstream {
    OpenAiUpstream::spawn(upstream(text, ttft, forced_error))
        .await
        .expect("spawn mock upstream")
}

/// An Envoy-mode bootstrap: one route splitting `weighted_clusters` 1:1 over
/// two plain clusters `a` and `b`, no retry policy. `route_extra` is spliced
/// into the route (for example its `metadata`), `cluster_extra` into every
/// cluster. `affinity` adds an `x-session-affinity` header hash policy
/// (ADR-0016).
fn envoy_bootstrap(
    listen: SocketAddr,
    ports: [u16; 2],
    route_extra: &str,
    cluster_extra: &str,
    affinity: bool,
) -> String {
    let (hash_policy, use_hash_policy) = if affinity {
        (
            "\n                            hash_policy: [{ header: { header_name: x-session-affinity } }]",
            "\n                              use_hash_policy: true",
        )
    } else {
        ("", "")
    };
    let cluster = |name: &str, port: u16| {
        format!(
            r#"
    - name: {name}
      type: STATIC
      connect_timeout: 1s{cluster_extra}
      load_assignment:
        cluster_name: {name}
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: 127.0.0.1, port_value: {port} }}"#
        )
    };
    format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {} }}
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
                        - match: {{ prefix: "/" }}{route_extra}
                          route:
                            timeout: 5s{hash_policy}
                            weighted_clusters:{use_hash_policy}
                              clusters:
                                - {{ name: a, weight: 1 }}
                                - {{ name: b, weight: 1 }}
  clusters:{}{}
"#,
        listen.port(),
        cluster("a", ports[0]),
        cluster("b", ports[1]),
    )
}

fn spawn_envoy_mode(
    label: &str,
    bootstrap: impl FnOnce(SocketAddr) -> String,
) -> (SocketAddr, ScratchDir, ProxyProcess) {
    let scratch = ScratchDir::new(label);
    let listen: SocketAddr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
    let path = scratch.write("envoy.yaml", &bootstrap(listen));
    let mut proxy = ProxyProcess::spawn_envoy(
        &resolve_llm_proxy_bin(),
        &path,
        &scratch.path().join("proxy.log"),
    );
    proxy.wait_until_ready(listen, READY_TIMEOUT);
    (listen, scratch, proxy)
}

async fn chat(addr: SocketAddr, headers: &[(&str, &str)]) -> RawResponse {
    send_chat(addr, headers, false).await
}

/// A streaming request: the mock holds its first event for its `ttft`, which
/// is what latency mode measures for a stream.
async fn stream(addr: SocketAddr, headers: &[(&str, &str)]) -> RawResponse {
    send_chat(addr, headers, true).await
}

async fn send_chat(addr: SocketAddr, headers: &[(&str, &str)], stream: bool) -> RawResponse {
    tokio::time::timeout(
        CLIENT_TIMEOUT,
        send_json(
            addr,
            "POST",
            "/v1/chat/completions",
            headers,
            &json!({
                "model": "gpt-mock",
                "stream": stream,
                "messages": [{ "role": "user", "content": "hi" }],
            }),
        ),
    )
    .await
    .expect("client request timed out")
}

/// Outlier detection that ejects a host on its first 5xx for longer than any
/// test run. `max_ejection_percent: 100` lets a one-host cluster eject it;
/// the default 10% of one host rounds down to zero.
const EJECT_ON_FIRST_5XX: &str = r#"
      outlier_detection:
        consecutive_5xx: 1
        base_ejection_time: 300s
        max_ejection_percent: 100"#;

/// A weighted route over plain clusters: `b` answers 500 and is ejected
/// after its first request. Envoy's `weighted_clusters` draw ignores health,
/// and `b`'s own load balancer then panics (no healthy host) and dials the
/// ejected host anyway, so about half the traffic would keep failing. The
/// draw must pass over a member with no healthy host.
///
/// The loop sends requests until `b` has served one; with a 1:1 split the
/// chance that 200 requests all miss `b` is 2^-200.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_weighted_draw_skips_a_member_whose_hosts_are_all_ejected() {
    let a = spawn_upstream("served by a", Duration::from_millis(1), None).await;
    let b = spawn_upstream("served by b", Duration::from_millis(1), Some(500)).await;
    let (addr, scratch, proxy) = spawn_envoy_mode("weighted-skip-ejected", |listen| {
        envoy_bootstrap(listen, [a.port(), b.port()], "", EJECT_ON_FIRST_5XX, false)
    });

    for _ in 0..200 {
        if !b.log.requests().is_empty() {
            break;
        }
        let res = chat(addr, &[]).await;
        assert!(res.status == 200 || res.status == 500, "{}", res.status);
    }
    assert_eq!(
        b.log.requests().len(),
        1,
        "b served its one failing request"
    );

    let a_before = a.log.requests().len();
    for i in 0..40 {
        let res = chat(addr, &[]).await;
        assert_eq!(
            res.status, 200,
            "request {i} after b's ejection: {}",
            res.body
        );
    }
    assert_eq!(b.log.requests().len(), 1, "ejected b was drawn again");
    assert_eq!(a.log.requests().len(), a_before + 40);

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

const LATENCY_MODE: &str = r#"
                          metadata:
                            filter_metadata:
                              io.llmproxy.selection: { mode: latency }"#;

/// `fast` answers its first event at once; `slow` holds it far longer than
/// any proxy or scheduler jitter, so the two averages never cross.
const FAST: Duration = Duration::from_millis(1);
const SLOW: Duration = Duration::from_millis(300);

/// Weights 1:1, `b` slow. Latency mode scales `b` to the floor (100 per
/// mille of its weight) once one sample of each exists, so of N sequential
/// requests `b` expects about 1 + (N - 2) / 11, 10 for N = 100. The bound
/// (30) is far above that and far below the 50 a static draw expects, so
/// it holds under a loaded box and fails if the latency weighting is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn latency_mode_sends_most_requests_to_the_fast_member() {
    const N: usize = 100;
    let a = spawn_upstream("served by a", FAST, None).await;
    let b = spawn_upstream("served by b", SLOW, None).await;
    let (addr, scratch, proxy) = spawn_envoy_mode("latency-mode", |listen| {
        envoy_bootstrap(listen, [a.port(), b.port()], LATENCY_MODE, "", false)
    });

    for i in 0..N {
        let res = stream(addr, &[]).await;
        assert_eq!(res.status, 200, "request {i}: {}", res.body);
    }
    let (fast, slow) = (a.log.requests().len(), b.log.requests().len());
    assert_eq!(fast + slow, N);
    assert!(slow >= 1, "the slow member keeps a trickle");
    assert!(
        slow <= 30,
        "slow member served {slow} of {N}; latency mode expects about 10"
    );

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

/// The same members without the extension: the draw is static and the split
/// follows the 1:1 weights however slow `b` is. `b`'s count is
/// Binomial(200, 0.5), standard deviation 7.1; +-40 is 5.6 standard
/// deviations. Requests go out 20 at a time so the slow member costs one
/// delay per batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_the_extension_the_split_follows_the_weights() {
    const N: usize = 200;
    let a = spawn_upstream("served by a", FAST, None).await;
    let b = spawn_upstream("served by b", SLOW, None).await;
    let (addr, scratch, proxy) = spawn_envoy_mode("latency-default", |listen| {
        envoy_bootstrap(listen, [a.port(), b.port()], "", "", false)
    });

    for _ in 0..N / 20 {
        let batch = (0..20).map(|_| stream(addr, &[]));
        for res in futures::future::join_all(batch).await {
            assert_eq!(res.status, 200, "{}", res.body);
        }
    }
    let slow = b.log.requests().len();
    assert_eq!(a.log.requests().len() + slow, N);
    assert!(
        slow.abs_diff(N / 2) <= 40,
        "slow member served {slow} of {N}"
    );

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}

/// Session affinity wins over latency (ADR-0016 decision 6): once the slow
/// member is measured, a session pinned to it stays there; only requests
/// with no session take the latency-weighted draw.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_stays_on_its_member_in_latency_mode() {
    let a = spawn_upstream("served by a", FAST, None).await;
    let b = spawn_upstream("served by b", SLOW, None).await;
    let (addr, scratch, proxy) = spawn_envoy_mode("latency-affinity", |listen| {
        envoy_bootstrap(listen, [a.port(), b.port()], LATENCY_MODE, "", true)
    });

    // Sessions until one lands on the slow member; each also measures it.
    let mut pinned = None;
    for i in 0..64 {
        let session = format!("session-{i}");
        let before = b.log.requests().len();
        let res = stream(addr, &[("x-session-affinity", &session)]).await;
        assert_eq!(res.status, 200, "{}", res.body);
        if b.log.requests().len() > before {
            pinned = Some(session);
            break;
        }
    }
    let pinned = pinned.expect("a 1:1 hash split puts one of 64 sessions on b");

    let before = b.log.requests().len();
    for i in 0..20 {
        let res = stream(addr, &[("x-session-affinity", &pinned)]).await;
        assert_eq!(res.status, 200, "request {i}: {}", res.body);
    }
    assert_eq!(
        b.log.requests().len(),
        before + 20,
        "the pinned session left the slow member"
    );

    drop(proxy);
    drop(scratch);
    a.shutdown().await;
    b.shutdown().await;
}
