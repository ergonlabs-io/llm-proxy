//! Protocol and failure-policy proof at the real downstream socket boundary.
use diffrig::harness::{
    free_port, resolve_llm_proxy_bin, send_json_optional, ProxyProcess, ScratchDir, READY_TIMEOUT,
};
use proxy_xds::authorization::test_service::{Mode, TestService};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

struct Upstream {
    address: std::net::SocketAddr,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Upstream {
    async fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::SeqCst);
                tokio::time::timeout(Duration::from_secs(3), async {
                    let mut received = Vec::new();
                    while !received.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        if socket.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        received.push(byte[0]);
                        assert!(received.len() <= 64 * 1024);
                    }
                    let head_text = String::from_utf8_lossy(&received).to_ascii_lowercase();
                    let length = head_text
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length:")
                                .and_then(|v| v.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    assert!(length <= 64 * 1024);
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).await.unwrap();
                    received.extend(body);
                    // Echo the actual request bytes for mutation and body-preservation assertions.
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        received.len()
                    );
                    socket.write_all(head.as_bytes()).await.unwrap();
                    socket.write_all(&received).await.unwrap();
                })
                .await
                .unwrap();
            }
        });
        Self {
            address,
            calls,
            task,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_real_binary_gates_upstream_and_preserves_denial() {
    let binary = resolve_llm_proxy_bin();
    for (mode, fail_open, status, dials) in [
        (Mode::Allow, false, 200, 1),
        (Mode::Deny, false, 401, 0),
        (Mode::Deny, true, 401, 0),
        (Mode::TransportError, false, 403, 0),
        (Mode::NoStatus, false, 200, 1),
        (Mode::UnsupportedResponse, false, 403, 0),
        (Mode::TransportError, true, 200, 1),
        (Mode::Stall, false, 403, 0),
    ] {
        let scratch = ScratchDir::new("ext-authz-e2e");
        let service = TestService::spawn(mode).await;
        let upstream = Upstream::spawn().await;
        let port = free_port();
        let admin_port = free_port();
        let access_log = scratch.path().join("access.log");
        let text = include_str!("../../../examples/ext-authz.yaml")
            .replace("port_value: 9000", &format!("port_value: {port}"))
            .replace("port_value: 9001", &format!("port_value: {}", service.address.port()))
            .replace("port_value: 9002", &format!("port_value: {}", upstream.address.port()))
            .replace("timeout: 0.2s", "timeout: 0.5s")
            .replace("validate_mutations: true", &format!("validate_mutations: true\n                      failure_mode_allow: {fail_open}\n                      failure_mode_allow_header_add: true"));
        let mut document: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        document["admin"] = serde_yaml::to_value(serde_json::json!({"address": {"socket_address": {"address": "127.0.0.1", "port_value": admin_port}}})).unwrap();
        document["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]["access_log"] = serde_yaml::to_value(serde_json::json!([{
            "name": "envoy.access_loggers.file", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog",
                "path": access_log, "log_format": {"text_format": "%RESPONSE_FLAGS%|%RESPONSE_CODE_DETAILS%\n"}
            }
        }])).unwrap();
        let config = scratch.write("bootstrap.yaml", &serde_yaml::to_string(&document).unwrap());
        let log = scratch.path().join("proxy.log");
        let mut proxy = ProxyProcess::spawn_envoy(&binary, &config, &log);
        let address = format!("127.0.0.1:{port}").parse().unwrap();
        proxy.wait_until_ready(address, READY_TIMEOUT);
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            send_json_optional(
                address,
                "GET",
                "/v1?q=1",
                &[
                    ("host", "application"),
                    ("authorization", "secret-must-not-be-logged"),
                ],
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status, status);
        if status == 401 {
            assert_eq!(response.body, "denied");
            assert!(response
                .headers
                .iter()
                .any(|(k, v)| k == "x-denial" && v == "yes"));
        }
        if status == 200 {
            let expected = if fail_open {
                "x-envoy-auth-failure-mode-allowed: true"
            } else {
                "x-authorized: yes"
            };
            if !matches!(mode, Mode::NoStatus) {
                assert!(response.body.to_ascii_lowercase().contains(expected));
            }
        }
        assert_eq!(upstream.calls.load(Ordering::SeqCst), dials);
        assert_eq!(service.calls.load(Ordering::SeqCst), 1);
        let logs = std::fs::read_to_string(&log).unwrap();
        assert!(!logs.contains("secret-must-not-be-logged"));
        if fail_open && status == 200 {
            assert!(logs.contains("explicit failure_mode_allow admitted the request"));
            let _ = tokio::time::timeout(
                Duration::from_secs(3),
                send_json_optional(address, "GET", "/v1", &[("host", "application")], None),
            )
            .await
            .unwrap();
            assert_eq!(
                std::fs::read_to_string(&log)
                    .unwrap()
                    .matches("explicit failure_mode_allow admitted the request")
                    .count(),
                1
            );
        }
        let admin_address = format!("127.0.0.1:{admin_port}").parse().unwrap();
        proxy.wait_until_ready(admin_address, READY_TIMEOUT);
        let stats = tokio::time::timeout(
            Duration::from_secs(3),
            send_json_optional(admin_address, "GET", "/stats", &[], None),
        )
        .await
        .unwrap();
        let error_count = if matches!(
            mode,
            Mode::TransportError | Mode::UnsupportedResponse | Mode::Stall
        ) {
            if fail_open {
                2
            } else {
                1
            }
        } else {
            0
        };
        for (outcome, count) in [
            (
                "ok",
                usize::from(matches!(mode, Mode::Allow | Mode::NoStatus)),
            ),
            ("denied", usize::from(matches!(mode, Mode::Deny))),
            ("error", error_count),
            (
                "failure_mode_allowed",
                if fail_open && status == 200 { 2 } else { 0 },
            ),
        ] {
            assert!(
                stats.body.contains(&format!(
                    "http.authorized_http.ext_authz.{outcome}: {count}\n"
                )),
                "{}",
                stats.body
            );
        }
        let metrics = tokio::time::timeout(
            Duration::from_secs(3),
            send_json_optional(admin_address, "GET", "/stats/prometheus", &[], None),
        )
        .await
        .unwrap();
        let series = metrics
            .body
            .lines()
            .filter(|line| line.starts_with("envoy_ext_authz{"))
            .collect::<Vec<_>>();
        assert_eq!(series.len(), 7);
        assert!(series
            .iter()
            .all(|line| line.contains("scope=\"authorized_http.ext_authz\"")
                && line.contains("outcome=\"")
                && line.matches('=').count() == 2));
        assert!(!metrics.body.contains("secret-must-not-be-logged"));
        if status != 200 {
            let expected = if status == 401 {
                "UAEX|ext_authz_denied"
            } else {
                "UAEX|ext_authz_error"
            };
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    if std::fs::read_to_string(&access_log)
                        .unwrap_or_default()
                        .contains(expected)
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap();
        }
        drop(proxy);
    }
}

const ENVOY: &str =
    "envoyproxy/envoy@sha256:8146b97ee61a42cd216514709e4e3198af75f014974e3d9f310aef9c901fcbdf";
struct Container(String);
impl Drop for Container {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let logs = std::process::Command::new("docker")
                .args(["logs", &self.0])
                .output()
                .unwrap();
            eprintln!(
                "container logs: {}{}",
                String::from_utf8_lossy(&logs.stdout),
                String::from_utf8_lossy(&logs.stderr)
            );
        }
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.0])
            .output();
    }
}
fn container(args: &[String]) -> Container {
    let output = std::process::Command::new("docker")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Container(String::from_utf8(output.stdout).unwrap().trim().to_owned())
}
async fn ready(address: std::net::SocketAddr) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
}

/// Docker is explicit: normal workspace runs retain deterministic local coverage.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker and the pinned Envoy image"]
async fn ext_authz_envoy_v138_differential() {
    let binary = resolve_llm_proxy_bin();
    for (mode, fail_open, expected, disabled) in [
        (Mode::Allow, false, 200, false),
        (Mode::NoStatus, false, 200, false),
        (Mode::Mutate, false, 200, false),
        (Mode::InvalidMutation, true, 500, false),
        (Mode::Stall, false, 200, true),
        (Mode::Deny, false, 401, false),
        (Mode::Deny, true, 401, false),
        (Mode::TransportError, false, 403, false),
        (Mode::TransportError, true, 200, false),
        (Mode::Stall, false, 403, false),
    ] {
        let scratch = ScratchDir::new("ext-authz-envoy-diff");
        let service = TestService::spawn(mode).await;
        let upstream = Upstream::spawn().await;
        let left_port = free_port();
        let right_port = free_port();
        let text = include_str!("../../../examples/ext-authz.yaml")
            .replace("port_value: 9000", &format!("port_value: {left_port}"))
            .replace("port_value: 9001", &format!("port_value: {}", service.address.port()))
            .replace("port_value: 9002", &format!("port_value: {}", upstream.address.port()))
            .replace("timeout: 0.2s", "timeout: 0.5s")
            .replace("validate_mutations: true", &format!("validate_mutations: true\n                      failure_mode_allow: {fail_open}\n                      failure_mode_allow_header_add: true"));
        let mut document: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        let hcm = &mut document["static_resources"]["listeners"][0]["filter_chains"][0]["filters"]
            [0]["typed_config"];
        let context = |scope: &str, key: &str| {
            serde_yaml::to_value(serde_json::json!({"envoy.filters.http.ext_authz": {"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute", "check_settings": {"context_extensions": {"scope": scope, key: "retained"}}}})).unwrap()
        };
        hcm["route_config"]["typed_per_filter_config"] = context("fleet", "fleet");
        hcm["route_config"]["virtual_hosts"][0]["typed_per_filter_config"] =
            context("vhost", "host");
        hcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] =
            if disabled {
                serde_yaml::to_value(serde_json::json!({"envoy.filters.http.ext_authz": {"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute", "disabled": true}})).unwrap()
            } else {
                context("route", "route")
            };
        let text = serde_yaml::to_string(&document).unwrap();
        let left_config = scratch.write("left.yaml", &text);
        let right_text = text
            .replace(
                &format!("port_value: {left_port}"),
                &format!("port_value: {right_port}"),
            )
            .replace("address: 127.0.0.1", "address: host.docker.internal")
            .replace("type: STATIC", "type: STRICT_DNS")
            .replacen("address: host.docker.internal", "address: 0.0.0.0", 1);
        let right_config = scratch.write("right.yaml", &right_text);
        let mut proxy =
            ProxyProcess::spawn_envoy(&binary, &left_config, &scratch.path().join("left.log"));
        let left = format!("127.0.0.1:{left_port}").parse().unwrap();
        proxy.wait_until_ready(left, READY_TIMEOUT);
        let envoy = container(&[
            "run".into(),
            "-d".into(),
            "-p".into(),
            format!("127.0.0.1:{right_port}:{right_port}"),
            "-v".into(),
            format!("{}:/etc/envoy/bootstrap.yaml:ro", right_config.display()),
            ENVOY.into(),
            "-c".into(),
            "/etc/envoy/bootstrap.yaml".into(),
            "--concurrency".into(),
            "1".into(),
        ]);
        let right = format!("127.0.0.1:{right_port}").parse().unwrap();
        tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                let logs = std::process::Command::new("docker")
                    .args(["logs", &envoy.0])
                    .output()
                    .unwrap();
                if String::from_utf8_lossy(&logs.stderr).contains("starting main dispatch loop")
                    || String::from_utf8_lossy(&logs.stdout).contains("starting main dispatch loop")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        ready(right).await;
        let mut responses = Vec::new();
        for address in [left, right] {
            eprintln!("differential target {address}, expected {expected}, fail_open {fail_open}");
            responses.push(
                tokio::time::timeout(
                    Duration::from_secs(3),
                    send_json_optional(
                        address,
                        "GET",
                        "/v1?q=1",
                        &[
                            ("host", "application"),
                            ("x-repeat", "one"),
                            ("x-repeat", "two"),
                        ],
                        None,
                    ),
                )
                .await
                .unwrap(),
            );
        }
        assert_eq!(responses[0].status, expected);
        assert_eq!(responses[1].status, expected);
        if expected == 401 {
            assert_eq!(responses[0].body, responses[1].body);
        }
        let captured = service.captured_requests();
        assert_eq!(captured.len(), if disabled { 0 } else { 2 });
        for request in captured {
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, "/v1?q=1");
            assert_eq!(request.authority, "application");
            assert_eq!(request.scheme, "http");
            assert_eq!(
                request.context_extensions,
                [
                    ("fleet".into(), "retained".into()),
                    ("host".into(), "retained".into()),
                    ("route".into(), "retained".into()),
                    ("scope".into(), "route".into())
                ]
                .into_iter()
                .collect()
            );
            assert_eq!(
                request
                    .headers
                    .iter()
                    .filter(|(k, _)| k == "x-repeat")
                    .map(|(_, v)| v.as_slice())
                    .collect::<Vec<_>>(),
                vec![b"one".as_slice(), b"two".as_slice()]
            );
        }
        assert_eq!(
            upstream.calls.load(Ordering::SeqCst),
            if expected == 200 { 2 } else { 0 }
        );
        if matches!(mode, Mode::Mutate) {
            for response in &responses {
                assert!(response.body.starts_with("GET /rerouted?q=2 HTTP/1.1"));
                assert!(response
                    .headers
                    .iter()
                    .any(|(k, v)| k == "x-response" && v == "authorized"));
            }
        }
        if matches!(mode, Mode::Deny) && !fail_open {
            for address in [left, right] {
                let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
                socket.write_all(b"POST /v1?q=1 HTTP/1.1\r\nHost: application\r\nContent-Length: 4\r\nConnection: close\r\n\r\n").await.unwrap();
                let mut head = Vec::new();
                tokio::time::timeout(Duration::from_secs(3), async {
                    while !head.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        socket.read_exact(&mut byte).await.unwrap();
                        head.push(byte[0]);
                        assert!(head.len() < 64 * 1024);
                    }
                })
                .await
                .unwrap();
                assert!(head.starts_with(b"HTTP/1.1 401"));
            }
            assert_eq!(service.calls.load(Ordering::SeqCst), 4);
            assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
        }
        drop(envoy);
        drop(proxy);
    }
}

const OPA: &str =
    "openpolicyagent/opa@sha256:3fa49a2d6fcf2f5bfbd58b54e83e19d5ee5b968727cb5fce73edd9c0f6742d50";
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires Docker and the pinned OPA-envoy-plugin image"]
async fn ext_authz_opa_envoy_plugin_allows_and_denies() {
    let binary = resolve_llm_proxy_bin();
    let scratch = ScratchDir::new("ext-authz-opa");
    scratch.write("opa.yaml", "plugins:\n  envoy_ext_authz_grpc:\n    addr: :9191\n    path: envoy/authz/allow\n    skip-request-body-parse: true\n");
    scratch.write("policy.rego", "package envoy.authz\nimport rego.v1\ndefault allow := false\nallow if input.attributes.request.http.path == \"/allow\"\n");
    let auth_port = free_port();
    let opa = container(&[
        "run".into(),
        "-d".into(),
        "--platform".into(),
        "linux/amd64".into(),
        "-p".into(),
        format!("127.0.0.1:{auth_port}:9191"),
        "-v".into(),
        format!("{}:/fixture:ro", scratch.path().display()),
        OPA.into(),
        "run".into(),
        "--server".into(),
        "--config-file=/fixture/opa.yaml".into(),
        "/fixture/policy.rego".into(),
    ]);
    ready(format!("127.0.0.1:{auth_port}").parse().unwrap()).await;
    let upstream = Upstream::spawn().await;
    let port = free_port();
    let text = include_str!("../../../examples/ext-authz.yaml")
        .replace("port_value: 9000", &format!("port_value: {port}"))
        .replace("port_value: 9001", &format!("port_value: {auth_port}"))
        .replace(
            "port_value: 9002",
            &format!("port_value: {}", upstream.address.port()),
        );
    let config = scratch.write("bootstrap.yaml", &text);
    let mut proxy = ProxyProcess::spawn_envoy(&binary, &config, &scratch.path().join("proxy.log"));
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    proxy.wait_until_ready(address, READY_TIMEOUT);
    for (path, status) in [("/allow", 200), ("/deny", 403)] {
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            send_json_optional(address, "GET", path, &[("host", "application")], None),
        )
        .await
        .unwrap();
        assert_eq!(response.status, status);
    }
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    drop(proxy);
    drop(opa);
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_route_context_disable_and_native_policy_remain_effective() {
    let binary = resolve_llm_proxy_bin();
    for (disabled, native, status) in [(false, false, 200), (false, true, 401), (true, false, 200)]
    {
        let scratch = ScratchDir::new("ext-authz-route-policy");
        let service = TestService::spawn(Mode::Allow).await;
        let upstream = Upstream::spawn().await;
        let port = free_port();
        let text = include_str!("../../../examples/ext-authz.yaml")
            .replace("port_value: 9000", &format!("port_value: {port}"))
            .replace(
                "port_value: 9001",
                &format!("port_value: {}", service.address.port()),
            )
            .replace(
                "port_value: 9002",
                &format!("port_value: {}", upstream.address.port()),
            );
        let mut document: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        let hcm = &mut document["static_resources"]["listeners"][0]["filter_chains"][0]["filters"]
            [0]["typed_config"];
        let context = |extensions: serde_json::Value| {
            serde_yaml::to_value(serde_json::json!({"envoy.filters.http.ext_authz": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute", "check_settings": {"context_extensions": extensions}
        }})).unwrap()
        };
        hcm["route_config"]["typed_per_filter_config"] =
            context(serde_json::json!({"scope": "fleet", "fleet": "retained"}));
        hcm["route_config"]["virtual_hosts"][0]["typed_per_filter_config"] =
            context(serde_json::json!({"scope": "vhost", "host": "retained"}));
        hcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] =
            if disabled {
                serde_yaml::to_value(serde_json::json!({"envoy.filters.http.ext_authz": {"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute", "disabled": true}})).unwrap()
            } else {
                context(serde_json::json!({"scope": "route"}))
            };
        if native {
            hcm["http_filters"].as_sequence_mut().unwrap().insert(1, serde_yaml::to_value(serde_json::json!({
                "name": "llmproxy.auth", "typed_config": {"@type": "type.llmproxy.dev/llmproxy.filters.v0.Authentication", "hmac_secret": {"inline_string": "test-native-secret"}}
            })).unwrap());
        }
        let config = scratch.write("bootstrap.yaml", &serde_yaml::to_string(&document).unwrap());
        let mut proxy =
            ProxyProcess::spawn_envoy(&binary, &config, &scratch.path().join("proxy.log"));
        let address = format!("127.0.0.1:{port}").parse().unwrap();
        proxy.wait_until_ready(address, READY_TIMEOUT);
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            send_json_optional(address, "GET", "/v1", &[("host", "application")], None),
        )
        .await
        .unwrap();
        assert_eq!(response.status, status);
        assert_eq!(service.calls.load(Ordering::SeqCst), usize::from(!disabled));
        assert_eq!(upstream.calls.load(Ordering::SeqCst), usize::from(!native));
        if !disabled {
            let requests = service.captured_requests();
            assert_eq!(
                requests[0].context_extensions,
                [
                    ("fleet".into(), "retained".into()),
                    ("host".into(), "retained".into()),
                    ("scope".into(), "route".into())
                ]
                .into_iter()
                .collect()
            );
        }
        drop(proxy);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_mutations_invalidate_routes_atomically_and_reach_encoder() {
    let binary = resolve_llm_proxy_bin();
    for (mode, clear, fail_open, status) in [
        (Mode::Mutate, false, false, 200),
        (Mode::Mutate, true, false, 200),
        (Mode::InvalidMutation, true, true, 500),
    ] {
        let scratch = ScratchDir::new("ext-authz-mutations");
        let service = TestService::spawn(mode).await;
        let original = Upstream::spawn().await;
        let rerouted = Upstream::spawn().await;
        let port = free_port();
        let text = include_str!("../../../examples/ext-authz.yaml")
            .replace("port_value: 9000", &format!("port_value: {port}"))
            .replace(
                "port_value: 9001",
                &format!("port_value: {}", service.address.port()),
            )
            .replace(
                "port_value: 9002",
                &format!("port_value: {}", original.address.port()),
            );
        let mut document: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        let mut cluster = document["static_resources"]["clusters"][1].clone();
        cluster["name"] = "rerouted".into();
        cluster["load_assignment"]["cluster_name"] = "rerouted".into();
        cluster["load_assignment"]["endpoints"][0]["lb_endpoints"][0]["endpoint"]["address"]
            ["socket_address"]["port_value"] =
            serde_yaml::to_value(rerouted.address.port()).unwrap();
        document["static_resources"]["clusters"]
            .as_sequence_mut()
            .unwrap()
            .push(cluster);
        let hcm = &mut document["static_resources"]["listeners"][0]["filter_chains"][0]["filters"]
            [0]["typed_config"];
        hcm["http_filters"][0]["typed_config"]["clear_route_cache"] = clear.into();
        hcm["http_filters"][0]["typed_config"]["failure_mode_allow"] = fail_open.into();
        hcm["route_config"]["virtual_hosts"][0]["routes"].as_sequence_mut().unwrap().insert(0, serde_yaml::to_value(serde_json::json!({"match": {"prefix": "/rerouted"}, "route": {"cluster": "rerouted"}})).unwrap());
        let config = scratch.write("bootstrap.yaml", &serde_yaml::to_string(&document).unwrap());
        let mut proxy =
            ProxyProcess::spawn_envoy(&binary, &config, &scratch.path().join("proxy.log"));
        let address = format!("127.0.0.1:{port}").parse().unwrap();
        proxy.wait_until_ready(address, READY_TIMEOUT);
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            send_json_optional(
                address,
                "GET",
                "/original",
                &[("host", "application"), ("x-remove", "gone")],
                None,
            ),
        )
        .await
        .unwrap();
        assert_eq!(response.status, status);
        assert_eq!(
            original.calls.load(Ordering::SeqCst),
            usize::from(status == 200 && !clear)
        );
        assert_eq!(
            rerouted.calls.load(Ordering::SeqCst),
            usize::from(status == 200 && clear)
        );
        if status == 200 {
            assert!(response.body.starts_with("GET /rerouted?q=2 HTTP/1.1"));
            assert!(!response.body.contains("x-remove"));
            assert!(response
                .headers
                .iter()
                .any(|(k, v)| k == "x-response" && v == "authorized"));
        }
        assert_eq!(service.calls.load(Ordering::SeqCst), 1);
        drop(proxy);
    }
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_pending_request_pins_old_client_across_sighup() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let binary = resolve_llm_proxy_bin();
    let scratch = ScratchDir::new("ext-authz-reload");
    let old = TestService::spawn(Mode::Stall).await;
    let new = TestService::spawn(Mode::Deny).await;
    let upstream = Upstream::spawn().await;
    let port = free_port();
    let text = include_str!("../../../examples/ext-authz.yaml")
        .replace("port_value: 9000", &format!("port_value: {port}"))
        .replace(
            "port_value: 9001",
            &format!("port_value: {}", old.address.port()),
        )
        .replace(
            "port_value: 9002",
            &format!("port_value: {}", upstream.address.port()),
        )
        .replace("timeout: 0.2s", "timeout: 10s");
    let config = scratch.write("bootstrap.yaml", &text);
    let log_path = scratch.path().join("proxy.log");
    let output = std::fs::File::create(&log_path).unwrap();
    let proxy = ChildGuard(
        std::process::Command::new(binary)
            .arg("-c")
            .arg(&config)
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    );
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    ready(address).await;
    let pending = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(12),
            send_json_optional(address, "GET", "/old", &[("host", "application")], None),
        )
        .await
        .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(3), old.entered.notified())
        .await
        .unwrap();
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    scratch.write(
        "bootstrap.yaml",
        &text.replace(
            &format!("port_value: {}", old.address.port()),
            &format!("port_value: {}", new.address.port()),
        ),
    );
    assert!(std::process::Command::new("kill")
        .args(["-HUP", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("SIGHUP: config reload succeeded")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        send_json_optional(address, "GET", "/new", &[("host", "application")], None),
    )
    .await
    .unwrap();
    assert_eq!(response.status, 401);
    assert_eq!(new.calls.load(Ordering::SeqCst), 1);
    assert_eq!(old.calls.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    old.release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), pending)
            .await
            .unwrap()
            .unwrap()
            .status,
        200
    );
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    drop(proxy);
}

/// AGENTS.md "Fail-open controls": the bypass warning is logged once per
/// process. Every worker builds its own filter chain, and a reload rebuilds
/// it, so a flag owned by one build would log again per worker and per update.
/// The reload forces a rebuild on any platform; the extra connections reach
/// other workers where the kernel balances accepts.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_fail_open_warning_is_not_repeated_after_reload() {
    struct ChildGuard(std::process::Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    async fn admitted(address: std::net::SocketAddr) {
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            send_json_optional(address, "GET", "/v1", &[("host", "application")], None),
        )
        .await
        .unwrap();
        assert_eq!(response.status, 200);
    }
    let binary = resolve_llm_proxy_bin();
    let scratch = ScratchDir::new("ext-authz-fail-open-reload");
    let service = TestService::spawn(Mode::TransportError).await;
    let upstream = Upstream::spawn().await;
    let port = free_port();
    let text = include_str!("../../../examples/ext-authz.yaml")
        .replace("port_value: 9000", &format!("port_value: {port}"))
        .replace(
            "port_value: 9001",
            &format!("port_value: {}", service.address.port()),
        )
        .replace(
            "port_value: 9002",
            &format!("port_value: {}", upstream.address.port()),
        )
        .replace(
            "validate_mutations: true",
            "validate_mutations: true\n                      failure_mode_allow: true",
        );
    let config = scratch.write("bootstrap.yaml", &text);
    let log_path = scratch.path().join("proxy.log");
    let warnings = || {
        std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .matches("explicit failure_mode_allow admitted the request")
            .count()
    };
    let output = std::fs::File::create(&log_path).unwrap();
    let proxy = ChildGuard(
        std::process::Command::new(binary)
            .arg("-c")
            .arg(&config)
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    );
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    ready(address).await;
    admitted(address).await;
    assert_eq!(warnings(), 1);
    assert!(std::process::Command::new("kill")
        .args(["-HUP", &proxy.0.id().to_string()])
        .status()
        .unwrap()
        .success());
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("SIGHUP: config reload succeeded")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    for _ in 0..4 {
        admitted(address).await;
    }
    assert_eq!(service.calls.load(Ordering::SeqCst), 5);
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 5);
    assert_eq!(warnings(), 1);
    drop(proxy);
}

#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_checks_headers_before_upload_and_preserves_body_after_allow() {
    let binary = resolve_llm_proxy_bin();
    let scratch = ScratchDir::new("ext-authz-upload");
    let service = TestService::spawn(Mode::Stall).await;
    let upstream = Upstream::spawn().await;
    let port = free_port();
    let text = include_str!("../../../examples/ext-authz.yaml")
        .replace("port_value: 9000", &format!("port_value: {port}"))
        .replace(
            "port_value: 9001",
            &format!("port_value: {}", service.address.port()),
        )
        .replace(
            "port_value: 9002",
            &format!("port_value: {}", upstream.address.port()),
        )
        .replace("timeout: 0.2s", "timeout: 5s");
    let config = scratch.write("bootstrap.yaml", &text);
    let mut proxy = ProxyProcess::spawn_envoy(&binary, &config, &scratch.path().join("proxy.log"));
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    proxy.wait_until_ready(address, READY_TIMEOUT);
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(b"POST /upload HTTP/1.1\r\nHost: application\r\nContent-Length: 4\r\nConnection: close\r\n\r\n").await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), service.entered.notified())
        .await
        .unwrap();
    socket.write_all(b"ra").await.unwrap();
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    service.release.notify_one();
    socket.write_all(b"w!").await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"raw!"));
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 1);
    assert_eq!(service.calls.load(Ordering::SeqCst), 1);
    drop(proxy);
}

/// A client must not be able to skip authorization by padding headers past the
/// local CheckRequest limit, even when the owner chose `failure_mode_allow`.
#[tokio::test(flavor = "multi_thread")]
async fn ext_authz_oversized_headers_are_denied_when_fail_open() {
    let binary = resolve_llm_proxy_bin();
    let scratch = ScratchDir::new("ext-authz-oversized");
    // A deny-everything service: only the bypass could make this request succeed.
    let service = TestService::spawn(Mode::Deny).await;
    let upstream = Upstream::spawn().await;
    let port = free_port();
    let text = include_str!("../../../examples/ext-authz.yaml")
        .replace("port_value: 9000", &format!("port_value: {port}"))
        .replace(
            "port_value: 9001",
            &format!("port_value: {}", service.address.port()),
        )
        .replace(
            "port_value: 9002",
            &format!("port_value: {}", upstream.address.port()),
        )
        .replace("timeout: 0.2s", "timeout: 0.5s")
        .replace(
            "validate_mutations: true",
            "validate_mutations: true\n                      failure_mode_allow: true\n                      failure_mode_allow_header_add: true",
        );
    let config = scratch.write("bootstrap.yaml", &text);
    let mut proxy = ProxyProcess::spawn_envoy(&binary, &config, &scratch.path().join("proxy.log"));
    let address = format!("127.0.0.1:{port}").parse().unwrap();
    proxy.wait_until_ready(address, READY_TIMEOUT);
    let mut request =
        String::from("GET /v1 HTTP/1.1\r\nHost: application\r\nConnection: close\r\n");
    for i in 0..10 {
        request.push_str(&format!("x-pad-{i}: {}\r\n", "a".repeat(7 * 1024)));
    }
    request.push_str("\r\n");
    let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), socket.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.starts_with(b"HTTP/1.1 431"),
        "{}",
        String::from_utf8_lossy(&response[..response.len().min(200)])
    );
    assert_eq!(upstream.calls.load(Ordering::SeqCst), 0);
    assert_eq!(service.calls.load(Ordering::SeqCst), 0);
    drop(proxy);
}
