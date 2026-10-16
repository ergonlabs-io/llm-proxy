//! Drives the binary and verifies recorded traffic through the real admin
//! renderers. `llm.client.token.usage` is Prometheus-only because it has no Envoy
//! text equivalent. `downstream_cx_total` is checked in both formats; its label
//! uses the listener name (internal-docs/envoy-divergences.md).

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use proxy_observability::stats::instruments::LLM_CLIENT_TOKEN_USAGE_NO_TENANT;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");

/// Reserves and returns an ephemeral port.
fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to reserve a port");
    listener.local_addr().expect("no local addr").port()
}

/// How long to wait for the freshly spawned `llm-proxy` to become
/// connectable -- see `tests/cli.rs`'s `STARTUP_TIMEOUT` for why this is a
/// liveness backstop, not a speed assertion.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

fn wait_for_connectable(addr: (&str, u16), timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).is_ok() {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spawn_line_reader(
    mut reader: BufReader<impl std::io::Read + Send + 'static>,
) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    rx
}

fn drain_available_lines(rx: &mpsc::Receiver<String>) -> Vec<String> {
    let mut lines = Vec::new();
    while let Ok(line) = rx.try_recv() {
        lines.push(line);
    }
    lines
}

/// A mock upstream: accepts connections in a loop, forever, answering each
/// with a quick `200 OK` -- what the proxy's `backend` cluster forwards to.
/// Plain `std::net`/`std::thread` (no tokio) since this whole test avoids an
/// async runtime, matching `tests/cli.rs`'s style.
fn spawn_mock_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind mock upstream");
    let addr = listener.local_addr().expect("no local addr");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                // Read whatever the client sent (don't bother parsing it --
                // this mock only cares that a request arrived) before
                // replying, so the reply isn't racing the request on the
                // wire.
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    addr
}

/// Sends a plain `GET <path> HTTP/1.1` with `Connection: close` to `addr` and
/// returns the full response (status line + headers + body) read up to EOF --
/// the server closing the connection (honoring `Connection: close`) is what
/// ends the read, matching hyper's (admin) and this proxy's (listener) own
/// HTTP/1.1 behavior for a closed-connection request.
fn get(addr: SocketAddr, path: &str, host: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read response to EOF");
    String::from_utf8_lossy(&response).to_string()
}

/// [`get`]'s `POST`-with-a-JSON-body counterpart -- what the
/// `llm.client.token.usage` test below needs to reach `llmproxy.usage`'s
/// dialect parser at all (it only ever looks at `POST` bodies).
fn post(addr: SocketAddr, path: &str, host: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .expect("set_read_timeout");
    stream
        .write_all(
            format!(
                "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("read response to EOF");
    String::from_utf8_lossy(&response).to_string()
}

/// Kills and reaps the child process on drop (AGENTS.md "Running The Product").
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Asks `cargo build` itself, via `--message-format=json-render-diagnostics`,
/// for the exact path of the `mock-upstream` binary it produced -- see this
/// file's module doc for why (`mockupstream` is a sibling workspace crate,
/// not a dependency of this one, and Cargo's binary artifact dependencies are
/// still nightly-only). Building here means the FIRST test that needs it pays
/// a compile, not the test author guessing whether `make ci`'s earlier
/// `cargo build --workspace` already did.
fn mock_upstream_bin_path() -> PathBuf {
    let output = Command::new(env!("CARGO"))
        .args([
            "build",
            "--package",
            "mockupstream",
            "--bin",
            "mock-upstream",
            "--message-format=json-render-diagnostics",
        ])
        .output()
        .expect("failed to run `cargo build` for mock-upstream");
    assert!(
        output.status.success(),
        "cargo build -p mockupstream --bin mock-upstream failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if msg.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
            continue;
        }
        let is_mock_upstream = msg
            .get("target")
            .and_then(|t| t.get("name"))
            .and_then(|n| n.as_str())
            == Some("mock-upstream");
        if !is_mock_upstream {
            continue;
        }
        if let Some(exe) = msg.get("executable").and_then(|e| e.as_str()) {
            return PathBuf::from(exe);
        }
    }
    panic!(
        "cargo build --message-format=json-render-diagnostics never reported an executable \
         path for the mock-upstream binary target; got:\n{stdout}"
    );
}

/// Spawns a real `mock-upstream` (`testing/mockupstream`) reporting
/// `prompt_tokens`/`tokens` (its `--prompt-tokens`/`--tokens` flags) in every
/// OpenAI-shaped response -- unlike [`spawn_mock_upstream`]'s bare `200 OK`,
/// this is a real provider response body the `llmproxy.usage` filter can
/// parse, which is what lets `llm.client.token.usage` have anything to
/// record. Returns a [`ChildGuard`] (so the process can't outlive the test)
/// and the address it bound -- read off its own first stdout line, the same
/// contract `main.rs`'s doc comment describes.
fn spawn_mock_llm_upstream(prompt_tokens: u32, completion_tokens: u32) -> (ChildGuard, SocketAddr) {
    let bin = mock_upstream_bin_path();
    let mut child = Command::new(bin)
        .args([
            "--listen",
            "127.0.0.1:0",
            "--prompt-tokens",
            &prompt_tokens.to_string(),
            "--tokens",
            &completion_tokens.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn mock-upstream");

    let stdout = child.stdout.take().expect("mock-upstream stdout not piped");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .expect("failed to read mock-upstream's startup line");
    // "mock-upstream listening on 127.0.0.1:PORT protocol=auto" -- see
    // `testing/mockupstream/src/main.rs`'s `main` doc comment for why this is
    // guaranteed to be the first, already-flushed stdout line.
    let addr_str = line
        .split_whitespace()
        .skip_while(|tok| *tok != "on")
        .nth(1)
        .unwrap_or_else(|| {
            panic!("could not find an address in mock-upstream's startup line: {line:?}")
        });
    let addr: SocketAddr = addr_str.parse().unwrap_or_else(|e| {
        panic!("mock-upstream printed an unparseable address {addr_str:?}: {e}")
    });

    (ChildGuard(child), addr)
}

/// The load-bearing test: two requests through a real
/// `llm-proxy` listener to a real (mock) upstream, then a real HTTP scrape of
/// `/stats` on the real admin server -- and the rendered text must show
/// exactly what happened, not an empty body and not a fabricated reading.
#[test]
fn served_requests_are_reflected_in_stats() {
    check_metadata_delivery(false);
}

#[test]
#[cfg(unix)]
fn metadata_write_failure_preserves_forwarding_and_readiness() {
    check_metadata_delivery(true);
}

fn check_metadata_delivery(fail_collector: bool) {
    let upstream_addr = spawn_mock_upstream();
    let listener_port = free_port();
    let admin_port = free_port();

    let config_yaml = format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}

static_resources:
  listeners:
    - name: ingress_http
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_http
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: backend
                http_filters:
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

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
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
        upstream_ip = upstream_addr.ip(),
        upstream_port = upstream_addr.port(),
    );

    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-stats-e2e-test-{}-{}.yaml",
        std::process::id(),
        listener_port
    ));
    std::fs::write(&config_path, config_yaml).expect("failed to write temp config");
    let records_path = config_path.with_extension("records.jsonl");

    // `ChildGuard` (not a bare `Child`): this function gained several more
    // assertions, each a new chance to panic before
    // reaching the manual `kill` at the bottom -- see `ChildGuard`'s doc.
    // Inherit an ignored SIGXFSZ and a one-block file size limit to produce a
    // real append error on a regular file, without filesystem-global changes.
    let mut command = if fail_collector {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "trap '' XFSZ; ulimit -f 1; exec \"$@\"",
            "metadata-test",
            BIN,
        ]);
        command
    } else {
        Command::new(BIN)
    };
    let mut child = ChildGuard(
        command
            .args([
                "-c",
                config_path.to_str().unwrap(),
                "--concurrency",
                "1",
                "--drain-time-s",
                "0",
                "--request-records-file",
                records_path.to_str().unwrap(),
            ])
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn llm-proxy"),
    );

    let stderr = child.0.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );
    let admin_ready = wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT);
    assert!(
        admin_ready,
        "admin at 127.0.0.1:{admin_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );

    // Two real requests through the real router to the real (mock) upstream
    // -- each a fresh h1 connection (connect-per-stream, matching this
    // router's v1 h1 behavior), so this also proves `upstream_rq` counts
    // requests, not connections.
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    for _ in 0..2 {
        let response = get(listener_addr, "/v1/chat/completions", "test.local");
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected the proxied request to succeed, got:\n{response}"
        );
    }

    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    if fail_collector {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let scrape = get(admin_addr, "/stats/prometheus", "admin.local");
            if scrape.contains("envoy_llmproxy_metadata_write_failures 1") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "collector never reported its write failure: {scrape}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(get(listener_addr, "/after-failure", "test.local").starts_with("HTTP/1.1 200"));
        assert!(get(admin_addr, "/ready", "admin.local").starts_with("HTTP/1.1 200"));
        let scrape = get(admin_addr, "/stats/prometheus", "admin.local");
        assert!(
            scrape.contains("envoy_llmproxy_metadata_admission{outcome=\"closed\"} 1")
                || scrape.contains("envoy_llmproxy_metadata_admission{outcome=\"closed\"} 2"),
            "the post-failure request must encounter closed capture admission: {scrape}"
        );
        assert!(scrape.contains("envoy_llmproxy_metadata_queue_depth 0"));
        drop(child);
        let _ = std::fs::remove_file(&records_path);
        let _ = std::fs::remove_file(&config_path);
        return;
    }
    let stats_response = get(admin_addr, "/stats", "admin.local");
    assert!(
        stats_response.starts_with("HTTP/1.1 200"),
        "expected /stats to answer 200, got:\n{stats_response}"
    );
    let body = stats_response
        .split("\r\n\r\n")
        .nth(1)
        .expect("response has a body separated from headers by a blank line");
    assert!(
        body.contains("cluster.backend.upstream_rq_total: 2"),
        "expected /stats to report 2 real requests against cluster \"backend\", got body:\n{body}\n\
         (full response: {stats_response})"
    );

    // `DOWNSTREAM_CX_TOTAL{listener}` -- the two
    // `get()` calls above each connect-then-close a fresh TCP connection
    // (`Connection: close`, no keep-alive reuse), so they are two ACCEPTED
    // connections on `ingress_http`'s accept loop -- PLUS one more from
    // `wait_for_connectable(("127.0.0.1", listener_port), ..)` above: its
    // final, successful `TcpStream::connect` is itself a real connection
    // `ingress_http`'s accept loop accepts and counts, even though it sends
    // no HTTP request before being dropped. 2 + 1 = 3, and this is the right
    // number, not a fudge -- `downstream_cx_total` counts every accepted
    // connection, not every HTTP request (that's `upstream_rq`'s job).
    // Asserted on BOTH rendered endpoints -- see this file's module doc: the
    // Envoy-text renderer had no case for this stat and silently omitted it
    // while Prometheus reported it correctly.
    let prometheus_response = get(admin_addr, "/stats/prometheus", "admin.local");
    assert!(
        prometheus_response.starts_with("HTTP/1.1 200"),
        "expected /stats/prometheus to answer 200, got:\n{prometheus_response}"
    );
    let prometheus_body = prometheus_response
        .split("\r\n\r\n")
        .nth(1)
        .expect("response has a body separated from headers by a blank line");
    assert!(
        prometheus_body.contains("envoy_downstream_cx_total{listener=\"ingress_http\"} 3"),
        "expected /stats/prometheus to report 3 accepted connections on listener \
         \"ingress_http\" (2 requests + 1 readiness probe), got body:\n{prometheus_body}\n\
         (full response: {prometheus_response})"
    );

    // The Envoy-text endpoint must agree. `get()` above opened one more
    // connection to fetch `/stats/prometheus`, but that one lands on the
    // ADMIN listener, not `ingress_http`, so this count is still 3 -- which
    // is itself worth asserting: it proves the counter is keyed per listener
    // rather than counting every accepted connection in the process.
    let stats_response = get(admin_addr, "/stats", "admin.local");
    assert!(
        stats_response.contains("listener.ingress_http.downstream_cx_total: 3"),
        "expected /stats to agree with /stats/prometheus on the connection count; \
         two renderers over one registry disagreeing is the bug this asserts against. \
         Got:\n{stats_response}"
    );

    let pid = child.0.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = child.0.try_wait() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
            panic!("proxy did not finish metadata drain before shutdown deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let records_text = std::fs::read_to_string(&records_path).unwrap();
    let records: Vec<proxy_observability::records::RequestRecord> = records_text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        records.len(),
        2,
        "all completed requests must survive graceful shutdown"
    );
    assert_ne!(records[0].request_id, records[1].request_id);
    for record in &records {
        assert_eq!(record.status, Some(200));
        assert_eq!(record.tenant_id, "default");
        assert!(record.user_id.is_none());
        assert_eq!(record.attempt_count, 1);
        assert_eq!(record.attempts[0].status, Some(200));
        assert_eq!(record.attempts[0].cluster.as_deref(), Some("backend"));
        assert_eq!(
            record.attempts[0].termination,
            proxy_observability::records::Termination::Complete
        );
        assert_eq!(record.instance_id.len(), 32);
        assert!(chrono_timestamp_is_rfc3339(&record.started_at));
    }
    let _ = std::fs::remove_file(&records_path);
    let _ = std::fs::remove_file(&config_path);
}

fn chrono_timestamp_is_rfc3339(value: &str) -> bool {
    // The envelope uses RFC3339 rather than an epoch string ending in Z.
    value.contains('T') && value.contains('-') && value.ends_with("+00:00")
}

/// `LLM_CLIENT_TOKEN_USAGE{provider,type}`
/// through the same real-binary/real-upstream/rendered-body shape as
/// [`served_requests_are_reflected_in_stats`] above. This needs a real
/// upstream that returns an OpenAI-shaped `usage` object (the plain
/// `200 OK`-with-no-body mock the other test uses has nothing for
/// `llmproxy.usage` to parse), so this spawns a real `mock-upstream`
/// (`testing/mockupstream`) instead -- see [`spawn_mock_llm_upstream`].
///
/// `access_log` has to be configured on the listener even though this test
/// never reads the log file: `FilterChainHandler::handle` only wraps a
/// response in `LoggingBody` (and so only ever calls `finish()`, which is
/// where `GenAiTokenStats::record_usage` is called) when `access_loggers` is
/// non-empty -- see `crates/proxy-http/src/filter_manager.rs`'s `handle`. A
/// listener with `llmproxy.usage` configured but no `access_log` would
/// silently never record token usage at all, same shape as the gap this
/// test closes for `downstream_cx_total`.
#[test]
fn token_usage_is_reflected_in_stats_prometheus() {
    const PROMPT_TOKENS: u32 = 37;
    const COMPLETION_TOKENS: u32 = 11;

    let (_upstream_guard, upstream_addr) =
        spawn_mock_llm_upstream(PROMPT_TOKENS, COMPLETION_TOKENS);
    let listener_port = free_port();
    let admin_port = free_port();

    let log_path = std::env::temp_dir().join(format!(
        "llm-proxy-token-usage-e2e-test-{}-{}.log",
        std::process::id(),
        listener_port
    ));
    let log_path_str = log_path.display().to_string();

    let config_yaml = format!(
        r#"
admin:
  address:
    socket_address: {{ address: 127.0.0.1, port_value: {admin_port} }}

static_resources:
  listeners:
    - name: ingress_llm
      address:
        socket_address: {{ address: 127.0.0.1, port_value: {listener_port} }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.http_connection_manager
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
                stat_prefix: ingress_llm
                http_filters:
                  - name: llmproxy.usage
                    typed_config:
                      "@type": type.llmproxy.dev/envoy.config.core.v3.DataSource
                      inline_string: openai
                  - name: envoy.filters.http.router
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
                route_config:
                  name: local_route
                  virtual_hosts:
                    - name: backend
                      domains: ["*"]
                      routes:
                        - match:
                            prefix: "/"
                          route:
                            cluster: llm_backend
                access_log:
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: {log_path_str}
                      log_format:
                        text_format: "%LLM_INPUT_TOKENS% %LLM_OUTPUT_TOKENS%\n"

  clusters:
    - name: llm_backend
      type: STATIC
      connect_timeout: 5s
      lb_policy: ROUND_ROBIN
      load_assignment:
        cluster_name: llm_backend
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: {upstream_ip}, port_value: {upstream_port} }}
"#,
        upstream_ip = upstream_addr.ip(),
        upstream_port = upstream_addr.port(),
    );

    let config_path = std::env::temp_dir().join(format!(
        "llm-proxy-token-usage-e2e-test-{}-{}.yaml",
        std::process::id(),
        listener_port
    ));
    std::fs::write(&config_path, config_yaml).expect("failed to write temp config");

    let mut proxy_child = ChildGuard(
        Command::new(BIN)
            .args(["-c", config_path.to_str().unwrap(), "--concurrency", "1"])
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn llm-proxy"),
    );

    let stderr = proxy_child.0.stderr.take().expect("child stderr not piped");
    let rx = spawn_line_reader(BufReader::new(stderr));

    let listener_ready = wait_for_connectable(("127.0.0.1", listener_port), STARTUP_TIMEOUT);
    assert!(
        listener_ready,
        "listener at 127.0.0.1:{listener_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );
    let admin_ready = wait_for_connectable(("127.0.0.1", admin_port), STARTUP_TIMEOUT);
    assert!(
        admin_ready,
        "admin at 127.0.0.1:{admin_port} did not become connectable in time \
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );

    // One real, non-streaming chat completion request -- `mock-upstream`
    // only reports `stream: true` responses when the request body asks for
    // it, so a plain JSON body with no `"stream"` field gets back its
    // non-streaming, usage-bearing response.
    let listener_addr: SocketAddr = format!("127.0.0.1:{listener_port}").parse().unwrap();
    let response = post(
        listener_addr,
        "/v1/chat/completions",
        "test.local",
        r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#,
    );
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected the proxied chat completion to succeed, got:\n{response}\n\
         (stderr so far: {:?})",
        drain_available_lines(&rx)
    );

    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    // Deliberately `/stats/prometheus`, not `/stats` -- see this file's
    // module doc for why `llm.client.token.usage` has no Envoy-text
    // rendering to assert against at all.
    let prometheus_response = get(admin_addr, "/stats/prometheus", "admin.local");
    assert!(
        prometheus_response.starts_with("HTTP/1.1 200"),
        "expected /stats/prometheus to answer 200, got:\n{prometheus_response}"
    );
    let body = prometheus_response
        .split("\r\n\r\n")
        .nth(1)
        .expect("response has a body separated from headers by a blank line");
    // `tenant` is a third label on this instrument now. This config
    // has no `auth` filter, so every series carries the no-tenant sentinel,
    // and the label order is the renderer's own sorted order (provider,
    // tenant, type) -- not the order they are declared in.
    assert!(
        body.contains(&format!(
            "envoy_llm_client_token_usage{{provider=\"llm_backend\",\
             tenant=\"{LLM_CLIENT_TOKEN_USAGE_NO_TENANT}\",type=\"input\"}} {PROMPT_TOKENS}"
        )),
        "expected /stats/prometheus to report {PROMPT_TOKENS} input tokens for provider \
         \"llm_backend\", got body:\n{body}\n(full response: {prometheus_response})"
    );
    assert!(
        body.contains(&format!(
            "envoy_llm_client_token_usage{{provider=\"llm_backend\",\
             tenant=\"{LLM_CLIENT_TOKEN_USAGE_NO_TENANT}\",type=\"output\"}} \
             {COMPLETION_TOKENS}"
        )),
        "expected /stats/prometheus to report {COMPLETION_TOKENS} output tokens for provider \
         \"llm_backend\", got body:\n{body}\n(full response: {prometheus_response})"
    );

    let pid = proxy_child.0.id().to_string();
    let _ = Command::new("kill").arg("-TERM").arg(&pid).status();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(Some(_)) = proxy_child.0.try_wait() {
            break;
        }
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&log_path);
}
