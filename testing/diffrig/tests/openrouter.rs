//! Hermetic OpenRouter endpoint, authentication, model ID, catalog and SSE coverage.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use diffrig::harness::{free_port, resolve_llm_proxy_bin, ProxyProcess, ScratchDir, READY_TIMEOUT};

#[test]
fn openrouter_forwards_model_ids_catalog_and_streaming() {
    let bin = resolve_llm_proxy_bin();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let upstream_port = upstream.local_addr().unwrap().port();
    let worker = std::thread::spawn(move || {
        for index in 0..3 {
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut stream = loop {
                match upstream.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "upstream accept timeout");
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 32768);
                if request.ends_with(b"\r\n\r\n") {
                    break request.len();
                }
            };
            let headers = String::from_utf8(request.clone()).unwrap().to_lowercase();
            assert!(headers.contains("authorization: bearer test-router-key\r\n"));
            let expected_path = "/api/v1/chat/completions?test=1";
            assert!(
                headers.lines().next().unwrap().contains(expected_path),
                "{headers}"
            );
            let length: usize = headers
                .lines()
                .find_map(|line| {
                    line.strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap())
                })
                .unwrap_or(0);
            assert!(length <= 4096);
            request.resize(header_end + length, 0);
            stream.read_exact(&mut request[header_end..]).unwrap();
            {
                let body: serde_json::Value =
                    serde_json::from_slice(&request[header_end..]).unwrap();
                let expected_model = if index == 0 {
                    "anthropic/claude-test"
                } else {
                    "future-vendor/new-model:free"
                };
                assert_eq!(body["model"], expected_model);
                assert_eq!(body["stream"], index == 2);
            }
            let (content_type, body) = if index == 2 {
                (
                    "text/event-stream",
                    "data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: [DONE]\n\n",
                )
            } else {
                ("application/json", "{\"choices\":[{\"message\":{\"content\":\"hello\"}}],\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1,\"total_tokens\":2}}")
            };
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        }
    });
    let scratch = ScratchDir::new("openrouter");
    let port = free_port();
    let admin_port = free_port();
    let config = scratch.write("proxy.yaml", &format!("version: 0\nlisten: 127.0.0.1:{port}\nadmin: 127.0.0.1:{admin_port}\nproviders:\n  openrouter:\n    base_url: http://127.0.0.1:{upstream_port}\n    api_key: test-router-key\nroutes: []\nmodels:\n  anthropic/claude-test: {{ providers: [openrouter] }}\n  future-vendor/new-model:free: {{ providers: [openrouter] }}\n  local-alias: {{ providers: [{{ provider: openrouter, model: future-vendor/new-model:free }}] }}\n"));
    let mut contents = std::fs::read_to_string(&config).unwrap();
    contents.push_str(
        r#"
pricing:
  catalog: { source: hermetic-test }
  price_list:
    version: test-openrouter
    effective_from: "2026-10-08T00:00:00Z"
    entries:
      - provider_type: openrouter
        model: anthropic/claude-test
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 150
            cached_input_nanodollars_per_token: 75
            cache_write_nanodollars_per_token: 200
            output_nanodollars_per_token: 600
observability:
  access_logs:
    output: stdout
    format: json
"#,
    );
    std::fs::write(&config, contents).unwrap();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut proxy = ProxyProcess::spawn(&bin, &config, &scratch.path().join("proxy.log"));
    proxy.wait_until_ready(addr, READY_TIMEOUT);
    let admin_addr: SocketAddr = format!("127.0.0.1:{admin_port}").parse().unwrap();
    let mut admin = TcpStream::connect_timeout(&admin_addr, Duration::from_secs(5)).unwrap();
    admin
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    admin
        .write_all(b"GET /pricing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut inventory = String::new();
    admin.read_to_string(&mut inventory).unwrap();
    assert!(inventory.starts_with("HTTP/1.1 200"), "{inventory}");
    assert!(
        inventory.contains("hermetic-test") && inventory.contains("input_nanodollars_per_token")
    );
    for index in 0..4 {
        let model = if index == 0 {
            "anthropic/claude-test"
        } else {
            "future-vendor/new-model:free"
        };
        let body = if index == 2 {
            String::new()
        } else {
            serde_json::json!({"model": model, "messages": [{"role": "user", "content": "hi"}], "stream": index == 3}).to_string()
        };
        let (method, path) = if index == 2 {
            ("GET", "/v1/models")
        } else {
            ("POST", "/v1/chat/completions?test=1")
        };
        let mut client = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(client, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer client-key\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "request {index}: {response}"
        );
        assert!(
            response.contains(if index == 2 { "local-alias" } else { "hello" }),
            "{response}"
        );
        if index == 3 {
            assert!(response.contains("[DONE]"));
        }
    }
    worker.join().unwrap();
    let logs = std::fs::read_to_string(scratch.path().join("proxy.log")).unwrap();
    assert!(
        logs.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .any(|entry| entry["llm_list_cost_nanodollars"] == "750"
                || entry["llm_list_cost_nanodollars"] == 750),
        "request token cost must be recorded: {logs}"
    );
}
