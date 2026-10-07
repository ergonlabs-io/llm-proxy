#![cfg(unix)]
use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};
const PREFIX: &str = "node.metadata[\"io.llmproxy.capture\"]";
fn parse(value: &str) -> Result<proxy_config::ConfigSnapshot, proxy_config::ConfigError> {
    let yaml = format!("node:\n  metadata:\n    io.llmproxy.capture: {value}\n");
    build_snapshot(&parse_bootstrap(
        yaml.as_bytes(),
        ConfigFormat::Yaml,
        StrictMode::Strict,
    )?)
}
fn enabled(extra: &str) -> String {
    format!("{{ version: 1, metadata: {{ enabled: true }}, policy: {{ version: first }}, endpoint: {{ unix_socket_path: /tmp/agent.sock, expected_agent_uid: 0, expected_node_id: agent, producer_id: proxy }}, emergency_control: {{ unix_socket_path: /tmp/control.sock, operator_uid: 0 }} {extra} }}")
}

#[test]
fn capture_fields_fail_with_exact_paths() {
    for (value, path) in [
        ("{}", ".version"),
        ("{ metadata_enabled: false }", ".metadata_enabled"),
        ("null", ""),
        ("{ body_capture: true }", ".body_capture"),
        (
            "{version: 1, metadata: {enabled: false, max_attempts: 8}}",
            ".metadata.max_attempts",
        ),
        (
            "{version: 1, metadata: {enabled: false}, budgets: {}}",
            ".budgets",
        ),
        (
            "{version: 1, metadata: {enabled: null}}",
            ".metadata.enabled",
        ),
        ("{version: 1.5}", ".version"),
    ] {
        assert!(parse(value)
            .unwrap_err()
            .to_string()
            .contains(&format!("{PREFIX}{path}")));
    }
    for (extra, path) in [
        (
            ", budgets: {max_queue_events: 1.5}",
            ".budgets.max_queue_events",
        ),
        (
            ", budgets: {max_capture_memory_bytes: 1}",
            ".budgets.max_capture_memory_bytes",
        ),
        (
            ", budgets: {max_queue_retained_bytes: 1}",
            ".budgets.max_queue_retained_bytes",
        ),
        (
            ", transport: {ack_deadline_seconds: 1.0e100}",
            ".transport.ack_deadline_seconds",
        ),
        (
            ", transport: {backoff_initial_seconds: 2, backoff_max_seconds: 1}",
            ".transport.backoff_initial_seconds",
        ),
        (", bodies: {}", ".bodies"),
    ] {
        assert!(parse(&enabled(extra))
            .unwrap_err()
            .to_string()
            .contains(&format!("{PREFIX}{path}")));
    }
}

#[test]
fn defaults_policy_identity_and_dynamic_carry_forward() {
    assert!(parse("{version: 1}").unwrap().end_user_capture.is_none());
    assert!(parse("{version: 1, metadata: {enabled: false}}")
        .unwrap()
        .end_user_capture
        .is_none());
    let snapshot = parse(&enabled("")).unwrap();
    let config = snapshot.end_user_capture.as_ref().unwrap();
    assert_eq!(config.metadata.max_attempts, 8);
    assert_eq!(config.budgets.max_active_requests, 4096);
    assert_eq!(config.transport.max_attempts, 4);
    let dynamic = snapshot.with_dynamic_resources(
        Default::default(),
        Default::default(),
        Default::default(),
        proxy_config::ir::SnapshotVersion(2),
    );
    assert_eq!(dynamic.end_user_capture.as_ref(), Some(config));
    let changed =
        parse(&enabled("").replace("enabled: true", "enabled: true, max_attempts: 2")).unwrap();
    assert_ne!(
        config.policy_version,
        changed.end_user_capture.unwrap().policy_version
    );
    let endpoint = parse(&enabled("").replace("/tmp/agent.sock", "/tmp/other.sock")).unwrap();
    assert_eq!(
        config.policy_version,
        endpoint.end_user_capture.unwrap().policy_version
    );
}

#[test]
fn identity_path_bounds_and_platform_limits() {
    for (old, new, path) in [
        (
            "expected_agent_uid: 0",
            "expected_agent_uid: -1",
            ".endpoint.expected_agent_uid",
        ),
        (
            "expected_agent_uid: 0",
            "expected_agent_uid: 4294967296",
            ".endpoint.expected_agent_uid",
        ),
        ("/tmp/agent.sock", "relative", ".endpoint.unix_socket_path"),
        (
            "/tmp/control.sock",
            "/tmp/agent.sock",
            ".emergency_control.unix_socket_path",
        ),
        ("version: first", "version: ''", ".policy.version"),
    ] {
        assert!(parse(&enabled("").replace(old, new))
            .unwrap_err()
            .to_string()
            .contains(&format!("{PREFIX}{path}")));
    }
    for value in ["null", "false", "1.5", "9007199254740992"] {
        let config = enabled(&format!(", budgets: {{max_queue_retained_bytes: {value}}}"));
        assert!(parse(&config).is_err());
    }
}

#[test]
fn permissive_mode_cannot_strip_capture_typos() {
    let yaml="node:\n  metadata:\n    io.llmproxy.capture: {version: 1, metadata: {enabled: false}, bodies: {}}\n";
    let loaded =
        parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Permissive).unwrap();
    assert!(build_snapshot(&loaded)
        .unwrap_err()
        .to_string()
        .contains(&format!("{PREFIX}.bodies")));
}
