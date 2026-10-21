//! The capture agent was retired in 0.7.0. A bootstrap that still carries its
//! namespace must fail with the full path, not be ignored (AGENTS.md
//! invariant 1), and the message must point at the replacement.
use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};

const PATH: &str = "node.metadata[\"io.llmproxy.capture\"]";

fn load(yaml: &str) -> Result<proxy_config::ConfigSnapshot, proxy_config::ConfigError> {
    build_snapshot(&parse_bootstrap(
        yaml.as_bytes(),
        ConfigFormat::Yaml,
        StrictMode::Strict,
    )?)
}

#[test]
fn the_retired_capture_key_fails_with_its_full_path_and_the_replacement() {
    // A disabled namespace is rejected too: presence alone is the error.
    for value in [
        "{ version: 1, metadata: { enabled: false } }",
        "{ version: 1, metadata: { enabled: true } }",
        "{}",
    ] {
        let yaml = format!("node:\n  metadata:\n    io.llmproxy.capture: {value}\n");
        let message = load(&yaml).unwrap_err().to_string();
        assert!(message.contains(PATH), "{message}");
        assert!(message.contains("retired"), "{message}");
        assert!(message.contains("io.llmproxy.traces"), "{message}");
    }
}

#[test]
fn a_bootstrap_without_the_capture_key_still_loads() {
    load("node:\n  metadata:\n    other: 1\n").expect("no capture key, no error");
}
