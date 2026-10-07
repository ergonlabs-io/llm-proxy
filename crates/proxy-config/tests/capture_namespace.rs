use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

#[test]
fn proposed_capture_namespace_is_never_silently_accepted() {
    for value in [
        "{}",
        "{ metadata_enabled: false }",
        "null",
        "{ body_capture: true }",
    ] {
        let yaml = format!("node:\n  metadata:\n    io.llmproxy.capture: {value}\n");
        let loaded =
            parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict).unwrap();
        match build_snapshot(&loaded).unwrap_err() {
            ConfigError::UnsupportedField { field_path, .. } => {
                assert_eq!(field_path, "node.metadata[\"io.llmproxy.capture\"]")
            }
            error => panic!("expected unsupported capture namespace, got {error}"),
        }
    }
}
