//! The dialect's `observability.traces` block (ADR-0008), lowered through the
//! real pipeline into the snapshot the Envoy-mode loader builds. Defaults and
//! ranges belong to `node.metadata["io.llmproxy.traces"]`
//! (`proxy-config/tests/traces_namespace.rs`); these tests pin what the
//! dialect adds: the key, the `observability.traces.<field>` paths for
//! required fields, duration syntax, and the requirement for `auth`.

use proxy_observability::traces::config::{
    S3Credentials, S3Destination, TraceCodec, TraceExportConfig,
};
use proxy_simple_config::{lower_to_loaded, parse_simple_config};
use std::path::PathBuf;
use std::time::Duration;

const BASE: &str = r#"version: 0
providers:
  openai: { type: openai, base_url: "http://127.0.0.1:1", api_key: sk-test }
routes:
  - { model: "*", provider: openai }
"#;

const AUTH: &str = "auth:\n  hmac_secret: \"0123456789abcdef0123456789abcdef\"\n  keys:\n    - { id: k1, tenant: acme, digest: \"0000000000000000000000000000000000000000000000000000000000000000\" }\n";

const REQUIRED: &str = "    directory: /var/lib/traces\n    max_disk_bytes: 10737418240\n";

fn load_text(text: &str) -> Result<Option<TraceExportConfig>, String> {
    let config = parse_simple_config(text).map_err(|e| e.to_string())?;
    let loaded = lower_to_loaded(&config).map_err(|e| e.to_string())?;
    let snapshot = proxy_config::build_snapshot(&loaded).map_err(|e| e.to_string())?;
    Ok(snapshot.traces)
}

fn load(traces: &str) -> Result<Option<TraceExportConfig>, String> {
    load_text(&format!("{BASE}{AUTH}observability:\n  traces:\n{traces}"))
}

#[test]
fn a_dialect_block_reaches_the_snapshot_like_envoy_mode() {
    let config = load(REQUIRED).unwrap().expect("traces configured");
    assert_eq!(
        config,
        TraceExportConfig {
            directory: PathBuf::from("/var/lib/traces"),
            max_disk_bytes: 10 << 30,
            max_age: None,
            codec: TraceCodec::Gzip,
            max_request_body_bytes: 1 << 20,
            max_response_body_bytes: 4 << 20,
            max_memory_bytes: 256 << 20,
            max_queued_traces: 4096,
            segment_max_bytes: 64 << 20,
            segment_max_age: Duration::from_secs(300),
            max_open_segments: 64,
            s3: None,
        }
    );
    let tuned = load(&format!(
        "{REQUIRED}    max_age: 168h\n    codec: zstd\n    zstd_window_log: 22\n    \
         segment_max_age: 90s\n    max_open_segments: 8\n"
    ))
    .unwrap()
    .unwrap();
    assert_eq!(tuned.max_age, Some(Duration::from_secs(168 * 3600)));
    assert_eq!(tuned.codec, TraceCodec::Zstd { window_log: 22 });
    assert_eq!(tuned.segment_max_age, Duration::from_secs(90));
    assert_eq!(tuned.max_open_segments, 8);

    let s3 = load(&format!(
        "{REQUIRED}    s3:\n      bucket: my-traces\n      region: eu-west-1\n      \
         path_style: true\n      prefix: llmproxy\n      access_key_id: AK\n      \
         secret_access_key: SK\n      session_token: TOK\n      upload_timeout: 30s\n"
    ))
    .unwrap()
    .unwrap()
    .s3;
    assert_eq!(
        s3,
        Some(S3Destination {
            bucket: "my-traces".into(),
            region: "eu-west-1".into(),
            endpoint: None,
            path_style: true,
            prefix: "llmproxy".into(),
            credentials: S3Credentials {
                access_key_id: "AK".into(),
                secret_access_key: "SK".into(),
                session_token: Some("TOK".into()),
            },
            upload_timeout: Duration::from_secs(30),
        })
    );
}

/// A missing required field is reported at its dialect path.
#[test]
fn missing_required_fields_name_their_dialect_path() {
    for field in ["directory", "max_disk_bytes"] {
        let traces: String = REQUIRED
            .lines()
            .filter(|l| !l.trim_start().starts_with(&format!("{field}:")))
            .map(|l| format!("{l}\n"))
            .collect();
        let error = load(&traces).unwrap_err();
        assert!(
            error.contains(&format!("observability.traces.{field}")),
            "{field}: {error}"
        );
    }
    let all = [
        ("bucket", "my-traces"),
        ("region", "eu-west-1"),
        ("access_key_id", "AK"),
        ("secret_access_key", "SK"),
    ];
    for missing in all.map(|(k, _)| k) {
        let s3: String = all
            .iter()
            .filter(|(k, _)| *k != missing)
            .map(|(k, v)| format!("      {k}: {v}\n"))
            .collect();
        let error = load(&format!("{REQUIRED}    s3:\n{s3}")).unwrap_err();
        assert!(
            error.contains(&format!("observability.traces.s3.{missing}")),
            "{missing}: {error}"
        );
    }
}

#[test]
fn unknown_fields_fail_at_their_dialect_path() {
    let error = load(&format!("{REQUIRED}    enabled: true\n")).unwrap_err();
    assert!(error.contains("enabled"), "{error}");
    let error = load(&format!(
        "{REQUIRED}    s3:\n      bucket: my-traces\n      region: r\n      access_key_id: a\n      \
         secret_access_key: b\n      acl: public\n"
    ))
    .unwrap_err();
    assert!(error.contains("acl"), "{error}");
}

/// The dialect rejects the block without `auth`; with `auth` the same block
/// loads, so the rejection is for that reason and no other.
#[test]
fn traces_without_auth_fail_at_observability_traces() {
    let text = format!("{BASE}observability:\n  traces:\n{REQUIRED}");
    let error = load_text(&text).unwrap_err();
    assert!(
        error.contains("observability.traces") && error.contains("requires auth"),
        "{error}"
    );
    assert!(load(REQUIRED).unwrap().is_some());
}

/// Ranges and cross-field rules keep the Envoy-mode path of the namespace the
/// dialect lowers to, and durations use the dialect's syntax.
#[test]
fn range_errors_report_the_namespace_path_and_bad_durations_fail() {
    let error = load(&format!("{REQUIRED}    max_open_segments: 0\n")).unwrap_err();
    assert!(
        error.contains("node.metadata[\"io.llmproxy.traces\"].max_open_segments"),
        "{error}"
    );
    let error = load(&format!("{REQUIRED}    segment_max_age: 5\n")).unwrap_err();
    assert!(
        error.contains("observability.traces.segment_max_age") && error.contains("unknown unit"),
        "{error}"
    );
}
