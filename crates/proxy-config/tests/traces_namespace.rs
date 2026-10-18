//! `node.metadata["io.llmproxy.traces"]` (ADR-0008): strict, with full
//! dotted paths, and the documented defaults.

use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};
use proxy_observability::traces::config::{
    S3Credentials, S3Destination, TraceCodec, TraceExportConfig,
};
use std::path::PathBuf;
use std::time::Duration;

const PREFIX: &str = "node.metadata[\"io.llmproxy.traces\"]";
const REQUIRED: &str = "directory: /var/lib/traces, max_disk_bytes: 10737418240";
const S3: &str = "{ bucket: my-traces, region: eu-west-1, access_key_id: AKIAEXAMPLE, \
                  secret_access_key: s3cr3t-value }";

fn parse(value: &str) -> Result<proxy_config::ConfigSnapshot, proxy_config::ConfigError> {
    let yaml = format!("node:\n  metadata:\n    io.llmproxy.traces: {value}\n");
    build_snapshot(&parse_bootstrap(
        yaml.as_bytes(),
        ConfigFormat::Yaml,
        StrictMode::Strict,
    )?)
}

fn traces(extra: &str) -> Result<TraceExportConfig, String> {
    parse(&format!("{{ {REQUIRED}{extra} }}"))
        .map(|s| s.traces.expect("traces configured"))
        .map_err(|e| e.to_string())
}

/// Whether `error` names exactly `PREFIX` + `path`, not a longer field that
/// starts with it.
fn names(error: &str, path: &str) -> bool {
    let full = format!("{PREFIX}{path}");
    error.match_indices(&full).any(|(at, _)| {
        !error[at + full.len()..]
            .starts_with(|c: char| c.is_alphanumeric() || c == '_' || c == '[' || c == '.')
    })
}

/// Each case sets one field on top of a valid block and must fail at
/// exactly that field's path.
fn assert_fails_at(cases: &[(&str, &str)]) {
    for (extra, path) in cases {
        let error = traces(extra).expect_err(extra);
        assert!(names(&error, path), "{extra}: {error}");
    }
}

#[test]
fn absent_traces_is_none_and_the_minimal_block_takes_the_defaults() {
    let yaml = "node:\n  id: n\n";
    let snapshot = build_snapshot(
        &parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict).unwrap(),
    )
    .unwrap();
    assert!(snapshot.traces.is_none());

    assert_eq!(
        traces("").unwrap(),
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
}

#[test]
fn a_full_block_reaches_the_snapshot() {
    let config = parse(&format!(
        "{{ {REQUIRED}, max_age: 604800, codec: zstd, zstd_window_log: 22, \
         max_request_body_bytes: 2048, max_response_body_bytes: 4096, \
         max_memory_bytes: 1048576, max_queued_traces: 8, segment_max_bytes: 2097152, \
         segment_max_age: 30, max_open_segments: 4 }}"
    ))
    .unwrap()
    .traces
    .unwrap();
    assert_eq!(config.max_age, Some(Duration::from_secs(604_800)));
    assert_eq!(config.codec, TraceCodec::Zstd { window_log: 22 });
    assert_eq!(config.max_request_body_bytes, 2048);
    assert_eq!(config.max_response_body_bytes, 4096);
    assert_eq!(config.max_memory_bytes, 1 << 20);
    assert_eq!(config.max_queued_traces, 8);
    assert_eq!(config.segment_max_bytes, 2 << 20);
    assert_eq!(config.segment_max_age, Duration::from_secs(30));
    assert_eq!(config.max_open_segments, 4);

    let with_s3 = traces(
        ", s3: { bucket: my.traces, region: eu-west-1, endpoint: 'http://minio:9000', \
         path_style: true, prefix: a/b, access_key_id: AK, secret_access_key: SK, \
         session_token: TOK, upload_timeout: 30 }",
    )
    .unwrap();
    assert_eq!(
        with_s3.s3,
        Some(S3Destination {
            bucket: "my.traces".into(),
            region: "eu-west-1".into(),
            endpoint: Some("http://minio:9000".into()),
            path_style: true,
            prefix: "a/b".into(),
            credentials: S3Credentials {
                access_key_id: "AK".into(),
                secret_access_key: "SK".into(),
                session_token: Some("TOK".into()),
            },
            upload_timeout: Duration::from_secs(30),
        })
    );

    let defaults = traces(&format!(", s3: {S3}")).unwrap().s3.unwrap();
    assert_eq!(defaults.endpoint, None);
    assert!(!defaults.path_style);
    assert_eq!(defaults.prefix, "");
    assert_eq!(defaults.credentials.session_token, None);
    assert_eq!(defaults.upload_timeout, Duration::from_secs(120));
}

#[test]
fn missing_and_unknown_fields_fail_with_exact_paths() {
    for (value, path) in [
        ("{ max_disk_bytes: 10737418240 }", ".directory"),
        ("{ directory: /var/lib/traces }", ".max_disk_bytes"),
        (
            "{ directory: var/traces, max_disk_bytes: 10737418240 }",
            ".directory",
        ),
        ("null", ""),
    ] {
        let error = parse(value).unwrap_err().to_string();
        assert!(names(&error, path), "{value}: {error}");
    }
    assert_fails_at(&[(", enabled: true", ".enabled")]);
    for (s3, path) in [
        (
            "{ region: r, access_key_id: a, secret_access_key: b }",
            ".s3.bucket",
        ),
        (
            "{ bucket: my-traces, access_key_id: a, secret_access_key: b }",
            ".s3.region",
        ),
        (
            "{ bucket: my-traces, region: r, secret_access_key: b }",
            ".s3.access_key_id",
        ),
        (
            "{ bucket: my-traces, region: r, access_key_id: a }",
            ".s3.secret_access_key",
        ),
        (
            "{ bucket: my-traces, region: r, access_key_id: a, secret_access_key: b, acl: x }",
            ".s3.acl",
        ),
    ] {
        let error = traces(&format!(", s3: {s3}")).unwrap_err();
        assert!(names(&error, path), "{s3}: {error}");
    }
}

#[test]
fn ranges_fail_at_the_offending_field() {
    assert_fails_at(&[
        (", max_disk_bytes: 1024", ".max_disk_bytes"),
        (", max_age: 0", ".max_age"),
        (", max_age: 400000000", ".max_age"),
        (", codec: lz4", ".codec"),
        (", codec: zstd, zstd_window_log: 19", ".zstd_window_log"),
        (", codec: zstd, zstd_window_log: 28", ".zstd_window_log"),
        (", max_request_body_bytes: 1023", ".max_request_body_bytes"),
        (
            ", max_response_body_bytes: 67108865",
            ".max_response_body_bytes",
        ),
        (", max_memory_bytes: 1024", ".max_memory_bytes"),
        (", max_queued_traces: 0", ".max_queued_traces"),
        (", max_queued_traces: 1048577", ".max_queued_traces"),
        (", segment_max_bytes: 1048575", ".segment_max_bytes"),
        (", segment_max_bytes: 1073741825", ".segment_max_bytes"),
        (", segment_max_age: 9", ".segment_max_age"),
        (", segment_max_age: 3601", ".segment_max_age"),
        (", segment_max_age: 5m", ".segment_max_age"),
        (", max_open_segments: 0", ".max_open_segments"),
        (", max_open_segments: 4097", ".max_open_segments"),
        (", max_request_body_bytes: 1.5", ".max_request_body_bytes"),
    ]);
    for (s3_extra, path) in [
        (", upload_timeout: 0.5", ".s3.upload_timeout"),
        (", upload_timeout: 3601", ".s3.upload_timeout"),
    ] {
        let error =
            traces(&format!(", s3: {}{s3_extra} }}", S3.trim_end_matches(" }"))).unwrap_err();
        assert!(names(&error, path), "{s3_extra}: {error}");
    }
}

#[test]
fn zstd_window_log_with_gzip_is_rejected() {
    assert_fails_at(&[
        (", zstd_window_log: 24", ".zstd_window_log"),
        (", codec: gzip, zstd_window_log: 24", ".zstd_window_log"),
    ]);
}

#[test]
fn cross_field_rules_fail_at_the_field_they_bound() {
    assert_fails_at(&[
        // One full trace (default 1 MiB + 4 MiB) does not fit.
        (", max_memory_bytes: 1048576", ".max_memory_bytes"),
        // Uploaded objects expire by the bucket's lifecycle rules.
        (&format!(", max_age: 3600, s3: {S3}"), ".max_age"),
        // Below the largest line, so every line would seal a segment.
        (", segment_max_bytes: 1048576", ".segment_max_bytes"),
        // 2 x 64 x 64 MiB = 8 GiB does not fit in 2 MiB.
        (", max_disk_bytes: 2097152", ".max_disk_bytes"),
        // 64 x 2^27 = 8 GiB of encoder windows.
        (", codec: zstd, zstd_window_log: 27", ".zstd_window_log"),
        // Virtual-hosted style breaks the wildcard certificate.
        (
            ", s3: { bucket: my.traces, region: r, access_key_id: a, secret_access_key: b }",
            ".s3.path_style",
        ),
    ]);
}

#[test]
fn bad_s3_values_fail_at_their_own_path() {
    for (s3_extra, path) in [
        (", bucket: UPPER", ".s3.bucket"),
        (", bucket: ab", ".s3.bucket"),
        (", region: EU_WEST", ".s3.region"),
        (", endpoint: 'ftp://host'", ".s3.endpoint"),
        (", endpoint: 'https://host/path'", ".s3.endpoint"),
        (", endpoint: 'https://u:p@host'", ".s3.endpoint"),
        (", prefix: /lead", ".s3.prefix"),
        (", prefix: trail/", ".s3.prefix"),
        (", prefix: 'a//b'", ".s3.prefix"),
        (", prefix: 'a/../b'", ".s3.prefix"),
        (", path_style: 'yes'", ".s3.path_style"),
    ] {
        // Later keys win in YAML flow maps only if repeated, so rebuild
        // the block from a base that omits the field under test.
        let field = s3_extra.trim_start_matches(", ").split(':').next().unwrap();
        let base: Vec<_> = [
            ("bucket", "my-traces"),
            ("region", "eu-west-1"),
            ("access_key_id", "AK"),
            ("secret_access_key", "SK"),
        ]
        .into_iter()
        .filter(|(k, _)| *k != field)
        .map(|(k, v)| format!("{k}: {v}"))
        .collect();
        let error = traces(&format!(", s3: {{ {}{s3_extra} }}", base.join(", "))).unwrap_err();
        assert!(names(&error, path), "{s3_extra}: {error}");
    }
}

/// The credential type redacts itself, and no config error echoes a value.
#[test]
fn secrets_reach_neither_debug_output_nor_errors() {
    let config = traces(
        ", s3: { bucket: my-traces, region: eu-west-1, access_key_id: AKIAEXAMPLE, \
         secret_access_key: s3cr3t-value, session_token: tok-value }",
    )
    .unwrap();
    let debug = format!("{config:?}");
    assert!(debug.contains("AKIAEXAMPLE"), "the key id is not secret");
    for secret in ["s3cr3t-value", "tok-value"] {
        assert!(!debug.contains(secret), "{debug}");
    }
    let error = traces(
        ", max_age: 3600, s3: { bucket: my-traces, region: eu-west-1, access_key_id: AK, \
         secret_access_key: s3cr3t-value, session_token: tok-value }",
    )
    .unwrap_err();
    assert!(
        !error.contains("s3cr3t-value") && !error.contains("tok-value"),
        "{error}"
    );
}

/// Bootstrap-scoped: an xDS delivery carries the block forward unchanged.
#[test]
fn traces_survive_dynamic_resource_delivery() {
    let snapshot = parse(&format!("{{ {REQUIRED} }}")).unwrap();
    let dynamic = snapshot.with_dynamic_resources(
        Default::default(),
        Default::default(),
        Default::default(),
        proxy_config::ir::SnapshotVersion(2),
    );
    assert!(dynamic.traces.is_some());
    assert_eq!(dynamic.traces, snapshot.traces);
}
