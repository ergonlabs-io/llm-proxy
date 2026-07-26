//! WP-24 (chunk 1) acceptance tests: HCM `access_log` -> `Vec<AccessLogIR>`.
//!
//! Covers stdout/stderr/file sinks, the Envoy default format, explicit
//! text/JSON formats, `status_code`/`response_flag` filters, and strict
//! rejection (with dotted paths) of unsupported logger types, filter kinds,
//! and unknown format operators.

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};
use proxy_observability::access_log::FormatOp;
use proxy_observability::ResponseFlag;

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// `access_log` block (caller-supplied, indented to match) wired into an
/// otherwise-minimal HCM with a match-all direct-response route (no cluster
/// needed).
fn hcm_with_access_log(access_log: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 8080 }}
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
                        - match: {{ prefix: "/" }}
                          direct_response: {{ status: 200 }}
                access_log:
{access_log}
"#
    );
    snapshot_from(&yaml)
}

fn access_logs(snapshot: &ConfigSnapshot) -> &[AccessLogIR] {
    let listener = snapshot.listeners.get("http").expect("listener");
    let NetworkFilterSpec::HttpConnectionManager(hcm) = &listener.filter_chains[0].filters[0]
    else {
        panic!("expected HCM filter");
    };
    &hcm.access_logs
}

fn err_path(err: &ConfigError) -> &str {
    match err {
        ConfigError::UnsupportedField { field_path, .. } => field_path,
        ConfigError::InvalidValue { field_path, .. } => field_path,
        ConfigError::UnknownTypeUrl { field_path, .. } => field_path,
        ConfigError::Validation { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

#[test]
fn stdout_sink_with_default_format() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
"#;
    let snapshot = hcm_with_access_log(yaml).expect("must lower");
    let logs = access_logs(&snapshot);
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].sink, AccessLogSink::Stdout);
    let AccessLogFormat::Text(fmt) = &logs[0].format else {
        panic!("expected text format");
    };
    // Envoy's default format opens with `[%START_TIME%]`.
    assert_eq!(fmt.0[0], FormatOp::Literal("[".to_string()));
    assert_eq!(fmt.0[1], FormatOp::StartTime(None));
    assert!(logs[0].filter.is_none());
}

#[test]
fn stderr_sink() {
    let yaml = r#"
                  - name: envoy.access_loggers.stderr
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog
"#;
    let snapshot = hcm_with_access_log(yaml).expect("must lower");
    assert_eq!(access_logs(&snapshot)[0].sink, AccessLogSink::Stderr);
}

#[test]
fn file_sink_with_explicit_text_format() {
    let yaml = r#"
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: /var/log/envoy/access.log
                      log_format:
                        text_format: "%RESPONSE_CODE% %PROTOCOL%\n"
"#;
    let snapshot = hcm_with_access_log(yaml).expect("must lower");
    let logs = access_logs(&snapshot);
    assert_eq!(
        logs[0].sink,
        AccessLogSink::File {
            path: "/var/log/envoy/access.log".to_string()
        }
    );
    let AccessLogFormat::Text(fmt) = &logs[0].format else {
        panic!("expected text format");
    };
    assert_eq!(
        fmt.0,
        vec![
            FormatOp::ResponseCode,
            FormatOp::Literal(" ".to_string()),
            FormatOp::Protocol,
            FormatOp::Literal("\n".to_string()),
        ]
    );
}

#[test]
fn file_sink_without_path_is_rejected() {
    let yaml = r#"
                  - name: envoy.access_loggers.file
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.file.v3.FileAccessLog
                      path: ""
                      log_format:
                        text_format: "x"
"#;
    let err = hcm_with_access_log(yaml).expect_err("empty path must be rejected");
    assert!(err_path(&err).contains("path"), "{err}");
}

#[test]
fn json_format_parses_each_value_as_a_format_string() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                      log_format:
                        json_format:
                          status: "%RESPONSE_CODE%"
                          proto: "%PROTOCOL%"
"#;
    let snapshot = hcm_with_access_log(yaml).expect("must lower");
    let logs = access_logs(&snapshot);
    let AccessLogFormat::Json(fields) = &logs[0].format else {
        panic!("expected json format");
    };
    assert_eq!(fields.len(), 2);
    let status = fields.iter().find(|(k, _)| k == "status").unwrap();
    assert_eq!(status.1 .0, vec![FormatOp::ResponseCode]);
    let proto = fields.iter().find(|(k, _)| k == "proto").unwrap();
    assert_eq!(proto.1 .0, vec![FormatOp::Protocol]);
}

#[test]
fn json_format_non_string_value_is_rejected() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                      log_format:
                        json_format:
                          status: 200
"#;
    let err = hcm_with_access_log(yaml).expect_err("numeric json_format value must be rejected");
    assert!(err_path(&err).contains("status"), "{err}");
}

#[test]
fn status_code_filter_lowers() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    filter:
                      status_code_filter:
                        comparison:
                          op: GE
                          value:
                            default_value: 500
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
"#;
    let snapshot = hcm_with_access_log(yaml).expect("must lower");
    let logs = access_logs(&snapshot);
    match &logs[0].filter {
        Some(AccessLogFilterIR::StatusCode { op, value }) => {
            assert_eq!(*op, ComparisonOp::Ge);
            assert_eq!(*value, 500);
        }
        other => panic!("expected status_code filter, got {other:?}"),
    }
}

#[test]
fn response_flag_filter_lowers() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    filter:
                      response_flag_filter:
                        flags: ["UF", "URX"]
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
"#;
    let snapshot = hcm_with_access_log(yaml).expect("must lower");
    let logs = access_logs(&snapshot);
    match &logs[0].filter {
        Some(AccessLogFilterIR::ResponseFlag(flags)) => {
            assert_eq!(
                flags,
                &vec![
                    ResponseFlag::UpstreamConnectionFailure,
                    ResponseFlag::UpstreamRetryLimitExceeded
                ]
            );
        }
        other => panic!("expected response_flag filter, got {other:?}"),
    }
}

#[test]
fn unmodeled_response_flag_code_is_rejected() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    filter:
                      response_flag_filter:
                        flags: ["DI"]
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
"#;
    let err = hcm_with_access_log(yaml).expect_err("DI is not implemented");
    assert!(err_path(&err).contains("flags"), "{err}");
}

#[test]
fn duration_filter_is_rejected_with_path() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    filter:
                      duration_filter:
                        comparison:
                          op: GE
                          value:
                            default_value: 1000
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
"#;
    let err = hcm_with_access_log(yaml).expect_err("duration_filter is not implemented");
    assert!(
        err_path(&err).contains("duration_filter"),
        "path should name duration_filter, got: {err}"
    );
}

/// A type URL that resolves in the descriptor pool (so it passes the
/// generic surface check) but isn't one of the two logger extensions
/// `convert_access_log` implements — must still be rejected, naming the
/// type URL and the dotted path, not silently accepted just because *some*
/// message decoded successfully.
#[test]
fn unknown_logger_type_url_is_rejected() {
    let yaml = r#"
                  - name: envoy.access_loggers.not_a_real_logger
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#;
    let err = hcm_with_access_log(yaml).expect_err("Router is not an access logger");
    match err {
        ConfigError::UnknownTypeUrl { field_path, .. } => {
            assert!(field_path.contains("access_log"), "{field_path}");
        }
        other => panic!("expected UnknownTypeUrl, got {other}"),
    }
}

#[test]
fn unknown_format_operator_is_rejected_with_path() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                      log_format:
                        text_format: "%NOT_A_REAL_OPERATOR%"
"#;
    let err = hcm_with_access_log(yaml).expect_err("unknown operator must be rejected");
    assert!(err_path(&err).contains("text_format"), "{err}");
}

#[test]
fn omit_empty_values_is_rejected_as_unimplemented() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                      log_format:
                        text_format: "x"
                        omit_empty_values: true
"#;
    let err = hcm_with_access_log(yaml).expect_err("omit_empty_values must be rejected");
    assert!(err_path(&err).contains("omit_empty_values"), "{err}");
}

#[test]
fn multiple_sinks_lower_in_order() {
    let yaml = r#"
                  - name: envoy.access_loggers.stdout
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog
                  - name: envoy.access_loggers.stderr
                    typed_config:
                      "@type": type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StderrAccessLog
"#;
    let snapshot = hcm_with_access_log(yaml).expect("must lower");
    let logs = access_logs(&snapshot);
    assert_eq!(logs.len(), 2);
    assert_eq!(logs[0].sink, AccessLogSink::Stdout);
    assert_eq!(logs[1].sink, AccessLogSink::Stderr);
}

#[test]
fn absent_access_log_lowers_to_empty_vec() {
    let yaml = r#"
static_resources:
  listeners:
    - name: http
      address:
        socket_address: { address: 0.0.0.0, port_value: 8080 }
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
                        - match: { prefix: "/" }
                          direct_response: { status: 200 }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    assert!(access_logs(&snapshot).is_empty());
}
