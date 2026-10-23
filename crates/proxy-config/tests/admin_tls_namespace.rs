//! `node.metadata["io.llmproxy.admin_tls"]`: TLS on the admin listener,
//! which Envoy's own admin does not have. Strict, with full dotted paths.

use proxy_config::ir::DataSourceIR;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};
use std::path::PathBuf;

const PREFIX: &str = "node.metadata[\"io.llmproxy.admin_tls\"]";
const ADMIN: &str =
    "admin:\n  address: { socket_address: { address: 127.0.0.1, port_value: 9901 } }\n";

fn parse(admin: &str, value: &str) -> Result<proxy_config::ConfigSnapshot, String> {
    let yaml = format!("{admin}node:\n  metadata:\n    io.llmproxy.admin_tls: {value}\n");
    parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)
        .and_then(|loaded| build_snapshot(&loaded))
        .map_err(|e| e.to_string())
}

#[test]
fn envoy_mode_admin_tls_reaches_the_snapshot_as_a_file_certificate() {
    let snapshot = parse(
        ADMIN,
        "{ cert_file: /etc/admin.crt, key_file: /etc/admin.key }",
    )
    .unwrap();
    let spec = snapshot.admin_tls.expect("admin TLS configured");
    let [cert] = spec.certificates.as_slice() else {
        panic!("expected one certificate, got {:?}", spec.certificates);
    };
    assert_eq!(
        cert.cert_chain,
        DataSourceIR::File(PathBuf::from("/etc/admin.crt"))
    );
    assert_eq!(
        cert.private_key,
        DataSourceIR::File(PathBuf::from("/etc/admin.key"))
    );
    assert!(
        spec.validation.is_none(),
        "admin TLS asks no client certificate"
    );
    assert!(
        build_snapshot(
            &parse_bootstrap(ADMIN.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict).unwrap()
        )
        .unwrap()
        .admin_tls
        .is_none(),
        "no namespace means plain HTTP"
    );
}

/// Each rejection names its full path, and TLS with no admin address is a
/// load error rather than an inert block.
#[test]
fn admin_tls_rejects_unknown_missing_and_misplaced_values_by_path() {
    let cases = [
        (
            ADMIN,
            "{ cert_file: a, key_file: b, ca_file: c }",
            ".ca_file",
        ),
        (ADMIN, "{ cert_file: a }", ".key_file"),
        (ADMIN, "{ cert_file: \"\", key_file: b }", ".cert_file"),
        (ADMIN, "{ cert_file: 1, key_file: b }", ".cert_file"),
        (ADMIN, "[a, b]", ""),
        ("", "{ cert_file: a, key_file: b }", ""),
    ];
    for (admin, value, path) in cases {
        let err = parse(admin, value).expect_err(value);
        let full = format!("{PREFIX}{path}");
        assert!(
            err.contains(&full),
            "`{value}` (admin set: {}): expected {full} in {err}",
            !admin.is_empty()
        );
    }
    let err = parse("", "{ cert_file: a, key_file: b }").unwrap_err();
    assert!(err.contains("requires an admin address"), "{err}");
}
