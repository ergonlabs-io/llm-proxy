//! The dialect's `admin` object form, lowered through the real pipeline
//! into the snapshot the Envoy-mode loader builds. The namespace's own
//! strictness is `proxy-config/tests/admin_tls_namespace.rs`; these tests
//! pin what the dialect adds: the object form, its paths, and the key.

use proxy_config::ir::DataSourceIR;
use proxy_simple_config::{lower_to_loaded, parse_simple_config};
use std::path::PathBuf;

const BASE: &str = r#"version: 0
providers:
  openai: { type: openai, base_url: "http://127.0.0.1:1", api_key: sk-test }
routes:
  - { model: "*", provider: openai }
"#;

fn load(admin: &str) -> Result<proxy_config::ConfigSnapshot, String> {
    let config =
        parse_simple_config(&format!("{BASE}admin: {admin}\n")).map_err(|e| e.to_string())?;
    let loaded = lower_to_loaded(&config).map_err(|e| e.to_string())?;
    proxy_config::build_snapshot(&loaded).map_err(|e| e.to_string())
}

#[test]
fn admin_tls_reaches_the_snapshot_and_the_shorthand_stays_plain() {
    let snapshot = load(
        "{ address: \"0.0.0.0:9901\", tls: { cert_file: /etc/admin.crt, key_file: /etc/admin.key } }",
    )
    .unwrap();
    assert_eq!(snapshot.admin, Some("0.0.0.0:9901".parse().unwrap()));
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

    for plain in ["\"127.0.0.1:9901\"", "{ address: \"127.0.0.1:9901\" }"] {
        let snapshot = load(plain).unwrap();
        assert_eq!(
            snapshot.admin,
            Some("127.0.0.1:9901".parse().unwrap()),
            "{plain}"
        );
        assert!(
            snapshot.admin_tls.is_none(),
            "{plain} must serve plain HTTP"
        );
    }
}

#[test]
fn admin_object_errors_name_their_field() {
    let err = load("{ address: \"nope\" }").unwrap_err();
    assert!(err.contains("admin.address"), "{err}");
    let err = load("\"nope\"").unwrap_err();
    assert!(
        err.contains("admin") && !err.contains("admin.address"),
        "{err}"
    );
    // An incomplete `tls` matches neither form of the untagged `admin`.
    let err =
        load("{ address: \"127.0.0.1:9901\", tls: { cert_file: /etc/admin.crt } }").unwrap_err();
    assert!(err.contains("admin"), "{err}");
}
