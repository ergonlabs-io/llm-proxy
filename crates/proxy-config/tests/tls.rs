//! WP-08 chunk A acceptance tests: TLS proto -> IR lowering.
//!
//! Covers the full supported `DownstreamTlsContext`/`UpstreamTlsContext`
//! surface: certificate counts, `TlsParameters` (including the
//! direction-dependent `TLS_AUTO` defaults), cipher-suite/curve name
//! translation, `CertificateValidationContext` (CA source + SAN matchers),
//! and `require_client_certificate`/session-resumption passthrough. Every
//! rejection case asserts on the offending dotted field path (ground rule
//! #2).

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// Wraps an `UpstreamTlsContext` YAML block into a full cluster and returns
/// the snapshot (so the borrowed `UpstreamTlsSpec` outlives the caller).
fn upstream_snapshot(ctx_yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  clusters:
    - name: c1
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
{ctx_yaml}
"#
    );
    snapshot_from(&yaml)
}

fn err_path(err: &ConfigError) -> &str {
    match err {
        ConfigError::UnsupportedField { field_path, .. } => field_path,
        ConfigError::InvalidValue { field_path, .. } => field_path,
        // `SdsSecretConfig.name`'s `min_len: 1` PGV constraint is caught
        // during `parse_bootstrap`, before `convert_certificate_sds_configs`
        // ever runs -- same defense-in-depth relationship as
        // `health_check.rs`'s `err_path`.
        ConfigError::Validation { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

const DOWNSTREAM_TLS_PATH: &str =
    "static_resources.listeners[0].filter_chains[0].transport_socket.typed_config";
const UPSTREAM_TLS_PATH: &str = "static_resources.clusters[0].transport_socket.typed_config";

// ---------------------------------------------------------------- helpers --

/// Wraps a `DownstreamTlsContext` YAML block into a full listener snapshot
/// (so the borrowed `DownstreamTlsSpec` outlives the caller).
fn downstream_snapshot(ctx_yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let yaml = format!(
        r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 10000 }}
      filter_chains:
        - filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: t
                cluster: c
          transport_socket:
            name: envoy.transport_sockets.tls
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
{ctx_yaml}
"#
    );
    snapshot_from(&yaml)
}

fn downstream_tls_of(snapshot: &ConfigSnapshot) -> &DownstreamTlsSpec {
    snapshot.listeners["l1"].filter_chains[0]
        .transport_socket
        .as_ref()
        .expect("transport_socket")
}

fn upstream_tls_of(snapshot: &ConfigSnapshot) -> &UpstreamTlsSpec {
    snapshot.clusters["c1"]
        .transport_socket
        .as_ref()
        .expect("transport_socket")
}

// --------------------------------------------------------------- case  1 --

/// Full downstream context: 2 certs, explicit tls_params (all six cipher
/// suites, all three curves), ALPN, mTLS validation (trusted_ca plus a
/// DNS-exact and a URI-safe_regex SAN matcher), require_client_certificate,
/// and disabled stateless session resumption.
#[test]
fn downstream_full_surface_lowers() {
    let ctx = r#"
              require_client_certificate: true
              disable_stateless_session_resumption: true
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_2
                  tls_maximum_protocol_version: TLSv1_3
                  cipher_suites:
                    - ECDHE-ECDSA-AES128-GCM-SHA256
                    - ECDHE-RSA-AES128-GCM-SHA256
                    - ECDHE-ECDSA-AES256-GCM-SHA384
                    - ECDHE-RSA-AES256-GCM-SHA384
                    - ECDHE-ECDSA-CHACHA20-POLY1305
                    - ECDHE-RSA-CHACHA20-POLY1305
                  ecdh_curves: ["X25519", "P-256", "P-384"]
                tls_certificates:
                  - certificate_chain: { inline_string: "cert-rsa" }
                    private_key: { inline_string: "key-rsa" }
                  - certificate_chain: { inline_string: "cert-ecdsa" }
                    private_key: { inline_string: "key-ecdsa" }
                alpn_protocols: ["h2", "http/1.1"]
                validation_context:
                  trusted_ca: { inline_string: "ca-bundle" }
                  match_typed_subject_alt_names:
                    - san_type: DNS
                      matcher: { exact: "example.com" }
                    - san_type: URI
                      matcher: { safe_regex: { regex: "spiffe://.*" } }
"#;
    let snapshot = downstream_snapshot(ctx).expect("must lower");
    let tls = downstream_tls_of(&snapshot);

    assert_eq!(tls.certificates.len(), 2);
    assert_eq!(
        tls.certificates[0].cert_chain,
        DataSourceIR::Inline("cert-rsa".into())
    );
    assert_eq!(
        tls.certificates[1].cert_chain,
        DataSourceIR::Inline("cert-ecdsa".into())
    );

    assert_eq!(tls.params.min_version, TlsVersion::V1_2);
    assert_eq!(tls.params.max_version, TlsVersion::V1_3);
    assert_eq!(
        tls.params.cipher_suites,
        vec![
            TlsCipherSuite::EcdheEcdsaAes128GcmSha256,
            TlsCipherSuite::EcdheRsaAes128GcmSha256,
            TlsCipherSuite::EcdheEcdsaAes256GcmSha384,
            TlsCipherSuite::EcdheRsaAes256GcmSha384,
            TlsCipherSuite::EcdheEcdsaChacha20Poly1305,
            TlsCipherSuite::EcdheRsaChacha20Poly1305,
        ]
    );
    assert_eq!(
        tls.params.ecdh_curves,
        vec![TlsEcdhCurve::X25519, TlsEcdhCurve::P256, TlsEcdhCurve::P384]
    );

    assert_eq!(
        tls.alpn_protocols,
        vec!["h2".to_string(), "http/1.1".to_string()]
    );
    assert!(tls.require_client_certificate);
    assert!(tls.disable_stateless_session_resumption);

    let validation = tls.validation.as_ref().expect("validation_context");
    assert!(matches!(
        validation.ca,
        CaSource::TrustedCa(DataSourceIR::Inline(ref s)) if s == "ca-bundle"
    ));
    assert_eq!(validation.san_matchers.len(), 2);
    assert_eq!(validation.san_matchers[0].san_type, SanType::Dns);
    assert!(matches!(
        &validation.san_matchers[0].matcher,
        StringMatcherIR::Exact { value, ignore_case } if value == "example.com" && !ignore_case
    ));
    assert_eq!(validation.san_matchers[1].san_type, SanType::Uri);
    assert!(matches!(
        &validation.san_matchers[1].matcher,
        StringMatcherIR::SafeRegex(re) if re.is_match("spiffe://foo")
    ));
    assert!(!validation.allow_expired_certificate);
}

// --------------------------------------------------------------- case  2 --

/// Defaults: an empty (or absent) `tls_params` resolves `TLS_AUTO` to
/// min=1.2/max=1.3 downstream, but min=1.2/max=1.2 upstream (Envoy: "By
/// default, it's TLSv1_2 for clients and TLSv1_3 for servers").
#[test]
fn tls_auto_defaults_are_direction_dependent() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let snapshot = downstream_snapshot(ctx).expect("must lower");
    let tls = downstream_tls_of(&snapshot);
    assert_eq!(tls.params.min_version, TlsVersion::V1_2);
    assert_eq!(tls.params.max_version, TlsVersion::V1_3);
    assert!(tls.params.cipher_suites.is_empty());
    assert!(tls.params.ecdh_curves.is_empty());

    let snapshot = upstream_snapshot("              sni: api.example.com\n").expect("must lower");
    let tls = upstream_tls_of(&snapshot);
    assert_eq!(tls.params.min_version, TlsVersion::V1_2);
    assert_eq!(tls.params.max_version, TlsVersion::V1_2); // pin the asymmetry
}

// --------------------------------------------------------------- case  3 --

#[test]
fn tls_v1_1_minimum_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_1
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("TLSv1.1 must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_params.tls_minimum_protocol_version")
    );
    assert!(err.to_string().contains("TLSv1.1"), "got: {err}");
}

#[test]
fn min_greater_than_max_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_params:
                  tls_minimum_protocol_version: TLSv1_3
                  tls_maximum_protocol_version: TLSv1_2
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("min > max must be rejected");
    assert!(
        err.to_string().contains("tls_minimum_protocol_version"),
        "got: {err}"
    );
}

#[test]
fn unknown_cipher_suite_lists_the_bad_name() {
    let ctx = r#"
              common_tls_context:
                tls_params:
                  cipher_suites: ["TLS_AES_128_GCM_SHA256"]
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("unknown cipher suite must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_params.cipher_suites")
    );
    assert!(
        err.to_string().contains("TLS_AES_128_GCM_SHA256"),
        "got: {err}"
    );
}

#[test]
fn bracketed_equal_preference_group_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_params:
                  cipher_suites: ["[ECDHE-ECDSA-AES128-GCM-SHA256|ECDHE-ECDSA-CHACHA20-POLY1305]"]
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("equal-preference group must be rejected");
    assert!(err.to_string().contains("equal-preference"), "got: {err}");
}

#[test]
fn unknown_curve_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_params:
                  ecdh_curves: ["P-521"]
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("unknown curve must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_params.ecdh_curves")
    );
    assert!(err.to_string().contains("P-521"), "got: {err}");
}

#[test]
fn three_downstream_certificates_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c1" }
                    private_key: { inline_string: "k1" }
                  - certificate_chain: { inline_string: "c2" }
                    private_key: { inline_string: "k2" }
                  - certificate_chain: { inline_string: "c3" }
                    private_key: { inline_string: "k3" }
"#;
    let err = downstream_snapshot(ctx).expect_err("3 certs must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificates")
    );
    assert!(err.to_string().contains("key type"), "got: {err}");
}

#[test]
fn zero_downstream_certificates_is_rejected() {
    let ctx = r#"
              common_tls_context: {}
"#;
    let err = downstream_snapshot(ctx).expect_err("0 certs must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificates")
    );
    assert!(
        err.to_string()
            .contains("tls_certificate_sds_secret_configs"),
        "got: {err}"
    );
}

#[test]
fn two_upstream_client_certificates_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c1" }
                    private_key: { inline_string: "k1" }
                  - certificate_chain: { inline_string: "c2" }
                    private_key: { inline_string: "k2" }
"#;
    let err = upstream_snapshot(ctx).expect_err("2 upstream certs must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{UPSTREAM_TLS_PATH}.common_tls_context.tls_certificates")
    );
}

#[test]
fn require_client_certificate_without_validation_is_rejected() {
    let ctx = r#"
              require_client_certificate: true
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("require_client_certificate needs validation");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.require_client_certificate")
    );
}

#[test]
fn trusted_ca_and_system_root_certs_together_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
                validation_context:
                  trusted_ca: { inline_string: "ca" }
                  system_root_certs: {}
"#;
    let err = downstream_snapshot(ctx).expect_err("mutually exclusive CA sources must be rejected");
    assert!(err.to_string().contains("mutually exclusive"), "got: {err}");
}

#[test]
fn neither_ca_source_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
                validation_context: {}
"#;
    let err = downstream_snapshot(ctx).expect_err("a CA source is required");
    assert!(err.to_string().contains("CA source"), "got: {err}");
}

#[test]
fn email_san_type_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
                validation_context:
                  trusted_ca: { inline_string: "ca" }
                  match_typed_subject_alt_names:
                    - san_type: EMAIL
                      matcher: { exact: "a@b.com" }
"#;
    let err = downstream_snapshot(ctx).expect_err("EMAIL san_type must be rejected");
    assert_eq!(
        err_path(&err),
        format!(
            "{DOWNSTREAM_TLS_PATH}.common_tls_context.validation_context.match_typed_subject_alt_names[0].san_type"
        )
    );
}

#[test]
fn ignore_case_with_safe_regex_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
                validation_context:
                  trusted_ca: { inline_string: "ca" }
                  match_typed_subject_alt_names:
                    - san_type: DNS
                      matcher: { safe_regex: { regex: "example.com" }, ignore_case: true }
"#;
    let err = downstream_snapshot(ctx).expect_err("ignore_case + safe_regex must be rejected");
    assert!(err.to_string().contains("ignore_case"), "got: {err}");
}

#[test]
fn session_ticket_keys_is_rejected() {
    let ctx = r#"
              session_ticket_keys:
                keys:
                  - inline_string: "ticket-key"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("session_ticket_keys must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.session_ticket_keys")
    );
}

#[test]
fn signature_algorithms_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_params:
                  signature_algorithms: ["rsa_pkcs1_sha256"]
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
"#;
    let err = downstream_snapshot(ctx).expect_err("signature_algorithms must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_params.signature_algorithms")
    );
}

#[test]
fn auto_host_sni_is_rejected() {
    let ctx = "              auto_host_sni: true\n";
    let err = upstream_snapshot(ctx).expect_err("auto_host_sni must be rejected");
    assert_eq!(err_path(&err), format!("{UPSTREAM_TLS_PATH}.auto_host_sni"));
}

// --------------------------------------------------------------- case  4 --

/// Upstream happy path: SNI, system_root_certs validation, and a client
/// (mTLS) certificate.
#[test]
fn upstream_happy_path() {
    let ctx = r#"
              sni: api.example.com
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "client-cert" }
                    private_key: { inline_string: "client-key" }
                validation_context:
                  system_root_certs: {}
"#;
    let snapshot = upstream_snapshot(ctx).expect("must lower");
    let tls = upstream_tls_of(&snapshot);
    assert_eq!(tls.sni.as_deref(), Some("api.example.com"));
    assert!(matches!(
        tls.client_certificate.as_ref().expect("client cert").cert_chain,
        DataSourceIR::Inline(ref s) if s == "client-cert"
    ));
    let validation = tls.validation.as_ref().expect("validation_context");
    assert!(matches!(validation.ca, CaSource::SystemRoots));
}

// --------------------------------------------------------------- case  5 --
// WP-22 increment 2a: `tls_certificate_sds_secret_configs` lowering.

#[test]
fn sds_only_chain_lowers_with_empty_certificates() {
    let ctx = r#"
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: server-cert
                    sds_config: { ads: {}, resource_api_version: V3 }
"#;
    let snapshot = downstream_snapshot(ctx).expect("must lower");
    let tls = downstream_tls_of(&snapshot);
    assert!(tls.certificates.is_empty());
    assert_eq!(tls.certificate_sds_names, vec!["server-cert".to_string()]);
}

#[test]
fn validation_context_sds_secret_config_lowers_as_a_separate_sds_name() {
    let ctx = r#"
              require_client_certificate: true
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: server-cert
                    sds_config: { ads: {}, resource_api_version: V3 }
                validation_context_sds_secret_config:
                  name: client-ca
                  sds_config: { ads: {}, resource_api_version: V3 }
"#;
    let snapshot = downstream_snapshot(ctx).expect("must lower");
    let tls = downstream_tls_of(&snapshot);
    assert!(tls.validation.is_none());
    assert_eq!(tls.validation_sds_name.as_deref(), Some("client-ca"));
    assert!(tls.require_client_certificate);
}

#[test]
fn two_sds_names_lower_in_declaration_order() {
    let ctx = r#"
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: server-cert-rsa
                    sds_config: { ads: {}, resource_api_version: V3 }
                  - name: server-cert-ecdsa
                    sds_config: { ads: {}, resource_api_version: V3 }
"#;
    let snapshot = downstream_snapshot(ctx).expect("must lower");
    let tls = downstream_tls_of(&snapshot);
    assert!(tls.certificates.is_empty());
    assert_eq!(
        tls.certificate_sds_names,
        vec![
            "server-cert-rsa".to_string(),
            "server-cert-ecdsa".to_string()
        ]
    );
}

#[test]
fn tls_certificates_and_sds_together_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificates:
                  - certificate_chain: { inline_string: "c" }
                    private_key: { inline_string: "k" }
                tls_certificate_sds_secret_configs:
                  - name: server-cert
                    sds_config: { ads: {}, resource_api_version: V3 }
"#;
    let err =
        downstream_snapshot(ctx).expect_err("mixing tls_certificates and SDS must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificate_sds_secret_configs")
    );
    assert!(err.to_string().contains("tls_certificates"), "got: {err}");
}

#[test]
fn neither_tls_certificates_nor_sds_is_rejected() {
    let ctx = r#"
              common_tls_context: {}
"#;
    let err = downstream_snapshot(ctx).expect_err("at least one of the two must be set");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificates")
    );
    assert!(
        err.to_string()
            .contains("tls_certificate_sds_secret_configs"),
        "got: {err}"
    );
}

#[test]
fn three_sds_names_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: c1
                    sds_config: { ads: {}, resource_api_version: V3 }
                  - name: c2
                    sds_config: { ads: {}, resource_api_version: V3 }
                  - name: c3
                    sds_config: { ads: {}, resource_api_version: V3 }
"#;
    let err = downstream_snapshot(ctx).expect_err("3 SDS names must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificate_sds_secret_configs")
    );
    assert!(err.to_string().contains("key type"), "got: {err}");
}

#[test]
fn duplicate_sds_names_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: server-cert
                    sds_config: { ads: {}, resource_api_version: V3 }
                  - name: server-cert
                    sds_config: { ads: {}, resource_api_version: V3 }
"#;
    let err = downstream_snapshot(ctx).expect_err("duplicate SDS names must be rejected");
    assert_eq!(
        err_path(&err),
        format!("{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificate_sds_secret_configs")
    );
    assert!(err.to_string().contains("server-cert"), "got: {err}");
}

#[test]
fn empty_sds_name_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - sds_config: { ads: {}, resource_api_version: V3 }
"#;
    let err = downstream_snapshot(ctx).expect_err("an empty SDS name must be rejected");
    assert_eq!(
        err_path(&err),
        format!(
            "{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificate_sds_secret_configs[0].name"
        )
    );
}

#[test]
fn missing_sds_config_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: server-cert
"#;
    let err = downstream_snapshot(ctx).expect_err("a name-only SDS entry must be rejected");
    assert_eq!(
        err_path(&err),
        format!(
            "{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificate_sds_secret_configs[0].sds_config"
        )
    );
    assert!(
        err.to_string().contains("static_resources.secrets"),
        "got: {err}"
    );
}

#[test]
fn sds_config_with_api_config_source_is_rejected() {
    let ctx = r#"
              common_tls_context:
                tls_certificate_sds_secret_configs:
                  - name: server-cert
                    sds_config:
                      resource_api_version: V3
                      api_config_source:
                        api_type: GRPC
                        transport_api_version: V3
                        grpc_services:
                          - envoy_grpc: { cluster_name: xds_cluster }
"#;
    let err = downstream_snapshot(ctx).expect_err("a per-type api_config_source must be rejected");
    assert_eq!(
        err_path(&err),
        format!(
            "{DOWNSTREAM_TLS_PATH}.common_tls_context.tls_certificate_sds_secret_configs[0].sds_config.api_config_source"
        )
    );
}
