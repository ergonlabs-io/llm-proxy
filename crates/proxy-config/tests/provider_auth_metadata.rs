//! `Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`
//! Tests lowering provider-auth metadata into cluster request headers. The
//! namespace carries per-provider credentials because Envoy has no dedicated
//! field for them. Unset metadata remains unaffected; malformed shapes fail
//! with dotted paths (AGENTS.md invariant 1).

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

fn err_path(err: &ConfigError) -> &str {
    match err {
        ConfigError::UnsupportedField { field_path, .. } => field_path,
        ConfigError::InvalidValue { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// No `metadata` at all: an ordinary hand-written Envoy cluster is unaffected.
#[test]
fn absent_metadata_leaves_request_headers_to_add_empty() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.request_headers_to_add.is_empty());
}

/// Other metadata namespaces remain untouched; strict checks reject unknown
/// fields, not entries inside an allowed metadata map.
#[test]
fn unrelated_metadata_namespace_is_left_alone() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          some.other.namespace:
            anything: "goes here"
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.request_headers_to_add.is_empty());
}

/// The documented shape: `headers: [{key, value}, ...]`, all lowered to
/// `OverwriteIfExistsOrAdd`.
#[test]
fn provider_auth_headers_lower_to_cluster_request_headers_to_add() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: authorization, value: "Bearer sk-test" }
              - { key: anthropic-version, value: "2023-06-01" }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.request_headers_to_add.len(), 2);
    assert_eq!(cluster.request_headers_to_add[0].key, "authorization");
    assert_eq!(cluster.request_headers_to_add[0].value, "Bearer sk-test");
    assert_eq!(
        cluster.request_headers_to_add[0].action,
        HeaderAppendAction::OverwriteIfExistsOrAdd
    );
    assert_eq!(cluster.request_headers_to_add[1].key, "anthropic-version");
    assert_eq!(cluster.request_headers_to_add[1].value, "2023-06-01");
}

/// `headers` missing entirely under the namespace: an empty (not absent)
/// namespace is treated the same as "no headers".
#[test]
fn provider_auth_with_no_headers_key_is_empty() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth: {}
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert!(cluster.request_headers_to_add.is_empty());
}

/// A sub-key other than `headers` under the namespace is a hard error with
/// its full dotted path -- AGENTS.md invariant 1: a typo here must never silently
/// mean "no auth header".
#[test]
fn unknown_sub_key_under_provider_auth_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers: []
            extra_stuff: true
"#;
    let err = snapshot_from(yaml).expect_err("unknown sub-key must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].extra_stuff"
    );
}

/// `headers` set to something other than a list is a hard error.
#[test]
fn non_list_headers_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers: "not a list"
"#;
    let err = snapshot_from(yaml).expect_err("non-list headers must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers"
    );
}

/// A `headers` entry that isn't an object is a hard error.
#[test]
fn non_object_header_entry_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers: ["not an object"]
"#;
    let err = snapshot_from(yaml).expect_err("non-object entry must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0]"
    );
}

/// A `headers` entry missing `value` is a hard error, not a header with an
/// empty value.
#[test]
fn header_entry_missing_value_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: authorization }
"#;
    let err = snapshot_from(yaml).expect_err("missing value must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0].value"
    );
}

/// A `headers` entry with a non-string `key` is a hard error.
#[test]
fn header_entry_non_string_key_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: 123, value: "x" }
"#;
    let err = snapshot_from(yaml).expect_err("non-string key must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0].key"
    );
}

/// A `headers` entry with an unrecognized sub-key (typo'd `keys`, say) is a
/// hard error rather than silently ignoring the typo and emitting no header.
#[test]
fn header_entry_unknown_sub_key_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: authorization, value: "x", extra: "y" }
"#;
    let err = snapshot_from(yaml).expect_err("unknown sub-key must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0].extra"
    );
}

/// A header the router cannot send fails at load rather than being dropped on
/// every request, which would send the provider call without its
/// credential. Neither error renders the value.
#[test]
fn header_entry_the_router_cannot_send_is_a_hard_error() {
    let entry = "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].headers[0]";
    for (header, field) in [
        (r#"{ key: "x org", value: "sk-metadata-secret" }"#, "key"),
        (
            r#"{ key: authorization, value: "Bearer sk-metadata-secret\u0001" }"#,
            "value",
        ),
    ] {
        let yaml = format!(
            r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - {header}
"#
        );
        let err = snapshot_from(&yaml).expect_err("an unsendable header must fail");
        assert_eq!(err_path(&err), format!("{entry}.{field}"));
        assert!(
            !err.to_string().contains("sk-metadata-secret"),
            "the error must not render the value: {err}"
        );
    }
}

/// A cluster without `tenant_credential` (and without any other runtime
/// metadata) keeps `provider_runtime` unset.
#[test]
fn cluster_without_tenant_credential_has_no_provider_runtime() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: authorization, value: "Bearer sk-test" }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.provider_runtime, None);
}

/// A slot alone (no credential, no path template, no model rewrites) is
/// enough to produce a `ProviderRuntimeConfig`. The header is stored
/// lowercase, and `prefix` is kept verbatim including its trailing space.
#[test]
fn tenant_credential_slot_alone_lowers_to_provider_runtime() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provider: openrouter, header: authorization, prefix: "Bearer " }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(
        cluster.provider_runtime,
        Some(ProviderRuntimeConfig {
            credential: None,
            path_template: None,
            model_rewrites: Vec::new(),
            request_field_policy: Default::default(),
            tenant_credential: Some(TenantCredentialSlot {
                provider: "openrouter".to_string(),
                header: "authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
                verify_path: None,
            }),
        })
    );
}

/// `prefix` is optional and defaults to empty, for raw API-key headers such
/// as `x-api-key`.
#[test]
fn tenant_credential_prefix_defaults_to_empty() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provider: anthropic, header: x-api-key }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let slot = cluster
        .provider_runtime
        .as_ref()
        .and_then(|r| r.tenant_credential.as_ref())
        .expect("slot");
    assert_eq!(slot.value_prefix, "");
    assert_eq!(slot.header, "x-api-key");
}

/// Header names are matched case-insensitively by Envoy and by `http`, so a
/// mixed-case `header` is stored lowercase.
#[test]
fn tenant_credential_header_is_stored_lowercase() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provider: openrouter, header: Authorization, prefix: "Bearer " }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    let slot = cluster
        .provider_runtime
        .as_ref()
        .and_then(|r| r.tenant_credential.as_ref())
        .expect("slot");
    assert_eq!(slot.header, "authorization");
}

/// The slot sits beside the existing `headers` list without disturbing it.
#[test]
fn tenant_credential_coexists_with_headers() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - { key: anthropic-version, value: "2023-06-01" }
            tenant_credential: { provider: anthropic, header: x-api-key }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.request_headers_to_add.len(), 1);
    assert_eq!(cluster.request_headers_to_add[0].key, "anthropic-version");
    assert!(cluster
        .provider_runtime
        .as_ref()
        .and_then(|r| r.tenant_credential.as_ref())
        .is_some());
}

/// `provider` is required.
#[test]
fn tenant_credential_missing_provider_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { header: authorization }
"#;
    let err = snapshot_from(yaml).expect_err("missing provider must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential.provider"
    );
}

/// An empty `provider` would store a credential under no name the router
/// could ever match, so it is rejected.
#[test]
fn tenant_credential_empty_provider_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provider: "", header: authorization }
"#;
    let err = snapshot_from(yaml).expect_err("empty provider must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential.provider"
    );
}

/// A header name with a space is not a valid HTTP header name.
#[test]
fn tenant_credential_bad_header_name_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provider: openrouter, header: "bad header" }
"#;
    let err = snapshot_from(yaml).expect_err("bad header name must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential.header"
    );
}

/// A CR/LF in `prefix` would let a tenant value split the header, so the
/// slot is rejected at load time.
#[test]
fn tenant_credential_crlf_in_prefix_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provider: openrouter, header: authorization, prefix: "Bearer \r\nX-Injected: 1" }
"#;
    let err = snapshot_from(yaml).expect_err("CR/LF in prefix must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential.prefix"
    );
}

/// A typo'd key (`provder`) is a hard error with the full dotted path, never
/// a slot that silently has no provider.
#[test]
fn tenant_credential_unknown_key_names_the_full_dotted_path() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provder: openrouter, header: authorization }
"#;
    let err = snapshot_from(yaml).expect_err("unknown key must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential.provder"
    );
}

/// `tenant_credential` must be an object, not a bare string.
#[test]
fn tenant_credential_non_object_is_a_hard_error() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: "openrouter"
"#;
    let err = snapshot_from(yaml).expect_err("non-object slot must fail");
    assert_eq!(
        err_path(&err),
        "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential"
    );
}

/// ADR-0007 decision 1: a tenant slot is a header API-key shape, so it cannot
/// sit beside Vertex OAuth2 or Bedrock SigV4. Both schemes are checked.
#[test]
fn tenant_credential_with_vertex_or_bedrock_is_a_hard_error() {
    let vertex = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            scheme: vertex-oauth2
            access_token: "ya29.test"
            tenant_credential: { provider: openrouter, header: authorization }
"#;
    let bedrock = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            scheme: bedrock-sigv4
            region: us-east-1
            access_key_id: AKIATEST
            secret_access_key: secret
            tenant_credential: { provider: openrouter, header: authorization }
"#;
    for yaml in [vertex, bedrock] {
        let err = snapshot_from(yaml).expect_err("slot beside a SigV4/OAuth2 credential must fail");
        assert_eq!(
            err_path(&err),
            "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential"
        );
    }
}

const TENANT_SLOT_PATH: &str =
    "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].tenant_credential";

/// A cluster whose tenant slot carries `verify_path` set to `verify_path_yaml`,
/// a YAML scalar spliced in as-is (so callers pass their own quoting).
fn tenant_slot_yaml(verify_path_yaml: &str) -> String {
    format!(
        r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: {{ provider: openrouter, header: authorization, prefix: "Bearer ", verify_path: {verify_path_yaml} }}
"#
    )
}

/// The `verify_path` of the one cluster in `tenant_slot_yaml`, when it lowers.
fn lowered_verify_path(verify_path_yaml: &str) -> Option<String> {
    let snapshot = snapshot_from(&tenant_slot_yaml(verify_path_yaml)).expect("must lower");
    snapshot
        .clusters
        .get("c1")
        .and_then(|c| c.provider_runtime.as_ref())
        .and_then(|r| r.tenant_credential.as_ref())
        .expect("slot")
        .verify_path
        .clone()
}

/// A `verify_path` on the slot lowers to `Some`, sent exactly as written.
#[test]
fn tenant_credential_verify_path_lowers_to_the_slot() {
    assert_eq!(
        lowered_verify_path("\"/api/v1/key\"").as_deref(),
        Some("/api/v1/key")
    );
}

/// `verify_path` is optional: a slot without it lowers to `None`, the same
/// as before the key existed.
#[test]
fn tenant_credential_verify_path_absent_lowers_to_none() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            tenant_credential: { provider: openrouter, header: authorization, prefix: "Bearer " }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let slot = snapshot
        .clusters
        .get("c1")
        .and_then(|c| c.provider_runtime.as_ref())
        .and_then(|r| r.tenant_credential.as_ref())
        .expect("slot");
    assert_eq!(slot.verify_path, None);
}

/// A path with a query is valid origin form, so it is kept whole.
#[test]
fn tenant_credential_verify_path_keeps_its_query() {
    assert_eq!(
        lowered_verify_path("\"/v1/models?limit=1\"").as_deref(),
        Some("/v1/models?limit=1")
    );
}

/// The 2048-byte cap is inclusive: exactly 2048 bytes lowers.
#[test]
fn tenant_credential_verify_path_at_the_length_cap_lowers() {
    let path = format!("/{}", "a".repeat(2047));
    assert_eq!(path.len(), 2048);
    assert_eq!(
        lowered_verify_path(&format!("\"{path}\"")).as_deref(),
        Some(path.as_str())
    );
}

/// Every refused `verify_path` names its full dotted path, with a reason that
/// says which rule it broke.
#[test]
fn tenant_credential_verify_path_invalid_values_are_hard_errors() {
    let too_long = format!("\"/{}\"", "a".repeat(2048));
    let cases: [(&str, &str); 12] = [
        ("\"\"", "must start with `/`"),
        ("\"api/v1/key\"", "must start with `/`"),
        ("\"/api/v1/key with space\"", "whitespace"),
        ("\"/api\\tv1\"", "whitespace"),
        (r#""/api/v1/key\r\nX-Injected: 1""#, "whitespace"),
        ("\"/caf\u{e9}\"", "non-ASCII"),
        ("\"/api/v1/key#frag\"", "must not contain `#`"),
        ("\"/api/v1/key?x=1#frag\"", "must not contain `#`"),
        (too_long.as_str(), "at most 2048 bytes"),
        ("\"/<x>\"", "valid URI path"),
        ("5", "must be a string"),
        ("[\"/api/v1/key\"]", "must be a string"),
    ];
    for (verify_path_yaml, reason) in cases {
        let yaml = tenant_slot_yaml(verify_path_yaml);
        match snapshot_from(&yaml) {
            Ok(_) => panic!("`{verify_path_yaml}` must be refused"),
            Err(ConfigError::InvalidValue {
                field_path,
                reason: got,
            }) => {
                assert_eq!(
                    field_path,
                    format!("{TENANT_SLOT_PATH}.verify_path"),
                    "wrong path for `{verify_path_yaml}`"
                );
                assert!(
                    got.contains(reason),
                    "reason for `{verify_path_yaml}` was `{got}`, expected it to contain `{reason}`"
                );
            }
            Err(other) => panic!("`{verify_path_yaml}`: expected InvalidValue, got: {other}"),
        }
    }
}

fn policy_yaml(policy: &str) -> String {
    format!(
        r#"
static_resources:
  clusters:
    - name: c1
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            request_field_policy: {policy}
"#
    )
}

const POLICY_PATH: &str = "static_resources.clusters[0].metadata.filter_metadata[\"io.llmproxy.provider_auth\"].request_field_policy";

/// A policy alone is enough to produce a `ProviderRuntimeConfig`, and the
/// lists are kept in order.
#[test]
fn request_field_policy_lowers_deny_and_strip() {
    let snapshot =
        snapshot_from(&policy_yaml("{ deny: [models, route], strip: [plugins] }")).expect("lower");
    let runtime = snapshot.clusters["c1"]
        .provider_runtime
        .clone()
        .expect("runtime");
    assert_eq!(runtime.request_field_policy.deny, ["models", "route"]);
    assert_eq!(runtime.request_field_policy.strip, ["plugins"]);
}

/// An absent or empty policy leaves `provider_runtime` unset.
#[test]
fn empty_request_field_policy_is_no_runtime() {
    let snapshot = snapshot_from(&policy_yaml("{}")).expect("lower");
    assert_eq!(snapshot.clusters["c1"].provider_runtime, None);
}

#[test]
fn request_field_policy_unknown_key_is_a_hard_error() {
    let err = snapshot_from(&policy_yaml("{ deny: [a], allow: [b] }")).unwrap_err();
    assert_eq!(err_path(&err), format!("{POLICY_PATH}.allow"));
}

#[test]
fn request_field_policy_wrong_types_are_hard_errors() {
    let err = snapshot_from(&policy_yaml("[a]")).unwrap_err();
    assert_eq!(err_path(&err), POLICY_PATH);
    let err = snapshot_from(&policy_yaml("{ deny: a }")).unwrap_err();
    assert_eq!(err_path(&err), format!("{POLICY_PATH}.deny"));
    let err = snapshot_from(&policy_yaml("{ strip: [a, 3] }")).unwrap_err();
    assert_eq!(err_path(&err), format!("{POLICY_PATH}.strip[1]"));
}

#[test]
fn request_field_policy_empty_name_is_a_hard_error() {
    let err = snapshot_from(&policy_yaml("{ deny: [\"\"] }")).unwrap_err();
    assert_eq!(err_path(&err), format!("{POLICY_PATH}.deny[0]"));
}

#[test]
fn request_field_in_both_deny_and_strip_is_a_hard_error() {
    let err = snapshot_from(&policy_yaml("{ deny: [a, b], strip: [c, b] }")).unwrap_err();
    assert_eq!(err_path(&err), format!("{POLICY_PATH}.strip[1]"));
}
