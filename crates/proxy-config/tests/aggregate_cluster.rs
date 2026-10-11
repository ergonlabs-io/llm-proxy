//! `cluster_type` (`envoy.clusters.aggregate`) -> IR
//! `ClusterKind::Aggregate` lowering. Covers the happy path (member order is
//! preserved -- it's the failover order), the regression that a plain
//! endpoints cluster is unaffected, and every rejection AGENTS.md invariant 1
//! requires: the `lb_policy: CLUSTER_PROVIDED` requirement in both
//! directions, the four fields that are inert-and-therefore-forbidden on an
//! aggregate, the unsupported custom cluster type name, the empty member
//! list, and that the surface walk actually recurses into the new `Any`.

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
        ConfigError::UnknownTypeUrl { field_path, .. } => field_path,
        // `empty_member_list_is_rejected`: the PGV validator enforces
        // `envoy.extensions.clusters.aggregate.v3.ClusterConfig.clusters`'s
        // `repeated.min_items = 1` rule during `parse_bootstrap`, before
        // `convert_cluster`'s own belt-and-suspenders check (kept for
        // defense in depth -- see its comment) ever gets a chance to run.
        ConfigError::Validation { field_path, .. } => field_path,
        // `unknown_field_inside_aggregate_typed_config_is_rejected`: the
        // reflective surface walk also runs before typed lowering, from
        // `build_snapshot`'s very first line.
        ConfigError::UnknownField { field_path, .. } => field_path,
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// A minimal pair of endpoints clusters an aggregate can name as members.
const MEMBER_CLUSTERS: &str = r#"
    - name: a
      type: STATIC
      load_assignment:
        cluster_name: a
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
    - name: b
      type: STATIC
      load_assignment:
        cluster_name: b
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.2, port_value: 443 } }
"#;

/// Build a YAML doc with `MEMBER_CLUSTERS` plus one aggregate cluster whose
/// body (`cluster_type`, `lb_policy`, and anything else the test wants) is
/// supplied by the caller.
fn yaml_with_aggregate(aggregate_body: &str) -> String {
    format!(
        r#"
static_resources:
  clusters:
{MEMBER_CLUSTERS}
    - name: agg
{aggregate_body}
"#
    )
}

const VALID_AGGREGATE: &str = r#"
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, b]
"#;

/// An aggregate cluster with `lb_policy: CLUSTER_PROVIDED` and members
/// `["a", "b"]` lowers to `ClusterKind::Aggregate`, with the members in
/// listed order -- order is the failover order.
#[test]
fn aggregate_lowers_with_members_in_listed_order() {
    let yaml = yaml_with_aggregate(VALID_AGGREGATE);
    let snapshot = snapshot_from(&yaml).expect("must lower");
    let agg = snapshot.clusters.get("agg").expect("cluster");

    assert_eq!(agg.lb_policy, LbPolicy::ClusterProvided);
    match &agg.kind {
        ClusterKind::Aggregate { members } => {
            assert_eq!(members, &vec!["a".to_string(), "b".to_string()]);
        }
        other => panic!("expected ClusterKind::Aggregate, got {other:?}"),
    }
}

/// Regression: a plain endpoints cluster (no `cluster_type`) still lowers to
/// `ClusterKind::Endpoints`, unaffected by the aggregate machinery.
#[test]
fn plain_endpoints_cluster_still_lowers_to_endpoints() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
"#;
    let snapshot = snapshot_from(yaml).expect("must lower");
    let cluster = snapshot.clusters.get("c1").expect("cluster");
    assert_eq!(cluster.kind, ClusterKind::Endpoints);
    assert_eq!(cluster.lb_policy, LbPolicy::RoundRobin);
}

/// An aggregate cluster that omits `lb_policy` gets the proto's ROUND_ROBIN
/// default, which is not CLUSTER_PROVIDED -- Envoy requires it be set
/// explicitly, so this must fail naming `lb_policy`.
#[test]
fn aggregate_without_cluster_provided_lb_policy_is_rejected() {
    let body = r#"
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, b]
"#;
    let yaml = yaml_with_aggregate(body);
    let err = snapshot_from(&yaml).expect_err("aggregate without CLUSTER_PROVIDED must fail");
    assert!(
        err_path(&err).contains("lb_policy"),
        "got path: {}",
        err_path(&err)
    );
}

/// `CLUSTER_PROVIDED` on a cluster that owns its own hosts (no
/// `cluster_type`) is unsupported -- there is no cluster-provided
/// host-picking implemented for anything but an aggregate.
#[test]
fn cluster_provided_on_an_endpoints_cluster_is_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: c1
      type: STATIC
      lb_policy: CLUSTER_PROVIDED
      load_assignment:
        cluster_name: c1
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
"#;
    let err = snapshot_from(yaml).expect_err("CLUSTER_PROVIDED on an endpoints cluster must fail");
    assert!(
        err_path(&err).contains("lb_policy"),
        "got path: {}",
        err_path(&err)
    );
}

/// `load_assignment` on an aggregate is inert (hosts come from its members)
/// and must be rejected rather than silently ignored.
#[test]
fn load_assignment_on_an_aggregate_is_rejected() {
    let body = format!(
        r#"
{VALID_AGGREGATE}
      load_assignment:
        cluster_name: agg
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: {{ socket_address: {{ address: 10.0.0.3, port_value: 443 }} }}
"#
    );
    let yaml = yaml_with_aggregate(&body);
    let err = snapshot_from(&yaml).expect_err("load_assignment on an aggregate must fail");
    assert!(
        err_path(&err).contains("load_assignment"),
        "got path: {}",
        err_path(&err)
    );
}

/// `metadata` on an aggregate is inert and, for the
/// `io.llmproxy.provider_auth` namespace specifically, dangerous (credentials
/// would silently never apply) -- reject regardless of namespace.
#[test]
fn metadata_on_an_aggregate_is_rejected() {
    let body = format!(
        r#"
{VALID_AGGREGATE}
      metadata:
        filter_metadata:
          io.llmproxy.provider_auth:
            headers:
              - key: x-api-key
                value: secret
"#
    );
    let yaml = yaml_with_aggregate(&body);
    let err = snapshot_from(&yaml).expect_err("metadata on an aggregate must fail");
    assert!(
        err_path(&err).contains("metadata"),
        "got path: {}",
        err_path(&err)
    );
}

/// `transport_socket` on an aggregate is inert (the member supplies TLS) and
/// must be rejected.
#[test]
fn transport_socket_on_an_aggregate_is_rejected() {
    let body = format!(
        r#"
{VALID_AGGREGATE}
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
"#
    );
    let yaml = yaml_with_aggregate(&body);
    let err = snapshot_from(&yaml).expect_err("transport_socket on an aggregate must fail");
    assert!(
        err_path(&err).contains("transport_socket"),
        "got path: {}",
        err_path(&err)
    );
}

/// `typed_extension_protocol_options` on an aggregate is inert (the member
/// supplies the upstream protocol) and must be rejected.
#[test]
fn typed_extension_protocol_options_on_an_aggregate_is_rejected() {
    let body = format!(
        r#"
{VALID_AGGREGATE}
      typed_extension_protocol_options:
        envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
          "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
          explicit_http_config:
            http2_protocol_options: {{}}
"#
    );
    let yaml = yaml_with_aggregate(&body);
    let err = snapshot_from(&yaml)
        .expect_err("typed_extension_protocol_options on an aggregate must fail");
    assert!(
        err_path(&err).contains("typed_extension_protocol_options"),
        "got path: {}",
        err_path(&err)
    );
}

/// The converse of the four rejections above, and a deliberate decision worth
/// pinning: `circuit_breakers` on an aggregate is NOT inert, so it must keep
/// lowering. The router applies the breaker to the *routed* cluster before the
/// host pick (matching Envoy), so an aggregate's own thresholds do real work
/// even though it owns no hosts. Rejecting it alongside the others would look
/// tidy and be wrong.
#[test]
fn circuit_breakers_on_an_aggregate_still_lower() {
    let body = format!(
        r#"
{VALID_AGGREGATE}
      circuit_breakers:
        thresholds:
          - priority: DEFAULT
            max_requests: 7
"#
    );
    let yaml = yaml_with_aggregate(&body);
    let snapshot = snapshot_from(&yaml).expect("an aggregate with circuit breakers must lower");
    let agg = snapshot.clusters.get("agg").expect("cluster");

    assert_eq!(agg.circuit_breakers.default.max_requests, 7);
    assert!(matches!(agg.kind, ClusterKind::Aggregate { .. }));
}

/// An empty `clusters` list inside the aggregate `typed_config` is invalid --
/// an aggregate needs at least one member to fail over across.
#[test]
fn empty_member_list_is_rejected() {
    let body = r#"
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: []
"#;
    let yaml = yaml_with_aggregate(body);
    let err = snapshot_from(&yaml).expect_err("empty member list must fail");
    assert!(
        err_path(&err).contains("cluster_type.typed_config.clusters"),
        "got path: {}",
        err_path(&err)
    );
}

/// `cluster_type.name` says `envoy.clusters.aggregate` but `typed_config`
/// carries some other resolvable type. The name is what Envoy dispatches on,
/// so a config can disagree with itself here; decoding the `Any` as an
/// aggregate `ClusterConfig` anyway would reinterpret whatever bytes are
/// present as a member list.
#[test]
fn aggregate_typed_config_of_the_wrong_type_is_rejected() {
    let body = r#"
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
"#;
    let yaml = yaml_with_aggregate(body);
    let err = snapshot_from(&yaml).expect_err("a non-aggregate typed_config must fail");
    // Assert the VARIANT, not just the path. An empty `Router` payload decodes
    // as an aggregate `ClusterConfig` with zero members, so the empty-member
    // check would reject this config too -- at a path that also starts
    // `cluster_type.typed_config`. Verified by mutation (2026-08-07): with a
    // path-only assertion, deleting the type check entirely left this test
    // green.
    assert!(
        matches!(err, ConfigError::UnknownTypeUrl { .. }),
        "expected UnknownTypeUrl, got: {err:?}"
    );
    assert!(
        err_path(&err).contains("cluster_type.typed_config"),
        "got path: {}",
        err_path(&err)
    );
}

/// A `cluster_type.name` other than `envoy.clusters.aggregate` is an
/// unsupported custom cluster type, naming `cluster_type.name`.
#[test]
fn unsupported_custom_cluster_type_name_is_rejected() {
    let body = r#"
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.something_else
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, b]
"#;
    let yaml = yaml_with_aggregate(body);
    let err = snapshot_from(&yaml).expect_err("unknown custom cluster type must fail");
    assert!(
        err_path(&err).contains("cluster_type.name"),
        "got path: {}",
        err_path(&err)
    );
}

/// An unknown field inside the aggregate `typed_config` is rejected by strict
/// mode, which proves the `Any` is decoded as a *typed message* whose type URL
/// resolves in the descriptor pool -- i.e. that
/// `envoy/extensions/clusters/aggregate/v3/cluster.proto` really is a
/// `proxy-api/build.rs` root. Without it the type URL would not resolve at all.
///
/// It does **not** prove the surface walk's allowlist does anything here, and
/// an earlier version of this test claimed that it did. Verified by mutation
/// (2026-08-07): adding `"bogus"` to the aggregate's `allowed_fields` entry
/// leaves this test green, because a field absent from the descriptor is
/// rejected by the proto3 JSON deserializer (`loader.rs:169`) long before
/// `check_supported_surface` ever runs. See that entry's comment for why it is
/// nonetheless correct to keep.
#[test]
fn unknown_field_inside_aggregate_typed_config_is_rejected() {
    let body = r#"
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, b]
          bogus: 1
"#;
    let yaml = yaml_with_aggregate(body);
    let err = snapshot_from(&yaml).expect_err("unknown field inside typed_config must fail");
    assert!(
        err_path(&err).contains("bogus"),
        "got path: {}",
        err_path(&err)
    );
}

// ---------------------------------------------------------------------------
// `validate_cluster_graph`, the cross-cluster post-pass
// that checks an aggregate's members once the whole cluster map exists.
// `err_path` above already covers `InvalidValue`, which is what every check
// here returns.

/// A valid multi-member aggregate over three endpoints clusters still lowers
/// -- regression against the post-pass being too strict.
#[test]
fn three_member_aggregate_still_lowers() {
    let yaml = r#"
static_resources:
  clusters:
    - name: a
      type: STATIC
      load_assignment:
        cluster_name: a
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
    - name: b
      type: STATIC
      load_assignment:
        cluster_name: b
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.2, port_value: 443 } }
    - name: c
      type: STATIC
      load_assignment:
        cluster_name: c
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.3, port_value: 443 } }
    - name: agg
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, b, c]
"#;
    let snapshot = snapshot_from(yaml).expect("a valid three-member aggregate must lower");
    let agg = snapshot.clusters.get("agg").expect("cluster");
    match &agg.kind {
        ClusterKind::Aggregate { members } => {
            assert_eq!(
                members,
                &vec!["a".to_string(), "b".to_string(), "c".to_string()]
            );
        }
        other => panic!("expected ClusterKind::Aggregate, got {other:?}"),
    }
}

/// A three-member aggregate whose *middle* member does not exist must be
/// rejected naming `clusters[1]` -- the middle position catches an off-by-one
/// in either index that a first- or last-position test would miss.
#[test]
fn missing_middle_member_is_rejected_with_correct_index() {
    let yaml = r#"
static_resources:
  clusters:
    - name: a
      type: STATIC
      load_assignment:
        cluster_name: a
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
    - name: c
      type: STATIC
      load_assignment:
        cluster_name: c
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.3, port_value: 443 } }
    - name: agg
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, missing, c]
"#;
    let err = snapshot_from(yaml).expect_err("a missing middle member must fail");
    let path = err_path(&err);
    assert!(
        path.contains("clusters[2]") // the aggregate is clusters[2]
            && path.contains("cluster_type.typed_config.clusters[1]"), // the missing member is member index 1
        "got path: {path}"
    );
    assert!(
        matches!(&err, ConfigError::InvalidValue { reason, .. } if reason.contains("unknown cluster")),
        "got: {err}"
    );
}

/// An aggregate naming another aggregate as a member must be rejected --
/// `select_aggregate_member` refuses to recurse into a nested aggregate, so
/// that member would be silently skipped at runtime. The error must mention
/// the nesting.
#[test]
fn aggregate_naming_another_aggregate_is_rejected() {
    let yaml = r#"
static_resources:
  clusters:
    - name: a
      type: STATIC
      load_assignment:
        cluster_name: a
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
    - name: b
      type: STATIC
      load_assignment:
        cluster_name: b
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.2, port_value: 443 } }
    - name: inner
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, b]
    - name: outer
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [inner]
"#;
    let err = snapshot_from(yaml).expect_err("an aggregate naming another aggregate must fail");
    assert!(
        err_path(&err).contains("clusters[3].cluster_type.typed_config.clusters[0]"),
        "got path: {}",
        err_path(&err)
    );
    assert!(
        matches!(&err, ConfigError::InvalidValue { reason, .. } if reason.contains("nest")),
        "expected a message mentioning nesting, got: {err}"
    );
}

/// An aggregate naming itself as a member is a special case of the nesting
/// check above, but must be reported plainly as a self-reference.
#[test]
fn aggregate_naming_itself_is_rejected() {
    let body = r#"
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, agg]
"#;
    let yaml = yaml_with_aggregate(body);
    let err = snapshot_from(&yaml).expect_err("an aggregate naming itself must fail");
    assert!(
        err_path(&err).contains("cluster_type.typed_config.clusters[1]"),
        "got path: {}",
        err_path(&err)
    );
    assert!(
        matches!(&err, ConfigError::InvalidValue { reason, .. } if reason.contains("names itself")),
        "expected a message saying it names itself, got: {err}"
    );
}

/// A duplicate member name within one aggregate is always a runtime no-op
/// (`LoadBalancerContext::attempted_clusters` skips a cluster already tried)
/// and must be rejected.
#[test]
fn duplicate_member_is_rejected() {
    let body = r#"
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, a]
"#;
    let yaml = yaml_with_aggregate(body);
    let err = snapshot_from(&yaml).expect_err("a duplicate member must fail");
    assert!(
        err_path(&err).contains("cluster_type.typed_config.clusters[1]"),
        "got path: {}",
        err_path(&err)
    );
    assert!(
        matches!(&err, ConfigError::InvalidValue { reason, .. } if reason.contains("duplicate")),
        "got: {err}"
    );
}

/// Declaration order must not matter: an aggregate declared *before* its
/// members in the config still lowers successfully. This is the test that
/// proves `validate_cluster_graph` really is a post-pass over the assembled
/// map, rather than an in-loop check that happened to work because the
/// fixture always listed members first.
#[test]
fn aggregate_declared_before_its_members_still_lowers() {
    let yaml = r#"
static_resources:
  clusters:
    - name: agg
      lb_policy: CLUSTER_PROVIDED
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a, b]
    - name: a
      type: STATIC
      load_assignment:
        cluster_name: a
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.1, port_value: 443 } }
    - name: b
      type: STATIC
      load_assignment:
        cluster_name: b
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: { socket_address: { address: 10.0.0.2, port_value: 443 } }
"#;
    let snapshot =
        snapshot_from(yaml).expect("an aggregate declared before its members must still lower");
    let agg = snapshot.clusters.get("agg").expect("cluster");
    assert!(matches!(agg.kind, ClusterKind::Aggregate { .. }));
}
