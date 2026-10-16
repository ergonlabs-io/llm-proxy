//! STRICT_DNS / LOGICAL_DNS re-resolution settings: `dns_refresh_rate`,
//! `dns_jitter`, `dns_failure_refresh_rate` and `respect_dns_ttl`, driven
//! through the real YAML -> IR path and, for the xDS door, through
//! `lower_dynamic_cluster`.
//!
//! The defaults and validation rules are Envoy v1.38's (`cluster.proto`):
//! refresh 5s, no jitter, failures retried at the refresh rate unless
//! `dns_failure_refresh_rate` says otherwise, whose `max_interval` defaults to
//! 10 times its `base_interval`. The fields mean nothing to a STATIC or EDS
//! cluster, where Envoy ignores them; we reject them there with their dotted
//! path (AGENTS.md invariant 1, and a row in `internal-docs/envoy-divergences.md`).

use std::time::Duration;

use prost::Message;
use proxy_api::envoy::config::cluster::v3 as cluster_v3;
use proxy_api::envoy::config::core::v3 as core_v3;
use proxy_api::envoy::config::endpoint::v3 as endpoint_v3;
use proxy_config::ir::*;
use proxy_config::{
    build_snapshot, lower_dynamic_cluster, parse_bootstrap, ConfigError, ConfigFormat, StrictMode,
};

fn lower(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// The dotted path of a field-scoped error and the reason text, whichever
/// layer produced it: the proto's own validation rules (`Validation`) catch
/// range violations during `parse_bootstrap`, typed lowering (`InvalidValue`,
/// `UnsupportedField`) catches the rest.
fn err_parts(err: &ConfigError) -> (&str, &str) {
    match err {
        ConfigError::UnsupportedField { field_path, reason }
        | ConfigError::InvalidValue { field_path, reason } => (field_path, reason),
        ConfigError::Validation { field_path, rule } => (field_path, rule),
        other => panic!("expected a field-scoped error, got: {other}"),
    }
}

/// One cluster named `dns` of the given discovery `type`, with `settings`
/// (already indented to cluster level, 6 spaces) spliced in and a single
/// hostname endpoint.
fn dns_cluster_yaml(discovery: &str, settings: &str) -> String {
    format!(
        r#"
static_resources:
  clusters:
    - name: dns
      type: {discovery}
{settings}
      load_assignment:
        cluster_name: dns
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: {{ address: api.example.com, port_value: 443 }}
"#
    )
}

/// The `DnsRefresh` a DNS cluster lowered to, whichever DNS type it is.
fn refresh_of(snapshot: &ConfigSnapshot) -> DnsRefresh {
    snapshot.clusters["dns"]
        .discovery
        .dns_refresh()
        .expect("a STRICT_DNS or LOGICAL_DNS cluster carries a DnsRefresh")
}

const DNS_TYPES: [&str; 2] = ["STRICT_DNS", "LOGICAL_DNS"];

// ------------------------------------------------------------- defaults --

#[test]
fn a_dns_cluster_without_refresh_fields_gets_envoys_defaults() {
    for ty in DNS_TYPES {
        let snapshot = lower(&dns_cluster_yaml(ty, "")).expect("lowers");
        assert_eq!(
            refresh_of(&snapshot),
            DnsRefresh {
                refresh_rate: Duration::from_secs(5),
                jitter: Duration::ZERO,
                // Envoy retries at the refresh rate when no failure rate is
                // configured, so base and max are both the refresh rate.
                failure_base_interval: Duration::from_secs(5),
                failure_max_interval: Duration::from_secs(5),
            },
            "{ty}"
        );
        assert_eq!(refresh_of(&snapshot), DnsRefresh::ENVOY_DEFAULT, "{ty}");
    }
}

#[test]
fn the_discovery_variant_follows_the_cluster_type() {
    let strict = lower(&dns_cluster_yaml("STRICT_DNS", "")).expect("lowers");
    assert_eq!(
        strict.clusters["dns"].discovery,
        DiscoveryType::StrictDns(DnsRefresh::ENVOY_DEFAULT)
    );
    let logical = lower(&dns_cluster_yaml("LOGICAL_DNS", "")).expect("lowers");
    assert_eq!(
        logical.clusters["dns"].discovery,
        DiscoveryType::LogicalDns(DnsRefresh::ENVOY_DEFAULT)
    );
}

// ------------------------------------------------------------ each field --

#[test]
fn dns_refresh_rate_is_lowered_and_failures_default_to_it() {
    for ty in DNS_TYPES {
        let snapshot = lower(&dns_cluster_yaml(ty, "      dns_refresh_rate: 30s")).expect("lowers");
        assert_eq!(
            refresh_of(&snapshot),
            DnsRefresh {
                refresh_rate: Duration::from_secs(30),
                jitter: Duration::ZERO,
                failure_base_interval: Duration::from_secs(30),
                failure_max_interval: Duration::from_secs(30),
            },
            "{ty}"
        );
    }
}

#[test]
fn dns_refresh_rate_just_above_the_floor_is_accepted() {
    let snapshot = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      dns_refresh_rate: 0.002s",
    ))
    .expect("2ms is above Envoy's 1ms floor");
    assert_eq!(refresh_of(&snapshot).refresh_rate, Duration::from_millis(2));
}

#[test]
fn dns_jitter_is_lowered() {
    for ty in DNS_TYPES {
        let snapshot = lower(&dns_cluster_yaml(ty, "      dns_jitter: 2s")).expect("lowers");
        let refresh = refresh_of(&snapshot);
        assert_eq!(refresh.jitter, Duration::from_secs(2), "{ty}");
        // Jitter does not touch the other timings.
        assert_eq!(refresh.refresh_rate, Duration::from_secs(5), "{ty}");
    }
}

#[test]
fn a_zero_dns_jitter_means_no_jitter() {
    let snapshot = lower(&dns_cluster_yaml("STRICT_DNS", "      dns_jitter: 0s")).expect("lowers");
    assert_eq!(refresh_of(&snapshot).jitter, Duration::ZERO);
}

#[test]
fn dns_failure_refresh_rate_lowers_base_and_max() {
    for ty in DNS_TYPES {
        let snapshot = lower(&dns_cluster_yaml(
            ty,
            "      dns_failure_refresh_rate:\n        base_interval: 1s\n        max_interval: 20s",
        ))
        .expect("lowers");
        let refresh = refresh_of(&snapshot);
        assert_eq!(
            refresh.failure_base_interval,
            Duration::from_secs(1),
            "{ty}"
        );
        assert_eq!(
            refresh.failure_max_interval,
            Duration::from_secs(20),
            "{ty}"
        );
        // The success cadence is independent of the failure backoff.
        assert_eq!(refresh.refresh_rate, Duration::from_secs(5), "{ty}");
    }
}

/// Envoy: "The default is 10 times the base_interval."
#[test]
fn dns_failure_max_interval_defaults_to_ten_times_the_base() {
    let snapshot = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      dns_failure_refresh_rate:\n        base_interval: 2s",
    ))
    .expect("lowers");
    let refresh = refresh_of(&snapshot);
    assert_eq!(refresh.failure_base_interval, Duration::from_secs(2));
    assert_eq!(refresh.failure_max_interval, Duration::from_secs(20));
}

/// Envoy requires `max_interval >= base_interval`, so equal is legal and means
/// a fixed retry interval.
#[test]
fn dns_failure_max_interval_equal_to_base_is_accepted() {
    let snapshot = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      dns_failure_refresh_rate:\n        base_interval: 3s\n        max_interval: 3s",
    ))
    .expect("lowers");
    let refresh = refresh_of(&snapshot);
    assert_eq!(refresh.failure_base_interval, refresh.failure_max_interval);
}

#[test]
fn every_dns_setting_together_lowers() {
    let snapshot = lower(&dns_cluster_yaml(
        "LOGICAL_DNS",
        "      dns_refresh_rate: 10s\n      dns_jitter: 1s\n      dns_failure_refresh_rate:\n        base_interval: 0.5s\n        max_interval: 8s",
    ))
    .expect("lowers");
    assert_eq!(
        snapshot.clusters["dns"].discovery,
        DiscoveryType::LogicalDns(DnsRefresh {
            refresh_rate: Duration::from_secs(10),
            jitter: Duration::from_secs(1),
            failure_base_interval: Duration::from_millis(500),
            failure_max_interval: Duration::from_secs(8),
        })
    );
}

// ------------------------------------------------------------ validation --

#[test]
fn dns_refresh_rate_at_or_below_one_millisecond_is_rejected_with_its_path() {
    for value in ["0s", "0.001s"] {
        for ty in DNS_TYPES {
            let err = lower(&dns_cluster_yaml(
                ty,
                &format!("      dns_refresh_rate: {value}"),
            ))
            .expect_err("Envoy requires dns_refresh_rate > 1ms");
            assert_eq!(
                err_parts(&err).0,
                "static_resources.clusters[0].dns_refresh_rate",
                "{ty} {value}"
            );
        }
    }
}

#[test]
fn a_negative_dns_jitter_is_rejected_with_its_path() {
    let err = lower(&dns_cluster_yaml("STRICT_DNS", "      dns_jitter: -1s"))
        .expect_err("dns_jitter must be >= 0");
    assert_eq!(err_parts(&err).0, "static_resources.clusters[0].dns_jitter");
}

#[test]
fn dns_failure_refresh_rate_without_a_base_interval_is_rejected_with_its_path() {
    let err = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      dns_failure_refresh_rate:\n        max_interval: 10s",
    ))
    .expect_err("base_interval is required");
    assert_eq!(
        err_parts(&err).0,
        "static_resources.clusters[0].dns_failure_refresh_rate.base_interval"
    );
}

#[test]
fn dns_failure_intervals_at_or_below_one_millisecond_are_rejected_with_their_paths() {
    let err = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      dns_failure_refresh_rate:\n        base_interval: 0.001s",
    ))
    .expect_err("base_interval must be > 1ms");
    assert_eq!(
        err_parts(&err).0,
        "static_resources.clusters[0].dns_failure_refresh_rate.base_interval"
    );

    let err = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      dns_failure_refresh_rate:\n        base_interval: 1s\n        max_interval: 0.001s",
    ))
    .expect_err("max_interval must be > 1ms");
    assert_eq!(
        err_parts(&err).0,
        "static_resources.clusters[0].dns_failure_refresh_rate.max_interval"
    );
}

#[test]
fn dns_failure_max_interval_below_the_base_is_rejected_with_its_path() {
    let err = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      dns_failure_refresh_rate:\n        base_interval: 10s\n        max_interval: 5s",
    ))
    .expect_err("max_interval must be >= base_interval");
    let (path, reason) = err_parts(&err);
    assert_eq!(
        path,
        "static_resources.clusters[0].dns_failure_refresh_rate.max_interval"
    );
    assert!(reason.contains("base_interval"), "got: {reason}");
}

// --------------------------------------------------------- respect_dns_ttl --

/// `getaddrinfo` reports no TTLs, so `respect_dns_ttl` cannot be honored.
#[test]
fn respect_dns_ttl_true_is_rejected_with_the_reason() {
    for ty in DNS_TYPES {
        let err = lower(&dns_cluster_yaml(ty, "      respect_dns_ttl: true"))
            .expect_err("respect_dns_ttl: true cannot be honored");
        assert!(matches!(err, ConfigError::UnsupportedField { .. }), "{err}");
        let (path, reason) = err_parts(&err);
        assert_eq!(path, "static_resources.clusters[0].respect_dns_ttl", "{ty}");
        assert!(reason.contains("TTL"), "got: {reason}");
        assert!(reason.contains("getaddrinfo"), "got: {reason}");
    }
}

/// `respect_dns_ttl` is a plain proto3 bool, so `false` is the unset value and
/// asks for exactly what the resolver does.
#[test]
fn respect_dns_ttl_false_is_the_same_as_unset() {
    let snapshot = lower(&dns_cluster_yaml(
        "STRICT_DNS",
        "      respect_dns_ttl: false",
    ))
    .expect("false is the default");
    assert_eq!(refresh_of(&snapshot), DnsRefresh::ENVOY_DEFAULT);
}

// ------------------------------------------- settings that do not apply --

/// Cluster bodies for the three kinds that never re-resolve on a timer, each
/// followed by the index its cluster sits at, so the expected path is exact.
fn inert_cluster_yaml(kind: &str, setting: &str) -> (String, usize) {
    match kind {
        "STATIC" => (
            format!(
                r#"
static_resources:
  clusters:
    - name: inert
      type: STATIC
{setting}
      load_assignment:
        cluster_name: inert
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: {{ socket_address: {{ address: 10.0.0.1, port_value: 443 }} }}
"#
            ),
            0,
        ),
        "EDS" => (
            format!(
                r#"
static_resources:
  clusters:
    - name: inert
      type: EDS
{setting}
      eds_cluster_config:
        eds_config:
          ads: {{}}
          resource_api_version: V3
"#
            ),
            0,
        ),
        "aggregate" => (
            format!(
                r#"
static_resources:
  clusters:
    - name: a
      type: STATIC
      load_assignment:
        cluster_name: a
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address: {{ socket_address: {{ address: 10.0.0.1, port_value: 443 }} }}
    - name: inert
      lb_policy: CLUSTER_PROVIDED
{setting}
      cluster_type:
        name: envoy.clusters.aggregate
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig
          clusters: [a]
"#
            ),
            1,
        ),
        other => panic!("unknown cluster kind {other}"),
    }
}

/// These settings apply only to STRICT_DNS and LOGICAL_DNS clusters.
#[test]
fn dns_settings_on_a_cluster_that_never_re_resolves_are_rejected_with_their_paths() {
    let settings = [
        ("dns_refresh_rate", "      dns_refresh_rate: 30s"),
        ("dns_jitter", "      dns_jitter: 1s"),
        (
            "dns_failure_refresh_rate",
            "      dns_failure_refresh_rate:\n        base_interval: 1s",
        ),
        ("respect_dns_ttl", "      respect_dns_ttl: true"),
    ];
    for kind in ["STATIC", "EDS", "aggregate"] {
        for (field, setting) in settings {
            let (yaml, index) = inert_cluster_yaml(kind, setting);
            let err = lower(&yaml).expect_err("the setting is inert here");
            let (path, reason) = err_parts(&err);
            assert_eq!(
                path,
                format!("static_resources.clusters[{index}].{field}"),
                "{kind} {field}"
            );
            assert!(
                reason.contains("STRICT_DNS and LOGICAL_DNS"),
                "{kind} {field}: {reason}"
            );
        }
    }
}

/// Control for the test above: the same three clusters with none of the
/// settings still lower, so the rejections above come from the settings.
#[test]
fn the_same_inert_clusters_lower_without_the_settings() {
    for kind in ["STATIC", "EDS", "aggregate"] {
        let (yaml, _) = inert_cluster_yaml(kind, "");
        let snapshot = lower(&yaml).unwrap_or_else(|e| panic!("{kind} must lower: {e}"));
        assert!(
            snapshot.clusters["inert"].discovery.dns_refresh().is_none(),
            "{kind}"
        );
    }
}

// ------------------------------------------ resolver configuration stays out --

/// Only the timing settings are accepted. Resolver selection and lookup-family
/// knobs are still rejected by path, because nothing configures the resolver.
#[test]
fn resolver_configuration_is_still_rejected_with_its_path() {
    for (field, setting) in [
        ("dns_lookup_family", "      dns_lookup_family: V4_ONLY"),
        (
            "use_tcp_for_dns_lookups",
            "      use_tcp_for_dns_lookups: true",
        ),
    ] {
        for ty in DNS_TYPES {
            let err = lower(&dns_cluster_yaml(ty, setting))
                .expect_err("resolver configuration is not implemented");
            assert!(matches!(err, ConfigError::UnsupportedField { .. }), "{err}");
            assert_eq!(
                err_parts(&err).0,
                format!("static_resources.clusters[0].{field}"),
                "{ty}"
            );
        }
    }
}

// ----------------------------------------------------------------- xDS --

fn dynamic_dns_cluster(discovery: cluster_v3::cluster::DiscoveryType) -> cluster_v3::Cluster {
    cluster_v3::Cluster {
        name: "dns".to_string(),
        cluster_discovery_type: Some(cluster_v3::cluster::ClusterDiscoveryType::Type(
            discovery as i32,
        )),
        load_assignment: Some(endpoint_v3::ClusterLoadAssignment {
            cluster_name: "dns".to_string(),
            endpoints: vec![endpoint_v3::LocalityLbEndpoints {
                lb_endpoints: vec![endpoint_v3::LbEndpoint {
                    host_identifier: Some(endpoint_v3::lb_endpoint::HostIdentifier::Endpoint(
                        endpoint_v3::Endpoint {
                            address: Some(core_v3::Address {
                                address: Some(core_v3::address::Address::SocketAddress(
                                    core_v3::SocketAddress {
                                        address: "10.0.0.1".to_string(),
                                        port_specifier: Some(
                                            core_v3::socket_address::PortSpecifier::PortValue(443),
                                        ),
                                        ..Default::default()
                                    },
                                )),
                            }),
                            ..Default::default()
                        },
                    )),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn any_of(cluster: &cluster_v3::Cluster) -> prost_types::Any {
    prost_types::Any {
        type_url: "type.googleapis.com/envoy.config.cluster.v3.Cluster".to_string(),
        value: cluster.encode_to_vec(),
    }
}

fn secs(seconds: i64, nanos: i32) -> prost_types::Duration {
    prost_types::Duration { seconds, nanos }
}

/// Rust note: the DNS timing fields are `#[deprecated]` in the generated
/// proto types (Envoy moved them under a cluster-type extension we do not
/// implement), and a test that sets them is exactly the use the lint flags.
#[allow(deprecated)]
fn set_dns_settings(
    cluster: &mut cluster_v3::Cluster,
    refresh: Option<prost_types::Duration>,
    jitter: Option<prost_types::Duration>,
    failure: Option<cluster_v3::cluster::RefreshRate>,
) {
    cluster.dns_refresh_rate = refresh;
    cluster.dns_jitter = jitter;
    cluster.dns_failure_refresh_rate = failure;
}

/// The xDS door runs `convert_cluster` too, so a CDS-delivered DNS cluster
/// carries its refresh settings.
#[test]
fn a_dynamic_dns_cluster_lowers_its_refresh_settings() {
    let mut cluster = dynamic_dns_cluster(cluster_v3::cluster::DiscoveryType::StrictDns);
    set_dns_settings(
        &mut cluster,
        Some(secs(15, 0)),
        Some(secs(0, 500_000_000)),
        Some(cluster_v3::cluster::RefreshRate {
            base_interval: Some(secs(2, 0)),
            max_interval: None,
        }),
    );
    let lowered = lower_dynamic_cluster(&any_of(&cluster), "cds.clusters[dns]").expect("lowers");
    assert_eq!(
        lowered.discovery,
        DiscoveryType::StrictDns(DnsRefresh {
            refresh_rate: Duration::from_secs(15),
            jitter: Duration::from_millis(500),
            failure_base_interval: Duration::from_secs(2),
            failure_max_interval: Duration::from_secs(20),
        })
    );
}

/// The proto's own validation rules are not run on an xDS resource, so the
/// range checks must hold in typed lowering, rooted at the caller's path.
#[test]
fn a_dynamic_dns_cluster_with_a_bad_value_is_refused_with_the_callers_path() {
    let mut sub_millisecond = dynamic_dns_cluster(cluster_v3::cluster::DiscoveryType::LogicalDns);
    set_dns_settings(&mut sub_millisecond, Some(secs(0, 1_000_000)), None, None);
    let err = lower_dynamic_cluster(&any_of(&sub_millisecond), "cds.clusters[dns]")
        .expect_err("1ms is not above Envoy's floor");
    assert_eq!(err_parts(&err).0, "cds.clusters[dns].dns_refresh_rate");

    let mut max_below_base = dynamic_dns_cluster(cluster_v3::cluster::DiscoveryType::StrictDns);
    set_dns_settings(
        &mut max_below_base,
        None,
        None,
        Some(cluster_v3::cluster::RefreshRate {
            base_interval: Some(secs(10, 0)),
            max_interval: Some(secs(5, 0)),
        }),
    );
    let err = lower_dynamic_cluster(&any_of(&max_below_base), "cds.clusters[dns]")
        .expect_err("max_interval below base_interval");
    assert_eq!(
        err_parts(&err).0,
        "cds.clusters[dns].dns_failure_refresh_rate.max_interval"
    );

    let mut no_base = dynamic_dns_cluster(cluster_v3::cluster::DiscoveryType::StrictDns);
    set_dns_settings(
        &mut no_base,
        None,
        None,
        Some(cluster_v3::cluster::RefreshRate {
            base_interval: None,
            max_interval: Some(secs(5, 0)),
        }),
    );
    let err = lower_dynamic_cluster(&any_of(&no_base), "cds.clusters[dns]")
        .expect_err("base_interval is required");
    assert_eq!(
        err_parts(&err).0,
        "cds.clusters[dns].dns_failure_refresh_rate.base_interval"
    );
}

#[test]
fn a_dynamic_static_cluster_with_a_dns_setting_is_refused_with_the_callers_path() {
    let mut cluster = dynamic_dns_cluster(cluster_v3::cluster::DiscoveryType::Static);
    set_dns_settings(&mut cluster, None, Some(secs(1, 0)), None);
    let err = lower_dynamic_cluster(&any_of(&cluster), "cds.clusters[dns]")
        .expect_err("dns_jitter is inert on a STATIC cluster");
    assert_eq!(err_parts(&err).0, "cds.clusters[dns].dns_jitter");
}

#[test]
fn a_dynamic_dns_cluster_asking_for_respect_dns_ttl_is_refused() {
    let mut cluster = dynamic_dns_cluster(cluster_v3::cluster::DiscoveryType::StrictDns);
    #[allow(deprecated)]
    {
        cluster.respect_dns_ttl = true;
    }
    let err = lower_dynamic_cluster(&any_of(&cluster), "cds.clusters[dns]")
        .expect_err("respect_dns_ttl: true cannot be honored");
    assert!(matches!(err, ConfigError::UnsupportedField { .. }), "{err}");
    assert_eq!(err_parts(&err).0, "cds.clusters[dns].respect_dns_ttl");
}
