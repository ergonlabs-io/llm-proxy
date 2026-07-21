//! WP-07 chunk A acceptance tests: the full 9-criteria `FilterChainMatch`,
//! listener socket options (`tcp_backlog_size`/`bind_to_port`), and the
//! `CidrRange` matcher that backs `prefix_ranges`/`source_prefix_ranges`.

use std::net::IpAddr;

use proxy_config::ir::*;
use proxy_config::{build_snapshot, parse_bootstrap, ConfigError, ConfigFormat, StrictMode};

fn snapshot_from(yaml: &str) -> Result<ConfigSnapshot, ConfigError> {
    let loaded = parse_bootstrap(yaml.as_bytes(), ConfigFormat::Yaml, StrictMode::Strict)?;
    build_snapshot(&loaded)
}

/// A tcp_proxy filter chain wrapper so each test only has to supply the
/// listener-level and filter_chain_match-level YAML under test.
fn listener_yaml(listener_extra: &str, match_yaml: &str) -> String {
    format!(
        r#"
static_resources:
  listeners:
    - name: l1
      {listener_extra}
      address:
        socket_address: {{ address: 0.0.0.0, port_value: 10000 }}
      filter_chains:
        - filter_chain_match:
{match_yaml}
          filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: t
                cluster: c
"#
    )
}

/// Every one of the 9 match criteria lowers into its IR field, and the new
/// listener socket options lower too.
#[test]
fn full_filter_chain_match_lowers_every_criterion() {
    let yaml = listener_yaml(
        "tcp_backlog_size: 512\n      bind_to_port: false",
        r#"            destination_port: 443
            prefix_ranges:
              - address_prefix: 10.0.0.0
                prefix_len: 8
            server_names: ["*.example.com", "api.example.com"]
            transport_protocol: tls
            application_protocols: ["h2", "http/1.1"]
            direct_source_prefix_ranges:
              - address_prefix: 192.168.0.0
                prefix_len: 16
            source_type: SAME_IP_OR_LOOPBACK
            source_prefix_ranges:
              - address_prefix: "2001:db8::"
                prefix_len: 32
            source_ports: [1024, 2048]
"#,
    );
    let snapshot = snapshot_from(&yaml).expect("config must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.tcp_backlog_size, Some(512));
    assert!(!listener.bind_to_port);

    let m = &listener.filter_chains[0].match_criteria;
    assert_eq!(m.destination_port, Some(443));
    assert_eq!(
        m.prefix_ranges,
        vec![CidrRange {
            addr: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
        }]
    );
    assert_eq!(
        m.server_names,
        vec!["*.example.com".to_string(), "api.example.com".to_string()]
    );
    assert_eq!(m.transport_protocol.as_deref(), Some("tls"));
    assert_eq!(
        m.application_protocols,
        vec!["h2".to_string(), "http/1.1".to_string()]
    );
    assert_eq!(
        m.direct_source_prefix_ranges,
        vec![CidrRange {
            addr: "192.168.0.0".parse().unwrap(),
            prefix_len: 16,
        }]
    );
    assert_eq!(m.source_type, SourceType::SameIpOrLoopback);
    assert_eq!(
        m.source_prefix_ranges,
        vec![CidrRange {
            addr: "2001:db8::".parse().unwrap(),
            prefix_len: 32,
        }]
    );
    assert_eq!(m.source_ports, vec![1024, 2048]);
}

/// `tcp_backlog_size`/`bind_to_port` default appropriately when unset.
#[test]
fn listener_socket_option_defaults() {
    let yaml = listener_yaml("", "            destination_port: 80\n");
    let snapshot = snapshot_from(&yaml).expect("config must lower");
    let listener = snapshot.listeners.get("l1").expect("listener");
    assert_eq!(listener.tcp_backlog_size, None);
    assert!(listener.bind_to_port); // Envoy default: true
}

/// `address_suffix` is Envoy's own `#not-implemented-hide` field; we reject
/// it with its full path rather than silently ignoring it.
#[test]
fn address_suffix_is_rejected() {
    let yaml = listener_yaml("", "            address_suffix: \"0.0\"\n");
    let err = snapshot_from(&yaml).expect_err("address_suffix must fail");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filter_chain_match.address_suffix"
    );
}

/// `suffix_len` is likewise `#not-implemented-hide` in Envoy.
#[test]
fn suffix_len_is_rejected() {
    let yaml = listener_yaml("", "            suffix_len: 8\n");
    let err = snapshot_from(&yaml).expect_err("suffix_len must fail");
    let ConfigError::UnsupportedField { field_path, .. } = &err else {
        panic!("expected UnsupportedField, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filter_chain_match.suffix_len"
    );
}

/// Only exact names and `*.`-prefixed suffix wildcards are valid server
/// names; every other use of `*` is rejected with its full path.
#[test]
fn bad_server_name_wildcards_are_rejected() {
    for bad in ["*", "a.*.b", "*example.com"] {
        let yaml = listener_yaml("", &format!("            server_names: [\"{bad}\"]\n"));
        let err = snapshot_from(&yaml).expect_err(&format!("`{bad}` must be rejected"));
        let ConfigError::InvalidValue { field_path, .. } = &err else {
            panic!("expected InvalidValue for `{bad}`, got: {err}");
        };
        assert_eq!(
            field_path,
            "static_resources.listeners[0].filter_chains[0].filter_chain_match.server_names[0]",
            "wrong path for `{bad}`"
        );
    }
}

/// A bad prefix_len (too long for the address family) is rejected with the
/// dotted path into the offending CidrRange.
#[test]
fn bad_prefix_len_is_rejected() {
    let yaml = listener_yaml(
        "",
        r#"            prefix_ranges:
              - address_prefix: 10.0.0.0
                prefix_len: 33
"#,
    );
    let err = snapshot_from(&yaml).expect_err("prefix_len 33 on an IPv4 range must fail");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filter_chain_match.prefix_ranges[0].prefix_len"
    );
}

/// `destination_port` above 65535 is rejected by the generic PGV validator
/// (it is a wrapped `UInt32Value` with a `lte: 65535` rule) before lowering
/// even runs; `source_ports` is a plain repeated scalar the PGV walker does
/// not check per-item, so lowering enforces the same bound itself.
#[test]
fn out_of_range_ports_are_rejected() {
    let yaml = listener_yaml("", "            destination_port: 70000\n");
    let err = snapshot_from(&yaml).expect_err("destination_port 70000 must fail");
    let ConfigError::Validation { field_path, .. } = &err else {
        panic!("expected Validation, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filter_chain_match.destination_port"
    );

    let yaml = listener_yaml("", "            source_ports: [70000]\n");
    let err = snapshot_from(&yaml).expect_err("source_ports 70000 must fail");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].filter_chains[0].filter_chain_match.source_ports[0]"
    );
}

/// Two filter chains with byte-identical match criteria are rejected,
/// naming the listener and both chain indices.
#[test]
fn duplicate_filter_chain_match_criteria_are_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      filter_chains:
        - filter_chain_match: { destination_port: 443 }
          filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: t
                cluster: c
        - filter_chain_match: { destination_port: 443 }
          filters:
            - name: envoy.filters.network.tcp_proxy
              typed_config:
                "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
                stat_prefix: t
                cluster: c
"#;
    let err = snapshot_from(yaml).expect_err("duplicate match criteria must fail");
    let ConfigError::InvalidValue { field_path, reason } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(field_path, "static_resources.listeners[0]");
    assert!(
        reason.contains('l'),
        "reason should name the listener, got: {reason}"
    );
    assert!(
        reason.contains("l1"),
        "reason should name listener `l1`, got: {reason}"
    );
    assert!(
        reason.contains("filter_chains[0]") && reason.contains("filter_chains[1]"),
        "reason should name both chain indices, got: {reason}"
    );
}

/// `default_filter_chain` with non-empty match criteria is rejected instead
/// of silently ignored (Envoy ignores match criteria there).
#[test]
fn default_filter_chain_with_match_criteria_is_rejected() {
    let yaml = r#"
static_resources:
  listeners:
    - name: l1
      address:
        socket_address: { address: 0.0.0.0, port_value: 10000 }
      default_filter_chain:
        filter_chain_match: { destination_port: 443 }
        filters:
          - name: envoy.filters.network.tcp_proxy
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy
              stat_prefix: t
              cluster: c
"#;
    let err = snapshot_from(yaml).expect_err("default_filter_chain with match criteria must fail");
    let ConfigError::InvalidValue { field_path, .. } = &err else {
        panic!("expected InvalidValue, got: {err}");
    };
    assert_eq!(
        field_path,
        "static_resources.listeners[0].default_filter_chain.filter_chain_match"
    );
}

// ---------------------------------------------------------------- CidrRange --

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn cidr_range_v4_prefix_match() {
    let range = CidrRange {
        addr: ip("10.1.2.0"),
        prefix_len: 24,
    };
    assert!(range.contains(ip("10.1.2.42")));
    assert!(!range.contains(ip("10.1.3.42")));
}

#[test]
fn cidr_range_v6_prefix_match() {
    let range = CidrRange {
        addr: ip("2001:db8::"),
        prefix_len: 32,
    };
    assert!(range.contains(ip("2001:db8::1")));
    assert!(!range.contains(ip("2001:db9::1")));
}

/// Address families never match each other, even for numerically-equivalent
/// addresses.
#[test]
fn cidr_range_families_never_cross_match() {
    let v4_range = CidrRange {
        addr: ip("0.0.0.0"),
        prefix_len: 0,
    };
    assert!(!v4_range.contains(ip("::1")));
    let v6_range = CidrRange {
        addr: ip("::"),
        prefix_len: 0,
    };
    assert!(!v6_range.contains(ip("10.0.0.1")));
}

#[test]
fn cidr_range_prefix_len_zero_matches_everything_in_family() {
    let v4 = CidrRange {
        addr: ip("0.0.0.0"),
        prefix_len: 0,
    };
    assert!(v4.contains(ip("255.255.255.255")));
    assert!(v4.contains(ip("1.2.3.4")));

    let v6 = CidrRange {
        addr: ip("::"),
        prefix_len: 0,
    };
    assert!(v6.contains(ip("ffff::1")));
}

#[test]
fn cidr_range_prefix_len_32_requires_exact_v4_match() {
    let range = CidrRange {
        addr: ip("192.168.1.1"),
        prefix_len: 32,
    };
    assert!(range.contains(ip("192.168.1.1")));
    assert!(!range.contains(ip("192.168.1.2")));
}

#[test]
fn cidr_range_prefix_len_128_requires_exact_v6_match() {
    let range = CidrRange {
        addr: ip("::1"),
        prefix_len: 128,
    };
    assert!(range.contains(ip("::1")));
    assert!(!range.contains(ip("::2")));
}
