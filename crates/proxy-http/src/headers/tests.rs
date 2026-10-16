//! envoy-semantics.md S9 conformance tests for [`super`].

use super::*;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn header_values(headers: &HeaderMap, name: &str) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------
// x-forwarded-for
// ---------------------------------------------------------------------

#[test]
fn xff_append_when_use_remote_address_true_and_absent() {
    let mut headers = HeaderMap::new();
    let opts = XffOptions {
        use_remote_address: true,
        xff_num_trusted_hops: 0,
    };
    apply_xff(&mut headers, v4(1, 2, 3, 4), &opts);
    assert_eq!(header_values(&headers, XFF), vec!["1.2.3.4"]);
}

#[test]
fn xff_append_when_use_remote_address_true_and_present() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("9.9.9.9, 8.8.8.8"),
    );
    let opts = XffOptions {
        use_remote_address: true,
        xff_num_trusted_hops: 0,
    };
    apply_xff(&mut headers, v4(1, 2, 3, 4), &opts);
    assert_eq!(
        header_values(&headers, XFF),
        vec!["9.9.9.9, 8.8.8.8, 1.2.3.4"]
    );
}

#[test]
fn xff_passthrough_untouched_when_use_remote_address_false() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("9.9.9.9"),
    );
    let opts = XffOptions {
        use_remote_address: false,
        xff_num_trusted_hops: 0,
    };
    apply_xff(&mut headers, v4(1, 2, 3, 4), &opts);
    assert_eq!(header_values(&headers, XFF), vec!["9.9.9.9"]);
}

#[test]
fn xff_passthrough_when_absent_and_use_remote_address_false() {
    let mut headers = HeaderMap::new();
    let opts = XffOptions {
        use_remote_address: false,
        xff_num_trusted_hops: 0,
    };
    apply_xff(&mut headers, v4(1, 2, 3, 4), &opts);
    assert!(!headers.contains_key(XFF));
}

#[test]
fn xff_multiple_header_instances_collapsed_into_one_on_append() {
    let mut headers = HeaderMap::new();
    headers.append(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("1.1.1.1"),
    );
    headers.append(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("2.2.2.2"),
    );
    let opts = XffOptions {
        use_remote_address: true,
        xff_num_trusted_hops: 0,
    };
    apply_xff(&mut headers, v4(3, 3, 3, 3), &opts);
    // Rust note: `get_all` after `insert` (which `apply_xff` uses to write
    // the result) should yield exactly one instance again.
    assert_eq!(
        header_values(&headers, XFF),
        vec!["1.1.1.1, 2.2.2.2, 3.3.3.3"]
    );
}

// --- resolve_trusted_address: xff_num_trusted_hops rightmost-N ---

fn opts(use_remote: bool, hops: u32) -> XffOptions {
    XffOptions {
        use_remote_address: use_remote,
        xff_num_trusted_hops: hops,
    }
}

#[test]
fn resolve_trusted_address_zero_hops_is_rightmost() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("1.1.1.1, 2.2.2.2, 3.3.3.3"),
    );
    let remote = v4(9, 9, 9, 9);
    assert_eq!(
        resolve_trusted_address(&headers, remote, &opts(false, 0)),
        v4(3, 3, 3, 3)
    );
}

#[test]
fn resolve_trusted_address_one_hop_skips_rightmost() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("1.1.1.1, 2.2.2.2, 3.3.3.3"),
    );
    let remote = v4(9, 9, 9, 9);
    assert_eq!(
        resolve_trusted_address(&headers, remote, &opts(false, 1)),
        v4(2, 2, 2, 2)
    );
}

#[test]
fn resolve_trusted_address_n_hops_reaches_leftmost() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("1.1.1.1, 2.2.2.2, 3.3.3.3"),
    );
    let remote = v4(9, 9, 9, 9);
    assert_eq!(
        resolve_trusted_address(&headers, remote, &opts(false, 2)),
        v4(1, 1, 1, 1)
    );
}

#[test]
fn resolve_trusted_address_hops_larger_than_list_falls_back_to_leftmost() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("1.1.1.1, 2.2.2.2, 3.3.3.3"),
    );
    let remote = v4(9, 9, 9, 9);
    assert_eq!(
        resolve_trusted_address(&headers, remote, &opts(false, 100)),
        v4(1, 1, 1, 1)
    );
}

#[test]
fn resolve_trusted_address_empty_xff_falls_back_to_remote() {
    let headers = HeaderMap::new();
    let remote = v4(9, 9, 9, 9);
    assert_eq!(
        resolve_trusted_address(&headers, remote, &opts(false, 0)),
        remote
    );
}

#[test]
fn resolve_trusted_address_use_remote_address_true_ignores_xff() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("1.1.1.1"),
    );
    let remote = v4(9, 9, 9, 9);
    assert_eq!(
        resolve_trusted_address(&headers, remote, &opts(true, 5)),
        remote
    );
}

#[test]
fn resolve_trusted_address_garbage_token_falls_back_to_remote() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("not-an-ip"),
    );
    let remote = v4(9, 9, 9, 9);
    assert_eq!(
        resolve_trusted_address(&headers, remote, &opts(false, 0)),
        remote
    );
}

// ---------------------------------------------------------------------
// internal vs external
// ---------------------------------------------------------------------

#[test]
fn internal_rfc1918_10_8_boundaries() {
    let headers = HeaderMap::new();
    assert!(!is_internal_request(&headers, v4(9, 255, 255, 255)));
    assert!(is_internal_request(&headers, v4(10, 0, 0, 0)));
    assert!(is_internal_request(&headers, v4(10, 255, 255, 255)));
    assert!(!is_internal_request(&headers, v4(11, 0, 0, 0)));
}

#[test]
fn internal_rfc1918_172_16_12_boundaries() {
    let headers = HeaderMap::new();
    assert!(!is_internal_request(&headers, v4(172, 15, 255, 255)));
    assert!(is_internal_request(&headers, v4(172, 16, 0, 0)));
    assert!(is_internal_request(&headers, v4(172, 31, 255, 255)));
    assert!(!is_internal_request(&headers, v4(172, 32, 0, 0)));
}

#[test]
fn internal_rfc1918_192_168_16_boundaries() {
    let headers = HeaderMap::new();
    assert!(!is_internal_request(&headers, v4(192, 167, 255, 255)));
    assert!(is_internal_request(&headers, v4(192, 168, 0, 0)));
    assert!(is_internal_request(&headers, v4(192, 168, 255, 255)));
    assert!(!is_internal_request(&headers, v4(192, 169, 0, 0)));
}

#[test]
fn internal_public_ip_is_external() {
    let headers = HeaderMap::new();
    assert!(!is_internal_request(&headers, v4(8, 8, 8, 8)));
}

#[test]
fn internal_loopback_v4_is_internal() {
    let headers = HeaderMap::new();
    assert!(is_internal_request(&headers, v4(127, 0, 0, 1)));
}

#[test]
fn internal_loopback_v6_is_internal() {
    let headers = HeaderMap::new();
    assert!(is_internal_request(
        &headers,
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    ));
}

#[test]
fn internal_ipv6_unique_local_fc00_7_boundaries() {
    let headers = HeaderMap::new();
    // fc00::/7 covers first byte 0xfc..=0xfd.
    assert!(is_internal_request(
        &headers,
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))
    ));
    assert!(is_internal_request(
        &headers,
        IpAddr::V6(Ipv6Addr::new(0xfdff, 0, 0, 0, 0, 0, 0, 1))
    ));
    assert!(!is_internal_request(
        &headers,
        IpAddr::V6(Ipv6Addr::new(0xfbff, 0, 0, 0, 0, 0, 0, 1))
    ));
    assert!(!is_internal_request(
        &headers,
        IpAddr::V6(Ipv6Addr::new(0xfe00, 0, 0, 0, 0, 0, 0, 1))
    ));
}

#[test]
fn internal_public_ipv6_is_external() {
    let headers = HeaderMap::new();
    assert!(!is_internal_request(
        &headers,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    ));
}

#[test]
fn internal_requires_single_xff_entry_multi_entry_is_external() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("10.0.0.1, 10.0.0.2"),
    );
    assert!(!is_internal_request(&headers, v4(10, 0, 0, 3)));
}

#[test]
fn internal_rfc1918_source_with_single_xff_entry_is_internal() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("10.0.0.1"),
    );
    assert!(is_internal_request(&headers, v4(10, 0, 0, 3)));
}

#[test]
fn internal_rfc1918_source_with_no_xff_is_internal() {
    let headers = HeaderMap::new();
    assert!(is_internal_request(&headers, v4(10, 0, 0, 3)));
}

// ---------------------------------------------------------------------
// x-request-id
// ---------------------------------------------------------------------

#[test]
fn request_id_generated_when_absent() {
    let mut headers = HeaderMap::new();
    let mut state = 42u64;
    let generated = ensure_request_id(&mut headers, &mut || generate_request_id(&mut state, false));
    assert!(generated);
    assert!(headers.contains_key("x-request-id"));
}

#[test]
fn request_id_preserved_when_present() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_static("existing-id"),
    );
    let mut called = false;
    let generated = ensure_request_id(&mut headers, &mut || {
        called = true;
        "should-not-be-used".to_string()
    });
    assert!(!generated);
    assert!(!called);
    assert_eq!(
        headers.get("x-request-id").unwrap().to_str().unwrap(),
        "existing-id"
    );
}

#[test]
fn request_id_deterministic_from_seed() {
    let mut a = 7u64;
    let mut b = 7u64;
    assert_eq!(
        generate_request_id(&mut a, false),
        generate_request_id(&mut b, false)
    );
}

#[test]
fn request_id_has_uuid_v4_shape() {
    let mut state = 1u64;
    let id = generate_request_id(&mut state, false);
    let parts: Vec<&str> = id.split('-').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);
    assert_eq!(&parts[2][..1], "4");
    assert!(matches!(&parts[3][..1], "8" | "9" | "a"));
}

#[test]
fn request_id_traced_sets_variant_nibble_to_b() {
    let mut state = 1u64;
    let id = generate_request_id(&mut state, true);
    let parts: Vec<&str> = id.split('-').collect();
    assert_eq!(&parts[3][..1], "b");
}

// ---------------------------------------------------------------------
// x-envoy-* stripping
// ---------------------------------------------------------------------

#[test]
fn strip_envoy_headers_removes_matching_lowercase() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-envoy-attempt-count"),
        HeaderValue::from_static("2"),
    );
    headers.insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_static("keep-me"),
    );
    strip_envoy_headers_from_external(&mut headers);
    assert!(!headers.contains_key("x-envoy-attempt-count"));
    assert!(headers.contains_key("x-request-id"));
}

#[test]
fn strip_envoy_headers_removes_mixed_case() {
    let mut headers = HeaderMap::new();
    // Rust note: `HeaderName::from_bytes` accepts uppercase ASCII bytes as a
    // valid token but normalizes/stores header names case-insensitively;
    // build via `from_bytes` (fallible) rather than `from_static` (which
    // requires an already-normalized literal) to exercise a mixed-case name.
    let name = HeaderName::from_bytes(b"X-Envoy-Internal").unwrap();
    headers.insert(name, HeaderValue::from_static("true"));
    strip_envoy_headers_from_external(&mut headers);
    assert!(!headers.contains_key("x-envoy-internal"));
}

#[test]
fn strip_envoy_headers_leaves_non_envoy_alone() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-custom"),
        HeaderValue::from_static("v"),
    );
    strip_envoy_headers_from_external(&mut headers);
    assert!(headers.contains_key("x-custom"));
}

#[test]
fn strip_envoy_headers_empty_map_does_not_panic() {
    let mut headers = HeaderMap::new();
    strip_envoy_headers_from_external(&mut headers);
    assert!(headers.is_empty());
}

#[test]
fn strip_envoy_headers_multiple_matching_names() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-envoy-attempt-count"),
        HeaderValue::from_static("1"),
    );
    headers.insert(
        HeaderName::from_static("x-envoy-upstream-service-time"),
        HeaderValue::from_static("5"),
    );
    strip_envoy_headers_from_external(&mut headers);
    assert!(!headers.contains_key("x-envoy-attempt-count"));
    assert!(!headers.contains_key("x-envoy-upstream-service-time"));
}

// ---------------------------------------------------------------------
// x-forwarded-proto
// ---------------------------------------------------------------------

#[test]
fn forwarded_proto_https_when_tls() {
    let mut headers = HeaderMap::new();
    set_forwarded_proto(&mut headers, true);
    assert_eq!(
        headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
        "https"
    );
}

#[test]
fn forwarded_proto_http_when_plaintext() {
    let mut headers = HeaderMap::new();
    set_forwarded_proto(&mut headers, false);
    assert_eq!(
        headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
        "http"
    );
}

#[test]
fn forwarded_proto_overwrites_existing() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("ftp"),
    );
    set_forwarded_proto(&mut headers, true);
    assert_eq!(
        headers.get("x-forwarded-proto").unwrap().to_str().unwrap(),
        "https"
    );
}

// ---------------------------------------------------------------------
// hop-by-hop sanitization
// ---------------------------------------------------------------------

#[test]
fn hop_by_hop_removes_connection_upgrade_transfer_encoding() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        HeaderValue::from_static("keep-alive"),
    );
    headers.insert(http::header::UPGRADE, HeaderValue::from_static("websocket"));
    headers.insert(
        http::header::TRANSFER_ENCODING,
        HeaderValue::from_static("chunked"),
    );
    sanitize_hop_by_hop(&mut headers);
    assert!(!headers.contains_key(http::header::CONNECTION));
    assert!(!headers.contains_key(http::header::UPGRADE));
    assert!(!headers.contains_key(http::header::TRANSFER_ENCODING));
}

#[test]
fn hop_by_hop_te_trailers_preserved() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::TE, HeaderValue::from_static("trailers"));
    sanitize_hop_by_hop(&mut headers);
    assert_eq!(
        headers.get(http::header::TE).unwrap().to_str().unwrap(),
        "trailers"
    );
}

#[test]
fn hop_by_hop_te_non_trailers_dropped() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::TE, HeaderValue::from_static("gzip"));
    sanitize_hop_by_hop(&mut headers);
    assert!(!headers.contains_key(http::header::TE));
}

#[test]
fn hop_by_hop_te_multi_valued_keeps_only_trailers() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::TE,
        HeaderValue::from_static("gzip, trailers, deflate"),
    );
    sanitize_hop_by_hop(&mut headers);
    assert_eq!(
        headers.get(http::header::TE).unwrap().to_str().unwrap(),
        "trailers"
    );
}

#[test]
fn hop_by_hop_te_multiple_header_instances_one_with_trailers() {
    let mut headers = HeaderMap::new();
    headers.append(http::header::TE, HeaderValue::from_static("gzip"));
    headers.append(http::header::TE, HeaderValue::from_static("trailers"));
    sanitize_hop_by_hop(&mut headers);
    assert_eq!(
        headers.get(http::header::TE).unwrap().to_str().unwrap(),
        "trailers"
    );
}

#[test]
fn hop_by_hop_leaves_other_headers_alone() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("application/json"),
    );
    sanitize_hop_by_hop(&mut headers);
    assert!(headers.contains_key("content-type"));
}

// ---------------------------------------------------------------------
// robustness: malformed / non-UTF-8 / empty input never panics
// ---------------------------------------------------------------------

#[test]
fn garbage_xff_values_do_not_panic() {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static(XFF),
        HeaderValue::from_static("!!!not,an,ip,,,"),
    );
    let opts = XffOptions {
        use_remote_address: true,
        xff_num_trusted_hops: 0,
    };
    apply_xff(&mut headers, v4(1, 2, 3, 4), &opts);
    // No panic; the garbage tokens are preserved, remote is appended.
    let joined = header_values(&headers, XFF).join("");
    assert!(joined.ends_with("1.2.3.4"));
}

#[test]
fn non_utf8_header_value_does_not_panic() {
    let mut headers = HeaderMap::new();
    // Rust note: `HeaderValue::from_bytes` accepts opaque non-UTF-8 octets
    // (obs-text, per RFC 9110) even though `HeaderValue::from_static` /
    // `from_str` require valid UTF-8 — this is the one legal way to build a
    // non-UTF-8 header value for the test.
    let value = HeaderValue::from_bytes(&[0xff, 0xfe, 0xfd]).unwrap();
    headers.insert(HeaderName::from_static(XFF), value);
    let remote = v4(10, 0, 0, 1);
    let opts = XffOptions {
        use_remote_address: false,
        xff_num_trusted_hops: 0,
    };
    // Should not panic, and should fall back to `remote` since the garbage
    // value can't be split into any usable token.
    assert_eq!(resolve_trusted_address(&headers, remote, &opts), remote);
    // The malformed value contributes zero usable tokens, so a private
    // `remote` with a non-UTF-8 XFF value is still treated as internal
    // (same as no XFF header at all) — just confirming no panic + a
    // deterministic result.
    assert!(is_internal_request(&headers, remote));
}

/// Request ids must not collide across workers. Under ADR-0003 every worker
/// owns its own generator state, so if seeding were constant (or derived from
/// something identical per worker) every worker would emit the *same* id
/// sequence and `x-request-id` would stop identifying requests at all — the
/// one job it has. Two independently drawn seeds must differ, and must produce
/// different first ids.
#[test]
fn independently_seeded_generators_do_not_produce_the_same_ids() {
    let mut a = seed_from_entropy();
    let mut b = seed_from_entropy();
    assert_ne!(a, b, "two entropy draws must not be identical");
    assert_ne!(
        generate_request_id(&mut a, false),
        generate_request_id(&mut b, false),
        "per-worker generators must not emit a shared id sequence"
    );
}

/// The flip side: a *pinned* seed stays reproducible, which is what makes the
/// generator testable at all.
#[test]
fn a_pinned_seed_is_reproducible() {
    let mut a = 42u64;
    let mut b = 42u64;
    assert_eq!(
        generate_request_id(&mut a, false),
        generate_request_id(&mut b, false)
    );
}

#[test]
fn empty_header_map_does_not_panic_anywhere() {
    let mut headers = HeaderMap::new();
    let remote = v4(10, 0, 0, 1);
    let opts = XffOptions {
        use_remote_address: false,
        xff_num_trusted_hops: 3,
    };
    let _ = resolve_trusted_address(&headers, remote, &opts);
    let _ = is_internal_request(&headers, remote);
    sanitize_hop_by_hop(&mut headers);
    strip_envoy_headers_from_external(&mut headers);
    set_forwarded_proto(&mut headers, false);
    let mut state = 0u64;
    let _ = ensure_request_id(&mut headers, &mut || generate_request_id(&mut state, false));
    assert!(!headers.is_empty());
}

// --- client_address: what rate limits key a request on ---

#[test]
fn client_address_ignores_x_forwarded_for_without_trusted_hops() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
    let remote = v4(10, 0, 0, 9);
    // A client can write this header itself, so it must not choose the
    // bucket on a mesh HCM with no trusted hops, nor at the edge.
    assert_eq!(client_address(&headers, remote, &opts(false, 0)), remote);
    assert_eq!(client_address(&headers, remote, &opts(true, 1)), remote);
}

#[test]
fn client_address_uses_the_entry_trusted_hops_vouch_for() {
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("1.2.3.4, 10.0.0.1"));
    let remote = v4(10, 0, 0, 9);
    assert_eq!(client_address(&headers, remote, &opts(false, 1)), v4(1, 2, 3, 4));
}
