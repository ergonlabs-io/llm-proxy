//! Synchronous route matching over the compiled IR (Envoy S1).
//!
//! The IR does not currently represent path-separated prefixes, query
//! parameter matchers, header range/contains/invert matchers, runtime fractions,
//! the gRPC flag, or route/weighted-cluster metadata merges.

use std::sync::Arc;

use proxy_config::ir::{
    ForwardTarget, HashSource, HeaderMatch, HeaderMatchKind, PathMatch, RouteEntry,
    RouteHashPolicy, RouteMatcher, RouteTable, VirtualHostIR, WeightedClusters,
};
use xxhash_rust::xxh64::{xxh64, Xxh64};

// Regexes are anchored during config compilation, so matching here is already
// whole-string. Re-anchoring or checking match spans would change alternation
// behavior; Envoy ignores `case_sensitive` for regex matches (S1.3).

/// One inbound request's routing-relevant data. Borrowed for the lifetime of
/// the call — this module never clones or owns request data.
pub struct RouteRequest<'a> {
    /// The `:authority` (or `Host`) header value, port included if present.
    pub authority: &'a str,
    /// `:path`, including any query string.
    pub path: &'a str,
    pub headers: &'a http::HeaderMap,
}

/// Result of [`match_route`].
///
/// Rust note: the `'t` lifetime ties every borrow here to the `RouteTable`
/// passed in, so the compiler enforces that a `RouteMatch` can never outlive
/// the config snapshot it came from — no cloning of `Arc<VirtualHostIR>` or
/// `Arc<RouteEntry>` needed just to hand a result back to the caller.
pub enum RouteMatch<'t> {
    Found {
        vhost: &'t VirtualHostIR,
        // Keep the Arc borrow so callers can cheaply clone a route into the
        // filter manager's stream-lifetime cache.
        route: &'t Arc<RouteEntry>,
    },
    /// A virtual host matched but no route did -> 404, response flag `NR`.
    NoRoute { vhost: &'t VirtualHostIR },
    /// No virtual host matched -> 404, response flag `NR`.
    NoVirtualHost,
}

/// S1.1 + S1.2 + S1.3 + S1.4: select a virtual host by `:authority` (port
/// stripped), then linear-scan its routes for the first full match.
pub fn match_route<'t>(table: &'t RouteTable, req: &RouteRequest<'_>) -> RouteMatch<'t> {
    let host = strip_port(req.authority);
    // Rust note: `find_virtual_host` returns `&Arc<VirtualHostIR>`; `&**` (or
    // `.as_ref()`/deref coercion via `&*`) peels the `Arc` down to a plain
    // `&VirtualHostIR` with the same `'t` lifetime — the `Arc`'s refcount
    // isn't touched, we're just borrowing through it.
    let Some(vhost) = table.find_virtual_host(host).map(|arc| arc.as_ref()) else {
        return RouteMatch::NoVirtualHost;
    };

    let path_no_query = strip_query(req.path);
    for route in &vhost.routes {
        if matcher_matches(&route.matcher, req.path, path_no_query, req.headers) {
            return RouteMatch::Found { vhost, route };
        }
    }
    RouteMatch::NoRoute { vhost }
}

/// S1.3: does this route's path + header matchers match the request?
/// `path_with_query` is `:path` unaltered; `path_no_query` has the query
/// string stripped (S1.3: `prefix` matches with-query, `exact`/`regex`
/// match without).
fn matcher_matches(
    matcher: &RouteMatcher,
    path_with_query: &str,
    path_no_query: &str,
    headers: &http::HeaderMap,
) -> bool {
    let path_matches = match &matcher.path {
        PathMatch::Prefix(_) => matcher
            .path
            .matches(path_with_query, matcher.case_sensitive),
        PathMatch::Exact(_) => matcher.path.matches(path_no_query, matcher.case_sensitive),
        // Already whole-string anchored at config compile time (see the note
        // above); `case_sensitive` is ignored for regexes, as in Envoy.
        PathMatch::Regex(_) => matcher.path.matches(path_no_query, matcher.case_sensitive),
    };
    if !path_matches {
        return false;
    }
    matcher.headers.iter().all(|hm| header_matches(hm, headers))
}

/// S1.4: match one `HeaderMatch` against a (possibly multi-valued) request
/// header. Envoy semantics: a header matcher is satisfied if ANY value of
/// that header satisfies it (documented here since `ir.rs` doesn't encode
/// this choice); `Present(true)`/`Present(false)` only look at whether the
/// header exists at all, ignoring values.
fn header_matches(hm: &HeaderMatch, headers: &http::HeaderMap) -> bool {
    if let HeaderMatchKind::Present(want_present) = &hm.kind {
        return headers.contains_key(hm.name.as_str()) == *want_present;
    }
    // Rust note: `get_all` returns an iterator over every value for a
    // (possibly repeated) header name; we short-circuit on the first value
    // that satisfies the matcher.
    headers.get_all(hm.name.as_str()).iter().any(|v| {
        // Envoy matches the value's bytes. A UTF-8 value matches as text;
        // `HeaderValue::to_str` would refuse every byte above 0x7E, so a
        // model such as `aéb` (which the model filter does publish) could
        // never match its route and fell through to the next one. Non-UTF-8
        // values still match nothing rather than panicking.
        let Ok(v) = std::str::from_utf8(v.as_bytes()) else {
            return false;
        };
        header_kind_matches(&hm.kind, v)
    })
}

fn header_kind_matches(kind: &HeaderMatchKind, value: &str) -> bool {
    match kind {
        HeaderMatchKind::Exact {
            value: want,
            ignore_case,
        } => {
            if *ignore_case {
                value.eq_ignore_ascii_case(want)
            } else {
                value == want
            }
        }
        HeaderMatchKind::Prefix {
            value: want,
            ignore_case,
        } => {
            if *ignore_case {
                value.len() >= want.len()
                    && value.is_char_boundary(want.len())
                    && value[..want.len()].eq_ignore_ascii_case(want)
            } else {
                value.starts_with(want.as_str())
            }
        }
        HeaderMatchKind::Suffix {
            value: want,
            ignore_case,
        } => {
            if *ignore_case {
                value.len() >= want.len()
                    && value.is_char_boundary(value.len() - want.len())
                    && value[value.len() - want.len()..].eq_ignore_ascii_case(want)
            } else {
                value.ends_with(want.as_str())
            }
        }
        // Anchored at config compile time, as above.
        HeaderMatchKind::Regex(re) => re.is_match(value),
        HeaderMatchKind::Present(_) => unreachable!("handled by header_matches"),
    }
}

/// S1.5: resolve a route's forward target to a concrete cluster name.
/// `draw` must be uniform in `[0, total_weight)`; the caller draws once per
/// request and reuses the same draw across retries (S1.5: cluster selection
/// is stable across retries) — this function takes no randomness itself.
///
/// `ClusterHeader`: reads the named request header. Missing, empty, or
/// non-UTF-8 -> `None` (the router turns that into 503 `NC`).
///
/// Rust note: `headers` shares the `'t` lifetime with `target` rather than
/// having its own. References are covariant in their lifetime, so callers
/// may still pass a `&HeaderMap` that lives shorter than the route table —
/// the compiler just picks `'t` to be the shorter of the two at each call
/// site. The alternative (giving `headers` an independent lifetime) doesn't
/// type-check: the `ClusterHeader` arm returns a slice of `headers`, so the
/// return type must be tied to whichever input it actually borrows from.
pub fn select_cluster<'t>(
    target: &'t ForwardTarget,
    headers: &'t http::HeaderMap,
    draw: u64,
) -> Option<&'t str> {
    match target {
        ForwardTarget::Cluster(name) => Some(name.as_str()),
        ForwardTarget::ClusterHeader(header_name) => {
            let value = headers.get(header_name.as_str())?;
            let value = value.to_str().ok()?;
            if value.is_empty() {
                None
            } else {
                Some(value)
            }
        }
        ForwardTarget::Weighted(weighted) => Some(weighted.pick(draw).as_str()),
    }
}

/// The authenticated identity a route hash policy may read (ADR-0016
/// decision 5): the values the authentication filter left on `AuthInfo`.
#[derive(Debug, Default, Clone, Copy)]
pub struct HashIdentity<'a> {
    pub key_id: Option<&'a str>,
    pub user_id: Option<&'a str>,
    pub tenant: Option<&'a str>,
}

/// Envoy `HashPolicyImpl::generateHash` (ADR-0016 decision 1). Each entry
/// that yields a value is folded in as `rotl(hash, 1) ^ value`, starting from
/// 0; a terminal entry stops the walk once a hash exists; no value from any
/// entry means no hash.
pub fn generate_hash(
    policy: &[RouteHashPolicy],
    headers: &http::HeaderMap,
    identity: &HashIdentity<'_>,
) -> Option<u64> {
    let mut hash: Option<u64> = None;
    for entry in policy {
        let value = match &entry.source {
            HashSource::Header(name) => header_hash(headers, name),
            HashSource::AuthKeyId => identity.key_id.map(|v| xxh64(v.as_bytes(), 0)),
            HashSource::AuthUserId => identity.user_id.map(|v| xxh64(v.as_bytes(), 0)),
            HashSource::AuthTenant => identity.tenant.map(|v| xxh64(v.as_bytes(), 0)),
        };
        if let Some(value) = value {
            hash = Some(hash.map_or(0, |h| h.rotate_left(1)) ^ value);
        }
        if entry.terminal && hash.is_some() {
            break;
        }
    }
    hash
}

/// Envoy `HeaderHashMethod`: no header, no value; otherwise xxHash64 (seed 0)
/// of every value, sorted and concatenated, so the order a client repeats
/// the header in does not matter. An empty value is hashed.
fn header_hash(headers: &http::HeaderMap, name: &http::HeaderName) -> Option<u64> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    let Some(second) = values.next() else {
        return Some(xxh64(first.as_bytes(), 0));
    };
    let mut all: Vec<&[u8]> = vec![first.as_bytes(), second.as_bytes()];
    all.extend(values.map(|v| v.as_bytes()));
    all.sort_unstable();
    let mut state = Xxh64::new(0);
    for value in all {
        state.update(value);
    }
    Some(state.digest())
}

/// How a weighted draw was made, for the router's affinity counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawSource {
    /// The target has no hash policy: today's random draw.
    Random,
    /// The hash policy yielded a hash.
    Hashed,
    /// A hash policy is configured but yielded nothing, so the draw is random
    /// (Envoy falls back the same way).
    Unhashed,
}

/// S1.5 with ADR-0016: the draw for a weighted target, in
/// `[0, total_weight)`. The hash, when there is one, replaces the random
/// value before the same modulo, as Envoy's `pickWeightedCluster` does.
/// `random` is called only when no hash is used.
pub fn weighted_draw(
    weighted: &WeightedClusters,
    headers: &http::HeaderMap,
    identity: &HashIdentity<'_>,
    random: impl FnOnce() -> u64,
) -> (u64, DrawSource) {
    let total = weighted.total_weight.max(1);
    if weighted.hash_policy.is_empty() {
        return (random() % total, DrawSource::Random);
    }
    match generate_hash(&weighted.hash_policy, headers, identity) {
        Some(hash) => (hash % total, DrawSource::Hashed),
        None => (random() % total, DrawSource::Unhashed),
    }
}

/// S1.3: strip the query string (and the `?` itself) from a `:path`. Returns
/// the whole string unchanged if there's no `?`.
///
/// Rust note: `split_once` on `str` operates on byte offsets that `?` (a
/// single-byte ASCII char) always produces at a UTF-8 char boundary, so
/// slicing here can never panic on a multi-byte path.
pub fn strip_query(path: &str) -> &str {
    match path.split_once('?') {
        Some((before, _)) => before,
        None => path,
    }
}

/// S1.1: strip a trailing `:port` from an `:authority`/`Host` value, per
/// Envoy's `strip_matching_host_port`. Only strips when everything after the
/// last `:` is all-ASCII-digit AND there's no unmatched `[` before it — a
/// bracketed IPv6 literal with a port (`[::1]:8080`) has its closing `]`
/// right before that last `:`, so `[` and `]` counts balance and stripping
/// proceeds, leaving `[::1]`. A bare IPv6 literal with no port (`[::1]`) has
/// no digits after any `:`, so the digit check alone already excludes it.
///
/// Rust note: `rfind` searches from the end and returns a byte index, which
/// is always a valid char boundary for finding a single-byte ASCII `:`.
pub fn strip_port(authority: &str) -> &str {
    let Some(colon) = authority.rfind(':') else {
        return authority;
    };
    let port_candidate = &authority[colon + 1..];
    if port_candidate.is_empty() || !port_candidate.bytes().all(|b| b.is_ascii_digit()) {
        return authority;
    }
    let before = &authority[..colon];
    let opens = before.matches('[').count();
    let closes = before.matches(']').count();
    if opens != closes {
        return authority;
    }
    before
}

/// Replace the matched prefix with `rewrite`, preserving the remainder of
/// the path and the query string (used by the router for `prefix_rewrite`).
/// Only meaningful when the route's matcher is `Prefix` or `Exact`; `None`
/// for `Regex` matchers, which have no fixed prefix to replace.
pub fn apply_prefix_rewrite(matcher: &RouteMatcher, rewrite: &str, path: &str) -> Option<String> {
    match &matcher.path {
        PathMatch::Prefix(p) => {
            // Prefix matching (case-insensitively, if configured) was against
            // the whole path including query, so the prefix is stripped from
            // the full path here too.
            if path.len() < p.len() || !path.is_char_boundary(p.len()) {
                return None;
            }
            let matches_prefix = if matcher.case_sensitive {
                path.starts_with(p.as_str())
            } else {
                path[..p.len()].eq_ignore_ascii_case(p)
            };
            if !matches_prefix {
                return None;
            }
            let mut out = String::with_capacity(rewrite.len() + path.len() - p.len());
            out.push_str(rewrite);
            out.push_str(&path[p.len()..]);
            Some(out)
        }
        PathMatch::Exact(e) => {
            // Exact matching was done with the query stripped; splice the
            // rewrite in for the path portion only, then reattach the query.
            let path_no_query = strip_query(path);
            let matches_exact = if matcher.case_sensitive {
                path_no_query == e
            } else {
                path_no_query.eq_ignore_ascii_case(e)
            };
            if !matches_exact {
                return None;
            }
            let query = &path[path_no_query.len()..];
            let mut out = String::with_capacity(rewrite.len() + query.len());
            out.push_str(rewrite);
            out.push_str(query);
            Some(out)
        }
        PathMatch::Regex(_) => None,
    }
}

#[cfg(test)]
#[path = "route/tests.rs"]
mod tests;
