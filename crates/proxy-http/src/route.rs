//! S1 route matching engine (WP-12): pure, synchronous, allocation-light
//! selection of virtual host -> route -> cluster on top of the pre-compiled
//! IR in `proxy_config::ir`. No async, no I/O — this module only reads data
//! the caller hands it.
//!
//! TODO(WP-12 follow-up): the IR (`proxy_config::ir`) does not yet model the
//! following S1 features, so they are unimplemented here for lack of a place
//! to store the compiled matcher. The orchestrator will extend the IR
//! separately:
//! - `path_separated_prefix` path specifier (S1.3): match `p` exactly or
//!   `p/`-prefixed. `RouteMatcher`/`PathMatch` has no variant for it.
//! - `query_parameters` route-level matching (S1.4): `RouteMatcher` has no
//!   field for query-parameter matchers.
//! - Header `range` and `contains` matchers, and `invert_match` on any header
//!   matcher (S1.4): `HeaderMatchKind` has no `Range`/`Contains` variants and
//!   no per-matcher invert flag.
//! - `runtime_fraction`-gated route matching (S1.4): `RouteEntry` has no
//!   runtime-fraction field, so a route can't be probabilistically skipped
//!   before the rest of its matcher is evaluated.
//! - `grpc` route-match flag (S1.4): no field on `RouteMatcher`.
//! - `metadata_match` merge between route- and weighted-cluster-level
//!   overrides (S1.5): `WeightedClusters`/`ForwardTarget` carry no metadata.

use proxy_config::ir::{
    ForwardTarget, HeaderMatch, HeaderMatchKind, PathMatch, RouteEntry, RouteMatcher, RouteTable,
    VirtualHostIR,
};

// S1.3 note on regex anchoring — **do not re-anchor here.** Envoy's
// `safe_regex` is a FULL match, and that is already enforced at *config
// compile time*: `proxy-config`'s `lower.rs::compile_regex` wraps every
// pattern as `^(?:{pattern})$` before handing it to `regex::Regex::new`, and
// all three `Regex` sites in the IR (path `safe_regex`, header `safe_regex`,
// and `StringMatcherIR::SafeRegex`) go through it. So `is_match` on an IR
// regex is already a whole-string test, and matching here is just a call to
// the IR's own helpers.
//
// Anchoring a second time at each call site would be redundant, and doing it
// by inspecting `find()`'s match span would actually be *wrong* on an
// unanchored pattern: `regex` returns the leftmost-first match, so an
// alternation like `/foo|/foobar` against `/foobar` yields the 4-byte `/foo`
// and a span check would reject it, even though the pattern does match the
// whole string. Compile-time anchoring has no such failure mode.
//
// `case_sensitive` is never applied to regexes (S1.3) — which holds here for
// free, since this module never case-folds a regex input.

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
        route: &'t RouteEntry,
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
        // Non-UTF-8 header values can never match a string/regex matcher;
        // treat them as simply not matching rather than panicking.
        let Ok(v) = v.to_str() else {
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
/// non-UTF-8 -> `None` (the router turns that into 503 `NC`, per WP-13).
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
/// the path and the query string (used by WP-13 for `prefix_rewrite`).
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
