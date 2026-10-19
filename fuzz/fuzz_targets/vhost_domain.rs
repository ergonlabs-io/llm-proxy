//! Virtual-host domain wildcard matching (`proxy-config` `RouteTable`, S1.1)
//! and the `:authority` port strip in front of it (`proxy-http` `route.rs`).
//! The client controls the `Host` header, and the selected virtual host picks
//! every route, filter config and credential that follows.
//!
//! Input: the first line is the request `:authority`; each further line is
//! one virtual host, its domains separated by `,`.
//!
//! Properties checked beyond "never panic":
//! - the selected virtual host is the one a brute-force reading of S1.1
//!   precedence picks: exact, then the longest `*suffix`, then the longest
//!   `prefix*`, then `*`, ties in config order, case-insensitive, and a
//!   wildcard never matches an empty run;
//! - the port strip returns a prefix of the authority and removes only a
//!   `:digits` tail.
#![no_main]

use std::collections::BTreeMap;

use libfuzzer_sys::fuzz_target;
use proxy_config::ir::{RouteTable, VirtualHostIR};
use proxy_http::route::{match_route, strip_port, RouteMatch, RouteRequest};

/// Index of the virtual host S1.1 selects for `host`, by scanning every
/// domain of every host for each precedence class in turn.
fn reference(vhosts: &[Vec<String>], host: &str) -> Option<usize> {
    let host = host.to_ascii_lowercase();
    let domains = || {
        vhosts
            .iter()
            .enumerate()
            .flat_map(|(i, ds)| ds.iter().map(move |d| (i, d.to_ascii_lowercase())))
    };
    // A domain with a leading or trailing `*` is a wildcard, never exact.
    let wildcard = |d: &str| d.starts_with('*') || d.ends_with('*');
    if let Some((i, _)) = domains().find(|(_, d)| !wildcard(d) && *d == host) {
        return Some(i);
    }
    // Longest wildcard first; `max_by_key` keeps the LAST maximum, so scan
    // in reverse to keep the first one in config order.
    let longest = |class: &dyn Fn(&str) -> Option<usize>| {
        let all: Vec<(usize, usize)> = domains()
            .filter(|(_, d)| d != "*")
            .filter_map(|(i, d)| class(&d).map(|len| (i, len)))
            .collect();
        all.into_iter()
            .rev()
            .max_by_key(|&(_, len)| len)
            .map(|(i, _)| i)
    };
    let suffix = |d: &str| {
        let s = d.strip_prefix('*')?;
        (host.len() > s.len() && host.ends_with(s)).then_some(s.len())
    };
    if let Some(i) = longest(&suffix) {
        return Some(i);
    }
    let prefix = |d: &str| {
        // A leading `*` already made this a suffix domain.
        if d.starts_with('*') {
            return None;
        }
        let p = d.strip_suffix('*')?;
        (host.len() > p.len() && host.starts_with(p)).then_some(p.len())
    };
    if let Some(i) = longest(&prefix) {
        return Some(i);
    }
    domains().find(|(_, d)| d == "*").map(|(i, _)| i)
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.split('\n');
    let authority = lines.next().unwrap_or_default();
    let vhosts: Vec<Vec<String>> = lines
        .take(32)
        .map(|line| line.split(',').map(str::to_string).collect())
        .collect();

    let stripped = strip_port(authority);
    assert!(authority.starts_with(stripped));
    if stripped.len() != authority.len() {
        let tail = &authority[stripped.len()..];
        assert!(
            tail.len() > 1
                && tail.starts_with(':')
                && tail[1..].bytes().all(|b| b.is_ascii_digit()),
            "strip_port removed {tail:?} from {authority:?}"
        );
    }

    let irs = vhosts
        .iter()
        .enumerate()
        .map(|(i, domains)| VirtualHostIR {
            name: format!("vh{i}"),
            domains: domains.clone(),
            routes: Vec::new(),
            typed_per_filter_config: BTreeMap::new(),
        })
        .collect();
    // Duplicate domains are a config error, not a lookup case.
    let Ok(table) = RouteTable::new("fuzz".to_string(), irs, BTreeMap::new()) else {
        return;
    };

    let selected = table.find_virtual_host(stripped).map(|vh| vh.name.clone());
    let expected = reference(&vhosts, stripped).map(|i| format!("vh{i}"));
    assert_eq!(selected, expected, "host {stripped:?} over {vhosts:?}");

    let headers = http::HeaderMap::new();
    let request = RouteRequest {
        authority,
        path: "/",
        headers: &headers,
    };
    let via_route = match match_route(&table, &request) {
        RouteMatch::Found { vhost, .. } | RouteMatch::NoRoute { vhost } => Some(vhost.name.clone()),
        RouteMatch::NoVirtualHost => None,
    };
    assert_eq!(
        via_route, expected,
        "match_route picked another virtual host"
    );
});
