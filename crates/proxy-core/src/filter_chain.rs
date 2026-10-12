//! Pure filter-chain matching algorithm. Given a listener's
//! `filter_chains` and the properties of an accepted connection, picks the one
//! Envoy's `FilterChainManager` would pick. No sockets, no async — this module
//! is a function of its inputs, which is what makes it property-testable.

use std::net::{IpAddr, SocketAddr};

use proxy_config::ir::{CidrRange, FilterChainSpec, ListenerConfig, SourceType};

/// Properties of an accepted connection that filter-chain matching consumes.
pub struct ConnectionProperties {
    /// Local address of the accepted socket.
    pub destination_addr: SocketAddr,
    /// Downstream source; equals `direct_source_addr` until `proxy_protocol`
    /// rewrites it from the PROXY header.
    pub source_addr: SocketAddr,
    /// The physically connected peer (never rewritten by `proxy_protocol`).
    pub direct_source_addr: SocketAddr,
    /// SNI, populated by the `tls_inspector` listener filter; `None`
    /// until then.
    pub server_name: Option<String>,
    /// e.g. "raw_buffer" or "tls"; "raw_buffer" until `tls_inspector` lands.
    pub transport_protocol: String,
    /// ALPN, populated by `tls_inspector`; empty until then.
    pub application_protocols: Vec<String>,
}

/// Select the filter chain Envoy's `FilterChainManager` would select for
/// `props` on `listener`, or `None` if there's no match and no default
/// (caller must close the connection — matches Envoy's `filter_chain_match`
/// miss behavior).
pub fn select_filter_chain<'a>(
    props: &ConnectionProperties,
    listener: &'a ListenerConfig,
) -> Option<&'a FilterChainSpec> {
    // Rust note: `Vec<&FilterChainSpec>` of survivors, narrowed step by step.
    // Starting from indices into `listener.filter_chains` would also work, but
    // references read more directly against the spec's "partition and keep"
    // language.
    let mut survivors: Vec<&FilterChainSpec> = listener.filter_chains.iter().collect();

    // 1. destination_port.
    survivors = narrow_by_option(survivors, |c| c.match_criteria.destination_port, &|p| {
        *p == u32::from(props.destination_addr.port())
    });

    // 2. prefix_ranges (destination IP), longest-prefix wins.
    survivors = narrow_by_longest_cidr(survivors, props.destination_addr.ip(), |c| {
        &c.match_criteria.prefix_ranges
    });

    // 3. server_names (SNI).
    survivors = narrow_by_server_name(survivors, props.server_name.as_deref());

    // 4. transport_protocol.
    survivors = narrow_by_option(
        survivors,
        |c| c.match_criteria.transport_protocol.clone(),
        &|tp| *tp == props.transport_protocol,
    );

    // 5. application_protocols (ALPN).
    survivors = narrow_by_list_intersection(survivors, &props.application_protocols, |c| {
        &c.match_criteria.application_protocols
    });

    // 6. direct_source_prefix_ranges, longest-prefix wins.
    survivors = narrow_by_longest_cidr(survivors, props.direct_source_addr.ip(), |c| {
        &c.match_criteria.direct_source_prefix_ranges
    });

    // 7. source_type.
    let classification = if props.source_addr.ip().is_loopback()
        || props.source_addr.ip() == props.destination_addr.ip()
    {
        SourceType::SameIpOrLoopback
    } else {
        SourceType::External
    };
    survivors = narrow_by_source_type(survivors, classification);

    // 8. source_prefix_ranges, longest-prefix wins.
    survivors = narrow_by_longest_cidr(survivors, props.source_addr.ip(), |c| {
        &c.match_criteria.source_prefix_ranges
    });

    // 9. source_ports.
    survivors = narrow_by_list_membership(survivors, u32::from(props.source_addr.port()), |c| {
        &c.match_criteria.source_ports
    });

    match survivors.len() {
        1 => Some(survivors[0]),
        0 => listener.default_filter_chain.as_ref(),
        _ => {
            // Unreachable by construction: proxy-config rejects any listener
            // whose filter chains have overlapping/duplicate match criteria
            // (Envoy's `DuplicateMatchException`), so at most one chain can
            // survive all 9 criteria. We keep this arm total (never panic on
            // the hot path) and pick the first in definition order, as Envoy's
            // own fallback ordering does.
            tracing::warn!(
                count = survivors.len(),
                "multiple filter chains matched a connection; this should be \
                 impossible for configs that passed validation — picking the \
                 first in definition order"
            );
            Some(survivors[0])
        }
    }
}

/// Steps 1 and 4: a chain with `Some(specific)` survives only on exact match;
/// if any specific chain survives, wildcard (`None`) chains are eliminated,
/// otherwise the wildcard chains are what's kept.
fn narrow_by_option<'a, T>(
    survivors: Vec<&'a FilterChainSpec>,
    get: impl Fn(&FilterChainSpec) -> Option<T>,
    matches: &impl Fn(&T) -> bool,
) -> Vec<&'a FilterChainSpec> {
    let mut specific = Vec::new();
    let mut wildcard = Vec::new();
    for chain in survivors {
        match get(chain) {
            Some(v) if matches(&v) => specific.push(chain),
            Some(_) => {} // eliminated: specific but non-matching
            None => wildcard.push(chain),
        }
    }
    if !specific.is_empty() {
        specific
    } else {
        wildcard
    }
}

/// Steps 2, 6, 8: keep chains whose longest containing-CIDR `prefix_len` is
/// among the survivors, tied for the maximum; chains with ranges that don't
/// contain `ip` are eliminated outright, and if no chain has a containing
/// range, fall back to the wildcard (empty-ranges) chains.
fn narrow_by_longest_cidr(
    survivors: Vec<&FilterChainSpec>,
    ip: IpAddr,
    ranges: impl Fn(&FilterChainSpec) -> &Vec<CidrRange>,
) -> Vec<&FilterChainSpec> {
    let mut best: Option<u8> = None;
    // Rust note: `Containing(len)` is a real match with that prefix length;
    // `Wildcard` is an empty-ranges chain (matches everything); a chain with
    // non-empty ranges none of which contain `ip` is dropped on the spot and
    // never makes it into `scored` at all — that's what step 2 means by
    // "eliminated", distinct from the wildcard fallback.
    enum Score {
        Containing(u8),
        Wildcard,
    }
    let mut scored: Vec<(&FilterChainSpec, Score)> = Vec::new();
    for chain in survivors {
        let rs = ranges(chain);
        if rs.is_empty() {
            scored.push((chain, Score::Wildcard));
            continue;
        }
        let longest = rs
            .iter()
            .filter(|r| r.contains(ip))
            .map(|r| r.prefix_len)
            .max();
        if let Some(len) = longest {
            best = Some(best.map_or(len, |b| b.max(len)));
            scored.push((chain, Score::Containing(len)));
        } // else: non-empty ranges, none containing `ip` — eliminated
    }
    match best {
        Some(max_len) => scored
            .into_iter()
            .filter_map(|(chain, score)| match score {
                Score::Containing(len) if len == max_len => Some(chain),
                _ => None,
            })
            .collect(),
        None => scored
            .into_iter()
            .filter_map(|(chain, score)| match score {
                Score::Wildcard => Some(chain),
                _ => None,
            })
            .collect(),
    }
}

/// Step 3: SNI matching. Exact beats longest-suffix-wildcard beats empty.
fn narrow_by_server_name<'a>(
    survivors: Vec<&'a FilterChainSpec>,
    server_name: Option<&str>,
) -> Vec<&'a FilterChainSpec> {
    let Some(sni) = server_name else {
        // No SNI: only chains with no configured server_names can match.
        return survivors
            .into_iter()
            .filter(|c| c.match_criteria.server_names.is_empty())
            .collect();
    };
    let sni_lower = sni.to_ascii_lowercase();

    // (a) exact match, case-insensitive.
    let exact: Vec<&FilterChainSpec> = survivors
        .iter()
        .filter(|c| {
            c.match_criteria
                .server_names
                .iter()
                .any(|n| n.eq_ignore_ascii_case(&sni_lower))
        })
        .copied()
        .collect();
    if !exact.is_empty() {
        return exact;
    }

    // (b) wildcard `*.suffix`: sni must end with ".suffix" and have at least
    // one label before it. Keep the longest matching suffix.
    let mut best_len: Option<usize> = None;
    let mut scored: Vec<(&FilterChainSpec, Option<usize>)> = Vec::new();
    for chain in &survivors {
        let longest = chain
            .match_criteria
            .server_names
            .iter()
            .filter_map(|n| n.strip_prefix('*'))
            .filter(|suffix| {
                // proxy-config validation only admits the `*.suffix` form, so
                // the stripped entry always starts with '.'. Lowercase it for
                // the comparison — the SNI side is already lowered, and both
                // sides of the match must be case-insensitive.
                let dotted = suffix.to_ascii_lowercase();
                sni_lower.len() > dotted.len() && sni_lower.ends_with(dotted.as_str())
            })
            .map(str::len)
            .max();
        if let Some(len) = longest {
            best_len = Some(best_len.map_or(len, |b| b.max(len)));
        }
        scored.push((chain, longest));
    }
    if let Some(max_len) = best_len {
        return scored
            .into_iter()
            .filter_map(|(chain, len)| (len == Some(max_len)).then_some(chain))
            .collect();
    }

    // (c) fall back to chains with no configured server_names.
    survivors
        .into_iter()
        .filter(|c| c.match_criteria.server_names.is_empty())
        .collect()
}

/// Step 5: ALPN. A chain with a non-empty list survives only if it intersects
/// `offered`; intersecting chains beat empty-list (wildcard) chains.
fn narrow_by_list_intersection<'a>(
    survivors: Vec<&'a FilterChainSpec>,
    offered: &[String],
    get: impl Fn(&FilterChainSpec) -> &Vec<String>,
) -> Vec<&'a FilterChainSpec> {
    let mut specific = Vec::new();
    let mut wildcard = Vec::new();
    for chain in survivors {
        let list = get(chain);
        if list.is_empty() {
            wildcard.push(chain);
        } else if list.iter().any(|p| offered.contains(p)) {
            specific.push(chain);
        } // else eliminated: specific but no intersection
    }
    if !specific.is_empty() {
        specific
    } else {
        wildcard
    }
}

/// Step 9 (also usable for any "list of exact values" criterion): a chain
/// with a non-empty list survives only if it contains `value`; specific beats
/// empty-list (wildcard) chains.
fn narrow_by_list_membership(
    survivors: Vec<&FilterChainSpec>,
    value: u32,
    get: impl Fn(&FilterChainSpec) -> &Vec<u32>,
) -> Vec<&FilterChainSpec> {
    let mut specific = Vec::new();
    let mut wildcard = Vec::new();
    for chain in survivors {
        let list = get(chain);
        if list.is_empty() {
            wildcard.push(chain);
        } else if list.contains(&value) {
            specific.push(chain);
        }
    }
    if !specific.is_empty() {
        specific
    } else {
        wildcard
    }
}

/// Step 7: source type. `Any` is the wildcard; exact classification match
/// beats it.
fn narrow_by_source_type(
    survivors: Vec<&FilterChainSpec>,
    classification: SourceType,
) -> Vec<&FilterChainSpec> {
    let mut specific = Vec::new();
    let mut wildcard = Vec::new();
    for chain in survivors {
        match chain.match_criteria.source_type {
            SourceType::Any => wildcard.push(chain),
            st if st == classification => specific.push(chain),
            _ => {} // eliminated: specific but wrong classification
        }
    }
    if !specific.is_empty() {
        specific
    } else {
        wildcard
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proxy_config::ir::{FilterChainMatch, FilterChainSpec};
    use std::net::Ipv4Addr;

    fn addr(ip: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), port)
    }

    fn base_props() -> ConnectionProperties {
        let a = addr("10.0.0.1", 8080);
        ConnectionProperties {
            destination_addr: a,
            source_addr: addr("192.168.1.1", 50000),
            direct_source_addr: addr("192.168.1.1", 50000),
            server_name: None,
            transport_protocol: "raw_buffer".to_string(),
            application_protocols: vec![],
        }
    }

    fn chain(name: &str, m: FilterChainMatch) -> FilterChainSpec {
        FilterChainSpec {
            name: Some(name.to_string()),
            match_criteria: m,
            transport_socket: None,
            filters: vec![],
        }
    }

    fn listener(chains: Vec<FilterChainSpec>, default: Option<FilterChainSpec>) -> ListenerConfig {
        ListenerConfig {
            name: "l".to_string(),
            address: addr("0.0.0.0", 8080),
            filter_chains: chains,
            default_filter_chain: default,
            listener_filters: vec![],
            per_connection_buffer_limit_bytes: 1024 * 1024,
            tcp_backlog_size: None,
            bind_to_port: true,
            ignore_global_conn_limit: false,
        }
    }

    fn cidr(s: &str, prefix_len: u8) -> CidrRange {
        CidrRange {
            addr: s.parse().unwrap(),
            prefix_len,
        }
    }

    fn name_of(spec: Option<&FilterChainSpec>) -> Option<&str> {
        spec.and_then(|c| c.name.as_deref())
    }

    // --- naive oracle for the property test -------------------------------

    /// Independently re-checks every one of the 9 criteria against `props`.
    /// This is intentionally written differently from `select_filter_chain`'s
    /// narrowing (no "most specific wins" logic — just "does this chain's
    /// match_criteria admit this connection at all") so it can catch bugs in
    /// the narrowing implementation.
    fn chain_matches(props: &ConnectionProperties, m: &FilterChainMatch) -> bool {
        if let Some(p) = m.destination_port {
            if p != u32::from(props.destination_addr.port()) {
                return false;
            }
        }
        if !m.prefix_ranges.is_empty()
            && !m
                .prefix_ranges
                .iter()
                .any(|r| r.contains(props.destination_addr.ip()))
        {
            return false;
        }
        if !m.server_names.is_empty() {
            match &props.server_name {
                None => return false,
                Some(sni) => {
                    let sni_lower = sni.to_ascii_lowercase();
                    let ok = m.server_names.iter().any(|n| {
                        if let Some(rest) = n.strip_prefix('*') {
                            let dotted = if rest.starts_with('.') {
                                rest.to_string()
                            } else {
                                format!(".{rest}")
                            };
                            sni_lower.len() > dotted.len() && sni_lower.ends_with(dotted.as_str())
                        } else {
                            n.eq_ignore_ascii_case(&sni_lower)
                        }
                    });
                    if !ok {
                        return false;
                    }
                }
            }
        }
        if let Some(tp) = &m.transport_protocol {
            if *tp != props.transport_protocol {
                return false;
            }
        }
        if !m.application_protocols.is_empty()
            && !m
                .application_protocols
                .iter()
                .any(|p| props.application_protocols.contains(p))
        {
            return false;
        }
        if !m.direct_source_prefix_ranges.is_empty()
            && !m
                .direct_source_prefix_ranges
                .iter()
                .any(|r| r.contains(props.direct_source_addr.ip()))
        {
            return false;
        }
        let classification = if props.source_addr.ip().is_loopback()
            || props.source_addr.ip() == props.destination_addr.ip()
        {
            SourceType::SameIpOrLoopback
        } else {
            SourceType::External
        };
        match m.source_type {
            SourceType::Any => {}
            st if st == classification => {}
            _ => return false,
        }
        if !m.source_prefix_ranges.is_empty()
            && !m
                .source_prefix_ranges
                .iter()
                .any(|r| r.contains(props.source_addr.ip()))
        {
            return false;
        }
        if !m.source_ports.is_empty()
            && !m
                .source_ports
                .contains(&u32::from(props.source_addr.port()))
        {
            return false;
        }
        true
    }

    // --- per-criterion: specific beats wildcard, mismatched-specific loses --

    #[test]
    fn destination_port_specific_beats_wildcard() {
        let props = base_props();
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "specific",
                    FilterChainMatch {
                        destination_port: Some(8080),
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("specific"));
    }

    #[test]
    fn destination_port_mismatch_eliminated_even_with_wildcard() {
        let props = base_props();
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "wrong",
                    FilterChainMatch {
                        destination_port: Some(9999),
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("wild"));
    }

    #[test]
    fn dest_ip_longest_prefix_beats_wildcard_and_shorter() {
        let props = base_props(); // dest ip 10.0.0.1
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "short",
                    FilterChainMatch {
                        prefix_ranges: vec![cidr("10.0.0.0", 8)],
                        ..Default::default()
                    },
                ),
                chain(
                    "long",
                    FilterChainMatch {
                        prefix_ranges: vec![cidr("10.0.0.0", 24)],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("long"));
    }

    #[test]
    fn dest_ip_non_containing_range_eliminated() {
        let props = base_props();
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "wrong",
                    FilterChainMatch {
                        prefix_ranges: vec![cidr("192.168.0.0", 16)],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("wild"));
    }

    #[test]
    fn sni_exact_beats_wildcard() {
        let mut props = base_props();
        props.server_name = Some("api.example.com".to_string());
        let l = listener(
            vec![
                chain(
                    "wild",
                    FilterChainMatch {
                        server_names: vec!["*.example.com".to_string()],
                        ..Default::default()
                    },
                ),
                chain(
                    "exact",
                    FilterChainMatch {
                        server_names: vec!["api.example.com".to_string()],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("exact"));
    }

    #[test]
    fn sni_mismatched_exact_eliminated_even_with_wildcard() {
        let mut props = base_props();
        props.server_name = Some("api.example.com".to_string());
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "wrong",
                    FilterChainMatch {
                        server_names: vec!["other.example.com".to_string()],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("wild"));
    }

    #[test]
    fn transport_protocol_specific_beats_wildcard_and_mismatch_eliminated() {
        let props = base_props();
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "tls",
                    FilterChainMatch {
                        transport_protocol: Some("tls".to_string()),
                        ..Default::default()
                    },
                ),
                chain(
                    "raw",
                    FilterChainMatch {
                        transport_protocol: Some("raw_buffer".to_string()),
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("raw"));
    }

    #[test]
    fn alpn_intersection_beats_wildcard_and_no_intersection_eliminated() {
        let mut props = base_props();
        props.application_protocols = vec!["h2".to_string()];
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "http1",
                    FilterChainMatch {
                        application_protocols: vec!["http/1.1".to_string()],
                        ..Default::default()
                    },
                ),
                chain(
                    "h2",
                    FilterChainMatch {
                        application_protocols: vec!["h2".to_string()],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("h2"));
    }

    #[test]
    fn direct_source_prefix_longest_wins() {
        let props = base_props(); // direct_source_addr 192.168.1.1
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "short",
                    FilterChainMatch {
                        direct_source_prefix_ranges: vec![cidr("192.168.0.0", 16)],
                        ..Default::default()
                    },
                ),
                chain(
                    "long",
                    FilterChainMatch {
                        direct_source_prefix_ranges: vec![cidr("192.168.1.0", 24)],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("long"));
    }

    #[test]
    fn source_type_same_ip_beats_any_and_external_eliminated() {
        let mut props = base_props();
        props.source_addr = addr("10.0.0.1", 12345); // == destination ip
        let l = listener(
            vec![
                chain("any", FilterChainMatch::default()),
                chain(
                    "external",
                    FilterChainMatch {
                        source_type: SourceType::External,
                        ..Default::default()
                    },
                ),
                chain(
                    "same",
                    FilterChainMatch {
                        source_type: SourceType::SameIpOrLoopback,
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("same"));
    }

    #[test]
    fn source_prefix_longest_wins() {
        let props = base_props(); // source ip 192.168.1.1
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "short",
                    FilterChainMatch {
                        source_prefix_ranges: vec![cidr("192.168.0.0", 16)],
                        ..Default::default()
                    },
                ),
                chain(
                    "long",
                    FilterChainMatch {
                        source_prefix_ranges: vec![cidr("192.168.1.0", 24)],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("long"));
    }

    #[test]
    fn source_port_specific_beats_wildcard_and_mismatch_eliminated() {
        let props = base_props(); // source port 50000
        let l = listener(
            vec![
                chain("wild", FilterChainMatch::default()),
                chain(
                    "wrong",
                    FilterChainMatch {
                        source_ports: vec![1234],
                        ..Default::default()
                    },
                ),
                chain(
                    "right",
                    FilterChainMatch {
                        source_ports: vec![50000, 1234],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("right"));
    }

    // --- precedence: earlier criterion beats later ------------------------

    #[test]
    fn precedence_port_beats_sni() {
        // "port-specific" chain has no SNI restriction; "sni-specific" chain
        // has the wrong port. Port narrowing runs first and eliminates the
        // wrong-port chain before SNI is even considered.
        let mut props = base_props();
        props.server_name = Some("api.example.com".to_string());
        let l = listener(
            vec![
                chain(
                    "port-only",
                    FilterChainMatch {
                        destination_port: Some(8080),
                        ..Default::default()
                    },
                ),
                chain(
                    "sni-only-wrong-port",
                    FilterChainMatch {
                        destination_port: Some(9999),
                        server_names: vec!["api.example.com".to_string()],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("port-only"));
    }

    #[test]
    fn precedence_dest_ip_longest_prefix_beats_transport_protocol() {
        let props = base_props(); // dest ip 10.0.0.1, transport_protocol raw_buffer
        let l = listener(
            vec![
                chain(
                    "ip-only",
                    FilterChainMatch {
                        prefix_ranges: vec![cidr("10.0.0.0", 24)],
                        ..Default::default()
                    },
                ),
                chain(
                    "transport-only-wrong-ip",
                    FilterChainMatch {
                        prefix_ranges: vec![cidr("192.168.0.0", 16)],
                        transport_protocol: Some("raw_buffer".to_string()),
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("ip-only"));
    }

    #[test]
    fn precedence_exact_sni_beats_wildcard_sni() {
        let mut props = base_props();
        props.server_name = Some("api.example.com".to_string());
        let l = listener(
            vec![
                chain(
                    "wildcard",
                    FilterChainMatch {
                        server_names: vec!["*.example.com".to_string()],
                        ..Default::default()
                    },
                ),
                chain(
                    "exact",
                    FilterChainMatch {
                        server_names: vec!["api.example.com".to_string()],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("exact"));
    }

    #[test]
    fn precedence_longer_wildcard_suffix_wins() {
        let mut props = base_props();
        props.server_name = Some("api.staging.example.com".to_string());
        let l = listener(
            vec![
                chain(
                    "short",
                    FilterChainMatch {
                        server_names: vec!["*.example.com".to_string()],
                        ..Default::default()
                    },
                ),
                chain(
                    "long",
                    FilterChainMatch {
                        server_names: vec!["*.staging.example.com".to_string()],
                        ..Default::default()
                    },
                ),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("long"));
    }

    // --- SNI edge cases ----------------------------------------------------

    #[test]
    fn no_sni_only_empty_server_names_chain_survives() {
        let props = base_props(); // server_name: None
        let l = listener(
            vec![
                chain(
                    "with-names",
                    FilterChainMatch {
                        server_names: vec!["api.example.com".to_string()],
                        ..Default::default()
                    },
                ),
                chain("no-names", FilterChainMatch::default()),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("no-names"));
    }

    #[test]
    fn wildcard_does_not_match_bare_domain() {
        let mut props = base_props();
        props.server_name = Some("example.com".to_string());
        let l = listener(
            vec![
                chain(
                    "wildcard",
                    FilterChainMatch {
                        server_names: vec!["*.example.com".to_string()],
                        ..Default::default()
                    },
                ),
                chain("fallback", FilterChainMatch::default()),
            ],
            None,
        );
        // "*.example.com" must NOT match bare "example.com" (no label before
        // the dot), so the wildcard chain is eliminated and the wildcard
        // (empty server_names) chain wins.
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("fallback"));
    }

    #[test]
    fn sni_case_insensitive() {
        let mut props = base_props();
        props.server_name = Some("API.EXAMPLE.COM".to_string());
        let l = listener(
            vec![chain(
                "exact",
                FilterChainMatch {
                    server_names: vec!["api.example.com".to_string()],
                    ..Default::default()
                },
            )],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("exact"));
    }

    #[test]
    fn sni_wildcard_case_insensitive() {
        // Regression: the wildcard branch must lowercase the configured
        // suffix too, not just the connection's SNI — `*.Example.COM` in
        // config matches `foo.example.com` on the wire.
        let mut props = base_props();
        props.server_name = Some("foo.example.com".to_string());
        let l = listener(
            vec![
                chain(
                    "wildcard",
                    FilterChainMatch {
                        server_names: vec!["*.Example.COM".to_string()],
                        ..Default::default()
                    },
                ),
                chain("fallback", FilterChainMatch::default()),
            ],
            None,
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("wildcard"));
    }

    // --- default_filter_chain fallback --------------------------------------

    #[test]
    fn falls_back_to_default_on_no_match() {
        let mut props = base_props();
        props.server_name = Some("nomatch.example.com".to_string());
        let l = listener(
            vec![chain(
                "specific",
                FilterChainMatch {
                    server_names: vec!["api.example.com".to_string()],
                    ..Default::default()
                },
            )],
            Some(chain("default", FilterChainMatch::default())),
        );
        assert_eq!(name_of(select_filter_chain(&props, &l)), Some("default"));
    }

    #[test]
    fn returns_none_on_no_match_and_no_default() {
        let mut props = base_props();
        props.server_name = Some("nomatch.example.com".to_string());
        let l = listener(
            vec![chain(
                "specific",
                FilterChainMatch {
                    server_names: vec!["api.example.com".to_string()],
                    ..Default::default()
                },
            )],
            None,
        );
        assert!(select_filter_chain(&props, &l).is_none());
    }

    // --- generated property-test matrix -------------------------------------

    /// Rust note: a tiny xorshift64* PRNG so the ~200-case matrix is
    /// deterministic without pulling in a `rand` dependency. `state` is
    /// mutated in place — the classic "generator as a struct with interior
    /// state" shape, no interior mutability needed since we own `&mut self`.
    struct Xorshift64(u64);

    impl Xorshift64 {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }

        fn next_range(&mut self, bound: u64) -> u64 {
            self.next_u64() % bound
        }

        fn choice<'a, T>(&mut self, options: &'a [T]) -> &'a T {
            &options[self.next_range(options.len() as u64) as usize]
        }
    }

    fn gen_ip(rng: &mut Xorshift64) -> IpAddr {
        let octets = [
            *rng.choice(&[10u8, 192, 172, 127]),
            rng.next_range(256) as u8,
            rng.next_range(256) as u8,
            rng.next_range(256) as u8,
        ];
        IpAddr::V4(Ipv4Addr::from(octets))
    }

    fn gen_props(rng: &mut Xorshift64) -> ConnectionProperties {
        let dest_ip = gen_ip(rng);
        let other_source_ip = gen_ip(rng);
        let source_ip = *rng.choice(&[other_source_ip, dest_ip]);
        let sni_options: [Option<&str>; 4] = [
            None,
            Some("api.example.com"),
            Some("foo.staging.example.com"),
            Some("example.com"),
        ];
        ConnectionProperties {
            destination_addr: SocketAddr::new(dest_ip, *rng.choice(&[80u16, 443, 8080])),
            source_addr: SocketAddr::new(source_ip, rng.next_range(65000) as u16 + 1),
            direct_source_addr: SocketAddr::new(gen_ip(rng), rng.next_range(65000) as u16 + 1),
            server_name: rng.choice(&sni_options).map(|s| s.to_string()),
            transport_protocol: rng.choice(&["raw_buffer", "tls"]).to_string(),
            application_protocols: match rng.next_range(3) {
                0 => vec![],
                1 => vec!["h2".to_string()],
                _ => vec!["http/1.1".to_string()],
            },
        }
    }

    fn gen_match_criteria(rng: &mut Xorshift64) -> FilterChainMatch {
        FilterChainMatch {
            destination_port: match rng.next_range(3) {
                0 => None,
                _ => Some(u32::from(*rng.choice(&[80u16, 443, 8080]))),
            },
            prefix_ranges: match rng.next_range(3) {
                0 => vec![],
                _ => vec![CidrRange {
                    addr: gen_ip(rng),
                    prefix_len: *rng.choice(&[8u8, 16, 24]),
                }],
            },
            server_names: match rng.next_range(3) {
                0 => vec![],
                1 => vec!["api.example.com".to_string()],
                _ => vec!["*.staging.example.com".to_string()],
            },
            transport_protocol: match rng.next_range(3) {
                0 => None,
                _ => Some(rng.choice(&["raw_buffer", "tls"]).to_string()),
            },
            application_protocols: match rng.next_range(3) {
                0 => vec![],
                1 => vec!["h2".to_string()],
                _ => vec!["http/1.1".to_string()],
            },
            direct_source_prefix_ranges: match rng.next_range(3) {
                0 => vec![],
                _ => vec![CidrRange {
                    addr: gen_ip(rng),
                    prefix_len: *rng.choice(&[8u8, 16, 24]),
                }],
            },
            source_type: *rng.choice(&[
                SourceType::Any,
                SourceType::SameIpOrLoopback,
                SourceType::External,
            ]),
            source_prefix_ranges: match rng.next_range(3) {
                0 => vec![],
                _ => vec![CidrRange {
                    addr: gen_ip(rng),
                    prefix_len: *rng.choice(&[8u8, 16, 24]),
                }],
            },
            source_ports: match rng.next_range(3) {
                0 => vec![],
                _ => vec![*rng.choice(&[80u32, 443, 50000])],
            },
        }
    }

    #[test]
    fn generated_matrix_never_panics_and_matches_oracle() {
        let mut rng = Xorshift64(0x2545_F491_4F6C_DD1D); // fixed seed: deterministic
        for _ in 0..200 {
            let props = gen_props(&mut rng);
            let n_chains = rng.next_range(4) + 1;
            let chains: Vec<FilterChainSpec> = (0..n_chains)
                .map(|i| chain(&format!("c{i}"), gen_match_criteria(&mut rng)))
                .collect();
            let has_default = rng.next_range(2) == 0;
            let default = has_default.then(|| chain("default", FilterChainMatch::default()));
            let l = listener(chains, default);

            // (a) never panics — the call itself is the assertion.
            let result = select_filter_chain(&props, &l);

            match result {
                Some(picked) => {
                    // (b) the picked chain must satisfy the oracle, UNLESS it
                    // is the default (which admits by definition — it has no
                    // criteria of its own to satisfy).
                    let is_default = l
                        .default_filter_chain
                        .as_ref()
                        .is_some_and(|d| std::ptr::eq(d, picked));
                    if !is_default {
                        assert!(
                            chain_matches(&props, &picked.match_criteria),
                            "picked chain does not satisfy its own match criteria"
                        );
                    }
                }
                None => {
                    // (c) None only when there was no default chain.
                    assert!(l.default_filter_chain.is_none());
                }
            }
        }
    }
}
