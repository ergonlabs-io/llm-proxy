//! The model wildcard matchers: the dialect's `routes[].model` / `models` key
//! glob (`proxy-simple-config` `parse.rs`), the cluster model-rewrite pattern
//! (`proxy-http` `router.rs`), and tenant and key model grants
//! (`proxy-control` `model_authz.rs`). A grant that matches too much is an
//! access-control hole; a rewrite that matches the wrong model sends the
//! wrong upstream model.
//!
//! Input: the pattern and the model name, split at the first 0xFF byte (which
//! never occurs in UTF-8).
//!
//! Properties checked beyond "never panic":
//! - the dialect glob agrees with a reference glob matcher;
//! - on every pattern the narrower grammars accept (a legal `models:` key, a
//!   valid grant), the cluster rewrite match and the grant match agree with
//!   the dialect glob, so the validator, the router and the authorizer read
//!   one pattern the same way;
//! - a pattern always matches itself once each `*` is removed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use proxy_control::model_authz::ModelPattern;
use proxy_http::router::fuzzing::provider_model_pattern_matches;
use proxy_simple_config::fuzzing::{glob_matches, is_valid_model_key};

/// `*` matches any run of characters, every other character itself. A plain
/// dynamic-programming matcher, deliberately unlike the greedy production one.
fn reference_glob(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    // reach[j]: the pattern prefix so far matches name[..j].
    let mut reach = vec![false; n.len() + 1];
    reach[0] = true;
    for &c in &p {
        let mut next = vec![false; n.len() + 1];
        if c == '*' {
            let mut seen = false;
            for j in 0..=n.len() {
                seen |= reach[j];
                next[j] = seen;
            }
        } else {
            for j in 0..n.len() {
                next[j + 1] = reach[j] && n[j] == c;
            }
        }
        reach = next;
    }
    reach[n.len()]
}

fuzz_target!(|data: &[u8]| {
    let (pattern, name) = match data.iter().position(|&b| b == 0xFF) {
        Some(at) => (&data[..at], &data[at + 1..]),
        None => (data, &data[..0]),
    };
    let (Ok(pattern), Ok(name)) = (std::str::from_utf8(pattern), std::str::from_utf8(name)) else {
        return;
    };
    // The reference is quadratic; keep each run fast.
    if pattern.len() > 256 || name.len() > 256 {
        return;
    }

    let glob = glob_matches(pattern, name);
    assert_eq!(
        glob,
        reference_glob(pattern, name),
        "dialect glob disagrees with the reference: {pattern:?} vs {name:?}"
    );
    let literal = pattern.replace('*', "");
    assert!(
        glob_matches(pattern, &literal),
        "{pattern:?} must match {literal:?}"
    );

    if is_valid_model_key(pattern) {
        assert_eq!(
            provider_model_pattern_matches(pattern, name),
            glob,
            "cluster rewrite and dialect glob disagree: {pattern:?} vs {name:?}"
        );
    }
    if ModelPattern::is_valid(pattern) {
        assert_eq!(
            ModelPattern::new(pattern).matches(name),
            glob,
            "model grant and dialect glob disagree: {pattern:?} vs {name:?}"
        );
    }
});
