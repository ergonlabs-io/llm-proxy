//! The shipped Grafana dashboard (`deploy/grafana/llm-proxy-dashboard.json`)
//! queries only series the proxy exports. The exported names are the metrics
//! golden file, which `contract_golden_e2e.rs` regenerates from the real
//! binary's scrape; metric names are in the 1.x contract, so a rename there
//! must break the dashboard here rather than leave a blank panel.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::collections::{BTreeMap, BTreeSet};

const DASHBOARD: &str = include_str!("../../../deploy/grafana/llm-proxy-dashboard.json");
const GOLDEN: &str = include_str!("golden/prometheus_metrics.golden");

struct Family {
    kind: String,
    labels: BTreeSet<String>,
}

/// Family name to kind and the union of its label names, from the golden
/// file's `<name> <type> [<label>,...]` lines.
fn exported() -> BTreeMap<String, Family> {
    let mut families: BTreeMap<String, Family> = BTreeMap::new();
    for line in GOLDEN.lines().filter(|l| l.starts_with("envoy_")) {
        let mut parts = line.split_whitespace();
        let name = parts.next().unwrap().to_owned();
        let kind = parts.next().unwrap().to_owned();
        let family = families.entry(name).or_insert_with(|| Family {
            kind,
            labels: BTreeSet::new(),
        });
        for label in parts
            .next()
            .unwrap_or("")
            .split(',')
            .filter(|l| !l.is_empty())
        {
            family.labels.insert(label.to_owned());
        }
    }
    families
}

/// Every problem in one PromQL expression: a series the proxy does not
/// export, a `llmproxy_` name missing the `envoy_` prefix the scrape adds, or
/// a label the queried series do not carry.
fn problems(expr: &str, families: &BTreeMap<String, Family>) -> Vec<String> {
    let mut found = Vec::new();
    let mut allowed: BTreeSet<&str> = BTreeSet::new();
    let mut used_labels: Vec<String> = Vec::new();
    let words: Vec<&str> = expr
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .filter(|w| !w.is_empty())
        .collect();
    for word in &words {
        if word.starts_with("llmproxy_") {
            found.push(format!("`{word}` lacks the envoy_ prefix"));
        }
        if !word.starts_with("envoy_") {
            continue;
        }
        let histogram_part = ["_bucket", "_sum", "_count"]
            .iter()
            .find_map(|suffix| word.strip_suffix(suffix))
            .filter(|base| families.get(*base).is_some_and(|f| f.kind == "histogram"));
        let Some(family) = families
            .get(*word)
            .or_else(|| histogram_part.and_then(|b| families.get(b)))
        else {
            found.push(format!("`{word}` is not an exported series"));
            continue;
        };
        allowed.extend(family.labels.iter().map(String::as_str));
        if histogram_part.is_some() {
            allowed.insert("le");
        }
    }
    // Labels named in `by (...)` groups and in `{label=...}` matchers.
    let mut rest = expr;
    while let Some(at) = rest.find("by (") {
        let tail = &rest[at + 4..];
        let end = tail.find(')').unwrap();
        used_labels.extend(tail[..end].split(',').map(|l| l.trim().to_owned()));
        rest = &tail[end..];
    }
    for group in expr.split('{').skip(1) {
        let inside = group.split('}').next().unwrap();
        for matcher in inside.split(',') {
            if let Some((label, _)) = matcher.split_once(['=', '!', '~']) {
                used_labels.push(label.trim().to_owned());
            }
        }
    }
    for label in used_labels.iter().filter(|l| !l.is_empty()) {
        if !allowed.contains(label.as_str()) {
            found.push(format!("label `{label}` is not on the queried series"));
        }
    }
    found
}

fn dashboard_expressions() -> Vec<(String, String)> {
    let dashboard: serde_json::Value = serde_json::from_str(DASHBOARD).unwrap();
    dashboard["panels"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|panel| {
            let title = panel["title"].as_str().unwrap().to_owned();
            panel["targets"]
                .as_array()
                .unwrap()
                .iter()
                .map(move |t| (title.clone(), t["expr"].as_str().unwrap().to_owned()))
        })
        .collect()
}

#[test]
fn every_dashboard_query_uses_an_exported_series_and_its_labels() {
    let families = exported();
    let expressions = dashboard_expressions();
    assert!(expressions.len() >= 10, "dashboard lost its panels");
    let failures: Vec<String> = expressions
        .iter()
        .flat_map(|(title, expr)| {
            problems(expr, &families)
                .into_iter()
                .map(move |p| format!("panel `{title}`: {p} in `{expr}`"))
        })
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The check itself must fail on a renamed series or label, or the test above
/// passes for an empty reason.
#[test]
fn a_renamed_series_or_label_is_reported() {
    let families = exported();
    let ok = "sum by (tenant) (rate(envoy_llm_client_token_usage[5m]))";
    assert!(problems(ok, &families).is_empty());
    let renamed = ok.replace("token_usage", "token_usages");
    assert!(problems(&renamed, &families)
        .iter()
        .any(|p| p.contains("not an exported series")));
    let relabelled = ok.replace("tenant", "team");
    assert_eq!(problems(&relabelled, &families).len(), 1);
    let unprefixed = "rate(llmproxy_spend_charged_micro_usd_total[5m])";
    assert_eq!(problems(unprefixed, &families).len(), 1);
}
