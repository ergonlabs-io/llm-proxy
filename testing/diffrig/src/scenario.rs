//! Scenario file model for the differential rig (WP-26): a scenario names a
//! bootstrap config, an ordered request script to replay against the proxy
//! under test, and an upstream script describing which scriptable upstream
//! backs it. This module only parses and validates the shape; actually
//! spinning up proxies/upstreams and comparing captures is a later WP-26
//! chunk.
//!
//! Strict-mode mindset: unknown fields are always errors, same standard as
//! the rest of the repo's config surfaces.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::upstreams::Action;

/// Top-level scenario file, e.g. `scenarios/*.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub name: String,
    pub bootstrap: Bootstrap,
    pub requests: Vec<ScriptedRequest>,
    pub upstream: UpstreamScript,
}

/// The bootstrap config under test: either a path to a file on disk or an
/// inline YAML document. Kept as data here — the rig (a later chunk)
/// decides how to hand it to a proxy process.
///
/// Rust note: `#[serde(untagged)]` tries each variant in order and picks the
/// first that matches the input shape; each variant is itself a
/// `deny_unknown_fields` struct so a stray key inside `bootstrap:` is still
/// an error rather than silently falling through to the other variant.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum Bootstrap {
    Path(BootstrapPath),
    Inline(BootstrapInline),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapPath {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapInline {
    pub inline: String,
}

/// One request in the scenario's ordered request script.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptedRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
}

/// Which scriptable upstream backs the scenario, and its configuration.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum UpstreamScript {
    Echo,
    Slow { delay_ms: u64 },
    Flaky { script: Vec<Action> },
}

/// A scenario file failed to parse or didn't pass semantic validation; every
/// variant names the offending field path, matching the repo's config-error
/// standard.
#[derive(Debug, thiserror::Error)]
pub enum ScenarioError {
    #[error("{field_path}: {reason}")]
    Parse { field_path: String, reason: String },
    #[error("{field_path}: {reason}")]
    Invalid { field_path: String, reason: String },
}

/// Parse a scenario file from disk.
pub fn load_scenario_file(path: &std::path::Path) -> Result<Scenario, ScenarioError> {
    let text = std::fs::read_to_string(path).map_err(|e| ScenarioError::Invalid {
        field_path: "<file>".to_string(),
        reason: format!("reading {}: {e}", path.display()),
    })?;
    parse_scenario(&text)
}

/// Parse scenario YAML text: strict deserialize, then semantic validation.
pub fn parse_scenario(text: &str) -> Result<Scenario, ScenarioError> {
    let de = serde_yaml::Deserializer::from_str(text);
    let scenario: Scenario =
        serde_path_to_error::deserialize(de).map_err(|e| ScenarioError::Parse {
            field_path: e.path().to_string(),
            reason: e.inner().to_string(),
        })?;
    validate(&scenario)?;
    Ok(scenario)
}

fn validate(scenario: &Scenario) -> Result<(), ScenarioError> {
    if scenario.requests.is_empty() {
        return Err(ScenarioError::Invalid {
            field_path: "requests".to_string(),
            reason: "must have at least one request".to_string(),
        });
    }
    for (i, req) in scenario.requests.iter().enumerate() {
        if req.method.trim().is_empty() {
            return Err(ScenarioError::Invalid {
                field_path: format!("requests[{i}].method"),
                reason: "must not be empty".to_string(),
            });
        }
        if !req.path.starts_with('/') {
            return Err(ScenarioError::Invalid {
                field_path: format!("requests[{i}].path"),
                reason: format!("must start with '/', got {:?}", req.path),
            });
        }
    }
    if let UpstreamScript::Flaky { script } = &scenario.upstream {
        if script.is_empty() {
            return Err(ScenarioError::Invalid {
                field_path: "upstream.script".to_string(),
                reason: "flaky upstream needs at least one scripted action".to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_example_scenario_file() {
        let text = include_str!("../scenarios/echo-basic.yaml");
        let scenario = parse_scenario(text).expect("example scenario should parse");

        assert_eq!(scenario.name, "echo-basic");
        assert!(matches!(scenario.bootstrap, Bootstrap::Path(_)));
        assert_eq!(scenario.requests.len(), 2);
        assert!(matches!(scenario.upstream, UpstreamScript::Echo));
    }

    #[test]
    fn rejects_unknown_top_level_fields() {
        let text = "name: x\nbootstrap:\n  path: a.yaml\nrequests:\n  - method: GET\n    path: /\nupstream:\n  type: echo\nbogus: true\n";
        let err = parse_scenario(text).expect_err("unknown field should error");
        assert!(matches!(err, ScenarioError::Parse { .. }));
    }

    #[test]
    fn rejects_empty_request_script() {
        let text = "name: x\nbootstrap:\n  path: a.yaml\nrequests: []\nupstream:\n  type: echo\n";
        let err = parse_scenario(text).expect_err("empty request script should error");
        assert!(matches!(
            err,
            ScenarioError::Invalid { field_path, .. } if field_path == "requests"
        ));
    }

    #[test]
    fn rejects_flaky_upstream_with_empty_script() {
        let text = "name: x\nbootstrap:\n  path: a.yaml\nrequests:\n  - method: GET\n    path: /\nupstream:\n  type: flaky\n  script: []\n";
        let err = parse_scenario(text).expect_err("empty flaky script should error");
        assert!(matches!(
            err,
            ScenarioError::Invalid { field_path, .. } if field_path == "upstream.script"
        ));
    }
}
