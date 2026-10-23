//! The schema gate: `schema/llmproxy-v1.schema.json` is normative for the
//! dialect (AGENTS.md "Architecture Invariants", 5), so every dialect config
//! the repository ships as valid must validate against it, and the parser
//! must accept it too. A violation names the file, the JSON pointer and the
//! validator's reason.
//!
//! Sources, all checked as written (before `${VAR}` interpolation, which is
//! what an editor validating against the schema sees):
//! - `examples/llmproxy*.yaml`
//! - `testing/perf/proxy.yaml`
//! - every fenced `yaml` block in the docs site and `README.md` that has a
//!   top-level `version: 1` (or deprecated `version: 0`) line, which marks
//!   it as a complete config rather than a fragment.

mod schema_support;

use schema_support::{repo_root, schema, validation_errors};
use std::path::{Path, PathBuf};

/// One config to check, with a label that locates it for the reader.
struct Fixture {
    label: String,
    text: String,
}

fn yaml_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join("examples"))
        .expect("examples/ is readable")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            name.starts_with("llmproxy") && name.ends_with(".yaml")
        })
        .collect();
    files.push(root.join("testing/perf/proxy.yaml"));
    files.sort();
    files
}

fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("docs dir is readable") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            markdown_files(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("md" | "mdx")
        ) {
            out.push(path);
        }
    }
}

/// Fenced `yaml` blocks that are complete dialect configs, labelled
/// `file:line` with the line of the opening fence.
fn markdown_configs(path: &Path) -> Vec<Fixture> {
    let text = std::fs::read_to_string(path).expect("markdown is readable");
    let rel = path.strip_prefix(repo_root()).unwrap_or(path).display();
    let mut out = Vec::new();
    let mut block: Option<(usize, String)> = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        match &mut block {
            None if trimmed.starts_with("```yaml") || trimmed.starts_with("```yml") => {
                block = Some((i + 1, String::new()));
            }
            Some((start, body)) if trimmed.starts_with("```") => {
                if body.lines().any(|l| l == "version: 1" || l == "version: 0") {
                    out.push(Fixture {
                        label: format!("{rel}:{start}"),
                        text: std::mem::take(body),
                    });
                }
                block = None;
            }
            Some((_, body)) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    out
}

fn fixtures() -> Vec<Fixture> {
    let root = repo_root();
    let mut out: Vec<Fixture> = yaml_files()
        .into_iter()
        .map(|p| Fixture {
            label: p.strip_prefix(&root).unwrap_or(&p).display().to_string(),
            text: std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display())),
        })
        .collect();
    let mut docs = Vec::new();
    markdown_files(&root.join("docs/site/src/content/docs"), &mut docs);
    docs.push(root.join("README.md"));
    docs.sort();
    for doc in docs {
        out.extend(markdown_configs(&doc));
    }
    out
}

#[test]
fn every_shipped_dialect_config_validates_against_the_schema_and_parses() {
    let validator = schema_support::validator(&schema());
    let fixtures = fixtures();
    let placeholder = |name: &str| Some(format!("sk-sample-{}", name.to_ascii_lowercase()));
    let mut failures = Vec::new();
    for f in &fixtures {
        let instance: serde_json::Value = match serde_yaml::from_str(&f.text) {
            Ok(v) => v,
            Err(e) => {
                failures.push(format!("{}: not YAML: {e}", f.label));
                continue;
            }
        };
        for (pointer, reason) in validation_errors(&validator, &instance) {
            failures.push(format!("{}: {pointer}: {reason}", f.label));
        }
        if let Err(e) = proxy_simple_config::parse_simple_config_with_env(&f.text, &placeholder) {
            failures.push(format!("{}: parser rejects it: {e}", f.label));
        }
    }
    assert!(
        failures.is_empty(),
        "{} schema-gate violation(s):\n{}",
        failures.len(),
        failures.join("\n")
    );
    // Guards the discovery itself: a moved docs tree or a renamed example
    // would otherwise turn this into a test of nothing.
    let labels: Vec<&str> = fixtures.iter().map(|f| f.label.as_str()).collect();
    for expected in [
        "examples/llmproxy.yaml",
        "testing/perf/proxy.yaml",
        "README.md:",
    ] {
        assert!(
            labels.iter().any(|l| l.starts_with(expected)),
            "schema gate found no fixture for {expected}; found {labels:?}"
        );
    }
    assert!(
        labels.iter().any(|l| l.starts_with("docs/site/")),
        "schema gate found no docs-site config block; found {labels:?}"
    );
}

/// The gate must fail on a violation, and say where: a passing gate that
/// cannot fail proves nothing.
#[test]
fn a_violation_is_reported_with_its_json_pointer() {
    let validator = schema_support::validator(&schema());
    let instance: serde_json::Value = serde_yaml::from_str(
        "version: 1\nproviders:\n  openai: {}\nroutes:\n  - model: '*'\n    provider: openai\n    idle_timeout: soon\n",
    )
    .unwrap();
    let errors = validation_errors(&validator, &instance);
    assert!(
        errors
            .iter()
            .any(|(pointer, _)| pointer == "/routes/0/idle_timeout"),
        "expected a violation at /routes/0/idle_timeout, got {errors:?}"
    );
}
