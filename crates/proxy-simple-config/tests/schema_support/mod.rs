//! Shared by the schema tests: locating and compiling the normative schema.
// Each test binary compiles this module separately and uses a subset of it.
#![allow(dead_code)]

use std::path::PathBuf;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn schema() -> serde_json::Value {
    let path = repo_root().join("schema/llmproxy-v0.schema.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("schema is JSON")
}

pub fn validator(schema: &serde_json::Value) -> jsonschema::Validator {
    jsonschema::validator_for(schema).expect("schema compiles")
}

/// Every violation as `(JSON pointer, reason)`; empty when valid.
pub fn validation_errors(
    validator: &jsonschema::Validator,
    instance: &serde_json::Value,
) -> Vec<(String, String)> {
    let mut errors: Vec<(String, String)> = validator
        .iter_errors(instance)
        .map(|e| {
            let pointer = e.instance_path().to_string();
            (
                if pointer.is_empty() {
                    "/".into()
                } else {
                    pointer
                },
                e.to_string(),
            )
        })
        .collect();
    errors.sort();
    errors
}
