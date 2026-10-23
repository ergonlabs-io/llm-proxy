//! The 1.x config promise: a `--config` file that loaded in an earlier
//! release still loads, unedited. `tests/fixtures/v0.7.0/` holds every dialect
//! example exactly as tag v0.7.0 shipped it (`git show v0.7.0:examples/<file>`);
//! do not edit those files, add a directory for each newer release instead.
//!
//! Each fixture goes through the real loader (`--mode validate`, which parses,
//! lowers and builds the IR exactly as `serve` does). The only change made to
//! a file is deployment data the host lacks: `/etc/llm-proxy/` paths point at a
//! scratch directory that holds a generated key, since the loader reads the
//! Vertex service-account key.
//!
//! Version 0 must load with exactly one deprecation warning at `version`. The
//! shipped example of the same name, which says `version: 1`, is the control: it
//! must load with none, so the warning is tied to the version and not to
//! anything else in the file.

#![allow(clippy::unwrap_used)] // Test code may panic; see AGENTS.md "Rust style".

use std::path::{Path, PathBuf};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_llm-proxy");
/// Where the examples expect operator-supplied files.
const DEPLOY_DIR: &str = "/etc/llm-proxy/";

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every `${NAME}` the file references, mapped to a value of the right shape.
/// A config that names an unset variable fails to load, so each one is set.
fn placeholder_env(text: &str) -> Vec<(String, String)> {
    let mut vars: Vec<(String, String)> = text
        .split("${")
        .skip(1)
        .filter_map(|rest| rest.split_once('}').map(|(name, _)| name.to_string()))
        .map(|name| {
            let value = if name.ends_with("_URL") {
                "http://127.0.0.1:9".to_string()
            } else {
                format!("compat-placeholder-{}", name.to_ascii_lowercase())
            };
            (name, value)
        })
        .collect();
    vars.sort();
    vars.dedup();
    vars
}

/// A scratch directory standing in for `/etc/llm-proxy/`, holding the
/// Vertex service-account key that `llmproxy-vertex-oauth2.yaml` names.
fn deploy_dir() -> PathBuf {
    use rsa::pkcs8::EncodePrivateKey;
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("config-compat-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // RSA generation takes seconds in a debug build, so one key is kept per
    // build directory. The loader refuses keys under 2048 bits.
    let cached = Path::new(env!("CARGO_TARGET_TMPDIR")).join("config-compat-vertex-sa.pem");
    if !cached.exists() {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
        let tmp = cached.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::write(&tmp, pem.as_bytes()).unwrap();
        std::fs::rename(&tmp, &cached).unwrap();
    }
    std::fs::copy(&cached, dir.join("vertex-sa.pem")).unwrap();
    dir
}

/// Runs `validate` on `path`; returns stderr lines that warn at `version`.
fn validate(path: &Path, deploy: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path)
        .unwrap()
        .replace(DEPLOY_DIR, &format!("{}/", deploy.display()));
    let copy = deploy.join(path.file_name().unwrap());
    std::fs::write(&copy, &text).unwrap();
    let output = Command::new(BIN)
        .args(["--config", copy.to_str().unwrap(), "--mode", "validate"])
        .envs(placeholder_env(&text))
        .output()
        .expect("failed to run llm-proxy");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success(),
        "{} must load without schema edits, got {:?}\nstderr:\n{stderr}",
        path.display(),
        output.status
    );
    stderr
        .lines()
        .filter(|l| l.starts_with("warning: `version`"))
        .map(str::to_string)
        .collect()
}

#[test]
fn every_v0_7_0_dialect_example_loads_with_one_version_deprecation_warning() {
    let fixtures = manifest_dir().join("tests/fixtures/v0.7.0");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&fixtures)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    // Guards the discovery: v0.7.0 shipped nine dialect examples, and an empty
    // directory would turn this into a test of nothing.
    assert_eq!(files.len(), 9, "v0.7.0 fixtures: {files:?}");
    let deploy = deploy_dir();

    for fixture in &files {
        let warnings = validate(fixture, &deploy);
        assert_eq!(
            warnings.len(),
            1,
            "{}: a version 0 config must warn once at `version`, got {warnings:?}",
            fixture.display()
        );
        assert!(
            warnings[0].contains("set `version: 1`"),
            "{}: the warning must say how to fix it, got {:?}",
            fixture.display(),
            warnings[0]
        );

        let name = fixture.file_name().unwrap();
        let current = manifest_dir().join("../../examples").join(name);
        let control = validate(&current, &deploy);
        assert!(
            control.is_empty(),
            "{}: a version 1 config must not warn at `version`, got {control:?}",
            current.display()
        );
    }
}
