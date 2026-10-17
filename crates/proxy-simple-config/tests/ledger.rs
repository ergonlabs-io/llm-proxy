//! The dialect's `ledger` block (ADR-0009), lowered through the real
//! pipeline into the snapshot the Envoy-mode loader builds. Defaults and
//! ranges belong to `node.metadata["io.llmproxy.ledger"]`
//! (`proxy-config/tests/ledger_namespace.rs`); these tests pin what the
//! dialect adds: the key, the `ledger.<field>` paths for required fields, and
//! duration syntax.

use proxy_observability::ledger::{LedgerConfig, LedgerKeyFile, OnUnavailable};
use proxy_simple_config::{lower_to_loaded, parse_simple_config};
use std::path::PathBuf;
use std::time::Duration;

const BASE: &str = r#"version: 0
providers:
  openai: { type: openai, base_url: "http://127.0.0.1:1", api_key: sk-test }
routes:
  - { model: "*", provider: openai }
"#;

const REQUIRED: &str = "  directory: /var/lib/ledger\n  encryption_key_file: /etc/ledger.key\n  encryption_key_id: k1\n  max_disk_bytes: 1073741824\n";

fn load(ledger: &str) -> Result<Option<LedgerConfig>, String> {
    let text = format!("{BASE}ledger:\n{ledger}");
    let config = parse_simple_config(&text).map_err(|e| e.to_string())?;
    let loaded = lower_to_loaded(&config).map_err(|e| e.to_string())?;
    let snapshot = proxy_config::build_snapshot(&loaded).map_err(|e| e.to_string())?;
    Ok(snapshot.ledger)
}

/// The dialect reaches the same IR as Envoy mode, and unset
/// `on_unavailable` is `reject` there too.
#[test]
fn a_dialect_ledger_reaches_the_snapshot_and_defaults_to_reject() {
    let ledger = load(REQUIRED).unwrap().expect("ledger configured");
    assert_eq!(
        ledger,
        LedgerConfig {
            directory: PathBuf::from("/var/lib/ledger"),
            encryption_key: LedgerKeyFile {
                id: "k1".into(),
                file: PathBuf::from("/etc/ledger.key"),
            },
            previous_keys: Vec::new(),
            max_disk_bytes: 1 << 30,
            max_reservations: 16_384,
            group_commit_max_entries: 512,
            group_commit_interval: Duration::from_millis(50),
            on_unavailable: OnUnavailable::Reject,
        }
    );
    let tuned = load(&format!(
        "{REQUIRED}  on_unavailable: admit\n  group_commit_interval: 10ms\n  max_reservations: 64\n  \
         previous_keys: [{{ id: k0, file: /etc/old.key }}]\n"
    ))
    .unwrap()
    .unwrap();
    assert_eq!(tuned.on_unavailable, OnUnavailable::Admit);
    assert_eq!(tuned.group_commit_interval, Duration::from_millis(10));
    assert_eq!(tuned.max_reservations, 64);
    assert_eq!(tuned.previous_keys.len(), 1);
}

/// A missing required field is reported at its dialect path. Other errors
/// keep the Envoy-mode path of the namespace the dialect lowers to.
#[test]
fn a_ledger_missing_a_required_field_names_its_dialect_path() {
    for field in [
        "encryption_key_file",
        "encryption_key_id",
        "directory",
        "max_disk_bytes",
    ] {
        let ledger: String = REQUIRED
            .lines()
            .filter(|l| !l.trim_start().starts_with(&format!("{field}:")))
            .map(|l| format!("{l}\n"))
            .collect();
        let error = load(&ledger).unwrap_err();
        assert!(error.contains(&format!("ledger.{field}")), "{field}: {error}");
    }
    let error = load(&format!("{REQUIRED}  on_unavailable: drop\n")).unwrap_err();
    assert!(error.contains("on_unavailable"), "{error}");
    let error = load(&format!("{REQUIRED}  max_reservations: 0\n")).unwrap_err();
    assert!(
        error.contains("node.metadata[\"io.llmproxy.ledger\"].max_reservations"),
        "{error}"
    );
}
