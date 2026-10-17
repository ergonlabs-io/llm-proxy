//! `node.metadata["io.llmproxy.ledger"]` (ADR-0009): strict, with full
//! dotted paths, and `on_unavailable` defaulting to `reject`.

use proxy_config::{build_snapshot, parse_bootstrap, ConfigFormat, StrictMode};
use proxy_observability::ledger::{LedgerConfig, LedgerKeyFile, OnUnavailable};
use std::path::PathBuf;
use std::time::Duration;

const PREFIX: &str = "node.metadata[\"io.llmproxy.ledger\"]";
const REQUIRED: &str =
    "directory: /var/lib/ledger, encryption_key_file: /etc/ledger.key, encryption_key_id: k1, max_disk_bytes: 1073741824";

fn parse(value: &str) -> Result<proxy_config::ConfigSnapshot, proxy_config::ConfigError> {
    let yaml = format!("node:\n  metadata:\n    io.llmproxy.ledger: {value}\n");
    build_snapshot(&parse_bootstrap(
        yaml.as_bytes(),
        ConfigFormat::Yaml,
        StrictMode::Strict,
    )?)
}

fn ledger(extra: &str) -> Result<LedgerConfig, String> {
    parse(&format!("{{ {REQUIRED}{extra} }}"))
        .map(|s| s.ledger.expect("ledger configured"))
        .map_err(|e| e.to_string())
}

/// Whether `error` names exactly `PREFIX` + `path`, not a longer field that
/// starts with it.
fn names(error: &str, path: &str) -> bool {
    let full = format!("{PREFIX}{path}");
    error.match_indices(&full).any(|(at, _)| {
        !error[at + full.len()..]
            .starts_with(|c: char| c.is_alphanumeric() || c == '_' || c == '[' || c == '.')
    })
}

/// Unset `on_unavailable` is `reject`, and the tuning fields take their
/// documented defaults.
#[test]
fn the_minimal_ledger_rejects_when_unavailable_and_takes_the_defaults() {
    assert_eq!(
        ledger("").unwrap(),
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
    let tuned = ledger(
        ", on_unavailable: admit, max_reservations: 8, group_commit_max_entries: 4, \
         group_commit_interval: 0.01, previous_keys: [{ id: k0, file: /etc/old.key }]",
    )
    .unwrap();
    assert_eq!(tuned.on_unavailable, OnUnavailable::Admit);
    assert_eq!(tuned.max_reservations, 8);
    assert_eq!(tuned.group_commit_max_entries, 4);
    assert_eq!(tuned.group_commit_interval, Duration::from_millis(10));
    assert_eq!(tuned.previous_keys[0].id, "k0");
    assert!(
        parse("{}").is_err(),
        "an empty ledger block is not `no ledger`"
    );
}

/// Every missing, unknown or out-of-range field names its full path.
#[test]
fn ledger_fields_fail_with_exact_paths() {
    let without = |field: &str| {
        REQUIRED
            .split(", ")
            .filter(|f| f.split(':').next() != Some(field))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (value, path) in [
        (
            format!("{{ {} }}", without("encryption_key_file")),
            ".encryption_key_file",
        ),
        (
            format!("{{ {} }}", without("encryption_key_id")),
            ".encryption_key_id",
        ),
        (format!("{{ {} }}", without("directory")), ".directory"),
        (
            format!("{{ {} }}", without("max_disk_bytes")),
            ".max_disk_bytes",
        ),
        ("null".to_owned(), ""),
    ] {
        let error = parse(&value).unwrap_err().to_string();
        assert!(names(&error, path), "{value}: {error}");
    }
    for (extra, path) in [
        (", encryption_key: x", ".encryption_key"),
        (", on_unavailable: drop", ".on_unavailable"),
        (", max_disk_bytes: 1024", ".max_disk_bytes"),
        (", max_reservations: 0", ".max_reservations"),
        (
            ", group_commit_max_entries: 4097",
            ".group_commit_max_entries",
        ),
        (", group_commit_interval: 5", ".group_commit_interval"),
        (", group_commit_interval: 50ms", ".group_commit_interval"),
        (
            ", previous_keys: [{ id: k1, file: /etc/k1 }]",
            ".previous_keys[0].id",
        ),
        (
            ", previous_keys: [{ id: k0, path: /etc/k0 }]",
            ".previous_keys[0].path",
        ),
    ] {
        // Each case replaces the field it sets rather than repeating a key.
        let field = extra.trim_start_matches(", ").split(':').next().unwrap();
        let value = format!("{{ {}{extra} }}", without(field));
        let error = parse(&value).unwrap_err().to_string();
        assert!(names(&error, path), "{value}: {error}");
    }
    let error = parse(&format!("{{ {REQUIRED}, directory_mode: 448 }}"))
        .unwrap_err()
        .to_string();
    assert!(names(&error, ".directory_mode"), "{error}");
    let relative = REQUIRED.replace("/etc/ledger.key", "ledger.key");
    let error = parse(&format!("{{ {relative} }}")).unwrap_err().to_string();
    assert!(names(&error, ".encryption_key_file"), "{error}");
}

/// Bootstrap-scoped: an xDS delivery carries the ledger forward unchanged.
#[test]
fn the_ledger_survives_dynamic_resource_delivery() {
    let snapshot = parse(&format!("{{ {REQUIRED} }}")).unwrap();
    let dynamic = snapshot.with_dynamic_resources(
        Default::default(),
        Default::default(),
        Default::default(),
        proxy_config::ir::SnapshotVersion(2),
    );
    assert_eq!(dynamic.ledger, snapshot.ledger);
}
