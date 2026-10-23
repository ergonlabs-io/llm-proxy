//! Golden-file comparison for the stable-surface contract tests
//! (`tests/contract_golden_e2e.rs` and the CLI test in `src/main.rs`).
//!
//! A golden file under `tests/golden/` lists one surface item per line, as the
//! running code produced it. Lines starting with `#` are commentary and are
//! not compared. A test fails when the code produces a line the file lacks, or
//! lacks a line the file has, so a renamed metric, admin path, access-log key
//! or CLI flag fails the suite.
//!
//! Changing a golden file is a deliberate, reviewed edit: operators' dashboards
//! and scripts depend on every line. To regenerate after an intended change,
//! run `make golden` (it sets `UPDATE_GOLDEN=1`, which rewrites the files from
//! the running code instead of comparing), then review the diff.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Compares `actual` with `tests/golden/<name>`, or rewrites that file from
/// `actual` when `UPDATE_GOLDEN=1`. `header` becomes the file's `#` lines.
pub fn check(name: &str, header: &str, actual: &BTreeSet<String>) {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        let mut text = String::new();
        for line in header.lines() {
            text.push_str(if line.is_empty() { "#" } else { "# " });
            text.push_str(line);
            text.push('\n');
        }
        for line in actual {
            text.push_str(line);
            text.push('\n');
        }
        std::fs::write(&path, text)
            .unwrap_or_else(|e| panic!("write golden file {}: {e}", path.display()));
        return;
    }
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read golden file {}: {e}; run `make golden` to create it",
            path.display()
        )
    });
    let expected: BTreeSet<String> = text
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_string)
        .collect();
    let missing: Vec<_> = expected.difference(actual).collect();
    let unexpected: Vec<_> = actual.difference(&expected).collect();
    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "stable surface changed against {}\n\
         in the golden file but no longer produced (renamed or removed): {missing:#?}\n\
         produced but not in the golden file (new or renamed): {unexpected:#?}\n\
         Operators depend on these names. If the change is intended, run \
         `make golden` and commit the reviewed golden diff with a CHANGELOG entry.",
        path.display()
    );
}
