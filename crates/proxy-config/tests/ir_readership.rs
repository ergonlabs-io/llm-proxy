//! WP-39: a CI guard against "IR field lowered but never read".
//!
//! Motivation (read before touching the allowlist): `RouteEntry.request_headers_to_add`
//! was lowered correctly by both config front-ends and read by no runtime code at
//! all — it's how the config dialect injects provider API keys, so every request
//! reached its provider with no credentials. Strict mode (ground rule #1) could not
//! catch this: it only proves a config field maps *into* the IR, not that the IR
//! field is then *consumed*. This test closes that gap on the other side of the
//! seam by grepping the runtime crates for a read of every `pub` IR field.
//!
//! Rust note: this is a source-scanning test, not real type reflection — it parses
//! `ir.rs` as text (looking for `pub struct` blocks and `pub <field>:` lines) and
//! greps the runtime crates' `src/` trees for `.field_name`. That's a weaker
//! guarantee than a proc-macro derive would give (it can't tell a read from a
//! write, and can be fooled by an unrelated field of the same name elsewhere), but
//! it is enough to catch exactly the class of bug above, and it runs in
//! milliseconds with no extra dependencies.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Runtime crates that consume the IR. `proxy-config` itself is deliberately
/// excluded — ground rule #2 says the data plane consumes the IR, and a field
/// read only inside `proxy-config` (e.g. by `RouteTable::new`'s precomputed
/// index) does not prove anything runs on it at request time.
///
/// **`proxy-admin` is excluded for the same reason, and the reason is worth
/// stating because it was NOT excluded originally.** It was listed here while
/// it was an empty stub, where the choice cost nothing. Once WP-50 landed
/// `/config_dump`, that stopped being true: the dump renders IR fields for
/// display, so every field it touches acquires a `.field` reference and would
/// silently satisfy this guard. `HttpConnectionManagerConfig.stat_prefix` is
/// what caught it — the dump rendered it and the staleness check immediately
/// declared its allowlist entry obsolete, even though nothing yet *acts* on
/// the field (that is still WP-23).
///
/// Displaying a field is not acting on it. This guard exists to catch the
/// `request_headers_to_add` class of bug — lowered, validated, and then read
/// by nothing, so every provider request went out unauthenticated. A
/// `/config_dump` that grows to render the whole IR would defeat it one field
/// at a time, quietly, with no test ever failing. That is precisely the
/// failure mode this file was written to make impossible.
const RUNTIME_CRATES: &[&str] = &[
    "proxy-http",
    "proxy-core",
    "proxy-cluster",
    "proxy-filters",
    "proxy-xds",
];

/// Why a field is exempted from "must have a runtime reader".
///
/// Rust note: a plain enum, not a trait object — the two categories need
/// different staleness checks (see `allowlist_has_no_stale_entries`), so the
/// test needs to distinguish them, not just carry a free-text reason.
#[derive(PartialEq)]
enum EntryKind {
    /// The field is read, but only inside `proxy-config` itself, via a method
    /// the runtime crates call (e.g. `RouteTable::find_virtual_host` reading
    /// `virtual_hosts`). It will *never* show up as directly read by the
    /// runtime-crates scan, by construction — that's not staleness, it's the
    /// whole reason for the entry.
    ConsumedInternally,
    /// The field is genuinely inert today (no reader anywhere), tracked
    /// against a work package that will wire it up. Once it does, this entry
    /// becomes stale and must be deleted.
    KnownInert,
    /// Same as `KnownInert`, but the field's *name* collides with an
    /// unrelated field of the same name on a different struct that genuinely
    /// is read — the text-based `.field_name` scan this test uses can't tell
    /// them apart (a real limitation of a source-scanning check rather than a
    /// type-aware one; see the module doc comment). The staleness recheck is
    /// skipped for these; the reason string must name the colliding struct so
    /// a human can re-verify by hand when touching this entry.
    KnownInertNameCollision,
}

/// One allowlist entry: a field that is a known, reasoned exception to "every
/// field must have a runtime reader". Every entry must carry a reason; an
/// entry that no longer matches reality (a `KnownInert` field now has a real
/// reader, or the field/struct no longer exists at all) is a test failure —
/// see `allowlist_has_no_stale_entries` below. That's what keeps this list
/// from quietly growing forever instead of shrinking as work lands.
struct AllowlistEntry {
    struct_name: &'static str,
    field_name: &'static str,
    kind: EntryKind,
    reason: &'static str,
}

const ALLOWLIST: &[AllowlistEntry] = &[
    AllowlistEntry {
        struct_name: "ClusterConfig",
        field_name: "usage_dialect",
        kind: EntryKind::KnownInert,
        reason: "WP-35 increment 1 lands the per-provider carrier (ground rule \
                  #6's third instance) additively: the usage filter still reads \
                  the route-level typed_per_filter_config copy, so nothing in a \
                  runtime crate reads this field yet. Increment 2 switches the \
                  filter over to it and deletes this entry -- and the \
                  cross-dialect fallback prohibition in \
                  proxy-simple-config/src/lower.rs must stay until it does, \
                  since that rejection is what currently prevents the route \
                  copy from reaching the wrong provider on failover.",
    },
    AllowlistEntry {
        struct_name: "VirtualHostIR",
        field_name: "domains",
        kind: EntryKind::ConsumedInternally,
        reason: "Consumed inside proxy-config itself, by RouteTable::new's \
                  precomputed DomainIndex (S1 virtual-host selection), which \
                  proxy-http calls via RouteTable::find_virtual_host — a \
                  genuine false positive for a runtime-crates-only scan, not \
                  an inert field.",
    },
    AllowlistEntry {
        struct_name: "RouteTable",
        field_name: "virtual_hosts",
        kind: EntryKind::ConsumedInternally,
        reason: "Same shape as VirtualHostIR.domains above: read inside \
                  proxy-config by RouteTable::find_virtual_host, which \
                  crates/proxy-http/src/route.rs calls rather than reading \
                  the field directly.",
    },
    AllowlistEntry {
        struct_name: "WeightedClusters",
        field_name: "cumulative",
        kind: EntryKind::ConsumedInternally,
        reason: "Read inside proxy-config by WeightedClusters::pick, which \
                  crates/proxy-http/src/route.rs calls (`weighted.pick(draw)`) \
                  rather than reading `.cumulative` directly.",
    },
    AllowlistEntry {
        struct_name: "HttpConnectionManagerConfig",
        field_name: "stat_prefix",
        kind: EntryKind::KnownInert,
        reason: "Accepted-but-inert today; WP-23 (stats registry) closes it. \
                  Named in IMPLEMENTATION_PLAN.md's WP-39 note alongside \
                  `access_logs` as one of two known survivors — `access_logs` \
                  has since landed (WP-24 chunk 3, see \
                  crates/proxy-core/src/listener.rs's `new_with_access_logs` \
                  call), leaving this one outstanding.",
    },
    AllowlistEntry {
        struct_name: "TcpProxyConfig",
        field_name: "stat_prefix",
        kind: EntryKind::KnownInert,
        reason: "Same stats gap as HttpConnectionManagerConfig.stat_prefix \
                  above (WP-23), on the TCP proxy's copy of the field; not \
                  separately called out in the plan's WP-39 note, but the \
                  same owning WP applies.",
    },
    AllowlistEntry {
        struct_name: "RetryPolicyIR",
        field_name: "host_selection_retry_max_attempts",
        kind: EntryKind::KnownInert,
        reason: "WP-14: lowering rejects any config where this would exceed \
                  1 (crates/proxy-config/src/lower.rs, `> 1` check) rather \
                  than silently ignoring it, so the field can only ever carry \
                  its default in the IR — but the router has no host-*repick* \
                  predicate yet (IMPLEMENTATION_PLAN.md's WP-14 remainder), \
                  so no runtime code reads even that default value.",
    },
    AllowlistEntry {
        struct_name: "RetryOn",
        field_name: "envoy_ratelimited",
        kind: EntryKind::KnownInert,
        reason: "WP-14: lowering rejects `retry_on: envoy-ratelimited` \
                  outright (crates/proxy-config/src/lower.rs) because no \
                  filter sets `x-envoy-ratelimited` until WP-31/WP-32, so the \
                  field can only ever be `false` in the IR, and retry.rs's \
                  outcome classifier never consults it.",
    },
    AllowlistEntry {
        struct_name: "RedirectIR",
        field_name: "host_redirect",
        kind: EntryKind::KnownInert,
        reason: "WP-13 follow-up: `RouteActionIR::Redirect` returns 501 \
                  unconditionally today (crates/proxy-http/src/router.rs, \
                  literally tagged `TODO(WP-13 follow-up: redirects)`), so \
                  none of RedirectIR's fields are read yet.",
    },
    AllowlistEntry {
        struct_name: "RedirectIR",
        field_name: "path_redirect",
        kind: EntryKind::KnownInert,
        reason: "Same WP-13 follow-up gap as RedirectIR.host_redirect above.",
    },
    AllowlistEntry {
        struct_name: "RedirectIR",
        field_name: "https_redirect",
        kind: EntryKind::KnownInert,
        reason: "Same WP-13 follow-up gap as RedirectIR.host_redirect above.",
    },
    AllowlistEntry {
        struct_name: "RedirectIR",
        field_name: "response_code",
        kind: EntryKind::KnownInertNameCollision,
        reason: "Same WP-13 follow-up gap as RedirectIR.host_redirect above, \
                  AND `response_code` collides with an unrelated, genuinely-read \
                  field of the same name on router/logging.rs's AccessLogContext \
                  (`ctx.response_code`) — verify by hand, not via this test's \
                  automated staleness recheck, that RouteActionIR::Redirect is \
                  still unimplemented before deleting this entry.",
    },
    AllowlistEntry {
        struct_name: "ConfigSnapshot",
        field_name: "admin",
        kind: EntryKind::KnownInert,
        reason: "WP-25: the admin server crate (proxy-admin) is a stub — its \
                  `src/lib.rs` doesn't yet bind or read the admin address this \
                  field carries. Field's own doc comment already names WP-25.",
    },
    AllowlistEntry {
        struct_name: "ConfigSnapshot",
        field_name: "secrets",
        kind: EntryKind::KnownInert,
        reason: "WP-08/WP-22: no runtime code looks up a TlsSecret by name \
                  yet (SDS-delivered secrets aren't consulted anywhere outside \
                  proxy-config); TlsSecret's own doc comment already names \
                  these WPs.",
    },
    AllowlistEntry {
        struct_name: "ConfigSnapshot",
        field_name: "tracing",
        kind: EntryKind::KnownInert,
        reason: "WP-51 increment 3: config surface only. No runtime crate runs \
                  an OTLP exporter or mints/propagates a span yet -- a later \
                  increment wires that and deletes this entry, plus the three \
                  TracingConfig entries below. Field's own doc comment already \
                  names the increment.",
    },
    AllowlistEntry {
        struct_name: "TracingConfig",
        field_name: "otlp_endpoint",
        kind: EntryKind::KnownInert,
        reason: "Same WP-51 increment 3 gap as ConfigSnapshot.tracing above -- \
                  delete alongside it once an exporter reads this field.",
    },
    AllowlistEntry {
        struct_name: "TracingConfig",
        field_name: "service_name",
        kind: EntryKind::KnownInert,
        reason: "Same WP-51 increment 3 gap as ConfigSnapshot.tracing above -- \
                  delete alongside it once an exporter reads this field.",
    },
    AllowlistEntry {
        struct_name: "TracingConfig",
        field_name: "sample_ratio",
        kind: EntryKind::KnownInert,
        reason: "Same WP-51 increment 3 gap as ConfigSnapshot.tracing above -- \
                  delete alongside it once the runtime that mints root spans \
                  reads this field (see TracingConfig's doc for the sampling \
                  contract it must satisfy).",
    },
];

/// A `pub struct` block parsed out of `ir.rs`, with its `pub` field names.
struct ParsedStruct {
    name: String,
    fields: Vec<String>,
}

/// Extract every `pub struct` and its `pub`-visible named fields from `ir.rs`.
///
/// This is a line-based scanner, not a real parser: it works because every
/// struct body in `ir.rs` is flat (no field type spans multiple lines, no
/// nested `{ }` inside a struct body — those only appear in enum variants,
/// which this scanner ignores entirely since it only triggers on `pub struct`).
/// Tuple structs (`pub struct Foo(pub u64);`) have no named fields to read via
/// `.field`, so they're skipped.
fn parse_structs(source: &str) -> Vec<ParsedStruct> {
    let mut structs = Vec::new();
    let mut lines = source.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("pub struct ") else {
            continue;
        };
        // Tuple struct / unit struct: declaration contains '(' before '{' (or
        // has no '{' at all, e.g. `pub struct Foo(pub u64);`). Skip — no named
        // fields to track.
        if rest.contains('(') {
            continue;
        }
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        // Find the opening brace, which may be on this line or the next
        // (generics/where-clauses could push it down, though none of today's
        // IR structs do that).
        let mut depth: i32 =
            trimmed.matches('{').count() as i32 - trimmed.matches('}').count() as i32;
        if depth == 0 {
            // No brace on the declaration line yet (or a one-line unit
            // struct with no body at all) — look at the next line.
            continue;
        }
        let mut fields = Vec::new();
        while depth > 0 {
            let Some(body_line) = lines.next() else {
                break;
            };
            depth += body_line.matches('{').count() as i32 - body_line.matches('}').count() as i32;
            let body_trimmed = body_line.trim_start();
            if let Some(field_rest) = body_trimmed.strip_prefix("pub ") {
                if let Some(colon) = field_rest.find(':') {
                    let field_name = field_rest[..colon].trim();
                    // Reject anything that isn't a plain identifier (guards
                    // against accidentally matching `pub fn foo(...)` inside a
                    // struct — none exist today, but the check is cheap).
                    if !field_name.is_empty()
                        && field_name.chars().all(|c| c.is_alphanumeric() || c == '_')
                    {
                        fields.push(field_name.to_string());
                    }
                }
            }
        }
        structs.push(ParsedStruct { name, fields });
    }
    structs
}

/// Recursively collect every `.rs` file under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// True if any file under `roots` reads field `field_name` via `.field_name`
/// (a dot immediately followed by the field's identifier, not itself preceded
/// or followed by an identifier character — i.e. not a substring of a longer
/// name, and not e.g. `::field_name`).
fn has_reader(field_name: &str, roots: &[PathBuf]) -> bool {
    let needle_suffix = field_name;
    for root in roots {
        let mut files = Vec::new();
        collect_rs_files(root, &mut files);
        for file in files {
            let Ok(contents) = fs::read_to_string(&file) else {
                continue;
            };
            let bytes = contents.as_bytes();
            let mut search_from = 0;
            while let Some(rel) = contents[search_from..].find(needle_suffix) {
                let idx = search_from + rel;
                // Rust note: manual boundary check instead of pulling in a
                // regex here — `has_reader` runs O(fields * files), and this
                // avoids compiling a fresh pattern per field for a workspace
                // this size. The IR's own matcher code uses `regex::Regex`
                // where the pattern is genuinely data-driven; this isn't.
                let preceded_by_dot = idx > 0 && bytes[idx - 1] == b'.';
                let prev_not_ident = idx == 0
                    || !(bytes[idx - 1] as char).is_alphanumeric() && bytes[idx - 1] != b'_';
                let after = idx + needle_suffix.len();
                let next_not_ident = after >= bytes.len()
                    || !(bytes[after] as char).is_alphanumeric() && bytes[after] != b'_';
                // Immediately before the match must be a `.` and not part of a
                // longer identifier (`prev_not_ident` is trivially true here
                // since the char right before is `.`, kept for clarity/symmetry).
                let _ = prev_not_ident;
                if preceded_by_dot && next_not_ident {
                    return true;
                }
                search_from = idx + 1;
            }
        }
    }
    false
}

fn repo_root() -> PathBuf {
    // Rust note: `CARGO_MANIFEST_DIR` is set by cargo at build time to this
    // crate's directory (`.../crates/proxy-config`); walk up two levels to
    // the workspace root.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("proxy-config sits at <repo>/crates/proxy-config")
        .to_path_buf()
}

fn allowlisted(struct_name: &str, field_name: &str) -> Option<&'static AllowlistEntry> {
    ALLOWLIST
        .iter()
        .find(|e| e.struct_name == struct_name && e.field_name == field_name)
}

#[test]
fn every_ir_field_has_a_runtime_reader() {
    let root = repo_root();
    let ir_path = root.join("crates/proxy-config/src/ir.rs");
    let source = fs::read_to_string(&ir_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", ir_path.display()));
    let structs = parse_structs(&source);
    assert!(
        !structs.is_empty(),
        "parsed zero `pub struct` blocks out of ir.rs — the scanner in \
         ir_readership.rs is out of sync with the file's shape, fix the parser"
    );

    let runtime_roots: Vec<PathBuf> = RUNTIME_CRATES
        .iter()
        .map(|c| root.join("crates").join(c).join("src"))
        .collect();
    for (crate_name, r) in RUNTIME_CRATES.iter().zip(&runtime_roots) {
        assert!(
            r.is_dir(),
            "expected runtime crate `{crate_name}` at {} — update RUNTIME_CRATES \
             if it moved or was renamed",
            r.display()
        );
    }

    let mut unread: Vec<(String, String)> = Vec::new();
    let mut used_allowlist_entries: BTreeMap<(&str, &str), bool> = ALLOWLIST
        .iter()
        .map(|e| ((e.struct_name, e.field_name), false))
        .collect();

    for s in &structs {
        for field in &s.fields {
            if let Some(entry) = allowlisted(&s.name, field) {
                used_allowlist_entries.insert((entry.struct_name, entry.field_name), true);
                continue;
            }
            if !has_reader(field, &runtime_roots) {
                unread.push((s.name.clone(), field.clone()));
            }
        }
    }

    if !unread.is_empty() {
        let mut msg = String::from(
            "IR field(s) are lowered into ir.rs but have no reader in any runtime \
             crate (proxy-http/proxy-core/proxy-cluster/proxy-filters/proxy-admin/proxy-xds).\n\
             Either wire up the runtime code that consumes the field, or — if this \
             is a genuine false positive or a known-inert field with an owning WP —\n\
             add a reasoned entry to ALLOWLIST in crates/proxy-config/tests/ir_readership.rs.\n\n\
             Unread fields:\n",
        );
        for (struct_name, field_name) in &unread {
            msg.push_str(&format!("  - {struct_name}.{field_name}\n"));
        }
        panic!("{msg}");
    }
}

/// An allowlist entry that no longer applies (its field now has a real
/// runtime reader, or the struct/field it names no longer exists in `ir.rs`)
/// must fail this test — otherwise the allowlist only ever grows.
#[test]
fn allowlist_has_no_stale_entries() {
    let root = repo_root();
    let ir_path = root.join("crates/proxy-config/src/ir.rs");
    let source = fs::read_to_string(&ir_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", ir_path.display()));
    let structs = parse_structs(&source);

    let runtime_roots: Vec<PathBuf> = RUNTIME_CRATES
        .iter()
        .map(|c| root.join("crates").join(c).join("src"))
        .collect();

    for entry in ALLOWLIST {
        let owning_struct = structs.iter().find(|s| s.name == entry.struct_name);
        let owning_struct = owning_struct.unwrap_or_else(|| {
            panic!(
                "allowlist entry `{}.{}` names a struct that no longer exists in \
                 ir.rs — remove the stale entry (reason on file: {})",
                entry.struct_name, entry.field_name, entry.reason
            )
        });
        assert!(
            owning_struct.fields.iter().any(|f| f == entry.field_name),
            "allowlist entry `{}.{}` names a field that no longer exists on that \
             struct in ir.rs — remove the stale entry (reason on file: {})",
            entry.struct_name,
            entry.field_name,
            entry.reason
        );
        // `ConsumedInternally` entries (e.g. `VirtualHostIR.domains`, read by
        // `RouteTable::new` inside proxy-config) will never show up as read
        // by `has_reader()` against the runtime crates — that's exactly why
        // they're allowlisted, not a staleness signal. `KnownInertNameCollision`
        // entries can't be auto-rechecked either, for the opposite reason: an
        // unrelated same-named field elsewhere already reads as "found", so
        // the assertion would always fail even while the entry stays correct.
        // Only plain `KnownInert` entries should start failing this assertion
        // (proving they're stale) the moment their owning WP wires up a real
        // reader.
        if entry.kind == EntryKind::ConsumedInternally
            || entry.kind == EntryKind::KnownInertNameCollision
        {
            continue;
        }
        assert!(
            !has_reader(entry.field_name, &runtime_roots),
            "allowlist entry `{}.{}` now has a runtime reader — the field is no \
             longer inert, remove this stale entry (it was: {})",
            entry.struct_name,
            entry.field_name,
            entry.reason
        );
    }
}
