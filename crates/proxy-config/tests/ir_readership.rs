//! A CI guard against "IR field lowered but never read".
//!
//! Motivation (read before touching the allowlist): `RouteEntry.request_headers_to_add`
//! was lowered correctly by both config front-ends and read by no runtime code at
//! all — it's how the config dialect injects provider API keys, so every request
//! reached its provider with no credentials. Strict mode (AGENTS.md invariant 1) could not
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
/// excluded — AGENTS.md invariant 2 says the data plane consumes the IR, and a field
/// read only inside `proxy-config` (e.g. by `RouteTable::new`'s precomputed
/// index) does not prove anything runs on it at request time.
///
/// **`proxy-admin` is excluded for the same reason, and the reason is worth
/// stating because it was NOT excluded originally.** It was listed here while
/// it was an empty stub, where the choice cost nothing. Once `proxy-admin` gained
/// `/config_dump`, that stopped being true: the dump renders IR fields for
/// display, so every field it touches acquires a `.field` reference and would
/// silently satisfy this guard. `HttpConnectionManagerConfig.stat_prefix` is
/// what caught it — the dump rendered it and the staleness check immediately
/// declared its allowlist entry obsolete, even though nothing yet *acts* on
/// the field (that is still outstanding).
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
    /// The field HAS a real reader and is acted on in production -- the
    /// reader just lives outside [`RUNTIME_CRATES`], on the control side
    /// (`proxy`, `proxy-admin`, `proxy-observability`). Nothing here is
    /// pending: this is the text-based scan's blind spot, not a gap in the
    /// data plane, and the entry stays for as long as the reader lives where
    /// it does. Added 2026-09-08, because filing these as `KnownInert` said
    /// something false -- `ConfigSnapshot.admin`'s reason claimed
    /// `proxy-admin` was a stub long after it had grown to 1917 lines and
    /// `main.rs` was binding the address this field carries.
    ///
    /// The staleness recheck still applies: a reader appearing inside
    /// `RUNTIME_CRATES` means the field no longer needs an exemption at all.
    /// The reason string must name the reader, by path, so it can be
    /// re-verified by hand.
    ReadOutsideRuntimeCrates,
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
    // --- Downstream admission limits: the IR lands first (shared interface), the
    //     listener/codec enforcement follows. Delete these entries when it does.
    AllowlistEntry {
        struct_name: "ConfigSnapshot",
        field_name: "max_downstream_connections",
        kind: EntryKind::KnownInert,
        reason: "Lowered from bootstrap overload_manager; the accept loop does not enforce it yet.",
    },
    AllowlistEntry {
        struct_name: "ListenerConfig",
        field_name: "ignore_global_conn_limit",
        kind: EntryKind::KnownInert,
        reason: "Exempts a listener from max_downstream_connections; inert until that cap is enforced.",
    },
    AllowlistEntry {
        struct_name: "HttpConnectionManagerConfig",
        field_name: "request_headers_timeout",
        kind: EntryKind::KnownInert,
        reason: "Lowered from the HCM; the codec does not enforce the header deadline yet.",
    },
    AllowlistEntry {
        struct_name: "HttpConnectionManagerConfig",
        field_name: "request_timeout",
        kind: EntryKind::KnownInert,
        reason: "Lowered from the HCM; the request deadline is not enforced yet.",
    },
    // --- The ADS config surface, lowered but not yet consumed. One of the
    //     original five has left: `AdsConfig.node` now reaches the wire, and
    //     the change that noticed found this entry's own reason had been
    //     wrong for a while. That is worth
    //     remembering, because this file could not have caught it: an unset
    //     field is inert either way, so the list stayed green while every
    //     DiscoveryRequest went out anonymous. The four below are genuinely
    //     still inert; each says what will read it.
    AllowlistEntry {
        struct_name: "AdsConfig",
        field_name: "initial_fetch_timeout",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "crates/proxy/src/main.rs::run_serve reads this field \
                 when building its readiness probe, so an ADS-backed \
                 ConfigSource timeout releases /ready without force-initializing \
                 a cluster. `proxy` is control-side and outside RUNTIME_CRATES.",
    },
    AllowlistEntry {
        struct_name: "AdsConfig",
        field_name: "lds_source",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "crates/proxy/src/main.rs owns mixed ADS/filesystem source startup; this control-plane reader is outside RUNTIME_CRATES.",
    },
    AllowlistEntry {
        struct_name: "AdsConfig",
        field_name: "cds_source",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "crates/proxy/src/main.rs owns mixed ADS/filesystem source startup; this control-plane reader is outside RUNTIME_CRATES.",
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
        struct_name: "TcpProxyConfig",
        field_name: "stat_prefix",
        kind: EntryKind::KnownInertNameCollision,
        reason: "Same stats gap as HttpConnectionManagerConfig.stat_prefix \
                  (still outstanding for the TCP proxy's own copy of the \
                  field) — still genuinely inert on THIS struct. Reclassified \
                  from KnownInert because `HttpConnectionManagerConfig`'s \
                  own `stat_prefix` (a DIFFERENT field on a different struct) \
                  now has a real runtime reader (`build_hcm_handler`, \
                  `proxy-core`), and `proxy_http::filter::FactoryContext` \
                  gained an unrelated `stat_prefix: String` field of its own \
                  (read as `ctx.stat_prefix`/`self.stat_prefix` across \
                  proxy-http/proxy-filters/proxy-core) -- the text-based scan \
                  can't tell any of these three same-named fields apart, so \
                  it now finds a `.stat_prefix` read regardless of whether \
                  TcpProxyConfig's own field is ever touched.",
    },
    AllowlistEntry {
        struct_name: "RetryOn",
        field_name: "envoy_ratelimited",
        kind: EntryKind::KnownInert,
        reason: "Lowering rejects `retry_on: envoy-ratelimited` \
                  outright (crates/proxy-config/src/lower.rs) because no \
                  filter sets `x-envoy-ratelimited` (no rate-limit filter exists), so the \
                  field can only ever be `false` in the IR, and retry.rs's \
                  outcome classifier never consults it.",
    },
    AllowlistEntry {
        struct_name: "ConfigSnapshot",
        field_name: "admin",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "Read and acted on by `crates/proxy/src/main.rs`'s `run_serve`, which \
                  passes it to `start_admin` -- the admin listener binds this address, \
                  or does not bind at all when it is `None`. `proxy-admin/src/dump.rs` \
                  renders it into `/config_dump` as well. Neither crate is in \
                  RUNTIME_CRATES, so the scan cannot see either. **The previous reason \
                  here was false and had been for a long time** -- it said `proxy-admin` \
                  was a stub whose `src/lib.rs` did not bind the address, written when \
                  that was true and never revisited; the crate is 1917 lines and \
                  ships the surface. Corrected 2026-09-08. It stayed green throughout, \
                  which is the point of this entry kind: a KnownInert entry whose field \
                  gained a CONTROL-side reader can never go stale on its own.",
    },
    AllowlistEntry {
        struct_name: "ConfigSnapshot",
        field_name: "secrets",
        kind: EntryKind::KnownInertNameCollision,
        reason: "No runtime code looks up a TlsSecret by name \
                  yet (SDS-delivered secrets aren't consulted anywhere outside \
                  proxy-config). Recorded as a NAME COLLISION: \
                  `ResourceApplier` in `crates/proxy-xds/src/apply.rs` gained its own \
                  `secrets` field (a `SotwSet` of SDS-delivered `DynamicSecret`s), and \
                  `has_reader` matches on field name alone, so this reads as covered \
                  while nothing consults `ConfigSnapshot.secrets`. The two are \
                  unrelated: one is the file-config secret ledger, the other is the \
                  xDS subscription cache. Delete when a real reader lands, and \
                  re-verify by hand rather than by the scan.",
    },
    AllowlistEntry {
        struct_name: "TracingConfig",
        field_name: "otlp_endpoint",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "The OTLP exporter that reads this field \
                  (`proxy_observability::otlp::run_trace_exporter`, called from \
                  `crates/proxy/src/main.rs`'s `run_serve`) lives on the \
                  control side, in `proxy-observability`/`proxy` -- neither is \
                  a RUNTIME_CRATES entry (see this file's module doc for why: \
                  `proxy-config` and `proxy-admin` are excluded for the same \
                  'displaying/config-holding is not acting on it' reason, and \
                  `proxy-observability`/`proxy` were never added because \
                  nothing in them consumed IR fields before this one). The \
                  field genuinely has a real reader now -- `ConfigSnapshot.tracing` \
                  and `TracingConfig::sample_ratio` (both read inside \
                  `proxy-http`) prove that by no longer needing an entry here \
                  at all -- this is a known limitation of the text-based scan, \
                  not a second inert field.",
    },
    // --- OTLP metric export. Same shape as the two
    //     `TracingConfig` entries above -- the reader is
    //     `proxy_observability::otlp::run_metric_exporter`, spawned from
    //     `crates/proxy/src/main.rs`'s `run_serve` and running on the control
    //     runtime, which is neither a RUNTIME_CRATES entry nor a
    //     data-plane path (see this file's module doc for why those two facts
    //     are different questions). These fields ARE acted on: an operator who
    //     configures `io.llmproxy.metrics` gets a running exporter task with
    //     exactly this interval, deadline, and endpoint.
    //
    //     `service_name` is deliberately absent from this group because the
    //     scan would have matched it anyway (it collides with
    //     `EdsClusterConfig.service_name`, read by `proxy-xds`) -- which is
    //     exactly the false pass the `KnownInertNameCollision` entries above
    //     exist to flag. It gets no entry at all, because the field genuinely
    //     has no reader this scan can see and pretending otherwise would make
    //     the list longer for no gain.
    AllowlistEntry {
        struct_name: "ConfigSnapshot",
        field_name: "metrics",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "Read at `crates/proxy/src/main.rs`'s \
                  `run_serve` (`snapshot.metrics.as_ref()`), which decides whether to spawn \
                  `proxy_observability::otlp::run_metric_exporter` at all. Control-side \
                  bootstrap wiring, outside RUNTIME_CRATES for the same reason \
                  `ConfigSnapshot.tracing` is -- see the `TracingConfig.otlp_endpoint` entry \
                  above.",
    },
    AllowlistEntry {
        struct_name:"ConfigSnapshot",field_name:"end_user_capture",kind:EntryKind::ReadOutsideRuntimeCrates,
        reason:"Control-side `crates/proxy/src/main.rs` validates runtime concurrency and calls CaptureSupervisor::configure at boot and SIGHUP. The supervisor consumes every policy/budget/endpoint/transport/control setting for admission, queue ownership, delivery, and emergency controls; workers consult its stable handle, not the bootstrap IR. This is a real reader outside RUNTIME_CRATES, not KnownInert.",
    },
    AllowlistEntry {
        struct_name:"ConfigSnapshot",field_name:"end_user_capture_configured",kind:EntryKind::ReadOutsideRuntimeCrates,
        reason:"Control-side `crates/proxy/src/main.rs` uses explicit namespace presence to reject mixing declarative capture (even disabled) with CLI destinations in validate/serve and SIGHUP. Presence has a mode-selection consumer even when the effective policy is None.",
    },
    AllowlistEntry {
        struct_name: "MetricsExportConfig",
        field_name: "otlp_endpoint",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "Passed to \
                  `proxy_observability::otlp::run_metric_exporter` as the OTLP endpoint, \
                  which builds its own lazy `tonic` `Endpoint` from it. The trace path's \
                  equivalent reader is `otlp::run_trace_exporter`; both are control-side.",
    },
    AllowlistEntry {
        struct_name: "MetricsExportConfig",
        field_name: "export_interval",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "Passed to \
                  `proxy_observability::otlp::run_metric_exporter` as its \
                  `tokio::time::interval` period. Independent of the trace exporter's fixed \
                  5s batch interval by design (`docs/telemetry-design.md` §5.3, separate \
                  scheduling), so there is no data-plane reader to find.",
    },
    AllowlistEntry {
        struct_name: "MetricsExportConfig",
        field_name: "export_deadline",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "Passed to \
                  `proxy_observability::otlp::run_metric_exporter` and applied as the \
                  `tokio::time::timeout` around each export RPC. Bounds a collector that \
                  accepts a connection and then stops responding; the trace exporter has no \
                  equivalent today, which is itself a known gap rather than an oversight.",
    },
    AllowlistEntry {
        struct_name: "TracingConfig",
        field_name: "export_deadline",
        kind: EntryKind::ReadOutsideRuntimeCrates,
        reason: "Passed to \
                  `proxy_observability::otlp::run_trace_exporter` as the per-batch export RPC \
                  deadline, closing the gap the `MetricsExportConfig.export_deadline` entry \
                  above used to call out -- a collector that accepts a trace connection and \
                  then goes silent now costs one bounded timeout per attempt instead of \
                  parking the exporter. Control-side, outside RUNTIME_CRATES like its \
                  metric-side twin.",
    },
    AllowlistEntry {
        struct_name: "TracingConfig",
        field_name: "service_name",
        kind: EntryKind::KnownInertNameCollision,
        reason: "Same as `otlp_endpoint` immediately above: read by \
                  `proxy_observability::otlp::build_resource`, which \
                  `run_trace_exporter` calls -- control-side, outside RUNTIME_CRATES. \
                  Reclassified from KnownInert to KnownInertNameCollision because \
                  `EdsClusterConfig.service_name` is a \
                  different field with the same name, and \
                  `proxy-xds/src/apply.rs::eds_resource_names` now reads it \
                  (`eds.service_name`), which the text scan cannot tell apart \
                  from a read of this one. Re-verify this entry by hand.",
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
             is a genuine false positive or a known-inert field with a named owner —\n\
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
        // Only plain `KnownInert` and `ReadOutsideRuntimeCrates` entries
        // should start failing this assertion (proving they're stale) the
        // moment a reader appears inside the runtime crates -- for the
        // former because its owner wired one up, for the latter because
        // the data plane now reads what only the control side read before,
        // which means the exemption is no longer needed at all.
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
