//! WP-23 increments 1–2 and 5 — the stats registry core: instruments,
//! [`Handle`]/[`HistogramHandle`] resolution, sharded, summed counters and
//! histograms, and the [`Registry`]/[`StatsControl`] split that lets
//! resolution survive a config swap. Pure library: no HTTP, no `/stats`
//! rendering, no Prometheus, no instrumentation call sites — rendering is
//! increment 3 (`envoy_render`, this crate), and call sites are increment 6
//! (`internal-docs/IMPLEMENTATION_PLAN.md`, which is normative for every
//! decision below).
//!
//! # Decision 1 — the hot path increments an index, not a name
//!
//! An OTel measurement is `(instrument, attribute set)`. Resolving that per
//! request means hashing an attribute set on the request path, which this
//! proxy cannot afford. So resolution and increment are split:
//!
//! ```
//! use proxy_observability::stats::{instruments, StatsControl, WorkerId};
//!
//! // Control side, once, when a cluster/listener/route enters the config
//! // snapshot. `StatsControl` is the only thing that can `resolve` -- see
//! // "Increment 5" below for why that is a type, not a receiver, split.
//! let control = StatsControl::new(1);
//! let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "provider:openai")]);
//!
//! // Hot path, per request: no hashing, no allocation, no string. Workers
//! // only ever hold the `Arc<Registry>` `StatsControl::registry` hands out.
//! let registry = control.registry();
//! registry.incr(WorkerId(0), h, 1);
//! ```
//!
//! [`Handle`] is an opaque index. **There is no way to increment by name** —
//! no `counter("x").with(..).inc()`, no `incr_by_name`. That is deliberate:
//! the tempting by-name API is the one that quietly puts a hash back on the
//! request path, one call site at a time.
//!
//! # Decision 2 — per-worker shards, and the shard is never the metric
//!
//! ADR-0005 names the trap: with N workers, a per-worker counter that never
//! aggregates is wrong by the worker count (the same mistake made a token
//! budget wrong by N — see `proxy_filters::token_limit`'s module doc for that
//! story). [`Registry`] lays out one contiguous shard per worker, indexed by
//! [`WorkerId`], each shard holding one slot per handle. A worker only ever
//! touches its own shard, so two workers never write the same cache line and
//! `Relaxed` increments never contend. Histograms (below) use exactly the
//! same layout and the same summed-read rule — nothing about sharding
//! changes for bucketed data.
//!
//! ```text
//! value(handle) = Σ over workers of shard[worker][handle]
//! ```
//!
//! **No public accessor returns a single shard's slot.** [`Registry::value`]
//! sums; that is the only read. [`Registry::shard_values_for_debugging`]
//! exists for tests only — the name is the friction, so a reviewer sees
//! immediately when someone reaches for the un-summed figure. Histograms get
//! the equivalent pair: [`Registry::histogram_snapshot`] (summed, the only
//! read) and [`Registry::histogram_shard_snapshots_for_debugging`].
//!
//! `Relaxed` ordering, on both increment and read: these are counters, not
//! synchronization. Nothing else is published through them, and a scrape
//! landing mid-increment is allowed to observe either the old or the new
//! value — it must not be a fence on the request path.
//!
//! # Increment 5 — resolution survives a config swap: split the API by TYPE
//!
//! Increment 1's `Registry::resolve` took `&mut self`, on the theory that
//! "resolution cannot race an increment" should be a compiler-checked
//! property. That reasoning was sound and the conclusion was still wrong: the
//! registry is shared as `Arc<Registry>` from process start
//! (`crates/proxy/src/main.rs`), so `&mut self` becomes unobtainable the
//! moment it is shared. Handles could only ever be resolved at boot, and a
//! config swap that introduced a new cluster could never register its
//! counters — the new cluster would serve traffic and report nothing,
//! silently, forever. See `internal-docs/IMPLEMENTATION_PLAN.md`'s "Correction,
//! 2026-08-09" section for the full argument.
//!
//! The fix keeps the compile-time guarantee, but moves it from a *receiver*
//! split (`&mut self` vs `&self`) to a *type* split:
//!
//! - [`Registry`] is the shared, hot-path type. Every method takes `&self`.
//!   **It has no public `resolve`/`resolve_histogram` at all** — a worker
//!   holding only `Arc<Registry>` cannot grow the registry for an
//!   attribute value this process's OWN config didn't already name at boot,
//!   and that is checked by the compiler rather than by a debug assertion
//!   or a comment. [`Registry::resolve_capped`] (WP-55) is the one deliberate,
//!   narrow exception — see its own doc for why: it exists for exactly one
//!   dimension (`tenant`, on `llm.client.token.usage`) whose values are NOT
//!   this process's own config, and it is capped rather than general.
//! - [`StatsControl`] is the control-side owner: it is the *only* type
//!   exposing [`StatsControl::resolve`]/[`StatsControl::resolve_histogram`].
//!   It is deliberately not `Clone` — there is exactly one control side per
//!   process. [`StatsControl::registry`] is what gets handed to workers.
//!
//! The real resolution logic lives in private `Registry` methods that only
//! `StatsControl` (defined in this same module) can call; the methods simply
//! aren't `pub`, so they don't exist as far as any other crate — including a
//! worker holding `Arc<Registry>` — is concerned.
//!
//! ## Interior mutability: one `ArcSwap` snapshot, a `Mutex` only on the control side
//!
//! Resolution now takes `&self` and reaches its state through interior
//! mutability, split into exactly the pieces each side needs:
//!
//! ```text
//! struct Registry {
//!     published: ArcSwap<Snapshot>,   // hot path: lock-free load
//!     control: Mutex<ControlState>,   // touched ONLY by resolve/resolve_histogram
//! }
//! ```
//!
//! `Snapshot` (private) is an immutable, versioned bundle of *everything* a
//! reader needs: the per-handle instrument metadata (`resolved`,
//! `resolved_attrs`, `resolved_histograms`, `resolved_histogram_attrs`) and
//! the shard storage itself. Bundling both together means a `Snapshot` a
//! worker loads is always internally consistent — it can never see a new
//! handle's metadata without also seeing that handle's shard slot, or vice
//! versa. Growth builds a whole new `Snapshot` and swaps it in;
//! `incr`/`value`/`observe`/etc. do one lock-free `published.load()` and read
//! everything out of the `Arc<Snapshot>` they get back. `ControlState`
//! (private) holds only the dedup maps (`lookup`, `histogram_lookup`) —
//! nothing on the request path ever takes that lock.
//!
//! This is the same "control computes, workers `load`" shape
//! `proxy_cluster::manager::ClusterManager` already uses for `HostSet`, and
//! the auth filter uses for its key set — not a new mechanism, a pattern this
//! codebase already reads fluently.
//!
//! ## Growth must not move or copy a live atomic — the crux of the whole design
//!
//! Rebuilding the registry on every config swap and copying counter values
//! across was considered and rejected: any increment landing between the old
//! snapshot's read and the new registry's publish is lost, which shows up as
//! a dip in `rate()` at every reload — a metrics bug that gets blamed on the
//! traffic, not the reload. But a naive `ArcSwap<Vec<AtomicU64>>` has the
//! *identical* bug: a `Vec` that reallocates on push moves every element,
//! including the ones concurrent writers are mid-`fetch_add` on.
//!
//! The fix is that growth never moves an atomic that already has a handle —
//! it only ever *appends*, and only ever behind another layer of `Arc` so
//! that "appending" is "cloning a `Vec` of pointers", not "reallocating the
//! things the pointers point to":
//!
//! - **Counters are worker-major and block-chunked**
//!   (`counter_shards: Vec<Vec<Arc<Vec<AtomicU64>>>>`, indexed
//!   `[worker][block]`, each block exactly [`COUNTER_BLOCK_LEN`] slots wide).
//!   A [`Handle`] indexes as `block = handle.0 / COUNTER_BLOCK_LEN`,
//!   `slot = handle.0 % COUNTER_BLOCK_LEN`. Growing by one handle clones the
//!   outer `Vec<Vec<Arc<..>>>` (copying only `Arc` pointers — every existing
//!   `AtomicU64` stays at the exact address it was at, still receiving
//!   increments from any thread holding the old `Snapshot`) and, only when
//!   the new handle starts a fresh block, appends one freshly-allocated
//!   `Arc<Vec<AtomicU64>>` block per worker. Blocks, not one `Arc<AtomicU64>`
//!   per slot, because Decision 2 above depends on per-worker
//!   *contiguity* — one `Arc` per slot would allocate worker 0's and worker
//!   1's slot for the same handle back-to-back in the growth loop, putting
//!   two different workers' counters on one cache line, exactly the false
//!   sharing Decision 2 exists to avoid. A block keeps one worker's counters
//!   contiguous within it and puts different workers in entirely separate
//!   allocations.
//! - **Histograms are one `Arc<HistogramShard>` per `(worker, handle)`**
//!   (`histogram_shards: Vec<Vec<Arc<HistogramShard>>>`, indexed
//!   `[worker][handle]`, no blocking). A histogram's bucket count varies per
//!   instrument (see [`ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS`] vs. a
//!   differently-bucketed instrument), so a fixed-size block scheme doesn't
//!   apply the way it does for the single-`AtomicU64` counter case. A
//!   [`HistogramShard`] is already north of 176 bytes (twenty-plus
//!   `AtomicU64` buckets, a sum, a count), so distinct per-handle allocations
//!   rarely share a cache line even without blocking, and [`Registry::observe`]
//!   is already three atomic operations — the false-sharing cost blocks avoid
//!   for a single `u64` counter matters much less against that backdrop.
//!
//! Handle values are stable across growth either way: a [`Handle`]/
//! [`HistogramHandle`] resolved before a swap indexes the exact same logical
//! counter/histogram after it, because growth only ever appends past the end
//! of what already existed.
//!
//! `Relaxed` ordering is unchanged everywhere on the increment/read path —
//! growth publishing a new `Snapshot` doesn't change what a plain counter
//! increment needs to synchronize with.
//!
//! # Decision 3 — this is not ADR-0005's distributed case
//!
//! Stats are *not* shared across replicas — each replica reports its own
//! counters and the time-series database sums them, same as any Prometheus
//! deployment. What ADR-0005 actually asks for here is the *intra-process*
//! aggregation above (across workers, not across replicas); see the design
//! brief's Decision 3 for the full argument against forcing a `StatsStore`
//! trait onto this subsystem.
//!
//! # Decision 5 — the semconv version is pinned in code
//!
//! [`SEMCONV_VERSION`] names the OTel semantic-conventions revision this
//! module's instrument names/attributes were written against. The GenAI
//! conventions are experimental upstream and have already churned once
//! (`gen_ai.usage.prompt_tokens` → `gen_ai.usage.input_tokens`). **Bumping
//! this constant is a breaking change to the metric surface** — for anyone
//! with a dashboard built on these names, it is exactly that — and belongs
//! in the CHANGELOG under a heading that says so.
//!
//! # Increment 2 — histograms
//!
//! ## Storage: non-cumulative bucket counts, `sum`, and `count`
//!
//! Each `(handle, worker)` slot stores a fixed array of **non-cumulative**
//! per-bucket counts (bucket `i` holds only the observations that landed in
//! bucket `i`, not "bucket `i` and below"), plus a running `sum` and a
//! running `count`. An observation is therefore "find the bucket, bump one
//! slot" — O(1) and allocation-free — rather than walking or rewriting every
//! bucket >= the observed value on every call. The opposite choice (storing
//! cumulative counts so a bucket bump touches every following bucket) is
//! tempting because it makes rendering trivial, but it moves O(n) work onto
//! the hot path to save O(n) work in the renderer, which runs orders of
//! magnitude less often. Cumulative (`le`) counts are a prefix-sum over
//! `bucket_counts`, computed where they're needed — [`Registry::percentile`]
//! here, the increment-3/4 renderers later — never stored.
//!
//! ## The overflow bucket
//!
//! Nineteen boundaries means **twenty** slots: one bucket per boundary for
//! `value <= boundary[i]`, plus one overflow bucket (Prometheus's `+Inf`)
//! for anything above the last boundary. `bucket_counts.len() ==
//! boundaries.len() + 1` throughout this module — getting that off by one
//! is the classic histogram bug, and [`ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS`]'s
//! test pins the count explicitly for exactly that reason.
//!
//! Boundaries are **inclusive** (Prometheus `le` semantics: a value exactly
//! equal to `boundary[i]` lands in bucket `i`, not `i + 1`) — see
//! [`Registry::observe`].
//!
//! ## Why not `hdrhistogram`
//!
//! It is already a workspace dependency (`testing/loadgen`), so it is worth
//! writing down why it doesn't belong here rather than leaving that as an
//! unasked question:
//!
//! - OTel explicit-bucket histograms and Prometheus both want **fixed,
//!   declared boundaries** that every scrape/export can rely on staying the
//!   same. `hdrhistogram`'s dynamic-precision buckets don't map onto a fixed
//!   boundary set without re-bucketing on every render — which reintroduces
//!   the O(n)-per-render cost this design avoids, just moved to a different
//!   place.
//! - Merging `hdrhistogram`s across worker shards is real, non-trivial work
//!   (it has its own merge algorithm and allocates). Summing twenty `u64`s,
//!   as this module does, is not.
//! - The hot path must not allocate. A fixed array satisfies that trivially;
//!   `hdrhistogram`'s dynamic structures do not offer the same guarantee.
//!
//! ## Percentiles live here, not in the `/stats` renderer
//!
//! Envoy's text `/stats` format reports **interpolated percentiles** (P0,
//! P25, P50, P75, P90, P95, P99, P99.5, P99.9, P100), not raw buckets. The
//! interpolation arithmetic is a pure function of bucket counts and belongs
//! next to the data structure that owns them — [`Registry::percentile`] —
//! rather than being reinvented inside increment 3's string formatting.
//!
//! ## The handle-space question: histogram handles are their own type
//!
//! [`HistogramHandle`] is a distinct type from [`Handle`], not the same
//! `usize` space reused. Concretely, that means a `Handle` returned by
//! [`StatsControl::resolve`] **cannot be passed to** [`Registry::observe`],
//! and a `HistogramHandle` returned by [`StatsControl::resolve_histogram`]
//! **cannot be passed to** [`Registry::incr`]/[`Registry::add`]/
//! [`Registry::value`] — not "rejected at runtime", but a compile error,
//! because the two types are unrelated as far as the type checker is
//! concerned. See [`HistogramHandle`]'s doc for a `compile_fail` example
//! proving this.
//!
//! This is the same argument as the `Registry`/`StatsControl` type split
//! above: making a mistake *impossible* is strictly better than making it
//! *loud*, when the type system can carry the whole cost at zero runtime
//! price (a `HistogramHandle` is exactly as cheap as a `Handle` — one
//! `usize`). A
//! shared handle space was the other defensible option (it would mean one
//! index space and a runtime `kind` check inside `incr`/`observe`), but it
//! trades a compile-time guarantee for a runtime one for no benefit, since
//! nothing needs `Handle` and `HistogramHandle` to be interchangeable. As a
//! second line of defense — because a *kind* mismatch is still possible even
//! with separate handle types, e.g. calling `resolve` on a `Histogram`
//! instrument — both `resolve` and `resolve_histogram` assert the
//! instrument's `InstrumentKind` up front and panic loudly (control-side
//! only, so this can never fire on the request path) rather than silently
//! handing back a handle that the wrong storage shape backs.
//!
//! ## One unit mismatch, recorded but not solved here
//!
//! Envoy's `rq_time` is **milliseconds**; OTel's semconv duration
//! instruments (e.g. `http.client.request.duration`) are **seconds**
//! (float). Both are legitimate — an [`Instrument`] declares its own `unit`
//! and its own bucket boundaries together (see
//! [`instruments::UPSTREAM_RQ_TIME`], which carries Envoy's millisecond
//! buckets), so nothing here assumes one global unit. **This module never
//! converts between them.** A future seconds-based semconv histogram would
//! carry OTel's own default boundaries under its own `unit`, unconverted.
//! Reconciling the two into one rendered number (if increments 3/4 ever need
//! to) is the *renderer's* problem, not the registry's — this comment is
//! here so whoever writes that renderer finds the warning instead of
//! rediscovering the bug.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// Rust note: `ArcSwap<Snapshot>` is the same "control computes, workers
// `load`" pattern `proxy_cluster::manager::ClusterManager` uses for
// `HostSet`, and the auth filter uses for its key set -- see the module
// doc's "Increment 5" section for why plain `&mut self` couldn't survive a
// config swap once this registry is shared as `Arc<Registry>`.
use arc_swap::ArcSwap;

/// WP-23 increment 3: renders a [`Registry`] into Envoy's flat `/stats` text
/// format. See the module's own doc comment for what is and is not verified
/// about that format.
pub mod envoy_render;

/// WP-23 increment 4: renders a [`Registry`] into Prometheus text exposition
/// format, with Envoy's own name-mangling/label-escaping rules. See the
/// module's own doc comment for how this deliberately differs from
/// [`envoy_render`]'s per-attribute-value name expansion.
pub mod prometheus_render;

/// WP-23 increment 4's Grafana-dashboard conformance test -- provisional,
/// see the module's own doc comment for why.
#[cfg(test)]
mod prometheus_conformance;

/// The OTel semantic-conventions revision this module's instrument names and
/// attribute keys were written against. See the module doc's "Decision 5" —
/// changing this value is a breaking change to the metric surface and must
/// be called out in the CHANGELOG, not just bumped in passing.
pub const SEMCONV_VERSION: &str = "1.27.0";

/// Envoy's default `rq_time`-family histogram bucket boundaries, in
/// **milliseconds**. Vendored verbatim from
/// `crates/proxy-api/vendor/envoy/config/metrics/v3/stats.proto`, lines
/// 86–104 (the `histogram_bucket_settings` field's doc comment, "the
/// following default buckets are used"). Nineteen boundaries, so any
/// histogram using this set has **twenty** bucket slots — see the module
/// doc's "overflow bucket" section.
///
/// Changing these values is a breaking change to anyone's dashboard, the
/// same standing this module gives [`SEMCONV_VERSION`] — a bucket boundary
/// changing shifts every rate/percentile query built against the old edges.
/// `tests::envoy_default_histogram_buckets_are_pinned` pins all nineteen.
pub const ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS: [f64; 19] = [
    0.5, 1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0, 10000.0, 30000.0,
    60000.0, 300000.0, 600000.0, 1800000.0, 3600000.0,
];

/// OTel GenAI v1.27's recommended explicit boundaries for time to first
/// token, in seconds. These deliberately do not reuse Envoy's millisecond
/// request-time buckets: an instrument's unit and its boundaries are one
/// contract, and these names are exported through OTLP as OTel metrics.
pub const GEN_AI_TIME_TO_FIRST_TOKEN_BUCKETS_SECONDS: [f64; 16] = [
    0.001, 0.005, 0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

/// OTel GenAI v1.27's recommended explicit boundaries for time per output
/// token, in seconds.
pub const GEN_AI_TIME_PER_OUTPUT_TOKEN_BUCKETS_SECONDS: [f64; 13] = [
    0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.4, 0.5, 0.75, 1.0, 2.5,
];

/// Which OTel instrument shape a metric follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentKind {
    /// Monotonically increasing. [`Registry::incr`] is the only way to move
    /// one; there is no decrement — see [`Registry::add`]'s doc for why that
    /// is enforced, not just conventional.
    Counter,
    /// May move in either direction. [`Registry::incr`] (always up) and
    /// [`Registry::add`] (signed delta, either direction) both work.
    UpDownCounter,
    /// Bucketed observations. [`Registry::resolve_histogram`] and
    /// [`Registry::observe`] are the only ways to build and move one — see
    /// the module doc's "Increment 2" section for the storage and handle-
    /// space design.
    Histogram,
}

/// One OTel instrument's identity and shape: a name, a unit, and the set of
/// attribute keys every measurement against it must supply — no more, no
/// fewer. [`StatsControl::resolve`]/[`StatsControl::resolve_histogram`] check
/// a caller's attributes against `attribute_keys`, order-insensitively, and
/// panic loudly on a mismatch rather than silently starting a second,
/// parallel time series for a typo'd key.
#[derive(Debug)]
pub struct Instrument {
    /// OTel semantic-conventions name (or this proxy's own gateway-metrics
    /// name where OTel has no upstream identity — each `pub const` below
    /// says which).
    pub name: &'static str,
    pub kind: InstrumentKind,
    /// UCUM-style unit string (`"{request}"`, `"{token}"`, `"ms"`, ...),
    /// following OTel's own convention for instrument units. See the module
    /// doc's "unit mismatch" note: a millisecond instrument and a
    /// seconds-based instrument can coexist, unconverted, each carrying its
    /// own `unit` and its own `buckets`.
    pub unit: &'static str,
    /// The attribute keys a measurement against this instrument must supply
    /// — exactly these, in any order. See [`StatsControl::resolve`].
    pub attribute_keys: &'static [&'static str],
    /// Histogram bucket boundaries, in `unit`, ascending, exclusive of the
    /// implicit overflow bucket. `Some` if and only if `kind` is
    /// [`InstrumentKind::Histogram`] — [`StatsControl::resolve_histogram`] and
    /// [`Registry::observe`] both rely on that invariant and panic loudly if
    /// it doesn't hold (a `Histogram` instrument with `None` here is a
    /// programming error in the instrument's own `const` definition, not
    /// something a caller can trigger).
    pub buckets: Option<&'static [f64]>,
}

/// A small starter set of instruments — enough to exercise the resolve/incr/
/// value/observe model end to end, not the full Envoy stats surface (that is
/// increment 5). Named `instruments` so call sites read as
/// `instruments::UPSTREAM_RQ`, matching the design brief's own examples.
pub mod instruments {
    use super::{
        Instrument, InstrumentKind, ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS,
        GEN_AI_TIME_PER_OUTPUT_TOKEN_BUCKETS_SECONDS, GEN_AI_TIME_TO_FIRST_TOKEN_BUCKETS_SECONDS,
    };

    /// Upstream requests issued to a cluster, one per request.
    ///
    /// This proxy's own gateway-metrics identity, not an upstream OTel
    /// semantic-conventions name — OTel has no generic "request count"
    /// counter (`http.client.request.duration`'s histogram implies a count,
    /// but does not name one). The name mirrors Envoy's own `upstream_rq`
    /// stat family directly (see the design brief, Decision 4) so the
    /// increment-3 `/stats` renderer has an obvious mapping:
    /// `cluster.<name>.upstream_rq_total`.
    pub const UPSTREAM_RQ: Instrument = Instrument {
        name: "upstream_rq",
        kind: InstrumentKind::Counter,
        unit: "{request}",
        attribute_keys: &["cluster"],
        buckets: None,
    };

    /// Downstream connections accepted on a listener.
    ///
    /// Same situation as [`UPSTREAM_RQ`]: no upstream OTel identity for
    /// "connections accepted", so this mirrors Envoy's own
    /// `downstream_cx_total` stat directly.
    pub const DOWNSTREAM_CX_TOTAL: Instrument = Instrument {
        name: "downstream_cx_total",
        kind: InstrumentKind::Counter,
        unit: "{connection}",
        attribute_keys: &["listener"],
        buckets: None,
    };

    /// Tokens consumed by a GenAI request/response exchange. **Has no Envoy
    /// equivalent** — Envoy predates LLM gateways — so this renders to
    /// nothing in the increment-3 `/stats` text output; it exists in
    /// Prometheus/OTLP output only (design brief, Decision 4, point 2).
    ///
    /// WP-51 increment 1: this is deliberately our own `llm.*` name, not the
    /// OTel GenAI semconv name for the equivalent instrument. Semconv's
    /// `gen_ai.usage.input_tokens` attribute is INCLUSIVE of the cached
    /// portion; our `type="input"` bucket (like `TokenUsage::input_tokens`,
    /// `proxy-filters/src/usage.rs:45`) deliberately EXCLUDES it so that
    /// `input`/`output`/`cached`/`cache_creation` sum to the total without
    /// double-counting. Shipping this under the semconv name would
    /// under-count input by exactly the cached portion on the field people
    /// bill from — the same "standard name, non-standard meaning" problem
    /// already rejected for the `%LLM_*%` access-log operators (see
    /// `access_log.rs`). Hence a proprietary `llm.*` name, not a borrowed
    /// semconv one.
    ///
    /// The upstream semconv equivalent is defined as a *histogram* (a
    /// per-request token count distribution), not a counter. This starter
    /// still models it as a running-total `Counter` rather than switching it
    /// to a `Histogram` now that increment 2 has landed — that switch needs
    /// its own bucket boundaries (OTel doesn't mandate Envoy's millisecond
    /// `rq_time` set for a token count) and is increment 5's call, not this
    /// one's. Keeping it a `Counter` here avoids guessing at that number
    /// now. Attribute keys (`provider`, `type`) match the design brief's own
    /// table rather than semconv's fully qualified attribute names; the
    /// increment-4 Prometheus renderer is where full key names matter.
    ///
    /// WP-55: `tenant` is the third attribute key, added so operators can
    /// build per-tenant usage dashboards over OTel export (the owner's
    /// (a)-export-only decision — see `internal-docs/IMPLEMENTATION_PLAN.md`
    /// WP-55 — this proxy never owns a usage datastore). Named `tenant`, not
    /// `gen_ai.*` anything: there is no upstream semconv attribute for this
    /// at all (semconv has no multi-tenancy concept), so there is no
    /// borrowed name to get wrong the way `llm.*` vs `gen_ai.*` was for the
    /// instrument name itself. The value is `StreamInfo::auth.tenant` — the
    /// id the auth filter resolved from the caller's own credential, never a
    /// caller-supplied parameter — verbatim; see
    /// [`LLM_CLIENT_TOKEN_USAGE_NO_TENANT`] for the unauthenticated case and
    /// [`LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW`]/
    /// [`LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING`] for the cardinality
    /// mitigation. Unlike `provider`/`type`, `tenant` is not bounded by this
    /// process's own config, so it cannot be pre-resolved for every value at
    /// boot the way `provider`/`type` are (`proxy_http::stat_handles`) —
    /// see [`Registry::resolve_capped`].
    pub const LLM_CLIENT_TOKEN_USAGE: Instrument = Instrument {
        name: "llm.client.token.usage",
        kind: InstrumentKind::Counter,
        unit: "{token}",
        attribute_keys: &["provider", "type", "tenant"],
        buckets: None,
    };

    /// [`LLM_CLIENT_TOKEN_USAGE`]'s `tenant` value for a stream with no
    /// authenticated caller (`StreamInfo::auth.tenant` is `None` — no `auth`
    /// filter configured on the listener, or one configured but the request
    /// never reached it). Recorded, not skipped: unauthenticated traffic
    /// still consumes real tokens and operators still need to see it in
    /// aggregate, so this is a naming decision, not a decision to drop the
    /// measurement — contrast the module's "no usage records nothing" rule,
    /// which is the opposite case (usage itself absent, not just the
    /// tenant).
    ///
    /// Chosen so it cannot be confused for a real tenant id: both places a
    /// tenant id is produced (`auth_filter.rs`'s static `virtual_keys`
    /// config field, and a JWT's tenant claim) reject an empty string, and
    /// neither a config author nor a JWT issuer has a reason to pick a value
    /// that opens AND closes with a hyphen the way a typical account/team
    /// slug (alphanumeric, maybe an internal dash) would not. That is a
    /// convention, not a cryptographic guarantee — the same shape as
    /// Kubernetes reserving the `kube-` namespace prefix — so an operator
    /// must not name a tenant this.
    pub const LLM_CLIENT_TOKEN_USAGE_NO_TENANT: &str = "-unauthenticated-";

    /// [`LLM_CLIENT_TOKEN_USAGE`]'s `tenant` value once the cardinality
    /// ceiling ([`LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING`]) has been reached —
    /// see [`Registry::resolve_capped`]'s doc for the mechanism. Every
    /// tenant this process already resolved a series for keeps its own
    /// series forever; every *new* tenant past the ceiling folds into this
    /// one shared series instead of growing the registry without bound.
    /// Same non-collision reasoning and same caveat as
    /// [`LLM_CLIENT_TOKEN_USAGE_NO_TENANT`], and deliberately a different
    /// string from it — an operator staring at a dashboard needs to tell
    /// "nobody was authenticated" apart from "so many tenants showed up we
    /// stopped giving them their own series".
    pub const LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW: &str = "-cardinality-overflow-";

    /// The cardinality budget for [`LLM_CLIENT_TOKEN_USAGE`]'s `tenant`
    /// dimension: the maximum number of resolved *series* (not tenants —
    /// each tenant contributes up to four, one per `type` bucket, per
    /// provider) this instrument may hold before
    /// [`Registry::resolve_capped`] starts folding new tenants into
    /// [`LLM_CLIENT_TOKEN_USAGE_TENANT_CARDINALITY_OVERFLOW`] instead of
    /// growing further. 4000 series is a round, generous, and frankly
    /// arbitrary starting budget — roughly 1000 distinct tenants summed
    /// across every configured provider — not derived from a measured
    /// deployment. It is a hardcoded constant rather than a config field for
    /// exactly that reason: there is no evidence yet for what the right
    /// number is, and a wrong config default is worse than an honestly
    /// unconfigurable one that is easy to find and bump (right here) once
    /// there is one. Tenants already resolved before the ceiling trips keep
    /// their own series — see [`Registry::resolve_capped`].
    pub const LLM_CLIENT_TOKEN_USAGE_TENANT_CEILING: usize = 4_000;

    /// Upstream request duration, per cluster, in **milliseconds**.
    ///
    /// Mirrors Envoy's own `upstream_rq_time` stat family directly (see the
    /// design brief, Decision 4), carrying Envoy's default `rq_time` bucket
    /// boundaries so the increment-3 `/stats` renderer's percentile output
    /// (`cluster.<name>.upstream_rq_time` P50/P90/P99/...) matches what
    /// Envoy itself would report for the same distribution. See the module
    /// doc's "unit mismatch" note: this is milliseconds, not the OTel
    /// semconv seconds convention, and nothing here converts between them.
    pub const UPSTREAM_RQ_TIME: Instrument = Instrument {
        name: "upstream_rq_time",
        kind: InstrumentKind::Histogram,
        unit: "ms",
        attribute_keys: &["cluster"],
        buckets: Some(&ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS),
    };

    /// OTel GenAI semantic conventions v1.27: proxy-observed time from
    /// receiving the downstream request to the first response-body byte.
    ///
    /// This is emitted only for successful LLM responses whose route exposed
    /// a trusted body-derived model name. `gen_ai.request.model` is therefore
    /// never fabricated from a provider/cluster name, and its unbounded input
    /// is capped by `GenAiLatencyStats` before it reaches the registry.
    pub const GEN_AI_SERVER_TIME_TO_FIRST_TOKEN: Instrument = Instrument {
        name: "gen_ai.server.time_to_first_token",
        kind: InstrumentKind::Histogram,
        unit: "s",
        attribute_keys: &[
            "gen_ai.operation.name",
            "gen_ai.request.model",
            "gen_ai.system",
        ],
        buckets: Some(&GEN_AI_TIME_TO_FIRST_TOKEN_BUCKETS_SECONDS),
    };

    /// OTel GenAI semantic conventions v1.27: proxy-observed mean decode
    /// time per output token after the first token. See the recorder for the
    /// exact eligibility and arithmetic rules.
    pub const GEN_AI_SERVER_TIME_PER_OUTPUT_TOKEN: Instrument = Instrument {
        name: "gen_ai.server.time_per_output_token",
        kind: InstrumentKind::Histogram,
        unit: "s",
        attribute_keys: &[
            "gen_ai.operation.name",
            "gen_ai.request.model",
            "gen_ai.system",
        ],
        buckets: Some(&GEN_AI_TIME_PER_OUTPUT_TOKEN_BUCKETS_SECONDS),
    };

    // ------------------------------------------------ operational self-signals --
    //
    // Everything above this line is about TRAFFIC -- a request happened, it
    // cost tokens, it was slow. The instruments below describe the telemetry
    // pipeline itself, which belongs to the operational domain
    // `docs/telemetry-design.md` §1 separates out. They are what an operator
    // reads when the question is "is the observability itself lying to me",
    // and they are the reason a collector outage is visible as a metric
    // rather than only as a gap in someone else's dashboard.
    //
    // They live under the `llmproxy_otel_*` prefix rather than `llm_*`
    // because they are this proxy's own operational identity with no
    // upstream semconv equivalent -- same reasoning as `UPSTREAM_RQ`'s
    // gateway-metrics name, and deliberately NOT `llm_capture_*`: the
    // end-user request-record/transcript pipeline is a separate domain with
    // separate resources and failure behavior (design doc §1), and reusing one
    // prefix across the two would invite exactly the "these are the same
    // thing" reading the design exists to prevent.

    /// The `signal` attribute's two legal values. Finite and exhaustive by
    /// construction: the exporter tasks are the only writers, and there is
    /// exactly one of each. A free-form string here would be an unbounded
    /// label source for no benefit.
    pub const EXPORT_SIGNAL_TRACES: &str = "traces";
    pub const EXPORT_SIGNAL_METRICS: &str = "metrics";

    /// OTLP export attempts that failed, by signal. Counts connect errors,
    /// collector rejections, and deadline expiries alike -- all three are the
    /// same operator-facing fact (this snapshot did not arrive) and
    /// distinguishing them would mean labelling a `tonic::Status` variant
    /// whose set is not ours to bound.
    ///
    /// Resolved once per signal at boot, never per failure, so cardinality is
    /// exactly two series for the life of the process. A failure counter with
    /// no success counter is deliberately still useful: it is compared against
    /// the export interval, not against a ratio, and design doc §5.5 makes
    /// these aggregate counters the dependable signal precisely because a
    /// per-request loss event cannot itself be delivered when the pipeline is
    /// what's broken.
    pub const OTEL_EXPORT_FAILURES: Instrument = Instrument {
        name: "llmproxy_otel_export_failures",
        kind: InstrumentKind::Counter,
        unit: "{failure}",
        attribute_keys: &["signal"],
        buckets: None,
    };

    /// Spans discarded before export: dropped by `SpanSink::emit` because its
    /// bounded channel was full, plus every span in a batch whose export
    /// failed.
    ///
    /// Monotonic within a process lifetime. The trace exporter adds only the
    /// increase in its combined queue/batch drop ledger, so this is a counter
    /// in both Prometheus and OTLP even though it is republished periodically.
    pub const OTEL_SPANS_DROPPED: Instrument = Instrument {
        name: "llmproxy_otel_spans_dropped",
        kind: InstrumentKind::Counter,
        unit: "{span}",
        attribute_keys: &[],
        buckets: None,
    };

    // ------------------------------------------------ metadata capture health --
    //
    // These are intentionally a separate `llmproxy_metadata_*` namespace.
    // Request-record capture is best effort and has different failure and
    // retention semantics from OTLP export; joining their instruments would
    // make a collector outage look like a trace-export problem. No capture
    // identity is an attribute: every dimension below is a closed vocabulary.

    /// Request-record admission attempts, by their terminal queue outcome.
    ///
    /// Updated synchronously by `BoundedRecordSink::submit`: accepted records
    /// are handed to the dedicated writer; capacity and closed outcomes are
    /// dropped without delaying the request worker. The three outcomes are
    /// resolved at boot, including when capture is disabled, so scrape and
    /// OTLP distinguish a real zero from a missing series.
    pub const METADATA_ADMISSION: Instrument = Instrument {
        name: "llmproxy_metadata_admission",
        kind: InstrumentKind::Counter,
        unit: "{record}",
        attribute_keys: &["outcome"],
        buckets: None,
    };
    pub const METADATA_ADMISSION_ACCEPTED: &str = "accepted";
    pub const METADATA_ADMISSION_CAPACITY_EXCEEDED: &str = "capacity_exceeded";
    pub const METADATA_ADMISSION_CLOSED: &str = "closed";

    /// Queue occupancy measured from producer reservation to collector dequeue
    /// observation. `depth / llmproxy_metadata_queue_capacity` estimates queue
    /// utilization. Concurrent reservation/dequeue updates can briefly include
    /// an unpublished record or one just removed from the channel; this is not
    /// an atomic channel snapshot. Collector write time is excluded.
    pub const METADATA_QUEUE_DEPTH: Instrument = Instrument {
        name: "llmproxy_metadata_queue_depth",
        kind: InstrumentKind::UpDownCounter,
        unit: "{record}",
        attribute_keys: &[],
        buckets: None,
    };

    /// Configured request-record queue capacity. Set once when capture starts;
    /// zero means capture was not configured for this process.
    pub const METADATA_QUEUE_CAPACITY: Instrument = Instrument {
        name: "llmproxy_metadata_queue_capacity",
        kind: InstrumentKind::UpDownCounter,
        unit: "{record}",
        attribute_keys: &[],
        buckets: None,
    };

    /// Records successfully delivered by the collector thread: append-write in
    /// legacy mode, authenticated durable-local receipt in agent mode.
    pub const METADATA_WRITTEN: Instrument = Instrument {
        name: "llmproxy_metadata_written",
        kind: InstrumentKind::Counter,
        unit: "{record}",
        attribute_keys: &[],
        buckets: None,
    };

    /// Agent durability-confirmed records. No attributes; local durability is
    /// distinct from legacy writes and remote indexing.
    pub const METADATA_DURABLE: Instrument = Instrument {
        name: "llmproxy_metadata_durable",
        kind: InstrumentKind::Counter,
        unit: "{record}",
        attribute_keys: &[],
        buckets: None,
    };

    /// Collector serialization/write or unconfirmed-delivery failures. Legacy
    /// write failures close admission; agent mode can reconnect on later events.
    pub const METADATA_WRITE_FAILURES: Instrument = Instrument {
        name: "llmproxy_metadata_write_failures",
        kind: InstrumentKind::Counter,
        unit: "{failure}",
        attribute_keys: &[],
        buckets: None,
    };
}

/// Pre-resolved operational signals for the best-effort request-record
/// collector. Constructed once by the control side and used by both request
/// workers (admission) and the dedicated collector thread (dequeue/write).
/// All updates use `WorkerId(0)`: these are process-level control signals,
/// not worker-owned traffic measurements.
#[derive(Clone)]
pub struct MetadataDeliveryStats {
    registry: Arc<Registry>,
    accepted: Handle,
    capacity_exceeded: Handle,
    closed: Handle,
    queue_depth: Handle,
    queue_capacity: Handle,
    written: Handle,
    durable: Handle,
    write_failures: Handle,
}

impl MetadataDeliveryStats {
    /// Resolve every finite metadata-capture series, even with capture
    /// disabled, so both Prometheus scrape and OTLP snapshots carry explicit
    /// zeroes for an idle process.
    pub fn resolve(control: &StatsControl) -> Self {
        Self {
            registry: control.registry(),
            accepted: control.resolve(
                &instruments::METADATA_ADMISSION,
                &[("outcome", instruments::METADATA_ADMISSION_ACCEPTED)],
            ),
            capacity_exceeded: control.resolve(
                &instruments::METADATA_ADMISSION,
                &[("outcome", instruments::METADATA_ADMISSION_CAPACITY_EXCEEDED)],
            ),
            closed: control.resolve(
                &instruments::METADATA_ADMISSION,
                &[("outcome", instruments::METADATA_ADMISSION_CLOSED)],
            ),
            queue_depth: control.resolve(&instruments::METADATA_QUEUE_DEPTH, &[]),
            queue_capacity: control.resolve(&instruments::METADATA_QUEUE_CAPACITY, &[]),
            written: control.resolve(&instruments::METADATA_WRITTEN, &[]),
            durable: control.resolve(&instruments::METADATA_DURABLE, &[]),
            write_failures: control.resolve(&instruments::METADATA_WRITE_FAILURES, &[]),
        }
    }

    /// Lifecycle point: once, when a configured collector takes ownership of
    /// its bounded channel.
    pub fn configure_queue(&self, capacity: usize) {
        self.registry.incr(
            WorkerId(0),
            self.queue_capacity,
            capacity.min(u64::MAX as usize) as u64,
        );
    }

    /// Lifecycle point: every nonblocking producer submission.
    pub fn record_submission(&self, outcome: crate::records::SubmitResult) {
        match outcome {
            crate::records::SubmitResult::Accepted => {
                self.registry.incr(WorkerId(0), self.accepted, 1);
            }
            crate::records::SubmitResult::CapacityExceeded => {
                self.registry.incr(WorkerId(0), self.capacity_exceeded, 1);
            }
            crate::records::SubmitResult::Closed => {
                self.registry.incr(WorkerId(0), self.closed, 1);
            }
            crate::records::SubmitResult::Disabled => {}
        }
    }

    /// After obtaining a channel permit, before publishing the record. This
    /// ordering prevents dequeue from subtracting an unpublished increment.
    pub fn record_enqueued(&self) {
        self.registry.incr(WorkerId(0), self.queue_depth, 1);
    }

    /// Lifecycle point: immediately after the collector removes a record from
    /// the bounded channel, including records discarded after a write failure.
    pub fn record_dequeued(&self) {
        self.registry.add(WorkerId(0), self.queue_depth, -1);
    }

    /// Lifecycle point: successful JSON serialization plus append write.
    pub fn record_written(&self) {
        self.registry.incr(WorkerId(0), self.written, 1);
    }

    /// Lifecycle point: one authenticated agent Durable receipt matching the event.
    pub fn record_durable(&self) {
        self.registry.incr(WorkerId(0), self.durable, 1);
    }

    /// Lifecycle point: JSON serialization or append write error.
    pub fn record_write_failure(&self) {
        self.registry.incr(WorkerId(0), self.write_failures, 1);
    }
}

/// Identifies a worker thread/runtime for [`Registry::incr`]/
/// [`Registry::add`]/[`Registry::observe`]'s shard indexing.
///
/// Rust note: this deliberately mirrors `proxy_core::runtime::WorkerId`'s
/// shape (`WorkerId(pub usize)`) rather than reusing it. `proxy-core`
/// depends on `proxy-config`, which depends on this crate
/// (`proxy-observability`), for [`crate::ResponseFlag`] and the access-log
/// format string type — so `proxy-observability -> proxy-core` would close a
/// dependency cycle. A later increment's call sites (living in `proxy-core`
/// or above, where the real `WorkerId` is in scope) convert with `.0` when
/// calling into this registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkerId(pub usize);

/// An opaque handle to one resolved `(counter/up-down-counter instrument,
/// attribute set)` pair. Returned by [`StatsControl::resolve`]; carries no
/// name, no attributes — that is the point (see the module doc's Decision
/// 1). The inner `usize` is private to this module: outside it, a `Handle`
/// can only be obtained from `resolve` and only used by handing it back to
/// `incr`/`add`/`value`.
///
/// **Not the same type as [`HistogramHandle`]** — see the module doc's
/// "handle-space question" section for why they are deliberately distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(usize);

/// An opaque handle to one resolved `(histogram instrument, attribute set)`
/// pair. Returned by [`StatsControl::resolve_histogram`]; used only with
/// [`Registry::observe`].
///
/// A **distinct type from [`Handle`]**, occupying its own index space, so
/// this and `Handle` can never be confused for one another — passing one
/// where the other is expected is a compile error, not a runtime check:
///
/// ```compile_fail
/// use proxy_observability::stats::{instruments, StatsControl, WorkerId};
///
/// let control = StatsControl::new(1);
/// let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
/// let registry = control.registry();
/// // ERROR: expected `HistogramHandle`, found `Handle`.
/// registry.observe(WorkerId(0), h, 1.0);
/// ```
///
/// and the mirror image:
///
/// ```compile_fail
/// use proxy_observability::stats::{instruments, StatsControl, WorkerId};
///
/// let control = StatsControl::new(1);
/// let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "openai")]);
/// let registry = control.registry();
/// // ERROR: expected `Handle`, found `HistogramHandle`.
/// registry.incr(WorkerId(0), h, 1);
/// ```
///
/// See the module doc's "handle-space question" section for why this was
/// chosen over a shared index space with a runtime `kind` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistogramHandle(usize);

/// Dedup key for [`Registry::resolve`]/[`Registry::resolve_histogram`]: an
/// instrument's name plus its attributes, sorted into a stable order. Named
/// as a `type` alias (rather than inlined into `ControlState`'s field) purely
/// to keep that field declaration readable — clippy's `type_complexity` lint
/// flagged the inline form.
type ResolveKey = (&'static str, Vec<(String, String)>);

/// Width, in slots, of one counter growth block — see the module doc's
/// "Growth must not move or copy a live atomic" section (Increment 5) for why
/// counters grow in fixed-size blocks rather than one `AtomicU64` at a time.
/// A round power of two comfortably larger than a cache line (64 `u64`s = 512
/// bytes), so a block amortizes its allocation over many handles without
/// wasting much unused space behind a rarely-resolved instrument.
const COUNTER_BLOCK_LEN: usize = 64;

/// One worker shard's histogram state for one handle. Bucket counts are
/// **non-cumulative** (see the module doc); `sum` and `count` are running
/// totals updated alongside the bucket bump on every [`Registry::observe`]
/// call. [`Registry::histogram_snapshot`] sums this across every worker
/// shard, the same summed-read rule counters use.
struct HistogramShard {
    /// `bucket_counts[i]` is the count of observations that landed in
    /// bucket `i` — `(boundary[i-1], boundary[i]]` for `i > 0`, `(-inf,
    /// boundary[0]]` for `i == 0`, with `boundary` from the owning
    /// instrument's `buckets`. Index `boundaries.len()` (the last slot) is
    /// the overflow bucket, Prometheus's `+Inf`, for anything above the
    /// last boundary — so this `Vec` always has `boundaries.len() + 1`
    /// entries, never `boundaries.len()`.
    bucket_counts: Vec<AtomicU64>,
    /// Sum of every observed value, in the instrument's declared `unit`,
    /// stored as the raw bit pattern of an `f64` inside an `AtomicU64`.
    ///
    /// Rust note: `std` has no `AtomicF64` (only integer atomics), so this
    /// is the standard bit-cast CAS-loop technique — see
    /// [`atomic_add_f64`]'s doc for the loop itself. The bits are never
    /// interpreted as an integer; `AtomicU64` here is purely a box that
    /// happens to be atomic and 64 bits wide.
    sum_bits: AtomicU64,
    /// Total observation count for this shard — equal to the sum of
    /// `bucket_counts`, but kept as its own atomic so a reader doesn't have
    /// to walk every bucket just to get the count.
    count: AtomicU64,
}

impl HistogramShard {
    /// Builds a fresh, all-zero shard with `num_buckets` slots
    /// (`boundaries.len() + 1` — see [`Self::bucket_counts`]'s doc).
    fn new(num_buckets: usize) -> Self {
        Self {
            // Rust note: `AtomicU64` isn't `Clone`, so `vec![AtomicU64::new(0);
            // n]` doesn't typecheck; building each slot from a fresh
            // constructor call sidesteps that.
            bucket_counts: (0..num_buckets).map(|_| AtomicU64::new(0)).collect(),
            // 0.0f64.to_bits() == 0, so this is "no observations yet" both
            // as bits and as the f64 they represent.
            sum_bits: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }
}

/// Atomically adds `delta` to the `f64` value stored, bit-for-bit, inside
/// `atomic`.
///
/// Rust note: `std::sync::atomic` has no `AtomicF64` (floats have no
/// hardware fetch-add instruction the way integers do), so this is the
/// standard compare-and-swap loop for atomic float accumulation: load the
/// current bits, reinterpret them as `f64`, add `delta`, reinterpret the
/// result back to bits, and try to swap it in — retrying with whatever the
/// racing thread actually left behind if the swap loses the race.
/// `compare_exchange_weak` (not the non-`_weak` form) is correct here
/// because a spurious failure just means "loop again with a fresh load",
/// which the loop already does. `Relaxed` throughout for the same reason
/// every other counter/histogram field in this module uses it: nothing else
/// is published through this value.
fn atomic_add_f64(atomic: &AtomicU64, delta: f64) {
    let mut current = atomic.load(Ordering::Relaxed);
    loop {
        let next = (f64::from_bits(current) + delta).to_bits();
        match atomic.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// A summed-across-shards view of one histogram handle's state: the same
/// three fields [`HistogramShard`] stores per shard, after
/// [`Registry::histogram_snapshot`]/[`Registry::histogram_shard_snapshots_for_debugging`]
/// have added them up (or, for the debugging accessor, left them as one
/// shard's own figures).
#[derive(Debug, Clone, PartialEq)]
pub struct HistogramSnapshot {
    /// Non-cumulative bucket counts, `boundaries.len() + 1` entries — see
    /// [`HistogramShard::bucket_counts`]'s doc for the indexing and the
    /// overflow bucket.
    pub bucket_counts: Vec<u64>,
    /// Sum of every observed value.
    pub sum: f64,
    /// Total observation count (`== bucket_counts.iter().sum()`).
    pub count: u64,
}

/// The immutable, versioned bundle [`Registry::published`] hands out to every
/// reader — see the module doc's "Increment 5" section. Metadata (`resolved`,
/// `resolved_attrs`, ...) and shard storage live in the same struct
/// deliberately: a `Snapshot` a worker `load()`s always describes one
/// consistent generation, so it can never show a new handle's metadata
/// without also showing that handle's freshly-grown shard slot, or vice
/// versa.
///
/// Rust note: growth (in [`Registry::resolve`]/[`Registry::resolve_histogram`])
/// builds a whole new `Snapshot` by cloning these `Vec`s -- which clones only
/// `&'static Instrument` references, `String`s, and `Arc` pointers, never an
/// `AtomicU64`/[`HistogramShard`] itself -- and `ArcSwap::store`s it. Every
/// atomic that already had a handle before the clone keeps living at the same
/// address afterwards, still receiving increments from any thread still
/// holding the *old* `Snapshot`.
struct Snapshot {
    /// Indexed by `Handle`'s inner `usize`. Kept so `incr`/`add` can look up
    /// an instrument's kind (to enforce "Counters don't decrement") and
    /// `envoy_render` can look up name/unit/attrs for rendering.
    resolved: Vec<&'static Instrument>,
    /// Indexed in lockstep with `resolved`: the sorted `(key, value)` attrs
    /// each handle was resolved with. `envoy_render` reads this to expand
    /// attribute values into Envoy `/stats` name segments (e.g. a
    /// `status_class` attribute becomes `..._2xx`/`..._5xx`) -- see
    /// [`Registry::counters`].
    resolved_attrs: Vec<Vec<(String, String)>>,
    /// `counter_shards[worker.0][block]` is that worker's block for that
    /// block index; `counter_shards[worker.0][block][slot]` is one
    /// [`Handle`]'s `AtomicU64`, where `block = handle.0 /
    /// COUNTER_BLOCK_LEN` and `slot = handle.0 % COUNTER_BLOCK_LEN` -- see
    /// the module doc's "Growth must not move or copy a live atomic" section
    /// for why counters are block-chunked rather than one `Arc` per slot.
    counter_shards: Vec<Vec<Arc<Vec<AtomicU64>>>>,
    /// Same role as `resolved`, for [`HistogramHandle`]s. A separate `Vec`
    /// in its own index space — see the module doc's "handle-space
    /// question".
    resolved_histograms: Vec<&'static Instrument>,
    /// Same role as `resolved_attrs`, for [`HistogramHandle`]s.
    resolved_histogram_attrs: Vec<Vec<(String, String)>>,
    /// `histogram_shards[worker.0][handle.0]` is that worker's
    /// [`HistogramShard`] for that histogram handle -- one `Arc` per
    /// `(worker, handle)` pair, unblocked (see the module doc for why
    /// histograms don't share the counter's block scheme).
    histogram_shards: Vec<Vec<Arc<HistogramShard>>>,
}

impl Snapshot {
    /// An empty snapshot sized for `num_workers` shards -- zero handles of
    /// either kind resolved yet.
    fn empty(num_workers: usize) -> Self {
        Self {
            resolved: Vec::new(),
            resolved_attrs: Vec::new(),
            // Rust note: `vec![x; n]` needs `x: Clone`. `Vec<Arc<..>>` is
            // `Clone` even though the `Arc`'s payload (`Vec<AtomicU64>` /
            // `HistogramShard`) is not, because `Arc<T>: Clone` holds for
            // every `T` -- cloning an `Arc` bumps a refcount, it never
            // touches what it points to. That is exactly the property the
            // rest of this module leans on for lock-free growth.
            counter_shards: vec![Vec::new(); num_workers],
            resolved_histograms: Vec::new(),
            resolved_histogram_attrs: Vec::new(),
            histogram_shards: vec![Vec::new(); num_workers],
        }
    }
}

/// Control-side-only state behind [`Registry::control`]'s `Mutex`: the dedup
/// maps [`Registry::resolve`]/[`Registry::resolve_histogram`] check before
/// growing anything. Nothing on the request path ever locks this -- see the
/// module doc's "Increment 5" section.
#[derive(Default)]
struct ControlState {
    /// Dedup key -> already-resolved `Handle`, so resolving the same
    /// `(instrument, attrs)` twice returns the same handle instead of
    /// growing a second, parallel time series.
    ///
    /// Rust note: keyed by `instrument.name`, not the `&'static Instrument`
    /// pointer. Two references to the same `const` are not guaranteed by
    /// the language to share an address (const promotion isn't a spec
    /// guarantee), so pointer equality would be a landmine here; OTel
    /// itself identifies an instrument by name, so keying on `name` matches
    /// the actual data model instead of an implementation accident.
    lookup: HashMap<ResolveKey, Handle>,
    /// Same role as `lookup`, for histograms.
    histogram_lookup: HashMap<ResolveKey, HistogramHandle>,
}

/// The stats registry: the shared, hot-path type every worker holds as
/// `Arc<Registry>`. Every method here takes `&self`, and **there is no
/// public `resolve`** -- see the module doc's "Increment 5" section for why
/// that is a type-level guarantee (a worker holding only `Arc<Registry>`
/// cannot reach resolution, full stop) rather than a runtime check.
/// [`StatsControl`] is the only way to grow one.
pub struct Registry {
    /// The current, immutable view every hot-path method `load()`s. Growth
    /// (control-side only, via the private `resolve`/`resolve_histogram`
    /// below) builds a new `Snapshot` and stores it here -- the same
    /// "control computes, workers `load`" pattern
    /// `proxy_cluster::manager::ClusterManager` uses for `HostSet`, and the
    /// auth filter uses for its key set.
    published: ArcSwap<Snapshot>,
    /// Control-side-only dedup state. A `Mutex`, not an atomic or another
    /// `ArcSwap`, because resolution needs to check-then-insert atomically
    /// with respect to *other resolutions* -- two concurrent `resolve` calls
    /// for the same new `(instrument, attrs)` must not both grow a slot.
    /// This lock is never taken on the request path.
    control: Mutex<ControlState>,
}

impl Registry {
    /// Build an empty registry sized for `num_workers` shards. Private:
    /// [`StatsControl::new`] is the only public constructor -- building a
    /// bare `Registry` from outside this module would hand out the shared
    /// type without the control-side gate, defeating the point of the
    /// `Registry`/`StatsControl` split (module doc, "Increment 5").
    /// `num_workers` is a config-time constant (`WorkerPoolConfig::concurrency`,
    /// in `proxy-core`) -- this increment does not support growing the
    /// worker count after construction.
    fn empty(num_workers: usize) -> Self {
        Self {
            published: ArcSwap::from_pointee(Snapshot::empty(num_workers)),
            control: Mutex::new(ControlState::default()),
        }
    }

    /// How many worker shards this registry was built with.
    pub fn num_workers(&self) -> usize {
        self.published.load().counter_shards.len()
    }

    /// Control side only -- reachable exclusively through
    /// [`StatsControl::resolve`] (defined in this same module; see the
    /// module doc's "Increment 5" section for why this method itself is not
    /// `pub`). Resolving the same `(instrument, attrs)` twice (attribute
    /// order does not matter) returns the same [`Handle`].
    ///
    /// Panics if `attrs`' keys don't exactly match `instrument.attribute_keys`
    /// (missing or unexpected) — loudly, on purpose: a typo'd attribute key
    /// must not silently start a second, parallel time series. Also panics
    /// if `instrument.kind` is [`InstrumentKind::Histogram`] — use
    /// [`Self::resolve_histogram`] for those; see the module doc's
    /// "handle-space question" for why this is checked here rather than
    /// left to produce a `Handle` that `incr`/`add` would then have to
    /// reject.
    fn resolve(&self, instrument: &'static Instrument, attrs: &[(&str, &str)]) -> Handle {
        assert_ne!(
            instrument.kind,
            InstrumentKind::Histogram,
            "stats::Registry::resolve: {} is a Histogram -- use resolve_histogram()",
            instrument.name
        );
        Self::validate_attrs(instrument, attrs);

        let key = Self::resolve_key(instrument, attrs);

        // Rust note: this lock guards the dedup map AND the check-then-grow
        // sequence below as one atomic unit with respect to other
        // resolve/resolve_histogram calls; it is never taken by
        // incr/value/observe, so it can never be held by, or block, a
        // request. `unwrap_or_else(PoisonError::into_inner)` rather than
        // `.unwrap()`: a panic while holding this lock (e.g. inside
        // `validate_attrs`, above) must not poison every future resolve --
        // the dedup map itself is still perfectly valid data.
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(&handle) = control.lookup.get(&key) {
            return handle;
        }

        let old = self.published.load();
        let handle = Handle(old.resolved.len());

        let mut resolved = old.resolved.clone();
        resolved.push(instrument);
        let mut resolved_attrs = old.resolved_attrs.clone();
        resolved_attrs.push(key.1.clone());

        // Growth: clone the outer Vec<Vec<Arc<..>>> (copies only Arc
        // pointers -- every existing AtomicU64 stays exactly where it is,
        // still receiving increments from any thread holding the OLD
        // Snapshot) and append one fresh block per worker only when this
        // handle is the first slot of a new block -- see the module doc's
        // "Growth must not move or copy a live atomic" section. This is
        // also the rejected-alternative pin: copying counter VALUES across
        // instead of sharing the same atomics would lose any increment that
        // landed between the read and the swap, below.
        let mut counter_shards = old.counter_shards.clone();
        if handle.0.is_multiple_of(COUNTER_BLOCK_LEN) {
            for worker_blocks in &mut counter_shards {
                worker_blocks.push(Arc::new(
                    (0..COUNTER_BLOCK_LEN).map(|_| AtomicU64::new(0)).collect(),
                ));
            }
        }

        self.published.store(Arc::new(Snapshot {
            resolved,
            resolved_attrs,
            counter_shards,
            resolved_histograms: old.resolved_histograms.clone(),
            resolved_histogram_attrs: old.resolved_histogram_attrs.clone(),
            histogram_shards: old.histogram_shards.clone(),
        }));
        control.lookup.insert(key, handle);
        handle
    }

    /// The histogram counterpart of [`Self::resolve`] — same identity,
    /// dedup, and control-side-only rules, but returns a [`HistogramHandle`]
    /// in its own index space and grows one [`HistogramShard`] per worker
    /// (unblocked -- see the module doc) instead of extending a shared
    /// block.
    ///
    /// Panics if `attrs`' keys don't match `instrument.attribute_keys`, same
    /// as `resolve`. Panics if `instrument.kind` is not
    /// [`InstrumentKind::Histogram`], or if a `Histogram` instrument's
    /// `buckets` is `None` (a malformed `const` definition, not something a
    /// caller can cause) — both loudly, both control-side only.
    fn resolve_histogram(
        &self,
        instrument: &'static Instrument,
        attrs: &[(&str, &str)],
    ) -> HistogramHandle {
        assert_eq!(
            instrument.kind,
            InstrumentKind::Histogram,
            "stats::Registry::resolve_histogram: {} is not a Histogram -- use resolve()",
            instrument.name
        );
        let num_boundaries = instrument
            .buckets
            .unwrap_or_else(|| {
                panic!(
                    "stats::Registry::resolve_histogram: {} is a Histogram instrument with no \
                     bucket boundaries -- this is a bug in the instrument's own definition",
                    instrument.name
                )
            })
            .len();
        Self::validate_attrs(instrument, attrs);

        let key = Self::resolve_key(instrument, attrs);

        let mut control = self
            .control
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        if let Some(&handle) = control.histogram_lookup.get(&key) {
            return handle;
        }

        let old = self.published.load();
        let handle = HistogramHandle(old.resolved_histograms.len());

        let mut resolved_histograms = old.resolved_histograms.clone();
        resolved_histograms.push(instrument);
        let mut resolved_histogram_attrs = old.resolved_histogram_attrs.clone();
        resolved_histogram_attrs.push(key.1.clone());

        // Nineteen boundaries means twenty slots -- see the module doc's
        // "overflow bucket" section. One freshly-allocated
        // Arc<HistogramShard> per worker, appended -- never resizing a
        // shard that already has a handle.
        let num_buckets = num_boundaries + 1;
        let mut histogram_shards = old.histogram_shards.clone();
        for worker_shards in &mut histogram_shards {
            worker_shards.push(Arc::new(HistogramShard::new(num_buckets)));
        }

        self.published.store(Arc::new(Snapshot {
            resolved: old.resolved.clone(),
            resolved_attrs: old.resolved_attrs.clone(),
            counter_shards: old.counter_shards.clone(),
            resolved_histograms,
            resolved_histogram_attrs,
            histogram_shards,
        }));
        control.histogram_lookup.insert(key, handle);
        handle
    }

    /// A single, deliberately narrow exception to "no public resolve" above
    /// (module doc, "Increment 5") — WP-55's tenant dimension. Every other
    /// instrument's attribute values are this process's OWN config (cluster
    /// names, listener names), known and bounded at boot, which is exactly
    /// why the general `resolve`/`resolve_histogram` stay control-side-only:
    /// a worker never needs to grow the registry for a value it didn't
    /// already know at boot. `tenant` breaks that premise — it comes from a
    /// caller's credential (`StreamInfo::auth.tenant`), is not known until a
    /// request actually authenticates, and (via a JWT claim) is partly
    /// caller-influenced, so an uncapped version of this method would be a
    /// real cardinality-exhaustion vector, not just an engineering
    /// inconvenience. Hence *capped*, not general: reachable from a worker's
    /// plain `Arc<Registry>` (unlike `resolve`), but growth stops the moment
    /// `instrument` already has `ceiling` or more resolved series — every
    /// call past that point resolves `overflow_attrs` instead of `attrs`.
    /// That is the WP-55 hazard note's own framing: drop the DIMENSION
    /// (fold into one shared series) rather than the MEASUREMENT (still
    /// recorded) or the alternative of letting a caller-chosen string grow
    /// the registry without bound.
    ///
    /// The cap check reads `resolved` off the currently-published
    /// `Snapshot` — the SAME state `resolve` itself maintains for
    /// rendering, not a second, parallel bookkeeping structure — so a
    /// tenant this process has already resolved keeps its own series
    /// (a fast dedup hit inside `resolve`, no growth) for as long as the
    /// process runs, even after the ceiling trips for anyone new.
    ///
    /// Panics under the same conditions as `resolve` (attribute key
    /// mismatch against `instrument.attribute_keys`, or a `Histogram`
    /// instrument) — `overflow_attrs` is checked too, since it reaches the
    /// same call once the ceiling trips. Note this means `validate_attrs`
    /// (see its own doc) is no longer *provably* off the request path the
    /// way it was when only `StatsControl` could reach `resolve` — a
    /// mismatch here would still only be a programming error in this
    /// module's own call sites (`attrs`/`overflow_attrs` are built from
    /// `'static` `Instrument`s in `proxy_http::stat_handles`, never from
    /// caller input), not something a request can trigger.
    pub fn resolve_capped(
        &self,
        instrument: &'static Instrument,
        attrs: &[(&str, &str)],
        ceiling: usize,
        overflow_attrs: &[(&str, &str)],
    ) -> Handle {
        // Rust note: locking once just to peek `lookup` (rather than
        // reusing `resolve`'s own internal lock for this) keeps this method
        // simple and correct at the cost of a second lock/unlock on a
        // genuinely new tenant -- fine here, this instrument is recorded at
        // most once per completed stream, not per byte. The point of this
        // peek is purely to avoid double-counting an ALREADY-resolved
        // tenant against `ceiling` below (which would wrongly divert it to
        // the overflow bucket once the process has resolved `ceiling` OTHER
        // tenants, fragmenting its own history) -- `resolve` itself is
        // idempotent regardless, this only affects which handle a call for
        // an existing tenant is routed to.
        let key = Self::resolve_key(instrument, attrs);
        {
            let control = self
                .control
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(&handle) = control.lookup.get(&key) {
                return handle;
            }
        }

        let already_resolved = self
            .published
            .load()
            .resolved
            .iter()
            .filter(|i| i.name == instrument.name)
            .count();
        if already_resolved >= ceiling {
            return self.resolve(instrument, overflow_attrs);
        }
        self.resolve(instrument, attrs)
    }

    /// Histogram counterpart to [`Self::resolve_capped`]. This is the one
    /// deliberate worker-side histogram-resolution escape hatch: the model
    /// name comes from a request body and therefore cannot be pre-resolved at
    /// boot, but it must not make a public proxy an unbounded-series source.
    /// Existing series always retain their handles; only new attribute sets
    /// past `ceiling` fold into the supplied shared overflow series.
    pub fn resolve_histogram_capped(
        &self,
        instrument: &'static Instrument,
        attrs: &[(&str, &str)],
        ceiling: usize,
        overflow_attrs: &[(&str, &str)],
    ) -> HistogramHandle {
        assert_eq!(
            instrument.kind,
            InstrumentKind::Histogram,
            "stats::Registry::resolve_histogram_capped: {} is not a Histogram",
            instrument.name
        );
        Self::validate_attrs(instrument, attrs);
        Self::validate_attrs(instrument, overflow_attrs);

        let key = Self::resolve_key(instrument, attrs);
        {
            let control = self
                .control
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(&handle) = control.histogram_lookup.get(&key) {
                return handle;
            }
        }

        let already_resolved = self
            .published
            .load()
            .resolved_histograms
            .iter()
            .filter(|i| i.name == instrument.name)
            .count();
        if already_resolved >= ceiling {
            return self.resolve_histogram(instrument, overflow_attrs);
        }
        self.resolve_histogram(instrument, attrs)
    }

    /// Builds the sorted `(instrument.name, attrs)` dedup key shared by
    /// `resolve` and `resolve_histogram`. Attribute order must not affect
    /// identity, hence the sort.
    fn resolve_key(instrument: &Instrument, attrs: &[(&str, &str)]) -> ResolveKey {
        let mut pairs: Vec<(String, String)> = attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        pairs.sort();
        (instrument.name, pairs)
    }

    /// Checks `attrs`' keys against `instrument.attribute_keys` as sets
    /// (order-insensitive, exact match). Called only from `resolve`/
    /// `resolve_histogram`, which are control-side, so panicking here is
    /// fine — it can never fire on the request path.
    fn validate_attrs(instrument: &Instrument, attrs: &[(&str, &str)]) {
        let mut given: Vec<&str> = attrs.iter().map(|(k, _)| *k).collect();
        given.sort_unstable();
        let mut expected: Vec<&str> = instrument.attribute_keys.to_vec();
        expected.sort_unstable();

        if given != expected {
            let missing: Vec<&&str> = expected.iter().filter(|k| !given.contains(k)).collect();
            let unexpected: Vec<&&str> = given.iter().filter(|k| !expected.contains(k)).collect();
            panic!(
                "stats::Registry::resolve({}): attribute keys don't match this instrument \
                 (expected {:?}, got {:?}; missing={:?} unexpected={:?}) -- a typo'd \
                 attribute key must not silently start a second, parallel time series",
                instrument.name, instrument.attribute_keys, given, missing, unexpected
            );
        }
    }

    /// Hot path. No hashing, no allocation, no string — `handle` and
    /// `worker` are both already-resolved indices, and reading the current
    /// [`Snapshot`] is one lock-free `ArcSwap::load`. Always moves `handle`'s
    /// counter up; valid for both [`InstrumentKind::Counter`] and
    /// [`InstrumentKind::UpDownCounter`] handles. See [`Self::add`] for the
    /// signed-delta counterpart `UpDownCounter` handles also get.
    ///
    /// Panics if `worker` is out of range for this registry's `num_workers`
    /// — a config-time invariant, not something a real request can trigger.
    pub fn incr(&self, worker: WorkerId, handle: Handle, delta: u64) {
        let state = self.published.load();
        let block = handle.0 / COUNTER_BLOCK_LEN;
        let slot = handle.0 % COUNTER_BLOCK_LEN;
        state.counter_shards[worker.0][block][slot].fetch_add(delta, Ordering::Relaxed);
    }

    /// Hot path, `UpDownCounter` handles only: `delta` may be negative.
    /// Panics if `handle` was resolved from a [`InstrumentKind::Counter`]
    /// instrument — **a `Counter` has no decrement, at all, enforced here**;
    /// [`Self::incr`] is the only way to move one, and it can only go up.
    ///
    /// Rust note: the running total is stored as a plain `AtomicU64`, so a
    /// negative `delta` is applied via `delta as u64`'s two's-complement
    /// wraparound plus `fetch_add`'s own wrapping arithmetic — the standard
    /// atomic up/down counter trick. It recovers the correct total as long
    /// as the true running total never leaves `u64`'s range, which holds for
    /// every legitimate use of an `UpDownCounter` here (e.g. "connections
    /// currently open" never truly goes negative).
    pub fn add(&self, worker: WorkerId, handle: Handle, delta: i64) {
        let state = self.published.load();
        let instrument = state.resolved[handle.0];
        assert_eq!(
            instrument.kind,
            InstrumentKind::UpDownCounter,
            "stats::Registry::add: {} is a Counter, which has no decrement -- use incr()",
            instrument.name
        );
        let block = handle.0 / COUNTER_BLOCK_LEN;
        let slot = handle.0 % COUNTER_BLOCK_LEN;
        state.counter_shards[worker.0][block][slot].fetch_add(delta as u64, Ordering::Relaxed);
    }

    /// Summed across every worker shard. **The only read.** No public
    /// accessor returns a single shard's slot — see
    /// [`Self::shard_values_for_debugging`] if you think you need one.
    ///
    /// `Relaxed` load, same justification as `incr`/`add`: a scrape must not
    /// be a fence on the request path, and observing a slightly-stale value
    /// mid-increment is fine for a counter.
    pub fn value(&self, handle: Handle) -> u64 {
        let state = self.published.load();
        let block = handle.0 / COUNTER_BLOCK_LEN;
        let slot = handle.0 % COUNTER_BLOCK_LEN;
        state
            .counter_shards
            .iter()
            .map(|worker_blocks| worker_blocks[block][slot].load(Ordering::Relaxed))
            .fold(0u64, u64::wrapping_add)
    }

    /// Per-worker figures, **unsummed**. Exists for tests only (see the
    /// module doc's "no public accessor may return a single shard's value"
    /// rule) — the ugly name is deliberate friction so a reviewer notices
    /// immediately if production code ever reaches for this instead of
    /// [`Self::value`]. Nothing outside `#[cfg(test)]` in this crate calls
    /// it, and nothing outside this crate should either.
    pub fn shard_values_for_debugging(&self, handle: Handle) -> Vec<u64> {
        let state = self.published.load();
        let block = handle.0 / COUNTER_BLOCK_LEN;
        let slot = handle.0 % COUNTER_BLOCK_LEN;
        state
            .counter_shards
            .iter()
            .map(|worker_blocks| worker_blocks[block][slot].load(Ordering::Relaxed))
            .collect()
    }

    /// Every resolved counter/up-down-counter handle, paired with its
    /// instrument identity, resolved attributes, and already-summed value —
    /// everything an exporter (WP-23 increment 3's `/stats` text renderer,
    /// increment 4's Prometheus renderer) needs to render one line, and
    /// nothing more: no by-name lookup, no shard-level figure (see the
    /// module doc's Decision 1/2). Control-side/scrape-side use only, same
    /// as [`Self::value`] itself, which this calls once per handle.
    ///
    /// Rust note: returns owned `Vec<(String, String)>` attrs rather than a
    /// `&self`-borrowed slice. Before this increment the underlying data
    /// lived directly on `Registry`, so a borrow tied to `&self` was safe;
    /// now it lives behind an `ArcSwap`-published `Snapshot` that a
    /// concurrent `resolve` could replace the instant this call returns, so
    /// there is no `&self`-scoped slice left to hand back. `load_full`
    /// clones the `Arc<Snapshot>` itself (a refcount bump, not a deep copy)
    /// so the returned iterator owns its own consistent view independent of
    /// `&self`'s lifetime and independent of any growth that happens after
    /// it was created.
    pub fn counters(
        &self,
    ) -> impl Iterator<Item = (&'static Instrument, Vec<(String, String)>, u64)> {
        let state = self.published.load_full();
        let n = state.resolved.len();
        (0..n).map(move |i| {
            let block = i / COUNTER_BLOCK_LEN;
            let slot = i % COUNTER_BLOCK_LEN;
            let value = state
                .counter_shards
                .iter()
                .map(|worker_blocks| worker_blocks[block][slot].load(Ordering::Relaxed))
                .fold(0u64, u64::wrapping_add);
            (state.resolved[i], state.resolved_attrs[i].clone(), value)
        })
    }

    /// Hot path. Records one observation of `value` (in the instrument's
    /// declared `unit`) against `handle`: finds `value`'s bucket and bumps
    /// its non-cumulative count, adds `value` into the running `sum`, and
    /// bumps the running `count` — three atomic ops, no allocation, no
    /// walking every bucket.
    ///
    /// Bucket boundaries are **inclusive**: `value` lands in the first
    /// bucket `i` with `value <= boundaries[i]` (Prometheus `le` semantics),
    /// or the overflow bucket (index `boundaries.len()`) if `value` exceeds
    /// every boundary.
    ///
    /// Panics if `worker` is out of range, same as `incr`/`add`.
    pub fn observe(&self, worker: WorkerId, handle: HistogramHandle, value: f64) {
        let state = self.published.load();
        let instrument = state.resolved_histograms[handle.0];
        let boundaries = instrument.buckets.expect(
            "stats::Registry::observe: instrument has no bucket boundaries -- \
             resolve_histogram should have rejected this at resolve time",
        );
        let bucket_index = boundaries
            .iter()
            .position(|&boundary| value <= boundary)
            .unwrap_or(boundaries.len());

        let shard = &state.histogram_shards[worker.0][handle.0];
        shard.bucket_counts[bucket_index].fetch_add(1, Ordering::Relaxed);
        atomic_add_f64(&shard.sum_bits, value);
        shard.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Summed across every worker shard. **The only read** for histogram
    /// data — see [`Self::histogram_shard_snapshots_for_debugging`] for the
    /// debug-only, unsummed per-shard view. `Relaxed` loads throughout, same
    /// justification as `value`.
    pub fn histogram_snapshot(&self, handle: HistogramHandle) -> HistogramSnapshot {
        let state = self.published.load();
        let num_buckets = state.resolved_histograms[handle.0]
            .buckets
            .expect("stats::Registry::histogram_snapshot: instrument has no bucket boundaries")
            .len()
            + 1;

        let mut bucket_counts = vec![0u64; num_buckets];
        let mut sum = 0.0f64;
        let mut count = 0u64;
        for worker_shards in &state.histogram_shards {
            let shard = &worker_shards[handle.0];
            for (i, bucket) in shard.bucket_counts.iter().enumerate() {
                bucket_counts[i] = bucket_counts[i].wrapping_add(bucket.load(Ordering::Relaxed));
            }
            sum += f64::from_bits(shard.sum_bits.load(Ordering::Relaxed));
            count = count.wrapping_add(shard.count.load(Ordering::Relaxed));
        }
        HistogramSnapshot {
            bucket_counts,
            sum,
            count,
        }
    }

    /// Per-worker snapshots, **unsummed**. Exists for tests only — same
    /// deliberate-friction naming as [`Self::shard_values_for_debugging`].
    pub fn histogram_shard_snapshots_for_debugging(
        &self,
        handle: HistogramHandle,
    ) -> Vec<HistogramSnapshot> {
        let state = self.published.load();
        state
            .histogram_shards
            .iter()
            .map(|worker_shards| {
                let shard = &worker_shards[handle.0];
                HistogramSnapshot {
                    bucket_counts: shard
                        .bucket_counts
                        .iter()
                        .map(|c| c.load(Ordering::Relaxed))
                        .collect(),
                    sum: f64::from_bits(shard.sum_bits.load(Ordering::Relaxed)),
                    count: shard.count.load(Ordering::Relaxed),
                }
            })
            .collect()
    }

    /// Every resolved histogram handle, paired with its instrument identity
    /// and resolved attributes — the histogram counterpart of
    /// [`Self::counters`]. Deliberately returns the [`HistogramHandle`]
    /// itself rather than a pre-summed figure: unlike a counter, a
    /// histogram's exporter-facing value is a *set* of percentiles (see
    /// [`Self::percentile`]), not one number, so the caller needs the
    /// handle to ask for each one. Control-side/scrape-side use only, same
    /// as [`Self::counters`] -- and, for the same reason, returns owned
    /// attrs rather than a `&self`-borrowed slice.
    pub fn histograms(
        &self,
    ) -> impl Iterator<Item = (HistogramHandle, &'static Instrument, Vec<(String, String)>)> {
        let state = self.published.load_full();
        let n = state.resolved_histograms.len();
        (0..n).map(move |i| {
            (
                HistogramHandle(i),
                state.resolved_histograms[i],
                state.resolved_histogram_attrs[i].clone(),
            )
        })
    }

    /// The `p`-th percentile (`p` in `[0, 100]`) of `handle`'s observations,
    /// summed across every worker shard, using **linear interpolation
    /// within the landing bucket** — what Envoy's `/stats` text format
    /// reports for P0/P25/.../P100, and increment 3's job to *render*, not
    /// to compute (see the module doc).
    ///
    /// Defined edge cases, so none of them are an accidental `NaN` or panic:
    /// - **Empty histogram** (`count == 0`): returns `0.0`. There is no
    ///   observation to derive a percentile from; `0.0` is a deliberate,
    ///   documented choice, not a fallen-through default.
    /// - **P0**: the lower edge of the first (lowest-boundary) bucket that
    ///   has any observations.
    /// - **P100**: the upper edge of the last (highest-boundary) bucket
    ///   that has any observations.
    /// - **All observations in one bucket**: interpolates linearly between
    ///   that bucket's lower and upper edge as `p` moves from 0 to 100 —
    ///   it does not snap to the bucket's boundary value regardless of `p`.
    /// - **Target falls in the overflow bucket**: the overflow bucket has
    ///   no declared upper edge (nothing above the last boundary is
    ///   tracked more precisely than "some value above it"), so this
    ///   returns that bucket's *lower* edge (the last real boundary) —
    ///   the same convention Prometheus's own `histogram_quantile` uses for
    ///   its `+Inf` bucket, for the same reason: interpolating towards an
    ///   upper bound we have no data for would be inventing precision.
    ///
    /// Panics if `p` is outside `[0, 100]` — a caller bug, not a data
    /// condition.
    pub fn percentile(&self, handle: HistogramHandle, p: f64) -> f64 {
        assert!(
            (0.0..=100.0).contains(&p),
            "stats::Registry::percentile: p must be in [0, 100], got {p}"
        );

        let snapshot = self.histogram_snapshot(handle);
        if snapshot.count == 0 {
            return 0.0;
        }

        let state = self.published.load();
        let instrument = state.resolved_histograms[handle.0];
        let boundaries = instrument
            .buckets
            .expect("stats::Registry::percentile: instrument has no bucket boundaries");

        let last_nonzero = snapshot
            .bucket_counts
            .iter()
            .rposition(|&c| c > 0)
            .expect("count > 0 implies at least one non-empty bucket");

        let target = (p / 100.0) * snapshot.count as f64;
        let mut cumulative_before = 0u64;
        for (i, &count) in snapshot.bucket_counts.iter().enumerate() {
            if count == 0 {
                continue;
            }
            let cumulative_after = cumulative_before + count;
            let lower = if i == 0 { 0.0 } else { boundaries[i - 1] };
            // Overflow bucket (i == boundaries.len()): no declared upper
            // edge, so fall back to its lower edge -- see the doc above.
            let upper = if i < boundaries.len() {
                boundaries[i]
            } else {
                lower
            };

            if target <= cumulative_after as f64 || i == last_nonzero {
                let fraction = ((target - cumulative_before as f64) / count as f64).clamp(0.0, 1.0);
                return lower + fraction * (upper - lower);
            }
            cumulative_before = cumulative_after;
        }
        // Unreachable given count > 0 (the loop above always returns from
        // the `last_nonzero` bucket at the latest), but a defensible
        // fallback rather than a panic if it's ever reached.
        *boundaries.last().unwrap_or(&0.0)
    }
}

/// The control-side owner of a [`Registry`]: the only type able to
/// [`resolve`](StatsControl::resolve)/
/// [`resolve_histogram`](StatsControl::resolve_histogram) new handles — see
/// the module doc's "Increment 5" section for why that is worth a whole
/// second type rather than a flag or a debug assertion.
///
/// Deliberately **not `Clone`**: there is exactly one control side per
/// process (config-lowering runs on one control runtime), and giving out
/// clones would just recreate the "who can resolve" ambiguity this type
/// exists to remove. [`Self::registry`] is what workers get instead — an
/// `Arc<Registry>` clone, which can resolve nothing.
pub struct StatsControl {
    registry: Arc<Registry>,
}

impl StatsControl {
    /// Build a fresh control side, and the empty [`Registry`] it owns, sized
    /// for `num_workers` shards. See [`Registry::empty`]'s doc for why
    /// `num_workers` is fixed here and not growable later.
    pub fn new(num_workers: usize) -> Self {
        Self {
            registry: Arc::new(Registry::empty(num_workers)),
        }
    }

    /// A clone of the `Arc<Registry>` this control side owns — what gets
    /// handed to workers (and to `/stats` scrape handlers). The clone can
    /// `incr`/`value`/`observe`/etc., but has no way to reach `resolve`: see
    /// the module doc's "Increment 5" section.
    pub fn registry(&self) -> Arc<Registry> {
        Arc::clone(&self.registry)
    }

    /// Resolves `(instrument, attrs)` into a [`Handle`], growing the
    /// underlying [`Registry`]'s published state if this is the first time
    /// this pair has been seen. See [`Registry::resolve`]'s doc for the
    /// dedup/validation/panic rules this forwards to unchanged.
    pub fn resolve(&self, instrument: &'static Instrument, attrs: &[(&str, &str)]) -> Handle {
        self.registry.resolve(instrument, attrs)
    }

    /// The histogram counterpart of [`Self::resolve`]. See
    /// [`Registry::resolve_histogram`]'s doc for the dedup/validation/panic
    /// rules this forwards to unchanged.
    pub fn resolve_histogram(
        &self,
        instrument: &'static Instrument,
        attrs: &[(&str, &str)],
    ) -> HistogramHandle {
        self.registry.resolve_histogram(instrument, attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // ---- 1: resolve identity -------------------------------------------

    #[test]
    fn resolving_same_instrument_and_attrs_twice_yields_same_handle() {
        let control = StatsControl::new(1);
        let a = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let b = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        assert_eq!(
            a, b,
            "same (instrument, attrs) must resolve to the same handle"
        );

        let c = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "anthropic")]);
        assert_ne!(
            a, c,
            "different attribute values must resolve to different handles"
        );
    }

    // ---- 2/3: attribute-key mismatch is rejected loudly -----------------

    #[test]
    #[should_panic(expected = "attribute keys don't match")]
    fn unexpected_attribute_key_is_rejected_loudly() {
        let control = StatsControl::new(1);
        // "region" is not in UPSTREAM_RQ's attribute_keys (["cluster"]).
        control.resolve(
            &instruments::UPSTREAM_RQ,
            &[("cluster", "openai"), ("region", "us-east-1")],
        );
    }

    #[test]
    #[should_panic(expected = "attribute keys don't match")]
    fn missing_expected_attribute_key_is_rejected_loudly() {
        let control = StatsControl::new(1);
        // LLM_CLIENT_TOKEN_USAGE expects "provider", "type", AND "tenant"
        // (WP-55) -- "tenant" is missing here.
        control.resolve(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[("provider", "openai"), ("type", "input")],
        );
    }

    // ---- 4: attribute order doesn't affect identity ----------------------

    #[test]
    fn attribute_order_does_not_affect_handle_identity() {
        let control = StatsControl::new(1);
        let a = control.resolve(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "acme"),
            ],
        );
        let b = control.resolve(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("tenant", "acme"),
                ("type", "input"),
                ("provider", "openai"),
            ],
        );
        assert_eq!(a, b, "attribute order must not affect handle identity");
    }

    // ---- 5: increments from several workers sum (the ADR-0005 trap) -----

    /// The ADR-0005 trap, stated as such: a per-worker counter that never
    /// aggregates is wrong by the worker count. Drives N > 1 worker ids and
    /// asserts `value()` is the *total* -- and explicitly that it is NOT the
    /// figure any single worker recorded, so a broken implementation that
    /// just returns one shard's slot cannot pass this test by accident (as
    /// it would if this only asserted `== total` with N == 1).
    #[test]
    fn increments_from_several_workers_sum_not_a_single_shards_figure() {
        let control = StatsControl::new(3);
        let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();

        registry.incr(WorkerId(0), h, 10);
        registry.incr(WorkerId(1), h, 20);
        registry.incr(WorkerId(2), h, 30);

        let total = registry.value(h);
        assert_eq!(
            total, 60,
            "value() must be the sum across every worker shard"
        );

        // The trap: none of the individual shards' figures equal the total.
        for (worker, single_worker_figure) in [(0, 10u64), (1, 20), (2, 30)] {
            assert_ne!(
                total, single_worker_figure,
                "value() must not equal worker {worker}'s figure alone -- that is exactly \
                 the ADR-0005 per-worker-counter-that-never-aggregates trap"
            );
        }

        // Confirmed directly against the debug-only per-shard view too.
        assert_eq!(registry.shard_values_for_debugging(h), vec![10, 20, 30]);
    }

    // ---- 6: concurrent increments from multiple threads total correctly --

    #[test]
    fn concurrent_increments_from_multiple_threads_total_correctly() {
        const WORKERS: usize = 4;
        const INCREMENTS_PER_WORKER: u64 = 10_000;

        let control = StatsControl::new(WORKERS);
        let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();

        let handles: Vec<_> = (0..WORKERS)
            .map(|w| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    for _ in 0..INCREMENTS_PER_WORKER {
                        registry.incr(WorkerId(w), h, 1);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(
            registry.value(h),
            WORKERS as u64 * INCREMENTS_PER_WORKER,
            "concurrent increments across worker threads must total correctly"
        );
    }

    // ---- 7: UpDownCounter vs Counter API shape ---------------------------

    #[test]
    fn up_down_counter_handles_negative_deltas() {
        // No starter UpDownCounter const exists yet (increment 1's set is
        // all Counters), so build one locally to exercise the shape.
        static CX_ACTIVE: Instrument = Instrument {
            name: "downstream_cx_active",
            kind: InstrumentKind::UpDownCounter,
            unit: "{connection}",
            attribute_keys: &["listener"],
            buckets: None,
        };

        let control = StatsControl::new(1);
        let h = control.resolve(&CX_ACTIVE, &[("listener", "ingress")]);
        let registry = control.registry();

        registry.add(WorkerId(0), h, 5);
        registry.add(WorkerId(0), h, 5);
        assert_eq!(registry.value(h), 10);

        registry.add(WorkerId(0), h, -3);
        assert_eq!(
            registry.value(h),
            7,
            "UpDownCounter must accept a negative delta and move the value down"
        );
    }

    #[test]
    #[should_panic(expected = "has no decrement")]
    fn counter_does_not_expose_a_decrement() {
        // Assert the API SHAPE, not just behaviour: `add` (the only method
        // that can carry a negative delta) is refused outright for a
        // Counter handle -- there is no way to move UPSTREAM_RQ down, full
        // stop, not "moving it down happens to leave it unchanged".
        let control = StatsControl::new(1);
        let h = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();
        registry.add(WorkerId(0), h, -1);
    }

    // ---- 8: semconv version is pinned ------------------------------------

    #[test]
    fn semconv_version_is_pinned() {
        // A change here is a breaking change to the metric surface (module
        // doc, "Decision 5") and must appear in the CHANGELOG -- this test
        // exists so bumping the literal without doing that is at least a
        // deliberate, visible edit to this assertion, not a drive-by.
        assert_eq!(SEMCONV_VERSION, "1.27.0");
    }

    // ==== Increment 2: histograms ==========================================

    // ---- 9: all nineteen Envoy default boundaries are pinned -------------

    #[test]
    fn envoy_default_histogram_buckets_are_pinned() {
        // Vendored from
        // crates/proxy-api/vendor/envoy/config/metrics/v3/stats.proto,
        // lines 86-104. Changing any of these values is a breaking change
        // to anyone's dashboard -- the same standing this module gives
        // SEMCONV_VERSION -- so a change here must be a deliberate, visible
        // edit to this assertion, not a drive-by.
        assert_eq!(
            ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS,
            [
                0.5, 1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2500.0, 5000.0,
                10000.0, 30000.0, 60000.0, 300000.0, 600000.0, 1800000.0, 3600000.0,
            ]
        );
        assert_eq!(
            ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS.len(),
            19,
            "nineteen boundaries -- twenty bucket slots once the overflow bucket is added"
        );
    }

    // ---- 10: an observation lands in the correct bucket, table-driven ----

    #[test]
    fn observation_lands_in_the_correct_bucket() {
        // (observed value, expected bucket index). Boundaries are
        // ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS:
        //   [0]=0.5 [1]=1 [2]=5 [3]=10 [4]=25 ... [18]=3_600_000
        // Boundaries are INCLUSIVE (Prometheus `le`): a value exactly on a
        // boundary lands in that boundary's own bucket, not the next one.
        let cases: &[(f64, usize)] = &[
            (0.0, 0), // below the first boundary
            (0.5, 0), // exactly on the first boundary -- inclusive
            (0.4, 0),
            (0.6, 1), // just above 0.5, below 1
            (1.0, 1), // exactly on the second boundary -- inclusive
            (5.0, 2), // exactly on a middle boundary -- inclusive
            (7.0, 3), // strictly between two boundaries (5, 10]
            (3_600_000.0, 18), // exactly on the LAST boundary -- inclusive,
                      // still lands in the last real bucket, not overflow
        ];

        for &(value, expected_bucket) in cases {
            let control = StatsControl::new(1);
            let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
            let registry = control.registry();
            registry.observe(WorkerId(0), h, value);

            let snapshot = registry.histogram_snapshot(h);
            assert_eq!(
                snapshot.bucket_counts[expected_bucket], 1,
                "value {value} expected in bucket {expected_bucket}, got counts {:?}",
                snapshot.bucket_counts
            );
            assert_eq!(
                snapshot.bucket_counts.iter().sum::<u64>(),
                1,
                "value {value} must land in exactly one bucket"
            );
        }
    }

    // ---- 11: an observation above the last boundary lands in overflow ----

    #[test]
    fn observation_above_last_boundary_lands_in_overflow_bucket() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();

        // Strictly greater than the last boundary, 3_600_000.
        registry.observe(WorkerId(0), h, 3_600_000.1);
        registry.observe(WorkerId(0), h, 10_000_000.0);

        let snapshot = registry.histogram_snapshot(h);
        assert_eq!(
            snapshot.bucket_counts.len(),
            20,
            "19 boundaries -> 20 bucket slots (19 boundary buckets + 1 overflow)"
        );
        let overflow_index = snapshot.bucket_counts.len() - 1;
        assert_eq!(
            snapshot.bucket_counts[overflow_index], 2,
            "both above-last-boundary observations must land in the overflow bucket"
        );
        // Nothing leaked into the last *finite* boundary's bucket.
        assert_eq!(snapshot.bucket_counts[18], 0);
        assert_eq!(snapshot.count, 2);
    }

    // ---- 12: bucket counts, sum, and count all sum across worker shards --

    #[test]
    fn histogram_bucket_counts_sum_and_count_sum_across_worker_shards() {
        let control = StatsControl::new(3);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();

        // Worker 0: two observations in the (5, 10] bucket (index 3).
        registry.observe(WorkerId(0), h, 7.0);
        registry.observe(WorkerId(0), h, 8.0);
        // Worker 1: one observation in the same bucket, one in overflow.
        registry.observe(WorkerId(1), h, 9.0);
        registry.observe(WorkerId(1), h, 5_000_000.0);
        // Worker 2: nothing.

        let snapshot = registry.histogram_snapshot(h);
        assert_eq!(snapshot.bucket_counts[3], 3, "3 observations in (5, 10]");
        assert_eq!(snapshot.bucket_counts[19], 1, "1 observation in overflow");
        assert_eq!(snapshot.count, 4);
        assert_eq!(snapshot.sum, 7.0 + 8.0 + 9.0 + 5_000_000.0);

        // The ADR-0005 trap again, for histograms: the summed snapshot must
        // differ from any single shard's own figures.
        let per_shard = registry.histogram_shard_snapshots_for_debugging(h);
        assert_eq!(per_shard.len(), 3);
        for shard_snapshot in &per_shard {
            assert_ne!(
                shard_snapshot.count, snapshot.count,
                "no single shard recorded all 4 observations"
            );
            assert_ne!(
                shard_snapshot.sum, snapshot.sum,
                "no single shard's sum equals the cross-shard total"
            );
            assert_ne!(
                *shard_snapshot, snapshot,
                "no single shard's full snapshot equals the summed one"
            );
        }
        // And the pieces really do add up: summing every per-shard bucket
        // count equals the registry's own summed snapshot.
        let bucket_total: u64 = per_shard
            .iter()
            .flat_map(|s| s.bucket_counts.iter())
            .sum::<u64>();
        assert_eq!(bucket_total, snapshot.bucket_counts.iter().sum::<u64>());
    }

    // ---- 13: percentile edges: P0, P100, empty, all-in-one-bucket --------

    #[test]
    fn percentile_of_empty_histogram_is_documented_zero_not_nan_or_panic() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();

        for p in [0.0, 50.0, 99.9, 100.0] {
            let result = registry.percentile(h, p);
            assert_eq!(
                result, 0.0,
                "empty histogram's P{p} must be the documented 0.0"
            );
            assert!(!result.is_nan());
        }
    }

    #[test]
    fn percentile_edges_of_all_observations_in_one_bucket() {
        // All four observations land in the (5, 10] bucket (index 3):
        // boundaries[2] = 5 (lower edge), boundaries[3] = 10 (upper edge).
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();
        for value in [6.0, 7.0, 8.0, 9.0] {
            registry.observe(WorkerId(0), h, value);
        }

        assert_eq!(
            registry.percentile(h, 0.0),
            5.0,
            "P0 is the bucket's lower edge"
        );
        assert_eq!(
            registry.percentile(h, 100.0),
            10.0,
            "P100 is the bucket's upper edge"
        );
        // Interpolated midpoint -- NOT snapped to either boundary, and not
        // equal to any of the four actual observed values (this is bucket-
        // count-based interpolation, not exact-value ranking).
        let p50 = registry.percentile(h, 50.0);
        assert_eq!(p50, 7.5, "P50 within a single bucket interpolates linearly");
        assert_ne!(p50, 5.0);
        assert_ne!(p50, 10.0);
    }

    // ---- 14: a percentile between two boundaries interpolates ------------

    #[test]
    fn percentile_spanning_two_buckets_interpolates_rather_than_snapping() {
        let control = StatsControl::new(1);
        let h = control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
        let registry = control.registry();

        // One observation in (1, 5] (index 2), one in (5, 10] (index 3).
        registry.observe(WorkerId(0), h, 3.0);
        registry.observe(WorkerId(0), h, 8.0);

        // target = 0.75 * 2 = 1.5, which falls inside the second bucket
        // (cumulative after bucket 2 is 1, after bucket 3 is 2):
        // fraction = (1.5 - 1) / 1 = 0.5 -> 5 + 0.5 * (10 - 5) = 7.5.
        let p75 = registry.percentile(h, 75.0);
        assert_eq!(p75, 7.5);
        assert_ne!(p75, 5.0, "must not snap to the lower boundary");
        assert_ne!(p75, 10.0, "must not snap to the upper boundary");
    }

    // ---- 15: a counter handle used with observe (or vice versa) does not
    //          compile -- see HistogramHandle's `compile_fail` doctests for
    //          the machine-checked proof. What remains for a runtime test is
    //          the *kind* mismatch a shared handle-space check would also
    //          need to reject: passing the wrong kind of instrument to
    //          resolve/resolve_histogram, which is checked at resolve time
    //          rather than deferred to incr/observe.

    #[test]
    #[should_panic(expected = "is a Histogram")]
    fn resolve_rejects_a_histogram_instrument() {
        let control = StatsControl::new(1);
        control.resolve(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
    }

    #[test]
    #[should_panic(expected = "is not a Histogram")]
    fn resolve_histogram_rejects_a_counter_instrument() {
        let control = StatsControl::new(1);
        control.resolve_histogram(&instruments::UPSTREAM_RQ, &[("cluster", "x")]);
    }

    // ==== Increment 5: resolution survives a config swap ===================
    //
    // Before this increment, `Registry::resolve` took `&mut self`, which
    // simply would not compile once `registry` below is shared as
    // `Arc<Registry>` and moved into a worker thread -- there would be no
    // way to reach `&mut self` through it. The tests in this section are
    // the ones that could not even be written, let alone pass, before the
    // `Registry`/`StatsControl` split.

    // ---- 16: the gate test -- resolution survives sharing -----------------

    #[test]
    fn resolution_survives_sharing_a_new_handle_resolves_while_a_worker_holds_the_registry() {
        let control = StatsControl::new(1);
        let existing = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();

        // A worker holds only `Arc<Registry>` -- exactly what
        // `crates/proxy/src/main.rs` hands to a worker thread -- and
        // increments an ALREADY-resolved handle from there while the
        // control side is still live.
        let worker_registry = Arc::clone(&registry);
        let worker = thread::spawn(move || {
            worker_registry.incr(WorkerId(0), existing, 5);
        });
        worker.join().unwrap();

        // The control side resolves a NEW handle -- the exact scenario that
        // could never happen once the registry was shared, before this
        // increment (WP-23's ship-gate: a config swap that introduces a new
        // cluster must be able to register its counters).
        let fresh = control.resolve(
            &instruments::DOWNSTREAM_CX_TOTAL,
            &[("listener", "ingress")],
        );
        registry.incr(WorkerId(0), fresh, 7);

        assert_eq!(
            registry.value(existing),
            5,
            "a handle resolved before sharing must keep working after a later resolve grows \
             the registry"
        );
        assert_eq!(
            registry.value(fresh),
            7,
            "a handle resolved AFTER the registry was already shared with a worker must work \
             -- this is the exact case increment 5 exists to fix"
        );
    }

    // ---- 17: no lost increments across growth ------------------------------

    /// Pins the design brief's explicitly REJECTED alternative as wrong:
    /// rebuilding the registry and copying counter VALUES across loses any
    /// increment landing between the read and the swap -- a metrics bug
    /// that would show up as a dip in `rate()` at every config reload. A
    /// naive `Vec` that reallocates on push has the identical bug for the
    /// same reason (it moves the atomics a concurrent writer is touching).
    /// This test hammers `incr` on an already-resolved handle from several
    /// threads while the control side concurrently resolves 200 new
    /// handles -- enough to cross several `COUNTER_BLOCK_LEN` boundaries --
    /// then asserts the total is EXACTLY the number of increments issued,
    /// not off by even one.
    #[test]
    fn no_lost_increments_while_resolving_new_handles_concurrently() {
        const INCR_THREADS: usize = 4;
        const INCREMENTS_PER_THREAD: u64 = 20_000;
        const NEW_HANDLES_TO_RESOLVE: usize = 200;

        let control = StatsControl::new(INCR_THREADS);
        let target = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = control.registry();

        let incrementers: Vec<_> = (0..INCR_THREADS)
            .map(|w| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    for _ in 0..INCREMENTS_PER_THREAD {
                        registry.incr(WorkerId(w), target, 1);
                    }
                })
            })
            .collect();

        // Growth, concurrently with the increments above: each resolve
        // clones the shard `Vec`s and swaps a new `Snapshot` in -- exactly
        // the operation that would race a concurrent `incr` under a naive
        // "reallocate the shard storage in place" implementation, and the
        // operation the rejected "copy counter values across" design (see
        // the module doc) would lose an in-flight increment against.
        let resolver = thread::spawn(move || {
            for i in 0..NEW_HANDLES_TO_RESOLVE {
                let cluster = format!("provider-{i}");
                control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", cluster.as_str())]);
            }
        });

        for t in incrementers {
            t.join().unwrap();
        }
        resolver.join().unwrap();

        assert_eq!(
            registry.value(target),
            INCR_THREADS as u64 * INCREMENTS_PER_THREAD,
            "every increment issued must be reflected exactly -- a lost increment here is \
             the rejected 'copy counter values across' bug, or the 'Vec reallocates on push' \
             bug, actually reproducing"
        );
    }

    // ---- 18: existing handles keep their values and indices across growth -

    #[test]
    fn existing_handles_keep_their_values_and_indices_across_a_block_boundary() {
        let control = StatsControl::new(1);
        let registry = control.registry();

        // Resolve handle 0 first and give it a distinctive value before
        // growing well past it.
        let first = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "block-0-handle")]);
        registry.incr(WorkerId(0), first, 42);

        // Resolve 70 handles total (>= COUNTER_BLOCK_LEN + 1), so growth
        // crosses a block boundary and a second block exists. Checked at
        // compile time (both sides are `const`) rather than a runtime
        // `assert!`, which clippy correctly flags as always-true.
        const NUM_HANDLES: usize = 70;
        const _: () = assert!(
            NUM_HANDLES > COUNTER_BLOCK_LEN,
            "test setup: need at least two blocks' worth of handles"
        );
        let mut last = first;
        for i in 1..NUM_HANDLES {
            let cluster = format!("cluster-{i}");
            last = control.resolve(&instruments::UPSTREAM_RQ, &[("cluster", cluster.as_str())]);
        }

        // `first`'s value and identity must be unaffected by every growth
        // that happened after it, including the block-boundary crossing.
        assert_eq!(
            registry.value(first),
            42,
            "a handle resolved before growth must keep its value after a block boundary"
        );

        // A handle resolved from the new block works too, independently.
        registry.incr(WorkerId(0), last, 99);
        assert_eq!(registry.value(last), 99);
        assert_eq!(
            registry.value(first),
            42,
            "incrementing a handle from the new block must not disturb block 0's handle"
        );
    }

    // ---- 19/20: histogram equivalents of 16 and 17 -------------------------

    #[test]
    fn histogram_resolution_survives_sharing_a_new_handle_resolves_while_a_worker_holds_the_registry(
    ) {
        let control = StatsControl::new(1);
        let existing =
            control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "openai")]);
        let registry = control.registry();

        let worker_registry = Arc::clone(&registry);
        let worker = thread::spawn(move || {
            worker_registry.observe(WorkerId(0), existing, 7.0);
        });
        worker.join().unwrap();

        let fresh =
            control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "anthropic")]);
        registry.observe(WorkerId(0), fresh, 3.0);

        assert_eq!(
            registry.histogram_snapshot(existing).count,
            1,
            "a histogram handle resolved before sharing must keep working after a later \
             resolve grows the registry"
        );
        assert_eq!(
            registry.histogram_snapshot(fresh).count,
            1,
            "a histogram handle resolved AFTER the registry was already shared must work"
        );
    }

    /// The histogram counterpart of test 17: hammers `observe` on an
    /// already-resolved histogram handle from several threads while the
    /// control side concurrently resolves 50 new histogram handles (each
    /// growth appends one fresh `Arc<HistogramShard>` per worker -- see the
    /// module doc for why histograms are unblocked, unlike counters).
    #[test]
    fn no_lost_histogram_observations_while_resolving_new_handles_concurrently() {
        const OBS_THREADS: usize = 4;
        const OBSERVATIONS_PER_THREAD: u64 = 5_000;
        const NEW_HANDLES_TO_RESOLVE: usize = 50;

        let control = StatsControl::new(OBS_THREADS);
        let target =
            control.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "openai")]);
        let registry = control.registry();

        let observers: Vec<_> = (0..OBS_THREADS)
            .map(|w| {
                let registry = Arc::clone(&registry);
                thread::spawn(move || {
                    for _ in 0..OBSERVATIONS_PER_THREAD {
                        registry.observe(WorkerId(w), target, 7.0);
                    }
                })
            })
            .collect();

        let resolver = thread::spawn(move || {
            for i in 0..NEW_HANDLES_TO_RESOLVE {
                let cluster = format!("provider-{i}");
                control.resolve_histogram(
                    &instruments::UPSTREAM_RQ_TIME,
                    &[("cluster", cluster.as_str())],
                );
            }
        });

        for t in observers {
            t.join().unwrap();
        }
        resolver.join().unwrap();

        let snapshot = registry.histogram_snapshot(target);
        assert_eq!(
            snapshot.count,
            OBS_THREADS as u64 * OBSERVATIONS_PER_THREAD,
            "every observation issued must be reflected exactly, same claim as test 17 but \
             for histograms"
        );
    }

    // ---- WP-55: Registry::resolve_capped ---------------------------------

    #[test]
    fn resolve_capped_below_ceiling_behaves_like_a_plain_resolve() {
        let control = StatsControl::new(1);
        let registry = control.registry();

        let a = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "acme"),
            ],
            10,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "OVERFLOW"),
            ],
        );
        let b = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "acme"),
            ],
            10,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "OVERFLOW"),
            ],
        );
        assert_eq!(
            a, b,
            "the same attrs must dedup to the same handle, well below the ceiling"
        );

        let c = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "widgetco"),
            ],
            10,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "OVERFLOW"),
            ],
        );
        assert_ne!(
            a, c,
            "a different tenant must get its own series below the ceiling"
        );
    }

    /// The mitigation itself: once `ceiling` resolved series exist for the
    /// instrument, a genuinely NEW attrs combination folds into
    /// `overflow_attrs` instead of growing the registry further -- and every
    /// such new combination shares the SAME overflow handle, not one each
    /// (which would just move the unbounded-growth problem one level down).
    #[test]
    fn resolve_capped_folds_new_attrs_into_one_shared_overflow_series_once_the_ceiling_trips() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let overflow_attrs = [
            ("provider", "openai"),
            ("type", "input"),
            ("tenant", "OVERFLOW"),
        ];
        let resolve = |tenant: &str| {
            registry.resolve_capped(
                &instruments::LLM_CLIENT_TOKEN_USAGE,
                &[
                    ("provider", "openai"),
                    ("type", "input"),
                    ("tenant", tenant),
                ],
                2, // ceiling: only 2 real series allowed
                &overflow_attrs,
            )
        };

        let a = resolve("tenant-a");
        let b = resolve("tenant-b");
        assert_ne!(a, b, "both series fit under the ceiling of 2");

        // The ceiling is now exactly met -- a third, never-seen tenant must
        // NOT get its own series.
        let c = resolve("tenant-c");
        let d = resolve("tenant-d");
        assert_eq!(
            c, d,
            "two DIFFERENT overflowing tenants must collapse onto the SAME overflow series, \
             not each get their own -- otherwise the mitigation just relabels the unbounded \
             growth instead of bounding it"
        );
        assert_ne!(
            c, a,
            "the overflow series must not alias a real tenant's series"
        );

        // The overflow handle must be reachable directly via the overflow
        // attrs too -- it is a real, first-class series, not a special case.
        let direct_overflow = registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &overflow_attrs,
            2,
            &overflow_attrs,
        );
        assert_eq!(c, direct_overflow);
    }

    /// The other half of the mitigation's honesty: a tenant that already had
    /// its own series BEFORE the ceiling tripped keeps using it afterwards --
    /// the ceiling only stops NEW growth, it does not retroactively merge
    /// already-distinguished tenants into the overflow bucket.
    #[test]
    fn resolve_capped_does_not_disturb_a_tenant_resolved_before_the_ceiling_tripped() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let overflow_attrs = [
            ("provider", "openai"),
            ("type", "input"),
            ("tenant", "OVERFLOW"),
        ];
        let resolve = |tenant: &str| {
            registry.resolve_capped(
                &instruments::LLM_CLIENT_TOKEN_USAGE,
                &[
                    ("provider", "openai"),
                    ("type", "input"),
                    ("tenant", tenant),
                ],
                1, // ceiling: only 1 real series allowed
                &overflow_attrs,
            )
        };

        let early = resolve("tenant-a");
        // Trips the ceiling for everyone else.
        let overflowed = resolve("tenant-b");
        assert_ne!(early, overflowed);

        // "tenant-a" must still resolve to ITS OWN handle, not the overflow
        // one, even though the ceiling has since been reached.
        let early_again = resolve("tenant-a");
        assert_eq!(
            early, early_again,
            "a tenant given its own series before the ceiling tripped must keep it"
        );
    }

    #[test]
    fn resolve_histogram_capped_folds_new_models_into_one_shared_overflow_series() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        let overflow_attrs = [
            ("gen_ai.operation.name", "chat"),
            ("gen_ai.request.model", "-cardinality-overflow-"),
            ("gen_ai.system", "openai"),
        ];
        let resolve = |model: &str| {
            registry.resolve_histogram_capped(
                &instruments::GEN_AI_SERVER_TIME_TO_FIRST_TOKEN,
                &[
                    ("gen_ai.operation.name", "chat"),
                    ("gen_ai.request.model", model),
                    ("gen_ai.system", "openai"),
                ],
                2,
                &overflow_attrs,
            )
        };

        let a = resolve("model-a");
        let b = resolve("model-b");
        let c = resolve("model-c");
        let d = resolve("model-d");

        assert_ne!(a, b, "two models fit below the ceiling");
        assert_eq!(
            c, d,
            "new models above the ceiling must share the overflow histogram"
        );
        assert_ne!(c, a);
        assert_eq!(c, resolve("-cardinality-overflow-"));
    }

    #[test]
    #[should_panic(expected = "attribute keys don't match")]
    fn resolve_capped_still_validates_attrs() {
        let control = StatsControl::new(1);
        let registry = control.registry();
        // Missing "tenant" -- same validation `resolve` itself enforces.
        registry.resolve_capped(
            &instruments::LLM_CLIENT_TOKEN_USAGE,
            &[("provider", "openai"), ("type", "input")],
            10,
            &[
                ("provider", "openai"),
                ("type", "input"),
                ("tenant", "OVERFLOW"),
            ],
        );
    }
}
