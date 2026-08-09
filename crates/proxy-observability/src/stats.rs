//! WP-23 increments 1–2 — the stats registry core: instruments, [`Handle`]/
//! [`HistogramHandle`] resolution, and sharded, summed counters and
//! histograms. Pure library: no HTTP, no `/stats` rendering, no Prometheus,
//! no instrumentation call sites — those are increments 3–5
//! (`docs/wp-23-stats-design-brief.md`, which is normative for every
//! decision below).
//!
//! # Decision 1 — the hot path increments an index, not a name
//!
//! An OTel measurement is `(instrument, attribute set)`. Resolving that per
//! request means hashing an attribute set on the request path, which this
//! proxy cannot afford. So resolution and increment are split:
//!
//! ```
//! use proxy_observability::stats::{instruments, Registry, WorkerId};
//!
//! // Control side, once, when a cluster/listener/route enters the config
//! // snapshot:
//! let mut registry = Registry::new(1);
//! let h = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "provider:openai")]);
//!
//! // Hot path, per request: no hashing, no allocation, no string.
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
//! # `resolve` takes `&mut self`; `incr`/`value` take `&self`
//!
//! Rust note: this split is not decorative — it is what makes "growing a
//! shard while a worker increments it" a thing the compiler forbids rather
//! than a race we have to reason about at runtime. [`Registry::resolve`]
//! needs `&mut self` because it appends a new slot to every shard; a worker's
//! [`Registry::incr`]/[`Registry::value`] only ever need `&self`. Once a
//! `Registry` is shared across worker threads (e.g. behind an `Arc`), the
//! only references any thread can hold are `&self` — there is no safe way to
//! reach `&mut self` through an `Arc` while other clones exist, so `resolve`
//! is simply unreachable at that point. In this increment that means: build
//! the `Registry` and call `resolve` for every handle a config snapshot
//! needs, *then* hand it out for concurrent `incr`/`value` calls. A future
//! config swap publishes a whole new `Registry` (the same lifecycle
//! `ClusterManager` already uses via `ArcSwap`) rather than mutating a shared
//! one in place — this increment does not build that publishing path, only
//! the type that makes it safe to build. [`Registry::resolve_histogram`]
//! follows the identical rule (`&mut self`, control-side only).
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
//! [`Registry::resolve`] **cannot be passed to** [`Registry::observe`], and a
//! `HistogramHandle` returned by [`Registry::resolve_histogram`] **cannot be
//! passed to** [`Registry::incr`]/[`Registry::add`]/[`Registry::value`] —
//! not "rejected at runtime", but a compile error, because the two types are
//! unrelated as far as the type checker is concerned. See
//! [`HistogramHandle`]'s doc for a `compile_fail` example proving this.
//!
//! This is the same argument as the `&mut self`/`&self` split above: making
//! a mistake *impossible* is strictly better than making it *loud*, when the
//! type system can carry the whole cost at zero runtime price (a
//! `HistogramHandle` is exactly as cheap as a `Handle` — one `usize`). A
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

/// WP-23 increment 3: renders a [`Registry`] into Envoy's flat `/stats` text
/// format. See the module's own doc comment for what is and is not verified
/// about that format.
pub mod envoy_render;

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
/// fewer. [`Registry::resolve`]/[`Registry::resolve_histogram`] check a
/// caller's attributes against `attribute_keys`, order-insensitively, and
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
    /// — exactly these, in any order. See [`Registry::resolve`].
    pub attribute_keys: &'static [&'static str],
    /// Histogram bucket boundaries, in `unit`, ascending, exclusive of the
    /// implicit overflow bucket. `Some` if and only if `kind` is
    /// [`InstrumentKind::Histogram`] — [`Registry::resolve_histogram`] and
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
    use super::{Instrument, InstrumentKind, ENVOY_DEFAULT_HISTOGRAM_BUCKETS_MS};

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
    /// The real OTel GenAI semantic conventions define
    /// `gen_ai.client.token.usage` as a *histogram* (a per-request token
    /// count distribution), not a counter. This starter still models it as a
    /// running-total `Counter` rather than switching it to a `Histogram` now
    /// that increment 2 has landed — that switch needs its own bucket
    /// boundaries (OTel doesn't mandate Envoy's millisecond `rq_time` set
    /// for a token count) and is increment 5's call, not this one's. Keeping
    /// it a `Counter` here avoids guessing at that number now. Attribute
    /// keys (`provider`, `type`) match the design brief's own table rather
    /// than the semconv's fully qualified `gen_ai.provider.name` /
    /// `gen_ai.token.type`; the increment-4 Prometheus renderer is where
    /// full key names matter.
    pub const GEN_AI_CLIENT_TOKEN_USAGE: Instrument = Instrument {
        name: "gen_ai.client.token.usage",
        kind: InstrumentKind::Counter,
        unit: "{token}",
        attribute_keys: &["provider", "type"],
        buckets: None,
    };

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
/// attribute set)` pair. Returned by [`Registry::resolve`]; carries no name,
/// no attributes — that is the point (see the module doc's Decision 1). The
/// inner `usize` is private to this module: outside it, a `Handle` can only
/// be obtained from `resolve` and only used by handing it back to
/// `incr`/`add`/`value`.
///
/// **Not the same type as [`HistogramHandle`]** — see the module doc's
/// "handle-space question" section for why they are deliberately distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(usize);

/// An opaque handle to one resolved `(histogram instrument, attribute set)`
/// pair. Returned by [`Registry::resolve_histogram`]; used only with
/// [`Registry::observe`].
///
/// A **distinct type from [`Handle`]**, occupying its own index space, so
/// this and `Handle` can never be confused for one another — passing one
/// where the other is expected is a compile error, not a runtime check:
///
/// ```compile_fail
/// use proxy_observability::stats::{instruments, Registry, WorkerId};
///
/// let mut registry = Registry::new(1);
/// let h = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
/// // ERROR: expected `HistogramHandle`, found `Handle`.
/// registry.observe(WorkerId(0), h, 1.0);
/// ```
///
/// and the mirror image:
///
/// ```compile_fail
/// use proxy_observability::stats::{instruments, Registry, WorkerId};
///
/// let mut registry = Registry::new(1);
/// let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "openai")]);
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
/// as a `type` alias (rather than inlined into `Registry`'s field) purely to
/// keep that field declaration readable — clippy's `type_complexity` lint
/// flagged the inline form.
type ResolveKey = (&'static str, Vec<(String, String)>);

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
            // Rust note: same reason as `Registry::new`'s shard construction
            // below -- `AtomicU64` isn't `Clone`, so `vec![AtomicU64::new(0);
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

/// The stats registry: resolves `(instrument, attrs)` into [`Handle`]s (for
/// counters/up-down-counters) or [`HistogramHandle`]s (for histograms) at
/// config-lowering time, and stores per-worker, per-handle data that
/// [`Registry::value`]/[`Registry::histogram_snapshot`] sum on read. See the
/// module doc for the full design — in particular why `resolve`/
/// `resolve_histogram` take `&mut self` while every hot-path method takes
/// `&self`.
pub struct Registry {
    /// Indexed by `Handle`'s inner `usize`. Kept so `incr`/`add` can look up
    /// an instrument's kind (to enforce "Counters don't decrement") and a
    /// future increment can look up name/unit/attrs for rendering.
    resolved: Vec<&'static Instrument>,
    /// Indexed in lockstep with `resolved`: the sorted `(key, value)` attrs
    /// each handle was resolved with. WP-23 increment 3 (`envoy_render`)
    /// reads this to expand attribute values into Envoy `/stats` name
    /// segments (e.g. a `status_class` attribute becomes
    /// `..._2xx`/`..._5xx`) -- see [`Self::counters`].
    resolved_attrs: Vec<Vec<(String, String)>>,
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
    /// `shards[worker.0][handle.0]` is that worker's slot for that handle.
    /// Every shard is grown in lockstep by `resolve`, so any handle that
    /// exists has a slot in every shard — see the module doc for why that
    /// growth can't race a concurrent `incr`/`value`.
    shards: Vec<Vec<AtomicU64>>,
    /// Same role as `resolved`, for [`HistogramHandle`]s. A separate `Vec`
    /// in its own index space — see the module doc's "handle-space
    /// question".
    resolved_histograms: Vec<&'static Instrument>,
    /// Same role as `resolved_attrs`, for [`HistogramHandle`]s.
    resolved_histogram_attrs: Vec<Vec<(String, String)>>,
    /// Same role as `lookup`, for histograms.
    histogram_lookup: HashMap<ResolveKey, HistogramHandle>,
    /// `histogram_shards[worker.0][handle.0]` is that worker's
    /// [`HistogramShard`] for that histogram handle. Grown in lockstep by
    /// `resolve_histogram`, same invariant as `shards`.
    histogram_shards: Vec<Vec<HistogramShard>>,
}

impl Registry {
    /// Build an empty registry sized for `num_workers` shards. `num_workers`
    /// is a config-time constant (`WorkerPoolConfig::concurrency`, in
    /// `proxy-core`) — this increment does not support growing the worker
    /// count after construction.
    pub fn new(num_workers: usize) -> Self {
        Self {
            resolved: Vec::new(),
            resolved_attrs: Vec::new(),
            lookup: HashMap::new(),
            // Rust note: not `vec![Vec::new(); num_workers]` -- that macro
            // needs `Vec<AtomicU64>: Clone`, which needs `AtomicU64: Clone`,
            // which atomics deliberately don't implement (cloning an atomic
            // would silently split one counter into two). Building each
            // shard from a fresh closure call sidesteps the bound entirely.
            shards: (0..num_workers).map(|_| Vec::new()).collect(),
            resolved_histograms: Vec::new(),
            resolved_histogram_attrs: Vec::new(),
            histogram_lookup: HashMap::new(),
            histogram_shards: (0..num_workers).map(|_| Vec::new()).collect(),
        }
    }

    /// How many worker shards this registry was built with.
    pub fn num_workers(&self) -> usize {
        self.shards.len()
    }

    /// Control side only, at config-lowering time — see the module doc for
    /// why this takes `&mut self`. Resolving the same `(instrument, attrs)`
    /// twice (attribute order does not matter) returns the same [`Handle`].
    ///
    /// Panics if `attrs`' keys don't exactly match `instrument.attribute_keys`
    /// (missing or unexpected) — loudly, on purpose: a typo'd attribute key
    /// must not silently start a second, parallel time series. Also panics
    /// if `instrument.kind` is [`InstrumentKind::Histogram`] — use
    /// [`Self::resolve_histogram`] for those; see the module doc's
    /// "handle-space question" for why this is checked here rather than
    /// left to produce a `Handle` that `incr`/`add` would then have to
    /// reject.
    pub fn resolve(&mut self, instrument: &'static Instrument, attrs: &[(&str, &str)]) -> Handle {
        assert_ne!(
            instrument.kind,
            InstrumentKind::Histogram,
            "stats::Registry::resolve: {} is a Histogram -- use resolve_histogram()",
            instrument.name
        );
        Self::validate_attrs(instrument, attrs);

        let key = Self::resolve_key(instrument, attrs);

        if let Some(&handle) = self.lookup.get(&key) {
            return handle;
        }

        let handle = Handle(self.resolved.len());
        self.resolved.push(instrument);
        self.resolved_attrs.push(key.1.clone());
        for shard in &mut self.shards {
            shard.push(AtomicU64::new(0));
        }
        self.lookup.insert(key, handle);
        handle
    }

    /// The histogram counterpart of [`Self::resolve`] — same identity,
    /// dedup, and `&mut self` rules, but returns a [`HistogramHandle`] in
    /// its own index space and allocates a [`HistogramShard`] (sized off
    /// `instrument.buckets`) per worker instead of a single `AtomicU64`.
    ///
    /// Panics if `attrs`' keys don't match `instrument.attribute_keys`, same
    /// as `resolve`. Panics if `instrument.kind` is not
    /// [`InstrumentKind::Histogram`], or if a `Histogram` instrument's
    /// `buckets` is `None` (a malformed `const` definition, not something a
    /// caller can cause) — both loudly, both control-side only.
    pub fn resolve_histogram(
        &mut self,
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

        if let Some(&handle) = self.histogram_lookup.get(&key) {
            return handle;
        }

        let handle = HistogramHandle(self.resolved_histograms.len());
        self.resolved_histograms.push(instrument);
        self.resolved_histogram_attrs.push(key.1.clone());
        // Nineteen boundaries means twenty slots -- see the module doc's
        // "overflow bucket" section.
        let num_buckets = num_boundaries + 1;
        for shard in &mut self.histogram_shards {
            shard.push(HistogramShard::new(num_buckets));
        }
        self.histogram_lookup.insert(key, handle);
        handle
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
    /// `worker` are both already-resolved indices. Always moves `handle`'s
    /// counter up; valid for both [`InstrumentKind::Counter`] and
    /// [`InstrumentKind::UpDownCounter`] handles. See [`Self::add`] for the
    /// signed-delta counterpart `UpDownCounter` handles also get.
    ///
    /// Panics if `worker` is out of range for this registry's `num_workers`
    /// — a config-time invariant, not something a real request can trigger.
    pub fn incr(&self, worker: WorkerId, handle: Handle, delta: u64) {
        self.shards[worker.0][handle.0].fetch_add(delta, Ordering::Relaxed);
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
        let instrument = self.resolved[handle.0];
        assert_eq!(
            instrument.kind,
            InstrumentKind::UpDownCounter,
            "stats::Registry::add: {} is a Counter, which has no decrement -- use incr()",
            instrument.name
        );
        self.shards[worker.0][handle.0].fetch_add(delta as u64, Ordering::Relaxed);
    }

    /// Summed across every worker shard. **The only read.** No public
    /// accessor returns a single shard's slot — see
    /// [`Self::shard_values_for_debugging`] if you think you need one.
    ///
    /// `Relaxed` load, same justification as `incr`/`add`: a scrape must not
    /// be a fence on the request path, and observing a slightly-stale value
    /// mid-increment is fine for a counter.
    pub fn value(&self, handle: Handle) -> u64 {
        self.shards
            .iter()
            .map(|shard| shard[handle.0].load(Ordering::Relaxed))
            .fold(0u64, u64::wrapping_add)
    }

    /// Per-worker figures, **unsummed**. Exists for tests only (see the
    /// module doc's "no public accessor may return a single shard's value"
    /// rule) — the ugly name is deliberate friction so a reviewer notices
    /// immediately if production code ever reaches for this instead of
    /// [`Self::value`]. Nothing outside `#[cfg(test)]` in this crate calls
    /// it, and nothing outside this crate should either.
    pub fn shard_values_for_debugging(&self, handle: Handle) -> Vec<u64> {
        self.shards
            .iter()
            .map(|shard| shard[handle.0].load(Ordering::Relaxed))
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
    /// Rust note: `impl Iterator<..> + '_` borrows `self` for the
    /// iterator's lifetime rather than collecting into a `Vec` up front —
    /// there's no reason to allocate a second copy of `resolved`/
    /// `resolved_attrs` just to hand it back out.
    pub fn counters(
        &self,
    ) -> impl Iterator<Item = (&'static Instrument, &'_ [(String, String)], u64)> + '_ {
        self.resolved
            .iter()
            .enumerate()
            .map(move |(i, instrument)| {
                (
                    *instrument,
                    self.resolved_attrs[i].as_slice(),
                    self.value(Handle(i)),
                )
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
        let instrument = self.resolved_histograms[handle.0];
        let boundaries = instrument.buckets.expect(
            "stats::Registry::observe: instrument has no bucket boundaries -- \
             resolve_histogram should have rejected this at resolve time",
        );
        let bucket_index = boundaries
            .iter()
            .position(|&boundary| value <= boundary)
            .unwrap_or(boundaries.len());

        let shard = &self.histogram_shards[worker.0][handle.0];
        shard.bucket_counts[bucket_index].fetch_add(1, Ordering::Relaxed);
        atomic_add_f64(&shard.sum_bits, value);
        shard.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Summed across every worker shard. **The only read** for histogram
    /// data — see [`Self::histogram_shard_snapshots_for_debugging`] for the
    /// debug-only, unsummed per-shard view. `Relaxed` loads throughout, same
    /// justification as `value`.
    pub fn histogram_snapshot(&self, handle: HistogramHandle) -> HistogramSnapshot {
        let num_buckets = self.resolved_histograms[handle.0]
            .buckets
            .expect("stats::Registry::histogram_snapshot: instrument has no bucket boundaries")
            .len()
            + 1;

        let mut bucket_counts = vec![0u64; num_buckets];
        let mut sum = 0.0f64;
        let mut count = 0u64;
        for worker_shards in &self.histogram_shards {
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
        self.histogram_shards
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
    /// as [`Self::counters`].
    pub fn histograms(
        &self,
    ) -> impl Iterator<Item = (HistogramHandle, &'static Instrument, &'_ [(String, String)])> + '_
    {
        self.resolved_histograms
            .iter()
            .enumerate()
            .map(move |(i, instrument)| {
                (
                    HistogramHandle(i),
                    *instrument,
                    self.resolved_histogram_attrs[i].as_slice(),
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

        let instrument = self.resolved_histograms[handle.0];
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    // ---- 1: resolve identity -------------------------------------------

    #[test]
    fn resolving_same_instrument_and_attrs_twice_yields_same_handle() {
        let mut registry = Registry::new(1);
        let a = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let b = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        assert_eq!(
            a, b,
            "same (instrument, attrs) must resolve to the same handle"
        );

        let c = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "anthropic")]);
        assert_ne!(
            a, c,
            "different attribute values must resolve to different handles"
        );
    }

    // ---- 2/3: attribute-key mismatch is rejected loudly -----------------

    #[test]
    #[should_panic(expected = "attribute keys don't match")]
    fn unexpected_attribute_key_is_rejected_loudly() {
        let mut registry = Registry::new(1);
        // "region" is not in UPSTREAM_RQ's attribute_keys (["cluster"]).
        registry.resolve(
            &instruments::UPSTREAM_RQ,
            &[("cluster", "openai"), ("region", "us-east-1")],
        );
    }

    #[test]
    #[should_panic(expected = "attribute keys don't match")]
    fn missing_expected_attribute_key_is_rejected_loudly() {
        let mut registry = Registry::new(1);
        // GEN_AI_CLIENT_TOKEN_USAGE expects both "provider" and "type".
        registry.resolve(
            &instruments::GEN_AI_CLIENT_TOKEN_USAGE,
            &[("provider", "openai")],
        );
    }

    // ---- 4: attribute order doesn't affect identity ----------------------

    #[test]
    fn attribute_order_does_not_affect_handle_identity() {
        let mut registry = Registry::new(1);
        let a = registry.resolve(
            &instruments::GEN_AI_CLIENT_TOKEN_USAGE,
            &[("provider", "openai"), ("type", "input")],
        );
        let b = registry.resolve(
            &instruments::GEN_AI_CLIENT_TOKEN_USAGE,
            &[("type", "input"), ("provider", "openai")],
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
        let mut registry = Registry::new(3);
        let h = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);

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

        let mut registry = Registry::new(WORKERS);
        let h = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
        let registry = Arc::new(registry);

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

        let mut registry = Registry::new(1);
        let h = registry.resolve(&CX_ACTIVE, &[("listener", "ingress")]);

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
        let mut registry = Registry::new(1);
        let h = registry.resolve(&instruments::UPSTREAM_RQ, &[("cluster", "openai")]);
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
            let mut registry = Registry::new(1);
            let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
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
        let mut registry = Registry::new(1);
        let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);

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
        let mut registry = Registry::new(3);
        let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);

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
        let mut registry = Registry::new(1);
        let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);

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
        let mut registry = Registry::new(1);
        let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
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
        let mut registry = Registry::new(1);
        let h = registry.resolve_histogram(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);

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
        let mut registry = Registry::new(1);
        registry.resolve(&instruments::UPSTREAM_RQ_TIME, &[("cluster", "x")]);
    }

    #[test]
    #[should_panic(expected = "is not a Histogram")]
    fn resolve_histogram_rejects_a_counter_instrument() {
        let mut registry = Registry::new(1);
        registry.resolve_histogram(&instruments::UPSTREAM_RQ, &[("cluster", "x")]);
    }
}
