//! WP-23 increment 1 — the stats registry core: instruments, [`Handle`]
//! resolution, and sharded, summed counters. Pure library: no HTTP, no
//! `/stats` rendering, no Prometheus, no histograms, no instrumentation call
//! sites — those are increments 2–5 (`docs/wp-23-stats-design-brief.md`,
//! which is normative for every decision below).
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
//! `Relaxed` increments never contend.
//!
//! ```text
//! value(handle) = Σ over workers of shard[worker][handle]
//! ```
//!
//! **No public accessor returns a single shard's slot.** [`Registry::value`]
//! sums; that is the only read. [`Registry::shard_values_for_debugging`]
//! exists for tests only — the name is the friction, so a reviewer sees
//! immediately when someone reaches for the un-summed figure.
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
//! the type that makes it safe to build.
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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// The OTel semantic-conventions revision this module's instrument names and
/// attribute keys were written against. See the module doc's "Decision 5" —
/// changing this value is a breaking change to the metric surface and must
/// be called out in the CHANGELOG, not just bumped in passing.
pub const SEMCONV_VERSION: &str = "1.27.0";

/// Which OTel instrument shape a metric follows. `Gauge` and `Histogram` are
/// increment 2 (bucketed data is its own compatibility question — see the
/// design brief).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstrumentKind {
    /// Monotonically increasing. [`Registry::incr`] is the only way to move
    /// one; there is no decrement — see [`Registry::add`]'s doc for why that
    /// is enforced, not just conventional.
    Counter,
    /// May move in either direction. [`Registry::incr`] (always up) and
    /// [`Registry::add`] (signed delta, either direction) both work.
    UpDownCounter,
}

/// One OTel instrument's identity and shape: a name, a unit, and the set of
/// attribute keys every measurement against it must supply — no more, no
/// fewer. [`Registry::resolve`] checks a caller's attributes against
/// `attribute_keys`, order-insensitively, and panics loudly on a mismatch
/// rather than silently starting a second, parallel time series for a
/// typo'd key.
#[derive(Debug)]
pub struct Instrument {
    /// OTel semantic-conventions name (or this proxy's own gateway-metrics
    /// name where OTel has no upstream identity — each `pub const` below
    /// says which).
    pub name: &'static str,
    pub kind: InstrumentKind,
    /// UCUM-style unit string (`"{request}"`, `"{token}"`, ...), following
    /// OTel's own convention for instrument units.
    pub unit: &'static str,
    /// The attribute keys a measurement against this instrument must supply
    /// — exactly these, in any order. See [`Registry::resolve`].
    pub attribute_keys: &'static [&'static str],
}

/// A small starter set of instruments — enough to exercise the resolve/incr/
/// value model end to end, not the full Envoy stats surface (that is
/// increment 5). Named `instruments` so call sites read as
/// `instruments::UPSTREAM_RQ`, matching the design brief's own examples.
pub mod instruments {
    use super::{Instrument, InstrumentKind};

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
    };

    /// Tokens consumed by a GenAI request/response exchange. **Has no Envoy
    /// equivalent** — Envoy predates LLM gateways — so this renders to
    /// nothing in the increment-3 `/stats` text output; it exists in
    /// Prometheus/OTLP output only (design brief, Decision 4, point 2).
    ///
    /// The real OTel GenAI semantic conventions define
    /// `gen_ai.client.token.usage` as a *histogram* (a per-request token
    /// count distribution), not a counter. Until increment 2 adds histogram
    /// support this starter models it as a running-total `Counter` instead
    /// — same name and identity, coarser aggregation — so the model can be
    /// exercised before buckets exist. Attribute keys (`provider`, `type`)
    /// match the design brief's own table rather than the semconv's fully
    /// qualified `gen_ai.provider.name` / `gen_ai.token.type`; the
    /// increment-4 Prometheus renderer is where full key names matter.
    pub const GEN_AI_CLIENT_TOKEN_USAGE: Instrument = Instrument {
        name: "gen_ai.client.token.usage",
        kind: InstrumentKind::Counter,
        unit: "{token}",
        attribute_keys: &["provider", "type"],
    };
}

/// Identifies a worker thread/runtime for [`Registry::incr`]/
/// [`Registry::add`]'s shard indexing.
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

/// An opaque handle to one resolved `(instrument, attribute set)` pair.
/// Returned by [`Registry::resolve`]; carries no name, no attributes — that
/// is the point (see the module doc's Decision 1). The inner `usize` is
/// private to this module: outside it, a `Handle` can only be obtained from
/// `resolve` and only used by handing it back to `incr`/`add`/`value`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle(usize);

/// Dedup key for [`Registry::resolve`]: an instrument's name plus its
/// attributes, sorted into a stable order. Named as a `type` alias (rather
/// than inlined into `Registry`'s field) purely to keep that field
/// declaration readable — clippy's `type_complexity` lint flagged the
/// inline form.
type ResolveKey = (&'static str, Vec<(String, String)>);

/// The stats registry: resolves `(instrument, attrs)` into [`Handle`]s at
/// config-lowering time, and stores per-worker, per-handle counters that
/// [`Registry::value`] sums on read. See the module doc for the full design
/// — in particular why `resolve` takes `&mut self` while every hot-path
/// method takes `&self`.
pub struct Registry {
    /// Indexed by `Handle`'s inner `usize`. Kept so `incr`/`add` can look up
    /// an instrument's kind (to enforce "Counters don't decrement") and a
    /// future increment can look up name/unit/attrs for rendering.
    resolved: Vec<&'static Instrument>,
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
}

impl Registry {
    /// Build an empty registry sized for `num_workers` shards. `num_workers`
    /// is a config-time constant (`WorkerPoolConfig::concurrency`, in
    /// `proxy-core`) — this increment does not support growing the worker
    /// count after construction.
    pub fn new(num_workers: usize) -> Self {
        Self {
            resolved: Vec::new(),
            lookup: HashMap::new(),
            // Rust note: not `vec![Vec::new(); num_workers]` -- that macro
            // needs `Vec<AtomicU64>: Clone`, which needs `AtomicU64: Clone`,
            // which atomics deliberately don't implement (cloning an atomic
            // would silently split one counter into two). Building each
            // shard from a fresh closure call sidesteps the bound entirely.
            shards: (0..num_workers).map(|_| Vec::new()).collect(),
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
    /// must not silently start a second, parallel time series.
    pub fn resolve(&mut self, instrument: &'static Instrument, attrs: &[(&str, &str)]) -> Handle {
        Self::validate_attrs(instrument, attrs);

        let mut pairs: Vec<(String, String)> = attrs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        pairs.sort();
        let key = (instrument.name, pairs);

        if let Some(&handle) = self.lookup.get(&key) {
            return handle;
        }

        let handle = Handle(self.resolved.len());
        self.resolved.push(instrument);
        for shard in &mut self.shards {
            shard.push(AtomicU64::new(0));
        }
        self.lookup.insert(key, handle);
        handle
    }

    /// Checks `attrs`' keys against `instrument.attribute_keys` as sets
    /// (order-insensitive, exact match). Called only from `resolve`, which
    /// is control-side, so panicking here is fine — it can never fire on
    /// the request path.
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
}
