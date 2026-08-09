# WP-23 stats registry — design brief

**Status:** design, 2026-08-08, written for v0.2.0. Implements the owner decision of
2026-08-03 (OTel-native model, Envoy names as an adapter) and sits under ADR-0005 — with
one deliberate departure from it, argued below.

## What the gate needs

v0.2.0's ship gate names `/stats` alongside `/config_dump`. `/config_dump` works today;
`/stats` returns a 404 that says "not implemented yet (WP-23); this proxy does not fake an
empty /stats" — which is the right placeholder and the reason this WP is the milestone's
main body of work.

## Decision 1 — the hot path increments an index, not a name

This is the decision everything else hangs off.

An OTel measurement is `(instrument, attribute set)`. Resolving that per request means
hashing an attribute set on the request path, which is not affordable at the rates this
proxy is built for. So resolution and increment are split:

```rust
// Control side, once, when a cluster/listener/route enters the config snapshot:
let h: Handle = registry.resolve(instruments::UPSTREAM_RQ, &[("cluster", "provider:openai")]);

// Hot path, per request: no hashing, no allocation, no string.
registry.incr(h, 1);
```

`Handle` is an opaque index. **A caller must not be able to increment by name**, or the
hash creeps back onto the hot path one call site at a time. This is the standard OTel
"bound instrument" idea; it is written down here because the tempting API
(`registry.counter("upstream_rq").with(...).inc()`) is the one that quietly costs the most.

Handles are resolved when config is lowered, so the set of live handles changes only on a
config swap — the same lifecycle the cluster manager already has.

## Decision 2 — per-worker shards, and the shard is never the metric

ADR-0005 names the trap by name: with N workers, a per-worker counter that never aggregates
is wrong by the worker count. The same mistake made a token budget wrong by N.

Layout: one contiguous shard per worker, indexed by `WorkerId(usize)`, each shard holding
one slot per handle. A worker touches only its own shard, so two workers never write the
same cache line and relaxed-ordering increments never contend.

```
value(handle) = Σ over workers of shard[worker][handle]
```

**The API must make the un-summed value unreachable.** No public accessor returns a shard
slot. `value()` sums; that is the only read. If a debugging need for per-worker figures ever
appears, it gets an explicitly-named method (`shard_values_for_debugging`) so a reviewer sees
what is happening — it does not get to be the natural-looking call.

Ordering is `Relaxed`. These are counters, not synchronisation: no other memory is published
through them, and a scrape that lands mid-increment is allowed to observe either value.
Scrape reads are `Relaxed` too, so a scrape is not a fence on the request path.

## Decision 3 — stats are NOT ADR-0005's distributed case, and forcing the trait is wrong

ADR-0005's summary table lists stats beside token budgets and control-plane state, all
awaiting a "distributed implementation behind the same trait". **For stats that is the wrong
shape, and building it would be cargo-culting the ADR.**

- A **budget** must be shared across replicas or the quota multiplies by replica count. That
  is why `BudgetStore` exists.
- **Stats must NOT be shared across replicas.** Each replica reports its own counters and the
  time-series database sums them. That is what every Prometheus deployment on earth does, and
  a proxy that tried to pre-aggregate across replicas would produce numbers no one could
  attribute, break `rate()` on restart, and add a network dependency to a scrape.

What ADR-0005 correctly demands for stats is the *intra-process* aggregation of Decision 2 —
across workers, not across replicas. The trait-shaped seam this WP owes is the **exporter**
(`/stats` text, `/stats/prometheus`, later OTLP push for WP-51), not the store.

ADR-0005's table should be amended to say so rather than left implying a `StatsStore` is
owed. Recording the disagreement here is the point: the next person to read that table will
otherwise build the wrong thing and cite the ADR while doing it.

## Decision 4 — Envoy names are rendered, and the mapping is not one-to-one

Each instrument declares how its attributes render into Envoy's flat namespace:

| OTel | Envoy `/stats` |
|---|---|
| `upstream_rq` `{cluster, status_class}` | `cluster.<name>.upstream_rq_<class>` |
| `upstream_rq` `{cluster}` | `cluster.<name>.upstream_rq_total` |
| `gen_ai.client.token.usage` `{provider, type}` | *(no Envoy equivalent — omitted)* |

Three consequences worth stating before someone hits them:

1. **One OTel instrument can render to several Envoy names.** Envoy's `upstream_rq_2xx…5xx`
   are separate stats; in OTel they are one counter with a `status_class` attribute. Rendering
   expands attribute values into name segments.
2. **Some instruments render to nothing.** `gen_ai.*` has no Envoy equivalent, and inventing
   one would be worse than omitting it — `/stats` is a compatibility surface, and a name Envoy
   never had is not compatibility. These appear in Prometheus and OTLP output only.
3. **Envoy's label mangling is lossy**, which is exactly why the model is OTel-first. The
   adapter is allowed to lose information on the way out; it must never be the source of truth.

`/stats` is therefore a rendering layer with its own conformance tests. The acceptance
criterion — Envoy's own Grafana dashboard queries populating against our Prometheus output —
is that conformance test, and it does not get easier for being downstream.

## Decision 5 — pin the semconv version in code

The OTel GenAI semantic conventions are experimental upstream and have already churned once
(`gen_ai.usage.prompt_tokens` → `gen_ai.usage.input_tokens`). A `SEMCONV_VERSION` constant
sits next to the instrument definitions, and **bumping it is a breaking change to the metric
surface** — for anyone with a dashboard, it is exactly that. It goes in the CHANGELOG under a
heading that says so.

## Correction, 2026-08-09 — `resolve(&mut self)` cannot survive a config swap

Increment 1 gave `Registry::resolve` a `&mut self` receiver, and Decision 1's write-up
praised it: the borrow split makes "resolution cannot race an increment" a compiler-checked
property rather than a comment. That reasoning is sound and the conclusion was still wrong,
for a reason none of the increment-1 tests could show.

**The registry is shared as `Arc<Registry>` from process start.** Once it is, `&mut self` is
unobtainable. So handles can be resolved only *before* sharing — at boot — and **a config
swap that introduces a new cluster can never register its counters.** The new cluster serves
traffic and reports nothing, silently, forever.

That is not a corner case here. *"A config swap under live traffic with zero dropped
streams"* is one of v0.2.0's three ship-gate clauses, and `run_listener_manager` already
rebuilds listeners on `config_ping`. The stats registry would be the one subsystem that
quietly does not participate.

### The fix, and why it is the shape this project already uses

Resolution must take `&self` and use interior mutability: a mutex around the
name→handle map and the shard growth, touched **only on the control side at config time**,
with increments staying lock-free atomics. This is what Envoy itself does.

The one real hazard is growing the shard storage while readers hold `&self` — a `Vec` that
reallocates moves its elements out from under a concurrent reader. So the shard storage is
published through **`ArcSwap`**: growth builds a new outer table and swaps it in, readers do
a lock-free `load`. That is precisely ADR-0005's *"the control side publishes an immutable
snapshot through `ArcSwap`; workers do a lock-free load"* — the same pattern `ClusterManager`
uses for host sets and the auth filter uses for key sets, so it is a pattern this codebase
already reads fluently rather than a new mechanism.

**What is lost by the change, stated honestly:** the compile-time no-race guarantee becomes a
runtime discipline. It should be replaced by something enforceable rather than by a comment —
a debug assertion that resolution never runs on a worker thread, or resolution taking a
control-side handle type that workers do not have.

**Rejected: rebuilding the registry on each swap and copying counter values across.** It
looks simpler and it loses increments that land between snapshot and swap. For monotonic
counters that shows up as a dip in `rate()` at every config reload — a metrics bug that would
be blamed on the traffic rather than on the reload.

## Increments

- **1 — the registry core.** Instruments, attributes, `Handle` resolution, sharded storage,
  summed reads. Pure library, no HTTP, no rendering. Counters and gauges only.
- **2 — histograms**, with Envoy's default `rq_time` buckets. Split out because bucket
  boundaries are their own compatibility question and would otherwise hide inside increment 1.
- **3 — the Envoy `/stats` text renderer** and the admin wiring that replaces the honest 404.
- **4 — `/stats/prometheus`**, with Envoy's label-mangling rules, and the Grafana-dashboard
  acceptance test.
- **5 — the registry lifecycle under config reload** (added 2026-08-09; see the correction
  above). `resolve(&self)` with control-side interior mutability and `ArcSwap`-published shard
  storage, so a config swap can register new instruments. **Must land before increment 6**:
  adding call sites first would bake in the assumption that every handle exists at boot, and
  every one of them would need revisiting.
- **6 — instrumentation call sites**: cluster/listener/HTTP counters at the points WP-13/14/15
  already own. Deliberately last: until the increments above exist, every call site added is a
  guess about an API that has not been exercised.

## What this brief does not decide

OTLP export (WP-51) — the exporter seam in Decision 3 is shaped for it, but push semantics,
batching, and resource attributes are that WP's. Nor does it decide whether `/stats` supports
Envoy's `?filter=` and `?format=json` query parameters; those are `/stats` surface questions
for increment 3 and do not affect the model.
