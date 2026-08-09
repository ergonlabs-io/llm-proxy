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

## Increments

- **1 — the registry core.** Instruments, attributes, `Handle` resolution, sharded storage,
  summed reads. Pure library, no HTTP, no rendering. Counters and gauges only.
- **2 — histograms**, with Envoy's default `rq_time` buckets. Split out because bucket
  boundaries are their own compatibility question and would otherwise hide inside increment 1.
- **3 — the Envoy `/stats` text renderer** and the admin wiring that replaces the honest 404.
- **4 — `/stats/prometheus`**, with Envoy's label-mangling rules, and the Grafana-dashboard
  acceptance test.
- **5 — instrumentation call sites**: cluster/listener/HTTP counters at the points WP-13/14/15
  already own. Deliberately last: until increments 1–4 exist, every call site added is a guess
  about an API that has not been exercised.

## What this brief does not decide

OTLP export (WP-51) — the exporter seam in Decision 3 is shaped for it, but push semantics,
batching, and resource attributes are that WP's. Nor does it decide whether `/stats` supports
Envoy's `?filter=` and `?format=json` query parameters; those are `/stats` surface questions
for increment 3 and do not affect the model.
