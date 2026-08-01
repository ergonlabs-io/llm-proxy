# ADR 0003 — Worker Send model: `!Send` worker-local data plane

**Status:** accepted (decision D1, 2026-07-19)

## Context

ADR-0001 fixed share-nothing worker runtimes but left open how that shows up in
the type system (open question D1): do the data-plane traits (`ClusterEntry`,
`HttpConnPool`, `HttpFilter`) carry `Send + Sync` bounds — allowing objects to
migrate across or be shared between threads — or are they worker-local and
`!Send`? The bounds must be fixed before WP-06 because every later lane codes
against these signatures (Part 0 ground rule 4).

## Decision

- **Data-plane runtime state is worker-local and `!Send`.** `ClusterEntry`,
  `HttpConnPool`, `HttpFilter`, and per-connection state drop their
  `Send`/`Sync` bounds. Worker-local shared handles use `Rc`, not `Arc`.
- **Worker runtimes are `new_current_thread()` with a `LocalSet`;** connection
  tasks are spawned with `tokio::task::spawn_local`.
- **Config-derived immutable data still crosses threads.** `ConfigSnapshot`
  and everything reachable from it remains `Send + Sync` (held in `Arc`),
  published control → worker via `ArcSwap` per ADR-0001.
  `TransportSocketFactory` keeps `Send + Sync`: it is built once from config
  and handed to workers, and rustls server/client configs are already
  `Send + Sync`.
- **Cross-worker interaction is explicit message passing** to the control
  runtime (stats aggregation, admin `/config_dump`, drain coordination) —
  never shared mutable state.

## Why

- Mirrors Envoy's proven model: cluster/LB/pool state is thread-local in
  Envoy; hosts and config are shared-immutable. We keep the same split.
- No `Arc`/`Mutex`/atomic traffic on the hot path, and the compiler rules out
  accidental cross-thread sharing instead of a code-review convention.
- Filter authors (including the LLM lane, WP-33+) can hold `Rc`, `RefCell`,
  and non-`Send` state without fighting bounds.
- Accepted costs: no work-stealing between workers (accept-side balance comes
  from `SO_REUSEPORT`, which is Envoy parity), and worker-local structures are
  instantiated per worker from the shared snapshot (N× memory for LB state —
  same trade Envoy makes).

## Consequences

- Part 1 §1.1/§1.2 signatures change: `pub trait ClusterEntry`,
  `pub trait HttpConnPool`, `pub trait HttpFilter` — no `Send`/`Sync`.
  Handles are `Rc<dyn ClusterEntry>` / `Rc<dyn HttpConnPool>` inside a worker.
- WP-06 builds each worker as a `current_thread` runtime driving a `LocalSet`
  on a dedicated (optionally core-pinned) OS thread.
- Per-worker cluster state (WP-16..19) is built per worker from
  `Arc<ClusterConfig>` on snapshot swap, not shared across workers.
- Tests exercising data-plane types must run inside a `LocalSet`; proxy-core
  provides a test helper for this.
