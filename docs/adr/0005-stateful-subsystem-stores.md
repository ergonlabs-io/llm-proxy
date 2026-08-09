# ADR-0005 — Stateful subsystems: embedded store by default, distributed behind a seam

**Status:** accepted, 2026-08-01
**Owner decision.** Supersedes nothing; generalises the `BudgetStore` seam built in WP-34.

## Context

Three subsystems need state that outlives a single request, and they arrived
separately enough that each nearly invented its own answer:

- **Token budgets** (WP-34) — how many tokens a caller has spent this window.
- **Stats / metrics** (WP-23) — counters and histograms under Envoy names.
- **Control-plane state** (WP-50) — virtual keys, teams, budgets, spend history.

Each faces the identical question: where does the state live, and what happens
when there is more than one proxy replica?

Two failure modes are already on record. WP-34's first implementation used a
`RefCell` store on the reasoning that ADR-0003 makes the data plane `!Send` and
worker-local — correct for *per-stream* state, wrong for a budget, which is
inherently cross-stream. The alternative considered, a `thread_local!` shard per
worker, was rejected outright: with N workers a configured limit of X becomes an
effective limit of **N·X**, and a quota that is wrong by the worker count is
worse than no quota at all. The same trap is waiting for stats (per-worker
counters that never aggregate) and for control-plane state (a key revoked on one
replica and still live on another).

## Decision

**Every stateful subsystem is defined by a trait, ships with an embedded
implementation as the default, and is shaped so a distributed implementation can
land behind the same trait without touching call sites.**

The embedded implementation is the product default and must be genuinely good —
not a placeholder. Single-replica deployments are a first-class target
(the project serves K8s *and* non-K8s users), and those users should never be
told to run Redis to get a working gateway.

A seam is only real if it accounts for what a remote implementation actually
needs. Shaping one requires all four of:

1. **A failure channel on reads.** A remote store can time out. A method
   returning a bare value has nowhere to put that, and retrofitting one later
   changes every call site *and* forces a security decision under pressure.
2. **A documented failure policy.** Fail-open or fail-closed is a product
   decision, made once, written down. Budgets fail **open** (Envoy's
   `failure_mode_deny: false` default — hard-denying every request when the
   backend blips is worse than briefly over-admitting). Authentication will fail
   **closed**; that is a different answer for a different subsystem, and the
   difference is the point.
3. **Writes documented as best-effort.** The caller must not block on, or fail
   from, bookkeeping. A remote implementation may batch and drop under
   backpressure, so an infallible signature must not be read as durable.
4. **Honest handling of process-local values.** `Instant` is monotonic *within a
   process* and means nothing across one. Where a trait passes one, say plainly
   that a remote store is its own time authority — naming the limitation beats
   pretending it is solved.

**The data plane never does I/O against these stores on the request path.**
Reads on the hot path come from an immutable snapshot published through
`ArcSwap`, exactly as `ClusterManager` already does for host sets ("control
computes, workers read"). The control side owns the store and republishes; the
worker does a lock-free load. Anything that would put a disk or network read
between a request and its response belongs on the control side of that boundary.

## Consequences

- Adding Redis/Postgres later is an additive implementation, not a refactor.
- Single-binary deployments keep working with no external dependency — which is
  also what keeps the test suite hermetic and docker-free.
- Each subsystem must state its own fail-open/fail-closed answer explicitly;
  there is no global default, because budgets and authentication genuinely
  differ.
- A synchronous trait cannot perform network I/O without blocking the worker.
  The migration path for any remote store is therefore the S2 hold-and-resume
  shape (`StopIteration`, then `continue_decoding()` when the answer arrives) —
  the same machinery WP-32's ext_authz and gRPC RLS already require. Each store
  call must be isolated to a single function so that swap has one call site.

## Status per subsystem

| Subsystem | Trait | Embedded impl | Distributed |
|---|---|---|---|
| Token budgets (WP-34) | `BudgetStore` ✅ | `InProcessBudgetStore` ✅ | not built — seam ready |
| Stats (WP-23) | not built | not built | — |
| Control plane (WP-50) | not built | not built | — |
