# ADR 0001 — Runtime model: share-nothing worker runtimes + control runtime

**Status:** accepted (scaffold)

## Decision

- One small multi-threaded tokio "control" runtime for xDS, admin, stats
  aggregation/flush, health-check scheduling.
- `--concurrency` (default: #cores) single-threaded tokio "worker" runtimes, each
  on a dedicated core-pinned OS thread, each with its own `SO_REUSEPORT` listener
  sockets. A downstream connection is accepted by one worker and stays there for
  its lifetime.
- Config flows control → workers as immutable `Arc<ConfigSnapshot>` published via
  `arc_swap` (+ a `watch` ping for listener socket add/remove). In-flight
  connections keep their snapshot `Arc`, which is what implements drain semantics.

## Why

Mirrors Envoy's proven threading model (main thread + pinned workers + TLS-slot
config propagation) and Orion's validated Rust translation of it. The hot path is
lock-free and share-nothing; cross-worker coordination is the rare, explicit case.

## Consequences

- Connection pools, LB state, and stats shards are per-worker (Envoy parity;
  documented in S5/S7).
- Zero-downtime restart is process-overlap via SO_REUSEPORT + drain (PLAN.md
  Part 9.2), not Envoy's shared-memory hot restart.
