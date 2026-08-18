---
title: Draining and shutdown
summary: SIGTERM/SIGINT trigger a drain window before the process exits. What
  the drain deadline actually bounds, and what it does not.
last_updated: 2026-08-09
related:
  - ../operations/config-reload/
  - ../reference/cli/
---

# Draining and shutdown

`SIGTERM` or `SIGINT` starts a drain sequence rather than killing the
process outright. Signal handlers are installed before the proxy binds any
listener, so there is no window at startup where a signal would fall back
to the OS default (immediate termination, no drain)
(`crates/proxy/src/main.rs`'s `ControlSignals::install`).

## What happens, in order

1. Every worker is told draining has started. A per-connection close
   probability is computed for the configured strategy (see "What
   `--drain-strategy` does today" below), broadcast to every worker
   (`crates/proxy-core/src/drain.rs`'s `DrainState`/`DrainCoordinator`).
2. Each worker races its own live-connection count reaching zero against
   the drain deadline (`--drain-time-s`, default 600 seconds) — whichever
   happens first. An open HTTP connection counts as live for as long as it
   is open, including an idle keep-alive connection nobody is actively
   using (`crates/proxy-core/src/drain.rs`'s `ConnectionRegistry`).
3. Once every worker has reported back (by either path), the process-wide
   shutdown flag flips. Every still-open HTTP/1.1 or HTTP/2 connection then
   receives a real protocol-level graceful shutdown: hyper finishes
   whatever request is currently in flight on that connection, refuses to
   accept a next one, and closes
   (`crates/proxy-http/src/codec.rs`'s `serve_http1`/`serve_http2`).
4. The control runtime waits for every worker thread to exit before the
   process exits.

Proven end to end by `sigterm_drains_then_exits_cleanly` in
`crates/proxy/tests/cli.rs`: the test config's real deployment shape, a
`SIGTERM`, and an assertion that the process exits `0` within a bounded
time.

## The drain deadline does not cut off an in-flight request

`--drain-time-s` bounds how long the proxy *waits* for connections to close
naturally before telling every remaining connection to stop accepting new
requests. It is not a hard deadline on a request already in flight: step 3
above only refuses a *next* request on a connection — a response already
streaming when the deadline arrives is allowed to finish, however long that
takes, before the connection actually closes and the process exits. For a
long-running LLM generation still streaming when the drain deadline is
reached, this means the response completes rather than being cut off
mid-stream.

## What `--drain-strategy` does today

`--drain-strategy` accepts `gradual` (the default) and `immediate`, and
both are threaded through to a computed close-probability ramp
(`DrainState::drain_close_probability`) — but nothing in the HTTP codec
currently reads that value. In practice, today, `gradual` and `immediate`
behave identically: neither one actively closes an idle keep-alive
connection any sooner than the plain "wait for the deadline" behavior
described above. The seam is built and unit-tested in isolation
(`crates/proxy-core/src/drain.rs`), but connecting it to a live HTTP
connection so the strategies actually diverge in practice is not done yet.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--drain-time-s` | `600` | Seconds to wait for connections to close before forcing every remaining one into graceful protocol shutdown. |
| `--drain-strategy` | `gradual` | `gradual` or `immediate` — see the note above for what these do and do not affect today. |

See [CLI reference](../reference/cli/) for the full flag list.
