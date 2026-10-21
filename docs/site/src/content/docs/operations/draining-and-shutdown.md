---
title: Draining and shutdown
description: "Stop the proxy without dropping in-flight requests: drain on SIGTERM and the shutdown sequence."
summary: What SIGTERM, SIGINT, and POST /drain_listeners do, how /ready
  changes, and what the drain deadline cuts.
lastUpdated: 2026-10-20
related:
  - operations/config-reload
  - reference/cli
---

# Draining and shutdown

Use a drain to stop the proxy without dropping requests that are in flight.
Send `SIGTERM` or `SIGINT`, or call `POST /drain_listeners`. Both start a drain
instead of killing the process. No config is needed to enable it. Signal
handlers are installed before any listener binds, so a signal at startup never
falls back to the OS default.

## What happens, in order

1. `/ready` on the admin port answers `503 DRAINING` at once. Your load
   balancer or Kubernetes stops sending new traffic.
2. Every worker closes its listening sockets. New connections are refused.
   A config reload (SIGHUP or xDS) during the drain does not open them again.
3. Each HTTP connection is told to close. With `--drain-strategy immediate`
   (the default), this happens to every connection now. With `gradual`, it is
   spread over the window: see [Gradual drain](#gradual-drain). An idle
   keep-alive connection closes when it is told to.
4. A request or stream already in flight keeps running. When it finishes, its
   connection closes: the response carries `Connection: close` on HTTP/1, and
   the proxy sends `GOAWAY` on HTTP/2.
5. When no connection is left, the process flushes the access-log queues,
   then request records, traces, and metrics. Then it exits `0`. It does not wait for
   the full window.
6. If connections are still open after `--drain-time-s` (default 600), they
   are cut and the process exits `0`. The request record of a cut stream has
   partial, estimated usage, `termination: downstream_disconnect` and
   `error_category: downstream_local_disconnect`. A client that disconnects
   gets `error_category: downstream_remote_disconnect` instead.

TCP proxy connections are not closed early. They run until the window ends.

An upgrade tunnel, for example a WebSocket, counts as an active connection. The
drain start does not close it. The drain stays open until a peer closes the
tunnel or the drain deadline passes.

## Gradual drain

Behind a load balancer, `immediate` closes every keep-alive connection at the
same moment, and all clients reconnect at once. Use `--drain-strategy gradual`
to spread the closes, as Envoy does:

- The proxy tells its HTTP connections to close one at a time, at even
  intervals over the first quarter of `--drain-time-s`. The first one closes at
  drain start. With `--drain-time-s 40` and 8 connections on a worker, one
  closes about every 1.25 seconds, and all are told within 10 seconds.
- A request that arrives during the drain can also close its connection after
  its response. The chance starts at 0 at drain start and grows to 1 at the
  deadline.
- A config reload (SIGHUP or xDS) during a gradual drain still closes every
  HTTP connection at once, so a rotated provider key is not sent on a
  kept-alive connection.

Each worker keeps its own schedule. The drain ends as soon as no connection is
left, so a gradual drain of idle connections ends after about a quarter of the
window.

## Access-log lines at exit

The proxy writes access-log lines from background writer threads (see
[Access logs](../../observability/access-logs/#where-a-line-goes)). After the
workers stop, the process waits for those queues to empty. It waits at most
5 seconds. After a second signal it waits at most 1 second. If a queue is not
empty at the end, the proxy logs `access-log writers did not drain before the
shutdown budget; queued lines are lost`.

## A second signal

A second `SIGTERM` or `SIGINT` during the drain means "stop waiting". The
proxy logs an error, cuts every connection that is still open, spends at most
about a second on each flush, skips the final metric snapshot, and exits with
status `1`.

The same holds at any point after the first signal, including while telemetry
is being flushed: a second `SIGTERM` or `SIGINT` abandons the remaining flushes
and exits promptly with status `1`.

## Admin endpoints

These need the admin port and the `LLMPROXY_ADMIN_TOKEN` environment variable.
Send the token as `Authorization: Bearer <token>`. All three are `POST`. If
the token is unset they answer `403`; a wrong token gets `401`.

| Endpoint | Effect |
|---|---|
| `POST /healthcheck/fail` | `/ready` answers `503 DRAINING`. Nothing else changes. |
| `POST /healthcheck/ok` | Undoes `/healthcheck/fail`. It never undoes a drain. |
| `POST /drain_listeners` | Starts the same drain as `SIGTERM`. The process keeps running until a signal arrives. |

After `POST /drain_listeners` the process keeps serving in-flight connections
(HTTP streams and TCP proxy sessions) past `--drain-time-s` until a signal
arrives. The deadline is enforced only from a signal, which is the point where
the process exits and cuts whatever is still open. Envoy's server drain
likewise closes connections only at exit.

`/drain_listeners` accepts `?graceful` and `?inboundonly` and treats both as
no-ops. Any other query parameter is a `400`.

## Readiness at startup

`/ready` answers `503 INITIALIZING` until at least one listener is bound. A
proxy with no listener, for example one that never receives LDS, never becomes
ready. After a listener binds, `/ready` also waits for clusters that are still
warming, until `initial_fetch_timeout`.

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--drain-time-s` | `600` | Seconds to wait for connections to finish before cutting them. |
| `--drain-strategy` | `immediate` | `immediate` tells every connection to close at drain start. `gradual` spreads the closes over the window (see [Gradual drain](#gradual-drain)). |

See [CLI reference](../../reference/cli/) for the full flag list.

## Implementation notes

This section is for maintainers.

- Shutdown sequence and the access-log flush budget: `crates/proxy/src/main.rs`.
- Drain strategy schedule: `connection_drain_delay` and `drain_close` in
  `crates/proxy-core/src/drain.rs`; deviations from Envoy are row 1 of
  `internal-docs/envoy-divergences.md`.
- Upgrade tunnel during a drain:
  `an_upgraded_tunnel_survives_drain_start_and_holds_drain_open_until_it_closes`
  in `crates/proxy-core/src/listener_drain_tests.rs`.
