---
title: Draining and shutdown
summary: What SIGTERM, SIGINT, and POST /drain_listeners do, how /ready
  changes, and what the drain deadline cuts.
last_updated: 2026-10-10
related:
  - ../operations/config-reload/
  - ../reference/cli/
---

# Draining and shutdown

`SIGTERM` or `SIGINT` starts a drain instead of killing the process. Signal
handlers are installed before any listener binds, so a signal at startup never
falls back to the OS default.

## What happens, in order

1. `/ready` on the admin port answers `503 DRAINING` at once. Your load
   balancer or Kubernetes stops sending new traffic.
2. Every worker closes its listening sockets. New connections are refused.
   A config reload (SIGHUP or xDS) during the drain does not open them again.
3. Idle keep-alive connections close now.
4. A request or stream already in flight keeps running. When it finishes, its
   connection closes: the response carries `Connection: close` on HTTP/1, and
   the proxy sends `GOAWAY` on HTTP/2.
5. When no connection is left, the process flushes capture, traces, and
   metrics, then exits `0`. It does not wait for the full window.
6. If connections are still open after `--drain-time-s` (default 600), they
   are cut and the process exits `0`.

TCP proxy connections are not closed early. They run until the window ends.

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
| `--drain-strategy` | `gradual` | Accepted for Envoy command lines. It has no effect: both values drain as described above, and the proxy logs a warning at startup. |

See [CLI reference](../reference/cli/) for the full flag list.
