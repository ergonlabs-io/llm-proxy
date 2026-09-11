---
title: Timeouts and retries
summary: The two timeouts a route actually has, exactly which failures
  trigger a retry, and a real gap worth knowing before you rely on this
  configuration format alone to bound a slow provider.
last_updated: 2026-08-26
related:
  - ../providers-and-routing/providers-and-clusters/
  - ../providers-and-routing/failover-and-aggregates/
  - ../configuration/configuration-file/
  - ../observability/access-logs/
---

# Timeouts and retries

A route has two independent timeouts, and they bound different things. This
page covers both, exactly what triggers a same-provider retry, and one gap
in what this configuration format can bound at all.

## Caution: nothing bounds the wait for a provider's first response byte

Read this before the rest of the page. `routes[]` has no `timeout` field in
this schema version — there is only `idle_timeout`, and `idle_timeout` bounds
gaps in the response **body**, only after headers have already arrived (see
below). The router's own total-timeout mechanism, `ForwardAction::timeout`,
does bound "time to response headers", but lowering always emits `timeout:
"0s"` — this engine's spelling for "disabled" — for every route this configuration
format produces, deliberately, because LLM generations are long-lived
(`crates/proxy-simple-config/src/lower.rs`'s `lower_route`/`lower_model`;
`ForwardAction::timeout`'s doc comment in `crates/proxy-config/src/ir.rs`).

The practical consequence: if a provider accepts a TCP connection and then
never sends a response at all, nothing in this configuration format ends
that request. `connect_timeout` has already succeeded (the connection is
open), and `idle_timeout` has not started (no response has arrived to have
gaps in). The request hangs until the client itself gives up. This is
verifiable directly: the router's own test for "connected, then silent
forever" (`s4_route_timeout_fires_as_a_504` in
`crates/proxy-http/src/router.rs`) only passes because that test's route sets
a `timeout` — a field this configuration format's schema does not expose.
`per_try_timeout` (a per-attempt bound a bootstrap configuration's retry
policies can set) is likewise not in this schema's `retries` object, which
carries only `attempts`.

## `connect_timeout`: bounds establishing the connection

Set per provider (`providers.<name>.connect_timeout`, default `5s`). Bounds
TCP/TLS connection establishment only, enforced with a real
`tokio::time::timeout` around the connect call
(`crates/proxy-cluster/src/pool.rs`). A connect failure or a connect timeout
both count as the same S3 outcome for retry purposes — see the trigger table
below.

## `idle_timeout`: bounds gaps in the response body

Set per route (`routes[].idle_timeout`, default `90s`). Once response
headers have arrived, a gap longer than `idle_timeout` between response body
frames — chunks, SSE events, or WebSocket frames — ends the stream, logged as
the `SI` response flag. The timer resets on every frame, so a long but
steadily-streaming response never trips it; only a genuine stall does. There
is deliberately no *total* duration timeout by default (see the caution
above) — LLM generations are long-lived, so an idle-based guard is the
correct one for the response direction, and this is the one this
configuration format actually gives you.

## What triggers a same-provider retry

`routes[].retries.attempts` (default `1`, maximum `5`) sets how many extra
attempts a route gets. Every retry in this configuration format's routes
uses the same fixed trigger set — you cannot widen or narrow it, unlike a
raw bootstrap configuration's `retry_on`:

| Outcome | Retried? |
|---|---|
| Connection failure (TCP or TLS) | Yes |
| h2 `REFUSED_STREAM` | Yes |
| Reset before any response byte | Yes |
| Response status `429` | Yes |
| Response status `500`, `502`, `503` | Yes |
| Response status `501`, `504`, or any other status | **No** |
| Circuit-breaker / queue overflow | Yes (synthesized as a 503) |
| Anything after the client has started receiving the stream | Never |

The exact tokens lowering emits are `connect-failure,refused-stream,reset,
retriable-status-codes` with a status list of `[429, 500, 502, 503]`
(`crates/proxy-simple-config/src/lower.rs`'s `lower_route`) — notably *not*
the broad `5xx` or `gateway-error` tokens, so a `501` or a `504` a
provider itself returns is passed straight through, not retried. This is
the same trigger table the retry engine uses everywhere, pinned by
`crates/proxy-http/src/retry.rs`'s unit tests (for example
`gateway_error_is_502_503_504_or_no_response_only`, which is why 504 needs
the `gateway-error` token this configuration format never sets).

A request whose body exceeds 1 MiB is never retried at all, regardless of
`attempts` — too large to safely hold a second copy of for replay
(`RETRY_REQUEST_BUFFER_LIMIT` in `crates/proxy-http/src/router.rs`).

Backoff between retries is fully jittered exponential: attempt *n* waits a
duration drawn uniformly from `[0, min((2ⁿ-1) × 25ms, 250ms)]` — fixed
defaults in this configuration format (there is no field to change
them). The point of drawing a random delay rather than waiting exactly the
cap is to keep clients that all failed at once from retrying in lockstep and
hammering a struggling upstream on a fixed beat.

## Retries and fallbacks share one budget

If a route also has `fallbacks`, the same retry count governs moving to the
next provider in the chain — see
[Failover and aggregates](../providers-and-routing/failover-and-aggregates/)
for exactly how `attempts` and the fallback chain interact, and the
non-obvious case where `attempts: 0` does *not* disable failover.

## Bootstrap configuration

The same engine exposes `per_try_timeout`, a configurable `retry_on` token
set, `retriable_status_codes`, and a configurable backoff — all reachable
directly on a raw bootstrap configuration's route `retry_policy`, none of
them exposed by this configuration format's `routes[].retries`. Raw bootstrap
routes can also use Envoy's `previous_hosts` retry-host predicate with its
empty typed config. The router records each dispatched socket address and
re-runs load balancing up to `host_selection_retry_max_attempts`; if no new
host is found, the final selection is used, matching Envoy's fallback rather
than turning a retriable request into `no healthy upstream`. Other retry-host
predicates are rejected at config load. The `envoy-ratelimited` `retry_on`
token is also rejected because nothing yet sets the
`x-envoy-ratelimited` response header it watches for.

### `x-envoy-attempt-count`

A raw bootstrap configuration's `VirtualHost` has two more fields with no
equivalent in this configuration format's schema, both `bool`, both default
`false`:

| Field | What it does |
|---|---|
| `include_request_attempt_count` | Sets `x-envoy-attempt-count` on the request forwarded upstream, to this attempt's own number (`1` on the first try, `2` on the first retry, and so on). |
| `include_attempt_count_in_response` | Sets `x-envoy-attempt-count` on the response sent to the downstream client, to the *total* number of attempts the request took. |

Both flags are denormalized onto every route under the vhost at config-lower
time (`RouteEntry::include_request_attempt_count`/
`include_attempt_count_in_response` in `crates/proxy-config/src/ir.rs`) and
proven end to end by `crates/proxy-http/tests/router_retry.rs`:
`attempt_count_request_header_is_1_on_the_first_attempt`,
`attempt_count_request_header_increments_on_retry`,
`attempt_count_response_header_carries_the_total_attempts_made`, and
`attempt_count_headers_are_absent_when_both_flags_are_off` for the default
case. A retry that lands on a `fallbacks` member (see
[Failover and aggregates](../providers-and-routing/failover-and-aggregates/))
increments the same counter — a fallback attempt is a retry against a
different member, not a separate count.
