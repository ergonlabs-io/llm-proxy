---
title: Timeouts and retries
description: "Set request and idle timeouts, and configure when llm-proxy retries a failed provider request."
summary: The timeouts a route and a listener have, exactly which failures
  trigger a retry, and what bounds a slow or silent provider.
lastUpdated: 2026-10-14
related:
  - providers-and-routing/providers-and-clusters
  - providers-and-routing/failover-and-aggregates
  - configuration/configuration-file
  - observability/access-logs
  - operations/tls
---

# Timeouts and retries

A route has two independent timeouts, and they bound different things. This
page covers both, the listener's stream limits, and exactly what triggers a
same-provider retry.

## The wait for a provider's first response byte: `listen.stream_idle_timeout`

`routes[]` has no `timeout` field in this schema version, and lowering always
emits `timeout: "0s"` (disabled) for every route, because LLM generations are
long-lived. `idle_timeout` only starts once response headers have arrived.
The bound on the wait for headers is the listener's `stream_idle_timeout`
(default `10m`, `0s` disables it).

If a provider accepts a TCP connection and then never answers, the proxy
answers the client `408` (`stream_idle_timeout`, response flag `SI`) after
`stream_idle_timeout`. It then releases the provider connection and the
cluster's concurrency permit. The default is long on purpose: a non-streaming
generation sends nothing until it finishes. Lower it if you only serve
streaming traffic.

This cuts the request. It does not fail over to the next provider, because
`routes[].retries` has no `per_try_timeout`. A hung provider therefore ends
the request instead of moving to a fallback.

`listen.max_stream_duration` (default: no limit) bounds the whole life of a
request, however active the stream is. Before response headers the proxy
answers `504` (`UMSDR`). After headers the stream ends without a clean finish.

Proof: `a_provider_that_never_answers_is_cut_and_its_permit_released`,
`a_stream_that_keeps_producing_outlives_the_idle_timeout`,
`a_stream_that_goes_quiet_mid_body_is_cut` and
`max_stream_duration_cuts_a_stream_that_is_still_producing` in
`crates/proxy-http/tests/stream_timeouts.rs`.

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
is deliberately no *total* duration timeout by default
(`listen.max_stream_duration` is opt-in) — LLM generations are long-lived, so
an idle-based guard is the correct one for the response direction.
`idle_timeout: 0s` turns the idle timeout off for that route, including the listener's `stream_idle_timeout` for the response body. Proof: `route_idle_timeout_zero_disables_the_idle_timeout_for_the_route` in `crates/proxy/tests/route_idle_timeout_e2e.rs`.

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

Every request that the listener accepts can be retried. A request body larger than the
listener's request body limit is rejected with `413` before it reaches the router, so the
retry limit and the body limit are the same value (default 1 MiB). When you raise the
limit with `listen.max_request_body_bytes`, larger requests also fail over.

The retry rules do not look at the HTTP method. A `POST` is retried on the same
outcomes as a `GET`: there is no idempotency check. This is deliberate for LLM
calls, where a retried completion is safe to repeat. A retry after a `5xx` or
`429` can send the same prompt to a provider twice, and the first attempt may
have been billed. If your route fronts a provider call with side effects, set
`attempts: 0` and do not use `fallbacks`.

When no retry remains, the client gets the last provider response unchanged:
its status, headers (for example `retry-after`) and body. This includes the
case where a route has `fallbacks` and every member has already been tried: the
last member's answer is returned, not a proxy-made `503`. The proxy reads at
most 64 KiB of the body of an earlier failed attempt before it drops that
attempt, so a provider that never ends an error body cannot hold the retry or
grow proxy memory.

Proof: `exhausting_every_member_returns_the_last_upstream_response` and
`a_failed_attempt_with_an_endless_body_is_abandoned_not_drained` in
`crates/proxy-http/tests/router_aggregate.rs`.

Backoff between retries is fully jittered exponential: attempt *n* waits a
duration drawn uniformly from `[0, min((2ⁿ-1) × 25ms, 250ms)]` — fixed
defaults in this configuration format (there is no field to change
them). The point of drawing a random delay rather than waiting exactly the
cap is to keep clients that all failed at once from retrying in lockstep and
hammering a struggling upstream on a fixed beat.

## What the client sees when the provider resets before any response byte

If the provider connection fails or closes before the first response byte,
and no retry remains, the client gets `503`. The access log shows a response
flag that tells the two cases apart:

| Case | Status | Flag |
|---|---|---|
| The provider sends an explicit reset | `503` | `UR` |
| The provider closes the connection, or the connection fails | `503` | `UC` |
| The provider sends bytes that are not valid HTTP | `502` | `UPE` |

Only a protocol error gives `502`. A reset gives `503`
(`codec_error_reply`, `crates/proxy-http/src/router.rs:2823-2848`).
The tests are `an_upstream_that_closes_before_headers_records_503_and_the_uc_flag`
and `a_garbled_upstream_response_records_and_renders_the_upe_flag`
(`crates/proxy-http/tests/response_flags.rs`).
Before this change, a failed send gave `502` with `UC`. Update any client
or alert that matches on `502` for this case.

## Downstream timeouts: how long a client has

The timeouts above bound the provider. Three more bound the client. They
protect the listener from slow clients. The page
[Listener TLS and downstream admission](../../operations/tls/) has the full
detail.

| Timeout | Field | Default | On expiry |
|---|---|---|---|
| TLS handshake | `transport_socket_connect_timeout` (Envoy mode only) | `10s` | The proxy closes the connection. |
| Request headers | `listen.request_headers_timeout` | `10s` | HTTP/1: the proxy closes the connection, with no `408`. HTTP/2: not enforced. |
| Whole request | `listen.request_timeout` | `60s` | The proxy answers `408` (`request_overall_timeout`) and closes the HTTP/1 connection. |
| No activity | `listen.stream_idle_timeout` | `10m` | Before response headers: `408` (`stream_idle_timeout`, flag `SI`). On a route with no `idle_timeout`, also cuts a response body that goes quiet. |
| Total life | `listen.max_stream_duration` | none | Before response headers: `504` (flag `UMSDR`). After: the stream ends without a clean finish. |

Set a request timeout to `0s` to disable it. The defaults above are the
`llmproxy` dialect defaults
(`crates/proxy-simple-config/src/model.rs:183-184`). A raw bootstrap
configuration has both HTTP timeouts disabled until it sets them. The
handshake default of `10s` applies in both front-ends.

The request timeout stops when the proxy has the whole request body. It does
not bound the response, so it does not cut a long generation. It also does
not bound the wait for the provider either: `listen.stream_idle_timeout` does
that (see above).

## Retries and fallbacks share one budget

If a route also has `fallbacks`, the same retry count governs moving to the
next provider in the chain — see
[Failover and aggregates](../../providers-and-routing/failover-and-aggregates/)
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

### Retry concurrency budget

At the upstream cluster, a raw Envoy bootstrap may set
`circuit_breakers.thresholds[].retry_budget`. It overrides that threshold's
fixed `max_retries` cap. The maximum active retries is
`max(min_retry_concurrency, floor(budget_percent × (active requests + pending requests)))`.
Omitted fields use Envoy's defaults: 20% and a minimum of 3. Both ordinary
retries and per-try-timeout hedges consume this same budget.

```yaml
circuit_breakers:
  thresholds:
    - priority: DEFAULT
      retry_budget:
        budget_percent: { value: 20.0 }
        min_retry_concurrency: 3
```

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
[Failover and aggregates](../../providers-and-routing/failover-and-aggregates/))
increments the same counter — a fallback attempt is a retry against a
different member, not a separate count.
