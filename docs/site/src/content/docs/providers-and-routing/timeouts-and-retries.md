---
title: Timeouts and retries
description: "Set request and idle timeouts, and configure when llm-proxy retries a failed provider request."
summary: The timeouts a route and a listener have, exactly which failures
  trigger a retry, and what bounds a slow or silent provider.
lastUpdated: 2026-11-09
related:
  - providers/overview
  - providers-and-routing/failover-and-aggregates
  - configuration/configuration-file
  - observability/access-logs
  - operations/tls
---

Use these settings to bound a slow or silent provider and to control which
failures the proxy retries. A route has two independent timeouts, and they
bound different things. The `llmproxy` dialect enables retries by default
(`routes[].retries.attempts`, default `1`). You set timeouts with the fields
below.

```yaml
listen:
  address: 0.0.0.0:8080
  stream_idle_timeout: 2m
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    connect_timeout: 3s
routes:
  - model: "gpt-*"
    provider: openai
    idle_timeout: 60s
    retries: { attempts: 2 }
```

This page covers both route timeouts, the listener's stream limits, and
exactly what triggers a same-provider retry.

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

This cuts the request. It does not fail over to the next provider. To fail
over instead, set `routes[].retries.per_try_timeout` (next section).

`listen.max_stream_duration` (default: no limit) bounds the whole life of a
request, however active the stream is. Before response headers the proxy
answers `504` (`UMSDR`). After headers the stream ends without a clean finish.

## `per_try_timeout`: fail over when a provider does not answer

Set per route (`routes[].retries.per_try_timeout`, no default, above `0` and
at most `1h`). It bounds the wait for one attempt's response headers, from
when the proxy sends the attempt. When it expires, the proxy abandons the
attempt and sends the next one: the next provider in `fallbacks`, or the same
provider again while `attempts` remain. With no attempt left, the client gets
`504` (`upstream request timeout`, response flag `UT`) at once, instead of
waiting for `stream_idle_timeout`. Each attempt gets the full timeout.

```yaml
routes:
  - model: "gpt-*"
    provider: openai
    fallbacks: [azure]
    retries: { per_try_timeout: 30s }
```

Choose a value above the longest time a healthy provider takes to send
response headers. For a non-streaming request that is the whole generation
time, because the provider sends nothing until it finishes.

The timeout ends when response headers arrive. It does not bound the
response body. A streaming provider that sends headers at once and then
stalls before its first token is not cut by `per_try_timeout`; the route
`idle_timeout` cuts that stream, and no failover occurs, because the client
already has the headers.

A timed-out attempt is charged. The provider received the whole request and
can still be generating, and billing, a response nobody reads. The proxy
charges that attempt by the provider's `unanswered_usage` (default `input`:
the estimated input tokens), on top of the attempt that answered. Each
attempt is charged at its own provider's rate card. Set `unanswered_usage:
none` on the provider to charge nothing; the proxy then counts and logs the
uncharged attempt.

## `connect_timeout`: bounds establishing the connection

Set per provider (`providers.<name>.connect_timeout`, default `5s`). Bounds
TCP/TLS connection establishment only. A connect failure or a connect timeout
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
`idle_timeout: 0s` turns the idle timeout off for that route, including the listener's `stream_idle_timeout` for the response body.

## What triggers a same-provider retry

`routes[].retries.attempts` (default `1`, maximum `5`) sets how many extra
attempts a route gets. `routes[].retries.on_status` sets which response
statuses are retried; the other triggers are fixed:

| Outcome | Retried? |
|---|---|
| Connection failure (TCP or TLS) | Yes |
| h2 `REFUSED_STREAM` | Yes |
| Connection reset before the provider received the whole request | Yes |
| Connection reset after the provider received the whole request, before any response byte | **No** |
| No response headers within `per_try_timeout` (when set) | Yes |
| A response status listed in `on_status` (default `429`, `500`, `502`, `503`) | Yes |
| Any other response status | **No** |
| Provider over its concurrency ceiling (the proxy answers `503` with the flag `UO`) | **No** |
| Anything after the client has started receiving the stream | Never |

```yaml
routes:
  - model: "claude-*"
    provider: anthropic
    fallbacks: [bedrock]
    # Fail over on a gateway timeout and on a 529 (overloaded),
    # but return a 429 to the client.
    retries: { on_status: [500, 502, 503, 504, 529] }
```

`on_status` takes at most 16 codes from `400` to `599`, each once. An empty
list retries no status. Absent, the list is `429, 500, 502, 503`. An unlisted
status passes straight through to the client. On a route with
`attempts: 0` and no `fallbacks` the field is a load error, because no retry
can happen.

Retrying a `4xx` answer is safe for billing in the normal case: providers do
not bill a request they refused with a `4xx`. Check your provider's terms
before you list a `4xx` other than `429`.

The dialect uses the retry tokens `connect-failure`, `refused-stream`,
`reset-before-request`, and `retriable-status-codes` (with the `on_status`
list). It does not use the broad `5xx`, `gateway-error`, or `reset` tokens. A
`per_try_timeout` is retried through a separate trigger, so setting it does
not make a reset after the whole request was sent retriable.

A connection that closes after the provider received the whole request is not
retried. The provider can already be generating a response, and a second
attempt can be billed a second time. The client gets `503` with the flag `UC`
or `UR`. The request record lists the attempt with `termination:
upstream_error`.

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

Backoff between retries is fully jittered exponential: attempt *n* waits a
duration drawn uniformly from `[0, min((2ⁿ-1) × 25ms, 250ms)]` — fixed
defaults in this configuration format (there is no field to change
them). The point of drawing a random delay rather than waiting exactly the
cap is to keep clients that all failed at once from retrying in lockstep and
hammering a struggling upstream on a fixed beat.

## `max_retry_after`: wait for a rate-limited provider

By default the proxy ignores `Retry-After`, so a `429` on a route with no
`fallbacks` is retried against the same provider after the short back-off
above, and that retry usually gets another `429`. Set
`routes[].retries.max_retry_after` (above `0`, at most `60s`) to honour the
header:

```yaml
routes:
  - model: "gpt-*"
    provider: openai
    retries: { attempts: 2, max_retry_after: 10s }
```

When a response that is retried carries `Retry-After` as a number of seconds,
the proxy waits that long, plus a random extra of up to half the value so
that clients do not retry together, but never longer than `max_retry_after`.
A longer `Retry-After` waits `max_retry_after`. A `Retry-After` given as an
HTTP date, or a missing header, gives the normal back-off. The wait is a
timer: it holds the client request, not a proxy thread.

The field is a load error on a route with `fallbacks`: each retry there goes to
the next provider, which has its own rate limit, so the proxy never waits on
the previous provider's `Retry-After`. It is also a load error with
`attempts: 0`. When no retry remains, the client gets the provider's response
with its `Retry-After` unchanged.

## What the client sees when the provider resets before any response byte

If the provider connection fails or closes before the first response byte,
and no retry remains, the client gets `503`. The access log shows a response
flag that tells the two cases apart:

| Case | Status | Flag |
|---|---|---|
| The provider sends an explicit reset | `503` | `UR` |
| The provider closes the connection, or the connection fails | `503` | `UC` |
| The provider sends bytes that are not valid HTTP | `502` | `UPE` |

Only a protocol error gives `502`. A reset gives `503`. Match on `503` with
the flag `UC` or `UR` for a failed or closed provider connection. An older
release answered `502` with `UC` for a failed send. Update any client or
alert that still matches on `502` for this case.

## Downstream timeouts: how long a client has

The timeouts above bound the provider. These bound the client. They
protect the listener from slow clients. The page
[TLS](/docs/llm-proxy/operations/tls/) has the full
detail.

| Timeout | Field | Default | On expiry |
|---|---|---|---|
| Request headers | `listen.request_headers_timeout` | `10s` | HTTP/1: the proxy closes the connection, with no `408`. HTTP/2: not enforced. |
| Whole request | `listen.request_timeout` | `60s` | The proxy answers `408` (`request_overall_timeout`) and closes the HTTP/1 connection. |
| No activity | `listen.stream_idle_timeout` | `10m` | Before response headers: `408` (`stream_idle_timeout`, flag `SI`). The route `idle_timeout` bounds the gap between response chunks. |
| Total life | `listen.max_stream_duration` | none | Before response headers: `504` (flag `UMSDR`). After: the stream ends without a clean finish. |

Set a request timeout to `0s` to disable it.

The request timeout stops when the proxy has the whole request body. It does
not bound the response, so it does not cut a long generation. It does
not bound the wait for the provider. `listen.stream_idle_timeout` does
that (see above).

## Retries and fallbacks share one budget

If a route also has `fallbacks`, the same retry count governs moving to the
next provider in the chain — see
[Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/)
for exactly how `attempts` and the fallback chain interact, and the
non-obvious case where `attempts: 0` does *not* disable failover.

## Implementation notes

This section is for maintainers.

- Dialect retry tokens and the default status list: `lower_retry_policy` in
  `crates/proxy-simple-config/src/lower.rs`; field bounds: `validate_retries`
  in `crates/proxy-simple-config/src/parse.rs`, tests in
  `crates/proxy-simple-config/tests/retries.rs`. Per-try timeout failover,
  its charge and credential isolation:
  `a_primary_that_never_answers_fails_over_at_the_per_try_timeout`, and
  `on_status`: `on_status_decides_which_answers_fail_over`, both in
  `crates/proxy/tests/partial_usage_e2e.rs`. `Retry-After`:
  `rate_limited_delay` in `crates/proxy-http/src/retry.rs`,
  `retry_after_sets_the_wait_before_the_retry_and_is_capped` in
  `router_retry.rs`, and
  `a_retry_after_from_one_member_does_not_delay_failover_to_the_next` in
  `router_aggregate.rs`. Dialect timeout defaults:
  `crates/proxy-simple-config/src/model.rs`. The retry engine's trigger set:
  unit tests in `crates/proxy-http/src/retry.rs`, for example
  `gateway_error_is_502_503_504_or_no_response_only` (504 needs the
  `gateway-error` token, which the dialect never sets).
- Connect timeout: `crates/proxy-cluster/src/pool.rs`.
- Stream timeouts, in `crates/proxy-http/tests/stream_timeouts.rs`:
  `a_provider_that_never_answers_is_cut_and_its_permit_released`,
  `a_stream_that_keeps_producing_outlives_the_idle_timeout`,
  `a_stream_that_goes_quiet_mid_body_is_cut`, and
  `max_stream_duration_cuts_a_stream_that_is_still_producing`. Route idle
  timeout `0s`: `route_idle_timeout_zero_disables_the_idle_timeout_for_the_route`
  in `crates/proxy/tests/route_idle_timeout_e2e.rs`.
- Last response returned when retries end, and the 64 KiB drain limit:
  `exhausting_every_member_returns_the_last_upstream_response` and
  `a_failed_attempt_with_an_endless_body_is_abandoned_not_drained` in
  `crates/proxy-http/tests/router_aggregate.rs`.
- Reset and close flags: `codec_error_reply` in
  `crates/proxy-http/src/router.rs`. Tests in
  `crates/proxy-http/tests/response_flags.rs`:
  `an_upstream_that_closes_before_headers_records_503_and_the_uc_flag` and
  `a_garbled_upstream_response_records_and_renders_the_upe_flag`.
