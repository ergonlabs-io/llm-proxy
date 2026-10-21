---
title: Response flags
description: "The response flag codes that llm-proxy sets, what each one means, and where the flags appear in access logs, trace spans, and request records."
summary: Reference for the response flag codes in the access log, the span
  attribute response_flags, and the request record field response_flags. Lists
  the codes that a --config file can cause and the codes the proxy never sets.
lastUpdated: 2026-10-21
related:
  - observability/access-logs
  - observability/tracing
  - observability/request-capture
  - help/troubleshooting
---

A response flag is a short code that tells you why a request ended the way it
did. One request can carry more than one flag. The codes come from Envoy's
access-log vocabulary.

## At a glance

- **Where flags appear**: the access log, the server span, and the request
  record.
- **Default when no flag is set**: the access log shows `-`.
- **Order**: the proxy lists the flags in the order it set them.

## Where flags appear

| Surface | Form |
|---|---|
| Access log, text and JSON (`%RESPONSE_FLAGS%`) | Codes joined with `,`, for example `UF,URX`. The log shows `-` if no flag is set. |
| Server span attribute `response_flags` | Same joined form. The value is an empty string if no flag is set. |
| Request record field `response_flags` | JSON array of codes, for example `["UF","URX"]`. The array is empty if no flag is set. |

## Flags that a `--config` file can cause

| Code | Name | Meaning |
|---|---|---|
| `UF` | Upstream connection failure | The TCP connect to the provider was refused, or the TLS handshake failed. |
| `URX` | Upstream retry limit exceeded | The retry rules said "retry", but the attempt budget was spent. |
| `UC` | Upstream connection termination | The connection to the provider failed after connect, and the failure was not a remote reset or a protocol error. For example, the provider closed the connection before it sent headers. The proxy answers `503`. A response stream that dies mid-body also gets `UC`. |
| `UR` | Upstream remote reset | The provider reset the stream before it sent a response byte (HTTP/2 `REFUSED_STREAM`). |
| `UPE` | Upstream protocol error | The proxy could not parse the response of the provider, for example a malformed status line or header. The proxy answers `502`. |
| `SI` | Stream idle timeout | The stream had no activity for longer than the idle limit. This covers a provider that never sends headers and a response body that goes quiet. See [Timeouts and retries](/docs/llm-proxy/providers-and-routing/timeouts-and-retries/). |
| `UMSDR` | Upstream request reached max stream duration | The stream reached the listener `max_stream_duration`. The cut can happen while the proxy waits for headers or while the provider streams. |
| `DC` | Downstream connection terminated | The client closed the connection, or its request body failed, before the proxy finished the stream. |
| `RL` | Rate limited | The token limiter or a spend budget refused the request. See [Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/) and [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/). |
| `UO` | Upstream overflow | A provider `circuit_breakers.max_requests` ceiling is full, so the proxy refused the request. |
| `UH` | No healthy upstream | The provider has no endpoint that the proxy can use, for example because every endpoint is ejected. The proxy answers `503` with `no_healthy_upstream`. |
| `NC` | No cluster found | The route points to a provider that is not ready, for example while it is still warming up. The proxy answers `503` with `cluster_not_warmed`. |
| `NR` | No route found | The request matched no route. The proxy answers with its built-in `404`. |

### Notes

- `RL` is not set when a limiter fails open (for example, a store error). The
  request is admitted, and no refusal happened.
- `UR` has one producer: an HTTP/2 refused stream. A TCP reset after connect
  still shows as `UF`.
- `UO` has one producer: the `max_requests` circuit breaker.
- A route with `fallbacks` raises the retry count so that each fallback gets
  one attempt. See
  [Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

## Codes that a `--config` file cannot cause

The proxy defines more codes than the table above. Do not build alerts on
these codes.

| Code | Why it does not occur |
|---|---|
| `UT` | The `llmproxy` dialect sets no total route timeout and no per-try timeout. It sets the route timeout to `0s`, which disables it. Only the idle limits and `max_stream_duration` end a slow request. |
| `UAEX` | The external authorization filter sets it. The dialect has no field for that filter. |
| `LH`, `LR`, `RLSE`, `IH`, `DPE` | No code path sets them. They match Envoy codes for features this proxy does not have, or for conditions that fail before the proxy creates a stream record. |

## Request-record termination

The request record also has a `termination` field. The proxy derives it from
the flags and the status. It checks the conditions in this order:

| Condition | `termination` |
|---|---|
| `DC` is set | `downstream_disconnect` |
| `SI`, `UT`, or `UMSDR` is set | `timeout` |
| `UC` is set, or the status is 500 or higher | `upstream_error` |
| The reply came from the proxy itself | `local_reply` |
| None of the above | `complete` |

The record can also carry the values `cancelled`, `rejected`, and `unknown`.
This page does not list the conditions for them.

## Limitations

- This page does not list the `response_code_details` strings.
- A TCP reset after connect shows as `UF`, not `UR`.
- The proxy does not set `UT`, so a total time limit on a request does not
  exist in the `llmproxy` dialect.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Each flag has this source or test.

- Codes and reachability notes: `crates/proxy-observability/src/flags.rs`.
- Tests that drive the real condition, all in `crates/proxy-http/tests/`:
  `response_flags.rs` for `UH`, `UF`, `UO`, `NR`, `DC`, `UR`, `UC`, `SI`, and
  `UPE`; `router_retry.rs` (`retry_limit_exceeded_renders_the_urx_response_flag`)
  for `URX`; `router_access_log.rs`
  (`unknown_cluster_records_and_renders_the_nc_flag`) for `NC`;
  `stream_timeouts.rs` for `SI` and `UMSDR`.
- `RL`: `token_limit_filter.rs` and `spend_limit_filter.rs` in
  `crates/proxy-filters/src/`. Test `a_denied_request_renders_the_rl_response_flag`
  in both files.
- `SI` and `UMSDR` classification: `LoggingBody::classify` in
  `crates/proxy-http/src/access_logging.rs`. Termination mapping:
  `metadata_termination` in the same file.
- Route timeout of `0s` in the dialect: `crates/proxy-simple-config/src/lower.rs`.
