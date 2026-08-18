---
title: Access logs
summary: The format-string engine behind observability.access_logs, the
  operators it supports, and when a line is actually written.
last_updated: 2026-08-09
related:
  - ../configuration/configuration-file/
  - ../observability/metrics-and-stats/
---

# Access logs

Configure `observability.access_logs` to have llm-proxy write one line per
completed request. Omit it and no access log is written at all — there is
no default destination.

```yaml
observability:
  access_logs:
    output: stdout    # stdout, stderr, or a file path
    format: json       # text (default) or json
```

## When a line is written

A line is rendered and written exactly once per request, at the end of the
response stream — not when response headers are produced, and not once per
chunk (`crates/proxy-http/src/access_logging.rs`). This matters for LLM
traffic specifically: a streamed response's headers arrive almost
immediately, but the tokens (the actual duration and byte count worth
logging) take the whole length of the generation. Logging at header time
would report a near-zero duration and byte count for every streamed
response.

A line is written whether the stream ends cleanly, errors, or is abandoned
(a client that disconnects mid-stream). llm-proxy never injects a synthetic
event into the response body to explain a failure — the client sees an
unclean end to the stream, and the failure is recorded in the access log
and a `tracing` warning instead. Forging an error frame in the provider's
own event schema risks a client mistaking it for something the model
actually said; this is a transparent proxy, and failure attribution belongs
in observability, not in the response body.

## Text format

The default. One line per request, in a fixed format built from the
operators below — llm-proxy does not yet expose a way to supply your own
format string:

```text
[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION%
"%REQ(X-REQUEST-ID)%" "%UPSTREAM_HOST%"
llm_tokens="%LLM_INPUT_TOKENS%/%LLM_CACHED_TOKENS%/%LLM_CACHE_CREATION_TOKENS%/%LLM_OUTPUT_TOKENS%/%LLM_TOTAL_TOKENS%"
llm_ttft_ms="%LLM_TTFT%" llm_tpot_ms="%LLM_TPOT%" llm_max_stall_ms="%LLM_MAX_STALL%"
llm_response_chunks="%LLM_RESPONSE_CHUNKS%"
```

Real output — one line, wrapped here for readability, for a request that
failed to connect to its provider:

```text
[2026-08-10T03:48:27.389Z] "POST /v1/chat/completions HTTP/1.1" 503 UF 67 24 11
"34c3ce00-a4e0-43ae-843e-68b42143d611" "127.0.0.1:18999"
llm_tokens="-/-/-/-/-" llm_ttft_ms="0" llm_tpot_ms="-" llm_max_stall_ms="-"
llm_response_chunks="1"
```

`UF` is the response flag for an upstream connection failure — see
"Response flags" below. `llm_tokens="-/-/-/-/-"` is five dashes, not zeros:
a dash means the provider reported no usage for this exchange, which is a
different fact from "zero tokens were used" and must not be confused with
it on a billing dashboard.

## JSON format

One JSON object per line, field order preserved from configuration. Every
value renders as a JSON string — including numbers — because the field
values are all rendered through the same format-string engine as the text
format; `AccessLogFormat::Json` carries no typed (numeric/boolean) value
today (`crates/proxy-http/src/access_logging.rs`'s `render_json`). See
[Getting started](../getting-started/quickstart/) for a full real example
line and field list.

## The operator set

The table below documents every operator the engine understands — useful
for reading the two fixed formats above field by field, even though
llm-proxy does not yet let you assemble your own format string from them.
Every operator is resolved once, at config-load time, into a
pre-built list — nothing is re-parsed per request
(`crates/proxy-observability/src/access_log.rs`). An unknown `%OPERATOR%`
is a load error, never silently dropped or emitted as literal text.

| Operator | Renders |
|---|---|
| `%START_TIME%` / `%START_TIME(fmt)%` | Request start time. `fmt` is a strftime pattern; default is ISO-8601 with millisecond precision. |
| `%REQ(X)%` / `%REQ(X?Y)%` / `%REQ(X):Z%` | Request header `X`, falling back to `Y` if absent, truncated to `Z` characters. `:METHOD`, `:PATH`, `:AUTHORITY`, `:SCHEME` are pseudo-headers. |
| `%RESP(X)%` / `%RESP(X?Y)%` | Response header `X`, same fallback/truncation rules. |
| `%TRAILER(X)%` / `%TRAILER(X?Y)%` | Response trailer `X`. |
| `%PROTOCOL%` | The HTTP protocol version. |
| `%RESPONSE_CODE%` | The HTTP status code, or `-` if none was ever produced. |
| `%RESPONSE_FLAGS%` | Comma-joined response flags (see below), or `-` if none fired. |
| `%DURATION%` | Total request duration, in milliseconds. |
| `%BYTES_RECEIVED%` / `%BYTES_SENT%` | Request/response body byte counts. |
| `%UPSTREAM_HOST%` / `%UPSTREAM_CLUSTER%` | The dialed upstream host and the cluster it belongs to. |
| `%DOWNSTREAM_REMOTE_ADDRESS%` | The client's socket address. |
| `%LLM_INPUT_TOKENS%` / `%LLM_CACHED_TOKENS%` / `%LLM_CACHE_CREATION_TOKENS%` / `%LLM_OUTPUT_TOKENS%` / `%LLM_TOTAL_TOKENS%` | Token counts from the provider's own usage report. `-` when the provider reported none — never a confident-looking `0`. |
| `%LLM_TTFT%` | Time to first token (response headers to first body byte), in milliseconds. |
| `%LLM_TPOT%` | Mean time per output token: `(duration - ttft) / output_tokens`, in fractional milliseconds. `-` if usage, TTFT, or duration is missing, or output tokens is zero. |
| `%LLM_MAX_STALL%` | The largest gap between two consecutive response chunks, in milliseconds — the tail of the per-token latency distribution, not the mean. |
| `%LLM_RESPONSE_CHUNKS%` | Number of response body chunks observed. |

A literal `%` is written as `%%`.

## Response flags

`%RESPONSE_FLAGS%` renders zero or more of these short codes, comma-joined
(`crates/proxy-observability/src/flags.rs`):

| Code | Meaning |
|---|---|
| `UH` | No healthy upstream host in the cluster. |
| `UF` | Upstream connection failure. |
| `UO` | Upstream overflow (circuit breaker open). |
| `NR` | No route matched. |
| `URX` | Upstream retry limit exceeded. |
| `NC` | Matched route's cluster not found. |
| `DC` | Downstream connection terminated. |
| `LH` | Local service failed health check. |
| `UT` | Upstream request timeout. |
| `LR` | Connection local reset. |
| `UR` | Upstream remote reset. |
| `UC` | Upstream connection terminated. |
| `RL` | Rate limited locally. |
| `UAEX` | Unauthorized by external authorization service. |
| `RLSE` | Rate limit service error. |
| `IH` | Invalid request header (strict header check). |
| `SI` | Stream idle timeout. |
| `DPE` | Downstream protocol error. |
| `UPE` | Upstream protocol error. |
| `UMSDR` | Upstream request reached max stream duration. |

## Where a line goes

`observability.access_logs.output` is `stdout`, `stderr`, or a file path.
A broken destination (disk full, a deleted stdout pipe) never fails or
slows a request — write failures are swallowed, rate-limited to at most one
warning every five seconds so a failing destination doesn't itself become a
performance problem (`crates/proxy-observability/src/sink.rs`).
