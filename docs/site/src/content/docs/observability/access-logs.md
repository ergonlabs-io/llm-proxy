---
title: Access logs
summary: The format-string engine behind observability.access_logs, the
  operators it supports, and when a line is actually written.
last_updated: 2026-10-13
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

The default. One line per request. The `llmproxy` config file does not let
you supply your own format string: it offers only `text` and `json`, and both
use a fixed format. In Envoy mode you can set `log_format` yourself. See
[Envoy mode](#envoy-mode-log_format).

The fixed text format of the `llmproxy` config file is
(`crates/proxy-simple-config/src/lower.rs`, `ACCESS_LOG_TEXT_FORMAT`):

```text
[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION%
"%REQ(X-REQUEST-ID)%" "%UPSTREAM_HOST%"
llm_tokens="%LLM_INPUT_TOKENS%/%LLM_CACHED_TOKENS%/%LLM_CACHE_CREATION_TOKENS%/%LLM_OUTPUT_TOKENS%/%LLM_TOTAL_TOKENS%"
llm_ttft_ms="%LLM_TTFT%" llm_tpot_ms="%LLM_TPOT%" llm_max_stall_ms="%LLM_MAX_STALL%"
llm_response_chunks="%LLM_RESPONSE_CHUNKS%"
key_id="%LLM_KEY_ID%" tenant="%LLM_TENANT%" user_id="%LLM_USER_ID%"
requested_model="%LLM_REQUESTED_MODEL%" resolved_model="%LLM_RESOLVED_MODEL%"
selected_provider="%UPSTREAM_CLUSTER%"
selected_model="%LLM_SELECTED_MODEL%" rate_card_version="%LLM_RATE_CARD_VERSION%"
llm_list_cost_nanodollars="%LLM_LIST_COST%"
llm_credential_source="%LLM_CREDENTIAL_SOURCE%" llm_served_model="%LLM_SERVED_MODEL%"
```

The real format is one line that ends with a newline. The block above is
wrapped for reading. The last five lines of the block carry the key, tenant,
user, model, provider, rate-card, and cost fields. The JSON format carries the
same fields.

For a request that fails to connect to its provider, `%RESPONSE_FLAGS%` is `UF`. See "Response
flags" below. A dash in `llm_tokens="-/-/-/-/-"` is not a zero. A dash means
the provider reported no usage for this exchange. That is a different fact
from "zero tokens were used". Do not confuse the two on a billing dashboard.

Both fixed formats include `%LLM_CREDENTIAL_SOURCE%` and `%LLM_SERVED_MODEL%`.
See [Tenant provider credentials](../../authentication/tenant-provider-credentials/#access-log).

## JSON format

One JSON object per line. Every value renders as a JSON string, including
numbers. The field values all go through the same format-string engine as the
text format. `AccessLogFormat::Json` carries no typed (numeric or boolean)
value today (`crates/proxy-http/src/access_logging.rs`, `render_json`). The
real line in [Getting started](../../getting-started/quickstart/#step-5-read-the-access-log)
shows the keys in alphabetical order.

The fixed JSON format of the `llmproxy` config file has these keys
(`crates/proxy-simple-config/src/lower.rs`, `lower_access_log`):

| Key | Operator |
|---|---|
| `start_time` | `%START_TIME%` |
| `method` | `%REQ(:METHOD)%` |
| `path` | `%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%` |
| `protocol` | `%PROTOCOL%` |
| `response_code` | `%RESPONSE_CODE%` |
| `response_flags` | `%RESPONSE_FLAGS%` |
| `bytes_received`, `bytes_sent` | `%BYTES_RECEIVED%`, `%BYTES_SENT%` |
| `duration_ms` | `%DURATION%` |
| `request_id` | `%REQ(X-REQUEST-ID)%` |
| `authority` | `%REQ(:AUTHORITY)%` |
| `upstream_host` | `%UPSTREAM_HOST%` |
| `selected_provider` | `%UPSTREAM_CLUSTER%` |
| `llm_input_tokens`, `llm_cached_tokens`, `llm_cache_creation_tokens`, `llm_output_tokens`, `llm_total_tokens` | The matching `%LLM_*_TOKENS%` operators |
| `llm_ttft_ms`, `llm_tpot_ms`, `llm_max_stall_ms`, `llm_response_chunks` | `%LLM_TTFT%`, `%LLM_TPOT%`, `%LLM_MAX_STALL%`, `%LLM_RESPONSE_CHUNKS%` |
| `llm_key_id`, `llm_tenant`, `llm_user_id` | `%LLM_KEY_ID%`, `%LLM_TENANT%`, `%LLM_USER_ID%` |
| `llm_requested_model`, `llm_resolved_model`, `llm_selected_model` | `%LLM_REQUESTED_MODEL%`, `%LLM_RESOLVED_MODEL%`, `%LLM_SELECTED_MODEL%` |
| `llm_rate_card_version` | `%LLM_RATE_CARD_VERSION%` |
| `llm_list_cost_nanodollars` | `%LLM_LIST_COST%` |
| `llm_credential_source` | `%LLM_CREDENTIAL_SOURCE%` (`platform` or `tenant`) |
| `llm_served_model` | `%LLM_SERVED_MODEL%`: the `model` the provider's response says it served, which can be a dated snapshot of the selected model or a different model. The cost is computed at this model when the rate card lists it for the provider; otherwise at the selected model. `-` when the response named none. |

The text format uses the same names without the `llm_` prefix for `key_id`,
`tenant`, `user_id`, `requested_model`, `resolved_model`, `selected_model`, and
`rate_card_version`. The names `selected_provider`,
`llm_list_cost_nanodollars`, `llm_credential_source`, and `llm_served_model` are the same in both formats.

### Envoy mode: `log_format`

In Envoy mode, the file, stdout, and stderr access loggers accept `log_format`
with `text_format` or `json_format`. If you omit `log_format`, the logger uses
Envoy's default format. `text_format_source` is not implemented
(`crates/proxy-config/src/lower.rs`, the `FileAccessLog`,
`StdoutAccessLog`, and `StderrAccessLog` field lists, and
`convert_substitution_format`). Any operator in the table below is valid in
`log_format`.

## The operator set

The table below documents every operator the engine understands. Use it to
read the two fixed formats above field by field. In Envoy mode you can build
your own format string from these operators.
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
| `%RESPONSE_CODE_DETAILS%` | The reason string set by the filter or router that ended the response, for example `cluster_not_found`. `-` when none was set. |
| `%DURATION%` | Total request duration, in milliseconds. |
| `%BYTES_RECEIVED%` / `%BYTES_SENT%` | Request/response body byte counts. |
| `%UPSTREAM_HOST%` / `%UPSTREAM_CLUSTER%` | The dialed upstream host and the cluster it belongs to. |
| `%DOWNSTREAM_REMOTE_ADDRESS%` | The client's socket address. |
| `%LLM_INPUT_TOKENS%` / `%LLM_CACHED_TOKENS%` / `%LLM_CACHE_CREATION_TOKENS%` / `%LLM_OUTPUT_TOKENS%` / `%LLM_TOTAL_TOKENS%` | Token counts from the provider's own usage report. `-` when the provider reported none — never a confident-looking `0`. |
| `%LLM_LIST_COST%` | Configured list cost in integer nanodollars, captured once when final response usage is available. `-` when usage, the requested model, actual provider, or a rate-card entry is unknown; this is distinct from a configured zero price. |
| `%LLM_TTFT%` | Time to first token (response headers to first body byte), in milliseconds. |
| `%LLM_TPOT%` | Mean time per output token: `(duration - ttft) / output_tokens`, in fractional milliseconds. `-` if usage, TTFT, or duration is missing, or output tokens is zero. |
| `%LLM_MAX_STALL%` | The largest gap between two consecutive response chunks, in milliseconds — the tail of the per-token latency distribution, not the mean. |
| `%LLM_RESPONSE_CHUNKS%` | Number of response body chunks observed. |
| `%LLM_TENANT%` | The authenticated tenant id the auth filter resolved. `-` when the request is not authenticated. |
| `%LLM_CREDENTIAL_SOURCE%` | The source of the last provider credential applied to this request: `platform` (the operator's) or `tenant` (the tenant's own key). `-` when no credential was applied, for example after a `403 tenant_credential_missing`. See [Tenant provider credentials](../../authentication/tenant-provider-credentials/#access-log). |
| `%LLM_KEY_ID%` | The `key_id` of the credential the auth filter resolved. This is the key's configured identifier, not the key itself. `-` when the request is not authenticated. |
| `%LLM_USER_ID%` | Always `-` in this release. The proxy does not yet publish an authenticated user, so there is no value to render. |
| `%LLM_REQUESTED_MODEL%` | The `model` value the body-rewrite filter read from the request body, before any provider model mapping. `-` when no filter set it. |
| `%LLM_RESOLVED_MODEL%` | The model a resolver chose when the requested model was `auto` (see [The auto model](../../providers-and-routing/auto-model/)). `-` when nothing was resolved. Takes no argument. `%LLM_REQUESTED_MODEL%` stays `auto`. |
| `%LLM_SELECTED_MODEL%` | The model name sent to the provider that served the response, after any provider model mapping. If no mapping matches, it is the requested model. `-` when there is no requested model. |
| `%LLM_RATE_CARD_VERSION%` | The version of the rate card used for `%LLM_LIST_COST%`. `-` when no list cost was computed. |
| `%LLM_USAGE_COMPLETENESS%` | `complete`, or `partial` for a stream cut off before the provider's final usage (its tokens and cost are then estimates). `-` when no usage filter ran. |
| `%LLM_COST_KIND%` | `list` for a rate-card price of provider-reported usage, `estimate` when the usage was estimated. `-` when there is no cost. |
| `%LLM_UPSTREAM_ID%` | The provider's own id for the response (`chatcmpl-...`, `msg_...`, `resp_...`), for matching a request against the provider's dashboard. `-` when the response carried none or the id was over 256 bytes. |
| `%LLM_UPSTREAM_USAGE%` | The provider's `usage` object exactly as it sent it (the last one, when a stream carries several). Evidence only: the proxy never reads a field of it, and `%LLM_LIST_COST%` comes from the rate card alone. In a `json_format` field whose whole value is this operator it is embedded as a JSON object (`null` when absent); elsewhere it is text, `-` when absent. Over 4096 bytes it is not stored and `llmproxy_usage_upstream_usage_oversized_total` counts the miss. Never a metric label. |

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
A worker thread never writes the line itself. It copies the line into a queue,
and a separate writer thread writes it
(`crates/proxy-observability/src/sink.rs`, `QueuedSink`).

- Each destination has one writer thread.
- `stdout` and `stderr` each share one queue in the process. Every logger that
  writes to `stdout` uses the same queue.
- The proxy turns each file path into an absolute path. Each absolute path gets
  one sink in the process. It does not resolve symlinks, so two symlinks to one
  file get two sinks (`canonical_key`).
- Each queue holds at most 8 MiB of line bytes (`QUEUE_MAX_BYTES`).

A full queue drops the new line, not an old one. The request is not affected.
Each dropped line adds 1 to `llmproxy_access_log_dropped_lines`. This counter
appears on `/stats/prometheus` and in OTLP export. It does not appear on
`/stats`. The proxy also logs a warning that names the destination. It logs at
most one such warning every 5 seconds. See
[Metrics and /stats](../../observability/metrics-and-stats/#telemetry-health-metrics).

At shutdown the proxy flushes the queues that still hold lines. It waits at most
5 seconds. See [Draining and shutdown](../../operations/draining-and-shutdown/#access-log-lines-at-exit).

A broken destination (disk full, a deleted stdout pipe) never fails a request.
The writer thread swallows the write error. It logs a warning at most once every
5 seconds, so a failing destination does not become a performance problem
(`RateLimiter` in `sink.rs`).
