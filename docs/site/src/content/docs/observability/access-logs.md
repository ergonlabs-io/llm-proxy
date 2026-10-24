---
title: Access logs
description: "Write one access log line per request, with token counts, timing, tenant, and selected provider."
summary: The format-string engine behind observability.access_logs, the
  operators it supports, and when a line is written.
lastUpdated: 2026-10-23
related:
  - observability/overview
  - configuration/configuration-file
  - observability/metrics-and-stats
  - reference/response-flags
  - reference/metrics
---

## At a glance

- **How to turn on**: set `observability.access_logs`.
- **Default when unset**: the proxy writes no access log. When you set the
  block and omit `output`, the destination is `stdout` and the format is
  `text`.
- **Failure mode**: fails open. A full queue or a broken destination never
  fails a request. The proxy drops the line and counts it.

Configure `observability.access_logs` to have llm-proxy write one line per
completed request. If you omit it, the proxy writes no access log. There is
no default destination.

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
observability:
  access_logs:
    output: stdout    # stdout, stderr, or a file path
    format: json      # text (default) or json
```

## When a line is written

The proxy writes one line for each request, at the end of the response
stream. It does not write at the response headers, and it does not write for
each chunk. This matters for LLM traffic. The headers of a streamed response
arrive at once, but the tokens take the whole generation. A line at header
time would show a near-zero duration and byte count for every streamed
response.

A line is written whether the stream ends cleanly, errors, or is abandoned
(a client that disconnects mid-stream). llm-proxy does not add a synthetic
event to the response body to explain a failure. The client sees an unclean
end to the stream. The proxy records the failure in the access log and in a
`tracing` warning. An error frame in the provider's event schema could look
like model output, so the proxy keeps failure reports out of the response
body.

## Text format

The default. One line per request. The `llmproxy` config file does not let
you supply your own format string: it offers only `text` and `json`, and both
use a fixed format.

The fixed text format of the `llmproxy` config file is:

```text
[%START_TIME%] "%REQ(:METHOD)% %REQ(X-ENVOY-ORIGINAL-PATH?:PATH)% %PROTOCOL%"
%RESPONSE_CODE% %RESPONSE_FLAGS% %BYTES_RECEIVED% %BYTES_SENT% %DURATION%
"%REQ(X-REQUEST-ID)%" "%UPSTREAM_HOST%"
llm_tokens="%LLM_INPUT_TOKENS%/%LLM_CACHED_TOKENS%/%LLM_CACHE_CREATION_TOKENS%/%LLM_OUTPUT_TOKENS%/%LLM_TOTAL_TOKENS%"
llm_ttft_ms="%LLM_TTFT%" llm_tpot_ms="%LLM_TPOT%" llm_max_stall_ms="%LLM_MAX_STALL%"
llm_response_chunks="%LLM_RESPONSE_CHUNKS%"
key_id="%LLM_KEY_ID%" tenant="%LLM_TENANT%" user_id="%LLM_USER_ID%"
requested_model="%LLM_REQUESTED_MODEL%" resolved_model="%LLM_RESOLVED_MODEL%"
guardrail="%LLM_GUARDRAIL%"
selected_provider="%UPSTREAM_CLUSTER%"
selected_model="%LLM_SELECTED_MODEL%" rate_card_version="%LLM_RATE_CARD_VERSION%"
llm_list_cost_nanodollars="%LLM_LIST_COST%"
llm_credential_source="%LLM_CREDENTIAL_SOURCE%" llm_served_model="%LLM_SERVED_MODEL%"
llm_usage_completeness="%LLM_USAGE_COMPLETENESS%" llm_cost_kind="%LLM_COST_KIND%"
llm_upstream_id="%LLM_UPSTREAM_ID%"
response_code_details="%RESPONSE_CODE_DETAILS%"
timing_us="ds_rx=%COMMON_DURATION(DS_RX_BEG:DS_RX_END:us)%
pre_upstream=%COMMON_DURATION(DS_RX_END:US_TX_BEG:us)%
us_tx=%COMMON_DURATION(US_TX_BEG:US_TX_END:us)%
us_wait=%COMMON_DURATION(US_TX_END:US_RX_BEG:us)%
resp_head=%COMMON_DURATION(US_RX_BEG:DS_TX_BEG:us)%
ds_tx=%COMMON_DURATION(DS_TX_BEG:DS_TX_END:us)%"
```

The real format is one line that ends with a newline. The block above is
wrapped for reading. The key, tenant, user, model, provider, rate-card, and
cost fields come before `timing_us`. The JSON format carries the same fields.

`timing_us` divides the request into phases, in microseconds. See
[Request phases](#request-phases). The phases have no upstream connect time.
On a connection that is used again, that value is from an earlier request. A
connect that the request did make is part of `pre_upstream`.

For a request that fails to connect to its provider, `%RESPONSE_FLAGS%` is
`UF`. See [Response flags](#response-flags). A dash in
`llm_tokens="-/-/-/-/-"` is not a zero. A dash means the provider reported no
usage for this exchange. That is different from "zero tokens were used". Do
not confuse the two on a billing dashboard.

Both fixed formats include `%LLM_CREDENTIAL_SOURCE%`, `%LLM_SERVED_MODEL%`,
`%LLM_USAGE_COMPLETENESS%`, `%LLM_COST_KIND%`, and `%LLM_UPSTREAM_ID%`. Only the
JSON format includes `%LLM_UPSTREAM_USAGE%`, because raw JSON breaks the
quoting of the text line.
See [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/#access-log).

## JSON format

One JSON object per line. Every value renders as a JSON string, including
numbers. The one exception is `llm_upstream_usage`, which is a JSON object
(or `null`). The field values all go through the same format-string engine as the
text format. The JSON format has no typed (numeric or boolean) value. The
keys appear in alphabetical order.

The fixed JSON format of the `llmproxy` config file has these keys:

| Key | Operator |
|---|---|
| `start_time` | `%START_TIME%` |
| `method` | `%REQ(:METHOD)%` |
| `path` | `%REQ(X-ENVOY-ORIGINAL-PATH?:PATH)%` |
| `protocol` | `%PROTOCOL%` |
| `response_code` | `%RESPONSE_CODE%` |
| `response_flags` | `%RESPONSE_FLAGS%` |
| `response_code_details` | `%RESPONSE_CODE_DETAILS%`: why the proxy ended the request itself, for example `endpoint_not_metered` or `spend_budget_exceeded` |
| `bytes_received`, `bytes_sent` | `%BYTES_RECEIVED%`, `%BYTES_SENT%` |
| `duration_ms` | `%DURATION%` |
| `request_id` | `%REQ(X-REQUEST-ID)%` |
| `authority` | `%REQ(:AUTHORITY)%` |
| `upstream_host` | `%UPSTREAM_HOST%` |
| `client_address` | `%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%`: the client address, without the port. Behind [`listen.trusted_hops`](/docs/llm-proxy/configuration/reference/#listener), it is the address from `x-forwarded-for` that the trusted proxies vouch for. |
| `selected_provider` | `%UPSTREAM_CLUSTER%` |
| `llm_input_tokens`, `llm_cached_tokens`, `llm_cache_creation_tokens`, `llm_output_tokens`, `llm_total_tokens` | The matching `%LLM_*_TOKENS%` operators |
| `llm_input_image_tokens`, `llm_output_image_tokens`, `llm_input_audio_tokens`, `llm_output_audio_tokens` | The matching `%LLM_*_IMAGE_TOKENS%` and `%LLM_*_AUDIO_TOKENS%` operators |
| `llm_images`, `llm_input_characters`, `llm_audio_ms`, `llm_price_basis` | `%LLM_IMAGES%`, `%LLM_INPUT_CHARACTERS%`, `%LLM_AUDIO_MS%`, `%LLM_PRICE_BASIS%` |
| `llm_ttft_ms`, `llm_tpot_ms`, `llm_max_stall_ms`, `llm_response_chunks` | `%LLM_TTFT%`, `%LLM_TPOT%`, `%LLM_MAX_STALL%`, `%LLM_RESPONSE_CHUNKS%` |
| `llm_key_id`, `llm_tenant`, `llm_user_id` | `%LLM_KEY_ID%`, `%LLM_TENANT%`, `%LLM_USER_ID%` |
| `llm_requested_model`, `llm_resolved_model`, `llm_selected_model` | `%LLM_REQUESTED_MODEL%`, `%LLM_RESOLVED_MODEL%`, `%LLM_SELECTED_MODEL%` |
| `llm_guardrail` | `%LLM_GUARDRAIL%` |
| `llm_rate_card_version` | `%LLM_RATE_CARD_VERSION%` |
| `llm_list_cost_nanodollars` | `%LLM_LIST_COST%` |
| `llm_credential_source` | `%LLM_CREDENTIAL_SOURCE%` (`platform` or `tenant`) |
| `llm_usage_completeness`, `llm_cost_kind` | `%LLM_USAGE_COMPLETENESS%`, `%LLM_COST_KIND%` |
| `llm_upstream_id` | `%LLM_UPSTREAM_ID%` |
| `llm_upstream_usage` | `%LLM_UPSTREAM_USAGE%`, embedded as a JSON object |
| `ds_rx_us`, `pre_upstream_us`, `us_tx_us`, `us_wait_us`, `resp_head_us`, `ds_tx_us` | The `%COMMON_DURATION%` phases of `timing_us` in the text format. See [Request phases](#request-phases). |
| `llm_served_model` | `%LLM_SERVED_MODEL%`: the `model` the provider's response says it served, which can be a dated snapshot of the selected model or a different model. The cost is computed at this model when the rate card lists it for the provider; otherwise at the selected model. `-` when the response named none. |

The text format uses the same names without the `llm_` prefix for `key_id`,
`tenant`, `user_id`, `requested_model`, `resolved_model`, `selected_model`,
`guardrail`, and `rate_card_version`. The names `selected_provider`,
`llm_list_cost_nanodollars`, `llm_credential_source`, `llm_served_model`,
`llm_usage_completeness`, `llm_cost_kind`, and `llm_upstream_id` are the same
in both formats.

## The operator set

The table below documents every operator in the two fixed formats above. Use
it to read a line field by field. The proxy resolves every operator once, at
config-load time. It does not parse the format again for each request.

| Operator | Renders |
|---|---|
| `%START_TIME%` / `%START_TIME(fmt)%` | Request start time. `fmt` is a strftime pattern; default is ISO-8601 with millisecond precision. A pattern with a specifier that cannot be formatted (for example `%E3S`) is a configuration error. |
| `%REQ(X)%` / `%REQ(X?Y)%` / `%REQ(X):Z%` | Request header `X`, falling back to `Y` if absent, truncated to `Z` characters. `:METHOD`, `:PATH`, `:AUTHORITY`, `:SCHEME` are pseudo-headers. For the credential headers `authorization`, `proxy-authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, and `cookie` (any case, also as a `?` fallback name), the operator renders `[REDACTED]` when the header is present and `-` when it is absent. The value never reaches the log. Envoy renders these headers verbatim; this is a deliberate difference. |
| `%RESP(X)%` / `%RESP(X?Y)%` | Response header `X`, same fallback/truncation rules. |
| `%TRAILER(X)%` / `%TRAILER(X?Y)%` | Response trailer `X`. |
| `%PROTOCOL%` | The HTTP protocol version. |
| `%RESPONSE_CODE%` | The HTTP status code, or `-` if none was ever produced. |
| `%RESPONSE_FLAGS%` | Comma-joined response flags (see below), or `-` if none fired. |
| `%RESPONSE_CODE_DETAILS%` | The reason string set by the filter or router that ended the response, for example `cluster_not_found`. `-` when none was set. |
| `%DURATION%` | Total request duration, in milliseconds. |
| `%COMMON_DURATION(START:END)%` / `%COMMON_DURATION(START:END:PRECISION)%` | The time from time point `START` to time point `END`. `PRECISION` is `ms` (the default), `us`, or `ns`; the value is truncated, not rounded. `-` when the request did not reach one of the two points, or when `END` is before `START`. See [Request phases](#request-phases). |
| `%BYTES_RECEIVED%` / `%BYTES_SENT%` | Request/response body byte counts. |
| `%UPSTREAM_HOST%` / `%UPSTREAM_CLUSTER%` | The dialed upstream host and the cluster it belongs to. |
| `%DOWNSTREAM_REMOTE_ADDRESS%` | The client address. It is the TCP peer address and port, except behind trusted hops (`listen.trusted_hops`): then it is the address from `x-forwarded-for` that the trusted proxies vouch for, with port `0`, as in Envoy. |
| `%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%` | The same address without the port. |
| `%LLM_INPUT_TOKENS%` / `%LLM_CACHED_TOKENS%` / `%LLM_CACHE_CREATION_TOKENS%` / `%LLM_OUTPUT_TOKENS%` / `%LLM_TOTAL_TOKENS%` | Token counts from the provider's own usage report. `-` when the provider reported none. It is never `0` in that case. |
| `%LLM_INPUT_IMAGE_TOKENS%` / `%LLM_OUTPUT_IMAGE_TOKENS%` / `%LLM_INPUT_AUDIO_TOKENS%` / `%LLM_OUTPUT_AUDIO_TOKENS%` | Image or audio tokens that the provider counted inside the input or output tokens. They are part of those counts, not extra tokens. `-` when the provider reported no tokens. `0` when it reported tokens and none were of this kind. |
| `%LLM_IMAGES%` | The number of images the response returned. `-` when no image count was observed. |
| `%LLM_INPUT_CHARACTERS%` | The number of Unicode characters in the request `input`. `-` when they were not counted. |
| `%LLM_AUDIO_MS%` | The audio duration the provider reported, in milliseconds. `-` when it reported none. |
| `%LLM_PRICE_BASIS%` | What the rate-card entry for this request prices: `tokens`, `images`, `characters`, or `audio_seconds`. `-` when no entry priced the request. |
| `%LLM_LIST_COST%` | Configured list cost in integer nanodollars, captured once when final response usage is available. `-` when usage, the requested model, actual provider, or a rate-card entry is unknown; this is distinct from a configured zero price. |
| `%LLM_TTFT%` | Time to first token (response headers to first body byte), in milliseconds. |
| `%LLM_TPOT%` | Mean time per output token: `(duration - ttft) / output_tokens`, in fractional milliseconds. `-` if usage, TTFT, or duration is missing, or output tokens is zero. |
| `%LLM_MAX_STALL%` | The largest gap between two consecutive response chunks, in milliseconds — the tail of the per-token latency distribution, not the mean. |
| `%LLM_RESPONSE_CHUNKS%` | Number of response body chunks observed. |
| `%LLM_TENANT%` | The authenticated tenant id the auth filter resolved. `-` when the request is not authenticated. |
| `%LLM_CREDENTIAL_SOURCE%` | The source of the last provider credential applied to this request: `platform` (the operator's) or `tenant` (the tenant's own key). `-` when no credential was applied, for example after a `403 tenant_credential_missing`. See [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/#access-log). |
| `%LLM_KEY_ID%` | The `key_id` of the credential the auth filter resolved. This is the key's configured identifier, not the key itself. `-` when the request is not authenticated. |
| `%LLM_USER_ID%` | The user identity that the auth filter resolved. For a virtual key it is the key ID, because one key is one user. For a JWT it is the synthetic key ID, and only when the JWT config names a subject claim. `-` when the request is not authenticated. |
| `%LLM_REQUESTED_MODEL%` | The `model` value the body-rewrite filter read from the request body, before any provider model mapping. `-` when no filter set it. |
| `%LLM_RESOLVED_MODEL%` | The model a resolver chose when the requested model was `auto` (see [The auto model](/docs/llm-proxy/providers-and-routing/auto-model/)). `-` when nothing was resolved. Takes no argument. `%LLM_REQUESTED_MODEL%` stays `auto`. |
| `%LLM_GUARDRAIL%` | The outcome of the request guardrail: `allowed`, `denied`, `error`, `timeout`, `over_limit`, or `failure_mode_allowed`. `-` when no guardrail checked the request. See [Request guardrails](/docs/llm-proxy/authentication/guardrails/). |
| `%LLM_SELECTED_MODEL%` | The model name sent to the provider that served the response, after any provider model mapping. If no mapping matches, it is the requested model. `-` when there is no requested model. |
| `%LLM_RATE_CARD_VERSION%` | The version of the rate card used for `%LLM_LIST_COST%`. `-` when no list cost was computed. |
| `%LLM_USAGE_COMPLETENESS%` | `complete`, or `partial` for a stream cut off before the provider's final usage (its tokens and cost are then estimates). `-` when no usage filter ran. |
| `%LLM_COST_KIND%` | `list` for a rate-card price of provider-reported usage, `estimate` when the usage was estimated. `-` when there is no cost. |
| `%LLM_UPSTREAM_ID%` | The provider's own id for the response (`chatcmpl-...`, `msg_...`, `resp_...`), for matching a request against the provider's dashboard. `-` when the response carried none or the id was over 256 bytes. |
| `%LLM_UPSTREAM_USAGE%` | The provider's `usage` object exactly as it sent it (the last one, when a stream carries several). Evidence only: the proxy never reads a field of it, and `%LLM_LIST_COST%` comes from the rate card alone. In a `json_format` field whose whole value is this operator it is embedded as a JSON object (`null` when absent); elsewhere it is text, `-` when absent. Over 4096 bytes it is not stored and `llmproxy_usage_upstream_usage_oversized_total` counts the miss. A `usage` object in a JSON body that a strict JSON parser refuses (a number outside the double range, or a lone `\u` surrogate) is not stored either. Never a metric label. |

A literal `%` is written as `%%`.

## Request phases

`%COMMON_DURATION%` measures the time between two points in the life of one
request. The points are the same as in Envoy v1.38. The names are
case-sensitive.

| Point | The time when |
|---|---|
| `DS_RX_BEG` | The request started. `%DURATION%` starts at the same time. |
| `DS_RX_END` | The proxy received the last byte of the request body. |
| `US_CX_BEG` | The TCP connect to the provider started. |
| `US_CX_END` | The TCP connect to the provider completed. |
| `US_HS_END` | The TLS handshake with the provider completed. A plaintext provider has no handshake, so a duration that uses this point is `-`. |
| `US_TX_BEG` | The proxy started to send the request to the provider. |
| `US_TX_END` | The proxy sent the last byte of the request body to the provider. |
| `US_RX_BEG` | The proxy received the response headers from the provider. |
| `US_RX_BODY_BEG` | The proxy received the first byte of the response body. |
| `US_RX_END` | The proxy received the last byte of the response. |
| `DS_TX_BEG` | The proxy started to send the response to the client. |
| `DS_TX_END` | The proxy sent the last byte of the response to the client. |

"Sent" and "received" mean given to or taken from the HTTP codec, not the
socket.

The proxy keeps connections to a provider open and uses them again. A request
on a connection that is used again shows the `US_CX_*` and `US_HS_END` points
of the connect that opened the connection. Envoy does the same. Thus
`%COMMON_DURATION(US_CX_BEG:US_CX_END)%` is not a cost of that request.
`%COMMON_DURATION(DS_RX_BEG:US_CX_BEG)%` is `-` on such a request, because the
connect started before the request.

The upstream points come from the attempt that gave the response. After a
retry, they come from the last attempt. A local reply, for example a `404` with
no route, has no upstream points.

A response that does not end correctly has no `DS_TX_END`. For example, the
client disconnects, or the provider resets the stream.

## Response flags

`%RESPONSE_FLAGS%` renders zero or more short codes, joined with `,` in the
order the proxy set them, for example `UF,URX`. It renders `-` if no flag was
set. For the meaning of each code and the codes that the proxy never sets,
see [Response flags](/docs/llm-proxy/reference/response-flags/).

## Where a line goes

`observability.access_logs.output` is `stdout`, `stderr`, or a file path.
A worker thread never writes the line itself. It copies the line into a queue,
and a separate writer thread writes it.

- Each destination has one writer thread.
- `stdout` and `stderr` each share one queue in the process. Every logger that
  writes to `stdout` uses the same queue.
- The proxy turns each file path into an absolute path. Each absolute path gets
  one sink in the process. It does not resolve symlinks, so two symlinks to one
  file get two sinks.
- Each queue holds at most 8 MiB of line bytes.

A full queue drops the new line, not an old one. The request is not affected.
Each dropped line adds 1 to `llmproxy_access_log_dropped_lines`. This counter
appears on `/stats/prometheus` and in OTLP export. It does not appear on
`/stats`. The proxy also logs a warning that names the destination. It logs at
most one such warning every 5 seconds. See
[Metrics and /stats](/docs/llm-proxy/observability/metrics-and-stats/#telemetry-health-metrics).

At shutdown the proxy flushes the queues that still hold lines. It waits at most
5 seconds. See [Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/#access-log-lines-at-exit).

### Rotating the file

The proxy does not rotate the file. To rotate it, rename the file, then send
`SIGUSR1` to the proxy. Envoy uses the same signal.

```sh
mv /var/log/llmproxy/access.log /var/log/llmproxy/access.log.1
kill -USR1 <pid>
```

- Lines that were queued before the signal go to the renamed file. Later
  lines go to a new file at the configured path.
- The same signal reopens the request-records file of `--request-records-file`.
- The proxy logs `SIGUSR1: reopened log files` with the count. If it cannot
  open the path again, it logs an error that names the file and keeps writing
  to the file that is already open.
- `stdout` and `stderr` are not reopened.
- With logrotate, use `postrotate` with `kill -USR1`. A
  `copytruncate` rotation also works and needs no signal.

The admin port has no `/reopen_logs` endpoint. Use the signal.

A broken destination (disk full, a deleted stdout pipe) never fails a request.
The writer thread does not retry the line. Each failed write adds 1 to
`llmproxy_access_log_write_failures`. The writer logs a warning at most once
every 5 seconds, so a failing destination does not become a performance
problem.

## Limitations

- The `llmproxy` config file has no field for a custom format string. It
  offers only the two fixed formats.
- The proxy has no access-log sampling and no filter by status. It writes one
  line for each request.
- The proxy writes one destination. The `observability.access_logs` block has
  one `output`.
- Delivery is best effort. A full queue drops the new line.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Each behavior above has this source.

- Write once at stream end: `crates/proxy-http/src/access_logging.rs`. JSON
  rendering: `render_json` in the same file.
- Fixed formats: `ACCESS_LOG_TEXT_FORMAT` and `lower_access_log` in
  `crates/proxy-simple-config/src/lower.rs`.
- Operator resolution: `crates/proxy-observability/src/access_log.rs`.
- Response flags: `crates/proxy-observability/src/flags.rs`.
- Write failure counter: `ACCESS_LOG_WRITE_FAILURES` in
  `crates/proxy-observability/src/stats.rs`.
- Queue, size limit, path keys, and warning rate limit: `QueuedSink`,
  `QUEUE_MAX_BYTES`, `canonical_key`, and `RateLimiter` in
  `crates/proxy-observability/src/sink.rs`.
