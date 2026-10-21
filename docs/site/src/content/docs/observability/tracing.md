---
title: Distributed tracing
description: "Export OpenTelemetry spans over OTLP/gRPC with W3C traceparent propagation, head sampling, and one client span for each provider attempt."
summary: How to turn on OTLP trace export, which spans and attributes the proxy
  emits, how it joins an inbound trace and passes traceparent to the provider,
  how sampling works, and what happens when the collector is slow or down.
lastUpdated: 2026-10-21
related:
  - observability/overview
  - observability/metrics-and-stats
  - observability/trace-export
  - reference/metrics
  - reference/response-flags
  - operations/config-reload
  - configuration/reference
---

llm-proxy exports spans to an OTLP/gRPC collector. For each sampled request it
emits one server span. For each attempt to a provider it emits one client
span. The proxy also reads and writes the W3C `traceparent` header, so your
trace continues through the proxy into the provider call.

Distributed tracing sends spans with no bodies. It is not body export. To
export request and response bodies, see
[Request and response body export](/docs/llm-proxy/observability/trace-export/).

## At a glance

- **How to turn on**: set `observability.tracing` with an `otlp_endpoint`.
- **Default when unset**: the proxy emits no spans. It does not read
  `traceparent` and does not add it to the provider request.
- **Failure mode**: fails open. A slow or dead collector never delays or
  fails a request. The proxy drops the spans and counts them.
- **Reload**: a reload that changes the block is refused. Restart the proxy to
  change it.

Tracing and OTLP metric export are independent. You can turn on one without
the other. Set `observability.metrics` for metrics. See
[Metrics and /stats](/docs/llm-proxy/observability/metrics-and-stats/#otlp-export).

## Turn on tracing

This file is a complete `llmproxy` config. Set `OPENAI_API_KEY` before you
start the proxy.

```yaml title="llmproxy.yaml"
version: 0
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
observability:
  tracing:
    otlp_endpoint: http://127.0.0.1:4317
    service_name: llm-proxy
    sample_ratio: 0.1
    export_deadline: 5s
```

1. Start a collector that accepts OTLP/gRPC on `127.0.0.1:4317`.
2. Run `llm-proxy --config llmproxy.yaml`.
3. Look for the log line `OTLP trace export enabled`. It shows the endpoint,
   the service name, and the sample ratio.
4. Send a request to `127.0.0.1:53421`.
5. Wait up to 5 seconds. The proxy sends spans in batches.

## Settings

The [field reference](/docs/llm-proxy/configuration/reference/#observability)
is generated from the schema. This table lists the same fields.

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `otlp_endpoint` | string | none | yes | OTLP/gRPC collector URL, for example `http://localhost:4317`. |
| `service_name` | string | `llm-proxy` | no | Value of the resource attribute `service.name`. |
| `sample_ratio` | number | `1.0` | no | Head-sampling ratio for a new root span. The range is `0.0` to `1.0`. |
| `export_deadline` | duration | `5s` | no | Time limit for one batch export. The range is 100ms to 60s. |

A value out of range fails the load with the field path.

## What the proxy emits

The proxy emits spans only for sampled requests. It emits no span for an
unsampled request.

### Server span

The proxy emits one server span when the response stream ends.

| Property | Value |
|---|---|
| Name | `<METHOD> <path>`, for example `POST /v1/chat/completions`. |
| Kind | server |
| Status | `Error` if the response status is 500 or higher. Otherwise `Ok`. |

| Attribute | Type | Value |
|---|---|---|
| `http.request.method` | string | Request method. |
| `http.route` | string | Request path. |
| `response_flags` | string | Flag codes joined with `,`. Empty string if none. See [Response flags](/docs/llm-proxy/reference/response-flags/). |
| `upstream.cluster` | string | Provider that the proxy dialled, as `provider:<name>`. Present only if it dialled one. |
| `x-request-id` | string | Value of the request header. Present only if the header exists. |
| `gen_ai.operation.name` | string | Operation, for example `chat`. Present only when the proxy knows it. |
| `gen_ai.provider.name` | string | Provider type. Present only when the proxy knows it. |
| `gen_ai.request.model` | string | Model that the client requested. Present only when the proxy read it. |
| `gen_ai.response.model` | string | Model that the provider says it served. Present only when the response names one. |
| `gen_ai.response.id` | string | The provider's id for the response. Present only when the response carries one. |
| `gen_ai.usage.input_tokens` | integer | Input tokens, including cached tokens and cache writes. Present only when the provider reported usage. |
| `gen_ai.usage.output_tokens` | integer | Output tokens. Present only when the provider reported usage. |
| `gen_ai.usage.cache_read.input_tokens` | integer | Cached input tokens. Present only when the provider reported usage. |
| `gen_ai.usage.cache_creation.input_tokens` | integer | Input tokens written to the cache. Present only when the provider reported usage. |

The `gen_ai.*` names follow OpenTelemetry GenAI semantic conventions 1.41.0.
The proxy pins that version in code. A change to the pin is a code change.

### Client span

The proxy emits one client span for each attempt to a provider. A retry or a
fallback adds another client span under the same server span.

| Property | Value |
|---|---|
| Name | `upstream provider:<name>` |
| Kind | client |
| Parent | The server span. |
| Status | `Error` for a connect failure, a timeout, a codec error, or a 5xx response. Otherwise `Ok`. |

| Attribute | Value |
|---|---|
| `upstream.cluster` | Provider of the attempt, as `provider:<name>`. |
| `upstream.host` | `address:port` of the attempt. |
| `outcome` | `response`, `connect_failure`, `per_try_timeout`, `per_try_timeout_hedged`, or `codec_error`. |
| `http.response.status_code` | Status of the provider response. Present only when `outcome` is `response`. |

Spans carry no prompt, no response content, no tenant, and no key.

## Trace context

| Case | Behavior |
|---|---|
| Valid inbound `traceparent` | The proxy joins the trace. The server span has the same trace ID. It takes the caller span as its parent. It keeps the sampled flag of the caller. |
| No `traceparent`, or an invalid one | The proxy starts a new trace. It samples the trace with probability `sample_ratio`. |
| Request to the provider | The proxy sets `traceparent` to the span ID of the client span of that attempt. It replaces any header the client sent. |

Only version `00` of `traceparent` is valid. A header with another version, a
wrong length, a non-hex digit, or an all-zero ID counts as invalid.

An inbound trace with the sampled flag set is always recorded, whatever the
value of `sample_ratio`. An inbound trace with the flag clear stays
unsampled, so the proxy emits no spans for it. The proxy still sends the
provider a `traceparent` with the flag clear.

The proxy does not read or write `tracestate`.

## Delivery

| Item | Value |
|---|---|
| Batch size | 512 spans |
| Batch interval | 5 seconds |
| Queue between workers and exporter | 4096 spans |
| Limit for one export | `export_deadline` |
| Retry | None |
| Final flush | The proxy exports the last batch when it shuts down. |

When the queue is full, the proxy drops the new span. When an export fails or
times out, the proxy drops the whole batch. It does not retry the batch. Both
cases add to `llmproxy_otel_spans_dropped`. A failed export adds 1 to
`llmproxy_otel_export_failures{signal="traces"}`. See
[Metrics reference](/docs/llm-proxy/reference/metrics/).

## Change the settings

The proxy starts the exporter once, at start. A `SIGHUP` reload that changes
`observability.tracing` or `observability.metrics` is refused. The proxy
keeps serving with the previous snapshot. It logs an error that ends with
`cannot change on reload; restart the process to apply it`.

To change the settings, edit the file and restart the proxy. See
[Config reload](/docs/llm-proxy/operations/config-reload/).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Log line `OTLP exporter: invalid collector endpoint; tracing spans will be dropped` | `otlp_endpoint` is not a valid URL. | Use a URL with a scheme, such as `http://host:4317`. Restart the proxy. |
| Log line `OTLP trace export failed; batch dropped` or `OTLP trace export timed out; batch dropped` | The collector is down, rejects the batch, or is too slow. | Check the collector. Raise `export_deadline` if the collector is slow. |
| `llmproxy_otel_export_failures{signal="traces"}` rises | The same as the line above. | The same as the line above. |
| No spans for a request that has a `traceparent` | The inbound sampled flag is `00`. | Send the flag `01`, or send no `traceparent` and let the proxy start the trace. |
| Log line `SIGHUP: ... cannot change on reload` | A reload changed `observability.tracing`. | Restart the proxy. |

## Limitations

- The proxy supports OTLP over gRPC only. It has no OTLP/HTTP exporter.
- Only `http://` collector endpoints are tested. The proxy has no test for TLS
  to the collector. Treat `https://` as unverified.
- The proxy has no `tracestate` support and no baggage support.
- The proxy does not re-sample an inbound trace whose sampled flag is clear.
- Spans have no events and no links.
- The block is fixed at start. A reload cannot change it.
- Tracing is a separate pipeline from request records and body export.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Each behavior above has this source or test.

- Join, head sampling, and the `traceparent` parse:
  `FilterChainHandler::handle` in `crates/proxy-http/src/filter_manager.rs`;
  `TraceContext::parse_traceparent` and `child` in
  `crates/proxy-observability/src/trace.rs`.
- Server span and attributes: `crates/proxy-http/src/access_logging.rs`.
- Client span, `outcome` values, and the `traceparent` overwrite:
  `emit_client_span` and the attempt loop in `crates/proxy-http/src/router.rs`.
- Batch size, interval, and drop on failure: `crates/proxy-observability/src/otlp.rs`
  (`MAX_BATCH`, `BATCH_INTERVAL`, `flush`). Queue size: `SPAN_SINK_CAPACITY` in
  `crates/proxy/src/main.rs`.
- Semantic-convention pin: `SEMCONV_VERSION` in
  `crates/proxy-observability/src/stats.rs`.
- Reload refusal: `reload` in `crates/proxy/src/main.rs`. Test
  `sighup_that_changes_otlp_export_is_refused_by_name` in
  `crates/proxy/tests/reload.rs`.
- End-to-end tests in `crates/proxy/tests/otlp_trace_e2e.rs`:
  `traceparent_join_and_fallback_produce_the_right_span_tree`,
  `a_hung_trace_export_is_bounded_and_its_batch_counted_as_dropped`,
  `a_clean_shutdown_delivers_a_final_trace_batch`, and
  `tracing_without_metrics_exports_spans_and_no_metrics`.
