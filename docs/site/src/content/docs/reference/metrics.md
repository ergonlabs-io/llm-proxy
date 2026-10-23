---
title: Metrics reference
description: "Every metric that llm-proxy records, with its type, unit, labels, and meaning, and the rules for how the names appear on /stats, /stats/prometheus, and OTLP."
summary: One table for each area (traffic, usage and cost, credentials, state
  and policy, telemetry health, request records, ledger, body export) that
  lists each metric name, type, unit, labels, and what it counts.
lastUpdated: 2026-10-21
related:
  - observability/metrics-and-stats
  - observability/tracing
  - observability/trace-export
  - observability/request-capture
  - limits-and-budgets/billing-ledger
  - reference/response-flags
---

llm-proxy records every metric in one registry. The admin server shows the
registry on `/stats` and `/stats/prometheus`. OTLP export pushes it to a
collector. This page lists the metrics. For how the outputs behave, see
[Metrics and /stats](/docs/llm-proxy/observability/metrics-and-stats/).

## At a glance

- **Where to read**: `/stats/prometheus` on the admin server, or an OTLP
  collector. `/stats` shows only 6 metrics.
- **Default when unset**: the proxy records every metric in memory. It shows
  them only when `admin` is set or `observability.metrics` is set.
- **Failure mode**: fails open. A scrape or an export never delays a request.

## Names

The tables use the registry name. This is the OTLP name. Two rules change it:

- **Prometheus**: the proxy adds the prefix `envoy_` and changes each
  character outside `[a-zA-Z0-9_]` to `_`. For example,
  `llm.client.token.usage` is `envoy_llm_client_token_usage`. The proxy adds
  no `_total` suffix. A histogram adds `_bucket`, `_sum`, and `_count`.
- **Type**: the registry has counters, up-down counters, and histograms.
  `/stats/prometheus` shows an up-down counter as a `gauge`. This page says
  `gauge`.

A label whose values come from requests has a cap on live series. See
[Label cardinality](/docs/llm-proxy/observability/metrics-and-stats/#label-cardinality).

In the tables below, `scope` is the name of the listener scope. In an
`llmproxy` config file it is `llmproxy`. The `cluster` label is the internal
cluster name. A provider named `ollama` appears as `provider:ollama`.

## Traffic

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `upstream_rq` | counter | requests | `cluster` | Each upstream attempt that the router dispatches. A retry counts as a new attempt. |
| `upstream_rq_time` | histogram | ms | `cluster` | The duration of each completed attempt. 19 bucket boundaries from 0.5 to 3,600,000. |
| `downstream_cx_total` | counter | connections | `listener` | Each connection that the listener accepts and admits. |
| `downstream_global_cx_overflow` | counter | connections | `listener` | Each connection that the proxy closes at accept because the global connection limit is reached. It is not in `downstream_cx_total`. |
| `downstream_cx_transport_socket_connect_timeout` | counter | connections | `listener` | Each accepted connection that the proxy closes because the TLS handshake missed its time limit. |
| `downstream_rq_active` | gauge | requests | `scope` | Requests in flight now. A streaming response counts for its whole stream. An upgraded (WebSocket) stream stops counting when the `101` response is sent. |

These six are the only metrics on `/stats`. The names there are:

| Registry name | `/stats` name |
|---|---|
| `upstream_rq` | `cluster.<cluster>.upstream_rq_total` |
| `upstream_rq_time` | `cluster.<cluster>.upstream_rq_time` |
| `downstream_cx_total` | `listener.<listener>.downstream_cx_total` |
| `downstream_global_cx_overflow` | `listener.<listener>.downstream_global_cx_overflow` |
| `downstream_cx_transport_socket_connect_timeout` | `listener.<listener>.downstream_cx_transport_socket_connect_timeout` |
| `downstream_rq_active` | `http.<scope>.downstream_rq_active` |

## Token usage and latency

These metrics have no `/stats` name. The proxy records
`llm.client.token.usage` only if the provider reported usage.

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llm.client.token.usage` | counter | tokens | `provider`, `type`, `tenant` | Tokens from the provider's own usage report. `type` is `input`, `output`, `cached`, or `cache_creation`. `input` excludes the cached tokens. `provider` is the cluster the proxy dialled, so after a fallback it names the fallback. A request with no tenant records `tenant="-unauthenticated-"`. |
| `gen_ai.client.token.usage` | histogram | tokens | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name`, `gen_ai.token.type` | Tokens of each successful request, one observation for `input` and one for `output`. `input` includes cached tokens and cache writes. 14 bucket boundaries from 1 to 67,108,864. |
| `gen_ai.client.operation.duration` | histogram | s | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name` | Time from the request to the end of the response, for successful requests only. 14 bucket boundaries from 0.01 to 81.92. |
| `gen_ai.server.time_to_first_token` | histogram | s | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name` | Time from the request to the first response body byte. 16 bucket boundaries from 0.001 to 10. |
| `gen_ai.server.time_per_output_token` | histogram | s | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name` | Mean time for each output token after the first token. 13 bucket boundaries from 0.01 to 2.5. |

The `gen_ai.*` names follow OpenTelemetry GenAI semantic conventions 1.41.0.
The proxy records the latency histograms only for a response with no response
flags and a `2xx` status. The request path must end in `/chat/completions`
or `/messages` (operation `chat`), `/completions` (`text_completion`),
`/responses` (`responses`), or `/embeddings` (`embeddings`).

## Usage and cost quality

All of these are on `/stats/prometheus` and OTLP only. `scope` is the
listener scope.

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_usage_partial_total` | counter | responses | `scope` | Streams that ended before the provider's final usage (client abort, upstream death). Each is recorded with `completeness: partial` and metered from an estimate. |
| `llmproxy_usage_estimated_total` | counter | responses | `scope` | Partial records whose token counts, and so cost, include an estimate. |
| `llmproxy_usage_oversized_body_unmetered_total` | counter | requests | `scope` | Oversized JSON responses whose `usage` the proxy could not recover. Such a request has no usage and no cost, and no spend budget or token limit counts it. |
| `llmproxy_usage_served_model_repriced_total` | counter | requests | `scope` | Requests priced at the model the provider says it served, because the active rate card lists that model for the provider. |
| `llmproxy_usage_underpriced_modality_requests_total` | counter | requests | `scope` | Priced requests whose image or audio tokens had no modality rate on their rate-card entry. The proxy charged them at the text rate. |
| `llmproxy_usage_upstream_usage_oversized_total` | counter | responses | `scope` | Responses whose `usage` object was over 4096 bytes. The record carries no `upstream_usage`. |
| `llmproxy_usage_upstream_id_oversized_total` | counter | responses | `scope` | Responses whose provider response id was over 256 bytes. The record carries no `upstream_response_id`. |
| `llmproxy_usage_rate_card_active` | gauge | cards | `scope`, `version` | One series for each rate-card version this process has held. The value is 1 for the active card and 0 for each retired card. No series has the value 1 while the chain has no card. |
| `llmproxy_realtime_usage_missing_total` | counter | responses | `scope`, `reason` | Realtime session responses whose usage was not metered. `reason` is `no_usage`, `unreadable`, `compressed`, or `cut` (in flight when the session ended). |
| `llmproxy_unmetered_endpoint_refused_total` | counter | requests | `endpoint`, `control` | Requests that a spend budget or a token limit refused because the proxy cannot count their endpoint. `control` is `spend` or `token_limit`. `endpoint` is `image_generation`, `image_edit`, `speech`, `transcription`, `translation`, or `unmetered`. |
| `llmproxy_token_limit_unknown_model_total` | counter | requests | none | Requests with no model the proxy could read that a token limit counted against every `limits` entry with `models`. See [Requests with no model the proxy can read](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/#requests-with-no-model-the-proxy-can-read). |

## Routing and request checks

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_router_session_affinity_total` | counter | requests | `outcome` | Requests on a weighted model with `session_affinity`. `outcome` is `hashed` (the session hash chose the provider) or `unhashed` (no source had a value, so the pick was random). |
| `llmproxy_router_max_output_tokens_rejected_total` | counter | requests | none | Requests refused with `400` because of the `max_output_tokens` cap of the model. |
| `llmproxy_guardrail_checks_total` | counter | checks | `scope`, `outcome` | Request guardrail outcomes: `allowed`, `denied`, `error`, `timeout`, `over_limit`, `failure_mode_allowed`. A fail-open admission counts both its cause and `failure_mode_allowed`. |
| `llmproxy_chargeback_tags_dropped_total` | counter | tags | `reason` | Chargeback tags dropped: `not_allowed`, `too_long`, `over_count`, `malformed`, `overridden`. Tag keys and values are never labels. |

## Provider credentials

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_tenant_credential_requests_total` | counter | requests | `provider`, `outcome` | Tenant-mode credential decisions: `applied`, `missing`, `unusable`. `provider` is `-` when a refused cluster has no slot. |
| `llmproxy_provider_credential_requests_total` | counter | requests | `cluster`, `outcome` | Provider credentials that the proxy could not apply, one count for each cluster that failed. `unavailable`: no unexpired minted OAuth2 token (the client gets `503 provider token unavailable`). `failed`: any other credential error (the client gets `503 provider credential failure`). `unavailable_failover` and `failed_failover`: the same errors, but the next provider in the fallback chain took the request. |

Alert on the `_failover` values. The client sees no error, so this counter and
the warning log are the only signs of a broken key.

## State and policy

These metrics describe the shared store that `auth.store` selects. They are on
`/stats/prometheus` and OTLP only.

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_policy_snapshot_age_seconds` | gauge | s | `scope` | Age of the replica's copy of keys, revocations, and policies. It updates at each poll tick. Past `max_policy_staleness_seconds`, virtual-key authentication fails closed. |
| `llmproxy_policy_store_emptied_total` | counter | events | `scope` | Policy loads that found no keys, or no tenants, after the previous load found some. Every virtual key the store held then gets 401. |
| `llmproxy_policy_store_rows` | gauge | rows | `scope`, `kind` | Keys and tenants in the last load. `kind` is `keys` or `tenants`. A `keys` value of 0 means every stored virtual key gets 401. |
| `llmproxy_counter_reconciliation_age_seconds` | gauge | s | `scope`, `seam` | Time since the counters of one seam last reconciled with the store. `seam` is `rate_window`, `stream_lease`, or `spend`. The value grows while the store is unreachable. During that time the proxy admits requests against the last known totals. |
| `llmproxy_control_plane_store_info` | gauge | stores | `scope`, `store`, `node_id` | Always 1. `store` is `in_memory`, `persistent`, or `shared`. `node_id` is the configured node id, or `-`. |
| `llmproxy_control_plane_load_duration` | histogram | ms | `scope` | Duration of each successful load from the Redis-backed store. 19 bucket boundaries from 0.5 to 3,600,000. |
| `llmproxy_control_plane_load_payload_bytes` | gauge | bytes | `scope` | Size of the last successful load from the Redis-backed store. |
| `llmproxy_control_plane_load_rows` | gauge | rows | `scope` | Row count of the last successful load from the Redis-backed store, all kinds together. |

## Telemetry health

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_access_log_dropped_lines` | counter | lines | none | Access-log lines that the proxy dropped because a destination queue was full. |
| `llmproxy_access_log_write_failures` | counter | failures | none | Access-log lines that a destination failed to write or flush (disk full, closed pipe). |
| `llmproxy_otel_export_failures` | counter | failures | `signal` | OTLP export attempts that failed: a connect error, a collector rejection, or an expired deadline. `signal` is `traces` or `metrics`. |
| `llmproxy_otel_spans_dropped` | counter | spans | none | Spans that the proxy discarded before export: the span queue was full, or the export of the batch failed. |

The proxy resolves the two `llmproxy_otel_*` metrics at start, even when OTLP
export is off. A scrape shows `0` and not a missing series.

## Request records

The proxy resolves these metrics at start, also when no
`--request-records-file` is set. `llmproxy_metadata_queue_capacity` of `0`
means the file is not set. See
[Request capture](/docs/llm-proxy/observability/request-capture/).

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_metadata_admission` | counter | records | `outcome` | Whether the queue took a record. `outcome` is `accepted`, `capacity_exceeded`, `closed`, `oversize` (the record alone passed the size limit), or `invalid` (the record failed schema validation). |
| `llmproxy_metadata_queue_depth` | gauge | records | none | Records in the queue. |
| `llmproxy_metadata_queue_capacity` | gauge | records | none | Queue size. |
| `llmproxy_metadata_written` | counter | records | none | Records appended to the file. |
| `llmproxy_metadata_write_failures` | counter | failures | none | Serialization or write failures. A write failure closes admission. |

## Billing ledger

The ledger registers these metrics at start. An idle ledger shows zeros. See
[Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/#metrics).

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_ledger_rejected_total` | counter | requests | `reason` | Requests refused with `503` because no ledger reservation was available and `on_unavailable` is `reject`. `reason` is `queue_full`, `writer_failed`, or `disk_full`. |
| `llmproxy_ledger_unledgered_total` | counter | requests | `reason` | Requests that the proxy dialled without a ledger entry under `on_unavailable: admit`. Same `reason` values. |
| `llmproxy_ledger_entries_committed_total` | counter | entries | none | Entries committed to the spool. |
| `llmproxy_ledger_entries_lost_total` | counter | entries | `reason` | Entries handed to the writer and never committed. `reason` is `writer_failed`, `oversize`, or `shutdown`. |
| `llmproxy_ledger_unclean_epochs_total` | counter | epochs | none | Starts that found the previous epoch not closed. The previous process crashed, or it stopped with entries it never committed. |
| `llmproxy_spend_charged_micro_usd_total` | counter | micro-USD | none | Micro-dollars the spend filter added to spend counters, once for each request that charged at least one scope. |
| `llmproxy_ledger_spend_written_micro_usd_total` | counter | micro-USD | none | Micro-dollars of spend charges in committed ledger entries. It equals the charged total unless entries were lost or served under `admit`. |

## Body export

The exporter registers these metrics at start. See
[Request and response body export](/docs/llm-proxy/observability/trace-export/#metrics)
for the reasons behind each label value.

| Metric | Type | Unit | Labels | What it counts |
|---|---|---|---|---|
| `llmproxy_trace_captured_total` | counter | traces | none | Captures handed to the exporter. |
| `llmproxy_trace_dropped_total` | counter | traces | `reason` | Whole traces lost. |
| `llmproxy_trace_written_total` | counter | traces | `capture` | Lines written. `capture` is `complete` or `partial`. |
| `llmproxy_trace_partial_total` | counter | traces | `reason` | Each partial reason on a written line. |
| `llmproxy_trace_segments_sealed_total` | counter | segments | `reason` | Segments sealed. |
| `llmproxy_trace_segments_uploaded_total` | counter | segments | none | Segments that the store accepted and the proxy deleted. |
| `llmproxy_trace_segments_lost_total` | counter | segments | `reason` | Segments lost before they reached a destination. |
| `llmproxy_trace_segments_expired_total` | counter | segments | `reason` | Segments removed by directory retention. |
| `llmproxy_trace_upload_failures_total` | counter | attempts | `reason` | Failed upload attempts. The proxy retries each one. |
| `llmproxy_trace_consent_stale_total` | counter | requests | none | JWT requests with an opt-in withheld because the policy snapshot was stale. |
| `llmproxy_trace_disk_bytes` | gauge | bytes | none | Segment bytes on disk, open and sealed. |
| `llmproxy_trace_memory_bytes` | gauge | bytes | none | Body bytes held by captures in flight or queued. |
| `llmproxy_trace_slots` | gauge | traces | none | Captures in flight or queued. |
| `llmproxy_trace_exporter_up` | gauge | 1 | none | `1` while the exporter thread runs. `0` after it stops. |
| `llmproxy_trace_capture_disabled` | gauge | 1 | none | `1` while the emergency switch is closed. `0` while capture is allowed. |

## Removed metrics

The `llmproxy_capture_*` metrics and `llmproxy_metadata_durable` no longer
exist. They belonged to the capture agent, which is removed.

## Limitations

- `/stats` shows 6 metrics. Use `/stats/prometheus` or OTLP for the rest.
- The `upstream_rq` metric has a `cluster` label only. It has no status class.
- Tenant, user, key, and session values are never labels, with one exception:
  `llm.client.token.usage` has a `tenant` label, with a cap.
- A series ends when its cluster or listener leaves the config.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. This page comes from these sources.

- Registry metrics: the `instruments` module in
  `crates/proxy-observability/src/stats.rs`.
- Metrics defined beside their recorder: `crates/proxy-http/src/stat_handles.rs`
  (`MAX_OUTPUT_TOKENS_REJECTED`, `SESSION_AFFINITY`),
  `crates/proxy-filters/src/guardrail_filter.rs` (`CHECKS`),
  `crates/proxy-filters/src/chargeback_tags.rs` (`DROPPED`), and
  `crates/proxy-control/src/control_redis.rs` (`LOAD_DURATION`,
  `LOAD_PAYLOAD_BYTES`, `LOAD_ROWS`).
- The registry also defines an `ext_authz` counter for the Envoy-mode external
  authorization filter. A `--config` file cannot reach it, so this page omits it.
- Prometheus names, the `envoy_` prefix, and the gauge mapping:
  `crates/proxy-observability/src/stats/prometheus_render.rs`. `/stats` names:
  `envoy_counter_name` in `crates/proxy-observability/src/stats/envoy_render.rs`.
- Semantic-convention version: `SEMCONV_VERSION` in `stats.rs`.
