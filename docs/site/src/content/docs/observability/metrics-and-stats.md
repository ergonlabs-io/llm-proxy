---
title: Metrics and /stats
description: "Read proxy metrics on /stats and /stats/prometheus, or export them over OTLP."
summary: The metrics llm-proxy records, how /stats, /stats/prometheus, and OTLP
  export show them, the limits on label cardinality, how a series ends when
  its cluster or listener leaves the config, and how to turn on OTLP export.
lastUpdated: 2026-10-21
related:
  - observability/overview
  - configuration/configuration-file
  - operations/config-reload
  - limits-and-budgets/billing-ledger
  - observability/tracing
  - reference/metrics
---

llm-proxy records every metric in one registry. Three outputs read that
registry:

- `/stats` is a flat text format in the style of Envoy.
- `/stats/prometheus` is the Prometheus text exposition format.
- OTLP export pushes the whole registry to a collector. See
  [OTLP export](#otlp-export).

The admin server (the top-level `admin` field) serves the first two. Both are
read-only. They differ in coverage: `/stats` shows only the metrics that have
an Envoy name. `/stats/prometheus` and OTLP show every metric.

For the name, type, and labels of every metric, see the
[Metrics reference](/docs/llm-proxy/reference/metrics/). This page explains how
the outputs behave.

Both endpoints return `404` if the admin server has no stats registry. The
proxy does not return an empty `200`, because an empty `/stats` would mean
"no traffic" when the real answer is "no stats registry".

## At a glance

- **How to turn on**: `/stats` and `/stats/prometheus` need the top-level
  `admin` field. OTLP export needs `observability.metrics`.
- **Default when unset**: no admin server and no OTLP export. The proxy
  still records every metric in memory.
- **Failure mode**: fails open. A scrape or an export never delays a request.
  A failed OTLP export is counted.

## Inventory

Each row names the metric as it appears in `/stats/prometheus` and OTLP. In
`/stats/prometheus`, the proxy adds the prefix `envoy_` and changes each
character outside `[a-zA-Z0-9_]` to `_`. For example, `llm.client.token.usage`
becomes `envoy_llm_client_token_usage`.

### Traffic metrics

| Metric | Type | Labels | Counts | In `/stats` as |
|---|---|---|---|---|
| `upstream_rq` | counter | `cluster` | Each upstream attempt that the router dispatches. A retry counts as a new attempt. | `cluster.<cluster>.upstream_rq_total` |
| `upstream_rq_time` | histogram, ms | `cluster` | The duration of each completed attempt. 19 bucket boundaries from 0.5 to 3,600,000. | `cluster.<cluster>.upstream_rq_time` |
| `downstream_cx_total` | counter | `listener` | Each connection that the listener accepts and admits. | `listener.<listener>.downstream_cx_total` |
| `downstream_global_cx_overflow` | counter | `listener` | Each connection that the proxy closes at accept because the global connection limit is reached. It is not in `downstream_cx_total`. | `listener.<listener>.downstream_global_cx_overflow` |
| `downstream_cx_transport_socket_connect_timeout` | counter | `listener` | Each accepted connection that the proxy closes because the TLS handshake missed `transport_socket_connect_timeout`. | `listener.<listener>.downstream_cx_transport_socket_connect_timeout` |
| `downstream_rq_active` | gauge | `scope` (the listener scope, `llmproxy` in a config file) | Requests in flight now: from the moment a request reaches the HTTP layer until its response body is written out or cut. A streaming response counts for its whole stream. An upgraded (WebSocket) stream stops counting when the `101` response is sent. The value starts at 0 in each process. | `http.<scope>.downstream_rq_active` |
| `llm.client.token.usage` | counter | `provider`, `type`, `tenant` | Tokens from the provider's own usage report. `type` is `input`, `output`, `cached`, or `cache_creation`. | Not shown |
| `gen_ai.client.token.usage` | histogram, {token} | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name`, `gen_ai.token.type` | Tokens of each successful request, one observation for `input` and one for `output`. `input` includes cached tokens and cache writes, as OpenTelemetry defines it. Thus on a request with cached tokens it is larger than the `input` of `llm.client.token.usage`. 14 bucket boundaries from 1 to 67,108,864. | Not shown |
| `gen_ai.client.operation.duration` | histogram, s | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name` | Time from the request to the end of the response, for successful requests only. 14 bucket boundaries from 0.01 to 81.92. | Not shown |
| `gen_ai.server.time_to_first_token` | histogram, s | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name` | Time from the request to the first response body byte. 16 bucket boundaries from 0.001 to 10. | Not shown |
| `gen_ai.server.time_per_output_token` | histogram, s | `gen_ai.operation.name`, `gen_ai.request.model`, `gen_ai.provider.name` | Mean time for each output token after the first token. 13 bucket boundaries from 0.01 to 2.5. | Not shown |
| `llmproxy_guardrail_checks_total` | counter | `scope`, `outcome` | Request guardrail outcomes: `allowed`, `denied`, `error`, `timeout`, `over_limit`, `failure_mode_allowed`. A fail-open admission counts both its cause and `failure_mode_allowed`. See [Request guardrails](/docs/llm-proxy/authentication/guardrails/). | Not shown |
| `llmproxy_chargeback_tags_dropped_total` | counter | `reason` | Chargeback tags dropped: `not_allowed`, `too_long`, `over_count`, `malformed`, `overridden`. Tag keys and values are never labels. See [Chargeback tags](/docs/llm-proxy/limits-and-budgets/chargeback-tags/). | Not shown |
| `llmproxy_tenant_credential_requests_total` | counter | `provider`, `outcome` | Tenant-mode credential decisions: `applied`, `missing`, `unusable`. | Not shown |
| `llmproxy_provider_credential_requests_total` | counter | `cluster`, `outcome` | Provider credentials that could not be applied, one count per cluster that failed. `outcome="unavailable"`: no unexpired minted OAuth2 token, and the request got `503 provider token unavailable`. `outcome="failed"`: any other credential error (for example a failed Bedrock signature), and the request got `503 provider credential failure`. `outcome="unavailable_failover"` and `outcome="failed_failover"`: the same errors, but the next provider in the fallback chain took the request. Alert on the `_failover` values: the client sees no error, so this counter and the warning log are the only signs of a broken key. | Not shown |
| `llmproxy_usage_partial_total` | counter | `scope` | Streams that ended before the provider's final usage (client abort, upstream death). Each is recorded with `completeness: partial` and metered from an estimate. `scope` is the listener scope (`llmproxy` in a config file). Prometheus only. | Not shown |
| `llmproxy_usage_estimated_total` | counter | `scope` | Partial records whose token counts, and so cost, include an estimate. Prometheus only. | Not shown |
| `llmproxy_usage_encoded_body_total` | counter | `scope` | Responses a provider sent compressed although the proxy asked for `identity`. Their usage cannot be read, so each one is charged an estimate. Prometheus only. | Not shown |
| `llmproxy_usage_unanswered_total` | counter | `scope` | Attempts that sent the provider the whole request and got no response, charged an estimate by the provider's `unanswered_usage`. Prometheus only. | Not shown |
| `llmproxy_usage_unanswered_uncharged_total` | counter | `scope` | The same attempts, charged nothing because the provider's `unanswered_usage` is `none`. The provider can still bill them. Prometheus only. | Not shown |
| `llmproxy_realtime_usage_missing_total` | counter | `scope`, `reason` | Realtime session responses whose usage was not metered: `no_usage`, `unreadable`, `compressed`, or `cut` (in flight when the session ended). Each is also warned about, at most once a minute. Prometheus only. | Not shown |
| `llmproxy_usage_underpriced_modality_requests_total` | counter | `scope` | Priced requests whose image or audio tokens had no modality rate on their rate-card entry, so they were charged at the text rate. Prometheus only. | Not shown |
| `llmproxy_usage_upstream_usage_oversized_total` | counter | `scope` | Responses whose `usage` object was over 4096 bytes, so the record carries no `upstream_usage`. Prometheus only. | Not shown |
| `llmproxy_usage_upstream_id_oversized_total` | counter | `scope` | Responses whose provider response id was over 256 bytes, so the record carries no `upstream_response_id`. Prometheus only. | Not shown |

Notes on the traffic metrics:

- **Cluster label.** The `cluster` label is the internal cluster name, not the
  bare provider name. A provider named `ollama` appears as `provider:ollama`.
- **Token usage.** The proxy records `llm.client.token.usage` once per
  completed stream, and only if the provider reported usage. A stream with no
  usage report records nothing. The `provider` label is the cluster that the
  proxy dialled, so after a fallback it names the fallback cluster.
- **Latency histograms.** The proxy records them only for a response with no
  response flags and a `2xx` status. The request path must end in
  `/chat/completions` or `/messages` (operation `chat`), `/completions`
  (`text_completion`), `/responses` (`responses`), or `/embeddings`
  (`embeddings`). The request must also
  have a model name that the body-rewrite filter read from the body. The proxy
  never uses a cluster name in its place. The time-per-output-token histogram
  needs at least two output tokens and a duration that is not shorter than the
  time to first token.
- **Tenant credentials.** The counter is for tenant-mode requests only. See
  [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/#counter).
- **No status classes.** The proxy counts `upstream_rq` with a `cluster` label
  only. It has no `status_class` label, so success and failure are in one count.

### Telemetry health metrics

These metrics describe the proxy itself. None of them are in `/stats`.
Alert on a rising `llmproxy_access_log_dropped_lines` (a log destination is
too slow) and on a rising `llmproxy_otel_export_failures` (a collector is not
reachable).

| Metric | Type | Labels | Counts |
|---|---|---|---|
| `llmproxy_access_log_dropped_lines` | counter | none | Access-log lines that the proxy dropped because a destination queue was full. See [Access logs](/docs/llm-proxy/observability/access-logs/#where-a-line-goes). |
| `llmproxy_access_log_write_failures` | counter | none | Access-log lines that a destination failed to write or flush (disk full, closed pipe). A full queue does not count here. |
| `envoy_llmproxy_policy_snapshot_age_seconds` | gauge | `scope` (the listener scope, `llmproxy` in a config file) | Age of the replica's copy of keys, revocations, and policies, in whole seconds. Updated each poll tick, so it lags by up to one poll interval. Only on `/stats/prometheus`. See [Policy staleness](/docs/llm-proxy/authentication/virtual-keys/#policy-staleness). |
| `envoy_llmproxy_policy_store_emptied_total` | counter | `scope` (the listener scope, `llmproxy` in a config file) | Policy loads that found no keys, or no tenants, after the previous load found some. The usual cause is a shared Redis that restarted without persistence or was flushed. Every virtual key the store held then gets 401. Counted once per transition. Only on `/stats/prometheus`. See [Share state across replicas](/docs/llm-proxy/operations/running-in-production/#the-shared-store-needs-persistence). |
| `envoy_llmproxy_policy_store_rows` | gauge | `scope` (the listener scope, `llmproxy` in a config file), `kind` (`keys` or `tenants`) | Keys and tenants in the replica's last load from the store that `auth.store` selects. Configured `auth.keys` entries are not counted. A keys value of 0 means every stored virtual key gets 401: alert on it. Only on `/stats/prometheus`. See [Share state across replicas](/docs/llm-proxy/operations/running-in-production/#the-shared-store-needs-persistence). |
| `envoy_llmproxy_counter_reconciliation_age_seconds` | gauge | `scope` (the listener scope, `llmproxy` in a config file), `seam` (`rate_window`, `stream_lease`, or `spend`) | Time since the counters of one seam last reconciled with the store that `auth.store` selects, in whole seconds. `rate_window` is the token and request counts of `llmproxy.token_limit`, `stream_lease` is its concurrent-stream counts, and `spend` is the spend totals of `llmproxy.spend_limit`. The value increases while the store is unreachable. During that time the proxy continues to admit requests against the last known totals. Updated after each reconcile attempt. Only on `/stats/prometheus`. See [Configure rate limits](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/#windows). |
| `envoy_llmproxy_control_plane_store_info` | gauge | `scope` (the listener scope, `llmproxy` in a config file), `store` (`in_memory`, `persistent`, or `shared`), `node_id` (the configured node id, or `-` when none is set) | Always 1. One series for each `llmproxy.auth` chain, which names the store that `auth.store` selects. If replicas report different `node_id` values and `store` is not `shared`, each replica enforces its own limits and budgets. Only on `/stats/prometheus`. See [Share state across replicas](/docs/llm-proxy/operations/running-in-production/#a-node-id-with-a-per-replica-store). |
| `llmproxy_otel_export_failures` | counter | `signal` (`traces` or `metrics`) | OTLP export attempts that failed: a connect error, a collector rejection, or an expired deadline. |
| `llmproxy_otel_spans_dropped` | counter | none | Spans that the proxy discarded before export: the span queue was full, or the export of the batch failed. |

The proxy resolves the two `llmproxy_otel_*` metrics at start, even when
OTLP export is off, so a scrape shows `0` and not a missing series.

### Request-record metrics

The request-records file records its own metrics. They are in
`/stats/prometheus` and OTLP only. This page lists the names. The meaning of
each is on [Request capture](/docs/llm-proxy/observability/request-capture/).

- Record admission and the writer queue: `llmproxy_metadata_admission`
  (label `outcome`), `llmproxy_metadata_queue_depth`, `llmproxy_metadata_queue_capacity`,
  `llmproxy_metadata_written`, `llmproxy_metadata_write_failures`.

### Ledger metrics

The billing ledger records six counters. They are in `/stats/prometheus` and
OTLP only: `llmproxy_ledger_rejected_total` (label `reason`),
`llmproxy_ledger_unledgered_total` (label `reason`),
`llmproxy_ledger_entries_committed_total`,
`llmproxy_ledger_entries_lost_total` (label `reason`),
`llmproxy_spend_charged_micro_usd_total`, and
`llmproxy_ledger_spend_written_micro_usd_total`. The meaning of each is on
[Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/#metrics).

### Unmetered endpoint refusals

`llmproxy_unmetered_endpoint_refused_total` (labels `endpoint` and `control`)
counts requests that a spend budget or a token limit refused because the
proxy cannot count their endpoint. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/#endpoints-a-budget-cannot-count).

### Token-limit requests with no model

`llmproxy_token_limit_unknown_model_total` counts requests with no model the
proxy could read that a token limit counted against every `limits` entry with
`models`. See
[Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/#requests-with-no-model-the-proxy-can-read).

### Unknown names

A recorder that gets a cluster or listener name with no resolved handle does
nothing and does not fail. It logs one warning for each unknown name, for up
to 64 names, then one summary line. The
metric does not appear until a config names the cluster or listener.

## `/stats`

One line per counter or histogram, sorted by name, in the form `name: value`.
The two cluster lines below are from a local run with one cluster, after one
request that failed to connect and one automatic retry against the same
provider. A running proxy also lists the `listener.*` lines and the
`http.<scope>.downstream_rq_active` line.

```text
cluster.provider:ollama.upstream_rq_time: P0(0,0) P25(0.125,0.125) P50(0.25,0.25) P75(0.375,0.375) P90(0.45,0.45) P95(0.475,0.475) P99(0.495,0.495) P99.5(0.4975,0.4975) P99.9(0.49950000000000006,0.49950000000000006) P100(0.5,0.5)
cluster.provider:ollama.upstream_rq_total: 2
```

A histogram line reports ten percentiles (P0 through P100) as `P<n>(a,b)`
pairs. Both numbers in a pair are always the same. The registry keeps only a
lifetime distribution, so it has no separate "since last flush" figure. A
histogram with no observations renders `No recorded values`.

Envoy keys the listener stats by the listener address. llm-proxy uses the
listener name. The name stays the same when the listener binds to a new
address.

## `/stats/prometheus`

The same numbers in Prometheus text exposition format. This is real output for
the same state as above:

```text
# TYPE envoy_upstream_rq counter
envoy_upstream_rq{cluster="provider:ollama"} 2
# TYPE envoy_upstream_rq_time histogram
envoy_upstream_rq_time_bucket{cluster="provider:ollama",le="0.5"} 2
envoy_upstream_rq_time_bucket{cluster="provider:ollama",le="1"} 2
envoy_upstream_rq_time_bucket{cluster="provider:ollama",le="5"} 2
...
envoy_upstream_rq_time_bucket{cluster="provider:ollama",le="+Inf"} 2
envoy_upstream_rq_time_sum{cluster="provider:ollama"} 0.5
envoy_upstream_rq_time_count{cluster="provider:ollama"} 2
```

Every attribute becomes a label. The proxy does not fold labels into the
metric name, as `/stats` does. Metric and label names outside `[a-zA-Z0-9_]`
change to `_`. The proxy escapes backslash, newline, and quote in label
values. Histogram buckets are cumulative and end in `le="+Inf"`, followed by
`_sum` and `_count`. The output has one `# TYPE` line for each metric family.

## Label cardinality

A label whose values come from a request can grow without bound. The proxy
caps the number of live series for each such metric. Past the cap, a new label
value folds into one shared overflow series. A value that already has its own
series keeps it.

| Metric | Label | Cap (live series) | Overflow value |
|---|---|---|---|
| `llm.client.token.usage` | `tenant` | 4,000 | `tenant="-cardinality-overflow-"` |
| `gen_ai.client.token.usage`, `gen_ai.client.operation.duration`, `gen_ai.server.time_to_first_token`, `gen_ai.server.time_per_output_token` | `gen_ai.request.model` | 1,000 for each histogram | `gen_ai.request.model="-cardinality-overflow-"` |
| `llmproxy_tenant_credential_requests_total` | `provider` | 256 | `provider="-cardinality-overflow-"` |
| `llmproxy_provider_credential_requests_total` | `cluster` | 256 | `cluster="-cardinality-overflow-"` |
| `downstream_rq_active` | `scope` | 1,024 | `scope="overflow"` |

The cap counts series, not label values. Each tenant of
`llm.client.token.usage` uses up to four series for each provider, one for each
`type`. The 4,000 series are about 1,000 tenants for one provider.

Three rules apply to every cap:

- A series that is hidden (see the next section) does not count against its
  cap. A live name that would have folded gets its own series again.
- The first fold of a metric logs one warning. The warning names the metric
  and the cap. It never names a label value, because a client can choose it.
- Do not name a tenant `-cardinality-overflow-` or `-unauthenticated-`. The
  proxy reserves both.

A request with no authenticated tenant records `llm.client.token.usage` with
`tenant="-unauthenticated-"`. The proxy records this usage and does not skip
it. It resolves these series for each cluster when it applies a config,
without the cap.

## Series lifetime and reload

The proxy ties the lifetime of a series to the config. A config apply (a
`SIGHUP` reload) gives the registry the set of cluster names
and listener names that the config still has. The registry checks these
labels: `cluster` and `provider` (both against the cluster names), and
`listener`.

1. **Hidden.** A series whose label is not in the set stops appearing in
   `/stats`, `/stats/prometheus`, and OTLP. It stops counting against its cap.
   It still records. If the next config names it again, it reappears with its
   value. A name that is absent from a single config loses nothing.
2. **Reclaimed.** A series that two consecutive configs hide is drained. Its
   old handles stop recording. The proxy then frees the slot for reuse, after
   no reader holds an older snapshot. A name that returns later starts a new
   series at zero.

The proxy does not hide or reclaim a series by its `tenant` or
`gen_ai.request.model` label. The registry can do this. The running binary
passes no tenant set and no model set, because no config field names them.
A tenant series ends
only when its `provider` cluster leaves the config.

## OTLP export

Set an OTLP/gRPC collector endpoint to push metrics. Metric export and trace
export are separate. Each has its own task, endpoint, and deadline. You can
turn on one without the other. Metric export does not need the admin server.

Each export sends a full cumulative snapshot of the registry. It includes the
metrics that `/stats` omits. On a clean shutdown the proxy sends a last
snapshot, including requests that finished during the drain.

### Configure OTLP export

The full field reference is in the
[field reference](/docs/llm-proxy/configuration/reference/#observability). This
page gives the defaults and an example. For the `tracing` block, see
[Distributed tracing](/docs/llm-proxy/observability/tracing/).

```yaml
observability:
  metrics:
    otlp_endpoint: http://localhost:4317
    service_name: llm-proxy
    export_interval: 15s
    export_deadline: 10s
```

| Field | Type | Default | Description |
|---|---|---|---|
| `metrics.otlp_endpoint` | string | none, required | OTLP/gRPC collector endpoint for metrics. |
| `metrics.service_name` | string | `llm-proxy` | The OTLP resource attribute `service.name`. |
| `metrics.export_interval` | duration | `15s` | Time between snapshots. Range: 1s to 1h. |
| `metrics.export_deadline` | duration | `10s` | Deadline for one export. It must be less than `export_interval`. Minimum: 100ms. |

A `SIGHUP` reload that changes `observability.metrics` is refused. Restart the
proxy to change it. See [Config reload](/docs/llm-proxy/operations/config-reload/).

### Distributed tracing

Span export has its own page. See
[Distributed tracing](/docs/llm-proxy/observability/tracing/).

### If the collector fails

A hung or unreachable collector costs one bounded timeout for each attempt, and
never stops request forwarding. Each failed export adds to
`llmproxy_otel_export_failures` for its signal. The proxy also counts a
dropped batch of spans in `llmproxy_otel_spans_dropped`. The proxy does not
retry a failed metric export. The next snapshot holds the same totals.

## What `/stats` does not do

- It has no `?histogram_buckets=` and no `?filter=` query parameter.
- It has no periodic flush and no reset. Every number is a lifetime total for
  the process, except that a series ends and restarts as described in
  [Series lifetime and reload](#series-lifetime-and-reload).
- It does not show the token, latency, health, or request-record metrics. Use
  `/stats/prometheus` or OTLP for these.

## Limitations

- `/stats` shows only the metrics that have an Envoy name. Use
  `/stats/prometheus` or OTLP for the rest.
- The proxy counts `upstream_rq` with a `cluster` label only. It has no status
  class label.
- The proxy does not hide a series by its `tenant` or `gen_ai.request.model`
  label.
- OTLP export is gRPC only. A reload cannot change the OTLP settings.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Each behavior above has this source or test.

- `/stats` coverage and Envoy names: `envoy_counter_name` and
  `envoy_histogram_name` in
  `crates/proxy-observability/src/stats/envoy_render.rs`. Prometheus format:
  `crates/proxy-observability/src/stats/prometheus_render.rs`.
- `404` without a registry: `crates/proxy-admin/src/server.rs`.
- Token usage and latency histograms: `crates/proxy-http/src/access_logging.rs`
  and `GenAiLatencyStats::record` in `crates/proxy-http/src/stat_handles.rs`.
- Metric definitions and label caps: `crates/proxy-observability/src/stats.rs`
  (`Registry::resolve_capped`) and `stat_handles.rs`.
- Unknown names: `UNKNOWN_NAME_WARN_CAP` in `stat_handles.rs`.
- Series lifetime: `live_scope_for` in `crates/proxy/src/main.rs`. Tests
  `a_series_absent_from_one_scope_is_hidden_and_reappears_with_its_old_value`,
  `a_series_absent_from_two_scopes_is_freed_and_returns_at_zero`, and
  `retiring_a_provider_frees_the_cap_slots_of_its_tenant_series`.
- OTLP export: `crates/proxy-observability/src/otlp.rs`. Lowering:
  `crates/proxy-simple-config/src/lower.rs`. Defaults come from
  `schema/llmproxy-v1.schema.json`.
- OTLP tests in `crates/proxy/tests/otlp_trace_e2e.rs`:
  `a_failing_metric_export_is_counted_and_forwarding_continues`,
  `a_clean_shutdown_delivers_a_final_metric_snapshot`,
  `the_final_snapshot_includes_traffic_served_during_drain`,
  `traceparent_join_and_fallback_produce_the_right_span_tree`,
  `a_hung_collector_is_bounded_by_the_export_deadline`, and
  `a_hung_trace_export_is_bounded_and_its_batch_counted_as_dropped`.
- Span attributes: `crates/proxy-http/src/access_logging.rs` and
  `crates/proxy-http/src/router.rs`.
