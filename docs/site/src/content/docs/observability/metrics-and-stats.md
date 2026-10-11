---
title: Metrics and /stats
summary: What the admin server's /stats and /stats/prometheus endpoints
  report today, in concrete terms, and which two metrics are defined but
  never incremented.
last_updated: 2026-08-09
related:
  - ../configuration/configuration-file/
  - ../operations/config-reload/
---

# Metrics and `/stats`

The admin server (bound with the top-level `admin` field) answers two
metrics endpoints: `/stats`, a flat text format, and `/stats/prometheus`, in
Prometheus text exposition format. Both are read-only and both render the
same underlying counters and histograms — they differ only in how they
format the same numbers (`crates/proxy-observability/src/stats/`, the
`/stats` and `/stats/prometheus` renderer modules).

## What is real today

Three instruments are wired to real traffic. The first two are per cluster:

- **`upstream_rq`** — a counter, incremented once for every upstream
  attempt the router actually dispatches (past circuit-breaker and host
  selection). A request that retries against the same provider counts each
  attempt separately (`crates/proxy-http/src/router.rs:475`,
  `crates/proxy-http/src/stat_handles.rs:141`).
- **`upstream_rq_time`** — a histogram, in milliseconds, observed once per
  completed attempt's duration, using a fixed set of 19 bucket boundaries
  defined in `crates/proxy-observability/src/stats.rs`
  (`crates/proxy-http/src/router.rs:524`,
  `crates/proxy-http/src/stat_handles.rs:143`).
- **`llmproxy_tenant_credential_requests_total`** — a counter with `provider`
  and `outcome` labels, incremented only for tenant-mode requests. It appears
  on `/stats/prometheus` as `envoy_llmproxy_tenant_credential_requests_total`
  and is omitted from the flat `/stats` output. The outcomes are `applied`,
  `missing`, and `unusable`. See
  [Tenant provider credentials](../authentication/tenant-provider-credentials/#counter)
  (`crates/proxy-observability/src/stats.rs`, `TENANT_CREDENTIAL_REQUESTS`).

The cluster label is the proxy's internal cluster name, not the bare
provider name from the config — a provider named `ollama` shows up
as `provider:ollama`. Both instruments are resolved once per cluster at
startup, from the boot config snapshot, and again for any cluster a `SIGHUP`
reload introduces (`crates/proxy/src/main.rs`'s `reload` function calls
`StatHandles::resolve_missing`) — see
[Config reload](../operations/config-reload/). A cluster the stats table has
never seen is a silent no-op, not a panic or an error: it simply does not
appear in either endpoint's output until a reload (or restart) introduces
it.

### `/stats`

One line per counter or histogram, sorted by name, `name: value`. Real
output from a local run, one cluster, after one request that failed to
connect and one automatic retry against the same provider:

```text
cluster.provider:ollama.upstream_rq_time: P0(0,0) P25(0.125,0.125) P50(0.25,0.25) P75(0.375,0.375) P90(0.45,0.45) P95(0.475,0.475) P99(0.495,0.495) P99.5(0.4975,0.4975) P99.9(0.49950000000000006,0.49950000000000006) P100(0.5,0.5)
cluster.provider:ollama.upstream_rq_total: 2
```

The histogram line reports ten percentiles (P0 through P100) as
`P<n>(a,b)` pairs, space-separated. Both numbers in each pair are always
identical — this registry keeps only a lifetime distribution, not a
separate "since last flush" one, so there is nothing to put in the first
slot that differs from the second. A histogram with no observations yet
renders `No recorded values` instead of a percentile line.

### `/stats/prometheus`

The same numbers, in Prometheus text exposition format. Real output for
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

Every attribute becomes a Prometheus label; nothing is folded into the
metric name the way `/stats` does. Metric and label names outside
`[a-zA-Z0-9_]` are sanitized to `_`; label values are backslash/newline/
quote-escaped. Histogram buckets are cumulative (`le="<boundary>"` counts
every observation at or below that boundary), ending in a `le="+Inf"` bucket
equal to the total count, followed by `_sum` and `_count` lines. One
`# TYPE` line is emitted per metric family, not per label combination
(`crates/proxy-observability/src/stats/`, the `/stats/prometheus` renderer
module).

Both endpoints return `404` if the admin server has no stats registry
configured for it — not a fabricated empty `200`, since an empty `/stats`
that looks legitimate would tell an operator "no traffic" when the real
answer is "not wired up" (`crates/proxy-admin/src/server.rs`).

## What is not wired yet

Two more instruments exist in code — a name, a unit, and a set of attribute
keys are fully defined — but no request-handling code path ever resolves or
increments them. They will not appear in either endpoint's output at all,
not even as a zero, because nothing ever calls `resolve` for them outside
this crate's own tests:

- **`downstream_cx_total`** — listener connections accepted. Defined with a
  `listener` attribute key, but nothing in the listener accept path
  increments it (`crates/proxy-observability/src/stats.rs`, the
  `DOWNSTREAM_CX_TOTAL` constant).
- **`gen_ai.client.token.usage`** — token counts by provider and type.
  Defined with `provider`/`type` attribute keys, but nothing in the usage
  filter or the router increments it — token counts today reach only the
  access log (see [Access logs](../observability/access-logs/)), not `/stats`
  or `/stats/prometheus` (`crates/proxy-observability/src/stats.rs`, the
  `GEN_AI_CLIENT_TOKEN_USAGE` constant).

Do not build a dashboard or an alert on either of these names yet — they are
reserved identifiers, not metrics a running proxy will ever populate today.

## What `/stats` does not do

There is no `?histogram_buckets=` or `?filter=` query parameter, no
per-status-class breakdown of `upstream_rq` (the counter is resolved with
only a `cluster` attribute, never `status_class`, so every attempt — success
or failure — is counted together), and no periodic flush or reset: every
number is a lifetime total for the life of the process.
