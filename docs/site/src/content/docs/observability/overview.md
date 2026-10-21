---
title: Observability overview
description: "Compare access logs, request records, metrics, distributed tracing, body export, and the billing ledger, and choose the one you need."
summary: One table that compares the six record streams of llm-proxy by
  purpose, contents, destination, tenant consent, delivery guarantee, and
  config field, with guidance on which to enable.
lastUpdated: 2026-10-21
related:
  - observability/access-logs
  - observability/request-capture
  - observability/metrics-and-stats
  - observability/trace-export
  - limits-and-budgets/billing-ledger
  - observability/tracing
  - reference/metrics
  - reference/response-flags
---

llm-proxy has six outputs that record what happened to a request. They have
different purposes, hold different data, and make different delivery promises.
The words "trace" and "capture" are easy to confuse. This page compares the
six outputs side by side.

Only one output holds request and response bodies: body export. Only one is
meant for billing: the billing ledger.

## At a glance

- **Default when unset**: every output is off, except `/stats` and
  `/stats/prometheus`, which the admin server serves when `admin` is set.
- **Failure mode**: all outputs except the billing ledger fail open. A slow or
  broken destination loses data and raises a counter.

## Comparison

| Output | Purpose | Contents | Destination | Tenant consent | Delivery guarantee | Config |
|---|---|---|---|---|---|---|
| [Access logs](/docs/llm-proxy/observability/access-logs/) | Read one line for each request in a log pipeline. | Status, timing, token counts, tenant, key ID, model, provider, cost. No bodies. | `stdout`, `stderr`, or a file. | None. | Best effort. A full queue drops the line and counts it. | `observability.access_logs` |
| [Request records](/docs/llm-proxy/observability/request-capture/) | Keep one structured metadata record for each request for analytics. | Identity, models, provider, status, usage, cost, attempts. No bodies, no headers. | A JSON-lines file you name. | None. The operator turns it on for all tenants. | Best effort. A full queue or a failed write drops records and counts them. | `--request-records-file` flag (no dialect field) |
| [Metrics](/docs/llm-proxy/observability/metrics-and-stats/) | Watch rates, latency, and errors. | Counters, gauges, and histograms. No bodies. Tenant appears as a label on token usage. | `/stats` and `/stats/prometheus` on the admin server, or an OTLP collector. | None. | A scrape reads the live total. OTLP export is periodic. A failed export is counted. | `admin`, `observability.metrics` |
| [Distributed tracing](/docs/llm-proxy/observability/tracing/) | Follow one request across services in a trace viewer. | OTLP spans: method, path, status, response flags, provider, request ID, and GenAI model and token attributes. No bodies. | An OTLP/gRPC collector. | None. | Best effort. A full queue or a failed export drops spans and counts them. | `observability.tracing` |
| [Body export](/docs/llm-proxy/observability/trace-export/) | Collect raw request and response bodies for analysis or fine-tuning. | Request body, response body, and the request record. Raw prompts and completions. | Compressed JSON-lines files in a directory, and optionally S3-compatible storage. | Required. The operator sets the block, and each tenant opts in. | Best effort. Losses are counted. Upload is at least once. | `observability.traces` |
| [Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/) | Charge tenants. | One encrypted entry for each request dialled to a provider, with the amount charged. No bodies. | An encrypted spool directory, read over the admin API. | None. | Durable per group commit. A crash loses uncommitted entries. At least once to the consumer. | `ledger` |

## Which output do I need

- **I want to debug one request or watch a dashboard.** Use access logs and
  metrics. Both are small and hold no bodies.
- **I want to see where time goes across services.** Use distributed tracing.
  It sends spans to a collector, not bodies.
- **I want per-request analytics by tenant, user, and model.** Use request
  records with `--request-records-file`.
- **I want to train or evaluate on real prompts and answers.** Use body
  export. Read the warning on that page first.
- **I want to bill tenants.** Use the billing ledger. Nothing else is a
  billing record.

## Rules that hold for every output

- Body export is the only output that holds a request body or a response
  body. It needs the `auth` block and a tenant opt-in.
- No output blocks forwarding. A slow or broken destination loses data and
  raises a counter. The one exception is the billing ledger with
  `on_unavailable: reject` (the default). Then a full ledger refuses new
  requests with `503`.
- Every output is off until you configure it, except `/stats` and
  `/stats/prometheus`, which the admin server serves when `admin` is set.
- The `llmproxy` config file has no field for request records. Use the
  command-line flag. See [Request capture](/docs/llm-proxy/observability/request-capture/).

## Limitations

The `llmproxy` config file has no field for request records. See
[Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. The table cells come from these sources.

- Access log queue and drop counter: `crates/proxy-observability/src/sink.rs`,
  `QueuedSink`.
- Request record file sink: `crates/proxy-observability/src/metadata.rs`,
  module doc and `MetadataDelivery::start`. Flags: `crates/proxy/src/main.rs`,
  `Args`.
- Span attributes: `crates/proxy-http/src/access_logging.rs`, the
  `FinishedSpan` emit. Schema: `observability.tracing`.
- Body export consent and contents: `crates/proxy-observability/src/traces/`.
  Schema: `observability.traces`.
- Ledger guarantee and `on_unavailable`: schema `ledger`;
  `crates/proxy-observability/src/ledger.rs`.
