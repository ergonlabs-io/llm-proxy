---
title: Usage and spend analytics
description: "Answer who spent what on which model last week with DuckDB over the billing ledger and request records, a Grafana dashboard for the metrics, and the Billing page of the admin UI."
summary: Three ways to see spend without a database in the proxy. DuckDB
  queries over saved ledger pages and the request-records file. A Grafana
  dashboard over the exported metrics. A spend table in the admin UI.
lastUpdated: 2026-11-08
related:
  - limits-and-budgets/billing-ledger
  - observability/request-capture
  - observability/metrics-and-stats
  - reference/metrics
---

llm-proxy has no analytics database. It writes two durable records of each
request, and you query them where you want. This page shows three ways to read
spend by model and key.

| You want | Use | Money source |
|---|---|---|
| A table for the last 30 days, per tenant, key and model | [Admin UI](#admin-ui) | `GET /ledger/entries` |
| Any question, over any period | [DuckDB recipe](#duckdb-recipe) | Ledger entries |
| Rates, latency and ledger health on a graph | [Grafana dashboard](#grafana-dashboard) | Prometheus metrics |

Spend per model and key is not a metric. Key and model values are unbounded,
and a metric label with unbounded values is not allowed. Read it from the
ledger.

## DuckDB recipe

DuckDB is one binary and needs no server. The two queries below run against
files written by the real proxy. A test runs them against records from the
proxy binary and checks that the totals equal the ledger entries.

1. Save the ledger pages. Each page has up to 1000 entries. Page with `after`
   until `entries` is empty. Saving a page twice does not double count,
   because the queries remove duplicates on `event_id`.

   ```sh
   curl --max-time 30 -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
     "http://127.0.0.1:53422/ledger/entries?limit=1000" -o ledger-entries-1.json
   curl --max-time 30 -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
     "http://127.0.0.1:53422/ledger/entries?after=$(jq .next_after ledger-entries-1.json)&limit=1000" \
     -o ledger-entries-2.json
   ```

   Do not call `/ledger/ack` for this. Acknowledged entries are deleted from
   the ledger. Only your billing export should acknowledge.

2. Optional. Start the proxy with `--request-records-file request-records.jsonl`
   and keep that file next to the ledger pages. See
   [Request records](/docs/llm-proxy/observability/request-capture/).

3. Run a query.

   ```sh
   duckdb -json < spend-by-model-and-key.sql
   ```

Spend by tenant, key and model. `charged_micro_usd` is the ledger's integer
charge, in millionths of a dollar. It is the amount added to the spend
counters, so it matches your budgets. The file is
`examples/analytics/spend-by-model-and-key.sql`.

```sql
-- Spend by tenant, key and model over the last 30 days, from billing-ledger
-- pages saved as ledger-entries-*.json (curl /ledger/entries, see the
-- "Usage and spend analytics" docs page). Run: duckdb -json < this-file.
-- charged_micro_usd is the ledger's own integer charge; divide by 1e6 for USD.
SELECT
  e.record.tenant_id AS tenant,
  e.record.key_id AS key,
  e.record.requested_model AS model,
  count(*) AS requests,
  sum(e.charged_micro_usd) AS charged_micro_usd
FROM (
  -- One row per request even if a page was saved twice.
  SELECT DISTINCT ON (entry.record.event_id) entry AS e
  FROM (SELECT unnest(entries) AS entry FROM read_json('ledger-entries-*.json'))
)
WHERE CAST(e.record.finished_at AS TIMESTAMPTZ) >= now() - INTERVAL 30 DAY
GROUP BY ALL
ORDER BY charged_micro_usd DESC, tenant, key, model;
```

Requests, tokens and latency from the records file, with the ledger charge
joined on `event_id`. A request that the proxy refused before a provider (a
wrong key, a model that is not allowed, a spend limit) is in the records file
and not in the ledger. Its charge is 0. The file is
`examples/analytics/requests-by-model-and-key.sql`.

```sql
-- Requests, tokens and latency by tenant, key and model, from the file written
-- by --request-records-file (request-records.jsonl), with the ledger's charge
-- joined on event_id. A request the proxy refused before a provider is in the
-- records file and not in the ledger, so its charge is 0.
-- Run: duckdb -json < this-file.
SELECT
  r.tenant_id AS tenant,
  r.key_id AS key,
  r.requested_model AS model,
  count(*) AS requests,
  coalesce(sum(r.usage.input_tokens), 0) AS input_tokens,
  coalesce(sum(r.usage.output_tokens), 0) AS output_tokens,
  coalesce(sum(l.charged_micro_usd), 0) AS charged_micro_usd
FROM read_json('request-records.jsonl') AS r
LEFT JOIN (
  SELECT DISTINCT ON (entry.record.event_id)
    entry.record.event_id AS event_id,
    entry.charged_micro_usd AS charged_micro_usd
  FROM (SELECT unnest(entries) AS entry FROM read_json('ledger-entries-*.json'))
) AS l ON l.event_id = r.event_id
WHERE CAST(r.finished_at AS TIMESTAMPTZ) >= now() - INTERVAL 30 DAY
GROUP BY ALL
ORDER BY charged_micro_usd DESC, tenant, key, model;
```

Do not sum `cost.amount` from a record to get spend. It is in nanodollars and
sums to less than the charges. The ledger's `charged_micro_usd` is the figure
that matches invoices and budgets.

### ClickHouse

The same queries work in ClickHouse with the `JSONEachRow` format for the
records file. Load ledger pages with `JSONAsString` and read `entries` with
`JSONExtractArrayRaw`. This path is not tested.

## Grafana dashboard

`deploy/grafana/llm-proxy-dashboard.json` has 11 panels: spend and spend rate,
tokens by tenant and type, requests and latency by cluster, time to first
token by model, ledger commits, ledger losses, the difference between charged
and ledgered spend, estimated usage, and request-record writes.

1. In Grafana, choose **Dashboards**, **New**, **Import**.
2. Upload the JSON file.
3. Choose your Prometheus data source for `DS_PROMETHEUS`.

The dashboard reads only the metric names in the
[metrics reference](/docs/llm-proxy/reference/metrics/). A test checks every
panel query against the metric names that the proxy exports, including the
label names. If a metric is renamed, the test fails.

The metrics use the `envoy_` prefix that the scrape adds. The `llmproxy_` names
in the reference are the same series without it.

## Admin UI

The **Billing** page has a table, **Spend by model and key, last 30 days**. It
groups ledger entries by tenant, key and requested model, and shows requests and
the charge. The admin UI does this in the browser, from `GET /ledger/entries`
with the admin token. It shows only what that token can already read, and it
adds no admin route.

One load reads at most 20000 entries. If the window holds more, the page says
that the figures are partial. Use the DuckDB recipe for a full result.

The ledger keeps entries until your billing export acknowledges them. Spend that
was acknowledged is not in the table. Keep the saved pages, or the export's own
store, for long periods.

## Limitations

- There is no OTLP log export of records.
- The admin UI table covers the last 30 days and the most recent 20000 ledger
  entries.
- The ledger has one entry for each request that reached a provider. See
  [Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/).

## Implementation notes

For maintainers.

- Recipe test: `the_duckdb_recipe_totals_match_the_ledger` in
  `crates/proxy/tests/ledger_e2e.rs`. It is `#[ignore]` and needs the `duckdb`
  CLI (`DUCKDB_BIN` sets the path). Run it with
  `cargo nextest run -p proxy --test ledger_e2e --run-ignored only -E 'test(duckdb)'`.
- Dashboard test: `crates/proxy/tests/dashboard_conformance.rs`, against
  `crates/proxy/tests/golden/prometheus_metrics.golden`.
- Admin UI grouping: `groupSpend` and `readLedgerSince` in
  `admin-ui/src/lib/observability.ts`.
