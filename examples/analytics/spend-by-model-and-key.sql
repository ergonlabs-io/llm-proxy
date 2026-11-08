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
