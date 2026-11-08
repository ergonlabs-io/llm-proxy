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
