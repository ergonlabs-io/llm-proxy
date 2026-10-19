---
title: Spend policies and recovery
description: "Key and tenant ceilings, migration, shared Redis accounting, and crash recovery."
lastUpdated: 2026-10-13
---

Spend enforcement uses two kinds of ceiling, and either one can refuse a
request. A key budget counts the spend of one stable `key_id`. A tenant budget
counts the spend of every key of one tenant. Each ceiling uses its own UTC
budget period and counts spend across every model and selected provider. There
is no per-user budget. A key budget never grants model access.

In the `llmproxy` dialect, an `auth:` block adds `llmproxy.spend_limit` to the
chain for you, with the `START_KEYS_FRESH` cutover already set (the dialect never
had legacy tenant budgets), and it prices requests from the `pricing` rate card.
Set `auth.enforce.spend: false` to leave the filter out. The proxy then warns at
load, and `PUT /tenants/{id}/budget` returns `409` with
`{"error":"not_enforced", ...}` instead of storing a budget nothing enforces.
With `auth:` and no `pricing`, every request costs $0, so the proxy warns that
budgets cannot fire.

Missing budget means unlimited; an explicit zero denies the first request.
Charges use integer micro-dollars and the rate card for the provider actually
dialled, including after fallback. A request that the rate card does not price
adds $0 to every budget. The
spend reports count these requests in `unpriced_requests`.

When a budget applies to such a request, the proxy logs one warning for each
filter chain and model. The warning names the chain, the model, the cluster,
and the reason. It also tells you to add the model to the rate card. A request with no applicable budget logs nothing. The proxy
remembers at most 256 model names for each chain. After that it logs one
summary line and names no more models. The request still adds $0 and still
counts in `unpriced_requests`
(`crates/proxy-filters/src/spend_limit_filter.rs`; tests
`an_unpriced_model_without_a_budget_stays_silent` and
`the_remembered_model_names_are_bounded_and_the_cap_logs_one_summary`).

The proxy does not reject a request because its model has no price. It serves
the request, adds $0 to the budget, and logs the warning above. This is a
choice for availability, not an oversight. The proxy learns the provider that
serves a request only when the router dials it, after the spend filter has
admitted the request. A model that the rate card prices on one provider can be
unpriced on its fallback provider. Rejecting at admission would therefore
refuse requests that are priced correctly. To close the gap, give every model
on every provider of a route a price. Then watch the warning and the
`unpriced_requests` count in the spend reports, and treat a non-zero value as
unbilled traffic.

## Endpoints a budget cannot count

The proxy can count the cost of five endpoints: chat completions,
completions, Responses, Messages and embeddings. It cannot count the cost of
other endpoints, such as images, audio, batches and files. A budget that
applies to a request for one of these endpoints refuses it with
`403` and the response-code detail `endpoint_not_metered`. The request does
not reach the provider. Before this, such a request was served and charged
$0.

- The proxy finds the endpoint from the request method and path, before any
  path rewrite. It compares whole path segments, so
  `POST /v1/messages/batches` is not a Messages request.
- Every path that the proxy does not know is refused in the same way. An
  endpoint that a provider adds later is refused under a budget until the
  proxy can count it.
- Three endpoints cost nothing and always pass: `GET .../models`,
  `GET .../usage` and `POST .../messages/count_tokens`. Their responses carry
  no usage, and the proxy does not log a missing-usage warning for them.
  Nor does it log one for a request that reached no provider, such as the
  synthetic `404` for an unknown model: nothing was spent.
- There is no exception for a request that matches no route. The proxy reads
  the model from the body after it chooses a first route, so a request can
  match no route at first and reach a provider later.
- A request that no budget applies to is not refused and logs nothing.
- A budget applies only when its credential scope matches the request
  (`credential_source`). A refused request adds nothing to any budget.

Each refusal increments
`llmproxy_unmetered_endpoint_refused_total{endpoint, control}`. `control` is
`spend` for a budget and `token_limit` for a token limit (see
[Token rate limiting](../token-rate-limiting/#endpoints-a-token-limit-cannot-count)).
`endpoint` is one of `image_generation`, `image_edit`, `speech`,
`transcription`, `translation` and `unmetered` (every other path). The access
log shows the detail in `%RESPONSE_CODE_DETAILS%` (`response_code_details` in
the `--config` formats). Tests: `crates/proxy/tests/unmetered_endpoint_e2e.rs`.
The design, and the phases that will meter images and audio, are in ADR-0010.

## Cut streams and estimated charges

A response stream that ends early is still charged, once. The client can
disconnect, the provider can reset the connection, or an idle or duration
timeout can cut the stream. The proxy records the request as `partial` and
charges the spend budget and the token window from an estimate:

- Counts that the provider reported before the cut are used as sent.
- A missing input count is estimated from the size of the forwarded request
  body, at 4 bytes per token.
- The output count is the larger of the provider's figure and the text that
  the proxy forwarded, at 4 bytes per token.

The access log shows `llm_usage_completeness="partial"` and
`llm_cost_kind="estimate"`. The counter `llmproxy_usage_partial_total` counts
these requests.

The estimate is not the provider's bill. The provider can generate tokens
after the cut that the proxy never sees, so the charge can be too low. Real
tokens are not exactly 4 bytes each, so the estimate can also be high or low
for the text that the proxy did see.

A client that disconnects before the provider sends response headers is not
charged and gets no access log line. The provider can still bill the input
tokens of that request.

## Key lifecycle and API version

Set a budget through the bearer-gated admin API:

```sh
curl -X PUT http://127.0.0.1:9901/keys/alice-laptop/budget \
  -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"schema_version":2,"budget":{"max_usd":"100.00","period":"monthly"}}'
```

`{"budget":null}` clears the ceiling. `GET /keys/{id}/spend` returns that
key's ledger and `GET /keys` lists policies without exposing secrets. Both
reads require admin authorization. Use `/chains/{stat_prefix}/...` when
multiple auth chains are configured. Key API responses identify
`schema_version: 2`; key mint/budget requests may omit the version for existing
clients, or explicitly send `2`. Other versions are rejected.

`POST /keys` with the same `key_id` and tenant rotates an active key. The new
secret immediately replaces the old one on the receiving replica; there is
**no secret overlap**. Other replicas observe it through the identity-policy
poller, within its configured polling bound when the store is reachable.
Budget, spend, and model grants remain unchanged. In-flight requests already
authenticated retain their identity and finish normally.

Ownership of a logical key ID is immutable. Minting that ID for another tenant
returns `409`. `DELETE /keys/{id}` revokes its secret and retains a permanent
tombstone: reminting the revoked ID returns `409`, even after tenant deletion.
Create a new logical ID for a new key. Retained rows prevent accidental ledger
reset or reassignment.

## Migrating tenant budgets

Stored key/budget rows now write schema version `2`. Readers accept unversioned
legacy rows as version `1`, and reject unknown versions. Existing tenant totals
stay in their original rows; they cannot establish per-key spend without
separate attribution evidence.

A spend filter refuses to start when the store holds any tenant budget, unless
its `typed_config` explicitly includes:

```yaml
legacy_tenant_budget_cutover: START_KEYS_FRESH
```

Without it, the load error names `typed_config.legacy_tenant_budget_cutover`
and reads `legacy tenant budgets require an explicit START_KEYS_FRESH cutover;
retain history and configure key budgets before serving`. A tenant budget that
you set at runtime with `PUT /tenants/{id}/budget` counts too, so that request
returns `409` while the serving spend filter lacks the policy. The error names
`typed_config.legacy_tenant_budget_cutover` and changes nothing, so the problem
shows when you write the budget and not at the next deploy. Clearing a tenant
budget (`{"budget": null}`) is always allowed, setting one on a chain with no spend
filter returns `409` `not_enforced`, and a tenant budget already in the store behaves as before: the
next start fails until you set the policy. Key budgets need no cutover.

This selects a deliberate fresh-key cutover while retaining legacy history.
Stop traffic, retain a backup of the original store, record the cutover time,
set this policy, and provision each key's ceiling through the admin API before
resuming traffic. Existing key budgets and ledgers are preserved. No tenant
total is copied to any key. Historical per-key seeding requires separately
verified attribution and an operator-controlled store correction; this policy
does not infer it.

## Tenant budgets

A tenant budget stays enforced after the cutover. The filter reads the cutover
value only when it starts, and the value does not disable a tenant budget.
`PUT /tenants/{id}/budget` sets or clears a tenant budget with the same body as
a key budget. `GET /tenants/{id}/spend` returns the tenant ledger. The ledger
adds the spend of every key of the tenant, in the tenant budget's own period.

A request gets `429` when its key ceiling or its tenant ceiling is reached.
Clearing one ceiling does not change the spend or the ceiling of the other. A
budget counts only the requests in its credential scope; see
[Budgets](../../authentication/tenant-provider-credentials/#budgets).
`%RESPONSE_CODE_DETAILS%` shows `spend_budget_exceeded` for the `429`.

When any key budget or tenant budget is configured, a request without an
authenticated key identity returns `403`. A request that has a key but no
tenant also returns `403` when any tenant budget is configured.
`%RESPONSE_CODE_DETAILS%` shows `spend_identity_missing` for both.

These tests in `crates/proxy-filters/src/spend_limit_filter.rs` prove the
behavior: `legacy_tenant_budgets_require_explicit_cutover_even_when_zero` (the
start refusal and the cutover),
`tenant_budget_aggregates_keys_with_independent_periods` (the tenant ledger and
the separate ceilings), `tenant_zero_budget_applies_without_any_key_budget` (a
tenant ceiling alone refuses), and
`missing_identity_cannot_bypass_a_tenant_budget` (the `403`). The end-to-end
test `tenant_budget_aggregates_multiple_keys_and_enforces_both_scopes` in
`testing/diffrig/tests/admin_e2e.rs` runs two keys against one tenant ceiling on
the real binary.

## Redis and crash recovery

Each live replica needs a distinct, stable `--service-node` (or bootstrap
`node.id`). Use the same ID after restart. Enable a distinct local file for
each replica and HTTP filter chain:

```yaml
recovery_journal_path: /var/lib/llmproxy/spend-recovery.redb
flush_interval_seconds: 5
reconciliation_bound_seconds: 60
```

The parent directory must exist. Keep the file on durable storage across
process replacement, together with the same replica ID, filter `stat_prefix`,
and shared-store namespace. A changed replica/chain identity, unsupported
journal version, corrupt file, or a path already held by another process is
rejected. The journal contains versioned counter checkpoints, not request
history or plaintext credentials.

The flusher checkpoints pending charges and frozen `(node_id, sequence,
delta)` attempts before sending them to Redis. After restart it replays the
same attempt; Redis deduplicates an already-applied write. New charges accrued
after an ambiguous response remain separate and are delivered on the next
sequence. A successful checkpoint survives SIGKILL, including during a Redis
outage. Request workers update memory; they never query the journal or Redis.
Startup prefetch and the flusher load shared totals. Store and disk I/O do not
hold the request bucket lock. If the startup prefetch cannot read Redis, the
listener still starts and logs one warning. Until the first successful flush,
the rows it could not read count only this replica's spend, so a budget can be
over-admitted for that time. Redis spend keys expire 32 days after their
period ends.

This is asynchronous durability. Charges since the last successful journal
checkpoint remain volatile. A healthy checkpoint loop limits the time window
to roughly one flush interval plus flush duration; disk errors or a stalled
control thread can extend it. Without a journal, the whole unflushed outage
backlog is volatile. There is no claim of zero loss from killing the process
before its checkpoint.

Admin spend reports expose `journal_checkpoint_at`,
`journal_pending_micro_usd`, and `journal_pending_rows`, independently of
Redis's `last_flush_at`, `reconciliation_age_seconds`,
`reconciliation_expired`, and `unreconciled_admissions`. The journal fields are
replica-wide, while `spend_micro_usd` is per key/window. A disk failure prevents
new remote attempts, keeps local enforcement active, and logs a flush warning.
Monitor checkpoint age as well as reconciliation age.

During a Redis outage, admission continues against the last confirmed global
total plus local accrual. A replica still denies once its own view reaches the
ceiling. Authentication boot remains fail-closed when Redis is unavailable;
a running replica keeps its last published identity-policy snapshot. Recovery
composes the retained deltas and refreshes all replicas' totals.

## Past-period buckets

The proxy keeps one spend bucket for each key or tenant and each budget
period. A bucket whose period has ended is settled after one successful
reconciliation with the store since the period ended, if it has no pending
charge. A settled bucket costs the store nothing more: the flusher does not
visit it, and the recovery journal does not grow with it. The proxy keeps a
settled bucket readable in memory until 1 hour after its period ends
(`SETTLED_BUCKET_GRACE_SECS` in `crates/proxy-control/src/spend.rs:828`). Then
it evicts the bucket.

A charge that arrives after eviction creates the bucket again. The new bucket
starts from the last flush sequence of the store, so the store total stays
exact (test
`a_late_charge_after_eviction_reseeds_from_the_store_and_lands_exactly_once`).
A report for an ended period with no bucket in memory reads the store and
creates nothing. The unpriced-request detail of an evicted bucket does not
survive eviction.

## Admission and overspend

Spend is checked at admission and recorded at response completion. There are
**no spend reservations**. Every concurrent request admitted while the visible
total is below the ceiling can finish above it. Remote spend is also invisible
until reconciliation. Overspend includes the sum of those admitted in-flight
costs and unreconciled remote charges. Without separate concurrency and
per-request cost limits, there is no finite strict overspend bound. Sequential
single-replica traffic can overspend by one request's cost.

Usage access logs export `LLM_KEY_ID`, `LLM_TENANT`, `LLM_USER_ID`,
`LLM_REQUESTED_MODEL`, `LLM_SELECTED_MODEL`, and `LLM_RATE_CARD_VERSION`.
Both default log formats include them with selected provider, tokens, cost,
status, and latency. Missing user identity is `-`: the current authentication
pipeline resolves keys and tenants. Key and user IDs are never metrics labels.
Versioned cards price the selected provider's upstream model; legacy spend
tables retain their requested-model lookup for compatibility.

QA-11 proves explicit tenant-to-key cutover, independent key ceilings, and
persisted Redis spend after SIGKILL. QA-12 proves three-process convergence,
socket partition, local enforcement and staleness observability, checkpointed
backlog recovery after SIGKILL, and clean restart without duplicate charges.
Unit tests additionally cover crash replay after an ambiguous remote response.
Run the process drills with a disposable Redis:

```sh
QA_REDIS_ADDR=127.0.0.1:6379 make qa-case CASE='TestQA11|TestQA12'
```
