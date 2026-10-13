---
title: Spend policies and recovery
description: Key and tenant ceilings, migration, shared Redis accounting, and crash recovery.
---

Spend enforcement uses two kinds of ceiling, and either one can refuse a
request. A key budget counts the spend of one stable `key_id`. A tenant budget
counts the spend of every key of one tenant. Each ceiling uses its own UTC
budget period and counts spend across every model and selected provider. There
is no per-user budget. A key budget never grants model access.

Missing budget means unlimited; an explicit zero denies the first request.
Charges use integer micro-dollars and the rate card for the provider actually
dialled, including after fallback. A request that neither the rate card nor the
`pricing` list of `llmproxy.spend_limit` prices adds $0 to every budget. The
proxy does not log a warning for it. The spend reports count these requests in
`unpriced_requests`.

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
you set at runtime with `PUT /tenants/{id}/budget` counts too. The next start
fails until you set the policy.

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
[Budgets](../authentication/tenant-provider-credentials/#budgets).
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
hold the request bucket lock.

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
