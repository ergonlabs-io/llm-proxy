---
title: Running in production
summary: What changes when you run more than one replica — which state is
  shared, which stays local, the propagation and staleness bounds for each,
  and what the store does when it cannot be reached. Configuring a shared
  store is Envoy-mode only today; the `llmproxy` dialect has no field for it.
last_updated: 2026-09-07
related:
  - ../authentication/virtual-keys/
  - ../limits-and-budgets/token-rate-limiting/
  - ../operations/config-reload/
---

# Running in production

A single `llm-proxy` replica needs no extra configuration. Every piece of
state — minted keys, revocations, tenant policy, accrued spend — lives in
that one process's memory (or its own `redb` file, if you configured
`persistent`). Nothing here applies until you run **more than one** replica
behind a load balancer and want them to agree with each other.

This page covers what agreeing actually means: which state is shared, on
what schedule, and what an operator should expect while it is catching up or
unreachable. It is normative for `llmproxy.auth`'s `store: shared` and
`llmproxy.spend_limit`, the two filters this applies to
(`internal-docs/adr/0006-shared-state-tiers.md`, ADR-0006, is the design
record this page follows).

**This is reachable only from Envoy-mode `typed_config` today.** The
`llmproxy` dialect schema (`schema/llmproxy-v0.schema.json`) has no `store`,
`shared`, or `service_node` field anywhere in it — a dialect config always
runs single-replica identity and budget state, however many processes you
start. Do not confuse this with the dialect's `limits:` block
(`tokens_per_minute`), which is a separate mechanism (`BudgetStore`, not
`ControlPlaneStore`) with no shared implementation at all; see
[Token rate limiting](../limits-and-budgets/token-rate-limiting/). Everything
below is about `llmproxy.auth` and `llmproxy.spend_limit`, configured through
a hand-written bootstrap.

## Four kinds of state, four different rules

ADR-0006 groups everything a replica holds into four tiers, by who writes it
and what going stale costs — not by subject, because a key and its
revocation flag have incompatible failure models even though they live on
the same record.

| Tier | What | Written by | Shared across replicas? | Stale means |
|---|---|---|---|---|
| 1 · configuration | listeners, routes, clusters, filters | operator / xDS | already solved, unrelated to this page | wrong routing |
| 2 · identity & policy | tenants, virtual keys, revocations, budget ceilings | admin API | yes, if `store: shared` | a revoked key still authenticates |
| 3 · accrued counters | spend in micro-dollars, per stable key per period | data plane, constantly | yes, if `store: shared` | budget over-admitted |
| 4 · live gauges | concurrency / in-flight requests | data plane, constantly | **no — see below** | unscoped, not designed yet |

Tiers 2 and 3 are what `store: shared` gives you. Tier 4 is not part of this
feature at all; see [What stays local](#what-stays-local-even-with-a-shared-store).

## Configuring a shared store

`llmproxy.auth`'s `typed_config.store` is a `oneof`: `in_memory` (the
default), `persistent` (one `redb` file, survives a restart, but takes an
exclusive file lock — a second process opening the same path fails outright,
which is why it cannot be the answer for N replicas), or `shared`.

```yaml
http_filters:
  - name: llmproxy.auth
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
      hmac_secret:
        inline_string: ${LLMPROXY_AUTH_SECRET}
      virtual_keys:
        - key_id: alice-laptop
          tenant: acme
          digest_hex: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a
          revoked: false
      shared:
        url:
          filename: /etc/llmproxy/redis-url.txt
        namespace: prod
      poll_interval_seconds: 48
  - name: llmproxy.spend_limit
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.SpendLimit
      pricing:
        - cluster: openai-primary
          models:
            - model: gpt-5
              input_per_million: "2.50"
              output_per_million: "10.00"
              cached_per_million: "1.25"
              cache_creation_per_million: "3.75"
      recovery_journal_path: /var/lib/llmproxy/spend-recovery.redb
      flush_interval_seconds: 5
      reconciliation_bound_seconds: 60
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

`llmproxy.spend_limit` has no `store` field of its own. It resolves the
`ControlPlane` singleton `llmproxy.auth` already built and flushes into
whatever store that filter was given
(`crates/proxy-filters/src/spend_limit_filter.rs:370–411`) — this is also why
`llmproxy.auth` must come first in the chain: with no `llmproxy.auth` earlier
in the same `http_filters` list, config load fails with

```text
llmproxy.spend_limit requires llmproxy.auth earlier in the same filter
chain -- its ControlPlane singleton is where this filter's tenant and
budgets live
```

(`crates/proxy-filters/src/spend_limit_filter.rs:372–378`). One `shared`
block on `llmproxy.auth` covers both filters.

### The Redis URL: `filename` or `inline_string` only

`store.shared.url` is a `DataSource`, and — like `hmac_secret` above it —
only two of the specifiers Envoy's `DataSource` message can carry are
accepted: `filename` and `inline_string`. Setting `environment_variable` (or
any other specifier) is rejected as a load error naming
`typed_config.store.shared.url`, not silently ignored
(`crates/proxy-filters/src/auth_filter.rs`'s `read_data_source_bytes`,
lines 95–129, and `parse_store`'s `shared` branch, lines 262–300; the
rejection is proven by
`parse_store_rejects_an_unsupported_data_source_specifier_under_shared_url`).
This is not an oversight specific to Redis: the same two-specifier surface
is enforced everywhere `DataSource` appears in this project, because a Redis
URL can embed a password
(`redis://:password@host:6379/0`) and this is the one restriction that keeps
that password out of every place credentials are not meant to travel — the
same reasoning `hmac_secret` already documents. A `filename` value's trailing
newline is stripped automatically, the same treatment `hmac_secret_file`
gets, so `echo "redis://..." > url.txt` cannot silently corrupt the URL.

`namespace` is optional and defaults to `llmproxy`
(`crates/proxy-filters/src/control_redis.rs`'s `DEFAULT_NAMESPACE`, line 63).
Set it explicitly when more than one deployment shares one Redis instance, so
their keys cannot collide.

## Node identity: `service_node`

Every replica needs a distinct identity, and today the only place to set one
is the CLI flag, at process start:

```sh
llm-proxy --mode serve --config bootstrap.yaml --service-node replica-a
```

`--service-node` overrides the bootstrap `node.id`
(`crates/proxy/src/main.rs`'s `effective_node`, lines 1177–1190); the
`llmproxy` dialect has no config-file field for it. This value is what
`llmproxy.spend_limit` uses as the writer identity in every `FlushToken` it
sends to the store.

**If you never set it, the proxy does not refuse to start.** It synthesizes
`unconfigured-<pid>-<nanos>` (process id plus a nanosecond timestamp) and
logs a warning once, at filter creation:

```text
llmproxy.spend_limit: no service_node is configured, so this replica has no stable
identity to write spend under; using a synthesised one. Spend is still counted
correctly, but set service_node in the bootstrap to keep a restarted replica's
identity stable
```

(`crates/proxy-filters/src/spend_limit_filter.rs`'s `resolve_node_id`, lines
837–863.) Two replicas that both fall through to this path still get
distinct ids — the pid/timestamp pair does not collide — so this does not
lose spend by itself. What it costs you: a **restarted** replica no longer
recognizes its own pre-restart sequence number, and a fresh synthesized id
appears in the store's per-writer dedup state every time the process
restarts. In production, always set `--service-node` to something stable per
replica (a pod name, a hostname) — do not rely on the synthesized fallback,
which exists so a metering detail never blocks the process from starting
(AGENTS.md "Fail-open controls"), not as a supported production identity.

With `recovery_journal_path` configured, a stable node ID is required at load;
the synthesized fallback is rejected for recoverable replicas.

## Spend counters converge — they do not update instantly

With a shared store, `add_spend` is additive: each flush sends a delta and a
`(node_id, monotonic_seq)` token, and the store returns the new
**authoritative total**, which the accumulator adopts as its new base
(`internal-docs/adr/0006-shared-state-tiers.md` §2; the convergence itself is
proven by
`two_accumulators_sharing_one_store_converge_on_the_true_total` in
`crates/proxy-filters/src/spend.rs`). That is what makes two replicas' spend
add up instead of last-writer-wins clobbering — but it means the number a
replica enforces against is never more current than its last successful
flush.

`flush_interval_seconds` defaults to **5 seconds**
(`crates/proxy-filters/src/spend_limit_filter.rs`'s `parse_flush_interval`,
line 273). Between flushes, a replica's own unflushed delta is invisible to
every other replica's admission check. In the steady state this bounds
over-admission at roughly:

```
flush_interval x replica_count x peak spend rate
```

This estimates completed-charge propagation only. Concurrent in-flight costs
are additional; without reservations, concurrency limits, and request-cost
limits there is no finite strict overspend bound.

(ADR-0006 §4.) At the 5-second default with 4 replicas each admitting up to
$10/second at peak, that is on the order of $200 of over-admission before
every replica's view catches up — tune `flush_interval_seconds` down if that
number is uncomfortable for your budgets, at the cost of more store writes.

## Policy and key revocation: propagation is bounded, not instant

`llmproxy.auth` polls a monotonic generation counter in the store —
bumped by every tier-2 admin write, never by a spend write — and only does
the full re-read of keys and policy when that counter has moved
(`crates/proxy-filters/src/control.rs`, `ControlPlane::poll_once`, and the
generation-stamp reads at lines 217–219). `poll_interval_seconds` defaults to
**48 seconds**, and the actual wait is jittered by up to a quarter of the
interval so that every replica does not wake up and re-read at the same
instant (`next_poll_delay`, `crates/proxy-filters/src/control.rs:2052–2070`).

That makes the worst case **48 + 12 = 60 seconds**
(`crates/proxy-api/vendor/llmproxy/filters/v0/auth.proto`'s
`poll_interval_seconds` doc: "a revoked key stops working within
`poll_interval_seconds` x 1.25, which is 60 seconds at the default"). Tell an
operator exactly that: **a key revoked through the admin API may still
authenticate on another replica for up to 60 seconds at the default
interval.** Revocation does not tear down a request already in flight either
way — it is a request-start decision, same as Envoy's own auth model.

A replica whose poll keeps failing does not silently keep going: it keeps
serving its last-known-good snapshot and logs a warning naming the snapshot
age and the bound once it is exceeded (`control.rs`'s `run_policy_poller`,
lines 2013–2029), suppressed to at most once per ten intervals so the
warning itself does not become the incident.

## Store outage: fails open, loudly

If a replica cannot reconcile with the shared store for longer than
`reconciliation_bound_seconds` (default **60 seconds**, measured from
construction if it has never once succeeded —
`crates/proxy-api/vendor/llmproxy/filters/v0/spend.proto` lines 51–71), it
does not stop serving and it does not stop enforcing. It keeps admitting
against `last confirmed total + its own accrual since`, so a replica that
has burned its own share of the budget still returns 429 — this is
deliberately better than Envoy's reference global rate-limit filter, which
holds no local state and admits everything for the duration of an RLS
outage (ADR-0006 §5).

**Only `ALLOW` is implemented.** `on_reconciliation_expired` names `DENY`
and `DEGRADE` in the proto so that tightening this later is a config value,
not a redesign, but selecting either today is a load error, not a silent
downgrade:

```text
DENY is declared in the config surface but not implemented in this build --
only ALLOW is. Refusing rather than quietly serving ALLOW, because an
operator who asked for the strict behaviour would otherwise get the
permissive one silently
```

(`crates/proxy-filters/src/spend_limit_filter.rs`'s `parse_reconciliation`,
lines 310–327; `DEGRADE` gets the equivalent message.) Do not configure
either value expecting it to take effect — configure `ALLOW` (or leave the
field unset) and treat the observability below as your actual signal.

While a replica is stale, over-admission grows to roughly:

```
(replica_count - 1) x per-replica spend during the outage
```

(ADR-0006 §5, and `crates/proxy-filters/src/spend.rs`'s `SpendReport`
doc, lines 1077–1080.) Unlike the steady-state bound above, this one is not
capped by a flush interval — it grows for as long as the outage lasts,
because `ALLOW` is the only wired behavior. Watch it end-to-end: `GET
/keys/{id}/spend` (or `GET /chains/{stat_prefix}/keys/{id}/spend`)
reports `reconciliation_age_seconds`, `reconciliation_expired`, and a
cumulative `unreconciled_admissions` count for exactly this reason
(`crates/proxy-admin/src/server.rs`, lines 1291–1293). Alert on
`reconciliation_expired: true`, not on the raw age, since the bound is a
config value you already chose.

The ledger self-heals once the store comes back: every replica's
accumulated delta flushes on recovery and the store's additive write
composes the backlog, so the total becomes exactly correct — nothing is
lost, only delayed (ADR-0006 §5). A configured local recovery journal preserves checkpointed outage
backlog across SIGKILL. Charges since the last successful local checkpoint
remain volatile; without a journal, the entire unflushed outage backlog is
volatile. See [Spend policies and recovery](/limits-and-budgets/spend-policies/)
for configuration, migration, key lifecycle, and concurrent admission limits.

## What stays local, even with a shared store

- **Concurrency / in-flight request limits (tier 4) are not part of this
  feature, and ADR-0006 rules that they will stay per-replica even once
  built.** They need lease/TTL semantics and a reaper — a crashed replica's
  in-flight count has to be actively released, unlike a counter that simply
  expires with its window — and ADR-0006 explicitly declines to extend the
  tier-3 store to cover it (`internal-docs/adr/0006-shared-state-tiers.md`,
  "Not decided here"). Today `concurrent_sessions` in the `limits:` dialect
  block is not enforced at all yet, by any replica count — it is recorded
  and produces a load-time warning (`schema/llmproxy-v0.schema.json`, the
  `concurrent_sessions` field description). Enforcement is not built yet. When
  it is, do not expect the shared store above to cover it.
- **Usage history is export-only.** The shared store holds current-window
  spend counters and nothing else — never per-request history. That lives in
  access logs and the usage filter, and stays there by owner decision:
  `ControlPlaneStore`'s own trait doc states "counters only" so this is not
  merely a backlog note (`crates/proxy-filters/src/control.rs`, lines
  195–211). If you need historical spend, export it from access logs; the
  admin `/spend` endpoint only ever answers "right now, this window."
- **Token rate limiting (`limits:`, `tokens_per_minute`) is a separate
  subsystem and has no shared implementation at all.** It runs on
  `BudgetStore`, not `ControlPlaneStore`, and only an in-process
  implementation exists — this is unaffected by everything above. See
  [Token rate limiting](../limits-and-budgets/token-rate-limiting/).

## Verifying a Redis-backed store

Run the process acceptance drills against disposable Redis:

```sh
QA_REDIS_ADDR=127.0.0.1:6379 make qa-case CASE='TestQA11|TestQA12'
```

QA-11 covers legacy tenant-history retention and key restart enforcement.
QA-12 covers three real processes, a socket partition, stale admissions, local
enforcement, checkpointed backlog recovery after SIGKILL, and exact replay.
Both explicitly skip when `QA_REDIS_ADDR` is absent; a plain `make tq` does not
run them. The lower-level Redis tests also require a real Redis and an explicit
ignored-test run. See the Makefile's `t1` target and
`crates/proxy-filters/src/control_redis.rs` for their environment variable.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Load error naming `typed_config.store.shared.url`: `only \`filename\` and \`inline_string\` data source specifiers are supported` | `store.shared.url` was set with `environment_variable` (or another unsupported `DataSource` specifier) | Put the Redis URL in a file and use `filename`, or use `inline_string` directly |
| Load error naming `typed_config.on_reconciliation_expired` | `on_reconciliation_expired` was set to `DENY` or `DEGRADE` | Remove the field, or set it to `ALLOW` explicitly — neither alternative is implemented |
| Load error: `llmproxy.spend_limit requires llmproxy.auth earlier in the same filter chain` | `llmproxy.spend_limit` appears before, or without, `llmproxy.auth` in `http_filters` | Place `llmproxy.auth` earlier in the same chain |
| A revoked key still authenticates on some replicas | Expected for up to `poll_interval_seconds x 1.25` (60s at the default) — see [Policy and key revocation](#policy-and-key-revocation-propagation-is-bounded-not-instant) | Wait out the bound, or lower `poll_interval_seconds` (raises store read load) |
| `GET /keys/{id}/spend` reports `reconciliation_expired: true` | This replica has not reconciled with the shared store within `reconciliation_bound_seconds` — a store outage or partition | Check connectivity to the shared store; enforcement continues on last-known totals in the meantime |
| A budget trips later than expected, or several replicas each admit up to the full ceiling | Every replica was given the same `--service-node` value (or all left it unset and happened to share a synthesized id, which the pid/timestamp scheme makes very unlikely) | Give every replica a distinct, stable `--service-node` |
