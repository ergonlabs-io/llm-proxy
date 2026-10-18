---
title: Running in production
summary: What changes when you run more than one replica — which state is
  shared, which stays local, the propagation and staleness bounds for each,
  and what the store does when it cannot be reached. Both configuration
  dialects support a shared store.
last_updated: 2026-10-17
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

Both configuration dialects support `auth.store`. In the `llmproxy` dialect,
configure Redis and give each replica a unique, stable node ID:

```yaml
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  store:
    shared:
      url_file: /run/secrets/redis-url
      namespace: llmproxy-production
```

This fragment belongs inside a complete configuration with providers and routes.
Start it with `llm-proxy --config llmproxy.yaml --service-node replica-a`.
Use the same namespace and HMAC secret across replicas; give each replica its
own node ID. Without that ID, a dialect configuration using a shared store
fails validation. The bootstrap equivalent is shown below.

Token and request windows also use the store selected by `auth.store`.
With `shared`, they reconcile fleet totals about once a second; concurrent
streams use expiring leases. See
[Token rate limiting](../../limits-and-budgets/token-rate-limiting/).

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
| 4 · live gauges | concurrent streams in flight | data plane, constantly | yes, if `store: shared`, as leases | streams over-admitted |

`store: shared` shares tiers 2, 3 and 4. Tier 4 uses leases, not counters;
see [Concurrent streams share leases](#concurrent-streams-share-leases).

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
      recovery_journal_path: /var/lib/llmproxy/spend-recovery.redb
      flush_interval_seconds: 5
      reconciliation_bound_seconds: 60
  # The rate card prices every request that spend_limit charges. With a
  # shared store it seeds the store once; PUT /pricing replaces it.
  - name: llmproxy.usage
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.Usage
      dialect: openai
      pricing_json: '{"price_list":{"effective_from":"2026-01-01T00:00:00Z","entries":[{"provider_type":"openai","model":"gpt-5","tier_mode":"whole_request","tiers":[{"input_nanodollars_per_token":2500,"cached_input_nanodollars_per_token":1250,"cache_write_nanodollars_per_token":3750,"output_nanodollars_per_token":10000}]}]},"providers":{"openai-primary":"openai"}}'
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

A `shared` store requires a node id. Start each replica with
`--service-node <name>`, or set the bootstrap `node.id`. Without one, the
proxy does not start: the load error names `typed_config.store.shared` (or
`auth.store.shared` in the dialect). See
[Node identity](#node-identity-service_node).

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

Every replica needs a distinct identity. Set it with the CLI flag, or with
`node.id` in an Envoy bootstrap:

```sh
llm-proxy --mode serve -c bootstrap.yaml --service-node replica-a
```

`--service-node` overrides the bootstrap `node.id`
(`crates/proxy/src/main.rs`'s `effective_node`, lines 1830–1843); the
`llmproxy` dialect has no config-file field for it. This value is what
`llmproxy.spend_limit` uses as the writer identity in every `FlushToken` it
sends to the store.

**With `auth.store: shared`, the node id is required.** Without one, the
config is a load error at `auth.store.shared` (dialect) or
`typed_config.store.shared` (Envoy mode), and the proxy does not start. The
reason: a per-boot id leaves that boot's dedup state in the shared store
after every restart, and spend rows for periods that never end keep it
permanently.

**With any other store, an unset node id does not stop the proxy.** It synthesizes
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

### A node id with a per-replica store

The proxy does not know how many replicas you run, so it cannot detect N
replicas that each use their own store. When a node id is set (bootstrap
`node.id` or `--service-node`) and `auth.store` is `in_memory` or
`persistent`, each auth chain logs one warning at startup:

```text
llmproxy.auth: a node id is configured, which suggests more than one replica,
but auth.store is not shared: limits and budgets apply per replica, so N
replicas admit up to N times each limit. Set auth.store to shared to enforce
them across the fleet
```

The proxy still starts. To check a fleet from metrics, read
`envoy_llmproxy_control_plane_store_info` on each replica: one series per
chain, with labels `scope`, `store`, and `node_id`. If replicas report
different `node_id` values and `store` is not `shared`, each replica enforces
its own limits.

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

A replica whose poll keeps failing logs warnings and retains its last-known-good
snapshot. Virtual-key authentication refuses requests once that snapshot exceeds
the staleness bound; see [Authentication during a store outage](#authentication-during-a-store-outage).
The 60-second propagation bound above assumes successful store reads.

## Redis connections and the policy load log

A replica opens up to two Redis connections to the shared store. It opens each
one on first use. The policy lane carries the generation poll, the policy load,
and every admin write. The spend lane carries spend reconciliation and the
spend reads at bind time. A slow call on one lane does not delay a call on the
other. Each lane has a 1 second timeout for connect, read, and write. After an
error, the lane drops its own connection and reconnects on the next call. The
other lane keeps its connection (`crates/proxy-filters/src/control_redis.rs:88`;
tests `a_flush_stuck_on_the_spend_lane_does_not_delay_policy_calls`,
`a_load_stuck_on_the_control_lane_does_not_delay_spend_reconciliation`, and
`a_failed_call_resets_only_its_own_lane_and_that_lane_reconnects`).

A Redis that stops answering still stalls both lanes, because both lanes use
it.

Each successful policy load logs one `info` line:
`loaded control-plane state from redis`. The line has these fields:

| Field | Meaning |
|---|---|
| `duration_ms` | Total time of the load, including decoding the rows. |
| `fetch_ms` | Time to read the replies from the wire, including any wait for the policy connection. |
| `tenants`, `keys`, `policies`, `budgets`, `tenant_credentials`, `rate_cards` | Row counts for each kind. |
| `payload_bytes` | Combined length of the field names, set members, and values read. |

The line carries counts and lengths only. It never carries row content (test
`a_load_logs_its_duration_and_size_and_never_row_content`). A load reads the
whole policy state, so `duration_ms` grows with the state. Use this line to
size a large deployment.

## Authentication during a store outage

Virtual-key authentication keeps serving the last policy snapshot only until
its staleness bound expires. It then returns `503` with `auth_policy_stale`
until the store can be read again. The dialect's `auth.max_policy_staleness`
defaults to `4m`; bootstrap mode uses `max_policy_staleness_seconds`, defaulting
to five policy-poll intervals. Monitor
`envoy_llmproxy_policy_snapshot_age_seconds`. This bounds how long a revoked
key can keep authenticating during a store outage.

## Store outage: spend keeps enforcing last-known totals

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
volatile. See [Spend policies and recovery](../../limits-and-budgets/spend-policies/)
for configuration, migration, key lifecycle, and concurrent admission limits.

## The shared store needs persistence

The shared Redis is the only copy of the minted keys, the tenants, and their
policies. Configure Redis persistence (AOF, RDB, or both) on it. A Redis that
restarts without persistence, or that is flushed, comes back empty. At their
next poll, all replicas load the empty state and adopt it. From then on,
every virtual key that the store held gets 401. This revokes every key on all
replicas, and it stays that way until you restore the data or mint the keys
again. Keys in the bootstrap `virtual_keys` list are not stored in Redis, so
they continue to authenticate.

The proxy cannot tell a lost store from an operator who removed every tenant
and key, so it does not refuse the empty state. Keeping the old copy would
continue to accept keys that the store no longer has. Thus the replica fails
closed and makes the transition loud.
When a load finds no tenants and no keys after the previous load found some,
the replica logs one `error` line:
`control-plane store is now EMPTY after holding tenants or keys`. The line has
these fields:

| Field | Meaning |
|---|---|
| `tenants_before`, `keys_before` | Row counts of the previous load. |
| `tenants_after`, `keys_after` | Row counts of this load (both 0). |
| `generation_before`, `generation_after` | The policy generation stamps. A lost Redis reads back as `Some(0)`, lower than before. An operator removal makes the stamp go up. |

The replica also increments `envoy_llmproxy_policy_store_emptied_total` (see
[Metrics and stats](../../observability/metrics-and-stats/)). Each replica
logs and counts once per transition, not once per poll. Alert on any increase
of this counter.

To recover, restore the Redis data from a backup or AOF file. The replicas
pick up the restored state at their next poll. If you have no copy, mint the
keys again and give them to their users.

## Concurrent streams share leases

With `store: shared`, a concurrent-stream ceiling applies to the fleet. This
includes `concurrent_sessions` in the `limits:` block and `concurrent_streams`
in tenant and key limits (ADR-0006 amendment E).

- Each replica admits a stream against its own in-flight count plus the
  count that the other replicas last published. Admission never waits for
  Redis.
- Once a second, each replica writes its in-flight count per limit to Redis
  as a lease row with a 5-second TTL, and reads the fleet total for every
  limit, including limits it has not served yet.
- A replica that stops (a crash or `SIGKILL`) does not release its slots.
  Its lease rows expire 5 seconds after its last write, and the other
  replicas then admit again.
- Between two writes, replicas do not see each other's new streams. The
  fleet can admit up to about one second of stream arrivals on the other
  replicas over a ceiling.
- If Redis cannot be reached, each replica keeps enforcing against the last
  fleet counts it read, plus its own streams (fail open). It logs one
  `stream-lease publish failed` warning per filter chain per minute, and the
  gauge `envoy_llmproxy_counter_reconciliation_age_seconds` with
  `seam="stream_lease"` grows.

Set a distinct `--service-node` on each replica. The lease rows of a replica
are keyed by its node ID.

## What stays local, even with a shared store

- **Usage history is export-only.** The shared store holds current-window
  spend counters and nothing else — never per-request history. That lives in
  access logs and the usage filter, and stays there by owner decision:
  `ControlPlaneStore`'s own trait doc states "counters only" so this is not
  merely a backlog note (`crates/proxy-filters/src/control.rs`, lines
  195–211). If you need historical spend, export it from access logs; the
  admin `/spend` endpoint only ever answers "right now, this window."
- **Token and request limits count locally unless `auth.store` is shared.**
  With a shared store, both configured `limits:` and tenant/key rate limits
  reconcile through Redis. Admission uses last-known totals plus local counts,
  so the fleet can exceed a ceiling between reconciles. See
  [Token rate limiting](../../limits-and-budgets/token-rate-limiting/).
- **The rate card is shared only through `auth.store: shared`.** With an `auth`
  store, the rate card is stored per chain and `PUT /pricing` writes it there.
  A `persistent` store is one replica's file, so only `shared` reaches other
  replicas. Every replica that shares the store installs it on its next policy poll, which is 48 to 60
  seconds at the default `poll_interval_seconds`, the same bound as a key
  revocation. The configured `pricing` only seeds an empty store. A restart or a
  `SIGHUP` reload never replaces a stored rate card, and the stored rate card
  wins over a different `pricing` at start. Only a `persistent` or `shared`
  store keeps the rate card across a restart; the default `in_memory` store does
  not, and `PUT /pricing` says `"persisted": false` for it.
  To check that every replica prices with the same card, compare the
  `envoy_llmproxy_usage_rate_card_active` series on `/stats/prometheus`. Its
  `scope` label is the chain and its `version` label is the card version that
  `PUT /pricing` returns. The active card has the value 1. A version that this
  process retired has the value 0. A chain with no card has no series at 1.

  Without an `auth` section, the rate card stays in the memory of each process.
  `PUT /pricing` then changes only the replica that receives it, a restart loads
  the configured `pricing`, and a `SIGHUP` reload installs a changed `pricing`.
  To change the rate card of a deployment without a store, change `pricing` in
  every replica's configuration and reload, or send the same `PUT /pricing`
  request to every replica.

  If another replica writes a card to the same store between your `PUT /pricing`
  write and the read-back, the other card stays active on the replica that
  received your `PUT`. The `note` in the response then says `written, but a
  concurrent publish to the same store superseded it; this replica now serves
  the store's card`. The delivery from the store decides the active card
  (`crates/proxy-filters/src/usage_filter.rs:473-484`; test
  `a_concurrent_publish_from_another_replica_wins_on_the_publishing_replica`
  in `crates/proxy-filters/src/usage_filter/rate_card_tests.rs`).

  Replicas with different rate cards price the same request differently. To find
  them, compare `rate_card_version` in `GET /pricing` on each replica, or the
  `%LLM_RATE_CARD_VERSION%` values in the access logs. The version covers the
  prices and the cluster-to-provider map.

  The rate card is the only price source for `llmproxy.spend_limit`. A request
  that the rate card does not price, under a dollar budget, adds $0 to the
  budget and logs one warning per chain and model. The fields and the limits of
  `PUT /pricing` are in
  [`pricing`](../../configuration/configuration-file/#pricing-pricing).

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
