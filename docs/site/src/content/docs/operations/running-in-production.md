---
title: Share state across replicas
description: "Run several replicas that share keys, policy, counters, and spend through one store."
summary: What changes when you run more than one replica. Which state is
  shared, which stays local, the propagation and staleness bounds for each,
  and what the store does when it cannot be reached.
lastUpdated: 2026-10-21
related:
  - authentication/virtual-keys
  - limits-and-budgets/token-rate-limiting
  - limits-and-budgets/spend-policies
  - operations/deployment
  - operations/config-reload
---

Use a shared store when you run more than one replica behind a load balancer
and the replicas must agree on keys, revocations, tenant policy, and spend. To
enable it, set `auth.store` to `shared` with a Redis URL, and give each replica
a unique, stable node ID. A single replica needs no extra configuration. Its
state lives in its own memory, or in its own `redb` file if you set
`persistent`.

This page covers which state is shared, on what schedule, and what to expect
while the replicas catch up or the store is unreachable.

## At a glance

- **Default when unset:** `auth.store` is `in_memory`. Each replica keeps its
  own keys, policy, counters, and spend.
- **Failure mode:** keys and policy fail closed after `auth.max_policy_staleness`
  (default `4m`). Spend and stream limits keep enforcing the last known totals
  (fail open).
- **Requires:** a Redis URL and a distinct `--service-node` on each replica.

## Configure a shared store

In the config file, set Redis and give each replica a unique, stable node ID:

```yaml
version: 0
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  store:
    shared:
      url_file: /run/secrets/redis-url
      namespace: llmproxy-production
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
```

Start each replica with its own node ID:

```bash
llm-proxy --config llmproxy.yaml --service-node replica-a
```

Use the same namespace and HMAC secret on every replica. Give each replica
its own node ID. Without that ID, a config with a shared store fails
validation.

Token and request windows also use the store selected by `auth.store`.
With `shared`, they reconcile fleet totals about once a second. Concurrent
streams use expiring leases. See
[Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/).

### Fields of `auth.store.shared`

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | string | none | The Redis URL, for example `redis://:${REDIS_PASSWORD}@host:6379/0`. Set this or `url_file`. |
| `url_file` | string | none | File that holds the Redis URL. The proxy trims trailing whitespace and reads the file once, at start. |
| `namespace` | string | `llmproxy` | Prefix for every Redis key. Set it when more than one deployment shares one Redis. |

A Redis URL can embed a password. Use `${ENV_VAR}` interpolation or
`url_file`. Do not write the password in the config file.

The other two stores are `in_memory` (the default) and `persistent` with a
`path`. A `persistent` store uses one `redb` file. It survives a restart, but
it takes an exclusive file lock. A second process that opens the same path
fails. So `persistent` cannot serve N replicas.

The spend limit uses the store that `auth` selects. One `shared` block
covers the keys, the policy, the spend counters, and the rate limits.

## Four kinds of state, four different rules

A replica holds four tiers of state. The tiers group state by who writes it
and what stale data costs. They do not group it by subject, because a key and
its revocation flag have different failure models, although they live on the
same record.

| Tier | What | Written by | Shared across replicas? | Stale means |
|---|---|---|---|---|
| 1 · configuration | listeners, routes, providers | operator (config file) | no, each replica reads its own file | wrong routing |
| 2 · identity and policy | tenants, virtual keys, revocations, budget ceilings | admin API | yes, if `store: shared` | a revoked key still authenticates |
| 3 · accrued counters | spend in micro-dollars, per stable key per period | data plane, constantly | yes, if `store: shared` | budget over-admitted |
| 4 · live gauges | concurrent streams in flight | data plane, constantly | yes, if `store: shared`, as leases | streams over-admitted |

`store: shared` shares tiers 2, 3 and 4. Tier 4 uses leases, not counters;
see [Concurrent streams share leases](#concurrent-streams-share-leases).

## Node identity: `service_node`

Every replica needs a distinct identity. Set it with the CLI flag:

```bash
llm-proxy --config llmproxy.yaml --service-node replica-a
```

The config file has no field for the node ID. The spend limit uses this
value as the writer identity in every flush it sends to the store.

**With `auth.store: shared`, the node ID is required.** Without one, the
config is a load error at `auth.store.shared`, and the proxy does not start.
The reason: a per-boot ID leaves that boot's dedup state in the shared store
after every restart, and spend rows for periods that never end keep it
permanently.

**With any other store, an unset node ID does not stop the proxy.** It
synthesizes `unconfigured-<pid>-<nanos>` (process ID plus a nanosecond
timestamp) and logs a warning once, when it builds the spend limit:

```text
llmproxy.spend_limit: no service_node is configured, so this replica has no stable
identity to write spend under; using a synthesised one. Spend is still counted
correctly, but pass --service-node (or set the bootstrap node.id) to a name
unique to this replica and stable across its restarts
```

The text says "or set the bootstrap node.id". The config file has no such
field. Use `--service-node`.

Two replicas that both use the synthesized ID still get distinct IDs, because
the pair of process ID and timestamp does not collide. So the fallback does
not lose spend by itself. It has a cost: a restarted replica no longer
recognizes its own pre-restart sequence number, and a new synthesized ID
appears in the per-writer dedup state of the store at every restart. In
production, set `--service-node` to a stable value for each replica, such as
a pod name or a host name.

### A node ID with a per-replica store

The proxy does not know how many replicas you run, so it cannot detect N
replicas that each use their own store. When a node ID is set and
`auth.store` is `in_memory` or `persistent`, the proxy logs one warning at
start:

```text
llmproxy.auth: a node id is configured, which suggests more than one replica, but auth.store is not shared: limits and budgets apply per replica, so N replicas admit up to N times each limit, and a rate card published with PUT /pricing reaches only the replica that receives it. Set auth.store to shared to enforce them and share the rate card across the fleet
```

The proxy still starts. To check a fleet from metrics, read
`envoy_llmproxy_control_plane_store_info` on each replica: one series per
auth scope, with labels `scope`, `store`, and `node_id`. If replicas report
different `node_id` values and `store` is not `shared`, each replica enforces
its own limits.

## Spend counters converge, they do not update instantly

With a shared store, spend writes are additive. Each flush sends a delta and a
`(node_id, monotonic_seq)` token. The store returns the new authoritative
total, and the replica adopts it as its new base. So the spend of two
replicas adds up, and one replica does not overwrite the other. The number that
a replica enforces against is never more current than its last successful
flush.

The flush interval is 5 seconds. The config file has no field to change it.
Between flushes, the unflushed delta of a replica is invisible to every other
replica's admission check. In the steady state this bounds over-admission at
roughly:

```text
flush_interval x replica_count x peak spend rate
```

This estimates completed-charge propagation only. Concurrent in-flight costs
are additional. Without reservations, concurrency limits, and request-cost
limits, there is no finite strict overspend bound.

At the 5-second interval with 4 replicas that each admit up to $10/second at
peak, that is on the order of $200 of over-admission before every replica's
view catches up.

## Policy and key revocation: propagation is bounded, not instant

The auth store keeps a generation counter. Every tier-2 admin write bumps it.
A spend write never bumps it. Each replica polls the counter, and it re-reads
keys and policy only when the counter has moved. The poll interval is 48
seconds. The config file has no field to change it. The actual wait is
jittered by up to a quarter of the interval, so that the replicas do not wake
up and re-read at the same instant.

That makes the worst case 48 + 12 = 60 seconds. **A key revoked through the
admin API may still authenticate on another replica for up to 60 seconds.**
Revocation does not stop a request that is already in flight. It is a
decision at request start.

A replica whose poll keeps failing logs warnings and retains its
last-known-good snapshot. Virtual-key authentication refuses requests once
that snapshot exceeds the staleness bound; see
[Authentication during a store outage](#authentication-during-a-store-outage).
The 60-second propagation bound assumes successful store reads.

## Redis connections and the policy load log

A replica opens up to five Redis connections to the shared store, one for each
lane. It opens each one on first use. The policy lane carries the generation
poll, the policy load, and every admin write. The spend lane carries spend
reconciliation and the spend reads at bind time. The windows lane carries
rate-window reconciliation and usage reads. The lease lane carries
concurrent-stream leases, and the objects lane carries file and batch
ownership. A slow call on one lane does not delay a call on another. Each lane has a 1 second timeout for connect, read, and write. After an
error, the lane drops its own connection and reconnects on the next call. The
other lanes keep their connections.

A Redis that stops answering still stalls all lanes, because all lanes use it.

Each successful policy load logs one `info` line:
`loaded control-plane state from redis`. The line has these fields:

| Field | Meaning |
|---|---|
| `duration_ms` | Total time of the load, including decoding the rows. |
| `fetch_ms` | Time to read the replies from the wire, including any wait for the policy connection. |
| `tenants`, `keys`, `policies`, `budgets`, `tenant_credentials`, `rate_cards` | Row counts for each kind. |
| `payload_bytes` | Combined length of the field names, set members, and values read. |

The line carries counts and lengths only. It never carries row content. A load
reads the whole policy state, so `duration_ms` grows with the state. Use this
line to size a large deployment.

## Authentication during a store outage

Virtual-key authentication keeps serving the last policy snapshot only until
its staleness bound expires. It then returns `503` with `auth_policy_stale`
until the store can be read again. The default of `auth.max_policy_staleness`
is `4m`. Monitor `envoy_llmproxy_policy_snapshot_age_seconds`. The bound
limits how long a revoked key can keep authenticating during a store outage.

## Store outage: spend keeps enforcing last-known totals

If a replica cannot reconcile with the shared store for longer than 60
seconds (measured from construction if it has never succeeded), it does not
stop serving and it does not stop enforcing. The config file has no field to
change the 60 seconds. The replica keeps admitting against the last confirmed
total plus its own accrual since. A replica that has used its own share of
the budget still returns 429.

While a replica is stale, over-admission grows to roughly:

```text
(replica_count - 1) x per-replica spend during the outage
```

Unlike the steady-state bound above, this bound has no cap from a flush
interval. It grows for as long as the outage lasts. To watch it, read
`GET /keys/{id}/spend`. It reports `reconciliation_age_seconds`,
`reconciliation_expired`, and a cumulative `unreconciled_admissions` count.
Alert on `reconciliation_expired: true`, not on the raw age.

The ledger heals once the store comes back. Every replica flushes its
accumulated delta on recovery, and the additive write of the store composes
the backlog, so the total becomes correct. The outage delays spend records.
It does not lose them, unless a replica stops before it flushes. The config
file has no recovery journal. The backlog that a replica has not flushed is
volatile. See
[Spend policies and recovery](/docs/llm-proxy/limits-and-budgets/spend-policies/)
for key lifecycle and concurrent admission limits.

### Object ownership fails closed

The object ownership check does not follow the rule above. If the store
cannot answer an owner lookup, the request gets `503` and the proxy logs a
warning with repeats suppressed. Owners are rows in `auth.store`. With
`in_memory` they are lost on restart, and the proxy then refuses those objects
as unknown. Use `persistent` or `shared`, or assign the objects
again with `PUT /tenants/{id}/objects/{object_id}`.

## The shared store needs persistence

The shared Redis is the only copy of the minted keys, the tenants, and their
policies. Configure Redis persistence (AOF, RDB, or both) on it. A Redis that
restarts without persistence, or that is flushed, comes back empty. At their
next poll, all replicas load the empty state and adopt it. From then on,
every virtual key that the store held gets 401. This revokes every key on all
replicas, and it stays that way until you restore the data or mint the keys
again. Keys in the `auth.keys` list are not stored in Redis, so they continue
to authenticate.

The proxy cannot tell a lost store from an operator who removed every tenant
and key, so it does not refuse the empty state. Keeping the old copy would
continue to accept keys that the store no longer has. Thus the replica fails
closed and makes the transition loud.
When a load finds no keys, or no tenants, after the previous load found some,
the replica logs one `error` line:
`control-plane store is now EMPTY of keys or tenants it held`. The line has
these fields:

| Field | Meaning |
|---|---|
| `tenants_before`, `keys_before` | Row counts of the previous load. |
| `tenants_after`, `keys_after` | Row counts of this load (at least one is 0). |
| `generation_before`, `generation_after` | The policy generation stamps. A lost Redis reads back as `Some(0)`, lower than before. An operator removal makes the stamp go up. |

The replica also increments `envoy_llmproxy_policy_store_emptied_total` (see
[Metrics and stats](/docs/llm-proxy/observability/metrics-and-stats/)). Each
replica logs and counts once per transition, not once per poll. Alert on any
increase of this counter.

The gauge `envoy_llmproxy_policy_store_rows{kind="keys"}` (and
`kind="tenants"`) shows the row counts of the last load. Configured
`auth.keys` entries are not counted. Alert when the keys gauge is 0 on a
deployment that mints keys: the counter shows the moment the store emptied,
and the gauge shows that it is still empty.

To recover, restore the Redis data from a backup or AOF file. The replicas
pick up the restored state at their next poll. If you have no copy, mint the
keys again and give them to their users.

## Concurrent streams share leases

With `store: shared`, a concurrent-stream ceiling applies to the fleet. This
includes `concurrent_sessions` in the `limits:` block and `concurrent_streams`
in tenant and key limits.

- Each replica admits a stream against its own in-flight count plus the
  count that the other replicas last published. Admission never waits for
  Redis.
- Four times a second, each replica writes its in-flight count per limit to
  Redis as a lease row with a 5-second TTL, and reads the fleet total for every
  limit, including limits it has not served yet.
- A replica that stops (a crash or `SIGKILL`) does not release its slots.
  Its lease rows expire 5 seconds after its last write, and the other
  replicas then admit again.
- Between two writes, replicas do not see each other's new streams. The
  fleet can admit up to about a quarter second of stream arrivals on the
  other replicas over a ceiling.
- If Redis cannot be reached, each replica keeps enforcing against the last
  fleet counts it read, plus its own streams (fail open). It logs one
  `stream-lease publish failed` warning per filter chain per minute, and the
  gauge `envoy_llmproxy_counter_reconciliation_age_seconds` with
  `seam="stream_lease"` grows.

Set a distinct `--service-node` on each replica. The lease rows of a replica
are keyed by its node ID.

## What stays local, even with a shared store

- **Usage history is export-only.** The shared store holds current-window
  spend counters and nothing else, never per-request history. Per-request
  history lives in access logs and request records. If you need historical
  spend, export it from them. The admin `/spend` endpoint only ever answers
  "right now, this window."
- **Token and request limits count locally unless `auth.store` is shared.**
  With a shared store, both configured `limits:` and tenant and key rate
  limits reconcile through Redis. Admission uses last-known totals plus local
  counts, so the fleet can exceed a ceiling between reconciles. See
  [Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/).
- **The rate card is shared only through `auth.store: shared`.** With an
  `auth` store, `PUT /pricing` writes the rate card there. A `persistent`
  store is one replica's file, so only `shared` reaches other replicas. Every
  replica that shares the store installs the card on its next policy poll,
  which is 48 to 60 seconds, the same bound as a key revocation. The
  configured `pricing` only seeds an empty store. A restart or a `SIGHUP`
  reload never replaces a stored rate card, and the stored rate card wins over
  a different `pricing` at start. Only a `persistent` or `shared` store keeps
  the rate card across a restart. The default `in_memory` store does not, and
  `PUT /pricing` says `"persisted": false` for it.

  To check that every replica prices with the same card, compare the
  `envoy_llmproxy_usage_rate_card_active` series on `/stats/prometheus`. Its
  `scope` label names the auth scope and its `version` label is the card
  version that `PUT /pricing` returns. The active card has the value 1. A
  version that this process retired has the value 0. A scope with no card has
  no series at 1.

  Without an `auth` block, the rate card stays in the memory of each process.
  `PUT /pricing` then changes only the replica that receives it, a restart
  loads the configured `pricing`, and a `SIGHUP` reload installs a changed
  `pricing`. To change the rate card of a deployment without a store, change
  `pricing` in every replica's configuration and reload, or send the same
  `PUT /pricing` request to every replica.

  If another replica writes a card to the same store between your
  `PUT /pricing` write and the read-back, the other card stays active on the
  replica that received your `PUT`. The `note` in the response then says
  `written, but a concurrent publish to the same store superseded it; this
  replica now serves the store's card`. The delivery from the store decides
  the active card.

  Replicas with different rate cards price the same request differently. To
  find them, compare `rate_card_version` in `GET /pricing` on each replica, or
  the `%LLM_RATE_CARD_VERSION%` values in the access logs. The version covers
  the prices and the map from each provider to its type.

  The rate card is the only price source for the spend limit. A request that
  the rate card does not price, under a dollar budget, adds $0 to the budget
  and logs one warning for each model. The fields and the limits of
  `PUT /pricing` are in
  [`pricing`](/docs/llm-proxy/configuration/reference/#pricing).

## Verify a Redis-backed store

Run the process acceptance drills against a disposable Redis. Run this from
the source tree:

```bash
QA_REDIS_ADDR=127.0.0.1:6379 make qa-case CASE='TestQA11|TestQA12'
```

QA-11 covers legacy tenant-history retention and key restart enforcement.
QA-12 covers three real processes, a socket partition, stale admissions,
local enforcement, checkpointed backlog recovery after SIGKILL, and exact
replay. Both skip when `QA_REDIS_ADDR` is absent. A plain `make tq` does not
run them. The lower-level Redis tests also require a real Redis and an
explicit ignored-test run. See the `t1` target of the Makefile for the
command.

## Limitations

- The flush interval (5 seconds), the poll interval (48 seconds), and the
  reconciliation bound (60 seconds) have no config field.
- During a store outage, spend and stream limits fail open. Only
  authentication fails closed.
- The config file has no spend recovery journal.
- `persistent` cannot serve more than one replica.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Load error at `auth.store.shared`: `a shared store requires a configured node id: pass --service-node <name> with a name unique to this replica and stable across its restarts (the dialect has no node id field)` | The replica started without `--service-node` | Pass `--service-node <name>` |
| A revoked key still authenticates on some replicas | Expected for up to 60 seconds. See [Policy and key revocation](#policy-and-key-revocation-propagation-is-bounded-not-instant) | Wait out the bound |
| `GET /keys/{id}/spend` reports `reconciliation_expired: true` | This replica has not reconciled with the shared store within 60 seconds. A store outage or partition | Check connectivity to the shared store. Enforcement continues on last-known totals |
| A budget trips later than expected, or several replicas each admit up to the full ceiling | Every replica has the same `--service-node` value, or `auth.store` is not shared | Give every replica a distinct, stable `--service-node`. Set `auth.store` to `shared` |

## Implementation notes

For maintainers.

- Store and polling: `ControlPlane::poll_once` and `next_poll_delay` in
  `crates/proxy-control/src/control.rs`. `DEFAULT_NAMESPACE` and the two Redis
  lanes are in `crates/proxy-control/src/control_redis.rs`.
- Spend: `parse_flush_interval`, `parse_reconciliation`, and `resolve_node_id`
  in `crates/proxy-filters/src/spend_limit_filter.rs`. The dialect lowering
  sets none of their fields: `crates/proxy-simple-config/src/lower.rs`.
- Node ID: `effective_node` in `crates/proxy/src/main.rs`.
- Tests: `two_accumulators_sharing_one_store_converge_on_the_true_total` in
  `crates/proxy-control/src/spend.rs`;
  `a_flush_stuck_on_the_spend_lane_does_not_delay_policy_calls`,
  `a_load_stuck_on_the_control_lane_does_not_delay_spend_reconciliation`, and
  `a_failed_call_resets_only_its_own_lane_and_that_lane_reconnects` in
  `crates/proxy-control`; `a_load_logs_its_duration_and_size_and_never_row_content`;
  `a_concurrent_publish_from_another_replica_wins_on_the_publishing_replica`
  in `crates/proxy-filters/src/usage_filter/rate_card_tests.rs`.
