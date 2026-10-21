---
title: Billing ledger
description: "Write a durable, per-request billing record stream and read its delivery guarantees."
summary: A durable, encrypted record of every request the proxy sends to a
  provider. What an entry holds, the ledger config, what happens when the
  ledger is full or fails, and how a consumer pulls and acknowledges entries.
lastUpdated: 2026-10-18
related:
  - limits-and-budgets/spend-policies
  - observability/admin-endpoints
  - observability/metrics-and-stats
  - observability/request-capture
  - configuration/reference
---

# Billing ledger

Use the billing ledger to give a billing system a durable, per-request record
of what the proxy charged. The ledger writes one encrypted entry for each
request that the proxy sends to a provider. The entry holds the request record
and the amount the proxy charged. A billing system pulls the entries over the
admin API and acknowledges them. Only an acknowledgement removes an entry.

The ledger is off by default. To enable it, add a `ledger` block to the
`llmproxy` config file, start the proxy with `--service-node`, and run a
consumer that acknowledges entries. See
[Configure the ledger](#configure-the-ledger). This page is for the operator
who runs the proxy and for the engineer who writes the billing consumer.

## The guarantee

The ledger is durable but not exactly-once across a crash. Read these points
together:

- **While the spool has space,** an entry is durable within one group-commit
  interval of the request (default 50 ms). The proxy does not hold a response
  until its entry is on disk.
- **A crash loses uncommitted entries.** The proxy commits entries in groups.
  A crash loses every entry that was not yet committed. While the spool has
  space, that is about the entries of the last `group_commit_interval`.
  While the spool is at `max_disk_bytes`, the proxy holds entries in memory
  until a consumer acknowledges, and a crash loses all of them. In every case
  the loss is at most `max_reservations` entries, because a slot is held until
  its entry is committed.
- **A loss in a running proxy is counted.** See [Metrics](#metrics).
- **A loss in a crash is detected, not counted.** The next start reports that
  the epoch did not close, but not how many entries it lost. See
  [Detect a gap](#detect-a-gap).
- **Delivery is at least once.** The proxy returns an entry again until you
  acknowledge it, so the consumer must deduplicate on `record.event_id`.

Source: `schema/llmproxy-v0.schema.json`, `ledger` description.

Two further rules:

- The proxy never evicts a committed entry. An entry leaves the spool only
  when a consumer acknowledges it.
- A clean shutdown commits the entries that were handed to the writer. The
  proxy waits up to 5 seconds, or 1 second on a fast exit. Entries not
  committed in that time are lost and logged.

## What gets an entry

An entry exists for each request that the proxy dialled to a provider. This
includes a request that the proxy charged zero, because the provider can still
bill it. A request that the proxy refused before it dialled gets no entry. This
covers a refusal for authentication, model access, budget, or rate limit, and
a refusal by the ledger itself.

The entry exists whether or not request capture is on.

### Fields of an entry

`GET /ledger/entries` returns each entry with its `cursor` and these fields.

| Field | Type | What it holds |
|---|---|---|
| `cursor` | integer | The position of the entry in the spool. Use it for `after` and `through`. It rises across restarts. |
| `schema_version` | integer | The entry format version. Version `2` adds `record.tags`. Version `1` entries can still be in the spool after an upgrade; they have no `record.tags`. |
| `instance_id` | string | The node id of the proxy that wrote the entry. |
| `epoch` | integer | The start time of that proxy process, in milliseconds. |
| `seq` | integer | The number of the entry in its epoch. It starts at 0 and has no gaps. |
| `charged_micro_usd` | integer | The amount charged, in micro-dollars. See below. |
| `charged_scopes` | list | The spend counters that received the charge. Empty if no spend filter charged. |
| `rate_card_version` | string or null | The rate-card version that priced the charge. Null if nothing priced it. |
| `policy_generation` | integer or null | The policy generation the request was admitted under. |
| `record` | object | The terminal request record. |

Each item in `charged_scopes` has `scope` (`tenant` or `key`), `id`, and
`period`. The `period` is the UTC budget period of the charge, `YYYY-MM-DD` or
`YYYY-MM`.

`charged_micro_usd` has two meanings:

- If the spend filter charged the request, the value is the amount added to the
  spend counters, and `charged_scopes` lists them.
- If the route has no spend filter, the value is the list price of the usage,
  and `charged_scopes` is empty. This is not a spend charge.
- If there is no usage or no price, the value is 0.

The deduplication key is `record.event_id`. It is inside `record`, not at the
top of the entry. The `record` also holds its own `instance_id` and
`request_id`, the tenant, the user, the models, the provider, the status, the
usage, the cost, and the chargeback tags (`tags`). See
[Chargeback tags](../chargeback-tags/).

## Configure the ledger

The `ledger` block is a top-level key of the `llmproxy` config file. The
schema is normative. See the
[field reference](../../configuration/reference/#ledger).

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `directory` | string | none | yes | Absolute path of the spool directory. The proxy creates it with mode 0700 if it is absent. An existing directory must be owner-only. One proxy process writes it. |
| `encryption_key_file` | string | none | yes | Absolute path of the key. The file must be a regular file with no group or other access (use 0600) and exactly 32 raw bytes. The proxy does not follow a symbolic link. |
| `encryption_key_id` | string | none | yes | A name for the key, 1 to 128 bytes. The proxy stores it beside each entry. |
| `previous_keys` | list of `{id, file}` | `[]` | no | Retired keys, at most 31. They only decrypt. Each `id` must be unique across this list and `encryption_key_id`. |
| `max_disk_bytes` | integer | none | yes | Disk budget of the spool, from 2097152 (2 MiB) to 1099511627776 (1 TiB). |
| `max_reservations` | integer | 16384 | no | Ledger slots, from 1 to 1048576. See [Slots](#slots). |
| `group_commit_max_entries` | integer | 512 | no | Commit a group when it reaches this size. From 1 to 4096. |
| `group_commit_interval` | duration | `50ms` | no | The longest an entry waits for a commit, from `1ms` to `1s`. |
| `on_unavailable` | `reject` or `admit` | `reject` | no | What a request gets when no slot is available. |

The encryption key is mandatory. The proxy has no unencrypted ledger.
Source: `schema/llmproxy-v0.schema.json`, `$defs/Ledger`.

In the `llmproxy` file, write `group_commit_interval` as a duration string such
as `50ms` or `1s`. The dialect accepts whole numbers with the unit `ms`, `s`,
`m`, or `h`. A
value outside 1 ms to 1 s fails the load.

### Slots

A request takes one slot before the proxy dials the provider. The request holds
the slot until its entry is committed. So `max_reservations` limits the
requests in flight plus the entries not yet committed. When every slot is held,
new requests follow `on_unavailable`.

### A complete example

The file `examples/llmproxy-ledger.yaml` in the repository has a similar
config with comments.

```yaml
version: 0

listen: 0.0.0.0:8080
admin: 127.0.0.1:9901

providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes:
  - model: "*"
    provider: openai

ledger:
  directory: /var/lib/llm-proxy/ledger
  encryption_key_file: /etc/llm-proxy/ledger.key
  encryption_key_id: ledger-2026
  max_disk_bytes: 10737418240
  max_reservations: 16384
  group_commit_max_entries: 512
  group_commit_interval: 50ms
  on_unavailable: reject
```

Start the proxy with a node id and the admin token:

```text
export LLMPROXY_ADMIN_TOKEN=$(openssl rand -hex 32)
head -c 32 /dev/urandom > /etc/llm-proxy/ledger.key
chmod 600 /etc/llm-proxy/ledger.key
llm-proxy --config llmproxy.yaml --service-node proxy-a
```

### The same config in Envoy mode

In Envoy mode, put the same fields in `node.metadata["io.llmproxy.ledger"]` of
the bootstrap. The field names and ranges are the same. One value differs:
`group_commit_interval` is a number of seconds, from `0.001` to `1`, not a
duration string. The `llmproxy` file lowers `50ms` to `0.05`. An unknown key in
the Envoy block fails the load with its full path.

### The node id

The ledger needs a node id. Pass `--service-node <name>`, or set `node.id` in
an Envoy bootstrap. The `llmproxy` file has no field for the node id. The node
id becomes the `instance_id` of every entry. It must be at most 128 bytes,
unique for each replica, and the same after each restart. It must not be `-`.
The spool also records it, so a spool written under another node id does not
open.

If the node id is missing, the proxy does not start and prints:

```text
node.metadata["io.llmproxy.ledger"]: the ledger requires a configured node id
of at most 128 bytes, unique to this replica and stable across its restarts:
pass --service-node <name> (or set the bootstrap node.id); it becomes every
entry's instance_id
```

If the key file is missing or wrong, the proxy does not start. The message
starts with `node.metadata["io.llmproxy.ledger"].encryption_key_file: cannot
load key file <path>:` and ends with the cause, for example `requires a
private (0600) regular file` or `requires exactly 32 bytes`.

### Reload

A reload cannot change the ledger. If a `SIGHUP` reload changes the `ledger`
block, the proxy refuses the whole reload. It logs `cannot change on reload;
restart the process to apply it` and keeps the previous config. Restart the
proxy to apply a ledger change.

## When the ledger is not available

A request finds no ledger capacity in three cases:

- Every slot is held. The reason is `queue_full`.
- The writer failed. The reason is `writer_failed`.
- The spool is at `max_disk_bytes`. The reason is `disk_full`.

`on_unavailable` decides what the request gets.

### reject (the default)

The proxy answers a local `503` and does not send the request to a provider.
The response has the `content-type` `text/plain; charset=utf-8`, and the body
is one line:

```text
billing ledger unavailable: disk_full
```

The word after the colon is the reason. The access log shows
`ledger_unavailable_<reason>` as the response code details. The proxy counts
each refusal in `llmproxy_ledger_rejected_total{reason}`.

The proxy reserves the ledger slot before any filter runs, but it sends the
`503` only at the point where it would dial a provider. So the filters answer
first: a request with no valid key gets `401`, and a request over its rate
limit gets `429`. Only a request that the proxy would dial gets the `503`
and counts as a rejection. A route that does not dial (a direct response or a
redirect) answers as usual.

**Warning.** With `reject`, the health of the ledger is the availability of
the proxy. A full or failed ledger refuses every request that would reach a
provider.

### admit

The proxy serves the request without an entry. This is a fail-open choice. It
counts each such request in `llmproxy_ledger_unledgered_total{reason}`. It logs
a warning at most once every 5 seconds. The warning names only the reason. The counter is the full record. A
request served this way is not in the ledger, and you cannot recover it from
the ledger.

### The writer fails

A storage error or a panic in the writer is terminal. The ledger does not
recover until you restart the proxy. The proxy counts the entries it still
held as lost in `llmproxy_ledger_entries_lost_total{reason="writer_failed"}`.
After that, every request follows `on_unavailable` with the reason
`writer_failed`.

### The disk is full

At `max_disk_bytes`, new requests follow `on_unavailable` with the reason
`disk_full`. The proxy does not evict a committed entry to make room. Only an
acknowledgement frees space.

**Warning.** The ledger needs a consumer that acknowledges entries on a
regular basis. Without one, the spool fills. Under `reject`, a full spool
refuses every request.

After an acknowledgement frees space, the writer commits what it held and
writes the held entries in order. Then admission resumes. You do not restart
the proxy. If one acknowledgement frees too little space, the answer says
`"admitting": false`. Keep acknowledging until it says `true`.

## Pull and acknowledge entries

A consumer uses two endpoints on the admin listener. Both need the admin
bearer token. See [Admin endpoints](../../observability/admin-endpoints/#auth-model).

### GET /ledger/entries

```text
curl -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  'http://127.0.0.1:9901/ledger/entries?after=0&limit=100'
```

| Parameter | Type | Default | What it does |
|---|---|---|---|
| `after` | unsigned integer | `0` | Return entries with a cursor above this value. |
| `limit` | integer | `100` | The most entries to return, from 1 to 1000. |

The answer has this shape. The values are an example.

```json
{
  "entries": [
    {
      "cursor": 1,
      "schema_version": 2,
      "instance_id": "proxy-a",
      "epoch": 1760000000000,
      "seq": 0,
      "charged_micro_usd": 14,
      "charged_scopes": [
        { "scope": "tenant", "id": "acme", "period": "2026-10" }
      ],
      "rate_card_version": "2026-01",
      "policy_generation": 3,
      "record": { "event_id": "...", "tags": { "team": "infra" } }
    }
  ],
  "next_after": 1,
  "committed_through": 1,
  "epochs": [
    { "epoch": 1759990000000, "closed": true },
    { "epoch": 1760000000000, "closed": false }
  ]
}
```

- `entries` has committed entries only, in cursor order.
- `next_after` is the cursor of the last entry returned. If the page is empty,
  it equals `after`.
- `committed_through` is the cursor of the last committed entry.
- `epochs` lists the last 64 epochs of this instance, oldest first. The last
  one is the running epoch, so it is not closed. An earlier epoch with
  `closed: false` crashed, or stopped with entries it did not commit. See
  [Detect a gap](#detect-a-gap).

### POST /ledger/ack

```text
curl -X POST -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  'http://127.0.0.1:9901/ledger/ack?through=1'
```

The request has no body. The `through` parameter is required. The proxy removes
every entry with a cursor at or below it. The answer is:

```json
{ "acknowledged_through": 1, "admitting": true }
```

`admitting` is `false` when the spool is still at its cap. See
[The disk is full](#the-disk-is-full).

### Status codes

| Status | Cause |
|---|---|
| `200` | The call worked. |
| `400` | A parameter is unknown, repeated, not an integer, or out of range. `limit` outside 1 to 1000 is a `400`. `through` is missing. An ack carries a body. |
| `401` | The bearer token is missing or wrong. |
| `403` | `LLMPROXY_ADMIN_TOKEN` is not set on the proxy. |
| `404` | The config has no `ledger` block. |
| `405` | The method is wrong. Use GET for entries and POST for ack. |
| `409` | `through` is past the last committed entry. |
| `429` | The peer sent too many wrong tokens. The answer has `Retry-After`. |
| `503` | The writer stopped or did not answer in 5 seconds. |
| `507` | Not even one entry of the ack fits in the full spool. Retry; part of the range may already be acknowledged. |

The proxy checks the token before the parameters, and the parameters before
the `404`. A refused ack removes nothing. Tests cover the other status codes. No test
covers the `503` for a stopped writer or the `507`.

### The consumer loop

Run this loop for each replica:

1. Call `GET /ledger/entries?after=<cursor>&limit=<n>`. Start with `after=0`.
2. Store each entry in your system. Skip an entry whose `record.event_id` you
   already have.
3. Call `POST /ledger/ack?through=<next_after>` after the store commits. The
   ack succeeds at the disk cap too: the spool keeps space in reserve for
   acknowledgements and frees the range in parts when it must.
4. Set `cursor` to `next_after`.
5. Repeat. If `admitting` was `false`, repeat at once.

Delivery is at least once. The proxy returns an entry again until you
acknowledge it. This includes after a restart. So you must deduplicate on
`record.event_id`.

Use the cursor for `after` and `through`, not `seq`. The cursor is the position
in the spool and rises across restarts. The `seq` restarts at 0 in each epoch.

### Detect a gap

Within one `(instance_id, epoch)`, `seq` starts at 0 and has no gaps. If
`seq` jumps inside an epoch, an entry is missing. A new `epoch` for the same
`instance_id` means the proxy restarted. The `epoch` is the start time in
milliseconds. It is always later than the epoch of the last entry that is not
yet acknowledged, even if the clock steps back.

`seq` cannot show the entries a crash removes from the end of an epoch,
because no later entry in that epoch shows the gap. The `epochs` list shows
it instead. A clean stop that committed every entry marks its epoch
`closed: true` in the spool. The next start reads that mark. If the previous
epoch is not closed, the proxy logs an error ("the previous epoch did not
close"), adds 1 to `llmproxy_ledger_unclean_epochs_total`, and reports the
epoch with `closed: false` in `epochs`. The mark is kept when you acknowledge
every entry, so it does not depend on what the consumer has read. A QA drill kills the proxy with `SIGKILL` and
checks that the ledger redelivers entries until they are acknowledged.

**Caution.** An epoch with `closed: false` may have lost entries from its end,
but the ledger cannot tell how many: those entries never reached the disk.
Plan for a loss at each crash of about one `group_commit_interval` of entries,
or, at the disk cap, of every entry held in memory, up to `max_reservations`.
A start at the disk cap cannot record its epoch; the proxy logs an error, and
a crash in that epoch is not detected.

## One ledger for each replica

Each replica has its own ledger. There is no shared ledger store. Collect from
every replica, with its own cursor for each. Give each replica a different
`--service-node`. If two replicas share a node id, their entries carry the
same `instance_id`, and a consumer cannot tell them apart.

## Metrics

The ledger counters are on `/stats/prometheus` and in OTLP. They are not on
`/stats`. On `/stats/prometheus` the proxy adds the prefix `envoy_`, so an
operator sees `envoy_llmproxy_ledger_rejected_total`. The ledger registers its
counters at start, so an idle ledger shows zeros.

| Metric | Labels | What it counts |
|---|---|---|
| `llmproxy_ledger_rejected_total` | `reason`: `queue_full`, `writer_failed`, `disk_full` | Requests refused with `503` under `reject`. |
| `llmproxy_ledger_unledgered_total` | `reason`: `queue_full`, `writer_failed`, `disk_full` | Requests served without an entry under `admit`. |
| `llmproxy_ledger_entries_committed_total` | none | Entries committed to the spool. |
| `llmproxy_ledger_entries_lost_total` | `reason`: `writer_failed`, `oversize`, `shutdown` | Entries handed to the writer and never committed. |
| `llmproxy_ledger_unclean_epochs_total` | none | Starts that found the previous epoch not closed. It is 0 or 1 for each process. |
| `llmproxy_spend_charged_micro_usd_total` | none | Micro-dollars the spend filter charged, once for each request that charged a scope. |
| `llmproxy_ledger_spend_written_micro_usd_total` | none | Micro-dollars of spend charges in committed entries. |

An `oversize` entry is larger than 1 MiB, or larger than 1/16 of
`max_disk_bytes` when that is less (128 KiB at the 2 MiB minimum). An entry
that large cannot be written at the disk cap. The proxy does not write it, and
logs an error at most once every 5 seconds. The counter counts every one.

### Reconcile

The two spend counters are equal, except for entries lost and requests served
under `admit`. A difference means billing data is missing. A list price on a
route without a spend filter is in the entry, but it is not a spend charge, so
it is in neither counter.

Check a period in three steps:

1. Sum `charged_micro_usd` from your consumer's store for one scope. Use the
   entries whose `charged_scopes` has that `scope`, `id`, and `period`.
2. Call `GET /tenants/{id}/spend` with the admin token. Read `period` and
   `spend_micro_usd`.
3. Compare the two numbers.

The totals match if no entry was lost and nothing was served under `admit`.
The spend report covers the current period only. Sum the ledgers of every
replica before you compare. The spend report covers all replicas only if they
share an `auth.store`. See
[Spend policies](../spend-policies/#tenant-budgets) and
[Metrics and /stats](../../observability/metrics-and-stats/).

## Failure modes

| You see | Cause | Fix |
|---|---|---|
| Every request gets `503` with `billing ledger unavailable: disk_full` | The spool is at `max_disk_bytes` and no consumer acknowledges. | Run the consumer loop. Acknowledge until `admitting` is `true`. |
| `503` with `billing ledger unavailable: writer_failed` | A storage error stopped the writer. | Read the error log, fix the disk, and restart the proxy. |
| `503` with `billing ledger unavailable: queue_full` | All slots are held. | Raise `max_reservations` or reduce `group_commit_interval`. Restart to apply it. |
| `409` from `/ledger/ack` | `through` is past `committed_through`. | Use the `next_after` from a `GET`. |
| `507` from `/ledger/ack` | Not even one entry could be acknowledged. The reserve is meant to prevent this. | Retry. If it repeats, report it with the proxy log. |
| Proxy does not start with `requires a configured node id` | No `--service-node`. | Pass `--service-node <name>`. |

## What the ledger is not

The ledger is not request capture. Capture is best-effort and drops records
under load. The ledger reserves a slot for each request and counts every loss.
See [Request capture](../../observability/request-capture/).

The ledger is not a spend limit. It records what the proxy charged. It does not
refuse a request for cost. See [Spend policies](../spend-policies/).

## Implementation notes

This section is for maintainers.

- Writer, epochs, and counters: `crates/proxy-observability/src/ledger.rs`
  (`Writer::acknowledge`, `Writer::fail`, `Writer::resume_after_cap`,
  `Unledgered::dialled`, `next_epoch`, `epoch_history`, `load_key`,
  `LedgerStats`, `MAX_ENTRY_BYTES`). Entry types: `LedgerEntry` and
  `RequestRecord` in `crates/proxy-observability/src/records.rs`.
- Entry selection (`upstream_host.is_some()`) and `ledger_charge`:
  `crates/proxy-http/src/access_logging.rs`. Refusal reply:
  `ledger_unavailable_reply` in `crates/proxy-http/src/router.rs`.
- Config ranges and defaults: `crates/proxy-config/src/ledger.rs`. Dialect
  lowering: `lower_ledger` in `crates/proxy-simple-config/src/lower.rs`;
  duration parsing: `SimpleDuration` in
  `crates/proxy-simple-config/src/model.rs`.
- Admin endpoints: `LedgerItem` and `ledger_error` in
  `crates/proxy-admin/src/server.rs`; tests in
  `crates/proxy-admin/src/server/tests/ledger.rs`, including
  `entries_are_paged_by_cursor_and_an_ack_removes_them`.
- Startup and reload: `crates/proxy/src/main.rs`. Tests in
  `crates/proxy/tests/ledger_e2e.rs`:
  `a_ledger_without_a_node_id_stops_startup`,
  `a_missing_key_file_stops_startup_naming_the_field`, and
  `a_reload_that_changes_the_ledger_is_refused`. The same file reads the
  `envoy_` metric names.
- Refusal while every slot is held:
  `with_every_slot_held_a_request_is_refused_503_and_never_dialled` in
  `crates/proxy-core/src/listener_ledger_tests.rs`.
- Crash drill: `TestQA13_LedgerSurvivesSigkillAndRedeliversUntilAcked` in
  `testing/qa/scenarios/qa13_billing_ledger_test.go`.
