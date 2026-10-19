---
title: Request capture
description: "Write one metadata record for each request (no bodies) to a JSON-lines file, or experimentally to the capture agent."
summary: Opt-in request metadata records. The supported file workflow comes
  first, then the record fields, loss accounting, and metrics. The
  experimental capture agent has its own section.
lastUpdated: 2026-10-18
related:
  - observability/overview
  - observability/access-logs
  - observability/metrics-and-stats
  - reference/cli
---

# Request capture

Request capture writes one metadata record for each completed request. A
record names the tenant, the user, the requested model, the selected provider
and model, the status, the token usage, and the cost. A record holds no
request body, no response body, and no headers. To export bodies, see
[Request and response body export](../trace-export/).

Capture is off by default. It starts only when you give the proxy a
destination. There are two destinations:

- A JSON-lines file you name. This is the supported destination.
- The `llm-capture-agent` spool. This destination is experimental. See
  [Experimental: capture agent](#experimental-capture-agent).

**A record contains end-user identities and model history.** Protect the
destination.

## Write records to a file

Use this procedure to turn capture on, make one record, and read it.

1. Choose a file path. The directory must exist, and the proxy user must be
   able to write to it.

2. Start the proxy with `--request-records-file`. The flag works with the
   `llmproxy` dialect (`--config`) and with a `-c` bootstrap.

   ```sh
   llm-proxy --config llmproxy.yaml \
     --request-records-file /var/lib/llmproxy/request-records.jsonl
   ```

3. Send one request through the proxy. Use any route in your config. This
   example assumes a route for `gpt-4o-mini` on port 8080.

   ```sh
   curl --max-time 30 http://127.0.0.1:8080/v1/chat/completions \
     -H "content-type: application/json" \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
   ```

4. Read the last record. The proxy writes each record as one JSON line.

   ```sh
   tail -n 1 /var/lib/llmproxy/request-records.jsonl | jq .
   ```

The record looks like this. The example is abridged and the values are
illustrative. A real record has more fields. See
[What a record holds](#what-a-record-holds).

```json
{
  "schema_version": 1,
  "request_id": "<request id>",
  "instance_id": "<instance id>",
  "record_seq": 1,
  "tenant_id": "default",
  "user_id": null,
  "key_id": null,
  "method": "POST",
  "requested_model": "gpt-4o-mini",
  "selected_provider": "openai",
  "selected_model": "gpt-4o-mini",
  "status": 200,
  "termination": "complete",
  "usage": {
    "input_tokens": 9,
    "output_tokens": 12,
    "completeness": "complete",
    "provenance": "provider"
  },
  "cost": {"amount": 1200, "unit": "nanodollars", "currency": "USD", "kind": "list"},
  "attempts_truncated": false
}
```

If the config has no price for the model, `cost` is `null`. A record never holds the
prompt or the answer.

### Destination permissions

The proxy creates a new file with mode `0600`. The file is a regular file.
The proxy refuses to start with `cannot start metadata collector: metadata
destination must be a regular file` if the path is a directory or another
kind of file. If the file already exists, the proxy keeps its mode. Set the
mode of an existing file yourself.

### Rotation and retention

You rotate the file. The proxy does not rotate, expire, or compress it. The
proxy opens the file once at start and appends to it. It does not reopen the
file on `SIGHUP`.

- A file that you rename keeps receiving records, because the proxy holds the
  open file. Renaming alone does not start a new file.
- A copy-then-truncate rotation works with the append mode of the proxy.
- To start on a new file, change the path and restart the proxy.

Set the retention and the access control of the old files in your own tooling.

### Delivery limits

File delivery is best effort. It is not a billing record. For billing, use the
[billing ledger](../../limits-and-budgets/billing-ledger/).

- The proxy hands each record to a writer thread through a queue of 1,024
  records. A full queue drops the new record and counts it. Forwarding does
  not wait.
- The proxy does not call `fsync`. A successful write is not a durability
  acknowledgement.
- After one failed write, the proxy stops accepting records for the rest of
  the process. It discards the queued records and counts them in
  `llmproxy_metadata_dropped{reason="drained_after_close"}`. Forwarding
  continues.
- On shutdown, the proxy writes the queued records for up to 5 seconds
  (less on a fast exit). A process that `SIGKILL` stops loses the queued
  records.

See [Check that no record was lost](#checking-that-no-record-was-lost) and
[Record delivery metrics](#record-delivery-metrics).

### Flags

| Flag | Required | Default | What it does |
|---|---|---|---|
| `--request-records-file <PATH>` | no | none | Append JSON lines to this file. Conflicts with `--request-records-agent`. |
| `--request-record-max-attempts <N>` | no | `64` | Attempt summaries to keep for each record. Range 1 to 64. Needs a file or an agent. |

The flags are read at start. A reload does not change them. The `llmproxy`
dialect has no capture field.

## What a record holds

These are some of the fields of a record:

| Field | Meaning |
|---|---|
| `request_id`, `event_id`, `instance_id` | Identify the request, the record, and the proxy instance. |
| `record_seq` | The record's number within its `instance_id`: 1, 2, 3, and so on, in the order the delivery path wrote the records. A gap means a record that was numbered but not delivered. Absent in records from older builds. |
| `tenant_id`, `user_id`, `key_id` | Identify who made the request. `user_id` and `key_id` can be `null`. `tenant_id` is `default` when the request had no tenant (no auth configured, or a credential that names none), and `unauthenticated` when the auth filter refused it; `error_category` then gives the reason, for example `auth_unknown_key`. Both names are reserved. |
| `requested_model` | The model name the client sent. |
| `selected_provider`, `selected_model` | The provider and model the proxy dialled. |
| `status`, `termination`, `error_category` | How the request ended. `error_category` is the Envoy response code details. A stream whose downstream connection closed is `termination: downstream_disconnect` with flag `DC`, and `error_category` says which side closed it: `downstream_remote_disconnect` when the client left, `downstream_local_disconnect` when the proxy cut it at shutdown (the end of `--drain-time-s`, or a second termination signal). |
| `usage`, `cost` | Token counts and cost. Both can be `null`. |
| `usage.completeness`, `usage.provenance` | `complete` for a finished response. `partial` for a stream cut off before the provider's final usage: the counts are then the provider's figures where they arrived and estimates (4 bytes per token) for the rest. `provenance` is `provider`, or `estimate` when any count was estimated; `usage.input_estimated` and `usage.output_estimated` say which. |
| `cost.kind` | `list` for a rate-card price of provider-reported usage, `estimate` when it prices estimated usage. A partial record is charged to spend and token limits at this estimate. |
| `upstream_response_id` | The provider's own id for the response, bounded to 256 bytes. `null` when absent. |
| `upstream_usage` | The provider's `usage` object exactly as sent, embedded as JSON (the last one, for a stream). Evidence only: cost never comes from it. `null` when absent or over 4096 bytes. |
| `attempts`, `attempts_truncated` | One summary for each provider attempt. Excess attempts are cut and flagged. |

## Checking that no record was lost

Each `instance_id` is one proxy process. When metadata delivery stops, the
proxy logs one line with `event="metadata_delivery_summary"`. The line has
`instance_id`, `last_record_seq`, `accepted`, `written`, `failed`, `unwritten`,
the admission drops (`dropped_capacity`, `dropped_oversize`, `dropped_invalid`,
`dropped_closed`), and `timed_out`. The level is `WARN` when a record was lost
or the flush timed out, and `INFO` otherwise.

To reconcile, for each `instance_id`:

1. Expect records with `record_seq` from 1 to `last_record_seq`, with no gaps.
2. Expect a summary line with nothing lost.
3. If there is no summary line, the process was killed (for example `SIGKILL`
   after a container stop timeout). The records after the last `record_seq`
   that arrived are unknown.

Give the proxy a stop timeout longer than `--drain-time-s`, so that it can
drain and write the summary.

### Record delivery metrics

These series are on `/stats/prometheus` with the `envoy_` prefix. See
[Metrics and stats](../metrics-and-stats/). The proxy creates them at start,
so an idle proxy shows `0` and not a missing series.

| Metric | Labels | Meaning |
|---|---|---|
| `llmproxy_metadata_admission` | `outcome`: `accepted`, `capacity_exceeded`, `closed` | Whether the queue took the record. |
| `llmproxy_metadata_queue_depth` | none | Records in the queue. |
| `llmproxy_metadata_queue_capacity` | none | Queue size. `0` means capture is not configured. |
| `llmproxy_metadata_written` | none | Records delivered. In file mode, an append. In agent mode, a durable local receipt. |
| `llmproxy_metadata_durable` | none | Records the agent confirmed as durable. |
| `llmproxy_metadata_write_failures` | none | Write failures, or deliveries with an unknown result. |

Alert on a rising `llmproxy_metadata_write_failures` and on
`llmproxy_metadata_admission{outcome="capacity_exceeded"}`.

## Experimental: capture agent

**Experimental.** Delivery to the `llm-capture-agent` spool is experimental.
Use `--request-records-file` for supported delivery. The proxy and the agent
print a warning at startup when the spool is in use.

- The agent writes records, and nothing reads them back except the inspection
  endpoints below.
- The agent never removes acknowledged records. It has no retention.
- The agent does not remove duplicates when the proxy sends a batch again.
- When the spool reaches its disk limit, capture stops. Free space does not
  restart it.

### Ways to deliver records

| Mode | Flags or key | Where records go |
|---|---|---|
| File | `--request-records-file` | One JSON line per record, appended to a file you name. Supported. See [Write records to a file](#write-records-to-a-file). |
| Agent | `--request-records-agent` and three more flags | The `llm-capture-agent`, over a Unix socket. The agent commits to an encrypted local spool. |
| Declarative | `node.metadata["io.llmproxy.capture"]` in a `-c` bootstrap | The agent, with limits set in the bootstrap file. |

`--request-records-file` conflicts with `--request-records-agent`. The
command line rejects the two flags together.

The declarative key cannot combine with any CLI capture flag. The proxy
refuses to start with this message:

```text
node.metadata["io.llmproxy.capture"]: cannot combine declarative and CLI capture
```

The `llmproxy` dialect (`--config`) has no capture field. Use the flags, or a
bootstrap file passed with `-c`.

### Run the capture agent

The release archive contains `llm-capture-agent` beside `llm-proxy`.
The installer script copies both
files into the same directory. The installer
does not create an agent configuration or start the agent.

Start the agent with a JSON file:

```sh
llm-capture-agent --config /absolute/path/agent.json
```

Example `agent.json`. Replace the paths, the UID, and the identifiers.

```json
{
  "version": 1,
  "mode": "metadata_spool_only",
  "socket_path": "/srv/llm-capture/metadata.sock",
  "node_id": "deployment-node-1",
  "producers": [
    {"producer_id": "proxy-1", "uid": 1000, "tenants": ["default"], "inspect": true}
  ],
  "spool": {
    "directory": "/srv/llm-capture/spool",
    "max_record_bytes": 524288,
    "max_disk_bytes": 4294967296,
    "cache_bytes": 4194304
  },
  "active_key_id": "deployment-key-1",
  "keys": [
    {"key_id": "deployment-key-1", "key_file": "/srv/llm-secrets/capture-key"}
  ]
}
```

Prepare the host before you start the agent:

1. Create the socket directory with mode `0700`.
2. Create a regular 32-byte key file with mode `0600`. Never put the key in
   `agent.json`.
3. Set `producers[].uid` to the OS UID of the `llm-proxy` process.

All fields are required except `spool.cache_bytes` (default 4 MiB) and
`producers[].inspect` (default `false`). An unknown field fails at its full
path. These limits also apply:

- The configuration file is at most 128 KiB.
- IDs are 1 to 128 bytes.
- The grant list has at most 256 producers and at most 16 keys.
- Tenant names have no wildcard.
- A record is at most 512 KiB.
- `max_disk_bytes` is at most 1 TiB and at least 2 MiB.
- `cache_bytes` is from 1 byte to 16 MiB.

The agent checks the OS UID of the proxy and the producer ID. Then it checks
the tenant of each record against the producer grant. The proxy checks the
UID and the node ID of the agent. The socket has mode `0600`. The normal
deployment runs both processes under the same UID. This does not protect
against a hostile process under the same UID, or against root.

### Enable capture in the proxy

Pass the agent socket and three identity values. Each of the three is
required when you pass `--request-records-agent`.

```sh
llm-proxy -c /absolute/path/bootstrap.yaml \
  --request-records-agent /srv/llm-capture/metadata.sock \
  --request-records-agent-uid 1000 \
  --request-records-agent-node deployment-node-1 \
  --request-records-producer proxy-1
```

| Flag | Required | Default | What it does |
|---|---|---|---|
| `--request-records-agent <SOCKET>` | no | none | Send records to the agent at this Unix socket. |
| `--request-records-agent-uid <UID>` | with agent | none | The OS UID the agent must run as. |
| `--request-records-agent-node <ID>` | with agent | none | The `node_id` the agent must report. The proxy checks it on the handshake and on every receipt. |
| `--request-records-producer <ID>` | with agent | none | The `producer_id` in the agent grant for this proxy. |
| `--request-record-max-attempts <N>` | no | `64` | Attempt summaries to keep for each record. Range 1 to 64. Needs a file or an agent. |

The flags are read at start. A reload does not change them. Setting
`--request-record-max-attempts` without a destination is an error.

#### The declarative bootstrap key

You can set capture in a bootstrap file instead of flags. The decoder is
strict. An unknown key fails with its full path.

```yaml
node:
  id: replica-a
  cluster: llm-proxy
  metadata:
    io.llmproxy.capture:
      version: 1
      metadata:
        enabled: true
      policy:
        version: first
      endpoint:
        unix_socket_path: /srv/llm-capture/metadata.sock
        expected_agent_uid: 1000
        expected_node_id: deployment-node-1
        producer_id: proxy-1
      emergency_control:
        unix_socket_path: /srv/llm-capture/control.sock
        operator_uid: 1000
```

| Key | Required | Default | Notes |
|---|---|---|---|
| `version` | yes | none | Must be `1`. |
| `metadata.enabled` | no | `false` | If `false`, every other key except `version` and `metadata` is an error. |
| `metadata.max_attempts` | no | `8` | 1 to 64. |
| `metadata.max_record_retained_bytes` | no | `65536` | 4096 to 65536. |
| `metadata.max_encoded_record_bytes` | no | `524288` | 4096 to 524288. |
| `policy.version` | when enabled | none | A string of 1 to 128 bytes. |
| `endpoint.*` | when enabled | none | Same four values as the agent flags. The socket path is absolute, at most 103 bytes. |
| `emergency_control.*` | when enabled | none | `unix_socket_path` and `operator_uid`. The path must differ from the agent socket. |
| `budgets.*`, `transport.*` | no | see source | Memory and deadline limits. Defaults are in `CaptureBudgets::default` and `CaptureTransportLimits::default`. |

A SIGHUP reload applies the declarative capture block. If the proxy rejects
the new block, it keeps the previous snapshot.
Declarative capture also requires `--concurrency` of 8 or less.

This page does not describe the emergency control protocol. Treat the
control socket as a privileged interface.

### What the proxy does when the agent is down

Capture never changes forwarding. The proxy sends a record from a dedicated
writer, with a queue of 1,024 events. The request worker never connects to
the agent. If the agent is down, the proxy keeps serving requests and the
counters below show the lost records. In the agent mode that the flags select, each event gets at most three
transport attempts.

Retries keep the event ID. A lost acknowledgement can leave a duplicate
record. Treat the spool as at-least-once, not exactly-once.

### Inspect the spool

Two admin endpoints read the spool through the proxy. Both need an agent
endpoint. Both need the producer grant to have `"inspect": true`. An
inspection never acknowledges a record and never changes the spool.

An inspect grant reads every stored record of its tenants, whichever
producer wrote the record.

#### `GET /capture/spool/stats`

This endpoint needs no token. It returns counters and byte sizes only, with
no record contents. The proxy caches the answer for 5 seconds. Concurrent
callers share one agent query, and the cache also holds errors.

```sh
curl --max-time 5 http://127.0.0.1:53422/capture/spool/stats
```

The JSON fields are `node_id`, `next_sequence`, `durable_through_sequence`,
`acknowledged_through_sequence`, `pending_records`, `retained_records`,
`database_bytes`, `disk_bytes`, `max_disk_bytes`, `quarantine_bytes`,
`poisoned`, `durable_total`, `rejected_total`, and `failures_total`.

#### `GET /capture/spool/records`

This endpoint needs the admin token (`Authorization: Bearer <token>`). The
token is the value of `LLMPROXY_ADMIN_TOKEN`. It returns one page of stored
records. The proxy does not cache it.

```sh
curl --max-time 5 -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  "http://127.0.0.1:53422/capture/spool/records?after=0&limit=50"
```

| Parameter | Default | Range |
|---|---|---|
| `after` | `0` | An unsigned integer sequence. The page starts after it. |
| `limit` | `50` | 1 to 100. |

The response has `records`, `next_after_sequence`, and
`durable_through_sequence`. Use `next_after_sequence` as the next `after`.
An unknown or repeated parameter gives `400`. A method other than `GET`
gives `405`.

#### Status codes

| Status | Endpoint | Cause | Fix |
|---|---|---|---|
| `404` | both | No agent endpoint is configured. Text: `no capture agent is configured for this proxy; /capture/spool/* needs a capture agent endpoint` | Pass the agent flags or the bootstrap key. |
| `401` | records | Missing or invalid bearer token. | Send the correct token. |
| `403` | records | `LLMPROXY_ADMIN_TOKEN` is not set on the proxy. | Set the variable and restart. |
| `403` | both | The agent refused the query. Text: `the capture agent refused the query; the proxy's producer grant needs "inspect": true` | Add `"inspect": true` to the grant and restart the agent. |
| `501` | both | The agent closed on the query. Text: `agent does not support spool inspection; upgrade the capture agent` | Upgrade the agent. A retry cannot help. |
| `503` | both | The agent is unreachable, or it did not answer in 2 seconds. Text: `capture agent unavailable` | Check that the agent runs and the socket path is right. |
| `400` | records | A bad `after` or `limit`, or an unknown parameter. | Correct the query. |

The error body is JSON: `{"error": "<text> (<detail>)"}`. Each message ends
with a fixed detail phrase. It never contains record contents.

### The Capture tab in the admin UI

The admin UI has a Capture tab. It shows the spool stats from
`/capture/spool/stats` and refreshes them every 10 seconds while the tab is
visible. It marks a poisoned spool with a red `SPOOL POISONED` banner. The
Records section loads pages of 50 records from `/capture/spool/records` with
the token from the header bar. You can filter the loaded rows by tenant,
user, model, or request ID. The filter works on the rows already loaded in
the browser.

### Agent and capture metrics

All names below appear on `/stats/prometheus` with the `envoy_` prefix, for
example `envoy_llmproxy_capture_agent_reachable`. See
[Metrics and stats](../metrics-and-stats/).

#### Spool gauges

The proxy asks the agent for spool stats every 10 seconds. The first poll
runs one period after start. Each poll has a 2-second limit. The poll runs
only when an agent endpoint exists at start. A reload that first adds an
endpoint is not polled until you restart.

| Gauge | Meaning |
|---|---|
| `llmproxy_capture_agent_reachable` | `1` if the agent answered the last poll, even with a refusal. `0` if the agent could not be reached. |
| `llmproxy_capture_spool_stats_available` | `1` if the last poll returned stats. `0` if the agent refused or did not answer. The gauges below are then stale. |
| `llmproxy_capture_spool_retained_records` | Records the spool holds. |
| `llmproxy_capture_spool_pending_records` | Durable records not yet acknowledged downstream. |
| `llmproxy_capture_spool_disk_bytes` | Disk bytes the spool uses. |
| `llmproxy_capture_spool_max_disk_bytes` | The disk ceiling. |
| `llmproxy_capture_spool_quarantine_bytes` | Bytes the spool quarantined. |
| `llmproxy_capture_spool_durable_through_sequence` | Highest durable sequence. |
| `llmproxy_capture_spool_poisoned` | `1` if the spool reports itself poisoned. |

The proxy logs on a change only, not on every poll:

- `capture agent unreachable: ...` at `warn`, when the agent goes down.
- `capture agent reachable again` at `info`.
- `capture agent spool stats are off: the producer grant lacks "inspect": true; ...`
  at `info`, once.
- `capture agent spool stats are off: the agent closed on the inspection query, ...`
  at `info`, once.

#### Capture pipeline counters

The proxy creates these series at start, so an idle proxy shows `0` and not
a missing series. The `llmproxy_metadata_*` series are in
[Record delivery metrics](#record-delivery-metrics).

| Metric | Labels | Meaning |
|---|---|---|
| `llmproxy_capture_state_admission` | `outcome`: `accepted`, `disabled`, `capacity_exceeded`, `closed` | Whether a request got capture state. |
| `llmproxy_capture_active_requests` | none | Requests with capture state now. |
| `llmproxy_capture_state_reserved_bytes` | none | Bytes reserved for request state. |
| `llmproxy_capture_event_reserved_bytes` | none | Bytes reserved for queued events. |
| `llmproxy_capture_drops` | `reason`: `disabled`, `expired`, `encoded_limit`, `delivery_unknown`, `identity_limit`, `transport_capacity`, `agent_rejected`, `unavailable` | Records dropped, by cause. |

### Limits

- **Local spool only.** The agent writes to a local encrypted spool. No
  upload, no query service, no transcripts, and no billing-ledger guarantee.
- **No expiry.** The agent does not expire or evict records. When the disk
  budget is full, the agent declines new records. Size `max_disk_bytes` for
  the longest outage you plan for.
- **Failure is quiet for traffic.** A metadata failure never changes
  forwarding or readiness. Watch `llmproxy_capture_agent_reachable` and
  `llmproxy_metadata_write_failures`.
- **At least once.** A lost acknowledgement can produce a duplicate record.
- **Memory.** The agent makes no whole-process memory limit. Set a memory
  limit for the agent process yourself.
- **Shutdown.** The agent waits at most 5 seconds for the writer to drain.
  After SIGKILL a stale socket can remain. Stop the old process, remove that
  socket, and restart. The agent never removes an existing socket.
- **Spool keys.** Keep the key file and the spool files. The spool cannot be
  read without the key.

### Troubleshooting

**`GET /capture/spool/stats` returns 404.** The proxy has no agent endpoint.
Pass the four agent flags or the bootstrap key.

**`llmproxy_capture_agent_reachable` is `0`.** The poll could not reach the
agent. Check that `llm-capture-agent` runs, that the socket path matches
`--request-records-agent`, and that the UIDs match. Request handling
continues.

**`llmproxy_capture_agent_reachable` is `1` and
`llmproxy_capture_spool_stats_available` is `0`.** The agent answers but
gives no stats. Add `"inspect": true` to the producer grant, or upgrade the
agent. Record delivery is not affected.

**The proxy refuses to start with `cannot combine declarative and CLI
capture`.** Remove the `--request-records-*` flags or remove the bootstrap
key.

## Implementation notes

For maintainers. Each behavior above has this source or test.

- File sink: `crates/proxy-observability/src/metadata.rs`. The module doc
  states the best-effort contract. `MetadataDelivery::start` sets mode `0600`
  and the append open. The writer thread stops admission after a failed write
  (`close_on_failure`) and stamps `record_seq`.
- Flags, conflicts, and the startup warning: `crates/proxy/src/main.rs`,
  `Args` and the capture setup in `serve`.
- Record type: `RequestRecord` in `crates/proxy-observability/src/records.rs`.
- Declarative decoder: `crates/proxy-config/src/capture.rs`.
- Agent limits: `crates/proxy-capture-agent/README.md`.
- Release archive and installer: `.github/workflows/release.yml` and
  `scripts/install.sh`.
- Admin endpoints: `crates/proxy-admin/src/server.rs`. Admin UI:
  `admin-ui/src/components/Capture.tsx`.
- Metric definitions: `crates/proxy-observability/src/stats.rs`. Tests:
  `crates/proxy-observability/src/capture_tests.rs`. The precise trigger of
  each `llmproxy_capture_drops` reason is checked only by those tests. The
  `delivery_unknown` reason does not prove the record was lost.
