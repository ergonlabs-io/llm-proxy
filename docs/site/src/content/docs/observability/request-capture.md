---
title: Request capture
summary: Opt-in end-user metadata records, the llm-capture-agent that stores
  them in a local spool, the flags and bootstrap key that enable them, the
  spool inspection endpoints, and the metrics.
last_updated: 2026-10-13
related:
  - ../observability/access-logs/
  - ../observability/metrics-and-stats/
  - ../reference/cli/
---

# Request capture

Request capture writes one metadata record for each completed request. A
record names the tenant, the user, the requested model, the selected provider
and model, the status, the token usage, and the cost. A record holds no
request body, no response body, and no headers.

Capture is off by default. It starts only when you supply a destination.

**Experimental.**
Delivery to the `llm-capture-agent` spool is experimental. The agent writes
records and nothing reads them back. It never removes acknowledged records.
It has no retention, and it does not remove duplicates when a batch is sent
again. When the spool reaches its disk limit, capture stops. Free space does
not restart it. For supported delivery, use `--request-records-file`.
The proxy and the agent print a warning at startup when the spool is in use.

**A record contains end-user identities and model history.** Protect the
destination. The spool is the place to restrict access.

## What a record holds

The record type is `RequestRecord` in
`crates/proxy-observability/src/records.rs`. These are some of its fields:

| Field | Meaning |
|---|---|
| `request_id`, `event_id`, `instance_id` | Identify the request, the record, and the proxy instance. |
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

## Ways to deliver records

| Mode | Flags or key | Where records go |
|---|---|---|
| File | `--request-records-file` | One JSON line per record, appended to a file you name. |
| Agent | `--request-records-agent` and three more flags | The `llm-capture-agent`, over a Unix socket. The agent commits to an encrypted local spool. |
| Declarative | `node.metadata["io.llmproxy.capture"]` in a `-c` bootstrap | The agent, with limits set in the bootstrap file. |

`--request-records-file` conflicts with `--request-records-agent`. Clap
rejects the two flags together (`crates/proxy/src/main.rs:104`).

The declarative key cannot combine with any CLI capture flag. The proxy
refuses to start with this message
(`crates/proxy/src/main.rs:311-319`):

```text
node.metadata["io.llmproxy.capture"]: cannot combine declarative and CLI capture
```

The `llmproxy` dialect (`--config`) has no capture field. Use the flags, or a
bootstrap file passed with `-c`.

## Run the capture agent

The release archive contains `llm-capture-agent` beside `llm-proxy`
(`.github/workflows/release.yml:74-76`). The installer script copies both
files into the same directory (`scripts/install.sh:241-245`). The installer
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
path. The agent README (`crates/proxy-capture-agent/README.md`) lists the
other limits:

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

## Enable capture in the proxy

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
| `--request-records-file <PATH>` | no | none | Append JSON lines to this file. Conflicts with `--request-records-agent`. |
| `--request-records-agent <SOCKET>` | no | none | Send records to the agent at this Unix socket. |
| `--request-records-agent-uid <UID>` | with agent | none | The OS UID the agent must run as. |
| `--request-records-agent-node <ID>` | with agent | none | The `node_id` the agent must report. The proxy checks it on the handshake and on every receipt. |
| `--request-records-producer <ID>` | with agent | none | The `producer_id` in the agent grant for this proxy. |
| `--request-record-max-attempts <N>` | no | `64` | Attempt summaries to keep for each record. Range 1 to 64. Needs a file or an agent. |

The flags are read at start. A reload does not change them. Source:
`crates/proxy/src/main.rs:102-121`, `:546-553`.

If you set neither `--request-records-file` nor `--request-records-agent`,
capture stays off. Setting `--request-record-max-attempts` alone is an error
because it requires a destination (`main.rs:120`).

### The file destination

`--request-records-file` appends records to the file as JSON lines. The
proxy does not rotate, expire, or restrict the file. Set the access mode and
the retention on the file yourself (`main.rs:102-103`).

### The declarative bootstrap key

You can set capture in a bootstrap file instead of flags. The decoder is
strict. An unknown key fails with its full path
(`crates/proxy-config/src/capture.rs`).

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
the new block, it keeps the previous snapshot (`main.rs:1920-1923`).
Declarative capture also requires `--concurrency` of 8 or less
(`main.rs:321`).

This page does not describe the emergency control protocol. The code
verified here shows only that the two keys are required. Treat the control
socket as a privileged interface.

## What the proxy does when the agent is down

Capture never changes forwarding. The proxy sends a record from a dedicated
writer, with a queue of 1,024 events. The request worker never connects to
the agent. If the agent is down, the proxy keeps serving requests and the
counters below show the lost records. Each event gets at most three transport
attempts in the legacy agent mode, per the agent README.

Retries keep the event ID. A lost acknowledgement can leave a duplicate
record. Treat the spool as at-least-once, not exactly-once.

## Inspect the spool

Two admin endpoints read the spool through the proxy. Both need an agent
endpoint. Both need the producer grant to have `"inspect": true`. An
inspection never acknowledges a record and never changes the spool.

An inspect grant reads every stored record of its tenants, whichever
producer wrote the record (agent README).

### `GET /capture/spool/stats`

This endpoint needs no token. It returns counters and byte sizes only, with
no record contents. The proxy caches the answer for 5 seconds. Concurrent
callers share one agent query, and the cache also holds errors
(`crates/proxy-admin/src/server.rs:203-214`).

```sh
curl --max-time 5 http://127.0.0.1:53422/capture/spool/stats
```

The JSON fields are `node_id`, `next_sequence`, `durable_through_sequence`,
`acknowledged_through_sequence`, `pending_records`, `retained_records`,
`database_bytes`, `disk_bytes`, `max_disk_bytes`, `quarantine_bytes`,
`poisoned`, `durable_total`, `rejected_total`, and `failures_total`
(`admin-ui/src/components/Capture.tsx:12-27`).

### `GET /capture/spool/records`

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
gives `405` (`server.rs:1462-1530`).

### Status codes

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

## The Capture tab in the admin UI

The admin UI has a Capture tab. It shows the spool stats from
`/capture/spool/stats` and refreshes them every 10 seconds while the tab is
visible. It marks a poisoned spool with a red `SPOOL POISONED` banner. The
Records section loads pages of 50 records from `/capture/spool/records` with
the token from the header bar. You can filter the loaded rows by tenant,
user, model, or request ID. The filter works on the rows already loaded in
the browser (`admin-ui/src/components/Capture.tsx`).

## Metrics

All names below appear on `/stats/prometheus` with the `envoy_` prefix, for
example `envoy_llmproxy_capture_agent_reachable`. See
[Metrics and stats](../metrics-and-stats/).

### Spool gauges

The proxy asks the agent for spool stats every 10 seconds. The first poll
runs one period after start. Each poll has a 2-second limit. The poll runs
only when an agent endpoint exists at start. A reload that first adds an
endpoint is not polled until you restart (`main.rs:1191-1202`).

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

The proxy logs on a change only, not on every poll (`main.rs:648-720`):

- `capture agent unreachable: ...` at `warn`, when the agent goes down.
- `capture agent reachable again` at `info`.
- `capture agent spool stats are off: the producer grant lacks "inspect": true; ...`
  at `info`, once.
- `capture agent spool stats are off: the agent closed on the inspection query, ...`
  at `info`, once.

### Record counters

The proxy creates these series at start, so an idle proxy shows `0` and not
a missing series (`crates/proxy-observability/src/stats.rs:769-776`).

| Metric | Labels | Meaning |
|---|---|---|
| `llmproxy_metadata_admission` | `outcome`: `accepted`, `capacity_exceeded`, `closed` | Whether the queue took the record. |
| `llmproxy_metadata_queue_depth` | none | Records in the queue. |
| `llmproxy_metadata_queue_capacity` | none | Queue size. `0` means capture is not configured. |
| `llmproxy_metadata_written` | none | Records delivered. In file mode, an append. In agent mode, a durable local receipt. |
| `llmproxy_metadata_durable` | none | Records the agent confirmed as durable. |
| `llmproxy_metadata_write_failures` | none | Write failures, or deliveries with an unknown result. |
| `llmproxy_capture_state_admission` | `outcome`: `accepted`, `disabled`, `capacity_exceeded`, `closed` | Whether a request got capture state. |
| `llmproxy_capture_active_requests` | none | Requests with capture state now. |
| `llmproxy_capture_state_reserved_bytes` | none | Bytes reserved for request state. |
| `llmproxy_capture_event_reserved_bytes` | none | Bytes reserved for queued events. |
| `llmproxy_capture_drops` | `reason`: `disabled`, `expired`, `encoded_limit`, `delivery_unknown`, `identity_limit`, `transport_capacity`, `agent_rejected`, `unavailable` | Records dropped, by cause. |

I did not verify the precise trigger for each `llmproxy_capture_drops`
reason beyond its name and the tests that increment it
(`crates/proxy-observability/src/capture_tests.rs`). The
`delivery_unknown` reason does not prove the record was lost.

## Limits

- **Local spool only.** The agent writes to a local encrypted spool. No
  upload, no query service, no transcripts, and no billing-ledger guarantee.
- **No expiry.** The agent does not expire or evict records. When the disk
  budget is full, the agent declines new records. Size `max_disk_bytes` for
  the longest outage you plan for.
- **Failure is quiet for traffic.** A metadata failure never changes
  forwarding or readiness. Watch `llmproxy_capture_agent_reachable` and
  `llmproxy_metadata_write_failures`.
- **At least once.** A lost acknowledgement can produce a duplicate record.
- **Memory.** The agent README makes no whole-process memory claim. Set a
  memory limit for the agent process yourself.
- **Shutdown.** The agent waits at most 5 seconds for the writer to drain.
  After SIGKILL a stale socket can remain. Stop the old process, remove that
  socket, and restart. The agent never removes an existing socket.
- **Spool keys.** Keep the key file and the spool files. The spool cannot be
  read without the key.

## Troubleshooting

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
