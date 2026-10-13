# Local metadata capture agent

`llm-capture-agent` receives metadata from `llm-proxy` on an authenticated Unix
connection and commits it to the encrypted local spool. This increment is
**local-spool-only**: no backend upload, query service, automatic reclamation,
transcripts, or billing-ledger guarantee. Committed data is not automatically
expired or evicted. Once storage fills, new records are declined.

## Deployment configuration

Use `llm-capture-agent --config /absolute/path/agent.json`. The strict JSON shape
below is supported; replace paths, numeric UIDs and deployment identifiers.
Prepare the socket directory with mode 0700 and provision an external, regular
32-byte key file with mode 0600. Do not put raw keys in this configuration.

```json
{
  "version": 1,
  "mode": "metadata_spool_only",
  "socket_path": "/srv/llm-capture/metadata.sock",
  "node_id": "deployment-node-1",
  "producers": [
    {"producer_id": "proxy-1", "uid": 1000, "tenants": ["default"]}
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

Configuration fields are required except `spool.cache_bytes`, which defaults
to 4 MiB, and the producer field `inspect`, which defaults to `false`. A grant
with `"inspect": true` may send stats and records queries on its connection;
records are limited to the grant's own tenants, and inspection never
acknowledges or changes the spool. An inspect grant reads every stored record of
its tenants, whichever producer wrote it. Grants without it are refused
(`unauthorized`) and disconnected. Unknown fields fail at their full path. Config files
are limited to 128 KiB; version and mode have exactly the values above. IDs are
1–128 UTF-8 bytes; node/event IDs reject control characters so receipts fit their
encoded control-frame bound. Grants allow at most 256 producers, unique producer IDs and
UID mappings, and 1,024 tenant entries total (each 1–512 bytes; no wildcard).
At most 16 deployment keys are loaded. Record size is at most 512 KiB, total
logical disk at most 1 TiB, and redb cache size is 1 byte–16 MiB (default 4 MiB).
The database must have at least 2 MiB of disk budget.

The agent authenticates OS peer UID plus the configured producer ID, then checks
each record's tenant grant. The proxy authenticates agent UID and expected node
identity. The socket is mode 0600 inside a private directory; the initial normal
deployment runs the two processes under the same trusted UID. Do not assume
different UIDs can traverse the private directory or access the socket. This is
not protection against hostile processes running under the same UID or root.
Mount/provision private paths and resource limits explicitly for a sidecar.

## Enable the proxy

```text
llm-proxy -c /absolute/path/bootstrap.yaml \
  --request-records-agent /srv/llm-capture/metadata.sock \
  --request-records-agent-uid 1000 \
  --request-records-agent-node deployment-node-1 \
  --request-records-producer proxy-1
```

These are boot-only deployment flags, independent of routing reloads and
operational exporters. They do not implement the broader capture-policy IR
proposal. `--request-records-file` conflicts with agent mode; the legacy JSONL
path and its semantics are unchanged. `--request-record-max-attempts` remains
1–64, default 64. Capture stays off when neither destination is supplied.
The separate [strict capture runtime](../../internal-docs/end-user-capture-runtime.md)
supports `node.metadata["io.llmproxy.capture"]`, including bounded policy/IR
consumers, SIGHUP reload, and authenticated emergency control. It cannot be
combined with these legacy CLI destinations. No simple-config capture fields
or body/backend knobs are supported.

The proxy never connects or serializes on a request worker. One dedicated writer
owns a persistent connection and a 1,024-event queue, with at most 2 MiB retained
per event plus channel overhead and one in-flight record. Serialization has a
512 KiB encoded frame ceiling. Metadata failure never changes forwarding or
readiness and never invokes a synchronous fallback. Existing per-stream caps
are unchanged; this increment does not implement the proposal's global active
capture-state supervisor or claim a whole-proxy memory cap.

Each legacy event has at most three transport attempts with bounded phase/event deadlines,
with finite reconnect jitter. Exhaustion records failed/unconfirmed delivery;
later events can reconnect. It is not proof that an ambiguous event was lost.
Retries preserve the event ID but may append duplicates after lost ACKs. Without
a backend, this increment makes no exactly-once visible-record guarantee.

## Collector and durability bounds

Version-1 frames use a nine-byte header with kind and declared length. All frame
lengths are validated before allocation: 512 KiB records and 1 KiB control
messages. Handshake and receipt versions/identity are checked. Unknown schemas,
oversized identifiers, undeclared fields (including bodies/headers), and tenants
outside the producer grant are declined before storage.

The agent admits at most eight connections and has an eight-event writer queue.
Each connection has one in-flight record; a semaphore also bounds tasks. The
single spool writer takes the first queued record, adds whatever else is
already queued (eight at most), and commits that batch at once. It never waits
for a fuller batch, because a connection sends nothing more until its receipt
arrives. The one exception is the connections the previous commit answered:
they send again only after it returned, so a batch missing any of them waits up
to 2 ms for exactly those connections, which keeps concurrent producers in one
batch instead of alternating half-size cohorts. A lone connection never waits,
and open but idle connections are never waited for. Records that arrive during
one commit's fsync form the next batch, and collecting a batch is capped at
50 ms. Handshakes/receipts have two-second
deadlines; idle reads expire after 30 seconds. Frame buffers, queue payloads
and batching are each bounded, but JSON parsing/serialization and spool crypto
add transient allocations. Enforce an independently provisioned process
memory/CPU limit; no measured RSS or 5,000-RPS performance claim is made.

In spool-only mode, repeated commits can exhaust the disk budget; size it for
the intended finite run/outage and observe declines. One durable checkpoint reserves the
whole batch's sequence range before payload encryption; gaps are allowed
but sequence reuse is not. An Immediate transaction atomically commits records
and authenticated inventory before durable receipts. Storage failures, including
database growth at the disk ceiling, poison the writer and report unavailable.
An unavailable receipt after transmission does not establish that the payload
was rejected; recovery can find a committed record whose receipt was lost. No silent eviction or fake backend acknowledgement is
used to keep admission running. Replay/checkpoint/reclaim remain explicit
library APIs for a future confirmed backend adapter.

`envoy_llmproxy_metadata_durable` counts authenticated matching durable ACKs in
the proxy; `metadata_written` counts successful selected-mode deliveries, and
`metadata_write_failures` includes rejection or unknown delivery. Existing
admission/queue series remain label-bounded and are exported to scrape and OTLP.
The agent exposes process-local counters through `Agent::health` and prints a
bounded aggregate summary at shutdown, not request bodies or credentials.

SIGTERM/SIGINT stop connections, close writer admissions, and wait at most five
seconds for writer drain. A blocked fsync cannot be forcibly cancelled; timeout
means unknown durability, resolved by restart. Graceful exit removes the owned
socket. After SIGKILL, a stale socket may remain: confirm the old process has
stopped before removing that exact socket and restarting. Startup never unlinks
an existing endpoint. Preserve keys and spool files. See the
[spool assumptions](../proxy-capture-spool/README.md) before claiming device,
power-loss, or replicated durability.

## Verification

Use `make tq-proxy-capture-protocol`, `make tq-proxy-capture-agent`,
`make t1 CRATE=proxy TEST=metadata_agent`, then `make tq-changed`, `make tq`,
`make tq-doc`, and workspace lint/dependency checks. Local socket and upstream
tests require sandbox permission to bind isolated endpoints. Backend, transcript,
and scale qualification remain separate work. The proxy's
[strict capture runtime](../../internal-docs/end-user-capture-runtime.md) now
provides policy reload and authenticated emergency control, independently of
this agent's deployment configuration.
