# Operational and end-user telemetry design

Status: implementation handoff proposal. Date: 2026-10-01.
Scope: operational telemetry and end-user request records/transcripts. This document does not implement either extension or change existing configuration semantics.

## 1. Decisions and ownership

Two domains have independent policies, resources, storage, access, and failure behavior:

1. **Operational telemetry** answers whether llm-proxy and its dependencies are healthy. Service operators own metrics, diagnostic traces, and service logs.
2. **End-user telemetry** answers what happened to a tenant's requests. Tenants and authorized users consume request records and optional transcripts. Request records and transcript content are separate pipelines within this domain.

A single request can contribute to both domains, but delivery to one never depends on delivery to the other. Request IDs and trace IDs provide correlation. They are not metric labels.

Authoritative spend accounting remains a third, existing policy concern. Neither telemetry pipeline becomes a billing ledger. Telemetry delivery failure must not undo charges, change budget enforcement, or use capture drops as evidence of zero usage.

The primary forwarding function must continue during telemetry outages. Capture is best effort until a collector durably commits it. Strong audit durability is outside this design; it would require a separate latency and availability contract.

## 2. Current implementation and integration points

Inspect these paths before editing; comments describing older behavior can be stale, so verify callers:

- `crates/proxy-observability/src/stats.rs`: in-memory counters, gauges, and histograms.
- `crates/proxy-admin/src/server.rs`: `/stats` and `/stats/prometheus` rendering and administrative spend APIs.
- `crates/proxy-observability/src/trace.rs`: bounded `SpanSink` and nonblocking `try_send`.
- `crates/proxy-observability/src/otlp.rs`: trace batching and cumulative metric export. Failed trace batches are currently discarded. Metrics are snapshots, not durable events.
- `crates/proxy/src/main.rs`: starts the OTLP exporter when tracing is configured. Independent metrics export needs its own configuration/lifecycle.
- `crates/proxy-http/src/access_logging.rs`: `LoggingBody` finalizes metadata at response completion, error, or drop. It currently supplies `llm_user_id: None`.
- `crates/proxy-observability/src/access_log.rs` and `sink.rs`: formatting and stdout/stderr/buffered append-file writers. Current writers can perform synchronous I/O on their caller.
- `crates/proxy-http/src/stream_info.rs`, `router.rs`, and `filter_manager.rs`: request state, upstream attempts, body transforms, and streaming lifecycle.
- `crates/proxy-filters/src/usage_filter.rs`: terminal usage extraction and pricing attribution.
- `crates/proxy-control/src/control.rs` and `spend/recovery.rs`: control-plane state, durable aggregate spend, and recovery checkpoints. The control store deliberately excludes request history.
- `crates/proxy-config/src/ir.rs`: configuration boundary. Other crates must consume IR, not generated Envoy configuration protos.

Read `AGENTS.md`, the pricing design brief, and the applicable S1–S10 sections of `internal-docs/envoy-semantics.md` before implementation. Existing Envoy metrics and access-log formatting are compatibility surfaces.

## 3. Scale assumptions and budgets

Design workload: sustained 5,000 logical requests/second, with streaming and multimodal traffic. At this rate there are 432 million requests/day. At an average 20-second duration, approximately 100,000 requests are active concurrently.

Illustrative combined captured request/response volume, before indexes and replication:

| Average bytes/request | Throughput | Daily volume |
| --- | --- | --- |
| 1 KB metadata | 5 MB/s | 432 GB |
| 10 KB content | 50 MB/s | 4.32 TB |
| 100 KB content | 500 MB/s | 43.2 TB |
| 1 MB content | 5 GB/s | 432 TB |

RPS is insufficient for sizing. Measure bytes/second, active streams, events/second, stream duration, amplification from upstream attempts, and retained allocation sizes. Compression ratios must be measured separately for text and already-compressed media.

Every queue has event and retained-byte limits. Every process has a total memory budget. Tenant, request, direction, and spool limits are additional constraints, not replacements for a global cap. A proposed initial configuration must state all limits numerically and fit the deployment memory/storage budget before scale validation.

Spool capacity = captured bytes/second × supported outage seconds, plus measured framing/index overhead and headroom. Upload capacity must exceed steady-state capture to drain backlog. Recovery time = backlog bytes / (upload throughput − incoming throughput), when the denominator is positive.

## 4. Architecture

```text
Proxy request workers
  ├─ bounded metric updates ── operational registry ── scrape / OTLP
  ├─ sampled diagnostic spans ── operational exporter ── trace backend
  ├─ bounded request records ── metadata queue ─┐
  └─ bounded content chunks ── content queue ───┤
                                               v
                                     delivery workers
                                               v
                                     collector (retired: see section 8)
                                      ├─ metadata durable spool → analytics store
                                      └─ content durable spool → object storage
                                                                    ↓
                                              tenant query API ← manifests/index
```

The capture agent was a separate process/sidecar with independent CPU, memory, disk, network, and concurrency limits. In-process transport runs outside request workers. Operational export must not share a congestible queue or worker pool with content processing.

The initial backend target is batched request records in ClickHouse and transcript objects in S3-compatible storage. Put backend-specific code behind collector interfaces. A broker is not required for the first implementation; add one only for replay or independent consumers. Backend/client versions and exact insertion/consistency semantics must be verified against official documentation when selected.

## 5. Operational telemetry

### 5.1 Signals and audience

Operators need:

- Forwarding: logical request rate, status classes, latency, active streams, downstream disconnects, timeout categories, rejected requests, and response flags.
- Upstreams: attempt rate, latency, connection/pool health, retries, fallback, circuit breaking, health checks, and outlier ejection.
- Process: worker saturation, event-loop lag, memory, connections, runtime task health, and shutdown progress. Platform CPU/disk/network metrics may come from the deployment monitor; do not invent them from application counters.
- Control plane: accepted/rejected config updates, active routing revision/policy generation in diagnostic status, reload latency, and reconciliation failures.
- Telemetry: export failures, queue utilization, drops by bounded reason, spool bytes/age, recovery errors, upload lag, and backend failures.

GenAI aggregate token/cost signals may remain operational where already supported. Individual customer history remains in end-user records. Operational metrics are never the authoritative source for customer billing.

### 5.2 Metric contract

Preserve existing Envoy-compatible stat names and histogram semantics. Add a separate documented namespace for new capture metrics, such as `llmproxy_capture_*`; names here are proposed until the instrument catalog is approved.

Define for every instrument: name, type, unit, description, aggregation, allowed attributes, and update point. Counters are monotonic within a process lifetime; gauges describe current state; histograms record one observation per documented lifecycle event. Export process-start identity/time so restarts can be interpreted.

Allowed dimensions must have bounded cardinality: configured cluster, configured listener, status class, finite termination category, capture direction, pipeline, and finite failure reason. Never label by raw user/key/request/trace IDs, arbitrary URL, prompt, header value, or unbounded model name. Bound dynamically configured cluster/model series and define retirement behavior. Preserve existing tenant-labelled compatibility metrics initially; document their cardinality and introduce explicit limits before adding more tenant dimensions.

Resource attributes include service name/version, instance identity, environment, and region. Do not encode revisions as an ever-growing family of metric labels; expose current versions through status or bounded informational state.

### 5.3 Export and persistence

- Prometheus scrape remains available without OTLP or tracing.
- Configure OTLP metric export independently of trace sampling/export. Disabling traces must not disable metrics.
- Separate metric and span scheduling/deadlines so a slow trace RPC cannot indefinitely delay metric snapshots.
- Export metrics cumulatively using the current registry contract. An unsuccessful snapshot can be superseded by a later snapshot; interval histograms must not be cleared on failed export.
- Span queues and batches are bounded. Export retries, if added, have bounded duration/bytes and explicit loss counters. No disk spool is required inside the proxy for operational signals.
- Shutdown order matters. Take the final metric snapshot only after the drain has finished and the trace exporter has flushed its last batch (bounded by a budget), so the snapshot includes drain-period traffic plus the exporter's own failure and drop counts. Taking it before the drain loses drain-period traffic and adds up to one export deadline to every shutdown. Each wait is bounded, so an unreachable collector cannot hang exit; a missing final snapshot is logged and does not change the exit code.
- Durable historical retention belongs to the operational collector/backends. This proposal does not persist the live registry across restarts.

### 5.4 Traces and service logs

Use sampled traces for forwarding and attempt diagnosis. Attributes include bounded model/provider context, timing, status, error category, and correlation IDs. Bodies and credentials are excluded. Tenant identity in traces is an explicit operator policy, not a default entitlement to customer content.

Service logs describe lifecycle, configuration, and failures. Rate-limit repeated exporter errors. Do not emit arbitrary upstream error bodies or credential-bearing URLs. Distinguish diagnostic service logs from legacy access logs and structured customer request records.

### 5.5 Alert behavior

Alert on forwarding availability/latency and worker health separately from telemetry degradation. Capture backend failure must not fail proxy readiness by default. Aggregate drop counters are the dependable signal when a per-request loss event cannot itself be delivered.

## 6. End-user telemetry

### 6.1 Policy and isolation

Request records are independently configurable from transcript capture. Body capture is opt-in. Policies come from immutable in-memory snapshots, evaluated at admission; workers never query disk or remote stores.

Normalize missing tenant to reserved `default` at the boundary. Use authenticated identity, not a body-supplied `user_id`, for access ownership. If an application-provided user identifier exists, store it separately with explicit trust semantics. Until authenticated user identity is wired, records carry `user_id: null`; never fabricate one.

Pin capture policy version at request admission. Record routing revision, policy generation, and pricing version separately. Security revocation must take effect independently of routing rollout; an emergency capture-disable generation can stop ongoing body capture without retroactively changing its original policy attribution.

Tenant/user access and deletion apply to metadata, manifests, objects, spool content, caches, and backups according to an explicit retention contract.

### 6.2 Logical request record, schema v1

Use a versioned envelope and stable opaque internal request ID. Do not trust caller-provided request IDs for uniqueness or authorization; retain a sanitized external correlation ID separately if enabled.

Required envelope fields:

- `schema_version`, `event_id`, `request_id`, `instance_id`, `started_at`, `finished_at`.
- `tenant_id`, nullable authenticated `user_id`, nullable non-secret `key_id`.
- Nullable `trace_id`; recording does not require trace sampling.
- `routing_revision`, `policy_generation`, `capture_policy_version` when applicable.
- Request method and bounded route/path representation; raw query strings are excluded by default.
- Requested model/alias, selected cluster/provider, selected upstream model.
- HTTP status when known, finite termination reason, response flags, sanitized error category.
- Duration, time to first response byte, time to first token only when semantically known, bytes forwarded in each direction.
- Nullable usage: noncached input, cache-read, cache-write, output tokens; usage provenance/completeness.
- Nullable cost: integer amount, unit, currency, rate-card version, and cost kind. Keep existing list-cost nanodollars distinct from spend-accounting micro-dollar charges; never silently convert or conflate them.
- Attempt count, bounded attempt summary/reference, capture state summary, transcript manifest reference when available.

Unknown usage/cost stays null, not zero. Failed, unauthenticated, rejected, and disconnected requests still produce records where possible; absent identity or upstream fields remain null or normalized according to boundary rules. The telemetry record must reflect the cluster actually dialled after fallback.

One immutable terminal request event is emitted at most once in-process. Delivery is at least once after durable spooling, so the index must deduplicate by event ID. Capture availability changes are separate versioned events; do not overwrite request facts merely to update an upload state.

### 6.3 Attempt record

Model logical requests and physical attempts separately:

- Request ID, attempt ID/index, parent trace/span reference, attempt event ID.
- Cluster/provider/upstream model, endpoint information subject to disclosure policy.
- Start/end timestamps and monotonic duration, status/termination, retry/fallback reason.
- Directional forwarded byte counts and content capture references.
- Usage/cost attribution only when known, with provenance and accounting classification.

Attempt count has an enforced configured maximum. Record intermediate unsuccessful attempts even if the final request succeeds. Terminal request usage must not accidentally sum duplicated provider usage from retries. Telemetry may report observed attempt usage separately; authoritative accounting decides what is charged.

### 6.4 Capture boundaries

Supported directions are explicit:

1. `downstream_request`: what the proxy received before provider/model/body transformations.
2. `upstream_request`: what was sent for each physical attempt after transformations.
3. `upstream_response`: what was received for each attempt before downstream transformations.
4. `downstream_response`: what was delivered toward the client after transformations.

A content chunk is observed at a documented body boundary. This captures HTTP entity bytes, not TLS records or necessarily identical HTTP transfer framing. Record content type/encoding and boundary semantics. If decompression or normalization occurs, store the source representation and transformation version; do not label normalized content as exact wire data.

Capture at existing read/forward points; do not force buffering, pre-read a stream, change chunking, or make a non-replayable body replayable. Request-body collection paths and local replies need explicit integration coverage. A failed attempt must not lose its association when router state switches to the next provider.

WebSocket, CONNECT, and other upgraded sessions are excluded from initial text capture. Expose `unsupported_protocol` rather than implying a complete transcript. Their future implementation needs frame/session contracts and bounded checkpoints.

### 6.5 Content events and manifests

A chunk envelope contains schema version, request ID, optional attempt ID, direction, sequence number, observed byte offset, observation time, payload length, payload, and capture policy version. Content type and sanitized headers belong in start metadata. End events record observed/captured totals, expected final sequence, termination, and capture outcome.

Use separate sequence spaces for each request/attempt/direction. Sequence assignment occurs before enqueue so missing chunks can be detected. Capture budgets are checked before retaining payload allocations. Chunking into export segments happens outside the request path.

A manifest maps each direction to ordered segments/objects, offsets, lengths, checksums, representation, and completeness. It records missing ranges where known and `unknown_tail` where a crash prevents an exact accounting. It distinguishes capture completeness from request success: an error response can be fully captured; a successful response can have partial capture.

Keep two independent state axes:

- Capture outcome: `disabled`, `complete`, `partial`, `not_captured`, `unknown`; include finite reason codes such as `policy`, `sampled_out`, `request_limit`, `tenant_limit`, `queue_full`, `agent_unavailable`, `unsupported_protocol`, `crash`, `redaction_failure`.
- Delivery stage: `memory`, `durable_local`, `objects_committed`, `indexed`, `expired`, `failed`.

`complete` requires a known terminal event and contiguous captured bytes for every policy-required direction. EOF caused by client abandonment is not proof of complete response capture. Loss of a terminal event leaves an orphan/unknown record for asynchronous reconciliation.

## 7. Hot-path contracts and resource accounting

The worker may read an immutable policy, update bounded state/counters, generate IDs, and make immediate enqueue attempts. It must not await capacity, serialize JSON, compress, parse transcript content, write files, upload, retry, or spawn an unbounded task per chunk.

Define an internal nonblocking sink interface with explicit results: accepted, disabled, capacity exceeded, closed. Rust result types must distinguish these outcomes. No remote-store clients belong in `proxy-http` or request filters.

A byte reservation travels with each queued event and is released on consume/drop. Account retained allocation size, not just slice length: a small `Bytes` slice can retain a much larger parent allocation. If the allocator backing size cannot be established safely, use bounded independent copies with an explicitly measured copy budget or decline capture. No `unsafe` workaround.

Cap per-stream state. Once a direction exceeds its budget, stop capturing that direction for the rest of the request and retain a bounded reason/missing-range summary; do not repeatedly allocate/drop chunks. Bound metadata fields, header count/bytes, event size, active capture state, and loss-range count. Unlimited rejected-identity cardinality must not create unlimited tenant quota entries.

Metadata has reserved capacity independent of content. Completion/loss events have reserved control capacity, but still cannot be guaranteed during total process failure. A content flood cannot exhaust operational telemetry or metadata memory. Agent transport is bounded and uses explicit frame/message sizes, deadlines, and reconnect backoff. Unix-domain socket or localhost authenticated transport is acceptable; never connect anew for every request.

Legacy synchronous access logs remain a compatibility surface. Add bounded asynchronous writers and explicit queue/drop behavior before enabling high-volume structured export. Formatting must also move off workers using bounded owned snapshots. A collector failure must not trigger a synchronous file/stdout fallback on a worker.

## 8. Capture agent and durable spooling

Retired 2026-10-21 (removal ships in 0.7.0). The capture agent
(`llm-capture-agent`), its protocol and its declarative
`io.llmproxy.capture` policy were removed. Body export is trace export
(`internal-docs/adr/0008-trace-export.md`, `internal-docs/trace-export-design.md`);
request metadata goes to the JSONL file sink (`--request-records-file`) and the
billing ledger (ADR-0009). The encrypted spool crate `proxy-capture-spool`
stays because the ledger is built on it. The text that stood here described a
design that was never fully built; the repository history has it.

## 9. Remote storage and querying

### 9.1 Request index

Batch by bounded rows, bytes, and time. Persist logical requests, attempts, and capture-state events as separate versioned datasets. Index principally by tenant, time, request ID, user identity, status, and configured model/provider dimensions. Explicitly choose backend deduplication semantics: ClickHouse insert acknowledgement alone does not define unique-row behavior. Queries must resolve duplicate event IDs and latest manifest versions correctly.

Maintain separate metadata delivery state from content delivery state. Metadata can become queryable before a transcript; show `pending` or partial capture truthfully.

### 9.2 Transcript objects

Batch small text records into independently readable compressed segments; large media may use dedicated objects. Do not create an object for each SSE frame. Bound retrieval work for one transcript. A manifest identifies object key, version, byte range, codec, checksum, and encryption key reference.

Group shared objects within compatible tenant, residency, encryption, and retention boundaries. Cross-user segments are permitted only if the query service enforces access and never gives users a signed URL granting the whole shared object. Physical deletion of one record in a shared object requires rewrite/compaction or a documented cryptographic deletion scheme.

Upload content first, confirm object integrity, then publish the manifest/index availability event. Deterministic segment IDs/object keys and stable event IDs make replay idempotent. On restart, uploads may be repeated; avoid duplicate visible transcripts. Multipart uploads have bounded part concurrency and lifecycle cleanup.

An asynchronous reconciler resolves uploaded-but-unindexed objects, abandoned uploads, orphan starts, stale manifests, and deletion backlog. It does not infer complete capture from object existence alone.

### 9.3 Query API

Run tenant-facing querying outside the proxy request runtime. APIs support bounded time-range listing, cursor pagination, request detail, attempt detail, and transcript retrieval. Apply authenticated tenant scope to every query and authenticated user scope to user-level queries. Tenant administrators need an explicit grant for tenant-wide inspection.

Authorize before returning manifests or signed URLs; recheck on retrieval. IDs and object keys are not authorization. Enforce maximum result rows, response bytes, query duration, and download size. Audit content access through a separate bounded security event mechanism. Transcript availability failure must not affect proxy requests.

## 10. Multimodal behavior

Policy modes: metadata only; bounded text; sampled content; selected full content within quotas; media references; retained media copies. Full means all policy-selected directions observed within limits, not unlimited capture.

Inline base64 and multipart content is extracted asynchronously with bounded parser/staging budgets. Preserve originals only when policy allows; identify normalized text/media derivatives separately. Malformed multipart content cannot grow buffers indefinitely.

Remote URL capture stores a sanitized reference; it does not guarantee retained media. Background fetching is a separate opt-in service with destination restrictions, size/time limits, redirect validation, and separate authorization. Do not fetch private-network endpoints merely because a prompt references them. Do not log signed URL credentials.

Initial text delivery excludes media archival and remote fetch. Metadata explicitly reports skipped media/unsupported representation. Never put prompts, transcripts, images, or video in metric labels or operational trace attributes.

## 11. Configuration and compatibility

Introduce separate IR domains for operational export and end-user capture. Proposed configuration concepts, not accepted YAML yet:

- Operational: metrics scrape/export enablement, endpoint, interval/deadline, trace sampling, span queue budgets, resource attributes.
- Capture: metadata enablement, local agent endpoint, queue budgets, policy snapshot/version, selected directions, sampling, header allowlists, body limits, tenant quotas, emergency disable.
- Agent: spool location/budgets/durability, storage destinations, credentials, encryption/residency, retries, batching, retention/deletion.

Defaults: existing operational behavior preserved; new transcript capture disabled; no remote destination or storage credentials guessed. Sampling uses a stable hash of internal request ID and policy version so all selected directions agree.

Every field maps to IR or fails with its full dotted path in strict mode. Generated config protos stay within established config/xDS boundaries. Simple configuration may expose only capabilities implemented in Envoy mode; update `schema/llmproxy-v0.schema.json` when that dialect gains support. Do not publish example YAML until parser/schema/tests support it.

Collector credentials belong to deployment/export configuration, not model routes. Provider credentials, Host rewriting, usage dialect, and pricing remain on provider clusters. No telemetry policy can let a tenant choose a provider or weaken identity restrictions.

Pin request policy snapshots; configuration updates must not reinterpret already-spooled data. Version event schemas and tolerate documented rolling-upgrade compatibility. Unknown schema versions are quarantined, not silently parsed as the current schema.

## 12. Failure matrix

| Failure | Forwarding | Operational outcome | End-user outcome |
| --- | --- | --- | --- |
| Operational collector unavailable | Continues | Bounded export failures/drops; scrape remains | Independent |
| Content queue full | Continues | Bounded reason counters | Stop affected capture; metadata prioritized |
| Metadata queue full | Continues | Metadata-loss counter | Request record may be absent |
| Remote storage unavailable | Continues | Spool growth/lag metrics | Retry durable records within spool policy |
| Spool full/unwritable | Continues | Capture health degraded | Decline new capture; preserve committed backlog |
| Proxy crash | Interrupted requests | Process reset visible | Memory-only events lost; incomplete tails unknown |
| Agent crash | Continues | Reconnect/recovery health | Replay durability-committed spool |
| Node/volume loss | Deployment-dependent | Instance failure visible | Local-only durability may be lost |
| Redaction/parser failure | Continues | Finite reason counter | No unauthorized raw fallback |
| Object upload succeeds, index fails | Continues | Reconciliation backlog | Content unavailable until reconciled |
| Deletion requested | Continues | Deletion backlog metrics | Access revoked; physical cleanup follows contract |

## 13. Shutdown and lifecycle

On graceful shutdown stop new admissions, let forwarding drain under existing rules, finalize observed streams, close capture producers, drain bounded queues to the agent within a deadline, then stop exporters. Report timeout losses; shutdown does not wait indefinitely for remote storage.

The agent seals and durability-commits pending segments within its own shutdown deadline. Remote upload can resume after restart. A proxy's graceful queue drain only proves delivery to the agent at the acknowledgement level actually received; do not imply durable storage from socket send success.

## 14. Implementation stages and acceptance

### Stage 1: contracts and operational independence

Scope: IR/config semantics, instrument catalog, independent metric export, bounded operational trace scheduling and counters. No body capture.

Acceptance: metrics export with traces disabled; scrape without OTLP; slow/failing trace export does not starve metrics; registry restart semantics documented; existing Envoy conformance remains green; strict unknown-field rejection.

### Stage 2: asynchronous request records

Scope: owned bounded record types, logical/attempt lifecycle events, authenticated identity wiring, independent metadata queue, asynchronous legacy sink option, local capture transport, metadata agent spool, batched index adapter.

Acceptance: terminal record exactly once in-process on success/local rejection/disconnect/error; replay deduplicates visible records; fallback attribution uses actual provider; absent usage remains null; overload causes no awaited worker work; secret headers excluded; cross-tenant/user queries rejected. Complete metadata-only end-to-end delivery before adding bodies.

### Stage 3: bounded text transcripts

Scope: explicit directional tee points, byte accounting, sequence/end events, content spool, compression, objects/manifests, retrieval and reconciliation.

Acceptance: arbitrary chunk boundaries, transforms, SSE, partial disconnects, and failed attempts preserved correctly; content-disabled path has no body retention; large backing allocations remain bounded; missing middle/tail chunks never appear complete; object commit precedes availability; crashes at each commit boundary replay safely.

### Stage 4: multimodal and retention

Scope: multipart/base64 extraction, media policies, scoped object grouping, deletion/compaction, optional separately authorized URL fetch service.

Acceptance: bounded malformed input handling; policy-respecting raw/normalized representations; media skipping explicit; shared objects cannot bypass user scope; deletion removes access immediately and physical data within the promised window.

### Stage 5: scale and failure qualification

Scope: sustained traffic, long streams, resource isolation, controlled crashes/outages, and operational runbook.

Acceptance: sustain 5,000 RPS on documented hardware/traffic profile; measure disabled versus metadata/text/full capture; publish throughput, p50/p95/p99 forwarding latency and time to first token, CPU, peak memory, retained bytes, lag, spool growth, drop rate, and recovery time. Test 100,000 concurrent streams only on a harness/hardware sized for that profile.

Provisional performance gate: no more than 5% p99 forwarding/first-token regression for metadata-only capture and 10% for bounded text capture at the declared workload, with queues/spool below capacity and stable memory. These are implementation targets requiring owner review against the existing baseline, not measured claims. Report absolute latency too. At saturation, forwarding remains within its separately agreed production SLO while capture degrades explicitly.

## 15. Verification plan

Use repository `make` targets, not bare `cargo test`. After each substantive edit run the narrowest relevant target; then `make tq-changed`; before landing run `make tq` and `make tq-doc`, plus `make ci` where required. Check `make tq-count` when tests change.

Required meaningful tests:

- Unit: policy evaluation, byte reservations/drop release, schema bounds, sequencing, completeness, money units, secret stripping, spool checksums/version rejection, deduplication.
- Local-server integration: actual router/filter/LoggingBody paths, request transforms, streaming response forwarding, retries/fallback, local replies, collector ACK boundaries, analytics/object adapters.
- Recovery: SIGKILL before/after group commit, torn segment/footer/checkpoint, replay after upload before indexing, corrupt length fields, unavailable encryption keys, disk full, volume loss simulation.
- Isolation: one tenant flooding large payloads cannot consume reserved metadata or operational budgets; capture outage does not fail forwarding readiness; user-scoped queries cannot enumerate another user's records.
- Lifecycle: config reload, emergency disable, identity revocation, shutdown deadlines, interrupted delivery and orphan reconciliation.

Use existing harnesses where possible, bound requests and servers with timeouts, clean up processes, and check orphan listeners. Record hardware, traffic distribution, payload/stream sizes, capture policy, and backend conditions alongside benchmark results. Green unit tests alone do not establish hot-path isolation or durability.

## 16. Agent handoff constraints and deliverables

Begin with the smallest relevant call site and nearby integration test. Preserve unrelated user changes. Do not commit unless requested. Architecture/IR/Envoy semantic changes require review before broad implementation. Avoid adding a large generic telemetry framework or introducing a broker before the first end-to-end lane works.

Suggested ownership: reuse `proxy-observability` for operational signals; keep end-user event/policy contracts in a narrowly scoped capture module or crate; keep transport/storage/recovery in a separate agent binary/library; keep tenant query service outside the forwarding runtime. Exact crate names are implementation decisions, not an instruction to create all crates immediately.

Before coding each stage, provide: explicit touched file list, IR/API changes, resource budgets, delivery contract, migration impact, and validation command. After completing it, report changed files, measured validation, remaining limitations, and unrelated failures. Do not claim the stage complete while its integration path or failure behavior is untested.

First implementation task: deliver Stage 1 and reviewable schema/interface definitions for Stage 2. Establish independent metrics export and bounded operational behavior before enabling customer content capture. Subsequent stages must preserve the two-domain separation throughout configuration, queues, runtime scheduling, storage, access, and failure handling.
