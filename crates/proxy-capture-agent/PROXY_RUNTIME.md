# Strict metadata capture runtime

Unix local-spool-only capture is independently configured through
`node.metadata["io.llmproxy.capture"]`. No body/header capture, remote backend,
query API, or automatic spool reclamation is supported. The simple v0 dialect
continues to reject capture configuration.

```yaml
node:
  metadata:
    io.llmproxy.capture:
      version: 1
      metadata:
        enabled: true
      policy:
        version: deployment-1
      endpoint:
        unix_socket_path: /srv/llm-capture/metadata.sock
        expected_agent_uid: 1000
        expected_node_id: deployment-node-1
        producer_id: proxy-1
      emergency_control:
        unix_socket_path: /srv/llm-control/capture.sock
        operator_uid: 1000
```

Provision private (0700) socket directories and the agent's producer/tenant
grants separately. The control socket is created with mode 0600. Existing
control paths are never unlinked at startup. Configure at most eight forwarding
workers (`--concurrency 8` or lower): the fixed terminal scratch allowance is
sized for eight simultaneous owners. Forwarding without capture has no
such restriction. Paths must be absolute Unix filesystem paths, at most 103
UTF-8 bytes. Unsupported fields, including bodies/backends, fail at full paths,
even in permissive mode. Integers must be finite, integral, representable, and
within explicit bounds. Disabled namespaces allow only version and enabled.
Any capture namespace, including explicit disablement, conflicts with legacy
file/agent CLI destinations. Legacy maximum-attempt tuning requires a destination.

Policy defaults: eight retained attempts, 64 KiB retained terminal record,
512 KiB encoded record. Limits may be narrowed using `metadata.max_attempts`
(1–64), `max_record_retained_bytes` (4–64 KiB), and
`max_encoded_record_bytes` (4–512 KiB). Effective `capture_policy_version` is
the operator label plus SHA-256 of normalized metadata limits. Destination
changes do not change disclosure identity. Trusted tenant/key identities over
128 bytes decline capture instead of being truncated. Missing trusted routing
revision, access-policy generation, user identity, and provider identity remain
null; no live store lookup or publication-counter substitution is performed.

Budget defaults in `budgets`:

- `max_active_requests`: 4096; `max_request_state_bytes`: 65536.
- `max_queue_events`: 1024; `max_queue_retained_bytes`: 67108864.
- `max_in_flight_events`: 8; `max_transport_retained_bytes`: 16777216.
- `max_capture_memory_bytes`: 402653184.

Admission reserves a full active-state slot before minting IDs/attempts. Attempt
retention additionally stops at a conservative 4096-byte base plus 4096 bytes
per attempt, so a state limit can truncate before the attempt-count limit.
Terminal event/byte capacity is reserved before cloning attempt summaries and
building a record. The full maximum record reservation travels through queue,
serialization, and acknowledgement; dequeue does not release it. This is
conservative capacity reservation, not measured allocation/RSS. Config sums
include 48 MiB fixed snapshot/control, bookkeeping, scratch, and headroom;
transport validation includes encoded output, input/decoder, and staging.
Delivery uses up to eight reusable authenticated sessions on one dedicated
runtime, capped by `max_in_flight_events` and the shared transport byte budget.
Each socket requests 64 KiB send/receive buffers and rejects reported capacities
above 128 KiB in either direction (allowing Linux's bookkeeping multiplier).
Current and draining destinations use the same slots and reservations; reload
reductions below live in-flight ownership are rejected. The initial agent
admits eight clients, so configured ceilings above eight do not expand this
deployment profile. No forwarding worker performs serialization or socket I/O.
Encoded output is bounded while writing,
including escaping, before transport. Capture overload never blocks forwarding.

Transport defaults in `transport` (seconds): connect 0.25, write 1, ACK 2,
event 10, initial backoff 0.05, maximum backoff 5, drain 5; maximum attempts 4.
Field names are `connect_deadline_seconds`, `write_deadline_seconds`,
`ack_deadline_seconds`, `event_deadline_seconds`, `backoff_initial_seconds`,
`backoff_max_seconds`, `drain_deadline_seconds`, and `max_attempts`.
Every phase/retry is bounded by the remaining event age, measured from enqueue.
Retries use bounded uniform exponential jitter and preserve event identity.
New sends/retries require at least `min(ack_deadline, 100 ms)` remaining; this
guard is not a prediction of filesystem completion. A possibly sent copy stays
unknown even if a later copy is explicitly rejected. Known agent rejections
and never-sent connection failures have separate finite drop reasons
`agent_rejected` and `unavailable`.
An agent `Unavailable` receipt after a failed commit barrier remains unknown;
it is not evidence that no durable ciphertext exists.
Only a matching authenticated fsync-backed agent receipt counts as durable;
failed/lost receipts can leave durability unknown and duplicates on disk.
The agent takes the first queued job, adds whatever else is already queued (at
most eight), and commits as soon as nothing more is queued. It never waits for a
fuller batch, because a connection sends nothing more until its receipt arrives.
The one bounded exception is the connections the previous commit just answered:
they send again only after it returned, so a batch missing any of them waits up
to 2 ms for exactly those connections, and a lone connection never waits. It
persists the batch's complete sequence reservation in one checkpoint before
encrypting any payload. Invalid or full entries may leave sequence gaps; crash
recovery never reuses reserved sequences. Positive receipts still wait for
segment and authenticated inventory commit.

SIGHUP validates the candidate before installing capture settings. New requests
on existing keepalive connections see new settings; admitted requests pin their
policy and destination. Current and one draining destination share a global
queue/pool; a third destination is rejected while draining. Late completions
after the old drain deadline are dropped, not rehomed. At most sixteen pinned
policy versions are allowed. Reductions below live state/event reservations
are rejected. The emergency control identity/path is boot-scoped: changing it
requires restart, and a reload fails instead of silently ignoring the change.
Operational metric/trace exporter lifecycle is unchanged.

Emergency control uses a four-byte big-endian length followed by at most 1024
bytes of strict JSON. Replies use the same framing. Only the configured peer
UID can connect successfully; one command at a time has a one-second deadline.
Commands are `{"command":"Status"}`, or
`{"command":"Disable","expected_generation":0}` / corresponding `Enable`.
Status reports gate generation, active requests, outstanding events, and
reserved event bytes. Mutations increment generation and reject stale values.
SIGHUP cannot clear the emergency gate. Worker-local generation notifications
clear idle capture-only state/reservations; disabled requests never resume after
Enable. Already sent/durable events cannot be revoked. Gate state is not durable
across restart, and disabling capture does not delete stored records.

Shutdown stops new admissions, drains forwarding, then bounds capture drain
before final operational metrics. Capture health adds finite-label
`llmproxy_capture_state_admission`, `llmproxy_capture_drops`, active-state and
state/event reservation gauges; existing queue/write/durable metrics remain.
No request, tenant, user, or policy identity appears in metric labels.
Neither green tests nor these reservations establish the design's throughput
or a whole-process RSS bound. The local pause profile qualified at 5 RPS
(147/150 confirmations per repetition, complete terminal accounting); losses
and high-rate variation remain explicit. It does not qualify the design's 5,000-RPS / 100,000-active-request deployment.
