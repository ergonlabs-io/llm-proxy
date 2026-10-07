# Encrypted metadata spool

`proxy-capture-spool` is a synchronous Unix library for a future independently
resourced capture agent. The [local agent](../proxy-capture-agent/README.md) now
uses it; it is not wired into the proxy's legacy JSONL collector. It
does not implement producer authentication, backend delivery, queries, or YAML
configuration. Never invoke its file operations on request workers.

## API and receipts

`MetadataSpool::open` takes `SpoolConfig`, an active `EncryptionKey`, and recovery
keys. The private directory is single-writer locked until the handle is dropped
or the process exits. Existing directories must have owner-only permissions.

- `append` reserves a monotonically increasing sequence in a durable checkpoint
  before writing pending encrypted payload. `AppendReceipt` is **not** a durable
  payload acknowledgement. Dropping the handle never commits pending payloads.
- `commit` and `seal` return `DurableReceipt` only after segment and checkpoint
  file synchronization, atomic publication, and directory synchronization.
- `replay(after_sequence, max_records, max_bytes)` authenticates committed data
  and returns opaque plaintext within both bounds. A record too large for the
  remaining window is not returned partially.
- `acknowledge` accepts only committed sequences. Call it only after backend
  confirmation: a durable checkpoint precedes deletion of fully covered
  segments. Partial segments are retained, with acknowledged records suppressed.
- `stats` reports pending/committed/quarantined storage, reservations, sequence
  and acknowledgement watermarks, and poisoned state.

Receipts are scoped to this spool/node, not globally unique event identifiers.
Future transport must bind receipts to authenticated producer/spool identity.
Replay can duplicate delivery after a lost acknowledgement; backend deduplication
requires stable event identifiers outside this library.

## Format, encryption and recovery

Format version 1 uses bounded headers, numeric segment filenames, AES-256-GCM
frames, authenticated sealed footers, and an encrypted checkpoint containing
node identity and segment inventory/digests. Node and key identifiers are limited
to 128 bytes. At most 32 active/recovery keys are accepted. Keys are supplied by
deployment and are neither stored in the spool nor exposed by diagnostic output.

Nonces are random 96-bit values from `ring::rand::SystemRandom`. Deployment owns
key separation and rotation; the library does not enforce a global per-key
invocation limit across nodes. Production-scale cryptographic qualification is
separate work. Retain old keys while unacknowledged data or the current checkpoint
requires them. Reclamation of already acknowledged leftover files needs no
retired payload key.

Reserved sequence numbers are never reused, even if pending records are lost.
Recovery discards uncommitted payloads; ambiguous commit outcomes may instead
recover committed data and cause duplicate delivery. Missing keys and unknown
versions fail closed. Corrupt committed segments are quarantined, not silently
skipped; quarantine requires operator recovery and still consumes capacity.
Mutation failures and replay authentication failures poison the handle: reopen
and recover before further use.

## Resource bounds

`SpoolConfig` bounds record size, segment size/count/age, and logical on-disk file
bytes. Capacity reserves a footer and two maximum checkpoints before admission.
Pending, committed, and quarantined files count toward limits. `Full` never evicts
committed backlog. Logical bytes do not represent filesystem blocks: provision
additional filesystem overhead/headroom. Do not shrink limits below backlog.

Age rotation occurs on the next append, not an idle timer; explicit commit also
seals a segment. Frequent small commits can exhaust the segment-count budget
before the byte budget. These bounds do not expire committed records.

For example, a caller can select 1 MiB records, 64 MiB segments, 1 GiB disk,
32 segments, and 60-second rotation, with replay windows of 64 rows/32 MiB.
These are caller-selected limits, not a production profile. Replay scratch can
include three record-sized buffers plus returned payloads and allocation
overhead. The parent agent must bound aggregate memory, queues, keys, inventory,
serialization scratch, and concurrent replay callers separately.

## Filesystem and performance assumptions

The directory and its ancestors are a trusted deployment boundary. A safe OS
advisory lock coordinates cooperating writers, not hostile same-UID processes.
Symlinks and unexpected inventory entries are rejected. This is Unix-only and
assumes local filesystem support for atomic rename and file/directory sync.

Tests establish process-crash behavior under those assumptions, not power-loss,
network-filesystem, volume-loss, replication, or adversarial rollback guarantees.
Each append synchronizes its sequence reservation. Grouping payload commits
does not amortize that per-append barrier; no throughput target is established.
The future agent must isolate blocking file I/O and bound shutdown independently.

## Verification

Run `make tq-proxy-capture-spool`. Coverage includes bounded replay/capacity,
key rotation, deterministic corruption, torn pending tails, unsupported formats,
symlinks, missing files, poisoned handles, injected synchronization/publication/
reclamation failures, and four subprocess SIGKILL recovery scenarios. These
tests do not substitute for filesystem qualification or agent/backend tests.
