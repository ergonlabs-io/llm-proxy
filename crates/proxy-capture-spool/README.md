# Encrypted metadata spool

`proxy-capture-spool` is a synchronous Unix library used by the independently
resourced local capture agent. Never invoke its operations on request workers.
It implements local durability, not backend delivery, queries, or YAML policy.

## API and receipts

`MetadataSpool::open` accepts `SpoolConfig`, an active `EncryptionKey`, and up to
31 additional recovery keys. The private directory is single-writer locked until
the database has closed. Existing directories/files require owner-only permissions.

- `append` durably reserves a monotonically increasing sequence before encrypting
  the payload in memory. `AppendReceipt` is not a payload durability receipt.
- `append_batch` accepts at most eight borrowed payloads and reserves the whole
  range in one Immediate transaction. Per-record size failures leave gaps.
  At most eight pending payloads may exist across calls; excess admission returns
  `Full`. Drop never commits pending payloads.
- `commit` and `seal` atomically publish encrypted records and authenticated
  inventory in a redb Immediate transaction. Only successful completion returns
  `DurableReceipt`. `seal` flushes; there is no segment rotation.
- `replay(after_sequence, max_records, max_bytes)` seeks through the ordered table
  and returns authenticated opaque plaintext within both bounds. A record too
  large for the remaining window is not returned partially. Calls release their
  read transaction before returning.
- `acknowledge` accepts only sequences at or below the durable watermark, after
  genuine backend confirmation. One Immediate transaction advances the backend
  acknowledgement watermark, deletes covered rows, and updates inventory.
  The LOCAL-SPOOL-ONLY agent never calls it. No unacknowledged data is evicted.
- `stats` reports sequence watermarks, pending/retained record counts, database
  and aggregate logical file bytes, quarantine bytes, and poisoned state.

Receipts are scoped to this spool/node. Transport binds them to authenticated
producer and spool identities. Lost receipts and replay can cause duplicates;
backend deduplication requires stable event IDs outside this library.

## Fresh format, encryption, and recovery

The production format is application version 3, with `LMREDB03` encrypted
envelopes in `capture.redb`. It is distinct from the v1 segmented format, the
unimplemented v2 proposal, and the redb evaluation prototype. There is no legacy
reader, automatic migration, downgrade, or automatic removal of old directories.
Use a fresh spool directory. Existing empty/partial databases fail closed unless
complete authenticated initialization survived. Unknown formats are rejected.

Payload and state envelopes use AES-256-GCM, externally supplied key IDs, and
random 96-bit nonces from `ring::rand::SystemRandom`. Associated data binds the
application format, node identity, state/record kind, sequence, and key ID.
Sequence keys and database structure are visible; metadata payloads are encrypted.
State authenticates sequence/acknowledgement watermarks, retained record count,
and a domain-separated SHA-256 digest of the ordered ciphertext inventory.
redb page checksums are not a substitute for application authentication.

Recovery streams and authenticates all retained envelopes before admissions,
without collecting the backlog in memory. Cost grows with retained bytes.
Missing keys and unknown versions fail closed without removing data. Corruption
quarantines the entire database as `capture.redb.bad` after closing it while
retaining the writer lock; operator recovery is required and bytes remain charged.
Strict inventory rejects unexpected files, public files, and symlinks.

New records use the active key. Opening with a new active key verifies existing
state/records using recovery keys, then durably rewraps only state. Retain old
keys while unacknowledged envelopes use them. Key IDs and node IDs are bounded to
128 UTF-8 bytes. Deployment owns per-key invocation limits across nodes; this
library does not enforce a global cryptographic budget or prevent snapshot rollback.

## Failure and resource bounds

Pre-publication size and pending-count rejections are definitive. Backend write,
resize, transaction, or synchronization failures poison the writer and return
storage errors, including growth failures at the disk ceiling. They are never
reported as definitive `Full` rejections. No positive receipt is emitted. Recovery
can select either atomic commit outcome; previously durable records must survive.
Reopen before further mutation. Replay authentication failures also poison handles.

`SpoolConfig` bounds maximum record bytes, aggregate logical on-disk file bytes,
and database cache. Segment size/count/age settings have been removed; the agent
rejects them at their full dotted paths. Cache defaults to 4 MiB at the agent
boundary and is bounded to 1 byte–16 MiB. The library requires at least 2 MiB of
disk budget and space for one maximum envelope, but actual redb allocation and
copy-on-write headroom can exhaust capacity earlier. The safe positional backend
checks every write/resize before growth. File lengths do not measure filesystem
blocks; deployment must provide filesystem overhead separately. No quota increase,
compaction copy, eviction, or invented backend ACK extends a full spool.

Cache is not a total-process memory limit. Up to eight pending encrypted payloads,
caller serialization, encryption/decryption scratch, transaction/page allocations,
keys, and returned replay bytes consume separate memory. Recovery holds at most
one decrypted record at a time. Backend acknowledgement recomputes the remaining
inventory digest in a streaming scan; it is not on the local ingestion path.
Deleted rows permit redb page reuse but do not promise file shrinkage.

## Filesystem and verification

The directory and ancestors are a trusted deployment boundary. Advisory locks
coordinate cooperating writers, not hostile same-UID processes. This Unix-only
library assumes a local filesystem supporting file/directory synchronization.
Process-crash tests do not establish power-loss, network-filesystem, volume-loss,
replication, or adversarial rollback guarantees.

Use `make tq-proxy-capture-spool` for production redb behavior, faults, abrupt
termination, and the isolated prototype/reference suites. The old v1 implementation
and unit tests remain test/example-only comparison evidence; the production
library does not link them. New throughput and integrated qualification must use
freshly built production redb binaries. See
[the selected design](../../internal-docs/capture-spool-redb-design.md).
