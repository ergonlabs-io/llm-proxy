# Capture spool: redb design

The spool stores capture records in redb. Backward compatibility with the
earlier v1 format was deliberately dropped, and increased disk use was accepted.

## Scope and ownership

Use the workspace's pinned redb dependency for page allocation, transaction
atomicity, crash recovery, and page reuse. Keep application encryption,
authenticated inventory, sequence reservations, quota enforcement, receipts,
and key management in `proxy-capture-spool`. Do not implement the custom v2
append-only group format, a legacy reader, migration, or downgrade tooling.
Deployment remains LOCAL-SPOOL-ONLY, without an uploader or query stack.

The existing comparison found median durable batch p99 of 19.3 ms for redb
versus 48.2 ms for v1, with 22.2% more file bytes in the ordinary workload.
Escaped metadata used 3.8 times the file space. Increased disk use is accepted;
the configured disk ceiling still applies. These are prototype measurements,
not production qualification.

## Fresh format and initialization

Use one private `capture.redb` database and `writer.lock`, with the existing
single-writer advisory lock and trusted-directory assumptions. Assign a new
application format identifier; it must not be mistaken for the prototype or
custom v2 proposal. Reject v1 files, prototype databases, unknown formats,
symlinks, unexpected files, and wrong node identities. Never automatically
delete or convert an existing directory. New qualification uses fresh directories;
old evidence and raw spools remain preserved.

Initialize only a new database. Existing databases must contain valid application
state; absence of state is corruption, not permission to initialize. Creation
requires a successful Immediate transaction, file synchronization, and directory
synchronization before opening the writer for admissions. Interrupted creation
fails closed unless recovery can authenticate the complete initialized state.

Records are sequence-keyed encrypted envelopes containing bounded key ID,
nonce, and ciphertext. Associated data binds application format, node identity,
record kind, sequence, and key ID. Retain AES-256-GCM, random nonces, external
keys, and the existing maximum of 32 active/recovery keys. Sequence keys and
database structure remain visible.

One encrypted state row contains format/node identity, next sequence, durable
and backend-acknowledgement watermarks, retained record count, and an ordered
inventory digest. Hash sequence, envelope length, and envelope bytes with domain
separation. Authenticate the state schema version; reject unknown schemas.
Do not rely on redb's unkeyed integrity checks as application authentication.

## Append, commit, and failures

Preserve bounded `append`, `append_batch`, `commit`, and durable receipt semantics.
Reserve the complete sequence range in an Immediate transaction before payload
encryption; failed or rejected records can leave gaps. Pending encrypted records
remain bounded in memory. A second Immediate transaction publishes records and
authenticated state atomically. Successful transaction completion precedes every
positive receipt. Dropping the handle never commits pending payloads.

`seal` is a durability flush equivalent to `commit`; a database has no segment
to close. Keep the agent's group commit and blocking I/O isolation. The writer
takes the first queued record, adds whatever else is already queued (at most
eight, the pending-record cap), and commits as soon as nothing more is
immediately available. It never lingers for a fuller batch: each connection
withholds its next record until its receipt arrives, so with fewer than eight
producers a batch cannot fill and a linger would charge every record its full
length (a lone connection managed 13-18 records/s under the former 50 ms
window). Records that arrive during the previous commit's fsync form the next
batch.

One bounded wait remains, for the connections the previous commit just
answered. They send again only after it returned, by which time the next batch
has been drained, so without the wait lockstep connections split into
alternating half-size cohorts (eight connections settled near four records per
batch in local measurement). A batch missing any of those connections waits up
to 2 ms for exactly them, tracked by connection and not by count, because a
count lets the other cohort satisfy it and the split persists. A lone
connection is its own previous batch and never waits, open but idle connections
are never waited for, and a connection that is answered and then goes silent
costs the next commit at most that 2 ms once. The 50 ms bound caps collection
time overall.

Only a provably pre-publication admission rejection may return per-record `Full`
or `RecordTooLarge`. Backend growth, write, resize, transaction, or sync failures
poison the handle and return a storage failure, even when caused by the disk
ceiling. Never translate the prototype's backend `Full` directly into the agent's
definitive `Outcome::Full`. The agent returns unavailable, with no positive receipt;
the producer retains unknown durability after a possibly sent attempt. Reopen
may recover either atomic outcome, including data whose receipt was lost.

Every recovered state must preserve all earlier acknowledged durable records
and its reserved sequence high-water mark. Do not retry a failed mutation through
the poisoned handle or infer durability from readable uncommitted data.

## Limits and memory

Preserve `max_record_bytes` and `max_disk_bytes` values and their strict validation.
Charge logical file lengths for the database, lock, initialization artifacts, and
quarantine. A safe StorageBackend wrapper checks each write/resize against the
remaining aggregate budget before growth. Copy-on-write headroom consumes that
same budget; a full database can stop before payload bytes reach the ceiling.
No capacity increase, eviction, or compaction copy may hide exhaustion.

Remove the segment-specific `max_segment_bytes`, `max_segments`, and
`max_segment_age_seconds` configuration fields with the fresh backend. Update
agent fixtures/examples and reject those fields at their full dotted paths.
This is an explicit configuration/API change requiring review with the adapter:
do not silently ignore them or invent logical segments to emulate the old layout.
Record count is constrained by disk and bounded record encoding; age is not a
retention/deletion policy. `SpoolStats` must replace segment counts with retained
record and database byte counts in that same reviewed interface increment.

Add a bounded database cache setting with a proposed 4 MiB default and 16 MiB
maximum. Cache size is not a total-process memory ceiling. Account separately
for at most eight pending encrypted payloads, caller-owned serialization,
encryption/decryption scratch, transaction allocations, keys, and replay output.
Before release, measure maximum valid 512 KiB records and simultaneous scratch
owners; report RSS and fail qualification if the declared agent budget is exceeded.

## Recovery, replay, keys, and reclamation

Before accepting admissions, authenticate state and stream through every retained
envelope, checking ordering, bounds, record authentication, count, digest, and
watermarks. Recovery costs O(retained bytes), without collecting the full backlog
in memory. Report recovery duration at measured retention size. Corruption blocks
admissions and remains charged; quarantine the whole database rather than trying
to delete corrupt pages. Missing keys fail closed without destructive cleanup.
Quarantine publication and directory sync failures must also leave data charged.

Replay seeks strictly after `max(after_sequence, acknowledged_watermark)` using
redb's ordered range iterator. Bound returned record count and plaintext bytes;
do not scan from the beginning on each page or return partial records. Bound
envelope length before allocation/decryption. An authentication failure poisons
the handle. Avoid holding read transactions across calls or network waits.

New records and state use the active key. Existing envelopes retain their key IDs;
old keys remain required while retained records use them. Opening with a new
active key authenticates old state with a recovery key, then transactionally
rewraps state before writing. It does not rewrite the backlog. No online payload
rotation or automatic key retirement is introduced.

Keep `acknowledge` as an explicit library boundary, callable only after genuine
backend confirmation; the local agent never invokes it. A transaction atomically
advances the acknowledgement watermark, deletes only covered records, and
updates count/digest. Digest recomputation can stream the remaining inventory;
do not introduce a custom Merkle tree in this increment. redb may reuse freed
pages without shrinking the file. No deletion of unacknowledged data, fake ACKs,
background retention expiry, or offline compaction is authorized.
