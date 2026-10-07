//! Bounded, encrypted metadata spool for a dedicated off-path writer.
//!
//! Append receipts are not durable. `commit`/`seal` publish an immutable batch
//! and return only after segment and authenticated checkpoint durability barriers.
//! Drop never commits. Restart discards pending batches; sequence reservations
//! survive those losses. See README.md for filesystem and delivery assumptions.

mod format;

use format::{Descriptor, State, FOOTER_BYTES, FRAME_OVERHEAD, HEADER_BYTES};
use ring::{aead, digest};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_ENCRYPTION_KEYS: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid spool configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("spool already has a writer")]
    Locked,
    #[error("spool resource budget exhausted")]
    Full,
    #[error("metadata record exceeds configured bound")]
    RecordTooLarge,
    #[error("spool integrity check failed")]
    Corrupt,
    #[error("unsupported spool format version {0}")]
    UnknownVersion(u32),
    #[error("required spool encryption key is unavailable")]
    MissingKey,
    #[error("encryption key identifiers must be unique")]
    DuplicateKey,
    #[error("spool contains quarantined data; operator recovery required")]
    Quarantined,
    #[error("spool writer is poisoned; reopen and recover before proceeding")]
    Poisoned,
    #[error("acknowledgement exceeds durability-committed sequence")]
    InvalidAcknowledgement,
    #[error("spool sequence space exhausted")]
    SequenceExhausted,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("spool I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Externally provisioned AES-256-GCM key. Never serialized or included in Debug.
pub struct EncryptionKey {
    id: String,
    key: aead::LessSafeKey,
}

impl EncryptionKey {
    pub fn new(key_id: impl Into<String>, key_bytes: [u8; 32]) -> Result<Self> {
        let id = key_id.into();
        if id.is_empty() || id.len() > 128 {
            return Err(Error::InvalidConfig(
                "encryption key identifier must be 1..=128 bytes",
            ));
        }
        let key =
            aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes).map_err(|_| Error::Crypto)?;
        Ok(Self {
            id,
            key: aead::LessSafeKey::new(key),
        })
    }
}

impl fmt::Debug for EncryptionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncryptionKey([REDACTED])")
    }
}

/// All sizes are logical file bytes; reserve includes two maximum checkpoints.
/// Segment age rotates on the next append, never expires committed backlog.
#[derive(Clone, Debug)]
pub struct SpoolConfig {
    pub directory: PathBuf,
    pub node_id: String,
    pub max_record_bytes: usize,
    pub max_segment_bytes: u64,
    pub max_disk_bytes: u64,
    /// Includes pending, sealed, and quarantined segments.
    pub max_segments: usize,
    pub max_segment_age: Duration,
}

impl SpoolConfig {
    /// Validate size arithmetic and bounds without opening files.
    pub fn validate(&self) -> Result<()> {
        if self.node_id.is_empty() || self.node_id.len() > 128 {
            return Err(Error::InvalidConfig("node_id must be 1..=128 bytes"));
        }
        if self.max_record_bytes == 0
            || self.max_record_bytes > u32::MAX as usize - FRAME_OVERHEAD
            || self.max_segments == 0
            || self.max_segment_age.is_zero()
        {
            return Err(Error::InvalidConfig(
                "record, segment count and age limits must be finite and positive",
            ));
        }
        let minimum =
            (HEADER_BYTES + FRAME_OVERHEAD + FOOTER_BYTES) as u64 + self.max_record_bytes as u64;
        let control = self.control_reserve()?;
        if self.max_segment_bytes < minimum
            || self.max_disk_bytes
                < control
                    .checked_add(self.max_segment_bytes)
                    .ok_or(Error::InvalidConfig("disk limit overflow"))?
        {
            return Err(Error::InvalidConfig(
                "disk/segment budgets cannot hold one maximum record and control reserve",
            ));
        }
        Ok(())
    }

    fn state_bound(&self) -> Result<usize> {
        let payload = self
            .max_segments
            .checked_mul(format::DESCRIPTOR_BYTES)
            .and_then(|n| n.checked_add(format::STATE_FIXED))
            .ok_or(Error::InvalidConfig("checkpoint limit overflow"))?;
        if payload > u32::MAX as usize - FRAME_OVERHEAD {
            return Err(Error::InvalidConfig("checkpoint length exceeds wire limit"));
        }
        Ok(payload)
    }

    fn control_reserve(&self) -> Result<u64> {
        Ok(2 * (self.state_bound()? + HEADER_BYTES + FRAME_OVERHEAD) as u64)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendReceipt {
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableReceipt {
    pub through_sequence: u64,
}

/// Owned metadata bytes. Debug deliberately does not reveal the metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct ReplayRecord {
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl fmt::Debug for ReplayRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayRecord")
            .field("sequence", &self.sequence)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpoolStats {
    pub next_sequence: u64,
    pub durable_through_sequence: u64,
    pub acknowledged_through_sequence: u64,
    pub pending_records: u64,
    pub committed_segments: usize,
    pub pending_segments: usize,
    /// Physical logical file lengths including checkpoints, lock, quarantine.
    pub disk_bytes: u64,
    pub control_reserved_bytes: u64,
    pub quarantine_bytes: u64,
    pub quarantine_segments: usize,
    /// Valid records discarded from pending batches at this open.
    pub recovered_pending_records: u64,
    pub poisoned: bool,
}

struct Pending {
    file: File,
    first: u64,
    last: u64,
    count: u64,
    bytes: u64,
    started: Instant,
    header: [u8; HEADER_BYTES],
    hash: digest::Context,
}

/// Single-writer, synchronous library. Call from the capture agent, never workers.
/// The OS lock is held until Drop, including on poisoned handles.
pub struct MetadataSpool {
    config: SpoolConfig,
    keys: BTreeMap<String, EncryptionKey>,
    active_id: String,
    state: State,
    pending: Option<Pending>,
    _lock: File,
    // Rust note: Cell lets read-only replay invalidate this handle after failed authentication.
    poisoned: Cell<bool>,
    recovered_pending_records: u64,
    #[cfg(test)]
    fault: Option<Fault>,
}

impl MetadataSpool {
    pub fn open(
        config: SpoolConfig,
        active: EncryptionKey,
        recovery_keys: impl IntoIterator<Item = EncryptionKey>,
    ) -> Result<Self> {
        config.validate()?;
        // A private directory is an ownership boundary, not an untrusted path store.
        if !config.directory.exists() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&config.directory)?;
            sync_directory(
                config
                    .directory
                    .parent()
                    .ok_or(Error::InvalidConfig("directory needs a parent"))?,
            )?;
        }
        if !fs::symlink_metadata(&config.directory)?
            .file_type()
            .is_dir()
        {
            return Err(Error::Corrupt);
        }
        if fs::metadata(&config.directory)?.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidConfig("spool directory must be owner-only"));
        }
        let lock_path = config.directory.join("writer.lock");
        if lock_path.try_exists()? && !fs::symlink_metadata(&lock_path)?.file_type().is_file() {
            return Err(Error::Corrupt);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |error| {
                if error == rustix::io::Errno::WOULDBLOCK {
                    Error::Locked
                } else {
                    Error::Io(error.into())
                }
            },
        )?;
        sync_directory(&config.directory)?;
        let active_id = active.id.clone();
        let mut keys = BTreeMap::new();
        keys.insert(active.id.clone(), active);
        for key in recovery_keys {
            if keys.len() >= MAX_ENCRYPTION_KEYS {
                return Err(Error::InvalidConfig("too many encryption keys"));
            }
            if keys.insert(key.id.clone(), key).is_some() {
                return Err(Error::DuplicateKey);
            }
        }
        let mut spool = Self {
            config,
            keys,
            active_id,
            state: State::empty(),
            pending: None,
            _lock: lock,
            poisoned: Cell::new(false),
            recovered_pending_records: 0,
            #[cfg(test)]
            fault: None,
        };
        spool.recover()?;
        Ok(spool)
    }

    /// Reserves a never-reused sequence durably, then writes a pending encrypted frame.
    /// A successful return is NOT a durability promise for this payload.
    pub fn append(&mut self, payload: &[u8]) -> Result<AppendReceipt> {
        self.healthy()?;
        if payload.len() > self.config.max_record_bytes {
            return Err(Error::RecordTooLarge);
        }
        let frame_bytes = (payload.len() + FRAME_OVERHEAD) as u64;
        if self.pending.as_ref().is_some_and(|p| {
            p.bytes + frame_bytes + FOOTER_BYTES as u64 > self.config.max_segment_bytes
                || p.started.elapsed() >= self.config.max_segment_age
        }) {
            self.commit()?;
        }
        let additional = frame_bytes
            + if self.pending.is_none() {
                HEADER_BYTES as u64
            } else {
                0
            };
        self.ensure_capacity(additional + FOOTER_BYTES as u64, self.pending.is_none())?;
        let sequence = self.state.next;
        let next = sequence.checked_add(1).ok_or(Error::SequenceExhausted)?;
        let mut reserved = self.state.clone();
        reserved.next = next;
        let result = (|| {
            self.persist_state(&reserved)?;
            self.state = reserved;
            if self.pending.is_none() {
                let header = format::header(&self.config, self.active_key(), sequence, false);
                let mut file = create_file(&self.path(sequence, "open"))?;
                file.write_all(&header)?;
                let mut hash = digest::Context::new(&digest::SHA256);
                hash.update(&header);
                self.pending = Some(Pending {
                    file,
                    first: sequence,
                    last: sequence,
                    count: 0,
                    bytes: HEADER_BYTES as u64,
                    started: Instant::now(),
                    header,
                    hash,
                });
            }
            let header = self.pending.as_ref().unwrap().header;
            let frame = format::encrypt(&header, self.active_key(), 1, sequence, payload)?;
            #[cfg(test)]
            self.trip(Fault::AppendWrite)?;
            let pending = self.pending.as_mut().unwrap();
            pending.file.write_all(&frame)?;
            pending.hash.update(&frame);
            pending.count += 1;
            pending.last = sequence;
            pending.bytes += frame.len() as u64;
            Ok(AppendReceipt { sequence })
        })();
        self.poison_on_failure(result)
    }

    /// Seals and commits the current batch, including its authenticated inventory.
    /// No pending batch means the existing committed high-water mark is returned.
    pub fn commit(&mut self) -> Result<DurableReceipt> {
        self.healthy()?;
        if self.pending.is_none() {
            return Ok(DurableReceipt {
                through_sequence: self.state.durable,
            });
        }
        let result = (|| {
            let pending = self.pending.as_ref().unwrap();
            let mut footer = Vec::with_capacity(format::FOOTER_PAYLOAD);
            footer.extend_from_slice(&pending.count.to_le_bytes());
            footer.extend_from_slice(&pending.last.to_le_bytes());
            footer.extend_from_slice(pending.hash.clone().finish().as_ref());
            let frame =
                format::encrypt(&pending.header, self.active_key(), 2, pending.last, &footer)?;
            let pending = self.pending.as_mut().unwrap();
            pending.file.write_all(&frame)?;
            pending.hash.update(&frame);
            pending.bytes += frame.len() as u64;
            #[cfg(test)]
            self.trip(Fault::SegmentSync)?;
            let pending = self.pending.as_mut().unwrap();
            pending.file.sync_all()?;
            let descriptor = Descriptor {
                first: pending.first,
                last: pending.last,
                bytes: pending.bytes,
                hash: pending.hash.clone().finish().as_ref().try_into().unwrap(),
            };
            fs::rename(
                self.path(descriptor.first, "open"),
                self.path(descriptor.first, "seg"),
            )?;
            #[cfg(test)]
            self.trip(Fault::PublishDirectorySync)?;
            sync_directory(&self.config.directory)?;
            let mut committed = self.state.clone();
            committed.durable = descriptor.last;
            committed.segments.push(descriptor);
            self.persist_state(&committed)?;
            self.state = committed;
            self.pending = None;
            Ok(DurableReceipt {
                through_sequence: self.state.durable,
            })
        })();
        self.poison_on_failure(result)
    }

    pub fn seal(&mut self) -> Result<DurableReceipt> {
        self.commit()
    }

    /// Replays only committed, unacknowledged payloads in sequence order. A record
    /// that cannot fit max_bytes is left for the next call; no oversized result.
    /// Bounds apply to returned plaintext bytes, including empty records' row count.
    pub fn replay(
        &self,
        after_sequence: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Vec<ReplayRecord>> {
        self.healthy()?;
        let result = self.replay_inner(after_sequence, max_records, max_bytes);
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn replay_inner(
        &self,
        after_sequence: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Vec<ReplayRecord>> {
        if max_records == 0 || max_bytes == 0 {
            return Ok(Vec::new());
        }
        let after = after_sequence.max(self.state.acknowledged);
        let mut records = Vec::new();
        let mut used = 0;
        let mut full = false;
        for descriptor in &self.state.segments {
            if descriptor.last <= after {
                continue;
            }
            self.scan_segment(descriptor, |sequence, payload| {
                if full || sequence <= after {
                    return;
                }
                if records.len() == max_records || payload.len() > max_bytes - used {
                    full = true;
                } else {
                    used += payload.len();
                    records.push(ReplayRecord { sequence, payload });
                }
            })?;
            if full || records.len() == max_records {
                break;
            }
        }
        Ok(records)
    }

    /// Caller must first obtain backend confirmation through this sequence.
    /// Persist the authenticated checkpoint BEFORE deleting whole covered segments.
    /// Partial-segment acknowledgements suppress replay but do not compact files.
    pub fn acknowledge(&mut self, through_sequence: u64) -> Result<()> {
        self.healthy()?;
        if through_sequence > self.state.durable {
            return Err(Error::InvalidAcknowledgement);
        }
        if through_sequence <= self.state.acknowledged {
            return Ok(());
        }
        let mut acknowledged = self.state.clone();
        acknowledged.acknowledged = through_sequence;
        acknowledged.segments.retain(|s| s.last > through_sequence);
        let result = (|| {
            self.persist_state(&acknowledged)?;
            let reclaim: Vec<u64> = self
                .state
                .segments
                .iter()
                .filter(|s| s.last <= through_sequence)
                .map(|s| s.first)
                .collect();
            self.state = acknowledged;
            #[cfg(test)]
            self.trip(Fault::Reclaim)?;
            for first in reclaim {
                fs::remove_file(self.path(first, "seg"))?;
            }
            sync_directory(&self.config.directory)?;
            Ok(())
        })();
        self.poison_on_failure(result)
    }

    /// Filesystem accounting may fail; stats surfaces it explicitly.
    pub fn stats(&self) -> Result<SpoolStats> {
        let inventory = self.inventory()?;
        Ok(SpoolStats {
            next_sequence: self.state.next,
            durable_through_sequence: self.state.durable,
            acknowledged_through_sequence: self.state.acknowledged,
            pending_records: self.pending.as_ref().map_or(0, |p| p.count),
            committed_segments: self.state.segments.len(),
            pending_segments: usize::from(self.pending.is_some()),
            disk_bytes: inventory.bytes,
            control_reserved_bytes: self.config.control_reserve()?,
            quarantine_bytes: inventory.quarantine_bytes,
            quarantine_segments: inventory.quarantine_count,
            recovered_pending_records: self.recovered_pending_records,
            poisoned: self.poisoned.get(),
        })
    }

    fn healthy(&self) -> Result<()> {
        if self.poisoned.get() {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }

    fn poison_on_failure<T>(&mut self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    fn active_key(&self) -> &EncryptionKey {
        self.keys.get(&self.active_id).unwrap()
    }

    fn path(&self, first: u64, suffix: &str) -> PathBuf {
        self.config
            .directory
            .join(format!("segment-{first:020}.{suffix}"))
    }

    fn persist_state(&mut self, state: &State) -> Result<()> {
        let temporary = self.config.directory.join("checkpoint.tmp");
        let mut file = create_file(&temporary)?;
        format::write_state(&mut file, &self.config, self.active_key(), state)?;
        #[cfg(test)]
        self.trip(Fault::CheckpointSync)?;
        file.sync_all()?;
        fs::rename(temporary, self.config.directory.join("checkpoint"))?;
        #[cfg(test)]
        self.trip(Fault::CheckpointDirectorySync)?;
        sync_directory(&self.config.directory)?;
        Ok(())
    }

    fn ensure_capacity(&self, additional: u64, new_segment: bool) -> Result<()> {
        let inventory = self.inventory()?;
        let segment_limit = inventory.segment_count + usize::from(new_segment);
        let bytes = inventory
            .segment_bytes
            .checked_add(additional)
            .and_then(|n| n.checked_add(self.config.control_reserve().ok()?));
        if segment_limit > self.config.max_segments
            || bytes.map_or(true, |n| n > self.config.max_disk_bytes)
        {
            return Err(Error::Full);
        }
        Ok(())
    }

    fn inventory(&self) -> Result<Inventory> {
        let mut inventory = Inventory::default();
        for entry in fs::read_dir(&self.config.directory)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if !metadata.file_type().is_file() {
                return Err(Error::Corrupt);
            }
            let name = entry.file_name();
            let name = name.to_str().ok_or(Error::Corrupt)?;
            let length = metadata.len();
            inventory.bytes = inventory.bytes.checked_add(length).ok_or(Error::Full)?;
            if matches!(name, "writer.lock" | "checkpoint" | "checkpoint.tmp") {
                let bound = (self.config.state_bound()? + HEADER_BYTES + FRAME_OVERHEAD) as u64;
                if (name == "writer.lock" && length != 0) || length > bound {
                    return Err(Error::Corrupt);
                }
                continue;
            }
            let (first, suffix) = parse_filename(name)?;
            inventory.segment_count += 1;
            if inventory.segment_count > self.config.max_segments {
                return Err(Error::Full);
            }
            inventory.segment_bytes = inventory
                .segment_bytes
                .checked_add(length)
                .ok_or(Error::Full)?;
            if length > self.config.max_segment_bytes {
                return Err(Error::Corrupt);
            }
            if suffix == "bad" {
                inventory.quarantine_count += 1;
                inventory.quarantine_bytes += length;
            }
            inventory
                .segments
                .push((first, suffix.to_owned(), entry.path()));
        }
        if inventory.bytes > self.config.max_disk_bytes {
            return Err(Error::Full);
        }
        Ok(inventory)
    }

    fn recover(&mut self) -> Result<()> {
        let inventory = self.inventory()?;
        if inventory.quarantine_count != 0 {
            return Err(Error::Quarantined);
        }
        let checkpoint_path = self.config.directory.join("checkpoint");
        if checkpoint_path.try_exists()? {
            let mut file = File::open(&checkpoint_path)?;
            let length = file.metadata()?.len();
            let (header, id, first) = format::read_header(&mut file, &self.config, true)?;
            if first != 0 {
                return Err(Error::Corrupt);
            }
            let key = format::find_key(&self.keys, &id)?;
            let frame = format::read_frame(
                &mut file,
                &header,
                key,
                self.config.state_bound()?,
                length
                    .checked_sub(HEADER_BYTES as u64)
                    .ok_or(Error::Corrupt)?,
            )?;
            if frame.kind != 3
                || frame.sequence != 0
                || length != (HEADER_BYTES + frame.encoded.len()) as u64
            {
                return Err(Error::Corrupt);
            }
            self.state = State::decode(&frame.plaintext, &self.config)?;
        } else {
            if !inventory.segments.is_empty() {
                return Err(Error::Corrupt);
            }
            // Initial checkpoint creation may have been killed before publication.
            let temporary = self.config.directory.join("checkpoint.tmp");
            if temporary.try_exists()? {
                fs::remove_file(&temporary)?;
            }
            self.persist_state(&State::empty())?;
        }
        // Verify the entire committed inventory before reclaiming anything.
        for descriptor in &self.state.segments {
            if let Err(error) = self.scan_segment(descriptor, |_, _| {}) {
                if matches!(error, Error::Corrupt | Error::UnknownVersion(_)) {
                    let source = self.path(descriptor.first, "seg");
                    if source.try_exists()? {
                        fs::rename(source, self.path(descriptor.first, "bad"))?;
                        sync_directory(&self.config.directory)?;
                    }
                }
                return Err(error);
            }
        }
        for (first, suffix, path) in inventory.segments {
            if suffix == "seg" && self.state.segments.iter().any(|s| s.first == first) {
                continue;
            }
            if suffix == "open" && self.state.segments.iter().any(|s| s.first == first) {
                return Err(Error::Corrupt);
            }
            if suffix == "seg" && first <= self.state.acknowledged {
                // The authenticated checkpoint already covers reclamation.
                // Do not require retired payload keys or count these as lost tails.
                fs::remove_file(path)?;
                continue;
            }
            // Unreferenced published segments are either acknowledged files left
            // after checkpoint publication, or batches never checkpoint-committed.
            if first <= self.state.durable && first > self.state.acknowledged {
                return Err(Error::Corrupt);
            }
            self.recovered_pending_records += self.scan_pending(&path, first)?;
            fs::remove_file(path)?;
        }
        let temporary = self.config.directory.join("checkpoint.tmp");
        if temporary.try_exists()? {
            fs::remove_file(temporary)?;
        }
        sync_directory(&self.config.directory)?;
        self.ensure_capacity(0, false)?;
        Ok(())
    }

    fn scan_pending(&self, path: &Path, expected_first: u64) -> Result<u64> {
        let mut file = File::open(path)?;
        let length = file.metadata()?.len();
        if length < HEADER_BYTES as u64 {
            return Ok(0);
        }
        let (header, id, first) = format::read_header(&mut file, &self.config, false)?;
        if first != expected_first || first >= self.state.next {
            return Err(Error::Corrupt);
        }
        let key = format::find_key(&self.keys, &id)?;
        let mut remaining = length - HEADER_BYTES as u64;
        let mut count = 0;
        let mut previous = first - 1;
        while remaining > 0 {
            match format::read_frame(
                &mut file,
                &header,
                key,
                self.config.max_record_bytes.max(format::FOOTER_PAYLOAD),
                remaining,
            ) {
                Ok(frame)
                    if frame.kind == 1
                        && frame.sequence > previous
                        && frame.sequence < self.state.next
                        && frame.plaintext.len() <= self.config.max_record_bytes =>
                {
                    remaining -= frame.encoded.len() as u64;
                    previous = frame.sequence;
                    count += 1;
                }
                Ok(_) | Err(Error::Corrupt) => break, // Only uncommitted tails may be discarded.
                Err(error) => return Err(error),
            }
        }
        Ok(count)
    }

    fn scan_segment(
        &self,
        descriptor: &Descriptor,
        mut record: impl FnMut(u64, Vec<u8>),
    ) -> Result<()> {
        let mut file = match File::open(self.path(descriptor.first, "seg")) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Corrupt),
            other => other?,
        };
        if file.metadata()?.len() != descriptor.bytes {
            return Err(Error::Corrupt);
        }
        let (header, id, first) = format::read_header(&mut file, &self.config, false)?;
        if first != descriptor.first {
            return Err(Error::Corrupt);
        }
        let key = format::find_key(&self.keys, &id)?;
        let mut hash = digest::Context::new(&digest::SHA256);
        hash.update(&header);
        let mut remaining = descriptor.bytes - HEADER_BYTES as u64;
        let mut count = 0_u64;
        let mut previous = first - 1;
        while remaining > 0 {
            let frame = format::read_frame(
                &mut file,
                &header,
                key,
                self.config.max_record_bytes.max(format::FOOTER_PAYLOAD),
                remaining,
            )?;
            remaining -= frame.encoded.len() as u64;
            match frame.kind {
                1 if frame.sequence > previous
                    && frame.sequence <= descriptor.last
                    && frame.plaintext.len() <= self.config.max_record_bytes =>
                {
                    if count == 0 && frame.sequence != first {
                        return Err(Error::Corrupt);
                    }
                    previous = frame.sequence;
                    count += 1;
                    hash.update(&frame.encoded);
                    record(frame.sequence, frame.plaintext);
                }
                2 if remaining == 0
                    && frame.plaintext.len() == format::FOOTER_PAYLOAD
                    && count > 0
                    && frame.sequence == descriptor.last
                    && previous == descriptor.last =>
                {
                    if format::number(&frame.plaintext[..8]) != count
                        || format::number(&frame.plaintext[8..16]) != previous
                        || frame.plaintext[16..] != *hash.clone().finish().as_ref()
                    {
                        return Err(Error::Corrupt);
                    }
                    hash.update(&frame.encoded);
                    if hash.finish().as_ref() != descriptor.hash {
                        return Err(Error::Corrupt);
                    }
                    return Ok(());
                }
                _ => return Err(Error::Corrupt),
            }
        }
        Err(Error::Corrupt) // A committed segment must end with an authenticated footer.
    }
}

#[derive(Default)]
struct Inventory {
    bytes: u64,
    segment_bytes: u64,
    segment_count: usize,
    quarantine_bytes: u64,
    quarantine_count: usize,
    segments: Vec<(u64, String, PathBuf)>,
}

fn parse_filename(name: &str) -> Result<(u64, &str)> {
    let (number, suffix) = name
        .strip_prefix("segment-")
        .ok_or(Error::Corrupt)?
        .split_once('.')
        .ok_or(Error::Corrupt)?;
    if number.len() != 20
        || !number.bytes().all(|b| b.is_ascii_digit())
        || !matches!(suffix, "seg" | "open" | "bad")
    {
        return Err(Error::Corrupt);
    }
    let first = number.parse::<u64>().map_err(|_| Error::Corrupt)?;
    if first == 0 {
        return Err(Error::Corrupt);
    }
    Ok((first, suffix))
}

fn create_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?)
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    AppendWrite,
    SegmentSync,
    PublishDirectorySync,
    CheckpointSync,
    CheckpointDirectorySync,
    Reclaim,
}

#[cfg(test)]
impl MetadataSpool {
    fn trip(&mut self, point: Fault) -> Result<()> {
        if self.fault == Some(point) {
            self.fault = None;
            return Err(Error::Io(std::io::Error::other(
                "injected spool I/O failure",
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
