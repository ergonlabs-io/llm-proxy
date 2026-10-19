//! Bounded, encrypted redb metadata spool for a dedicated off-path writer.
//!
//! Append receipts are not durable. Immediate transactions reserve sequences
//! before encryption and atomically publish encrypted records with authenticated
//! inventory. Drop never commits pending payloads. See README.md for assumptions.
mod format;
mod storage;
#[cfg(test)]
mod testing;

use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use ring::{aead, digest};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fmt,
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
#[cfg(test)]
use testing::{Fault, Hooks};

pub type Result<T> = std::result::Result<T, Error>;
pub const MAX_ENCRYPTION_KEYS: usize = 32;
pub const DEFAULT_CACHE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CACHE_BYTES: usize = 16 * 1024 * 1024;
// redb 4.2 starts with 1 MiB usable pages plus metadata and commit headroom.
pub const MIN_DISK_BYTES: u64 = 2 * 1024 * 1024;
/// Upper bound for `SpoolConfig::max_pending_records`.
pub const MAX_PENDING_RECORDS: usize = 4096;
const RECORDS: TableDefinition<u64, &[u8]> = TableDefinition::new("records");
const STATE: TableDefinition<u64, &[u8]> = TableDefinition::new("state");
/// One encrypted row the caller owns, kept across acknowledgements.
const APPLICATION: TableDefinition<u64, &[u8]> = TableDefinition::new("application");
/// Envelope kind of the application row; 0 is state and 1 is a record.
const APPLICATION_KIND: u8 = 2;
/// One row of reserved pages that only an acknowledgement may spend.
const HEADROOM: TableDefinition<u64, &[u8]> = TableDefinition::new("headroom");
/// Headroom bounds. An acknowledgement copy-on-writes the B-tree pages it
/// touches and records every page it frees, and redb grows a database file by
/// doubling it, so at the ceiling only pages already inside the file are
/// usable. The reserve is sized to the ceiling so it scales with what a full
/// acknowledgement has to free.
const MIN_HEADROOM_BYTES: u64 = 64 * 1024;
const MAX_HEADROOM_BYTES: u64 = 4 * 1024 * 1024;
const DATABASE: &str = "capture.redb";
const QUARANTINE: &str = "capture.redb.bad";

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
    #[error("spool database failed: {0}")]
    Storage(String),
}

/// Externally provisioned AES-256-GCM key. Never persisted or exposed in Debug.
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

#[derive(Clone, Debug)]
pub struct SpoolConfig {
    pub directory: PathBuf,
    pub node_id: String,
    pub max_record_bytes: usize,
    /// Logical aggregate file bytes, including database copy-on-write growth.
    pub max_disk_bytes: u64,
    /// Database cache only; pending records and caller scratch are separate.
    pub cache_bytes: usize,
    /// Records held between `commit` calls, which is also the largest batch one
    /// commit publishes. Pending memory is at most this many encrypted records.
    pub max_pending_records: usize,
}
impl SpoolConfig {
    pub fn validate(&self) -> Result<()> {
        if self.node_id.is_empty() || self.node_id.len() > 128 {
            return Err(Error::InvalidConfig("node_id must be 1..=128 bytes"));
        }
        if self.max_record_bytes == 0
            || self.max_record_bytes > u32::MAX as usize - format::MAX_ENVELOPE_OVERHEAD
        {
            return Err(Error::InvalidConfig(
                "record size must be finite and positive",
            ));
        }
        if self.max_pending_records == 0 || self.max_pending_records > MAX_PENDING_RECORDS {
            return Err(Error::InvalidConfig("max_pending_records must be 1..=4096"));
        }
        if self.cache_bytes == 0 || self.cache_bytes > MAX_CACHE_BYTES {
            return Err(Error::InvalidConfig("cache_bytes must be 1..=16777216"));
        }
        if self.max_disk_bytes < MIN_DISK_BYTES
            || self.max_disk_bytes
                < self.max_record_bytes as u64 + format::MAX_ENVELOPE_OVERHEAD as u64
        {
            return Err(Error::InvalidConfig(
                "disk budget cannot hold database metadata and a maximum record",
            ));
        }
        Ok(())
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
    pub retained_records: u64,
    pub database_bytes: u64,
    pub disk_bytes: u64,
    pub quarantine_bytes: u64,
    pub poisoned: bool,
    /// Whether the acknowledgement reserve is held. Admissions run only while
    /// it is.
    pub headroom_reserved: bool,
}

/// Single-writer synchronous library. Never call from request workers.
/// The database is dropped before releasing the writer lock, including on error.
pub struct MetadataSpool {
    // Only `None` between closing a database refused at the disk ceiling and
    // reopening it; a failed reopen poisons the handle.
    db: Option<Database>,
    file: Arc<File>,
    quota: Arc<storage::Quota>,
    /// Database byte ceiling: the disk budget less the other charged files.
    database_cap: u64,
    /// Set when a transaction was refused at the ceiling; admissions are refused
    /// without touching storage until an acknowledgement commits.
    at_cap: bool,
    /// The acknowledgement reserve is in the database. Spent only when an
    /// acknowledgement is refused at the ceiling; restored before admissions
    /// resume, so every acknowledgement finds it.
    headroom: bool,
    /// The application row's plaintext and the key that sealed it.
    application: Option<(Vec<u8>, String)>,
    config: SpoolConfig,
    keys: BTreeMap<String, EncryptionKey>,
    active_id: String,
    state: format::State,
    hash: digest::Context,
    pending: Vec<(u64, Vec<u8>)>,
    poisoned: Cell<bool>,
    #[cfg(test)]
    hooks: Arc<Hooks>,
    _lock: File,
}
impl MetadataSpool {
    pub fn open(
        config: SpoolConfig,
        active: EncryptionKey,
        recovery_keys: impl IntoIterator<Item = EncryptionKey>,
    ) -> Result<Self> {
        Self::open_inner(
            config,
            active,
            recovery_keys,
            #[cfg(test)]
            Arc::new(Hooks::default()),
        )
    }
    #[cfg(test)]
    fn open_with_hooks(
        config: SpoolConfig,
        active: EncryptionKey,
        recovery_keys: impl IntoIterator<Item = EncryptionKey>,
        hooks: Arc<Hooks>,
    ) -> Result<Self> {
        Self::open_inner(config, active, recovery_keys, hooks)
    }
    fn open_inner(
        config: SpoolConfig,
        active: EncryptionKey,
        recovery_keys: impl IntoIterator<Item = EncryptionKey>,
        #[cfg(test)] hooks: Arc<Hooks>,
    ) -> Result<Self> {
        config.validate()?;
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
        match fs::symlink_metadata(&config.directory) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
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
            other => {
                other?;
            }
        }
        let metadata = fs::symlink_metadata(&config.directory)?;
        if !metadata.is_dir() {
            return Err(Error::Corrupt);
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::InvalidConfig("spool directory must be owner-only"));
        }
        let lock_path = config.directory.join("writer.lock");
        // Inspect a pre-existing lock before opening it; never follow symlinks.
        match fs::symlink_metadata(&lock_path) {
            Ok(meta)
                if !meta.is_file() || meta.len() != 0 || meta.permissions().mode() & 0o077 != 0 =>
            {
                return Err(Error::Corrupt)
            }
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(lock_path)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |e| {
                if e == rustix::io::Errno::WOULDBLOCK {
                    Error::Locked
                } else {
                    Error::Io(e.into())
                }
            },
        )?;
        let inventory = inventory(&config.directory)?;
        if inventory.bytes > config.max_disk_bytes {
            return Err(Error::Full);
        }
        if inventory.quarantine_bytes != 0 || config.directory.join(QUARANTINE).try_exists()? {
            return Err(Error::Quarantined);
        }
        let path = config.directory.join(DATABASE);
        let fresh = !path.try_exists()?;
        if !fresh && inventory.database_bytes == 0 {
            return Err(Error::Corrupt);
        }
        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(fresh)
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
                .open(&path)?,
        );
        let other_bytes = inventory.bytes - inventory.database_bytes;
        let database_cap = config.max_disk_bytes - other_bytes;
        let quota = Arc::new(storage::Quota::new(database_cap));
        let db = match open_database(
            &file,
            &quota,
            config.cache_bytes,
            #[cfg(test)]
            &hooks,
        ) {
            Ok(db) => db,
            Err(error) => {
                if matches!(error, Error::Corrupt) {
                    quarantine(
                        &config.directory,
                        #[cfg(test)]
                        &hooks,
                    )?;
                }
                return Err(error);
            }
        };
        let mut spool = Self {
            db: Some(db),
            file,
            quota,
            database_cap,
            at_cap: false,
            headroom: false,
            application: None,
            config,
            keys,
            active_id,
            state: format::State::empty(),
            hash: format::inventory_hash(),
            pending: Vec::new(),
            poisoned: Cell::new(false),
            #[cfg(test)]
            hooks,
            _lock: lock,
        };
        let result = (|| {
            if fresh {
                #[cfg(test)]
                spool.hooks.trip(Fault::InitializeBeforeCommit)?;
                spool.publish(&spool.state, &[], None)?;
                #[cfg(test)]
                spool.hooks.trip(Fault::InitializeAfterCommit)?;
                #[cfg(test)]
                spool.hooks.trip(Fault::InitializeDirectorySync)?;
                sync_directory(&spool.config.directory)?;
            }
            let state_key = spool.recover()?;
            // Rewrap state on key change without rewriting retained record envelopes.
            if state_key != spool.active_id {
                #[cfg(test)]
                spool.hooks.trip(Fault::RewrapBeforeCommit)?;
                spool.publish(&spool.state, &[], None)?;
                #[cfg(test)]
                spool.hooks.trip(Fault::RewrapAfterCommit)?;
            }
            if let Some((bytes, key)) = spool.application.clone() {
                if key != spool.active_id {
                    spool.set_application_state(&bytes)?;
                }
            }
            // A fresh spool, or one opened at its ceiling after the reserve was
            // spent: admissions wait until the reserve is back.
            spool.restore_headroom()?;
            // Repeat after recovery so a valid initialization lost before directory
            // sync cannot admit new payloads until publication is durable.
            sync_directory(&spool.config.directory)?;
            Ok(())
        })();
        if let Err(error) = result {
            let directory = spool.config.directory.clone();
            #[cfg(test)]
            let hooks = spool.hooks.clone();
            let Self {
                db, _lock: lock, ..
            } = spool;
            drop(db);
            if matches!(error, Error::Corrupt) {
                quarantine(
                    &directory,
                    #[cfg(test)]
                    &hooks,
                )?;
            }
            drop(lock);
            return Err(error);
        }
        Ok(spool)
    }

    /// A successful append reserves a sequence, but does not acknowledge durability.
    pub fn append(&mut self, payload: &[u8]) -> Result<AppendReceipt> {
        self.admissible()?;
        if payload.len() > self.config.max_record_bytes {
            return Err(Error::RecordTooLarge);
        }
        if self.pending.len() == self.config.max_pending_records {
            return Err(Error::Full);
        }
        let first = self.reserve(1)?;
        self.append_reserved(first, payload)
    }
    /// Reserve the complete range before encryption; per-record rejections leave gaps.
    pub fn append_batch(&mut self, payloads: &[&[u8]]) -> Result<Vec<Result<AppendReceipt>>> {
        self.admissible()?;
        if payloads.len() > self.config.max_pending_records {
            return Err(Error::InvalidConfig(
                "append batch exceeds max_pending_records",
            ));
        }
        if payloads.is_empty() {
            return Ok(Vec::new());
        }
        // Pending-capacity rejection is definitive: this batch cannot publish payloads.
        if self.pending.len() + payloads.len() > self.config.max_pending_records {
            return Err(Error::Full);
        }
        let first = self.reserve(payloads.len() as u64)?;
        let mut results = Vec::with_capacity(payloads.len());
        for (index, payload) in payloads.iter().enumerate() {
            if payload.len() > self.config.max_record_bytes {
                results.push(Err(Error::RecordTooLarge));
            } else {
                results.push(Ok(self.append_reserved(first + index as u64, payload)?));
            }
        }
        Ok(results)
    }
    fn reserve(&mut self, count: u64) -> Result<u64> {
        let first = self.state.next;
        let mut state = self.state;
        state.next = first.checked_add(count).ok_or(Error::SequenceExhausted)?;
        self.quota.arm(self.database_cap);
        let result = (|| {
            #[cfg(test)]
            self.hooks.trip(Fault::ReserveBeforeCommit)?;
            self.publish(&state, &[], None)?;
            #[cfg(test)]
            self.hooks.trip(Fault::ReserveAfterCommit)?;
            self.state = state;
            Ok(first)
        })();
        self.settle(result)
    }
    fn append_reserved(&mut self, sequence: u64, payload: &[u8]) -> Result<AppendReceipt> {
        let result = (|| {
            #[cfg(test)]
            self.hooks.trip(Fault::Encrypt)?;
            let bytes = format::encrypt(
                self.active_key(),
                &self.config.node_id,
                1,
                sequence,
                payload,
            )?;
            self.pending.push((sequence, bytes));
            Ok(AppendReceipt { sequence })
        })();
        self.poison_on_failure(result)
    }
    /// Publishes every pending record in one transaction. `Full` means the disk
    /// ceiling refused it: nothing was published and the records stay pending,
    /// so a commit after an acknowledgement frees space can still publish them.
    pub fn commit(&mut self) -> Result<DurableReceipt> {
        self.healthy()?;
        if self.pending.is_empty() {
            return Ok(DurableReceipt {
                through_sequence: self.state.durable,
            });
        }
        self.admissible()?;
        self.quota.arm(self.database_cap);
        let result = (|| {
            let mut hash = self.hash.clone();
            for (sequence, bytes) in &self.pending {
                format::hash_record(&mut hash, *sequence, bytes);
            }
            let mut state = self.state;
            state.durable = self.pending.last().unwrap().0;
            state.count = state
                .count
                .checked_add(self.pending.len() as u64)
                .ok_or(Error::Corrupt)?;
            state.digest = hash.clone().finish().as_ref().try_into().unwrap();
            #[cfg(test)]
            self.hooks.trip(Fault::CommitBeforeCommit)?;
            self.publish(&state, &self.pending, None)?;
            #[cfg(test)]
            self.hooks.trip(Fault::CommitAfterCommit)?;
            self.state = state;
            self.hash = hash;
            self.pending.clear();
            Ok(DurableReceipt {
                through_sequence: state.durable,
            })
        })();
        self.settle(result)
    }
    /// Flushes pending payloads. There is no segment rotation in the redb format.
    pub fn seal(&mut self) -> Result<DurableReceipt> {
        self.commit()
    }

    pub fn replay(
        &self,
        after_sequence: u64,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Vec<ReplayRecord>> {
        self.healthy()?;
        let result = (|| {
            let after = after_sequence.max(self.state.acknowledged);
            if max_records == 0 || max_bytes == 0 || after == u64::MAX {
                return Ok(Vec::new());
            }
            let tx = self.db()?.begin_read().map_err(storage_error)?;
            let table = tx.open_table(RECORDS).map_err(storage_error)?;
            let mut records = Vec::new();
            let mut used = 0;
            for row in table.range(after + 1..).map_err(storage_error)? {
                if records.len() == max_records {
                    break;
                }
                let (sequence, envelope) = row.map_err(storage_error)?;
                let sequence = sequence.value();
                if sequence > self.state.durable || sequence >= self.state.next {
                    return Err(Error::Corrupt);
                }
                let payload = format::decrypt(
                    &self.keys,
                    &self.config.node_id,
                    1,
                    sequence,
                    envelope.value(),
                    self.config.max_record_bytes,
                )?;
                if payload.len() > max_bytes - used {
                    break;
                }
                used += payload.len();
                records.push(ReplayRecord { sequence, payload });
            }
            Ok(records)
        })();
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }

    /// Only the caller's genuine backend confirmation permits deletion.
    /// The local-only capture agent never invokes this API.
    ///
    /// Deletes the covered rows; redb reuses their pages, which is how a spool at
    /// its ceiling accepts appends again. Refused at the ceiling, it spends the
    /// headroom reserve and acknowledges in committed prefixes, each freeing
    /// pages for the next, so any committed range can be acknowledged at the
    /// ceiling. Admissions resume only once the reserve is restored. `Full`
    /// means even a one-record prefix did not fit; `stats` then shows how far
    /// the watermark moved.
    pub fn acknowledge(&mut self, through_sequence: u64) -> Result<()> {
        self.healthy()?;
        if through_sequence > self.state.durable {
            return Err(Error::InvalidAcknowledgement);
        }
        if through_sequence <= self.state.acknowledged {
            // Nothing new to delete, but an earlier acknowledgement may have
            // spent the reserve and failed to put it back. With everything
            // acknowledged, a repeat is the consumer's only way to reopen
            // admissions, so it retries the reserve. With the reserve held,
            // admissions are already open or wait for space a repeat cannot
            // free.
            if !self.headroom {
                return self.restore_headroom();
            }
            return Ok(());
        }
        let result = match self.acknowledge_prefix(through_sequence) {
            Err(Error::Full) => self.acknowledge_at_ceiling(through_sequence),
            other => other,
        };
        result?;
        self.restore_headroom()
    }
    /// The first attempt was refused. Spend the reserve, then halve the
    /// prefix on each refusal and double it on each success.
    fn acknowledge_at_ceiling(&mut self, through_sequence: u64) -> Result<()> {
        self.release_headroom()?;
        let mut step = ((through_sequence - self.state.acknowledged) / 2).max(1);
        while self.state.acknowledged < through_sequence {
            let target = through_sequence.min(self.state.acknowledged.saturating_add(step));
            match self.acknowledge_prefix(target) {
                Ok(()) => step = step.saturating_mul(2),
                Err(Error::Full) if step > 1 => step /= 2,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
    /// One transaction deleting the rows through `through_sequence`.
    fn acknowledge_prefix(&mut self, through_sequence: u64) -> Result<()> {
        self.quota.arm(self.database_cap);
        #[cfg(test)]
        if self.hooks.take_refused_acknowledgement() {
            self.quota.arm(0);
        }
        let result = (|| {
            let mut hash = format::inventory_hash();
            let mut count = 0u64;
            {
                let tx = self.db()?.begin_read().map_err(storage_error)?;
                let table = tx.open_table(RECORDS).map_err(storage_error)?;
                for row in table.range(through_sequence + 1..).map_err(storage_error)? {
                    let (sequence, envelope) = row.map_err(storage_error)?;
                    let sequence = sequence.value();
                    format::decrypt(
                        &self.keys,
                        &self.config.node_id,
                        1,
                        sequence,
                        envelope.value(),
                        self.config.max_record_bytes,
                    )?;
                    format::hash_record(&mut hash, sequence, envelope.value());
                    count = count.checked_add(1).ok_or(Error::Corrupt)?;
                }
            }
            let mut state = self.state;
            state.acknowledged = through_sequence;
            state.count = count;
            state.digest = hash.clone().finish().as_ref().try_into().unwrap();
            #[cfg(test)]
            self.hooks.trip(Fault::AcknowledgeBeforeCommit)?;
            self.publish(&state, &[], Some(through_sequence))?;
            #[cfg(test)]
            self.hooks.trip(Fault::AcknowledgeAfterCommit)?;
            self.state = state;
            self.hash = hash;
            Ok(())
        })();
        self.settle(result)
    }
    /// The caller's application row, if one was ever written. It is
    /// encrypted and authenticated like a record, bound to this node, and
    /// never deleted by an acknowledgement.
    pub fn application_state(&self) -> Option<&[u8]> {
        self.application.as_ref().map(|(bytes, _)| bytes.as_slice())
    }
    /// Replaces the application row in one Immediate transaction. It is at
    /// most `max_record_bytes`. `Full` at the ceiling, like any write.
    pub fn set_application_state(&mut self, bytes: &[u8]) -> Result<()> {
        self.healthy()?;
        if bytes.len() > self.config.max_record_bytes {
            return Err(Error::RecordTooLarge);
        }
        self.quota.arm(self.database_cap);
        let result = (|| {
            let envelope = format::encrypt(
                self.active_key(),
                &self.config.node_id,
                APPLICATION_KIND,
                0,
                bytes,
            )?;
            let mut tx = self.db()?.begin_write().map_err(storage_error)?;
            tx.set_durability(Durability::Immediate)
                .map_err(storage_error)?;
            tx.open_table(APPLICATION)
                .map_err(storage_error)?
                .insert(0, envelope.as_slice())
                .map_err(storage_error)?;
            tx.commit().map_err(storage_error)
        })();
        self.settle(result)?;
        self.application = Some((bytes.to_vec(), self.active_id.clone()));
        Ok(())
    }
    fn headroom_bytes(&self) -> usize {
        (self.database_cap / 32).clamp(MIN_HEADROOM_BYTES, MAX_HEADROOM_BYTES) as usize
    }
    /// Frees the reserve in its own transaction. Deleting one large row
    /// rewrites a single leaf, so it fits where the acknowledgement did not.
    fn release_headroom(&mut self) -> Result<()> {
        if !self.headroom {
            return Ok(());
        }
        self.quota.arm(self.database_cap);
        let result = self.write_headroom(None);
        self.settle(result)?;
        self.headroom = false;
        Ok(())
    }
    /// Puts the reserve back and reopens admissions. If it does not fit yet,
    /// admissions stay refused and the next acknowledgement frees more.
    fn restore_headroom(&mut self) -> Result<()> {
        if !self.headroom {
            self.quota.arm(self.database_cap);
            #[cfg(test)]
            if self.hooks.take_refused_restore() {
                self.quota.arm(0);
            }
            let zeros = vec![0u8; self.headroom_bytes()];
            let result = self.write_headroom(Some(&zeros));
            match self.settle(result) {
                Ok(()) => self.headroom = true,
                Err(Error::Full) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
        self.at_cap = false;
        Ok(())
    }
    fn write_headroom(&self, reserve: Option<&[u8]>) -> Result<()> {
        let mut tx = self.db()?.begin_write().map_err(storage_error)?;
        tx.set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut table = tx.open_table(HEADROOM).map_err(storage_error)?;
            match reserve {
                Some(bytes) => table.insert(0, bytes).map(drop),
                None => table.remove(0).map(drop),
            }
            .map_err(storage_error)?;
        }
        tx.commit().map_err(storage_error)
    }
    pub fn stats(&self) -> Result<SpoolStats> {
        let inventory = inventory(&self.config.directory)?;
        Ok(SpoolStats {
            next_sequence: self.state.next,
            durable_through_sequence: self.state.durable,
            acknowledged_through_sequence: self.state.acknowledged,
            pending_records: self.pending.len() as u64,
            retained_records: self.state.count,
            database_bytes: inventory.database_bytes,
            disk_bytes: inventory.bytes,
            quarantine_bytes: inventory.quarantine_bytes,
            poisoned: self.poisoned.get(),
            headroom_reserved: self.headroom,
        })
    }
    fn active_key(&self) -> &EncryptionKey {
        self.keys.get(&self.active_id).unwrap()
    }
    fn healthy(&self) -> Result<()> {
        if self.poisoned.get() {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    /// Refuses admissions while the last transaction was refused at the disk
    /// ceiling, so a full spool answers without reopening its database each time.
    fn admissible(&self) -> Result<()> {
        self.healthy()?;
        if self.at_cap {
            Err(Error::Full)
        } else {
            Ok(())
        }
    }
    fn db(&self) -> Result<&Database> {
        self.db.as_ref().ok_or(Error::Poisoned)
    }
    /// Classifies a failed storage mutation. redb latches every backend error, so
    /// a transaction refused at the disk ceiling leaves the database unusable
    /// although nothing in it is wrong. Reopen it from its last commit and report
    /// `Full`; any other failure poisons the handle (DESIGN.md "Append, commit, and
    /// failures").
    fn settle<T>(&mut self, result: Result<T>) -> Result<T> {
        let error = match result {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if !self.quota.refused() {
            self.poisoned.set(true);
            return Err(error);
        }
        match self.reload() {
            Ok(()) => {
                self.at_cap = true;
                Err(Error::Full)
            }
            Err(error) => {
                self.poisoned.set(true);
                Err(error)
            }
        }
    }
    /// Reopens the database after a refusal at the ceiling and re-authenticates
    /// it. A refusal precedes redb's commit point, so the recovered state is the
    /// one this handle already holds; anything else is treated as corruption.
    fn reload(&mut self) -> Result<()> {
        let before = self.state;
        // Close the latched database before another handle opens the file.
        drop(self.db.take());
        self.quota.arm(self.database_cap);
        self.db = Some(open_database(
            &self.file,
            &self.quota,
            self.config.cache_bytes,
            #[cfg(test)]
            &self.hooks,
        )?);
        self.recover()?;
        if self.state != before {
            return Err(Error::Corrupt);
        }
        Ok(())
    }
    fn poison_on_failure<T>(&self, result: Result<T>) -> Result<T> {
        if result.is_err() {
            self.poisoned.set(true);
        }
        result
    }
    fn publish(
        &self,
        state: &format::State,
        records: &[(u64, Vec<u8>)],
        delete_through: Option<u64>,
    ) -> Result<()> {
        let envelope = format::encrypt(
            self.active_key(),
            &self.config.node_id,
            0,
            0,
            &state.encode(&self.config.node_id),
        )?;
        let mut tx = self.db()?.begin_write().map_err(storage_error)?;
        tx.set_durability(Durability::Immediate)
            .map_err(storage_error)?;
        {
            let mut table = tx.open_table(RECORDS).map_err(storage_error)?;
            if let Some(through) = delete_through {
                table
                    .retain_in(..=through, |_, _| false)
                    .map_err(storage_error)?;
            }
            for (sequence, bytes) in records {
                table
                    .insert(*sequence, bytes.as_slice())
                    .map_err(storage_error)?;
            }
        }
        tx.open_table(STATE)
            .map_err(storage_error)?
            .insert(0, envelope.as_slice())
            .map_err(storage_error)?;
        tx.commit().map_err(storage_error)
    }
    fn recover(&mut self) -> Result<String> {
        let tx = self.db()?.begin_read().map_err(storage_error)?;
        let mut table_count = 0;
        let mut has_headroom = false;
        let mut has_application = false;
        for table in tx.list_tables().map_err(storage_error)? {
            match table.name() {
                "records" | "state" => table_count += 1,
                "headroom" => has_headroom = true,
                "application" => has_application = true,
                _ => return Err(Error::Corrupt),
            }
        }
        // The reserve is unauthenticated filler: its only state is presence.
        let headroom = has_headroom
            && match tx.open_table(HEADROOM).map_err(storage_error)?.len() {
                Ok(0) => false,
                Ok(1) => true,
                Ok(_) => return Err(Error::Corrupt),
                Err(error) => return Err(storage_error(error)),
            };
        if table_count != 2
            || tx
                .list_multimap_tables()
                .map_err(storage_error)?
                .next()
                .is_some()
        {
            return Err(Error::Corrupt);
        }
        let states = tx.open_table(STATE).map_err(storage_error)?;
        if states.len().map_err(storage_error)? != 1 {
            return Err(Error::Corrupt);
        }
        let envelope = states
            .get(0)
            .map_err(storage_error)?
            .ok_or(Error::Corrupt)?;
        let state_key = format::key_id(envelope.value(), format::MAX_STATE_BYTES)?.to_owned();
        let plain = format::decrypt(
            &self.keys,
            &self.config.node_id,
            0,
            0,
            envelope.value(),
            format::MAX_STATE_BYTES,
        )?;
        let state = format::State::decode(&plain, &self.config.node_id)?;
        let table = tx.open_table(RECORDS).map_err(storage_error)?;
        if table.len().map_err(storage_error)? != state.count {
            return Err(Error::Corrupt);
        }
        let mut hash = format::inventory_hash();
        let mut last = state.acknowledged;
        let mut count = 0u64;
        for row in table.iter().map_err(storage_error)? {
            let (sequence, envelope) = row.map_err(storage_error)?;
            let sequence = sequence.value();
            if sequence <= last || sequence > state.durable || sequence >= state.next {
                return Err(Error::Corrupt);
            }
            format::decrypt(
                &self.keys,
                &self.config.node_id,
                1,
                sequence,
                envelope.value(),
                self.config.max_record_bytes,
            )?;
            format::hash_record(&mut hash, sequence, envelope.value());
            count = count.checked_add(1).ok_or(Error::Corrupt)?;
            last = sequence;
        }
        if count != state.count
            || last != state.durable
            || hash.clone().finish().as_ref() != state.digest
        {
            return Err(Error::Corrupt);
        }
        self.state = state;
        self.hash = hash;
        let application = if has_application {
            let table = tx.open_table(APPLICATION).map_err(storage_error)?;
            if table.len().map_err(storage_error)? > 1 {
                return Err(Error::Corrupt);
            }
            match table.get(0).map_err(storage_error)? {
                None => None,
                Some(envelope) => {
                    let key =
                        format::key_id(envelope.value(), self.config.max_record_bytes)?.to_owned();
                    let plain = format::decrypt(
                        &self.keys,
                        &self.config.node_id,
                        APPLICATION_KIND,
                        0,
                        envelope.value(),
                        self.config.max_record_bytes,
                    )?;
                    Some((plain, key))
                }
            }
        } else {
            None
        };
        self.headroom = headroom;
        self.application = application;
        Ok(state_key)
    }
}

fn open_database(
    file: &Arc<File>,
    quota: &Arc<storage::Quota>,
    cache_bytes: usize,
    #[cfg(test)] hooks: &Arc<Hooks>,
) -> Result<Database> {
    let backend = storage::Backend {
        file: file.clone(),
        quota: quota.clone(),
        #[cfg(test)]
        hooks: hooks.clone(),
    };
    Database::builder()
        .set_cache_size(cache_bytes)
        .create_with_backend(backend)
        .map_err(storage_error)
}
fn storage_error(error: impl Into<redb::Error>) -> Error {
    match error.into() {
        redb::Error::Io(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            Error::Corrupt
        }
        redb::Error::Io(e) => Error::Io(e),
        redb::Error::Corrupted(_)
        | redb::Error::TableDoesNotExist(_)
        | redb::Error::TableTypeMismatch { .. }
        | redb::Error::TableIsMultimap(_)
        | redb::Error::TableIsNotMultimap(_) => Error::Corrupt,
        redb::Error::UpgradeRequired(v) => Error::UnknownVersion(v as u32),
        other => Error::Storage(other.to_string()),
    }
}
#[derive(Default)]
struct Inventory {
    bytes: u64,
    database_bytes: u64,
    quarantine_bytes: u64,
}
fn inventory(directory: &Path) -> Result<Inventory> {
    let mut inventory = Inventory::default();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Corrupt);
        }
        inventory.bytes = inventory
            .bytes
            .checked_add(metadata.len())
            .ok_or(Error::Full)?;
        match entry.file_name().to_str() {
            Some("writer.lock") if metadata.len() == 0 => {}
            Some(DATABASE) => inventory.database_bytes = metadata.len(),
            Some(QUARANTINE) => inventory.quarantine_bytes = metadata.len(),
            _ => return Err(Error::Corrupt),
        }
    }
    Ok(inventory)
}
fn quarantine(directory: &Path, #[cfg(test)] hooks: &Hooks) -> Result<()> {
    #[cfg(test)]
    hooks.trip(Fault::QuarantineRename)?;
    fs::rename(directory.join(DATABASE), directory.join(QUARANTINE))?;
    #[cfg(test)]
    hooks.trip(Fault::QuarantineDirectorySync)?;
    sync_directory(directory)
}
fn sync_directory(directory: &Path) -> Result<()> {
    File::open(directory)?.sync_all()?;
    Ok(())
}
#[cfg(test)]
#[path = "redb_tests.rs"]
mod tests;
