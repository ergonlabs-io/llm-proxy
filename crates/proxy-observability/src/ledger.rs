//! The billing ledger's admission and in-process writer (ADR-0009 decisions 5
//! and 6).
//!
//! A request reserves one slot at admission, before anything is dialled. The
//! slot is held while the request runs and until its entry is committed, so
//! the slot count bounds both in-flight requests and uncommitted entries. A
//! request refused before dialling drops its reservation, which releases the
//! slot. A dialled request hands its entry, unnumbered, to a channel; one
//! writer thread numbers entries in the order it receives them, so `seq` is
//! gapless per `(instance_id, epoch)` without a lock on the request path.
//! Workers never wait on the writer: admission is one atomic increment and
//! the hand-off is one channel send.
//!
//! The writer appends to an encrypted `proxy-capture-spool` with group
//! commit: a batch is committed when it reaches `group_commit_max_entries` or
//! `group_commit_interval` after its first entry. Committed entries are never
//! evicted; they leave the spool only by acknowledgement.
//!
//! A crash loses every entry not yet committed. With space on disk that is
//! about one `group_commit_interval` of entries. At the disk cap the writer
//! holds entries in memory until an acknowledgement frees space, and a crash
//! loses all of them. Slots are held until commit, so `max_reservations`
//! bounds the loss in every case.
//!
//! The spool is single-writer, so reads and acknowledgements for the admin
//! API (ADR-0009 decision 8) travel to the writer thread on the same channel
//! as entries and are answered there. They block their caller, never a
//! worker: the admin server runs them off the data plane.

use crate::records::{LedgerCharge, LedgerEntry, RequestRecord, LEDGER_SCHEMA_VERSION};
use crate::stats::{instruments, Handle, Registry, StatsControl, WorkerId};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// What admission does when no reservation is available. Unset means
/// `Reject` (ADR-0009 decision 5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OnUnavailable {
    /// A local 503; no unledgered request reaches a provider.
    #[default]
    Reject,
    /// Serve the request without an entry. Fail-open, so it is counted and
    /// warned about (AGENTS.md "Fail-open controls").
    Admit,
}

/// Why no reservation was available. A closed set: it is a metric label and
/// part of the 503 body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// Every slot is held by a request in flight or an uncommitted entry.
    QueueFull,
    /// The writer stopped on a storage error or a panic.
    WriterFailed,
    /// The spool refused a write at its disk cap.
    DiskFull,
}

impl Unavailable {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::WriterFailed => "writer_failed",
            Self::DiskFull => "disk_full",
        }
    }

    const ALL: [Self; 3] = [Self::QueueFull, Self::WriterFailed, Self::DiskFull];
}

/// One spool encryption key: an id and a 0600 file of exactly 32 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerKeyFile {
    pub id: String,
    pub file: PathBuf,
}

pub const DEFAULT_MAX_RESERVATIONS: usize = 16_384;
pub const MAX_RESERVATIONS: usize = 1 << 20;
pub const DEFAULT_GROUP_COMMIT_MAX_ENTRIES: usize = 512;
/// The spool's own bound on one commit.
pub const MAX_GROUP_COMMIT_ENTRIES: usize = 4096;
pub const DEFAULT_GROUP_COMMIT_INTERVAL: Duration = Duration::from_millis(50);
/// An entry larger than this is not written; it is counted as lost. Entries
/// carry bounded record fields, so reaching it means a producer bug.
pub const MAX_ENTRY_BYTES: usize = 1024 * 1024;

/// `node.metadata["io.llmproxy.ledger"]`, or the dialect's `ledger` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerConfig {
    /// The spool directory. Created owner-only if absent.
    pub directory: PathBuf,
    /// The key new entries are sealed under.
    pub encryption_key: LedgerKeyFile,
    /// Retired keys, decrypt-only.
    pub previous_keys: Vec<LedgerKeyFile>,
    pub max_disk_bytes: u64,
    /// Slots: requests in flight plus entries not yet committed.
    pub max_reservations: usize,
    pub group_commit_max_entries: usize,
    pub group_commit_interval: Duration,
    pub on_unavailable: OnUnavailable,
}

const HEALTHY: u8 = 0;
const DISK_FULL: u8 = 1;
const FAILED: u8 = 2;

/// Seconds between unledgered-request warnings; the counter counts every one.
const UNLEDGERED_WARN_INTERVAL_SECS: u64 = 5;

/// How often an idle writer looks at the stop flag.
const IDLE_POLL: Duration = Duration::from_millis(100);

/// The terminal record and its charge, before the writer numbers it.
struct Pending {
    record: RequestRecord,
    charge: LedgerCharge,
}

/// What the writer thread receives: entries from workers, queries from the
/// admin API.
// Entries are nearly every message; boxing one would add an allocation per
// request to spare the rare query a few hundred bytes of channel slot.
#[allow(clippy::large_enum_variant)]
enum Message {
    Entry(Pending),
    Read {
        after: u64,
        limit: usize,
        reply: mpsc::SyncSender<Result<LedgerPage, LedgerQueryError>>,
    },
    Acknowledge {
        through: u64,
        reply: mpsc::SyncSender<Result<Acknowledged, LedgerQueryError>>,
    },
}

/// The most entries one read returns.
pub const MAX_PAGE_ENTRIES: usize = 1000;
/// The most payload bytes one read decrypts. Above [`MAX_ENTRY_BYTES`], so a
/// page always makes progress.
const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;

/// One committed entry and its position in this instance's spool.
///
/// `cursor` is what `after` and `through` take. It is not `seq`: `seq`
/// restarts at 0 in every epoch, and entries of an earlier epoch can still be
/// unacknowledged, so only the spool's position orders every entry the
/// ledger holds. It increases across restarts and never repeats.
#[derive(Debug, Clone, PartialEq)]
pub struct CommittedEntry {
    pub cursor: u64,
    pub entry: LedgerEntry,
}

/// One page of committed entries, in cursor order.
#[derive(Debug, Clone, PartialEq)]
pub struct LedgerPage {
    pub entries: Vec<CommittedEntry>,
    /// The cursor of the last committed entry; 0 when none was ever committed.
    pub committed_through: u64,
    /// This instance's recent epochs, oldest first; the last is the running
    /// one, which is not closed yet.
    pub epochs: Vec<EpochStatus>,
}

/// Whether an epoch ended with every entry handed to its writer committed.
/// An earlier epoch that is not `closed` crashed, or stopped with entries it
/// never committed, so entries may be missing from its end, where `seq`
/// cannot show the gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochStatus {
    pub epoch: u64,
    pub closed: bool,
}

/// Epochs remembered in the spool's application row, newest last.
const MAX_EPOCH_HISTORY: usize = 64;

/// The result of an acknowledgement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acknowledged {
    /// Every entry at or below this cursor is gone from the spool.
    pub acknowledged_through: u64,
    /// False while the spool is still at its disk cap after the
    /// acknowledgement freed what it could.
    pub admitting: bool,
}

/// Why a read or an acknowledgement got no answer. Fixed phrases: none
/// carries entry contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LedgerQueryError {
    #[error("the billing ledger writer has stopped")]
    Stopped,
    #[error("the billing ledger writer did not answer in time")]
    Timeout,
    #[error("through {through} is past the last committed entry ({committed_through})")]
    BeyondCommitted {
        through: u64,
        committed_through: u64,
    },
    #[error(
        "the ledger spool is at its disk cap and could not record even one entry of \
         this acknowledgement; retry"
    )]
    AcknowledgementFull,
    #[error("the billing ledger spool could not be read")]
    Storage,
}

/// The shared admission handle. One per process, shared by every worker.
pub struct Ledger {
    sender: mpsc::Sender<Message>,
    reserved: AtomicUsize,
    capacity: usize,
    state: AtomicU8,
    on_unavailable: OnUnavailable,
    stopping: AtomicBool,
    last_unledgered_warn_secs: AtomicU64,
    stats: LedgerStats,
}

/// Admission's grant: either a held slot or, under `admit`, a marker that the
/// request runs unledgered. Dropping either without using it is how a
/// request refused before dialling gives it back.
pub enum LedgerTicket {
    Reserved(LedgerReservation),
    Unledgered(Unledgered),
}

/// One held slot. [`Self::append`] hands the entry to the writer, which
/// releases the slot once the entry is committed; dropping the reservation
/// unused releases it at once.
pub struct LedgerReservation {
    ledger: Arc<Ledger>,
    /// Cleared once the entry is handed to the writer.
    armed: bool,
}

/// No slot under `on_unavailable: reject`. Admission runs before any filter,
/// but the refusal is answered only where the request would be dialled, so
/// a request that authentication, model access, a budget or a rate limit
/// refuses gets that answer instead. Counted only when answered.
pub struct LedgerRefusal {
    ledger: Arc<Ledger>,
    reason: Unavailable,
}

impl std::fmt::Debug for LedgerRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("LedgerRefusal").field(&self.reason).finish()
    }
}

impl LedgerRefusal {
    pub fn reason(&self) -> Unavailable {
        self.reason
    }

    /// The request is answered with the local 503: count it.
    pub fn refuse(self) -> Unavailable {
        self.ledger.stats.rejected(self.reason);
        self.reason
    }
}

/// A request admitted without a slot under `on_unavailable: admit`.
pub struct Unledgered {
    ledger: Arc<Ledger>,
    reason: Unavailable,
}

impl Ledger {
    /// Reserve a slot for one request. `Err` means `on_unavailable: reject`
    /// refused it; the caller answers with a local 503 before dialling and
    /// calls [`LedgerRefusal::refuse`].
    pub fn admit(self: &Arc<Self>) -> Result<LedgerTicket, LedgerRefusal> {
        let unavailable = match self.state.load(Ordering::Acquire) {
            FAILED => Some(Unavailable::WriterFailed),
            DISK_FULL => Some(Unavailable::DiskFull),
            _ => (!self.try_reserve()).then_some(Unavailable::QueueFull),
        };
        let Some(reason) = unavailable else {
            return Ok(LedgerTicket::Reserved(LedgerReservation {
                ledger: Arc::clone(self),
                armed: true,
            }));
        };
        match self.on_unavailable {
            OnUnavailable::Reject => Err(LedgerRefusal {
                ledger: Arc::clone(self),
                reason,
            }),
            OnUnavailable::Admit => Ok(LedgerTicket::Unledgered(Unledgered {
                ledger: Arc::clone(self),
                reason,
            })),
        }
    }

    fn try_reserve(&self) -> bool {
        let mut held = self.reserved.load(Ordering::Acquire);
        while held < self.capacity {
            match self.reserved.compare_exchange_weak(
                held,
                held + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(now) => held = now,
            }
        }
        false
    }

    fn release(&self, slots: usize) {
        if slots > 0 {
            self.reserved.fetch_sub(slots, Ordering::AcqRel);
        }
    }

    /// Slots held right now: requests in flight plus uncommitted entries.
    pub fn reserved(&self) -> usize {
        self.reserved.load(Ordering::Acquire)
    }

    /// Up to `limit` committed entries with a cursor above `after`, in cursor
    /// order. Entries handed over but not yet committed are never returned.
    /// Blocks until the writer answers or `deadline` passes; never call it
    /// from a request worker.
    pub fn read_committed(
        &self,
        after: u64,
        limit: usize,
        deadline: Duration,
    ) -> Result<LedgerPage, LedgerQueryError> {
        let limit = limit.clamp(1, MAX_PAGE_ENTRIES);
        self.ask(deadline, |reply| Message::Read {
            after,
            limit,
            reply,
        })
    }

    /// Remove every committed entry with a cursor at or below `through`. The
    /// space freed clears a disk-cap hold: entries held at the cap are
    /// written, and admission resumes without a restart. Blocks like
    /// [`Self::read_committed`].
    pub fn acknowledge(
        &self,
        through: u64,
        deadline: Duration,
    ) -> Result<Acknowledged, LedgerQueryError> {
        self.ask(deadline, |reply| Message::Acknowledge { through, reply })
    }

    fn ask<T>(
        &self,
        deadline: Duration,
        message: impl FnOnce(mpsc::SyncSender<Result<T, LedgerQueryError>>) -> Message,
    ) -> Result<T, LedgerQueryError> {
        let (reply, answer) = mpsc::sync_channel(1);
        self.sender
            .send(message(reply))
            .map_err(|_| LedgerQueryError::Stopped)?;
        answer.recv_timeout(deadline).map_err(|e| match e {
            mpsc::RecvTimeoutError::Timeout => LedgerQueryError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => LedgerQueryError::Stopped,
        })?
    }

    fn should_warn_unledgered(&self) -> bool {
        let now = unix_secs();
        let last = self.last_unledgered_warn_secs.load(Ordering::Relaxed);
        if last != 0 && now.saturating_sub(last) < UNLEDGERED_WARN_INTERVAL_SECS {
            return false;
        }
        self.last_unledgered_warn_secs
            .compare_exchange(last, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }
}

impl LedgerReservation {
    /// Hand the terminal entry to the writer. Never blocks: the channel is
    /// unbounded, and its depth is bounded by the slots already reserved.
    pub fn append(mut self, record: RequestRecord, charge: LedgerCharge) {
        // From here the writer owns the slot and releases it on commit.
        self.armed = false;
        if self
            .ledger
            .sender
            .send(Message::Entry(Pending { record, charge }))
            .is_err()
        {
            // The writer has exited; this entry has nowhere to go.
            self.ledger.stats.lost(LostReason::WriterFailed, 1);
            self.ledger.release(1);
        }
    }
}

impl Drop for LedgerReservation {
    fn drop(&mut self) {
        if self.armed {
            self.ledger.release(1);
        }
    }
}

impl Unledgered {
    /// The request was dialled without an entry: count it, and warn at most
    /// once per window. The warning names only the reason.
    pub fn dialled(self) {
        self.ledger.stats.unledgered(self.reason);
        if self.ledger.should_warn_unledgered() {
            tracing::warn!(
                reason = self.reason.as_str(),
                "billing ledger unavailable: request served without a ledger entry \
                 (on_unavailable: admit); further warnings are suppressed for \
                 {UNLEDGERED_WARN_INTERVAL_SECS}s, llmproxy_ledger_unledgered_total counts every one"
            );
        }
    }
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone, Copy)]
enum LostReason {
    WriterFailed,
    Oversize,
    Shutdown,
}

/// The ledger's counters. All resolved at open, so an idle ledger scrapes as
/// explicit zeroes.
struct LedgerStats {
    registry: Arc<Registry>,
    rejected: [Handle; 3],
    unledgered: [Handle; 3],
    committed: Handle,
    lost: [Handle; 3],
    spend_written: Handle,
    unclean_epochs: Handle,
}

impl LedgerStats {
    fn resolve(control: &StatsControl) -> Self {
        let by_reason = |instrument| {
            Unavailable::ALL.map(|r| control.resolve(instrument, &[("reason", r.as_str())]))
        };
        Self {
            registry: control.registry(),
            rejected: by_reason(&instruments::LEDGER_REJECTED),
            unledgered: by_reason(&instruments::LEDGER_UNLEDGERED),
            committed: control.resolve(&instruments::LEDGER_COMMITTED, &[]),
            lost: ["writer_failed", "oversize", "shutdown"]
                .map(|r| control.resolve(&instruments::LEDGER_LOST, &[("reason", r)])),
            spend_written: control.resolve(&instruments::LEDGER_SPEND_WRITTEN, &[]),
            unclean_epochs: control.resolve(&instruments::LEDGER_UNCLEAN_EPOCHS, &[]),
        }
    }

    fn unclean_epoch(&self) {
        self.registry.incr(WorkerId(0), self.unclean_epochs, 1);
    }

    fn index(reason: Unavailable) -> usize {
        Unavailable::ALL.iter().position(|r| *r == reason).unwrap()
    }

    fn rejected(&self, reason: Unavailable) {
        self.registry
            .incr(WorkerId(0), self.rejected[Self::index(reason)], 1);
    }

    fn unledgered(&self, reason: Unavailable) {
        self.registry
            .incr(WorkerId(0), self.unledgered[Self::index(reason)], 1);
    }

    fn committed(&self, entries: usize, spend_micro_usd: u64) {
        self.registry
            .incr(WorkerId(0), self.committed, entries as u64);
        self.registry
            .incr(WorkerId(0), self.spend_written, spend_micro_usd);
    }

    fn lost(&self, reason: LostReason, entries: usize) {
        if entries > 0 {
            self.registry
                .incr(WorkerId(0), self.lost[reason as usize], entries as u64);
        }
    }
}

#[cfg(all(unix, test))]
pub(crate) use writer::test_hooks as writer_test_hooks;
#[cfg(unix)]
pub use writer::{open, LedgerOpenError, LedgerWriter};

#[cfg(unix)]
mod writer {
    use super::*;
    use proxy_capture_spool::{EncryptionKey, Error as SpoolError, MetadataSpool, SpoolConfig};
    use std::collections::VecDeque;
    use std::io::Read;
    use std::time::Instant;

    /// Why the ledger could not start. `Key` and `Spool` messages start with
    /// the config field they concern; none renders key material.
    #[derive(Debug, thiserror::Error)]
    pub enum LedgerOpenError {
        #[error("{field}: cannot load key file {path}: {reason}")]
        Key {
            field: String,
            path: PathBuf,
            reason: String,
        },
        #[error("directory: cannot open ledger spool at {path}: {source}")]
        Spool {
            path: PathBuf,
            #[source]
            source: SpoolError,
        },
        #[error("cannot start ledger writer thread: {0}")]
        Thread(std::io::Error),
    }

    /// Owns the writer thread. [`Self::shutdown`] commits what is queued.
    pub struct LedgerWriter {
        ledger: Arc<Ledger>,
        done: mpsc::Receiver<()>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl LedgerWriter {
        /// Stop after committing every entry already handed over. Call once
        /// no worker can append any more. Blocks for up to `deadline`;
        /// returns whether the writer finished in time.
        pub fn shutdown(mut self, deadline: Duration) -> bool {
            self.ledger.stopping.store(true, Ordering::Release);
            let finished = matches!(
                self.done.recv_timeout(deadline),
                Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected)
            );
            if finished {
                if let Some(thread) = self.thread.take() {
                    let _ = thread.join();
                }
            }
            finished
        }
    }

    /// Open the spool, choose this start's epoch, and start the writer.
    /// `instance_id` must be unique per writer and stable across restarts;
    /// it is also the spool's node id, so a spool written under another id
    /// does not open.
    pub fn open(
        config: &LedgerConfig,
        instance_id: &str,
        stats: &StatsControl,
    ) -> Result<(Arc<Ledger>, LedgerWriter), LedgerOpenError> {
        let active = load_key(&config.encryption_key, "encryption_key_file")?;
        let previous = config
            .previous_keys
            .iter()
            .enumerate()
            .map(|(i, key)| load_key(key, &format!("previous_keys[{i}].file")))
            .collect::<Result<Vec<_>, _>>()?;
        let spool_error = |source| LedgerOpenError::Spool {
            path: config.directory.clone(),
            source,
        };
        let mut spool = MetadataSpool::open(
            SpoolConfig {
                directory: config.directory.clone(),
                node_id: instance_id.to_owned(),
                max_record_bytes: MAX_ENTRY_BYTES,
                max_disk_bytes: config.max_disk_bytes,
                cache_bytes: proxy_capture_spool::DEFAULT_CACHE_BYTES,
                max_pending_records: config.group_commit_max_entries,
            },
            active,
            previous,
        )
        .map_err(spool_error)?;
        let stats = LedgerStats::resolve(stats);
        let mut epochs = epoch_history(&spool);
        if let Some(previous) = epochs.last().filter(|e| !e.closed) {
            stats.unclean_epoch();
            tracing::error!(
                instance_id,
                epoch = previous.epoch,
                "billing ledger: the previous epoch did not close; it crashed or stopped with \
                 uncommitted entries, so entries may be missing from its end"
            );
        }
        let after_history = epochs.last().map_or(0, |e| e.epoch.saturating_add(1));
        let epoch = next_epoch(&spool).map_err(spool_error)?.max(after_history);
        epochs.push(EpochStatus {
            epoch,
            closed: false,
        });
        if epochs.len() > MAX_EPOCH_HISTORY {
            epochs.drain(..epochs.len() - MAX_EPOCH_HISTORY);
        }
        match spool.set_application_state(&encode_history(&epochs)) {
            Ok(()) => {}
            // A start at the disk cap: the ledger still serves, but this
            // epoch's end cannot be judged after a restart.
            Err(SpoolError::Full) => tracing::error!(
                epoch,
                "billing ledger spool is at its disk cap and cannot record this epoch; \
                 a crash in it will not be detected after restart"
            ),
            Err(error) => return Err(spool_error(error)),
        }
        let (sender, receiver) = mpsc::channel();
        let ledger = Arc::new(Ledger {
            sender,
            reserved: AtomicUsize::new(0),
            capacity: config.max_reservations,
            state: AtomicU8::new(HEALTHY),
            on_unavailable: config.on_unavailable,
            stopping: AtomicBool::new(false),
            last_unledgered_warn_secs: AtomicU64::new(0),
            stats,
        });
        let (done_tx, done) = mpsc::channel();
        let writer = Writer {
            ledger: Arc::clone(&ledger),
            receiver,
            spool,
            instance_id: instance_id.to_owned(),
            epoch,
            next_seq: 0,
            max_batch: config.group_commit_max_entries,
            interval: config.group_commit_interval,
            uncommitted: 0,
            uncommitted_spend: 0,
            backlog: VecDeque::new(),
            epochs,
            #[cfg(test)]
            hooks: test_hooks::current(),
        };
        let thread = std::thread::Builder::new()
            .name("ledger-writer".into())
            .spawn(move || {
                let _guard = FailOnPanic(Arc::clone(&writer.ledger));
                writer.run();
                let _ = done_tx.send(());
            })
            .map_err(LedgerOpenError::Thread)?;
        tracing::info!(
            instance_id,
            epoch,
            on_unavailable = ?config.on_unavailable,
            "billing ledger writer started"
        );
        Ok((
            Arc::clone(&ledger),
            LedgerWriter {
                ledger,
                done,
                thread: Some(thread),
            },
        ))
    }

    /// Marks the writer failed if its thread unwinds, so admission stops
    /// granting slots nobody will release.
    struct FailOnPanic(Arc<Ledger>);

    impl Drop for FailOnPanic {
        fn drop(&mut self) {
            if std::thread::panicking() {
                self.0.state.store(FAILED, Ordering::Release);
                tracing::error!(
                    "billing ledger writer panicked; admissions now follow on_unavailable"
                );
            }
        }
    }

    /// A private regular file of exactly 32 bytes, as the capture agent and
    /// tenant credential keys require.
    fn load_key(key: &LedgerKeyFile, field: &str) -> Result<EncryptionKey, LedgerOpenError> {
        use std::os::unix::fs::PermissionsExt;
        let fail = |reason: &str| LedgerOpenError::Key {
            field: field.to_owned(),
            path: key.file.clone(),
            reason: reason.to_owned(),
        };
        let metadata = std::fs::symlink_metadata(&key.file).map_err(|e| fail(&e.to_string()))?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(fail("requires a private (0600) regular file"));
        }
        let mut bytes = Vec::with_capacity(33);
        std::fs::File::open(&key.file)
            .and_then(|f| f.take(33).read_to_end(&mut bytes))
            .map_err(|e| fail(&e.to_string()))?;
        let raw: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| fail("requires exactly 32 bytes"))?;
        bytes.fill(0);
        EncryptionKey::new(key.id.clone(), raw).map_err(|_| fail("invalid key id"))
    }

    /// The epochs recorded in the spool's application row. Unreadable means
    /// none: the row is authenticated, so only a format change gets here.
    fn epoch_history(spool: &MetadataSpool) -> Vec<EpochStatus> {
        #[derive(serde::Deserialize)]
        struct History {
            epochs: Vec<EpochStatus>,
        }
        spool.application_state().map_or_else(Vec::new, |bytes| {
            serde_json::from_slice::<History>(bytes).map_or_else(
                |_| {
                    tracing::warn!(
                        "billing ledger epoch history does not decode; starting a new one"
                    );
                    Vec::new()
                },
                |h| h.epochs,
            )
        })
    }

    fn encode_history(epochs: &[EpochStatus]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "epochs": epochs }))
            .expect("epoch history serializes")
    }

    /// Wall-clock milliseconds, but always past the epoch of the last
    /// unacknowledged entry, so a clock step back cannot repeat an epoch
    /// while that entry is still in the spool.
    fn next_epoch(spool: &MetadataSpool) -> Result<u64, SpoolError> {
        #[derive(serde::Deserialize)]
        struct EpochOnly {
            epoch: u64,
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let stats = spool.stats()?;
        let last = if stats.durable_through_sequence > stats.acknowledged_through_sequence {
            spool
                .replay(stats.durable_through_sequence - 1, 1, MAX_ENTRY_BYTES)?
                .pop()
                .and_then(|r| serde_json::from_slice::<EpochOnly>(&r.payload).ok())
                .map(|e| e.epoch)
        } else {
            None
        };
        Ok(last.map_or(now, |e| now.max(e.saturating_add(1))))
    }

    struct Writer {
        ledger: Arc<Ledger>,
        receiver: mpsc::Receiver<Message>,
        spool: MetadataSpool,
        instance_id: String,
        epoch: u64,
        next_seq: u64,
        max_batch: usize,
        interval: Duration,
        /// Appended to the spool, not yet committed. Their slots are held.
        uncommitted: usize,
        /// Their spend charges, counted written once they commit.
        uncommitted_spend: u64,
        /// Received while the spool is at its cap: numbered when appended.
        backlog: VecDeque<LedgerEntry>,
        /// Recent epochs, this one last; marked closed at a clean stop.
        epochs: Vec<EpochStatus>,
        #[cfg(test)]
        hooks: Arc<test_hooks::Hooks>,
    }

    impl Writer {
        fn run(mut self) {
            let mut batch = Vec::with_capacity(self.max_batch);
            while !self.ledger.stopping.load(Ordering::Acquire) {
                let first = match self.receiver.recv_timeout(IDLE_POLL) {
                    Ok(Message::Entry(pending)) => pending,
                    Ok(query) => {
                        if let Err(error) = self.answer(query) {
                            return self.fail(error, batch);
                        }
                        continue;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                batch.push(self.entry(first));
                let deadline = Instant::now() + self.interval;
                while batch.len() < self.max_batch {
                    let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    match self.receiver.recv_timeout(wait) {
                        Ok(Message::Entry(pending)) => batch.push(self.entry(pending)),
                        // Answered at once, before this batch commits: a
                        // read sees only what is already committed.
                        Ok(query) => {
                            if let Err(error) = self.answer(query) {
                                return self.fail(error, batch);
                            }
                        }
                        Err(_) => break,
                    }
                }
                if let Err(error) = self.write(&mut batch) {
                    return self.fail(error, batch);
                }
            }
            // Stopping: workers can no longer append, so drain what is queued.
            // Queries are dropped unanswered; their callers see `Stopped`.
            loop {
                batch.extend(
                    self.receiver
                        .try_iter()
                        .filter_map(|m| match m {
                            Message::Entry(pending) => Some(pending),
                            _ => None,
                        })
                        .take(self.max_batch)
                        .map(|p| self.entry(p))
                        .collect::<Vec<_>>(),
                );
                if batch.is_empty() {
                    break;
                }
                if let Err(error) = self.write(&mut batch) {
                    return self.fail(error, batch);
                }
            }
            let lost = self.backlog.len() + self.uncommitted;
            if lost > 0 {
                self.ledger.stats.lost(LostReason::Shutdown, lost);
                tracing::warn!(
                    entries = lost,
                    "billing ledger stopped at its disk cap with uncommitted entries; they are lost"
                );
                // Not closed: the next start reports this epoch's end as
                // incomplete, after this process's counters are gone.
                return;
            }
            self.close_epoch();
        }

        /// Record that this epoch ended with every entry committed. Refused
        /// at the cap, the next start reports it unclean: a false alarm, never
        /// a missed one.
        fn close_epoch(&mut self) {
            if let Some(current) = self.epochs.last_mut() {
                current.closed = true;
            }
            if let Err(error) = self
                .spool
                .set_application_state(&encode_history(&self.epochs))
            {
                tracing::warn!(
                    %error,
                    epoch = self.epoch,
                    "billing ledger could not record a clean close; the next start reports \
                     this epoch unclean"
                );
            }
        }

        /// Answer one admin query. `Err` is a storage failure the writer
        /// cannot continue past; the caller then sees `Stopped`.
        fn answer(&mut self, query: Message) -> Result<(), SpoolError> {
            match query {
                Message::Entry(_) => unreachable!("entries are batched, not answered"),
                Message::Read {
                    after,
                    limit,
                    reply,
                } => {
                    let page = self.read(after, limit)?;
                    let _ = reply.send(page);
                }
                Message::Acknowledge { through, reply } => {
                    let outcome = self.acknowledge(through)?;
                    let _ = reply.send(outcome);
                }
            }
            Ok(())
        }

        fn read(
            &self,
            after: u64,
            limit: usize,
        ) -> Result<Result<LedgerPage, LedgerQueryError>, SpoolError> {
            let Ok(stats) = self.spool.stats() else {
                // A directory listing failed; the spool itself is unharmed.
                return Ok(Err(LedgerQueryError::Storage));
            };
            // The spool replays durable records only: what a refused commit
            // keeps pending is not returned.
            let records = self.spool.replay(after, limit, MAX_PAGE_BYTES)?;
            let mut entries = Vec::with_capacity(records.len());
            for record in records {
                let Ok(entry) = serde_json::from_slice(&record.payload) else {
                    tracing::error!(
                        cursor = record.sequence,
                        "billing ledger entry does not decode; reads cannot pass it"
                    );
                    return Ok(Err(LedgerQueryError::Storage));
                };
                entries.push(CommittedEntry {
                    cursor: record.sequence,
                    entry,
                });
            }
            Ok(Ok(LedgerPage {
                entries,
                committed_through: stats.durable_through_sequence,
                epochs: self.epochs.clone(),
            }))
        }

        fn acknowledge(
            &mut self,
            through: u64,
        ) -> Result<Result<Acknowledged, LedgerQueryError>, SpoolError> {
            match self.spool.acknowledge(through) {
                Ok(()) => {}
                Err(SpoolError::InvalidAcknowledgement) => {
                    let committed_through =
                        self.spool.stats().map_or(0, |s| s.durable_through_sequence);
                    return Ok(Err(LedgerQueryError::BeyondCommitted {
                        through,
                        committed_through,
                    }));
                }
                // The spool spends its reserve and acknowledges in prefixes
                // before it answers this, so even one entry did not fit; a
                // prefix may have been acknowledged.
                Err(SpoolError::Full) => return Ok(Err(LedgerQueryError::AcknowledgementFull)),
                Err(error) => return Err(error),
            }
            if self.ledger.state.load(Ordering::Acquire) == DISK_FULL {
                self.resume_after_cap()?;
            }
            let acknowledged_through = self
                .spool
                .stats()
                .map_or(through, |s| s.acknowledged_through_sequence);
            Ok(Ok(Acknowledged {
                acknowledged_through,
                admitting: self.ledger.state.load(Ordering::Acquire) == HEALTHY,
            }))
        }

        /// An acknowledgement freed space: commit what a refused commit left
        /// pending, then write the held entries in arrival order, then let
        /// admission resume. If the space runs out again part way, the rest
        /// stays held and the cap is re-entered.
        fn resume_after_cap(&mut self) -> Result<(), SpoolError> {
            if self.uncommitted > 0 && !self.commit()? {
                return Ok(());
            }
            self.ledger.state.store(HEALTHY, Ordering::Release);
            tracing::info!(
                held = self.backlog.len(),
                "billing ledger spool has space again after an acknowledgement; admissions resume"
            );
            while !self.backlog.is_empty() {
                let take = self.backlog.len().min(self.max_batch);
                let mut batch: Vec<_> = self.backlog.drain(..take).collect();
                // Refused at the cap, `write` holds the batch in the backlog,
                // which is empty here, so it stays ahead of the entries that
                // arrived after it.
                let rest = std::mem::take(&mut self.backlog);
                let result = self.write(&mut batch);
                self.backlog.extend(rest);
                if let Err(error) = result {
                    // Counted lost with the backlog by `fail`.
                    self.backlog.extend(batch);
                    return Err(error);
                }
                if self.ledger.state.load(Ordering::Acquire) != HEALTHY {
                    break;
                }
            }
            Ok(())
        }

        /// The entry as received; `seq` is set when it is appended.
        fn entry(&self, pending: Pending) -> LedgerEntry {
            LedgerEntry {
                schema_version: LEDGER_SCHEMA_VERSION,
                instance_id: self.instance_id.clone(),
                epoch: self.epoch,
                seq: 0,
                charged_micro_usd: pending.charge.charged_micro_usd,
                charged_scopes: pending.charge.charged_scopes,
                rate_card_version: pending.charge.rate_card_version,
                policy_generation: pending.record.policy_generation,
                record: pending.record,
            }
        }

        /// Append and commit one batch, or hold it while the spool is at its
        /// cap. `Err` is a storage failure the writer cannot continue past.
        fn write(&mut self, batch: &mut Vec<LedgerEntry>) -> Result<(), SpoolError> {
            #[cfg(test)]
            self.hooks.before_write()?;
            if self.ledger.state.load(Ordering::Acquire) == DISK_FULL {
                // Only an acknowledgement frees space; until one arrives the
                // spool refuses at once, so hold the entries unnumbered.
                self.backlog.extend(batch.drain(..));
                return Ok(());
            }
            // Numbered in arrival order. An entry that cannot be written is
            // not numbered, so `seq` stays gapless.
            let first_seq = self.next_seq;
            let mut payloads = Vec::with_capacity(batch.len());
            let mut oversize = 0;
            let mut spend = 0u64;
            batch.retain_mut(|entry| {
                entry.seq = self.next_seq;
                let bytes = serde_json::to_vec(&*entry).expect("ledger entries serialize");
                if bytes.len() > MAX_ENTRY_BYTES {
                    oversize += 1;
                    return false;
                }
                self.next_seq += 1;
                // Only a charge the spend filter made is a spend charge
                // (ADR-0009 decision 7); a list price on an unbudgeted route
                // is not.
                if !entry.charged_scopes.is_empty() {
                    spend = spend.saturating_add(entry.charged_micro_usd);
                }
                payloads.push(bytes);
                true
            });
            if oversize > 0 {
                self.ledger.stats.lost(LostReason::Oversize, oversize);
                self.ledger.release(oversize);
                tracing::error!(
                    entries = oversize,
                    max_bytes = MAX_ENTRY_BYTES,
                    "billing ledger entries exceed the entry size limit and were not written"
                );
            }
            let views: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            #[cfg(test)]
            let appended = if self.hooks.take_refused_append() {
                Err(SpoolError::Full)
            } else {
                self.spool.append_batch(&views)
            };
            #[cfg(not(test))]
            let appended = self.spool.append_batch(&views);
            match appended {
                Ok(results) => {
                    if let Some(Err(error)) = results.into_iter().find(Result::is_err) {
                        return Err(error);
                    }
                    self.uncommitted += payloads.len();
                    self.uncommitted_spend = self.uncommitted_spend.saturating_add(spend);
                    batch.clear();
                }
                Err(SpoolError::Full) => {
                    // Nothing was appended: give the numbers back.
                    self.next_seq = first_seq;
                    self.at_cap();
                    self.backlog.extend(batch.drain(..));
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
            self.commit().map(|_| ())
        }

        /// Commit what is appended. `Ok(false)`: refused at the disk cap; the
        /// records stay pending in the spool, slots held.
        fn commit(&mut self) -> Result<bool, SpoolError> {
            match self.spool.commit() {
                Ok(_) => {
                    self.ledger
                        .stats
                        .committed(self.uncommitted, self.uncommitted_spend);
                    self.ledger.release(self.uncommitted);
                    self.uncommitted = 0;
                    self.uncommitted_spend = 0;
                    Ok(true)
                }
                Err(SpoolError::Full) => {
                    self.at_cap();
                    Ok(false)
                }
                Err(error) => Err(error),
            }
        }

        fn at_cap(&self) {
            if self.ledger.state.swap(DISK_FULL, Ordering::AcqRel) != DISK_FULL {
                tracing::error!(
                    "billing ledger spool is at its disk cap; committed entries are kept, and \
                     admissions follow on_unavailable until entries are acknowledged"
                );
            }
        }

        /// Stop for good: count everything this writer still owed as lost and
        /// give its slots back, then exit, which closes the channel.
        fn fail(self, error: SpoolError, batch: Vec<LedgerEntry>) {
            self.ledger.state.store(FAILED, Ordering::Release);
            let queued = self
                .receiver
                .try_iter()
                .filter(|m| matches!(m, Message::Entry(_)))
                .count();
            let lost = batch.len() + self.backlog.len() + self.uncommitted + queued;
            self.ledger.stats.lost(LostReason::WriterFailed, lost);
            self.ledger.release(lost);
            tracing::error!(
                %error,
                entries_lost = lost,
                "billing ledger writer failed; admissions now follow on_unavailable"
            );
        }
    }

    /// Test-only control over the writer, in the spirit of the spool's own
    /// fault hooks: a stall that holds the writer before its next write, a
    /// storage failure on its next write, and refusals at the disk cap of
    /// its next appends. The spool refuses an append at the cap only when its
    /// small reservation transaction is the one that crosses the cap, which
    /// no entry size makes deterministic.
    #[cfg(test)]
    pub(crate) mod test_hooks {
        use super::SpoolError;
        use std::sync::{Arc, Condvar, Mutex};

        #[derive(Default)]
        pub(crate) struct Hooks {
            stalled: Mutex<bool>,
            resumed: Condvar,
            fail_next: Mutex<bool>,
            refuse_appends: Mutex<usize>,
        }

        impl Hooks {
            pub(crate) fn stall(&self) {
                *self.stalled.lock().unwrap() = true;
            }
            pub(crate) fn resume(&self) {
                *self.stalled.lock().unwrap() = false;
                self.resumed.notify_all();
            }
            pub(crate) fn fail_next_write(&self) {
                *self.fail_next.lock().unwrap() = true;
            }
            /// Refuse the next `n` appends at the disk cap.
            pub(crate) fn refuse_appends(&self, n: usize) {
                *self.refuse_appends.lock().unwrap() = n;
            }
            pub(super) fn take_refused_append(&self) -> bool {
                let mut left = self.refuse_appends.lock().unwrap();
                let refuse = *left > 0;
                *left = left.saturating_sub(1);
                refuse
            }
            pub(super) fn before_write(&self) -> Result<(), SpoolError> {
                let mut stalled = self.stalled.lock().unwrap();
                while *stalled {
                    stalled = self.resumed.wait(stalled).unwrap();
                }
                if std::mem::take(&mut *self.fail_next.lock().unwrap()) {
                    return Err(SpoolError::Storage("injected by test".into()));
                }
                Ok(())
            }
        }

        thread_local! {
            static NEXT: std::cell::RefCell<Option<Arc<Hooks>>> = const { std::cell::RefCell::new(None) };
        }

        /// Hooks for the next `open` on this thread.
        pub(crate) fn install() -> Arc<Hooks> {
            let hooks = Arc::new(Hooks::default());
            NEXT.with(|n| *n.borrow_mut() = Some(Arc::clone(&hooks)));
            hooks
        }

        pub(super) fn current() -> Arc<Hooks> {
            NEXT.with(|n| n.borrow_mut().take()).unwrap_or_default()
        }
    }
}

/// Shared test infrastructure: a ledger in a temporary directory, and a reader
/// for what its writer committed. Used by this crate's tests and, through
/// the `test-support` feature, by the HTTP and listener tests.
#[cfg(all(unix, any(test, feature = "test-support")))]
pub mod testing {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    pub const INSTANCE_ID: &str = "test-instance";

    /// A key file and a spool directory under one temporary directory.
    pub struct TempLedgerDir {
        pub root: tempfile::TempDir,
    }

    impl TempLedgerDir {
        pub fn new() -> Self {
            let root = tempfile::tempdir().expect("tempdir");
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
                .expect("chmod tempdir");
            let key = root.path().join("ledger.key");
            std::fs::write(&key, [7u8; 32]).expect("write key");
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
                .expect("chmod key");
            Self { root }
        }

        pub fn config(
            &self,
            max_reservations: usize,
            on_unavailable: OnUnavailable,
        ) -> LedgerConfig {
            LedgerConfig {
                directory: self.root.path().join("spool"),
                encryption_key: LedgerKeyFile {
                    id: "k1".into(),
                    file: self.root.path().join("ledger.key"),
                },
                previous_keys: Vec::new(),
                max_disk_bytes: 64 * 1024 * 1024,
                max_reservations,
                group_commit_max_entries: DEFAULT_GROUP_COMMIT_MAX_ENTRIES,
                group_commit_interval: Duration::from_millis(5),
                on_unavailable,
            }
        }
    }

    impl Default for TempLedgerDir {
        fn default() -> Self {
            Self::new()
        }
    }

    /// An open ledger with its writer, its directory, and its counters.
    pub struct TempLedger {
        pub ledger: Arc<Ledger>,
        pub config: LedgerConfig,
        pub stats: StatsControl,
        writer: Option<LedgerWriter>,
        dir: TempLedgerDir,
    }

    impl TempLedger {
        pub fn open(max_reservations: usize, on_unavailable: OnUnavailable) -> Self {
            let dir = TempLedgerDir::new();
            let config = dir.config(max_reservations, on_unavailable);
            Self::open_with(dir, config)
        }

        pub fn open_with(dir: TempLedgerDir, config: LedgerConfig) -> Self {
            let stats = StatsControl::new(1);
            let (ledger, writer) = open(&config, INSTANCE_ID, &stats).expect("open ledger");
            Self {
                ledger,
                config,
                stats,
                writer: Some(writer),
                dir,
            }
        }

        /// Stop the writer, committing what it was handed, and return every
        /// committed entry in spool order.
        pub fn entries(&mut self) -> Vec<LedgerEntry> {
            if let Some(writer) = self.writer.take() {
                assert!(writer.shutdown(Duration::from_secs(10)), "writer stops");
            }
            committed_entries(&self.config, INSTANCE_ID)
        }

        /// Stop the writer and open the same spool again: a process restart.
        pub fn restart(&mut self) {
            if let Some(writer) = self.writer.take() {
                assert!(writer.shutdown(Duration::from_secs(10)), "writer stops");
            }
            self.stats = StatsControl::new(1);
            let (ledger, writer) =
                open(&self.config, INSTANCE_ID, &self.stats).expect("reopen ledger");
            self.ledger = ledger;
            self.writer = Some(writer);
        }

        /// The Prometheus rendering of this ledger's counters.
        pub fn scrape(&self) -> String {
            crate::stats::prometheus_render::render(&self.stats.registry())
        }

        pub fn dir(&self) -> &TempLedgerDir {
            &self.dir
        }
    }

    impl Drop for TempLedger {
        fn drop(&mut self) {
            if let Some(writer) = self.writer.take() {
                writer.shutdown(Duration::from_secs(10));
            }
        }
    }

    /// A completed request's record, as an entry carries it.
    pub fn record(event_id: &str) -> RequestRecord {
        use crate::records::{Termination, SCHEMA_VERSION};
        RequestRecord {
            schema_version: SCHEMA_VERSION,
            event_id: event_id.into(),
            request_id: "r".into(),
            instance_id: "i".into(),
            started_at: "2026-10-01T00:00:00Z".into(),
            finished_at: "2026-10-01T00:00:01Z".into(),
            tenant_id: "default".into(),
            user_id: None,
            key_id: None,
            trace_id: None,
            routing_revision: None,
            policy_generation: None,
            capture_policy_version: None,
            method: "POST".into(),
            route: "/v1/chat/completions".into(),
            requested_model: None,
            resolved_model: None,
            selected_cluster: None,
            selected_provider: None,
            selected_model: None,
            upstream_response_id: None,
            upstream_usage: None,
            status: Some(200),
            termination: Termination::Complete,
            error_category: None,
            response_flags: vec![],
            duration_ms: 1,
            time_to_first_byte_ms: None,
            bytes_request: 0,
            bytes_response: 0,
            usage: None,
            cost: None,
            attempt_count: 0,
            physical_attempt_count: 0,
            attempts: vec![],
            attempts_truncated: false,
            credential_source: None,
            record_seq: None,
        }
    }

    /// Every committed, unacknowledged entry in a closed ledger spool.
    pub fn committed_entries(config: &LedgerConfig, instance_id: &str) -> Vec<LedgerEntry> {
        let key = |k: &LedgerKeyFile| {
            let raw: [u8; 32] = std::fs::read(&k.file).unwrap().try_into().unwrap();
            proxy_capture_spool::EncryptionKey::new(k.id.clone(), raw).unwrap()
        };
        let spool = proxy_capture_spool::MetadataSpool::open(
            proxy_capture_spool::SpoolConfig {
                directory: config.directory.clone(),
                node_id: instance_id.to_owned(),
                max_record_bytes: MAX_ENTRY_BYTES,
                max_disk_bytes: config.max_disk_bytes,
                cache_bytes: proxy_capture_spool::DEFAULT_CACHE_BYTES,
                max_pending_records: config.group_commit_max_entries,
            },
            key(&config.encryption_key),
            config.previous_keys.iter().map(key).collect::<Vec<_>>(),
        )
        .expect("reopen ledger spool");
        let mut entries = Vec::new();
        let mut after = 0;
        loop {
            let page = spool.replay(after, 1024, usize::MAX).expect("replay");
            let Some(last) = page.last() else {
                return entries;
            };
            after = last.sequence;
            entries.extend(
                page.iter()
                    .map(|r| serde_json::from_slice(&r.payload).expect("entry json")),
            );
        }
    }
}
