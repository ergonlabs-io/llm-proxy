//! Trace segments on disk (ADR-0008 decision 7; design note section 6).
//!
//! ```text
//! <directory>/tenant=<t>/date=<yyyy-mm-dd>/<instance>-<epoch>-<seq>.jsonl.gz        sealed
//! <directory>/tenant=<t>/date=<yyyy-mm-dd>/.<instance>-<epoch>-<seq>.jsonl.gz.open  being written
//! <directory>/.lock  .capture-disabled  .epoch-<instance>                          control files
//! ```
//!
//! One process owns the directory (an exclusive `flock`), so every `.open`
//! file found at startup is a crash leftover. Sealing finishes the encoder,
//! syncs the file, renames it to its sealed name and syncs the directory, so
//! a reader (or the uploader) only ever sees whole compressed files. The
//! epoch in each name is raised past a persisted mark on every start, so a
//! name, and the object key derived from it, is never reused, even after
//! every segment has been uploaded and removed.

use crate::traces::config::TraceCodec;
use crate::traces::encode_path_component;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// The longest encoded node id: segment file names stay under `NAME_MAX`.
pub const MAX_ENCODED_INSTANCE_BYTES: usize = 160;

const LOCK_FILE: &str = ".lock";

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("another process holds {0}; one proxy writes a trace directory at a time")]
    Locked(String),
    #[error(
        "the node id must be 1-128 bytes, not `-`, and at most 160 bytes once percent-encoded; it \
         names every segment and object"
    )]
    NodeId,
    #[error("{path}: {reason}")]
    Io { path: String, reason: String },
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> OpenError + '_ {
    move |e| OpenError::Io {
        path: path.display().to_string(),
        reason: e.to_string(),
    }
}

/// Counts the compressed bytes the encoder hands down, so a segment's size
/// is known without a `stat` per line.
struct Counting<W> {
    inner: W,
    written: u64,
}

impl<W: Write> Write for Counting<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

type Sink = Counting<BufWriter<File>>;

enum Encoder {
    Gzip(flate2::write::GzEncoder<Sink>),
    Zstd(zstd::stream::write::Encoder<'static, Sink>),
}

impl Encoder {
    fn new(codec: TraceCodec, sink: Sink) -> io::Result<Self> {
        Ok(match codec {
            TraceCodec::Gzip => Encoder::Gzip(flate2::write::GzEncoder::new(
                sink,
                flate2::Compression::default(),
            )),
            TraceCodec::Zstd { window_log } => {
                let mut encoder = zstd::stream::write::Encoder::new(sink, 3)?;
                // Agent turns resend the whole conversation; a long window
                // finds the repetition across turns (ADR-0008 decision 11).
                encoder.long_distance_matching(true)?;
                encoder.window_log(u32::from(window_log))?;
                encoder.include_checksum(true)?;
                Encoder::Zstd(encoder)
            }
        })
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Encoder::Gzip(e) => e.write_all(buf),
            Encoder::Zstd(e) => e.write_all(buf),
        }
    }

    fn written(&self) -> u64 {
        match self {
            Encoder::Gzip(e) => e.get_ref().written,
            Encoder::Zstd(e) => e.get_ref().written,
        }
    }

    fn finish(self) -> io::Result<File> {
        let sink = match self {
            Encoder::Gzip(e) => e.finish()?,
            Encoder::Zstd(e) => e.finish()?,
        };
        sink.inner.into_inner().map_err(|e| e.into_error())
    }
}

/// A sealed segment, oldest first in [`SegmentStore::sealed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub path: PathBuf,
    /// The path relative to the directory: the object key's suffix.
    pub relative: String,
    pub bytes: u64,
    pub sealed_at: SystemTime,
    /// Lines in it, when this process sealed it; unknown after a restart.
    pub lines: Option<u64>,
    /// How long it was open, when this process sealed it.
    pub open_for: Option<std::time::Duration>,
}

/// Why a segment was sealed. A closed set: it is a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealReason {
    Size,
    Age,
    Date,
    Lru,
    Shutdown,
}

impl SealReason {
    pub const ALL: [Self; 5] = [Self::Size, Self::Age, Self::Date, Self::Lru, Self::Shutdown];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Age => "age",
            Self::Date => "date",
            Self::Lru => "lru",
            Self::Shutdown => "shutdown",
        }
    }
}

struct OpenSegment {
    open_path: PathBuf,
    sealed_path: PathBuf,
    relative: String,
    encoder: Encoder,
    lines: u64,
    opened: Instant,
    last_write: Instant,
}

/// What a write did, for the exporter's counters.
pub enum WriteOutcome {
    Written,
    /// The segment failed and was removed with every line in it.
    Failed {
        lines_lost: u64,
    },
}

/// The directory, its lock, and the segments being written.
pub struct SegmentStore {
    root: PathBuf,
    instance: String,
    epoch: u64,
    seq: u64,
    codec: TraceCodec,
    segment_max_bytes: u64,
    max_open: usize,
    open: BTreeMap<(String, String), OpenSegment>,
    sealed: Vec<Sealed>,
    /// Kept open for the lock's lifetime.
    _lock: File,
    /// `.open` leftovers deleted at startup.
    pub leftovers_removed: u64,
}

impl SegmentStore {
    pub fn open(
        root: &Path,
        node_id: &str,
        codec: TraceCodec,
        segment_max_bytes: u64,
        max_open: usize,
    ) -> Result<Self, OpenError> {
        let instance = encode_path_component(node_id);
        if node_id.is_empty()
            || node_id.len() > 128
            || node_id == "-"
            || instance.len() > MAX_ENCODED_INSTANCE_BYTES
        {
            return Err(OpenError::NodeId);
        }
        create_private_dir(root).map_err(io_err(root))?;
        let lock_path = root.join(LOCK_FILE);
        let lock = lock(&lock_path)?;

        let mut leftovers_removed = 0;
        let mut sealed = Vec::new();
        let mut max_epoch = 0;
        let prefix = format!("{instance}-");
        for (path, relative) in segment_files(root).map_err(io_err(root))? {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if name.starts_with('.') && name.ends_with(".open") {
                // The lock proves no other process writes here: whichever
                // node id named it, it is a crash leftover.
                std::fs::remove_file(&path).map_err(io_err(&path))?;
                leftovers_removed += 1;
                continue;
            }
            if let Some(epoch) = name
                .strip_prefix(&prefix)
                .and_then(|rest| rest.split('-').next())
                .and_then(|e| e.parse::<u64>().ok())
            {
                max_epoch = max_epoch.max(epoch);
            }
            let meta = std::fs::metadata(&path).map_err(io_err(&path))?;
            sealed.push(Sealed {
                path,
                relative,
                bytes: meta.len(),
                sealed_at: meta.modified().unwrap_or(UNIX_EPOCH),
                lines: None,
                open_for: None,
            });
        }
        sealed.sort_by(|a, b| a.sealed_at.cmp(&b.sealed_at).then(a.path.cmp(&b.path)));

        let mark_path = root.join(format!(".epoch-{instance}"));
        let mark = match std::fs::read_to_string(&mark_path) {
            Ok(text) => text.trim().parse::<u64>().unwrap_or(0),
            Err(e) if e.kind() == io::ErrorKind::NotFound => 0,
            Err(e) => return Err(io_err(&mark_path)(e)),
        };
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        let epoch = now_ms.max(mark + 1).max(max_epoch + 1);
        write_synced(&mark_path, epoch.to_string().as_bytes()).map_err(io_err(&mark_path))?;

        Ok(SegmentStore {
            root: root.to_path_buf(),
            instance,
            epoch,
            seq: 0,
            codec,
            segment_max_bytes,
            max_open,
            open: BTreeMap::new(),
            sealed,
            _lock: lock,
            leftovers_removed,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Sealed segments still on disk, oldest first.
    pub fn sealed(&self) -> &[Sealed] {
        &self.sealed
    }

    /// Every segment byte on disk: sealed plus what open segments have
    /// written so far.
    pub fn disk_bytes(&self) -> u64 {
        self.sealed.iter().map(|s| s.bytes).sum::<u64>()
            + self.open.values().map(|o| o.encoder.written()).sum::<u64>()
    }

    /// Write one line to the `(tenant, date)` segment, sealing first when
    /// the line would take it past the size bound, or when a new segment
    /// would exceed the open-segment cap. Sealed segments are returned with
    /// their reason.
    pub fn write_line(
        &mut self,
        tenant: &str,
        date: &str,
        line: &[u8],
        sealed: &mut Vec<(Sealed, SealReason)>,
    ) -> Result<WriteOutcome, OpenError> {
        let key = (tenant.to_string(), date.to_string());
        let would_overflow = self.open.get(&key).is_some_and(|seg| {
            seg.lines > 0 && seg.encoder.written() + line.len() as u64 > self.segment_max_bytes
        });
        if would_overflow {
            if let Some(s) = self.seal(&key)? {
                sealed.push((s, SealReason::Size));
            }
        }
        if !self.open.contains_key(&key) {
            while self.open.len() >= self.max_open {
                let lru = self
                    .open
                    .iter()
                    .min_by_key(|(_, seg)| seg.last_write)
                    .map(|(k, _)| k.clone())
                    .expect("the cap is at least one");
                if let Some(s) = self.seal(&lru)? {
                    sealed.push((s, SealReason::Lru));
                }
            }
            let segment = self.new_segment(tenant, date)?;
            self.open.insert(key.clone(), segment);
        }
        let seg = self.open.get_mut(&key).expect("opened above");
        match seg.encoder.write_all(line) {
            Ok(()) => {
                seg.lines += 1;
                seg.last_write = Instant::now();
                Ok(WriteOutcome::Written)
            }
            Err(_) => {
                let seg = self.open.remove(&key).expect("present");
                let _ = std::fs::remove_file(&seg.open_path);
                Ok(WriteOutcome::Failed {
                    lines_lost: seg.lines + 1,
                })
            }
        }
    }

    fn new_segment(&mut self, tenant: &str, date: &str) -> Result<OpenSegment, OpenError> {
        let dir_rel = format!("{}/date={date}", crate::traces::tenant_dir(tenant));
        let dir = self.root.join(&dir_rel);
        create_private_dir_all(&dir).map_err(io_err(&dir))?;
        let name = format!(
            "{}-{}-{}.{}",
            self.instance,
            self.epoch,
            self.seq,
            self.codec.extension()
        );
        self.seq += 1;
        let open_path = dir.join(format!(".{name}.open"));
        let file = create_private_file(&open_path).map_err(io_err(&open_path))?;
        let sink = Counting {
            inner: BufWriter::with_capacity(64 * 1024, file),
            written: 0,
        };
        let encoder = Encoder::new(self.codec, sink).map_err(io_err(&open_path))?;
        let now = Instant::now();
        Ok(OpenSegment {
            sealed_path: dir.join(&name),
            relative: format!("{dir_rel}/{name}"),
            open_path,
            encoder,
            lines: 0,
            opened: now,
            last_write: now,
        })
    }

    /// Finish, sync and publish one open segment under its sealed name.
    fn seal(&mut self, key: &(String, String)) -> Result<Option<Sealed>, OpenError> {
        let Some(seg) = self.open.remove(key) else {
            return Ok(None);
        };
        let publish = || -> io::Result<u64> {
            let file = seg.encoder.finish()?;
            file.sync_all()?;
            let bytes = file.metadata()?.len();
            drop(file);
            std::fs::rename(&seg.open_path, &seg.sealed_path)?;
            if let Some(dir) = seg.sealed_path.parent() {
                File::open(dir)?.sync_all()?;
            }
            Ok(bytes)
        };
        let open_path = seg.open_path.clone();
        match publish() {
            Ok(bytes) => {
                let sealed = Sealed {
                    path: seg.sealed_path,
                    relative: seg.relative,
                    bytes,
                    sealed_at: SystemTime::now(),
                    lines: Some(seg.lines),
                    open_for: Some(seg.opened.elapsed()),
                };
                self.sealed.push(sealed.clone());
                Ok(Some(sealed))
            }
            Err(e) => {
                let _ = std::fs::remove_file(&open_path);
                Err(io_err(&open_path)(e))
            }
        }
    }

    /// Seal segments open longer than `max_age`, and those of a date other
    /// than `today`.
    pub fn seal_due(
        &mut self,
        max_age: std::time::Duration,
        today: &str,
        sealed: &mut Vec<(Sealed, SealReason)>,
        failed: &mut u64,
    ) {
        let due: Vec<_> = self
            .open
            .iter()
            .filter_map(|(key, seg)| {
                if key.1 != today {
                    Some((key.clone(), SealReason::Date))
                } else if seg.opened.elapsed() >= max_age {
                    Some((key.clone(), SealReason::Age))
                } else {
                    None
                }
            })
            .collect();
        for (key, reason) in due {
            let lines = self.open.get(&key).map_or(0, |s| s.lines);
            match self.seal(&key) {
                Ok(Some(s)) => sealed.push((s, reason)),
                Ok(None) => {}
                Err(_) => *failed += lines,
            }
        }
    }

    /// Seal everything (shutdown). Returns the lines in segments that could
    /// not be sealed.
    pub fn seal_all(&mut self, sealed: &mut Vec<(Sealed, SealReason)>) -> u64 {
        let keys: Vec<_> = self.open.keys().cloned().collect();
        let mut failed = 0;
        for key in keys {
            let lines = self.open.get(&key).map_or(0, |s| s.lines);
            match self.seal(&key) {
                Ok(Some(s)) => sealed.push((s, SealReason::Shutdown)),
                Ok(None) => {}
                Err(_) => failed += lines,
            }
        }
        failed
    }

    /// Delete the oldest sealed segment that `skip` does not protect.
    pub fn remove_oldest(&mut self, skip: impl Fn(&Sealed) -> bool) -> Option<Sealed> {
        let i = self.sealed.iter().position(|s| !skip(s))?;
        let s = self.sealed.remove(i);
        let _ = std::fs::remove_file(&s.path);
        Some(s)
    }

    /// Forget a sealed segment that left the disk another way (uploaded).
    pub fn forget(&mut self, path: &Path) {
        self.sealed.retain(|s| s.path != path);
    }

    /// Delete sealed segments older than `max_age`; returns them.
    pub fn remove_older_than(&mut self, max_age: std::time::Duration) -> Vec<Sealed> {
        let now = SystemTime::now();
        let (old, keep): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.sealed).into_iter().partition(|s| {
                now.duration_since(s.sealed_at)
                    .is_ok_and(|age| age > max_age)
            });
        self.sealed = keep;
        for s in &old {
            let _ = std::fs::remove_file(&s.path);
        }
        old
    }
}

fn lock(path: &Path) -> Result<File, OpenError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(io_err(path))?;
    #[cfg(unix)]
    rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
        |e| {
            if e == rustix::io::Errno::WOULDBLOCK {
                OpenError::Locked(path.display().to_string())
            } else {
                io_err(path)(e.into())
            }
        },
    )?;
    Ok(file)
}

/// Every file under `tenant=*/date=*/`, with its path relative to `root`.
/// Control files at the root are not segments.
fn segment_files(root: &Path) -> io::Result<Vec<(PathBuf, String)>> {
    let mut out = Vec::new();
    for tenant in std::fs::read_dir(root)? {
        let tenant = tenant?;
        let tenant_name = tenant.file_name().to_string_lossy().into_owned();
        if !tenant_name.starts_with("tenant=") || !tenant.file_type()?.is_dir() {
            continue;
        }
        for date in std::fs::read_dir(tenant.path())? {
            let date = date?;
            let date_name = date.file_name().to_string_lossy().into_owned();
            if !date_name.starts_with("date=") || !date.file_type()?.is_dir() {
                continue;
            }
            for file in std::fs::read_dir(date.path())? {
                let file = file?;
                if file.file_type()?.is_file() {
                    let name = file.file_name().to_string_lossy().into_owned();
                    out.push((file.path(), format!("{tenant_name}/{date_name}/{name}")));
                }
            }
        }
    }
    Ok(out)
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

fn create_private_dir_all(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

fn write_synced(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}
