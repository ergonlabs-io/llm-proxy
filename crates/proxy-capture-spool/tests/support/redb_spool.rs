//! Isolated evaluation prototype, never used by the production spool.
use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, StorageBackend,
    TableDefinition,
};
use ring::{
    aead, digest,
    rand::{SecureRandom, SystemRandom},
};
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

pub const RECORDS: TableDefinition<u64, &[u8]> = TableDefinition::new("records");
pub const STATE: TableDefinition<u64, &[u8]> = TableDefinition::new("state");
#[derive(Clone)]
pub struct Config {
    pub directory: PathBuf,
    pub node_id: String,
    pub max_record_bytes: usize,
    pub max_disk_bytes: u64,
    pub cache_bytes: usize,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid prototype input")]
    Invalid,
    #[error("prototype disk quota exhausted")]
    Full,
    #[error("prototype writer poisoned")]
    Poisoned,
    #[error("prototype authentication failed")]
    Authentication,
    #[error("prototype storage: {0}")]
    Storage(String),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
struct Backend {
    file: Arc<File>,
    cap: u64,
    full: Arc<AtomicBool>,
    fail_sync: Arc<AtomicBool>,
    pause_sync: Arc<Mutex<Option<(PathBuf, bool)>>>,
}
impl Backend {
    fn bound(&self, length: u64) -> io::Result<()> {
        if length > self.cap {
            self.full.store(true, Ordering::SeqCst);
            return Err(io::Error::other("prototype disk quota"));
        }
        Ok(())
    }
}
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.file.read_exact_at(out, offset)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.bound(len)?;
        self.file.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        if self.fail_sync.swap(false, Ordering::SeqCst) {
            return Err(io::Error::other("injected sync failure"));
        }
        let pause = self.pause_sync.lock().unwrap().take();
        if let Some((marker, false)) = &pause {
            pause_at_sync(marker)?;
        }
        self.file.sync_all()?;
        if let Some((marker, true)) = &pause {
            pause_at_sync(marker)?;
        }
        Ok(())
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let length = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::other("offset overflow"))?;
        self.bound(length)?;
        self.file.write_all_at(data, offset)
    }
}

fn pause_at_sync(marker: &PathBuf) -> io::Result<()> {
    // Harness marker is outside spool storage; it never represents a receipt.
    fs::write(marker, b"{\"barrier\":\"sync\"}")?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(io::Error::other("bounded crash hook was not killed"))
}
#[derive(Debug, Clone)]
pub struct Stats {
    pub next_sequence: u64,
    pub durable: u64,
    pub count: u64,
    pub disk_bytes: u64,
    pub poisoned: bool,
}
#[derive(Clone, Copy)]
struct State {
    next: u64,
    durable: u64,
    count: u64,
    digest: [u8; 32],
}
pub struct Prototype {
    db: Database,
    config: Config,
    key: aead::LessSafeKey,
    _lock: File,
    file: Arc<File>,
    full: Arc<AtomicBool>,
    fail_sync: Arc<AtomicBool>,
    pause_sync: Arc<Mutex<Option<(PathBuf, bool)>>>,
    state: State,
    hash: digest::Context,
    pending: Vec<(u64, Vec<u8>)>,
    poisoned: bool,
}
fn storage(e: impl std::fmt::Display) -> Error {
    Error::Storage(e.to_string())
}
impl Prototype {
    pub fn open(config: Config, key: [u8; 32]) -> Result<Self> {
        if config.node_id.is_empty()
            || config.node_id.len() > 128
            || config.max_record_bytes == 0
            || config.max_record_bytes > 524288
            || config.cache_bytes == 0
            || config.cache_bytes > 16 * 1024 * 1024
            || config.max_disk_bytes == 0
        {
            return Err(Error::Invalid);
        }
        if !config.directory.exists() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&config.directory)
                .map_err(storage)?;
            fs::set_permissions(&config.directory, fs::Permissions::from_mode(0o700))
                .map_err(storage)?;
            File::open(config.directory.parent().ok_or(Error::Invalid)?)
                .and_then(|f| f.sync_all())
                .map_err(storage)?;
        }
        let metadata = fs::symlink_metadata(&config.directory).map_err(storage)?;
        if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(Error::Invalid);
        }
        for entry in fs::read_dir(&config.directory).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let meta = fs::symlink_metadata(entry.path()).map_err(storage)?;
            if !meta.is_file()
                || meta.permissions().mode() & 0o077 != 0
                || !["writer.lock", "prototype.redb"]
                    .iter()
                    .any(|n| entry.file_name() == *n)
            {
                return Err(Error::Invalid);
            }
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(config.directory.join("writer.lock"))
            .map_err(storage)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(storage)?;
        let path = config.directory.join("prototype.redb");
        let fresh = !path.exists();
        let file = Arc::new(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .map_err(storage)?,
        );
        if file.metadata().map_err(storage)?.len() > config.max_disk_bytes {
            return Err(Error::Full);
        }
        let full = Arc::new(AtomicBool::new(false));
        let fail_sync = Arc::new(AtomicBool::new(false));
        let pause_sync = Arc::new(Mutex::new(None));
        let backend = Backend {
            file: file.clone(),
            cap: config.max_disk_bytes,
            full: full.clone(),
            fail_sync: fail_sync.clone(),
            pause_sync: pause_sync.clone(),
        };
        let db = Database::builder()
            .set_cache_size(config.cache_bytes)
            .create_with_backend(backend)
            .map_err(|e| {
                if full.load(Ordering::SeqCst) {
                    Error::Full
                } else {
                    storage(e)
                }
            })?;
        let hash = digest::Context::new(&digest::SHA256);
        let mut value = Self {
            db,
            config,
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, &key).map_err(|_| Error::Invalid)?,
            ),
            _lock: lock,
            file,
            full,
            fail_sync,
            pause_sync,
            state: State {
                next: 1,
                durable: 0,
                count: 0,
                digest: hash.clone().finish().as_ref().try_into().unwrap(),
            },
            hash,
            pending: Vec::new(),
            poisoned: false,
        };
        if fresh {
            value.write_state(value.state, &[])?;
            File::open(&value.config.directory)
                .and_then(|f| f.sync_all())
                .map_err(storage)?;
        }
        value.recover()?;
        Ok(value)
    }
    fn aad(&self, kind: u8, sequence: u64) -> Vec<u8> {
        let mut out = b"redb-spool-prototype-v1".to_vec();
        out.extend_from_slice(&(self.config.node_id.len() as u64).to_le_bytes());
        out.extend_from_slice(self.config.node_id.as_bytes());
        out.push(kind);
        out.extend_from_slice(&sequence.to_le_bytes());
        out
    }
    fn encrypt(&self, kind: u8, seq: u64, plain: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0; 12];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| Error::Authentication)?;
        let mut cipher = plain.to_vec();
        self.key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(self.aad(kind, seq)),
                &mut cipher,
            )
            .map_err(|_| Error::Authentication)?;
        let mut out = nonce.to_vec();
        out.extend(cipher);
        Ok(out)
    }
    fn decrypt(&self, kind: u8, seq: u64, cipher: &[u8], bound: usize) -> Result<Vec<u8>> {
        if cipher.len() < 28 || cipher.len() > bound.checked_add(28).ok_or(Error::Invalid)? {
            return Err(Error::Authentication);
        }
        let nonce: [u8; 12] = cipher[..12].try_into().unwrap();
        let mut bytes = cipher[12..].to_vec();
        let plain = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(self.aad(kind, seq)),
                &mut bytes,
            )
            .map_err(|_| Error::Authentication)?;
        Ok(plain.to_vec())
    }
    fn encode(state: State) -> Vec<u8> {
        let mut out = Vec::with_capacity(56);
        for n in [state.next, state.durable, state.count] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.extend_from_slice(&state.digest);
        out
    }
    fn write_state(&mut self, state: State, records: &[(u64, Vec<u8>)]) -> Result<()> {
        let cipher = self.encrypt(0, 0, &Self::encode(state))?;
        let result = (|| {
            let mut tx = self.db.begin_write().map_err(storage)?;
            tx.set_durability(Durability::Immediate).map_err(storage)?;
            {
                let mut table = tx.open_table(RECORDS).map_err(storage)?;
                for (seq, value) in records {
                    table.insert(*seq, value.as_slice()).map_err(storage)?;
                }
            }
            {
                tx.open_table(STATE)
                    .map_err(storage)?
                    .insert(0, cipher.as_slice())
                    .map_err(storage)?;
            }
            tx.commit().map_err(storage)
        })();
        if let Err(e) = result {
            self.poisoned = true;
            return Err(if self.full.load(Ordering::SeqCst) {
                Error::Full
            } else {
                e
            });
        }
        Ok(())
    }
    fn recover(&mut self) -> Result<()> {
        let tx = self.db.begin_read().map_err(storage)?;
        let states = tx.open_table(STATE).map_err(storage)?;
        if states.len().map_err(storage)? != 1 {
            return Err(Error::Authentication);
        }
        let row = states
            .get(0)
            .map_err(storage)?
            .ok_or(Error::Authentication)?;
        let bytes = self.decrypt(0, 0, row.value(), 56)?;
        if bytes.len() != 56 {
            return Err(Error::Authentication);
        }
        let read = |off| u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
        let state = State {
            next: read(0),
            durable: read(8),
            count: read(16),
            digest: bytes[24..].try_into().unwrap(),
        };
        let mut hash = digest::Context::new(&digest::SHA256);
        let mut last = 0;
        let mut count = 0;
        for row in tx
            .open_table(RECORDS)
            .map_err(storage)?
            .iter()
            .map_err(storage)?
        {
            let (seq, value) = row.map_err(storage)?;
            let seq = seq.value();
            if seq <= last || seq >= state.next {
                return Err(Error::Authentication);
            }
            self.decrypt(1, seq, value.value(), self.config.max_record_bytes)?;
            hash.update(&seq.to_le_bytes());
            hash.update(value.value());
            last = seq;
            count += 1;
        }
        if state.next == 0
            || last != state.durable
            || count != state.count
            || hash.clone().finish().as_ref() != state.digest
        {
            return Err(Error::Authentication);
        }
        self.state = state;
        self.hash = hash;
        Ok(())
    }
    pub fn append_batch(&mut self, records: &[&[u8]]) -> Result<Vec<u64>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if records.is_empty()
            || records.len() > 8
            || !self.pending.is_empty()
            || records
                .iter()
                .any(|r| r.len() > self.config.max_record_bytes)
        {
            return Err(Error::Invalid);
        }
        let start = self.state.next;
        let mut state = self.state;
        state.next = start
            .checked_add(records.len() as u64)
            .ok_or(Error::Invalid)?;
        self.write_state(state, &[])?;
        self.state = state;
        let result = records
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let seq = start + i as u64;
                Ok((seq, self.encrypt(1, seq, r)?))
            })
            .collect::<Result<Vec<_>>>();
        match result {
            Ok(pending) => {
                let sequences = pending.iter().map(|(s, _)| *s).collect();
                self.pending = pending;
                Ok(sequences)
            }
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }
    pub fn commit(&mut self) -> Result<u64> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if self.pending.is_empty() {
            return Ok(self.state.durable);
        }
        let pending = std::mem::take(&mut self.pending);
        let mut hash = self.hash.clone();
        for (seq, value) in &pending {
            hash.update(&seq.to_le_bytes());
            hash.update(value);
        }
        let mut state = self.state;
        state.durable = pending.last().unwrap().0;
        state.count = state
            .count
            .checked_add(pending.len() as u64)
            .ok_or(Error::Invalid)?;
        state.digest = hash.clone().finish().as_ref().try_into().unwrap();
        self.write_state(state, &pending)?;
        self.hash = hash;
        self.state = state;
        Ok(state.durable)
    }
    pub fn replay(&mut self, max_records: usize, max_bytes: usize) -> Result<Vec<(u64, Vec<u8>)>> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        let result = (|| {
            let tx = self.db.begin_read().map_err(storage)?;
            let table = tx.open_table(RECORDS).map_err(storage)?;
            let mut out = Vec::new();
            let mut bytes = 0usize;
            for row in table.iter().map_err(storage)? {
                if out.len() >= max_records {
                    break;
                }
                let (seq, value) = row.map_err(storage)?;
                let seq = seq.value();
                let plain = self.decrypt(1, seq, value.value(), self.config.max_record_bytes)?;
                if plain.len() > max_bytes.saturating_sub(bytes) {
                    break;
                }
                bytes += plain.len();
                out.push((seq, plain));
            }
            Ok(out)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn stats(&self) -> Stats {
        Stats {
            next_sequence: self.state.next,
            durable: self.state.durable,
            count: self.state.count,
            disk_bytes: self.file.metadata().map(|m| m.len()).unwrap_or(u64::MAX),
            poisoned: self.poisoned,
        }
    }
    pub fn fail_next_sync(&self) {
        self.fail_sync.store(true, Ordering::SeqCst);
    }
    #[allow(dead_code)] // The example's subprocess harness exercises this hook.
    pub fn pause_next_sync(&self, marker: PathBuf, after_sync: bool) {
        *self.pause_sync.lock().unwrap() = Some((marker, after_sync));
    }
}
