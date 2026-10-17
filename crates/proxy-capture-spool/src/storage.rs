//! Safe positional I/O with a hard logical file-length ceiling.
use redb::StorageBackend;
use std::{
    fs::File,
    io,
    os::unix::fs::FileExt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
};

/// The database's length ceiling, shared with the spool so it can tell a refusal
/// at the ceiling apart from a genuine I/O failure: redb reports both as the same
/// latched I/O error.
#[derive(Debug)]
pub(crate) struct Quota {
    limit: AtomicU64,
    refused: AtomicBool,
}
impl Quota {
    pub fn new(limit: u64) -> Self {
        Self {
            limit: AtomicU64::new(limit),
            refused: AtomicBool::new(false),
        }
    }
    /// Sets the ceiling for the next transaction and clears any earlier refusal.
    pub fn arm(&self, limit: u64) {
        self.limit.store(limit, Ordering::Relaxed);
        self.refused.store(false, Ordering::Relaxed);
    }
    pub fn refused(&self) -> bool {
        self.refused.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub(crate) struct Backend {
    pub file: Arc<File>,
    pub quota: Arc<Quota>,
    #[cfg(test)]
    pub hooks: Arc<crate::testing::Hooks>,
}
impl Backend {
    fn bound(&self, length: u64) -> io::Result<()> {
        if length > self.quota.limit.load(Ordering::Relaxed) {
            self.quota.refused.store(true, Ordering::Relaxed);
            return Err(io::Error::other("spool database disk quota exhausted"));
        }
        Ok(())
    }
}
impl StorageBackend for Backend {
    fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
    fn read(&self, offset: u64, bytes: &mut [u8]) -> io::Result<()> {
        self.file.read_exact_at(bytes, offset)
    }
    fn set_len(&self, length: u64) -> io::Result<()> {
        self.bound(length)?;
        #[cfg(test)]
        self.hooks.trip(crate::testing::Fault::BackendResize)?;
        self.file.set_len(length)?;
        #[cfg(test)]
        self.hooks.trip(crate::testing::Fault::BackendAfterResize)?;
        Ok(())
    }
    fn sync_data(&self) -> io::Result<()> {
        #[cfg(test)]
        self.hooks.trip(crate::testing::Fault::BackendSync)?;
        self.file.sync_all()?;
        #[cfg(test)]
        self.hooks.trip(crate::testing::Fault::BackendAfterSync)?;
        Ok(())
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::other("spool database offset overflow"))?;
        self.bound(end)?;
        #[cfg(test)]
        self.hooks.trip(crate::testing::Fault::BackendWrite)?;
        #[cfg(test)]
        if let Err(error) = self.hooks.trip(crate::testing::Fault::BackendPartialWrite) {
            self.file.write_all_at(&data[..data.len() / 2], offset)?;
            return Err(error);
        }
        self.file.write_all_at(data, offset)
    }
}
