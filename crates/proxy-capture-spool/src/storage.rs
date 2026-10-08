//! Safe positional I/O with a hard logical file-length ceiling.
use redb::StorageBackend;
use std::{fs::File, io, os::unix::fs::FileExt, sync::Arc};

#[derive(Debug)]
pub(crate) struct Backend {
    pub file: Arc<File>,
    pub cap: u64,
    #[cfg(test)]
    pub hooks: Arc<crate::testing::Hooks>,
}
impl Backend {
    fn bound(&self, length: u64) -> io::Result<()> {
        if length > self.cap {
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
