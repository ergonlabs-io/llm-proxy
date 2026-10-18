//! The trace-export emergency switch (ADR-0008 decision 2; design note
//! section 3.3).
//!
//! One `AtomicU64` packs `(generation << 1) | disabled`, the capture
//! supervisor's shape, so a single load answers both "is capture allowed"
//! and "has anything changed since this request was admitted". Every toggle
//! moves the generation; a capture pinned to an older generation is
//! discarded, even if the gate has been reopened since.
//!
//! A disable is written to `<directory>/.capture-disabled` so it survives a
//! restart. A disable always takes effect, even when the marker cannot be
//! written: the answer then says it was not persisted, and the error is
//! logged. An enable removes the marker first and is refused if it cannot,
//! so a restart can never reopen a gate the operator believes is closed in
//! the other direction. A marker that exists but cannot be read starts the
//! gate closed: when in doubt, capture nothing.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// The marker file name inside the trace directory.
pub const DISABLED_MARKER: &str = ".capture-disabled";

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct GateStatus {
    pub disabled: bool,
    pub generation: u64,
}

/// What a toggle did. `persisted` is false when a disable took effect but
/// its marker could not be written, so a restart would reopen the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct GateChange {
    #[serde(flatten)]
    pub status: GateStatus,
    pub persisted: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error("stale generation: the gate is at {current}")]
    Stale { current: u64 },
    #[error("generation exhausted")]
    Exhausted,
    /// The disable marker could not be removed, so an enable was refused
    /// and the gate stays closed. Names the path, never anything else.
    #[error("cannot update {path}: {reason}")]
    Marker { path: String, reason: String },
}

#[derive(Debug)]
pub struct TraceGate {
    state: AtomicU64,
    marker: Option<PathBuf>,
}

impl TraceGate {
    /// The gate for the trace directory: closed when its marker exists, or
    /// when the marker's presence cannot be determined.
    pub fn open(directory: &Path) -> Self {
        let marker = directory.join(DISABLED_MARKER);
        let disabled = match std::fs::symlink_metadata(&marker) {
            Ok(_) => true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => false,
            Err(e) => {
                tracing::error!(
                    path = %marker.display(),
                    error = %e,
                    "cannot tell whether trace capture was disabled; starting with capture disabled"
                );
                true
            }
        };
        TraceGate {
            state: AtomicU64::new(u64::from(disabled)),
            marker: Some(marker),
        }
    }

    /// A gate with no marker file: open, and a disable lasts until restart.
    pub fn unpersisted() -> Self {
        TraceGate {
            state: AtomicU64::new(0),
            marker: None,
        }
    }

    /// The packed state. Equal values mean nothing changed.
    pub fn load(&self) -> u64 {
        self.state.load(Ordering::Acquire)
    }

    pub fn status(&self) -> GateStatus {
        let g = self.load();
        GateStatus {
            disabled: g & 1 != 0,
            generation: g >> 1,
        }
    }

    /// Compare-and-set on the generation. A disable always takes effect; an
    /// enable takes effect only once the marker is gone.
    pub fn set_disabled(
        &self,
        disabled: bool,
        expected_generation: u64,
    ) -> Result<GateChange, GateError> {
        let old = self.load();
        if old >> 1 != expected_generation {
            return Err(GateError::Stale { current: old >> 1 });
        }
        let next_generation = expected_generation
            .checked_add(1)
            .filter(|g| *g <= u64::MAX >> 1)
            .ok_or(GateError::Exhausted)?;
        let mut persisted = true;
        if let Some(marker) = &self.marker {
            if disabled {
                if let Err(e) = write_marker(marker) {
                    tracing::error!(
                        path = %marker.display(),
                        error = %e,
                        "trace capture disabled, but the disable could not be persisted; \
                         a restart would re-enable capture"
                    );
                    persisted = false;
                }
            } else {
                match std::fs::remove_file(marker) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => {
                        return Err(GateError::Marker {
                            path: marker.display().to_string(),
                            reason: e.to_string(),
                        })
                    }
                    _ => {}
                }
            }
        } else {
            persisted = !disabled;
        }
        let next = (next_generation << 1) | u64::from(disabled);
        self.state
            .compare_exchange(old, next, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|now| GateError::Stale { current: now >> 1 })?;
        Ok(GateChange {
            status: self.status(),
            persisted,
        })
    }
}

fn write_marker(path: &Path) -> io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.sync_all()?;
    if let Some(dir) = path.parent() {
        // The marker must survive a crash right after the answer.
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A disable survives a restart, a reopened gate is closed, an enable
    /// removes the marker, and a stale generation changes nothing.
    #[test]
    fn a_disable_is_persisted_and_toggles_are_compare_and_set() {
        let dir = tempfile::tempdir().unwrap();
        let gate = TraceGate::open(dir.path());
        assert_eq!(
            gate.status(),
            GateStatus {
                disabled: false,
                generation: 0
            }
        );
        let closed = gate.set_disabled(true, 0).unwrap();
        assert!(closed.persisted && closed.status.disabled && closed.status.generation == 1);
        assert!(matches!(
            gate.set_disabled(false, 0),
            Err(GateError::Stale { current: 1 })
        ));

        let reopened = TraceGate::open(dir.path());
        assert!(reopened.status().disabled, "a disable survives a restart");
        reopened.set_disabled(false, 0).unwrap();
        assert!(!TraceGate::open(dir.path()).status().disabled);
        assert!(!dir.path().join(DISABLED_MARKER).exists());
    }

    /// A disable whose marker cannot be written still stops capture and
    /// says it was not persisted: an emergency stop never fails open.
    #[cfg(unix)]
    #[test]
    fn a_disable_that_cannot_be_persisted_still_takes_effect() {
        let dir = tempfile::tempdir().unwrap();
        let gate = TraceGate::open(&dir.path().join("missing"));
        let change = gate.set_disabled(true, 0).unwrap();
        assert!(!change.persisted);
        assert!(gate.status().disabled);
    }
}
