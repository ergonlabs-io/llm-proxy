//! Fault controls are compiled only into this crate's unit-test binary.
use std::{
    fs, io,
    path::PathBuf,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    InitializeBeforeCommit,
    InitializeAfterCommit,
    InitializeDirectorySync,
    ReserveBeforeCommit,
    ReserveAfterCommit,
    Encrypt,
    CommitBeforeCommit,
    CommitAfterCommit,
    RewrapBeforeCommit,
    RewrapAfterCommit,
    AcknowledgeBeforeCommit,
    AcknowledgeAfterCommit,
    QuarantineRename,
    QuarantineDirectorySync,
    BackendWrite,
    BackendPartialWrite,
    BackendResize,
    BackendAfterResize,
    BackendSync,
    BackendAfterSync,
}
#[derive(Debug, Default)]
pub(crate) struct Hooks {
    control: Mutex<Control>,
}
#[derive(Debug, Default)]
struct Control {
    fail: Option<Fault>,
    pause: Option<(Fault, PathBuf)>,
    refused_acknowledgements: usize,
}
impl Hooks {
    /// The next `n` acknowledgement transactions hit the disk ceiling.
    pub fn refuse_acknowledgements(&self, n: usize) {
        self.control.lock().unwrap().refused_acknowledgements = n;
    }
    pub fn take_refused_acknowledgement(&self) -> bool {
        let mut control = self.control.lock().unwrap();
        let refuse = control.refused_acknowledgements > 0;
        control.refused_acknowledgements = control.refused_acknowledgements.saturating_sub(1);
        refuse
    }
    pub fn fail(&self, at: Fault) {
        self.control.lock().unwrap().fail = Some(at);
    }
    pub fn pause(&self, at: Fault, marker: PathBuf) {
        self.control.lock().unwrap().pause = Some((at, marker));
    }
    pub fn trip(&self, at: Fault) -> io::Result<()> {
        let pause = {
            let mut control = self.control.lock().unwrap();
            if control.fail == Some(at) {
                control.fail = None;
                return Err(io::Error::other("injected spool I/O failure"));
            }
            if control
                .pause
                .as_ref()
                .is_some_and(|(point, _)| *point == at)
            {
                control.pause.take().map(|(_, path)| path)
            } else {
                None
            }
        };
        if let Some(marker) = pause {
            fs::write(marker, b"ready")?;
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            return Err(io::Error::other("bounded crash hook was not killed"));
        }
        Ok(())
    }
}
