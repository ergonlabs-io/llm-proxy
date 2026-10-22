//! The worker side of trace export (ADR-0008 decision 4; design note
//! section 3): admission against global budgets, the bounded copies of the
//! two downstream bodies, and the hand-off to the exporter.
//!
//! What a worker does for an opted-in request, and nothing more: two CAS at
//! admission, one copy of the request body, one copy of each delivered
//! response byte into fixed blocks, one CAS per block, and one channel send.
//! It never serialises, compresses, parses or writes.
//!
//! Bodies are copied, not kept as `Bytes`: a `Bytes` is often a slice of
//! hyper's read buffer and keeps the whole buffer alive, a size this crate
//! cannot read without `unsafe` (`docs/telemetry-design.md` section 7).
//!
//! Every admitted capture is counted exactly once: written by the exporter,
//! or dropped with one finite reason. The reservation carries that duty, so
//! a capture that vanishes on any path still counts.

use crate::records::RequestRecord;
use crate::stats::{instruments, Handle, Registry, StatsControl, WorkerId};
use crate::traces::config::TraceExportConfig;
use crate::traces::gate::TraceGate;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};

/// The response is copied into blocks of this size. A block is reserved,
/// allocated once, filled, and never moved.
pub const BLOCK_BYTES: usize = 64 * 1024;

/// Why a whole trace was lost. A closed set: it is a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    QueueFull,
    MemoryBudget,
    EmergencyDisabled,
    UnsupportedProtocol,
    ExporterFailed,
    Abandoned,
    WriteError,
    UploadBacklog,
    Shutdown,
}

impl DropReason {
    pub const ALL: [Self; 9] = [
        Self::QueueFull,
        Self::MemoryBudget,
        Self::EmergencyDisabled,
        Self::UnsupportedProtocol,
        Self::ExporterFailed,
        Self::Abandoned,
        Self::WriteError,
        Self::UploadBacklog,
        Self::Shutdown,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueueFull => "queue_full",
            Self::MemoryBudget => "memory_budget",
            Self::EmergencyDisabled => "emergency_disabled",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::ExporterFailed => "exporter_failed",
            Self::Abandoned => "abandoned",
            Self::WriteError => "write_error",
            Self::UploadBacklog => "upload_backlog",
            Self::Shutdown => "shutdown",
        }
    }
}

/// Why a written trace is incomplete. A closed set: it is a metric label and
/// part of the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PartialReason {
    RequestOverCap,
    ResponseOverCap,
    MemoryBudget,
    StreamUnterminated,
    UnsupportedDialect,
    UnsupportedShape,
    MalformedStream,
    RequestNotJson,
    ResponseNotJson,
    ContentEncoding,
}

impl PartialReason {
    pub const ALL: [Self; 10] = [
        Self::RequestOverCap,
        Self::ResponseOverCap,
        Self::MemoryBudget,
        Self::StreamUnterminated,
        Self::UnsupportedDialect,
        Self::UnsupportedShape,
        Self::MalformedStream,
        Self::RequestNotJson,
        Self::ResponseNotJson,
        Self::ContentEncoding,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RequestOverCap => "request_over_cap",
            Self::ResponseOverCap => "response_over_cap",
            Self::MemoryBudget => "memory_budget",
            Self::StreamUnterminated => "stream_unterminated",
            Self::UnsupportedDialect => "unsupported_dialect",
            Self::UnsupportedShape => "unsupported_shape",
            Self::MalformedStream => "malformed_stream",
            Self::RequestNotJson => "request_not_json",
            Self::ResponseNotJson => "response_not_json",
            Self::ContentEncoding => "content_encoding",
        }
    }
}

/// The response dialect the exporter reassembles, from the cluster that was
/// dialled (AGENTS.md invariant 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceDialect {
    OpenAi,
    Anthropic,
}

/// Small, bounded facts the exporter needs besides the bodies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceMeta {
    /// Request path without the query, at most 512 bytes.
    pub path: String,
    pub status: Option<u16>,
    pub request_content_type: Option<String>,
    pub request_content_encoding: Option<String>,
    pub response_content_type: Option<String>,
    pub response_content_encoding: Option<String>,
    pub dialect: Option<TraceDialect>,
}

/// The counters and gauges of trace export. Every label is resolved at
/// start, so an idle exporter scrapes explicit zeroes.
pub struct TraceStats {
    registry: Arc<Registry>,
    captured: Handle,
    dropped: [Handle; DropReason::ALL.len()],
    memory: Handle,
    slots: Handle,
}

impl TraceStats {
    pub fn resolve(control: &StatsControl) -> Self {
        TraceStats {
            registry: control.registry(),
            captured: control.resolve(&instruments::TRACE_CAPTURED, &[]),
            dropped: DropReason::ALL
                .map(|r| control.resolve(&instruments::TRACE_DROPPED, &[("reason", r.as_str())])),
            memory: control.resolve(&instruments::TRACE_MEMORY_BYTES, &[]),
            slots: control.resolve(&instruments::TRACE_SLOTS, &[]),
        }
    }

    pub fn dropped(&self, reason: DropReason, n: u64) {
        let i = DropReason::ALL
            .iter()
            .position(|r| *r == reason)
            .expect("ALL lists every variant");
        self.registry.incr(WorkerId(0), self.dropped[i], n);
    }

    pub(crate) fn incr(&self, handle: Handle, n: u64) {
        self.registry.incr(WorkerId(0), handle, n);
    }

    fn gauge(&self, handle: Handle, delta: i64) {
        self.registry.add(WorkerId(0), handle, delta);
    }
}

/// Admission and the hand-off channel, shared by every worker.
pub struct TraceAdmission {
    max_request: usize,
    max_response: usize,
    max_memory: usize,
    max_slots: usize,
    slots: AtomicUsize,
    bytes: AtomicUsize,
    gate: Arc<TraceGate>,
    sender: mpsc::Sender<Box<CapturedTrace>>,
    pub(crate) stats: TraceStats,
}

impl TraceAdmission {
    /// Admission for `config`, and the receiver the exporter drains.
    pub fn new(
        config: &TraceExportConfig,
        gate: Arc<TraceGate>,
        stats: TraceStats,
    ) -> (Arc<Self>, mpsc::Receiver<Box<CapturedTrace>>) {
        let (sender, receiver) = mpsc::channel();
        let admission = Arc::new(TraceAdmission {
            max_request: config.max_request_body_bytes,
            max_response: config.max_response_body_bytes,
            max_memory: config.max_memory_bytes,
            max_slots: config.max_queued_traces,
            slots: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            gate,
            sender,
            stats,
        });
        (admission, receiver)
    }

    /// The trace gate's packed state; bit 0 set means emergency-disabled.
    fn pinned(&self) -> u64 {
        self.gate.load()
    }

    /// Whether capture is allowed right now: two atomic loads.
    pub fn gate_open(&self) -> bool {
        self.pinned() & 1 == 0
    }

    /// The gate a request was admitted under has not moved.
    pub fn gate_value(&self) -> u64 {
        self.gate.load()
    }

    pub fn gate(&self) -> &Arc<TraceGate> {
        &self.gate
    }

    /// Bytes retained by captures in flight or queued.
    pub fn retained_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    /// Captures in flight or queued.
    pub fn held_slots(&self) -> usize {
        self.slots.load(Ordering::Acquire)
    }

    pub fn count_drop(&self, reason: DropReason) {
        self.stats.dropped(reason, 1);
    }

    fn try_reserve_bytes(&self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        let mut held = self.bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = held.checked_add(n).filter(|next| *next <= self.max_memory) else {
                return false;
            };
            match self
                .bytes
                .compare_exchange_weak(held, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.stats.gauge(self.stats.memory, n as i64);
                    return true;
                }
                Err(now) => held = now,
            }
        }
    }

    fn release_bytes(&self, n: usize) {
        if n > 0 {
            self.bytes.fetch_sub(n, Ordering::AcqRel);
            self.stats.gauge(self.stats.memory, -(n as i64));
        }
    }

    fn try_reserve_slot(&self) -> bool {
        let mut held = self.slots.load(Ordering::Acquire);
        while held < self.max_slots {
            match self.slots.compare_exchange_weak(
                held,
                held + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.stats.gauge(self.stats.slots, 1);
                    return true;
                }
                Err(now) => held = now,
            }
        }
        false
    }

    fn release_slot(&self) {
        self.slots.fetch_sub(1, Ordering::AcqRel);
        self.stats.gauge(self.stats.slots, -1);
    }

    /// Admit one opted-in request whose body, as received, is `request`.
    /// `None` means it is not captured; the loss is already counted, and
    /// nothing was allocated or retained. A closed gate is not a loss to
    /// count per request: the operator chose it.
    pub fn admit(self: &Arc<Self>, request: &[u8]) -> Option<TraceCapture> {
        let pinned = self.pinned();
        if pinned & 1 != 0 {
            self.count_drop(DropReason::EmergencyDisabled);
            return None;
        }
        if !self.try_reserve_slot() {
            self.count_drop(DropReason::QueueFull);
            return None;
        }
        let kept = request.len().min(self.max_request);
        if !self.try_reserve_bytes(kept) {
            self.release_slot();
            self.count_drop(DropReason::MemoryBudget);
            return None;
        }
        let mut partial = Vec::new();
        if request.len() > self.max_request {
            partial.push(PartialReason::RequestOverCap);
        }
        Some(TraceCapture {
            admission: Arc::clone(self),
            reservation: Some(Reservation {
                admission: Arc::clone(self),
                bytes: kept,
                state: State::Capturing,
            }),
            pinned,
            request: request[..kept].to_vec(),
            blocks: Vec::new(),
            response_len: 0,
            response_open: true,
            partial,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    /// On the worker.
    Capturing,
    /// Handed to the exporter, not yet written or dropped by it.
    Queued,
    /// Counted: written, or dropped with a reason.
    Accounted,
}

/// A slot and the bytes retained under it. Released on drop; a capture that
/// was never accounted for is counted here, so no path loses one silently.
struct Reservation {
    admission: Arc<TraceAdmission>,
    bytes: usize,
    state: State,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        match self.state {
            State::Capturing => self.admission.count_drop(DropReason::Abandoned),
            State::Queued => self.admission.count_drop(DropReason::ExporterFailed),
            State::Accounted => {}
        }
        self.admission.release_bytes(self.bytes);
        self.admission.release_slot();
    }
}

/// One request's capture while it runs on its worker.
pub struct TraceCapture {
    admission: Arc<TraceAdmission>,
    /// `None` once discarded or handed over.
    reservation: Option<Reservation>,
    pinned: u64,
    request: Vec<u8>,
    blocks: Vec<Box<[u8]>>,
    response_len: usize,
    /// Cleared at the first refusal; nothing is copied after it.
    response_open: bool,
    partial: Vec<PartialReason>,
}

impl std::fmt::Debug for TraceCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the bodies.
        f.debug_struct("TraceCapture")
            .field("request_len", &self.request.len())
            .field("response_len", &self.response_len)
            .field("partial", &self.partial)
            .finish()
    }
}

impl TraceCapture {
    /// Whether the gate is still where it was at admission.
    fn live(&self) -> bool {
        self.admission.pinned() == self.pinned
    }

    /// Bytes this capture holds against the global budget.
    pub fn retained_bytes(&self) -> usize {
        self.reservation.as_ref().map_or(0, |r| r.bytes)
    }

    /// Copy one delivered response frame. Returns `false` once the capture
    /// has been discarded by an emergency disable; nothing more is copied.
    pub fn push_response(&mut self, mut data: &[u8]) -> bool {
        if self.reservation.is_none() {
            return false;
        }
        if !self.live() {
            self.discard();
            return false;
        }
        while self.response_open && !data.is_empty() {
            let room = self
                .blocks
                .last()
                .map_or(0, |block| block.len() - self.fill());
            if room == 0 {
                let remaining_cap = self.admission.max_response - self.response_len;
                if remaining_cap == 0 {
                    self.stop(PartialReason::ResponseOverCap);
                    break;
                }
                let size = BLOCK_BYTES.min(remaining_cap);
                if !self.admission.try_reserve_bytes(size) {
                    self.stop(PartialReason::MemoryBudget);
                    break;
                }
                if let Some(r) = self.reservation.as_mut() {
                    r.bytes += size;
                }
                self.blocks.push(vec![0u8; size].into_boxed_slice());
                continue;
            }
            let n = room.min(data.len());
            let start = self.fill();
            let block = self.blocks.last_mut().expect("a block with room exists");
            block[start..start + n].copy_from_slice(&data[..n]);
            self.response_len += n;
            data = &data[n..];
        }
        true
    }

    /// Bytes used in the last block. Every block but the last is full.
    fn fill(&self) -> usize {
        let full: usize = self
            .blocks
            .iter()
            .take(self.blocks.len().saturating_sub(1))
            .map(|b| b.len())
            .sum();
        self.response_len - full
    }

    fn stop(&mut self, reason: PartialReason) {
        self.response_open = false;
        self.partial.push(reason);
    }

    /// An emergency disable since admission: count it once, release
    /// everything now.
    fn discard(&mut self) {
        if let Some(mut r) = self.reservation.take() {
            r.admission.count_drop(DropReason::EmergencyDisabled);
            r.state = State::Accounted;
        }
        self.response_open = false;
        self.request = Vec::new();
        self.blocks = Vec::new();
    }

    /// Hand the finished capture to the exporter. Never blocks.
    pub fn finish(mut self, record: RequestRecord, meta: TraceMeta) {
        if !self.live() {
            self.discard();
        }
        let Some(mut reservation) = self.reservation.take() else {
            return;
        };
        reservation.state = State::Queued;
        let trace = Box::new(CapturedTrace {
            record,
            meta,
            request: std::mem::take(&mut self.request),
            response: std::mem::take(&mut self.blocks),
            response_len: self.response_len,
            partial: std::mem::take(&mut self.partial),
            gate: self.pinned,
            reservation: Some(reservation),
        });
        // A send error means the exporter is gone; the returned trace drops
        // here and its reservation counts it as `exporter_failed`.
        if self.admission.sender.send(trace).is_ok() {
            self.admission.stats.incr(self.admission.stats.captured, 1);
        }
    }
}

/// A finished capture on its way to the exporter.
pub struct CapturedTrace {
    pub record: RequestRecord,
    pub meta: TraceMeta,
    /// The request as received, up to the request cap.
    pub request: Vec<u8>,
    /// The delivered response in fixed blocks; the first `response_len`
    /// bytes are filled.
    pub response: Vec<Box<[u8]>>,
    pub response_len: usize,
    /// Reasons known on the worker (caps, memory budget).
    pub partial: Vec<PartialReason>,
    /// The trace gate's packed state at admission.
    pub gate: u64,
    reservation: Option<Reservation>,
}

impl std::fmt::Debug for CapturedTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturedTrace")
            .field("event_id", &self.record.event_id)
            .field("request_len", &self.request.len())
            .field("response_len", &self.response_len)
            .field("partial", &self.partial)
            .finish()
    }
}

impl CapturedTrace {
    /// The delivered response bytes, concatenated. Off the worker only.
    pub fn response_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.response_len);
        for block in &self.response {
            let take = (self.response_len - out.len()).min(block.len());
            out.extend_from_slice(&block[..take]);
        }
        out
    }

    /// Whether the gate moved since admission: an emergency disable after
    /// this request was admitted means it is not written.
    pub fn gate_moved(&self) -> bool {
        self.reservation
            .as_ref()
            .is_some_and(|r| r.admission.gate.load() != self.gate)
    }

    /// The exporter wrote it, or dropped it and counted the reason: either
    /// way, its reservation no longer counts it on drop.
    pub fn mark_accounted(&mut self) {
        if let Some(r) = self.reservation.as_mut() {
            r.state = State::Accounted;
        }
    }

    /// Count this trace as dropped for `reason` and mark it accounted.
    pub fn drop_for(mut self, reason: DropReason) {
        if let Some(r) = self.reservation.as_mut() {
            r.admission.count_drop(reason);
            r.state = State::Accounted;
        }
    }
}
