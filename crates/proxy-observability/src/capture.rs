//! Stable process-wide metadata admission. No socket, serialization, or await on workers.
use crate::{
    capture_policy::EndUserCaptureConfig,
    capture_transport::{DeliveryOutcome, TransportSession},
    records::{RequestRecord, RequestRecordSink, SubmitResult},
    stats::MetadataDeliveryStats,
};
use arc_swap::ArcSwapOption;
use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Default)]
struct Pool {
    lock: Mutex<()>,
    active: AtomicUsize,
    state: AtomicUsize,
    events: AtomicUsize,
    bytes: AtomicUsize,
    transport: AtomicUsize,
    in_flight: AtomicUsize,
}
struct Destination {
    deadline: Mutex<Option<Instant>>,
}
impl Destination {
    fn live(&self) -> bool {
        self.deadline
            .lock()
            .unwrap()
            .is_none_or(|d| Instant::now() < d)
    }
}
struct Policy {
    config: EndUserCaptureConfig,
    destination: Arc<Destination>,
}
struct State {
    previous: Option<Arc<Destination>>,
    policies: Vec<Weak<Policy>>,
}
struct Shared {
    current: ArcSwapOption<Policy>,
    state: Mutex<State>,
    pool: Arc<Pool>,
    // Packed publication keeps disabled and generation coherent.
    gate: AtomicU64,
    closed: AtomicBool,
    changes: watch::Sender<u64>,
    stats: MetadataDeliveryStats,
    tx: mpsc::Sender<Option<Event>>,
    control: Mutex<Option<Control>>,
    instance_id: String,
}
#[derive(Clone)]
pub struct CaptureSupervisor {
    shared: Arc<Shared>,
}
pub struct CaptureDelivery {
    done: oneshot::Receiver<()>,
    shared: Arc<Shared>,
}
struct Event {
    record: RequestRecord,
    permit: CaptureTerminalPermit,
    enqueued: Instant,
}
pub struct CaptureLease {
    shared: Arc<Shared>,
    policy: Arc<Policy>,
    generation: u64,
}
impl std::fmt::Debug for CaptureLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureLease")
            .field("policy_version", &self.policy.config.policy_version)
            .finish_non_exhaustive()
    }
}
impl Drop for CaptureLease {
    fn drop(&mut self) {
        self.shared
            .stats
            .release_state(self.policy.config.budgets.max_request_state_bytes);
        self.shared.pool.active.fetch_sub(1, Ordering::AcqRel);
        self.shared.pool.state.fetch_sub(
            self.policy.config.budgets.max_request_state_bytes,
            Ordering::AcqRel,
        );
    }
}
impl CaptureLease {
    pub fn live(&self) -> bool {
        self.shared.gate.load(Ordering::Acquire) == self.generation
            && self.generation & 1 == 0
            && self.policy.destination.live()
    }
    pub fn version(&self) -> &str {
        &self.policy.config.policy_version
    }
    pub fn max_attempts(&self) -> u16 {
        self.policy.config.metadata.max_attempts
    }
    pub fn max_state_bytes(&self) -> usize {
        self.policy.config.budgets.max_request_state_bytes
    }
    pub fn changes(&self) -> watch::Receiver<u64> {
        self.shared.changes.subscribe()
    }
    pub fn identity_limit(&self) {
        self.shared
            .stats
            .capture_drop(crate::stats::CaptureDrop::IdentityLimit);
    }
    /// Reserve terminal ownership before duplicating attempt state or building a record.
    pub fn reserve_terminal(&self) -> Result<CaptureTerminalPermit, SubmitResult> {
        if !self.live() {
            return Err(SubmitResult::Disabled);
        }
        let shared = &self.shared;
        let _lock = shared
            .pool
            .lock
            .try_lock()
            .map_err(|_| SubmitResult::CapacityExceeded)?;
        let current = shared
            .current
            .load_full()
            .unwrap_or_else(|| self.policy.clone());
        let b = &current.config.budgets;
        let bytes = self.policy.config.metadata.max_record_retained_bytes;
        if shared.pool.events.load(Ordering::Acquire) >= b.max_queue_events
            || shared
                .pool
                .bytes
                .load(Ordering::Acquire)
                .saturating_add(bytes)
                > b.max_queue_retained_bytes
        {
            shared
                .stats
                .record_submission(SubmitResult::CapacityExceeded);
            return Err(SubmitResult::CapacityExceeded);
        }
        shared.pool.events.fetch_add(1, Ordering::AcqRel);
        shared.pool.bytes.fetch_add(bytes, Ordering::AcqRel);
        shared.stats.reserve_event(bytes);
        Ok(CaptureTerminalPermit {
            shared: shared.clone(),
            policy: self.policy.clone(),
            generation: self.generation,
            bytes,
        })
    }
}
pub struct CaptureTerminalPermit {
    shared: Arc<Shared>,
    policy: Arc<Policy>,
    generation: u64,
    bytes: usize,
}
impl Drop for CaptureTerminalPermit {
    fn drop(&mut self) {
        self.shared.stats.release_event(self.bytes);
        self.shared.pool.events.fetch_sub(1, Ordering::AcqRel);
        self.shared
            .pool
            .bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
impl CaptureTerminalPermit {
    fn live(&self) -> bool {
        self.shared.gate.load(Ordering::Acquire) == self.generation
            && self.generation & 1 == 0
            && self.policy.destination.live()
    }
    pub fn submit(self, mut record: RequestRecord) -> SubmitResult {
        let shared = self.shared.clone();
        record.capture_policy_version = Some(self.policy.config.policy_version.clone());
        record.instance_id = self.shared.instance_id.clone();
        let result = if !self.live() {
            SubmitResult::Disabled
        } else if record.retained_bytes() > self.bytes
            || record
                .validate(self.policy.config.metadata.max_attempts)
                .is_err()
        {
            SubmitResult::CapacityExceeded
        } else {
            match shared.tx.try_reserve() {
                Ok(slot) => {
                    shared.stats.record_enqueued();
                    slot.send(Some(Event {
                        record,
                        permit: self,
                        enqueued: Instant::now(),
                    }));
                    SubmitResult::Accepted
                }
                Err(_) => SubmitResult::Closed,
            }
        };
        shared.stats.record_submission(result);
        result
    }
}
#[derive(Debug, serde::Serialize)]
pub struct CaptureStatus {
    pub disabled: bool,
    pub generation: u64,
    pub active_requests: usize,
    pub outstanding_events: usize,
    pub retained_event_bytes: usize,
}
impl CaptureSupervisor {
    pub fn start(stats: MetadataDeliveryStats) -> io::Result<(Self, CaptureDelivery)> {
        let (tx, rx) = mpsc::channel::<Option<Event>>(65536);
        let (changes, _) = watch::channel(0);
        let (done_tx, done) = oneshot::channel();
        let instance_id = crate::trace::TraceContext::new_root(false)
            .trace_id
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let shared = Arc::new(Shared {
            current: ArcSwapOption::empty(),
            state: Mutex::new(State {
                previous: None,
                policies: Vec::new(),
            }),
            pool: Arc::new(Pool::default()),
            gate: AtomicU64::new(0),
            closed: AtomicBool::new(false),
            changes,
            stats,
            tx,
            control: Mutex::new(None),
            instance_id,
        });
        // Receiver must not hold Shared (which owns the sender), or shutdown could never close it.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let delivery_changes = shared.changes.subscribe();
        std::thread::Builder::new()
            .name("llmproxy-capture".into())
            .spawn(move || {
                runtime.block_on(run_delivery(rx, delivery_changes));
                let _ = done_tx.send(());
            })?;
        Ok((
            Self {
                shared: shared.clone(),
            },
            CaptureDelivery { done, shared },
        ))
    }
    pub fn configure(
        &self,
        config: Option<EndUserCaptureConfig>,
        workers: usize,
    ) -> Result<(), String> {
        let path = "node.metadata[\"io.llmproxy.capture\"]";
        let mut state = self.shared.state.lock().unwrap();
        let _pool = self.shared.pool.lock.lock().unwrap();
        let current = self.shared.current.load_full();
        if current.as_ref().map(|p| &p.config) == config.as_ref() {
            return Ok(());
        }
        if let Some(c) = &config {
            c.budgets
                .validate(&c.metadata)
                .map_err(|(f, why)| format!("{path}.budgets.{f}: {why}"))?;
            if workers > 8 {
                return Err(format!("{path}.budgets.max_capture_memory_bytes: concurrency {workers} exceeds eight scratch owners"));
            }
            let p = &self.shared.pool;
            for (field, used, limit) in [
                (
                    "max_active_requests",
                    p.active.load(Ordering::Acquire),
                    c.budgets.max_active_requests,
                ),
                (
                    "max_queue_events",
                    p.events.load(Ordering::Acquire),
                    c.budgets.max_queue_events,
                ),
                (
                    "max_in_flight_events",
                    p.in_flight.load(Ordering::Acquire),
                    c.budgets.max_in_flight_events,
                ),
                (
                    "max_queue_retained_bytes",
                    p.bytes.load(Ordering::Acquire),
                    c.budgets.max_queue_retained_bytes,
                ),
            ] {
                if used > limit {
                    return Err(format!(
                        "{path}.budgets.{field}: reduction below live reservations"
                    ));
                }
            }
            if p.state.load(Ordering::Acquire)
                > c.budgets.max_active_requests * c.budgets.max_request_state_bytes
            {
                return Err(format!(
                    "{path}.budgets.max_request_state_bytes: reduction below live reservations"
                ));
            }
            if p.transport
                .load(Ordering::Acquire)
                .saturating_add(2 * 1024 * 1024)
                > c.budgets.max_transport_retained_bytes
            {
                return Err(format!("{path}.budgets.max_transport_retained_bytes: reduction below live reservations"));
            }
            if current
                .as_ref()
                .is_some_and(|old| old.config.emergency_control != c.emergency_control)
            {
                return Err(format!("{path}.emergency_control: control endpoint is boot-scoped; disable and restart to change it"));
            }
            state.policies.retain(|p| p.strong_count() > 0);
            if state.policies.len() >= 16 {
                return Err(format!(
                    "{path}.policy.version: sixteen pinned versions are still live"
                ));
            }
            let same = current
                .as_ref()
                .is_some_and(|old| old.config.endpoint == c.endpoint);
            if !same && state.previous.as_ref().is_some_and(|e| e.live()) {
                return Err(format!(
                    "{path}.endpoint.unix_socket_path: previous destination is still draining"
                ));
            }
            self.ensure_control(&c.emergency_control)
                .map_err(|e| format!("{path}.emergency_control.unix_socket_path: {e}"))?;
            let destination = if same {
                current.as_ref().unwrap().destination.clone()
            } else {
                if let Some(old) = &current {
                    *old.destination.deadline.lock().unwrap() =
                        Some(Instant::now() + old.config.transport.drain_deadline);
                    state.previous = Some(old.destination.clone());
                }
                Arc::new(Destination {
                    deadline: Mutex::new(None),
                })
            };
            let policy = Arc::new(Policy {
                config: c.clone(),
                destination,
            });
            state.policies.push(Arc::downgrade(&policy));
            self.shared.current.store(Some(policy));
        } else {
            if let Some(old) = &current {
                *old.destination.deadline.lock().unwrap() =
                    Some(Instant::now() + old.config.transport.drain_deadline);
                state.previous = Some(old.destination.clone());
            }
            self.shared.current.store(None);
        }
        let old_capacity = current
            .as_ref()
            .map_or(0, |p| p.config.budgets.max_queue_events);
        let new_capacity = config.as_ref().map_or(0, |c| c.budgets.max_queue_events);
        self.shared
            .stats
            .change_queue_capacity(new_capacity as i64 - old_capacity as i64);
        Ok(())
    }
    pub fn status(&self) -> CaptureStatus {
        let g = self.shared.gate.load(Ordering::Acquire);
        CaptureStatus {
            disabled: g & 1 != 0,
            generation: g >> 1,
            active_requests: self.shared.pool.active.load(Ordering::Acquire),
            outstanding_events: self.shared.pool.events.load(Ordering::Acquire),
            retained_event_bytes: self.shared.pool.bytes.load(Ordering::Acquire),
        }
    }
    pub fn set_disabled(
        &self,
        disabled: bool,
        expected_generation: u64,
    ) -> Result<CaptureStatus, &'static str> {
        let old = self.shared.gate.load(Ordering::Acquire);
        if old >> 1 != expected_generation {
            return Err("stale generation");
        }
        let next = (expected_generation
            .checked_add(1)
            .filter(|g| *g <= u64::MAX >> 1)
            .ok_or("generation exhausted")?
            << 1)
            | u64::from(disabled);
        self.shared
            .gate
            .compare_exchange(old, next, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "stale generation")?;
        self.shared.changes.send_replace(next);
        Ok(self.status())
    }
    pub fn stop_admissions(&self) {
        self.shared.closed.store(true, Ordering::Release);
    }
    pub fn drain_deadline(&self) -> Duration {
        self.shared
            .current
            .load_full()
            .map(|p| p.config.transport.drain_deadline)
            .unwrap_or(Duration::from_secs(5))
    }
}
impl RequestRecordSink for CaptureSupervisor {
    fn requires_admission(&self) -> bool {
        true
    }
    fn try_admit(&self) -> Result<Option<Arc<CaptureLease>>, SubmitResult> {
        let result = self.admit();
        self.shared.stats.state_admission(match &result {
            Ok(_) => SubmitResult::Accepted,
            Err(r) => *r,
        });
        result
    }
    fn submit(&self, _: RequestRecord) -> SubmitResult {
        SubmitResult::Disabled
    }
}
impl CaptureSupervisor {
    fn admit(&self) -> Result<Option<Arc<CaptureLease>>, SubmitResult> {
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(SubmitResult::Closed);
        }
        let generation = self.shared.gate.load(Ordering::Acquire);
        if generation & 1 != 0 {
            return Err(SubmitResult::Disabled);
        }
        let _lock = self
            .shared
            .pool
            .lock
            .try_lock()
            .map_err(|_| SubmitResult::CapacityExceeded)?;
        let policy = self
            .shared
            .current
            .load_full()
            .ok_or(SubmitResult::Disabled)?;
        let b = &policy.config.budgets;
        if self.shared.pool.active.load(Ordering::Acquire) >= b.max_active_requests
            || self
                .shared
                .pool
                .state
                .load(Ordering::Acquire)
                .saturating_add(b.max_request_state_bytes)
                > b.max_active_requests * b.max_request_state_bytes
        {
            return Err(SubmitResult::CapacityExceeded);
        }
        self.shared.pool.active.fetch_add(1, Ordering::AcqRel);
        self.shared
            .pool
            .state
            .fetch_add(b.max_request_state_bytes, Ordering::AcqRel);
        self.shared.stats.reserve_state(b.max_request_state_bytes);
        Ok(Some(Arc::new(CaptureLease {
            shared: self.shared.clone(),
            policy,
            generation,
        })))
    }
}
impl CaptureDelivery {
    pub async fn shutdown(self, deadline: Duration) -> bool {
        self.shared.closed.store(true, Ordering::Release);
        self.shared.control.lock().unwrap().take();
        let _ = self.shared.tx.try_send(None);
        !matches!(tokio::time::timeout(deadline, self.done).await, Ok(Ok(())))
    }
}
const DELIVERY_SLOTS: usize = 8;

enum TransportAdmission {
    Ready(TransportReservation),
    Busy,
    TooLarge,
}
fn reserve_transport(event: &Event) -> TransportAdmission {
    let shared = &event.permit.shared;
    let config = &event.permit.policy.config;
    let scratch = config.metadata.max_record_retained_bytes
        + config.metadata.max_encoded_record_bytes
        + 65536;
    let _lock = shared.pool.lock.lock().unwrap();
    let current = shared.current.load_full();
    let budgets = current
        .as_ref()
        .map_or(&config.budgets, |p| &p.config.budgets);
    if scratch.saturating_add(2 * 1024 * 1024) > budgets.max_transport_retained_bytes {
        return TransportAdmission::TooLarge;
    }
    if shared.pool.in_flight.load(Ordering::Acquire)
        >= budgets
            .max_in_flight_events
            .min(config.budgets.max_in_flight_events)
            .min(DELIVERY_SLOTS)
        || shared
            .pool
            .transport
            .load(Ordering::Acquire)
            .saturating_add(scratch)
            .saturating_add(2 * 1024 * 1024)
            > budgets.max_transport_retained_bytes
    {
        return TransportAdmission::Busy;
    }
    shared.pool.transport.fetch_add(scratch, Ordering::AcqRel);
    shared.pool.in_flight.fetch_add(1, Ordering::AcqRel);
    TransportAdmission::Ready(TransportReservation {
        pool: shared.pool.clone(),
        bytes: scratch,
    })
}

async fn run_delivery(mut rx: mpsc::Receiver<Option<Event>>, mut changes: watch::Receiver<u64>) {
    let mut jobs = tokio::task::JoinSet::new();
    let mut idle: Vec<(usize, Option<TransportSession>)> =
        (0..DELIVERY_SLOTS).map(|i| (i, None)).collect();
    let mut pending: Option<Event> = None;
    let mut closed = false;
    loop {
        if let Some(event) = pending.take() {
            use crate::stats::CaptureDrop;
            let drop_reason = if !event.permit.live() {
                Some(CaptureDrop::Disabled)
            } else if event.enqueued.elapsed()
                >= event.permit.policy.config.transport.event_deadline
            {
                Some(CaptureDrop::Expired)
            } else {
                None
            };
            if let Some(reason) = drop_reason {
                event.permit.shared.stats.record_dequeued();
                event.permit.shared.stats.capture_drop(reason);
                continue;
            }
            let admission = if idle.is_empty() {
                TransportAdmission::Busy
            } else {
                reserve_transport(&event)
            };
            match admission {
                TransportAdmission::Ready(reservation) => {
                    event.permit.shared.stats.record_dequeued();
                    let (slot, session) = idle.pop().unwrap();
                    jobs.spawn(async move {
                        let session = deliver_event(event, reservation, session).await;
                        (slot, session)
                    });
                    continue;
                }
                TransportAdmission::TooLarge => {
                    event.permit.shared.stats.record_dequeued();
                    event
                        .permit
                        .shared
                        .stats
                        .capture_drop(CaptureDrop::TransportCapacity);
                    continue;
                }
                TransportAdmission::Busy => pending = Some(event),
            }
        }
        if closed && pending.is_none() && jobs.is_empty() {
            break;
        }
        tokio::select! {
            joined = jobs.join_next(), if !jobs.is_empty() => {
                match joined {
                    Some(Ok(slot)) => idle.push(slot),
                    // Fail closed on an internal task panic instead of losing a slot and spinning.
                    _ => { rx.close(); break; }
                }
            }
            received = rx.recv(), if pending.is_none() && !closed => {
                match received {
                    Some(Some(event)) => pending = Some(event),
                    Some(None) => rx.close(),
                    None => closed = true,
                }
            }
            changed = changes.changed() => {
                if changed.is_err() && jobs.is_empty() && pending.is_none() { rx.close(); closed = true; }
            }
        }
    }
}

async fn deliver_event(
    event: Event,
    _reservation: TransportReservation,
    session: Option<TransportSession>,
) -> Option<TransportSession> {
    use crate::stats::CaptureDrop;
    let config = &event.permit.policy.config;
    let deadline = event.enqueued + config.transport.event_deadline;
    let deadline = event
        .permit
        .policy
        .destination
        .deadline
        .lock()
        .unwrap()
        .map_or(deadline, |d| d.min(deadline));
    // Dispatch and the first task poll can straddle disable or destination drain.
    // Check again before cloning endpoint identity or allocating encoded output.
    let drop_reason = if !event.permit.live() {
        Some(CaptureDrop::Disabled)
    } else if Instant::now() >= deadline {
        Some(CaptureDrop::Expired)
    } else {
        None
    };
    if let Some(reason) = drop_reason {
        event.permit.shared.stats.capture_drop(reason);
        return session;
    }
    let mut session = session
        .filter(|s| s.matches(&config.endpoint))
        .unwrap_or_else(|| TransportSession::new(config.endpoint.clone()));
    let mut bytes = BoundedEncoding {
        data: Vec::with_capacity(config.metadata.max_encoded_record_bytes),
        limit: config.metadata.max_encoded_record_bytes,
    };
    if serde_json::to_writer(&mut bytes, &event.record).is_err() {
        event
            .permit
            .shared
            .stats
            .capture_drop(CaptureDrop::EncodedLimit);
        event.permit.shared.stats.record_write_failure();
        return Some(session);
    }
    let outcome = session
        .deliver(
            &bytes.data,
            &event.record.event_id,
            &config.transport,
            deadline,
            || event.permit.live(),
        )
        .await;
    match outcome {
        DeliveryOutcome::Durable => {
            event.permit.shared.stats.record_written();
            event.permit.shared.stats.record_durable();
        }
        other => {
            let reason = match other {
                DeliveryOutcome::Rejected => CaptureDrop::AgentRejected,
                DeliveryOutcome::Unavailable => CaptureDrop::Unavailable,
                DeliveryOutcome::Expired => CaptureDrop::Expired,
                DeliveryOutcome::Disabled => CaptureDrop::Disabled,
                _ => CaptureDrop::DeliveryUnknown,
            };
            event.permit.shared.stats.capture_drop(reason);
            event.permit.shared.stats.record_write_failure();
        }
    }
    // Both input and serialization reservations remain owned through the ACK.
    Some(session)
}

struct BoundedEncoding {
    data: Vec<u8>,
    limit: usize,
}
struct TransportReservation {
    pool: Arc<Pool>,
    bytes: usize,
}
impl Drop for TransportReservation {
    fn drop(&mut self) {
        self.pool.transport.fetch_sub(self.bytes, Ordering::AcqRel);
        self.pool.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Write for BoundedEncoding {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if self.data.len().saturating_add(b.len()) > self.limit {
            return Err(io::Error::other("encoded capture limit"));
        }
        self.data.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct Control {
    config: crate::capture_policy::LocalCaptureControl,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Control {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.config.unix_socket_path);
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    command: Action,
    expected_generation: Option<u64>,
}
#[derive(serde::Deserialize)]
enum Action {
    Disable,
    Enable,
    Status,
}
impl CaptureSupervisor {
    fn ensure_control(
        &self,
        config: &crate::capture_policy::LocalCaptureControl,
    ) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mut control = self.shared.control.lock().unwrap();
        if let Some(old) = &*control {
            if old.config != *config {
                return Err(io::Error::other(
                    "control identity/path cannot change during reload",
                ));
            }
            return Ok(());
        }
        let parent = config
            .unix_socket_path
            .parent()
            .ok_or_else(|| io::Error::other("missing control socket parent"))?;
        if std::fs::metadata(parent)?.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "control socket parent must be private (0700)",
            ));
        }
        // Never unlink an existing socket owned by another process or an old deployment.
        let listener = tokio::net::UnixListener::bind(&config.unix_socket_path)?;
        std::fs::set_permissions(
            &config.unix_socket_path,
            std::fs::Permissions::from_mode(0o600),
        )?;
        let weak = Arc::downgrade(&self.shared);
        let uid = config.operator_uid;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                if !stream.peer_cred().is_ok_and(|p| p.uid() == uid) {
                    continue;
                }
                let weak = weak.clone();
                let _ = tokio::time::timeout(Duration::from_secs(1), async {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let size = stream.read_u32().await? as usize;
                    if size == 0 || size > 1024 {
                        return Err(io::Error::other("invalid control frame length"));
                    }
                    let mut bytes = vec![0; size];
                    stream.read_exact(&mut bytes).await?;
                    let command: Command = serde_json::from_slice(&bytes)
                        .map_err(|_| io::Error::other("invalid control command"))?;
                    let shared = weak
                        .upgrade()
                        .ok_or_else(|| io::Error::other("capture shutting down"))?;
                    let supervisor = CaptureSupervisor { shared };
                    let response = match command.command {
                        Action::Status => serde_json::to_vec(&supervisor.status()),
                        Action::Disable | Action::Enable => match command.expected_generation {
                            Some(g) => match supervisor
                                .set_disabled(matches!(command.command, Action::Disable), g)
                            {
                                Ok(s) => serde_json::to_vec(&s),
                                Err(e) => serde_json::to_vec(&serde_json::json!({"error":e})),
                            },
                            None => serde_json::to_vec(
                                &serde_json::json!({"error":"expected_generation required"}),
                            ),
                        },
                    }
                    .map_err(io::Error::other)?;
                    stream.write_u32(response.len() as u32).await?;
                    stream.write_all(&response).await?;
                    Ok::<(), io::Error>(())
                })
                .await;
            }
        });
        *control = Some(Control {
            config: config.clone(),
            task,
        });
        Ok(())
    }
}
