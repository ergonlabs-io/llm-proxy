//! Outlier detection (S6): ejects hosts that are misbehaving --
//! consecutive errors or a statistically bad success/failure rate relative to
//! their peers -- from load-balancer selection, without waiting for active
//! health checking to notice.
//!
//! **This module is the detection engine.** It is fully wired:
//! [`crate::manager::ClusterManager`] builds an [`OutlierDetector`] per
//! cluster from the lowered `outlier_detection` config, spawns its sweep, and
//! the router feeds it one [`OutlierDetector::report_result`] per upstream
//! attempt through [`crate::ClusterEntry::report_outlier_result`]. The tests
//! in this file still drive the engine directly through its public API (that
//! is the right level to pin the S6 state machine); the end-to-end path is
//! covered by the manager tests (`outlier_detection_ejects_a_host_after_consecutive_5xx`)
//! and the router tests.
//!
//! The IR carries the config as `proxy_config::ir::OutlierDetectionIR`;
//! [`OutlierDetectionConfig`] here is the runtime twin, built from it via
//! `From<&OutlierDetectionIR>`. The two hold Envoy's S6 defaults independently
//! (`proxy-config` cannot depend on `proxy-cluster`), and
//! `ir_defaults_match_runtime_defaults` in this file's tests pins that they
//! agree so they cannot silently drift.
//!
//! # Design notes worth reading before touching this file
//!
//! **A gateway failure bumps *both* the consecutive-5xx and
//! consecutive-gateway-failure counters.** This matches real Envoy, where a
//! gateway error is a *subset* of 5xx, not a separate axis --
//! `DetectorImpl::putHttpResponseCode` does:
//!
//! ```cpp
//! if (Http::CodeUtility::is5xx(response_code)) {
//!   if (Http::CodeUtility::isGatewayError(response_code)) {
//!     // ... bump consecutive gateway failure
//!   }
//!   // ... and ALSO bump consecutive 5xx
//! }
//! ```
//!
//! The consequence, which is correct Envoy behaviour and not a bug: **five
//! consecutive gateway failures do cause an ejection**, even though
//! `enforcing_consecutive_gateway_failure` defaults to 0%. They eject
//! through the consecutive-5xx detector (`enforcing_consecutive_5xx`
//! defaults to 100%), which fires on the very same request that trips the
//! gateway-failure counter. `enforcing_consecutive_gateway_failure = 0` only
//! disables *that detector's own* ejections -- it cannot stop the 5xx
//! detector from seeing (and enforcing on) the same failures. A
//! [`RequestResult::Success`] (or any non-5xx result) resets both counters,
//! as it does in Envoy.
//!
//! **A threshold crossing always resets its counter**, whether or not the
//! resulting ejection was actually enforced (blocked by the enforcement-
//! percent dice roll or by [`OutlierDetectionConfig::max_ejection_percent`]).
//! This matches Envoy's own edge-triggered counters: the *detection* fired
//! either way, so the run restarts from zero rather than re-firing on every
//! subsequent request.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use chrono::SecondsFormat;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use tokio::task::JoinHandle;

use crate::host_set::HostSet;
use crate::{HealthFlags, Host};

/// What one completed request told us about the host that served it.
/// [`RequestResult::GatewayFailure`] bumps *both* the consecutive-5xx and
/// consecutive-gateway-failure counters -- see the module doc's note on why
/// a gateway error is a subset of 5xx, not an independent axis.
///
/// [`RequestResult::LocalOriginFailure`] (connect failure, timeout, reset --
/// anything that never got as far as an upstream HTTP status) is folded into
/// the same bucket as [`RequestResult::Http5xx`], matching
/// `split_external_local_origin_errors = false` (S6's default, and the only
/// mode implemented here -- see [`OutlierDetectionConfig::split_external_local_origin_errors`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestResult {
    Success,
    Http5xx,
    GatewayFailure,
    LocalOriginFailure,
}

/// Timing + thresholds for one cluster's outlier detector (Envoy's
/// `OutlierDetection` message). Every field is commented with its S6 default;
/// [`Default`] reproduces those defaults exactly.
#[derive(Debug, Clone, PartialEq)]
pub struct OutlierDetectionConfig {
    /// How often the success-rate and failure-percentage detectors re-run
    /// over the whole host set. S6 default: 10s.
    pub interval: Duration,
    /// First ejection's duration; later ejections grow by this amount per
    /// consecutive ejection (see [`OutlierDetectionConfig::max_ejection_time`]).
    /// S6 default: 30s.
    pub base_ejection_time: Duration,
    /// Ceiling on ejection duration regardless of growth, clamped to be at
    /// least `base_ejection_time`. S6 default: `max(300s, base_ejection_time)`.
    pub max_ejection_time: Duration,
    /// Percent of a cluster's hosts that may be simultaneously ejected. S6
    /// default: 10.
    pub max_ejection_percent: u8,
    /// If true, at least one host may always be ejected even if
    /// `max_ejection_percent` would otherwise round down to zero for a small
    /// cluster. S6 default: false -- there is deliberately no "at least one"
    /// exemption.
    pub always_eject_one_host: bool,

    /// Consecutive 5xx (or folded local-origin failure) responses required
    /// to trip this detector. S6 default: 5.
    pub consecutive_5xx: u32,
    /// Percent chance a tripped consecutive-5xx detection is actually
    /// enforced (ejects the host) rather than merely logged/counted. S6
    /// default: 100.
    pub enforcing_consecutive_5xx: u8,
    /// Consecutive gateway-failure (502/503/504) responses required to trip
    /// this detector. S6 default: 5.
    pub consecutive_gateway_failure: u32,
    /// Percent chance a tripped consecutive-gateway-failure detection is
    /// enforced. S6 default: **0** -- tracked but never enforced out of the
    /// box; this is the default most implementations get wrong.
    pub enforcing_consecutive_gateway_failure: u8,

    /// Minimum number of hosts (with at least `success_rate_request_volume`
    /// requests in the interval) required before the success-rate detector
    /// runs at all. S6 default: 5.
    pub success_rate_min_hosts: u32,
    /// Minimum requests a host must have seen in the interval to be eligible
    /// for success-rate detection. S6 default: 100.
    pub success_rate_request_volume: u32,
    /// Ejection threshold in thousandths of a standard deviation below the
    /// mean success rate (1900 == 1.9 sigma). S6 default: 1900.
    pub success_rate_stdev_factor: u32,
    /// Percent chance a tripped success-rate detection is enforced. S6
    /// default: 100.
    pub enforcing_success_rate: u8,

    /// Failure-percentage threshold (0-100) above which a host is a
    /// candidate for ejection. S6 default: 85.
    pub failure_percentage_threshold: u8,
    /// Percent chance a tripped failure-percentage detection is enforced. S6
    /// default: **0**.
    pub enforcing_failure_percentage: u8,
    /// Minimum number of eligible hosts required before the
    /// failure-percentage detector runs. S6 default: 5.
    pub failure_percentage_min_hosts: u32,
    /// Minimum requests a host must have seen in the interval to be eligible
    /// for failure-percentage detection. S6 default: 50.
    pub failure_percentage_request_volume: u32,

    /// Whether locally-originated failures (connect failure, timeout, reset)
    /// are tracked as a separate axis from externally-observed 5xx
    /// responses. S6 default: false. **Only `false` is implemented** --
    /// [`RequestResult::LocalOriginFailure`] always folds into the 5xx path
    /// regardless of this field's value; setting it `true` is accepted (no
    /// error) but has no additional effect, since nothing in this crate
    /// exposes it through the IR yet for a caller to actually rely on the
    /// split. Implementing the split is future work, not a silent
    /// approximation of a reachable config surface.
    pub split_external_local_origin_errors: bool,
    /// Whether a host un-ejects the moment it passes an active health check
    /// independent of its outlier ejection timer. S6 default: true.
    /// Envoy *does* expose this as a configurable field --
    /// `envoy.config.cluster.v3.OutlierDetection.successful_active_health_check_uneject_host`
    /// (field 23, a `BoolValue` defaulting to true). It is modeled here so [`OutlierDetector`]
    /// stays testable without requiring a real
    /// [`crate::health_check::HealthCheckEngine`] wired up (see
    /// [`OutlierDetector::on_active_health_check_pass`]).
    pub uneject_on_healthy_active_hc: bool,
}

impl Default for OutlierDetectionConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            base_ejection_time: Duration::from_secs(30),
            max_ejection_time: Duration::from_secs(300),
            max_ejection_percent: 10,
            always_eject_one_host: false,
            consecutive_5xx: 5,
            enforcing_consecutive_5xx: 100,
            consecutive_gateway_failure: 5,
            enforcing_consecutive_gateway_failure: 0,
            success_rate_min_hosts: 5,
            success_rate_request_volume: 100,
            success_rate_stdev_factor: 1900,
            enforcing_success_rate: 100,
            failure_percentage_threshold: 85,
            enforcing_failure_percentage: 0,
            failure_percentage_min_hosts: 5,
            failure_percentage_request_volume: 50,
            split_external_local_origin_errors: false,
            uneject_on_healthy_active_hc: true,
        }
    }
}

impl From<&proxy_config::ir::OutlierDetectionIR> for OutlierDetectionConfig {
    /// The lowered IR is this config minus
    /// `split_external_local_origin_errors` (which lowering rejects unless
    /// `false` -- see the IR type's doc), so that field always takes its only
    /// implemented value here. Every other field maps 1:1; the two field-name
    /// differences (`success_rate_min_hosts` / `failure_percentage_min_hosts`)
    /// are spelled out below. The `ir_defaults_match_runtime_defaults` test in
    /// this module pins that the two sides' defaults agree, so this mapping
    /// and the IR cannot silently drift apart.
    fn from(ir: &proxy_config::ir::OutlierDetectionIR) -> Self {
        Self {
            interval: ir.interval,
            base_ejection_time: ir.base_ejection_time,
            max_ejection_time: ir.max_ejection_time,
            max_ejection_percent: ir.max_ejection_percent,
            always_eject_one_host: ir.always_eject_one_host,
            consecutive_5xx: ir.consecutive_5xx,
            enforcing_consecutive_5xx: ir.enforcing_consecutive_5xx,
            consecutive_gateway_failure: ir.consecutive_gateway_failure,
            enforcing_consecutive_gateway_failure: ir.enforcing_consecutive_gateway_failure,
            success_rate_min_hosts: ir.success_rate_min_hosts,
            success_rate_request_volume: ir.success_rate_request_volume,
            success_rate_stdev_factor: ir.success_rate_stdev_factor,
            enforcing_success_rate: ir.enforcing_success_rate,
            failure_percentage_threshold: ir.failure_percentage_threshold,
            enforcing_failure_percentage: ir.enforcing_failure_percentage,
            failure_percentage_min_hosts: ir.failure_percentage_min_hosts,
            failure_percentage_request_volume: ir.failure_percentage_request_volume,
            // Only `false` is implemented; lowering guarantees a `true` never
            // reaches here (`convert_outlier_detection` rejects it).
            split_external_local_origin_errors: false,
            uneject_on_healthy_active_hc: ir.uneject_on_healthy_active_hc,
        }
    }
}

/// Per-host counters the detector needs between requests/intervals. Control-
/// runtime-only state, guarded by a single [`Mutex`] on
/// [`OutlierDetector::states`] -- unlike `Host::active_requests`, these
/// counters are read/written far less often (once per request-completion,
/// not once per in-flight-gauge check), so a `Mutex<HashMap<..>>` is simple
/// and fast enough; there's no per-worker hot path touching this map.
#[derive(Debug, Default, Clone)]
struct HostState {
    consecutive_5xx: u32,
    consecutive_gateway_failure: u32,
    /// How many times this host has been ejected in its lifetime --  drives
    /// ejection-time growth (S6: `base_ejection_time * consecutive-ejection
    /// count`).
    ejection_count: u32,
    /// Successes/failures accumulated since the last interval tick, for the
    /// success-rate/failure-percentage detectors.
    interval_success: u32,
    interval_failure: u32,
}

/// Which detector fired, for the event log's `type` field. Names match
/// Envoy's own outlier-detector type strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EjectionCause {
    Consecutive5xx,
    ConsecutiveGatewayFailure,
    SuccessRate,
    FailurePercentage,
}

impl EjectionCause {
    fn detector_type(self) -> &'static str {
        match self {
            EjectionCause::Consecutive5xx => "5XX",
            EjectionCause::ConsecutiveGatewayFailure => "GATEWAY_FAILURE",
            EjectionCause::SuccessRate => "SUCCESS_RATE",
            EjectionCause::FailurePercentage => "FAILURE_PERCENTAGE",
        }
    }
}

/// Why a host was un-ejected, for the event log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnejectReason {
    EjectionExpired,
    HealthCheckPass,
}

impl UnejectReason {
    fn detector_type(self) -> &'static str {
        match self {
            UnejectReason::EjectionExpired => "EJECTION_EXPIRED",
            UnejectReason::HealthCheckPass => "ACTIVE_HC_PASS",
        }
    }
}

/// `eject`/`uneject`, Envoy's own event-log discriminator.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EjectAction {
    Eject,
    Uneject,
}

/// Envoy's outlier-detection event-log JSON shape (diffable, S6's
/// acceptance criterion). Field names/shape approximate Envoy's real
/// `EventLoggerImpl` output; exact fidelity (e.g. `secs_since_last_action`,
/// which needs cluster-wide last-event tracking we don't keep) is left for
/// whoever wires this to a real diff-rig fixture -- what matters here is
/// that every ejection/un-ejection decision produces one structured,
/// serializable record a caller can capture and compare.
#[derive(Debug, Clone, Serialize)]
pub struct OutlierEvent {
    pub action: EjectAction,
    pub cluster_name: String,
    pub upstream_url: String,
    /// RFC 3339 / ISO 8601, matching Envoy's own event-log timestamp format.
    pub timestamp: String,
    /// How many times *this host* has been ejected in its lifetime so far
    /// (including this event, if it was an ejection).
    pub num_ejections: u32,
    /// Whether this event actually changed live routing state. `false`
    /// covers both "the enforcement-percent dice roll said no" and "blocked
    /// by `max_ejection_percent`" -- the detector fired either way, but nothing
    /// was enforced.
    pub enforced: bool,
    /// Which detector/reason fired (Envoy's `type` field).
    #[serde(rename = "type")]
    pub detector_type: &'static str,
    /// Set only for an enforced ejection.
    pub eject_duration_ms: Option<u64>,
}

/// Where [`OutlierEvent`]s go. Behind a trait so tests can capture them
/// in-process instead of this module opening a file -- production wiring
/// (a real event-log sink file, per S6) is left to whoever calls
/// [`OutlierDetector::new`], not this module's concern.
pub trait OutlierEventSink: Send + Sync {
    fn record(&self, event: OutlierEvent);
}

/// Default sink: logs the event's JSON via `tracing` rather than opening a
/// file. Real Envoy writes its event log to a configured file path; nothing
/// in this crate owns file I/O, so a caller who wants that can implement
/// [`OutlierEventSink`] over a file themselves.
pub struct TracingEventSink;

impl OutlierEventSink for TracingEventSink {
    fn record(&self, event: OutlierEvent) {
        match serde_json::to_string(&event) {
            Ok(json) => tracing::info!(target: "outlier_detection", "{json}"),
            Err(err) => tracing::warn!("failed to serialize outlier event: {err}"),
        }
    }
}

/// Runs one cluster's outlier detection: immediate consecutive-error checks
/// on every reported request result, plus a periodic (`interval`) pass of
/// the statistical success-rate/failure-percentage detectors over the whole
/// host set.
///
/// Rust note: like [`crate::health_check::HealthCheckEngine`], this type
/// only runs on the control runtime (the interval loop is a `tokio::spawn`ed
/// task) but is `Send + Sync` so [`OutlierDetector::report_result`] can be
/// called from any worker thread that just finished a request. The `Arc`
/// wrapping `OutlierDetector::host_set`/`OutlierDetector::sink` (rather
/// than borrowing) is what lets `OutlierDetector::eject` hand a cheap
/// clone of "how to un-eject this host" to a detached `tokio::spawn`ed timer
/// without needing the whole detector wrapped in an `Arc` itself -- unlike
/// `HealthCheckEngine`, `report_result` is a plain `&self` method (matching
/// the seam the router integration expects), so nothing here requires
/// callers to hold an `Arc<OutlierDetector>` at all except to call
/// [`OutlierDetector::spawn`].
pub struct OutlierDetector {
    config: OutlierDetectionConfig,
    cluster_name: String,
    host_set: Arc<ArcSwap<HostSet>>,
    states: Mutex<HashMap<SocketAddr, HostState>>,
    rng: Mutex<StdRng>,
    sink: Arc<dyn OutlierEventSink>,
    /// Test-only seam: handles for every detached un-eject timer spawned by
    /// [`OutlierDetector::schedule_uneject`]. `tokio::time::advance` moves
    /// the virtual clock but does not by itself run tasks parked on an
    /// already-expired timer back to completion -- only actually polling
    /// them (awaiting the `JoinHandle`) does. Production code never reads
    /// this; it exists purely so tests can deterministically wait for a
    /// scheduled un-ejection to finish after advancing time, instead of
    /// guessing how many `yield_now`s are enough.
    #[cfg(test)]
    uneject_handles: Mutex<Vec<JoinHandle<()>>>,
}

impl OutlierDetector {
    pub fn new(
        config: OutlierDetectionConfig,
        cluster_name: impl Into<String>,
        host_set: Arc<ArcSwap<HostSet>>,
        sink: Arc<dyn OutlierEventSink>,
    ) -> Arc<Self> {
        Self::with_seed(config, cluster_name, host_set, sink, rand::random())
    }

    /// Test/determinism seam: fixes the enforcement-percent dice roll's seed.
    /// Every S6 default is 0% or 100% (never in between), so the roll is
    /// deterministic regardless of seed for the tests in this file -- this
    /// exists for parity with the rest of the crate's RNG-seeding
    /// convention ([`crate::load_balancer`]'s `with_seed` constructors) and
    /// for whoever configures a non-default enforcement percentage later.
    pub fn with_seed(
        config: OutlierDetectionConfig,
        cluster_name: impl Into<String>,
        host_set: Arc<ArcSwap<HostSet>>,
        sink: Arc<dyn OutlierEventSink>,
        seed: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            config,
            cluster_name: cluster_name.into(),
            host_set,
            states: Mutex::new(HashMap::new()),
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            sink,
            #[cfg(test)]
            uneject_handles: Mutex::new(Vec::new()),
        })
    }

    /// Test-only: wait for every un-eject timer spawned so far to run to
    /// completion. Only meaningful *after* advancing the virtual clock past
    /// a scheduled ejection's deadline -- see the field doc on
    /// [`OutlierDetector::uneject_handles`].
    #[cfg(test)]
    async fn await_pending_unejects(&self) {
        let handles: Vec<JoinHandle<()>> = self.uneject_handles.lock().unwrap().drain(..).collect();
        for handle in handles {
            handle.await.expect("un-eject task must not panic");
        }
    }

    /// Spawn the periodic success-rate/failure-percentage sweep on the
    /// current (control) runtime. Consecutive-5xx/gateway-failure detection
    /// needs no spawned loop -- it runs synchronously inside
    /// [`OutlierDetector::report_result`].
    pub fn spawn(self: &Arc<Self>) -> JoinHandle<()> {
        let engine = Arc::clone(self);
        tokio::spawn(async move { engine.run_interval_loop().await })
    }

    async fn run_interval_loop(&self) {
        loop {
            tokio::time::sleep(self.config.interval).await;
            self.run_interval_tick();
        }
    }

    /// Feed one request's outcome to the detector. Updates the host's
    /// consecutive counters and interval success/failure tally, and
    /// immediately attempts an ejection if a consecutive threshold was just
    /// crossed (Envoy's own consecutive detectors are edge-triggered per
    /// request, not interval-batched).
    pub fn report_result(&self, addr: SocketAddr, result: RequestResult) {
        let (fired_5xx, fired_gateway) = {
            let mut states = self.states.lock().unwrap();
            let state = states.entry(addr).or_default();
            match result {
                RequestResult::Success => {
                    state.consecutive_5xx = 0;
                    state.consecutive_gateway_failure = 0;
                    state.interval_success += 1;
                }
                RequestResult::Http5xx | RequestResult::LocalOriginFailure => {
                    // `split_external_local_origin_errors` is not
                    // implemented (see the config field's doc comment) --
                    // local-origin failures always fold in here.
                    state.consecutive_5xx += 1;
                    state.interval_failure += 1;
                }
                RequestResult::GatewayFailure => {
                    // Envoy's `DetectorImpl::putHttpResponseCode`: a gateway
                    // error (502/503/504) is a *subset* of 5xx, so it bumps
                    // both counters -- see the module doc for the full
                    // reasoning and the consequence (five consecutive
                    // gateway failures do eject, via the 5xx detector).
                    state.consecutive_5xx += 1;
                    state.consecutive_gateway_failure += 1;
                    state.interval_failure += 1;
                }
            }
            let fired_5xx = state.consecutive_5xx >= self.config.consecutive_5xx;
            let fired_gateway =
                state.consecutive_gateway_failure >= self.config.consecutive_gateway_failure;
            // Reset on crossing regardless of whether the ejection attempt
            // below is actually enforced -- see the module doc.
            if fired_5xx {
                state.consecutive_5xx = 0;
            }
            if fired_gateway {
                state.consecutive_gateway_failure = 0;
            }
            (fired_5xx, fired_gateway)
        };

        if fired_5xx {
            self.attempt_eject(
                addr,
                EjectionCause::Consecutive5xx,
                self.config.enforcing_consecutive_5xx,
            );
        }
        if fired_gateway {
            self.attempt_eject(
                addr,
                EjectionCause::ConsecutiveGatewayFailure,
                self.config.enforcing_consecutive_gateway_failure,
            );
        }
    }

    /// Un-eject a host that just passed an active health check, if
    /// [`OutlierDetectionConfig::uneject_on_healthy_active_hc`] says to
    /// (default true). No-op if the host wasn't outlier-ejected.
    ///
    /// Called by [`crate::health_check::HealthCheckEngine`]'s host loop on a
    /// passing active check when the cluster configures outlier detection.
    /// Tests in this file also call it directly.
    pub fn on_active_health_check_pass(&self, addr: SocketAddr) {
        if !self.config.uneject_on_healthy_active_hc {
            return;
        }
        if Self::set_outlier_flag(&self.host_set, addr, false) {
            self.emit_uneject_event(addr, UnejectReason::HealthCheckPass);
        }
    }

    /// Interval sweep: snapshot + reset every host's interval counters, then
    /// run the success-rate and failure-percentage detectors over the
    /// snapshot.
    fn run_interval_tick(&self) {
        let snapshot: Vec<(SocketAddr, u32, u32)> = {
            let mut states = self.states.lock().unwrap();
            states
                .iter_mut()
                .map(|(addr, state)| {
                    let entry = (*addr, state.interval_success, state.interval_failure);
                    state.interval_success = 0;
                    state.interval_failure = 0;
                    entry
                })
                .collect()
        };
        self.run_success_rate_detection(&snapshot);
        self.run_failure_percentage_detection(&snapshot);
    }

    /// S6 success-rate detection: eject hosts whose success rate falls more
    /// than `stdev_factor` (in thousandths of a standard deviation) below
    /// the mean of all eligible hosts, requiring at least `min_hosts`
    /// eligible hosts (each with at least `request_volume` requests in the
    /// interval) before running at all.
    fn run_success_rate_detection(&self, snapshot: &[(SocketAddr, u32, u32)]) {
        let eligible: Vec<(SocketAddr, f64)> = snapshot
            .iter()
            .filter_map(|&(addr, success, failure)| {
                let volume = success + failure;
                (volume >= self.config.success_rate_request_volume)
                    .then(|| (addr, f64::from(success) / f64::from(volume) * 100.0))
            })
            .collect();
        if eligible.len() < self.config.success_rate_min_hosts as usize {
            return;
        }

        let mean: f64 = eligible.iter().map(|&(_, rate)| rate).sum::<f64>() / eligible.len() as f64;
        let variance: f64 = eligible
            .iter()
            .map(|&(_, rate)| (rate - mean).powi(2))
            .sum::<f64>()
            / eligible.len() as f64;
        let stdev = variance.sqrt();
        let threshold = mean - (f64::from(self.config.success_rate_stdev_factor) / 1000.0) * stdev;

        for &(addr, rate) in &eligible {
            if rate < threshold {
                self.attempt_eject(
                    addr,
                    EjectionCause::SuccessRate,
                    self.config.enforcing_success_rate,
                );
            }
        }
    }

    /// S6 failure-percentage detection: eject hosts whose interval failure
    /// rate is at or above `failure_percentage_threshold`, requiring at
    /// least `failure_percentage_min_hosts` eligible hosts (each with at
    /// least `failure_percentage_request_volume` requests).
    fn run_failure_percentage_detection(&self, snapshot: &[(SocketAddr, u32, u32)]) {
        let eligible: Vec<(SocketAddr, u32)> = snapshot
            .iter()
            .filter_map(|&(addr, success, failure)| {
                let volume = success + failure;
                (volume >= self.config.failure_percentage_request_volume).then(|| {
                    let failure_percent = u64::from(failure) * 100 / u64::from(volume);
                    (addr, failure_percent as u32)
                })
            })
            .collect();
        if eligible.len() < self.config.failure_percentage_min_hosts as usize {
            return;
        }

        for &(addr, failure_percent) in &eligible {
            if failure_percent >= u32::from(self.config.failure_percentage_threshold) {
                self.attempt_eject(
                    addr,
                    EjectionCause::FailurePercentage,
                    self.config.enforcing_failure_percentage,
                );
            }
        }
    }

    /// The enforcement-percent dice roll, then (if it lands) the actual
    /// ejection attempt.
    fn attempt_eject(&self, addr: SocketAddr, cause: EjectionCause, enforcing_percent: u8) {
        let enforce = {
            let mut rng = self.rng.lock().unwrap();
            rng.gen_range(0..100u32) < u32::from(enforcing_percent)
        };
        if !enforce {
            self.emit_eject_event(addr, cause, false, None, 0);
            return;
        }
        self.eject(addr, cause);
    }

    /// Actually eject `addr`, subject to `max_ejection_percent` and
    /// "already ejected" short-circuits. Schedules the automatic un-eject
    /// timer on success.
    fn eject(&self, addr: SocketAddr, cause: EjectionCause) {
        let snapshot = self.host_set.load();
        let all_hosts = snapshot.all_hosts();
        let total = all_hosts.len() as u64;
        if total == 0 {
            return;
        }
        let Some(target) = all_hosts.iter().find(|h| h.address == addr) else {
            // Host isn't part of the set (removed by discovery, or never
            // was) -- nothing to eject.
            return;
        };
        if target.health_flags.failed_outlier_check {
            // Already ejected; not a new event.
            return;
        }

        let currently_ejected = all_hosts
            .iter()
            .filter(|h| h.health_flags.failed_outlier_check)
            .count() as u64;
        let allowed = (total * u64::from(self.config.max_ejection_percent)) / 100;
        let allowed = if self.config.always_eject_one_host {
            allowed.max(1)
        } else {
            allowed
        };
        if currently_ejected >= allowed {
            // Detection fired, but the cluster-wide cap blocks enforcement.
            // The consecutive counter that got us here was already reset in
            // `report_result` (or, for the statistical detectors, there's no
            // consecutive counter to reset) -- see the module doc for why a
            // crossing always resets regardless of enforcement outcome.
            self.emit_eject_event(addr, cause, false, None, 0);
            return;
        }

        let ejection_count = {
            let mut states = self.states.lock().unwrap();
            let state = states.entry(addr).or_default();
            state.ejection_count += 1;
            state.ejection_count
        };
        let duration = self.ejection_duration(ejection_count);
        Self::set_outlier_flag(&self.host_set, addr, true);
        self.emit_eject_event(addr, cause, true, Some(duration), ejection_count);
        self.schedule_uneject(addr, duration);
    }

    /// `base_ejection_time * ejection_count`, capped at
    /// `max(max_ejection_time, base_ejection_time)` (S6: growth per
    /// consecutive ejection, capped).
    fn ejection_duration(&self, ejection_count: u32) -> Duration {
        let base = self.config.base_ejection_time;
        let cap = self.config.max_ejection_time.max(base);
        base.saturating_mul(ejection_count.max(1)).min(cap)
    }

    /// Detached un-eject timer. Deliberately does not need `Arc<Self>` --
    /// only clones of `host_set`/`sink`/`cluster_name` cross into the
    /// spawned task, so `report_result`/`eject` can stay plain `&self`
    /// methods (matching the router-facing API shape the router expects) even
    /// though ejection itself needs a background timer.
    fn schedule_uneject(&self, addr: SocketAddr, duration: Duration) {
        let host_set = Arc::clone(&self.host_set);
        let sink = Arc::clone(&self.sink);
        let cluster_name = self.cluster_name.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(duration).await;
            if Self::set_outlier_flag(&host_set, addr, false) {
                Self::emit_uneject_event_static(
                    &cluster_name,
                    sink.as_ref(),
                    addr,
                    UnejectReason::EjectionExpired,
                );
            }
        });
        #[cfg(test)]
        self.uneject_handles.lock().unwrap().push(handle);
        #[cfg(not(test))]
        drop(handle);
    }

    /// Toggle one host's `failed_outlier_check` bit, preserving
    /// `failed_active_hc` and `active_requests` untouched -- same discipline
    /// as `health_check::apply_health_transition`, and a free-standing
    /// associated function (not `&self`) so both instance methods and the
    /// detached `schedule_uneject` task above can share it.
    ///
    /// Returns whether the flag actually changed (a no-op toggle -- e.g.
    /// un-ejecting an already-healthy host -- returns `false` so callers
    /// know not to emit a redundant event).
    fn set_outlier_flag(host_set: &ArcSwap<HostSet>, addr: SocketAddr, ejected: bool) -> bool {
        // Rust note: `rcu`, not `load()`/`store()` -- see
        // `health_check::apply_health_transition`'s Rust note for the full
        // lost-update argument. The interval sweep, the immediate
        // consecutive-error path, and the un-eject timers can all publish to
        // this same `ArcSwap` concurrently, so a plain read-modify-write
        // would silently drop concurrent transitions on other hosts.
        //
        // `changed` is an `AtomicBool` (not a plain `bool`) captured by
        // reference into the closure: `rcu` may invoke the closure more than
        // once if it loses the compare-and-swap race, and a `Fn` closure
        // can't capture a plain `&mut bool`. Only the matching host's branch
        // ever touches it, so a retried invocation just overwrites it with
        // the (same) correct answer for that retry's snapshot.
        let changed = std::sync::atomic::AtomicBool::new(false);
        host_set.rcu(|current| {
            let updated: Vec<Arc<Host>> = current
                .all_hosts()
                .into_iter()
                .map(|h| {
                    if h.address != addr {
                        return h;
                    }
                    if h.health_flags.failed_outlier_check == ejected {
                        changed.store(false, std::sync::atomic::Ordering::Relaxed);
                        return h;
                    }
                    changed.store(true, std::sync::atomic::Ordering::Relaxed);
                    Arc::new(Host {
                        address: h.address,
                        hostname: h.hostname.clone(),
                        metadata: h.metadata.clone(),
                        weight: h.weight,
                        priority: h.priority,
                        health_flags: HealthFlags {
                            failed_active_hc: h.health_flags.failed_active_hc,
                            failed_outlier_check: ejected,
                        },
                        active_requests: Arc::clone(&h.active_requests),
                    })
                })
                .collect();
            Arc::new(HostSet::from_hosts(updated))
        });
        changed.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn emit_eject_event(
        &self,
        addr: SocketAddr,
        cause: EjectionCause,
        enforced: bool,
        duration: Option<Duration>,
        num_ejections: u32,
    ) {
        self.sink.record(OutlierEvent {
            action: EjectAction::Eject,
            cluster_name: self.cluster_name.clone(),
            upstream_url: format!("tcp://{addr}"),
            timestamp: now_rfc3339(),
            num_ejections,
            enforced,
            detector_type: cause.detector_type(),
            eject_duration_ms: duration.map(|d| d.as_millis() as u64),
        });
    }

    fn emit_uneject_event(&self, addr: SocketAddr, reason: UnejectReason) {
        Self::emit_uneject_event_static(&self.cluster_name, self.sink.as_ref(), addr, reason);
    }

    fn emit_uneject_event_static(
        cluster_name: &str,
        sink: &dyn OutlierEventSink,
        addr: SocketAddr,
        reason: UnejectReason,
    ) {
        sink.record(OutlierEvent {
            action: EjectAction::Uneject,
            cluster_name: cluster_name.to_string(),
            upstream_url: format!("tcp://{addr}"),
            timestamp: now_rfc3339(),
            num_ejections: 0,
            enforced: true,
            detector_type: reason.detector_type(),
            eject_duration_ms: None,
        });
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_balancer::{HostPicker, RoundRobinLb};
    use crate::LoadBalancerContext;
    use std::net::{IpAddr, Ipv4Addr};

    /// The IR duplicates every S6 default because `proxy-config` cannot
    /// depend on `proxy-cluster` (the dependency runs the other way). This
    /// crate can see both, so it is the only place that can prove the two
    /// independent copies agree -- and that the IR->config `From` mapping
    /// wires each field to its namesake. Without this, a default changed on
    /// one side alone would silently give a config-built detector different
    /// behavior from a `Default`-built one.
    #[test]
    fn ir_defaults_match_runtime_defaults() {
        let from_ir =
            OutlierDetectionConfig::from(&proxy_config::ir::OutlierDetectionIR::default());
        assert_eq!(from_ir, OutlierDetectionConfig::default());
    }

    fn addr(last: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)), 80)
    }

    fn host(last: u8) -> Arc<Host> {
        Arc::new(Host {
            address: addr(last),
            hostname: None,
            metadata: Default::default(),
            weight: 1,
            priority: 0,
            health_flags: HealthFlags::default(),
            active_requests: Default::default(),
        })
    }

    #[test]
    fn ejection_rebuild_shares_the_in_flight_counter() {
        let host_set = ArcSwap::from_pointee(HostSet::from_hosts(vec![host(1)]));
        let guard = host_set.load().all_hosts()[0].begin_request();

        assert!(OutlierDetector::set_outlier_flag(&host_set, addr(1), true));
        let rebuilt = host_set.load().all_hosts()[0].clone();
        assert!(
            !rebuilt.is_healthy(),
            "the ejection really rebuilt the host"
        );
        assert_eq!(rebuilt.active_request_count(), 1);

        drop(guard);
        assert_eq!(rebuilt.active_request_count(), 0, "not stuck at 1");
    }

    /// Captures every event emitted, for assertion.
    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<OutlierEvent>>,
    }

    impl OutlierEventSink for CapturingSink {
        fn record(&self, event: OutlierEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn detector(
        hosts: Vec<Arc<Host>>,
        config: OutlierDetectionConfig,
    ) -> (
        Arc<OutlierDetector>,
        Arc<ArcSwap<HostSet>>,
        Arc<CapturingSink>,
    ) {
        let host_set = Arc::new(ArcSwap::from_pointee(HostSet::from_hosts(hosts)));
        let sink = Arc::new(CapturingSink::default());
        let engine = OutlierDetector::with_seed(
            config,
            "test-cluster",
            Arc::clone(&host_set),
            sink.clone(),
            1,
        );
        (engine, host_set, sink)
    }

    fn is_ejected(host_set: &ArcSwap<HostSet>, target: SocketAddr) -> bool {
        host_set
            .load()
            .all_hosts()
            .iter()
            .find(|h| h.address == target)
            .expect("host present")
            .health_flags
            .failed_outlier_check
    }

    /// Most tests below use a 2-host cluster and want to isolate the
    /// consecutive/statistical detectors from `max_ejection_percent`'s cap
    /// (which its own dedicated test below exercises): S6's default 10% over
    /// 2 hosts rounds down to `allowed = 0`, i.e. *no* ejection would ever
    /// be enforced. Effectively-uncapped is the right default everywhere
    /// else in this file.
    fn config_without_ejection_cap() -> OutlierDetectionConfig {
        OutlierDetectionConfig {
            max_ejection_percent: 100,
            ..OutlierDetectionConfig::default()
        }
    }

    // ---------------------------------------------------- consecutive 5xx --

    #[tokio::test]
    async fn five_consecutive_5xx_ejects_the_host() {
        let a = addr(1);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
    }

    #[test]
    fn four_consecutive_5xx_does_not_eject() {
        let a = addr(1);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());
        for _ in 0..4 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(!is_ejected(&host_set, a));
    }

    #[test]
    fn a_success_resets_the_consecutive_5xx_run() {
        let a = addr(1);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());
        for _ in 0..4 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        engine.report_result(a, RequestResult::Success);
        for _ in 0..4 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(!is_ejected(&host_set, a));
    }

    // ------------------------------------------------------- ejection TTL --

    #[tokio::test(start_paused = true)]
    async fn ejection_expires_after_base_ejection_time_and_the_host_rejoins_the_lb() {
        let a = addr(1);
        let b = addr(2);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));

        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let ctx = LoadBalancerContext::default();
        // Only `b` is healthy while `a` is ejected.
        for _ in 0..10 {
            assert_eq!(picker.pick(&host_set.load(), &ctx).unwrap().address, b);
        }

        tokio::time::advance(Duration::from_secs(30) + Duration::from_millis(1)).await;
        engine.await_pending_unejects().await;

        assert!(!is_ejected(&host_set, a));
    }

    // ------------------------------------------- ejection-time growth --

    #[tokio::test(start_paused = true)]
    async fn ejection_duration_grows_with_each_consecutive_ejection_and_caps() {
        let a = addr(1);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());

        // 1st ejection: 30s.
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
        tokio::time::advance(Duration::from_secs(30) + Duration::from_millis(1)).await;
        engine.await_pending_unejects().await;
        assert!(!is_ejected(&host_set, a));

        // 2nd ejection: 60s -- must still be ejected at 30s + eps, cleared by 60s + eps.
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
        tokio::time::advance(Duration::from_secs(30)).await;
        assert!(
            is_ejected(&host_set, a),
            "2nd ejection must last 60s, not 30s"
        );
        tokio::time::advance(Duration::from_secs(30) + Duration::from_millis(1)).await;
        engine.await_pending_unejects().await;
        assert!(!is_ejected(&host_set, a));

        // 3rd ejection: 90s.
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(
            is_ejected(&host_set, a),
            "3rd ejection must last 90s, not 60s"
        );
        tokio::time::advance(Duration::from_secs(30) + Duration::from_millis(1)).await;
        engine.await_pending_unejects().await;
        assert!(!is_ejected(&host_set, a));
    }

    #[tokio::test(start_paused = true)]
    async fn ejection_duration_is_capped_at_max_ejection_time() {
        let a = addr(1);
        let config = OutlierDetectionConfig {
            base_ejection_time: Duration::from_secs(100),
            max_ejection_time: Duration::from_secs(250),
            ..config_without_ejection_cap()
        };
        let (engine, host_set, _sink) = detector(vec![host(1), host(2)], config);

        // 1st: 100s.
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
        tokio::time::advance(Duration::from_secs(100) + Duration::from_millis(1)).await;
        engine.await_pending_unejects().await;
        assert!(!is_ejected(&host_set, a));

        // 2nd: would be 200s (still under cap).
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
        tokio::time::advance(Duration::from_secs(200) + Duration::from_millis(1)).await;
        engine.await_pending_unejects().await;
        assert!(!is_ejected(&host_set, a));

        // 3rd: would be 300s uncapped, but max_ejection_time=250s caps it --
        // still ejected at 249s, cleared just past 250s.
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
        tokio::time::advance(Duration::from_secs(249)).await;
        assert!(
            is_ejected(&host_set, a),
            "must still be ejected before the 250s cap is reached"
        );
        tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
        engine.await_pending_unejects().await;
        assert!(
            !is_ejected(&host_set, a),
            "3rd ejection must be capped at max_ejection_time (250s), not the uncapped 300s"
        );
    }

    // --------------------------------- gateway failure, 0% enforcement --

    /// Envoy behaviour (`DetectorImpl::putHttpResponseCode`): a gateway
    /// failure bumps *both* the consecutive-5xx and
    /// consecutive-gateway-failure counters, so with S6 defaults (both
    /// thresholds 5, `enforcing_consecutive_5xx` 100%,
    /// `enforcing_consecutive_gateway_failure` 0%) five consecutive gateway
    /// failures DO eject -- via the 5xx detector, not the gateway detector.
    /// See the module doc for the full reasoning.
    #[tokio::test]
    async fn five_consecutive_gateway_failures_eject_via_the_5xx_detector() {
        let a = addr(1);
        let (engine, host_set, sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());
        for _ in 0..5 {
            engine.report_result(a, RequestResult::GatewayFailure);
        }
        assert!(
            is_ejected(&host_set, a),
            "a gateway failure also bumps the consecutive-5xx counter, which \
             is enforced 100% by default -- five in a row must eject"
        );

        let events = sink.events.lock().unwrap();
        assert!(
            events.iter().any(|e| matches!(e.action, EjectAction::Eject)
                && e.enforced
                && e.detector_type == "5XX"),
            "the enforced ejection must be attributed to the 5xx detector, \
             which is the one that actually enforced it"
        );
        assert!(
            !events.iter().any(|e| matches!(e.action, EjectAction::Eject)
                && e.enforced
                && e.detector_type == "GATEWAY_FAILURE"),
            "the gateway-failure detector must not be credited with an \
             enforced ejection at its default 0% enforcement"
        );
    }

    /// Isolates the gateway detector by making `consecutive_5xx`
    /// unreachable (100, but only 5 requests are fed): only the gateway
    /// detector can fire, and at its default 0% enforcement it must not
    /// eject. This is what `enforcing_consecutive_gateway_failure = 0`
    /// actually guarantees -- not that gateway failures never eject at all
    /// (they do, via the 5xx detector; see the sibling test).
    #[test]
    fn gateway_failure_detector_alone_does_not_eject_at_zero_enforcement() {
        let a = addr(1);
        let config = OutlierDetectionConfig {
            consecutive_5xx: 100,
            ..config_without_ejection_cap()
        };
        let (engine, host_set, sink) = detector(vec![host(1), host(2)], config);
        for _ in 0..5 {
            engine.report_result(a, RequestResult::GatewayFailure);
        }
        assert!(
            !is_ejected(&host_set, a),
            "enforcing_consecutive_gateway_failure defaults to 0% -- must count without ejecting"
        );
        // The gateway detector still fired (and logged), just wasn't enforced.
        let events = sink.events.lock().unwrap();
        assert!(events
            .iter()
            .any(|e| e.detector_type == "GATEWAY_FAILURE" && !e.enforced));
    }

    // ----------------------------------------------- max_ejection_percent --

    #[tokio::test]
    async fn max_ejection_percent_caps_simultaneous_ejections() {
        let hosts: Vec<Arc<Host>> = (1..=10).map(host).collect();
        let (engine, host_set, _sink) = detector(hosts, OutlierDetectionConfig::default());

        // 10 hosts, default 10% -> only 1 may be ejected at once.
        for _ in 0..5 {
            engine.report_result(addr(1), RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, addr(1)));

        for _ in 0..5 {
            engine.report_result(addr(2), RequestResult::Http5xx);
        }
        assert!(
            !is_ejected(&host_set, addr(2)),
            "a 2nd simultaneous ejection must be blocked by max_ejection_percent=10% over 10 hosts"
        );
    }

    // --------------------------------------- success-rate volume gating --

    /// Feeds `pattern` repeated `repeats` times, alternating success/failure
    /// so the *immediate* consecutive-5xx detector (threshold 5, S6 default)
    /// never fires and confounds these tests -- only the interval-driven
    /// success-rate/failure-percentage detectors should be under test here.
    fn feed_pattern(
        engine: &OutlierDetector,
        target: SocketAddr,
        pattern: &[RequestResult],
        repeats: usize,
    ) {
        for _ in 0..repeats {
            for &result in pattern {
                engine.report_result(target, result);
            }
        }
    }

    #[tokio::test]
    async fn success_rate_detection_respects_min_hosts_and_request_volume() {
        // Only 3 hosts (< min_hosts=5) each well past request_volume -- one
        // host clearly failing most requests (in a S,F,F,F,F pattern so the
        // consecutive-5xx detector never trips), the rest clean. Must not
        // eject: not enough eligible hosts.
        let hosts: Vec<Arc<Host>> = (1..=3).map(host).collect();
        let (engine, host_set, _sink) = detector(hosts, config_without_ejection_cap());
        feed_pattern(
            &engine,
            addr(1),
            &[
                RequestResult::Success,
                RequestResult::Http5xx,
                RequestResult::Http5xx,
                RequestResult::Http5xx,
                RequestResult::Http5xx,
            ],
            20,
        );
        for h in 2..=3 {
            feed_pattern(&engine, addr(h), &[RequestResult::Success], 100);
        }
        engine.run_interval_tick();
        assert!(
            !is_ejected(&host_set, addr(1)),
            "fewer than success_rate_min_hosts eligible hosts -> detector must not run"
        );

        // Now 5 hosts but below request_volume=100 each -- still must not
        // eject.
        let hosts: Vec<Arc<Host>> = (1..=5).map(host).collect();
        let (engine, host_set, _sink) = detector(hosts, config_without_ejection_cap());
        feed_pattern(
            &engine,
            addr(1),
            &[
                RequestResult::Success,
                RequestResult::Http5xx,
                RequestResult::Http5xx,
                RequestResult::Http5xx,
                RequestResult::Http5xx,
            ],
            10,
        );
        for h in 2..=5 {
            feed_pattern(&engine, addr(h), &[RequestResult::Success], 50);
        }
        engine.run_interval_tick();
        assert!(
            !is_ejected(&host_set, addr(1)),
            "hosts below request_volume=100 are not eligible -> detector must not run"
        );
    }

    #[tokio::test]
    async fn success_rate_detection_ejects_a_clear_outlier_once_thresholds_are_met() {
        // 5 hosts (== min_hosts), all with >= 100 requests. Host 1 succeeds
        // only 1 request in every 5 (20%, in a S,F,F,F,F pattern so the
        // consecutive-5xx detector never trips); hosts 2-5 are 100% --  a
        // wide enough gap to clear a 1.9-sigma bar even with the low-variance
        // peer group.
        let hosts: Vec<Arc<Host>> = (1..=5).map(host).collect();
        let (engine, host_set, _sink) = detector(hosts, config_without_ejection_cap());
        feed_pattern(
            &engine,
            addr(1),
            &[
                RequestResult::Success,
                RequestResult::LocalOriginFailure,
                RequestResult::LocalOriginFailure,
                RequestResult::LocalOriginFailure,
                RequestResult::LocalOriginFailure,
            ],
            20,
        );
        for h in 2..=5 {
            feed_pattern(&engine, addr(h), &[RequestResult::Success], 100);
        }
        engine.run_interval_tick();
        assert!(is_ejected(&host_set, addr(1)));
    }

    // ----------------------------------- un-eject on passing active HC --

    #[tokio::test]
    async fn uneject_on_passing_active_health_check() {
        let a = addr(1);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());
        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        assert!(is_ejected(&host_set, a));
        engine.on_active_health_check_pass(a);
        assert!(!is_ejected(&host_set, a));
    }

    // ------------------------------------- excluded from / rejoins the LB --

    #[tokio::test]
    async fn an_ejected_host_is_excluded_from_lb_selection_and_clearing_returns_it() {
        let a = addr(1);
        let b = addr(2);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());
        let picker = HostPicker::with_seed(Box::new(RoundRobinLb::new()), 1);
        let ctx = LoadBalancerContext::default();

        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }
        for _ in 0..10 {
            assert_eq!(picker.pick(&host_set.load(), &ctx).unwrap().address, b);
        }

        engine.on_active_health_check_pass(a);
        let seen: std::collections::HashSet<_> = (0..20)
            .map(|_| picker.pick(&host_set.load(), &ctx).unwrap().address)
            .collect();
        assert!(
            seen.contains(&a),
            "clearing the ejection must return the host to the pool"
        );
    }

    // --------------------------------------------------- both flags at once --

    #[tokio::test]
    async fn both_health_flags_render_together_and_clearing_one_leaves_the_other() {
        let a = addr(1);
        let (engine, host_set, _sink) =
            detector(vec![host(1), host(2)], config_without_ejection_cap());

        // Fail active HC directly on the snapshot (no HealthCheckEngine
        // needed for this assertion -- we're testing HealthFlags rendering
        // and is_healthy(), not the active health check engine).
        host_set.rcu(|current| {
            let updated: Vec<Arc<Host>> = current
                .all_hosts()
                .into_iter()
                .map(|h| {
                    if h.address == a {
                        Arc::new(Host {
                            address: h.address,
                            hostname: h.hostname.clone(),
                            metadata: h.metadata.clone(),
                            weight: h.weight,
                            priority: h.priority,
                            health_flags: HealthFlags {
                                failed_active_hc: true,
                                failed_outlier_check: h.health_flags.failed_outlier_check,
                            },
                            active_requests: Arc::clone(&h.active_requests),
                        })
                    } else {
                        h
                    }
                })
                .collect();
            Arc::new(HostSet::from_hosts(updated))
        });

        for _ in 0..5 {
            engine.report_result(a, RequestResult::Http5xx);
        }

        let flags = host_set
            .load()
            .all_hosts()
            .iter()
            .find(|h| h.address == a)
            .unwrap()
            .health_flags;
        assert!(!flags.is_healthy());
        assert_eq!(flags.to_string(), "/failed_active_hc/failed_outlier_check");

        // Clearing only the outlier flag leaves the host unhealthy.
        engine.on_active_health_check_pass(a);
        let flags = host_set
            .load()
            .all_hosts()
            .iter()
            .find(|h| h.address == a)
            .unwrap()
            .health_flags;
        assert!(!flags.is_healthy());
        assert_eq!(flags.to_string(), "/failed_active_hc");
    }
}
