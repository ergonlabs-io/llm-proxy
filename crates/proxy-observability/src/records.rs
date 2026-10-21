//! End-user telemetry metadata contracts.
//!
//! These types are owned by the observability boundary so the data plane can
//! submit an owned, bounded event without knowing about ClickHouse, object
//! storage, or a remote collector. The sink is deliberately nonblocking: an
//! unavailable collector must never delay forwarding or alter accounting.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub const SCHEMA_VERSION: u16 = 1;
pub const MAX_RECORD_BYTES: usize = 64 * 1024;
pub const MAX_ATTEMPTS: u16 = 64;

/// Longest tenant or key id a record may carry. Ids are trusted ownership
/// identifiers: the capture path rejects longer ones and the non-capture path
/// would truncate them at `bounded_field`'s 512 bytes, merging two long ids
/// that share a prefix. Minting and config load enforce this bound so neither
/// outcome is reachable.
pub const MAX_PRINCIPAL_ID_BYTES: usize = 128;

/// The tenant id on the record of a request that carried no tenant
/// (AGENTS.md "Policy Domains"): a deployment without auth, or a credential
/// that names none.
pub const DEFAULT_TENANT: &str = "default";

/// The tenant id on the record of a request the auth filter refused, so no
/// identity was established (ADR-0011 decision 3).
pub const UNAUTHENTICATED_TENANT: &str = "unauthenticated";

/// Tenant ids a record gives a meaning of its own. No tenant may be created
/// or keyed under one, or its records could not be told from those.
pub const RESERVED_TENANT_IDS: [&str; 2] = [DEFAULT_TENANT, UNAUTHENTICATED_TENANT];

/// Copy bounded metadata into independent storage. Caller-controlled paths
/// and models cannot pin an arbitrarily large String allocation in a queue.
pub fn bounded_field(value: &str) -> String {
    let mut end = value.len().min(512);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    Complete,
    LocalReply,
    UpstreamError,
    DownstreamDisconnect,
    Cancelled,
    Timeout,
    Rejected,
    Unknown,
}

/// Whose provider credential an attempt was sent with (ADR-0007).
///
/// Records carry it as an optional field under schema version 1. Three shapes
/// occur on the wire:
///
/// - Field absent: a record from a build before tenant credentials. It was
///   sent on the operator's credential, so read it as `Platform`.
/// - Present with a value: the credential the attempt was sent with.
/// - Present and `null`: no attempt reached the credential step, so nothing
///   was sent upstream and there is no cost.
///
/// The Rust field is an `Option`, so absent and `null` both decode to `None`.
/// Readers that must tell them apart need the raw JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSource {
    /// The cluster's own credential, configured by the operator.
    Platform,
    /// The authenticated tenant's stored credential for the cluster's provider.
    Tenant,
}

impl CredentialSource {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialSource::Platform => "platform",
            CredentialSource::Tenant => "tenant",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UsageCompleteness {
    Complete,
    Partial,
}

/// JSON kept exactly as a provider sent it, embedded in a record as a JSON
/// value (not a quoted string).
///
/// Rust note: `RawValue` is serde_json's "unparsed JSON" type. It serializes
/// as the original text, so number formatting and key order survive. It only
/// deserializes from a JSON text (`from_slice`/`from_str`), not from a
/// `serde_json::Value`, which is how every record consumer reads records.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RawJson(Box<serde_json::value::RawValue>);

impl RawJson {
    /// Wrap `text`, which must be valid JSON; `None` otherwise.
    pub fn from_text(text: &str) -> Option<Self> {
        serde_json::value::RawValue::from_string(text.to_owned())
            .ok()
            .map(Self)
    }

    /// The JSON text.
    pub fn get(&self) -> &str {
        self.0.get()
    }
}

impl PartialEq for RawJson {
    fn eq(&self, other: &Self) -> bool {
        self.get() == other.get()
    }
}

impl Eq for RawJson {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub input_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub output_tokens: u64,
    pub completeness: UsageCompleteness,
    /// `provider` when every count is the provider's own figure, `estimate`
    /// when the proxy estimated any of them (see the two flags below).
    pub provenance: String,
    /// The input count was estimated from the request size. Added under
    /// schema version 1: absent in older records, read as `false`.
    #[serde(default)]
    pub input_estimated: bool,
    /// The output count was estimated from the streamed text. Same default.
    #[serde(default)]
    pub output_estimated: bool,
    // The fields below were added under schema version 1 (ADR-0010 decision
    // 6). Older records lack them and read as `None`; older readers ignore
    // them. A modality token count is a subset of `input_tokens` or
    // `output_tokens`, never added to a total, and is `Some` only when it
    // is above 0.
    /// Image tokens inside `input_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_image_tokens: Option<u64>,
    /// Image tokens inside `output_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_image_tokens: Option<u64>,
    /// Audio tokens inside `input_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_audio_tokens: Option<u64>,
    /// Audio tokens inside `output_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_audio_tokens: Option<u64>,
    /// Images the response returned. `None` when no image count was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub images: Option<u64>,
    /// The images' `size`, as the rate card matches it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_size: Option<String>,
    /// The images' `quality`, as the rate card matches it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_quality: Option<String>,
    /// Unicode characters in the request `input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_characters: Option<u64>,
    /// Audio duration the provider reported, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_milliseconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cost {
    pub amount: u64,
    pub unit: String,
    pub currency: String,
    pub rate_card_version: String,
    /// `list` for a rate-card price of provider-reported usage; `estimate`
    /// when the usage it prices was estimated (a stream that ended early).
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptRecord {
    pub schema_version: u16,
    pub event_id: String,
    pub request_id: String,
    pub attempt_id: String,
    pub attempt_index: u16,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub cluster: Option<String>,
    pub provider: Option<String>,
    pub upstream_model: Option<String>,
    /// The model the provider reported serving (response `model`), set on the
    /// selected attempt only. Often a dated snapshot of `upstream_model`.
    /// `null` when the response named none; absent in records from older builds.
    #[serde(default)]
    pub served_model: Option<String>,
    /// The provider's id for this attempt's response; selected attempt only.
    /// Added under schema version 1: absent in older records, `null` when the
    /// response named none.
    #[serde(default)]
    pub upstream_response_id: Option<String>,
    /// The provider's `usage` object exactly as sent, embedded as JSON;
    /// selected attempt only. Evidence, never read for cost.
    #[serde(default)]
    pub upstream_usage: Option<RawJson>,
    pub started_at: String,
    pub finished_at: String,
    pub duration_ms: u64,
    pub status: Option<u16>,
    pub termination: Termination,
    pub retry_reason: Option<String>,
    pub bytes_request: Option<u64>,
    pub bytes_response: u64,
    pub usage: Option<Usage>,
    pub cost: Option<Cost>,
    /// The endpoint class label (`chat_completions`, `image_generation`, ...).
    /// `Some` when the record has usage or the endpoint is not `unmetered`.
    /// Added under schema version 1: absent in older records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// What the rate-card entry that priced `usage` prices: `tokens`,
    /// `images`, `characters` or `audio_seconds`. `None` when nothing priced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_basis: Option<String>,
    /// `null` when the attempt never reached the credential step. Absent in
    /// records from a build before tenant credentials; see [`CredentialSource`].
    #[serde(default)]
    pub credential_source: Option<CredentialSource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRecord {
    pub schema_version: u16,
    pub event_id: String,
    pub request_id: String,
    pub instance_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub tenant_id: String,
    pub user_id: Option<String>,
    pub key_id: Option<String>,
    pub trace_id: Option<String>,
    pub routing_revision: Option<String>,
    pub policy_generation: Option<u64>,
    pub capture_policy_version: Option<String>,
    pub method: String,
    pub route: String,
    pub requested_model: Option<String>,
    /// The model alias a resolver chose when `requested_model` was a
    /// resolver trigger such as `auto`; `None` otherwise.
    #[serde(default)]
    pub resolved_model: Option<String>,
    pub selected_cluster: Option<String>,
    pub selected_provider: Option<String>,
    pub selected_model: Option<String>,
    /// The provider's id for the response that answered this request (the
    /// selected attempt's). Added under schema version 1: absent in older
    /// records, `null` when the response named none.
    #[serde(default)]
    pub upstream_response_id: Option<String>,
    /// The provider's `usage` object exactly as sent, embedded as a JSON
    /// value. Audit evidence: `cost` comes from the rate card, never from
    /// this. `null` when absent or over the size bound.
    #[serde(default)]
    pub upstream_usage: Option<RawJson>,
    pub status: Option<u16>,
    pub termination: Termination,
    pub error_category: Option<String>,
    pub response_flags: Vec<String>,
    pub duration_ms: u64,
    pub time_to_first_byte_ms: Option<u64>,
    pub bytes_request: u64,
    pub bytes_response: u64,
    pub usage: Option<Usage>,
    pub cost: Option<Cost>,
    /// The endpoint class label (`chat_completions`, `image_generation`, ...).
    /// `Some` when the record has usage or the endpoint is not `unmetered`.
    /// Added under schema version 1: absent in older records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// What the rate-card entry that priced `usage` prices: `tokens`,
    /// `images`, `characters` or `audio_seconds`. `None` when nothing priced it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub price_basis: Option<String>,
    /// Number of retained summaries (schema-v1 compatibility).
    pub attempt_count: u16,
    /// All physical dispatches, including summaries omitted at the retention limit.
    pub physical_attempt_count: u64,
    pub attempts: Vec<AttemptRecord>,
    pub attempts_truncated: bool,
    /// The selected (final) attempt's source; `None` when no attempt reached
    /// the credential step.
    #[serde(default)]
    pub credential_source: Option<CredentialSource>,
    /// This record's number within its `instance_id`, 1-based, stamped by the
    /// delivery path that writes it (ADR-0011 decision 2). A gap means a record
    /// numbered but not delivered. `None` until delivery stamps it; absent in
    /// records from older builds.
    #[serde(default)]
    pub record_seq: Option<u64>,
    /// Chargeback tags the request was attributed with: allow-listed key
    /// metadata and, when the operator enables it, the client's tag header
    /// (`crate::chargeback`). Added under schema version 1: absent in older
    /// records, read as empty.
    #[serde(default)]
    pub tags: crate::chargeback::ChargebackTags,
    /// The client address the request was attributed to, without a port:
    /// the TCP peer, or behind trusted hops the `x-forwarded-for` entry they
    /// vouch for (envoy-semantics S9). The same address `client-ip` limits
    /// key on. Added under schema version 1: absent in older records.
    #[serde(default)]
    pub client_address: Option<String>,
}

impl RequestRecord {
    pub fn retained_bytes(&self) -> usize {
        let mut total = std::mem::size_of::<Self>()
            + self.attempts.capacity() * std::mem::size_of::<AttemptRecord>()
            + self.tags.len() * 2 * std::mem::size_of::<String>();
        total =
            total.saturating_add(self.response_flags.capacity() * std::mem::size_of::<String>());
        let mut add = |value: &String| total = total.saturating_add(value.capacity());
        for value in [
            &self.event_id,
            &self.request_id,
            &self.instance_id,
            &self.started_at,
            &self.finished_at,
            &self.tenant_id,
            &self.method,
            &self.route,
        ] {
            add(value);
        }
        for value in [
            &self.user_id,
            &self.key_id,
            &self.trace_id,
            &self.routing_revision,
            &self.capture_policy_version,
            &self.requested_model,
            &self.resolved_model,
            &self.selected_cluster,
            &self.selected_provider,
            &self.selected_model,
            &self.upstream_response_id,
            &self.error_category,
            &self.client_address,
        ]
        .into_iter()
        .flatten()
        {
            add(value);
        }
        let mut raw_usage_bytes = self.upstream_usage.as_ref().map_or(0, |u| u.get().len());
        for flag in &self.response_flags {
            add(flag);
        }
        for (key, value) in &self.tags {
            add(key);
            add(value);
        }
        if let Some(usage) = &self.usage {
            add(&usage.provenance);
        }
        if let Some(cost) = &self.cost {
            for value in [
                &cost.unit,
                &cost.currency,
                &cost.rate_card_version,
                &cost.kind,
            ] {
                add(value);
            }
        }
        for attempt in &self.attempts {
            for value in [
                &attempt.event_id,
                &attempt.request_id,
                &attempt.attempt_id,
                &attempt.started_at,
                &attempt.finished_at,
            ] {
                add(value);
            }
            for value in [
                &attempt.trace_id,
                &attempt.span_id,
                &attempt.parent_span_id,
                &attempt.cluster,
                &attempt.provider,
                &attempt.upstream_model,
                &attempt.served_model,
                &attempt.upstream_response_id,
                &attempt.retry_reason,
            ]
            .into_iter()
            .flatten()
            {
                add(value);
            }
            raw_usage_bytes += attempt.upstream_usage.as_ref().map_or(0, |u| u.get().len());
            if let Some(usage) = &attempt.usage {
                add(&usage.provenance);
            }
            if let Some(cost) = &attempt.cost {
                for value in [
                    &cost.unit,
                    &cost.currency,
                    &cost.rate_card_version,
                    &cost.kind,
                ] {
                    add(value);
                }
            }
        }
        total.saturating_add(raw_usage_bytes)
    }
    pub fn validate(&self, max_attempts: u16) -> Result<(), &'static str> {
        if self.schema_version != SCHEMA_VERSION {
            return Err("unsupported schema_version");
        }
        if self.tenant_id.is_empty() {
            return Err("tenant_id must not be empty");
        }
        if self.attempt_count as usize != self.attempts.len() {
            return Err("attempt_count does not match attempts");
        }
        if self.physical_attempt_count < u64::from(self.attempt_count)
            || self.attempts_truncated
                != (self.physical_attempt_count > u64::from(self.attempt_count))
        {
            return Err("physical_attempt_count does not match truncation");
        }
        if self.attempt_count > max_attempts {
            return Err("attempt_count exceeds configured maximum");
        }
        if self.event_id.is_empty() || self.request_id.is_empty() {
            return Err("event_id and request_id are required");
        }
        Ok(())
    }
}

/// Version of the [`LedgerEntry`] shape, separate from [`SCHEMA_VERSION`]:
/// the ledger is the invoice source (ADR-0009) and changes on its own terms.
///
/// - 1: the shape ADR-0009 decision 3 describes.
/// - 2: adds `record.tags` (chargeback tags). Nothing else changes, so a
///   version-1 reader that ignores unknown fields still reads it, and an
///   entry written as version 1 reads here with no tags. Entries keep the
///   version they were written with; the spool may hold both after an upgrade.
pub const LEDGER_SCHEMA_VERSION: u16 = 2;

/// One billing-ledger entry: the terminal [`RequestRecord`] of a request that
/// was dialled to an upstream, plus what it was charged (ADR-0009 decision 3).
/// `record.event_id` is the deduplication key; `(instance_id, epoch, seq)`
/// lets a consumer see that no entry of an epoch is missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub schema_version: u16,
    /// The writing instance. Unique per writer, like the spend `node_id`.
    pub instance_id: String,
    /// Chosen once per process start.
    pub epoch: u64,
    /// Consecutive per `(instance_id, epoch)`, starting at 0, no gaps.
    pub seq: u64,
    /// The amount added to the spend counters when the spend filter charged
    /// this request, else the same function's price for its usage. 0 when
    /// there was no usage or no price. Never derived from `record.cost`,
    /// whose nanodollars sum to less than the charges (ADR-0009 Context).
    pub charged_micro_usd: u64,
    /// The spend counters the charge was added to, each with its budget
    /// period. Empty when no spend filter charged.
    pub charged_scopes: Vec<ChargedScope>,
    /// The rate-card version that priced `charged_micro_usd`; `None` when
    /// nothing priced it.
    pub rate_card_version: Option<String>,
    /// The control-plane policy the request was admitted under; the same
    /// value as `record.policy_generation`.
    pub policy_generation: Option<u64>,
    pub record: RequestRecord,
}

/// Which spend counter a charge was added to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargeScope {
    Tenant,
    /// The virtual key, which is also the user.
    Key,
}

/// One spend counter a charge was added to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChargedScope {
    pub scope: ChargeScope,
    pub id: String,
    /// The UTC budget period the charge fell in: `YYYY-MM-DD` or `YYYY-MM`.
    pub period: String,
}

/// What the terminal-record point adds to the record to make an entry; the
/// ledger writer adds the numbering (`crate::ledger`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LedgerCharge {
    pub charged_micro_usd: u64,
    pub charged_scopes: Vec<ChargedScope>,
    pub rate_card_version: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitResult {
    Accepted,
    Disabled,
    /// The bounded queue (or capture budget) is full. Nothing is wrong with
    /// the record itself.
    CapacityExceeded,
    /// The record alone exceeds the per-record retained-byte limit. Retrying
    /// can never succeed, so a biller must not read this as overload.
    Oversize,
    /// The record failed `RequestRecord::validate`: a producer bug, not load.
    Invalid,
    Closed,
}

pub trait RequestRecordSink: Send + Sync {
    fn submit(&self, record: RequestRecord) -> SubmitResult;
    fn max_attempts(&self) -> u16 {
        MAX_ATTEMPTS
    }
}

/// Monotonic metadata-lane delivery counters. These deliberately have no
/// tenant, request, or event dimensions, so capture overload cannot create an
/// unbounded metric series.
#[derive(Debug, Default)]
pub struct DropCounters {
    accepted: AtomicU64,
    capacity_exceeded: AtomicU64,
    oversize: AtomicU64,
    invalid: AtomicU64,
    closed: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DropCounterSnapshot {
    pub accepted: u64,
    pub capacity_exceeded: u64,
    pub oversize: u64,
    pub invalid: u64,
    pub closed: u64,
}

impl DropCounters {
    pub fn snapshot(&self) -> DropCounterSnapshot {
        DropCounterSnapshot {
            accepted: self.accepted.load(Ordering::Relaxed),
            capacity_exceeded: self.capacity_exceeded.load(Ordering::Relaxed),
            oversize: self.oversize.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            closed: self.closed.load(Ordering::Relaxed),
        }
    }

    fn record(&self, result: SubmitResult) {
        let counter = match result {
            SubmitResult::Accepted => &self.accepted,
            SubmitResult::CapacityExceeded => &self.capacity_exceeded,
            SubmitResult::Oversize => &self.oversize,
            SubmitResult::Invalid => &self.invalid,
            SubmitResult::Closed => &self.closed,
            SubmitResult::Disabled => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct BoundedRecordSink {
    tx: mpsc::Sender<RequestRecord>,
    counters: Arc<DropCounters>,
    max_attempts: u16,
    /// Optional process-level capture instrumentation. Keeping it optional
    /// preserves this sink's use as a pure bounded test/sidecar primitive;
    /// production installs it at metadata-delivery startup.
    delivery_stats: Option<crate::stats::MetadataDeliveryStats>,
}

impl BoundedRecordSink {
    pub fn new(capacity: usize) -> (Self, mpsc::Receiver<RequestRecord>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Self {
                tx,
                counters: Arc::new(DropCounters::default()),
                max_attempts: MAX_ATTEMPTS,
                delivery_stats: None,
            },
            rx,
        )
    }

    pub fn counters(&self) -> Arc<DropCounters> {
        self.counters.clone()
    }
    pub fn with_max_attempts(mut self, maximum: u16) -> Self {
        self.max_attempts = maximum.clamp(1, MAX_ATTEMPTS);
        self
    }

    /// Attach the pre-resolved, finite operational series for the production
    /// metadata lane. This cannot affect `submit`'s nonblocking outcome: the
    /// registry update is an in-memory atomic increment after that outcome is
    /// known, never collector I/O.
    pub fn with_delivery_stats(mut self, stats: crate::stats::MetadataDeliveryStats) -> Self {
        self.delivery_stats = Some(stats);
        self
    }
}

impl RequestRecordSink for BoundedRecordSink {
    fn submit(&self, record: RequestRecord) -> SubmitResult {
        let result = if record.retained_bytes() > MAX_RECORD_BYTES {
            SubmitResult::Oversize
        } else if record.validate(self.max_attempts).is_err() {
            SubmitResult::Invalid
        } else {
            match self.tx.try_reserve() {
                Ok(permit) => {
                    // Publish occupancy before the receiver can see the record.
                    if let Some(stats) = &self.delivery_stats {
                        stats.record_enqueued();
                    }
                    permit.send(record);
                    SubmitResult::Accepted
                }
                Err(mpsc::error::TrySendError::Full(_)) => SubmitResult::CapacityExceeded,
                Err(mpsc::error::TrySendError::Closed(_)) => SubmitResult::Closed,
            }
        };
        self.counters.record(result);
        if let Some(stats) = &self.delivery_stats {
            stats.record_submission(result);
        }
        result
    }
    fn max_attempts(&self) -> u16 {
        self.max_attempts
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn record() -> RequestRecord {
        crate::ledger::testing::record("e")
    }

    /// Provider usage text survives a record's JSON round trip byte for byte
    /// and is embedded as a JSON object, not a quoted string. The number
    /// `0.000012340` would not survive a pass through `serde_json::Value`.
    #[test]
    fn upstream_usage_is_embedded_raw_and_round_trips() {
        let raw = r#"{"cost":0.000012340,"prompt_tokens":7,"nested":{"b":1,"a":2}}"#;
        let mut r = record();
        r.upstream_response_id = Some("chatcmpl-abc".into());
        r.upstream_usage = RawJson::from_text(raw);
        let bytes = serde_json::to_vec(&r).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            text.contains(&format!(r#""upstream_usage":{raw}"#)),
            "{text}"
        );
        let back: RequestRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.upstream_usage.unwrap().get(), raw);
        // The same record as a `Value` has the usage as an object.
        let value = serde_json::to_value(&r).unwrap();
        assert_eq!(value["upstream_usage"]["prompt_tokens"], 7);
        assert_eq!(value["upstream_response_id"], "chatcmpl-abc");
    }

    /// Records from before these fields exist still parse, with both unset.
    #[test]
    fn record_without_upstream_fields_still_parses() {
        let mut value = serde_json::to_value(record()).unwrap();
        let object = value.as_object_mut().unwrap();
        object.remove("upstream_response_id");
        object.remove("upstream_usage");
        let back: RequestRecord =
            serde_json::from_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(back.upstream_response_id, None);
        assert_eq!(back.upstream_usage, None);
    }

    fn meter_usage() -> Usage {
        Usage {
            input_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            output_tokens: 0,
            completeness: UsageCompleteness::Complete,
            provenance: "provider".into(),
            input_estimated: false,
            output_estimated: false,
            input_image_tokens: None,
            output_image_tokens: None,
            input_audio_tokens: None,
            output_audio_tokens: None,
            images: Some(2),
            image_size: Some("1024x1024".into()),
            image_quality: None,
            input_characters: None,
            audio_milliseconds: None,
        }
    }

    /// New fields round-trip; unset ones are omitted from the JSON; a record
    /// written before they existed still parses with them unset.
    #[test]
    fn media_fields_round_trip_are_omitted_when_none_and_default_on_read() {
        let mut r = record();
        r.usage = Some(meter_usage());
        r.endpoint = Some("image_generation".into());
        r.price_basis = Some("images".into());
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: RequestRecord = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back, r);

        let value = serde_json::to_value(&r).unwrap();
        let usage = value["usage"].as_object().unwrap();
        assert_eq!(usage["images"], 2);
        assert_eq!(usage["image_size"], "1024x1024");
        for absent in [
            "input_image_tokens",
            "output_image_tokens",
            "input_audio_tokens",
            "output_audio_tokens",
            "image_quality",
            "input_characters",
            "audio_milliseconds",
        ] {
            assert!(!usage.contains_key(absent), "{absent} should be omitted");
        }
        assert_eq!(value["endpoint"], "image_generation");
        assert_eq!(value["price_basis"], "images");

        // A plain record omits endpoint and price_basis entirely.
        let plain = serde_json::to_value(record()).unwrap();
        assert!(!plain.as_object().unwrap().contains_key("endpoint"));
        assert!(!plain.as_object().unwrap().contains_key("price_basis"));

        // An old record: strip every new field and parse it.
        let mut old = value;
        let object = old.as_object_mut().unwrap();
        object.remove("endpoint");
        object.remove("price_basis");
        let usage = object.get_mut("usage").unwrap().as_object_mut().unwrap();
        usage.remove("images");
        usage.remove("image_size");
        let back: RequestRecord = serde_json::from_value(old).unwrap();
        assert_eq!(back.endpoint, None);
        assert_eq!(back.price_basis, None);
        let usage = back.usage.unwrap();
        assert_eq!(usage.images, None);
        assert_eq!(usage.image_size, None);
    }

    #[test]
    fn retained_bytes_counts_the_raw_usage_text() {
        let mut r = record();
        let base = r.retained_bytes();
        r.upstream_usage = RawJson::from_text(&format!(r#"{{"k":"{}"}}"#, "x".repeat(1000)));
        assert!(r.retained_bytes() >= base + 1000);
    }

    #[test]
    fn schema_serializes_flags_and_physical_attempt_count() {
        let mut r = record();
        r.response_flags = vec!["UF".into(), "URX".into()];
        r.physical_attempt_count = 2;
        r.attempts_truncated = true;
        assert!(r.validate(1).is_ok());
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["response_flags"], serde_json::json!(["UF", "URX"]));
        assert_eq!(json["physical_attempt_count"], 2);
        assert_eq!(json["attempt_count"], 0);
        assert!(json["user_id"].is_null());
        assert!(json["selected_provider"].is_null());
        r.attempts_truncated = false;
        assert!(r.validate(1).is_err());
    }

    #[test]
    fn flag_allocations_are_included_in_the_queue_budget() {
        let (sink, _) = BoundedRecordSink::new(1);
        let mut r = record();
        r.response_flags = Vec::with_capacity(MAX_RECORD_BYTES);
        assert_eq!(sink.submit(r), SubmitResult::Oversize);
    }

    #[test]
    fn record_rejects_mismatched_attempt_count() {
        let mut r = record();
        r.attempt_count = 1;
        assert_eq!(r.validate(3), Err("attempt_count does not match attempts"));
    }
    #[test]
    fn metadata_bound_counts_retained_allocation_not_just_text_length() {
        let (sink, mut rx) = BoundedRecordSink::new(1);
        let mut record = record();
        record.route = String::with_capacity(MAX_RECORD_BYTES + 1);
        record.route.push('/');
        assert_eq!(sink.submit(record), SubmitResult::Oversize);
        assert!(rx.try_recv().is_err());
        // Only the oversize reason moves; a biller must not read this as a full queue.
        assert_eq!(
            sink.counters().snapshot(),
            DropCounterSnapshot {
                oversize: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn invalid_record_counts_as_invalid_not_capacity() {
        let (sink, mut rx) = BoundedRecordSink::new(1);
        let mut bad = record();
        bad.event_id.clear();
        assert_eq!(sink.submit(bad), SubmitResult::Invalid);
        assert!(rx.try_recv().is_err());
        assert_eq!(
            sink.counters().snapshot(),
            DropCounterSnapshot {
                invalid: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn bounded_sink_never_waits_for_capacity() {
        let (sink, mut rx) = BoundedRecordSink::new(1);
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        assert_eq!(sink.submit(record()), SubmitResult::CapacityExceeded);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn concurrent_dequeue_never_observes_unsigned_depth_underflow() {
        let control = crate::stats::StatsControl::new(1);
        let registry = control.registry();
        let stats = crate::stats::MetadataDeliveryStats::resolve(&control);
        let (sink, mut receiver) = BoundedRecordSink::new(1);
        let sink = sink.with_delivery_stats(stats.clone());
        let depth = control.resolve(&crate::stats::instruments::METADATA_QUEUE_DEPTH, &[]);
        let observer_registry = registry.clone();
        let receiver_thread = std::thread::spawn(move || {
            while receiver.blocking_recv().is_some() {
                stats.record_dequeued();
                assert!(observer_registry.value(depth) <= 2);
            }
        });
        for _ in 0..10_000 {
            sink.submit(record());
            assert!(registry.value(depth) <= 2);
        }
        drop(sink);
        receiver_thread.join().unwrap();
        assert_eq!(registry.value(depth), 0);
    }

    #[test]
    fn bounded_sink_counts_each_delivery_outcome() {
        let (sink, mut rx) = BoundedRecordSink::new(1);
        let counters = sink.counters();
        assert_eq!(sink.submit(record()), SubmitResult::Accepted);
        assert_eq!(sink.submit(record()), SubmitResult::CapacityExceeded);
        let _ = rx.try_recv();
        drop(rx);
        assert_eq!(sink.submit(record()), SubmitResult::Closed);
        assert_eq!(
            counters.snapshot(),
            DropCounterSnapshot {
                accepted: 1,
                capacity_exceeded: 1,
                closed: 1,
                ..Default::default()
            }
        );
    }
}
