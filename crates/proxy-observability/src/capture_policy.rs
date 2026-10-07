//! Plain capture policy contracts shared by configuration and the runtime.
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataCapturePolicy {
    pub max_attempts: u16,
    pub max_record_retained_bytes: usize,
    pub max_encoded_record_bytes: usize,
}

impl Default for MetadataCapturePolicy {
    fn default() -> Self {
        Self {
            max_attempts: 8,
            max_record_retained_bytes: 65_536,
            max_encoded_record_bytes: 524_288,
        }
    }
}

impl MetadataCapturePolicy {
    /// Content identity includes every disclosure/retention setting, not the destination.
    pub fn effective_version(&self, label: &str) -> String {
        let normalized = format!(
            "metadata-v1:{}:{}:{}",
            self.max_attempts, self.max_record_retained_bytes, self.max_encoded_record_bytes
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, normalized.as_bytes());
        let hash: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        format!("{label}:{hash}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureBudgets {
    pub max_active_requests: usize,
    pub max_request_state_bytes: usize,
    pub max_queue_events: usize,
    pub max_queue_retained_bytes: usize,
    pub max_in_flight_events: usize,
    pub max_transport_retained_bytes: usize,
    pub max_capture_memory_bytes: usize,
}
impl Default for CaptureBudgets {
    fn default() -> Self {
        Self {
            max_active_requests: 4096,
            max_request_state_bytes: 65536,
            max_queue_events: 1024,
            max_queue_retained_bytes: 67_108_864,
            max_in_flight_events: 8,
            max_transport_retained_bytes: 16_777_216,
            max_capture_memory_bytes: 402_653_184,
        }
    }
}
impl CaptureBudgets {
    pub fn validate(
        &self,
        policy: &MetadataCapturePolicy,
    ) -> Result<(), (&'static str, &'static str)> {
        let bad = |field| (field, "capture memory budget is inconsistent or overflows");
        if self.max_queue_retained_bytes < policy.max_record_retained_bytes {
            return Err(bad("max_queue_retained_bytes"));
        }
        let transport = policy
            .max_record_retained_bytes
            .checked_add(policy.max_encoded_record_bytes)
            .and_then(|n| n.checked_add(65_536))
            .and_then(|n| n.checked_mul(self.max_in_flight_events))
            .and_then(|n| n.checked_add(2 * 1024 * 1024))
            .ok_or(bad("max_transport_retained_bytes"))?;
        if self.max_transport_retained_bytes < transport {
            return Err(bad("max_transport_retained_bytes"));
        }
        // Fixed allowances: snapshots/control 8 MiB, bookkeeping 16 MiB,
        // eight terminal scratch owners 8 MiB, allocator/headroom 16 MiB.
        let sum = self
            .max_active_requests
            .checked_mul(self.max_request_state_bytes)
            .and_then(|n| n.checked_add(self.max_queue_retained_bytes))
            .and_then(|n| n.checked_add(self.max_transport_retained_bytes))
            .and_then(|n| n.checked_add(48 * 1024 * 1024))
            .ok_or(bad("max_capture_memory_bytes"))?;
        if sum > self.max_capture_memory_bytes {
            return Err(bad("max_capture_memory_bytes"));
        }
        if self
            .max_queue_events
            .checked_add(self.max_active_requests)
            .and_then(|n| n.checked_mul(256))
            .is_none_or(|n| n > 16 * 1024 * 1024)
        {
            return Err(bad("max_queue_events"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalCaptureControl {
    pub unix_socket_path: PathBuf,
    pub operator_uid: u32,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndUserCaptureConfig {
    pub metadata: MetadataCapturePolicy,
    pub policy_version: String,
    pub endpoint: crate::capture_transport::AgentTransportConfig,
    pub budgets: CaptureBudgets,
    pub transport: crate::capture_transport::CaptureTransportLimits,
    pub emergency_control: LocalCaptureControl,
}
