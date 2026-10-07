use crate::{
    capture::*,
    capture_policy::*,
    capture_transport::*,
    records::{RequestRecordSink, SubmitResult},
    stats::{prometheus_render, MetadataDeliveryStats, StatsControl},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};
fn config(temp: &tempfile::TempDir) -> EndUserCaptureConfig {
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let uid = tokio::net::UnixStream::pair()
        .unwrap()
        .0
        .peer_cred()
        .unwrap()
        .uid();
    let metadata = MetadataCapturePolicy::default();
    EndUserCaptureConfig {
        policy_version: metadata.effective_version("first"),
        metadata,
        endpoint: AgentTransportConfig {
            socket_path: temp.path().join("agent.sock"),
            expected_agent_uid: uid,
            expected_node_id: "node".into(),
            producer_id: "proxy".into(),
        },
        budgets: CaptureBudgets::default(),
        transport: CaptureTransportLimits::default(),
        emergency_control: LocalCaptureControl {
            unix_socket_path: temp.path().join("control.sock"),
            operator_uid: uid,
        },
    }
}
fn supervisor() -> (CaptureSupervisor, CaptureDelivery, StatsControl) {
    let stats = StatsControl::new(1);
    let (s, d) = CaptureSupervisor::start(MetadataDeliveryStats::resolve(&stats)).unwrap();
    (s, d, stats)
}
#[tokio::test]
async fn admission_is_disabled_bounded_pinned_and_released() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.budgets.max_active_requests = 1;
    let (s, d, stats) = supervisor();
    assert!(matches!(s.try_admit(), Err(SubmitResult::Disabled)));
    s.configure(Some(c.clone()), 1).unwrap();
    let old = s.try_admit().unwrap().unwrap();
    assert!(matches!(s.try_admit(), Err(SubmitResult::CapacityExceeded)));
    c.policy_version = c.metadata.effective_version("second");
    c.metadata.max_attempts = 2;
    s.configure(Some(c.clone()), 1).unwrap();
    assert_ne!(old.version(), c.policy_version);
    assert_eq!(old.max_attempts(), 8);
    assert_eq!(s.status().active_requests, 1);
    drop(old);
    let new = s.try_admit().unwrap().unwrap();
    assert_eq!(new.max_attempts(), 2);
    drop(new);
    assert!(prometheus_render::render(&stats.registry())
        .contains("envoy_llmproxy_capture_state_reserved_bytes 0"));
    assert!(!d.shutdown(Duration::from_secs(1)).await);
}
#[tokio::test]
async fn queue_byte_reservations_live_until_permit_drop_and_reject_shrink() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.budgets.max_queue_retained_bytes = 65536;
    let (s, d, _) = supervisor();
    s.configure(Some(c.clone()), 1).unwrap();
    let lease = s.try_admit().unwrap().unwrap();
    let permit = lease.reserve_terminal().unwrap();
    assert_eq!(s.status().retained_event_bytes, 65536);
    assert!(matches!(
        lease.reserve_terminal(),
        Err(SubmitResult::CapacityExceeded)
    ));
    c.metadata.max_record_retained_bytes = 4096;
    c.budgets.max_queue_retained_bytes = 4096;
    assert!(s
        .configure(Some(c.clone()), 1)
        .unwrap_err()
        .contains("max_queue_retained_bytes"));
    drop(permit);
    assert_eq!(s.status().retained_event_bytes, 0);
    s.configure(Some(c), 1).unwrap();
    drop(lease);
    assert!(!d.shutdown(Duration::from_secs(1)).await);
}
#[tokio::test]
async fn gate_is_generation_checked_survives_reload_and_never_revives_old_requests() {
    let temp = tempfile::tempdir().unwrap();
    let c = config(&temp);
    let (s, d, _) = supervisor();
    s.configure(Some(c.clone()), 1).unwrap();
    let lease = s.try_admit().unwrap().unwrap();
    s.set_disabled(true, 0).unwrap();
    assert!(!lease.live());
    assert_eq!(s.set_disabled(false, 0).unwrap_err(), "stale generation");
    s.configure(Some(c), 1).unwrap();
    assert!(s.status().disabled);
    s.set_disabled(false, 1).unwrap();
    assert!(!lease.live());
    assert!(s.try_admit().is_ok());
    drop(lease);
    assert!(!d.shutdown(Duration::from_secs(1)).await);
}
#[tokio::test]
async fn two_destination_epochs_are_bounded_and_late_completions_expire() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.drain_deadline = Duration::from_millis(10);
    let (s, d, _) = supervisor();
    s.configure(Some(c.clone()), 1).unwrap();
    let old = s.try_admit().unwrap().unwrap();
    c.endpoint.socket_path = temp.path().join("second.sock");
    s.configure(Some(c.clone()), 1).unwrap();
    c.endpoint.socket_path = temp.path().join("third.sock");
    assert!(s
        .configure(Some(c.clone()), 1)
        .unwrap_err()
        .contains("endpoint.unix_socket_path"));
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!old.live());
    s.configure(Some(c), 1).unwrap();
    drop(old);
    assert!(!d.shutdown(Duration::from_secs(1)).await);
}
#[tokio::test]
async fn pinned_versions_and_concurrency_are_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    let (s, d, _) = supervisor();
    assert!(s
        .configure(Some(c.clone()), 9)
        .unwrap_err()
        .contains("concurrency 9"));
    let mut leases = Vec::new();
    for n in 0..16 {
        c.policy_version = c.metadata.effective_version(&n.to_string());
        s.configure(Some(c.clone()), 1).unwrap();
        leases.push(s.try_admit().unwrap().unwrap());
    }
    c.policy_version = "seventeenth".into();
    assert!(s
        .configure(Some(c.clone()), 1)
        .unwrap_err()
        .contains("sixteen pinned"));
    leases.clear();
    s.configure(Some(c), 1).unwrap();
    assert!(!d.shutdown(Duration::from_secs(1)).await);
}
#[tokio::test]
async fn escaped_json_is_dropped_before_exceeding_encoded_allocation() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.metadata.max_encoded_record_bytes = 4096;
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    let lease = s.try_admit().unwrap().unwrap();
    let permit = lease.reserve_terminal().unwrap();
    let mut record = crate::records::tests::record();
    record.route = "\u{0001}".repeat(3000);
    assert_eq!(permit.submit(record), SubmitResult::Accepted);
    assert!(!d.shutdown(Duration::from_secs(1)).await);
    let scrape = prometheus_render::render(&stats.registry());
    assert!(scrape.contains("envoy_llmproxy_capture_drops{reason=\"encoded_limit\"} 1"));
    assert_eq!(s.status().outstanding_events, 0);
    drop(lease);
}

#[tokio::test]
async fn dequeue_does_not_release_bytes_and_disable_discards_unsent_events() {
    use proxy_capture_protocol::{encode, read_frame, write_frame, Kind, Welcome, VERSION};
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.ack_deadline = Duration::from_millis(100);
    c.transport.max_attempts = 1;
    let listener = tokio::net::UnixListener::bind(&c.endpoint.socket_path).unwrap();
    let (ready, seen) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_frame(&mut stream).await.unwrap().kind, Kind::Hello);
        write_frame(
            &mut stream,
            Kind::Welcome,
            &encode(&Welcome {
                version: VERSION,
                node_id: "node".into(),
            })
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(read_frame(&mut stream).await.unwrap().kind, Kind::Record);
        ready.send(()).unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    let lease = s.try_admit().unwrap().unwrap();
    assert_eq!(
        lease
            .reserve_terminal()
            .unwrap()
            .submit(crate::records::tests::record()),
        SubmitResult::Accepted
    );
    tokio::time::timeout(Duration::from_secs(1), seen)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(s.status().retained_event_bytes, 65536);
    assert!(prometheus_render::render(&stats.registry())
        .contains("envoy_llmproxy_metadata_queue_depth 0"));
    assert_eq!(
        lease
            .reserve_terminal()
            .unwrap()
            .submit(crate::records::tests::record()),
        SubmitResult::Accepted
    );
    s.set_disabled(true, 0).unwrap();
    assert!(!d.shutdown(Duration::from_secs(1)).await);
    assert_eq!(s.status().retained_event_bytes, 0);
    assert!(prometheus_render::render(&stats.registry())
        .contains("envoy_llmproxy_capture_drops{reason=\"disabled\"} 1"));
    drop(lease);
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn wrong_operator_uid_cannot_read_or_mutate_control_gate() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.emergency_control.operator_uid = c.emergency_control.operator_uid.saturating_add(1);
    let (s, d, _) = supervisor();
    s.configure(Some(c.clone()), 1).unwrap();
    let mut stream = tokio::net::UnixStream::connect(c.emergency_control.unix_socket_path)
        .await
        .unwrap();
    let command = br#"{"command":"Disable","expected_generation":0}"#;
    let _ = stream.write_u32(command.len() as u32).await;
    let _ = stream.write_all(command).await;
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.read_u32())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(s.status().generation, 0);
    assert!(!s.status().disabled);
    assert!(!d.shutdown(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn four_thousand_ninety_seventh_capture_is_declined_without_overbooking() {
    let temp = tempfile::tempdir().unwrap();
    let c = config(&temp);
    let (s, d, _) = supervisor();
    s.configure(Some(c), 1).unwrap();
    let mut leases = Vec::with_capacity(4096);
    for _ in 0..4096 {
        leases.push(s.try_admit().unwrap().unwrap());
    }
    assert!(matches!(s.try_admit(), Err(SubmitResult::CapacityExceeded)));
    assert_eq!(s.status().active_requests, 4096);
    leases.clear();
    assert_eq!(s.status().active_requests, 0);
    assert!(!d.shutdown(Duration::from_secs(1)).await);
}
