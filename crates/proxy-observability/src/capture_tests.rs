use crate::{
    capture::*,
    capture_policy::*,
    capture_transport::*,
    records::{RequestRecordSink, SubmitResult},
    stats::{prometheus_render, MetadataDeliveryStats, StatsControl},
};
use std::{os::unix::fs::PermissionsExt, time::Duration};
pub(crate) fn config(temp: &tempfile::TempDir) -> EndUserCaptureConfig {
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
    c.budgets.max_in_flight_events = 1;
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

async fn verify_delivery_slots(slots: usize) {
    use proxy_capture_protocol::{
        decode, encode, read_frame, write_frame, Kind, Outcome, Receipt, Welcome, VERSION,
    };
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.budgets.max_in_flight_events = slots;
    let listener = tokio::net::UnixListener::bind(&c.endpoint.socket_path).unwrap();
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::channel(4);
    let release = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let server_release = release.clone();
    let server = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                connected = listener.accept() => {
                    let (mut stream, _) = connected.unwrap();
                    let seen = seen_tx.clone();
                    let release = server_release.clone();
                    clients.spawn(async move {
                        read_frame(&mut stream).await.unwrap();
                        write_frame(&mut stream, Kind::Welcome, &encode(&Welcome { version: VERSION, node_id: "node".into() }).unwrap()).await.unwrap();
                        while let Ok(frame) = read_frame(&mut stream).await {
                            let record: crate::records::RequestRecord = decode(&frame.payload).unwrap();
                            seen.send(()).await.unwrap();
                            release.acquire().await.unwrap().forget();
                            write_frame(&mut stream, Kind::Receipt, &encode(&Receipt { version:VERSION, node_id:"node".into(), event_id:record.event_id, sequence:Some(1), outcome:Outcome::Durable }).unwrap()).await.unwrap();
                        }
                    });
                }
                _ = clients.join_next(), if !clients.is_empty() => {},
            }
        }
    });
    let (s, d, stats) = supervisor();
    s.configure(Some(c.clone()), 1).unwrap();
    let lease = s.try_admit().unwrap().unwrap();
    // Admission intentionally declines on a contended pool lock. Reserve the
    // test's records before dispatch so this test isolates transport ownership.
    let permits: Vec<_> = (0..slots + 1)
        .map(|_| lease.reserve_terminal().unwrap())
        .collect();
    for permit in permits {
        assert_eq!(
            permit.submit(crate::records::tests::record()),
            SubmitResult::Accepted
        );
    }
    for _ in 0..slots {
        tokio::time::timeout(Duration::from_secs(1), seen_rx.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), seen_rx.recv())
            .await
            .is_err()
    );
    assert_eq!(s.status().retained_event_bytes, (slots + 1) * 65536);
    c.budgets.max_in_flight_events = 1;
    assert!(s
        .configure(Some(c), 1)
        .unwrap_err()
        .contains("max_in_flight_events"));
    release.add_permits(slots + 1);
    assert!(!d.shutdown(Duration::from_secs(2)).await);
    assert_eq!(s.status().retained_event_bytes, 0);
    assert!(prometheus_render::render(&stats.registry())
        .contains(&format!("envoy_llmproxy_metadata_durable {}", slots + 1)));
    drop(lease);
    server.abort();
    let _ = server.await;
}

// The first handshake fails. Later handshakes wait on an explicit test gate;
// a Welcome alone never releases the destination's single-probe ownership.
async fn gated_agent(
    path: &std::path::Path,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Receiver<usize>,
    std::sync::Arc<tokio::sync::Semaphore>,
) {
    gated_agent_behavior(path, true, false).await
}

async fn gated_agent_behavior(
    path: &std::path::Path,
    fail_first: bool,
    hold_receipts: bool,
) -> (
    tokio::task::JoinHandle<()>,
    tokio::sync::mpsc::Receiver<usize>,
    std::sync::Arc<tokio::sync::Semaphore>,
) {
    use proxy_capture_protocol::{
        decode, encode, read_frame, write_frame, Kind, Outcome, Receipt, Welcome, VERSION,
    };
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let (seen, rx) = tokio::sync::mpsc::channel(32);
    let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
    let agent_gate = gate.clone();
    let task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        let mut count = 0;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    count += 1;
                    seen.send(count).await.unwrap();
                    let gate = agent_gate.clone();
                    let seen = seen.clone();
                    clients.spawn(async move {
                        if read_frame(&mut stream).await.is_err() || (fail_first && count == 1) { return; }
                        gate.acquire().await.unwrap().forget();
                        if write_frame(&mut stream, Kind::Welcome, &encode(&Welcome {
                            version: VERSION, node_id: "node".into(),
                        }).unwrap()).await.is_err() { return; }
                        while let Ok(frame) = read_frame(&mut stream).await {
                            let record: crate::records::RequestRecord = decode(&frame.payload).unwrap();
                            if hold_receipts {
                                seen.send(0).await.unwrap();
                                gate.acquire().await.unwrap().forget();
                            }
                            if write_frame(&mut stream, Kind::Receipt, &encode(&Receipt {
                                version: VERSION, node_id: "node".into(), event_id: record.event_id,
                                sequence: Some(1), outcome: Outcome::Durable,
                            }).unwrap()).await.is_err() { return; }
                        }
                    });
                }
                _ = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });
    (task, rx, gate)
}

fn submit_event(s: &CaptureSupervisor) {
    let lease = s.try_admit().unwrap().unwrap();
    assert_eq!(
        lease
            .reserve_terminal()
            .unwrap()
            .submit(crate::records::tests::record()),
        SubmitResult::Accepted
    );
}

async fn seen_connection(rx: &mut tokio::sync::mpsc::Receiver<usize>, expected: usize) {
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap(),
        Some(expected)
    );
}

#[tokio::test]
async fn unavailable_destination_retains_bounded_backlog_and_recovers_with_one_probe() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.connect_deadline = Duration::from_secs(2);
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    c.budgets.max_queue_events = 9;
    c.budgets.max_queue_retained_bytes = 9 * 65536;
    let (agent, mut seen, gate) = gated_agent(&c.endpoint.socket_path).await;
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 1).await;
    seen_connection(&mut seen, 2).await;
    for _ in 0..8 {
        submit_event(&s);
    }
    let lease = s.try_admit().unwrap().unwrap();
    assert!(matches!(
        lease.reserve_terminal(),
        Err(SubmitResult::CapacityExceeded)
    ));
    assert_eq!(s.status().retained_event_bytes, 9 * 65536);
    assert!(tokio::time::timeout(Duration::from_millis(50), seen.recv())
        .await
        .is_err());
    gate.add_permits(8);
    assert!(!d.shutdown(Duration::from_secs(3)).await);
    assert_eq!(s.status().retained_event_bytes, 0);
    assert!(
        prometheus_render::render(&stats.registry()).contains("envoy_llmproxy_metadata_durable 9")
    );
    agent.abort();
    let _ = agent.await;
}

#[tokio::test]
async fn disable_waiting_and_probing_events_never_revives_them_on_enable() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.connect_deadline = Duration::from_secs(2);
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    let (agent, mut seen, gate) = gated_agent(&c.endpoint.socket_path).await;
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 1).await;
    seen_connection(&mut seen, 2).await;
    for _ in 0..4 {
        submit_event(&s);
    }
    s.set_disabled(true, 0).unwrap();
    s.set_disabled(false, 1).unwrap();
    gate.add_permits(8);
    assert!(!d.shutdown(Duration::from_secs(2)).await);
    let scrape = prometheus_render::render(&stats.registry());
    assert!(scrape.contains("envoy_llmproxy_metadata_durable 0"));
    assert!(scrape.contains("envoy_llmproxy_capture_drops{reason=\"disabled\"} 5"));
    assert_eq!(s.status().retained_event_bytes, 0);
    agent.abort();
    let _ = agent.await;
}

#[tokio::test]
async fn unavailable_shutdown_expires_original_age_without_resetting_retry_budget() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.connect_deadline = Duration::from_millis(100);
    c.transport.event_deadline = Duration::from_millis(350);
    c.transport.ack_deadline = Duration::from_millis(10);
    c.transport.max_attempts = 2;
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    let (agent, mut seen, _gate) = gated_agent(&c.endpoint.socket_path).await;
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 1).await;
    seen_connection(&mut seen, 2).await;
    assert!(!d.shutdown(Duration::from_secs(1)).await);
    // Exactly two physical attempts, even though the first immediately failed.
    assert!(seen.try_recv().is_err());
    let scrape = prometheus_render::render(&stats.registry());
    assert!(scrape.contains("envoy_llmproxy_capture_drops{reason=\"unavailable\"} 1"));
    assert_eq!(s.status().retained_event_bytes, 0);
    agent.abort();
    let _ = agent.await;
}

#[tokio::test]
async fn recovery_after_original_deadline_explicitly_expires_waiting_events() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.connect_deadline = Duration::from_secs(2);
    c.transport.event_deadline = Duration::from_millis(250);
    c.transport.ack_deadline = Duration::from_millis(10);
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    let (agent, mut seen, gate) = gated_agent(&c.endpoint.socket_path).await;
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 1).await;
    seen_connection(&mut seen, 2).await;
    for _ in 0..4 {
        submit_event(&s);
    }
    assert!(!d.shutdown(Duration::from_secs(1)).await);
    gate.add_permits(8);
    let scrape = prometheus_render::render(&stats.registry());
    assert!(
        scrape.contains("envoy_llmproxy_capture_drops{reason=\"expired\"} 5"),
        "{scrape}"
    );
    assert!(scrape.contains("envoy_llmproxy_metadata_durable 0"));
    assert_eq!(s.status().retained_event_bytes, 0);
    agent.abort();
    let _ = agent.await;
}

async fn verify_destination_isolation(slots: usize) {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.connect_deadline = Duration::from_millis(50);
    c.transport.drain_deadline = Duration::from_millis(500);
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    c.budgets.max_in_flight_events = slots;
    let (old_agent, mut seen, _old_gate) = gated_agent(&c.endpoint.socket_path).await;
    let (s, d, stats) = supervisor();
    s.configure(Some(c.clone()), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 1).await;
    seen_connection(&mut seen, 2).await;
    for _ in 0..8 {
        submit_event(&s);
    }
    c.endpoint.socket_path = temp.path().join("new.sock");
    let (new_agent, _new_seen, gate) =
        gated_agent_behavior(&c.endpoint.socket_path, false, false).await;
    gate.add_permits(8);
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    tokio::time::timeout(Duration::from_millis(400), async {
        while !prometheus_render::render(&stats.registry())
            .contains("envoy_llmproxy_metadata_durable 1")
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(s.status().outstanding_events > 0);
    assert!(!d.shutdown(Duration::from_secs(1)).await);
    assert_eq!(s.status().retained_event_bytes, 0);
    assert!(
        prometheus_render::render(&stats.registry()).contains("envoy_llmproxy_metadata_durable 1")
    );
    old_agent.abort();
    new_agent.abort();
    let _ = old_agent.await;
    let _ = new_agent.await;
}

#[tokio::test]
async fn stopping_admissions_preserves_terminal_delivery_for_admitted_requests() {
    let temp = tempfile::tempdir().unwrap();
    let c = config(&temp);
    let (agent, _seen, gate) = gated_agent(&c.endpoint.socket_path).await;
    gate.add_permits(8);
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    let lease = s.try_admit().unwrap().unwrap();
    s.stop_admissions();
    assert!(matches!(s.try_admit(), Err(SubmitResult::Closed)));
    assert_eq!(
        lease
            .reserve_terminal()
            .unwrap()
            .submit(crate::records::tests::record()),
        SubmitResult::Accepted
    );
    assert!(!d.shutdown(Duration::from_secs(2)).await);
    assert!(
        prometheus_render::render(&stats.registry()).contains("envoy_llmproxy_metadata_durable 1")
    );
    agent.abort();
    let _ = agent.await;
}

#[tokio::test]
async fn authenticated_identity_change_at_same_path_has_independent_availability() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.connect_deadline = Duration::from_secs(2);
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    let (agent, mut seen, gate) = gated_agent(&c.endpoint.socket_path).await;
    let (s, d, stats) = supervisor();
    s.configure(Some(c.clone()), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 1).await;
    seen_connection(&mut seen, 2).await;
    // The old identity owns the unavailable probe; the same path under a new
    // authenticated producer identity must still be independently dispatchable.
    c.endpoint.producer_id = "new-producer".into();
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 3).await;
    gate.add_permits(8);
    assert!(!d.shutdown(Duration::from_secs(2)).await);
    assert!(
        prometheus_render::render(&stats.registry()).contains("envoy_llmproxy_metadata_durable 2")
    );
    agent.abort();
    let _ = agent.await;
}

#[tokio::test]
async fn delivery_slots_are_concurrent_capped_and_owned_through_ack() {
    for slots in [2, 8] {
        verify_delivery_slots(slots).await;
    }
}

#[tokio::test]
async fn supervisor_keeps_lost_receipt_ambiguous_after_rescheduled_rejection() {
    use proxy_capture_protocol::{
        decode, encode, read_frame, write_frame, Kind, Outcome, Receipt, Welcome, VERSION,
    };
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.max_attempts = 2;
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    let listener = tokio::net::UnixListener::bind(&c.endpoint.socket_path).unwrap();
    let agent = tokio::spawn(async move {
        for attempt in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame(&mut stream).await.unwrap();
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
            let frame = read_frame(&mut stream).await.unwrap();
            let record: crate::records::RequestRecord = decode(&frame.payload).unwrap();
            if attempt == 0 {
                continue;
            }
            write_frame(
                &mut stream,
                Kind::Receipt,
                &encode(&Receipt {
                    version: VERSION,
                    node_id: "node".into(),
                    event_id: record.event_id,
                    sequence: None,
                    outcome: Outcome::Full,
                })
                .unwrap(),
            )
            .await
            .unwrap();
        }
    });
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    assert!(!d.shutdown(Duration::from_secs(2)).await);
    let scrape = prometheus_render::render(&stats.registry());
    assert!(scrape.contains("envoy_llmproxy_capture_drops{reason=\"delivery_unknown\"} 1"));
    assert!(scrape.contains("envoy_llmproxy_capture_drops{reason=\"agent_rejected\"} 0"));
    assert_eq!(s.status().retained_event_bytes, 0);
    tokio::time::timeout(Duration::from_secs(1), agent)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn unavailable_draining_destination_does_not_block_current_destination() {
    for slots in [1, 2] {
        verify_destination_isolation(slots).await;
    }
}

#[tokio::test]
async fn successful_probe_handshake_does_not_reopen_parallel_delivery_before_durable_ack() {
    let temp = tempfile::tempdir().unwrap();
    let mut c = config(&temp);
    c.transport.connect_deadline = Duration::from_secs(2);
    c.transport.backoff_initial = Duration::ZERO;
    c.transport.backoff_max = Duration::ZERO;
    let (agent, mut seen, gate) = gated_agent_behavior(&c.endpoint.socket_path, true, true).await;
    let (s, d, stats) = supervisor();
    s.configure(Some(c), 1).unwrap();
    submit_event(&s);
    seen_connection(&mut seen, 1).await;
    seen_connection(&mut seen, 2).await;
    for _ in 0..4 {
        submit_event(&s);
    }
    gate.add_permits(1);
    // The authenticated Welcome and Record exchange succeeded; the spool
    // receipt is still blocked. No other transport slot may probe this identity.
    seen_connection(&mut seen, 0).await;
    assert!(tokio::time::timeout(Duration::from_millis(50), seen.recv())
        .await
        .is_err());
    assert!(
        prometheus_render::render(&stats.registry()).contains("envoy_llmproxy_metadata_durable 0")
    );
    assert_eq!(s.status().retained_event_bytes, 5 * 65536);
    gate.add_permits(16);
    assert!(!d.shutdown(Duration::from_secs(2)).await);
    assert!(
        prometheus_render::render(&stats.registry()).contains("envoy_llmproxy_metadata_durable 5")
    );
    assert_eq!(s.status().retained_event_bytes, 0);
    agent.abort();
    let _ = agent.await;
}
