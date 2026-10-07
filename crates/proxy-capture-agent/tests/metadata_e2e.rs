#![cfg(unix)]

use proxy_capture_agent::{
    config::{Config, Key, Producer, Spool},
    Agent, Health,
};
use proxy_capture_protocol::{
    decode, encode, read_frame, write_frame, Frame, Hello, Kind, Outcome, Receipt, Welcome, VERSION,
};
use proxy_capture_spool::{MetadataSpool, ReplayRecord};
use proxy_observability::{
    capture_transport::AgentTransportConfig,
    metadata::MetadataDelivery,
    records::{RequestRecord, RequestRecordSink, SubmitResult},
    stats::{instruments, MetadataDeliveryStats, StatsControl},
};
use std::{
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::UnixStream,
    sync::oneshot,
    task::JoinHandle,
    time::{sleep, timeout},
};

const WAIT: Duration = Duration::from_secs(3);

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

macro_rules! bounded_test {
    ($name:ident, $body:block) => {
        #[tokio::test]
        async fn $name() {
            timeout(Duration::from_secs(15), async $body).await.expect("test exceeded 15 seconds");
        }
    };
}

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    uid: u32,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut key = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("key"))
            .unwrap();
        std::io::Write::write_all(&mut key, &[37; 32]).unwrap();
        let uid = UnixStream::pair().unwrap().0.peer_cred().unwrap().uid();
        Self {
            _directory: directory,
            root,
            uid,
        }
    }

    fn config(&self) -> Config {
        Config {
            version: 1,
            mode: "metadata_spool_only".into(),
            socket_path: self.root.join("agent.sock"),
            node_id: "node".into(),
            producers: vec![Producer {
                producer_id: "producer".into(),
                uid: self.uid,
                tenants: vec!["default".into()],
            }],
            spool: Spool {
                directory: self.root.join("spool"),
                max_record_bytes: 4096,
                max_segment_bytes: 8192,
                max_disk_bytes: 1_048_576,
                max_segments: 16,
                max_segment_age_seconds: 60,
            },
            active_key_id: "key".into(),
            keys: vec![Key {
                key_id: "key".into(),
                key_file: self.root.join("key"),
            }],
        }
    }

    fn transport(&self) -> AgentTransportConfig {
        AgentTransportConfig {
            socket_path: self.root.join("agent.sock"),
            expected_agent_uid: self.uid,
            expected_node_id: "node".into(),
            producer_id: "producer".into(),
        }
    }

    fn replay(&self, config: &Config) -> Vec<ReplayRecord> {
        let (active, recovery) = config.load_keys().unwrap();
        MetadataSpool::open(config.spool_config(), active, recovery)
            .unwrap()
            .replay(0, 64, 262144)
            .unwrap()
    }

    async fn connect(&self) -> UnixStream {
        let mut stream = timeout(WAIT, UnixStream::connect(self.root.join("agent.sock")))
            .await
            .unwrap()
            .unwrap();
        send(
            &mut stream,
            Kind::Hello,
            &encode(&Hello {
                version: VERSION,
                producer_id: "producer".into(),
            })
            .unwrap(),
        )
        .await;
        let frame = frame(&mut stream).await.unwrap();
        assert_eq!(frame.kind, Kind::Welcome);
        let welcome: Welcome = decode(&frame.payload).unwrap();
        assert_eq!(welcome.version, VERSION);
        assert_eq!(welcome.node_id, "node");
        stream
    }
}

// Aborting drops Agent's connection jobs and closes its writer channel. Sending
// shutdown first also permits graceful draining when the runtime polls it.
struct TaskAbortGuard {
    task: JoinHandle<io::Result<()>>,
    shutdown: Option<oneshot::Sender<()>>,
    health: Arc<Health>,
}

impl TaskAbortGuard {
    fn start(config: Config) -> Self {
        let agent = Agent::start(config).unwrap();
        let health = agent.health.clone();
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(agent.run(async {
            let _ = receiver.await;
        }));
        Self {
            task,
            shutdown: Some(shutdown),
            health,
        }
    }

    async fn stop(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        timeout(Duration::from_secs(6), &mut self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

impl Drop for TaskAbortGuard {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

fn record(event_id: &str) -> RequestRecord {
    serde_json::from_value(serde_json::json!({
        "schema_version":1,"event_id":event_id,"request_id":"request","instance_id":"instance",
        "started_at":"2026-10-01T00:00:00Z","finished_at":"2026-10-01T00:00:01Z",
        "tenant_id":"default","user_id":null,"key_id":null,"trace_id":null,
        "routing_revision":null,"policy_generation":null,"capture_policy_version":null,
        "method":"POST","route":"/v1/chat/completions","requested_model":null,
        "selected_cluster":null,"selected_provider":null,"selected_model":null,
        "status":200,"termination":"complete","error_category":null,"response_flags":[],
        "duration_ms":1,"time_to_first_byte_ms":null,"bytes_request":0,"bytes_response":0,
        "usage":null,"cost":null,"attempt_count":0,"physical_attempt_count":0,
        "attempts":[],"attempts_truncated":false
    }))
    .unwrap()
}

async fn send(stream: &mut UnixStream, kind: Kind, payload: &[u8]) {
    timeout(WAIT, write_frame(stream, kind, payload))
        .await
        .unwrap()
        .unwrap();
}

async fn frame(stream: &mut UnixStream) -> io::Result<Frame> {
    timeout(WAIT, read_frame(stream))
        .await
        .expect("frame deadline exceeded")
}

async fn receipt(stream: &mut UnixStream, payload: &[u8]) -> Receipt {
    send(stream, Kind::Record, payload).await;
    let frame = frame(stream).await.unwrap();
    assert_eq!(frame.kind, Kind::Receipt);
    let receipt: Receipt = decode(&frame.payload).unwrap();
    assert_eq!(receipt.version, VERSION);
    assert_eq!(receipt.node_id, "node");
    receipt
}

async fn poll(mut ready: impl FnMut() -> bool) {
    timeout(Duration::from_secs(8), async {
        while !ready() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("condition deadline exceeded");
}

bounded_test!(durable_ack_payload_and_event_id_survive_reopen, {
    let fixture = Fixture::new();
    let config = fixture.config();
    let agent = TaskAbortGuard::start(fixture.config());
    let mut stream = fixture.connect().await;
    let expected = record("durable-event");
    let ack = receipt(&mut stream, &encode(&expected).unwrap()).await;
    assert_eq!(ack.outcome, Outcome::Durable);
    assert_eq!(ack.event_id, expected.event_id);
    assert_eq!(ack.sequence, Some(1));
    drop(stream);
    agent.stop().await;
    let replay = fixture.replay(&config);
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].sequence, ack.sequence.unwrap());
    assert_eq!(
        decode::<RequestRecord>(&replay[0].payload).unwrap(),
        expected
    );
});

bounded_test!(unauthorized_tenant_never_appends, {
    let fixture = Fixture::new();
    let agent = TaskAbortGuard::start(fixture.config());
    let mut stream = fixture.connect().await;
    let mut denied = record("denied");
    denied.tenant_id = "other-tenant".into();
    let ack = receipt(&mut stream, &encode(&denied).unwrap()).await;
    assert_eq!(ack.outcome, Outcome::Unauthorized);
    assert_eq!(ack.event_id, "denied");
    assert_eq!(ack.sequence, None);
    drop(stream);
    agent.stop().await;
    assert!(fixture.replay(&fixture.config()).is_empty());
});

bounded_test!(
    attempt_schema_and_request_ownership_must_match_the_envelope,
    {
        let fixture = Fixture::new();
        let agent = TaskAbortGuard::start(fixture.config());
        let mut stream = fixture.connect().await;
        for (version, request_id) in [(2, "request"), (1, "different-request")] {
            let mut value = serde_json::to_value(record("bad-attempt")).unwrap();
            value["attempt_count"] = 1.into();
            value["physical_attempt_count"] = 1.into();
            value["attempts"] = serde_json::json!([{
                "schema_version":version,"event_id":"attempt-event","request_id":request_id,
                "attempt_id":"attempt-1","attempt_index":1,"trace_id":null,"span_id":null,"parent_span_id":null,
                "cluster":null,"provider":null,"upstream_model":null,"started_at":"2026-10-01T00:00:00Z",
                "finished_at":"2026-10-01T00:00:01Z","duration_ms":1,"status":200,"termination":"complete",
                "retry_reason":null,"bytes_request":null,"bytes_response":0,"usage":null,"cost":null
            }]);
            assert_eq!(
                receipt(&mut stream, &encode(&value).unwrap()).await.outcome,
                Outcome::Invalid
            );
        }
        drop(stream);
        agent.stop().await;
        assert!(fixture.replay(&fixture.config()).is_empty());
    }
);

bounded_test!(producer_uid_and_id_are_rejected, {
    for wrong_uid in [false, true] {
        let fixture = Fixture::new();
        let mut config = fixture.config();
        if wrong_uid {
            config.producers[0].uid = fixture.uid.wrapping_add(1);
        }
        let agent = TaskAbortGuard::start(config);
        let mut stream = UnixStream::connect(fixture.root.join("agent.sock"))
            .await
            .unwrap();
        send(
            &mut stream,
            Kind::Hello,
            &encode(&Hello {
                version: VERSION,
                producer_id: if wrong_uid { "producer" } else { "intruder" }.into(),
            })
            .unwrap(),
        )
        .await;
        assert!(
            frame(&mut stream).await.is_err(),
            "unauthorized producer received a frame"
        );
        drop(stream);
        agent.stop().await;
        assert!(fixture.replay(&fixture.config()).is_empty());
    }
});

bounded_test!(transport_rejects_wrong_agent_uid_and_node, {
    for wrong_uid in [false, true] {
        let fixture = Fixture::new();
        let agent = TaskAbortGuard::start(fixture.config());
        let mut transport = fixture.transport();
        if wrong_uid {
            transport.expected_agent_uid = fixture.uid.wrapping_add(1);
        } else {
            transport.expected_node_id = "wrong-node".into();
        }
        let control = StatsControl::new(1);
        let (sink, delivery) =
            MetadataDelivery::start_agent(transport, 2, MetadataDeliveryStats::resolve(&control))
                .unwrap();
        assert_eq!(
            sink.submit(record("rejected-agent")),
            SubmitResult::Accepted
        );
        drop(sink);
        let summary = delivery.shutdown(Duration::from_secs(8)).await;
        assert!(!summary.timed_out);
        assert_eq!(
            (summary.written, summary.failed, summary.unwritten),
            (0, 1, 0)
        );
        agent.stop().await;
        assert!(fixture.replay(&fixture.config()).is_empty());
    }
});

bounded_test!(full_spool_preserves_committed_payload, {
    let fixture = Fixture::new();
    let mut config = fixture.config();
    config.spool.max_segments = 1;
    let mut reopen = fixture.config();
    reopen.spool.max_segments = 1;
    let agent = TaskAbortGuard::start(config);
    let mut stream = fixture.connect().await;
    let payload = encode(&record("preserved")).unwrap();
    assert_eq!(
        receipt(&mut stream, &payload).await.outcome,
        Outcome::Durable
    );
    let ack = receipt(&mut stream, &encode(&record("full")).unwrap()).await;
    assert_eq!(ack.outcome, Outcome::Full);
    assert_eq!(ack.sequence, None);
    drop(stream);
    agent.stop().await;
    let replay = fixture.replay(&reopen);
    assert_eq!(replay.len(), 1);
    assert_eq!(replay[0].payload, payload);
});

bounded_test!(unknown_schema_and_body_extra_are_rejected_without_append, {
    for extra_body in [false, true] {
        let fixture = Fixture::new();
        let agent = TaskAbortGuard::start(fixture.config());
        let mut stream = fixture.connect().await;
        let mut value = serde_json::to_value(record("invalid")).unwrap();
        if extra_body {
            value["body"] = serde_json::json!("customer content must not be accepted");
        } else {
            value["schema_version"] = serde_json::json!(2);
        }
        let ack = receipt(&mut stream, &encode(&value).unwrap()).await;
        // Stop before asserting so even a behavior regression drains the writer.
        drop(stream);
        agent.stop().await;
        assert_eq!(ack.outcome, Outcome::Invalid);
        assert_eq!(ack.sequence, None);
        assert!(fixture.replay(&fixture.config()).is_empty());
    }
});

bounded_test!(nested_unknown_fields_are_rejected_without_append, {
    let fixture = Fixture::new();
    let agent = TaskAbortGuard::start(fixture.config());
    let mut stream = fixture.connect().await;
    let usage = serde_json::json!({
        "input_tokens":1,"cache_read_tokens":0,"cache_write_tokens":0,
        "output_tokens":1,"completeness":"complete","provenance":"provider"
    });
    let cost = serde_json::json!({
        "amount":1,"unit":"nanodollars","currency":"USD",
        "rate_card_version":"v1","kind":"list"
    });
    let attempt = serde_json::json!({
        "schema_version":1,"event_id":"attempt-event","request_id":"request",
        "attempt_id":"attempt","attempt_index":0,"trace_id":null,"span_id":null,
        "parent_span_id":null,"cluster":null,"provider":null,"upstream_model":null,
        "started_at":"2026-10-01T00:00:00Z","finished_at":"2026-10-01T00:00:01Z",
        "duration_ms":1,"status":200,"termination":"complete","retry_reason":null,
        "bytes_request":0,"bytes_response":0,"usage":usage,"cost":cost
    });
    for pointer in [
        "/usage/body",
        "/cost/body",
        "/attempts/0/body",
        "/attempts/0/usage/body",
        "/attempts/0/cost/body",
    ] {
        let mut value = serde_json::to_value(record("nested-invalid")).unwrap();
        value["usage"] = usage.clone();
        value["cost"] = cost.clone();
        value["attempts"] = serde_json::json!([attempt.clone()]);
        value["attempt_count"] = serde_json::json!(1);
        value["physical_attempt_count"] = serde_json::json!(1);
        // Prove that the base envelope is valid before adding the unsupported field.
        decode::<RequestRecord>(&encode(&value).unwrap())
            .unwrap()
            .validate(64)
            .unwrap();
        let parent = pointer.strip_suffix("/body").unwrap();
        value.pointer_mut(parent).unwrap()["body"] = serde_json::json!("unsupported content");
        let ack = receipt(&mut stream, &encode(&value).unwrap()).await;
        assert_eq!(
            ack.outcome,
            Outcome::Invalid,
            "accepted unknown field at {pointer}"
        );
        assert_eq!(ack.sequence, None);
    }
    drop(stream);
    agent.stop().await;
    assert!(fixture.replay(&fixture.config()).is_empty());
});

bounded_test!(
    string_and_identifier_limits_reject_excess_and_accept_boundaries,
    {
        let fixture = Fixture::new();
        let agent = TaskAbortGuard::start(fixture.config());
        let mut stream = fixture.connect().await;
        for (field, maximum) in [
            ("event_id", 128),
            ("request_id", 128),
            ("route", 512),
            ("instance_id", 512),
            ("user_id", 512),
            ("error_category", 512),
        ] {
            let mut value = serde_json::to_value(record("over-limit")).unwrap();
            value[field] = serde_json::json!("x".repeat(maximum + 1));
            let ack = receipt(&mut stream, &encode(&value).unwrap()).await;
            assert_eq!(ack.outcome, Outcome::Invalid, "accepted overlong {field}");
            assert_eq!(ack.sequence, None);
        }
        for nested in [false, true] {
            let mut value = serde_json::to_value(record("nested-over-limit")).unwrap();
            if nested {
                value["usage"] = serde_json::json!({
                    "input_tokens":0,"cache_read_tokens":0,"cache_write_tokens":0,
                    "output_tokens":0,"completeness":"complete","provenance":"x".repeat(513)
                });
            } else {
                value["response_flags"] = serde_json::json!(["x".repeat(513)]);
            }
            let ack = receipt(&mut stream, &encode(&value).unwrap()).await;
            assert_eq!(ack.outcome, Outcome::Invalid);
            assert_eq!(ack.sequence, None);
        }
        let mut boundary = record(&"e".repeat(128));
        let escaped = record(&"\u{0001}".repeat(128));
        assert_eq!(
            receipt(&mut stream, &encode(&escaped).unwrap())
                .await
                .outcome,
            Outcome::Invalid
        );
        boundary.request_id = "r".repeat(128);
        boundary.route = "x".repeat(512);
        boundary.user_id = Some("u".repeat(512));
        let ack = receipt(&mut stream, &encode(&boundary).unwrap()).await;
        assert_eq!(ack.outcome, Outcome::Durable);
        assert_eq!(ack.event_id, boundary.event_id);
        assert_eq!(ack.sequence, Some(1));
        drop(stream);
        agent.stop().await;
        let replay = fixture.replay(&fixture.config());
        assert_eq!(replay.len(), 1);
        assert_eq!(
            decode::<RequestRecord>(&replay[0].payload).unwrap(),
            boundary
        );
    }
);

bounded_test!(outage_reports_failure_then_same_delivery_recovers, {
    let fixture = Fixture::new();
    let control = StatsControl::new(1);
    let registry = control.registry();
    let failures = control.resolve(&instruments::METADATA_WRITE_FAILURES, &[]);
    let written = control.resolve(&instruments::METADATA_WRITTEN, &[]);
    let (sink, delivery) = MetadataDelivery::start_agent(
        fixture.transport(),
        2,
        MetadataDeliveryStats::resolve(&control),
    )
    .unwrap();
    assert_eq!(sink.submit(record("outage")), SubmitResult::Accepted);
    poll(|| registry.value(failures) == 1).await;
    assert_eq!(registry.value(written), 0);
    let agent = TaskAbortGuard::start(fixture.config());
    assert_eq!(sink.submit(record("recovered")), SubmitResult::Accepted);
    poll(|| registry.value(written) == 1).await;
    assert_eq!(sink.counters().snapshot().accepted, 2);
    drop(sink);
    let summary = delivery.shutdown(Duration::from_secs(2)).await;
    assert!(!summary.timed_out);
    assert_eq!(
        (summary.written, summary.failed, summary.unwritten),
        (1, 1, 0)
    );
    agent.stop().await;
    let replay = fixture.replay(&fixture.config());
    assert_eq!(replay.len(), 1);
    assert_eq!(
        decode::<RequestRecord>(&replay[0].payload)
            .unwrap()
            .event_id,
        "recovered"
    );
});

bounded_test!(lost_durable_ack_replay_retains_duplicate_stable_event_id, {
    let fixture = Fixture::new();
    let agent = TaskAbortGuard::start(fixture.config());
    let payload = encode(&record("stable-event")).unwrap();
    let mut first = fixture.connect().await;
    send(&mut first, Kind::Record, &payload).await;
    // Observe the durability barrier but deliberately never consume its ACK.
    poll(|| agent.health.durable.load(Ordering::Relaxed) == 1).await;
    drop(first);
    let mut retry = fixture.connect().await;
    let ack = receipt(&mut retry, &payload).await;
    assert_eq!(ack.outcome, Outcome::Durable);
    assert_eq!(ack.event_id, "stable-event");
    assert_eq!(ack.sequence, Some(2));
    drop(retry);
    agent.stop().await;
    let replay = fixture.replay(&fixture.config());
    // Local spool provides at-least-once delivery, explicitly no backend dedup.
    assert_eq!(replay.len(), 2);
    assert_eq!(replay[0].sequence, 1);
    assert_eq!(replay[1].sequence, 2);
    for entry in replay {
        assert_eq!(entry.payload, payload);
    }
});

bounded_test!(malformed_frames_never_receive_a_false_ack, {
    let fixture = Fixture::new();
    let agent = TaskAbortGuard::start(fixture.config());
    for bytes in [
        b"BAD!\x03\x00\x00\x00\x01".as_slice(),
        b"LMC2\x03\x00\x00\x00\x01",
        b"LMC1\xff\x00\x00\x00\x01",
        b"LMC1\x03\x00\x00\x00\x00",
        b"LMC1\x03\x00\x08\x00\x01",
        b"LMC1\x03\x00\x00",
        b"LMC1\x03\x00\x00\x00\x05ab",
        b"LMC1\x01\x00\x00\x00\x01x",
    ] {
        let mut stream = fixture.connect().await;
        timeout(WAIT, stream.write_all(bytes))
            .await
            .unwrap()
            .unwrap();
        stream.shutdown().await.unwrap();
        assert!(
            frame(&mut stream).await.is_err(),
            "malformed frame received a response"
        );
    }
    agent.stop().await;
    assert!(fixture.replay(&fixture.config()).is_empty());
});

bounded_test!(
    agent_binary_sigkill_and_sigterm_preserve_durability_acknowledged_records,
    {
        for graceful in [false, true] {
            let fixture = Fixture::new();
            let path = fixture.root.join("agent.json");
            let value = serde_json::json!({"version":1,"mode":"metadata_spool_only","socket_path":fixture.root.join("agent.sock"),"node_id":"node",
            "producers":[{"producer_id":"producer","uid":fixture.uid,"tenants":["default"]}],
            "spool":{"directory":fixture.root.join("spool"),"max_record_bytes":4096,"max_segment_bytes":8192,"max_disk_bytes":1048576,"max_segments":16,"max_segment_age_seconds":60},
            "active_key_id":"key","keys":[{"key_id":"key","key_file":fixture.root.join("key")}]});
            std::fs::write(&path, value.to_string()).unwrap();
            let mut child = ChildGuard(
                std::process::Command::new(env!("CARGO_BIN_EXE_llm-capture-agent"))
                    .arg("--config")
                    .arg(path)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            poll(|| {
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "agent exited before binding"
                );
                fixture.root.join("agent.sock").exists()
            })
            .await;
            let mut stream = fixture.connect().await;
            let payload = encode(&record("process-event")).unwrap();
            assert_eq!(
                receipt(&mut stream, &payload).await.outcome,
                Outcome::Durable
            );
            drop(stream);
            if graceful {
                assert!(std::process::Command::new("kill")
                    .args(["-TERM", &child.0.id().to_string()])
                    .status()
                    .unwrap()
                    .success());
                poll(|| child.0.try_wait().unwrap().is_some()).await;
                assert!(!fixture.root.join("agent.sock").exists());
            } else {
                child.0.kill().unwrap();
                child.0.wait().unwrap();
            }
            let replay = fixture.replay(&fixture.config());
            assert_eq!(replay.len(), 1);
            assert_eq!(replay[0].payload, payload);
        }
    }
);
