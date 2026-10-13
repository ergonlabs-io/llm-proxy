//! Inspection frames through the real socket and `serve` path, against a real
//! agent and spool. One test process has one UID, and a UID maps to one grant,
//! so each test starts its own agent with the single grant it needs. Records of
//! a tenant the grant lacks are seeded into the spool before the agent opens it.
use super::*;
use crate::config::{Key, Spool};
use proxy_capture_protocol::SpooledRecord;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use tokio::{task::JoinHandle, time::timeout};

const WAIT: Duration = Duration::from_secs(10);

fn record_json(event_id: &str, tenant: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version":1,"event_id":event_id,"request_id":"request","instance_id":"instance",
        "started_at":"2026-10-01T00:00:00Z","finished_at":"2026-10-01T00:00:01Z",
        "tenant_id":tenant,"user_id":null,"key_id":null,"trace_id":null,
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

struct Harness {
    _directory: tempfile::TempDir,
    socket: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<io::Result<()>>,
}

impl Harness {
    /// Starts an agent whose only grant has `tenants` and `inspect`. `seed`
    /// holds `(event_id, tenant)` records appended to the spool beforehand.
    fn start(tenants: &[&str], inspect: bool, seed: &[(&str, &str)]) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().to_path_buf();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut key = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("key"))
            .unwrap();
        io::Write::write_all(&mut key, &[37; 32]).unwrap();
        let uid = UnixStream::pair().unwrap().0.peer_cred().unwrap().uid();
        let config = Config {
            version: 1,
            mode: "metadata_spool_only".into(),
            socket_path: root.join("agent.sock"),
            node_id: "node".into(),
            producers: vec![Producer {
                producer_id: "producer".into(),
                uid,
                tenants: tenants.iter().map(|t| (*t).to_owned()).collect(),
                inspect,
            }],
            spool: Spool {
                directory: root.join("spool"),
                max_record_bytes: 4096,
                max_disk_bytes: 4 * 1_048_576,
                cache_bytes: 4 * 1024 * 1024,
            },
            active_key_id: "key".into(),
            keys: vec![Key {
                key_id: "key".into(),
                key_file: root.join("key"),
            }],
        };
        if !seed.is_empty() {
            let (active, recovery) = config.load_keys().unwrap();
            let mut spool = MetadataSpool::open(config.spool_config(), active, recovery).unwrap();
            let payloads: Vec<Vec<u8>> = seed
                .iter()
                .map(|(event, tenant)| record_json(event, tenant))
                .collect();
            let refs: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
            for appended in spool.append_batch(&refs).unwrap() {
                appended.unwrap();
            }
            spool.commit().unwrap();
        }
        let socket = config.socket_path.clone();
        let agent = Agent::start(config).unwrap();
        let (shutdown, stop) = oneshot::channel();
        let task = tokio::spawn(agent.run(async {
            let _ = stop.await;
        }));
        Self {
            _directory: directory,
            socket,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn connect(&self) -> Client {
        let mut stream = UnixStream::connect(&self.socket).await.unwrap();
        let hello = Hello {
            version: VERSION,
            producer_id: "producer".into(),
        };
        write_frame(&mut stream, Kind::Hello, &encode(&hello).unwrap())
            .await
            .unwrap();
        let welcome = read_frame(&mut stream).await.unwrap();
        assert_eq!(welcome.kind, Kind::Welcome);
        Client(stream)
    }

    async fn stop(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        timeout(WAIT, self.task).await.unwrap().unwrap().unwrap();
    }
}

struct Client(UnixStream);

impl Client {
    async fn submit(&mut self, event_id: &str, tenant: &str) -> Receipt {
        write_frame(&mut self.0, Kind::Record, &record_json(event_id, tenant))
            .await
            .unwrap();
        let frame = read_frame(&mut self.0).await.unwrap();
        assert_eq!(frame.kind, Kind::Receipt);
        decode(&frame.payload).unwrap()
    }

    async fn stats_with_version(&mut self, version: u16) -> StatsReply {
        write_frame(
            &mut self.0,
            Kind::StatsQuery,
            &encode(&StatsQuery { version }).unwrap(),
        )
        .await
        .unwrap();
        let frame = read_frame(&mut self.0).await.unwrap();
        assert_eq!(frame.kind, Kind::StatsReply);
        decode(&frame.payload).unwrap()
    }

    async fn stats(&mut self) -> StatsReply {
        self.stats_with_version(VERSION).await
    }

    async fn records(&mut self, after_sequence: u64, max_records: u16) -> RecordsReply {
        write_frame(
            &mut self.0,
            Kind::RecordsQuery,
            &encode(&RecordsQuery {
                version: VERSION,
                after_sequence,
                max_records,
            })
            .unwrap(),
        )
        .await
        .unwrap();
        let frame = read_frame(&mut self.0).await.unwrap();
        assert_eq!(frame.kind, Kind::RecordsReply);
        decode(&frame.payload).unwrap()
    }
}

fn event_ids(records: &[SpooledRecord]) -> Vec<String> {
    records
        .iter()
        .map(|row| row.record["event_id"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn grant_without_inspect_is_refused_both_queries_and_still_submits() {
    timeout(WAIT, async {
        let harness = Harness::start(&["default"], false, &[]);
        let mut client = harness.connect().await;
        assert_eq!(
            client.submit("before", "default").await.outcome,
            Outcome::Durable
        );
        let denied = client.stats().await;
        assert_eq!(denied.outcome, InspectOutcome::Unauthorized);
        assert!(denied.stats.is_none());
        // The refusal ends the connection.
        assert!(read_frame(&mut client.0).await.is_err());

        let mut client = harness.connect().await;
        let denied = client.records(0, 10).await;
        assert_eq!(denied.outcome, InspectOutcome::Unauthorized);
        assert!(denied.records.is_empty());
        assert!(read_frame(&mut client.0).await.is_err());

        // Submission is unaffected, and the refused queries read nothing.
        let mut client = harness.connect().await;
        assert_eq!(
            client.submit("after", "default").await.outcome,
            Outcome::Durable
        );
        harness.stop().await;
    })
    .await
    .expect("test exceeded its deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_report_the_spool_after_durable_records() {
    timeout(WAIT, async {
        let harness = Harness::start(&["default"], true, &[]);
        let mut client = harness.connect().await;
        for n in 0..3 {
            let receipt = client.submit(&format!("e{n}"), "default").await;
            assert_eq!(receipt.outcome, Outcome::Durable);
        }
        let reply = client.stats().await;
        assert_eq!(reply.outcome, InspectOutcome::Ok);
        let stats = reply.stats.unwrap();
        assert_eq!(stats.node_id, "node");
        assert_eq!(stats.retained_records, 3);
        assert_eq!(stats.durable_total, 3);
        assert_eq!(stats.durable_through_sequence, 3);
        assert_eq!(stats.acknowledged_through_sequence, 0);
        assert_eq!(stats.rejected_total, 0);
        assert_eq!(stats.max_disk_bytes, 4 * 1_048_576);
        assert!(!stats.poisoned);
        harness.stop().await;
    })
    .await
    .expect("test exceeded its deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn record_pages_cover_every_record_once_and_leave_the_spool_unchanged() {
    timeout(WAIT, async {
        let harness = Harness::start(&["default"], true, &[]);
        let mut client = harness.connect().await;
        for n in 1..=5 {
            client.submit(&format!("e{n}"), "default").await;
        }
        let mut cursor = 0;
        let mut sequences = Vec::new();
        let mut ids = Vec::new();
        loop {
            let page = client.records(cursor, 2).await;
            assert_eq!(page.outcome, InspectOutcome::Ok);
            assert_eq!(page.durable_through_sequence, 5);
            if page.records.is_empty() {
                // Nothing newer: the cursor stays where it was asked from.
                assert_eq!(page.next_after_sequence, cursor);
                break;
            }
            assert!(page.records.len() <= 2);
            sequences.extend(page.records.iter().map(|row| row.sequence));
            ids.extend(event_ids(&page.records));
            cursor = page.next_after_sequence;
        }
        assert_eq!(sequences, [1, 2, 3, 4, 5]);
        assert_eq!(ids, ["e1", "e2", "e3", "e4", "e5"]);
        // Reading acknowledged nothing: the same page is still there.
        assert_eq!(client.records(0, 100).await.records.len(), 5);
        let stats = client.stats().await.stats.unwrap();
        assert_eq!(stats.retained_records, 5);
        assert_eq!(stats.acknowledged_through_sequence, 0);
        harness.stop().await;
    })
    .await
    .expect("test exceeded its deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn records_of_tenants_outside_the_grant_are_hidden_but_the_cursor_passes_them() {
    timeout(WAIT, async {
        // Sequences 1 and 2 belong to another tenant; 3 and 4 are submitted.
        let harness = Harness::start(&["alpha"], true, &[("beta-1", "beta"), ("beta-2", "beta")]);
        let mut client = harness.connect().await;
        client.submit("alpha-1", "alpha").await;
        client.submit("alpha-2", "alpha").await;

        let first = client.records(0, 2).await;
        assert_eq!(first.outcome, InspectOutcome::Ok);
        assert!(first.records.is_empty());
        assert_eq!(first.next_after_sequence, 2);

        let second = client.records(first.next_after_sequence, 2).await;
        assert_eq!(event_ids(&second.records), ["alpha-1", "alpha-2"]);
        assert_eq!(
            second
                .records
                .iter()
                .map(|r| r.sequence)
                .collect::<Vec<_>>(),
            [3, 4]
        );

        let everything = client.records(0, 100).await;
        let ids = event_ids(&everything.records);
        assert_eq!(ids, ["alpha-1", "alpha-2"]);
        assert!(!ids.iter().any(|id| id.starts_with("beta")));
        harness.stop().await;
    })
    .await
    .expect("test exceeded its deadline");
}

#[tokio::test(flavor = "multi_thread")]
async fn out_of_range_queries_are_invalid_and_leave_the_connection_usable() {
    timeout(WAIT, async {
        let harness = Harness::start(&["default"], true, &[]);
        let mut client = harness.connect().await;
        client.submit("e1", "default").await;
        for max_records in [0, 101] {
            let reply = client.records(7, max_records).await;
            assert_eq!(reply.outcome, InspectOutcome::Invalid);
            assert!(reply.records.is_empty());
            assert_eq!(reply.next_after_sequence, 7);
        }
        let reply = client.stats_with_version(VERSION + 1).await;
        assert_eq!(reply.outcome, InspectOutcome::Invalid);
        assert!(reply.stats.is_none());
        // The bound itself is accepted, on the same connection.
        let reply = client.records(0, 100).await;
        assert_eq!(reply.outcome, InspectOutcome::Ok);
        assert_eq!(reply.records.len(), 1);
        harness.stop().await;
    })
    .await
    .expect("test exceeded its deadline");
}
