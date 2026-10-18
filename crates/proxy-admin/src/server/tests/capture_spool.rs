//! `/capture/spool/stats` and `/capture/spool/records`, driven over a real
//! admin socket against a fake capture agent on a Unix socket in a private
//! (0700) temp dir. The fake speaks the real frame protocol, so the proxy's
//! real client (handshake, uid check, framing) is what runs.

use std::path::PathBuf;

use proxy_capture_protocol::{
    decode, encode, read_frame, write_frame, InspectOutcome, Kind, RecordsQuery, RecordsReply,
    SpoolSnapshot, SpooledRecord, StatsReply, Welcome, VERSION,
};
use proxy_observability::capture_transport::AgentTransportConfig;
use tokio::net::{UnixListener, UnixStream};

use super::*;
use crate::server::{serve_with_stats_ttl, CaptureAgentProvider, CAPTURE_STATS_TTL};

const NODE: &str = "node-1";
/// Marks the stored record so a test can prove contents reach the caller.
const RECORD_MARKER: &str = "record-marker-3d1f";

/// What the fake agent saw after the handshake, in arrival order.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Stats,
    Records { after: u64, max: u16 },
}

struct FakeAgent {
    _dir: tempfile::TempDir,
    socket: PathBuf,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl FakeAgent {
    /// `outcome` is what every query is answered with.
    fn start(outcome: InspectOutcome) -> Self {
        Self::spawn(outcome, false)
    }

    /// An agent that completes the handshake, then closes on any query, as an
    /// agent predating spool inspection does for the unknown frame kind.
    fn start_closing_on_query() -> Self {
        Self::spawn(InspectOutcome::Ok, true)
    }

    fn spawn(outcome: InspectOutcome, close_on_query: bool) -> Self {
        // `tempdir()` creates the directory 0700, so only this user can reach the socket.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_task = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let seen = Arc::clone(&seen_by_task);
                tokio::spawn(async move {
                    let _ = serve_one(stream, outcome, close_on_query, seen).await;
                });
            }
        });
        Self {
            _dir: dir,
            socket,
            seen,
        }
    }

    fn config(&self) -> AgentTransportConfig {
        config_for(self.socket.clone())
    }

    fn seen(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().unwrap())
    }
}

fn config_for(socket_path: PathBuf) -> AgentTransportConfig {
    AgentTransportConfig {
        socket_path,
        // The fake runs in this process, so its uid is ours.
        expected_agent_uid: UnixStream::pair().unwrap().0.peer_cred().unwrap().uid(),
        expected_node_id: NODE.into(),
        producer_id: "proxy".into(),
    }
}

fn snapshot() -> SpoolSnapshot {
    SpoolSnapshot {
        node_id: NODE.into(),
        next_sequence: 43,
        durable_through_sequence: 42,
        acknowledged_through_sequence: 40,
        pending_records: 2,
        retained_records: 12,
        database_bytes: 1_000,
        disk_bytes: 4_096,
        max_disk_bytes: 8_192,
        quarantine_bytes: 0,
        poisoned: false,
        durable_total: 42,
        rejected_total: 1,
        failures_total: 0,
    }
}

async fn serve_one(
    mut stream: UnixStream,
    outcome: InspectOutcome,
    close_on_query: bool,
    seen: Arc<Mutex<Vec<Seen>>>,
) -> std::io::Result<()> {
    read_frame(&mut stream).await?; // Hello
    let welcome = encode(&Welcome {
        version: VERSION,
        node_id: NODE.into(),
    })?;
    write_frame(&mut stream, Kind::Welcome, &welcome).await?;
    let frame = read_frame(&mut stream).await?;
    if close_on_query {
        return Ok(());
    }
    let ok = outcome == InspectOutcome::Ok;
    match frame.kind {
        Kind::StatsQuery => {
            seen.lock().unwrap().push(Seen::Stats);
            let reply = StatsReply {
                version: VERSION,
                outcome,
                stats: ok.then(snapshot),
            };
            write_frame(&mut stream, Kind::StatsReply, &encode(&reply)?).await
        }
        Kind::RecordsQuery => {
            let query: RecordsQuery = decode(&frame.payload)?;
            seen.lock().unwrap().push(Seen::Records {
                after: query.after_sequence,
                max: query.max_records,
            });
            let reply = RecordsReply {
                version: VERSION,
                outcome,
                records: if ok {
                    (1..=2)
                        .map(|n| SpooledRecord {
                            sequence: query.after_sequence + n,
                            record: serde_json::json!({ "event_id": RECORD_MARKER }),
                        })
                        .collect()
                } else {
                    Vec::new()
                },
                next_after_sequence: query.after_sequence + 2,
                durable_through_sequence: 99,
            };
            write_frame(&mut stream, Kind::RecordsReply, &encode(&reply)?).await
        }
        _ => Ok(()),
    }
}

async fn start_admin(
    admin_token: Option<&str>,
    capture_agent: Option<CaptureAgentProvider>,
) -> (AdminServer, SocketAddr) {
    start_admin_with_ttl(admin_token, capture_agent, CAPTURE_STATS_TTL).await
}

async fn start_admin_with_ttl(
    admin_token: Option<&str>,
    capture_agent: Option<CaptureAgentProvider>,
    stats_ttl: Duration,
) -> (AdminServer, SocketAddr) {
    let config = SnapshotHandles::new().register(snapshot_with_secret());
    let server = serve_with_stats_ttl(
        "127.0.0.1:0".parse().unwrap(),
        AdminRuntime {
            config,
            registry: None,
            started_at: Instant::now(),
            factory_state: Arc::new(SharedFactoryState::default()),
            admin_token: admin_token.map(str::to_string),
            readiness: None,
            cluster_state: None,
            ui: None,
            lifecycle: None,
            credential_probe: None,
            capture_agent,
            ledger: None,
            trace_gate: None,
        },
        stats_ttl,
    )
    .await
    .expect("admin server bind");
    let addr = server.local_addr();
    (server, addr)
}

fn provider(config: AgentTransportConfig) -> Option<CaptureAgentProvider> {
    Some(Arc::new(move || Some(config.clone())))
}

/// Bounded so a wedged agent or server fails the test instead of hanging it.
async fn call(addr: SocketAddr, path: &str, bearer: Option<&str>) -> (StatusCode, String) {
    let (status, _, body) = tokio::time::timeout(
        Duration::from_secs(10),
        request(addr, "GET", path, bearer, ""),
    )
    .await
    .expect("admin request timed out");
    (status, body)
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_returns_the_agents_snapshot() {
    let agent = FakeAgent::start(InspectOutcome::Ok);
    let (_server, addr) = start_admin(None, provider(agent.config())).await;

    let (status, body) = call(addr, "/capture/spool/stats", None).await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["retained_records"], 12);
    assert_eq!(value["durable_through_sequence"], 42);
    assert_eq!(value["poisoned"], false);
    assert_eq!(agent.seen(), [Seen::Stats]);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_and_records_are_404_when_no_agent_is_configured() {
    // No provider at all, and a provider whose declarative endpoint is gone.
    let absent: CaptureAgentProvider = Arc::new(|| None);
    for capture_agent in [None, Some(absent)] {
        let (_server, addr) = start_admin(Some(ADMIN_TOKEN), capture_agent).await;
        let (status, body) = call(addr, "/capture/spool/stats", None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
        assert!(body.contains("no capture agent"), "{body}");
        let (status, body) = call(addr, "/capture/spool/records", Some(ADMIN_TOKEN)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_agent_is_503_json_for_both_endpoints() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_for(dir.path().join("absent.sock"));
    let (_server, addr) = start_admin(Some(ADMIN_TOKEN), provider(config)).await;

    for (path, bearer) in [
        ("/capture/spool/stats", None),
        ("/capture/spool/records", Some(ADMIN_TOKEN)),
    ] {
        let (status, body) = call(addr, path, bearer).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(value["error"].is_string(), "{body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn records_are_refused_without_a_valid_token_and_never_reach_the_agent() {
    let agent = FakeAgent::start(InspectOutcome::Ok);
    let path = "/capture/spool/records";

    // No token configured: refused exactly like the spend read (403).
    let (_server, addr) = start_admin(None, provider(agent.config())).await;
    let (status, body) = call(addr, path, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _) = call(addr, path, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Token configured: missing or wrong bearer is 401.
    let (_server, addr) = start_admin(Some(ADMIN_TOKEN), provider(agent.config())).await;
    let (status, body) = call(addr, path, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    let (status, body) = call(addr, path, Some("not-the-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(!body.contains(RECORD_MARKER));

    assert_eq!(
        agent.seen(),
        [],
        "a refused request must not query the agent"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn records_with_bad_parameters_are_400_and_never_reach_the_agent() {
    let agent = FakeAgent::start(InspectOutcome::Ok);
    let (_server, addr) = start_admin(Some(ADMIN_TOKEN), provider(agent.config())).await;

    for query in [
        "limit=0",
        "limit=101",
        "limit=abc",
        "after=abc",
        "after=-1",
        "after=1&after=2",
        "cursor=5",
    ] {
        let (status, body) = call(
            addr,
            &format!("/capture/spool/records?{query}"),
            Some(ADMIN_TOKEN),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
    }
    assert_eq!(agent.seen(), []);
}

#[tokio::test(flavor = "multi_thread")]
async fn records_forward_after_and_limit_and_return_the_page() {
    let agent = FakeAgent::start(InspectOutcome::Ok);
    let (_server, addr) = start_admin(Some(ADMIN_TOKEN), provider(agent.config())).await;

    let (status, body) = call(
        addr,
        "/capture/spool/records?after=7&limit=100",
        Some(ADMIN_TOKEN),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let value: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(value["records"][0]["sequence"], 8);
    assert_eq!(value["records"][1]["sequence"], 9);
    assert_eq!(value["records"][0]["record"]["event_id"], RECORD_MARKER);
    assert_eq!(value["next_after_sequence"], 9);
    assert_eq!(value["durable_through_sequence"], 99);
    assert_eq!(agent.seen(), [Seen::Records { after: 7, max: 100 }]);

    // Defaults: after 0, limit 50.
    let (status, _) = call(addr, "/capture/spool/records", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(agent.seen(), [Seen::Records { after: 0, max: 50 }]);
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_refusals_map_to_403_with_an_inspect_hint_and_503_otherwise() {
    for (outcome, expected) in [
        (InspectOutcome::Unauthorized, StatusCode::FORBIDDEN),
        (InspectOutcome::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
        (InspectOutcome::Invalid, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let agent = FakeAgent::start(outcome);
        let (_server, addr) = start_admin(Some(ADMIN_TOKEN), provider(agent.config())).await;
        let (status, body) = call(addr, "/capture/spool/records", Some(ADMIN_TOKEN)).await;
        assert_eq!(status, expected, "{outcome:?}: {body}");
        if outcome == InspectOutcome::Unauthorized {
            let value: serde_json::Value = serde_json::from_str(&body).unwrap();
            let hint = value["error"].as_str().unwrap();
            assert!(hint.contains("\"inspect\": true"), "{hint}");
        }
        assert!(!body.contains(RECORD_MARKER));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_that_closes_on_the_query_is_501_with_an_upgrade_hint() {
    let agent = FakeAgent::start_closing_on_query();
    let (_server, addr) = start_admin(Some(ADMIN_TOKEN), provider(agent.config())).await;
    for (path, bearer) in [
        ("/capture/spool/stats", None),
        ("/capture/spool/records", Some(ADMIN_TOKEN)),
    ] {
        let (status, body) = call(addr, path, bearer).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "{path}: {body}");
        assert!(body.contains("upgrade the capture agent"), "{path}: {body}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_query_outcome_says_so_instead_of_claiming_the_agent_is_unavailable() {
    let agent = FakeAgent::start(InspectOutcome::Invalid);
    let (_server, addr) = start_admin(Some(ADMIN_TOKEN), provider(agent.config())).await;
    let (status, body) = call(addr, "/capture/spool/records", Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("rejected the query as invalid"), "{body}");
    assert!(!body.contains("unavailable"), "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_are_single_flight_cached_so_a_flood_costs_one_agent_query() {
    let agent = FakeAgent::start(InspectOutcome::Ok);
    // A long TTL makes "within the window" deterministic on a loaded box.
    let (_server, addr) =
        start_admin_with_ttl(None, provider(agent.config()), Duration::from_secs(3600)).await;

    let concurrent: Vec<_> = (0..8)
        .map(|_| tokio::spawn(call(addr, "/capture/spool/stats", None)))
        .collect();
    for task in concurrent {
        let (status, body) = task.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.contains("\"retained_records\":12"), "{body}");
    }
    for _ in 0..4 {
        let (status, _) = call(addr, "/capture/spool/stats", None).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        agent.seen(),
        [Seen::Stats],
        "twelve requests inside the window must cost exactly one agent query"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_are_queried_again_once_the_cache_window_has_passed() {
    let agent = FakeAgent::start(InspectOutcome::Ok);
    // A zero TTL is "always expired": the second GET is after the window.
    let (_server, addr) =
        start_admin_with_ttl(None, provider(agent.config()), Duration::ZERO).await;
    for _ in 0..2 {
        let (status, _) = call(addr, "/capture/spool/stats", None).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(agent.seen(), [Seen::Stats, Seen::Stats]);
}

#[tokio::test(flavor = "multi_thread")]
async fn records_are_not_cached() {
    let agent = FakeAgent::start(InspectOutcome::Ok);
    let (_server, addr) = start_admin_with_ttl(
        Some(ADMIN_TOKEN),
        provider(agent.config()),
        Duration::from_secs(3600),
    )
    .await;
    for _ in 0..2 {
        let (status, _) = call(addr, "/capture/spool/records", Some(ADMIN_TOKEN)).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(agent.seen().len(), 2);
}
