//! `/ledger/entries` and `/ledger/ack` (ADR-0009 decision 8), driven over a
//! real admin socket against a real ledger writer and encrypted spool in a
//! temp dir. What the writer commits, holds or reclaims is tested with the
//! writer (`proxy-observability`'s `ledger_tests.rs`); these tests own the
//! HTTP contract: the gate, strict parameters, and the response shape.

use proxy_observability::ledger::testing::{record, TempLedger, INSTANCE_ID};
use proxy_observability::ledger::{LedgerTicket, OnUnavailable};
use proxy_observability::records::LedgerCharge;

use super::*;
use crate::server::serve;

async fn start_admin(admin_token: Option<&str>, ledger: Option<&TempLedger>) -> AdminServer {
    serve(
        "127.0.0.1:0".parse().unwrap(),
        AdminRuntime {
            config: SnapshotHandles::new().register(snapshot_with_secret()),
            registry: None,
            started_at: Instant::now(),
            factory_state: Arc::new(SharedFactoryState::default()),
            admin_token: admin_token.map(str::to_string),
            readiness: None,
            cluster_state: None,
            ui: None,
            lifecycle: None,
            credential_probe: None,
            capture_agent: None,
            ledger: ledger.map(|l| Arc::clone(&l.ledger)),
        },
    )
    .await
    .expect("admin server bind")
}

/// A ledger holding `n` committed entries, `event-0` .. `event-{n-1}`.
fn ledger_with(n: usize) -> TempLedger {
    let ledger = TempLedger::open(16, OnUnavailable::Reject);
    for i in 0..n {
        let Ok(LedgerTicket::Reserved(slot)) = ledger.ledger.admit() else {
            panic!("no slot");
        };
        slot.append(record(&format!("event-{i}")), LedgerCharge::default());
    }
    // Committed entries give their slots back.
    for _ in 0..1000 {
        if ledger.ledger.reserved() == 0 {
            return ledger;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("entries were never committed");
}

/// Bounded so a wedged writer or server fails the test instead of hanging it.
async fn call(
    addr: SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: &str,
) -> (StatusCode, String) {
    let (status, _, body) = tokio::time::timeout(
        Duration::from_secs(10),
        request(addr, method, path, bearer, body),
    )
    .await
    .expect("admin request timed out");
    (status, body)
}

async fn events(addr: SocketAddr, query: &str) -> Vec<String> {
    let (status, body) = call(
        addr,
        "GET",
        &format!("/ledger/entries{query}"),
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page: serde_json::Value = serde_json::from_str(&body).unwrap();
    page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["record"]["event_id"].as_str().unwrap().to_owned())
        .collect()
}

/// A page carries each entry's own fields and its cursor; `next_after` is
/// what the next pull passes, and an ack through a cursor removes every
/// entry up to it.
#[tokio::test(flavor = "multi_thread")]
async fn entries_are_paged_by_cursor_and_an_ack_removes_them() {
    let ledger = ledger_with(3);
    let server = start_admin(Some(ADMIN_TOKEN), Some(&ledger)).await;
    let addr = server.local_addr();

    let (status, body) = call(
        addr,
        "GET",
        "/ledger/entries?after=0&limit=2",
        Some(ADMIN_TOKEN),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let page: serde_json::Value = serde_json::from_str(&body).unwrap();
    let entries = page["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["cursor"], 1);
    assert_eq!(entries[0]["seq"], 0);
    assert_eq!(entries[0]["instance_id"], INSTANCE_ID);
    assert!(entries[0]["epoch"].as_u64().unwrap() > 0);
    assert_eq!(entries[0]["record"]["event_id"], "event-0");
    assert_eq!(page["next_after"], 2);
    assert_eq!(page["committed_through"], 3);
    assert_eq!(events(addr, "?after=2").await, ["event-2"]);

    let (status, body) = call(addr, "POST", "/ledger/ack?through=2", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ack: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(ack["acknowledged_through"], 2);
    assert_eq!(ack["admitting"], true);
    assert_eq!(events(addr, "").await, ["event-2"]);

    let (status, body) = call(addr, "POST", "/ledger/ack?through=9", Some(ADMIN_TOKEN), "").await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("past the last committed entry"), "{body}");
    server.abort();
}

/// Both endpoints sit behind the shared admin gate and fail closed: 403 with
/// no token configured, 401 for a missing or wrong bearer. A refused ack
/// removes nothing, and a refused read returns no entry.
#[tokio::test(flavor = "multi_thread")]
async fn both_endpoints_refuse_without_a_valid_bearer() {
    let ledger = ledger_with(1);
    let unset = start_admin(None, Some(&ledger)).await;
    let gated = start_admin(Some(ADMIN_TOKEN), Some(&ledger)).await;
    for (method, path) in [
        ("GET", "/ledger/entries"),
        ("POST", "/ledger/ack?through=1"),
    ] {
        let (status, body) = call(unset.local_addr(), method, path, Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        for bearer in [None, Some("not-the-token")] {
            let (status, body) = call(gated.local_addr(), method, path, bearer, "").await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}: {body}");
            assert!(!body.contains("event-0"), "{body}");
        }
    }
    assert_eq!(events(gated.local_addr(), "").await, ["event-0"]);
    unset.abort();
    gated.abort();
}

/// Unknown, repeated, malformed or out-of-range parameters are a 400, never
/// ignored, and a refused ack removes nothing. A body on the ack is refused
/// too: `through` is a query parameter only.
#[tokio::test(flavor = "multi_thread")]
async fn bad_parameters_are_400_and_change_nothing() {
    let ledger = ledger_with(1);
    let server = start_admin(Some(ADMIN_TOKEN), Some(&ledger)).await;
    let addr = server.local_addr();
    for query in [
        "limit=0",
        "limit=1001",
        "limit=abc",
        "after=abc",
        "after=-1",
        "after=1&after=2",
        "cursor=5",
    ] {
        let path = format!("/ledger/entries?{query}");
        let (status, body) = call(addr, "GET", &path, Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {body}");
    }
    for (query, body) in [
        ("", ""),
        ("through=", ""),
        ("through=abc", ""),
        ("through=1&through=1", ""),
        ("through=1&after=0", ""),
        ("through=1", r#"{"through":1}"#),
    ] {
        let path = format!("/ledger/ack?{query}");
        let (status, text) = call(addr, "POST", &path, Some(ADMIN_TOKEN), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query} {body}: {text}");
    }
    assert_eq!(events(addr, "").await, ["event-0"]);
    for (method, path) in [
        ("POST", "/ledger/entries"),
        ("GET", "/ledger/ack?through=1"),
    ] {
        let (status, _) = call(addr, method, path, Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path}");
    }
    server.abort();
}

/// With no ledger configured both endpoints say so with a 404, after the
/// gate, rather than an empty page that reads as nothing to bill.
#[tokio::test(flavor = "multi_thread")]
async fn without_a_ledger_both_endpoints_are_404() {
    let server = start_admin(Some(ADMIN_TOKEN), None).await;
    for (method, path) in [
        ("GET", "/ledger/entries"),
        ("POST", "/ledger/ack?through=1"),
    ] {
        let (status, body) = call(server.local_addr(), method, path, Some(ADMIN_TOKEN), "").await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
        assert!(body.contains("no billing ledger"), "{body}");
        let (status, _) = call(server.local_addr(), method, path, None, "").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "gate first: {path}");
    }
    server.abort();
}
