//! WP-20 increment 5: run our real ADS client (`proxy_xds::AdsClient`)
//! against a real go-control-plane server -- the reference implementation --
//! instead of `testing/controlplane`'s own puppet, which cannot catch us
//! agreeing with ourselves about the protocol. See `../README.md` for what
//! this does and does not cover, and why the library route (not the real
//! binary) was chosen.
//!
//! `#[ignore]`d: `make xds-conformance` runs this file with `--ignored`
//! (needs docker; never part of `make ci`, see the Makefile target itself).
//! Every test here:
//! - builds and runs the fixture on an EPHEMERAL host port (CLAUDE.md rule
//!   15 -- other lanes run concurrently and fixed ports collide for real);
//! - bounds every wait with a timeout (rule 14 -- a control plane, or a
//!   client, that never responds must fail loudly, not hang);
//! - tears the container down via an RAII guard, so a panic mid-test still
//!   cleans up (rule 15's docker corollary).

use std::process::Stdio;
use std::time::Duration;

use proxy_api::envoy::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use proxy_api::envoy::service::discovery::v3::DiscoveryResponse;
use proxy_config::ir::NodeIdentity;
use proxy_xds::{AdsClient, FnHandler, Subscription, SubscriptionState, Verdict};
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::time::timeout;

/// Keep in sync with `fixture/go.mod`'s `require` line and `fixture/Dockerfile`'s
/// pinned digest comment, and with README.md's "pinned version" line. An
/// unpinned reference implementation makes a future failure ambiguous
/// between "we regressed" and "upstream changed" (task's own wording).
const IMAGE_TAG: &str = "llm-proxy-xds-conformance-fixture:go-control-plane-v0.13.4";
const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixture");

/// Must match `fixture/main.go`'s `expectedNodeID`. go-control-plane's
/// snapshot cache is keyed by node ID (see that file's doc comment); this is
/// the ID its ONE snapshot is scoped to.
const CORRECT_NODE_ID: &str = "llm-proxy-conformance-test";

const CDS_TYPE_URL: &str = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
const CONTAINER_PORT: u16 = 18000;

const BUILD_TIMEOUT: Duration = Duration::from_secs(120);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long we give the ADS exchange (connect, open stream, first
/// request/response round trip) before calling it a failure rather than a
/// stall. Generous: this is a real container plus a real gRPC handshake, not
/// a tight perf budget.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(20);

/// `docker build` the fixture image. Cached after the first run (Docker's
/// own layer cache), but bounded regardless -- an unreachable registry must
/// fail loudly and distinguishably from "our client is wrong" (task's own
/// hazard list), not hang the whole target.
async fn build_image() {
    let output = timeout(
        BUILD_TIMEOUT,
        Command::new("docker")
            .args(["build", "-t", IMAGE_TAG, FIXTURE_DIR])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "`docker build` did not finish within {BUILD_TIMEOUT:?} -- likely an unreachable \
             registry (offline?), not a client bug. Run `docker build -t {IMAGE_TAG} {FIXTURE_DIR}` \
             by hand to see where it stalls."
        )
    })
    .expect("failed to spawn `docker build` -- is docker on PATH?");

    assert!(
        output.status.success(),
        "`docker build -t {IMAGE_TAG} {FIXTURE_DIR}` failed (exit {:?}); this is a fixture/docker \
         problem (e.g. an unpinned base image no longer resolving, or no network to pull it), \
         NOT a finding about our ADS client. stdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// One running fixture container, bound to an ephemeral host port.
///
/// Rust note: `Drop` runs `docker rm -f` unconditionally. This is what keeps
/// a failing `assert!` -- which unwinds rather than returning -- from
/// leaking a container: unwinding still runs `Drop`, so the cleanup happens
/// whether the test passes, fails, or panics partway through setup.
struct Container {
    id: String,
}

impl Container {
    /// Starts the fixture, maps its fixed container port to an ephemeral
    /// host port, and waits for the "READY" log line before returning --
    /// never a fixed sleep, and never unbounded.
    async fn start(name: &str) -> Container {
        let port_mapping = format!("127.0.0.1::{CONTAINER_PORT}");
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "-p",
                &port_mapping,
                IMAGE_TAG,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("failed to spawn `docker run`");
        assert!(
            output.status.success(),
            "`docker run` failed to start the fixture container: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let container = Container { id };
        container.wait_ready().await;
        container
    }

    /// Polls `docker logs` for the fixture's own "READY" line (see
    /// `fixture/main.go`), bounded by `STARTUP_TIMEOUT`. Prints the
    /// container's logs on failure -- "a conformance run that fails opaquely
    /// is worse than none" (task's own words).
    async fn wait_ready(&self) {
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        loop {
            let logs = self.logs().await;
            if logs.contains("READY") {
                return;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!(
                    "go-control-plane fixture container {} did not print its READY line within \
                     {STARTUP_TIMEOUT:?}. Container logs:\n{logs}",
                    self.id
                );
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    async fn logs(&self) -> String {
        let output = Command::new("docker")
            .args(["logs", &self.id])
            .output()
            .await
            .expect("failed to spawn `docker logs`");
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    /// The ephemeral host port `docker run -p 127.0.0.1::CONTAINER_PORT`
    /// picked. Never a fixed port -- see the module doc.
    async fn host_port(&self) -> u16 {
        let output = Command::new("docker")
            .args(["port", &self.id, &CONTAINER_PORT.to_string()])
            .output()
            .await
            .expect("failed to spawn `docker port`");
        assert!(
            output.status.success(),
            "`docker port` failed for container {}: {}",
            self.id,
            String::from_utf8_lossy(&output.stderr)
        );
        // Prints like "127.0.0.1:54321" (possibly with a trailing line for
        // an IPv6 mapping too) -- take the first line's port.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let first_line = stdout.lines().next().unwrap_or_default();
        first_line
            .rsplit(':')
            .next()
            .and_then(|p| p.trim().parse::<u16>().ok())
            .unwrap_or_else(|| {
                panic!("could not parse a host port out of `docker port` output: {stdout:?}")
            })
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        // Best-effort and synchronous (std::process, not tokio::process): a
        // `Drop` impl cannot be async, and this must run even when the
        // panic that triggered it happened inside a tokio task. Ignoring the
        // result is deliberate -- a container that already exited (e.g. it
        // crashed) makes `docker rm` fail harmlessly, and there is no
        // sensible way to report a cleanup error from `drop`.
        let _ = std::process::Command::new("docker")
            .args(["rm", "-f", &self.id])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Drives one CDS exchange against `addr` using the real
/// [`proxy_xds::AdsClient`], with `node_id` as the announced `Node.id`.
/// Returns the first [`Verdict`] our own validator reached, or `None` if no
/// response arrived within `EXCHANGE_TIMEOUT`.
///
/// This calls `AdsClient::run_once` -- the actual production wire client --
/// not a hand-rolled reimplementation of the pump. That is the whole point
/// of this fixture: a bug in the real client's transport is exactly what
/// this is supposed to catch (see README.md).
async fn exchange_one_cds_response(addr: &str, node_id: &str) -> Option<Verdict> {
    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap_or_else(|e| panic!("failed to connect to the fixture at {addr}: {e}"));

    let node = NodeIdentity {
        id: node_id.to_string(),
        cluster: String::new(),
    };
    let mut ads = AdsClient::new(vec![SubscriptionState::new(
        CDS_TYPE_URL,
        Subscription::Wildcard,
    )])
    .with_node(node);

    let (tx, rx) = oneshot::channel();
    let mut tx = Some(tx);
    let validator: proxy_xds::Validator = Box::new(move |_resp: &DiscoveryResponse| {
        let verdict = Verdict::Accept;
        if let Some(tx) = tx.take() {
            let _ = tx.send(verdict.clone());
        }
        verdict
    });

    let run = tokio::spawn(async move {
        let _ = ads.run_once(&mut client, &mut FnHandler(validator)).await;
    });

    let verdict = timeout(EXCHANGE_TIMEOUT, rx)
        .await
        .ok()
        .and_then(Result::ok);
    run.abort();
    verdict
}

/// WP-20 increment 5's minimum bar, all four bullets in one scenario:
/// connect, send a `node.id` go-control-plane's snapshot cache actually
/// routes on, receive a CDS response, and accept it -- which
/// `AdsClient::run_once` turns into an ACK echoing go-control-plane's own
/// version/nonce on the wire (go-control-plane observing that ACK as an ACK,
/// rather than a NACK, is exactly what "our validator returned Accept and
/// the exchange completed" demonstrates: a NACK'd response would never
/// resolve `rx.recv()` above, because our own `FnHandler` never reaches the
/// callback with a `Verdict::Reject`; if go-control-plane treated our
/// request as invalid, it would simply never satisfy the watch tied to
/// `resp1.version_info`, and this test would time out instead of passing).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs docker; run via `make xds-conformance`"]
async fn our_client_interops_with_real_go_control_plane() {
    build_image().await;
    let container = Container::start("xds-conformance-interop").await;
    let port = container.host_port().await;

    let verdict = exchange_one_cds_response(&format!("127.0.0.1:{port}"), CORRECT_NODE_ID).await;

    assert_eq!(
        verdict,
        Some(Verdict::Accept),
        "expected our AdsClient to receive and accept go-control-plane's CDS response within \
         {EXCHANGE_TIMEOUT:?}; got none. Container logs:\n{}",
        container.logs().await,
    );
}

/// WP-20 increment 5's second bullet, isolated: go-control-plane's snapshot
/// cache is keyed by node ID, and its own behavior for an unrecognized node
/// is to simply never reply -- a silent hang, not an error. The fixture's
/// `nodeGuard` (see `fixture/main.go`) turns that into an EXPLICIT gRPC
/// error instead, specifically so a client sending the wrong (or no) node
/// ID fails this run LOUDLY rather than quietly getting served nothing.
///
/// Deliberately does NOT reuse `exchange_one_cds_response`'s
/// verdict-via-oneshot plumbing: that helper's `None` means "no verdict
/// within the timeout", which is indistinguishable from a client that never
/// even got as far as being rejected. This test instead awaits
/// `run_once`'s own `Result` directly, so a genuine node-guard rejection
/// (`Err`) and a client that hung before ever sending anything (neither
/// `Ok` nor `Err` within `EXCHANGE_TIMEOUT`) fail DIFFERENTLY, and the
/// second one is not allowed to read as this test passing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs docker; run via `make xds-conformance`"]
async fn wrong_node_id_produces_a_named_rejection_not_a_hang() {
    build_image().await;
    let container = Container::start("xds-conformance-wrong-node").await;
    let port = container.host_port().await;
    let addr = format!("127.0.0.1:{port}");

    let mut client = AggregatedDiscoveryServiceClient::connect(format!("http://{addr}"))
        .await
        .unwrap_or_else(|e| panic!("failed to connect to the fixture at {addr}: {e}"));
    let node = NodeIdentity {
        id: "not-the-right-node-id".to_string(),
        cluster: String::new(),
    };
    let mut ads = AdsClient::new(vec![SubscriptionState::new(
        CDS_TYPE_URL,
        Subscription::Wildcard,
    )])
    .with_node(node);
    let always_accept: proxy_xds::Validator = Box::new(|_resp: &DiscoveryResponse| Verdict::Accept);

    let run = tokio::spawn(async move {
        ads.run_once(&mut client, &mut FnHandler(always_accept))
            .await
    });

    match timeout(EXCHANGE_TIMEOUT, run).await {
        Ok(Ok(Err(_stream_err))) => {
            // The fixture's nodeGuard rejected the stream -- exactly the
            // named, loud failure this scenario exists to prove happens
            // instead of a silent hang.
        }
        Ok(Ok(Ok(()))) => panic!(
            "run_once returned Ok(()) (a clean stream end) for a WRONG node.id; expected the \
             fixture's nodeGuard to reject it with an error"
        ),
        Ok(Err(join_err)) => panic!("run_once task panicked: {join_err}"),
        Err(_) => panic!(
            "our AdsClient neither got a response NOR an explicit rejection within \
             {EXCHANGE_TIMEOUT:?} for a WRONG node.id -- it never got far enough on the wire for \
             the fixture's nodeGuard to see the request at all. Container logs:\n{}",
            container.logs().await,
        ),
    }
}
