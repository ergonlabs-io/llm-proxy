---
title: xDS conformance
summary: An opt-in, docker-based check that runs the real ADS client
  against go-control-plane, the reference xDS implementation, instead of
  our own test harness. What it checks, its current status, and how to
  run it.
last_updated: 2026-09-07
related:
  - ../operations/config-reload/
  - ../configuration/configuration-file/
---

# xDS conformance

llm-proxy can receive its cluster and listener configuration dynamically,
over xDS/ADS, from bootstrap `dynamic_resources`
(`crates/proxy-config/src/lower.rs`'s `convert_dynamic_resources`,
`crates/proxy/src/main.rs`'s ADS client wiring — WP-20). `make
xds-conformance` runs the real client, `proxy_xds::AdsClient`, against a real
**go-control-plane** server — the reference xDS implementation, the same one
a production Envoy talks to — instead of `testing/controlplane`'s own
scripted stand-in.

## Why a separate check

`testing/controlplane`'s puppet server is written by this project, for this
project. It cannot catch a case where our client and our test server agree
with each other about the protocol and are both wrong — the two sides were
never independent. go-control-plane is: an unrelated implementation that
real Envoy deployments already trust, so agreement with it is evidence about
the protocol itself, not just about internal consistency.

## Why it is not part of `make ci`

It needs `docker` and a working daemon, and `make ci` is meant to stay
hermetic. So this is an opt-in target with a stated cadence instead:

- run it before closing WP-20, and
- run it before the v0.3.0 ship gate is declared closed
  (`internal-docs/MILESTONES.md`'s v0.3.0 section names this target as the
  gate's verification).

An opt-in target nobody runs reads as coverage it does not provide — the
Makefile records this reasoning directly above the target, next to the
warning that this project has already lost a whole work package's worth of
coverage to exactly that pattern once (`local_openai_smoke.rs`, an `#[ignore]`d
end-to-end smoke test that had not run since the feature it protected
landed).

## What it checks

1. The client connects and opens `StreamAggregatedResources` against a real
   go-control-plane server.
2. The `node.id` the client sends is one go-control-plane's snapshot cache
   actually routes on — an unrecognized node ID produces an explicit, named
   rejection rather than a silent hang, which is the same class of bug an
   earlier increment already found once (the client sending no node
   identity at all).
3. The client receives a CDS (cluster) response and accepts it.
4. go-control-plane observes that acceptance as an ACK, not a NACK.

## What it does not check

- **LDS, RDS, EDS, or SDS.** The fixture serves one CDS resource only. RDS,
  EDS, and SDS are separate work packages.
- **Reconnect, resync, or backoff.** The fixture drives exactly one stream;
  it does not drop the connection or assert on retry timing.
- **The real `llm-proxy` binary's own wiring** — bootstrap parsing and
  applying a received snapshot to the running cluster manager. The fixture
  drives `proxy_xds::AdsClient` directly so a failure here localizes to the
  wire protocol itself, not to the binary's own plumbing around it.

## Current status: does not pass, and the reason is a real bug, not the fixture

As of the fixture's first real run against go-control-plane (2026-09-06),
**both scenarios time out.** The client opens the stream — go-control-plane's
own log shows it — then never sends its first request, and so never gets a
response.

The confirmed root cause is an ordering problem in
`AdsClient::run_once` (`crates/proxy-xds/src/client.rs`): it awaits the
stream handle from `stream_aggregated_resources` before sending the first
request. `tonic`'s generated client does not return that handle until it
has received the server's response headers, and go-control-plane (built on
`grpc-go`) does not send response headers until it has read a first message
from the client — so each side is waiting on the other, and it deadlocks
every time.

Our own scripted test server (`testing/controlplane`) never surfaced this,
because it sends response headers as soon as its handler starts, before
reading anything from the client — a different, more permissive behavior
than a real `grpc-go` server. This is exactly the failure mode this target
exists to catch: two implementations we control agreeing with each other
and both being wrong. See `testing/xds-conformance/README.md` for the full
account, including the confirmed manual reproduction. Fixing
`AdsClient::run_once`'s send ordering is tracked separately and is not done
as of this writing.

## Running it

```sh
make xds-conformance
```

Needs `docker` on `PATH` and a running daemon. If docker is missing, the
target fails loudly — exit 1, with the reason printed — rather than skipping
silently. Every wait inside the fixture is bounded by a timeout, so an
unreachable registry, a container that never becomes ready, or a client that
never gets a response all fail as a named, readable error instead of hanging
the run.

To iterate on the fixture itself, without the `Makefile` wrapper:

```sh
cd testing/xds-conformance
cargo test --test go_control_plane -- --ignored --nocapture --test-threads=1
```

`testing/xds-conformance` is its own Cargo workspace, not a member of the
root one, so `cargo build --workspace` and `make ci` at the repo root never
see it. It depends on `proxy-xds`, `proxy-api`, and `proxy-config` by path —
the real crates, not a copy.

## The pinned reference version

**go-control-plane `v0.13.4`.** Pinned deliberately: an unpinned reference
implementation would make a future red run ambiguous between "we regressed"
and "upstream changed", which defeats the point of an independent check. If
this version is ever bumped, `testing/xds-conformance/README.md` lists the
three places that must move together.
