# xds-conformance

`make xds-conformance` runs our real ADS client (`proxy_xds::AdsClient`) against a
real **go-control-plane** server -- the reference implementation -- instead of
`testing/controlplane`'s own puppet `ScriptedAds`. The puppet cannot catch us
agreeing with ourselves about the protocol and both being wrong; this fixture can,
because go-control-plane is a real, independent implementation that a real Envoy
talks to in production.

## What this checks

1. Our client connects and opens `StreamAggregatedResources` against a real
   go-control-plane server.
2. The `node.id` we send is one go-control-plane's snapshot cache actually routes
   on. go-control-plane keys its snapshot cache by node ID (`cachev3.IDHash{}`),
   and its own behavior for an unrecognized node is to simply never reply -- a
   silent hang, not an error. This fixture's snapshot is scoped to exactly one
   node ID (`fixture/main.go`'s `expectedNodeID`), and a `nodeGuard` callback turns
   a wrong or absent ID into an explicit, immediate gRPC error instead of a hang
   (`wrong_node_id_produces_a_named_rejection_not_a_hang`), which is exactly the
   class of bug already found once (our client sending no node
   at all).
3. We receive a CDS response and accept it.
4. go-control-plane observes that acceptance as an ACK, not a NACK -- proven
   indirectly: our validator only ever returns `Verdict::Accept`, and
   `AdsClient::run_once` turns that into an ACK on the wire; there is nothing in
   this fixture that would make go-control-plane's watch resolve at all if it had
   received something it read as a NACK, so the exchange completing is itself the
   proof.

## What this does NOT check

- **LDS, RDS, EDS, or SDS.** The fixture serves one CDS resource. LDS, RDS and SDS are
  outside its scope, and EDS is explicitly deferred.
- **Reconnect, resync, or backoff** (`AdsClient::run`). This fixture
  drives exactly one stream via `AdsClient::run_once`; it does not drop the
  connection or assert on `Reconnect`'s jittered delay.
- **The real binary's wiring** (bootstrap parsing, `ConfigPublisher::publish`,
  `ClusterManager::update_from_snapshot`). See "Why the library route" below.
- **A wrong-node-id run's node-guard rejection landing in `error_detail` in any
  particular shape.** go-control-plane's own server maps a `StreamRequestFunc`
  error to a plain gRPC stream error (a `tonic::Status`); this fixture asserts
  that arrives as *some* explicit error within the timeout, not a specific code
  or message.
- **Multiple concurrent node IDs, snapshot updates over time, or `SetSnapshot`
  being called more than once.** The fixture's snapshot is set once, at startup,
  and never changes.

## Why the library route, not the real binary

Two options were considered: drive `proxy-xds` directly, or boot
the real `llm-proxy` binary against a bootstrap with `dynamic_resources`. This
fixture uses the **library route** (`proxy_xds::AdsClient` directly, the same
public API `crates/proxy-xds/tests/client.rs` already drives against
`testing/controlplane`'s puppet server).

Reasoning: the property this fixture exists to prove is *protocol* agreement with
a third party -- version/nonce bookkeeping, node identity, ACK/NACK semantics --
which lives entirely in `proxy-xds`. Booting the real binary would additionally
exercise bootstrap parsing and the `ConfigPublisher::publish` apply path, which is
real coverage, but it is coverage of *our* wiring, not of whether we agree with
go-control-plane about the wire protocol -- and it would make a protocol-level
failure harder to localize (was it the client, or the bootstrap parser, or the
apply path?). The library route keeps the failure signal narrow: a red run here
means the wire exchange itself disagrees with a real third party.

## The pinned version

**go-control-plane `v0.13.4`** (`fixture/go.mod`'s `require` line and
`fixture/Dockerfile`'s comment). An unpinned reference implementation makes a
future failure ambiguous between "we regressed" and "upstream changed", which
defeats the point of this check. If bumping it, update all three: `go.mod`,
`go.sum` (regenerate with `go mod tidy` inside `fixture/`), and the Dockerfile's
comment.

The Docker build also pins its base images by digest (`golang:1.22-alpine` for
the builder, `gcr.io/distroless/static-debian12:nonroot` for the runtime) --
see `fixture/Dockerfile`.

## Cadence

Preserved from the Makefile's own comment above the `xds-conformance` target,
because AGENTS.md "Coverage" records exactly this shape (`local_openai_smoke.rs`)
quietly going stale for a whole work package while the suite stayed green:

- run it before the v0.3.2 ship gate is declared closed.

An opt-in target nobody runs is worse than no target -- it reads as coverage it
is not providing.

## How to run it

```
make xds-conformance
```

Needs `docker` on `PATH` and a working daemon; the target fails loudly (exit 1,
with the reason) if docker is missing entirely, and each test bounds every wait
with a timeout, so an unreachable registry, a container that never becomes
ready, or a client that never gets a response all fail as a named, readable
error -- never a hang.

Directly, for iterating on the fixture itself:

```
cd testing/xds-conformance
cargo test --test go_control_plane -- --ignored --nocapture --test-threads=1
```

`testing/xds-conformance` is deliberately its OWN Cargo workspace (an empty
`[workspace]` table in its `Cargo.toml`), not a member of the root one, so
`cargo build --workspace` / `make ci` at the repo root cannot see it. It depends
on `proxy-xds`, `proxy-api`, and `proxy-config` by path -- a real dependency on
the real crates, resolved and built independently of the root workspace's own
`Cargo.lock`.

## What actually happened the first time this was run against a real
go-control-plane (2026-09-06)

**`make xds-conformance` does not currently pass, and the fixture is not the
reason.** Both scenarios in `tests/go_control_plane.rs` time out identically:
our client opens the stream (go-control-plane's own log shows
`stream 1 opened`), then never sends its first `DiscoveryRequest` at all, and
never gets a response.

Root cause, confirmed by hand with a minimal reproduction outside this crate:
`AdsClient::run_once` (`crates/proxy-xds/src/client.rs`) calls

```rust
let response = client.stream_aggregated_resources(OutboundStream(rx)).await?;
```

and only sends the initial request *after* that `.await` resolves. Tonic's
generated `stream_aggregated_resources` does not return a `Response` until it
receives the server's response HEADERS frame. `testing/controlplane`'s own
puppet server (built on tonic too) sends that frame the instant its handler
returns `Response::new(stream)`, before it has read anything from the client --
which is why this exact code path has always looked correct against our own
harness. **grpc-go defers sending response headers until the handler's first
outgoing `Send`/`SendHeader` call** (confirmed by reading
`google.golang.org/grpc@v1.67.1`'s `serverStream.SendMsg`/`SendHeader`, and by a
raw `grpc-go` client against this same fixture, which returns instantly because
`StreamAggregatedResources` on the client side does not wait for headers the
way tonic's call does). go-control-plane cannot write a response before it has
read our first request. The two sides deadlock: tonic will not return the
stream handle until it has headers; go-control-plane will not produce headers
until it has our first message; nothing sends that message until tonic returns
the handle.

Manually forcing the initial-request send onto a concurrently `tokio::spawn`ed
task (so it runs while the awaiting future is still pending, rather than
after it resolves) made the full exchange complete in the confirmed
reproduction. That is exactly what `testing/controlplane`'s own sentence at the
top of the Makefile target predicted: *"the one check that catches us agreeing
with ourselves about the protocol and both being wrong. testing/controlplane's
own puppet server cannot do that: we wrote both sides of it."* This fixture
found that.

**Fixed in the same commit that landed this fixture** (`e32bc9d`).
`run_once` now queues every initial request into the outbound channel before
it opens the stream, so they are waiting for tonic to send the moment the
connection is live, and neither side is left waiting on the other. The
comment in `client.rs` at that send site records why the ordering is
load-bearing rather than stylistic.

Confirmed clean teardown on both the failing run above and a docker-unavailable
run: `docker ps -a` shows no leftover containers (each test's `Container` is an
RAII guard that runs `docker rm -f` in `Drop`, so a panicking `assert!` still
tears the container down), and `pgrep -f llm-proxy` is empty (this fixture never
touches the `llm-proxy` binary at all -- see "Why the library route").
