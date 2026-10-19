---
title: xDS conformance
description: "Check the Envoy-mode xDS client against go-control-plane, a reference xDS server. Advanced and contributor material."
summary: An opt-in, docker-based check that runs the real ADS client against
  go-control-plane. What it checks, what it does not check, and how to run it.
lastUpdated: 2026-10-18
related:
  - operations/config-reload
  - configuration/configuration-file
---

# xDS conformance

Use this check to verify the Envoy-mode xDS client against an independent
server. It is for contributors and for operators who change the xDS client or
who want evidence that it speaks the protocol correctly. You do not need it to
run the proxy.

In Envoy mode, llm-proxy can receive its cluster and listener configuration
over xDS/ADS from bootstrap `dynamic_resources`. The `llmproxy` dialect has no
`dynamic_resources`. The command `make xds-conformance` runs the real ADS
client against a real **go-control-plane** server. go-control-plane is the
reference xDS implementation that Envoy deployments use.

## Run the check

```sh
make xds-conformance
```

The check needs `docker` on `PATH` and a running daemon. If docker is
missing, the target fails with exit code 1 and prints the reason. It does not
skip silently. Every wait in the check has a timeout. An unreachable registry,
a container that never becomes ready, or a client that gets no response each
fail with a named error instead of a hang.

To iterate on the check without the `Makefile` wrapper:

```sh
cd testing/xds-conformance
cargo test --test go_control_plane -- --ignored --nocapture --test-threads=1
```

`make ci` does not run this check. It needs docker, and `make ci` stays
hermetic. Run it when you change the xDS client or its transport.

## Why a separate check

The repository also has a scripted test server (`testing/controlplane`). This
project wrote it, so the client and the server can agree with each other and
both be wrong. go-control-plane is an unrelated implementation. Agreement with
it is evidence about the protocol itself.

## What it checks

1. The client connects and opens `StreamAggregatedResources`.
2. The `node.id` that the client sends is one that the go-control-plane
   snapshot cache routes on. An unknown node ID produces a named rejection,
   not a hang.
3. The client receives a CDS (cluster) response and accepts it.
4. go-control-plane sees that acceptance as an ACK, not a NACK.
5. The same exchange works over TLS. go-control-plane terminates TLS with
   `grpc-go` credentials. The client dials through the channel that the
   binary builds from the ADS cluster's `UpstreamTlsContext`. A server
   certificate from a CA that the client does not trust fails the stream
   before the client sends a request.

## What it does not check

- **LDS, RDS, EDS, or SDS.** The check serves one CDS resource.
- **Reconnect, resync, or backoff.** The check drives one stream. It does not
  drop the connection or measure retry timing.
- **The `llm-proxy` binary.** The check drives the client library directly,
  so a failure points at the wire protocol and not at bootstrap parsing or at
  applying a snapshot to the running cluster manager.

## The pinned reference version

The check pins **go-control-plane `v0.13.4`**. A fixed version means a red run
shows a regression in llm-proxy and not a change upstream.
`testing/xds-conformance/README.md` lists the three places that change
together when you update the version.

## Implementation notes

This section is for maintainers.

- The check lives in `testing/xds-conformance`. It is its own Cargo
  workspace, so `cargo build --workspace` and `make ci` at the repository root
  do not build it. It depends on `proxy-xds`, `proxy-api`, `proxy-config`,
  and `proxy-core` by path.
- Dynamic resources are lowered by `convert_dynamic_resources` in
  `crates/proxy-config/src/lower.rs`. The binary wires the client in
  `crates/proxy/src/main.rs`. The TLS channel comes from
  `proxy_core::ads_transport::ads_channel`.
- The first run of this check found a deadlock in `AdsClient::run_once`
  (`crates/proxy-xds/src/client.rs`). `tonic` returns the stream handle only
  after it receives response headers. `grpc-go` sends headers only after it
  reads a first client message. The client now queues its initial requests
  before it opens the stream. The scripted server did not show this, because
  it sends headers at once. `testing/xds-conformance/README.md` has the full
  account.
