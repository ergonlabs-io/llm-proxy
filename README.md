# llm-proxy

A high-performance proxy for LLM inference APIs, written in Rust: native token metering
and token-based rate limiting, SSE-first streaming, model-aware routing and provider
fallback, and Gateway API Inference Extension support — without ext_proc sidecar hops.
Runs identically in Kubernetes and non-Kubernetes environments: one static binary, one
YAML file. Speaks standard Envoy configuration and xDS, so it also drops into existing
Envoy/Istio/Envoy Gateway estates unchanged.

**Status: config plane working, data plane not yet.** Both config styles load
end to end — strict parsing with full field-path errors (WP-03), PGV constraint
validation (WP-04), and lowering to the internal IR (WP-05) — for Envoy
bootstrap files (`-c`) and the simple LLM-native dialect (`--config`, WP-38).
`--mode validate` checks a config; `--mode translate` prints the Envoy
bootstrap generated from a dialect file. Serve mode lands with WP-06.

## Documents (local, untracked for now)

- `PLAN.md` — research, architecture, Envoy pain points addressed, scaling model,
  deployment model, product model.
- `IMPLEMENTATION_PLAN.md` — the build broken into work packages (WP-01…WP-36) sized
  for individual devs/subagents, plus the normative Envoy semantics specs (S1–S9:
  route-match precedence, filter iteration, retry timing, resilience defaults).

Read `IMPLEMENTATION_PLAN.md` Part 0 (ground rules) before picking up any work package.

## Workspace layout

```
crates/
  proxy-api            WP-02   generated Envoy v3 protos + descriptor pool
  proxy-config         WP-03..05  bootstrap loading, validation, proto -> internal IR
  proxy-core           WP-06..09  runtimes, listeners, transport sockets, L4 filters
  proxy-http           WP-10..15  codecs, HTTP filter manager, routing, router, retries
  proxy-cluster        WP-15..19  cluster manager, LB, health checks, outlier, pools
  proxy-xds            WP-20..22  ADS client, warming, SDS, delta + file transports
  proxy-observability  WP-23/24   stats (Envoy naming), access logs, response flags
  proxy-admin          WP-25   admin server (/config_dump, /stats, /ready, ...)
  proxy-filters        WP-31..36  non-core filters + the LLM lane (Lane H)
  proxy-simple-config  WP-38   the LLM-native dialect -> Envoy resources lowering
  proxy                          the llm-proxy binary
testing/
  diffrig              WP-26   side-by-side differential harness vs pinned Envoy
  corpus               WP-27   Envoy config corpus + compatibility scorecard
  controlplane         WP-28   scriptable xDS server for integration tests
```

## Life of a request

Every stage is annotated with the owning crate, work package (WP), and normative
spec section (S*) from `IMPLEMENTATION_PLAN.md` — use it to track implementation
progress and to find where a behavior lives.

```text
 ┌────────┐
 │ client │
 └───┬────┘
     │ 1. TCP connect — kernel picks a worker via SO_REUSEPORT;
     │    the connection is PINNED to that worker for life        proxy-core   WP-06
 ┌───▼──────────────────────────────────────────────────────┐
 │ LISTENER (per-worker)                                     │  proxy-core   WP-07
 │  2. listener filters: tls_inspector (SNI/ALPN peek),      │  proxy-core   WP-08
 │     proxy_protocol, original_dst                          │
 │  3. filter-chain match: port → dst IP → SNI → transport   │  proxy-core   WP-07
 │     protocol → ALPN → source (8-step, most-specific-first)│
 └───┬──────────────────────────────────────────────────────┘
     │
 ┌───▼──────────────────────────┐
 │ TRANSPORT SOCKET             │  4. TLS handshake + decrypt  proxy-core   WP-08
 └───┬──────────────────────────┘     (rustls; certs hot-swap via SDS, WP-22)
     │ plaintext byte stream
 ┌───▼──────────────────────────────────────────────────────┐
 │ NETWORK (L4) FILTER CHAIN                                 │  proxy-core   WP-09
 │  5. terminal filter = tcp_proxy (stop here for L4)        │
 │     …or HTTP CONNECTION MANAGER ↓                         │
 └───┬──────────────────────────────────────────────────────┘
     │
 ┌───▼──────────────────────────────────────────────────────┐
 │ HTTP CONNECTION MANAGER                                   │  proxy-http   WP-10
 │  6. h1/h2 codec: bytes → independent HTTP streams         │
 │  7. DECODER FILTER CHAIN (config order)              S2   │  proxy-http   WP-11
 │     e.g. auth / rate limit (WP-31/32),                    │
 │     model router: bounded body peek → cluster        S2.8 │  proxy-filters WP-35
 │  8. ROUTER FILTER (terminal decoder filter)               │  proxy-http   WP-13
 │     route match: vhost domain precedence →           S1   │  proxy-http   WP-12
 │     first-matching route → action (cluster/redirect/      │
 │     direct response), timeouts armed                 S4   │
 └───┬──────────────────────────────────────────────────────┘
     │ cluster name (+ hash policy, priority)
 ┌───▼──────────────────────────────────────────────────────┐
 │ CLUSTER SUBSYSTEM                                         │  proxy-cluster WP-16
 │  9. circuit breakers (open → 503 UO,                 S5   │  proxy-cluster WP-15
 │     x-envoy-overloaded)                                   │
 │ 10. load-balancer host pick                          S7   │  proxy-cluster WP-17
 │     (RR/least-request/ring-hash/Maglev; panic             │
 │      threshold; outlier-ejected hosts excluded S6,        │  proxy-cluster WP-19
 │      health-checked hosts only               WP-18)       │  proxy-cluster WP-18
 │     — or endpoint-picker override (EPP)                   │  proxy-filters WP-36
 │ 11. per-worker conn pool: reuse or connect                │  proxy-cluster WP-15
 │     every attempt wrapped by the RETRY/HEDGE      S3/S4   │  proxy-http   WP-14
 │     engine (jittered backoff, per-try timeouts,           │
 │     never retry after first streamed byte)                │
 └───┬──────────────────────────────────────────────────────┘
     │ upstream codec (WP-10) + upstream TLS (WP-08)
 ┌───▼──────────────────────┐
 │ upstream / LLM provider  │
 └───┬──────────────────────┘
     │ response (often a long-lived SSE stream)
 ┌───▼──────────────────────────────────────────────────────┐
 │ RESPONSE PATH                                             │
 │ 12. ENCODER FILTER CHAIN (REVERSE config order)      S2   │  proxy-http   WP-11
 │     SSE flush-through — no buffering on streamed          │  proxy-filters WP-33
 │     routes; token usage extraction (tail-parse)           │  proxy-filters WP-34
 │ 13. downstream codec writes to client                     │  proxy-http   WP-10
 └───┬──────────────────────────────────────────────────────┘
     │
 14. stream end: stats (Envoy names)                           proxy-observability WP-23
     access log + response flags, TTFT/TPOT GenAI metrics      proxy-observability WP-24 / WP-33
```

WebSocket / realtime sessions follow the same path with three differences (spec S10,
WP-37): the router validates the upgrade and returns 101 (step 8), retries/hedging are
off after 101, and the upgraded byte stream keeps flowing through the filter chain as
data — where the realtime layer does frame-aware token metering and session accounting.
Toward h2 upstreams the upgrade travels as extended CONNECT (RFC 8441).

Configuration reaches the data plane out-of-band (never on the hot path):

```text
 xDS server (gRPC ADS) ─┐
                        ├─► proxy-xds (subscribe, ACK/NACK, warming  S8)   WP-20..22
 watched config files ──┘         │ validated protos
                                  ▼
                        proxy-config (validate → internal IR)              WP-03..05
                                  │ immutable Arc<ConfigSnapshot>
                                  ▼
                        workers swap snapshots atomically (arc-swap);      WP-06
                        in-flight connections keep the old snapshot
                        until they finish — that IS drain semantics
```

## Building

`make help` lists every developer target. The common ones:

```
make build                   # debug build of everything
make test                    # run all tests
make ci                      # what CI enforces: fmt check, clippy -D warnings, tests
make validate                # validate examples/tcp-proxy.yaml through the real loader
make validate CONFIG=x.yaml  # validate your own config
make test-proxy-config       # per-crate pattern: build-/check-/test-<crate>
```

Dialect mode (see `examples/llmproxy.yaml` and `schema/llmproxy-v0.schema.json`):

```
llm-proxy --config llmproxy.yaml --mode validate    # check a dialect config
llm-proxy --config llmproxy.yaml --mode translate   # print the generated Envoy bootstrap
```

Building `proxy-api` requires `protoc` (`brew install protobuf` / `apt install protobuf-compiler`).
