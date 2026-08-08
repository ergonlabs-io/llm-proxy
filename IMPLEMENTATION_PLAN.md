# Detailed Implementation Plan — Envoy-Compatible Rust Proxy

Companion to [PLAN.md](PLAN.md) (research + phasing). This document decomposes the build into
**work packages (WPs)** sized for individual devs/subagents, and pins down the **normative
semantic specifications** (Appendices S1–S9) that live in Envoy's C++ rather than its protos —
route-match precedence, filter iteration, retry timing, resilience defaults. The spec sections
are extracted from Envoy's source (`envoy/http/filter.h`), the v3 API protos
(`route_components.proto`, `outlier_detection.proto`), and the router filter docs, and are
**binding** on implementations: a WP is not done until its acceptance tests pass against the
relevant spec section *and* the differential rig (WP-26).

---

## Status (updated 2026-08-01)

**904 tests green workspace-wide, 0 failed, 21 ignored.** `make ci` clean. Branch
`data-plane-foundations`, not pushed (no remote configured).

> Count them with `cargo test --workspace --no-fail-fast` — plain `--workspace` fail-fasts
> and undercounts.

**🚢 v0.0.1 — "First light" — SHIPPED 2026-08-01. The live milestone is met.** The
`#[ignore]`d smoke test in `testing/diffrig/tests/live_smoke.rs` was run against the real
OpenAI and Anthropic endpoints and **passed all four cases** (both providers, streaming and
non-streaming) on the first attempt. A client request now traverses dialect config → cluster
with upstream TLS → SNI → certificate verification → auth-header injection → h1 → real SSE
streaming back, **against real providers**, and returns the response unmodified. See
`CHANGELOG.md` and `docs/MILESTONES.md`; tagged `v0.0.1`.

Those tests stay `#[ignore]`d permanently — they bill real tokens and CI holds no keys — so
this gate's evidence is a deliberate manual run, not a CI green.

**The hermetic end-to-end milestone was the precondition and remains the daily gate.** The
same path runs in `make ci` against OpenAI- and Anthropic-shaped mock providers with no
network, no API keys, no docker, and no `#[ignore]`. The negative control (wrong `ca_file` →
503, not 200) is what makes it proof rather than decoration.

**Read the clean first run correctly.** The expectation was that the first real round-trip
would expose defects — a path that has never carried a real request has never been tested,
and that lesson had already cost two `StreamInfo` bugs found only at socket level. It
exposed none. That says the mock tier modeled both providers accurately; it does *not* say
the path is proven under load, concurrency, provider error shapes, or long streams, none of
which are in the gate. Coverage therefore stays three-tiered: our mocks (`mock_e2e.rs`), a
real third-party server (`local_openai_smoke.rs`, Ollama), and real providers
(`live_smoke.rs`).

**Current milestone is now v0.1.0 — LLM gateway** (WP-33 remainder, WP-34, WP-35, WP-45,
WP-14).

| WP | Title | State |
|---|---|---|
| WP-01 | Repo scaffolding & CI | ✅ done (ADR-0001/0002 seeded, CI config in `.github/workflows/ci.yml`) |
| WP-02 | `proxy-api` protos + descriptor pool | ✅ done — 5 tests |
| WP-03 | Bootstrap loader | ✅ done — corpus-runner acceptance deferred to WP-27 |
| WP-04 | Validation engine (PGV) | ✅ done — Envoy-error-string fixtures deferred to WP-26 |
| WP-05 | Internal IR + proto→IR | ✅ done (S1 domain index, surface check, precomputed matchers) |
| WP-38 | Simple config dialect | ✅ done — `--config` / `--mode translate` wired into the binary; provider lowering now emits Anthropic's default `anthropic-version` and a SAN matcher per provider host |
| WP-06 | Runtimes + config propagation + drain | 🔶 functionally done — pool/drain/serve + SIGTERM + Envoy CLI; formal close waits on the swap-under-load differential gate (needs the WP-26 traffic rig) |
| WP-07 | Listener manager + filter-chain matching | ✅ done — IR criteria + 9-step matcher + SO_REUSEPORT per-worker binds; initial binds fatal, reconcile binds log-and-skip |
| WP-08 | Transport sockets (TLS) + listener filters | ✅ done — downstream termination (dual-cert hot-reload resolver, SAN/mTLS/expired-cert verifiers), `tls_inspector` ClientHello peek → SNI/ALPN matching, **and upstream TLS now live at runtime** (see WP-15) |
| WP-09 | Network filter framework + `tcp_proxy` | ✅ done — deadlock-free bidirectional pump with half-close FIN propagation and idle timeout; serves plaintext and TLS-terminated streams |
| WP-10 | h1/h2 codecs | 🔶 downstream h1 + `StreamHandler` seam + listener wiring + **upstream h1 (`send_upstream_http1`) and upstream h2 (`send_upstream_http2`)** done, with dispatch selected by `UpstreamProtocol`. **Downstream h2 and upgrades (S10) outstanding** |
| WP-11 | HTTP filter manager (S2) | 🔶 chunks 1–3 done (S2.1 ordering, S2.2/S2.3 hold+resume, S2.5 local replies through the encoder chain, S2.7 buffer APIs, streaming encode). The chunk-2 conformance suite found one real S2.5 bug, now fixed. **Chunk 4 outstanding** — `ContinueAndDontEndStream`, watermark backpressure, StopAll out-of-band resume, decode trailer-hold, `inject_*_data_to_filter_chain` (**panics if a filter calls it today**), 1xx (S2.6), route cache (S2.8) |
| WP-12 | Route table & matching engine (S1) | ✅ done — 36 tests built through real YAML lowering; regexes anchored at config-compile time |
| WP-13 | Router filter & upstream lifecycle | 🔶 route → cluster → LB pick → S5 permit → pool → TLS → h1/h2 → response back through the encode chain. **S9 request transforms are now complete** — XFF, `x-request-id`, `:authority`, `prefix_rewrite`/`host_rewrite`, **and `request_headers_to_add` (see the P0 below)**. **S4 timeouts** (route `timeout` bounding the whole attempt loop, `idle_timeout`, per-try, `x-envoy-expected-rq-timeout-ms`) landed. **Outstanding**: maintenance-mode check, `x-envoy-upstream-service-time`, `x-envoy-attempt-count` (needs an IR field), all of upgrade routing (S10.1), redirects (501), file-sourced `direct_response` (500), HCM `stream_idle_timeout` inheritance, and the lifecycle differential suite — which is gated on access-log response flags (WP-24) |
| WP-14 | Retry & hedging engine (S3) | 🔶 **engine built AND wired.** `retry.rs` (26 tests) + a real attempt loop in `router.rs`: per-attempt CB permit and host re-pick, outcome classification, S3.3 fully-jittered exponential backoff, S3.4 body-replay buffering (only when a policy exists, so retry-free routes keep the zero-copy path), and the **S4.2 per-try timeout** armed fresh per attempt. **Outstanding**: `x-envoy-max-retries` header override, S5.2 retry *budgets* (20% default, `min_retry_concurrency` 3), the previously-attempted-host predicate, **hedge-on-per-try-timeout (half this WP's title)**, and the differential chaos suite. Two knobs the router cannot honor are now **rejected at config load** rather than silently dropped: `host_selection_retry_max_attempts > 1` and `retry_on: envoy-ratelimited` |
| WP-15 | Upstream conn pools + circuit breakers | 🔶 **upstream TLS done** — the pool dials TCP then hands off to a per-cluster `UpstreamTransportSocket` (rustls client handshake, SNI + ALPN derived from `UpstreamProtocol`); `UpstreamStream.io` is a boxed transport and `UpstreamTlsSpec` is consumed at cluster build. A cluster with a `transport_socket` and no registered builder is a **fatal startup error**, never a plaintext downgrade. **S5 `max_requests` circuit breaker** enforced in the router. **Outstanding**: real connection reuse — still connect-per-stream, so `UO`/`UR` overflow paths exist but rarely fire. Note this also caps the WP-30 rig at ~8k streams (two ephemeral ports per stream), so pooling and the capacity work compound |
| WP-16 | Cluster manager + discovery | ✅ done — `HostSet` snapshots + diffing, `HostResolver` seam, STATIC/STRICT_DNS/LOGICAL_DNS, warming via `is_initialized`/`force_initialize`. **EDS is a manager-level stub only** (the IR has no `Eds` variant — see WP-21) |
| WP-17 | Load balancers (S7) | ✅ done — `RoundRobinLb` (nginx SWRR), `RandomLb`, `LeastRequestLb` (P2C), `HostPicker` (priority spillover + 50% panic + host override); ring-hash/Maglev rejected at **config** time pending an Envoy differential hashing harness |
| WP-24 | Access logging | 🔶 **config + formatter + sink done; nothing emits.** IR, lowering for `FileAccessLog`/`StdoutAccessLog`/`StderrAccessLog`, a `parse_format`/`render` command-operator engine, and now the **writer**: `AccessLogWriter` + stdout/stderr/file sinks, logrotate `reopen()`, and a registry that dedups file sinks by canonical path. `write_line` returns no `Result` — a broken log destination must never fail a request. **Outstanding (chunk 3)**: the router populates no response flags, and nothing calls the sink. **This is the card closest to done, and WP-13's differential suite is gated on it** |
| WP-26 | Differential rig | 🔶 upstreams (echo/flaky/slow/**OpenAI chat**/**OpenAI Responses**/**Anthropic Messages**, real SSE pacing) + scenario model + **config-validation differential vs real Envoy v1.38.0** (docker-gated; `make ci` stays docker-free). Latest run: 3 agree-accept, 2 agree-reject, 3 gap-we-reject, **0 bug-we-accept**. **Now also hosts the hermetic TLS e2e** (rcgen CA + `tokio-rustls` mock providers, RFC 6761 `*.test.localhost` for hermetic DNS, dual-stack loopback binds, wrong-CA negative control). **The `#[ignore]`d live smoke test is written AND RUN** — 4 cases against real OpenAI/Anthropic endpoints, keys from env, all passing 2026-08-01; this is what shipped v0.0.1. **Outstanding**: HTTP traffic-replay topology (which also closes WP-06's swap-under-load gate — the only thing keeping Lane B from complete) |
| WP-27 | Config corpus + scorecard | 🔶 17 real Envoy v1.38.0 bootstraps harvested with provenance; **3/20 (15.0%)**, all rejections carrying full field paths and **zero parse errors**. Vendoring the access-log protos moved four fixtures off an opaque `Any`-decode failure onto their real next gap |
| WP-28 | Control-plane xDS harness | 🔶 ScriptedAds SotW puppet + ACK/NACK request log |
| WP-30 | Perf benchmarks | 🔶 **phases 1+2.** Open-loop coordinated-omission-aware driver, SSE parsing, hdrhistogram latency/TTFT/TPOT; plus a process sampler (RSS/CPU/fds, macOS + Linux, explicit error rather than zeros on an unsupported platform), a ramp-hold-bisect concurrency sweep with a multi-clause SLO gate, and a capacity table with a least-squares cost model (bytes/stream, CPU-ms/request). **The rig detects and reports its own ceilings** — ~8k streams here from the ephemeral port range — and marks a run harness-bound rather than passing it off as proxy capacity. **Outstanding**: the Linux `/proc` sampler path is written to spec but unverified (no Linux box), and the plan's Nighthawk/fortio comparison |
| WP-34 | Token metering (Lane H) | ✅ **extraction done** — `proxy-filters/src/usage.rs` meters OpenAI chat completions, **OpenAI Responses**, and Anthropic Messages across four separately-priced buckets, streaming and non-streaming; all previously-ignored acceptance tests now pass. **Not yet wired as an `HttpFilter`** — that's WP-33 |

Lane A is complete: both config front-ends load end to end (strict parse → PGV → IR), and
`--mode validate` / `--mode translate` work in the binary. Per Part 0 #5, the differential-rig
gates for WP-03/04/38 remain open until WP-26/27 mature — tracked there, not here.

**A real request is proxied end to end, over TLS, through the filter chain.** A connection
matched to an `http_connection_manager` chain is handed to the h1 codec over its real socket;
its `http_filters` chain is built once at bind time from a shared `FilterRegistry` (a `type_url`
with no registered factory is a **fatal bind error**, never a silent skip); the router matches a
route, picks a host, acquires an S5 `max_requests` permit, dials the cluster's transport socket
(plaintext or rustls with SNI/ALPN), speaks h1 or h2 upstream per config, and streams the
response back through the encode chain. Error→status parity is wired: `NR`→404,
`NC`/`UH`/`UF`/`UO`/`UR`→503 (`UO` adds `x-envoy-overloaded`), upstream codec error→502.

**Two upstream-certificate-verification holes were found and fixed in the dialect** while
landing upstream TLS. A provider with no `ca_file` emitted no validation context at all, which
rustls-side meant *accept any server certificate*; and the `ca_file` path verified chain trust
without verifying identity. Both branches now emit a validation context (`trusted_ca` or
`system_root_certs`) **and** a DNS-exact SAN matcher on the provider host. Envoy-mode parity is
deliberately unchanged: Envoy really does default to accept-any, and `trusted_ca` alone really
does skip hostname verification — the fix belongs in the dialect, which is our own surface.

**A P0 found on 2026-07-25, worth recording because of how it hid.** `request_headers_to_add` was
lowered onto `RouteEntry` by *both* config front-ends and read by **nothing**. It is how the simple
dialect injects the provider API key, `anthropic-version`, and every `extra_header`, so every request
reached its provider with no credentials — and the live e2e milestone was unreachable. It survived a
full plan audit earlier the same day because the status notes asserted it worked, and it looked
correct from every angle except the one that mattered: config parsed, validated, translated, and
then evaporated. It was found only because an end-to-end test's mock *required* the header and
returned 401, and the agent that hit it reported a product bug instead of relaxing its assertion.
Two lessons are now encoded as work items (WP-39) and a test-harness fix: a lowered IR field with no
runtime reader is invisible to every check the project had, and a test that can validate a **stale
binary** can go green while the code is broken.

### Strategy change, 2026-07-26 — the L7 floor is reached; pivot to the LLM layer

The data plane can now serve real traffic end to end. That was the precondition, and it has been
met, so **the center of gravity moves from Envoy parity to the LLM layer** — Lane H is the reason
this project exists, and it is currently two files (`proxy-filters/{lib,usage}.rs`).

The honest framing: measured against the north star — *a performant proxy/gateway for LLM traffic*
— nearly everything shipped so far would be identical if the goal were "gateway for gRPC
microservices." That work is real and load-bearing, and the Envoy-compatible surface is the
on-ramp. But it is the substrate, not the product. Two fields the dialect currently **rejects**
with clean errors, `limits` and `fallbacks`, are exactly the two things a user would name first
when asked why they want an LLM gateway at all. Rejecting them was correct under ground rule #2;
it is also the schema pointing at the hole.

Second gap, of a different kind: **"performant" is an untested claim.** `testing/loadgen` is built
and coordinated-omission-aware, but no capacity sweep has been run and published. There is no p99
under load, no tokens/sec ceiling, no memory profile for many concurrent long-lived streams — and
that traffic shape (high connection count, low request rate per connection, multi-minute streams,
large bodies) is not exercised anywhere in the suite. A north star that leads with *performant*
needs a number, even a bad one, because a baseline is also what makes regressions visible.

**Next up, in priority order** (P0 first, then P1 by leverage):

1. **WP-33 — wire `usage.rs` in as an encode filter (P0).** Converts the LLM layer from library
   code into a working feature and is the foundation for metering *and* token-based limits. This is
   the single step that starts making us an LLM gateway. Owner's Lane H — confirm it is moving,
   since it is now the critical path to the differentiator.
2. **WP-34 token-based rate limiting / WP-35 model routing + provider fallback (P0)** — i.e. make
   the dialect's rejected `limits` and `fallbacks` real. First genuinely LLM-native features.
3. **WP-30 — run one capacity sweep and publish the numbers (P1).** Turns *performant* from
   aspiration into a baseline. Include the LLM traffic shape, not just RPC-shaped load.
4. **WP-11 chunk 4 (P1)** — `inject_*_to_filter_chain` **panics the worker** if any filter calls
   it: a live landmine directly under the Lane H filter work in items 1–2. *(In flight.)*
5. **WP-24 chunk 3 (P1)** — response flags + emit; **WP-13's lifecycle differential suite is gated
   on it**. *(In flight.)*
6. **WP-15 real pooling (P1)** — h1 keep-alive reuse. Compounds with WP-30: connect-per-stream is
   what caps the rig at ~8k streams, and long-lived LLM streams make pooling matter more, not less.
7. **WP-26 live smoke (P1)** — `#[ignore]`d, keys from env; the hermetic e2e and its auth-header
   blocker are both done. Deferred by the owner, small whenever picked up.
8. **WP-14 remainder (P1)** — hedging especially: tail latency is the LLM-serving problem.
9. **P2 parity backlog** — xDS (WP-20/21/22), admin (WP-25), corpus (WP-27), filters (WP-31/32),
   downstream h2 + S10 upgrades, the six S1 match extensions. **Not cancelled** — see the Part 0
   priority scale. WP-37 (Realtime/WebSocket) is P2 only because it is blocked on S10.

**New cross-cutting items identified 2026-07-25 (WP-39, WP-40 in Part 2).** WP-39 makes the
lowered-but-unread class of bug detectable instead of relying on someone thinking to grep; WP-40 is
the dependency-tree review the owner asked for after the access-log sink hit a real cycle constraint.

Also outstanding: downstream h2 + upgrades (S10); six S1 IR extensions (`path_separated_prefix`,
`query_parameters`, header range/contains, `invert_match`, `runtime_fraction`, `grpc`);
`manager.rs`'s unconsumed `LbError` from `update_from_snapshot`; `HttpConnectionManagerConfig`'s
`access_logs` and `stat_prefix`, which are both accepted-but-inert today (WP-24 chunk 3 and WP-23
respectively close them — until then they are the two known survivors of the WP-39 sweep); and one
Linux smoke run for WP-30's `/proc` sampler.

---

## Part 0 — Ground rules (read before starting any WP)

1. **Pinned reference version.** All semantics, protos, and differential tests target **Envoy
   v1.38 / xDS v3** (pin the exact `envoyproxy/envoy` release tag in `proxy-api`; pin the same
   Envoy docker image digest in the differential rig). Nobody "upgrades Envoy" inside a feature WP.
2. **Strict config mode is the default.** Any bootstrap/xDS field we have not implemented →
   load error (static) or NACK (xDS) with the full field path in the message. `--permissive`
   downgrades to a warning. **Silently ignoring a field is a P0 bug.**
3. **The data plane never touches protobuf types.** Protos exist only in `proxy-config`
   (parse/validate/convert) and `proxy-xds` (transport). Everything else consumes the internal
   IR (WP-05). This keeps hot-path types compact and lets IR evolve independently.
4. **Interface-first development.** WP-02…WP-06 define the traits and IR types everything else
   codes against. Later WPs must not change shared trait signatures unilaterally — propose the
   change, get it reviewed, land it as its own commit.
5. **Every WP lands with tests.** Unit tests in-crate; each WP's acceptance criteria name the
   differential/integration tests that must pass. A WP that only compiles is not done.
6. **When docs and Envoy behavior disagree, behavior wins** — capture it in the differential
   rig as a pinned fixture and note the divergence in `docs/envoy-divergences.md`.
7. **Defaults marked ✅ below were verified against Envoy docs/source during planning.**
   Anything marked ⚠️ must be re-verified against the pinned version docs by the implementing
   dev before coding (they are high-confidence but were not re-checked this pass).
8. **Every WP carries a priority** (added 2026-07-26). Priority answers *"what does this buy the
   product?"*, and is independent of Size (cost) and State (progress). It is set here, in the plan
   — not improvised per batch — so that the ordering survives context loss and hand-offs.

### Priority scale

| P | Meaning | Test |
|---|---|---|
| **P0** | **Product-defining.** The LLM gateway itself. Without these we are a general-purpose proxy that happens to carry LLM bytes. | Would a user choose us over nginx/Envoy *because of this*? |
| **P1** | **Serving-critical.** Required to run real production traffic safely, observably, and provably fast — regardless of which features sit on top. | Would we be negligent to serve traffic without it? |
| **P2** | **Envoy parity / breadth.** The compatibility moat and the long tail of extensions. Strategically important, rarely urgent. | Does this widen the set of configs/deployments we can accept? |
| **P3** | **Deferred.** Known, sized, deliberately not scheduled. | — |

**P2 is a commitment, not a graveyard.** Standing shoulder-to-shoulder with Envoy on
configuration surface is the project's on-ramp: it is what lets a team point an existing
bootstrap at us and what makes the LLM features reachable without a migration. The 2026-07-26
re-prioritization moves LLM work *ahead* of parity work in time; it does not remove parity work
from the backlog, and no P2 item has been cancelled. Concretely, these remain owed: xDS
(WP-20/21/22), the admin server (WP-25), the corpus scorecard climbing off 15% (WP-27),
`ext_authz`/`ext_proc`/`ratelimit` and the batch-1 filters (WP-31/32), downstream h2 and upgrades
(S10), and the six S1 IR match extensions. The differential rig (WP-26) is the instrument that
keeps parity honest, which is why it is P1 rather than P2.

### Dependency lanes (what can run in parallel)

```
Lane A (foundations):  WP-01 → WP-02 → WP-03 → WP-04 → WP-05          ✅ complete (+ WP-38)
Lane B (runtime/L4):              WP-06 → WP-07 → WP-08 → WP-09        (needs WP-05 IR stubs)
Lane C (HTTP):                    WP-10 → WP-11 → WP-12 → WP-13 → WP-14 → WP-15
Lane D (cluster):                 WP-16 → WP-17 → WP-18 → WP-19        (needs WP-05, WP-06)
Lane E (xDS):                     WP-20 → WP-21 → WP-22                (needs WP-03..05)
Lane F (observability):           WP-23 → WP-24 → WP-25                (needs WP-06)
Lane G (test infra):              WP-26, WP-27 start at day 1; WP-28..30 as features land
Filters:                          WP-31 → WP-32                        (needs WP-11)
Lane H (LLM layer):               WP-33 → WP-34 → WP-35 → WP-36 → WP-37 (needs WP-11..15; WP-36 needs WP-32 ext_proc;
                                                                         WP-37 needs S10 upgrade support in WP-10/11/13)
```

Lanes B–G can be staffed concurrently once Lane A publishes the IR and trait crates. Within a
lane, WPs are sequential. Cross-lane contract: **traits/IR are the only shared surface.**

---

## Part 1 — Workspace layout and shared interfaces

```
llm-proxy/
├── Cargo.toml                  # workspace
├── crates/
│   ├── proxy-api/              # WP-02: generated Envoy protos + FileDescriptorSet
│   ├── proxy-config/           # WP-03/04/05: bootstrap load, validation, proto→IR
│   ├── proxy-core/             # WP-06..09: runtimes, listeners, transport sockets, L4 filters
│   ├── proxy-http/             # WP-10..15: codecs, HTTP filter manager, routing, router
│   ├── proxy-cluster/          # WP-16..19: cluster manager, LB, health, outlier, pools*
│   ├── proxy-xds/              # WP-20..22: ADS client, warming orchestration
│   ├── proxy-observability/    # WP-23/24: stats registry, access-log formatter
│   ├── proxy-admin/            # WP-25
│   ├── proxy-filters/          # WP-31..33: non-core filters (feature-gated)
│   ├── proxy-simple-config/    # WP-38: LLM-native dialect -> Envoy resources lowering
│   └── proxy/                  # binary: CLI, wiring, main()
├── schema/
│   └── llmproxy-v0.schema.json # WP-38: normative dialect schema (docs generate from this)
├── testing/
│   ├── diffrig/                # WP-26: side-by-side Envoy differential harness
│   ├── corpus/                 # WP-27: config corpus + scorecard tool
│   └── controlplane/           # WP-28: scripted xDS server harness
└── docs/
    ├── envoy-divergences.md    # every intentional/known behavior difference
    └── adr/                    # architecture decision records
```

\* Connection pools (WP-15) live in `proxy-cluster` but their interface is consumed by
`proxy-http`'s router; the trait is defined in `proxy-cluster` and re-exported.

### 1.1 Core shared types (defined in WP-05/WP-06, frozen early)

```rust
// proxy-config: the IR root. Immutable after build; shared via Arc.
pub struct ConfigSnapshot {
    pub listeners: HashMap<ListenerName, Arc<ListenerConfig>>,
    pub clusters:  HashMap<ClusterName,  Arc<ClusterConfig>>,
    pub routes:    HashMap<RouteConfigName, Arc<RouteTable>>,
    pub secrets:   HashMap<SecretName,   Arc<TlsSecret>>,
    pub version:   SnapshotVersion,       // monotonic, for /config_dump + logs
}

// proxy-core: how workers see config. Control plane swaps; workers load().
pub struct WorkerConfigHandle(arc_swap::ArcSwap<ConfigSnapshot>);

// proxy-core: transport socket abstraction (raw TCP, TLS).
pub trait TransportSocketFactory: Send + Sync {
    fn wrap_downstream(&self, io: TcpStream) -> BoxFuture<io::Result<BoxedIo>>;
    fn wrap_upstream(&self, io: TcpStream, ctx: &UpstreamTlsCtx) -> BoxFuture<io::Result<BoxedIo>>;
}

// proxy-cluster: what the router asks for. THE seam between HTTP and cluster lanes.
// Worker-local (!Send) per ADR-0003; handles are Rc<dyn ClusterEntry> inside a worker.
pub trait ClusterEntry {
    fn pick_host(&self, lb_ctx: &LoadBalancerContext) -> Option<Arc<Host>>;   // S7
    fn http_pool(&self, host: &Arc<Host>, proto: UpstreamProtocol) -> Arc<dyn HttpConnPool>;
    fn circuit_breaker(&self, prio: RoutingPriority) -> &CircuitBreakerState;  // S5
}

pub trait HttpConnPool {  // worker-local (!Send) per ADR-0003
    // Resolves when a stream slot is available; carries pool-level failure reasons
    // (overflow, connect-failure, timeout) distinctly — retry engine (S3) needs them.
    fn new_stream(&self) -> BoxFuture<Result<UpstreamStream, PoolError>>;
}
```

### 1.2 HTTP filter API (defined in WP-11; mirrors `envoy/http/filter.h` — see S2)

```rust
pub enum FilterHeadersStatus { Continue, StopIteration, ContinueAndDontEndStream,
                               StopAllIterationAndBuffer, StopAllIterationAndWatermark }
pub enum FilterDataStatus    { Continue, StopIterationAndBuffer,
                               StopIterationAndWatermark, StopIterationNoBuffer }
pub enum FilterTrailersStatus{ Continue, StopIteration }
pub enum Filter1xxStatus     { Continue, StopIteration }

pub trait HttpFilter {  // worker-local (!Send) per ADR-0003
    fn decode_headers(&mut self, cb: &mut dyn DecoderCallbacks, h: &mut RequestHeaderMap,
                      end_stream: bool) -> FilterHeadersStatus { FilterHeadersStatus::Continue }
    fn decode_data(&mut self, cb: &mut dyn DecoderCallbacks, data: &mut Bytes,
                   end_stream: bool) -> FilterDataStatus { FilterDataStatus::Continue }
    fn decode_trailers(&mut self, cb: &mut dyn DecoderCallbacks, t: &mut RequestTrailerMap)
                   -> FilterTrailersStatus { FilterTrailersStatus::Continue }
    fn encode_headers(...) -> FilterHeadersStatus;   // + encode_data / encode_trailers
    fn encode_1xx_headers(...) -> Filter1xxStatus;
    fn on_destroy(&mut self) {}
}

pub trait DecoderCallbacks {
    fn send_local_reply(&mut self, code: StatusCode, body: &str,
                        modify: Option<HeaderMutationFn>, details: &str);
    fn continue_decoding(&mut self);
    fn add_decoded_data(&mut self, data: Bytes, streaming: bool);
    fn inject_decoded_data_to_filter_chain(&mut self, data: Bytes, end_stream: bool);
    fn decoding_buffer(&self) -> Option<&BufferedBody>;
    fn modify_decoding_buffer(&mut self, f: &mut dyn FnMut(&mut BytesMut));
    fn route(&self) -> Option<Arc<RouteEntry>>;
    fn clear_route_cache(&mut self);
    fn stream_info(&mut self) -> &mut StreamInfo;   // dynamic metadata, filter state
}

// Registration — keyed by Envoy type URL, used by static config AND xDS identically.
pub trait HttpFilterFactory: Send + Sync {
    fn type_url(&self) -> &'static str;   // e.g. ".../v3.Router"
    fn create(&self, cfg: &prost_reflect::DynamicMessage, ctx: &FactoryContext)
        -> Result<Box<dyn FilterInstanceFactory>, ConfigError>;
    fn parse_per_route(&self, cfg: &DynamicMessage) -> Result<Arc<dyn PerRouteConfig>, ConfigError>;
}
```

---

## Part 2 — Work packages

Format: **Goal / Tasks / Interfaces / Acceptance / Size** (S ≈ ≤3 dev-days, M ≈ 1 wk, L ≈ 2 wk).
Each WP references its normative spec sections.

### Lane A — Foundations

#### WP-01 — Repo scaffolding & CI  (Size: S)  — **Priority: P1**
> **Status: done** (workspace, Makefile, toolchain pin, ADR-0001/0002, CI config; CI runs once the repo is pushed to a remote).
- Cargo workspace as in Part 1; `rust-toolchain.toml` (pin stable), rustfmt/clippy configs
  (`clippy::pedantic` triaged, `unsafe_code = "forbid"` except `proxy-core` runtime pinning).
- CI: fmt + clippy + test + doc build; job matrix stub for the diff rig (WP-26).
- `docs/adr/0001-runtime-model.md`, `0002-config-pipeline.md` seeded from PLAN.md.
- **Acceptance:** `cargo check --workspace` green in CI from an empty checkout.

#### WP-02 — `proxy-api`: Envoy protos + descriptor pool  (Size: M)  — **Priority: P1**
> **Status: done** (vendored v1.38 protos, generate-ourselves per ADR, embedded `FileDescriptorSet`, 5 tests).
- Vendor Envoy API protos at the pinned tag (git submodule or `buf export`); generate with
  `prost-build` + `tonic-build` (services: ADS, SDS, ALS, ext_authz, ratelimit).
- Emit and embed the **`FileDescriptorSet`** (needed by `prost-reflect` for JSON parsing and
  by strict-mode unknown-field detection). Expose `pub fn descriptor_pool() -> &'static DescriptorPool`.
- Decision (spike, timeboxed 1 day): generate ourselves vs. re-export
  [`xds-api`](https://github.com/junction-labs/xds-api). Generate-ourselves is the default —
  we need the descriptor set and version pinning; record in ADR.
- **Acceptance:** `Bootstrap`, `Listener`, `Cluster`, `RouteConfiguration`,
  `ClusterLoadAssignment`, `HttpConnectionManager`, `Router`, ADS service types all
  addressable; descriptor pool resolves every `type.googleapis.com/envoy.*` URL used in the
  corpus (WP-27).

#### WP-03 — Bootstrap loader (YAML/JSON/pb → typed protos)  (Size: M)  — **Priority: P1**
> **Status: done** (`crates/proxy-config/src/loader.rs`, 9 tests). Corpus-runner acceptance open until WP-27.
- Pipeline: file → (by extension) `serde_yaml`/`serde_json` → `serde_json::Value` →
  `prost_reflect::DynamicMessage::deserialize` with `DeserializerOptions { deny_unknown_fields: true }`
  against `envoy.config.bootstrap.v3.Bootstrap` → typed prost message.
- Must handle the full proto3 JSON mapping: durations (`"0.25s"`), `google.protobuf.Any` by
  type URL, wrapper types, `oneof`s, enums by name or number, `base64` bytes.
- Error type: `ConfigError { field_path: String, reason, source_location }` — field path must
  be the full dotted path (`static_resources.listeners[0].filter_chains[0].filters[0].typed_config`).
- `--permissive` flag: unknown fields → structured warnings, collected and exposed at
  `/config_dump?include_warnings` later.
- **Acceptance:** parses `envoyproxy/envoy` example configs byte-for-byte equivalently to
  `envoy --mode validate` accept/reject (validated in WP-27 corpus runner); rejects a config
  with one misspelled field naming the exact path.

#### WP-04 — Validation engine (PGV subset)  (Size: M)  — **Priority: P1**
> **Status: done** (`crates/proxy-config/src/validate.rs`, reflective interpreter over the
> descriptor pool, 14 tests). Envoy-error-string fixture harvest open until WP-26.
- Envoy protos carry `validate.rules` annotations (protoc-gen-validate). Implement an
  interpreter over the descriptor pool for the rule types Envoy actually uses on our supported
  surface: `duration.gt`, `uint32.lte`, `repeated.min_items`, `string.min_len/in/well_known`,
  `message.required`, oneof-required.
- Runs on *every* config entry point: bootstrap after WP-03, every xDS resource before ACK.
- **Acceptance:** table-driven tests mirroring ~30 known Envoy validation failures (harvest
  exact Envoy error strings into fixtures via the diff rig); NACK path unit-tested.

#### WP-05 — Internal IR + proto→IR conversion  (Size: L, **critical path**)  — **Priority: P1**
> **Status: done** (`ir.rs` + `lower.rs`, 13 tests): S1 domain index, per-message allow-list
> surface check (unsupported set field → full dotted path error), anchored compiled regexes,
> weighted-cluster cumulative arrays. Golden `insta` snapshots not adopted — coverage is via
> direct IR assertions instead; revisit if fixture count grows past what asserts stay readable at.
- Define `ConfigSnapshot`, `ListenerConfig`, `FilterChainSpec` (+ match criteria),
  `ClusterConfig` (type, LB policy, timeouts, CB thresholds, outlier config, health checks,
  transport socket), `RouteTable`/`VirtualHostIR`/`RouteEntry` (pre-compiled matchers: sorted
  domain sets per S1, compiled regexes, header matchers), `TlsSecret`.
- Conversion functions `TryFrom<&envoy::...> for ...IR` with `ConfigError` on unsupported
  fields (strict rule #2). **Every proto field either maps to IR, or errors, exhaustively —
  use a macro/checklist per message so new fields fail loudly after proto upgrades.**
- Pre-computation at conversion time (never on hot path): domain-match lookup structure
  (exact HashMap + suffix/prefix wildcard lists sorted longest-first per S1), regex
  compilation (`regex` crate, RE2-compatible subset — reject look-around like Envoy's
  safe_regex does), weighted-cluster cumulative weight arrays, header-matcher closures.
- **Interfaces produced:** the IR structs — the single most load-bearing API in the project.
- **Acceptance:** golden tests — YAML fixture in, `insta` snapshot of IR debug out, for ≥40
  fixtures covering every supported field; unsupported-field fixtures error with exact paths.

### Lane B — Runtime core & L4

#### WP-06 — Runtime bootstrap & config propagation  (Size: M)  — **Priority: P1**
> **Status: next on the critical path — unblocked.** D1 resolved 2026-07-19: share-nothing
> `!Send` current-thread worker runtimes with a `LocalSet` — see
> `docs/adr/0003-worker-send-model.md`. Part 1 trait bounds updated to match.
- Control runtime (multi-thread tokio, 2 threads) + `--concurrency` (default: #cores) worker
  runtimes: `tokio::runtime::Builder::new_current_thread()` each on a dedicated OS thread,
  core-pinned via `core_affinity` (flag to disable pinning).
- `ConfigPublisher` (control side) → `WorkerConfigHandle` (ArcSwap) per worker + a
  `tokio::sync::watch` ping so workers can react to listener add/remove (not just lazy-load).
- **Drain manager**: listener drain state (`draining_until: Instant`), per-connection
  registration, `--drain-time-s` (default 600s ⚠️), drain triggers: listener update/remove,
  admin `/drain_listeners`, SIGTERM graceful shutdown sequence.
- CLI: Envoy-compatible flags we support: `-c`, `--concurrency`, `--mode validate`,
  `--base-id` (parse+ignore with warning), `--log-level`, `-l`, `--service-node`,
  `--service-cluster` (feed into xDS `Node`).
- **Acceptance:** `proxy -c bootstrap.yaml --mode validate` exits 0/1 correctly; config swap
  under load test shows zero dropped connections (old snapshot Arc keeps old conns alive);
  SIGTERM drains then exits.
- **Closure path, surveyed 2026-08-06.** Two of the three acceptance clauses pass. The third
  is the only thing holding Lane B open (WP-07/08/09 are done), and the board's note —
  "needs the WP-26 rig" — is true but understates one thing and overstates another.
  1. **Overstated: this does not need WP-26's docker topology.** A config swap under live
     connections is *already* exercised in-process by
     `listener_removal_stops_new_accepts_but_keeps_existing_open`
     (`proxy-core/src/listener.rs` test module): it opens a connection under v1, publishes v2
     mid-flight, asserts the pre-existing connection stays open, and asserts a fresh
     connection observes v2. That is the acceptance clause's exact semantic at N=1. The
     delta to the gate is **sustained concurrent load with in-flight HTTP requests, plus a
     zero-dropped/zero-errored accounting across the swap** — a bounded extension of an
     existing harness, needing no docker, no pinned Envoy, and no traffic-replay topology.
     `testing/loadgen` already supplies a driver, an SSE client, and metrics if a second
     source of sustained load is wanted.
  2. **Understated, and unrecorded anywhere until now: the binary cannot swap config at
     runtime at all.** There is no SIGHUP handler, no config file watcher, and no other
     reload trigger; `-c bootstrap.yaml` is read exactly once at startup. Every
     `ConfigPublisher::publish` call site in the repo is inside a `#[cfg(test)]` module. The
     propagation machinery (control-side publisher → per-worker `ArcSwap` + `watch` ping) is
     real and unit-tested, but **nothing in production ever drives it** — its intended
     production driver is xDS, which is v0.3.0 (WP-20/21/22).
     So an end-to-end swap *through the binary* is not merely untested, it is not currently
     expressible. The acceptance clause is written against the propagation machinery, not the
     binary, so closing it at the library level is honest rather than a dodge — but the
     binary's inability to reload is a distinct gap that no card records, and it must not be
     allowed to hide behind a green WP-06.
  3. **Prerequisite that is not optional:** `sigterm_drains_then_exits_cleanly`
     (`crates/proxy/tests/cli.rs`) is flaky on timing and guards the same drain path this
     gate depends on. A gate whose neighbouring test intermittently lies is worth little, so
     that suite has to be made deterministic first — see CLAUDE.md rule 14 for the mechanism
     (a hardcoded `127.0.0.1:10000` from `examples/tcp-proxy.yaml` that cannot run
     concurrently with itself) and for why raising `STARTUP_TIMEOUT` a third time is the
     wrong fix.

#### WP-07 — Listener manager & filter-chain matching  (Size: M)  — **Priority: P1**
- Per-worker listener sockets with `SO_REUSEPORT` (+ `reuse_port` semantics on macOS dev vs
  Linux prod documented); listener options from proto: `tcp_backlog_size`,
  `per_connection_buffer_limit_bytes` (default 1 MiB ⚠️), `bind_to_port`.
- **Filter-chain matching algorithm** — Envoy's is a fixed 8-step narrowing, most-specific-first
  on each criterion, in this exact order: destination port → destination IP (longest CIDR) →
  server name / SNI (exact, then suffix wildcard longest-first) → transport protocol →
  application protocols (ALPN) → direct source IP → source type (local/external) → source IP
  (longest CIDR) → source port. Implement exactly; property-test against the diff rig with
  generated criteria matrices. `default_filter_chain` fallback; no match → close (TCP RST
  behavior matches Envoy's `filter_chain_match` miss).
- Listener add/update/remove lifecycle hooks for WP-21 (in-place filter-chain update NOT
  required; full listener replace + drain is the v1 semantics).
- **Acceptance:** matching matrix differential test (≥200 generated cases) equals Envoy's
  choice; reload under load drops nothing.

#### WP-08 — Transport sockets + listener filters  (Size: L)  — **Priority: P1**
- `RawBufferSocket`; `TlsDownstream`/`TlsUpstream` on rustls: full
  `DownstreamTlsContext`/`UpstreamTlsContext` IR mapping — cert chains, private keys,
  `validation_context` (trusted CA, SAN matchers: exact/prefix/suffix/regex per type
  DNS/URI/IP), `require_client_certificate`, ALPN, min/max TLS version, cipher suites
  (translate Envoy/BoringSSL names → rustls; **error** on unsupported suites, list them),
  session resumption (tickets off by default ⚠️ — check parity).
- Cert hot-reload seam: `ArcSwap<rustls::sign::CertifiedKey>` resolver (SDS lands in WP-22).
- Listener filters: `tls_inspector` (parse ClientHello: SNI + ALPN without consuming bytes —
  peek buffer), `proxy_protocol` (v1+v2), `original_dst` (Linux `SO_ORIGINAL_DST`, stub on macOS).
- **Acceptance:** TLS interop matrix (curl/openssl: TLS1.2/1.3, mTLS ok/bad-SAN/expired,
  SNI-based chain selection); differential handshake-failure *behavior* (connection close
  patterns, not error text).

#### WP-09 — Network filter framework + `tcp_proxy`  (Size: M)  — **Priority: P1**
- `NetworkFilter` trait (`on_new_connection`, `on_data(&mut BytesMut, end) -> NetFilterStatus
  {Continue, StopIteration}`), write-path counterpart; terminal-filter enforcement (config
  error if `tcp_proxy`/HCM not last — matches Envoy validation).
- `tcp_proxy` v3 config: `cluster`, `weighted_clusters`, `idle_timeout` (default 1h ✅ in
  proto), `max_connect_attempts` (default 1), access log hooks, upstream via
  `ClusterEntry::pick_host` + raw TCP pool (simple per-worker reuse-none pool for v1).
- **Acceptance:** iperf-style bidirectional proxy correctness (checksummed streams both
  directions, half-close semantics correct — FIN propagation like Envoy); idle timeout fires.

### Lane C — HTTP data plane

#### WP-10 — Codec integration (h1/h2, downstream + upstream)  (Size: L)  — **Priority: P1**
- Downstream: `hyper::server::conn::http1/http2` low-level `Connection` driving our
  `StreamHandler` per request; upstream: `hyper::client::conn` handles held by pools (WP-15).
  **Spike (2 days, timeboxed):** verify hyper 1.x lets us (a) flush response headers before
  body without buffering, (b) stream trailers both ways, (c) propagate h2 RST_STREAM as a
  distinct error, (d) disable h1 keep-alive per connection for drain. If any fail → fall back
  to `httparse`+own h1 conn loop and raw `h2` crate (Orion forked hyper-util for related
  reasons; expect this).
- HCM config subset v1: `codec_type` (AUTO/HTTP1/HTTP2), `stat_prefix`, `route_config`
  (inline) / `rds`, `http_filters`, `use_remote_address`, `xff_num_trusted_hops`,
  `generate_request_id`, `stream_idle_timeout` (default 5 min ⚠️), `request_timeout`
  (default 0 = disabled ✅), `common_http_protocol_options.idle_timeout` (default 1h ⚠️),
  `max_request_headers_kb` (default 60 ⚠️), `server_name` ("envoy" default — ours defaults to
  configurable, `server_header_transformation` honored).
- **Upgrades (S10):** h1 101-Switching-Protocols handling downstream and upstream (headers
  validated, then the codec hands the stream over to bidirectional tunnel mode); h2
  **extended CONNECT (RFC 8441)** translation — h1 `Upgrade: websocket` ⇄ h2 `CONNECT` +
  `:protocol: websocket` in both directions when upstream h2 has `allow_connect` (S10.3),
  including the documented constraints (assumed GET, no upgrade-with-body proxying ✅).
- **Acceptance:** h2spec compliance run ≥ Envoy's pass set; h1 conformance fixtures
  (pipelining, chunked, `Connection` header handling, 100-continue plumbing to S2);
  WebSocket echo differential test (h1→h1 and h1→h2-CONNECT→h1 chains) vs Envoy.

#### WP-11 — HTTP filter manager  (Size: L, **the crown jewel — assign strongest dev**)  — **Priority: P1**
- Implement the S2 state machine **exactly**: per-stream decode/encode filter chains, all
  five `FilterHeadersStatus` variants, four `FilterDataStatus` variants, buffering with
  limits (`per_connection_buffer_limit_bytes`-derived; overflow → **413** decode / **500**
  encode ✅), watermark propagation (readDisable on downstream conn / upstream stream),
  `continue_decoding/encoding` re-entry (must resume at the *next* filter, replay buffered
  body, then trailers), `add_decoded_data` (append to buffer; legal in headers/trailers cb),
  `inject_*_data_to_filter_chain` (out-of-callback injection), local replies (S2.5 rules:
  headers-not-sent → full local reply through *encoder* filters; headers-sent → reset),
  1xx encode path, per-route config lookup (`most_specific_wins` semantics), route cache +
  `clear_route_cache()`, filter destruction order (reverse creation ✅ matches Envoy).
- The **router filter is just the last decoder filter** (WP-13) — no special casing in the manager.
- **Upgraded streams (S10.2):** after 101, WebSocket payload continues to flow through the
  HTTP filter chain as data callbacks ✅; per-upgrade-type filter chains supported (buffering
  filters are incompatible with upgrades — config-error, not silent breakage).
- **Acceptance:** the S2 conformance suite (write it first, ~60 table-driven cases: every
  status × {headers-only, body, trailers} × resume paths); mutation-tested (cargo-mutants ≥85%
  caught on this module); differential fixtures for buffer-overflow status codes.

#### WP-12 — Route table & matching engine  (Size: M)  — **Priority: P1**
- Implements S1 exactly on the IR from WP-05: domain precedence (exact → suffix-wildcard
  longest-first → prefix-wildcard longest-first → `*` ✅), route list first-match-wins ✅,
  path specifiers: `prefix`, `path` (query stripped ✅), `safe_regex` (full-path match ✅),
  `path_separated_prefix` (`/api/dev` matches `/api/dev`, `/api/dev/…`, not `/api/developer` ✅),
  `case_sensitive` default **true** ✅ (applies to prefix/path, never regex), `headers`
  matchers (exact/regex/range/present/prefix/suffix/contains, `invert_match`),
  `query_parameters`, `runtime_fraction` gate.
- Route actions IR: cluster / `weighted_clusters` (weights relative, sum>0 ✅; per-request
  stable pick — hash once) / `cluster_header`; `prefix_rewrite`, `regex_rewrite`,
  `host_rewrite_literal`/`auto_host_rewrite`; redirects (https/host/path/prefix/strip_query,
  response code); `direct_response`; `request_headers_to_add/remove` etc. merged
  route→vhost→global with correct append/overwrite semantics (`append_action` all 4 modes).
- **Acceptance:** ≥300-case differential routing table test: generated `(RouteConfiguration,
  request)` pairs replayed against Envoy with an echo upstream that reflects the chosen
  cluster; 100% agreement required.

#### WP-13 — Router filter & upstream request lifecycle  (Size: L)  — **Priority: P1**
- Route resolution → cluster lookup (miss → 503 `NC` ✅-flag parity), maintenance-mode check,
  CB check (open → 503 + `x-envoy-overloaded: true` ✅), host pick (S7 context: hash policy
  from route for ring-hash/maglev), pool `new_stream`, request header transforms (S9):
  `x-forwarded-for` append vs preserve by `use_remote_address`/`xff_num_trusted_hops`,
  `x-request-id` generate/propagate, `x-envoy-*` internal header consumption (S3 list) and
  **strip-from-external** rules, `:authority` rewrite, `x-envoy-expected-rq-timeout-ms` set.
- Timeouts per S4: global route timeout (default **15s**, `0` disables ✅), per-try, per-try
  idle, upstream response started → timeout disarmed rules; on timeout: 504 (or 408 config),
  stream reset upstream.
- Response path: `x-envoy-upstream-service-time` ✅, `x-envoy-attempt-count` (opt-in ✅),
  hedging seam for WP-14.
- **Upgrade routing (S10.1):** `upgrade_configs` enable/disable hierarchy (HCM × route
  override table), 403 on disallowed upgrade type, no retries after 101, upgrade stats
  (`downstream_cx_upgrades_total/active` ✅). CONNECT proxy/termination modes deferred to
  Phase 7 (strict-mode error until then).
- **Acceptance:** lifecycle differential suite: {timeout, upstream reset mid-headers,
  mid-body, pool overflow, no-healthy-host} × {h1,h2} — status code, response flags
  (`UT`,`UR`,`UO`,`NC`,`URX`) and headers must match Envoy (flags visible via access log, WP-24).

#### WP-14 — Retry & hedging engine  (Size: M)  — **Priority: P1**
- Implements S3 exactly: trigger evaluation (each `retry_on` value per S3.2 — including the
  subtle ones: `5xx` includes *no response*; `connect-failure` excludes request timeout;
  `retriable-4xx` = 409 only ✅), attempt budget (`num_retries` default **1** ✅,
  `x-envoy-max-retries` override), **fully-jittered exponential backoff: delay ~ U[0,
  min((2^n − 1)·B, M)] with B=25ms default, M=10·B default ✅** (progression 0–24ms, 0–74ms,
  0–174ms ✅), retry budgets (S5.2: default budget 20% ⚠️, `min_retry_concurrency` 3 ⚠️ —
  budget replaces `max_retries` CB when configured), `host_selection_retry_max_attempts`
  (default 1 ✅) + previously-attempted-host predicate, per-try timeout interplay (S4.3),
  request buffering constraint: **a request whose body exceeded the buffer limit or was
  streamed is not retriable** (matches Envoy; flag `no_retry_body_too_large`), hedge-on-per-try-timeout.
- **Acceptance:** deterministic-clock unit tests (tokio `start_paused`) asserting exact delay
  distributions (seeded RNG) and attempt counts; differential chaos suite: scripted flaky
  upstream (fail N then succeed) × every retry_on — attempt counts observed at upstream must
  match Envoy's within jitter-independent assertions.

#### WP-15 — Upstream connection pools + circuit breakers  (Size: L)  — **Priority: P1**
- Per-worker, per-host, per-protocol pools. h1: connection reuse queue, max requests/conn;
  h2: single (or `max_concurrent_streams`-aware N) connection multiplexing with stream
  accounting. Pool states: ready/busy/draining/failed; pending-request queue with S5 limits;
  distinct `PoolError` variants (overflow / connect-failure / connect-timeout / reset-before-headers)
  because S3 trigger mapping and stats/response-flags depend on them.
- Circuit breakers per S5: per-priority (`DEFAULT`/`HIGH`) thresholds `max_connections`,
  `max_pending_requests`, `max_requests`, `max_retries` (defaults all **1024**, retries **3**
  ⚠️); gauges exposed with Envoy stat names (`cx_open`, `rq_pending_open`, …); `track_remaining`.
- Cluster `connect_timeout` (default **5s** ⚠️), `per_connection_buffer_limit_bytes`,
  `upstream_connection_options.tcp_keepalive`.
- **Acceptance:** pool soak (10k conns churn, zero leak via gauge assertions); CB differential:
  drive exact concurrency N against limit L for each threshold, assert same accept/reject
  counts and same response flags as Envoy.

### Lane D — Cluster subsystem

#### WP-16 — Cluster manager & discovery types  (Size: M)  — **Priority: P1**
- Cluster types v1: `STATIC`, `STRICT_DNS` (re-resolve every `dns_refresh_rate`, default 5s ⚠️;
  all A/AAAA records = membership), `LOGICAL_DNS` (single logical host, resolve at
  connect), `EDS` (fed by WP-20), `ORIGINAL_DST` (deferred, Phase 7).
- Endpoint model: `ClusterLoadAssignment` → priorities (0..N) → localities (weights) → hosts
  (weight, health status, metadata). Host set diffing (add/remove/health-change) published to
  workers as immutable `Arc<HostSet>` snapshots (main-thread computes, workers swap — Envoy's
  model exactly).
- Warming semantics stub for WP-21: cluster not "initialized" until first EDS response / DNS
  resolution; `initial_fetch_timeout` (default 15s ⚠️) → proceed-empty.
- **Acceptance:** DNS flap simulation (record set changes) produces same membership timeline
  as Envoy (observable via `/clusters`); EDS update → traffic shifts within one RTT, no drops.

#### WP-17 — Load balancers  (Size: M)  — **Priority: P1**
- Implements S7: `ROUND_ROBIN` (weighted, EDF-based like Envoy for smooth weighting ⚠️),
  `LEAST_REQUEST` (P2C, `choice_count` default 2 ⚠️; weighted variant switches to full-scan
  EDF when weights differ — mirror Envoy), `RANDOM`, `RING_HASH` (ketama, `minimum_ring_size`
  default 1024 ⚠️, xxhash ⚠️ — **must match Envoy's hash exactly or session affinity breaks
  cross-fleet**; verify hash function + endpoint key format `address:port|weight` against
  Envoy source), `MAGLEV` (table size 65537 ⚠️, permutation algorithm from the paper as Envoy
  implements it).
- Common behaviors: **healthy-panic threshold** (default 50% ⚠️: if healthy% < threshold,
  route to *all* hosts), priority spillover (100% to P0 while ≥ threshold healthy, overflow
  formula per Envoy docs ⚠️), locality-weighted LB (v1: implement zone-aware OFF, structure
  ready), `hash_policy` evaluation (header, cookie w/ TTL-generation, source IP) in WP-13
  feeding `LoadBalancerContext`.
- **Acceptance:** statistical differential tests: 100k picks against fixed host sets, per-host
  distribution within 1% of Envoy's; ring-hash/maglev: **exact** pick agreement on 10k random
  hash keys (this catches hash mismatches).

#### WP-18 — Active health checking  (Size: M)  — **Priority: P1**
- HTTP (`path`, expected statuses default 200 ✅, host header), TCP (send/expect bytes),
  gRPC (`grpc.health.v1.Health/Check`). Timing: `interval`, `timeout`,
  `unhealthy_threshold`/`healthy_threshold`, `no_traffic_interval` (default 60s ⚠️), jitter
  (`interval_jitter`), first-check immediate on host add ⚠️.
- Runs on control runtime; health transitions publish HostSet updates (WP-16). `/clusters`
  and `health_flags` strings match Envoy (`/failed_active_hc`, `/failed_outlier_check`).
- **Acceptance:** scripted upstream (healthy↔unhealthy sequences) → transition timeline
  (edge counts, timing windows) matches Envoy; panic-threshold interaction test with WP-17.

#### WP-19 — Outlier detection  (Size: M)  — **Priority: P1**
- Implements S6 with exact defaults (verified table): consecutive-5xx (5 ✅), interval 10s ✅,
  base ejection 30s ✅, `max_ejection_percent` 10% ✅ (note: Envoy always allows ejecting ≥1
  host only if `always_eject_one_host` — default false ✅), ejection time growth = base ×
  consecutive-ejection-count capped at `max_ejection_time` (max(300s, base) ✅),
  enforcement percentages (consecutive-5xx 100% ✅, gateway-failure 0% ✅ — i.e. gateway
  failure *tracked but not enforced* by default), success-rate detection (min 5 hosts ✅,
  100 rq volume ✅, stdev factor 1900 = 1.9σ ✅), un-eject on active-HC success (default true ✅).
- **Acceptance:** deterministic-clock simulation harness: scripted per-host response codes →
  ejection/un-ejection event log equality with Envoy (Envoy's observable via
  `outlier_detection` event log file — parse it in the diff rig).

### Lane E — xDS

#### WP-20 — ADS client (SotW)  (Size: L)  — **Priority: P2**
- tonic bidi stream to `ads_config` cluster (bootstrapped cluster only, v1); `Node` from
  bootstrap/CLI. Per-type subscription state machines per S8: resource-name sets (LDS/CDS
  wildcard; RDS/EDS names derived from accepted LDS/CDS), `version_info`+`nonce` bookkeeping
  ✅, **per-response atomic validate→accept-or-NACK** (a NACK'd response changes *nothing*),
  NACK carries `error_detail` with our WP-03/04 field-path errors, ACK echoes version ✅,
  stream re-establishment with backoff (jittered, 500ms–30s ⚠️) and **state re-sync rules**
  (re-send subscriptions with last-ACKed versions; versions survive reconnect ✅).
- SotW union semantics: LDS/CDS responses are the *complete* set (missing ⇒ delete);
  RDS/EDS are per-name (absence ≠ delete ✅ — spec'd difference, get it right).
- **Acceptance:** WP-28 harness scripts: {ACK, NACK-recover, reconnect-resync, spurious-nonce,
  out-of-order-response} scenarios; run against go-control-plane test server too.

#### WP-21 — Warming, ordering & make-before-break  (Size: M)  — **Priority: P2**
- Cluster warming: new/updated cluster serves no traffic until EDS/DNS arrives ✅;
  `initial_fetch_timeout` fallback. Listener warming: LDS listener with RDS dependency waits
  for route config ✅. Active/warming/draining listener sets; update = warm new → atomic swap
  → drain old (WP-06 drain manager). Removal ordering per S8.4 ✅ (adds before removes).
- Init manager for startup: bootstrap → CDS → EDS → LDS → RDS → workers start → `/ready` 200
  (matches Envoy's init sequence; `/ready` gating exact).
- **Acceptance:** control-plane scripted "make-before-break" churn (rename clusters+listeners
  every 2s) under 5k rps load: **zero** 5xx from our proxy AND Envoy baseline equal
  behavior; kill control plane mid-warm → old config keeps serving.

#### WP-22 — SDS + delta xDS  (Size: M)  — **Priority: P2**
- SDS: `tls_certificate_sds_secret_configs` + `validation_context_sds_secret_config`;
  hot cert rotation via the WP-08 ArcSwap resolver; missing secret = warming (listener waits).
- Delta ADS (`DeltaDiscoveryRequest`): per-resource versions, `resource_names_subscribe/unsubscribe`,
  `removed_resources`; wired to same subscription state machines (S8 written to make the
  SotW/delta split a strategy trait).
- **Acceptance:** cert rotation under TLS load (zero handshake failures, new cert observed);
  delta scenarios in WP-28 harness; Istio ambient/sidecar smoke test (stretch).

### Lane F — Observability & admin

#### WP-23 — Stats registry  (Size: M)  — **Priority: P1**
> **Owner decision 2026-08-03 — the internal model is OTel, Envoy names are an adapter.**
> This reverses the emphasis of the bullets below, which were written Envoy-first; they stay
> because the Envoy-exact output is still a deliverable, but it becomes a *rendering* of the
> registry rather than the registry's own shape. Design the instrument model as OpenTelemetry
> — instruments plus attribute sets, semconv names — and render Envoy's flat dotted names from
> it for `/stats`.
> **Why this direction and not the reverse:** attributes are strictly more expressive than flat
> names. `envoy_cluster_provider:openai_upstream_rq_total` is derivable from a counter carrying
> `{cluster="provider:openai"}`, but recovering the attribute set from the flat string means
> parsing structure back out of names we ourselves mangled — and Envoy's label-mangling rules
> are lossy. Going Envoy-first would also leave the LLM metrics homeless: `gen_ai.*` token
> counts have no Envoy equivalent to be exact about, so half the registry would have invented
> names either way.
> **Costs, recorded honestly:** `/stats` becomes a rendering layer needing its own conformance
> tests (the acceptance bullet below is exactly that, and does not get easier); and the OTel
> GenAI semantic conventions are still marked experimental upstream — they have already churned
> once (`gen_ai.usage.prompt_tokens` → `gen_ai.usage.input_tokens`). Pin a semconv version in
> the code and treat a bump as a breaking change to the metric surface, because for anyone with
> a dashboard it is one.
> **Also note ADR-0005** already names stats as a stateful subsystem: the per-worker-shard
> approach in the bullets below is the trap that ADR calls out by name (with N workers, a
> per-worker counter that never aggregates is wrong by the worker count). Whatever WP-23 builds
> needs the trait + embedded-default + distributed-seam shape, and export must happen on the
> control side — never I/O on the request path.
- Counter/gauge/histogram registry, **Envoy-exact names**: `cluster.<name>.upstream_rq_total`,
  `upstream_rq_2xx…5xx`, `upstream_rq_retry`, `upstream_rq_timeout`, `upstream_cx_*`,
  `listener.<addr>.downstream_cx_*`, `http.<stat_prefix>.downstream_rq_*`, `rq_time` histogram
  (Envoy default buckets ⚠️). Per-worker shards, control-plane aggregation on scrape (no hot-path
  atomics contention; relaxed-ordering counters).
- Prometheus exposition at admin `/stats/prometheus` with Envoy's label mangling rules ⚠️;
  plain `/stats` text format too.
- **Acceptance:** run Envoy's Grafana dashboard queries against our Prometheus output for a
  scripted traffic mix — all panels populate; per-stat differential counters within exact
  equality for deterministic scenarios.

#### WP-24 — Access logging  (Size: M)  — **Priority: P1**
- Format-string engine: default format ✅ (`[%START_TIME%] "%REQ(:METHOD)% …"`) and the
  operator set: `%REQ(X?Y):Z%`, `%RESP%`, `%TRAILER%`, `%DURATION%`, `%REQUEST_DURATION%`,
  `%RESPONSE_DURATION%`, `%RESPONSE_FLAGS%` (full flag vocabulary — UH,UF,UO,NR,URX,NC,DC,LH,
  UT,LR,UR,RL,UAEX,RLSE,IH,SI,DPE,UPE,UMSDR…), `%BYTES_RECEIVED/SENT%`, `%UPSTREAM_HOST%`,
  `%UPSTREAM_CLUSTER%`, `%DOWNSTREAM_REMOTE_ADDRESS%`, `%CONNECTION_TERMINATION_DETAILS%`,
  `%START_TIME(fmt)%` strftime. JSON format (`json_format`) with typed values.
  File sink (async, buffered, reopen on SIGUSR1 ⚠️ parity) + stdout/stderr sinks; `filter`
  (status_code, duration, response_flag, runtime) support.
- **Response flags are set throughout Lanes B–D** — this WP owns the enum + the contract doc;
  WP-13/14/15 populate.
- **Acceptance:** differential log-line comparison (field-by-field, timestamps masked) for the
  WP-13 lifecycle suite; every response flag reachable by at least one test.

#### WP-25 — Admin server  (Size: S→M)  — **Priority: P2**
- Endpoints v1: `/ready`, `/stats`, `/stats/prometheus`, `/clusters` (Envoy text format),
  `/config_dump` (**real Envoy proto JSON shapes** — serialize IR back through proxy-api
  types; istioctl-parseable), `/listeners`, `/server_info`, `/drain_listeners?graceful`,
  `/healthcheck/fail|ok`, `/logging` (level change), `/quitquitquit`.
- Bound per bootstrap `admin` stanza; own tiny HTTP server (not the data plane).
- **Acceptance:** `istioctl proxy-config listeners/clusters/routes` works against us (uses
  /config_dump); smoke-diff `/clusters` text vs Envoy.

### Lane G — Test infrastructure (starts day 1)

#### WP-26 — Differential test rig  (Size: L, **staff early — everything gates on it**)  — **Priority: P1**
- docker-compose topology: {our proxy, pinned Envoy} × shared {echo upstream (reflects
  received headers/cluster), flaky upstream (scriptable fail sequences), slow upstream} +
  scenario runner (Rust bin in `testing/diffrig`).
- Scenario = (bootstrap config, request script, upstream script) → captures from both proxies:
  status, headers (minus normalization allowlist: `date`, `server`, `x-request-id` values),
  body, access-log fields, key stats deltas, upstream-observed request sequence (attempt
  counts, headers). Assert equality; divergences either fail or are pinned in
  `envoy-divergences.md` with justification.
- Deterministic mode (seeded, paused-clock where possible) + chaos mode (jitter-tolerant assertions).
- CI: full suite on merge queue; smoke subset on PR.
- **Acceptance:** rig runs a trivial scenario green against Envoy-vs-Envoy (self-check),
  and red when configs intentionally differ (mutation self-test).

#### WP-27 — Config corpus & scorecard  (Size: S, ongoing)  — **Priority: P2**
- Harvest: envoyproxy examples, Envoy Gateway translator outputs (run its test suite,
  collect xDS dumps), istioctl-generated sidecar/gateway bootstrap+dumps, Gloo/Contour
  examples. Store as versioned fixtures.
- Scorecard tool: for each config → {fully-supported | rejected-with-path | parse-error},
  emits `corpus-report.md` (the headline compat metric, tracked in CI comment).
- **Acceptance:** report runs in CI; baseline recorded.

#### WP-28 — Control-plane harness (Size: M) — scriptable in-process xDS server (build on  — **Priority: P2**
  `tonic`; consider `jpittis/rust-control-plane`): scenario DSL for update/NACK/reconnect
  sequences used by WP-20..22. Plus go-control-plane docker fixture.
#### WP-29 — Fuzzing (Size: M) — `cargo-fuzz` targets: h1 request parser (smuggling vectors:  — **Priority: P2**
  CL/TE conflicts must match Envoy's rejections), h2 frame sequences, config parser
  (arbitrary YAML → must never panic), route matcher (path strings). CI nightly.
#### WP-30 — Perf benchmarks (Size: M) — Nighthawk (Envoy's own load gen) + fortio profiles:  — **Priority: P1**
  h1/h2 × {small, 64KB, streaming} × {plaintext, TLS}; p50/p99/p999 proxy-added latency,
  RPS/core, RSS/10k-conns; run vs Envoy same host; regression gate ±5% on merge queue.

### Filters & extensions

#### WP-31 — Batch 1 filters (Size: M) — `envoy.filters.http.cors` (full spec: origin  — **Priority: P2**
  matchers, credentials, max-age), `envoy.filters.http.local_ratelimit` (token bucket, per-route,
  descriptors, `x-envoy-ratelimited`, 429 + `x-ratelimit-*` headers opt-in), header-mutation
  filter. Each: exact type URL, PGV validation, per-route config, stats parity.
#### WP-32 — Batch 2 filters (Size: L) — `ext_authz` (gRPC v3: CheckRequest population rules  — **Priority: P2**
  — which attributes/headers included; header mutations from CheckResponse; failure_mode_allow;
  buffered body forwarding), `ratelimit` (gRPC RLS: descriptor generation from route/vhost
  rate_limits actions — generic_key, request_headers, remote_address…), and **`ext_proc`
  (client side)** — bidirectional per-transaction gRPC stream, BUFFERED and STREAMED body
  modes, header/body mutation application, `mode_override`, failure handling. ext_proc matters
  doubly: it's how existing Envoy AI Gateway processors and Inference-Extension endpoint
  pickers plug in (WP-36). Test against real `envoyproxy/ratelimit`, OPA-envoy-plugin, and an
  Envoy AI Gateway processor.

### Lane H — LLM inference layer (native, in-process — see PLAN.md Part 7.2)

All Lane H extensions live under our own namespace (`type.llmproxy.dev/...`) registered
through the same factory registry (WP-11); the core stays pure-Envoy-configurable. Design
goal: Envoy AI Gateway's capability set **without the ext_proc sidecar hop**.

#### WP-33 — Streaming-first guarantees + GenAI observability  (Size: M)  — **Priority: P0**
- SSE/streamed-response invariants: flush-through by default on the encode path (no
  filter-manager buffering unless a filter explicitly requests it — that's already S2, but add
  a **route-level `streaming: strict` assertion** that config-errors if any configured filter
  on the route buffers the response), chunked/SSE framing preserved byte-exact, upstream
  flow-control → downstream backpressure without coalescing tokens.
- Timeout profile for LLM routes: idle-based (`per_try_idle_timeout`, stream idle) rather than
  duration-based; lint/warn when a route to an LLM cluster has the 15s default global timeout.
- GenAI metrics per OTel GenAI semantic conventions: TTFT (time-to-first-byte-of-body /
  first SSE event), TPOT (inter-chunk latency distribution), input/output token counters
  (fed by WP-34), per-model dimensions under the WP-23 cardinality budget.
- **Acceptance:** SSE stream through proxy is byte- and timing-shape-identical (chunk
  boundaries preserved, first-byte latency overhead < 1ms p99 on loopback); metrics visible
  in Prometheus with model labels.

#### WP-34 — Token metering & token-based rate limiting  (Size: M)  — **Priority: P0**
- Response-side usage extraction: OpenAI-schema `usage` object (JSON responses and the
  final SSE `data:` frame / `usage` chunk when `stream_options.include_usage`), Anthropic
  `usage` events; extraction is streaming-safe (tail-parse, never buffer the stream).
- Token bucket limiter keyed by configurable descriptors (api-key header, route, model),
  limits on input/output/total tokens with per-model cost weights; enforcement at request
  time against accumulated usage (429 + standard `x-ratelimit-*` headers), Envoy AI
  Gateway-style semantics (over-limit rejects next request rather than truncating streams).
- Budget store trait: in-process (per-worker shard + control-plane aggregation) now; Redis
  impl later behind the same trait.
- **Acceptance:** deterministic usage-sequence tests (scripted provider responses → exact
  counter values, exact 429 onset); streaming path adds zero buffering (WP-33 invariant test).

#### WP-35 — Model routing & provider fallback  (Size: M)  — **Priority: P0**
- Body-peek model router: **moved to WP-45**, which owns the shared bounded-buffer /
  parse / rewrite pipeline. Two features needed the same machinery (the other is forced
  `include_usage` injection) and building it twice would mean two disagreeing buffer caps.
  WP-35 consumes it; the routing semantics (cluster-selection metadata then
  `clear_route_cache()`, S2.8) are specified there.
- Provider fallback policy on the S3 retry engine: custom retriable predicate
  (429/5xx/connect-failure per provider), **never retry after first response byte of a
  stream**, retry budgets denominated in tokens/requests, fallback chain across
  clusters/models (priority list), request re-write per provider adapter (OpenAI↔Anthropic
  shape translation as an explicit, versioned mapping table).
- **Credentials must follow the cluster, not the route — build this FIRST (2026-08-03).**
  Provider auth is attached at the route today: `proxy-simple-config/src/lower.rs:566` sets
  `route["request_headers_to_add"]` from the *primary* provider, and the IR carries it on
  `RouteEntry` (`ir.rs:623`). Fallback across providers on top of that shape sends the
  primary's API key to the fallback's endpoint — the `request_headers_to_add` P0 inverted:
  not "credentials never reach the provider" but "credentials reach the **wrong** provider,"
  and a real key disclosure to a third party. Nothing leaks today only because `fallbacks`
  is dropped with a warning and no failover happens at all.
  **Therefore: per-cluster header mutation lands before any cluster-selection work.** Envoy's
  own precedent is `WeightedCluster.ClusterWeight.request_headers_to_add` — headers that
  depend on which cluster was picked. `envoy.clusters.aggregate` deliberately has no
  equivalent: it was designed for failover between *homogeneous* clusters (same service,
  different zones). LLM providers are the heterogeneous case, which is the whole difficulty
  of this WP and the reason it is sized M.
- **IR decision (owner, 2026-08-03): the fallback chain is an aggregate cluster**, not a
  per-route `fallback_clusters` list. Rationale: it is Envoy-native, so real Envoy configs
  using `envoy.clusters.aggregate` begin working and the WP-27 scorecard can move; and it
  keeps cluster selection inside the existing priority machinery (`load_balancer.rs`
  `HostPicker::choose_priority` — S7 spillover, overprovisioning factor, panic threshold are
  all built and green) rather than restructuring the router's attempt loop. Cost: a new
  `ClusterKind` variant, member-cluster resolution, and a host pick that yields its **owning
  cluster** so the right transport socket *and* the right credential headers apply.
- **Router shape note.** `router.rs:273-289` resolves `cluster_name` once, *before* the
  `attempt_loop` at :334. Every retry re-picks a host, never a cluster. Under the aggregate
  decision this hoist survives — the aggregate is one cluster name — but only if the host
  pick carries its owning cluster back out.
- **How the dialect reaches a field with no Envoy proto source (increment 1b design,
  2026-08-03).** The `llmproxy` dialect does not build IR directly — it emits Envoy YAML and
  lowers through the identical strict-parse → PGV → IR pipeline ("one engine, two
  front-ends"). So it *cannot* populate `ClusterConfig.request_headers_to_add` simply by
  wanting to: with no Envoy `Cluster` field to carry it, there is nothing for the dialect to
  emit, and `check_supported_surface`'s per-message allowlist (`lower.rs:99+`) would reject
  any field it invented. This is not a flaw in the IR decision; it is the seam the
  architecture is supposed to have.
  **Decision: carry it in `Cluster.metadata.filter_metadata` under the key
  `io.llmproxy.provider_auth`,** add `metadata` to the `envoy.config.cluster.v3.Cluster`
  surface allowlist, and lower that one namespace into the IR field. `metadata` is chosen
  over the alternatives because it is the one Envoy message genuinely *designed* to carry
  arbitrary per-cluster side-channel data — unlike the `DataSource`/`RuntimeFeatureFlag`/
  `RateLimitSettings` stretching WP-47 already exists to undo. It remains stringly-typed
  (`filter_metadata` is `map<string, google.protobuf.Struct>`), so **this is a fourth
  customer for WP-47's vendored Lane-H proto**, and WP-47's scope note should say so.
  Ground rule #1 still binds: the dialect must reject an `io.llmproxy.provider_auth` block it
  cannot fully map, with its dotted path.
- **A latent gap increment 1a opened, to be closed by WP-21 (recorded 2026-08-03).**
  `ClusterHandle::request_headers_to_add` (`proxy-cluster/src/manager.rs`) returns `&[]` for
  `ClusterSource::Eds`, because an EDS cluster has no `ClusterConfig` to read from. That is
  correct and harmless *today* — EDS is a manager-level stub and the IR has no `Eds` discovery
  variant — but the moment WP-21 makes EDS real, an EDS-discovered cluster will silently carry
  **no credentials**, which is the `request_headers_to_add` P0 again by a different route. It
  will not fail any current test, because no test can construct a real EDS cluster yet. WP-21
  must either give `ClusterSource::Eds` a credential source or make the empty case a hard
  error; it must not inherit the silent `&[]`.
- **Acceptance:** differential-style scripted provider outage drills: primary 429s →
  fallback within policy, streams in flight never retried, attempt accounting exact. **Plus a
  credential-isolation test that is not optional:** a request that fails over from provider A
  to provider B must carry B's `Authorization` (and `anthropic-version`, and B's
  `extra_headers`) and must **not** carry A's. Assert the negative explicitly — asserting only
  that B's key is present passes just as well when both are sent.
- **The retry half of this WP is smaller than the bullets above imply (surveyed 2026-08-06,
  while increment 2 was in flight).** Two of the three retry-side deliverables turn out to
  need no new mechanism, and saying so is worth more than building them twice:
  1. **"Custom retriable predicate: 429" needs no new IR.** An upstream 429 is already
     expressible Envoy-natively as `retry_on: retriable-status-codes` plus
     `retriable_status_codes: [429]`, and both fields exist on `RetryPolicyIR`
     (`ir.rs:836-839`) and are honored by `trigger_fires` (`retry.rs:103`). Note that
     Envoy's `envoy-ratelimited` token is *not* this — it fires on the local ratelimit
     filter's own 429, not an upstream's. Combined with increment 2's `attempted_clusters`
     skip, a 429 from provider A retries onto provider B with nothing new in the retry
     engine. What remains is the dialect lowering `fallbacks:` to exactly this policy.
  2. **"Never retry after the first response byte of a stream" is already true by
     construction.** The router returns at `router.rs:585` the moment response *headers*
     arrive, handing back a streaming body; there is no retry decision anywhere after that
     point, so no byte forwarded downstream can ever be followed by a second attempt. The
     one post-headers retry that does exist (a retriable status, `router.rs:560`) drains the
     failed attempt's body first and has forwarded nothing downstream, which is
     Envoy-correct. `AttemptOutcome::ResetAfterHeaders` is therefore unreachable from the
     router's own paths today.
     **So this deliverable is a regression test, not a mechanism** — and it should still be
     written, because the property is currently an emergent consequence of where the
     `return` sits rather than a stated invariant. Anyone later adding mid-stream retry (a
     reasonable-sounding feature) would silently double-bill tokens and hand the client
     duplicated content, and nothing in the suite would object.
- **Cross-cluster validation has no home yet, and increment 2b needs one.** `lower_bootstrap`
  converts clusters one at a time (`lower.rs:82-95`); nothing ever looks at the assembled
  cluster map. An aggregate naming a member that does not exist — or naming another aggregate,
  which the manager refuses to recurse into — is exactly the class of error that must fail at
  config time with a dotted path (ground rule #1) rather than degrade into a 503 at runtime.
  **Decision: a `validate_cluster_graph` post-pass after the cluster loop**, which both
  front-ends inherit for free since the dialect lowers through this same pipeline. Also note
  `envoy/extensions/clusters/aggregate/v3/cluster.proto` is vendored but **not** in
  `proxy-api/build.rs`'s roots list, so its type URL does not resolve today; 2b must add it,
  as that file's own comment instructs. And Envoy *requires* `lb_policy: CLUSTER_PROVIDED` on
  an aggregate cluster, which the IR's `LbPolicy` has no variant for and `convert_cluster`
  currently rejects.
- **Increment 2 landed 2026-08-07/08 (`cb84f83`, `a2bfef7`, `d4ac161`, `399b954`) — the
  failover mechanism now exists and the v0.1.0 gate's failover clause is code-complete.**
  2a built the runtime mechanism (member-order failover via `attempted_clusters`, a host pick
  that yields its owning member) with a credential-isolation test that asserts the negative —
  B's request must **not** carry A's key, not just that B's key is present. 2b-i made the
  aggregate reachable from Envoy-mode config (`ClusterDiscoveryType::ClusterType` lowering,
  `LbPolicy::ClusterProvided` as a real IR variant, five fields — `load_assignment`,
  `transport_socket`, `typed_extension_protocol_options`, `metadata`, any non-`CLUSTER_PROVIDED`
  `lb_policy` — rejected outright on an aggregate as inert-and-therefore-silently-ignored
  otherwise). 2b-ii added `validate_cluster_graph`, a post-pass over the assembled cluster map
  run after (not inside) the per-cluster loop so declaration order doesn't matter; it rejects a
  missing member, a nested aggregate, a self-reference, or a duplicate member at config time
  with a dotted path. 2c made the `llmproxy` dialect lower `fallbacks:` to exactly this — an
  aggregate named `fallback:route-{index}`, members in listed order (listed order **is**
  failover order), `num_retries` raised to `max(attempts, members - 1)` so every member is
  reachable. The Host header follows the same per-cluster-headers mechanism increment 1a
  built, for the identical reason 1a existed: a route-level `host_rewrite_literal` would have
  sent the primary's Host to the fallback's endpoint.
- **The retry-side survey (recorded above, 2026-08-06) held — no new retry-engine mechanism
  was needed.** 429-as-retriable is existing `RetryPolicyIR` config; never-retry-after-first-byte
  is already true by construction. So the one dependency this WP carried on WP-14 is resolved
  without any WP-14 change.
- **Scope actually closes at same-dialect fallback — cross-dialect is a hard error, not built,
  and split into WP-52 (2026-08-08).** A `fallbacks:` entry naming a different dialect (e.g. an
  `openai`-shaped route falling back to an `anthropic` provider) is rejected at config time
  naming `routes[i].fallbacks[j]`. The request/response shape translation this WP's original
  bullet called for ("OpenAI↔Anthropic shape translation as an explicit, versioned mapping
  table") is real, substantial, un-started work — not a corner of this WP. See WP-52. **This WP
  is done for what it now covers: same-dialect provider fallback via an aggregate cluster.**
  Leaving it "open" indefinitely for scope that was never going to land this milestone would
  have been the less honest call than closing it at what actually shipped.
- **Acceptance criterion satisfied end-to-end 2026-08-08 (`c1314b6`), not just at the router-unit
  level.** `testing/diffrig/tests/failover_e2e.rs` is the differential-style outage drill this
  WP's acceptance bullet called for: the real `llm-proxy` binary, a real `llmproxy` dialect
  config with `fallbacks:`, real HTTP over sockets, a mock primary forced to 429. Three
  assertions, each mutation-tested (mutating the WP-35 mechanism it targets turns the matching
  assertion red, then restores clean): attempt accounting exact (one request per upstream); the
  credential-isolation negative (standby's own key, primary's key nowhere on the wire — not
  merely "the standby's key is present"); and the standby's own Host header. This is the
  evidence the v0.1.0 gate's failover clause needed to move from code-complete to verified.

#### WP-36 — Gateway API Inference Extension (EPP) support  (Size: M)  — **Priority: P2**
- Implement the Endpoint Picker protocol as consumed by Envoy AI Gateway / GKE Inference
  Gateway: ext_proc-based picker call (reuses WP-32 client), honor
  `x-gateway-destination-endpoint` by overriding LB host selection (ORIGINAL_DST-style
  host-override load balancer keyed off dynamic metadata — Envoy parity behavior),
  InferencePool semantics for endpoint sets.
- **In-process picker trait** as the hop-free alternative: same decision interface
  (prefix-hash affinity, queue-depth/util signals scraped from vLLM metrics endpoints),
  pluggable so KV-cache-aware strategies (CacheRoute-style) can be compiled in.
- **Acceptance:** conformance against the upstream inference-extension test EPP; A/B bench:
  in-process picker vs ext_proc picker latency delta published in WP-30 report.

#### WP-37 — Realtime endpoints over WebSocket  (Size: M)  — **Priority: P2**
Providers' realtime APIs (OpenAI Realtime, speech-to-speech/transcription services) are
WebSocket-based: long-lived bidirectional sessions, JSON event frames, usage reported in
events (e.g. `response.done`), model selected via query param or first session event.
Builds on the S10 core (WP-10/11/13) — this WP is the LLM layer on top:
- **Session-aware routing:** route on upgrade + query param (`?model=...`) using standard
  S1 matchers; optional first-event body peek (bounded, pre-101 config only via query/header
  — post-101 rerouting is impossible, document it). Sessions pin to the picked host for
  connection lifetime (no mid-session rebalance; EPP pick happens once at upgrade).
- **WS-frame-aware token metering (extends WP-34):** streaming parse of provider event
  frames for `usage` payloads without buffering or re-framing; per-session and per-key
  token accounting; session-count + concurrent-session limits as first-class limit
  descriptors (connection-oriented quotas matter more than request quotas here).
- **Realtime observability (extends WP-33):** session duration, time-to-first-event,
  event-rate metrics, per-model session gauges; access-log entry at session end with
  usage totals (+ periodic checkpoint option for very long sessions, PLAN.md Part 8.6).
- **Drain behavior:** on drain, send a proper WS Close frame (1001 going-away) ahead of the
  drain deadline instead of a raw TCP reset; `sessions_blocking_drain` gauge (Part 8.3).
- **Acceptance:** WS echo + scripted realtime-event differential vs Envoy for the S10 core;
  scripted OpenAI-Realtime-shaped session fixtures → exact usage accounting, session limits
  enforced at upgrade time (429 pre-101), drain sends Close frames (client observes 1001).

#### WP-38 — Simple config dialect (`proxy-simple-config`)  (Size: M)  — **Priority: P0**
> **Status: done** for the config-plane scope (14 tests): strict parse + env interpolation,
> lowering through the identical strict-parse→PGV→IR pipeline, `--config` / `--mode translate`
> in the binary, unenforced features surface as explicit warnings. Open until their WPs land:
> model-glob **body**-based matching (WP-35), fallbacks/limits/observability enforcement
> (WP-34/35/24), docgen CI job, diff-rig acceptance (WP-26).
The OSS on-ramp: an LLM-native config that compiles to Envoy resources — one engine, two
front-ends. **Normative schema: `schema/llmproxy-v0.schema.json`** (JSON Schema 2020-12,
descriptions on every field — user docs, editor autocomplete, and validation all generate
from it; the crate implements the schema and must never accept anything it doesn't define).
- **Parsing:** env-var interpolation (`${VAR}`) pre-parse; strict (unknown field → error with
  field path, same standard as Envoy mode); mode selection in the binary: `-c` = Envoy
  bootstrap, `--config` = dialect (plus top-level `version:` sniffing for a helpful error).
- **Lowering rules (deterministic, documented in the crate):** `providers` → clusters
  (LOGICAL_DNS or STATIC, upstream TLS w/ `ca_file`, auth-header injection per provider
  `type`, `connect_timeout`) + host-rewrite; `routes` → one listener + HCM + route table
  (model-glob → header/body-based match via the WP-35 model router; first-match-wins mirrors
  S1); `fallbacks`/`retries` → S3 retry engine + WP-35 fallback policy (LLM-safe defaults:
  connect-failure/429/5xx-before-first-byte only, never after first streamed byte);
  `idle_timeout` → per-route idle (no total timeout — deliberate divergence from Envoy's 15s
  default, dialect-only); `limits` → WP-34 token limiter + WP-37 session limits descriptors;
  `listen.tls` → downstream TLS with file-watch reload; `observability` → WP-24 sinks.
- **`llm-proxy config translate`:** prints the lowered Envoy bootstrap YAML (learning tool,
  escape hatch, and migration path); `config validate` for CI use.
- **Doc generation:** CI job renders `schema/llmproxy-v0.schema.json` → `docs/config.md`
  (every property: description, type, default, examples). Schema lint gate: every property
  MUST have `description` + `examples`/`default`; `additionalProperties: false` everywhere.
- **Schema evolution:** `version: 0` is frozen at first release; changes require a version
  bump + migration notes. Reserved top-level keys (`envoy`, `tracing`, `clusters`) rejected
  in v0 so they can be added compatibly.
- **Acceptance:** `examples/llmproxy.yaml` validates against the schema and, lowered, passes
  the WP-26 diff rig (translate output must be accepted verbatim by real Envoy except for
  `type.llmproxy.dev/*` filters, which are stripped for the Envoy side); TTHW drill: a new
  user with an OpenAI key reaches a working streaming gateway in <5 minutes following only
  generated docs; docgen output reviewed as a release artifact.

---

## Appendix S — Normative semantics (the "lives in C++" spec)

Sources: `envoy/http/filter.h` @ pinned tag, `route_components.proto`, `outlier_detection.proto`,
router-filter docs. ✅ = verified this pass; ⚠️ = verify at implementation time.

### S1 — Route matching  (binds WP-05, WP-12)

**S1.1 Virtual-host selection** by `:authority` (port stripped ⚠️ check
`strip_matching_host_port`), precedence ✅:
1. exact domain (`www.foo.com`)
2. suffix wildcard (`*.foo.com`, `*-bar.foo.com`) — **longest wildcard pattern first**
3. prefix wildcard (`foo.*`, `foo-*`) — longest first
4. `*` (at most one vhost may claim it)
Wildcards never match the empty prefix/suffix (`*-bar.foo.com` ≠ `-bar.foo.com` ✅).
No vhost match → 404 with response flag `NR`.

**S1.2 Route selection**: linear scan of the vhost's `routes`, **first match wins** ✅ — no
specificity re-ordering, ever. A matching route with an unsatisfiable action still wins
(e.g., cluster absent → 503 `NC`, not fall-through).

**S1.3 Path specifiers** ✅: `prefix` = byte prefix of `:path` *including query*
(⚠️ verify: prefix matches against path-with-query? Envoy matches prefix against the `:path`
header which includes query — confirm with fixture); `path` = exact match with query removed;
`safe_regex` = **full-path** match, query removed, RE2 semantics (reject look-around/backrefs
at config time); `path_separated_prefix` = match `p` exactly or `p/`-prefixed;
`case_sensitive` default **true**, applies to prefix/path/path_separated_prefix only.

**S1.4 Additional matchers**: all listed `headers` must match (AND); header match types:
exact / `safe_regex` / range / present / prefix / suffix / contains, each with `invert_match`;
`:method` etc. are just headers. `query_parameters` post-`?` matching. `grpc` route match
flag ⚠️. `runtime_fraction`: match diverted by runtime percentage before evaluating rest.

**S1.5 Weighted clusters** ✅: pick ∝ weight among entries (sum > 0); selection happens once
per request (stable across retries — retries reuse the chosen cluster); `metadata_match`
merge: entry-level overrides route-level.

### S2 — HTTP filter iteration  (binds WP-11; from `envoy/http/filter.h` ✅)

**S2.1 Ordering**: decoder filters run in config order; encoder filters in **reverse** config
order ✅. Dual filters appear in both chains. Filter instances are per-stream; destroyed in
reverse creation order.

**S2.2 Header statuses** ✅:
- `Continue` — next filter.
- `StopIteration` — headers held; resumes only on `continue_*()`, or on returning
  `Continue` from a later data callback of the *same* filter. While stopped, data callbacks
  for *this* filter still fire (data is not implicitly buffered!) — a filter that stops
  headers and gets data must itself return a buffering data status or data will pass the
  held headers. (This is the classic gotcha; encode it in tests.)
- `ContinueAndDontEndStream` — forward headers with `end_stream=false` even if request had
  no body; filter must later inject data with `end_stream=true` (via `inject_*`); using
  `add_*_data` + `continue_*` afterwards is **unsupported** ✅.
- `StopAllIterationAndBuffer` — nothing (headers/data/trailers) proceeds past this filter;
  incoming data buffered; **buffer overflow → 413 (decode) / 500 (encode)** ✅; resume via
  `continue_*()` only.
- `StopAllIterationAndWatermark` — as above but on overflow applies backpressure
  (readDisable / h2 flow control) instead of erroring ✅.

**S2.3 Data statuses** ✅:
- `Continue` — proceed; if headers are still held (plain `StopIteration`), they are sent first ✅.
- `StopIterationAndBuffer` — buffer chunk into the filter-manager buffer; overflow → 413/500.
- `StopIterationAndWatermark` — buffer + backpressure on overflow.
- `StopIterationNoBuffer` — stop, drop (do not accumulate); resume still via `continue_*()`.
  Buffered body is replayed to *subsequent* filters on resume, not to the stopping filter.

**S2.4 Trailers**: `Continue`/`StopIteration` ✅. Trailer arrival while data is stopped queues
trailers; resume delivers buffered data then trailers, in order.

**S2.5 Local replies** ✅: `send_local_reply` before response headers forwarded → synthesize
response and run it through the **encoder** chain (filters after the sender on decode path
never see the request; `is_local_reply` marked in StreamInfo; details string recorded).
After response headers already sent → reset stream. Local reply during encode → ship direct
to codec or reset ✅. `StopIterationForLocalReply` metadata status exists for this ✅.

**S2.6 1xx** ✅: separate encode callback; `StopIteration` blocks the 1xx; resumption
requires `continue_encoding()` or `Continue` from a later `encode_data`. 100-continue:
HCM handles `expect: 100-continue` (sends 100 upstream-independent when
`proxy_100_continue=false` ⚠️).

**S2.7 Buffer & injection APIs** ✅: `add_decoded_data(data, streaming)` legal from
headers/data/trailers callbacks (appends to buffer / emits); `inject_decoded_data_to_filter_chain`
callable outside callback context, delivers directly to *subsequent* filters incl.
`end_stream` signaling; `modify_decoding_buffer` only before data continued past the filter ✅;
`recreate_stream` (internal redirect support): only when request complete & body-free ✅.

**S2.8 Route cache**: route resolved lazily, cached per stream; any filter mutating
routing-relevant headers must call `clear_route_cache()` — the cache is *not* auto-invalidated ✅
(differential fixture required).

### S3 — Retries & timing  (binds WP-14; router docs ✅)

**S3.1 Budget**: `num_retries` default **1** ✅; `x-envoy-max-retries` header overrides;
also gated by CB `max_retries` (default 3 ⚠️) or, if configured, cluster `retry_budget`
(budget_percent default 20% ⚠️, min_retry_concurrency 3 ⚠️) which **disables** the max_retries CB.

**S3.2 Triggers** (`retry_on`, comma-list; header-appendable) ✅:
| value | fires on |
|---|---|
| `5xx` | any 5xx response **or no response at all** (reset/disconnect/timeout ↔ but NOT if per-try/global timeout when `timeout`-based exclusions apply ⚠️ verify: request timeout does count for 5xx? Envoy: timeout → 504 counts under 5xx but retries won't fire if global timeout exhausted) |
| `gateway-error` | 502/503/504 or no response |
| `reset` | disconnect / reset / read timeout before response |
| `reset-before-request` | reset before request fully sent |
| `connect-failure` | TCP/TLS connect failure or connect timeout (**not** request timeout) |
| `retriable-4xx` | **409 only** |
| `refused-stream` | h2 REFUSED_STREAM (always safe) |
| `retriable-status-codes` | codes in policy / `x-envoy-retriable-status-codes` |
| `retriable-headers` | response header matches policy / `x-envoy-retriable-header-names` |
| `envoy-ratelimited` | `x-envoy-ratelimited` present on response |
| `http3-post-connect-failure` | (defer with h3) |

`retry_grpc_on` ✅: `cancelled`(1), `deadline-exceeded`(4), `internal`(13),
`resource-exhausted`(8), `unavailable`(14) — from `grpc-status` trailer (or header for
trailers-only).

**S3.3 Timing** ✅: attempt n delay ~ **Uniform[0, min((2ⁿ−1)·B, M)]**, B=`base_interval`
default 25ms, M=`max_interval` default 10·B. Progression: 0–24ms, 0–74ms, 0–174ms….
`x-envoy-ratelimited` + rate-limited retry-after ⚠️ (`RateLimitedRetryBackOffStrategy` with
`retry-after`/`x-ratelimit-reset` headers — check version support).

**S3.4 Interplay**: per-try timeout (default = global timeout ✅) resets per attempt; global
route timeout (S4) spans **all** attempts incl. backoff — expiry mid-backoff → 504 now.
Retriable request must be fully buffered; body > buffer limit → not retriable, mark
StreamInfo. Host selection: previously-attempted hosts excluded via retry predicates,
`host_selection_retry_max_attempts` default 1 ✅ (LB re-pick attempts, then use what it got).
**Hedging** (`hedge_on_per_try_timeout`): per-try timeout fires → issue parallel attempt,
first good response wins, others reset; retries-after-hedge use same budget.

**S3.5 Headers** ✅: consume `x-envoy-upstream-rq-timeout-ms`,
`x-envoy-upstream-rq-per-try-timeout-ms`, `x-envoy-max-retries`, `x-envoy-retry-on`,
`x-envoy-retry-grpc-on`, `x-envoy-hedge-on-per-try-timeout` (internal-only headers: honored
only from internal requests unless configured; **always stripped** before forwarding
upstream/downstream per S9). Emit `x-envoy-attempt-count` (opt-in), increment per attempt.

### S4 — Timeouts  (binds WP-13; ✅ from route_components + router docs)

| timer | default | disable | on expiry |
|---|---|---|---|
| `route.timeout` (global, spans retries; starts at **request complete** i.e. end of request body ⚠️verify) | **15s** ✅ | `0s` ✅ | 504, flag `UT`, upstream reset |
| `per_try_timeout` (per attempt, from attempt start) | = global ✅ | unset | attempt failure (retriable as timeout) |
| `per_try_idle_timeout` | unset ✅ | unset | attempt failure |
| `route.idle_timeout` (per-stream, reset on any encode/decode activity) | unset (HCM `stream_idle_timeout` governs, default 5min ⚠️) | `0s` ✅ | 408/reset, flag `SI` ⚠️ |
| HCM `request_timeout` (request receipt: headers→end of request body) | 0=disabled ✅ | `0s` | 408 |
| HCM `request_headers_timeout` | 0=disabled ⚠️ | `0s` | reset |
| cluster `connect_timeout` | 5s ⚠️ | — | pool connect-failure |
| conn `idle_timeout` (downstream & upstream, no active streams) | 1h ⚠️ | `0s` | graceful conn close (GOAWAY/FIN) |
| `drain_timeout` (HCM, h2 goaway→close) | 5s ⚠️ | — | force close |

`x-envoy-expected-rq-timeout-ms` set on upstream request = effective timeout ✅ (grpc-timeout
interplay ⚠️: gRPC requests use `grpc-timeout` header when `max_grpc_timeout` configured —
check current field, it moved to `MaxStreamDuration`).

### S5 — Circuit breakers  (binds WP-15)

Per cluster × priority (DEFAULT used unless route priority HIGH). Defaults ⚠️(verify, stable
for years): `max_connections` 1024, `max_pending_requests` 1024, `max_requests` 1024 (h2/h3;
h1 uses connections+pending), `max_retries` 3, `max_connection_pools` unlimited.
Overflow behavior: pending overflow → immediate 503 + `UO` flag + `upstream_rq_pending_overflow`
counter + `x-envoy-overloaded` ✅; retry overflow → retry abandoned silently (original
response returned), `upstream_rq_retry_overflow` counter. `retry_budget` presence disables
`max_retries` accounting (S3.1). Gauges + `remaining_*` when `track_remaining`.

### S6 — Outlier detection  (binds WP-19; **all ✅**, from `outlier_detection.proto`)

Defaults: `consecutive_5xx`=5, `interval`=10s, `base_ejection_time`=30s,
`max_ejection_percent`=10, `enforcing_consecutive_5xx`=100%, `consecutive_gateway_failure`=5
w/ enforcement **0%**, success-rate: min_hosts=5, request_volume=100, stdev_factor=1900
(mean − 1.9σ), enforcement 100%; failure-percentage: threshold 85%, enforcement 0%,
min_hosts 5, volume 50; `max_ejection_time`=max(300s, base), growth = base ×
consecutive-ejection count, jitter 0, un-eject on passing active HC (default true),
`split_external_local_origin_errors`=false (local-origin folded into 5xx),
`always_eject_one_host`=false. Ejection = host marked, excluded from LB (until panic mode).
Emit Envoy's outlier event log JSON format (diffable, WP-19 acceptance).

### S7 — Load balancing  (binds WP-17)

Weighted RR via EDF schedule (smooth, Envoy-equivalent ⚠️); least-request: if all weights
equal → P2C over active request counts (choice_count default 2 ⚠️), unequal weights → EDF
weighted by `weight / (active+1)^active_request_bias` ⚠️; ring-hash: ketama on xxhash64 ⚠️
of `address:port` repeated by normalized weight, min ring 1024 ⚠️, request hash from route
`hash_policy` chain (first policy that produces a hash; `terminal` stops evaluation ⚠️);
Maglev table 65537 ⚠️. Panic threshold: healthy_hosts/total < 50% ⚠️ → LB over all hosts,
`lb_healthy_panic` counter. Priority levels: traffic to P0 scaled by its health%, spillover
per Envoy's overprovisioning factor (default 140 ⚠️). Degraded hosts, zone-aware routing:
explicitly out of v1 scope (documented rejection if configured? No — accept and ignore is
forbidden; **error** on `zone_aware_lb_config` until implemented).

### S8 — xDS client state machine  (binds WP-20..22; protocol docs ✅)

Per type: `state = {subscribed: Set<Name>, acked_version, last_nonce}`. On response:
validate **all** resources (WP-04) → all-or-nothing accept ✅ → apply → ACK(version, nonce);
any failure → NACK(prev version, nonce, error_detail) and **discard entire response** ✅.
Requests must echo latest nonce; responses with stale nonce ignored ⚠️(verify: client
ignores? server-side concern; client behavior = respond to every response). SotW: LDS/CDS
full-set semantics (absence = removal); **EDS/RDS absence ≠ removal** ✅. Ordering
expectation (server-side, but client must tolerate any order): make-before-break CDS→EDS→
LDS→RDS→removes ✅; client must not crash/drop on out-of-order — warming handles it.
Reconnect: new stream, re-send all subscriptions with acked versions ✅ (versions persist
across streams for same server ✅). Resource-name matching is exact-string incl. wildcard `*`
subscription for LDS/CDS.

### S9 — Header sanitization & standard mutations  (binds WP-13; ⚠️ verify table against
`docs: configuration/http/http_conn_man/headers` at pinned version)

- `x-forwarded-for`: `use_remote_address=true` → append downstream remote IP;
  false (default) → pass through untouched. `xff_num_trusted_hops` affects
  internal/external determination (rightmost-N). "Internal" = RFC1918 source AND
  single XFF entry ⚠️ — internal/external drives `x-envoy-*` header trust (S3.5) and
  `internal_address_config`.
- `x-request-id`: generate UUID if absent+`generate_request_id` (default true); edge proxies
  should force-regenerate (`always_set_request_id_in_response` opt); tracing decision encoded
  in UUID variant nibble (Envoy trick — implement for trace parity or document divergence).
- `x-envoy-*` request headers from **external** sources: stripped (unless
  `suppress_envoy_headers` semantics / trusted). `x-envoy-expected-rq-timeout-ms`,
  `x-envoy-attempt-count` set per S3/S4. Response direction: `x-envoy-upstream-service-time`
  added; internal `x-envoy-*` stripped toward downstream external clients.
- `:authority`/`host` rewrite rules (S1 actions); `x-forwarded-proto` set from downstream
  transport; `x-forwarded-host` on host rewrite (opt-in `append_x_forwarded_host`);
  `server` header: overwrite/append-if-absent/passthrough per HCM config; `date` added;
  hop-by-hop headers (`connection`, `te` except `te: trailers` for gRPC, `upgrade`,
  `transfer-encoding`) sanitized per codec rules.

---

### S10 — HTTP upgrades & WebSocket  (binds WP-10, WP-11, WP-13, WP-37; arch docs ✅)

**S10.1 Enablement hierarchy** ✅: `upgrade_configs` at HCM level, overridable per route —
route setting wins when present:

| HCM | Route | Result |
|---|---|---|
| enabled | (unset) | enabled |
| enabled | disabled | disabled |
| disabled | enabled | enabled |
| disabled | disabled | disabled |

(⚠️ verify at implementation whether an *unconfigured* HCM allows `websocket` by default at
the pinned version — the arch doc's table implies enabled-by-default; historical behavior
required listing the upgrade type. Pin with a diff-rig fixture either way.)
Disallowed upgrade type → **403**. Upgrade matching is case-insensitive on the `Upgrade`
header value.

**S10.2 Post-101 data flow** ✅: upgrade headers, any request/response bodies, and the
upgraded payload all pass through the (per-upgrade-type, if configured) HTTP filter chain as
normal header/data callbacks. Buffering filters are incompatible with upgrades — reject at
config time when a buffering filter is on an upgrade-enabled route's chain. No retries,
no hedging, no per-try semantics after 101; route `timeout` does not bound the upgraded
stream (⚠️ verify — long-lived by design), idle/stream-idle timeouts still apply.

**S10.3 h2 extended CONNECT (RFC 8441)** ✅: with upstream h2 `allow_connect`, an h1
`GET + Upgrade: websocket` becomes h2 `CONNECT` with `:protocol: websocket`; downgraded back
to h1 Upgrade on the next hop. Constraints (Envoy-documented): method assumed GET on
downgrade; upgrade requests/responses **with bodies** are not proxied across the h2 hop.
Downstream h2 extended-CONNECT accepted when h2 options enable it.

**S10.4 CONNECT** ✅: disabled by default (403). Proxy mode forwards CONNECT upstream;
termination mode (`connect_config`) strips to raw TCP + synthesized 200. Both deferred to
Phase 7; strict-mode config error until implemented.

**S10.5 Stats** ✅: `downstream_cx_upgrades_total`, `downstream_cx_upgrades_active`
(bundled across upgrade types). Drain: upgraded streams count as active for drain purposes;
WS close-frame courtesy on drain is a Lane H behavior (WP-37), not Envoy parity.

---

### Cross-cutting work packages (added 2026-07-25)

Both come out of defects found while landing WP-13/14/24/26, not from the original decomposition.

#### WP-39 — IR readership guard (Size: S, **hygiene / correctness**)  — **Priority: P1**
- **The bug class it exists for.** `RouteEntry.request_headers_to_add` was lowered correctly by both
  config front-ends and read by no runtime code, so every request reached its provider without
  credentials. Strict mode did not catch it: strict mode proves a config field maps *into the IR*,
  and this one did. Nothing proves the IR field is then *consumed*. A field can pass parsing,
  validation, PGV, `--mode translate`, the corpus scorecard, and the config differential while being
  inert at runtime — every existing check looks at the config side of the seam.
- **Build:** a test (or `xtask`) that enumerates public fields of the runtime-facing IR structs and
  asserts each has at least one reader outside `proxy-config`. A hand-rolled version of this sweep
  found the P0 plus two known-inert fields and one false positive, so the shape is proven; make it
  automatic and CI-enforced. False positives are real and must be expressible: `VirtualHostIR.domains`
  is consumed *inside* `proxy-config` by `RouteTable::new`'s precomputed `DomainIndex`, which is
  correct. Provide an explicit allowlist whose entries each carry a reason and, where applicable, the
  WP that will consume the field.
- **Acceptance:** reverting the `request_headers_to_add` router fix makes the guard fail; the two
  currently-inert fields (`HttpConnectionManagerConfig.access_logs`, `stat_prefix`) are allowlisted
  with their owning WP and drop off the list when consumed.

#### WP-40 — Dependency-tree review & cleanup (Size: S→M, owner-requested)  — **Priority: P2**
- **Why.** The access-log sink hit a genuine cycle constraint (`proxy-config` → `proxy-observability`,
  never the reverse), and a worker's first instinct was to duplicate an enum across the seam. That
  resolved cleanly by moving `AccessLogSink` into `proxy-observability` and re-exporting it, but it is
  the second time an edge has forced a design decision — a real cycle was hit once before, when
  `proxy-cluster` carried an unused `proxy-core` dep referenced only in a doc comment, which also
  masked that `proxy-cluster` used `rand` only transitively.
- **Build:** audit every crate edge for necessity and direction; remove unused/transitively-relied-on
  deps; write down which crate owns which shared type and why, so the next cross-cutting type has an
  obvious home. Preserve the ground-rule-#2 boundary — generated protos stay confined to
  `proxy-config` and `proxy-xds`.
- **Acceptance:** a documented dependency graph in `docs/`; no unused deps (`cargo-udeps` or
  equivalent in CI); no duplicated same-shaped types across a crate boundary.

#### WP-41 — Black-box QA suite (Go) (Size: M)  — **Priority: P1**
- **Why.** Every Rust test in this repo is written by someone who has read the code, and shares its
  blind spots. On its first day this suite found four defects that code review had walked past —
  one of them *described as intended* in its own doc comment. See `testing/qa/SCENARIOS.md`.
- **Build:** a Go module under `testing/qa` with zero dependencies. It knows only the built binary,
  a config file, and what a client observes on the wire. Being a different language makes the
  boundary physical rather than a convention — a Go module cannot import a Rust crate by accident.
  `make ci` runs it, skipping **loudly** when the Go toolchain is absent.
- **Process:** scenarios come from the repo owner; the `qa-analyst` agent may propose candidates.
  **Every case is owner-approved before a test is written.** `SCENARIOS.md` is the reviewed spec and
  is tracked in git via an explicit `.gitignore` exception.
- **Acceptance:** cases carry their QA-id into the test name; a case blocked by a product gap
  degrades to a *named* skip rather than a weakened assertion, so it cannot silently pass.

#### WP-42 — Spend controls & budgets (Size: M)  — **Priority: P1**
- **Why.** Competitive review (Vercel AI Gateway, 2026-08-01) treats per-key budgets and per-user
  spending limits as a first-class feature, and it is often the actual reason a team puts a gateway
  in front of providers at all. WP-34's token rate limits are **not** this: a tokens/minute cap is a
  throttle, not a budget. Nothing else in this plan says "this key may spend $X, then stop."
- **Build:** a cost model over WP-34's four non-overlapping token buckets (input / cache-read /
  cache-write / output) priced per model; budget scopes (key, user, project) with a period; and an
  enforcement point that rejects rather than queues once a budget is exhausted.
- **Depends on:** WP-33 (usage on live traffic) and WP-34 (extraction — already done).
- **Acceptance:** a request that would exceed a configured budget is rejected with a distinguishable
  status and response flag; spend accounting survives a streamed response (usage arrives at stream
  end, so a naive header-time hook under-counts every stream).

#### WP-43 — Response caching (Size: L)  — **Priority: P2**
- **Why.** A standard AI-gateway feature we have no analogue for; the cheapest possible token is one
  never bought.
- **Build:** exact-match caching first (prompt + model + params), with an explicit position on what
  is *not* cached. Streaming makes this genuinely hard: a cached SSE response must be replayed as a
  stream, and the cache entry can only be written once usage is known at stream end.
- **Open question, decide before building:** semantic (embedding-similarity) caching is a different
  product with different correctness risks — a near-miss served as a hit is a wrong answer, not a
  slow one. Do not fold it in silently.
- **Acceptance:** a cache hit is observable in the access log; a hit replays as a stream, not a
  single flush (the QA-3 property must still hold on a cached response).

#### WP-44 — Cost-aware model routing (Size: M)  — **Priority: P2**
- **Why.** The natural extension of WP-35: route by *price* as well as availability — cheap requests
  to a cheap model, hard ones to a strong one.
- **Build:** extends WP-35's model router with a per-model cost dimension from WP-42's cost model.
- **Depends on:** WP-35 (model routing + fallback) and WP-42 (cost model).
- **Acceptance:** routing decisions are explainable — the chosen model and the reason appear in the
  access log, because a router that silently downgrades a model is indistinguishable from a bug.

#### WP-45 — Request-body rewrite pipeline (Size: M)  — **Priority: P0** · **Milestone: v0.1.0**
> **Consumer B (body-based model routing) is the next increment — owner direction 2026-08-04,
> raised above the rest of WP-35.** The reason is that today the `routes:` surface is
> effectively decorative for real clients: model matching reads the `x-llmproxy-model` request
> header, and OpenAI and Anthropic SDKs send the model in the JSON **body** and no such header.
> So a multi-provider routes table silently sends every request to the `*` backstop. It looks
> configured and it does not route. Provider failover (WP-35) is the named gate clause, but a
> routing table that does not route is the worse defect, and it is reachable from the shipped
> example config.
>
> **The machinery is already built.** `BodyFacts.model` is extracted today
> (`proxy-filters/src/body_rewrite.rs`), `modify_decoded_headers` exists
> (`proxy-http/src/filter.rs:175`), and `clear_route_cache()` exists (`filter.rs:189`). The
> remaining work is to join them, not to build them.
>
> **Design decisions, made in the orchestrator (2026-08-04):**
> 1. **Extend `body_rewrite_filter`; do NOT add a second body-scanning filter.** This WP exists
>    precisely because two independent scanners would mean two disagreeing buffer caps. One
>    scan, one held prefix, two consumers.
> 2. **Separate the scan decision from the splice decision.** Today `decode_headers` short-
>    circuits to `PassThrough` when `dialect != OpenAi`, because the only consumer was the
>    OpenAI-only `include_usage` splice. Model extraction is dialect-agnostic — an
>    Anthropic-dialect request still has a `model` field and still needs to match a
>    `claude-*` route. So: scan for every dialect, splice only for OpenAI.
> 3. **No new config knob.** When the filter is in the chain it always publishes the model
>    header. Its borrowed `RuntimeFeatureFlag` config has no room for a third fact (WP-47), and
>    inventing one would be a fourth stretched field. Consequence: the dialect must insert the
>    filter whenever `routes` or `models` exist, not only when `force_usage_reporting` is on.
> 4. **The filter must OVERWRITE a client-supplied `x-llmproxy-model`, never append or defer to
>    it.** This is a security property, not a tidiness one. Routing is header-based today, so a
>    client can currently steer its own request to a different provider — a cheaper model, a
>    different tenant's credential path, a route with a laxer limit — just by setting the
>    header. Once the body is the source of truth, the header must be derived, never trusted.
>    A request whose body has no extractable model must have any client-supplied value
>    **removed**, not left standing.
> 5. **`ScanOutcome::CapExceeded` means absence is not proven.** A `model` field sitting past
>    the prefix cap yields `None`. That must route to the backstop *deliberately*, with a test
>    naming the behavior, rather than falling through by accident.
> 6. **Cross-crate constant hazard, applies here exactly as it did to WP-35 increment 1b.**
>    `MODEL_HEADER` (`x-llmproxy-model`) is defined in `proxy-simple-config` and would be
>    consumed by a filter in `proxy-filters`. Two crates agreeing on a string by convention is
>    the shape that produced the `io.llmproxy.provider_auth` seam gap found 2026-08-03, where
>    each crate's tests pinned its own literal and nothing tested the join. **Acceptance
>    requires one end-to-end test** that drives a real request with a model in the body through
>    a dialect-generated config and asserts it reached the right cluster — asserting on
>    behavior, not on the header string.
- **Why.** Two v0.1.0 features need to read and edit the JSON request body, and neither can
  exist without it. Building it once, deliberately, beats two half-implementations that
  disagree about buffering limits.
  1. **Forced usage reporting.** Verified 2026-08-01 against a real OpenAI-compatible
     upstream: without `stream_options.include_usage`, a streamed response carries **no
     usage block at all**. So today a streaming client that doesn't opt in produces no
     token data — the WP-33 filter runs correctly and finds nothing. That is the most
     common request shape in existence, and token accounting is the product. Non-streaming
     OpenAI and all Anthropic traffic are unaffected (Anthropic reports usage in
     `message_start`/`message_delta` with no opt-in), so the gap is exactly one quadrant:
     **OpenAI-dialect + streaming**.
  2. **Body-based model routing.** The dialect matches models on the `x-llmproxy-model`
     header today and warns that it does. Real clients put the model in the body. This is
     WP-35's "body-peek model router" bullet — it moves here as a *consumer* of the shared
     machinery rather than a second implementation of it.
- **Build:**
  - **Bounded PREFIX scan, never whole-body buffering.** This is the load-bearing design
    decision and the obvious approach is wrong. A "buffer the body, parse it, re-serialize"
    pipeline dies on multimodal requests: a vision call carries base64 image data inline and
    runs to megabytes, so any cap large enough to admit it is also large enough to let
    `cap × concurrent_streams` exhaust the worker — and any cap small enough to be safe
    silently drops exactly the requests a customer most wants metered. Both horns are
    unacceptable, so don't buffer the body.
  - What makes the bounded approach work: **every field we need is a top-level scalar, and
    the bulk is nested inside `messages`.** `model`, `stream`, and `stream_options` are
    siblings of `messages`, not children of it, and SDKs emit them early. So scan the body
    with a depth-tracking incremental tokenizer (same shape as the `SseUsageScanner` already
    in `proxy-filters/src/usage.rs`) that skips over nested structures **without
    materializing them** and retains only the handful of top-level keys of interest. Memory
    is O(prefix cap), not O(body) — a 40MB vision request costs the same as a 2KB one.
  - **Mutation is a prefix splice, not a re-serialization.** `stream_options` is injected
    immediately after the opening `{`, which lives in the held prefix. Hold bytes only until
    the decision is made (found `stream`, or hit the cap), splice, emit the prefix, then
    stream every remaining byte through **untouched**. `content-length` adjusts by the exact
    injected length; on a chunked request nothing needs recomputing at all. The body is
    never reassembled, so it also never round-trips through a JSON serializer that could
    reorder keys or renormalize numbers.
  - **`content-length` adjustment needed a seam that did not exist (found 2026-08-01).** This
    bullet assumed a decode filter could update the request's `content-length`. It could not:
    every `content-length` code path in `proxy-http` was response-side, nothing recomputed the
    request's, and `DecoderCallbacks` had no way to touch request headers after
    `decode_headers` returned — which is exactly when the injection decision gets made, since
    it depends on body bytes. Splicing without it sends N+42 bytes under `content-length: N`:
    a protocol error on every injected request.
    The alternative — strip `content-length` and force `transfer-encoding: chunked` — was
    **rejected**: it changes wire framing on every OpenAI-dialect request including the ones
    we never modify, and this project treats request transparency as a property worth paying
    for (cf. the 2026-08-01 "never synthesize SSE frames" decision). So WP-45 increment 2
    splits: **2a** adds `DecoderCallbacks::modify_decoded_headers` (mirroring the existing
    `modify_decoding_buffer` idiom, returning `false` once headers can no longer affect the
    upstream request), **2b** builds the filter on top of it.
  - Prefix cap default 64KiB, configurable — but note it now bounds *how far in we look for
    top-level keys*, not how large a body we accept. Bodies of any size pass through.
  - If the keys aren't found within the window, or the body isn't valid JSON: **pass through
    untouched and continue**, never fail the request, and record the skip. A proxy that 400s
    a request it merely failed to *understand* is worse than one that forwards it unmetered.
    Worth stating plainly: a client that puts `messages` before `model` will fall out of the
    window and route by header. That is a real, accepted limitation — the alternative is
    unbounded buffering.
  - Consumer A: inject `stream_options.include_usage = true` when `stream == true` **and**
    the route's usage dialect is `openai`. Never touch Anthropic bodies — it is not a field
    there, and adding it risks a 400 from a strict provider.
  - Consumer B: extract `model` for routing — set a cluster-selection header / dynamic
    metadata, then `clear_route_cache()` (S2.8) so standard Envoy routing takes over via
    `cluster_header`. Works with plain Envoy route configs, not just the dialect.
  - Dialect surface: `observability.force_usage_reporting` (default **true**), so an
    operator who wants strict passthrough can turn it off.
- **The transparency decision (owner, 2026-08-01).** `include_usage` makes the provider emit
  an extra final SSE frame with `choices: []` and a usage block — a frame the client did not
  ask for. This is a deliberate, bounded exception to the 2026-08-01 "never modify SSE
  streams" rule: that rule forbids *us* synthesizing frames (an unclean EOF is the honest
  signal); this asks the **provider** for spec-compliant data it already knows how to emit.
  Owner's call, recorded because the two rules look contradictory from outside: the change
  is acceptable *because* it is confined to adding usage data, which is the point of the
  product. It does not license any other body or stream mutation.
  - Known hazard to document in user-facing docs: a client iterating `choices[0]` without a
    guard will crash on the usage frame. Well-behaved SDKs handle it; ours is the hand-rolled
    client. This is what the escape hatch is for.
- **Depends on:** WP-33 (per-route dialect — decides whether a body is OpenAI-shaped), the
  S2 buffering machinery (WP-11), ADR-0004's filter chain.
- **Acceptance:**
  1. A streaming OpenAI request **without** `stream_options` produces an access log with
     real, non-`"-"` `llm_input_tokens`/`llm_output_tokens`. This is the whole WP; against
     a real third-party upstream (`local_openai_smoke.rs`), not a mock, since a mock that
     reports usage unconditionally cannot fail this test.
  2. A client that **already** set `stream_options.include_usage` sees its body forwarded
     unchanged (no duplicate key, no reordering surprise).
  3. An Anthropic-dialect route's body is byte-identical in and out.
  4. A non-JSON body, and a body whose keys fall outside the prefix window, both reach the
     upstream untouched, with the request succeeding and the skip visible in the log.
  4b. **A multimodal request works and is metered.** A body carrying several MB of inline
     base64 image data, with `model`/`stream` in their normal leading position, is injected
     into correctly, forwarded byte-identical after the splice point, and produces real
     token counts. Assert peak memory does not scale with body size — this is the criterion
     that fails if someone "simplifies" the scanner back into a full-body buffer, which is
     the single most likely way this WP gets built wrong.
  5. Body-based routing: a request whose `model` is only in the body reaches the right
     provider, with no `x-llmproxy-model` header set — and the dialect's stale
     "header-matching only" warning is gone.
  6. Streaming is not regressed: the request-body buffer must not delay *response* bytes.
     `local_openai_smoke.rs`'s arrival-spread assertion covers this.

#### WP-46 — TPOT in the access log  (Size: S)  — **Priority: P0** · **Milestone: v0.1.0**
- **Why.** The v0.1.0 gate requires per-request token counts **and TTFT/TPOT** to reach the
  access log for live traffic. `%LLM_TTFT%` exists; there is no TPOT operator, so the gate
  clause is half met. Found 2026-08-01 by auditing the gate clause by clause — no test
  covers a *missing* operator, and nothing else would have surfaced it.
- **The trap, and why this is not simply "add a reader".** `StreamInfo::LlmStats` already
  carries `max_inter_chunk`, and the obvious move is to render it as `%LLM_TPOT%`. That
  would be **wrong**: its own doc defines it as the *largest gap between two consecutive
  chunks* — "the tail of the TPOT distribution, which is what users feel as a stall" — not
  TPOT. Publishing a max-gap under a TPOT label would put a number in customers' dashboards
  that does not mean what its name says, which is worse than the field being absent.
- **Build:**
  - `%LLM_TPOT%` = mean time per output token, computed at render time as
    `(duration − ttft) / output_tokens`. Every input already reaches `LogContext`
    (`duration`, `llm_ttft`, `llm_tokens.output`), so this needs **no new `StreamInfo`
    plumbing** — it is arithmetic in the formatter.
  - Guard the degenerate cases the way the other LLM operators do: `output_tokens == 0`, a
    missing TTFT, and `duration < ttft` all render `-` rather than a garbage number or a
    division panic. Per WP-48, the arithmetic saturates.
  - Expose `max_inter_chunk` **separately** as its own operator (e.g. `%LLM_MAX_STALL%`)
    rather than discarding it — it is a genuinely useful stall metric, it is already
    computed, and it is currently unreadable. `response_chunks` is in the same position.
- **Depends on:** WP-33's usage filter (populates the fields), WP-24's format engine.
- **Acceptance:** a streamed response through the proxy produces an access-log line whose
  `%LLM_TPOT%` equals `(duration − ttft) / output_tokens` within rounding, asserted against
  a scripted response with known timing and a known token count — not a mock that reports
  the value back to itself. A non-streamed response, and a response with zero output tokens,
  both render `-`. Mutation: rendering `max_inter_chunk` as `%LLM_TPOT%` must fail the test,
  since that is the specific mistake this WP exists to avoid.
- **Completeness gap, found+fixed 2026-08-08 (b0485e8), while building the verification this
  WP's own acceptance criterion calls for.** The operators landed 2026-08-02 and the acceptance
  criterion above was satisfied at the unit level, but **neither `llmproxy` dialect access-log
  format (text or JSON) ever emitted `%LLM_TPOT%`/`%LLM_MAX_STALL%`/`%LLM_RESPONSE_CHUNKS%`** —
  both formats stopped at `%LLM_TTFT%` in `lower.rs`. A user configuring this proxy through its
  own primary surface (the dialect, not hand-written Envoy YAML) could not obtain TPOT at any
  setting, while the v0.1.0 gate names it explicitly. Fixed: both formats now carry all three.
  New QA-10 (`testing/qa/SCENARIOS.md`) is the end-to-end acceptance evidence this WP's own
  criterion asked for and never had until now; in writing it, it also caught a real bug —
  `%LLM_RESPONSE_CHUNKS%` over-reported by exactly one on every response with a body
  (`encode_data` timed the synthetic empty end-of-stream frame as a chunk, which also fed a
  phantom gap into `%LLM_MAX_STALL%`) — also fixed.

#### WP-47 — Vendored Lane-H filter proto  (Size: M)  — **Priority: P1** · **Milestone: v0.1.0**
- **Why.** `FilterRegistry::register` keys on `type_url` and **asserts** on a duplicate, so
  every Lane-H filter needs a distinct one. With no vendored Lane-H proto, three filters have
  each borrowed an unrelated already-compiled Envoy message and read fields whose names
  happen to fit:
  `llmproxy.usage` → `DataSource.inline_string`;
  `llmproxy.body_rewrite` → `RuntimeFeatureFlag.default_value`/`runtime_key`;
  `llmproxy.token_limit` → `RateLimitSettings.max_tokens`/`fill_rate`, which is really
  Envoy's *xDS discovery throttling* config.
  Each of those three modules independently documents that a vendored proto is the real
  answer. The fourth filter has to stretch a fifth message.
- **A fourth customer, and it is not a filter (added 2026-08-03).** WP-35 increment 1b carries
  per-provider credentials to `ClusterConfig.request_headers_to_add` through
  `Cluster.metadata.filter_metadata["io.llmproxy.provider_auth"]`, because no Envoy `Cluster`
  field exists for it and the dialect can only reach the IR by emitting Envoy config. That is
  a better-founded borrow than the three above — `filter_metadata` really is meant for
  arbitrary per-cluster data — but it is still an untyped `google.protobuf.Struct` holding
  what should be a typed message, and it means this WP's surface is no longer "the Lane-H
  filters" but "everything Lane-H needs that Envoy has no field for". **Credentials travelling
  through an unvalidated Struct raises this WP's priority case**: a typo in the metadata shape
  is a provider that silently gets no auth header.
- **The cost is not aesthetic.** A reader cannot tell config *intent* from a borrowed message
  name; `--mode translate` output shows operators a type URL that describes a different
  feature; and every filter is capped at whatever fields its borrowed message happens to
  have — which is exactly what forced WP-34's thin slice (`LimitOn::Total`, one fixed bucket
  key, no per-descriptor config).
- **Build:** one `llmproxy/filters/v0/*.proto` vendored into `proxy-api` and reachable from
  `build.rs`'s roots (note `envoy.type.v3.TokenBucket` is vendored but **not** compiled —
  it is not transitively imported by any current root, which is why WP-34 could not use it).
  Migrate the three filters onto real messages, keeping the old type URLs accepted for one
  release so existing configs keep loading.
- **Acceptance:** all three filters parse their own proto; a config using a legacy borrowed
  type URL still loads and logs a deprecation warning; the schema-lint and `--mode translate`
  output name Lane-H messages rather than unrelated Envoy ones.

#### WP-48 — Sweep arithmetic on wire-derived numbers  (Size: S)  — **Priority: P1** · **Milestone: v0.1.0**
- **Why.** Two instances of one defect were found by review on 2026-08-01, both a plain `+`
  on a number that arrived over the wire:
  `TokenUsage::total()` summed four provider-reported `u64`s on the live access-log path, and
  the WP-45 `content-length` fix-up added to a value parsed from a **client** header. Both
  panic the worker in debug and wrap silently in release; the second is downstream-reachable,
  so any client could trigger it. Two in one day is a pattern, and **the suites stayed green
  through both** — neither was found by a test.
- **Build:** audit every arithmetic operation on a value parsed from a request, a response,
  a header, or a provider body. Saturating (or explicitly clamped) everywhere, with a test
  per site that panics or wraps without it. Prefer making the *parse* clamp at its boundary
  over auditing each downstream use, where that is possible.
- **Acceptance:** each converted site has a test using boundary inputs (`u64::MAX`, and the
  largest value the parser will accept) that fails against the unfixed arithmetic. A grep-based
  or lint-based guard against reintroduction is a stretch goal, not the deliverable.
- **Landed 2026-08-07 (`41f1c59`), re-scoped by the audit itself.** There was no live overflow
  bug: every wire-derived arithmetic site outside `usage.rs` already saturates. The audit found
  a different defect in the same class instead: `serde_json::Value::as_u64()` returns `None`
  for **any** JSON number that is not a non-negative integer — including an ordinary `150.0`,
  which real providers emit — so `read_tokens`'s `unwrap_or(0)` billed a real usage report as
  **zero**, silently, with the request succeeding and nothing logged. All five `as_u64()` call
  sites now route through one `token_count` helper: a non-negative integer passes through, a
  non-negative finite float truncates toward zero, anything else (negative, non-finite,
  non-number, absent) is `None` — never `0`. `None` is the load-bearing choice: downstream it
  renders as absent ("this provider reported no usage"), where `0` is a number someone bills
  against ("this provider reported zero tokens").
- **Deliberately not done: unifying `TokenUsage`, `LlmTokenUsage`, and `LlmTokens`.** The audit
  flagged the four-bucket sum as triplicated across the three types, but all three `total()`
  implementations already saturate correctly — merging them buys no correctness fix and is a
  cross-crate dependency-direction decision, out of scope for an arithmetic sweep.

#### WP-49 — Backend taxonomy: providers, models, and credential schemes  (Size: L)  — **Priority: P0** · **Milestone: v0.1.0**
- **Why (owner, 2026-08-01).** One logical model is served by several backends: Claude by
  Anthropic *or* Vertex *or* Bedrock; Kimi-K2 by Nebius *or* Vertex. The v0 dialect cannot
  express this at all — a `RouteRule` names exactly one `ProviderModelRef`, so a model has
  exactly one backend. This WP is the **naming and data model only**; which backend gets
  picked (fallback / weighted split / cost-aware) is deliberately deferred to WP-35 and WP-44.
- **The real problem is not the list, it is that `Provider` conflates four things:** the
  *endpoint* (host, TLS, URL path shape), the *credential scheme* (static header vs minted
  OAuth token vs per-request signature), the *wire dialect* (OpenAI- vs Anthropic-shaped), and
  the *model catalogue* (which models, under which upstream IDs). Multi-backend is only
  expressible once those separate.
- **The hierarchy (three levels):**
  1. **Provider type** — built into the code, not config: `openai`, `anthropic`,
     `openai-compatible`, `azure-openai`, `vertex`, `bedrock`. Fixes the endpoint shape, the
     credential *mechanism*, and the default dialect.
  2. **Provider instance** (today's `providers:` map — the name stays): a named, credentialed
     placement of a type. Config supplies the *material* (api key, service-account file,
     region, project, deployment host), never the mechanism. Two instances of one type is a
     first-class case — `vertex-us` and `vertex-eu`, or two Anthropic accounts with separate
     quota pools — which the current model also cannot express.
  3. **Model** (new `models:` block): a logical name clients use, mapping to an ordered list of
     `{provider, model, dialect?}` entries. `ProviderModelRef` already parses `provider/model`,
     so per-provider upstream IDs are half-built already, and the shorthand string form reuses it.
- **Vocabulary (owner, 2026-08-02): the config surface has exactly two nouns, `providers` and
  `models`.** Vertex, Groq, Anthropic, and Nebius are all *providers*; a model names the providers
  that serve it. The word "backend" is deliberately absent from the config — an earlier draft of
  this WP used it for the per-model binding while the owner uses it for the connection object, which
  would have made one word mean two things depending on nesting depth. The per-model list is
  therefore `models.<name>.providers[]`, whose entries carry `provider:` and so read consistently
  against the top-level `providers:` map they reference. Each entry accepts either the
  `provider/model` shorthand string or an object form (needed when `dialect` must be explicit);
  both must lower identically, pinned by a test.
- **Credential schemes are a trait, not a schema field.** The mechanism follows the provider
  type: static header (`anthropic`, `openai`, `openai-compatible`, `azure-openai`), minted
  OAuth2 with refresh (`vertex`), per-request SigV4 signing (`bedrock`). Introduce a
  `CredentialProvider` seam with the static implementation only — the same shape as WP-34's
  `BudgetStore`. **Critically, the two unbuilt schemes are not header injection:** an OAuth
  token needs a refresh loop with its own failure mode, and SigV4 signs the canonical request,
  so it must run *after* body rewriting (WP-45) and cannot be a `request_headers_to_add` entry.
  Both therefore need a router hook that does not exist yet.
- **Dialect must follow the WIRE FORMAT, not the provider name — and for two types it cannot
  be derived at all.** Vertex serves Anthropic-shaped Claude, Google-shaped Gemini, *and*
  OpenAI-shaped Kimi; Bedrock is similar. So `dialect` is derivable for the unambiguous types
  and **required** on the backend entry for `vertex`/`bedrock` — omitting it is a load error,
  not a guess. Getting this wrong is not cosmetic: `usage_dialect`'s own doc records that the
  OpenAI parser on an Anthropic body *partially* matches, billing a customer against a number
  nobody computed.
- **URL path templating.** Anthropic is `POST /v1/messages`; Vertex is
  `/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model}:streamRawPredict`;
  Azure puts a *deployment name* in the path plus an `api-version` query parameter. Host rewrite
  and `prefix_rewrite` do not reach this — the provider type owns a path template rendered from
  instance + model variables.
- **Accepting a list without selection semantics is a ground-rule-#1 hazard.** Until WP-35
  lands, entries after the first are not selectable. They must **warn precisely** (naming
  `models.<name>.backends[N]` and why), never be silently accepted — the same standard the
  `limits` surface is held to.
- **Model names support `*`, matched through a trie (owner, 2026-08-02).** The catalogue is
  keyed by model name, and those keys take wildcards — `claude-*` and `gpt-4*` are how an
  operator avoids enumerating every point release the day a provider ships one.
  - **Precedence is the normative part; the trie is how it is made fast.** Exact match wins,
    then the **longest** matching prefix, then a bare `*` catch-all. So with both `claude-*`
    and `claude-sonnet-*` defined, `claude-sonnet-4-5` resolves to the latter. This is
    deliberately the same shape as S1's virtual-host domain precedence (exact map, then
    wildcard lists sorted longest-first) so the project has **one** precedence rule to learn
    rather than two that differ in a corner.
  - **A trie rather than S1's sorted-list scan**, because the access pattern differs: domains
    are matched per connection against a handful of vhosts, whereas the model catalogue is hit
    on every request once body-based routing (WP-45 consumer B) lands, and a catalogue can
    reach hundreds of entries. A trie gives O(len(model_name)) independent of catalogue size;
    the sorted scan is O(entries). Built once at config-load time, immutable thereafter, and
    reachable from the request path through the same `ArcSwap` snapshot everything else uses
    (ADR-0005: control computes, workers read).
  - **Wildcard positions are restricted to exact / `prefix*` / `*`.** A trie cannot answer
    mid-string globs (`*-sonnet-*`), and S1's domain matcher does not accept them either. Note
    this is *narrower* than `routes[].model`, which falls back to `safe_regex` for a general
    glob — so a mid-string `*` in a `models:` key must be a **load error naming the field and
    the supported forms**, never silently treated as a literal. Two glob dialects that differ
    silently is worse than one that is explicitly narrower.
  - **Ambiguity must be impossible, not merely unlikely.** Two catalogue keys cannot resolve
    the same name at equal specificity (duplicate exact keys, or two identical prefixes), so
    that is a load error at build time rather than a first-match-wins accident.
  - **Acceptance:** exact beats prefix beats `*`; longest prefix wins among competing
    prefixes; a mid-string `*` is a load error; a duplicate key is a load error; lookup cost
    does not grow with catalogue size (assert structurally — trie depth is bounded by the
    queried name's length, not by entry count).
- **Depends on:** WP-38 (dialect), WP-33 (per-route dialect wiring). **Unblocks:** WP-35
  (fallback now has a list to fall back *through*), WP-44 (cost-aware routing needs a price per
  backend, not per model). **Raises the stakes on WP-19** — shifting off a degraded Anthropic to
  Vertex *is* outlier ejection, which is built (78 tests) but has no IR field to enable it.
- **Acceptance:** a config defining one model across Anthropic + Vertex + Bedrock + an
  OpenAI-compatible backend loads, validates, and lowers; each backend gets its own cluster,
  upstream model ID, dialect, and credential scheme. Omitting `dialect` on a `vertex` backend is
  a load error naming the field. Backends after the first warn that they are not yet selectable.
  A second instance of the same provider type (`vertex-us` + `vertex-eu`) lowers to two distinct
  clusters. Static-credential backends work end to end against the mock tier; OAuth and SigV4
  land with their schemes and are out of scope for the first increment.

#### WP-50 — Operator control plane: admin surface, virtual keys, teams, budgets  (Size: L)  — **Priority: P0** · **Milestone: v0.2.0**
> **Owner decision, 2026-08-01:** build the *operator* control plane before the xDS one
> (WP-20/21/22). Non-K8s deployments have no Envoy Gateway to drive xDS, so for them this
> **is** the management plane. State follows **ADR-0005**: embedded by default, distributed
> behind the same trait.
- **The hole this closes, stated plainly.** WP-34 enforces token budgets keyed on
  `(route, hashed authorization header)` — that is, it enforces quotas against credentials
  **nothing can register, attach to a team, rotate, or revoke**. The data plane grew
  enforcement with no way to administer it. WP-42's competitive review records that budgets are
  "often the actual reason a team fronts providers with a gateway at all"; today we can meter a
  caller we have no way to name.
- **Increment 1 — read-only surface (this is WP-25, absorbed here).** `/config_dump`,
  `/stats`, `/ready`, `/clusters`. Named explicitly by the v0.2.0 ship gate, already unblocked,
  and the prerequisite for operating the proxy at all. `/config_dump` must redact credentials —
  the access-log path already learned this lesson once.
- **Increment 2 — virtual keys. Design brief: `docs/wp-50-auth-design-brief.md` (2026-08-08),
  which is normative for the seams; this bullet is the summary.** A client presents a
  proxy-issued key; the proxy authenticates it, resolves it to a tenant, and **replaces it**
  with the real provider credential upstream.
  - **This is on v0.1.0's critical path, not v0.2.0's, for one reason:** WP-34 buckets on
    `hash_credential(<client-supplied Authorization header>)` and nothing verifies that header,
    so a caller gets a fresh quota by changing it. v0.1.0's "a token-based rate limit is
    enforced" clause cannot be honestly verified until the limiter keys on an identity the
    proxy assigns. Increment 2a re-keys it onto `Principal.tenant`; that is the point of it.
  - **Authentication is a trait, not a virtual-key filter** — OIDC lands later as a second
    `impl Authenticator` and nothing above it changes. `AuthOutcome` must distinguish
    "no credential of this kind" from "bad credential of this kind": collapsing them turns a
    chain of authenticators into a probing oracle.
  - **Model-scoped authz cannot run at header time.** The model name is in the request body,
    so "may this tenant use `gpt-5`?" is structurally a post-WP-45-body-peek filter.
  - **SHA-256 (keyed, HMAC) is correct; Argon2/bcrypt is not.** These are high-entropy keys the
    proxy generates, not user-chosen passwords — deliberately-slow hashing on the hot path is a
    self-inflicted DoS.
  The replacing half already exists (`request_headers_to_add` injection, and the access-log
  snapshot that deliberately runs before it); the authenticating half does not.
  - **Do NOT reuse `token_limit_filter::hash_credential` for this.** That is FNV-1a, chosen for
    stability across processes on a *non-adversarial* bucket key. Authenticating a credential
    needs a cryptographic hash and a constant-time comparison; FNV gives neither, and using it
    here would be a preimage and timing-attack surface. Different job, different primitive —
    the fact that both "hash a credential" is exactly why this is worth writing down.
  - Keys are stored hashed, never in plaintext, and never logged.
- **Increment 3 — tenants, budgets, spend.** Teams/projects owning a set of keys; per-tenant
  model allow-lists; budgets with a period (distinct from WP-34's tokens-per-minute throttle —
  a rate limit is not a spend ceiling, see WP-42); spend history queryable per tenant.
- **State (ADR-0005).** A `ControlPlaneStore` trait; embedded implementation (sqlite/sled) as
  the shipped default so a single binary works with no external dependency; distributed
  implementation later behind the same trait. Fail policy is **closed** for authentication —
  deliberately the opposite of `BudgetStore`'s fail-open, and the difference must be documented
  at both sites.
- **The hot path does no I/O.** Per-request key lookup must not touch sqlite. The control side
  owns the store and publishes an immutable snapshot through `ArcSwap`; workers do a lock-free
  load, exactly as `ClusterManager` does for host sets. A key revoked through the API takes
  effect on the next snapshot publish, and that latency must be stated, not hidden.
- **Depends on:** WP-24 ✅ (access logs), WP-34 ✅ (the limiter this gives an identity to),
  ADR-0005. **Related:** WP-23 (stats registry — same store principle), WP-42 (spend controls
  become administrable once tenants exist), WP-49 (per-tenant model allow-lists reference the
  model catalogue).
- **Acceptance:** `/config_dump` renders live config with every credential redacted (asserted
  against a config whose keys are known, so a leak fails the test); a key created through the
  API authenticates a real request end to end and a revoked one is refused; the upstream sees
  the *provider* credential and never the virtual key; per-tenant budget exhaustion returns 429
  with `x-ratelimit-*`; the proxy starts and serves with no external datastore configured.

#### WP-51 — OpenTelemetry: traces, metric export, and semconv naming  (Size: L)  — **Priority: P1** · **Milestone: v0.2.0**
> **Owner direction, 2026-08-03: "make the project OTel telemetry ready since it is a
> standard."** Recorded now, scheduled later — v0.1.0's scope stays frozen (milestone hygiene
> rule 1) and its open gate clause is still WP-35 provider failover.

**Where we actually stand, measured 2026-08-03 (not assumed):**

| OTel signal | State | What blocks it |
|---|---|---|
| Logs | Strong. 79 access-log command operators, 9 LLM-specific, structured sinks with rotation. | Names are ours, not semconv. |
| Traces | `traceparent` **passes through** — headers are cloned per attempt and mutations only add, so we never strip it. But we emit no spans and never join the trace. | Nothing. Additive. |
| Metrics | **Nothing exists.** `/stats` is a deliberate 404. Zero `opentelemetry`/`prometheus`/`metrics` dependencies in any `Cargo.toml`. | WP-23. |

Note `proxy-observability/src/lib.rs`'s own first line calls the crate a "Stats registry with
Envoy-exact naming (WP-23)" — there is no registry module. Aspirational doc comment, same class
as the `fallbacks` claim corrected in `docs/MILESTONES.md` today. Fix it when this WP lands.

- **Increment 1 — semconv naming for the LLM access-log operators.** Align `%LLM_INPUT_TOKENS%`,
  `%LLM_OUTPUT_TOKENS%`, `%LLM_CACHED_TOKENS%`, `%LLM_CACHE_CREATION_TOKENS%`, `%LLM_TTFT%`,
  `%LLM_TPOT%` to the OTel GenAI conventions (`gen_ai.usage.input_tokens`, etc.), keeping the
  existing operator names as accepted aliases for one release.
  **Do this first, and do it before anyone builds a dashboard.** It is the cheapest item here
  today and the most expensive one later — renaming a metric surface after it has consumers is
  a breaking change no matter how it is packaged.
- **Increment 2 — trace participation.** Parse W3C `traceparent`/`tracestate` on ingress, emit a
  server span per request and a client span per upstream *attempt* (the attempt loop is where
  fallback and retry become visible, which is most of the diagnostic value), propagate a
  correct child context upstream. Relate it to the existing `x-request-id` (S9) rather than
  replacing it — Envoy parity keeps that header. Sampling decisions must be honored, not
  invented.
- **Increment 3 — OTLP export.** Gated on WP-23, and see WP-23's amended header: the registry's
  internal model is OTel, so export is direct rather than a mapping. **ADR-0005 binds here** —
  the exporter is control-side; the request path never does I/O for telemetry.
- **The `!Send` collision, flagged early because it will surprise whoever picks this up.**
  ADR-0003 makes the data plane `!Send` and worker-local; the OTel Rust SDK's providers and
  batching exporters are `Send + Sync` and async. These do not compose directly. The shape that
  works is ADR-0005's, inverted: workers write into worker-local buffers, the control side
  aggregates and exports. Do not reach for the SDK's global provider from a worker.
- **Dependency-tree cost.** `opentelemetry` + `opentelemetry_sdk` + `opentelemetry-otlp` is a
  substantial subtree. `tonic`/`prost` are already present (WP-02/WP-20), so OTLP-over-gRPC is
  cheaper here than it looks, but this should be weighed against WP-40 (dep-tree cleanup) rather
  than landing without a look.
- **Semconv stability, stated honestly.** The OTel GenAI conventions are still marked
  experimental upstream and have already churned once
  (`gen_ai.usage.prompt_tokens` → `gen_ai.usage.input_tokens`). Pin a semconv version in code;
  treat a bump as a breaking change to the metric surface, because for anyone with a dashboard
  it is one.
- **Depends on:** WP-23 (increment 3 only), WP-24 (done). **Related:** WP-40 (dep tree),
  ADR-0003, ADR-0005.
- **Acceptance:** a scripted traffic mix produces an OTLP trace whose span tree shows one server
  span and one client span per upstream attempt, with a fallback visible as a second client
  span under the same server span; `traceparent` from a synthetic upstream caller is joined, not
  replaced; token counts appear under pinned semconv names; and the Envoy-name `/stats` adapter
  still passes WP-23's own conformance tests unchanged.

#### WP-52 — Cross-dialect provider fallback: request/response translation table  (Size: L)  — **Priority: P2** · **Milestone: v1.0.0**
- **Why (split out of WP-35, 2026-08-08).** WP-35 closes same-dialect provider fallback
  (openai-compatible chains, e.g. `openai` → `local-vllm`) for v0.1.0. Cross-dialect fallback
  (e.g. an `openai`-shaped route falling back to an `anthropic` provider) is a **hard
  config-time error** as of WP-35 increment 2c, not a warning and not silently wrong — it has
  to stay rejected until this WP exists. Forwarding an OpenAI-shaped request body to Anthropic's
  endpoint produces a malformed request, and even where an endpoint tolerated it, the response
  would be scanned for tokens by the wrong dialect's usage parser — the wrong-provider-shape
  version of the silently-wrong-billing-number failure WP-48 exists to prevent at the
  arithmetic level.
- **Build:** an explicit, versioned per-provider-pair mapping — not a generic JSON diff —
  covering at minimum: request shape (`model`, `messages`/`content` blocks, sampling params),
  streaming event framing (OpenAI's and Anthropic's SSE `data:` chunk shapes differ), and the
  usage/token block each dialect's usage filter parses. Runs on the fallback attempt only —
  same-dialect chains keep the zero-translation path WP-35 already built. This WP owns, and
  must not inherit unexamined, the decision of whether translation is expressible as a
  bounded-buffer transform (reusing WP-45's substrate) or needs a full reshape: a
  request/response *shape* change is not generally a prefix splice the way `include_usage`
  injection is.
- **Depends on:** WP-35 (done — same-dialect fallback and the aggregate-cluster mechanism this
  reuses), WP-45 (bounded-buffer body pipeline, possible substrate), WP-49 (backend taxonomy —
  translation needs to know the source and target provider *type*, not just the cluster name).
- **Acceptance:** a scripted primary-fails/fallback-succeeds drill across dialects (openai →
  anthropic and the reverse) produces a response indistinguishable from what the fallback
  provider's own dialect would produce natively — non-streaming and streaming — with usage
  attributed to the fallback provider's fields, never defaulted or dropped. A provider pair with
  no registered mapping still hard-errors at config time naming the dotted path, exactly as
  today.

## Part 3 — Milestone gates (roll-up)

| Gate | Requires WPs | Demo |
|---|---|---|
| **G1: L4 proxy** | 01–09, 26, 27 | Envoy bootstrap YAML → TCP proxy w/ TLS termination, diff-rig green |
| **G2: HTTP router** | 10–15, 23, 24 | Full HTTP routing/retries/timeouts, routing diff suite 100%, lifecycle flags parity |
| **G3: Dynamic** | 16–22, 25, 28 | Envoy Gateway drives us via ADS; make-before-break churn zero-loss |
| **G4: Prod-ready** | 18, 19, 29, 30, 31 | Health/outlier parity, fuzz-clean, perf ≥ Envoy, dashboards work |
| **G5: LLM gateway** | 32, 33–37, 45, 46, 47 | SSE streaming, token metering/limits, model routing + fallback, EPP inference LB, realtime WebSocket sessions — Envoy AI Gateway capability set with zero sidecar hops |

## Part 4 — Scaffolding decision

**Yes — scaffold now** (recommendation): an interface-first skeleton removes the biggest
multi-agent failure mode (incompatible assumptions about shared types). The scaffold contains:
workspace + all crates compiling, the S2 status enums and `HttpFilter`/callbacks traits, the
`TransportSocketFactory`/`ClusterEntry`/`HttpConnPool` seams, IR struct skeletons, response-flag
enum, error types, and `todo!()`-free stub impls so `cargo check && cargo test` is green from
commit zero. Each WP then fills in its crate against frozen trait surfaces. See repo state —
scaffolding is committed alongside this document.
