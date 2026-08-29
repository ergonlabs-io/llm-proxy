# Changelog

All notable changes to this project are recorded here. Releases and their ship gates are
defined in [`internal-docs/MILESTONES.md`](internal-docs/MILESTONES.md); work packages are defined in
[`internal-docs/IMPLEMENTATION_PLAN.md`](internal-docs/IMPLEMENTATION_PLAN.md). This file records _what shipped_, not
what is planned.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project is pre-1.0: the config surface is not yet stable, and the `llmproxy` dialect's
`version: 0` schema is frozen only from its first release onward.

## [Unreleased]

Nothing yet. Work toward **v0.3.0** — see `internal-docs/MILESTONES.md`.

## [0.2.0] — 2026-08-29

**Production-ready serving.** v0.1.0 made the proxy understand its traffic; this release
makes it safe to run unattended and honest about its own performance.

### The gate

A published capacity report (p99, tokens/sec ceiling, RSS under sustained long-lived
streams) from a run that is not harness-bound, plus `/config_dump` and `/stats` served by
the admin endpoint, plus a config swap under live traffic with zero dropped streams. All
three clauses are met.

- **Admin + stats** — `/config_dump`, `/stats` (Envoy text), and `/stats/prometheus` are
  served and report real traffic, proven by `crates/proxy/tests/stats_e2e.rs` against the
  real binary and a real HTTP scrape.
- **Capacity report** — published from a not-harness-bound run (`054b809`), unblocked by
  HTTP/1.1 and HTTP/2 upstream connection reuse.
- **Config swap under load** — SIGHUP re-reads the config file and publishes a new
  snapshot; a parse failure keeps the previous snapshot serving and logs the full
  dotted-path detail. Proven by `testing/diffrig/tests/swap_under_load.rs`: streams in
  flight at the swap, all SSE streams reaching their terminal frame, zero transport errors.

### Added

- **Metrics registry (WP-23)** — an OpenTelemetry-native internal model (instruments plus
  attribute sets) rendered to Envoy-exact `/stats` text and to Prometheus, with histograms
  on Envoy's default buckets.
- **Admin server (WP-25)** — `/config_dump`, `/clusters`, `/stats`, `/stats/prometheus`,
  each resolving the live snapshot after a reload rather than the boot snapshot.
- **Active health checking (WP-18)** and **outlier detection (WP-19)** — reachable from
  config and running; an active-health-check recovery clears an outlier ejection.
- **Circuit breakers and connection reuse (WP-15)** — `max_connections` enforced at the
  dial site; per-worker HTTP/2 multiplexing and HTTP/1.1 keep-alive upstream connection
  pools.
- **OpenTelemetry (WP-51)** — distributed spans (W3C trace-context join/propagation) plus
  OTLP/gRPC export of both traces and metrics, zero-cost when unconfigured.
- **HTTP upgrades and WebSocket tunneling (WP-10, S10)** — transparent HTTP/1.1 Upgrade
  and HTTP/2 extended CONNECT (RFC 8441) tunnels, gated by `upgrade_configs`, with an idle
  timeout on the tunnel.
- **Routing (WP-13)** — `x-envoy-attempt-count`, redirect route actions.

### Changed

- `loadgen` percentiles now describe successful requests only, and the driver detects SSE
  truncation (a cut-short stream is no longer counted as success) — both were measurement
  defects that would have skewed a published capacity number.

## [0.1.0] — 2026-08-08

**The pipe gets smart.** v0.0.1 proved a request could go all the way through. This release
is about the proxy _understanding_ what is going through it.

### The gate

The proxy emits per-request token counts (input / cache-read / cache-write / output) and
TTFT/TPOT to the access log, enforces a token-based rate limit, and fails over from one
provider to another mid-request without the client seeing an error.

All three clauses are verified end to end against the real binary over real sockets, not
merely implemented — **against mock upstreams**. Unlike v0.0.1, this release was tagged
without executing its live-provider drill; that drill exists
(`testing/diffrig/tests/live_gate_v0_1_0.rs`, one command, three billable calls) and the
departure from v0.0.1's standard is recorded in `internal-docs/MILESTONES.md`.

- **Token counts + TTFT/TPOT** — QA-10 (`testing/qa/scenarios/qa10_llm_latency_test.go`)
  against a mock paced at 400ms TTFT / 150ms inter-chunk: `ttft=402ms tpot=122.129ms
max_stall=152ms`. QA-1 covers per-route counts for both providers from one config.
- **Provider failover** — `testing/diffrig/tests/failover_e2e.rs`: primary forced to 429,
  fallback serves, attempt accounting exact, and the standby receives its own credential
  with the primary's appearing nowhere.
- **Token rate limiting** — `testing/diffrig/tests/auth_e2e.rs`: a tenant's budget is
  exhausted and a _second, different_ key belonging to that tenant is refused with 429.

**Read this clause carefully, because the obvious version of it is not what shipped.** A
token limit was already enforced in code before this release, and that was not enough. The
limiter bucketed on the client's own `Authorization` header, and nothing verified that
header — so any caller who exhausted a quota changed one string and received a fresh one.
The limit was advisory by construction. Closing this clause required giving callers an
identity the _proxy_ assigns, which is why downstream authentication is in this release at
all. It was not planned scope; it was the precondition.

### Added

- **Downstream authentication (WP-50 increment 2a).** Proxy-issued virtual keys, verified as
  keyed HMAC-SHA-256 digests in constant time, resolving a request to a tenant. Fails
  **closed**: with the filter configured, an unrecognized credential is a 401, always.
  Configuration carries only digests — a plaintext key never appears in a config file.
  Authentication is an `Authenticator` trait behind a chain, so OIDC lands later as a second
  implementation without reshaping anything above it.
- **Token budgets keyed on tenant.** The rate limiter now buckets on the authenticated
  tenant when there is one, and on the hashed credential only when no auth filter ran. The
  two key spaces are distinguished by descriptor _name_, so they cannot collide.
- **`auth:` in the `llmproxy` dialect**, plus `limits: key: tenant`.
- **Provider fallback (WP-35).** `fallbacks:` in the dialect lowers to an Envoy aggregate
  cluster with member-order failover, and per-provider credentials travel on the _cluster_
  so a failover cannot send provider A's key to provider B's endpoint. Same-dialect chains
  only; a cross-dialect chain is a config-time error, not a silent drop.
- **Body-based model routing and forced usage reporting (WP-45).** A bounded request-body
  prefix scan routes on the `model` field in the body, and splices
  `stream_options.include_usage` into OpenAI-dialect streaming requests — without which an
  OpenAI-compatible provider reports no usage in a stream at all.
- **TTFT/TPOT (WP-46).** `%LLM_TTFT%`, `%LLM_TPOT%`, `%LLM_MAX_STALL%`,
  `%LLM_RESPONSE_CHUNKS%`, carried by both dialect log formats.
- **The first Lane-H proto (WP-47 increment 1).** `llmproxy/filters/v0/auth.proto` — the
  first config message this project defines rather than borrowing an unrelated Envoy one.
- **Lane-H filter ordering is validated at config load.** Two orderings among the LLM
  filters fail silently when reversed; both are now errors naming the filter to move and the
  consequence.

### Fixed

- **Usage reported as a JSON float billed as zero.** `as_u64()` returns `None` for any
  number that is not a non-negative integer — including an ordinary `150.0`, which real
  providers emit — so `unwrap_or(0)` recorded a genuine usage report as zero tokens,
  silently, with the request succeeding. All five call sites now route through one helper
  where unparseable input is `None` (renders absent), never `0` (a number someone bills
  against).
- **`%LLM_RESPONSE_CHUNKS%` over-reported by one** on every response with a body, and fed a
  phantom gap into `%LLM_MAX_STALL%`: the synthetic empty end-of-stream frame was timed as a
  chunk.
- **The dialect silently dropped `fallbacks:`.** It parsed, validated, lowered, and was
  discarded with one stderr warning — an operator who configured failover got a proxy that
  did not fail over.

### Known limitations

- **Authentication keys live in config and are in-memory only.** No persistent or shared
  store yet, so revoking a key means a config change (WP-50 increment 2b). Multi-instance
  deployments have no shared key set.
- **Authorization defaults open.** An authenticated tenant with no configured policy may use
  every model and provider; per-tenant allow-lists and budgets are WP-50 increment 3.
- **No admin API.** Keys are minted with the CLI and pasted into config; there is no
  create/revoke endpoint and no spend history.
- Upstream connections are still **not pooled** (WP-15).
- Downstream HTTP/2 and protocol upgrades (S10) are not implemented.
- xDS and the stats registry are not wired (v0.2.0/v0.3.0).
- Cross-dialect fallback (OpenAI primary → Anthropic fallback) is rejected at config time;
  it needs request/response translation (WP-52, v1.0.0).
- Every gate verification runs against mock upstreams. v0.0.1's gate was closed by a manual
  live run against real OpenAI and Anthropic endpoints; the equivalent for this release's
  two new clauses is recorded in `internal-docs/MILESTONES.md` as a judgment call rather than a
  completed step.

## [0.0.1] — 2026-08-01

**First light.** One request, all the way through, for real.

### The gate

A client sends a chat-completion request to the proxy, configured from a single `llmproxy`
config file pointed at a real provider endpoint, and receives the provider's response back
unmodified — both non-streaming and streamed (SSE) — for OpenAI and for Anthropic.

Closed by `testing/diffrig/tests/live_smoke.rs`: four cases against the real OpenAI and
Anthropic endpoints, all passing. Those tests are `#[ignore]`d by design — they bill real
tokens and CI holds no keys — so this gate's evidence is a deliberate manual run:

```sh
OPENAI_API_KEY=... ANTHROPIC_API_KEY=... \
  cargo test -p diffrig --test live_smoke -- --ignored
```

The release carries everything built to date. The features were never the milestone; the
working path through them was.

### Added

- **Config.** Envoy bootstrap (YAML/JSON) → typed protos → PGV-subset validation → internal
  IR, in strict mode: every field either maps or errors with its full dotted path. Plus the
  `llmproxy` dialect (`--config`), which lowers providers → clusters + upstream TLS + auth
  headers, with `--mode translate` to print the equivalent Envoy bootstrap.
- **L4.** Listener manager with the 9-step filter-chain matcher, `SO_REUSEPORT` bind/accept,
  and `tcp_proxy` serving real bidirectional streams with half-close and idle timeout.
- **TLS.** Downstream and upstream, SNI, ALPN, SAN matchers, mTLS, dual-cert hot reload. An
  upstream `transport_socket` with no registered builder is a fatal startup error, never a
  silent plaintext downgrade.
- **HTTP.** h1 downstream; h1 and h2 upstream, dispatched by config. Filter manager
  implementing S2 (ordering, buffering, local replies, injection, streaming encode). Route
  table implementing S1 (domain precedence, first-match-wins, weighted pick).
- **Router.** S9 request transforms (XFF, `x-request-id`, `:authority`, rewrites,
  `request_headers_to_add`) and S4 timeouts (route, idle, per-try) that disarm on response
  headers so streams are not truncated. S3 retry engine with fully-jittered backoff and body
  replay. S5 `max_requests` circuit breaker.
- **Clusters.** Cluster manager over `ArcSwap`; STATIC/STRICT_DNS/LOGICAL_DNS discovery; S7
  load balancers (round-robin SWRR, random, least-request P2C); active health checking; S6
  outlier detection.
- **Observability.** Access logs with the command-operator format engine and file/stdout/stderr
  sinks with logrotate reopen, emitted at stream end so streamed responses log real
  `bytes_sent`.
- **LLM.** Token extraction for OpenAI chat completions, OpenAI Responses, and Anthropic
  Messages — streaming and not — into four non-overlapping cost buckets, wired into the
  encode path per-route via the dialect.
- **Test infrastructure.** Differential rig against real Envoy v1.38.0 (docker-gated);
  hermetic TLS end-to-end with a generated CA; a third-party tier against a local Ollama;
  config corpus scorecard; in-process xDS control-plane puppet; open-loop load generator
  with a capacity model; and a black-box Go QA suite.

### Fixed

- **Credentials never reached providers.** `request_headers_to_add` was lowered onto
  `RouteEntry` by both config front-ends and read by nothing, so every request arrived at
  its provider unauthenticated. It survived a full plan audit because the config parsed,
  validated, and translated correctly — and then evaporated. Found only because an
  end-to-end test's mock _required_ the header and returned 401.
- **Two upstream certificate-verification holes in the `llmproxy` dialect.** A provider with
  no `ca_file` emitted no validation context at all, which on the rustls side means _accept
  any server certificate_; and the `ca_file` path verified chain trust without verifying
  identity. Both branches now emit a validation context and a DNS-exact SAN matcher on the
  provider host. Envoy-mode parity is deliberately unchanged — Envoy really does default to
  accept-any, so the fix belongs in our own surface, not in the compatibility layer.
- **Credential leak into access logs.** Credentials are now snapshotted out before
  route-injected auth headers are applied.
- Two `StreamInfo` layering bugs that only a socket-level test could find: Envoy owns
  `StreamInfo` at the filter-manager level and logs above the chain.

### Known limitations

- Upstream connections are **not pooled** — still connect-per-stream (WP-15). Four smoke
  requests cannot surface this; a sustained workload will.
- Downstream HTTP/2 and protocol upgrades (S10) are not implemented.
- xDS, the admin server, and the stats registry are not wired (planned for v0.2.0/v0.3.0).
- Token rate limits, model routing, provider fallback, and GenAI TTFT/TPOT metrics are
  v0.1.0 scope. v0.0.1 proves the pipe works; making the pipe smart is next.
- The dialect matches models on the `x-llmproxy-model` header, not on the request body.
