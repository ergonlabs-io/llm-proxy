# Changelog

All notable changes to this project are recorded here. Releases and their ship gates are
defined in [`internal-docs/MILESTONES.md`](internal-docs/MILESTONES.md); work packages are defined in
[`internal-docs/IMPLEMENTATION_PLAN.md`](internal-docs/IMPLEMENTATION_PLAN.md). This file records _what shipped_, not
what is planned.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project is pre-1.0: the config surface is not yet stable, and the `llmproxy` dialect's
`version: 0` schema is frozen only from its first release onward.

## [Unreleased]

Work toward **v0.3.0** (ADS/xDS) is in progress. The proxy now connects to an ADS control plane,
ACKs/NACKs strict LDS/CDS/RDS/SDS/EDS resources, applies accepted snapshots, reconnects with
resync, and gates readiness/request admission on cluster warming. Named RDS delivery warms
dependent listeners; replacement listeners retain last-good generations until warm, and ADS
initial-fetch timeout is honored. Delta xDS, init-manager sequencing, and full differential churn
verification remain open. Configuration loading rejects unsupported sources with full dotted paths.
Everything else below is WP-50 increment 3 (operator control plane: tenants, budgets, spend),
which shipped between the v0.2.0 tag and this point and gates neither release — see
`internal-docs/MILESTONES.md`'s v0.2.0 section for why it's recorded there.

### Added

- **Delta xDS subscription state.** Per-resource accepted versions, removals, named
  subscribe/unsubscribe differences, ACK/NACK nonce handling, and reconnect persistence now have
  transport-independent state and tests (`61e70a4`). gRPC delta transport remains open.
- **xDS warming-race script predicates.** Control-plane scenarios can wait for an exact ACK or
  NACK without unrelated subscriptions advancing the script (`376d8d0`).
- **`x-envoy-upstream-service-time`.** Successful upstream responses report final-attempt elapsed
  milliseconds, replace spoofed upstream values, and omit the header on local failures
  (`498adba`).
- **Vertex bearer-token and Bedrock signing support.** Vertex applies configured access
  tokens and provider paths; Bedrock signs final request bodies with SigV4. Strict validation, IR
  lowering, dialect handling, and focused tests landed in `9c939b9`; Vertex token mint/refresh and
  live-provider E2E remain deferred.
- **Owned Lane-H filter protos.** TokenLimit, Usage, and BodyRewrite now use versioned
  `llmproxy.filters.v0` typed config with legacy borrowed decoders retained for one release.
- **Direct-response file bodies load during config lowering.** Request workers perform no file I/O
  for this path (`24b42fb`).
- **Local rate-limit request header mutations.** `request_headers_to_add_when_not_enforced`
  parses strictly and applies on disabled, no-bucket, not-enforced, and shadow-denied paths
  (`f979f38`).

- **Admin write API, gated by `LLMPROXY_ADMIN_TOKEN`.** `POST /keys` (mints a virtual key,
  returns the plaintext exactly once), `DELETE /keys/{id}`, tenant CRUD, and
  `PUT /tenants/{id}/policy` (per-tenant model allow-lists). Fails closed with `403` when the
  token env var is unset, `401` with a challenge on a wrong token, `503` during the brief
  startup race before a control plane is registered. Request bodies are capped at 64 KiB.
- **Per-tenant spend budgets.** `PUT /tenants/{id}/budget` sets a ceiling (an absent budget is
  unlimited; a configured zero denies everything) with a daily or monthly period. A new
  `llmproxy.spend_limit` filter enforces it against a live in-memory counter, returning `429`
  with `x-ratelimit-*` headers (values in **micro-dollars**, not request counts) on
  exhaustion; the budget restores on period rollover.
- **Per-request pricing.** A `(cluster, model)` price table, in integer micro-dollars, priced
  independently per token bucket (input/output/cached/cache-creation) and resolved against
  the cluster a request actually dialled — never the route — so a failover is billed at the
  fallback's price, not the primary's.
- **`GET /tenants/{id}/spend`**, gated behind the admin token despite being a `GET` (it's
  financial data): live spend, budget and remaining, last-flush time, and the count plus
  distinct `(cluster, model)` pairs of unpriced requests, so an operator can see a pricing gap
  instead of assuming a model is billed when it silently isn't.
- **An end-to-end test drill for the admin write API against the real binary.** Spawns the
  shipped executable with `LLMPROXY_ADMIN_TOKEN` set and a mock upstream, then drives the admin
  surface over a real socket: the `403`/`401`/success gate, a minted key authenticating real
  traffic through the data plane, a revocation taking effect on the very next request, a policy
  write changing enforcement with no reload, a budget write producing `429` with `x-ratelimit-*`,
  and scoped versus unscoped chain addressing. This closes the coverage gap recorded below and
  found the `model_authz` defect above on its first run.
- **A selectable, persistent control-plane store.** The auth filter's config gains
  `oneof store { in_memory | persistent { path } }`; unset defaults to `in_memory`, so every
  config written before this change is unaffected. The persistent option is an embedded
  `redb` database — keys, tenants, policies, and budgets survive a restart.
- **Chains addressed by name, not position.** Admin endpoints are now scoped as
  `/chains/{stat_prefix}/...`, matching the operator-chosen name already required on the HTTP
  connection manager, so reordering filter chains in config can't silently reassign a
  tenant's billing history to the wrong chain. The pre-existing unscoped endpoints keep
  working as a single-chain convenience alias.

### Changed

- **Per-tenant model allow-lists are now enforced live, not just stored.** `llmproxy.model_authz`
  reads the published control-plane snapshot instead of its own static config, so an admin
  `PUT /tenants/{id}/policy` changes what the next request from that tenant is allowed to do,
  with no restart or reload. As part of this, a tenant with no policy in the snapshot is now
  **permitted** every model, reversing the previous default of denying an unrecognized tenant
  — authorization defaults open once a caller is authenticated, consistent with how an
  unconfigured tenant is treated everywhere else in the control plane.

### Fixed

- **`llmproxy.model_authz` refused every request in any filter chain that enabled it.** Per-tenant
  model allow-lists were therefore non-functional: a chain configuring the filter returned `403`
  for 100% of traffic, whatever the policy said. The filter read the requested model during the
  header phase, but that value is published during the body phase, and the proxy runs every
  filter's header callbacks before it delivers any body data — so the value was always absent and
  the filter took its "no model to authorize" denial path. Filter ordering could not affect this
  and no configuration worked around it. The tenant check still happens on headers; the model
  check now happens once the body (or the trailers) has been seen. Requests with no body and
  requests carrying trailers are both still checked, so the fix does not turn a refusal into a
  gap. The filter fails **closed**, so this was an outage rather than an authorization bypass.
- **Security: a configured token-per-minute rate limit admitted roughly (limit × core count)
  tokens per minute, not the configured limit.** The limiter built a separate budget store
  per worker process instead of sharing one; an operator relying on, say, a 1000
  tokens/minute ceiling was silently getting up to 8000/minute on an 8-core box. Fixed by
  sharing one budget per filter chain and rule; existing configs need no changes.
- **Security: two listeners each configuring `llmproxy.auth` could authenticate against the
  wrong one's keys.** The shared factory state that holds parsed auth config (HMAC secret,
  virtual keys, store) was keyed on the filter's type alone, so a second chain's config was
  parsed, validated, and then silently discarded in favor of the first chain's — a request
  presenting the *second* chain's key would authenticate against the *first* chain's tenant
  set. Now keyed per filter chain as well as filter type. Only affects configs with more than
  one `llmproxy.auth`-configured chain.

### Known limitations

- **Spend budgets are enforced per process, not per fleet.** N replicas behind a load
  balancer enforce N independent ceilings — the same shape as the rate-limit bug above, one
  level up, and not yet fixed for spend. Closing it needs an additive/CAS write on a
  distributed `ControlPlaneStore`, which does not exist yet.
- **The admin write API's unscoped endpoints (`/keys`, `/tenants`, ...) support exactly one
  `llmproxy.auth`-configured chain**; with several, they refuse explicitly rather than
  guess. The scoped `/chains/{stat_prefix}/...` form has no such limit.
- OIDC/JWT as a second authentication method is not built; the `Authenticator` trait was
  designed for it but nothing implements it yet.

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
