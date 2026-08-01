# Changelog

All notable changes to this project are recorded here. Releases and their ship gates are
defined in [`docs/MILESTONES.md`](docs/MILESTONES.md); work packages are defined in
[`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md). This file records *what shipped*, not
what is planned.

The format is loosely [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This
project is pre-1.0: the config surface is not yet stable, and the `llmproxy` dialect's
`version: 0` schema is frozen only from its first release onward.

## [Unreleased]

Work toward **v0.1.0 — LLM gateway**. See `docs/MILESTONES.md`.

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
  end-to-end test's mock *required* the header and returned 401.
- **Two upstream certificate-verification holes in the `llmproxy` dialect.** A provider with
  no `ca_file` emitted no validation context at all, which on the rustls side means *accept
  any server certificate*; and the `ca_file` path verified chain trust without verifying
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
