<div align="center">

# llm-proxy

### One static binary and one YAML file between your applications and your model providers.

**llm-proxy** puts token metering, budgets, authentication, failover, and access
logging in one place instead of in every service that calls a model. It is a
full proxy data plane specialised for LLM traffic: the core is general-purpose
and production-grade — listeners, filter chains, clusters, load balancers,
health checking, outlier detection, retries, xDS — and the LLM parts (token
accounting, spend budgets, provider dialects, per-tenant quotas) are filters
and cluster policy on top of it, not a parallel system.

[![CI](https://github.com/ergonlabs-io/llm-proxy/actions/workflows/ci.yml/badge.svg)](https://github.com/ergonlabs-io/llm-proxy/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/ergonlabs-io/llm-proxy?sort=semver)](https://github.com/ergonlabs-io/llm-proxy/releases)
[![Docs](https://img.shields.io/badge/docs-ergonlabs.io-blue.svg)](https://ergonlabs.io/docs/llm-proxy/)
![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-yellow.svg)

</div>

```sh
export UPSTREAM_BASE_URL=https://api.openai.com UPSTREAM_API_KEY=sk-...
llm-proxy --config examples/llmproxy-quickstart.yaml
curl http://127.0.0.1:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

See [Quick start](#quick-start) for the binary, container, and source options,
and the [documentation](https://ergonlabs.io/docs/llm-proxy/) for everything
else.

> [!NOTE]
> **Pre-1.0.** The data plane serves real traffic, but interfaces still change
> between releases and there are no backports to earlier tags. Read
> [What is not built yet](#what-is-not-built-yet) before you depend on it —
> that section is deliberately specific — and [Roadmap](#roadmap) for where
> each release stands.

---

## Why this shape

Two design decisions explain most of the code.

**Real data-plane semantics, not an approximation.** The proxy reads a
standard proxy bootstrap configuration and speaks xDS — the config format and
protocol the industry's mainstream data planes use. Response flags, access-log
operators, retry-on conditions, outlier ejection, cluster warming — these
follow that ecosystem's documented behaviour rather than a convenient
reinterpretation of it, so operators who already run one of these data planes
do not have to learn a second set of rules, and divergences have to be argued
for in writing.

**A small LLM-native dialect that lowers onto it.** Nobody wants to write a
full data-plane bootstrap to put a rate limit in front of OpenAI. `--config`
takes a compact dialect — providers, routes, limits — which lowers to standard
data-plane resources and then flows through the identical parse → validate → IR
pipeline as bootstrap mode. `--mode translate` prints exactly what it lowered
to. The rule that keeps this honest: **a capability must exist in the
bootstrap-mode surface before the dialect may expose it.** The dialect is a
front end, never a second config system.

Both surfaces are **strict**. An unknown or misspelled field is an error
carrying its full dotted path, never a silent no-op — a silently ignored field
is treated as a P0 bug in this repo, because a limit you think you configured
and did not is worse than no limit at all.

## Architecture

```
   clients (OpenAI / Anthropic SDKs, base URL set to the proxy)
        │
        ▼
 ┌─ listener + filter chain ────────────────────────────────┐
 │                                                          │
 │  auth      virtual keys (HMAC-SHA256, constant time)     │
 │  model     per-tenant model allow-lists                  │
 │  limits    per-tenant token budgets, windowed            │
 │  spend     currency budgets from the rate card           │
 │  usage     token accounting, streaming and not           │
 │                                                          │
 └──────────────────────┬───────────────────────────────────┘
                        │  route match on model pattern
                        ▼
 ┌─ cluster ────────────────────────────────────────────────┐
 │  load balancing · health checks · outlier detection      │
 │  circuit breakers · retries + retry budgets              │
 │  failover to the next provider in the chain              │
 │  per-provider credentials live HERE, never on the route  │
 └──────────────────────┬───────────────────────────────────┘
                        │
                        ▼
          OpenAI · Anthropic · vLLM · Ollama · TGI · any
                    OpenAI-compatible endpoint

 side channels
 ─────────────
 admin :53422  read:  /ready /config_dump /clusters /server_info
                       /stats /stats/prometheus /models
                write: /keys /tenants /tenants/{id}/policy|budget
                       GET /keys lists the keys, same gate as the writes
                       (bearer-gated; no token means 403, never open)
                ui:    /ui — single-page admin console over the same API
 logs          access logs with tokens, TTFT, TPOT, response flags
 traces        OTLP, W3C traceparent propagated
 config        SIGHUP reload, or xDS from a control plane
 shared state  in-memory, embedded redb, or Redis across replicas
```

Everything per-provider — credentials, `Host` rewrites, upstream protocol —
belongs to the **cluster**, not the route. A route picks an aggregate; the
member is what actually gets dialled, so a per-provider value hung off the route
follows the routing decision instead of the connection and reaches the wrong
provider on failover. That has been a real key-disclosure bug here twice.

## What it does today

- **Speaks your provider's API.** OpenAI Chat Completions, OpenAI Responses, and
  Anthropic Messages. Point an existing client at llm-proxy by setting its base
  URL to the proxy and its API key to a virtual key. Bodies pass through; the
  proxy replaces the credential, and rewrites the model name only where a
  `models` entry maps it. There is no translation between API dialects. See
  [Connect your application](docs/site/src/content/docs/getting-started/connect-your-application.md).

- **Streams properly.** Server-sent events are forwarded as they arrive, and the
  proxy never injects frames of its own into a stream. An unclean end of stream
  stays unclean, because inventing a well-formed ending would hide a real failure
  from the client.

- **Meters tokens.** Input, output, and separately-priced buckets are read from
  provider responses, for streaming and non-streaming requests alike, and land in
  the access log. `/v1/embeddings` requests are metered and charged the same way.
  The proxy answers `GET /v1/models` itself, with the models the caller may use.

- **Enforces token budgets.** A tenant over its limit gets a 429 with
  `x-ratelimit-*` headers before the request reaches a provider. A request already
  in flight is never cut short. Limits are keyed to the authenticated tenant, so
  changing a header does not buy a fresh quota. A tenant can read its own
  current-window standing at `GET /v1/usage`, scoped to the key it presented —
  never to a tenant it names itself.

- **Enforces spend budgets.** Token counts are priced from an integer micro-USD
  table and charged against a per-tenant ceiling; over it, a 429 with
  `spend_budget_exceeded`. Cost is only knowable when a response ends, so the
  request that crosses the line is admitted and the *next* one is refused —
  overspend is bounded by one request, never unbounded.

- **Authenticates callers.** Virtual keys verified with HMAC-SHA256 in constant
  time. Authentication fails closed: with an `auth` block configured, a request
  with no recognised credential is refused rather than admitted anonymously.
  After a request is authenticated, its `Authorization` header is removed, so
  no provider ever receives the virtual key. As a result, any filter placed
  after `llmproxy.auth` in an Envoy-mode `http_filters` chain (for example
  `ext_authz`) does not see that header either. Envoy's `jwt_authn` with
  `forward: false` behaves the same way.

- **Authorizes models.** A tenant can be restricted to named models and exclude
  specific models from that grant. The effective access is allow minus deny,
  enforced before routing. It fails closed on an unauthenticated request. It
  also refuses an authenticated tenant with no stored policy (403), unless
  `auth.enforce.tenants_without_policy` is `allow`. The dialect's `auth:` block turns this on; `auth.enforce.model_policy: false` turns it off, and the admin API then refuses policy writes with `409`.

- **Mints and revokes keys at runtime.** A bearer-gated admin write API creates
  tenants, mints and revokes virtual keys, and sets per-tenant policies and
  budgets, against an in-memory, embedded (redb), or shared (Redis) control-plane
  store. A revocation through the API applies at once on that replica and within
  one policy poll on the others, without a restart. Keys listed in the config
  file change only on restart.

- **Fails over between providers.** A route can name an ordered list; if the
  primary fails, the next is tried, with retries, retry budgets, and per-try
  timeouts. Every provider in a chain must speak the same wire format, and a chain
  that mixes formats is rejected when the configuration loads rather than at
  request time.

- **Keeps bad upstreams out of rotation.** Active health checks and outlier
  detection eject hosts that fail, with the ejection visible in `/clusters` and in
  the access log's response flags. Circuit breakers bound connections, pending
  requests, and in-flight requests per cluster.

- **Terminates TLS.** Listener TLS from the dialect; mTLS, SAN matchers, and dual
  certificates from the bootstrap surface.

- **Meters realtime sessions.** With `realtime: { enabled: true }`, a WebSocket
  session on a `/realtime` path — the shape several providers' realtime APIs use —
  is authenticated, model-checked, limited and budgeted when it opens, metered
  from its `response.done` events (text and audio tokens) and charged and ledgered
  once when it closes. Drain closes open sessions with code 1001. Other upgrades
  pass through byte for byte once the upstream accepts them.

- **Tells you what it is doing.** Access logs with token counts,
  time-to-first-token, time-per-output-token, and standard response flags. OTLP
  traces with W3C `traceparent` propagation. An admin endpoint serving `/ready`,
  `/config_dump`, `/clusters`, `/server_info`, `/stats`, `/stats/prometheus`
  and the model inventory `/models` unauthenticated, and the control-plane
  writes plus the `GET /keys` key inventory behind a bearer token — unset
  means 403, never open. A single-page admin console at `/ui` drives the same
  API.

- **Survives operations.** Configuration reloads on SIGHUP — and a configuration
  that fails to parse leaves the previous one serving, with the error logged
  against its exact field path. SIGTERM drains connections instead of dropping
  them: `/ready` turns 503, the listeners close, idle connections close, and
  in-flight streams finish until `--drain-time-s`. A config swap under live traffic is covered by a differential test that
  asserts every in-flight SSE stream still reaches its terminal frame.

- **Takes configuration from a control plane.** ADS state-of-the-world for
  clusters, listeners, and endpoints, with correct ACK/NACK, reconnect with
  backoff, and last-good config retained on failure. Conformance is checked
  against go-control-plane (`make xds-conformance`), not only against our own
  harness — a harness we wrote both sides of cannot catch us agreeing with
  ourselves and both being wrong. The v0.3.2 gate shipped in tag v0.3.5; see
  [Roadmap](#roadmap).

## Quick start

From download to a first proxied request in about five minutes. Pick one way to
get the proxy; the run steps after it are the same for all three.

**Release binary** (Linux x86-64 and arm64, macOS on Apple silicon):

```sh
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSLO "https://github.com/ergonlabs-io/llm-proxy/releases/latest/download/llm-proxy-$os-$arch.tar.gz"
tar -xzf "llm-proxy-$os-$arch.tar.gz"
curl -fsSLO https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/examples/llmproxy-quickstart.yaml
```

Releases before v0.7.0 have no Linux arm64 archive; build from source there.

**Container image** (`ghcr.io/ergonlabs-io/llm-proxy`, linux/amd64 and
linux/arm64; published from v0.7.0):

```sh
curl -fsSLO https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/examples/llmproxy-quickstart-container.yaml
export UPSTREAM_BASE_URL=https://api.openai.com UPSTREAM_API_KEY=sk-...
docker run --rm -p 127.0.0.1:8080:8080 -e UPSTREAM_BASE_URL -e UPSTREAM_API_KEY \
  -v "$PWD/llmproxy-quickstart-container.yaml:/etc/llm-proxy/llmproxy.yaml:ro" \
  ghcr.io/ergonlabs-io/llm-proxy:latest
```

Then skip to step 3.

**From source.** Install [rustup](https://rustup.rs), a C toolchain, and `protoc`.
`rustup` then installs the pinned Rust version on the first build.

```sh
xcode-select --install; brew install protobuf                 # macOS
sudo apt install build-essential protobuf-compiler            # Debian and Ubuntu
```

```sh
git clone https://github.com/ergonlabs-io/llm-proxy.git && cd llm-proxy
cargo build --release -p proxy
```

In the steps below, use `./target/release/llm-proxy` for `./llm-proxy` and
`examples/llmproxy-quickstart.yaml` for `llmproxy-quickstart.yaml`.

**1. Point it at a provider.** `examples/llmproxy-quickstart.yaml` routes every
model to one OpenAI-compatible provider and reads both its address and its key
from the environment:

```sh
export UPSTREAM_BASE_URL=https://api.openai.com   # scheme, host and port only, no /v1
export UPSTREAM_API_KEY=sk-...                     # your provider key
./llm-proxy --config llmproxy-quickstart.yaml --mode validate
# configuration 'llmproxy-quickstart.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

For a local Ollama, use `UPSTREAM_BASE_URL=http://127.0.0.1:11434` and any
value for the key.

**2. Start it.** It listens on `127.0.0.1:8080`, with the admin endpoint on
`127.0.0.1:9901`.

```sh
./llm-proxy --config llmproxy-quickstart.yaml
```

**3. Send a request** from a second terminal:

```sh
curl http://127.0.0.1:8080/v1/chat/completions -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

The proxy replaces the caller's `Authorization` header with the provider key
and prints one JSON access-log line per request, with `llm_input_tokens` and
`llm_output_tokens`. The quick-start config has no `auth` section, so it does
not check callers; keep it on loopback. Next:
[virtual keys](https://ergonlabs.io/docs/llm-proxy/authentication/virtual-keys/),
budgets, and [`llm-proxy init`](https://ergonlabs.io/docs/llm-proxy/getting-started/quickstart/),
which writes a starter config with authentication turned on.

### Install as a service

On macOS (Apple silicon) or Linux, the install script downloads the release,
verifies its SHA-256 checksum, writes a starter configuration with
`llm-proxy init` and an admin token, and starts the proxy as a launchd agent or
a systemd unit:

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh
```

It prints the admin UI address (`http://127.0.0.1:53422/ui/`), the admin token,
and an API key for the proxy on port `53421`. Re-run it to upgrade. For its
options, and for Kubernetes with the Helm chart in `deploy/helm/llm-proxy`, see
[Install llm-proxy](https://ergonlabs.io/docs/llm-proxy/getting-started/installation/)
and [Kubernetes and Helm](https://ergonlabs.io/docs/llm-proxy/operations/kubernetes/).

### Providers

OpenAI, Anthropic, OpenRouter, Azure OpenAI, Vertex AI, Amazon Bedrock, and any
OpenAI-compatible server (vLLM, Ollama, TGI). `examples/` has a runnable file
for several of them; `examples/llmproxy-openrouter.yaml` carries OpenRouter's
model catalog and token rates. See
[Providers](https://ergonlabs.io/docs/llm-proxy/providers/overview/).

### A fuller configuration

A configuration with failover and a token limit is still small:

```yaml
version: 0
listen: 0.0.0.0:53421
admin: 127.0.0.1:53422

providers:
  openai:                              # type and base_url inferred from the name
    api_key: ${OPENAI_API_KEY}
  local-vllm:                          # anything else defaults to openai-compatible
    base_url: http://vllm.internal:8000

routes:                                # first match wins, top to bottom
  - model: gpt-5*
    provider: openai
    fallbacks: [local-vllm]
  - model: "*"
    provider: local-vllm

limits:
  - key: header:authorization
    tokens_per_minute: 100k
```

`examples/llmproxy.yaml` is the annotated version of the same file, and
`schema/llmproxy-v0.schema.json` is the authority on every field — editors that
understand `yaml-language-server` autocomplete against it. `--mode translate`
prints the data-plane bootstrap a dialect file lowers to.

## Configuration surfaces

| Flag | Format |
|---|---|
| `--config PATH` | The LLM-native dialect. Always strict. |
| `-c, --config-path PATH` | A data-plane bootstrap (`.yaml`/`.json`/`.pb`). Strict unless `--permissive`. |

Bootstrap mode is where the full standard surface lives, including
`dynamic_resources` for xDS. Dialect mode covers the common gateway shape and
lowers onto it.

## Modes

| Command | What it does |
|---|---|
| `--mode serve` | Run the proxy. The default. |
| `--mode validate` | Check a configuration and exit. |
| `--mode translate` | Print the data-plane bootstrap a `--config` dialect file lowers to. |
| `--mode keygen` | Print a fresh virtual key and its digest. Needs `--tenant` and `--hmac-secret-file`; touches no configuration file. |

## Measured capacity

One published sweep, so the numbers are not a claim. Open-loop,
coordinated-omission-aware driver against a mock upstream, HTTP/2 on both hops,
128-token chat completions with 250 ms TTFT and 25 ms inter-token pacing; SLO
gate p99 ≤ 6900 ms and TTFT p99 ≤ 1000 ms. 80,507 requests over 20 levels on an
8-core, 16 GB MacBook Pro.

**Max sustainable concurrency within SLO: 808** (237 rps at that level, p99
3793 ms, TTFT p99 397 ms, peak RSS 84.4 MB, 22% mean CPU).

- RSS ≈ 31.5 MB baseline + **63.8 KB per concurrent stream** (R² = 0.981)
- CPU ≈ 544 ms baseline + **0.871 ms per request** (R² = 0.973)
- Error rate **0.00 at every level, including every failing one** — levels fail
  the SLO on latency, never on correctness. Nothing is dropped or truncated;
  requests queue.

Reproduce with `make sweep`.

### Added latency with controls on

What the proxy adds to one non-streaming request over a direct call to the
same mock upstream, with auth, token and request limits, a spend budget and
the billing ledger on. Minimum of 5 alternated rounds, open loop at 200
requests/s, on a quiet dedicated host (DigitalOcean, 16 vCPU Xeon Platinum
8168, CPU steal 0; 1-minute load average 0.1 for most runs), commit
`bf196879`.

| | p50 | p99 |
|---|---|---|
| Direct to the mock (baseline) | 0.21 ms | 0.36 ms |
| Proxy, controls off: added | +0.32 ms | +0.42 ms |
| Proxy, controls on: added | +0.40 ms | +0.50 ms |

Against a mock, added latency is a floor: a real provider adds far more
latency and variance than this. The full control chain costs about 0.08 ms
over the proxy alone. Reproduce with `make bench-added-latency`.

## Roadmap

| Release | Theme | |
|---|---|---|
| **v0.0.1** | First light — pass-through to OpenAI and Anthropic, streaming and not | Shipped 2026-08-01 |
| **v0.1.0** | LLM gateway — token metering, rate limits, provider failover | Shipped 2026-08-08 |
| **v0.2.0** | Production-ready serving — capacity report, admin endpoints, swap-under-load | Shipped 2026-08-29 |
| **v0.3.0** | ADS/xDS delivery | Shipped 2026-09-29; tagged with the dynamic-configuration gate still open |
| **v0.3.1** | Follow-up fixes, OpenRouter defaults, local metadata capture | Shipped 2026-10-09 |
| **v0.3.2** | Dynamic configuration — ADS/xDS gate, plus live-defect fixes | Shipped 2026-10-14 in tag v0.3.5 |
| **v0.3.3** | Tenant provider credentials — tenants send traffic on their own provider keys | Shipped 2026-10-11 as tag v0.3.2; follow-ups in tag v0.3.3 |
| **v0.3.4** | Hardening — production hardening from the 2026-10-10 design review | Shipped 2026-10-14 in tag v0.3.5 |
| **v0.4.0** | Gateway completeness — every control enforced as written; tenant limits and model access flow down to keys, which can only narrow them | Shipped 2026-10-16 in tag v0.4.0; follow-up tag v0.4.1 |
| **v0.5.0** | Billing ledger and trace export — a durable, encrypted billing ledger a consumer pulls and reconciles, and opt-in raw trace export for analytics | Shipped 2026-10-18 in tag v0.5.0 |
| **v0.6.0** | Metering completeness — every request a budgeted tenant can send is charged in the units the provider bills or refused, with chargeback tags and OTel GenAI semantic conventions | Shipped 2026-10-20 in tag v0.6.0; follow-up tag v0.6.1 |
| **v0.7.0** | Production deployment — several replicas behind a load balancer on Kubernetes: Helm chart and image, trusted hops for `client-ip`, gradual drain, and the overhead and scale numbers taken on a dedicated host | Shipped 2026-10-22 in tag v0.7.0 (latest release) |
| — | Data-plane parity — widen the set of standard bootstrap configs accepted, without migration | Unscheduled |
| **v1.0.0** | To be re-planned. The old theme (Gateway API Inference Extension, realtime sessions) was retired on 2026-10-15 | No gate, no scope |

Data-plane parity is not scheduled. Its Envoy differential rig work and corpus scorecard were closed as not needed on 2026-10-17.

## What is not built yet

Stated plainly, because a feature list without this is not much use:

- **HTTP/1.1 upstream reuse is bounded and not multiplexed.** Both protocols
  are cached per (cluster, address, protocol) on each worker thread. h1 keeps
  up to 8 idle keep-alive connections per key, and each one carries one request
  at a time. Concurrent h1 load past that still dials — and, where TLS is configured, handshakes — per request. Set
  `protocol: http2` where the provider supports it. There is no fallback: an
  HTTP/2 provider is offered `h2` and nothing else, so a backend that cannot
  speak it fails the TLS handshake rather than downgrading, which rules out most
  local plaintext servers. Upgrade requests bypass the cache by design.
- **Realtime sessions are metered from `response.done` events only.** Usage is
  read in the OpenAI Realtime event shape; a provider that reports it otherwise
  is counted as missing usage and warned about, not charged. A response cut
  before its `response.done` is not charged, and client frames are never
  inspected. There are no per-session gauges or mid-session log checkpoints.
- **The Envoy-baselined rename-churn comparison was waived.** The v0.3.2 gate
  is met without it. A zero-5xx run on a capacity host passed, but no run
  compares the proxy with Envoy at 5k requests per second. Static config plus SIGHUP
  remains supported; SIGHUP is refused when `dynamic_resources` is set.
- **Nothing watches files, and some auth settings need a restart.** A `SIGHUP`
  reload reads `api_key_file` and the TLS `cert_file`/`key_file` again. It does
  not apply changes to `auth.keys`, the HMAC secret, the auth store, or the
  OTLP `tracing`/`metrics` blocks; a change to any of them refuses the whole
  reload, and the proxy keeps serving the previous snapshot until a restart.
  See the reload table in
  [Reload configuration](docs/site/src/content/docs/operations/config-reload.md).
- **Authorization covers models only.** There is no per-provider
  authorization. An authenticated tenant with no stored model policy is refused
  with 403 unless `auth.enforce.tenants_without_policy` is `allow`.
- **A JWT caller's chargeback tags come only from mapped claims and the header.**
  `auth.jwt` (and `jwt_providers` in Envoy mode) admits a verified token as a
  tenant, with that tenant's stored provider credentials as for a virtual key
  (ADR-0014). Its tags come from the claims its provider maps
  (`auth.jwt[].claim_tags`) and from the `x-cost-tags` header; there is no
  per-JWT key metadata.
- **Limits apply to the fleet only with a `shared` store, and loosely.**
  With `auth.store: shared`, token and request windows reconcile through Redis
  about once a second, and each replica publishes its concurrent streams as a
  lease row once a second. The fleet can admit a little over a limit between
  reconciles. With another store each replica counts alone, so N replicas
  admit up to N times a limit.
- **Spend over-admission is bounded, not zero.** With a `shared` store,
  replicas share spend totals. During a store outage each replica enforces
  against the last confirmed total plus its own spend.
- **Token-usage metrics do not appear on `/stats`.** They have no data-plane
  equivalent, so they render on `/stats/prometheus` and over OTLP only.
- **No Kubernetes controller or CRDs.** The Helm chart
  (`deploy/helm/llm-proxy`) is plain manifests.

## Layout

```
crates/
  proxy/                  the binary: CLI, boot, ADS wiring, drain
  proxy-config/           bootstrap load, PGV validation, and the IR
                          (ir.rs — every other crate consumes this)
  proxy-simple-config/    the LLM-native dialect and its lowering
  proxy-core/             runtimes, config propagation, listeners,
                          transport sockets, L4 filter framework
  proxy-http/             HTTP data plane: router, retries, pools,
                          filter manager, access logging
  proxy-cluster/          cluster manager, discovery, load balancers,
                          health checks, outlier detection
  proxy-filters/          auth, JWT, model authz, token limits,
                          spend limits, usage accounting
  proxy-observability/    stats registry, access-log formatter, OTLP
  proxy-admin/            the admin server
  proxy-xds/              xDS client: subscriptions, ACK/NACK, backoff
  proxy-api/              generated data-plane API protos (the only place)
admin-ui/                 the single-page admin console served at /ui
docs/site/                Astro Starlight user documentation
examples/                 runnable configurations
schema/                   llmproxy-v0.schema.json — normative for the dialect
testing/                  diffrig, loadgen, mockupstream, controlplane,
                          xds-conformance, Go QA suite
```

## Documentation

The documentation is published at
[ergonlabs.io/docs/llm-proxy](https://ergonlabs.io/docs/llm-proxy/). Its source is
the Astro Starlight site in `docs/site/`: build it with `make docs-build`, check
its links with `make docs-check`, or serve it locally with `make docs-dev`.

## Development

The Makefile is the entry point; `make help` lists every target.

```sh
make tq-changed        # changed crates only — the default edit loop
make tq-<crate>        # one crate, e.g. make tq-proxy-http
make tq                # full workspace via nextest
make tq-doc            # doctests (nextest does not run them)
make ci                # fmt, clippy, tests, doctests, and QA — what CI enforces
make validate          # load examples/tcp-proxy.yaml
make xds-conformance   # xDS behaviour against a real go-control-plane server
make sweep             # the capacity sweep behind the numbers above
```

The code conventions are in [`AGENTS.md`](AGENTS.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the
[code of conduct](CODE_OF_CONDUCT.md). Report a suspected vulnerability
privately, as [SECURITY.md](SECURITY.md) describes, never in a public issue.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
