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
![Version: v0.6.1](https://img.shields.io/badge/version-v0.6.1-blue.svg)
![Status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-yellow.svg)
![Rust](https://img.shields.io/badge/rust-stable-orange.svg)

</div>

```sh
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml            # serve, against a local Ollama
cargo run -p proxy -- --config examples/llmproxy.yaml --mode validate   # check a configuration; exit
cargo run -p proxy -- --config examples/llmproxy.yaml --mode translate  # print the data-plane bootstrap it lowers to
```

> [!NOTE]
> **The data plane serves real traffic; workspace qualification passed 2,335 tests.**
> `v0.6.1` is the current release.
> Interfaces still change between releases and there are no backports to earlier
> tags. Read [What is not built yet](#what-is-not-built-yet) before you depend
> on it — that section is deliberately specific — and
> [Roadmap](#roadmap) for where each release stands.

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
for in writing (`internal-docs/` keeps the divergence log).

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

## Build

Requires a Rust toolchain and `protoc` (`brew install protobuf`, or
`apt install protobuf-compiler`). The result is a single static binary,
`llm-proxy`, with no runtime dependencies.

```sh
git clone https://github.com/ergonlabs-io/llm-proxy.git
cd llm-proxy
cargo build --workspace          # -> target/debug/llm-proxy
make ci                          # fmt, clippy, tests, doctests, qa — what CI enforces
make tq                          # the whole test suite via nextest
```

### Use OpenRouter locally

The OpenRouter provider forwards OpenAI-compatible chat requests requests, rewriting `/v1` to OpenRouter's `/api/v1` on the selected cluster. The
example contains 469 model IDs imported on 2026-10-08, including vendor prefixes
and suffixes. `/v1/models` serves those IDs locally; it does not query OpenRouter. Availability, supported
parameters, and account permissions are determined by OpenRouter.

```sh
export OPENROUTER_API_KEY='your-openrouter-key'
python3 scripts/import-openrouter-models.py  # optional explicit catalog refresh
make build
./target/debug/llm-proxy --config examples/llmproxy-openrouter.yaml
```

Point your OpenAI-compatible client at `http://127.0.0.1:8080/v1`. Discover model
IDs with `curl http://127.0.0.1:8080/v1/models`, then use one as the request's `model`:

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}'
```

The example denies the `models`, `route`, `plugins`, and `transforms` body fields on the OpenRouter provider: OpenRouter honors them to run other models or paid plugins, and they bypass the proxy's model authorization. Remove entries from `request_fields.deny` to allow them.

The example listens only on loopback and has no downstream authentication. The
OpenRouter key comes from the environment and replaces downstream authorization
on the provider cluster. Live requests use your OpenRouter account and may incur
charges. This configuration covers OpenAI-compatible chat and streaming; other
OpenRouter API families are not qualified by this example. See the
[OpenRouter model API](https://openrouter.ai/docs/api/api-reference/models/get-models).

The OpenRouter importer installs exact token rates in
`pricing.price_list`, and preserves all published pricing in `pricing.catalog`.
The Pricing UI reads `GET /pricing` from the proxy, including the active version
and explicit reasons for models without a usable token rate card. No cache rates
are inferred and fractional nanodollars are never rounded. An unknown cache rate
makes requests reporting that cache bucket unpriced; ordinary requests still use
the known input/output rates. Whole-request tier overrides are imported with
inclusive thresholds. Non-token charges remain visible but are excluded from
token cost calculation.

Where the rate card lives depends on whether the filter chain has a
control-plane store: an `auth` section in the dialect, or `llmproxy.auth` in
bootstrap mode. `examples/llmproxy-openrouter.yaml` has none.

- **With a store**, the store holds the rate card, per chain, and it wins. At
  start the configured rate card seeds an empty store once. After that, neither a
  restart nor a `SIGHUP` reload replaces a stored rate card; the proxy logs once
  when the configuration differs from the stored card. `PUT /pricing` writes the
  store and installs the card on the replica that received it at once. Every
  other replica that shares the store installs it on its next policy poll, which
  is 48 to 60 seconds at the default `poll_interval_seconds`. Only the
  `persistent` and `shared` stores keep the card across a restart. The default
  in-memory store loses it, and the response says `"persisted": false`.
- **Without a store**, the configuration is the only durable source. A `SIGHUP`
  reload installs the configured rate card when it changed, and a reload that did
  not change it keeps a rate card installed with `PUT`. `PUT /pricing` changes
  only the replica that receives it, and a restart loads the configured rate card
  again. The response says `"persisted": false`.

A request that has started keeps the rate card that was active when it started.
A listener rebuilds its filter chain when a connection arrives after a reload, so
a changed configured rate card applies from the first new connection.

**Warning:** A model with no price adds $0 to every `llmproxy.spend_limit`
dollar budget. The proxy does not refuse the request. It logs one warning for
each chain and model, with the reason, and stops logging that model. It names at
most 256 models per chain, then logs one summary line. A model has no price when
the rate card has no entry for it. `PUT /pricing` replaces the whole rate card, so a model that is
missing from the new rate card has no price. The access log shows `-` for
`%LLM_LIST_COST%` when the rate card has no price. `GET /keys/{id}/spend` counts
these requests in `unpriced_requests`.

`PUT /pricing` needs the admin token (`LLMPROXY_ADMIN_TOKEN`) as a bearer token.
It does not need an `auth` section. It accepts a body up to 4 MiB, which holds
the rate card in `examples/llmproxy-openrouter.yaml` with its catalog (268 KB
compact, 401 KB pretty-printed); every other admin write is limited to 64 KiB.
It returns `400` for invalid JSON, an invalid rate card, or an `effective_from`
in the future. A rate card applies from the moment it is installed, so a future
date is refused instead of applied early. It returns `503` when the store
refuses the write, and then no replica has changed.

Each priced request records the rate card version (`%LLM_RATE_CARD_VERSION%` in
the access log). The version covers the price entries and the map from cluster to
provider type, so replicas that differ in either record different versions.
`GET /pricing` also shows `rate_card_version`.

Importing prices does not create dollar budgets.

### Install a release

On macOS (Apple Silicon) or Linux (x86-64), install the latest release and start
it as a service:

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh
```

The installer:

- downloads the release for your platform and verifies its SHA-256 checksum;
- creates a starter configuration with `llm-proxy init` and an admin token;
- starts the proxy as a launchd agent (macOS) or a systemd user unit (Linux),
  so it restarts after a crash and at login;
- waits until the proxy is ready, then prints the admin UI address, the admin
  token, and the proxy API key.

Open `http://127.0.0.1:53422/ui/` and paste the admin token to manage keys,
tenants, and pricing. The proxy API listens on port `53421`. The admin UI
listens on loopback only; on a remote host, use `ssh -L 53422:127.0.0.1:53422`,
or install with `--admin-address 0.0.0.0:53422` on a network you trust. The
admin API is plain HTTP, so on that address the admin token crosses the network
unencrypted, and `/config_dump`, `/stats`, and `/clusters` are readable without
it. The installer warns about this on every run.

Run as root on Linux, the installer writes a system unit that runs as an
`llm-proxy` system user, with files in `/usr/local/bin` and `/var/lib/llm-proxy`.
Without systemd (for example, in a container), it starts a background process.

Re-run the same command to upgrade. It keeps the existing configuration,
secrets, and admin token. Pass options after `sh -s --`:

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh -s -- --version v0.6.1 --port 8080 --admin-port 8081
```

| Option | Effect |
| --- | --- |
| `--version TAG` | Install this release instead of the latest. |
| `--port N`, `--admin-port N` | Ports for a new configuration. |
| `--admin-address HOST:PORT` | Admin and UI address for a new configuration, for example `0.0.0.0:53422`. |
| `--no-start` | Install only. |
| `--no-service` | Start a background process instead of a service. |
| `--uninstall [--purge]` | Remove the service and binary; `--purge` also deletes the data directory. |

## Quick start

**1. Check the configuration without starting anything.**

```sh
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml --mode validate
# configuration 'examples/llmproxy-ollama.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

`examples/llmproxy-ollama.yaml` runs against a local Ollama and needs no API
keys or environment variables. `--mode validate` warns when you switch a control off
(for example `auth.enforce.model_policy: false`), so a configuration that says
more than the proxy does tells you at load time rather than in production.

**2. See what it lowers to.**

```sh
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml --mode translate
```

**3. Serve, and send it an ordinary OpenAI-shaped request** on the port the file
lists:

```sh
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml
```

A useful configuration is small:

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
understand `yaml-language-server` autocomplete against it.

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

Full method, the not-harness-bound argument, and what is *not* saturated:
`internal-docs/capacity/README.md`. Reproduce with `make sweep`.

### Added latency with controls on

What the proxy adds to one non-streaming request over a direct call to the
same mock upstream, with auth, token and request limits, a spend budget and
the billing ledger on. Minimum of 5 alternated rounds, open loop at 200
requests/s, M1 Pro MacBook Pro. **Measured under load** (1-minute load average
5-50 on 8 cores, from other builds): a quiet-machine run is still to come.

| | p50 | p99 |
|---|---|---|
| Direct to the mock (baseline) | 0.29 ms | 2.45 ms |
| Proxy, controls off: added | +0.17 ms | +1.18 ms |
| Proxy, controls on: added | +0.23 ms | +0.97 ms |

Against a mock, added latency is a floor: a real provider adds far more
latency and variance than this. On this box, controls on and controls off
differ by less than the spread between rounds. Method, exact configs, a row
per control group, and raw results: `internal-docs/capacity/added-latency.md`.
Reproduce with `make bench-added-latency`.

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
| **v0.6.0** | Metering completeness — every request a budgeted tenant can send is charged in the units the provider bills or refused, with chargeback tags and OTel GenAI semantic conventions | Shipped 2026-10-20 in tag v0.6.0; latest release is tag v0.6.1 |
| — | Data-plane parity — widen the set of standard bootstrap configs accepted, without migration | Unscheduled |
| **v1.0.0** | To be re-planned. The old theme (Gateway API Inference Extension, realtime sessions) was retired on 2026-10-15 | No gate, no scope |

Ship gates, evidence, and deliberate caveats for each release:
[`internal-docs/MILESTONES.md`](internal-docs/MILESTONES.md). Data-plane parity
is not scheduled. Its Envoy differential rig work and corpus scorecard were closed as not needed on 2026-10-17.

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
  compares the proxy with Envoy at 5k requests per second
  (`internal-docs/MILESTONES.md`, v0.3.2 section). Static config plus SIGHUP
  remains supported; SIGHUP is refused when `dynamic_resources` is set.
- **Nothing watches files, and some auth settings need a restart.** A `SIGHUP`
  reload reads `api_key_file` and the TLS `cert_file`/`key_file` again. It does
  not apply changes to `auth.keys`, the HMAC secret, the auth store, or the
  OTLP `tracing`/`metrics` blocks; those take a restart. Changing the HMAC
  secret and sending `SIGHUP` refuses every key until a restart (a known
  defect). See the reload table in
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
- **`client-ip` buckets see the balancer address behind a load balancer.** The
  dialect has no trusted-hops setting. It uses the TCP peer address and never
  reads `x-forwarded-for`.
- **A key budget counts one credential source.** A budget is scoped to
  `platform` or `tenant` credentials. It ignores spend of the other source
  (ADR-0007). A per-key `include_byok_in_limit` flag that counts both is
  planned for v0.8.0.
- **Token-usage metrics do not appear on `/stats`.** They have no data-plane
  equivalent, so they render on `/stats/prometheus` and over OTLP only.
- **`--drain-strategy` has no effect.** It is accepted and warns at startup when given; both values drain like Envoy's `immediate`.
- **No Kubernetes controller or CRDs.**

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
internal-docs/            architecture, Envoy semantics and divergences,
                          milestones, ADRs, capacity
```

## Documentation

Full documentation lives in `docs/site/` — an Astro Starlight site covering
getting started, the configuration reference, providers and routing,
authentication, limits and budgets, observability, and operations. Build it with
`make docs-build`, or run it locally with `make docs-dev`. It is not published to
a public URL yet.

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

Release gates, work packages, and architecture decision records are in
`internal-docs/`; contribution conventions are summarised in
[`AGENTS.md`](AGENTS.md).

## Contributing and security

Vulnerability reports: see [SECURITY.md](SECURITY.md). Do not report a
suspected vulnerability in a public issue. The private reporting channel is not
published yet.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
