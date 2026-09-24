# llm-proxy

One static binary and one YAML file between your applications and your model
providers, so token metering, budgets, authentication, failover, and access
logging happen in one place instead of in every service that calls a model.

It is an Envoy-shaped proxy specialised for LLM traffic. The data plane is
Envoy's — listeners, filter chains, clusters, load balancers, health checking,
outlier detection, retries, xDS — and the LLM parts (token accounting, spend
budgets, provider dialects, per-tenant quotas) are filters and cluster policy on
top of it, not a parallel system.

**Status: pre-1.0.** `v0.2.0` is the current tag; `v0.3.0` (dynamic
configuration) is in progress. The data plane serves real traffic and is covered
by **1868 tests**. Interfaces still change between releases and there are no
backports to earlier tags. Read [What is not built yet](#what-is-not-built-yet)
before you depend on it — that section is deliberately specific.

## Why this shape

Two design decisions explain most of the code.

**Envoy semantics, not an Envoy-inspired approximation.** The proxy reads a
standard Envoy bootstrap and speaks xDS. Response flags, access-log operators,
retry-on conditions, outlier ejection, cluster warming — these follow Envoy's
documented behaviour rather than a convenient reinterpretation of it, so
operators who already run Envoy do not have to learn a second set of rules, and
divergences have to be argued for in writing (`internal-docs/envoy-divergences.md`).

**A small LLM-native dialect that lowers onto it.** Nobody wants to write an
Envoy bootstrap to put a rate limit in front of OpenAI. `--config` takes a
compact dialect — providers, routes, limits — which lowers to standard Envoy
resources and then flows through the identical parse → validate → IR pipeline as
bootstrap mode. `--mode translate` prints exactly what it lowered to. The rule
that keeps this honest: **a capability must exist in the Envoy-mode surface
before the dialect may expose it.** The dialect is a front end, never a second
config system.

Both surfaces are **strict**. An unknown or misspelled field is an error
carrying its full dotted path, never a silent no-op — a silently ignored field
is treated as a P0 bug in this repo, because a limit you think you configured
and did not is worse than no limit at all.

## Architecture

```
   clients (OpenAI / Anthropic SDKs, unchanged base URL)
        │
        ▼
 ┌─ listener + filter chain ────────────────────────────────┐
 │                                                          │
 │  auth      virtual keys (HMAC-SHA256, constant time)     │
 │  model     per-tenant model allow-lists                  │
 │  limits    per-tenant token budgets, windowed            │
 │  spend     currency budgets from a price table           │
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
 admin :9901   read:  /ready /config_dump /clusters /server_info
                      /stats /stats/prometheus
               write: /keys /tenants /tenants/{id}/policy|budget
                      (bearer-gated; no token means 403, never open)
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

**Speaks your provider's API.** OpenAI Chat Completions, OpenAI Responses, and
Anthropic Messages. Point an existing client at llm-proxy by changing its base
URL; requests and responses pass through unchanged.

**Streams properly.** Server-sent events are forwarded as they arrive, and the
proxy never injects frames of its own into a stream. An unclean end of stream
stays unclean, because inventing a well-formed ending would hide a real failure
from the client.

**Meters tokens.** Input, output, and separately-priced buckets are read from
provider responses, for streaming and non-streaming requests alike, and land in
the access log.

**Enforces token budgets.** A tenant over its limit gets a 429 with
`x-ratelimit-*` headers before the request reaches a provider. A request already
in flight is never cut short. Limits are keyed to the authenticated tenant, so
changing a header does not buy a fresh quota. A tenant can read its own
current-window standing at `GET /v1/usage`, scoped to the key it presented —
never to a tenant it names itself.

**Enforces spend budgets.** Token counts are priced from an integer micro-USD
table and charged against a per-tenant ceiling; over it, a 429 with
`spend_budget_exceeded`. Cost is only knowable when a response ends, so the
request that crosses the line is admitted and the *next* one is refused —
overspend is bounded by one request, never unbounded.

**Authenticates callers.** Virtual keys verified with HMAC-SHA256 in constant
time. Authentication fails closed: with an `auth` block configured, a request
with no recognised credential is refused rather than admitted anonymously.

**Authorizes models.** A tenant can be restricted to named models and exclude
specific models from that grant. The effective access is allow minus deny,
enforced before routing. It fails closed on an unauthenticated request and
defaults to all models for an authenticated tenant with no policy.

**Mints and revokes keys at runtime.** A bearer-gated admin write API creates
tenants, mints and revokes virtual keys, and sets per-tenant policies and
budgets, against an in-memory, embedded (redb), or shared (Redis) control-plane
store. Revocation takes effect on the auth path without a restart.

**Fails over between providers.** A route can name an ordered list; if the
primary fails, the next is tried, with retries, retry budgets, and per-try
timeouts. Every provider in a chain must speak the same wire format, and a chain
that mixes formats is rejected when the configuration loads rather than at
request time.

**Keeps bad upstreams out of rotation.** Active health checks and outlier
detection eject hosts that fail, with the ejection visible in `/clusters` and in
the access log's response flags. Circuit breakers bound connections, pending
requests, and in-flight requests per cluster.

**Terminates TLS.** Listener TLS from the dialect; mTLS, SAN matchers, and dual
certificates from the Envoy surface.

**Tunnels HTTP upgrades.** A WebSocket `Upgrade` — the shape several providers'
realtime APIs use — passes through byte for byte once the upstream accepts it.
Bootstrap configuration only; `upgrade_configs` is not reachable from the
dialect.

**Tells you what it is doing.** Access logs with token counts,
time-to-first-token, time-per-output-token, and Envoy response flags. OTLP
traces with W3C `traceparent` propagation. An admin endpoint serving `/ready`,
`/config_dump`, `/clusters`, `/server_info`, `/stats` and `/stats/prometheus`
unauthenticated, and the control-plane writes behind a bearer token — unset
means 403, never open.

**Survives operations.** Configuration reloads on SIGHUP — and a configuration
that fails to parse leaves the previous one serving, with the error logged
against its exact field path. SIGTERM drains connections instead of dropping
them. A config swap under live traffic is covered by a differential test that
asserts every in-flight SSE stream still reaches its terminal frame.

**Takes configuration from a control plane.** ADS state-of-the-world for
clusters, listeners, and endpoints, with correct ACK/NACK, reconnect with
backoff, and last-good config retained on failure. Conformance is checked
against go-control-plane (`make xds-conformance`), not only against our own
harness — a harness we wrote both sides of cannot catch us agreeing with
ourselves and both being wrong. See
[What is not built yet](#what-is-not-built-yet) for how far this goes today.

## Build

Requires a Rust toolchain and `protoc` (`brew install protobuf`, or
`apt install protobuf-compiler`).

```sh
cargo build --workspace
make ci          # fmt, clippy, tests, doctests, qa — what CI enforces
make tq          # the whole test suite via nextest
```

## Try it

`examples/llmproxy-ollama.yaml` runs against a local Ollama and needs no API
keys or environment variables:

```sh
# Check the configuration without starting anything.
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml --mode validate
# configuration 'examples/llmproxy-ollama.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))

# See what it lowers to.
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml --mode translate

# Serve.
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml
```

Then send it an ordinary OpenAI-shaped request on the port the file lists.

A useful configuration is small:

```yaml
version: 0
listen: 0.0.0.0:8080
admin: 127.0.0.1:9901

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

`--mode validate` warns about any field that parses but is not yet enforced, so
a configuration that says more than the proxy does tells you at load time rather
than in production.

`examples/llmproxy.yaml` is the annotated version of the same file, and
`schema/llmproxy-v0.schema.json` is the authority on every field — editors that
understand `yaml-language-server` autocomplete against it.

## Configuration surfaces

| Flag | Format |
|---|---|
| `--config PATH` | The LLM-native dialect. Always strict. |
| `-c, --config-path PATH` | An Envoy bootstrap (`.yaml`/`.json`/`.pb`). Strict unless `--permissive`. |

Bootstrap mode is where the full Envoy surface lives, including
`dynamic_resources` for xDS. Dialect mode covers the common gateway shape and
lowers onto it.

## Modes

| Command | What it does |
|---|---|
| `--mode serve` | Run the proxy. The default. |
| `--mode validate` | Check a configuration and exit. |
| `--mode translate` | Print the Envoy bootstrap a `--config` dialect file lowers to. |
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

## What is not built yet

Stated plainly, because a feature list without this is not much use:

- **HTTP/1.1 upstream reuse is one idle connection at a time.** Both protocols
  are cached per (cluster, address, protocol), but h1 keeps a single idle
  keep-alive connection where h2 keeps a bounded set. Concurrent h1 load past
  that still dials — and, where TLS is configured, handshakes — per request. Set
  `protocol: http2` where the provider supports it. There is no fallback: an
  HTTP/2 provider is offered `h2` and nothing else, so a backend that cannot
  speak it fails the TLS handshake rather than downgrading, which rules out most
  local plaintext servers. Upgrade requests bypass the cache by design.
- **Dynamic configuration is partial.** CDS, LDS, RDS, SDS, and EDS are wired.
  RDS-dependent and replacement listeners warm while last-good generations keep
  serving, and ADS initial-fetch timeout is honored. Delta xDS, file transport,
  init-manager sequencing, and full 5k-rps differential rename-churn verification
  remain open (`v0.3.0`). SDS supports downstream certificate and validation-context
  delivery with inline data sources. Static config plus SIGHUP remains supported.
- **File-sourced credentials and certificates are read once.** `api_key_file`,
  `hmac_secret_file`, `cert_file`/`key_file` take effect on restart or SIGHUP —
  nothing watches them. Changing the control-plane store spec or its poll
  interval needs a restart even with SIGHUP.
- **Authorization defaults open, and covers models only.** Authentication fails
  closed, and so does model authz for an unauthenticated request — but an
  authenticated tenant absent from the policy snapshot is allowed everything.
  There is no per-provider authorization.
- **Model authz and spend budgets are Envoy-bootstrap only.** Neither filter is
  in the chain the `llmproxy` dialect lowers to.
- **Spend ceilings are enforced per process.** N replicas means N ceilings, even
  with a shared store.
- **JWT verification is library-only.** `jwt_auth` verifies RS256 against a
  static JWKS but is not wired into the authenticator chain, so it cannot be
  reached from configuration.
- **Three dialect fields parse but do nothing:** `limits[].requests_per_minute`,
  `limits[].concurrent_sessions`, and `limits[].models`. Rate-limit bucket keys
  are also not configurable — the token limiter keys on the authenticated
  tenant, or on the `authorization` header when there is none, so only
  `key: tenant` and `key: header:authorization` do anything. All of these warn
  at load rather than failing silently.
- **Token-usage metrics do not appear on `/stats`.** They have no Envoy
  equivalent, so they render on `/stats/prometheus` and over OTLP only.
- **`--drain-strategy` has no effect.** It is accepted and warns at startup.
- **No embeddings and no `/v1/models` handling.** A request to any other path
  proxies through, but gets no token metering.
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
  proxy-api/              generated Envoy v3 protos (the only place)
docs/site/                Astro Starlight user documentation
examples/                 runnable configurations
schema/                   llmproxy-v0.schema.json — normative for the dialect
testing/                  diffrig, loadgen, mockupstream, controlplane,
                          xds-conformance, Go QA suite
internal-docs/            implementation plan, milestones, ADRs, capacity
```

## Documentation

Full documentation lives in `docs/site/` — an Astro Starlight site covering
getting started, the configuration reference, providers and routing,
authentication, limits and budgets, observability, and operations. Build it with
`make docs-build`, or run it locally with `make docs-dev`. It is not published to
a public URL yet.

## Contributing and security

Vulnerability reports: see [SECURITY.md](SECURITY.md). Please report privately
rather than in a public issue — note that the private contact is not filled in
yet.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
