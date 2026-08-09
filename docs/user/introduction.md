---
title: Introduction to llm-proxy
summary: llm-proxy is a Rust proxy for LLM inference APIs that speaks standard
  Envoy configuration and xDS, with a simpler LLM-native config dialect as an
  alternative front end. It meters tokens, enforces token-based rate limits,
  fails over between same-dialect providers, and authenticates callers.
last_updated: 2026-08-09
related:
  - getting-started.md
  - configuration-dialect.md
---

# Introduction to llm-proxy

llm-proxy is a proxy for LLM inference APIs, written in Rust. It sits between
your callers and providers such as OpenAI, Anthropic, or a self-hosted
OpenAI-compatible server (vLLM, Ollama, TGI), and it understands the shape of
an LLM request well enough to meter tokens, route by model, fail over between
providers, and enforce per-caller budgets.

## It speaks standard Envoy configuration

llm-proxy's engine accepts an Envoy v3 bootstrap file — listeners, clusters,
routes, HTTP filters — the same resources Envoy itself takes on `-c`. If your
team already has Envoy-shaped configuration, you can point it at llm-proxy
unchanged for the parts of Envoy's surface it implements. This is a
compatibility target, not a claim of full parity: `docs/envoy-divergences.md`
records every place llm-proxy's behavior differs from Envoy on purpose, and a
handful of fields and extensions are rejected outright rather than silently
ignored — the same strict-parsing principle the dialect uses (see "Strict
parsing" in `configuration-dialect.md`). Read `docs/envoy-divergences.md`,
and the CLI flag policy in it, before assuming a specific Envoy flag or
extension is supported.

## Two config front ends

llm-proxy has exactly one engine and two ways to configure it:

- **Envoy bootstrap mode** (`-c bootstrap.yaml`): the full Envoy-compatible
  surface — listeners, clusters, filters, everything the engine implements.
  Use this when you are migrating an existing Envoy/Istio/Envoy Gateway
  config, or you need a capability the dialect does not expose yet.
- **The `llmproxy` dialect** (`--config llmproxy.yaml`): a smaller,
  LLM-native config format, normatively defined by
  `schema/llmproxy-v0.schema.json`. You name providers and routes by model
  pattern instead of writing clusters and route matches by hand.

The dialect is a front end, not a second engine: `llm-proxy --config
llmproxy.yaml --mode translate` prints the exact Envoy bootstrap it lowers to,
and that bootstrap runs through the same validation pipeline as a hand-written
one. Because of that, the dialect can only expose a capability that already
exists on the Envoy-mode surface — it is a shorthand, never a superset. Pick
the dialect to get running in minutes with a handful of providers and routes;
drop to Envoy bootstrap mode when you need a capability the dialect has not
grown yet, or you are already operating Envoy-shaped config elsewhere.

## What ships today

Four LLM-specific behaviors are implemented and exercised by tests, in both
config front ends where the dialect exposes them:

- **Token metering.** Every response is parsed for token counts — OpenAI chat
  completions, OpenAI Responses, and Anthropic Messages, streaming and
  non-streaming — without buffering the response body
  (`crates/proxy-filters/src/usage.rs`). Counts reach the access log as
  `%LLM_INPUT_TOKENS%`, `%LLM_OUTPUT_TOKENS%`, `%LLM_CACHED_TOKENS%`,
  `%LLM_CACHE_CREATION_TOKENS%`, and `%LLM_TOTAL_TOKENS%`, plus TTFT and TPOT
  timing (`crates/proxy-observability/src/access_log.rs`).
- **Token-based rate limiting.** A limit keyed on `header:authorization` (or
  `tenant`, when `auth:` is configured) admits or refuses a request based on a
  rolling token budget, with a 429 and `x-ratelimit-*` headers on refusal.
  A request already streaming is never truncated
  (`crates/proxy-filters/src/token_limit_filter.rs`).
- **Provider failover.** A route's `fallbacks` list is tried in order when the
  primary provider's connection fails, or it returns a 429 or a 5xx before any
  response byte — never after streaming to the client has begun. This works
  today between providers that speak the **same** wire dialect (for example,
  one OpenAI-shaped provider falling back to another); a cross-dialect chain
  (OpenAI primary, Anthropic fallback) is a load-time error, not a silent
  best-effort attempt, because the wrong dialect's parser would read the
  response and report the wrong token counts
  (`crates/proxy-simple-config/src/lower.rs`, `lower_route`).
- **Downstream authentication.** With an `auth:` block configured, a request
  must carry a recognized virtual key or it is refused with a 401 before any
  provider is reached. Authentication fails closed; authorization (which
  models or providers an authenticated caller may use) is a separate,
  currently open, axis (`crates/proxy-filters/src/auth_filter.rs`).

## What it is not

llm-proxy does not reload configuration while running. A config file is read
once at startup; there is no watch-and-republish path wired into the running
proxy today. Changing a config means restarting the process. Dynamic
configuration via xDS is planned (see the crate layout in the repository
root's `README.md`) but is not the boot path `serve` mode takes today.

Provider fallback is scoped to same-dialect chains, as described above — it
is not yet a general "try any provider on failure" mechanism. And the
`models` catalogue in the dialect (a named model mapped to an ordered list of
providers) records every provider you list but, in this schema version, only
ever routes to the first one; see `configuration-dialect.md` for the exact
field-by-field behavior.
