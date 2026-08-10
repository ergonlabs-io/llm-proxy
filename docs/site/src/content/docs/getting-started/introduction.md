---
title: Introduction to llm-proxy
summary: llm-proxy is a Rust proxy for LLM inference APIs, configured with the
  llmproxy dialect (schema/llmproxy-v0.schema.json). It meters tokens,
  enforces token-based rate limits, fails over between same-dialect
  providers, and authenticates callers.
last_updated: 2026-08-09
related:
  - /getting-started/quickstart/
  - /configuration/the-llmproxy-dialect/
---

# Introduction to llm-proxy

llm-proxy is a proxy for LLM inference APIs, written in Rust. It sits between
your callers and providers such as OpenAI, Anthropic, or a self-hosted
OpenAI-compatible server (vLLM, Ollama, TGI), and it understands the shape of
an LLM request well enough to meter tokens, route by model, fail over between
providers, and enforce per-caller budgets.

## Configuration

llm-proxy is configured with the `llmproxy` dialect: a single YAML file,
normatively defined by `schema/llmproxy-v0.schema.json`. You name providers
and routes by model pattern; llm-proxy handles the rest. Parsing is strict —
an unknown or misspelled field is a load error naming its exact dotted path,
never a silent ignore. [The `llmproxy` configuration dialect](/configuration/the-llmproxy-dialect/)
is the field-by-field reference.

## What ships today

Four LLM-specific behaviors are implemented and exercised by tests:

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

llm-proxy does not watch its config file for changes. A running process
re-reads its config only on `SIGHUP` — see
[Config reload](/operations/config-reload/) — never automatically. Changing a
config file on disk has no effect until you either send `SIGHUP` or restart
the process.

Provider fallback is scoped to same-dialect chains, as described above — it
is not yet a general "try any provider on failure" mechanism. And the
`models` catalogue in the dialect (a named model mapped to an ordered list of
providers) records every provider you list but, in this schema version, only
ever routes to the first one; see
[The `llmproxy` configuration dialect](/configuration/the-llmproxy-dialect/)
for the exact field-by-field behavior.
