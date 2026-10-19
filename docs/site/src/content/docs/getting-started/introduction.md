---
title: Introduction to llm-proxy
description: "What llm-proxy is, what it does for LLM traffic, its security defaults, and where to start."
summary: llm-proxy is a Rust proxy for LLM inference APIs, configured with a
  single YAML file (schema/llmproxy-v0.schema.json). It meters tokens,
  enforces token-based rate limits, fails over between same-dialect
  providers, and authenticates callers.
lastUpdated: 2026-10-18
related:
  - getting-started/quickstart
  - configuration/configuration-file
---

# Introduction to llm-proxy

llm-proxy is a proxy for LLM inference APIs, written in Rust. It sits between
your callers and providers such as OpenAI, Anthropic, or a self-hosted
OpenAI-compatible server (vLLM, Ollama, TGI), and it understands the shape of
an LLM request well enough to meter tokens, route by model, fail over between
providers, and enforce per-caller budgets.

## Configuration

llm-proxy is configured with a single YAML file, normatively defined by
`schema/llmproxy-v0.schema.json`. You name providers and routes by model
pattern; llm-proxy handles the rest. Parsing is strict — an unknown or
misspelled field is a load error naming its exact dotted path, never a
silent ignore. [Configuration file reference](../../configuration/configuration-file/)
is the field-by-field reference.

## Features

These LLM-specific behaviors are implemented and covered by tests:

- **Token metering.** Every response is parsed for token counts — OpenAI chat
  completions, OpenAI Responses, and Anthropic Messages, streaming and
  non-streaming — without buffering the response body
  (`crates/proxy-filters/src/usage.rs`). Counts reach the access log as
  `%LLM_INPUT_TOKENS%`, `%LLM_OUTPUT_TOKENS%`, `%LLM_CACHED_TOKENS%`,
  `%LLM_CACHE_CREATION_TOKENS%`, and `%LLM_TOTAL_TOKENS%`, plus TTFT and TPOT
  timing (`crates/proxy-observability/src/access_log.rs`).
- **Rate limiting.** A `limits` entry keyed on `global`, `client-ip`,
  `tenant`, or `header:<name>` caps tokens, requests, or concurrent streams
  in a one-minute window. A refusal is a 429 with `x-ratelimit-*` headers.
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
- **Authentication and model access.** With an `auth:` block, a request must
  carry a recognized virtual key, or the proxy refuses it with `401` before
  any provider is reached. An authenticated tenant also needs a model policy
  that permits the requested model, or it gets `403`. See
  [Security defaults](#security-defaults).
- **Spend budgets and pricing.** Tenant and key budgets in US dollars, priced
  from a rate card. See [Spend policies](../../limits-and-budgets/spend-policies/).
- **Tenant provider credentials.** A tenant can store its own provider key.
  See [Tenant provider credentials](../../authentication/tenant-provider-credentials/).
- **Admin API and UI.** Read endpoints, a bearer-gated write API, and a
  browser UI at `/ui`. See [Admin endpoints](../../observability/admin-endpoints/).
- **OTLP metrics export.** `observability.metrics` sends metrics to an
  OTLP/gRPC collector. See [Metrics and /stats](../../observability/metrics-and-stats/).
- **Request capture.** See [Request capture](../../observability/request-capture/).
- **External authorization.** See
  [External authorization](../../authentication/external-authorization/).
- **Envoy config and xDS.** The same engine loads an Envoy bootstrap and
  takes xDS updates. See [xDS conformance](../../operations/xds-conformance/).

## Security defaults

| Control | Default | Exception |
|---|---|---|
| Authentication | Without an `auth:` block, there is none. With one, a request without a recognized virtual key gets `401`. | None. |
| Model authorization | With an `auth:` block, a tenant with no stored model policy gets `403` (`auth.enforce.tenants_without_policy: deny`). | The starter config from `llm-proxy init` sets `allow`. Remove it before you issue keys to other people. |
| Provider authorization | None. A tenant that may use a model may use every provider that serves it. | A tenant that stores its own provider key can use only providers it holds a key for. |
| Admin write API | Refused (`403`) unless `LLMPROXY_ADMIN_TOKEN` is set. | None. |
| Revocation | Through the admin API, at once on the replica that receives it, and within one policy poll on others. A key in `auth.keys` changes only on restart. | None. |

See [Virtual keys](../../authentication/virtual-keys/) and
[Manage configured virtual keys](../../authentication/managing-secrets/).

## Where to start

1. [Quickstart](../quickstart/): install, connect one provider, send a request.
2. [Connect your application](../connect-your-application/): point an SDK at the proxy.
3. [Manage configured virtual keys](../../authentication/managing-secrets/): keys and model access.
4. [Configure rate limits](../../limits-and-budgets/token-rate-limiting/) and
   [spend budgets](../../limits-and-budgets/spend-policies/).
5. [Share state across replicas](../../operations/running-in-production/) for production.

## What it is not

llm-proxy does not watch its config file for changes. A running process
re-reads its config only on `SIGHUP` — see
[Config reload](../../operations/config-reload/) — never automatically. Changing a
config file on disk has no effect until you either send `SIGHUP` or restart
the process.

Provider fallback is scoped to same-dialect chains, as described above — it
is not yet a general "try any provider on failure" mechanism. And the
`models` catalogue in the configuration (a named model mapped to an ordered
list of providers) lowers a list of more than one provider to an ordered
fallback chain, and the same-dialect rule applies to it; see
[Configuration file reference](../../configuration/configuration-file/)
for the exact field-by-field behavior.
