---
title: Introduction
description: "What llm-proxy is, what it does today, what it does not do, and how it differs from a hosted router and from the LiteLLM proxy."
summary: llm-proxy is a self-hosted Rust proxy for LLM inference APIs,
  configured with one YAML file (schema/llmproxy-v1.schema.json). It forwards
  requests in the provider's own dialect and adds token metering, virtual keys
  and JWT authentication, token limits, spend budgets, guardrails, failover,
  weighted routing, and usage records.
lastUpdated: 2026-10-21
related:
  - getting-started/installation
  - getting-started/quickstart
  - getting-started/core-concepts
  - getting-started/coming-from-litellm-or-openrouter
  - reference/stability
---

llm-proxy is a self-hosted gateway for LLM inference APIs, written in Rust. It
sits between your applications and your providers, such as OpenAI, Anthropic,
or a self-hosted OpenAI-compatible server (vLLM, Ollama, TGI). It is one binary
that you configure with one YAML file. Use it to put token accounting, access
control, limits, and failover in one place instead of in every service.

The project is pre-1.0. Interfaces change between releases.

## At a glance

- **Config:** one YAML file, passed with `llm-proxy --config <file>`. The
  schema is `schema/llmproxy-v1.schema.json`.
- **Strict by default:** an unknown or misspelled field is a load error that
  names the dotted path. The proxy does not start.
- **Authentication:** none unless the file has an `auth` block. With the block,
  a request without a recognized credential gets `401`.
- **Reload:** the proxy re-reads its file on `SIGHUP`. It does not watch the
  file. See [Reload configuration](/docs/llm-proxy/operations/config-reload/).
- **Versioning:** [Stability and versioning](/docs/llm-proxy/reference/stability/)
  lists what the 1.x releases keep stable across an upgrade.

## What it does today

| Capability | Behavior | Learn more |
|---|---|---|
| Passthrough | Forwards OpenAI Chat Completions, OpenAI Responses, and Anthropic Messages requests without translation. | [API compatibility](/docs/llm-proxy/api-compatibility/overview/) |
| Streaming | Forwards server-sent events as they arrive. The proxy does not buffer a response. | [API compatibility](/docs/llm-proxy/api-compatibility/overview/) |
| Token metering | Reads token counts from each response, streaming or not, without buffering. Counts reach the access log, the usage record, limits, and budgets. | [Access logs](/docs/llm-proxy/observability/access-logs/) |
| Authentication | Virtual keys (`llmp_...`) and JWT principals (`auth.jwt`). Fails closed. | [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/) |
| Model access | Per-tenant model allow-lists. A tenant with no policy gets `403` by default. | [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/) |
| Token and request limits | `limits` entries cap tokens per minute, requests per minute, and concurrent streams. A refusal is `429` with `x-ratelimit-*` headers. | [Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/) |
| Spend budgets | Budgets in US dollars for keys and tenants, priced from a rate card. | [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/) |
| Guardrails | The proxy sends each request body to an HTTP check you run. The check allows or denies. | [Guardrails](/docs/llm-proxy/authentication/guardrails/) |
| Failover | A route's `fallbacks`, or the providers of a `models` entry, are tried in order on a connection failure, `429`, `500`, `502`, or `503`. | [Failover](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/) |
| Weighted routing | A `models` entry can split requests across providers by weight, with optional session affinity. | [Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/) |
| The `auto` model | A request for `auto` is routed as the model that you pick for its tenant. | [The auto model](/docs/llm-proxy/providers-and-routing/auto-model/) |
| Tenant provider credentials | A tenant can store its own provider key. | [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/) |
| Usage records | Request records file, billing ledger, chargeback tags, and body export. | [Observability](/docs/llm-proxy/observability/overview/) |
| Realtime | WebSocket sessions, metered, when `realtime.enabled` is `true`. | [Realtime](/docs/llm-proxy/api-compatibility/realtime/) |
| Admin API and UI | Read endpoints, a bearer-gated write API, and a browser UI at `/ui/`. | [Admin API](/docs/llm-proxy/administration/admin-api/) |

## What it is not

- **Not a translator.** A request for an Anthropic provider must be an
  Anthropic request. A fallback chain that mixes dialects is a load error.
- **Not a hosted service.** You run it. It does not hold your provider
  accounts and does not bill you.
- **Not a cache.** The proxy has no response cache.
- **Not a content filter.** The proxy does not inspect prompts itself. A
  guardrail check that you run does.
- **Not a file watcher.** A change to the config file has no effect until
  `SIGHUP` or a restart.

The full list is on [Limitations](/docs/llm-proxy/help/limitations/).

## How it compares

| | llm-proxy | Hosted router (for example OpenRouter) | LiteLLM proxy |
|---|---|---|---|
| Where it runs | Your infrastructure | The vendor's infrastructure | Your infrastructure |
| Dialect handling | Passthrough, no conversion | One API for many providers | Converts between provider formats |
| Provider credentials | Yours, held on each provider | The vendor's, or yours | Yours |
| Configuration | One strict YAML file | Dashboard and API | YAML file and a database |

For a term-by-term map, read
[Coming from LiteLLM or OpenRouter](/docs/llm-proxy/getting-started/coming-from-litellm-or-openrouter/).

## Security defaults

| Control | Default | Exception |
|---|---|---|
| Authentication | Without an `auth:` block, there is none. With one, a request without a recognized credential gets `401`. | None. |
| Model authorization | With an `auth:` block, a tenant with no stored model policy gets `403` (`auth.enforce.tenants_without_policy: deny`). | The starter config from `llm-proxy init` sets `allow`. Remove it before you issue keys to other people. |
| Provider authorization | None. A tenant that may use a model may use every provider that serves it. | A tenant that stores its own provider key can use only providers it holds a key for. |
| Admin write API | Refused (`403`) unless `LLMPROXY_ADMIN_TOKEN` is set. | None. |
| Revocation | Through the admin API, at once on the replica that receives it, and within one policy poll on others. A key in `auth.keys` changes only on restart. | None. |

See [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/) and
[Manage configured virtual keys](/docs/llm-proxy/authentication/managing-secrets/).

## Where to start

1. [Install llm-proxy](/docs/llm-proxy/getting-started/installation/).
2. [Quickstart](/docs/llm-proxy/getting-started/quickstart/): connect one
   provider and send a request.
3. [Core concepts](/docs/llm-proxy/getting-started/core-concepts/): the terms
   and the path of a request.
4. [Connect your application](/docs/llm-proxy/getting-started/connect-your-application/):
   point an SDK at the proxy.
5. [Manage configured virtual keys](/docs/llm-proxy/authentication/managing-secrets/),
   then [limits](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/) and
   [spend budgets](/docs/llm-proxy/limits-and-budgets/spend-policies/).
6. [Running in production](/docs/llm-proxy/operations/running-in-production/):
   share state across replicas.

## Limitations

- Fallback works only within a chain of providers that use the same dialect.
- Replicas share counters, keys, and policy only with `auth.store: shared`.
  See [Running in production](/docs/llm-proxy/operations/running-in-production/).
- Nothing watches credential or certificate files. A new provider key or
  certificate needs a `SIGHUP` reload.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.
