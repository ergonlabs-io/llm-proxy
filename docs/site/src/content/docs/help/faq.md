---
title: FAQ
description: "Short answers to the questions engineers ask when they compare llm-proxy with a hosted router or the LiteLLM proxy, with links to the full pages."
summary: Questions an evaluator asks, answered in a few sentences each. Every
  answer states what the proxy does today and links to the page that explains
  it.
lastUpdated: 2026-10-22
related:
  - getting-started/introduction
  - getting-started/coming-from-litellm-or-openrouter
  - help/limitations
  - help/troubleshooting
---

Each answer describes the current code in the repository. The 1.x releases follow the
[stability policy](/docs/llm-proxy/reference/stability/). See
[Limitations](/docs/llm-proxy/help/limitations/) for every gap.

## What it is

### What is llm-proxy?

A proxy for LLM inference APIs, written in Rust. It sits between your clients
and your providers. It routes, fails over, authenticates callers, meters
tokens and cost, limits usage, and logs. It reads one YAML config file. See
[Introduction](/docs/llm-proxy/getting-started/introduction/).

### How is it different from a hosted router?

A hosted router is a service with its own accounts and billing. llm-proxy is
software that you run. You bring your own provider keys, and traffic goes from
your proxy to the provider directly. llm-proxy can use a hosted router as one
of its providers. See [OpenRouter](/docs/llm-proxy/providers/openrouter/).

### How is it different from the LiteLLM proxy?

Both are self-hosted gateways. llm-proxy is a single Rust binary that passes
requests through in the client's own API format. It does not translate between
provider formats. See
[Coming from LiteLLM or OpenRouter](/docs/llm-proxy/getting-started/coming-from-litellm-or-openrouter/).

## Compatibility

### Which providers work?

The provider `type` accepts `openai`, `anthropic`, `openai-compatible`,
`openrouter`, `azure-openai`, `vertex`, and `bedrock`. A provider named
`openai`, `anthropic`, or `openrouter` infers its type and base URL. See
[Providers](/docs/llm-proxy/providers/overview/).

### Can I send an OpenAI request and reach Anthropic?

No. The proxy does not translate between dialects. A client that speaks the
OpenAI format must reach an OpenAI-format provider. A fallback chain that
mixes dialects fails at load. See
[API compatibility](/docs/llm-proxy/api-compatibility/overview/).

### Do the official SDKs work?

Yes, if you change the base URL and send a virtual key. The Anthropic SDK must
pass the key as `auth_token`, because the proxy does not read `x-api-key`. See
[Connect your application](/docs/llm-proxy/getting-started/connect-your-application/).

### Does it support streaming?

Yes. The proxy passes server-sent events through and reads token usage from
the stream. By default it adds `stream_options.include_usage` to streaming
OpenAI requests (`force_usage_reporting`). It never replays a request after
bytes reach the client.

### Does it support WebSocket?

Yes, for realtime sessions. Set `realtime.enabled: true`. The proxy meters a
session on a path that ends in `/realtime`. A WebSocket on another path is
tunnelled but not metered. See
[Realtime](/docs/llm-proxy/api-compatibility/realtime/).

### Which endpoints does it meter?

Chat completions, completions, Responses, Messages, embeddings, image
generation, image edits, speech, transcription, translation, and realtime
sessions. Batches, files, and image variations pass through unmetered, and a
spend budget or token limit refuses them. See
[API compatibility](/docs/llm-proxy/api-compatibility/overview/).

## Reliability

### How does failover work?

List providers in `models.<name>.providers`, or list `fallbacks` on a route.
The proxy tries the next provider on a connection failure or a `429`, `500`,
`502`, or `503` that arrives before any response byte. See
[Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

### Can I split traffic across providers?

Yes. Set `weight` on every provider of a `models` entry. The proxy picks the
first provider in proportion to the weights. `session_affinity` keeps one
session on one provider. See
[Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/).

### Does it pick the cheapest or fastest provider?

No. Failover is ordered and weights are fixed.

### Does it cache responses?

No. There is no response cache and no semantic cache.

### Does it have guardrails?

Yes. The `guardrails` block sends each request body to an HTTP check that you
run. The check allows or denies. See
[Guardrails](/docs/llm-proxy/authentication/guardrails/).

## Access control and spend

### How do I give each team a key?

Make virtual keys with `llm-proxy --mode keygen`, or with the admin API. Each
key belongs to a tenant. A request without a valid key gets `401`. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

### Does it support JWT?

Yes. Set `auth.jwt` to accept signed tokens from an issuer. The proxy accepts
RS256 only. See [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

### Can I limit usage?

Yes. `limits` entries cap tokens per minute, requests per minute, and
concurrent streams. A refusal is `429` with `x-ratelimit-*` headers. See
[Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/).

### Can I set a dollar budget?

Yes. Set a budget on a key or a tenant with the admin API. It needs an `auth`
block and a `pricing` rate card. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

### Can I restrict which models a tenant uses?

Yes. A tenant has a model policy. A tenant with no policy gets `403` unless
`auth.enforce.tenants_without_policy` is `allow`. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

### Can a tenant use its own provider key?

Yes, for providers that use a header API key. See
[Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

## Operations

### How do I run it in production?

Run the single binary under a supervisor, with an admin address for `/ready`.
See [Running in production](/docs/llm-proxy/operations/running-in-production/).

### Is there a Docker image or Helm chart?

Yes, from v0.7.0. The release workflow publishes a container image,
`ghcr.io/ergonlabs-io/llm-proxy`, and a Helm chart,
`oci://ghcr.io/ergonlabs-io/charts/llm-proxy`. See
[Kubernetes and Helm](/docs/llm-proxy/operations/kubernetes/).

### Can I reload config without downtime?

Yes, for most settings. Send `SIGHUP`. A config that fails to load leaves the
previous config in service. Auth, OTLP, ledger, and trace export settings need
a restart. See
[Reload configuration](/docs/llm-proxy/operations/config-reload/).

### Does it scale to many replicas?

Yes. With `auth.store: shared`, replicas share keys, policies, the rate card,
and limit counts through Redis. Each replica needs its own `--service-node`.
See [Running in production](/docs/llm-proxy/operations/running-in-production/).

### What do I monitor?

Use `/stats/prometheus` for metrics, the access log for per-request flags and
token counts, and OTLP for traces. See
[Observability](/docs/llm-proxy/observability/overview/).

### Does it store my prompts?

Only if you turn it on. The request record file holds metadata and no bodies.
Trace export writes bodies for tenants that opt in. See
[Request capture](/docs/llm-proxy/observability/request-capture/) and
[Trace export](/docs/llm-proxy/observability/trace-export/).

## Configuration

### What happens if I misspell a field?

The load fails and the error names the full dotted path. No option turns
strict parsing off. See
[Strict config mode](/docs/llm-proxy/configuration/strict-config-mode/).

### Can I use an Envoy bootstrap?

The binary accepts one with `-c`. This site covers the `--config` file only.
See [Limitations](/docs/llm-proxy/help/limitations/#available-only-in-envoy-mode).

## Related

- [Troubleshooting](/docs/llm-proxy/help/troubleshooting/)
- [Limitations](/docs/llm-proxy/help/limitations/)
- [Introduction](/docs/llm-proxy/getting-started/introduction/)
