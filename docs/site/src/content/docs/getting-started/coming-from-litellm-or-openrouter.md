---
title: Coming from LiteLLM or OpenRouter
description: Map LiteLLM proxy and OpenRouter concepts to llm-proxy terms, and see which features have no equivalent.
summary: >-
  Two concept maps, one for the LiteLLM proxy and one for OpenRouter. Each row
  names the llm-proxy equivalent, or says that there is none.
lastUpdated: 2026-10-21
related:
  - getting-started/core-concepts
  - getting-started/introduction
  - help/limitations
---

This page helps you move from another gateway. llm-proxy is a self-hosted
gateway that you configure with one YAML file. The page maps familiar terms to
llm-proxy terms. It does not replace the documentation of those products.

## The main difference

llm-proxy passes requests through in the provider's own format. The LiteLLM
proxy converts requests between provider formats. OpenRouter is a hosted
service. If your application sends one OpenAI-style call and expects it to
reach an Anthropic model, llm-proxy does not do that. A client must send an
Anthropic Messages request to an Anthropic provider.

## LiteLLM proxy to llm-proxy

| LiteLLM concept | llm-proxy equivalent | Notes |
|---|---|---|
| `model_list` entry | A `providers` entry plus a `routes` rule or a `models` entry | A route matches a pattern on the request's `model` field. |
| `model_name` alias | A `models` entry | The entry lists providers in failover order. Each provider can set the upstream `model`. |
| `litellm_params.api_key` | `providers.<name>.api_key` or `api_key_file` | Set only one of the two. Use `${ENV_VAR}` for the value. |
| `os.environ/KEY` | `${KEY}` in the YAML | The loader applies interpolation before it parses the file. |
| Format conversion between providers | None | Passthrough only. A fallback chain that mixes dialects is a load error. |
| `fallbacks` | `routes[].fallbacks`, or later providers of a `models` entry | Same dialect only. Triggers: connection failure, `429`, `500`, `502`, `503`. |
| `num_retries` | `routes[].retries.attempts` | Default 1. Maximum 5. |
| `timeout` | `routes[].idle_timeout` | Default 90s. It measures time with no bytes flowing. There is no total-duration timeout by default. |
| `simple-shuffle` with weights | `weight` on the providers of a `models` entry | The first provider is picked in proportion to weight. |
| Sticky routing for prompt caching | `models.<name>.session_affinity` | Pins a session to one provider of a weighted model. |
| `least-busy`, `latency-based-routing`, cost-based routing | None | Cost-aware selection is not supported. |
| Cooldown of a failing deployment | `providers.<name>.outlier_detection` | Ejection is per proxy process. |
| `max_parallel_requests` | `limits[].concurrent_sessions`, and `providers.<name>.circuit_breakers` | The first counts streams for each bucket. The second caps requests to one provider. |
| Virtual keys | `auth.keys`, or keys minted through the admin API | A key belongs to a tenant. Create a key with `--mode keygen` or the admin API. |
| SSO and JWT authentication | `auth.jwt` | RS256 tokens with a `kid` header. A claim maps to a tenant. |
| Teams | Tenants | One tenant has many keys. |
| Users | Users under a tenant | A virtual key's id names its user. A JWT user comes from a claim. |
| `max_budget` for a key or team | Spend budgets | In US dollars, for keys and tenants. Needs a rate card in `pricing`. |
| `tpm_limit` and `rpm_limit` | `limits[].tokens_per_minute` and `requests_per_minute` | Keyed on `global`, `client-ip`, `tenant`, or `header:<name>`. |
| Model access per key or team | Per-tenant and per-key model allow-lists | Set through the admin API. |
| Guardrails | `guardrails` | The proxy sends each request body to an HTTP check you run. The check can allow or deny. It cannot change the request. |
| Callbacks and logging integrations | Access logs, request records, billing ledger, trace export, OTLP metrics and traces | There is no callback plug-in system. |
| Spend tags | Chargeback tags | Tags come from key metadata, JWT claims, or the `x-cost-tags` header. |
| Admin dashboard | Admin UI at `/ui/` | See [Admin UI](/docs/llm-proxy/administration/admin-ui/). |
| Database for keys and spend | `auth.store` | Use `persistent` for one replica, or `shared` (Redis) for many. |
| Model aliases for "smart" routing | The `auto` model | The tenant selects the model. The request does not. |
| Response caching | None | The proxy has no response cache. |
| Python SDK | None | Use the OpenAI or Anthropic SDK against the proxy. |

## OpenRouter to llm-proxy

| OpenRouter concept | llm-proxy equivalent | Notes |
|---|---|---|
| One API key for many models | A virtual key, plus one provider for each upstream | You hold each provider account. |
| `vendor/model` model IDs | The `openrouter` provider type | It sends OpenAI-compatible requests to OpenRouter. It rewrites `/v1` to `/api/v1`. |
| Model list | `GET /v1/models`, from your `models` and `routes` | The proxy answers from its config. It does not query a provider. |
| Credits and billing | `pricing` rate card and spend budgets | You pay providers directly. The proxy prices tokens and can enforce a budget. |
| Provider fallback | `routes[].fallbacks`, or a `models` entry | Same dialect only. |
| Provider routing preferences | `weight` and `session_affinity` on a `models` entry | The operator sets these for the fleet. A caller does not choose a provider. |
| Hosted availability | None | You run and scale the proxy. |
| Cross-provider normalization | None | Passthrough. |

You can put OpenRouter behind llm-proxy as one provider. See
[OpenRouter](/docs/llm-proxy/providers/openrouter/).

## What llm-proxy adds

- Strict configuration with dotted-path errors.
- Streaming that the proxy does not buffer and does not add frames to.
- Credentials bound to the provider, not the route.
- Tenant-owned provider objects: a tenant cannot read another tenant's files
  or batches.
- An encrypted billing ledger with one entry for each dialled request.

## Limitations

- No response caching.
- No translation between dialects.
- No routing by latency or cost.
- No prebuilt Docker image or Helm chart.
- Token counters are shared between replicas only with `auth.store: shared`.

See [Limitations](/docs/llm-proxy/help/limitations/).
