---
title: Core concepts
description: The terms of llm-proxy (providers, models, routes, fallbacks, dialects, virtual keys, tenants) and the order of checks that a request passes.
summary: >-
  Defines each term that the configuration and the docs use, then walks one
  request from the client to the provider and back. Read this before the
  reference pages.
lastUpdated: 2026-10-21
related:
  - configuration/configuration-file
  - configuration/models-and-routes
  - authentication/virtual-keys
  - providers-and-routing/failover-and-aggregates
---

Each term below has one meaning across the docs. The config has two nouns for
what serves a request: `providers` and `models`. The docs do not use the word
"backend".

## Terms

| Term | Meaning |
|---|---|
| Provider | One upstream LLM API: a name, a type, a base URL, and credentials. The `providers` key in the file. |
| Model | A client-facing model name in the optional `models` catalog. It maps to an ordered list of providers. |
| Route | A rule that matches the request's `model` field and names a provider. The `routes` key. |
| Fallback | A provider that the proxy tries after the primary fails. A route lists `fallbacks`. A `models` entry lists later providers. |
| Dialect | The wire format of a provider: OpenAI-shaped or Anthropic-shaped. It decides how the proxy reads token usage. |
| Virtual key | A bearer token with the prefix `llmp_`. The proxy issues it to a caller. It is not a provider key. |
| JWT principal | A caller that sends a signed JWT from an issuer in `auth.jwt`, instead of a virtual key. |
| Tenant | The account or team that a caller belongs to. Limits, budgets, and model access apply to the tenant. |
| User | A person under a tenant. A virtual key's id names its user. A JWT user is `jwt:<issuer>:<tenant>:<user claim>`. |
| `auto` | A reserved model name. The proxy replaces it with the model that `auto` selects for the tenant. |

## Providers and dialects

A provider has a `type`. The schema lists these values: `openai`,
`anthropic`, `openai-compatible`, `openrouter`, `azure-openai`, `vertex`, and
`bedrock`. A provider named `openai`, `anthropic`, or `openrouter` infers its
type and base URL. Any other name defaults to `openai-compatible` and needs a
`base_url`. See [Providers](/docs/llm-proxy/providers/overview/).

The proxy passes requests through. It does not convert an OpenAI request into
an Anthropic request. The client must send the format that the provider
expects. A provider of type `vertex` or `bedrock` serves more than one wire
format, so a `models` entry that uses it must name the `dialect`.

## Routes and first-match order

A route has a `model` pattern and a `provider`. The proxy reads the `model`
field of the JSON body and checks `routes` from top to bottom. The first match
wins. There is no reordering by specificity, so put specific patterns above
broad ones.

The `models` catalog adds one implicit route for each entry. The proxy checks
those routes after `routes`. A `*` route therefore hides every `models` entry.
A request that matches no route and no `models` entry gets a `404`. See
[Models and routes](/docs/llm-proxy/configuration/models-and-routes/).

## The models catalog

The `models` key maps a client-facing name to an ordered list of providers.
The first provider serves the request. Each later provider is a fallback. A
provider entry can set the upstream `model` name, which the proxy writes into
the request for that provider. If you set `weight` on every provider, the proxy
picks the first provider in proportion to the weights. The remaining providers
stay the fallback chain. `session_affinity` keeps one session on one provider.
See [Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/).

## Fallbacks

A route can list `fallbacks` as provider names. The proxy tries them in order
after a connection failure, or a `429`, `500`, `502`, or `503` response. It
never retries after the first response byte reaches the client. Every provider
in a chain must use the same dialect. A mixed chain is a load error. See
[Failover and fallbacks](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

## Credentials follow the provider

Provider credentials live on the provider, never on the route. A request can
fail over to another provider. A credential on the route would then reach the
wrong provider. Each provider sends only its own key. The proxy removes the
caller's `Authorization` header after it authenticates the request, so the
virtual key never reaches a provider. A tenant can store its own key for a
provider. See
[Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

## Virtual keys, JWT principals, tenants, and users

With an `auth` block, every request must carry a recognized credential. The
credential is a virtual key (`Authorization: Bearer llmp_...`) or a JWT from an
issuer in `auth.jwt`. Authentication fails closed: a request with neither gets
`401`.

Each key belongs to one tenant. Many keys can share one tenant, so you can
revoke one key without revoking the account. A JWT is admitted as the tenant
that its `tenant.values` entry names. A tenant can have a model allow-list, a
spend budget, and limits. A key or user setting only narrows what the tenant
allows. An authenticated tenant with no stored model policy gets `403` unless
`auth.enforce.tenants_without_policy` is `allow`. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

## The `auto` model

If the config has an `auto` block, a request for the model `auto` is routed as
the model that the block selects. The block picks the tenant's entry in
`tenants`, or else `default`. With no match, the request gets `400`. The
access log and the usage record show both `auto` and the resolved model. See
[The auto model](/docs/llm-proxy/providers-and-routing/auto-model/).

## Request lifecycle

The proxy runs its checks in a fixed order. The order comes from the filter
chain that the config loader builds
(`crates/proxy-simple-config/src/lower.rs`). A step runs only if its feature
is in the config. A request that fails a step stops there.

1. The proxy accepts the connection. It ends TLS if you set `listen.tls`.
2. **Authentication.** The proxy checks the virtual key or JWT. A failure
   returns `401`.
3. **Object ownership.** The proxy checks that the tenant owns the file,
   batch, or stored response that the request names. A foreign or unknown
   object gets `404`.
4. **Model extraction.** The proxy reads the body to find the `model`. For
   streaming OpenAI requests it adds `stream_options.include_usage`, unless
   `observability.force_usage_reporting` is `false`.
5. **The `auto` model.** The proxy replaces `auto` with the selected model.
6. **Model authorization.** The proxy checks the tenant's model policy. A
   failure returns `403`.
7. **Guardrails.** The proxy sends the body to the check you configured. A
   denial returns `403`.
8. **Limits.** The proxy checks the token, request, and concurrent-stream
   limits. A failure returns `429` with `x-ratelimit-*` headers.
9. **Spend budget.** The proxy checks the key and tenant budgets. A request
   over a budget is refused.
10. **Routing and failover.** The proxy matches the route, picks the provider,
    adds the provider credential, and sends the request. On a failure it moves
    to the next provider in the chain.
11. **Metering.** The response streams back. The proxy reads the token counts
    and prices them with the rate card. It records them against the limits
    and budgets.
12. **Records.** The proxy writes the access log line. It also writes the
    request record and the billing ledger entry, if you enabled them.

## Limitations

- The proxy does not translate between dialects.
- Counters, keys, and policy are shared between replicas only with
  `auth.store: shared`.
- The proxy has no response cache.

See [Limitations](/docs/llm-proxy/help/limitations/).
