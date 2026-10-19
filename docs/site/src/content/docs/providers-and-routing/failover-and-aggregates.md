---
title: Failover and aggregates
description: "Try more providers in order when one fails, with fallbacks and model entries that list several providers."
summary: How to use a route's `fallbacks` list or a `models` entry with several
  providers, which failures move a request to the next provider, and how
  retry count and the same-dialect rule affect a chain.
lastUpdated: 2026-10-18
related:
  - providers-and-routing/providers-and-clusters
  - providers-and-routing/timeouts-and-retries
  - configuration/configuration-file
---

# Failover and aggregates

Use `fallbacks` to try additional providers in order. Every provider in the
chain must use the same API dialect. Use this feature when one provider can
fail or reach a rate limit, and a second provider can serve the same model
name.

## Enable failover

Add a `fallbacks` list to a route. The route's `provider` is the primary.
The proxy tries it first. Each entry in `fallbacks` is tried in the order
you write it.

```yaml
version: 0
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  together:
    type: openai-compatible
    base_url: https://api.together.xyz
    api_key: ${TOGETHER_API_KEY}
routes:
  - model: "gpt-4o*"
    provider: openai
    fallbacks: [together]
```

A `models` entry does the same. The first provider is the primary. Each
later provider is a fallback.

```yaml
models:
  chat-default:
    providers: [openai, together]
```

Source for the fields: `schema/llmproxy-v0.schema.json`, `$defs/Route`
(`fallbacks`, `retries`) and `$defs/ModelDef` (`providers`). A route with
no `fallbacks` sends the request to its one provider and has no chain.

## When a request moves to the next provider

The proxy tries each provider once for a request. It moves to the next
provider only on an outcome that shows the provider did not serve the request:

- A connection failure.
- An HTTP/2 `refused-stream`.
- A reset before any response byte.
- A response with status 429, 500, 502, or 503.

The route's retry triggers are fixed to this list, and you cannot change them
in the `llmproxy` dialect. See
[Timeouts and retries](../../providers-and-routing/timeouts-and-retries/) for
the full trigger table. A fallback attempt is a retry that lands on a
different provider, so the same table applies.

After the client starts to receive a stream, that response is final. The
proxy never tries a later provider after the first response byte reaches the
client. A partial reply is never replaced by the answer of a different
provider.

If every provider fails, the client gets the last provider's response
unchanged. The proxy does not make up its own `503` in that case.

Selection is strict order. The proxy does not send a share of traffic to the
fallback while the primary is partly healthy. This differs from Envoy's
aggregate cluster, which can send a share of traffic across a partly healthy
member boundary. For LLM providers, that share would reach the fallback's
billing and rate limits while the primary still works. The dialect has no
setting to change this. Nested chains are not supported: a chain is one level
of failover.

## Credentials stay with each provider

Each provider in the chain keeps its own TLS settings, credentials, and
`Host` header. When a request fails over, the fallback request carries the
fallback provider's API key. It does not carry the primary's key. See
[Providers and clusters](../../providers-and-routing/providers-and-clusters/)
for the reason.

## `retries.attempts` and the chain use one retry count

`routes[].retries.attempts` (default `1`, maximum `5`) is not a separate
budget from failover. Both use the same retry count. To reach the last of
*N* providers, a request needs at least *N*-1 retries. The proxy uses the
larger of two numbers: your `attempts` value, or the number needed to reach
every fallback.

For example, a chain of three providers (a primary and two fallbacks) with
`retries: { attempts: 1 }` gets 2 retries.

Two results follow from this:

- **`retries: { attempts: 0 }` does not disable failover** on a route that
  has `fallbacks`. It removes only the extra retries beyond those that reach
  the last fallback. On a route with no `fallbacks`, `attempts: 0` turns
  retries off.
- On a route with `fallbacks`, `retries.attempts` does not repeat the
  primary. The first failed attempt marks the primary as tried for this
  request. The next retry goes to the first fallback. A retry against the
  same provider is possible only on a route with no `fallbacks`.

## Use the same API dialect

Every provider in a chain must use the same API dialect as the primary. An
OpenAI-shaped provider can fall back to another OpenAI-shaped provider,
including `openai-compatible`. A chain that mixes OpenAI-shaped and
Anthropic-shaped providers is a load error. It is not a warning.

The reason is accuracy. The primary's request body is not valid for the
fallback's API. The proxy would also read the fallback's response with the
wrong dialect's parser, so token counts and billing would be wrong. For
`models` entries, the load error names the path `models.<name>.providers[<n>]`.
See [Getting started](../../getting-started/quickstart/) for the error text.

## Failover in the `models` catalogue

`models.<name>.providers` is an ordered list. A list with more than one
provider gets the same retry count as `routes[].fallbacks`: the number of
providers minus 1. A `models` entry has no `retries` field. See
[Configuration file](../../configuration/configuration-file/) for the fields
a `models` entry accepts.

## Bootstrap configuration

The Envoy-mode equivalent is an `envoy.clusters.aggregate` cluster. Set
`lb_policy: CLUSTER_PROVIDED` and a `cluster_type.typed_config.clusters`
member list, then point a route's `cluster` at the aggregate.

The same-dialect rule applies to the `llmproxy` dialect only, because that
format checks the dialect of the usage-metering filter. A raw bootstrap
configuration has no such check.

## Implementation notes

This section is for maintainers.

- A route with `fallbacks` lowers to an `envoy.clusters.aggregate` cluster
  named `fallback:route-<index>`. A `models` entry with several providers
  lowers to `fallback:model-<name>`. Members are the primary's cluster
  followed by each fallback's cluster. Code: `lower_route` and `lower_model`
  in `crates/proxy-simple-config/src/lower.rs`. Tests:
  `one_fallback_emits_an_aggregate_with_members_in_order` and
  `route_with_fallback_targets_the_aggregate_not_the_primary` in
  `crates/proxy-simple-config/tests/fallbacks.rs`;
  `models_multiple_providers_lower_to_ordered_fallback` in
  `crates/proxy-simple-config/tests/dialect.rs`.
- Lowering sets `retry_on` to `connect-failure,refused-stream,reset,
  retriable-status-codes` with the status list 429, 500, 502, 503.
- Lowering raises `num_retries` to reach every member. Test:
  `num_retries_is_raised_to_reach_every_member`.
- Strict member order: `ClusterHandle::select_aggregate_member` in
  `crates/proxy-cluster/src/manager.rs`.
- Credential isolation: `credential_isolation_across_failover` in
  `crates/proxy-http/tests/router_aggregate.rs`.
- Cross-dialect rejection: `cross_dialect_fallback_is_rejected` in
  `crates/proxy-simple-config/tests/fallbacks.rs`.
