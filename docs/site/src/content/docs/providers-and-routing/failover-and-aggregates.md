---
title: Failover and aggregates
description: "Try more providers in order when one fails, with fallbacks and model entries that list several providers."
summary: How to use a route's `fallbacks` list or a `models` entry with several
  providers, which failures move a request to the next provider, how a
  provider that fails often is passed over, and how retry count and the
  same-dialect rule affect a chain.
lastUpdated: 2026-10-20
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
- The provider's credential cannot be applied: no unexpired minted OAuth2
  token, or a failed Bedrock signature. Nothing is sent to that provider.

The route's retry triggers are fixed to this list, and you cannot change them
in the `llmproxy` dialect. See
[Timeouts and retries](../../providers-and-routing/timeouts-and-retries/) for
the full trigger table. A fallback attempt is a retry that lands on a
different provider, so the same table applies. A credential failure is the
exception: it moves to the next provider without using a retry, because the
failed provider received nothing. The proxy counts it in
`llmproxy_provider_credential_requests_total` with an `outcome` that ends in
`_failover`, and logs a warning that names the provider's cluster, at most
once a minute per cluster on each worker.

After the client starts to receive a stream, that response is final. The
proxy never tries a later provider after the first response byte reaches the
client. A partial reply is never replaced by the answer of a different
provider.

If every provider fails, the client gets the last provider's response
unchanged. The proxy does not make up its own `503` in that case. If the
last provider's credential cannot be applied, there is no response to
return, and the client gets a local `503` (`provider token unavailable` or
`provider credential failure`).

Selection is strict order. The proxy does not send a share of traffic to the
fallback while the primary is partly healthy. To spread first picks across
the providers of a `models` entry, see
[Weighted selection](#weighted-selection-in-the-models-catalogue). This differs from Envoy's
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

## A provider that is not healthy is passed over

A chain passes over a member when none of its hosts is healthy. A host is
not healthy when outlier detection ejected it or when it fails its active
health checks. The proxy passes over such a member only while a later member
has a healthy host. This rule applies to `fallbacks`, to `models` entries
with or without weights, and to aggregates in Envoy mode.

When every member is unhealthy, the chain runs in list order as if no member
were ejected. If all of them fail, the client gets the last provider's own
answer.

In the `llmproxy` dialect, `providers.<name>.outlier_detection` ejects a
provider. It is off when you omit it.

| Field | Type | Default | What it does |
|---|---|---|---|
| `consecutive_5xx` | integer, 1 or more | `5` | Consecutive failed attempts that eject the provider. A 5xx response and a local failure count. A 429 does not count and ends the run. |
| `base_ejection_time` | duration | `30s` | Length of the first ejection. Each later ejection lasts this value times the number of ejections so far. Must be greater than 0. |
| `max_ejection_time` | duration | the larger of `300s` and `base_ejection_time` | Upper bound on one ejection. Must not be less than `base_ejection_time`. |

Ejection is per proxy process. Replicas do not share it. A provider cluster
has one host, so the lowering sets `max_ejection_percent` to 100.

```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    outlier_detection:
      consecutive_5xx: 3
      base_ejection_time: 30s
models:
  chat-default:
    providers: [openai, together]
```

In this example, 3 failed attempts in a row eject `openai` for 30 seconds.
The second ejection lasts 60 seconds. Requests for `chat-default` go to
`together` while `openai` is ejected.

## Weighted selection in the `models` catalogue

Add `weight` to every entry of `models.<name>.providers` to spread first
picks across providers. Write each entry in the object form. The shorthand
string form cannot carry `weight`.

```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    outlier_detection: {}
  together:
    type: openai-compatible
    base_url: https://api.together.xyz
    api_key: ${TOGETHER_API_KEY}
    outlier_detection: {}
models:
  chat-default:
    providers:
      - { provider: openai, weight: 3 }
      - { provider: together, weight: 1 }
```

About 3 of 4 requests start at `openai`. About 1 of 4 starts at `together`.
For each request, the other entries are its fallbacks in list order. The
fallback rules in this page apply without change.

Rules for `weight`:

- The value is an integer from 0 to 1000000.
- Set `weight` on every entry or on none.
- Weight `0` makes an entry a fallback only. It never gets a first pick.
- At least one weight must be above 0.
- A provider must appear once in a weighted list.
- Without `weight`, `providers[0]` serves and the rest are fallbacks.

A mix of weighted and unweighted entries, a shorthand string entry in a
weighted list, all-zero weights, and a provider listed twice are load
errors. Each error names the path `models.<name>.providers[<n>]`. The
all-zero error names `models.<name>.providers`.

The proxy picks the first provider once for each request, with a uniform
random draw. The draw uses no per-worker state, so the split is the same on
every worker. Replicas do not coordinate. The split matches the weights over
many requests, not over a few. Retries stay inside the chain of the picked
provider.

A provider that is ejected by its `outlier_detection` gets no first picks.
Its share goes to the next entry in list order that is not ejected. It
serves first picks again when the ejection ends.

Weighting never changes the model that the client gets. Each member is still
a provider with its own credentials, `Host` header, upstream model ID, and
usage dialect. The proxy charges a request at the rate card of the provider
that it dialled. The proxy does not support cost-aware selection. Entries
with different API dialects are still a load error.

## Bootstrap configuration

The Envoy-mode equivalent is an `envoy.clusters.aggregate` cluster. Set
`lb_policy: CLUSTER_PROVIDED` and a `cluster_type.typed_config.clusters`
member list, then point a route's `cluster` at the aggregate.

For weighted first picks, point the route at `weighted_clusters`. Each entry
names an aggregate cluster, and each aggregate lists the same providers with
a different first member. Put `outlier_detection` on the member clusters.

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
- A weighted `models` entry lowers to a route with `weighted_clusters` over
  one aggregate for each entry with weight above 0. The aggregate is named
  `fallback:model-<name>@<provider>`. Its members are that provider, then
  every other entry in list order. Code: `lower_model` in
  `crates/proxy-simple-config/src/lower.rs`. Tests in
  `crates/proxy-simple-config/tests/weighted_models.rs`:
  `an_alias_without_weights_lowers_exactly_as_before`,
  `weights_lower_to_weighted_clusters_over_rotated_aggregates`,
  `every_draw_starts_at_the_provider_its_weight_owns`, and
  `a_weight_on_a_single_provider_alias_targets_the_provider`.
- Weight validation: `check_model_weights` in
  `crates/proxy-simple-config/src/parse.rs`. Tests in the same file as
  above: `a_shorthand_entry_in_a_weighted_list_is_refused`,
  `an_object_entry_without_a_weight_in_a_weighted_list_is_refused`,
  `all_zero_weights_are_refused`, `a_weight_over_the_maximum_is_refused`,
  `a_provider_listed_twice_in_a_weighted_list_is_refused`, and
  `a_cross_dialect_member_of_a_weighted_alias_is_still_refused`.
- Outlier detection lowering: `lower_outlier_detection` in
  `crates/proxy-simple-config/src/lower.rs`. Tests:
  `outlier_detection_lowers_to_the_provider_cluster`,
  `an_empty_outlier_detection_block_uses_the_defaults`,
  `outlier_detection_values_that_cannot_eject_are_refused`, and
  `an_unknown_outlier_detection_field_is_refused`.
- Passing over an unhealthy member: `select_aggregate_member` and
  `walk_aggregate_members` in `crates/proxy-cluster/src/manager.rs`. The
  first pass skips members with no healthy host. The second pass runs
  without that preference. Tests in the same file:
  `aggregate_passes_over_an_ejected_member_until_it_recovers` and
  `aggregate_with_every_member_ejected_still_walks_the_whole_chain`.
- End-to-end: `the_split_follows_the_weights_and_every_request_gets_the_aliass_model`,
  `an_ejected_provider_gets_no_weighted_traffic`,
  `an_ejected_provider_gets_weighted_traffic_again_after_it_recovers`,
  `a_fully_down_weighted_alias_returns_the_exhausted_chain_answer`, and
  `failover_after_a_weighted_pick_isolates_credentials_and_charges_the_dialled_provider`
  in `testing/diffrig/tests/weighted_e2e.rs`. QA scenario:
  `TestQA15_WeightedAliasSplitsAndSkipsAnEjectedProvider` in
  `testing/qa/scenarios/qa15_weighted_providers_test.go`.
- Lowering sets `retry_on` to `connect-failure,refused-stream,reset,
  retriable-status-codes` with the status list 429, 500, 502, 503.
- Lowering raises `num_retries` to reach every member. Test:
  `num_retries_is_raised_to_reach_every_member`.
- Strict member order: `ClusterHandle::select_aggregate_member` in
  `crates/proxy-cluster/src/manager.rs`.
- Credential isolation: `credential_isolation_across_failover` in
  `crates/proxy-http/tests/router_aggregate.rs`.
- Failover on a credential failure: `crates/proxy-http/tests/router_credential_failover.rs`
  (Bedrock signing) and `with_no_token_a_request_fails_over_to_the_fallback_provider`
  in `crates/proxy/tests/oauth2_token_e2e.rs` (OAuth2 token, rate card).
- Cross-dialect rejection: `cross_dialect_fallback_is_rejected` in
  `crates/proxy-simple-config/tests/fallbacks.rs`.
