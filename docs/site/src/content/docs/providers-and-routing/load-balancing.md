---
title: Load balancing
description: "Spread requests across the providers of a model with weights, keep a session on one provider, and set concurrency ceilings for each provider."
summary: How weights pick the first provider of a models entry, how
  session_affinity pins a session to one provider so its prompt cache stays
  warm, and how each provider's concurrency ceilings shed load. A provider has
  one endpoint, so balancing happens between providers.
lastUpdated: 2026-10-21
related:
  - providers-and-routing/failover-and-aggregates
  - configuration/models-and-routes
  - providers/overview
  - authentication/virtual-keys
  - reference/metrics
---

Load balancing in llm-proxy happens between the providers of one model. You
add a `weight` to each provider of a `models` entry. The proxy then picks the
first provider of each request in proportion to the weights. The other
providers of the entry are the fallbacks of that request. Use this page to
spread load, to move traffic in small steps, or to keep a conversation on one
provider.

## At a glance

- **Default when unset:** without `weight`, the first provider serves every
  request. The other providers are fallbacks only.
- **Failure mode:** weights never remove failover. A provider that fails still
  moves the request to the next provider in the list.
- **Scope:** weights act on the providers of one `models` entry. A `routes`
  entry has no weights.

## Minimal example

```yaml title="llmproxy.yaml"
version: 0
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  together:
    type: openai-compatible
    base_url: https://api.together.xyz
    api_key: ${TOGETHER_API_KEY}
models:
  chat-default:
    providers:
      - { provider: openai, weight: 3 }
      - { provider: together, weight: 1 }
```

About 3 of 4 requests for `chat-default` start at `openai`. About 1 of 4
starts at `together`. If the first provider fails, the request moves to the
other provider.

## Weights

The proxy draws the first provider once for each request. The draw is random
and has no per-worker state, so the split is the same on every worker.
Replicas do not coordinate. The split matches the weights over many requests,
not over a few.

| Field | Type | Default | Description |
|---|---|---|---|
| `models.<name>.providers[].weight` | integer, 0 to 1000000 | none | Share of requests that start at this provider. |

Rules for `weight`:

- Write each entry in the object form. The shorthand string form cannot carry
  `weight`.
- Set `weight` on every entry or on none.
- Weight `0` makes an entry a fallback only. It never gets a first pick.
- At least one weight must be above 0.
- A provider must appear once in a weighted list.

A mix of weighted and unweighted entries, a shorthand entry in a weighted list,
all-zero weights, and a provider listed twice are load errors. Each error
names the path `models.<name>.providers[<n>]`. The all-zero error names
`models.<name>.providers`.

A provider that its `outlier_detection` ejected gets no first picks. The next
entry in list order that is not ejected takes its share. The provider serves
first picks again when the ejection ends. The proxy does not support
cost-aware selection.

For the fallback chain, the retry count, and `outlier_detection`, see
[Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/#weighted-selection-in-the-models-catalogue).

## Keep a session on one provider

A provider keeps a prompt cache for the conversations it serves. If each turn
of a conversation goes to a different provider, each provider sees only part
of the conversation, and its cache does not help. To send all turns of a
conversation to one provider, add `session_affinity` to a weighted model.

```yaml title="llmproxy.yaml (fragment)"
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  keys:
    - id: alice-laptop
      tenant: acme
      digest: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a
models:
  chat-default:
    providers:
      - { provider: openai, weight: 3 }
      - { provider: together, weight: 1 }
    session_affinity:
      header: x-session-affinity
      identity: key
```

The `digest` is a placeholder. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/) to make a real one.

The proxy hashes the session value with xxHash64. The hash, not a random
draw, picks the first provider, in proportion to the weights. The same value
reaches the same provider on every worker and every replica. This needs no
shared state, while the weights and the provider list do not change.

| Field | Type | Default | Description |
|---|---|---|---|
| `session_affinity.header` | string | none | Request header that holds the session key. The proxy checks it first. |
| `session_affinity.identity` | `key`, `user`, or `tenant` | none | Authenticated identity to use when the request has no `header`. Needs the `auth` block. |

Set at least one of the two fields.

- `header`: a request with this header is pinned by the header only. The proxy
  hashes the raw value and forwards the header upstream unchanged. If the
  request repeats the header, the proxy hashes all its values, sorted.
- `identity`: `key` is the virtual key that authenticated the request. `user`
  is the authenticated user. `tenant` is the tenant. All traffic of one
  identity goes to one provider. For a JWT without `subject_claim`, the key is
  the signing key, so use `user`.

A request with no session value gets the usual random draw. Each pick on such
a model adds 1 to `llmproxy_router_session_affinity_total`, with
`outcome="hashed"` or `outcome="unhashed"`. The session value is never a
metric label.

Affinity does not change failover. If the pinned provider is ejected, or the
tenant credentials cannot serve it, the session goes to the next provider in
the list. The session returns when the pinned provider recovers. The fallback
request carries only the fallback provider's credentials. The proxy charges
the provider that served the request.

A weight change that changes the sum of the weights moves most sessions to a
new provider once. To move only the sessions whose share changed, keep the sum
fixed, for example at 100. A caller that sets the header can choose which of
the model's providers it reaches. It cannot reach a provider that is not in
the model. If you do not want callers to choose, use `identity` and no
`header`.

These are the load errors for `session_affinity`:

| Cause | Path |
|---|---|
| The model has no `weight` on its providers. | `models.<name>.session_affinity` |
| Neither `header` nor `identity` is set. | `models.<name>.session_affinity` |
| `header` is not a valid header name. | `models.<name>.session_affinity.header` |
| `identity` is set and the file has no `auth` block. | `models.<name>.session_affinity.identity` |

A model with a single provider accepts `session_affinity`. It has no effect,
because every request already reaches that provider.

## Concurrency ceilings

Each provider has its own ceilings. They shed load before a provider is
overloaded. A request over the ceiling gets an immediate `503` with the header
`x-envoy-overloaded: true` and the response flag `UO`. The proxy does not retry
that request and does not send it to a fallback provider.

| Field | Type | Default | Description |
|---|---|---|---|
| `providers.<name>.circuit_breakers.max_requests` | integer, 1 or more | `1024` | Requests in flight to this provider. A streaming response counts until its last byte. |
| `providers.<name>.circuit_breakers.max_pending_requests` | integer, 1 or more | `1024` | Requests that wait for a connection when `max_connections` connections are open. |
| `providers.<name>.circuit_breakers.max_connections` | integer, 1 or more | `1024` | Open upstream connections to this provider. |

A value of 0 is a load error at `providers.<name>.circuit_breakers.<field>`.
The dialect has no field for the retry limit of a provider. See
[Providers overview](/docs/llm-proxy/providers/overview/) for details and a
full example.

## Limitations

- A provider has one endpoint: the host and port of its `base_url`. The
  dialect has no field to list more endpoints for one provider, so it has no
  setting to balance across endpoints.
- Weights apply to `models` entries only. A `routes` entry sends the request
  to its one provider and then to its fallbacks, in order.
- The weighted pick does not use load, latency, or cost. The proxy does not
  support cost-aware selection.
- The random split is not coordinated across replicas. Session affinity is
  the same on every replica as long as the weights and providers match.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

This section is for maintainers.

- Weighted selection across the providers of a `models` entry: `lower_model`
  and `check_model_weights` in `crates/proxy-simple-config/`. Tests are listed
  in
  [Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/#implementation-notes).
- Session affinity validation: `check_session_affinity` in
  `crates/proxy-simple-config/src/parse.rs`. Tests in
  `crates/proxy-simple-config/tests/session_affinity.rs`:
  `header_and_identity_lower_to_an_envoy_hash_policy`,
  `a_single_provider_alias_carries_no_hash_policy`, and
  `refused_shapes_name_their_path`. End-to-end tests in
  `testing/diffrig/tests/session_affinity_e2e.rs`:
  `one_session_reaches_one_provider_and_sessions_split_by_weight`,
  `ejecting_the_pinned_provider_moves_the_session_with_only_the_fallback_key`,
  `without_a_header_each_virtual_key_keeps_its_provider`, and
  `no_session_value_keeps_the_random_weighted_pick`.
- Circuit breakers: `lower_circuit_breakers` in
  `crates/proxy-simple-config/src/lower.rs`. Tests in
  `crates/proxy-simple-config/tests/circuit_breakers.rs`, and the shedding in
  `crates/proxy/tests/provider_circuit_breaker_e2e.rs`:
  `max_requests_sheds_the_third_concurrent_request_while_another_provider_serves`
  and `a_fallback_model_sheds_at_the_dialled_providers_ceiling`.
- The connection and pending limits: `ConnectPool::new_stream` in
  `crates/proxy-cluster/src/pool.rs` (test
  `max_connections_is_enforced_at_dial_and_released_on_drop`).
