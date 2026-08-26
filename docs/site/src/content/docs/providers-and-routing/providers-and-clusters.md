---
title: Providers and clusters
summary: How a configuration `provider` becomes an engine cluster, what
  identity (TLS, credentials, headers) travels with it, and how the `models`
  catalogue differs from `routes`.
last_updated: 2026-08-26
related:
  - ../configuration/configuration-file/
  - ../providers-and-routing/failover-and-aggregates/
  - ../providers-and-routing/load-balancing/
  - ../providers-and-routing/timeouts-and-retries/
---

# Providers and clusters

A `providers.<name>` entry in the configuration names one upstream LLM API.
Internally the engine calls its routing unit a *cluster* — every provider
becomes exactly one cluster, named `provider:<name>`
(`crates/proxy-simple-config/src/lower.rs`'s `lower_provider`). This page
describes what that conversion does, and what stays attached to the cluster
rather than the route that picks it.

## One provider, one cluster, one endpoint

Lowering derives a cluster's address from `base_url`: a literal IP becomes a
`STATIC` cluster; a hostname becomes `LOGICAL_DNS`, re-resolved on a fixed
5-second cadence that this schema version has no field to change
(`crates/proxy-cluster/src/discovery.rs`'s `DEFAULT_DNS_REFRESH_RATE`). Either
way, a provider gets exactly one endpoint: the host and port parsed out of
`base_url`. There is no field for a second address behind one provider name.

That matters for load balancing: with one endpoint, the load-balancing policy
a cluster runs has nothing to choose between. See
[Load balancing](../providers-and-routing/load-balancing/) for where a real
choice of endpoints and policy is actually reachable.

## Provider types

| `type` | `base_url` default | Notes |
|---|---|---|
| `openai` | `https://api.openai.com` | Inferred automatically when the provider is named `openai`. |
| `anthropic` | `https://api.anthropic.com` | Inferred automatically when the provider is named `anthropic`. Gets a default `anthropic-version` header — see below. |
| `openai-compatible` | none (required) | The default for any other provider name — vLLM, Ollama, TGI, Together, Fireworks, DeepSeek, and most self-hosted servers. |
| `azure-openai`, `vertex`, `bedrock` | — | Named in the schema's `models` catalogue but **not loadable as a `providers` entry**. Each needs a credential scheme (deployment-name URL templating, minted OAuth2, or per-request SigV4 signing) that is not implemented. Configuring one is a load error naming the gap, not a silent 401 at request time (`crates/proxy-simple-config/src/lower.rs`'s `unsupported_credential_scheme`). |

`base_url` is host-and-port only. A path prefix (Groq's API sits under
`/openai`) is a load error, not a silent truncation — there is no workaround
for that in this schema version.

## Credentials, TLS, and headers travel with the cluster

An API key, the Anthropic `anthropic-version` default, and every
`extra_headers` entry are resolved once per provider and attached to that
provider's cluster, never to the routes that target it
(`ClusterConfig::request_headers_to_add` in `crates/proxy-config/src/ir.rs`).
This is deliberate, and the reason is failover: the moment a route can reach
more than one provider (see
[Failover and aggregates](../providers-and-routing/failover-and-aggregates/)),
a credential attached to the *route* would follow the routing decision
instead of the connection — the primary provider's API key sent to the
fallback's endpoint, a real key disclosure to a third party. Attaching it to
the cluster means whichever member actually gets dialed supplies its own
key, never a previous attempt's.

The auth header follows the provider's wire shape: `Authorization: Bearer
<key>` for OpenAI-shaped providers, `x-api-key: <key>` for Anthropic
(`crates/proxy-simple-config/src/lower.rs`'s `auth_header`). Headers apply in
this order — the auth header, then the `anthropic-version` default (skipped
if `extra_headers` already sets it, matched case-insensitively), then every
`extra_headers` entry — and each later entry overwrites an earlier header of
the same name rather than duplicating it, so `extra_headers` can deliberately
override the default `anthropic-version`.

An `https://` `base_url` gets upstream TLS, with the upstream's certificate
checked against a subject-alternative-name match on its hostname, verified
against `ca_file` if set or the platform trust store otherwise
(`crates/proxy-simple-config/src/lower.rs`'s `lower_provider`). `ca_file` on a
plaintext (`http://`) provider is ignored and produces a load-time warning.
`protocol: http2` (default `http1`) reuses one multiplexed connection per
worker to that provider instead of connecting fresh on every request; most
hosted providers support it, many local plaintext servers do not.

`http1` reuses connections too, automatically, with no field to configure it.
Each worker keeps up to 8 idle keep-alive connections per (cluster, address);
a request that finds one reuses it instead of dialing fresh, and a
connection is only ever returned to that idle pool once its current response
body has reached a clean, error-free end of stream — a truncated body, a
`Connection: close` response, or a full idle pool all cause the connection to
be dropped rather than reused (`H1ConnCache`/`H1ReuseBody` in
`crates/proxy-http/src/upstream_pool.rs`; proven end to end by
`reuse_across_two_requests_opens_one_connection` and
`connection_close_response_is_not_reused` in
`crates/proxy-http/src/router.rs`'s test module).

## `routes` vs. the `models` catalogue

Both a `routes` entry and a `models.<name>` entry produce a route in the
lowered configuration, matched against the client's `model` field. `models`
entries are evaluated after the explicit `routes` list and before the 404
backstop.

The two surfaces are not equivalent. `models.<name>` has no `fallbacks`,
`retries`, or `idle_timeout` fields at all — the schema's `ModelDef` carries
only `providers`, and only `providers[0]` is ever used to serve traffic in
this schema version. Every later entry still validates at load time (a bad
one still fails to load) but produces a load-time warning naming its exact
path instead of being selected. Failover, per-route retries, and a per-route
idle timeout are only reachable through `routes`. See
[Configuration file reference](../configuration/configuration-file/) for the
full field list of both surfaces.

## Bootstrap configuration

The concept is the same in a bootstrap configuration — a `Cluster` resource
under `static_resources.clusters` — except you write it directly, and you are
not limited to one endpoint: `load_assignment.endpoints` can list several,
weighted and prioritized (see
[Load balancing](../providers-and-routing/load-balancing/)). There is also no
standard `Cluster` field for a per-provider credential header the way
this configuration format's `api_key`/`extra_headers` are. A route's own
`request_headers_to_add` works for a route that only ever reaches one
cluster, but it carries exactly the key-disclosure risk described above the
moment that cluster is (or becomes) an `envoy.clusters.aggregate` with
heterogeneous members — the aggregate cluster mechanism has no per-member
credential mechanism of its own. That gap is the reason this configuration
format exists as its own front end rather than asking every user to write
a raw bootstrap configuration for LLM provider fallback.
