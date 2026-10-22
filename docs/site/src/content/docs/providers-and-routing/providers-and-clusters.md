---
title: Providers and clusters
description: "Add an LLM provider, set its base URL and credential, and control upstream connections."
summary: How a configuration `provider` becomes an engine cluster, what
  identity (TLS, credentials, headers) travels with it, and how the `models`
  catalogue differs from `routes`.
lastUpdated: 2026-10-18
related:
  - configuration/configuration-file
  - providers-and-routing/failover-and-aggregates
  - providers-and-routing/load-balancing
  - providers-and-routing/timeouts-and-retries
---

# Providers and clusters

A `providers.<name>` entry names one upstream LLM API: its type, base URL,
and credential. Add a provider for each API that your routes send requests to.
The engine calls its routing unit a *cluster*. Every provider becomes exactly
one cluster, named `provider:<name>`. This page describes what that conversion
does, and what stays attached to the cluster and not to the route that picks it.

A minimal provider in the `llmproxy` dialect:

```yaml
version: 0
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "gpt-*"
    provider: openai
```

The name `openai` sets the provider type and the `base_url` default. For a
self-hosted server, set `type: openai-compatible` and a `base_url`. The field
list is in the
[Field reference](../../configuration/reference/#provider).

## One provider, one cluster, one endpoint

The proxy derives a cluster's address from `base_url`: a literal IP becomes a
`STATIC` cluster; a hostname becomes `LOGICAL_DNS`, looked up again every 5
seconds (this schema version has no field to change that; a bootstrap
configuration does, see [DNS re-resolution](#dns-re-resolution)). Either
way, a provider gets exactly one endpoint: the host and port parsed out of
`base_url`. There is no field for a second address behind one provider name.

That matters for load balancing: with one endpoint, the load-balancing policy
a cluster runs has nothing to choose between. See
[Load balancing](../../providers-and-routing/load-balancing/) for where a real
choice of endpoints and policy is reachable.

## DNS re-resolution

A hostname is looked up when its cluster is built and then again every 5
seconds for as long as the cluster exists, so a provider that moves to new
addresses is picked up without a restart or a reload.

- **Nothing changed:** nothing happens. The cluster keeps its current hosts
  and their health state.
- **Address rotation:** a provider's DNS often returns the same addresses in a
  different order on every query. The cluster holds one address and stays on it
  for as long as the answer still contains it, so rotating answers do not move
  traffic between addresses or force new TCP and TLS handshakes. It moves to
  the first address in the answer only when its own is gone.
- **A lookup fails:** the cluster keeps serving the addresses it last resolved
  and tries again after the same 5 seconds. The first failure is logged at
  `warn` level, then the 2nd, 4th, 8th and so on (not every retry), and the
  lookup that ends the outage is logged once at `info`.
- **The first lookup fails at startup:** the cluster starts with no hosts, so
  requests to it get a 503 and `/ready` waits for it, up to the 15-second
  initial fetch timeout. The first retry that succeeds fills the cluster in;
  no restart or reload is needed.

A bootstrap configuration can tune this on a `STRICT_DNS` or `LOGICAL_DNS`
cluster with the standard Envoy fields:

| Field | Default | Meaning |
|---|---|---|
| `dns_refresh_rate` | 5s | Time between lookups; must be above 1ms. |
| `dns_jitter` | none | Upper bound of a random delay added to every lookup wait. |
| `dns_failure_refresh_rate` | the refresh rate | Retry back-off after a failed lookup. `base_interval` is required; `max_interval` defaults to 10 times the base. Each consecutive failure doubles the wait, from the base up to the max, with jitter. |

Other things to know, because they differ from what a similar Envoy
configuration might lead you to expect:

- `STRICT_DNS` serves every address in the answer: new addresses join and
  vanished ones leave at the next lookup. `LOGICAL_DNS` serves one.
- The endpoints of one cluster are looked up together. If any hostname fails,
  the whole lookup counts as failed and the cluster keeps all the addresses it
  had.
- `respect_dns_ttl: true` is rejected at load, because the proxy's resolver does
  not report record TTLs. Setting any of the fields above on a `STATIC` or
  `EDS` cluster, where Envoy ignores them, is rejected too.
- There is no per-lookup timeout: a resolver that hangs delays that cluster's
  next refresh until the system resolver gives up.

`internal-docs/envoy-divergences.md` records each of these departures from
Envoy in detail.

## Provider types

| `type` | `base_url` default | Notes |
|---|---|---|
| `openai` | `https://api.openai.com` | Inferred automatically when the provider is named `openai`. |
| `anthropic` | `https://api.anthropic.com` | Inferred automatically when the provider is named `anthropic`. Gets a default `anthropic-version` header — see below. |
| `openai-compatible` | none (required) | The default for any other provider name — vLLM, Ollama, TGI, Together, Fireworks, DeepSeek, and most self-hosted servers. |
| `openrouter` | `https://openrouter.ai` | Inferred automatically when the provider is named `openrouter`. OpenAI-shaped. The cluster rewrites the path prefix `/v1` to `/api/v1`. |
| `azure-openai` | none (required) | Needs `deployment` and `api_version`. The cluster rewrites `/v1` to `/openai/deployments/<deployment>` and adds `api-version=<api_version>`. The key goes in the `api-key` header. |
| `vertex` | none (required) | Needs `project`, `location`, `publisher`, and one OAuth access token. The proxy sends `Authorization: Bearer <token>`. The dialect comes from a `models` entry. |
| `bedrock` | none (required) | Needs `region`, an access key ID, and a secret access key. The proxy signs each request with AWS SigV4. The dialect comes from a `models` entry. |

The fields for `azure-openai`, `vertex`, and `bedrock` are in
[Field reference](../../configuration/reference/#provider).
The proxy stores each one in the cluster's metadata, so the credential
follows the cluster, as the next section describes. Vertex and
Bedrock credentials are static values read at load time.

`base_url` is host-and-port only. A path prefix (Groq's API sits under
`/openai`) is a load error. There is no workaround
for that in this schema version.

## Credentials, TLS, and headers travel with the cluster

An API key, the Anthropic `anthropic-version` default, and every
`extra_headers` entry are resolved once per provider and attached to that
provider's cluster, never to the routes that target it. This is deliberate, and the reason is
failover: the moment a route can reach
more than one provider (see
[Failover and aggregates](../../providers-and-routing/failover-and-aggregates/)),
a credential attached to the *route* would follow the routing decision
instead of the connection — the primary provider's API key sent to the
fallback's endpoint, a real key disclosure to a third party. Attaching it to
the cluster means whichever member the proxy dials supplies its own
key, never a previous attempt's.

The auth header follows the provider's wire shape: `Authorization: Bearer
<key>` for OpenAI-shaped providers, `x-api-key: <key>` for Anthropic.
Headers apply in
this order — the auth header, then the `anthropic-version` default (skipped
if `extra_headers` already sets it, matched case-insensitively), then every
`extra_headers` entry — and each later entry overwrites an earlier header of
the same name rather than duplicating it, so `extra_headers` can deliberately
override the default `anthropic-version`.

Every header name and value is checked when the config loads. A value that
is not valid HTTP, such as a key file with a second line, fails at its own
path (`providers.<name>.api_key`, `providers.<name>.api_key_file`, or
`providers.<name>.extra_headers.<key>`), and the error does not show the
value. `extra_headers` cannot set `host`, which comes from `base_url`. It also
cannot set the provider's credential header when `api_key` or `api_key_file`
sets it, or for Vertex and Bedrock providers, whose credential replaces
`authorization`.

An `https://` `base_url` gets upstream TLS. The proxy checks the upstream's
certificate against the hostname (subject-alternative-name match). It verifies
the chain against `ca_file` if set, or against the platform trust store
otherwise. `ca_file` on a plaintext (`http://`) provider is ignored and
produces a load-time warning.

### Connection reuse

`protocol` sets how the proxy talks to the provider. The default is `http1`.
Most hosted providers support `http2`. Many local plaintext servers do not.

- **`http1`** reuses connections with no field to configure it. Each worker
  thread keeps up to 8 idle HTTP/1.1 connections per (cluster, address,
  protocol) key. A request that finds an idle connection reuses it and does
  not dial a new one. The proxy returns a connection to the idle pool only
  after its response body ends cleanly. A truncated body, a `Connection: close`
  response, or a full idle pool (8 connections) causes the proxy to drop the
  connection and not reuse it.
- **`http2`** multiplexes streams. Each worker thread keeps up to 4
  connections per (cluster, address, protocol) key. A request takes the
  connection with the fewest streams. The worker dials another connection when
  every open connection carries 100 streams or more, up to the limit of 4.

The idle cache belongs to each worker thread, so these limits apply for each
worker and not for the whole process. The cache key also includes the build of
the cluster, as described below.

### How a pooled connection ends

Three mechanisms end a pooled connection. None needs a request to trigger it.

- **The slot goes with the socket.** A pooled connection holds one slot of the
  cluster's `max_connections` budget, and an idle pooled connection holds its
  slot too. The slot returns when the socket closes: when the peer hangs up,
  on an error, or when the cache lets go. An h2 connection that the cache drops
  while streams still run on it keeps its slot until those streams end.
- **A sweep runs every 60 seconds.** Each worker sweeps its caches. The sweep
  closes connections that the peer already closed, and connections that have
  had no stream for 1 hour (Envoy's default upstream idle timeout; no
  field changes it, and strict mode rejects the Envoy field for it). It also removes
  cache keys that have no connection left. A connection can live up to 60
  seconds past the hour. The first dial of a cache starts its sweep.
- **A cluster rebuild gets new connections.** The cache key includes the build
  of the cluster. A reload that changes a cluster (for example its TLS
  settings or its protocol) builds it again, and the new build never reuses a
  connection from the old one. A reload that leaves the cluster unchanged
  keeps its warm connections.

### When DNS or EDS removes an endpoint

When a DNS refresh or an EDS update removes an address from a cluster, the next
sweep closes the pooled connections to that address. The sweep asks the live
cluster registry whether the address is still a host, so it does not wait for
the 1 hour idle timeout. This frees the `max_connections` slots for the new
addresses. For h1, the sweep closes idle connections. For h2, a stream that is
already running on a removed address finishes first, and then the connection
closes. See [DNS re-resolution](#dns-re-resolution) for how often the
addresses refresh.

If a dial or handshake to an h2 address fails, the cache removes the empty key
that the dial created. A dial that another request is waiting on keeps its key.

### Hop-by-hop headers

The proxy removes the headers that describe one connection, so a peer cannot
manage the other connection. It removes `connection`, `upgrade`,
`transfer-encoding`, `keep-alive`, and `proxy-connection`. It keeps `te` only
when the value is `trailers`. It does this on every request before the
filter chain, and on every response after it. An upstream `Connection: close`
does not reach the client. A client `Connection: close` does not reach the
provider, so it does not close a pooled connection. When the proxy closes a
downstream connection itself (for example during drain), it adds its own
`connection: close`. For an upgrade request the rules differ; see
[WebSocket and upgrades](../../providers-and-routing/websocket-and-upgrades/#hop-by-hop-headers-on-an-upgrade).

## Concurrency ceilings

Each provider has a ceiling on the requests it has in flight at one time. The
default is 1024 requests. A streaming response counts until its last byte, so
1024 long streams fill the ceiling. The next request to that provider gets an
immediate `503` with the header `x-envoy-overloaded: true`. The proxy does not
queue it and does not send it to a fallback provider.

To raise or lower the ceiling, set `circuit_breakers` on the provider:

```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    circuit_breakers:
      max_requests: 4096
```

| Field | Default | Meaning |
|---|---|---|
| `max_requests` | 1024 | Requests in flight to this provider at the same time. |
| `max_pending_requests` | 1024 | Requests that wait for a connection when `max_connections` connections are open. A request over this value gets the same `503`. |
| `max_connections` | 1024 | Open upstream connections to this provider. |

- Each value must be 1 or more. A value of 0 is a load error.
- The ceiling belongs to the provider, not to a route or a model. Every route
  and model that sends requests to the provider shares it. On a failover chain,
  each provider applies its own ceiling when the proxy sends a request to it.
- Each replica of the proxy applies its own ceiling. With N replicas behind a
  load balancer, the provider can get up to N times the value.
- An `http1` provider needs one connection for each request in flight. When
  you raise `max_requests` for it, raise `max_connections` too.

The access log shows a shed request with the response flag `UO`.

## `routes` vs. the `models` catalogue

Both a `routes` entry and a `models.<name>` entry produce a route in the
lowered configuration, matched against the client's `model` field. `models`
entries are evaluated after the explicit `routes` list and before the 404
backstop.

The two surfaces are not equivalent. `models.<name>` has no `retries`,
`idle_timeout`, or `streaming` field. The schema's `ModelDef` carries only
`providers` and `max_output_tokens`. Providers after the first are fallbacks,
in order: the route retries `count - 1` times, and every provider must speak
the same wire dialect as the first. The
idle timeout is always `90s`. A `routes` entry lets you set the retry count,
the idle timeout, and `streaming`. See
[Configuration file reference](../../configuration/configuration-file/) for the
full field list of both surfaces.

## Bootstrap configuration

The concept is the same in a bootstrap configuration — a `Cluster` resource
under `static_resources.clusters` — except you write it directly, and you are
not limited to one endpoint: `load_assignment.endpoints` can list several,
weighted and prioritized (see
[Load balancing](../../providers-and-routing/load-balancing/)). There is also no
standard `Cluster` field for a per-provider credential header the way
this configuration format's `api_key`/`extra_headers` are. A route's own
`request_headers_to_add` works for a route that only ever reaches one
cluster, but it carries exactly the key-disclosure risk described above the
moment that cluster is (or becomes) an `envoy.clusters.aggregate` with
heterogeneous members — the aggregate cluster mechanism has no per-member
credential mechanism of its own. That gap is the reason this configuration
format exists as its own front end rather than asking every user to write
a raw bootstrap configuration for LLM provider fallback.

## Implementation notes

This section is for maintainers.

- Provider lowering: `lower_provider`, `auth_header`, and `lower_model` in
  `crates/proxy-simple-config/src/lower.rs`. The cluster header list is
  `ClusterConfig::request_headers_to_add` in `crates/proxy-config/src/ir.rs`.
- Connection cache: `H1ConnCache`, `H1ReuseBody`, `MAX_IDLE_PER_KEY` (8),
  `MAX_CONNECTIONS_PER_KEY` (4), `SOFT_STREAMS_PER_CONNECTION` (100), and the
  per-worker `thread_local` `WORKER_H1_CONN_CACHE` in
  `crates/proxy-http/src/upstream_pool.rs`. `ConnKey` holds the cluster name,
  address, protocol, and cluster build ID. Tests in the same file:
  `an_idle_connection_closed_by_its_peer_gives_its_slot_back`,
  `evicting_an_h2_connection_keeps_its_slot_until_the_stream_on_it_ends`,
  `the_sweep_retires_a_key_whose_endpoint_is_gone`,
  `h1_removed_endpoints_idle_connection_is_closed_at_the_next_sweep`,
  `h2_removed_endpoints_idle_connection_is_closed_at_the_next_sweep`,
  `a_removed_endpoints_h2_stream_in_flight_finishes_before_the_connection_closes`,
  and `a_failed_dial_removes_its_slot_but_not_one_another_checkout_is_waiting_on`.
- Reuse tests in the `crates/proxy-http/src/router.rs` test module:
  `reuse_across_two_requests_opens_one_connection` and
  `connection_close_response_is_not_reused`. Reload test:
  `connection_reuse_follows_the_cluster_build_across_reloads` in
  `crates/proxy-http/tests/router_cluster_rebuild.rs`.
- Endpoint removal: `has_host_follows_an_eds_replacement` in
  `crates/proxy-cluster/src/manager.rs`. The binary installs the membership
  check per worker with `set_worker_membership` in `crates/proxy/src/main.rs`.
- Hop-by-hop headers: `sanitize_hop_by_hop` in
  `crates/proxy-http/src/headers.rs`, called by `serve_one` in
  `crates/proxy-http/src/codec.rs`. Tests that run the real binary:
  `a_downstream_keepalive_connection_survives_an_upstream_connection_close`
  and `client_connection_management_headers_do_not_reach_the_upstream` in
  `crates/proxy/tests/hop_by_hop_e2e.rs`.
