---
title: Provider overview
description: The seven provider types, how each one authenticates, which fields each one needs, and how a provider keeps its credential, connections, and concurrency ceilings.
summary: A matrix of the seven provider types, the fields common to all of
  them, and the rules for credentials, base URLs, DNS, connection reuse, and
  concurrency ceilings.
lastUpdated: 2026-10-21
related:
  - providers/openai
  - providers/anthropic
  - providers/openrouter
  - providers/azure-openai
  - providers/vertex-ai
  - providers/amazon-bedrock
  - providers/openai-compatible
  - providers-and-routing/failover-and-aggregates
  - configuration/models-and-routes
---

A provider is one upstream LLM API. You declare it under `providers` in the
`llmproxy` configuration file. Each provider has a type, a base URL, and a
credential. The proxy forwards the request body as the client sent it. It does
not translate between API formats. A client that sends an OpenAI request
reaches an OpenAI-shaped provider. A client that sends an Anthropic request
reaches an Anthropic-shaped provider.

## At a glance

- **Default type:** a provider named `openai`, `anthropic`, or `openrouter`
  gets that type. Any other name gets `openai-compatible`.
- **Default `base_url`:** set for `openai`, `anthropic`, and `openrouter` only.
  The other four types need an explicit `base_url`.
- **Failure mode:** an invalid provider block fails at load with the full
  dotted field path. The proxy does not start with a partial provider.
- **Missing credential:** a provider with no `api_key` loads. The proxy then
  adds no auth header, and the provider rejects the request. This is the
  intended shape for a local server.

## Minimal example

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
  local-vllm:
    base_url: http://vllm.internal:8000

routes:
  - model: gpt-*
    provider: openai
  - model: claude-*
    provider: anthropic
  - model: "*"
    provider: local-vllm
```

Check the file with `llm-proxy --config llmproxy.yaml --mode validate`.
Set the two environment variables first. The load fails if a `${VAR}`
reference names an unset variable.

## Provider types

| Type | Auth the proxy adds | Dialect | Required fields | Default `base_url` | Path rewrite |
|---|---|---|---|---|---|
| `openai` | `Authorization: Bearer <api_key>` | openai | none | `https://api.openai.com` | none |
| `anthropic` | `x-api-key: <api_key>`, plus `anthropic-version: 2023-06-01` | anthropic | none | `https://api.anthropic.com` | none |
| `openai-compatible` | `Authorization: Bearer <api_key>`, only if a key is set | openai | `base_url` | none | none |
| `openrouter` | `Authorization: Bearer <api_key>` | openai | none | `https://openrouter.ai` | `/v1` becomes `/api/v1` |
| `azure-openai` | `api-key: <api_key>` | openai | `base_url`, `deployment`, `api_version` | none | `/v1` becomes `/openai/deployments/<deployment>`; the query becomes `api-version=<api_version>` |
| `vertex` | `Authorization: Bearer <token>` | `openai` or `anthropic`, set on each `models` entry | `base_url`, `project`, `location`, `publisher`, one token source | none | the whole path becomes `/v1/projects/<project>/locations/<location>/publishers/<publisher>/models/<model>:streamRawPredict` |
| `bedrock` | AWS SigV4 signature, service name `bedrock` | `openai` or `anthropic`, set on each `models` entry | `base_url`, `region`, an access key ID, a secret access key | none | the whole path becomes `/model/<model>/invoke` |

The proxy infers the type from the name only for `openai`, `anthropic`, and
`openrouter`. Any other name gets `openai-compatible`. Set `type` for
`azure-openai`, `vertex`, `bedrock`, and for a name like `openai` that does
not match the server. The pages in the next list describe each type:

- [OpenAI](/docs/llm-proxy/providers/openai/)
- [Anthropic](/docs/llm-proxy/providers/anthropic/)
- [OpenRouter](/docs/llm-proxy/providers/openrouter/)
- [Azure OpenAI](/docs/llm-proxy/providers/azure-openai/)
- [Vertex AI](/docs/llm-proxy/providers/vertex-ai/)
- [Amazon Bedrock](/docs/llm-proxy/providers/amazon-bedrock/)
- [OpenAI-compatible](/docs/llm-proxy/providers/openai-compatible/)

`base_url` takes a scheme, a host, and an optional port. A path prefix is a
load error:

```text
invalid value at `providers.<name>.base_url`: `https://api.groq.com/openai` has a path prefix; v0 does not support base_url paths
```

A provider that nests its API under a path prefix cannot be configured. Groq
is one example.

## Fields common to all types

The generated [field reference](/docs/llm-proxy/configuration/reference/)
lists every field. Defaults come from `schema/llmproxy-v1.schema.json`
(`Provider`).

| Field | Type | Default | Description |
|---|---|---|---|
| `type` | enum | inferred from the name | One of the seven types above. |
| `base_url` | URI | implied by the type, if any | Scheme, host, and optional port. No path. |
| `api_key` | string | none | Key sent in the native auth header of the type. Not valid for `vertex` and `bedrock`. |
| `api_key_file` | string | none | File that holds the key. Set `api_key` or `api_key_file`, not both. |
| `extra_headers` | map | empty | Headers added to every request to this provider. |
| `ca_file` | string | system roots | PEM bundle that verifies the TLS certificate of the provider. Ignored, with a warning, for `http://` URLs. |
| `connect_timeout` | duration | `5s` | Connection setup timeout, TCP and TLS. |
| `protocol` | `http1` or `http2` | `http1` | HTTP version used toward the provider. |
| `circuit_breakers` | object | see [Concurrency ceilings](#concurrency-ceilings) | Ceilings on requests and connections. |
| `unanswered_usage` | `none`, `input`, `output_cap` | `input` | What a request is charged when this provider got the whole request and sent no response. See [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/#requests-that-get-no-response). |
| `outlier_detection` | object | absent: never ejected | Passes over a provider after repeated failures. See [Failover](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/). |
| `request_fields` | object | none | Lists of top-level body keys to refuse (`deny`) or remove (`strip`) for this provider. |
| `tenant_credentials` | boolean | `false` | Let a tenant send its own key for this provider. See [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/). |

A name in `request_fields.deny` makes the request fail with `400` and the
body `request field not permitted: <field>`. The rule runs
on every attempt, against the provider that the proxy dials. It holds on
failover.

## Credentials, TLS, and headers travel with the provider

The proxy attaches the API key, the `Host` header, and every `extra_headers`
entry to the provider. It never attaches them to the route. This is
deliberate. A route can fail over to another provider. A key on the route
would then reach the fallback endpoint, and that is a key disclosure to a third
party. With the credential on the provider, each provider that the proxy dials
sends only its own key and its own `Host`. The proxy applies provider headers
after route changes, so the selected provider wins if two headers collide.

The auth header follows the type: `Authorization: Bearer <key>` for
OpenAI-shaped providers, `x-api-key: <key>` for `anthropic`, and `api-key: <key>`
for `azure-openai`. The proxy applies headers in this order:

1. The auth header.
2. The `anthropic-version` default, for an `anthropic` provider. The proxy
   skips it if `extra_headers` already sets it. The match ignores case.
3. Every `extra_headers` entry.

A later header replaces an earlier header of the same name. A header from the
client with the same name is replaced too.

The proxy checks every header name and value when the config loads. A value
that is not valid HTTP, such as a key file with a second line, fails at its own
path (`providers.<name>.api_key`, `providers.<name>.api_key_file`, or
`providers.<name>.extra_headers.<key>`). The error does not show the value.
`extra_headers` cannot set `host`, because `host` comes from `base_url`. It
also cannot set the provider's auth header when `api_key` or `api_key_file`
sets it. For Vertex and Bedrock providers, it cannot set `authorization`,
because their credential replaces that header.

An `https://` `base_url` gets upstream TLS. The proxy checks the certificate
chain and the host name. It verifies the chain against `ca_file` if you set
one, and against the platform trust store otherwise. A
`ca_file` on an `http://` provider has no effect. The check prints this
warning on stderr:

```text
warning: `providers.<name>.ca_file`: ca_file is ignored for plaintext (http://) providers
```

### Read secrets from the environment or a file

1. Write `${ENV_VAR}` in a value to read an environment variable. An unset
   variable fails the load with ``environment variable `NAME` is not set``.
   Write `$${` for a literal `${`.
2. Use `api_key_file` for a mounted secret. The proxy trims trailing
   whitespace. It reads the file at startup and again on each `SIGHUP`
   reload. Requests that start after the reload use the new key.

The check prints this warning on stderr for each credential file:

```text
warning: `providers.<name>.api_key_file`: the key file is read at startup and again on each SIGHUP reload; to rotate it, replace the file and reload
```

Nothing watches the file. See
[Managing secrets](/docs/llm-proxy/authentication/managing-secrets/).

## Dialects and usage metering

The dialect is the wire format of a request and its response. The usage
filter reads token counts from the response in that format, for streamed
responses too. The proxy supports two dialects: `openai` and `anthropic`.

- The `anthropic` type uses the `anthropic` dialect. The five other
  OpenAI-shaped types use the `openai` dialect.
- `vertex` and `bedrock` serve more than one wire format. Each `models` entry
  for them must set `dialect` in the object form. A missing `dialect` is a
  load error.
- An explicit `dialect` on a `models` entry wins over the type. A provider cannot have two dialects. If two entries
  disagree, the load fails.
- A streaming `openai` request that has no `stream_options` gets
  `stream_options.include_usage = true` added. The setting
  `observability.force_usage_reporting` controls this. It is on by default.
  The proxy does not add it on the Responses and Messages paths, and it never
  adds it to an `anthropic` provider.
- Every provider in a failover chain must use the same dialect. A chain that
  crosses dialects fails the load. See
  [Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

## One provider, one endpoint

Every provider has exactly one endpoint: the host and port in `base_url`. A
literal IP address is used as is. A host name is looked up in DNS. There is no
field for a second address behind one provider name. To spread requests across
several servers, put a load balancer behind the `base_url`. To spread requests
across providers, use `weight` in a `models` entry. See
[Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/).

### DNS re-resolution

The proxy looks up a host name when it builds the provider. It then looks it up
again every 5 seconds for as long as the provider exists. A provider that moves
to new addresses is picked up without a restart or a reload. No field changes
the 5-second interval.

- **Nothing changed:** nothing happens. The provider keeps its current
  address and its health state.
- **Address rotation:** the DNS of a provider often returns the same addresses
  in a different order on every query. The proxy holds one address and stays on
  it while the answer still contains it. Rotating answers do not move traffic
  between addresses. They do not force new TCP and TLS handshakes. The proxy
  moves to the first address in the answer only when its own address is gone.
- **A lookup fails:** the proxy keeps serving the addresses it last resolved.
  It tries again after the same 5 seconds. It logs the first failure at `warn`
  level, then the 2nd, 4th, 8th, and so on. It logs the lookup that ends the
  outage once at `info` level.
- **The first lookup fails at startup:** the provider starts with no
  addresses. Requests to it get a `503`, and `/ready` waits for it, up to the
  15-second initial fetch timeout. The first retry that succeeds fills the
  provider in. No restart or reload is needed.

## Connection reuse

`protocol` sets how the proxy talks to the provider. The default is `http1`.
Most hosted providers support `http2`. Many local plaintext servers do not.

- **`http1`** reuses connections. No field configures it. Each worker thread
  keeps up to 8 idle HTTP/1.1 connections for each provider address. A request
  that finds an idle connection reuses it. The proxy returns a connection to
  the idle pool only after its response body ends cleanly. A truncated body, a
  `Connection: close` response, or a full idle pool makes the proxy drop the
  connection.
- **`http2`** multiplexes streams. Each worker thread keeps up to 4
  connections for each provider address. A request takes the connection with
  the fewest streams. The worker dials another connection when every open
  connection carries 100 streams or more, up to the limit of 4.

The idle cache belongs to each worker thread. These limits apply to each
worker and not to the whole process.

### How a pooled connection ends

Three mechanisms end a pooled connection. None needs a request to trigger it.

- **The slot goes with the socket.** A pooled connection holds one slot of the
  `max_connections` budget of the provider. An idle pooled connection holds its
  slot too. The slot returns when the socket closes: when the peer hangs up, on
  an error, or when the cache lets go. An `http2` connection that the cache
  drops while streams still run on it keeps its slot until those streams end.
- **A sweep runs every 60 seconds.** Each worker sweeps its caches. The sweep
  closes connections that the peer already closed. It closes connections that
  had no stream for 1 hour. No field changes this idle limit. The sweep also
  closes connections to an address that DNS no longer returns, so it does not
  wait for the 1-hour limit. A connection can live up to 60 seconds past the
  hour.
- **A reload that changes a provider gets new connections.** A reload that
  changes a provider, for example its TLS settings or its protocol, builds the
  provider again. The new build never reuses a connection from the old one. A
  reload that leaves the provider unchanged keeps its warm connections.

### Hop-by-hop headers

The proxy removes the headers that describe one connection, so a peer cannot
manage the other connection. It removes `connection`, `upgrade`,
`transfer-encoding`, `keep-alive`, and `proxy-connection`. It keeps `te` only
when the value is `trailers`. It does this on every request before the filter
chain, and on every response after it. An upstream `Connection: close` does not
reach the client. A client `Connection: close` does not reach the provider, so
it does not close a pooled connection. When the proxy closes a client
connection itself, for example during drain, it adds its own
`connection: close`. An upgrade request follows other rules. See
[Realtime](/docs/llm-proxy/api-compatibility/realtime/).

## Concurrency ceilings

Each provider has a ceiling on the requests it has in flight at one time. The
default is 1024 requests. A streaming response counts until its last byte, so
1024 long streams fill the ceiling. The next request to that provider gets an
immediate `503` with the body `upstream overloaded` and the header
`x-envoy-overloaded: true`. The proxy does not queue the
request. It does not send it to a fallback provider.

To raise or lower the ceiling, set `circuit_breakers` on the provider:

```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
    circuit_breakers:
      max_requests: 4096
```

| Field | Default | Description |
|---|---|---|
| `max_requests` | 1024 | Requests in flight to this provider at the same time. |
| `max_pending_requests` | 1024 | Requests that wait for a connection when `max_connections` connections are open. A request over this value gets the same `503`. |
| `max_connections` | 1024 | Open upstream connections to this provider. |

- Each value must be 1 or more. A value of 0 is a load error. A field that you leave unset keeps its default.
- The ceiling belongs to the provider, not to a route or a model. Every route
  and model that sends requests to the provider shares it. On a failover chain,
  each provider applies its own ceiling when the proxy sends a request to it.
- Each replica of the proxy applies its own ceiling. With N replicas behind a
  load balancer, the provider can get up to N times the value.
- An `http1` provider needs one connection for each request in flight. When you
  raise `max_requests` for it, raise `max_connections` too.

The access log shows a shed request with the response flag `UO`.

## `routes` and the `models` catalogue

Both a `routes` entry and a `models.<name>` entry match the `model` field of
the client request. The proxy tries the `routes` list first, in order. It then
tries the `models` entries. If nothing matches, the client gets a `404`.

The two surfaces are not equal. A `routes` entry can set `retries`,
`idle_timeout`, and `streaming`. A `models` entry cannot: its idle timeout is
always `90s`. A `models` entry can set `weight`,
`dialect`, and a different upstream `model` for each provider. See
[Models and routes](/docs/llm-proxy/configuration/models-and-routes/).

## Limitations

- The proxy forwards the body. It does not convert OpenAI requests into
  Anthropic, Gemini-native, or Bedrock Converse requests.
- A provider has one endpoint, and `base_url` cannot carry a path.
- Credentials for `bedrock` are static values from the configuration. The proxy
  does not read the AWS credential chain.
- Balancing across the endpoints of one provider is not available. Use a load
  balancer in front of the provider.
- See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

This section is for maintainers.

- Provider lowering: `lower_provider`, `auth_header`, and `lower_model` in
  `crates/proxy-simple-config/src/lower.rs`. The provider header list is
  `ClusterConfig::request_headers_to_add` in `crates/proxy-config/src/ir.rs`.
  The engine calls its routing unit a cluster. Every provider becomes one
  cluster named `provider:<name>`.
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
- Hop-by-hop headers: `sanitize_hop_by_hop` in
  `crates/proxy-http/src/headers.rs`, called by `serve_one` in
  `crates/proxy-http/src/codec.rs`. Tests that run the real binary:
  `a_downstream_keepalive_connection_survives_an_upstream_connection_close`
  and `client_connection_management_headers_do_not_reach_the_upstream` in
  `crates/proxy/tests/hop_by_hop_e2e.rs`.
