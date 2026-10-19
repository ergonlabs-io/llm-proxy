---
title: API compatibility
description: "Which provider APIs llm-proxy forwards, what it changes in a request, how it meters each endpoint, and what it does not do."
summary: Reference for the passthrough model, the supported API families,
  endpoints the proxy answers itself, streaming, credentials, model names, and
  limitations.
lastUpdated: 2026-10-18
related:
  - getting-started/connect-your-application
  - providers-and-routing/providers-and-clusters
  - authentication/virtual-keys
  - providers-and-routing/auto-model
  - limits-and-budgets/token-rate-limiting
---

# API compatibility

llm-proxy forwards requests to a provider. It does not translate them. A client
that speaks a provider's API keeps speaking that API through the proxy. For
client setup, see [Connect your application](../../getting-started/connect-your-application/).

## Passthrough model

- The proxy does not convert OpenAI requests to Anthropic requests, or the
  reverse.
- A request must reach a provider that speaks the same dialect as the request.
- A failover chain must hold providers of one dialect. A chain that mixes
  dialects is a load error.
- The proxy sends the client path to the provider unchanged, except for the
  rewrites in [Per-provider path rewrites](#per-provider-path-rewrites).
- A provider `base_url` cannot contain a path.

## Supported API families

The proxy meters these endpoints. Metering means the proxy reads the token
usage in the response and applies token limits, spend budgets, and the usage
record.

| Family | Method and path | Notes |
| --- | --- | --- |
| OpenAI Chat Completions | `POST .../chat/completions` | Metered. Streaming usage is forced on (see [Streaming](#streaming)). |
| OpenAI Completions | `POST .../completions` | Metered. |
| OpenAI Responses | `POST .../responses` | Metered. The proxy does not add `stream_options`. |
| OpenAI Embeddings | `POST .../embeddings` | Metered. |
| Anthropic Messages | `POST .../messages` | Metered. The proxy does not add `stream_options`. |

The proxy recognizes `POST .../messages/count_tokens` and treats it as free. It
recognizes image and audio endpoints, but it does not meter them.

## Endpoints the proxy answers

| Request | Behavior |
| --- | --- |
| `GET /v1/models` | The proxy answers. It never forwards the request. The list holds the catalogue: every `routes[].model` and `models:` key except `*` and `auto`. With model policy on, it lists only models the caller may use. When the catalogue is empty, the request gets `403 forbidden`. |
| `GET /v1/usage` | The proxy answers through the token-limit filter. It returns `401 unauthorized` without a tenant and `503 usage unavailable` if the store fails. |

The model list uses the OpenAI list shape. Each entry has `id`, `object:
"model"`, `created: 0`, and `owned_by: "llm-proxy"`.

## Other paths

The proxy forwards every other path to the provider the model selects. This
includes files, batches, images, and audio. The proxy does not meter these
paths. Two controls change what happens:

- **Budget or limit.** If a spend budget or token limit applies to the caller,
  the proxy refuses an unmetered path with `403` and the body `this endpoint
  cannot be metered, so it is refused under a spend budget or token limit`.
  Without a budget or limit, the proxy forwards the request.
- **Object ownership.** With authentication on, the proxy records which tenant
  owns each file or batch. A request for another tenant's object, or for an
  unknown ID, gets `404` with `{"error":{"message":"object not found"}}`.
  Listing a collection, such as `GET /v1/files`, also gets `404`.

A request with no JSON `model`, such as a `GET` or a multipart upload, gets
`403 forbidden` when model policy is on. This holds even if
`tenants_without_policy` is `allow`.

## Request bodies

The proxy buffers the whole request body. The limit is
`listen.max_request_body_bytes`. The default is 1048576 bytes (1 MiB). A larger
body gets `413` with the text `request body exceeds buffer limit`. The same
value is the largest body the proxy can retry or fail over. Each in-flight
request can hold that many bytes in memory. The proxy does not buffer
responses.

## Streaming

The proxy passes server-sent events (SSE) through as they arrive. It does not
buffer a streamed response.

`observability.force_usage_reporting` defaults to `true`. With it on, the proxy
sets `stream_options.include_usage` to `true` on a streaming request in the
OpenAI dialect, even when the client sent `false`. The provider then sends one
extra final chunk. That chunk has an empty `choices` list and a `usage` object.
Standard SDKs handle it. A client that reads `choices[0]` without a check fails
on that chunk.

The proxy does not add the option to Responses or Messages requests. Those
APIs report usage on every stream.

To pass the request through unchanged, set `observability.force_usage_reporting`
to `false`. Then the provider reports usage only if the client asks for it.

```yaml
observability:
  force_usage_reporting: false
```

## Credentials

Two kinds of key exist. They never travel together.

| Key | Set by | Header the proxy reads or sends |
| --- | --- | --- |
| Virtual key (`llmp_...`) | The client | The proxy reads `Authorization: Bearer llmp_...` only. It never reads `x-api-key`. |
| Provider key | The provider config | The proxy sends it: `x-api-key` for `anthropic`, `api-key` for `azure-openai`, `Authorization: Bearer` for other types. |

After authentication, the proxy removes the inbound `Authorization` header. The
virtual key never reaches any provider. The provider key comes from the
cluster, so the provider the proxy selects decides which key it sends. See
[Virtual keys](../../authentication/virtual-keys/).

## Model names

- The proxy routes on the JSON `model` field. It matches `routes:` in order,
  then `models:` keys: exact, then longest prefix, then `*`.
- A `models:` entry written as `provider/model` rewrites the model in the
  request body sent to the provider. The response is not rewritten. It shows
  the provider's model name.
- A `provider/model` value in `routes[].provider` does not rewrite the model.
  The loader warns.
- `auto` resolves for each tenant. If no rule exists, the proxy returns `400`
  with `no model is configured for` `` `auto` ``. See
  [The auto model](../../providers-and-routing/auto-model/).
- If no rule matches and there is no `*` rule, the proxy returns `404` with the
  type `model_not_found`.

## Preserved and changed fields

| Item | What the proxy does |
| --- | --- |
| Request body | Forwards it unchanged, except for the `model` rewrite and the `stream_options` injection above. |
| `model` | Rewrites it if a `models:` entry maps it. |
| `Authorization` | Removes the virtual key and adds the provider credential. |
| `anthropic-version` | Adds it for `anthropic` providers if the config does not set it. |
| `x-llmproxy-model` | Sets it from the body `model` for routing. It removes any value the client sent. |
| Response body | Passes it through unchanged. |

## Per-provider path rewrites

| Provider type | Client path | Path sent to the provider |
| --- | --- | --- |
| `openrouter` | `/v1/...` | `/api/v1/...` |
| `azure-openai` | `/v1/...` | `/openai/deployments/{deployment}/...` with `?api-version={api_version}` |
| `vertex` | any | `/v1/projects/{project}/locations/{location}/publishers/{publisher}/models/{model}:streamRawPredict` |
| `bedrock` | any | `/model/{model}/invoke` |

For `vertex` and `bedrock`, `{model}` is the upstream model from the
`models:` mapping. If no mapping matches, it is the requested model. The proxy
keeps the client query string.

## Limitations

- No translation between OpenAI and Anthropic formats.
- No CORS support. Browser clients cannot call the proxy.
- Image and audio endpoints are not metered, so a budget or limit refuses them.
- Files and batches are forwarded only when no budget or limit applies, and
  only for the tenant that owns the object.
- The listener caps the request body (1 MiB by default).
- `GET /v1/models` returns `403` when the config names no concrete model.
- The repository has no test that runs an OpenAI or Anthropic SDK.

## Implementation notes

- Endpoint classes and metering: `crates/proxy-http/src/endpoint.rs:49-83`.
- Unmetered refusal text: `crates/proxy-filters/src/unmetered.rs:32`; tests in
  `crates/proxy/tests/unmetered_endpoint_e2e.rs`.
- Object ownership `404`: `crates/proxy-filters/src/object_ownership_filter.rs:470`.
- `include_usage` injection and its exclusions:
  `crates/proxy-filters/src/body_rewrite_filter.rs:301-310, 453-470`.
- Routing header: `crates/proxy-simple-config/src/lower.rs:22`; 404 backstop at
  `lower.rs:466-475`.
- Path rewrites: `crates/proxy-simple-config/src/lower.rs:1155-1178`;
  Vertex and Bedrock paths in `crates/proxy-http/src/router.rs:2665-2710`.
- Provider header names: `crates/proxy-simple-config/src/lower.rs:1376-1377`;
  `anthropic-version`: `lower.rs:1990-2005`.
- Virtual key header: `crates/proxy-control/src/auth.rs:738-757`; test
  `the_virtual_key_never_reaches_any_provider_type`.
- Body limit: `crates/proxy-http/src/filter_manager.rs:1539`.
