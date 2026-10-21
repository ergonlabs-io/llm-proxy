---
title: API compatibility
description: "Which provider APIs llm-proxy forwards, what it changes in a request, how it meters each endpoint, and what it does not do."
summary: Reference for the passthrough model, the supported API families,
  endpoints the proxy answers itself, streaming, credentials, model names, and
  limitations.
lastUpdated: 2026-10-21
related:
  - getting-started/connect-your-application
  - api-compatibility/openai-chat-completions
  - api-compatibility/openai-responses
  - api-compatibility/anthropic-messages
  - api-compatibility/realtime
  - api-compatibility/errors
  - providers/overview
  - authentication/virtual-keys
  - providers-and-routing/auto-model
  - limits-and-budgets/token-rate-limiting
---

llm-proxy forwards requests to a provider. It does not translate them. A client
that speaks a provider's API keeps speaking that API through the proxy. For
client setup, see
[Connect your application](/docs/llm-proxy/getting-started/connect-your-application/).

## At a glance

- **Default behavior:** the proxy reads the JSON `model` field, picks a
  provider, and forwards the request. It does not change the response.
- **Failure mode:** authentication and model access fail closed. A request
  for an endpoint that the proxy cannot meter fails closed when a budget or
  limit applies. A response whose usage the proxy cannot read fails open for
  token limits, with a warning.

| Page | What it covers |
| --- | --- |
| [OpenAI Chat Completions](/docs/llm-proxy/api-compatibility/openai-chat-completions/) | `POST .../chat/completions`: routing, streaming usage, usage fields. |
| [OpenAI Responses](/docs/llm-proxy/api-compatibility/openai-responses/) | `POST .../responses`: routing and metering. |
| [Anthropic Messages](/docs/llm-proxy/api-compatibility/anthropic-messages/) | `POST .../messages`: headers, client authentication, metering. |
| [Realtime](/docs/llm-proxy/api-compatibility/realtime/) | WebSocket sessions on `.../realtime`. |
| [Errors](/docs/llm-proxy/api-compatibility/errors/) | Every reply that the proxy makes itself. |

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

The proxy recognizes `POST .../messages/count_tokens` as free. A free path
costs nothing, so no budget or limit refuses it.

A WebSocket session on a path that ends in `/realtime` is also metered. See
[Realtime](/docs/llm-proxy/api-compatibility/realtime/).

### What each control counts

| Endpoint | Token limit | Spend budget |
| --- | --- | --- |
| Chat Completions, Completions, Responses, Messages, Embeddings | Counts tokens. | Counts cost. |
| Realtime session | Counts tokens. | Counts cost. |
| Image generation, image edits, speech, transcription, translation | Refuses the request. | Counts cost, if the proxy can count the request. |
| `GET /v1/models`, `GET /v1/usage`, `POST .../messages/count_tokens` | Allows the request. | Allows the request. |
| Every other path | Refuses the request. | Refuses the request. |

A control refuses a path only if it applies to the caller. See
[Other paths](#other-paths).

Image generation, image edits, speech, transcription and translation
(`POST .../images/generations`, `.../images/edits`, `.../audio/speech`,
`.../audio/transcriptions`, `.../audio/translations`) are metered for spend
budgets, in provider units: images, characters or audio duration, or tokens
when the provider reports them. A budget refuses a request whose cost the
proxy cannot count from its shape, such as a translation without
`response_format: verbose_json`. Token limits count tokens only, so they
refuse these endpoints. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

## Endpoints the proxy answers

| Request | Behavior |
| --- | --- |
| `GET /v1/models` | The proxy answers. It never forwards the request. The list holds the catalogue: every `routes[].model` and `models:` key except `*` and `auto`. With model policy on, it lists only models the caller may use. When the catalogue is empty, the request gets `403 forbidden`. |
| `GET /v1/usage` | The proxy answers through the token-limit filter. It returns `401 unauthorized` without a tenant and `503 usage unavailable` if the store fails. |

The model list uses the OpenAI list shape. Each entry has `id`, `object:
"model"`, `created: 0`, and `owned_by: "llm-proxy"`.

## Other paths

The proxy forwards every other path to the provider the model selects. This
includes files, batches and image variations. The proxy does not meter these
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

The proxy reads the `model` field from a body that has a JSON content type
(`application/json`). It scans the first 64 KiB of the body. If it does not
find a `model` there, it treats the request as having no model. The request
then follows the `*` rule, or gets the `404` `model_not_found` reply. A body
with another content type, such as `text/plain`, also has no model. A
`multipart/form-data` body (transcription, translation, image edits) is read
for its `model` part.

Before the proxy forwards a request, it checks the whole buffered body against
the model it routed on. A body with a repeated `model` key, or a `model` that
differs from the routed model, gets `400`. See
[Errors](/docs/llm-proxy/api-compatibility/errors/).

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
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

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
  [The auto model](/docs/llm-proxy/providers-and-routing/auto-model/).
- If no rule matches and there is no `*` rule, the proxy returns `404` with the
  type `model_not_found`.

## Preserved and changed fields

| Item | What the proxy does |
| --- | --- |
| Request body | Forwards it unchanged, except for the `model` rewrite and the `stream_options` injection above. |
| `model` | Rewrites it if a `models:` entry maps it. |
| `Authorization` | Removes the virtual key and adds the provider credential. |
| `anthropic-version` | For `anthropic` providers, sets `2023-06-01` unless `extra_headers` sets a value. It replaces any value the client sent. |
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

See also [Limitations](/docs/llm-proxy/help/limitations/).

- No translation between OpenAI and Anthropic formats.
- No CORS support. Browser clients cannot call the proxy.
- Image variations are not metered, so a budget or limit refuses them. Image
  and audio endpoints count toward spend budgets but not token limits.
- Files and batches are forwarded only when no budget or limit applies, and
  only for the tenant that owns the object.
- The listener caps the request body (1 MiB by default).
- `GET /v1/models` returns `403` when the config names no concrete model.
- The repository has no test that runs an OpenAI or Anthropic SDK.

## Implementation notes

- Endpoint classes and metering: `crates/proxy-http/src/endpoint.rs`.
- Unmetered refusal text: `crates/proxy-filters/src/unmetered.rs`; tests in
  `crates/proxy/tests/unmetered_endpoint_e2e.rs`.
- Object ownership `404`: `crates/proxy-filters/src/object_ownership_filter.rs`.
- `include_usage` injection and its exclusions:
  `crates/proxy-filters/src/body_rewrite_filter.rs`.
- Routing header: `crates/proxy-simple-config/src/lower.rs`; 404 backstop at
  `lower.rs`.
- Path rewrites: `crates/proxy-simple-config/src/lower.rs`;
  Vertex and Bedrock paths in `crates/proxy-http/src/router.rs`.
- Provider header names: `crates/proxy-simple-config/src/lower.rs`;
  `anthropic-version`: `lower.rs` (`provider_headers_to_add`). The router
  replaces a client header of the same name (`OverwriteIfExistsOrAdd`).
- Model scan: `crates/proxy-filters/src/body_rewrite_filter.rs` (JSON content
  type, 64 KiB prefix); body check against the routed model:
  `reconcile_request_body` in `crates/proxy-http/src/router.rs`.
- Virtual key header: `crates/proxy-control/src/auth.rs`; test
  `the_virtual_key_never_reaches_any_provider_type`.
- Body limit: `crates/proxy-http/src/filter_manager.rs`.
