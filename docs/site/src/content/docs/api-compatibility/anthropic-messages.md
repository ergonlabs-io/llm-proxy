---
title: Anthropic Messages
description: "Route POST /v1/messages to Anthropic, with the headers the proxy sets, client authentication, and token metering."
summary: What the proxy does with an Anthropic Messages request - routing,
  provider headers, why x-api-key does not authenticate a client, and which
  usage fields it reads.
lastUpdated: 2026-10-21
related:
  - api-compatibility/overview
  - api-compatibility/errors
  - getting-started/connect-your-application
  - providers/anthropic
  - authentication/virtual-keys
---

`POST /v1/messages` is a metered endpoint. The proxy routes on the `model`
field and streams the response without buffering. It reads cache tokens as
well as input and output tokens, for JSON and for streaming responses. The
proxy does not translate between Messages and Chat Completions.

## At a glance

- **Default behavior:** the proxy sets `x-api-key` and `anthropic-version`
  on the request to the provider. It replaces any value the client sent for
  these headers.
- **Failure mode:** with `auth:` on, a request without a valid
  `Authorization: Bearer` virtual key gets `401`. Authentication fails closed.
  Token limits fail open when the proxy cannot read usage, with a warning.

## Example

Save this file as `messages.yaml`. A provider named `anthropic` has the type
`anthropic` and the base URL `https://api.anthropic.com` by default.

```yaml title="messages.yaml"
version: 0
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}

routes: []
models:
  claude-sonnet-4-5:
    providers: [anthropic]
  claude-haiku-4-5:
    providers: [anthropic]
```

```bash
llm-proxy --config messages.yaml --mode validate
llm-proxy --config messages.yaml > /tmp/llm-proxy.log 2>&1 &
```

```bash
curl --max-time 30 -s http://127.0.0.1:53421/v1/messages \
  -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":64,
       "messages":[{"role":"user","content":"hi"}]}'
```

The client sends no provider key and no version header. The proxy adds both.

## Headers the proxy sets

| Header | Value |
| --- | --- |
| `x-api-key` | The provider `api_key`. |
| `anthropic-version` | `2023-06-01`, unless `extra_headers` sets one. |

The proxy replaces a header of the same name that the client sent. A client
`anthropic-version` does not reach Anthropic. To use a different version for
all clients, set it on the provider:

```yaml title="Fragment - pin another API version"
providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    extra_headers:
      anthropic-version: "2023-06-01"
```

Replace the value with the version you need. The default is `2023-06-01`. A
newer version can change the response shape that the usage parser reads.

## What the proxy reads

The proxy reads the `usage` object of the response:

| Field | Becomes |
| --- | --- |
| `input_tokens` | Input tokens. Anthropic already excludes cached tokens. |
| `cache_read_input_tokens` | Cached tokens. |
| `cache_creation_input_tokens` | Cache write tokens. |
| `output_tokens` | Output tokens. |

## Streaming

The proxy forwards server-sent events (SSE) as they arrive. It reads
`message.usage` from the `message_start` event for the input and cache counts.
It reads `usage` from the `message_delta` events for the output count. The
output count in `message_delta` is cumulative, so the proxy keeps the last
value and does not add the values.

The `force_usage_reporting` rewrite does not apply. Anthropic always reports
usage in the stream, so the proxy does not change the request body.

## Limit the output tokens

A `models` entry can set `max_output_tokens`. For a Messages request, the
proxy checks the `max_tokens` body field. A request over the cap gets `400`.
The proxy does not lower the value.

## Client authentication

When `auth:` is on, the proxy reads the virtual key from
`Authorization: Bearer llmp_...` and from no other header. The Anthropic SDK
sends its `api_key` in `x-api-key`. The proxy does not read `x-api-key` for
authentication, so that call gets `401 unauthorized`. Pass the virtual key as
`auth_token`, not `api_key`. For an example, see
[Connect your application](/docs/llm-proxy/getting-started/connect-your-application/#anthropic-sdk).

After authentication succeeds, the proxy removes the client `Authorization`
header. The virtual key does not reach Anthropic. The provider key goes out in
`x-api-key`.

Without `auth:`, the proxy does not check a client key. A client
`x-api-key` is replaced by the provider key when the provider has an
`api_key`.

## Other Messages paths

| Request | Behavior |
| --- | --- |
| `POST /v1/messages/count_tokens` | Forwarded. The proxy treats it as free. No budget or limit refuses it. |
| `POST /v1/messages/batches` | Forwarded only when no budget or token limit applies. Otherwise `403`. |
| `GET /v1/models` | The proxy answers in the OpenAI list shape. |

## Failure modes

| Symptom | Cause |
| --- | --- |
| `404` `model_not_found` | No route matches the `model` value. |
| `401` `unauthorized` | `auth:` is on and the request has no valid `Authorization: Bearer` virtual key. |
| `4xx` from Anthropic | The proxy forwards the provider error response unchanged. |

See [Errors](/docs/llm-proxy/api-compatibility/errors/).

## Limitations

- No translation between Messages and Chat Completions. An OpenAI client
  cannot call a Claude model through this proxy.
- A failover chain from an Anthropic provider to an OpenAI provider is a load
  error.
- Anthropic on Vertex AI or Amazon Bedrock needs `dialect: anthropic` in the
  `models` entry. See [Providers](/docs/llm-proxy/providers/overview/).
- See [Limitations](/docs/llm-proxy/help/limitations/).

## Related

- [API compatibility](/docs/llm-proxy/api-compatibility/overview/)
- [Connect your application](/docs/llm-proxy/getting-started/connect-your-application/)
- [Anthropic provider](/docs/llm-proxy/providers/anthropic/)
