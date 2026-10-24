---
title: OpenAI Chat Completions
description: "Route POST /v1/chat/completions to OpenAI or an OpenAI-compatible provider, with streaming, token metering, and the include_usage behavior."
summary: What the proxy does with a Chat Completions request - model routing,
  the forced stream_options.include_usage, which usage fields it reads, and
  what it leaves alone.
lastUpdated: 2026-10-21
related:
  - api-compatibility/overview
  - api-compatibility/errors
  - getting-started/connect-your-application
  - providers/openai-compatible
  - observability/access-logs
  - limits-and-budgets/token-rate-limiting
---

`POST /v1/chat/completions` is the best supported API. The proxy routes on
the `model` field, streams the response without buffering, and reads token
usage from JSON and streaming responses. Use it with OpenAI, OpenRouter, Azure
OpenAI, vLLM, Ollama, TGI, and other OpenAI-shaped providers.

## At a glance

- **Default behavior:** the proxy sets `stream_options.include_usage` to
  `true` on every streaming request, even if the client sent `false`.
  `observability.force_usage_reporting` controls this. Its default is `true`.
- **Failure mode:** token limits fail open when the proxy cannot read usage.
  The proxy admits the request, charges nothing, and logs a warning. The
  warning repeats at most once a minute for each limit key.

## Example

Save this file as `chat.yaml`. It sends two model names to OpenAI. The
`models` entries also make `GET /v1/models` list both names.

```yaml title="chat.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes: []
models:
  gpt-4o:
    providers: [openai]
  gpt-4o-mini:
    providers: [openai]
```

Check the file, then start the proxy.

```bash
llm-proxy --config chat.yaml --mode validate
llm-proxy --config chat.yaml > /tmp/llm-proxy.log 2>&1 &
```

Send a request.

```bash
curl --max-time 30 -s http://127.0.0.1:53421/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

The response is the OpenAI response, unchanged. The proxy reads
`usage.prompt_tokens` and `usage.completion_tokens` from it.

## What the proxy reads

The proxy reads these fields of the top-level `usage` object:

| Field | Becomes | Note |
| --- | --- | --- |
| `prompt_tokens` | Input tokens | The proxy first subtracts `cached_tokens` and `cache_write_tokens`. |
| `prompt_tokens_details.cached_tokens` | Cached tokens | A subset of `prompt_tokens`. |
| `prompt_tokens_details.cache_write_tokens` | Cache write tokens | A subset of `prompt_tokens`. Gateways that front Anthropic or Gemini report it. |
| `completion_tokens` | Output tokens | |
| `prompt_tokens_details.audio_tokens`, `completion_tokens_details.audio_tokens` | Audio tokens | A subset of the input and output counts. A rate card can price them at an audio rate. |
| `total_tokens` | Not read | The proxy computes its own total. |

If the `usage` object has none of the token fields, the request has no usage
record. If it has some of them, the missing fields count as 0.

## Streaming

The proxy forwards server-sent events (SSE) as they arrive. It scans each
`data:` line for a `usage` object. It accepts `\r\n` line ends, `data:{...}`
without a space, and `data: [DONE]`.

OpenAI sends usage in a stream only when the request sets
`stream_options.include_usage`. The proxy sets it for you:

| Request body | What the proxy sends to the provider |
| --- | --- |
| `"stream": true`, no `stream_options` | Adds `"stream_options":{"include_usage":true}`. |
| `"stream": true`, `stream_options` without `include_usage` | Adds `include_usage: true`. Keeps the other options. |
| `"stream": true`, `include_usage: false` | Changes `include_usage` to `true`. |
| `"stream": false`, or no `stream` | Leaves the body unchanged. |
| Not JSON | Leaves the body unchanged. |

The proxy changes the `content-length` header to match.

The client then receives one extra final chunk. It has an empty `choices`
array and a `usage` object. Official SDKs handle this chunk. A hand-written
client that reads `choices[0]` on every chunk can fail on it.

To stop this behavior, set `observability.force_usage_reporting: false`. The
proxy then does not touch the request. A streaming request that does not set
`include_usage` has no usage record in this case, because the provider sends
none.

```yaml title="Fragment - strict passthrough for streaming"
observability:
  force_usage_reporting: false
```

The rewrite applies to routes that use the OpenAI dialect. It does not apply
to paths that end in `/responses` or `/messages`.

## Routing and model rewrite

The proxy matches the `model` field against `routes` and `models`. First
match wins for `routes`, and the proxy checks `routes` before `models`. To
rewrite the model name before the request reaches the provider, set `model` on
a provider in a `models` entry:

```yaml title="Fragment - serve the alias gpt-4o from a local vLLM"
providers:
  vllm:
    base_url: http://127.0.0.1:8000
models:
  gpt-4o:
    providers:
      - { provider: vllm, model: llama-3.3-70b }
```

The proxy reads `model` only from a body with a JSON content type. See
[API compatibility](/docs/llm-proxy/api-compatibility/overview/#request-bodies).
For the match order, see
[Models and routes](/docs/llm-proxy/configuration/models-and-routes/).

## Limit the output tokens

A `models` entry can set `max_output_tokens`. The proxy refuses a request
that asks for more output tokens than the cap. It does not lower the value.
For Chat Completions, the proxy checks both `max_completion_tokens` and
`max_tokens`. A request that names no limit passes unchanged.

```yaml title="Fragment - cap output at 4096 tokens"
models:
  gpt-4o:
    providers: [openai]
    max_output_tokens: 4096
```

A request over the cap gets `400`. For example, the body is
`` `max_tokens` 9000 exceeds the maximum of 4096 output tokens for this model ``.

## Failure modes

| Symptom | Cause |
| --- | --- |
| `404` with a `model_not_found` body | No route matches the `model` value, or the body has no readable `model`, and the config has no `*` rule. |
| `401` `unauthorized` | `auth:` is on and the `Authorization: Bearer` header has no valid virtual key. |
| `429` `token budget exceeded` | A token limit is spent. |
| `403` `forbidden` | The key may not use the model. |

See [Errors](/docs/llm-proxy/api-compatibility/errors/) for the full list and
for the exact bodies.

## Limitations

- Local replies from the proxy are not in the OpenAI error JSON format. Most
  are plain text. See [Errors](/docs/llm-proxy/api-compatibility/errors/).
- The proxy scans only the first 64 KiB of the body for `model` and
  `stream`. The router then checks the whole buffered body, so a client cannot
  hide an opt-out after the scan window.
- The `force_usage_reporting` rewrite applies to OpenAI-dialect routes only.
  It does not apply to `anthropic` routes.
- See [Limitations](/docs/llm-proxy/help/limitations/).

## Related

- [API compatibility](/docs/llm-proxy/api-compatibility/overview/)
- [Connect your application](/docs/llm-proxy/getting-started/connect-your-application/)
- [Access logs](/docs/llm-proxy/observability/access-logs/)
- [Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/)
