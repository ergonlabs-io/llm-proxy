---
title: OpenAI Responses
description: "Route POST /v1/responses to OpenAI, with streaming, token metering, and the output token cap."
summary: What the proxy does with an OpenAI Responses request - model routing,
  which usage fields it reads, and which controls apply.
lastUpdated: 2026-10-21
related:
  - api-compatibility/overview
  - api-compatibility/openai-chat-completions
  - api-compatibility/errors
  - limits-and-budgets/token-rate-limiting
  - limits-and-budgets/spend-policies
---

`POST /v1/responses` is a metered endpoint. The proxy routes on the `model`
field, as it does for Chat Completions. It streams the response without
buffering and reads token usage from JSON and streaming responses.

## At a glance

- **Default behavior:** routing, streaming, token limits, spend budgets, and
  the usage record all work. The proxy picks the Responses usage parser from
  the request path. It does not add `stream_options`.
- **Failure mode:** token limits fail open when the proxy cannot read usage.
  The proxy admits the request, charges nothing, and logs a warning.

## Example

This config routes `gpt-4o` to OpenAI. The same model serves both
`/v1/chat/completions` and `/v1/responses`.

```yaml title="responses.yaml"
version: 0
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes: []
models:
  gpt-4o:
    providers: [openai]
```

```bash
llm-proxy --config responses.yaml --mode validate
llm-proxy --config responses.yaml > /tmp/llm-proxy.log 2>&1 &
curl --max-time 30 -s http://127.0.0.1:53421/v1/responses \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o","input":"hi"}'
```

The provider replies with its Responses object. The proxy forwards it
unchanged.

## What the proxy reads

The proxy reads the `usage` object of the response:

| Field | Becomes | Note |
| --- | --- | --- |
| `input_tokens` | Input tokens | The proxy first subtracts `cached_tokens`. |
| `input_tokens_details.cached_tokens` | Cached tokens | A subset of `input_tokens`. |
| `output_tokens` | Output tokens | |
| `input_tokens_details.image_tokens`, `output_tokens_details.image_tokens` | Image tokens | A subset of the input and output counts. |
| `total_tokens` | Not read | The proxy computes its own total. |

In a stream, usage arrives once, in the `response.completed` event, under
`response.usage`. The Responses API sends no `data: [DONE]` line. The proxy
does not need one.

## Streaming

The proxy forwards server-sent events (SSE) as they arrive. The proxy does
not add `stream_options.include_usage` to a request whose path ends in
`/responses`. The Responses API reports usage on every stream, so the
`observability.force_usage_reporting` setting has no effect on this path.

## Limit the output tokens

A `models` entry can set `max_output_tokens`. For a Responses request, the
proxy checks the `max_output_tokens` body field. A request over the cap gets
`400`. The proxy does not lower the value. A request that names no limit
passes unchanged.

```yaml title="Fragment - cap output at 4096 tokens"
models:
  gpt-4o:
    providers: [openai]
    max_output_tokens: 4096
```

## Which controls apply

| Control | Effect on `POST /v1/responses` |
| --- | --- |
| Token limit | Counts the tokens of the response. |
| Spend budget | Counts the cost of the response. |
| Access log `llm_*` fields | Hold the token counts. |

A stored-object request, such as `GET /v1/responses/{id}`, is not a new
generation. The proxy does not meter it. It forwards the request when no
budget or limit applies. Otherwise it refuses the request with `403`. See
[Errors](/docs/llm-proxy/api-compatibility/errors/#refusals-for-paths-that-cannot-be-metered).

## Limitations

- No translation between Responses and Chat Completions. The model must
  speak the API the client calls.
- See [Limitations](/docs/llm-proxy/help/limitations/).

## Related

- [API compatibility](/docs/llm-proxy/api-compatibility/overview/)
- [OpenAI Chat Completions](/docs/llm-proxy/api-compatibility/openai-chat-completions/)
- [Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/)
