---
title: Connect your application
description: "Point an existing OpenAI or Anthropic client at llm-proxy: base URL, virtual key, model name, streaming, and the errors you can see."
summary: Change three settings in an OpenAI-style client, see Python and Node
  examples, and look up the status codes the proxy returns.
lastUpdated: 2026-10-21
related:
  - getting-started/quickstart
  - api-compatibility/overview
  - api-compatibility/openai-chat-completions
  - api-compatibility/anthropic-messages
  - api-compatibility/errors
  - authentication/virtual-keys
  - providers-and-routing/auto-model
---

This tutorial shows how to change an existing client so that it sends requests
through llm-proxy. It assumes the proxy runs. If it does not, follow the
[quickstart](/docs/llm-proxy/getting-started/quickstart/) first. It also assumes you have a virtual key, which
starts with `llmp_`. `llm-proxy init` prints one key, once.

> **Test status.** The repository has no test that runs an OpenAI or Anthropic
> SDK. The SDK code on this page is an illustration. It uses the standard SDK
> API and relies on HTTP behavior that the test suite pins. Run it against your
> own proxy before you depend on it.

## What to change in the client

Change three settings. Nothing else in your application changes.

| Setting | Value |
| --- | --- |
| Base URL | `http://127.0.0.1:53421/v1` for OpenAI-style clients. This is the address the starter config listens on. |
| API key | Your virtual key (`llmp_...`). Do not use a provider key. |
| Model name | A name that a `routes:` entry or a `models:` key matches. |

Each SDK builds the final URL from the base URL. Use the base URL that
matches the SDK:

| Client | Base URL | Why |
| --- | --- | --- |
| OpenAI Python and Node SDK | `http://127.0.0.1:53421/v1` | The SDK appends `/chat/completions`. The proxy needs the `/v1`. |
| Anthropic Python and Node SDK | `http://127.0.0.1:53421` | The SDK appends `/v1/messages`. Do not add `/v1`. |
| curl | The full path | You write the path yourself. |

The proxy reads the model from the JSON request body. It does not use the URL
to choose a provider. Set the key in an environment variable, not in code:

```sh
export LLMPROXY_KEY="llmp_..."
```

## Python (OpenAI SDK)

Install the SDK with `pip install openai`. Then create the client with the
proxy address and the virtual key.

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:53421/v1",
    api_key=os.environ["LLMPROXY_KEY"],
)

reply = client.chat.completions.create(
    model="gpt-4o-mini",  # use a name your config matches
    messages=[{"role": "user", "content": "Say hello."}],
)
print(reply.choices[0].message.content)
```

For a streaming request, guard the last chunk. By default the proxy sets
`stream_options.include_usage` to `true` on every streaming Chat Completions
request. The provider then sends one extra final chunk. That chunk has an empty
`choices` list and a `usage` object.

```python
stream = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Count to five."}],
    stream=True,
)
for chunk in stream:
    if not chunk.choices:  # the final usage-only chunk
        continue
    print(chunk.choices[0].delta.content or "", end="")
print()
```

Code that reads `chunk.choices[0]` without the guard fails on the last chunk.
To remove the extra chunk, set `observability.force_usage_reporting: false`.
Then the provider reports usage for a streamed response only if the client asks
for it, so the proxy can miss the token count. See the
[API compatibility](/docs/llm-proxy/api-compatibility/overview/#streaming) page.

## JavaScript (Node, OpenAI SDK)

Install the SDK with `npm install openai`. Run this code in Node. A browser
cannot call the proxy (see [Browser clients](#browser-clients)).

```js
import OpenAI from "openai";

const client = new OpenAI({
  baseURL: "http://127.0.0.1:53421/v1",
  apiKey: process.env.LLMPROXY_KEY,
});

const stream = await client.chat.completions.create({
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "Count to five." }],
  stream: true,
});

for await (const chunk of stream) {
  if (!chunk.choices?.length) continue; // the final usage-only chunk
  process.stdout.write(chunk.choices[0].delta?.content ?? "");
}
process.stdout.write("\n");
```

## Anthropic SDK

The proxy forwards Anthropic Messages requests to a provider of the
`anthropic` type. It does not translate between OpenAI and Anthropic formats.
A request sent to the Messages API must reach an Anthropic-dialect provider.

Two settings differ from the OpenAI example:

- Set the base URL without `/v1`: `http://127.0.0.1:53421`. The SDK adds
  `/v1/messages` itself.
- Pass the virtual key as an auth token, not as an API key.

The proxy reads the virtual key only from `Authorization: Bearer llmp_...`. It
never reads `x-api-key`. The Anthropic SDK sends `api_key` in `x-api-key`, so
that option fails with `401`. The `auth_token` option sends the Bearer header.

```python
import os
import anthropic

client = anthropic.Anthropic(
    base_url="http://127.0.0.1:53421",
    auth_token=os.environ["LLMPROXY_KEY"],
)
message = client.messages.create(
    model="claude-sonnet-4-5",  # use a name your config matches
    max_tokens=256,
    messages=[{"role": "user", "content": "Say hello."}],
)
print(message.content[0].text)
```

In Node, use `new Anthropic({ baseURL: "http://127.0.0.1:53421", authToken:
process.env.LLMPROXY_KEY })`. The proxy adds the `anthropic-version` header for
the provider. Your client does not need to match it.

If you set only `api_key`, the request carries no `Authorization` header. With
authentication on, the proxy returns `401 unauthorized`. The access log shows
`auth_no_credential` as the response code details. You can also keep
`api_key` and add the header yourself with
`default_headers={"Authorization": "Bearer llmp_..."}`.

With authentication off, the proxy does not check the client key. Any
non-empty `api_key` works, because the proxy replaces it with the provider key.

## curl

Chat Completions:

```sh
curl --max-time 30 -s http://127.0.0.1:53421/v1/chat/completions \
  -H "authorization: Bearer $LLMPROXY_KEY" \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

Messages:

```sh
curl --max-time 30 -s http://127.0.0.1:53421/v1/messages \
  -H "authorization: Bearer $LLMPROXY_KEY" \
  -H 'content-type: application/json' \
  -d '{"model":"claude-haiku-4-5","max_tokens":64,
       "messages":[{"role":"user","content":"hi"}]}'
```

Model list (the proxy answers this request itself):

```sh
curl --max-time 10 -s http://127.0.0.1:53421/v1/models \
  -H "authorization: Bearer $LLMPROXY_KEY"
```

The reply has one entry for each model name in the config:

```json
{"data":[{"created":0,"id":"claude-haiku-4-5","object":"model","owned_by":"llm-proxy"},{"created":0,"id":"gpt-4o-mini","object":"model","owned_by":"llm-proxy"}],"object":"list"}
```

The order of the keys and entries can differ in your output.

## Model names

The `model` value in the request must match a route or a `models:` key. The
proxy checks `routes:` in order. Then it checks `models:` keys: exact match
first, then the longest prefix, then `*`.

- A `models:` entry written as `provider/model` changes the model name sent to
  the provider. The response is not changed. It shows the provider's model
  name, not the alias your client sent.
- The name `auto` is reserved. The proxy replaces it with the model the
  operator chose for the tenant. See [The auto model](/docs/llm-proxy/providers-and-routing/auto-model/).
- If no rule matches and the config has no `*` rule, the proxy returns `404`.

## List the models

`client.models.list()` calls `GET /v1/models`. The proxy answers this request
itself and does not forward it. It works only when the config names concrete
models. The catalogue is every `routes[].model` and every `models:` key that is
not `*`, minus `auto`. With authentication on, the list holds only the models
the caller may use.

The starter config has one route with `model: "*"`. Its catalogue is empty.
There, `models.list()` returns `403 forbidden`. Add a named model to the config
to fix this.

## SDK retries

An SDK usually retries a `429`. A token limit or spend budget stays spent
until its window resets, so a quick retry does not help. Read the `retry-after`
header and the `x-ratelimit-*` headers instead.

## Common errors

Errors from the proxy are plain text unless the table says JSON. For every
proxy-made reply, see [Errors](/docs/llm-proxy/api-compatibility/errors/).

| Status | Body | Cause | Fix |
| --- | --- | --- | --- |
| 401 | `unauthorized` | The `Authorization: Bearer` header is missing, wrong, or revoked. The response has `www-authenticate: Bearer`. | Send the virtual key as a Bearer token. For the Anthropic SDK, use `auth_token`. |
| 403 | `forbidden` | The key may not use the model, or the request has no model (a `GET`, or a multipart upload). | Ask the operator to grant the model. Send a JSON body with a `model`. |
| 403 | `this endpoint cannot be metered, so it is refused under a spend budget or token limit` | The path is not metered and a budget or limit applies to the caller. | Use a metered endpoint. See [API compatibility](/docs/llm-proxy/api-compatibility/overview/#other-paths). |
| 404 | JSON, type `model_not_found` | No route or `models:` key matches, and the config has no `*` rule. | Use a name the config matches, or add a rule. |
| 404 | JSON, `object not found` | The file or batch ID belongs to another tenant, or is unknown. | Use an ID your tenant created. |
| 413 | `request body exceeds buffer limit` | The body is larger than `listen.max_request_body_bytes` (1 MiB by default). | Send a smaller body, or raise the limit. |
| 429 | `token budget exceeded`, `request rate exceeded`, `too many concurrent streams` | A token limit applies. | Wait for `retry-after` seconds. The response also has `x-ratelimit-limit`, `x-ratelimit-remaining`, and `x-ratelimit-reset`. |
| 429 | `spend budget exceeded` | The spend budget for the period is used. | Wait for `retry-after` seconds, or ask the operator to raise the budget. |
| 503 | `service unavailable` | The proxy policy data is stale. | Retry. Tell the operator if it continues. |
| 503 | `upstream connect failure`, `upstream overloaded`, `upstream reset`, `no healthy upstream` | The provider did not accept or complete the request. | Retry. Check the provider and the failover config. |
| 504 | `upstream request timeout` | The provider did not answer in time. | Retry, or ask the operator to raise the route timeout. |

The proxy can also return `400 invalid request body`, `408` for a stream or
request timeout, and `403` with a JSON body for a missing tenant provider
credential.

## Browser clients

Browser clients are not supported. The proxy has no CORS filter, so a browser
blocks the response. Call the proxy from a server, such as Node. Do not put a
virtual key in code that runs in a browser.

## Implementation notes

The statements above rest on this code and these tests.

- Virtual key read from `Authorization: Bearer` only:
  `crates/proxy-control/src/auth.rs`.
- Routing by body `model`: `crates/proxy-simple-config/src/lower.rs`
  (404 backstop; test `missing_catch_all_gets_404_backstop`).
- No-model refusal: test `a_bodyless_request_is_refused_rather_than_slipping_through`.
- Model list: tests `models_lists_only_what_the_caller_may_use_and_is_never_forwarded`
  and `models_without_auth_lists_the_whole_catalogue` in
  `crates/proxy/tests/embeddings_e2e.rs`.
- Body limit: `crates/proxy-http/src/filter_manager.rs`; tests in
  `crates/proxy/tests/request_body_limit_e2e.rs`.
- Unmetered refusal: `crates/proxy-filters/src/unmetered.rs`.
- Object ownership: `crates/proxy-filters/src/object_ownership_filter.rs`.
- Token and spend 429: `crates/proxy-filters/src/token_limit_filter.rs`,
  `crates/proxy-filters/src/spend_limit_filter.rs`.
- `anthropic-version` default: `crates/proxy-simple-config/src/lower.rs`.
