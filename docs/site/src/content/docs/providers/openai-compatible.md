---
title: OpenAI-compatible
description: Route to vLLM, Ollama, TGI, and hosted OpenAI-compatible APIs such as xAI, with optional keys, private CAs, and HTTP/2.
summary: The openai-compatible provider block for self-hosted and hosted
  servers, with examples for Ollama, vLLM, and xAI, TLS and protocol options,
  and the base_url path limit.
lastUpdated: 2026-10-21
related:
  - providers/overview
  - providers/openai
  - providers-and-routing/failover-and-aggregates
  - providers-and-routing/load-balancing
---

The `openai-compatible` type covers any server that serves the OpenAI API at
its root. Examples are vLLM, Ollama, TGI, and hosted APIs such as xAI. It is
the default type. Any provider name other than `openai`, `anthropic`, or
`openrouter` gets this type if you do not set `type`.

## At a glance

- **Default behavior:** type `openai-compatible` for an unrecognized name.
  `base_url` is required.
- **Auth:** `Authorization: Bearer <api_key>` if a key is set. With no key, the
  proxy adds no auth header. This suits local servers.
- **Dialect:** `openai`.
- **Fails closed or open:** a missing `base_url` fails the load. A missing key
  does not.

## Minimal example

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  ollama:
    base_url: http://127.0.0.1:11434

routes:
  - model: "*"
    provider: ollama
```

1. Check the file.

   ```bash
   llm-proxy --config llmproxy.yaml --mode validate
   ```

2. Start the proxy in a second terminal.

   ```bash
   llm-proxy --config llmproxy.yaml
   ```

3. Send a request.

   ```bash
   curl --max-time 60 http://127.0.0.1:53421/v1/chat/completions \
     -H 'content-type: application/json' \
     -d '{"model":"llama3.1:8b","messages":[{"role":"user","content":"hi"}]}'
   ```

Ollama needs no key and no `type`. The file `examples/llmproxy-ollama.yaml` has
the same shape. A missing `base_url` fails the load:

```text
invalid value at `providers.ollama.base_url`: base_url is required for `ollama` (only providers named/typed openai, anthropic, or openrouter have an implied URL)
```

## Fields

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `type` | enum | `openai-compatible` for other names | no | Set it when the name is `openai`, `anthropic`, or `openrouter` but the server is not. |
| `base_url` | URI | none | yes | Scheme, host, and optional port. No path. |
| `api_key`, `api_key_file` | string | none | no | Bearer token. Omit both for a local server. |
| `extra_headers` | map | empty | no | Added to every request. |
| `ca_file` | string | system roots | no | PEM bundle for a private CA. Ignored, with a warning, for `http://`. |
| `connect_timeout` | duration | `5s` | no | |
| `protocol` | `http1`, `http2` | `http1` | no | `http2` keeps up to 4 multiplexed connections for each worker and address. |
| `tenant_credentials` | boolean | `false` | no | Let a tenant send its own key. |

## Examples by server

```yaml title="Fragment: vLLM with a private CA"
providers:
  local-vllm:
    base_url: https://vllm.internal:8443
    ca_file: /etc/ssl/internal-ca.pem
    api_key: ${VLLM_API_KEY}
```

```yaml title="Fragment: xAI, hosted"
providers:
  xai:
    type: openai-compatible
    base_url: https://api.x.ai
    api_key: ${XAI_API_KEY}
    protocol: http2
```

The line `protocol: http2` is optional. The schema says most hosted
OpenAI-compatible APIs support it and many plaintext local servers do not.
Leave it at `http1` for a plaintext server.

The same fields serve TGI, Together, Fireworks, and DeepSeek. Only the URL
changes. The proxy sends the OpenAI wire format. It does not check how a server
implements it. The file `examples/llmproxy-multi-provider.yaml` has an xAI
example.

## Load balancing

One provider is one endpoint: one `base_url`. The proxy does not spread load
across several URLs in one provider. For several replicas, put a load balancer
behind the `base_url`. To spread requests across providers, use `weight` in a
`models` entry. See
[Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/).

## Failover

A local server often serves as the last fallback for a hosted provider. Both
use the `openai` dialect, so the chain loads:

```yaml title="Fragment: OpenAI, then local vLLM"
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  local-vllm:
    base_url: http://vllm.internal:8000

models:
  chat:
    providers:
      - { provider: openai, model: gpt-5-mini }
      - { provider: local-vllm, model: llama-3.3-70b }
```

A request for `chat` goes to OpenAI with `model: gpt-5-mini`. After a failure
that shows OpenAI did not serve the request, the proxy sends it to vLLM with
`model: llama-3.3-70b`. vLLM never sees the OpenAI key. See
[Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

## Gotchas

- `base_url` with a path fails the load, for example Groq at
  `https://api.groq.com/openai`. See the
  [provider overview](/docs/llm-proxy/providers/overview/).
- The proxy forwards the client path as sent. A server that serves its API at
  `/v1/chat/completions` works. A server that needs a different path does not.
- A streaming request without `stream_options` gets
  `stream_options.include_usage = true`. A server that rejects that field
  rejects the request. Set `observability.force_usage_reporting: false` to stop
  the addition.
- Ollama model names carry tags such as `llama3.1:8b`. The `*` character
  matches any run of characters, so `llama3.1*` works as a route pattern.

## Limitations

- No path in `base_url`.
- One endpoint for each provider.
- The proxy does not check that a server really implements the OpenAI API.
- See [Limitations](/docs/llm-proxy/help/limitations/).
