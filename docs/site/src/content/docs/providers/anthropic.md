---
title: Anthropic
description: Configure the Anthropic provider, the default anthropic-version header, and failover between Anthropic-shaped providers.
summary: The Anthropic provider block, how the x-api-key and anthropic-version
  headers are set, how to pin a version, and the same-dialect rule for
  fallbacks.
lastUpdated: 2026-10-21
related:
  - providers/overview
  - providers/vertex-ai
  - providers/amazon-bedrock
  - api-compatibility/anthropic-messages
  - getting-started/connect-your-application
---

The `anthropic` type sends Anthropic Messages requests to
`https://api.anthropic.com`. A provider named `anthropic` needs only an API
key. The proxy sets the two headers that Anthropic requires.

## At a glance

- **Default behavior:** type `anthropic` and `base_url`
  `https://api.anthropic.com` when the provider is named `anthropic`.
- **Headers added:** `x-api-key: <api_key>` and `anthropic-version: 2023-06-01`.
  The proxy replaces any `anthropic-version` that the client sends with the
  provider value.
- **Dialect:** `anthropic`. The proxy parses Anthropic usage objects and does
  not add `stream_options`.
- **Fails closed or open:** a missing `api_key` does not fail the load.
  Anthropic returns an authentication error to the client.

## Minimal example

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}

routes:
  - model: claude-*
    provider: anthropic
```

1. Set the key and check the file.

   ```bash
   export ANTHROPIC_API_KEY=sk-ant-...
   llm-proxy --config llmproxy.yaml --mode validate
   ```

2. Start the proxy in a second terminal.

   ```bash
   llm-proxy --config llmproxy.yaml
   ```

3. Send a request.

   ```bash
   curl --max-time 30 http://127.0.0.1:53421/v1/messages \
     -H 'content-type: application/json' \
     -d '{"model":"claude-sonnet-4-5","max_tokens":64,
          "messages":[{"role":"user","content":"hi"}]}'
   ```

The client sends no `x-api-key` and no `anthropic-version`. The proxy adds
both. If you enable `auth`, Anthropic SDK users pass the virtual key as
`auth_token`, because the proxy reads the virtual key only from
`Authorization: Bearer`. See
[Connect your application](/docs/llm-proxy/getting-started/connect-your-application/).

## Fields

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `type` | enum | `anthropic` when the name is `anthropic` | no | Set `anthropic` to use another provider name. |
| `base_url` | URI | `https://api.anthropic.com` | no | Scheme, host, and optional port. No path. |
| `api_key` | string | none | no | Use `${ANTHROPIC_API_KEY}`. |
| `api_key_file` | string | none | no | File with the key. Not with `api_key`. |
| `extra_headers` | map | empty | no | Added to every request. `anthropic-version` here replaces the default. |
| `ca_file` | string | system roots | no | |
| `connect_timeout` | duration | `5s` | no | |
| `protocol` | `http1`, `http2` | `http1` | no | |
| `tenant_credentials` | boolean | `false` | no | Let a tenant send its own key. See [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/). |

## Pin the API version

Set `anthropic-version` in `extra_headers`. The match ignores case. The proxy
then sends your value and does not add the default.

```yaml title="Fragment: pin a version and a beta"
providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
    extra_headers:
      anthropic-version: "2023-06-01"
      anthropic-beta: prompt-caching-2024-07-31
```

The proxy sends other `extra_headers` entries as written. It does not validate
their values.

## Model names

The proxy forwards the `model` from the body unchanged. A `models` entry maps
an alias to a dated model ID:

```yaml title="Fragment: alias to a dated ID"
models:
  sonnet:
    providers:
      - { provider: anthropic, model: claude-sonnet-4-5-20250929 }
```

## Failover

A fallback for an Anthropic route must also use the `anthropic` dialect. Valid
members are another `anthropic` provider, for example a second account, or a
`vertex` or `bedrock` provider whose `models` entry sets `dialect: anthropic`.
Use a `models` entry for the chain, because only that form can state the
dialect.

```yaml title="Fragment: Anthropic first, Bedrock second"
providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
  bedrock:
    type: bedrock
    base_url: https://bedrock-runtime.us-east-1.amazonaws.com
    region: us-east-1
    access_key_id: ${AWS_ACCESS_KEY_ID}
    secret_access_key: ${AWS_SECRET_ACCESS_KEY}

models:
  claude-sonnet-4-5:
    providers:
      - { provider: anthropic, model: claude-sonnet-4-5-20250929 }
      - { provider: bedrock, model: anthropic.claude-sonnet-4-5-20250929-v1:0, dialect: anthropic }
```

Each member sends its own credential and its own upstream model name. A chain
from `anthropic` to an `openai` provider fails the load:

```text
invalid value at `models.<name>.providers[1]`: `<provider>` speaks `openai`, but the primary provider `anthropic` speaks `anthropic`; cross-dialect model fallback needs request/response translation and is not supported
```

The Bedrock model ID in this example is illustrative. Check the ID in your AWS
account. The Bedrock request body must carry the fields that Bedrock expects.
See [Amazon Bedrock](/docs/llm-proxy/providers/amazon-bedrock/).

## Gotchas

- The proxy does not read `ANTHROPIC_API_KEY` by itself. Write
  `${ANTHROPIC_API_KEY}` in the file.
- The client `anthropic-version` header does not reach Anthropic. The provider
  value replaces it. To use another version, set it in `extra_headers`.

## Limitations

- The proxy does not convert OpenAI requests to Anthropic requests. Send the
  Anthropic Messages format to an Anthropic provider.
- The proxy does not add `anthropic-beta` headers for you.
- See [Limitations](/docs/llm-proxy/help/limitations/).
