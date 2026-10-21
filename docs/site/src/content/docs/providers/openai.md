---
title: OpenAI
description: Configure the OpenAI provider with one API key, route gpt models to it, and fail over to an OpenAI-compatible provider.
summary: The minimal OpenAI provider block, how the key is sent, model aliases,
  and a failover example to a second OpenAI-shaped provider.
lastUpdated: 2026-10-21
related:
  - providers/overview
  - providers/openai-compatible
  - api-compatibility/openai-chat-completions
  - providers-and-routing/failover-and-aggregates
---

The `openai` type sends OpenAI-shaped requests to `https://api.openai.com`.
A provider named `openai` needs only an API key. The proxy infers the type and
the URL from the name.

## At a glance

- **Default behavior:** type `openai` and `base_url` `https://api.openai.com`
  when the provider is named `openai`.
- **Auth:** `Authorization: Bearer <api_key>`. With no key set, the proxy adds
  no auth header.
- **Dialect:** `openai`.
- **Fails closed or open:** an unset `${OPENAI_API_KEY}` fails the load. A
  missing `api_key` does not fail the load. The request reaches OpenAI with no
  credential, and OpenAI rejects it.

## Minimal example

```yaml title="llmproxy.yaml"
version: 0
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes:
  - model: "*"
    provider: openai
```

1. Set the key and check the file.

   ```bash
   export OPENAI_API_KEY=sk-...
   llm-proxy --config llmproxy.yaml --mode validate
   ```

2. Start the proxy in a second terminal.

   ```bash
   llm-proxy --config llmproxy.yaml
   ```

3. Send a request.

   ```bash
   curl --max-time 30 http://127.0.0.1:53421/v1/chat/completions \
     -H 'content-type: application/json' \
     -d '{"model":"gpt-5","messages":[{"role":"user","content":"hi"}]}'
   ```

The client sends no key to OpenAI. The proxy adds it. To require a key from
the client, see [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

## Fields

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `type` | enum | `openai` when the name is `openai` | no | Set `openai` to use another provider name. |
| `base_url` | URI | `https://api.openai.com` | no | Scheme, host, and optional port. Override for a proxy or a regional endpoint. |
| `api_key` | string | none | no | Use `${OPENAI_API_KEY}`. |
| `api_key_file` | string | none | no | File with the key. Not with `api_key`. |
| `extra_headers` | map | empty | no | For example `OpenAI-Organization`. |
| `ca_file` | string | system roots | no | Only for a private CA. |
| `connect_timeout` | duration | `5s` | no | |
| `protocol` | `http1`, `http2` | `http1` | no | The schema says OpenAI supports `http2`. `http2` keeps up to 4 multiplexed connections for each worker. |
| `tenant_credentials` | boolean | `false` | no | Let a tenant send its own key. See [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/). |

The fields for other provider types (`deployment`, `project`, `region`, and so
on) fail the load with the field path. The
[field reference](/docs/llm-proxy/configuration/reference/) lists the common
fields. See also the [provider overview](/docs/llm-proxy/providers/overview/).

## Read the key from a file

```yaml title="Fragment: key from a mounted file"
providers:
  openai:
    api_key_file: /run/secrets/openai_key
```

The proxy trims trailing whitespace. It reads the file at startup and again on
each `SIGHUP` reload, and it prints a warning that says so. To rotate the key,
replace the file and send `SIGHUP`. If you set both `api_key` and
`api_key_file`, the load fails:

```text
invalid value at `providers.openai`: set either api_key or api_key_file, not both
```

## Model names

The proxy matches the `model` field in the request body against the route
patterns. The first match wins. The proxy forwards the name unchanged. See
[Models and routes](/docs/llm-proxy/configuration/models-and-routes/). To give
clients an alias, use a `models` entry:

```yaml title="Fragment: alias"
models:
  fast:
    providers:
      - { provider: openai, model: gpt-5-mini }
```

A request for `fast` reaches OpenAI with `model` set to `gpt-5-mini`. If the
body names a different model than the one the proxy routed on, the proxy
refuses the request with a `400`. A `provider/model` value in `routes` is
accepted, but the proxy does not apply the model part. It forwards the
original model name and prints a load warning.

## Failover

```yaml title="Fragment: OpenAI first, then xAI"
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  xai:
    base_url: https://api.x.ai
    api_key: ${XAI_API_KEY}

routes:
  - model: gpt-*
    provider: openai
    fallbacks: [xai]
```

The proxy dials `xai` only after `openai` fails in a way that shows it did not
serve the request. `xai` receives its own key and its own `Host`, never the
OpenAI key. `xai` is `openai-compatible`, so both providers use the `openai`
dialect. A fallback to an `anthropic` provider fails the load. See
[Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

## Gotchas

- A streaming request without `stream_options` gets `include_usage` added so
  the proxy can count tokens. The client did not ask for this setting. Set
  `observability.force_usage_reporting: false` to turn it off. The proxy does
  not add it on the Responses and Messages paths.
- `base_url` with a path fails the load.

## Limitations

- The proxy forwards the body. It does not translate Chat Completions to
  Responses or the reverse.
- Key rotation needs a `SIGHUP` reload or a restart.
- See [Limitations](/docs/llm-proxy/help/limitations/).
