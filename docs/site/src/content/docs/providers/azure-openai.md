---
title: Azure OpenAI
description: Configure an Azure OpenAI deployment with the api-key header, a deployment path rewrite, and the api-version query value.
summary: The azure-openai provider block, the three required fields, the path
  and query rewrite, and the load errors for bad values.
lastUpdated: 2026-10-21
related:
  - providers/overview
  - providers/openai
  - providers-and-routing/failover-and-aggregates
---

The `azure-openai` type sends OpenAI-shaped requests to one Azure OpenAI
deployment. Azure puts the deployment name in the URL path and the API version
in the query string. The proxy builds both from the provider block, so standard
OpenAI clients work without a change.

## At a glance

- **Default behavior:** none. `base_url`, `deployment`, and `api_version` are
  all required.
- **Auth:** `api-key: <api_key>`. Not `Authorization`.
- **Dialect:** `openai`.
- **Fails closed or open:** a missing or unsafe field fails the load with its
  field path.

## Minimal example

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  azure:
    type: azure-openai
    base_url: https://my-resource.openai.azure.com
    deployment: gpt-4o-prod
    api_version: 2024-10-21
    api_key: ${AZURE_OPENAI_API_KEY}

routes:
  - model: "*"
    provider: azure
```

1. Set the key and check the file.

   ```bash
   export AZURE_OPENAI_API_KEY=...
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
     -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'
   ```

The name `azure` does not imply a type. You must write `type: azure-openai`.

## What the proxy sends

For the request above, the proxy changes the path prefix and the query:

| Part | Client sends | Azure receives |
|---|---|---|
| Path | `/v1/chat/completions` | `/openai/deployments/gpt-4o-prod/chat/completions` |
| Query | none, or any | `api-version=2024-10-21` only |
| Header | none | `api-key: <api_key>` |

The rewrite replaces the whole query string. A query value from the client does
not survive. A request with `?client=ignored` reaches Azure with only
`api-version=...`.

## Fields

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `type` | enum | `openai-compatible` | yes: set `azure-openai` | |
| `base_url` | URI | none | yes | Scheme, host, and optional port, for example `https://my-resource.openai.azure.com`. No path. |
| `deployment` | string | none | yes | Azure deployment name. ASCII letters, digits, `-`, `.`, `_`, `~`. |
| `api_version` | string | none | yes | Sent as `api-version`. Same character set. |
| `api_key`, `api_key_file` | string | none | no | Set one of the two. |
| `extra_headers`, `ca_file`, `connect_timeout`, `protocol` | | empty, system roots, `5s`, `http1` | no | Common fields. See the [provider overview](/docs/llm-proxy/providers/overview/). |
| `tenant_credentials` | boolean | `false` | no | Let a tenant send its own key. |

The proxy rejects `deployment` and `api_version` on any other provider type.
The [field reference](/docs/llm-proxy/configuration/reference/) lists every
field.

## Load errors

Each error starts with ``invalid value at `<path>`:``.

```text
invalid value at `providers.azure.deployment`: deployment is required for azure-openai providers
invalid value at `providers.azure.api_version`: api_version is required for azure-openai providers
invalid value at `providers.azure.deployment`: must contain only ASCII letters, digits, hyphen, dot, underscore, or tilde
invalid value at `providers.x.deployment`: deployment is only valid for azure-openai providers
```

The last error appears when you set `deployment` on a provider that is not
`azure-openai`. This includes a provider named `azure` with no `type`.

## One provider is one deployment

A deployment belongs to the provider, not to the request. To serve two
deployments, declare two providers and give each its own route:

```yaml title="Fragment: two deployments"
providers:
  azure-gpt4o:
    type: azure-openai
    base_url: https://my-resource.openai.azure.com
    deployment: gpt-4o-prod
    api_version: 2024-10-21
    api_key: ${AZURE_OPENAI_API_KEY}
  azure-mini:
    type: azure-openai
    base_url: https://my-resource.openai.azure.com
    deployment: gpt-4o-mini-prod
    api_version: 2024-10-21
    api_key: ${AZURE_OPENAI_API_KEY}

routes:
  - model: gpt-4o-mini*
    provider: azure-mini
  - model: gpt-4o*
    provider: azure-gpt4o
```

The first matching route wins, so the more specific pattern comes first.

## Failover

Azure uses the `openai` dialect. It can fail over to `openai`, `openrouter`, or
an `openai-compatible` provider, and the reverse. Each member sends its own
`Host` and its own key.

```yaml title="Fragment: Azure first, OpenAI second"
providers:
  azure:
    type: azure-openai
    base_url: https://my-resource.openai.azure.com
    deployment: gpt-4o-prod
    api_version: 2024-10-21
    api_key: ${AZURE_OPENAI_API_KEY}
  openai:
    api_key: ${OPENAI_API_KEY}

routes:
  - model: gpt-4o*
    provider: azure
    fallbacks: [openai]
```

## Gotchas

- The body `model` is forwarded unchanged. Azure selects the model from the
  deployment in the path.
- The path match is the prefix `/v1`. A client that calls `/openai/...`
  directly is not rewritten.
- Only the `api-key` header is available. The `azure-openai` type does not
  support Microsoft Entra ID tokens.

## Limitations

- One deployment for each provider.
- No Entra ID (bearer token) auth for Azure.
- `base_url` cannot carry a path.
- See [Limitations](/docs/llm-proxy/help/limitations/).
