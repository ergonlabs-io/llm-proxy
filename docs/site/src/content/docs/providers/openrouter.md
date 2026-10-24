---
title: OpenRouter
description: Route to OpenRouter with one key, import its model catalog and token rates with a script, and fail over from a direct provider.
summary: The OpenRouter provider block, the /v1 to /api/v1 path rewrite, the
  generated catalog example, the denied request fields, and the pricing
  snapshot.
lastUpdated: 2026-10-21
related:
  - providers/overview
  - limits-and-budgets/pricing-and-cost-tracking
  - configuration/models-and-routes
  - providers-and-routing/failover-and-aggregates
---

The `openrouter` type sends OpenAI-shaped requests to `https://openrouter.ai`.
OpenRouter serves its API under `/api/v1`, and OpenAI clients call `/v1`. The
proxy rewrites the path prefix on the provider, so the client needs no change.

## At a glance

- **Default behavior:** type `openrouter` and `base_url`
  `https://openrouter.ai` when the provider is named `openrouter`.
- **Path rewrite:** the prefix `/v1` becomes `/api/v1`. The query string of
  the client is kept.
- **Auth:** `Authorization: Bearer <api_key>`.
- **Dialect:** `openai`.

## Minimal example

```yaml title="llmproxy.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

providers:
  openrouter:
    api_key: ${OPENROUTER_API_KEY}

routes:
  - model: "*"
    provider: openrouter
```

1. Set the key and check the file.

   ```bash
   export OPENROUTER_API_KEY=sk-or-...
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
     -d '{"model":"anthropic/claude-sonnet-4.5","messages":[{"role":"user","content":"hi"}]}'
   ```

The request reaches `https://openrouter.ai/api/v1/chat/completions`. The
proxy forwards the client model name unchanged, so use the OpenRouter model
IDs.

## Fields

| Field | Type | Default | Required | Description |
|---|---|---|---|---|
| `type` | enum | `openrouter` when the name is `openrouter` | no | Set `openrouter` to use another provider name. |
| `base_url` | URI | `https://openrouter.ai` | no | Scheme, host, and optional port. No path. |
| `api_key`, `api_key_file` | string | none | no | Set one of the two. |
| `extra_headers` | map | empty | no | For example `HTTP-Referer` and `X-Title`. The proxy does not set them. |
| `request_fields` | object | none | no | `deny` and `strip` lists of top-level body keys. See [Fields the importer denies](#fields-the-importer-denies). |
| `tenant_credentials` | boolean | `false` | no | Let a tenant send its own key. The default verify path is `/api/v1/key` when `base_url` is unset. |
| `ca_file`, `connect_timeout`, `protocol` | | system roots, `5s`, `http1` | no | Common fields. See the [provider overview](/docs/llm-proxy/providers/overview/). |

## Model names with slashes

OpenRouter IDs contain a slash, for example `aion-labs/aion-2.0`. The
`provider:` value in `routes` is read as `provider/model`. The first slash
splits the name. Do not put an OpenRouter ID in `routes[].provider`. Match the
ID in `routes[].model`, or use it as a `models` key. Both forms take the ID as
a model pattern.

## Import the whole catalog

The script `scripts/import-openrouter-models.py` calls
`https://openrouter.ai/api/v1/models` and writes two files. It needs Python 3
and no extra packages.

```bash
export OPENROUTER_API_KEY=sk-or-...
python3 scripts/import-openrouter-models.py \
  --out examples/llmproxy-openrouter.yaml \
  --pricing-out examples/openrouter-pricing.json
```

Without the variable, the script asks for the key. With `--prompt-key`, it
always asks, and it does not echo the key.

- `--out` is an `llmproxy` configuration file. JSON is valid YAML, and the
  script writes JSON. It has one `models` entry for each catalog ID. Each entry
  points at `openrouter` with the same ID as `model:`. It sets `routes: []`.
- `--pricing-out` is a snapshot of the public catalog and prices.
- The `pricing.price_list` block holds integer nanodollar token rates. The
  `pricing.catalog` block holds the snapshot. The proxy never uses the catalog
  as a rate. See
  [Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/).

The checked-in example `examples/llmproxy-openrouter.yaml` was generated at
`2026-10-09T04:01:00Z`. It has 469 model entries and 438 exact rate cards. The
script skips a model whose input or output rate is dynamic or is not a whole
number of nanodollars, or whose price tiers are not valid. It records the
reason in `billing_status` in the snapshot. For a model with no cache rate, or a
cache rate it cannot represent, the script sets that rate to 0 and flags the
entry `cached_input_unpriced` or `cache_write_unpriced`. The script does not
price non-token charges. Run the script again to refresh the files. The counts
change over time.

Check the generated file:

```bash
export OPENROUTER_API_KEY=sk-or-...
llm-proxy --config examples/llmproxy-openrouter.yaml --mode validate
```

The generated file listens on `127.0.0.1:8080` and puts the admin listener on
`127.0.0.1:9901`. It does not use the ports `53421` and `53422`. Edit `listen`
and `admin` if you need other ports. The `/v1/models` endpoint lists the exact
IDs from `models`. It does not list wildcard keys.

### Fields the importer denies

The generated provider block sets `request_fields.deny` to `models`, `route`,
`plugins`, and `transforms`. OpenRouter accepts these body fields to pick other
models, enable paid plugins, or rewrite prompts. They bypass the model access
rules of the proxy, which see only the `model` that the client names. A client
request with one of these keys gets a `400` with the body
`request field not permitted: <field>`. To allow a field, remove it from the
list in the generated file. The proxy has no built-in list for OpenRouter. The
list is part of the generated file only.

## Fail over from a direct provider

```yaml title="Fragment: OpenAI direct, OpenRouter as fallback"
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  openrouter:
    api_key: ${OPENROUTER_API_KEY}

routes:
  - model: gpt-*
    provider: openai
    fallbacks: [openrouter]
```

Both providers use the `openai` dialect, so the chain loads. The fallback sends
the OpenRouter key and the `Host` `openrouter.ai`. The model name is forwarded
unchanged. OpenRouter names OpenAI models `openai/gpt-5`, so a client name such
as `gpt-5` may not exist there. To map the name, use a `models` entry with
`model: openai/gpt-5` on the `openrouter` entry:

```yaml title="Fragment: upstream names for each provider"
models:
  gpt-5:
    providers:
      - openai
      - { provider: openrouter, model: openai/gpt-5 }
```

The `openai` entry has no `model:`, so it keeps the client name. The
`openrouter` entry replaces the model in the body with `openai/gpt-5`.

## Gotchas

- The path rewrite matches the prefix `/v1`. A client that calls `/api/v1`
  directly is not rewritten.
- A `base_url` of `https://openrouter.ai/api/v1` fails the load, because
  `base_url` cannot carry a path.
- Pricing covers token rates only. OpenRouter routes to many providers, and the
  snapshot is a copy from one point in time.

## Limitations

- The proxy changes the request body only for a `models` `model:` rewrite, the
  `request_fields` policy, and the `include_usage` addition.
- The pricing snapshot does not refresh itself.
- See [Limitations](/docs/llm-proxy/help/limitations/).
