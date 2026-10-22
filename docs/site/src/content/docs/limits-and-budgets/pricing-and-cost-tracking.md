---
title: Pricing and cost tracking
description: Define a versioned rate card in nanodollars, price each completed request in tokens, images, characters or audio seconds, and replace the card at run time.
summary: >-
  How the proxy prices a request from the rate card in the `pricing` block,
  which endpoints it can price and in which unit, which provider the charge
  uses after failover, where the cost appears, and how to read and replace the
  card.
lastUpdated: 2026-10-21
related:
  - limits-and-budgets/spend-policies
  - limits-and-budgets/token-rate-limiting
  - limits-and-budgets/billing-ledger
  - observability/access-logs
  - observability/request-capture
  - authentication/tenant-provider-credentials
  - providers/openrouter
---

The proxy prices each completed request from the usage in the provider
response. The price comes from a versioned rate card that you supply in the
`pricing` block. The proxy writes the result to the access log, to the request
record, and to the spend budgets. Use this page to set up the card, to read
what the proxy charged, and to replace the card without a restart.

Spend budgets themselves are on
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

## At a glance

- **Default when unset:** no card. A request has no price and no cost in the
  record. With `auth:` set and no card, a spend budget never fires, and the
  proxy warns at load.
- **Failure mode:** a request that the card cannot price is unpriced. The
  access log shows `-` for it. The spend budget adds $0 for it and the proxy
  logs a warning. The proxy still serves the request. It is never a priced
  zero.
- **Unit:** integer nanodollars. One nanodollar is 1e-9 USD.

## Example

This file prices one OpenAI model. The two rates are examples, not a
provider's prices. Check the file with `llm-proxy --config llmproxy.yaml
--mode validate`.

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
pricing:
  price_list:
    version: example-2026-10
    effective_from: "2026-10-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: example-chat-model
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 150
            cached_input_nanodollars_per_token: 75
            cache_write_nanodollars_per_token: 200
            output_nanodollars_per_token: 600
```

A request with 100 input tokens, no cached tokens, no cache-write tokens, and
50 output tokens costs `100 * 150 + 50 * 600 = 45000` nanodollars.

The access log prints the price in nanodollars, or `-` when the request is
unpriced. See [Where the cost appears](#where-the-cost-appears).

## What the proxy prices

Each rate-card entry has a `basis`. The basis is the unit that the entry
prices. An entry prices only its own basis, so one request is never charged
twice for the same work.

| `basis` | Unit | Rate field |
|---|---|---|
| `tokens` (default) | Token buckets of the response `usage`. | `tiers[]` |
| `images` | Images that the response returned. | `image_prices[]` |
| `characters` | Characters of the speech request `input`. | `nanodollars_per_character` |
| `audio_seconds` | Audio duration that the response reports. | `nanodollars_per_second` |

The next table shows which endpoints the proxy can price, and in which unit.

| Endpoint | Priced in |
|---|---|
| Chat completions, completions, Responses, Messages, embeddings | `tokens` |
| Image generation, image edits | `images`, or `tokens` for models that bill images in tokens |
| Speech | `characters`, or `tokens` |
| Transcription, translation | `audio_seconds`, or `tokens` |
| Realtime sessions | `tokens`, from the `response.done` events of the session |

The proxy cannot price other endpoints, such as batches and files. A spend
budget or token limit that applies to a request for one of them refuses it
with `403` and the detail `endpoint_not_metered`. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/#endpoints-a-budget-cannot-count).

The proxy computes the price after the response ends. A stream that ends early
is priced from an estimate, and the cost kind is `estimate`. See
[Cut streams and estimated charges](/docs/llm-proxy/limits-and-budgets/spend-policies/#cut-streams-and-estimated-charges).

A request is unpriced in these cases:

- The response has no usage of the entry's basis.
- The card has no entry for the pair of provider type and model.
- The entry sets `cached_input_unpriced` and the request reports cache-read
  tokens.
- The entry sets `cache_write_unpriced` and the request reports cache-write
  tokens.
- An `images` entry has no row for the size and quality of the request.

## Token pricing

A `tokens` entry has four text buckets. Each bucket has its own rate.

| Bucket | Rate field |
|---|---|
| Input tokens, not cached | `input_nanodollars_per_token` |
| Cache-read input tokens | `cached_input_nanodollars_per_token` |
| Cache-write input tokens | `cache_write_nanodollars_per_token` |
| Output tokens | `output_nanodollars_per_token` |

All math is integer math. It saturates and does not wrap.

### Image and audio token rates

Some models report image or audio tokens inside the input or output count. A
tier can set one rate for each of these four kinds:

- `image_input_nanodollars_per_token`
- `image_output_nanodollars_per_token`
- `audio_input_nanodollars_per_token`
- `audio_output_nanodollars_per_token`

Set each of these on every tier of the entry, or on none. A card that sets one
on only some tiers is a load error.

If a tier sets a rate, the proxy splits those tokens out of their text bucket
and charges them at that rate. If the tier does not set it, the proxy charges
them at the text rate. The request is then counted in
`llmproxy_usage_underpriced_modality_requests_total`. Under a spend budget the
proxy also logs a warning. The charge is never lower than the text rate, but it
can be lower than the provider's price.

### Tiers

The proxy picks a tier from the context size: input plus cache-read plus
cache-write tokens. Output tokens do not move a request to a higher tier. The
`up_to` value is inclusive. A request with exactly `500000` context tokens
stays in a tier with `up_to: 500000`.

| `tier_mode` | Effect |
|---|---|
| `whole_request` | The tier that holds the context size prices every bucket of the request. |
| `graduated` | The context is laid out in order: cache-read tokens, cache-write tokens, then input tokens. The proxy cuts it into bands. Each token costs its own bucket's rate in the band that holds its position. Output tokens cost the rate of the tier that the whole context selects. |

There is no default `tier_mode`, because the two modes give different prices.

For example, a model has one tier with `up_to: 1000` at 1000 nanodollars per
input token, and an open last tier at 2000. A request has 1500 input tokens
and no output.

- `whole_request`: `1500 * 2000 = 3,000,000` nanodollars.
- `graduated`: `1000 * 1000 + 500 * 2000 = 2,000,000` nanodollars.

## Image pricing

An `images` entry prices the number of images in the response. Each row of
`image_prices` can name a `size`, a `quality`, both, or neither (the rates here
are examples):

```yaml title="pricing.price_list.entries (fragment)"
- provider_type: openai
  model: example-image-model
  basis: images
  image_prices:
    - { nanodollars_per_image: 70000000 }
    - { size: "1024x1024", quality: high, nanodollars_per_image: 90000000 }
```

- The proxy counts the elements of the top-level `data` array of a JSON
  response, or the `*.completed` events of a stream.
- The proxy reads `size` and `quality` from the response. If the response does
  not show them, it reads them from the request body.
- The most specific row that matches wins: both attributes, then one, then
  none. Values match as exact strings.
- Two rows that one request can match at the same specificity are a load
  error.
- A cut image response is charged for the images that were complete.

Models that bill images in tokens, such as `gpt-image-1`, use `basis: tokens`
with the image token rates above.

## Speech and transcription pricing

Two more bases price audio (the rates here are examples):

```yaml title="pricing.price_list.entries (fragment)"
- provider_type: openai
  model: example-speech-model
  basis: characters
  nanodollars_per_character: 15000      # 15 USD per million characters
- provider_type: openai
  model: example-transcription-model
  basis: audio_seconds
  nanodollars_per_second: 100000        # 0.006 USD per minute
```

- `characters` counts the Unicode code points of the request `input` after
  JSON unescaping. The charge is the characters times the rate. The proxy
  charges it only when the response status is 2xx.
- `audio_seconds` uses the duration that the response reports: `usage.seconds`
  of a `duration` usage, else `usage.prompt_audio_seconds`, else the
  top-level `duration` of a `verbose_json` response. The proxy prices it per
  millisecond and rounds up to a whole nanodollar. There is no minimum
  duration.
- Models that report tokens, such as `gpt-4o-transcribe`, use `basis: tokens`.

The file `examples/llmproxy-media.yaml` in the repository is a complete card
for these endpoints. It states which provider facts are assumptions until you
check them against a recorded response.

## Rounding

The rate card works in nanodollars. A spend budget works in micro-dollars. The
proxy rounds each charge up to a whole micro-dollar, so a charge is never lower
than the price. The access log and the request record show the price in
nanodollars. The [billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/)
shows the charge in micro-dollars.

## The charge follows the provider that served the request

The proxy prices with the provider that the router dialled, not the provider
that the route named. After a failover, the price is the fallback provider's
price. Three parts make this work:

- The card holds a `providers` map from the name of a dialled provider to its
  provider type. The proxy fills the map from your `providers` block. The keys
  have the form `provider:<name>`, for example `provider:openai`.
- The price uses the model ID that the proxy sent to the provider, after any
  model rewrite. If there is no rewrite, it uses the requested model.
- If the provider reports a different served model, and the card has an entry
  for that model on the same provider type, the proxy prices the served model.
  If the card has no entry for the served model, the proxy keeps the model it
  sent.

## Requests that use a tenant credential

A request that uses a stored tenant credential has a price like any other
request. The access log field `llm_credential_source` shows `tenant` for it.
Whether the price counts toward a spend budget depends on the budget scope
(`credential_source` on a tenant budget, `include_byok_in_limit` on a key
budget). See
[Budgets](/docs/llm-proxy/authentication/tenant-provider-credentials/#budgets).

## Where the cost appears

| Where | What you see |
|---|---|
| Access log | The field `llm_list_cost_nanodollars` holds the price in nanodollars, or `-` when the request is unpriced. `rate_card_version` holds the card version. `llm_cost_kind` is `list` or `estimate`. `llm_price_basis` is the basis that priced the request. See [Access logs](/docs/llm-proxy/observability/access-logs/). |
| Request records | Each record has a `cost` object with `amount`, `unit` (`nanodollars`), `currency`, `rate_card_version` and `kind`. It has `price_basis` and `credential_source`. See [Request capture](/docs/llm-proxy/observability/request-capture/). |
| Billing ledger | Each entry has `charged_micro_usd`, `charged_scopes` and `rate_card_version`. See [Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/). |
| Spend reports | `GET /keys/{id}/spend` and `GET /tenants/{id}/spend` give the micro-dollars charged to a budget period. See [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/). |
| `GET /pricing` | The active card. |

The counter `llmproxy_spend_charged_micro_usd_total` adds up the
micro-dollars that spend budgets charged. It has no labels. No metric carries a
tenant, a key, or a model. `GET /v1/usage` reports tokens only. It has no cost
field.

## Fields

The field reference is generated from the schema. See the
[`pricing` section](/docs/llm-proxy/configuration/reference/#pricing). This
section lists the fields that this page explains.

| Field | Type | Default | Description |
|---|---|---|---|
| `pricing.price_list` | object | none | Inline price list. Set exactly one of `price_list` or `price_list_file`. |
| `pricing.price_list_file` | string | none | Path to a YAML or JSON price list with the same fields as `price_list`. |
| `pricing.catalog` | object | none | Public source metadata for the admin pricing inventory. The proxy never uses it as a rate. |
| `price_list.version` | string | none | Human label. |
| `price_list.effective_from` | RFC 3339 date-time | none (required) | Date of the list, shown in `GET /pricing`. A future date is an error. |
| `price_list.entries[]` | list | none (1 or more required) | One entry for each pair of `provider_type` and `model`. |
| `entries[].provider_type` | string | none (required) | Provider type, for example `openai`. It matches the type of the provider that served the request. |
| `entries[].model` | string | none (required) | Exact, case-sensitive model name. |
| `entries[].basis` | `tokens`, `images`, `characters`, `audio_seconds` | `tokens` | What the entry prices. |
| `entries[].tier_mode` | `whole_request` or `graduated` | none | Required for `tokens`. Not allowed for the other bases. |
| `entries[].tiers[]` | list | none | Required for `tokens` (1 or more). Not allowed for the other bases. |
| `tiers[].up_to` | integer | none | Inclusive upper bound of context tokens. Leave it out on the last tier only. |
| `tiers[].*_nanodollars_per_token` | integer, 0 or more | none (4 required) | Rate for each of the four text buckets. |
| `tiers[].image_*` and `audio_*` rates | integer, 0 or more | none | Optional rates for image and audio tokens. Set on every tier or on none. |
| `entries[].image_prices[]` | list | none | Required for `images` (1 or more). Rows of `size`, `quality` and `nanodollars_per_image`. |
| `entries[].nanodollars_per_character` | integer, 0 or more | none | Required for `characters`. |
| `entries[].nanodollars_per_second` | integer, 0 or more | none | Required for `audio_seconds`. |
| `entries[].cached_input_unpriced` | boolean | `false` | A request that reports cache-read tokens stays unpriced. Only for `tokens`. |
| `entries[].cache_write_unpriced` | boolean | `false` | A request that reports cache-write tokens stays unpriced. Only for `tokens`. |

The load step names the bad field with its full dotted path. These checks run
at load:

- `effective_from` is RFC 3339, and it is not in the future.
- The list has at least one entry.
- A pair of `provider_type` and `model` appears once.
- A `tokens` entry has `tier_mode` and at least one tier.
- The `up_to` values increase, and exactly one open-ended tier is last.
- An entry sets only the fields of its own basis.

### Version

The recorded version is the label plus a short content hash, for example
`example-2026-10+3f9a1c0b2d44`. The hash covers the prices and the map of
providers. If you edit a rate and keep the label, the hash still changes. The
hash does not cover `effective_from`. Every cost in a request record carries
the version.

A card that uses `basis`, `image_prices`, `nanodollars_per_character`,
`nanodollars_per_second` or an image or audio token rate is stored at rate-card
schema version 2. An older replica ignores such a card and keeps its last
card. Upgrade every replica before you publish such a card.

## Read and replace the card at run time

`GET /pricing` returns the active card. It needs no token.

```bash
curl --max-time 5 http://127.0.0.1:53422/pricing
```

```json
{
  "rate_card_version": "example-2026-10+3f9a1c0b2d44",
  "price_list": {
    "version": "example-2026-10",
    "effective_from": "2026-10-01T00:00:00+00:00",
    "entries": [
      {
        "cached_input_unpriced": false,
        "cache_write_unpriced": false,
        "provider_type": "openai",
        "model": "example-chat-model",
        "tier_mode": "whole_request",
        "tiers": [
          {
            "up_to": null,
            "input_nanodollars_per_token": 150,
            "cached_input_nanodollars_per_token": 75,
            "cache_write_nanodollars_per_token": 200,
            "output_nanodollars_per_token": 600
          }
        ]
      }
    ]
  },
  "providers": { "provider:openai": "openai" }
}
```

If no card is active, `GET /pricing` returns `503` with the text
`llmproxy.usage has no active pricing rate card`.

`PUT /pricing` replaces the card. It needs the admin token. Send the keys
`price_list` and `providers`, and optionally `catalog`. These are the keys that
`GET` returns. Remove `rate_card_version` first, because the proxy rejects
unknown keys. The body limit for this route is 4 MiB.

```bash
curl --max-time 10 -X PUT http://127.0.0.1:53422/pricing \
  -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @new-card.json
```

The response is `200` with three keys: `rate_card_version`, `persisted`, and
`note`. The `note` tells you where the card now lives. A request already in
flight keeps the card that it started with. A new request uses the new card.

| Status | Cause |
|---|---|
| `400` | The body is not valid JSON, has an unknown key, or fails a check above. The text names the field. The old card stays. |
| `401` | The bearer token is missing or wrong. |
| `403` | `LLMPROXY_ADMIN_TOKEN` is not set on the proxy. |
| `413` | The body is larger than 4 MiB. |
| `503` | The auth store refused the card. Nothing changed. |

The admin UI **Pricing** tab shows the card and the catalog. See
[Admin UI](/docs/llm-proxy/administration/admin-ui/) and
[Admin API](/docs/llm-proxy/administration/admin-api/).

## Where the active card lives

The place depends on `auth.store`:

| Setup | Effect of `PUT /pricing` |
|---|---|
| No `auth:` block | The card applies to this process only. A restart loads the card from the config file. |
| `auth.store: in_memory` | The card lives in memory. A restart loses it, and the proxy loads the card from the config file. |
| `auth.store: persistent` | The card survives a restart. Other replicas do not read it. |
| `auth.store: shared` | Every replica that shares the store installs the card on its next policy poll. The poll runs about every 48 seconds. |

With an `auth.store`, the stored card wins over the config file. The proxy
seeds the store from the config file only when the store has no card. A
restart does not undo a card that you published.

A `price_list_file` is read at startup and on each `SIGHUP` reload. If the
reload changes the configured card and the store already holds a card, the
store keeps the active card. The proxy logs this warning: `the reloaded pricing
was not applied: the rate card in the control-plane store stays in force;
publish with PUT /pricing to replace it`. Use `PUT /pricing` to replace a
stored card.

Without an `auth.store`, a reload that changes the configured card installs it.
A reload that removes `pricing` clears the card, and the proxy logs a warning.
A reload that does not change `pricing` keeps a card that you published with
`PUT /pricing`.

A card that is dated after the clock of a replica is not installed there. This
can happen when another replica with a faster clock published it. The replica
keeps its current card and tries again on each policy poll.

## The OpenRouter example

`examples/llmproxy-openrouter.yaml` is a complete dialect file with a large
catalog of models and their prices. The importer script
`scripts/import-openrouter-models.py` writes the rates as integer nanodollars.
See [OpenRouter](/docs/llm-proxy/providers/openrouter/).

A `catalog` entry is information only. A model that is in the catalog and not
in the price list has no price.

## Limitations

- The card prices list rates only. It does not apply a discount or a contract
  rate.
- A card does not schedule a price change. A card applies from the moment the
  proxy installs it.
- Tier selection uses the input context size only. Output tokens never pick a
  tier.
- The proxy cannot price batches, files, and other endpoints that report no
  usage. A spend budget or token limit refuses them.
- Cost has no per-tenant, per-key, or per-model metric series. Read cost from
  the access log, the request records, the ledger, and the spend reports.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.
