---
title: Models and routes
description: Match the model name in a request to a provider with routes, or give clients a stable name with the models catalog.
summary: >-
  How llm-proxy picks a provider from the model name in the request. Covers
  the pattern grammar of routes and of the models catalog, first-match order,
  precedence inside the catalog, the upstream model name for each provider,
  the /v1/models list, and the 404 for an unmatched model.
lastUpdated: 2026-10-21
related:
  - configuration/configuration-file
  - configuration/strict-config-mode
  - providers-and-routing/failover-and-aggregates
  - providers-and-routing/load-balancing
  - getting-started/core-concepts
---

The proxy reads the `model` name of a request. It matches the name against an
ordered list of rules. It sends the request to the first provider of the first
rule that matches. You write rules in two places: `routes` and `models`. Use
`routes` to send a family of model names to one provider. Use `models` to give
clients a stable name that you can move between providers.

## At a glance

- **Default when unset:** a request that matches no rule gets a `404` with the
  error type `model_not_found`.
- **Failure mode:** fails closed. An unknown model never reaches a provider
  unless you add a catch-all (`*`).
- **Order:** the proxy checks `routes` from top to bottom. Then it checks the
  `models` catalog. Then it returns the `404`.

## Minimal example

```yaml title="llmproxy.yaml"
version: 1
listen: 0.0.0.0:53421
admin: 127.0.0.1:53422

providers:
  openai:
    api_key: ${OPENAI_API_KEY}
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
  xai:
    type: openai-compatible
    base_url: https://api.x.ai
    api_key: ${XAI_API_KEY}

routes:
  - model: gpt-*
    provider: openai
    fallbacks: [xai]
  - model: claude-*
    provider: anthropic

models:
  fast:
    providers:
      - openai/gpt-4o-mini
      - xai/grok-2-latest
```

Set the three API keys in the environment. Then check the file:

```bash
export OPENAI_API_KEY=sk-... ANTHROPIC_API_KEY=sk-ant-... XAI_API_KEY=xai-...
llm-proxy --config llmproxy.yaml --mode validate
```

The command prints a line that starts with `configuration 'llmproxy.yaml' OK`.

With this file:

- A request for `gpt-4o` goes to `openai`.
- A request for `claude-sonnet-4-5` goes to `anthropic`.
- A request for `fast` goes to `openai`, and the body carries `gpt-4o-mini`.
  If `openai` fails, the proxy tries `xai` and the body carries
  `grok-2-latest`.
- A request for any other name gets a `404`.

## How the proxy reads the model name

For a JSON request, the proxy reads the `model` field of the body. For a
realtime WebSocket request, it reads the `model` query parameter. The proxy
writes the name to the internal request header `x-llmproxy-model`. The rules
match on that header.

A client cannot choose its own route with that header. The proxy overwrites
the header with the name from the body. If the request has no model, or the
body is not JSON, the proxy removes the header.

## Routes

`routes` is an ordered list. The proxy tests the rules from top to bottom.
The first rule that matches wins. The proxy does not reorder rules by
specificity. Put specific patterns above broad ones.

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | string | required | Pattern matched against the request model. It is case-sensitive. |
| `provider` | string | required | A key in `providers`. |
| `fallbacks` | list of strings | none | Providers to try, in order, when the first provider fails. |
| `retries.attempts` | integer, 0 to 5 | `1` | Extra attempts. A value above 5 is a load error. |
| `idle_timeout` | duration | `90s` | Maximum time with no bytes flowing. There is no total timeout. |
| `streaming` | `strict` | unset | Fail the load if a filter can buffer a response on this route. |

The full field list is in the
[field reference](/docs/llm-proxy/configuration/reference/).

### Route pattern grammar

The shape of the pattern decides how the proxy matches it.

| Pattern shape | Example | Matches |
|---|---|---|
| No `*` | `gpt-5` | That exact name only. |
| One `*`, at the end | `gpt-5*` | Any name that starts with `gpt-5`, including `gpt-5`. |
| `*` alone | `*` | Every request. |
| Any other use of `*` | `a*b`, `*-mini` | A regular expression. Each `*` becomes `.*`. The proxy escapes all other characters. |

Only `*` is a wildcard. The characters `?`, `[`, and `]` are literal. For
example, the pattern `o[0-9]*` has one `*` at the end. It is a prefix match on
the literal text `o[0-9]`. It does not match `o3-mini`. Write `o1*`, `o3*`,
and `o4*` as separate rules.

### Catch-all and the 404

If no rule matches, the proxy answers `404` with this body:

```json
{"error":{"message":"no route matched the requested model","type":"model_not_found"}}
```

The proxy adds this `404` rule only when no catch-all exists. A catch-all is a
route with `model: "*"` or a `models` key of `*`. To make an unknown model an
error, do not add a catch-all. See [Errors](/docs/llm-proxy/api-compatibility/errors/)
for all proxy errors.

## Fallbacks

`fallbacks` lists extra providers. The chain is the first provider and then
each fallback, in the order you write them. Each retry moves to the next
provider in the chain.

- Every provider in the chain must speak the same dialect as the first
  provider. A chain that crosses dialects is a load error at
  `routes[<i>].fallbacks[<j>]`. For example, `openai` to `anthropic` is
  rejected. `openai` to an `openai-compatible` provider is accepted.
- Each provider gets its own credentials and its own `Host` header. A fallback
  never receives the credentials of the first provider.
- Failover needs retries. The proxy raises the retry count to at least the
  number of fallbacks. So `retries.attempts: 0` does not turn off failover on
  a route that has fallbacks.
- The proxy retries on a connection failure, a refused stream, a reset, and
  the status codes 429, 500, 502, and 503.

See [Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/)
for the runtime behavior.

## The upstream model name

A provider can receive a different model name than the client sent. The client
sees no change. The form `provider/model` sets the name. Two places accept the
form, and they behave differently.

| Where you write `provider/model` | What the proxy does |
|---|---|
| `models.<name>.providers[]` | The proxy replaces the `model` field of the JSON body. The name belongs to that provider, so a fallback uses its own upstream name. |
| `routes[].provider` or `routes[].fallbacks[]` | The proxy loads the file and prints a warning. It forwards the original model name unchanged. |

The proxy prints one warning for each route reference that uses this form. The
warning names the path `routes[<i>].provider` or `routes[<i>].fallbacks[<j>]`.
Use a `models` entry when you need a different upstream name.

How the replacement works:

1. Each provider keeps a list of pairs. A pair is a `models` key and an
   upstream model name. The pairs follow the catalog precedence order.
2. After the proxy chooses the provider, it finds the first pair whose key
   matches the model of the request.
3. The proxy writes the upstream name to the `model` field of the body.
4. For `vertex` and `bedrock` providers, the proxy writes the name into the
   URL path instead.

If the body is not a JSON object, or its `model` differs from the routed
model, the proxy answers `400` with the text `provider model rewrite failed`.

The pairs belong to the provider. They apply to every request that reaches the
provider and matches the key. This includes requests that arrived through
`routes`.

## The models catalog

`models` maps a client-facing name to an ordered list of providers. Each entry
creates a route for its own name. The proxy checks the catalog after `routes`
and before the `404`.

| Field | Type | Default | Description |
|---|---|---|---|
| `providers` | list | required, at least one | Each item is a string (`provider` or `provider/model`) or an object. |
| `providers[].provider` | string | required | A key in `providers`. |
| `providers[].model` | string | the catalog key | The model name sent to this provider. |
| `providers[].dialect` | `openai` or `anthropic` | derived from the provider type | Required for `vertex` and `bedrock` providers. Only the object form can set it. |
| `providers[].weight` | integer, 0 to 1000000 | none | Share of first picks. Set it on every entry or on none. See [Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/). |
| `max_output_tokens` | integer, 1 or more | none | Largest output-token limit a request may ask for. A larger request gets `400`. |
| `session_affinity` | object | none | Pin a session to one weighted provider. See [Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/#keep-a-session-on-one-provider). |

A `models` entry has no `retries` or `idle_timeout` field. The route that the
proxy builds uses an `idle_timeout` of `90s` and no total timeout.

### Catalog key grammar

The catalog keys use a narrower grammar than `routes[].model`.

| Key shape | Example |
|---|---|
| Exact name | `fast` |
| One `*`, at the end | `gpt-4*` |
| `*` alone | `*` |

A `*` anywhere else is a load error at the path `models.<key>`. These keys
fail: `*-4o`, `gpt-*-mini`, `**`, and `a*b*`. A duplicate key is a load error
at the path `models`.

### Precedence inside the catalog

When more than one key matches, the order is fixed. An exact name wins. Then
the longest matching prefix wins. Then `*` wins. The key order in the YAML file
does not matter.

For example, the keys `gpt-4o`, `gpt-4*`, `gpt-*`, and `*` give this result:

| Request model | Key that wins |
|---|---|
| `gpt-4o` | `gpt-4o` |
| `gpt-4-turbo` | `gpt-4*` |
| `gpt-3.5-turbo` | `gpt-*` |
| `llama-3` | `*` |

### Fallback inside the catalog

A `models` entry with more than one provider is an ordered failover chain. The
retry count is the number of providers minus one. The retry status codes are
the same as for `routes`. All providers in one entry must speak the same
dialect. A mismatch is a load error at `models.<name>.providers[<i>]`.

## The `/v1/models` list

The proxy answers `GET /v1/models` itself when it has at least one exact name
to list. It lists every exact name from `routes[].model` and from the `models`
keys. The list is sorted and has no duplicates. A name that contains `*` is a
rule, not a model, so the list omits it. Each item has `owned_by` set to
`llm-proxy`.

If a config has only wildcard names, the proxy does not answer
`GET /v1/models`. The request follows the normal route match.

When `auth` is set and `auth.enforce.model_policy` is on, the proxy lists only
the models that the caller may use. That setting is on by default.

The local list route sits after all model routes and before the first
catch-all or the `404`.

## Common mistakes

| Symptom | Cause | Fix |
|---|---|---|
| A `models` alias returns `404` or goes to the wrong provider. | A `routes` rule with `model: "*"` matches first. The proxy always checks `routes` before `models`. | Move the broad rule into `models`, or remove it. |
| Load error ``unknown provider `xyz` (defined providers: openai, anthropic)``. | A `provider` or fallback names a key that is not in `providers`. | Fix the name. The error path is `routes[<i>].provider`. |
| Load error at `models.<key>` about `*`. | The key puts `*` in the middle or uses more than one. | Use an exact name or one `*` at the end. |
| Load error at `routes[<i>].fallbacks[<j>]` that names two dialects. | The fallback speaks a different dialect than the first provider. | Use a provider of the same dialect. |
| A route with `provider: openai/gpt-4o-mini` still sends the client model name. | `routes` does not apply the model part. | Use a `models` entry. |

## Limitations

- Pattern matching sees only the `model` value. It cannot match on tenant,
  user, header, or path.
- `routes[].provider: prov/model` does not change the model. Use `models`.
- `models` entries cannot set `retries` or `idle_timeout`.
- Fallback chains cannot cross dialects. The proxy does not translate request
  or response bodies.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.
