---
title: Configuration file
description: "Write an llmproxy.yaml file: how the blocks relate, strict parsing, environment variables, validation, and three complete examples."
lastUpdated: 2026-10-18
related:
  - configuration/reference
  - getting-started/quickstart
  - providers-and-routing/providers-and-clusters
  - operations/config-reload
---

# Configuration file

The configuration file is a YAML file that you pass with `--config`. This page
shows how the file is built, how its blocks depend on each other, and how to
check a file before you start the proxy.

Field definitions are not on this page. Each field, its type, its default and
its rules are in the [Configuration field reference](../reference/). That page
is generated from `schema/llmproxy-v0.schema.json`, the normative schema. If
this page and the reference disagree, the reference is right. Report the
difference.

## How the file is structured

The file has one top-level block for each job. Read the blocks in this order.
Each block builds on the one before it.

| Block | Job | Depends on |
|---|---|---|
| [`version`](../reference/#top-level) | Names the schema version. Always `0`. | Nothing |
| [`providers`](../reference/#provider) | Names each upstream LLM API and holds its credentials. | Nothing |
| [`routes`](../reference/#route) and [`models`](../reference/#modeldef) | Choose a provider (or an ordered list of providers) for each requested model name. | `providers` |
| [`auto`](../reference/#automodel) | Resolves the reserved model name `auto` to a real model. | `routes` or `models`; `auth` for per-tenant entries |
| `guardrails` | Sends each request body to an HTTP check that allows or denies it. See [Request guardrails](../../authentication/guardrails/). | `auth` for per-tenant entries |
| [`auth`](../reference/#auth) | Checks who the caller is, and which models the caller may use. | Nothing |
| [`limits`](../reference/#limit) | Limits requests, tokens and concurrent streams. | `auth` for the `tenant` key |
| [`pricing`](../reference/#pricing) | Gives each completed request a price. | `providers` (the `type` of each provider) |
| [`observability`](../reference/#observability) | Writes access logs and exports metrics and traces. | `auth` for `traces` |
| [`ledger`](../reference/#ledger) | Writes one encrypted entry for each request sent to a provider. | `--service-node` |
| [`listen`](../reference/#listener) and `admin` | Set the addresses the proxy binds. | Nothing |

A request moves through the blocks in this way:

1. The listener accepts the request. If `auth` is set, the proxy then
   identifies the caller.
2. The proxy reads the `model` name from the request.
3. The proxy applies `routes` from top to bottom. The first route whose
   `model` pattern matches wins. If no route matches, the proxy applies the
   `models` entry for the name.
4. The proxy sends the request to the first provider in the chosen list. It
   moves to the next provider on failure.
5. The proxy sends the request with the credentials of the provider it
   dialled.
6. `limits`, `pricing` and `observability` use the result.

Credentials and other values that vary by provider belong to the provider, not
to the route. After a failover, the request carries the credentials of the
fallback provider only. The page
[Providers and clusters](../../providers-and-routing/providers-and-clusters/)
explains this.

## Strict parsing and errors

Parsing is strict. An unknown or misspelled field is a load error. The error
names the full dotted path of the field. The proxy never ignores a field
silently, and no option turns this off for a `--config` file.

For example, `fallback` instead of `fallbacks` gives this error:

```text
unknown field at `routes[0].fallback`: not a recognized llm-proxy configuration field at this position (the configuration is always strict; see schema/llmproxy-v0.schema.json for valid fields)
```

The top-level keys `envoy`, `tracing` and `clusters` are reserved for a future
schema version. The proxy rejects them in version 0. To export traces, use
`observability.tracing`.

The editor can check the file while you type. Point a YAML language server at
`schema/llmproxy-v0.schema.json`.

## Environment variables

Any string in the file can contain `${VAR_NAME}`. The proxy replaces each
reference with the value of the environment variable before it parses the
file. Use this for secrets, so the file can be stored in version control.

- A variable name has letters, digits and underscores only.
- A reference to an unset variable is a load error. The error names the
  variable.
- Write `$${` to get a literal `${`.
- The proxy does not replace references in YAML comments.

```text
invalid value at `providers.openai.api_key`: environment variable `OPENAI_API_KEY` is not set (referenced as ${OPENAI_API_KEY})
```

The proof is `interpolate_env` in `crates/proxy-simple-config/src/parse.rs`.

## Secrets from files

Most secret fields have a `*_file` form that reads the value from a file. A
secret manager that mounts files can supply these files. The `*_file` form and
the inline form of one field exclude each other. The reference lists each pair
and the rule for it.

| Kind | Fields |
|---|---|
| Provider credentials | `api_key_file`, `access_token_file`, `access_key_id_file`, `secret_access_key_file`, `session_token_file`, `oauth2_jwt_bearer.private_key_file` |
| Authentication | `auth.hmac_secret_file`, `auth.store.shared.url_file` |
| Encryption keys | `auth.tenant_credentials.encryption_key_file`, `ledger.encryption_key_file` |
| Price list | `pricing.price_list_file` |

Which files a `SIGHUP` reload reads again, and which settings need a restart,
is in [What a reload applies](../../operations/config-reload/#what-a-reload-applies).

## Validate a file

Check a file before you start the proxy. `--mode validate` loads the file,
checks it, and exits. It binds no listener and sends no request.

```bash
llm-proxy --config llmproxy.yaml --mode validate
```

A valid file prints one line and exits with code 0. The counts depend on the
file:

```text
configuration 'llmproxy.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

An invalid file prints each error with its path and exits with code 1. Read the
warning count too. A warning marks a setting that loads but may not do what you
expect. For example, an `auth` block with no keys is a warning.

`validate` reads the same environment variables as `serve`. Set the same
variables, and pass `--service-node` if the file needs it. See
[Rules that span fields](#rules-that-span-fields).

`--mode translate` prints the Envoy bootstrap configuration that the proxy
builds from your file. Use it to see what a setting becomes. Secrets print as
`[REDACTED]` unless you pass `--reveal-secrets`.

```bash
llm-proxy --config llmproxy.yaml --mode translate
```

The flags are in the [command-line reference](../../reference/cli/).

## Example: the smallest file

This file sends every request to OpenAI. The provider name `openai` implies the
provider type and the base URL.

```yaml
version: 0
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
```

Validate it with a dummy key:

```bash
OPENAI_API_KEY=sk-dummy llm-proxy --config min.yaml --mode validate
```

```text
configuration 'min.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

## Example: authentication, limits and pricing

This file adds three things to the smallest file. A virtual key identifies the
caller. Two limits protect the providers. A rate card prices each request.

```yaml
version: 0
listen: 0.0.0.0:8080
admin: 127.0.0.1:9901

auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  keys:
    - id: alice-laptop
      tenant: acme
      digest: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a

providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes:
  - model: "gpt-*"
    provider: openai

limits:
  - key: global
    requests_per_minute: 1000
  - key: tenant
    tokens_per_minute: 100k
    concurrent_sessions: 5

pricing:
  price_list:
    version: "2026-10"
    effective_from: "2026-10-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: gpt-4o-mini
        tier_mode: whole_request
        tiers:
          - input_nanodollars_per_token: 150
            cached_input_nanodollars_per_token: 75
            cache_write_nanodollars_per_token: 150
            output_nanodollars_per_token: 600
```

The `digest` is a placeholder. Make a real key and its digest with
`llm-proxy --mode keygen --tenant acme --key-id alice-laptop`. The command uses
the secret in `LLMPROXY_AUTH_SECRET`. The digest depends on the secret, so a
digest made with another secret does not match.

```bash
OPENAI_API_KEY=sk-dummy LLMPROXY_AUTH_SECRET=dummy-secret \
  llm-proxy --config auth.yaml --mode validate
```

```text
configuration 'auth.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

Three links connect the blocks in this file:

- The `tenant` limit needs the `auth` block. Without it, the file does not
  load.
- The `tenant` on each key is the account that the limit and the budget count.
- The price list has one entry for each `provider_type` and `model` pair.
  `provider_type` is the type of the provider that served the request. A
  request for a model with no entry has no price.

Tenant model grants, budgets and per-tenant limits are not in the file. You
set them with the admin API. See [Virtual keys](../../authentication/virtual-keys/).

## Example: failover

This file has a route with a fallback, and two `models` entries. The `routes`
entry sends `gpt-4*` requests to OpenAI. If OpenAI fails, the proxy tries
`local-vllm`. The `assistant` entry lists two providers in priority order. The
`claude-sonnet` entry maps one client name to a dated upstream model name.

```yaml
version: 0

providers:
  anthropic:
    api_key: ${ANTHROPIC_API_KEY}
  openai:
    api_key: ${OPENAI_API_KEY}
  local-vllm:
    base_url: http://vllm.internal:8000

routes:
  - model: "gpt-4*"
    provider: openai
    fallbacks: [local-vllm]
    retries:
      attempts: 2

models:
  assistant:
    max_output_tokens: 4096
    providers:
      - openai/gpt-4o-mini
      - local-vllm/llama-3.3-70b
  claude-sonnet:
    providers:
      - anthropic/claude-sonnet-4-5-20250929
```

```bash
OPENAI_API_KEY=sk-dummy ANTHROPIC_API_KEY=sk-dummy \
  llm-proxy --config failover.yaml --mode validate
```

```text
configuration 'failover.yaml' OK (1 listener(s), 5 cluster(s), 0 warning(s))
```

The `local-vllm` provider has no key. It has the type `openai-compatible`,
because its name is not one of the three names that imply a type. Every
provider in one chain must speak the same wire dialect, so you cannot add
`anthropic` as a fallback for `openai`. See
[Failover and aggregates](../../providers-and-routing/failover-and-aggregates/).

## Rules that span fields

These rules involve more than one block. Each rule is stated once here. The
field reference holds the definition of each field.

### Which rule routes a request

- The proxy applies [`routes`](../reference/#route) first, from top to bottom.
  The first match wins. It does not reorder routes by how specific they are.
  Put specific patterns above broad ones.
- A [`models`](../reference/#modeldef) entry works as an implicit route that
  the proxy applies after `routes`. A route with the pattern `*` therefore
  hides every `models` entry.
- A request that matches nothing gets a `404` with a JSON body that lists the
  known models.
- The file needs at least one entry in `routes`, or at least one entry in
  `models`.
- If you set [`auto`](../reference/#automodel), a `models` key or a
  `routes[].model` of `auto` is a load error. See
  [The auto model](../../providers-and-routing/auto-model/).

### Chains stay in one dialect

Every provider in `routes[].fallbacks` and in `models.<name>.providers` must
speak the same wire dialect as the first provider. A mismatch is a load error.
The proxy does not translate between dialects.

A `vertex` or `bedrock` provider can serve more than one dialect. A route
cannot say which one. Use a `models` entry in the object form, and set
`dialect` in it.

### Settings that need an `auth` block

| Setting | Why |
|---|---|
| [`limits[].key: tenant`](../reference/#limit) | Nothing else identifies a tenant. |
| [`auto.tenants`](../reference/#automodel) | The entries use the tenant names from `auth`. |
| [`observability.traces`](../reference/#traces) | Only a tenant can opt in. |
| [`providers.<name>.tenant_credentials`](../reference/#provider) | It needs `auth.tenant_credentials`. That block needs a durable `auth.store`: `persistent` or `shared`. |

With `auth` set, a tenant that has no stored model policy is refused with a
`403`. Set a policy with the admin API, or set
[`auth.enforce.tenants_without_policy`](../reference/#authenforce) to `allow`.
Setting a control in `auth.enforce` to `false` removes that control and logs a
warning at load. See [Virtual keys](../../authentication/virtual-keys/).

### Settings that need `--service-node`

The dialect has no field for the node identity of a replica. These settings
need the `--service-node` flag, with a value that is unique to the replica and
stable across restarts:

- [`auth.store.shared`](../reference/#authstore). Without the flag, the load
  error names `auth.store.shared`.
- [`ledger`](../reference/#ledger).
- [`observability.traces`](../reference/#traces).

The setup of a shared store is in
[Running in production](../../operations/running-in-production/).

### Prices and budgets

- Spend budgets use the price from [`pricing`](../reference/#pricing). With
  `auth.enforce.spend` on and no `pricing`, every request costs `$0`, and the
  proxy warns at load.
- A request for a model with no price entry is charged `$0` under a dollar
  budget, and is not refused. See
  [Spend policies](../../limits-and-budgets/spend-policies/).
- With `auth` set, `auth.store` holds the rate card. A change to `pricing` in
  the file does not replace a card that the store already holds. See the
  [`pricing` reference](../reference/#pricing).

### Syntax that is not yet applied

The `provider/model` form is applied in a `models` entry. In `routes[].provider`
and `routes[].fallbacks`, the proxy accepts the form but does not rewrite the
model. The client's model name goes upstream unchanged, and the load logs a
warning that names the field. See [`ProviderModelRef`](../reference/#providermodelref).

## Where each feature is explained

The field reference defines the fields. These pages explain how to use them.

| Topic | Page |
|---|---|
| Provider types, base URLs, Azure OpenAI, Vertex, Bedrock, OpenRouter | [Providers and clusters](../../providers-and-routing/providers-and-clusters/) |
| Fallbacks and ordered `models` lists | [Failover and aggregates](../../providers-and-routing/failover-and-aggregates/) |
| Retries and timeouts | [Timeouts and retries](../../providers-and-routing/timeouts-and-retries/) |
| Virtual keys, tenants and the HMAC secret | [Virtual keys](../../authentication/virtual-keys/) |
| Tenant provider credentials | [Tenant provider credentials](../../authentication/tenant-provider-credentials/) |
| Request, token and concurrency limits | [Token rate limiting](../../limits-and-budgets/token-rate-limiting/) |
| Budgets and the rate card | [Spend policies](../../limits-and-budgets/spend-policies/) |
| The billing ledger | [Billing ledger](../../limits-and-budgets/billing-ledger/) |
| Access logs, metrics and tracing | [Observability overview](../../observability/overview/) |
| The `/v1/models` and `/v1/embeddings` endpoints | [API compatibility](../../api-compatibility/overview/) |
| TLS on the listener and the handshake deadline | [TLS](../../operations/tls/) |
| Changing a file while the proxy runs | [Reload configuration](../../operations/config-reload/) |

## What the file does not express

The file has no field for a route that replies with a redirect. That action
exists only in an Envoy bootstrap configuration loaded with `-c`. Every route
in a `--config` file forwards to a provider.
