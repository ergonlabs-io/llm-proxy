---
title: Strict config mode
description: How llm-proxy rejects unknown config fields with the full dotted path, and what the load-time warnings mean.
summary: >-
  Strict parsing is always on for a --config file. This page shows the exact
  error and warning text, explains why --permissive has no effect, and lists
  every load-time warning.
lastUpdated: 2026-10-21
related:
  - configuration/configuration-file
  - configuration/models-and-routes
  - reference/cli
  - help/limitations
---

llm-proxy does not ignore a config field that it does not understand. Every
field must map to something the proxy implements, or the load fails with the
full dotted path of the field. A setting that the proxy accepts and then
ignores looks like it works, so the proxy refuses it. Use this page to read a
load error and to understand the warnings that the proxy prints before it
keeps running.

## At a glance

- **Default:** strict. You cannot turn it off for a `--config` file.
- **`--permissive`:** has no effect on a `--config` file. It relaxes unknown
  fields only for a bootstrap file that you load with `-c`. A `--config` error
  does not suggest the flag.
- **Failure mode:** a bad file stops the proxy before it binds a port. A
  warning does not stop the proxy.

## What strict mode checks

| Check | Result |
|---|---|
| Unknown field | Load error with the full dotted path. |
| Reserved top-level key (`envoy`, `tracing`, `clusters`) | Load error. |
| Bad value (type, range, enum, cross-field rule) | Load error with the full dotted path. |
| Environment variable that is not set | Load error. The error names the variable. |
| Setting that loads but may not do what its name suggests | Load-time warning. |

## Read an error

When a load fails, the proxy prints two lines to stderr and exits with code 1:

```text
configuration 'llmproxy.yaml' INVALID
  <error>
```

The `<error>` line has one of the forms below. The path is always the full
dotted path. List positions are in square brackets.

### Unknown field

A misspelled key, such as `api_keyy`, gives this error:

```text
unknown field at `providers.openai.api_keyy`: not a recognized llm-proxy configuration field at this position (the configuration is always strict; see schema/llmproxy-v0.schema.json for valid fields)
```

The valid fields are in the [field reference](/docs/llm-proxy/configuration/reference/).
That page is generated from the schema.

### Reserved top-level key

The format reserves three top-level keys for a later schema version: `envoy`,
`tracing`, and `clusters`. Version 0 rejects them:

```text
unsupported field `clusters`: `clusters` is reserved for a future schema version; v0 rejects it so it can be added compatibly later (strict mode; see https://ergonlabs.io/docs/llm-proxy/help/limitations/)
```

To export traces, use `observability.tracing`.

### Invalid value

```text
invalid value at `routes[0].provider`: unknown provider `nonexistent` (defined providers: openai)
```

These are other texts that you can meet:

| Cause | Path | Reason text |
|---|---|---|
| `version` is not `0` | `version` | `this build understands schema version 0, not <n>` |
| No providers | `providers` | `at least one provider is required` |
| No routes and no models | `routes` | `at least one route or model is required` |
| Two key sources | `providers.<name>` | `set either api_key or api_key_file, not both` |
| Unknown provider name | `routes[<i>].provider` | ``unknown provider `<name>` (defined providers: <list>)`` |
| Retries above the limit | `routes[<i>].retries.attempts` | `at most 5 retry attempts are allowed` |
| `*` in the wrong place in a `models` key | `models.<key>` | ``<key> is not a supported model pattern -- `*` may appear at most once, ...`` |
| Same `models` key twice | `models` | ``duplicate `models` entry `<key>` -- each catalogue key must be ...`` |
| Weights on some entries only | `models.<name>.providers[<i>]` | ``... sets `weight` on another entry, so every entry needs one ...`` |
| Session affinity on an unweighted model | `models.<name>.session_affinity` | ``session affinity pins a session to one provider of a weighted split; set `weight` on every entry of `providers` `` |
| Bad listen address | `listen` | ``` `<value>` is not `host:port` ``` |
| Environment variable not set | the field that uses it | ``environment variable `<NAME>` is not set (referenced as ${<NAME>})`` |

For the environment variable error, the proxy names the field when it can find
it. If it cannot, the error starts with `failed to parse config:` and has no
path.

If you pass a bootstrap file to `--config`, the load fails with
`this looks like an Envoy bootstrap; use -c instead of --config`. The `-c`
option is outside the scope of these pages.

## Warnings that do not stop the proxy

A warning marks a file that loads but may not do what you expect. The proxy
prints each warning to stderr before it starts, in this form:

```text
warning: `pricing`: spend budgets are enforced but no `pricing` rate card is set, so every request costs zero and a budget never fires; set `pricing` to meter spend
```

`--mode validate` prints the same warnings and reports their count. A reload
logs each warning at level `warn` with the message `config reload warning`.
A warning does not change the exit code.

The `llmproxy` dialect produces these warnings:

| Path | When | Meaning |
|---|---|---|
| `auth.keys` | `auth` has no keys, no JWT provider, no `admin` address, and no `persistent` or `shared` store. | The block authenticates nothing. It refuses every request (fails closed). Add a key or remove `auth`. |
| `auth.enforce.model_policy` | You set it to `false`. | Tenant model allow-lists are not enforced. Every tenant can call every routed model. The admin API refuses `PUT /tenants/{id}/policy`. |
| `auth.enforce.tenants_without_policy` | You set it to `allow` while model policy is on. | A tenant with no stored model policy can use every model. |
| `auth.enforce.limits` | You set it to `false` and the file has no `limits`. | Tenant and key limits are not enforced. The admin API refuses `PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits`. |
| `auth.enforce.object_ownership` | You set it to `false`. | A tenant that knows the ID of another tenant's file or batch can read, cancel, or delete it. A list returns every tenant's objects. |
| `auth.enforce.spend` | You set it to `false`. | Spend budgets never refuse a request. The admin API refuses `PUT /tenants/{id}/budget`. |
| `pricing` | Spend is enforced and the file has no `pricing`. | Every request costs zero. A budget never fires. |
| `pricing.price_list_file` | You use a price list file. | The proxy reads the file at startup and on each reload. With an `auth` store, the stored rate card wins over a changed file. |
| `auth.hmac_secret_file` | You use a secret file. | The proxy reads the file at startup and on each reload. A reload that changes the secret is refused. Rotation needs a restart. |
| `providers.<name>.api_key_file` | You use a key file. | The proxy reads the file at startup and on each reload. To rotate the key, replace the file and reload. |
| `providers.<name>.<field>_file` | You use a credential file (for example `access_token_file`). | The same rule as `api_key_file`. |
| `providers.<name>.ca_file` | The provider uses `http://`. | The proxy ignores the file for a plaintext provider. |
| `routes[<i>].provider` and `routes[<i>].fallbacks[<j>]` | The value uses the form `provider/model`. | The proxy does not change the model for a route. It forwards the original model name. See [Models and routes](/docs/llm-proxy/configuration/models-and-routes/#the-upstream-model-name). |

The warnings for the `auth.enforce.*` settings need an `auth` block. Each one
names a control that you switched off. Read the warnings at startup.

The proxy does not watch any file that a warning names. A reload reads the
file again. See [Reload configuration](/docs/llm-proxy/operations/config-reload/).

## Limitations

- A warning does not change the exit code. `--mode validate` exits with code 0
  when the only findings are warnings.
- The field check covers the fields in the schema. It cannot tell you that a
  value is wrong for your provider.
- `--mode validate` reads the same environment variables as `serve`. Set them
  before you validate.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.
