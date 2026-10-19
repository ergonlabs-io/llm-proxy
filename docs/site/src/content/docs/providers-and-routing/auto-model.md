---
title: The auto model
description: "Let a client send model \"auto\" and have the proxy replace it with the model the operator chose for the tenant."
summary: How the reserved model name `auto` resolves to a real model for each
  tenant, what the provider and the logs see, and the Envoy-mode filter and
  its ordering rules.
lastUpdated: 2026-10-18
related:
  - configuration/configuration-file
  - providers-and-routing/failover-and-aggregates
  - observability/access-logs
  - authentication/virtual-keys
---

# The auto model

A client sends `"model": "auto"`. The proxy replaces `auto` with a model
name that the operator chose for the caller's tenant. The client does not
choose a provider. The operator chooses the model, and the routes choose the
provider.

Use `auto` when the operator, not the client, must decide which model a
tenant gets. To enable it in the `llmproxy` dialect, add a top-level `auto`
block with a `default` model. See [Simple config](#simple-config).

`auto` is a model alias, not a provider selector. The resolver picks a model
name. The `routes` and `models` entries then pick the provider and the
failover chain for that name.

## What a request sees

A request whose `model` is not `auto` is not changed.

For a request whose `model` is `auto`, the proxy does these steps:

1. It looks up the authenticated tenant in the rules.
2. If the tenant has no rule, it uses the default model. A request with no
   authenticated tenant also gets the default model.
3. It routes the request as the resolved model.
4. It refuses the request with status 400 if no model is found.

The refusal body is `no model is configured for `auto``. The
`%RESPONSE_CODE_DETAILS%` value is `auto_model_not_configured`. No provider
is dialled.

The resolver runs at the end of the request body, because the model is read
from the body. It decides once for each request.

## Simple config

Use the top-level `auto` key. The schema is `schema/llmproxy-v0.schema.json`
(property `auto` and `$defs/AutoModel`).

```yaml
version: 0
providers:
  openai:
    type: openai
    api_key: ${OPENAI_API_KEY}
  anthropic:
    type: anthropic
    api_key: ${ANTHROPIC_API_KEY}
routes:
  - model: gpt-4o-mini
    provider: openai
  - model: claude-sonnet
    provider: anthropic
auto:
  default: gpt-4o-mini
```

With this file, a request for `auto` goes to the `openai` provider as
`gpt-4o-mini`.

The `providers` and `routes` fields follow the schema (`$defs/Provider`,
`$defs/Route`).

### Per-tenant models

Use `auto.tenants` to give each tenant its own model. The tenant is the
`tenant` of the `auth.keys` entry (see
[Virtual keys](../../authentication/virtual-keys/)) that authenticated the request.

```yaml
auth:
  hmac_secret: ${AUTH_HMAC_SECRET}
  keys:
    - id: acme-prod
      tenant: acme
      digest: <digest of the virtual key>
auto:
  default: gpt-4o-mini
  tenants:
    acme: claude-sonnet
```

Tenant `acme` gets `claude-sonnet`. Every other tenant gets `gpt-4o-mini`.

| Field | Type | Default | What it does |
|---|---|---|---|
| `auto.default` | string | none | The model for a tenant with no entry, and for a request with no tenant. With no default, such a request gets 400. |
| `auto.tenants` | object, tenant to model | none | The model for each named tenant. Needs an `auth` block. |

### Load errors

The proxy checks the block at load time. Each error names its field path.

| Field path | Cause |
|---|---|
| `auto` | The block has no `default` and no `tenants`. |
| `auto.tenants` | The block has `tenants` and the file has no `auth` block. |
| `auto.tenants` | A tenant name is empty. |
| `models.auto` | A `models` key is exactly `auto`. |
| `routes[N].model` | A route `model` is exactly `auto`. |
| `auto.default` or `auto.tenants.<tenant>` | The model is empty, is `auto`, or contains `*`. |
| `auto.default` or `auto.tenants.<tenant>` | No route and no `models` entry serves the model. |

While the `auto` block is set, `auto` is reserved. Without the block, `auto`
is an ordinary model name.

## What the provider and the logs see

**Provider.** The proxy replaces the `model` in the request body after it
picks the cluster. The provider gets the resolved name. If
the cluster maps that name to an upstream model, the provider gets the
upstream model. The provider never gets `auto`.

**Client.** The proxy sends the provider's response to the client without
change. The `model` field in the response is the model that the provider
served, not `auto`.

**Logs.** `requested_model` stays `auto`. A new field, `resolved_model`,
holds the resolved name. It is `-` in a text log, and `null` in a usage
record, when nothing was resolved. See
[Access logs](../../observability/access-logs/).

**Price and budgets.** The proxy prices and authorizes the resolved model.

## Envoy mode

The filter is `llmproxy.model_resolver`. Its `typed_config` type is
`llmproxy.filters.v0.ModelResolver`. The `llmproxy` dialect lowers `auto` to
this filter.

```yaml
http_filters:
  - name: llmproxy.auth
    # ...
  - name: llmproxy.body_rewrite
    # ...
  - name: llmproxy.model_resolver
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.ModelResolver
      rules:
        default_model: gpt-4o-mini
        tenants:
          - tenant: acme
            model: claude-sonnet
  - name: llmproxy.model_authz
    # ...
```

| Field | Meaning |
|---|---|
| `rules.default_model` | The model for an unlisted tenant or no tenant. Empty means no default. |
| `rules.tenants[].tenant` | Required and unique. Matches the tenant that `llmproxy.auth` wrote. |
| `rules.tenants[].model` | Required. Must not be `auto` and must not contain `*`. |

Exactly one resolver branch must be set. The only branch is `rules`.

### Filter order

The proxy checks the order at load time. A wrong order is a load error.

- `llmproxy.auth` must come before `llmproxy.model_resolver`.
- `llmproxy.body_rewrite` must come before `llmproxy.model_resolver`.
- `llmproxy.model_resolver` must come before `llmproxy.model_authz`.
- `llmproxy.body_rewrite` is required. Without it the load fails.

`llmproxy.model_authz` authorizes the resolved model, not `auto`. The
resolver never widens a grant. The simple config does not
emit `model_authz`, so this applies in Envoy mode only.

## Limits of this feature

- The rules are static. Change them, then reload the config.
- There is no external resolver. The proto has a `oneof` for one later, but
  `rules` is the only branch.
- The rule key is the tenant only. The resolver does not read the user, the
  prompt, or a header.

## Implementation notes

This section is for maintainers.

- Resolver: `ModelResolverFilterInstance::resolve` in
  `crates/proxy-filters/src/model_resolver_filter.rs`. Proto:
  `crates/proxy-api/vendor/llmproxy/filters/v0/model_resolver.proto`.
- Dialect lowering: `model_resolver_typed_config` in
  `crates/proxy-simple-config/src/lower.rs`. Load checks: `validate_auto` in
  `crates/proxy-simple-config/src/parse.rs`. Envoy filter order:
  `check_lane_h_filter_order` in `crates/proxy-config/src/lower.rs`.
- Body rewrite: `rewrite_cluster_provider_model` in
  `crates/proxy-http/src/router.rs`. Pricing model:
  `StreamInfo::routing_model` in `crates/proxy-http/src/stream_info.rs`.
- Tests: `a_concrete_model_is_routed_unchanged` in
  `crates/proxy-simple-config/tests/model_resolver_routing.rs`;
  `auto_with_no_rule_is_refused_with_400_and_dials_nothing`;
  `auto_resolved_to_an_unmapped_alias_reaches_its_provider_as_the_alias`;
  `auto_resolved_to_a_mapped_alias_reaches_its_provider_as_the_upstream_model`;
  `a_resolved_model_is_authorized_instead_of_the_trigger` in
  `crates/proxy-filters/src/model_authz_filter.rs`.
