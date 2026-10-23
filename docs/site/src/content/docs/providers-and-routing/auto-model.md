---
title: The auto model
description: "Let a client send model \"auto\" and have the proxy replace it with the model the operator chose for the tenant."
summary: How the reserved model name `auto` resolves to a real model for each
  tenant, which load errors the `auto` block can cause, and what the provider
  and the logs see.
lastUpdated: 2026-10-21
related:
  - configuration/configuration-file
  - configuration/models-and-routes
  - providers-and-routing/failover-and-aggregates
  - observability/access-logs
  - authentication/virtual-keys
---

A client sends `"model": "auto"`. The proxy replaces `auto` with a model
name that the operator chose for the caller's tenant. The client does not
choose a provider. The operator chooses the model, and the routes choose the
provider.

Use `auto` when the operator, not the client, must decide which model a
tenant gets. To enable it in the `llmproxy` dialect, add a top-level `auto`
block with a `default` model. See [Configure the auto model](#configure-the-auto-model).

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

## Configure the auto model

Use the top-level `auto` key. The schema is `schema/llmproxy-v1.schema.json`
(property `auto` and `$defs/AutoModel`).

```yaml
version: 1
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
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/)) that authenticated the request.

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
[Access logs](/docs/llm-proxy/observability/access-logs/).

**Price and budgets.** The proxy prices and authorizes the resolved model.

## Authorization of the resolved model

With `auth` set and `auth.enforce.model_policy` on (the default), the proxy
authorizes the resolved model, not `auto`. A tenant limited to `gpt-4*` can use
`auto` only while `auto` resolves inside that grant. The resolver never widens
a grant. The proxy runs the resolver before the model policy check.

## Limits of this feature

- The rules are static. Change them, then reload the config.
- There is no external resolver. The rules in the `auto` block are the only
  source.
- The rule key is the tenant only. The resolver does not read the user, the
  prompt, or a header.

## Implementation notes

This section is for maintainers.

- Resolver: `ModelResolverFilterInstance::resolve` in
  `crates/proxy-filters/src/model_resolver_filter.rs`. Proto:
  `crates/proxy-api/vendor/llmproxy/filters/v0/model_resolver.proto`.
- Dialect lowering: `model_resolver_typed_config` in
  `crates/proxy-simple-config/src/lower.rs`. Load checks: `validate_auto` in
  `crates/proxy-simple-config/src/parse.rs`. The check that the resolver runs
  after `llmproxy.auth` and `llmproxy.body_rewrite` and before
  `llmproxy.model_authz`: `check_lane_h_filter_order` in
  `crates/proxy-config/src/lower.rs`.
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
