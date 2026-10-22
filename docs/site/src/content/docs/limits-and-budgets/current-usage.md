---
title: Read current usage
description: "Call GET /v1/usage to read the token budget that remains for the tenant of the key you present."
summary: How an authenticated caller reads the current-window token usage of
  its own tenant, the response fields, the status codes, and what the
  endpoint does not report.
lastUpdated: 2026-10-21
related:
  - limits-and-budgets/token-rate-limiting
  - authentication/virtual-keys
  - observability/access-logs
  - configuration/configuration-file
---

`GET /v1/usage` returns the token usage of the tenant that owns the key you
present. The proxy answers the call itself. It never sends the call to a
provider. Use it to show a caller how much of its token limit remains in the
current window, without an operator reading logs.

To set the limits that this endpoint reports, see
[Configure rate limits](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/).

## At a glance

- **Default when unset:** the proxy does not answer the call. It routes
  `GET /v1/usage` as an ordinary request.
- **Needs:** an `auth:` block and a token limiter in the filter chain.
- **Failure mode:** fails closed. With no authenticated tenant, the answer is
  `401`. With a `shared` store that cannot be read, the answer is `503`. The
  endpoint never answers with a guess.

## What the endpoint reports

The endpoint reports the standing of the current window. It reports each
`limits` entry with `key: tenant` and `tokens_per_minute`. Such a rule does not
depend on the route, so its row has `route` set to `*`. A rule with `models`
adds its scope to the name, for example `*|models=gpt-4o`. Two rules on the
same bucket give one row with the lower limit.

Entries keyed on `global`, `client-ip`, or a header do not appear. Request
limits, concurrent-stream limits, and tenant and key limits set through the
admin API do not appear. To see that usage, read the `429` headers or the
[access log](/docs/llm-proxy/observability/access-logs/).

## Requirements

Two conditions must be true.

1. **Configure `auth:`.** The tenant in the response comes only from the
   identity that the `llmproxy.auth` filter verified. Without `auth:`, no
   tenant exists, and the endpoint answers `401`. It never answers `200` on a
   listener with no `auth:` block.
2. **Have a token limiter.** The endpoint is part of the token limiter. The
   proxy adds the limiter when the config has a `limits` entry. It also adds
   the limiter when `auth:` is set and `auth.enforce.limits` is `true`. With
   neither, `GET /v1/usage` is an ordinary request and the proxy does not
   answer it.

### The key scopes the answer

There is no tenant parameter. The proxy does not read a query parameter, a
header, or a path segment to choose whose usage to return. A caller reads only
the budget of the key it presents. A path that only starts with `/v1/usage`,
such as `/v1/usage/other`, is not this endpoint. The proxy routes it as a
normal request.

## Example

The dialect config below enforces a tenant limit. The endpoint reports it as
the route `*`.

```yaml title="llmproxy.yaml"
version: 0
listen: 127.0.0.1:53421
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  keys:
    - id: alice-laptop
      tenant: acme
      digest: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a
      revoked: false
limits:
  - key: tenant
    tokens_per_minute: 100000
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
```

```sh
curl --max-time 5 -s http://127.0.0.1:53421/v1/usage \
  -H "Authorization: Bearer llmp_<the key>"
```

The caller gets status `200` and `content-type: application/json`. The body
below is for a tenant that used 2,200 tokens, 43 seconds into the current
window:

```json
{"routes":[{"limit":100000.0,"remaining":97800.0,"reset_after_seconds":17,"route":"*","used":2200.0}],"tenant":"acme","window":"fixed"}
```

The proxy writes the fields in alphabetical order. Parse the response as
JSON. Do not depend on the order.

## Response fields

| Field | Type | What it is |
|---|---|---|
| `tenant` | string | The authenticated caller's tenant, as set in `auth.keys[].tenant`. |
| `window` | string | Always `"fixed"`. The limiter uses a fixed window. |
| `routes` | array of objects | One entry for each route that holds a current-window budget for this tenant. Empty if the tenant has no such budget, or has not been counted yet. An empty array is a correct answer, not an error. |
| `routes[].route` | string | The route name the budget is counted under. |
| `routes[].used` | number | Weighted tokens used in the current window. |
| `routes[].limit` | number | The configured `tokens_per_minute` cap for this window. |
| `routes[].remaining` | number | `limit - used`. The lowest value is zero. |
| `routes[].reset_after_seconds` | integer | Seconds until the current window ends. |

## Status codes

| Status | When | Body |
|---|---|---|
| `200` | An authenticated tenant. | The JSON body above. A tenant with no budgets gets `routes: []`. |
| `401` | No authenticated tenant: no `auth:` block on the listener, no credential presented, or the credential was rejected. | `unauthorized` (plain text, no usage data). |
| `503` | `auth.store` is `shared`, and the store returned an error or did not answer within about 2 seconds. | `usage unavailable` (plain text), with `retry-after: 1`. |

The source of the numbers depends on `auth.store`:

- **`in_memory` or `persistent`:** One replica holds the counters. The
  endpoint answers from them, and the answer is exact.
- **`shared`:** The endpoint reads the fleet totals from the store, for every
  route of the listener. A replica that never served a route still reports the
  usage that other replicas counted on it. The read does not block the worker.
  Requests for the same tenant share one read. The proxy reuses an answer for
  about 1 second, so frequent calls do not add load on the store. The numbers
  can lag the replica's own latest requests by up to one reconcile interval
  (about 1 second).

If the store read fails, the endpoint answers `503`. It does not use the
counters of the replica. A replica that has not served a route would report 0
for it, and that number is wrong.

## Limitations

- **No history.** It reports only the current fixed window. You cannot ask for
  the usage of an earlier hour or week. A historical export is not available.
- **No cost.** The response has no dollar or currency field. The rate card
  prices each completed request, and the access log shows the price in
  nanodollars as `%LLM_LIST_COST%`. To total the cost of one tenant, sum
  `%LLM_LIST_COST%` by `%LLM_TENANT%` in your log pipeline. See
  [Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/)
  and the
  [access log reference](/docs/llm-proxy/observability/access-logs/#the-operator-set).
  For a dollar total from the proxy, read the spend reports. See
  [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Each behavior above has this source or test.

- Interception, source of the tenant, and rows:
  `crates/proxy-filters/src/token_limit_filter.rs` (`decode_headers`,
  `USAGE_PATH`, `usage_entries`, `render_usage_response`).
- No query, header, or path can select a tenant: test
  `no_query_parameter_header_or_path_segment_can_read_a_different_tenants_usage`.
- No `200` without `auth`: test
  `with_no_auth_filter_in_the_chain_the_usage_endpoint_never_returns_200`.
- When the dialect adds the filter: `lower_limits` and
  `enforces_tenant_limits` in `crates/proxy-simple-config/src/lower.rs`.
- Field order: `serde_json` serializes map keys alphabetically, because the
  workspace does not enable `preserve_order`.
