---
title: Token rate limiting
summary: How the token limiter buckets and enforces a budget, and the
  `GET /v1/usage` endpoint an authenticated caller uses to read its own
  current standing.
last_updated: 2026-09-07
related:
  - ../authentication/virtual-keys/
  - ../configuration/configuration-file/
  - ../observability/metrics-and-stats/
---

# Token rate limiting

A `limits:` entry in the configuration file can cap the tokens a caller may
spend per minute. Only one combination is enforced today —
`key: tenant` (which needs `auth:` configured) or `key: header:authorization`,
with `tokens_per_minute` set. Every other `limits:` field is accepted,
recorded, and produces a load-time warning rather than a rejection; see
[Configuration file](../configuration/configuration-file/)'s `limits[]`
reference for the full field table, and
[Virtual keys](../authentication/virtual-keys/) for why the limiter buckets
on the authenticated tenant rather than the caller's raw header once `auth:`
is configured.

This page covers the read side: `GET /v1/usage`, an endpoint the proxy
answers itself so an authenticated caller can see its own budget without an
operator reading logs on its behalf.

## `GET /v1/usage`

The proxy intercepts `GET /v1/usage` before any budget check and answers it
directly — it is never forwarded to a provider
(`crates/proxy-filters/src/token_limit_filter.rs`'s `decode_headers`, the
`USAGE_PATH` branch). It reports the current-window standing of every route
the caller's tenant has a budget on.

### The key authenticates and scopes

The tenant in the response comes from **only** `StreamInfo::auth.tenant`, the
identity an upstream `llmproxy.auth` filter wrote after verifying the
caller's credential. There is no tenant parameter: nothing in the handler
reads a query parameter, a header, or a path segment to select whose usage to
return. A caller can read only the budget belonging to the key it presented.

This is tested directly, not just asserted: a query string naming a second
tenant (`?tenant=other`), a header naming a second tenant (`x-tenant:
other`), and a path that merely starts with `/v1/usage` (`/v1/usage/other`,
which is not an exact match and falls through to ordinary routing instead of
this endpoint) are all tried against a store that holds real, very different
usage for both tenants, and none of them ever returns the second tenant's
numbers
(`no_query_parameter_header_or_path_segment_can_read_a_different_tenants_usage`
in `crates/proxy-filters/src/token_limit_filter.rs`).

### Requires both `auth:` and an enforced `limits:` entry

Two things must be true for this endpoint to return real data:

1. **`auth:` must be configured.** Without it, nothing ever writes
   `StreamInfo::auth.tenant`, so the only reachable outcome is `401` — this
   is what makes "the endpoint never returns 200 on a listener with no
   `auth:` block" true by construction, not by a separate check
   (`crates/proxy-filters/src/token_limit_filter.rs`'s module doc, and
   `with_no_auth_filter_in_the_chain_the_usage_endpoint_never_returns_200`).
2. **A `limits:` entry must actually produce the token limiter.** The
   endpoint is implemented inside the `llmproxy.token_limit` filter itself,
   so a listener with `auth:` but no enforced `limits:` entry (see
   [Configuration file](../configuration/configuration-file/)) never loads
   that filter at all — `GET /v1/usage` is then an ordinary, unmatched
   request like any other, not a 401
   (`crates/proxy-simple-config/src/lower.rs`'s `lower_limits`, which emits
   at most one `llmproxy.token_limit` filter per listener, only for
   `key: tenant` or `key: header:authorization` with `tokens_per_minute`
   set).

### Example

```yaml
version: 0
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
curl -s http://127.0.0.1:8080/v1/usage \
  -H "Authorization: Bearer llmp_<the key>"
```

A tenant `acme` that has spent 2,200 of its 100,000-token-per-minute budget
on a route named `chat`, 43 seconds into the current window, gets this body
(`content-type: application/json`, status `200`):

```json
{"routes":[{"limit":100000.0,"remaining":97800.0,"reset_after_seconds":43,"route":"chat","used":2200.0}],"tenant":"acme","window":"fixed"}
```

The key order above is exact, not illustrative — it comes from `serde_json`'s
default map (no `preserve_order` feature is enabled anywhere in this
workspace's `Cargo.lock`), so fields serialize alphabetically rather than in
the order they are written in
`render_usage_response`(`crates/proxy-filters/src/token_limit_filter.rs`).
Do not parse this response positionally; parse it as JSON.

### Response fields

| Field | Type | What it is |
|---|---|---|
| `tenant` | string | The authenticated caller's tenant, exactly as configured in `auth.keys[].tenant`. |
| `window` | string, always `"fixed"` | The limiter's windowing algorithm. Only a fixed window exists today, so this never varies. |
| `routes` | array of objects | One entry per route this tenant has a current-window budget on. Empty (`[]`) if the tenant has never been bucketed against any route — a true answer, not an error. |
| `routes[].route` | string | The route name the budget is bucketed under. |
| `routes[].used` | number | Weighted tokens consumed in the current window. |
| `routes[].limit` | number | The configured `tokens_per_minute` cap for this window. |
| `routes[].remaining` | number | `limit - used`, floored at zero — never negative. |
| `routes[].reset_after_seconds` | integer | Seconds remaining until the current window rolls over. |

### Status codes

| Status | When | Body |
|---|---|---|
| `200` | An authenticated tenant, budget store reachable. | The JSON body above — including an empty `routes: []` for a tenant with no budgets anywhere. |
| `401` | No authenticated tenant: no `auth:` block on the listener, no credential presented, or the credential was rejected. | `unauthorized` (plain text, no usage data). |
| `503` | The budget store could not be read. | `usage temporarily unavailable` (plain text, no body fields). |

The `503` case is deliberate, not an oversight: every other path through the
token limiter fails open on a store error (an unreadable budget must never
block real traffic), but this read-only reporting endpoint inverts that
policy, because a caller silently shown a wrong or stale number is a worse
outcome than a visible failure
(`BudgetStore::usage_for_tenant`'s doc in
`crates/proxy-filters/src/token_limit.rs`,
`usage_endpoint_returns_503_when_the_budget_store_is_unavailable`).

### What this endpoint deliberately does not do

- **No history.** It reports only the current fixed window — the same
  numbers a live budget check would see at that instant. There is no way to
  ask it for last hour's or last week's usage. A historical export is a
  separate, not-yet-built feature.
- **No cost.** The response has no dollar or currency field. Converting
  tokens to cost needs a price-per-token rate card, which does not exist yet
  (not built). If you need cost today, multiply `used` by your own rate outside
  the proxy.

## Bootstrap configuration

The underlying filter is `llmproxy.token_limit`
(`type.llmproxy.dev/llmproxy.filters.v0.TokenLimit`). It must be placed **after**
`llmproxy.auth` in `http_filters`, for the same reason `auth:` must exist for
this endpoint to authenticate anyone: decode-path callbacks run in config
order, and the limiter reads `auth.tenant` on decode.

```yaml
http_filters:
  - name: llmproxy.auth
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
      hmac_secret:
        inline_string: ${LLMPROXY_AUTH_SECRET}
      virtual_keys:
        - key_id: alice-laptop
          tenant: acme
          digest_hex: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a
          revoked: false
  - name: llmproxy.token_limit
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.TokenLimit
      max_tokens: 100000
      fill_rate: 1666.6666666666667
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

`max_tokens` and `fill_rate` are both required; the limiter derives its
window as `max_tokens / fill_rate` seconds, so a 100,000-token,
60-second window needs `fill_rate = 100000 / 60`
(`crates/proxy-filters/src/token_limit_filter.rs`'s `parse_config`).
For one release, hand-written bootstraps using the former borrowed
`type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings` type still load
with the same semantics but emit a deprecation warning; migrate them to
`TokenLimit` now. The dialect always emits the owned type.
`crates/proxy-config/src/lower.rs`'s `check_lane_h_filter_order` rejects the
wrong filter order at load time — this is a hand-written bootstrap's own
responsibility; the dialect above always emits the correct order.
