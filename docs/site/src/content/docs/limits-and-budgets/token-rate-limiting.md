---
title: Token rate limiting
summary: How the token limiter buckets and enforces a budget, and the
  `GET /v1/usage` endpoint an authenticated caller uses to read its own
  current standing.
last_updated: 2026-10-17
related:
  - ../authentication/virtual-keys/
  - ../configuration/configuration-file/
  - ../observability/access-logs/
  - ../observability/metrics-and-stats/
---

# Token rate limiting

A `limits:` entry in the configuration file caps the tokens, the requests,
or the concurrent streams of a group of callers. The proxy enforces every
`limits` field and every key: `global`, `client-ip`, `tenant`, and
`header:<name>`. No load warning remains for them. See the `limits[]`
reference in [Configuration file](../../configuration/configuration-file/#limits-limit)
for the field table, the keys, and how entries combine.

`key: header:authorization` counts each credential apart. With `auth:`
configured, the proxy removes the verified `authorization` header, so the
entry counts each virtual key apart (two keys of one tenant get two
buckets). Use `key: tenant` for a limit for each tenant. See [Virtual keys](../../authentication/virtual-keys/) for why the
tenant is the safer key.

## Endpoints a token limit cannot count

A token limit counts tokens, and only five endpoints report tokens that the
proxy can read: chat completions, completions, Responses, Messages and
embeddings. A token limit that applies to a request for any other endpoint,
such as images, audio, batches or files, refuses it with `403`
`endpoint_not_metered`. The request does not reach the provider.

- A token limit applies to a request when the static rule is set, when the
  tenant or key has a `tokens_per_minute` limit, or when a `limits` entry with
  `tokens_per_minute` matches the request. An entry with `models` applies
  only when the request names a matching model, so the proxy refuses at the
  end of the request body.
- Request limits and concurrent-stream limits can count every endpoint, so
  they never refuse a request for this reason.
- `GET .../models`, `GET .../usage` and `POST .../messages/count_tokens` cost
  nothing and pass without a missing-usage warning.
- A request that no token limit applies to is not refused and logs nothing.

The counter and the detail are the same as for spend budgets. See
[Spend policies](../spend-policies/#endpoints-a-budget-cannot-count).

## Windows

A window is a fixed period aligned to the Unix epoch: a 60-second window
always starts on a whole minute (`floor(unix_time / length)`). Every replica
therefore counts the same minute under the same name. As a result, the first
window a caller sees can be shorter than the configured length. A caller whose
first request arrives 50 seconds into a minute has 10 seconds of budget before
the window resets. `x-ratelimit-reset` and `retry-after` count down to the end
of the current window.

Each replica checks a request against its own counters and never waits for
the store. The counters reconcile with the store that `auth.store` selects
about once a second, and sooner when a caller nears its limit. With a
`shared` store, the token and request counts are shared by every replica, so
the fleet can admit a little over a limit between reconciles. If the store
cannot be reached, the proxy keeps enforcing against the last known totals,
and logs a warning when the counters stay unreconciled past their bound. The
gauge `envoy_llmproxy_counter_reconciliation_age_seconds` on
`/stats/prometheus` shows how long ago the counters last reconciled, with
`seam="rate_window"` for token and request counts and
`seam="stream_lease"` for concurrent streams. Concurrent streams are shared
in the same way with a `shared` store: each replica publishes its count about
once a second, and the count of a replica that stops expires after 5
seconds. A `limits` entry on a listener with no `auth:` counts per process.

This page also covers the read side: `GET /v1/usage`, an endpoint the proxy
answers itself so an authenticated caller can see its own budget without an
operator reading logs on its behalf.

## `GET /v1/usage`

The proxy intercepts `GET /v1/usage` before any budget check and answers it
directly — it is never forwarded to a provider
(`crates/proxy-filters/src/token_limit_filter.rs`'s `decode_headers`, the
`USAGE_PATH` branch). It reports the current-window standing of the
caller's tenant: each `key: tenant` entry of `limits` that sets
`tokens_per_minute`, and the per-route rule of a bootstrap (Envoy-mode)
`TokenLimit`. See "What the endpoint reports".

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

### Requires `auth:` and the token limiter

Two things must be true for this endpoint to return real data:

1. **`auth:` must be configured.** Without it, nothing ever writes
   `StreamInfo::auth.tenant`, so the only reachable outcome is `401` — this
   is what makes "the endpoint never returns 200 on a listener with no
   `auth:` block" true by construction, not by a separate check
   (`crates/proxy-filters/src/token_limit_filter.rs`'s module doc, and
   `with_no_auth_filter_in_the_chain_the_usage_endpoint_never_returns_200`).
2. **The token limiter must be in the filter chain.** The endpoint is
   part of the `llmproxy.token_limit` filter. The dialect adds that filter
   when the config has a `limits` entry. It also adds it when `auth:` is set
   and `auth.enforce.limits` is `true`. With neither, `GET /v1/usage` is an
   ordinary request, not a 401
   (`lower_limits` and `enforces_tenant_limits` in
   `crates/proxy-simple-config/src/lower.rs`).

### What the endpoint reports

The endpoint reports two kinds of row (`usage_entries` in
`crates/proxy-filters/src/token_limit_filter.rs`):

- Each `limits` entry with `key: tenant` and `tokens_per_minute`. Such a rule
  does not depend on the route, so its row has `route` set to `*`. A rule
  with `models` adds its scope to the name, for example
  `*|models=gpt-4o`. Two rules on the same bucket give one row with the
  lower limit.
- The per-route rule of a bootstrap `TokenLimit` (the rule set with
  `max_tokens` and `fill_rate`): one row per route.

Entries keyed on `global`, `client-ip` or a header, request and
concurrent-stream limits, and tenant and key limits from the admin API do not
appear. Use the 429 headers or the access log to see that usage.

### Example

The dialect config below enforces a tenant limit. The endpoint reports it as
the route `*`.

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

The caller gets status `200`, `content-type: application/json`, and a body
like this one, after the tenant used 2,200 tokens, 43 seconds into the
current window:

```json
{"routes":[{"limit":100000.0,"remaining":97800.0,"reset_after_seconds":17,"route":"*","used":2200.0}],"tenant":"acme","window":"fixed"}
```

With the bootstrap in "Bootstrap configuration" below, a tenant `acme` that
has spent 2,200 of its 100,000 tokens on a route named `chat`, 43 seconds
into the current window, gets this body:

```json
{"routes":[{"limit":100000.0,"remaining":97800.0,"reset_after_seconds":17,"route":"chat","used":2200.0}],"tenant":"acme","window":"fixed"}
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
| `routes` | array of objects | One entry per route this tenant has a current-window budget on, for a `key: tenant` entry of `limits` with `tokens_per_minute` (route `*`) or the per-route rule of a bootstrap `TokenLimit`. Empty with neither. Also empty if the tenant has never been bucketed against any route — a true answer, not an error. |
| `routes[].route` | string | The route name the budget is bucketed under. |
| `routes[].used` | number | Weighted tokens consumed in the current window. |
| `routes[].limit` | number | The configured `tokens_per_minute` cap for this window. |
| `routes[].remaining` | number | `limit - used`, floored at zero — never negative. |
| `routes[].reset_after_seconds` | integer | Seconds remaining until the current window rolls over. |

### Status codes

| Status | When | Body |
|---|---|---|
| `200` | An authenticated tenant. | The JSON body above — including an empty `routes: []` for a tenant with no budgets anywhere. |
| `401` | No authenticated tenant: no `auth:` block on the listener, no credential presented, or the credential was rejected. | `unauthorized` (plain text, no usage data). |
| `503` | `auth.store` is `shared`, and the store returned an error or did not answer within about 2 seconds. | `usage unavailable` (plain text), with `retry-after: 1`. |

Where the numbers come from depends on `auth.store`:

- **`in_memory` or `persistent`:** one replica. The endpoint answers from the
  counters of that replica, and the answer is exact.
- **`shared`:** the endpoint reads the fleet totals from the store, for every
  route of the listener. A replica that has never served a route still
  reports the usage that other replicas counted on it. The read does not
  block the worker: the proxy holds the request while a background thread
  reads the store. Requests for the same tenant share one read, and the
  proxy reuses an answer for about 1 second, so frequent calls do not add
  load on the store. The numbers can lag the replica's own most recent
  requests by up to one reconcile interval (about 1 second).

If the store read fails, the endpoint answers `503`. It does not fall back to
the counters of the replica, because a replica that has not served a route
would report 0 for it, which is a wrong number.

### What this endpoint deliberately does not do

- **No history.** It reports only the current fixed window — the same
  numbers a live budget check would see at that instant. There is no way to
  ask it for last hour's or last week's usage. A historical export is a
  separate, not-yet-built feature.
- **No cost.** The response has no dollar or currency field. The rate card
  prices each completed request, and the access log shows the price in
  nanodollars as `%LLM_LIST_COST%`. To total the cost of one tenant, sum
  `%LLM_LIST_COST%` by `%LLM_TENANT%` in your log pipeline. The rate card is the
  `pricing` section of the configuration file; see
  [`pricing`](../../configuration/configuration-file/#pricing-pricing). The
  operators are in the
  [access log reference](../../observability/access-logs/#the-operator-set).

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
