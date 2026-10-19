---
title: Configure rate limits
description: "Limit tokens, requests, or concurrent streams per tenant, key, or header, and learn how the limiter windows and reconciles counts."
summary: How to set limits entries, which endpoints a token limit cannot
  count, how fixed windows and replica reconciliation work, and the bootstrap
  form of the token limiter.
lastUpdated: 2026-10-18
related:
  - limits-and-budgets/current-usage
  - authentication/virtual-keys
  - configuration/configuration-file
  - observability/access-logs
  - observability/metrics-and-stats
---

# Configure rate limits

A `limits:` entry in the configuration file caps the tokens, the requests,
or the concurrent streams of a group of callers. The proxy enforces every
`limits` field and every key: `global`, `client-ip`, `tenant`, and
`header:<name>`. See the `limits[]`
reference in [Field reference](../../configuration/reference/#limit)
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
- `GET .../models`, `GET .../usage`, and `POST .../messages/count_tokens` cost
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

To read the current standing of a tenant against these limits, see
[Read current usage](../current-usage/).

## Bootstrap configuration

The underlying filter is `llmproxy.token_limit`
(`type.llmproxy.dev/llmproxy.filters.v0.TokenLimit`). It must be placed **after**
`llmproxy.auth` in `http_filters`. Decode-path callbacks run in config
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
60-second window needs `fill_rate = 100000 / 60`.
A hand-written bootstrap that uses the former borrowed
`type.llmproxy.dev/envoy.config.core.v3.RateLimitSettings` type still loads
with the same semantics, but it emits a deprecation warning. Change it to
`TokenLimit`. The dialect always emits the `TokenLimit` type.

The proxy rejects the wrong filter order at load time. The dialect always
emits the correct order, so this check matters only for a hand-written
bootstrap.

## Implementation notes

For maintainers. Each behavior above has this source.

- Bootstrap fields: `parse_config` in
  `crates/proxy-filters/src/token_limit_filter.rs`.
- Filter order check: `check_lane_h_filter_order` in
  `crates/proxy-config/src/lower.rs`.
- When the dialect adds the filter: `lower_limits` in
  `crates/proxy-simple-config/src/lower.rs`.
