---
title: Configure rate limits
description: "Limit tokens, requests, or concurrent streams per tenant, key, client address, or header, and learn how the limiter windows and shares counts across replicas."
summary: How to set limits entries, the 429 response, tenant and key limits from
  the admin API, which endpoints a token limit cannot count, and how fixed
  windows and replica reconciliation work.
lastUpdated: 2026-10-21
related:
  - limits-and-budgets/current-usage
  - limits-and-budgets/spend-policies
  - authentication/virtual-keys
  - configuration/configuration-file
  - observability/access-logs
  - observability/metrics-and-stats
---

A `limits:` entry in the configuration file caps the tokens, the requests, or
the concurrent streams of a group of callers. The proxy checks every limit
before it sends the request to a provider. A request over a limit gets `429`
and never reaches a provider. Use a limit to stop one tenant, one client
address, or one caller from using the capacity of a provider.

## At a glance

- **Default when unset:** no limit.
- **Failure mode, counters:** fails open and loud. If the shared store cannot be
  read, the proxy keeps enforcing against the last known totals. It logs a
  warning when the counters stay unreconciled for too long.
- **Failure mode, usage:** if a provider reports no usage, the proxy charges
  the token limit nothing and logs a warning. It does not refuse the request.
- **Failure mode, endpoint:** fails closed. A token limit refuses an endpoint
  that it cannot count with `403`. See
  [Endpoints a token limit cannot count](#endpoints-a-token-limit-cannot-count).

## Example

This file limits each tenant to 100,000 tokens a minute. It also limits the
whole proxy to 600 requests a minute, and each client address to 10 concurrent
streams. Check it with `llm-proxy --config llmproxy.yaml --mode validate`.

```yaml title="llmproxy.yaml"
version: 0
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
limits:
  - key: tenant
    tokens_per_minute: 100k
  - key: global
    requests_per_minute: 600
  - key: client-ip
    concurrent_sessions: 10
```

## Limit fields

Each entry of `limits` needs a `key` and at least one other field. The
[field reference](/docs/llm-proxy/configuration/reference/#limit) is generated
from the schema.

| Field | Type | Default | Description |
|---|---|---|---|
| `key` | string | none (required) | What the limit counts against. See the next table. |
| `tokens_per_minute` | integer, or a string with `k` or `m` | none | Input plus output tokens in one window for each bucket. The proxy reads usage from the provider response, also for streams. |
| `requests_per_minute` | integer, or a string with `k` or `m` | none | Requests in one window for each bucket. The proxy counts a request when it admits it. |
| `concurrent_sessions` | integer, 1 or more | none | Streams in flight for each bucket. This includes SSE streams and `realtime` sessions. The proxy frees the slot when the stream or session ends. |
| `models` | list of model patterns | all models | Apply the entry only to requests for a matching model. A pattern is an exact name or a name with one trailing `*`. Other models neither count against the limit nor get refused by it. |

A value above 4294967295 for `concurrent_sessions` is a load error.

| `key` | Counted against |
|---|---|
| `global` | One bucket for all traffic. |
| `client-ip` | The client address. See [Client address](#client-address). |
| `tenant` | The authenticated tenant. This key needs an `auth:` block. Without one, the load fails with an error at `limits[N].key`. |
| `header:<name>` | The hashed value of the named request header. A request without that header is not counted against this limit. |

`key: header:authorization` counts each credential apart. With `auth:`
configured, the proxy removes the verified `authorization` header, so the
entry counts each virtual key apart. Two keys of one tenant get two buckets.
Use `key: tenant` for a limit for each tenant. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/) for why the tenant
is the safer key.

The proxy never stores or logs the raw header value.

### How entries combine

Every entry that applies to a request must pass. If entries share a bucket,
the proxy merges them and uses the lowest limit, so it counts the request one
time. An entry with `models` is decided when the proxy has read the request
body and found the model.

## The 429 response

A request over a limit gets `429`. The response has a plain-text body that
names the limit, and the detail in `%RESPONSE_CODE_DETAILS%` names it too:

| Limit | Body | Response code detail |
|---|---|---|
| `tokens_per_minute` | `token budget exceeded` | `token_limit_exceeded` |
| `requests_per_minute` | `request rate exceeded` | `request_limit_exceeded` |
| `concurrent_sessions` | `too many concurrent streams` | `concurrency_limit_exceeded` |

Each `429` carries four headers:

| Header | Value |
|---|---|
| `x-ratelimit-limit` | The configured limit. |
| `x-ratelimit-remaining` | What remains in the window. |
| `x-ratelimit-reset` | Seconds until the window ends. |
| `retry-after` | Seconds until the client should retry. |

The access log shows the response flag `RL`. The proxy checks token usage
before the request and records it after the response. A stream already in
flight is never cut off. The request that crosses a token limit completes, and
the next request is refused. A request or stream limit refuses the request
before it starts.

## Limits for a tenant or a key

An operator can also set limits on a tenant or on a key with the admin API.
These limits are not config-file fields. The proxy applies them when `auth:` is
set and `auth.enforce.limits` is `true` (the default).

```bash
curl --max-time 10 -X PUT http://127.0.0.1:53422/tenants/acme/limits \
  -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"schema_version":1,"limits":{"tokens_per_minute":100000,"requests_per_minute":60,"concurrent_streams":5}}'
```

- `PUT /keys/{id}/limits` takes the same body for a key.
- A tenant sets the ceiling. A key can only narrow it. A request must pass the
  bucket of its tenant and the bucket of its key.
- A field that you leave out sets no limit at that level. A value of `0`
  refuses all traffic that the counter measures.
- `{"limits": null}` clears the limits. The call returns `204`.
- With `auth.enforce.limits: false` and no `limits` entry, the call returns
  `409` with `{"error":"not_enforced", ...}`.

See [Admin API](/docs/llm-proxy/administration/admin-api/) for the status
codes.

## Client address

By default the address is the TCP peer. Behind a load balancer, all clients
then share the address of the balancer and one bucket. Set
`listen.trusted_hops` to the number of proxies in front of llm-proxy. The limit
then counts the address in `x-forwarded-for` that the outermost trusted proxy
saw. A client cannot choose its bucket by sending its own `x-forwarded-for`,
because llm-proxy ignores the entries to the left of that address.

```yaml title="llmproxy.yaml (fragment)"
listen:
  address: 0.0.0.0:53421
  trusted_hops: 1   # one load balancer appends the client address
```

Set `trusted_hops` only when all connections come through those proxies. A
client that connects to llm-proxy directly can write any address in
`x-forwarded-for`. See the
[`listen` reference](/docs/llm-proxy/configuration/reference/#listener).

## Endpoints a token limit cannot count

A token limit counts tokens. Six kinds of request report tokens that the
proxy can read: chat completions, completions, Responses, Messages,
embeddings, and `realtime` sessions. A token limit that applies to a request
for any other endpoint, such as images, audio, batches, or files, refuses it
with `403` and the detail `endpoint_not_metered`. The request does not reach
the provider.

- A token limit applies to a request when the tenant or the key has a
  `tokens_per_minute` limit, or when a `limits` entry with `tokens_per_minute`
  matches the request. An entry with `models` applies only when the request
  names a matching model, so the proxy refuses at the end of the request body.
- Request limits and concurrent-stream limits can count every endpoint, so
  they never refuse a request for this reason.
- `GET .../models`, `GET .../usage`, and `POST .../messages/count_tokens` cost
  nothing and pass without a missing-usage warning.
- A request that no token limit applies to is not refused and logs nothing.

Spend budgets count more endpoints than token limits do. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/#endpoints-a-budget-cannot-count).
Each refusal increments `llmproxy_unmetered_endpoint_refused_total` with the
label `control="token_limit"`.

## Windows

A window is a fixed period aligned to the Unix epoch. A 60-second window always
starts on a whole minute. Every replica therefore counts the same minute under
the same name. As a result, the first window that a caller sees can be shorter
than 60 seconds. A caller whose first request arrives 50 seconds into a minute
has 10 seconds before the window resets. `x-ratelimit-reset` and `retry-after`
count down to the end of the current window.

## Sharing counts across replicas

Each replica checks a request against its own counters and never waits for the
store. The counters reconcile with the store that `auth.store` selects about
once a second, and sooner when a caller nears its limit.

| `auth.store` | Effect |
|---|---|
| `in_memory` or `persistent` | Each replica counts alone. N replicas admit up to N times a limit. |
| `shared` | Token and request counts are shared by every replica. The fleet can admit a little over a limit between reconciles. |

With a `shared` store, each replica also publishes its count of concurrent
streams four times a second. The count of a replica that stops expires after 5
seconds. A `limits` entry on a proxy with no `auth:` block counts per process.

If the store cannot be reached, the proxy keeps enforcing against the last
known totals. It logs a warning when the counters stay unreconciled past their
bound. The gauge `envoy_llmproxy_counter_reconciliation_age_seconds` on
`/stats/prometheus` shows how long ago the counters last reconciled. The label
`seam="rate_window"` is for token and request counts. The label
`seam="stream_lease"` is for concurrent streams.

To read the current standing of a tenant against these limits, see
[Read current usage](/docs/llm-proxy/limits-and-budgets/current-usage/).

## Limitations

- The window is fixed at one minute. The dialect has no other window length.
- With a store that is not `shared`, limits apply for each replica.
- A token limit refuses endpoints that report no tokens. Use a request limit
  or a concurrent-stream limit for those endpoints.
- `GET /v1/usage` reports only the tenant token limits. See
  [Read current usage](/docs/llm-proxy/limits-and-budgets/current-usage/).
- Limits are not dollar budgets. For a ceiling in dollars, see
  [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Each behavior above has this source.

- Keyed rules, windows, and refusals:
  `crates/proxy-filters/src/token_limit_filter.rs` (`refuse`, `Refusal`,
  `admit_buckets`, `admit_policy`).
- Unmetered endpoint refusal: `metered_under_token_limit` in
  `crates/proxy-filters/src/unmetered.rs`.
- When the dialect adds the filter, and the load error for `key: tenant`
  without `auth:`: `lower_limits` and `enforces_tenant_limits` in
  `crates/proxy-simple-config/src/lower.rs`.
- Tests: `crates/proxy/tests/dialect_limits_e2e.rs`
  (`global_requests_per_minute_counts_every_caller`,
  `client_ip_requests_per_minute_counts_the_peer`,
  `tenant_tokens_per_minute_charges_actual_usage`,
  `header_authorization_buckets_per_key_even_with_auth`,
  `concurrent_sessions_holds_a_slot_while_a_response_is_in_flight`,
  `models_scope_limits_only_matching_models`);
  `crates/proxy/tests/shared_limits_redis_e2e.rs`
  (`redis_two_processes_share_tenant_and_key_stream_ceilings_and_a_killed_replica_releases`);
  `crates/proxy/tests/trusted_hops_e2e.rs`.
