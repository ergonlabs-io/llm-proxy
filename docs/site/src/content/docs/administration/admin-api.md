---
title: Admin API
description: "Use the admin server: readiness, config dump, stats, the web UI, and the bearer-gated write API for keys, tenants, budgets, limits, credentials, and pricing."
summary: Reference for every route the admin server answers, which routes
  need the admin token, the request body limits, and the status codes.
lastUpdated: 2026-10-21
related:
  - administration/admin-ui
  - authentication/virtual-keys
  - authentication/tenant-provider-credentials
  - limits-and-budgets/spend-policies
  - limits-and-budgets/billing-ledger
  - limits-and-budgets/pricing-and-cost-tracking
  - operations/draining-and-shutdown
  - observability/metrics-and-stats
  - help/limitations
---

Use the admin server to check readiness, read the loaded config and stats,
manage keys and tenants, and drain the proxy. It is an HTTP listener. It
serves read endpoints, a write API for keys, tenants, budgets, limits,
credentials, and pricing, three lifecycle commands, and the
[admin UI](/docs/llm-proxy/administration/admin-ui/).

This page lists each route and its auth rule. It does not repeat the request
and response details that other pages already own.

## At a glance

- **Default when unset:** no admin server. Set the top-level `admin` field to
  turn it on.
- **Failure mode:** fails closed. If `LLMPROXY_ADMIN_TOKEN` is unset, empty,
  or only spaces, every gated route answers `403`.
- **Open routes:** the read routes for probes, config, stats, and the rate
  card need no token.
- **Transport:** plain HTTP by default. Set `admin.tls` to serve the admin
  API over TLS. See [TLS on the admin port](#tls-on-the-admin-port).

```yaml title="llmproxy.yaml"
version: 0
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422
auth:
  hmac_secret_file: ./auth-secret
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
```

```sh
LLMPROXY_ADMIN_TOKEN="$(cat admin-token)" llm-proxy --config llmproxy.yaml
curl --max-time 5 http://127.0.0.1:53422/ready
```

Expected output: `LIVE`.

The key, tenant, budget, limit, and credential routes need the `auth` section.
Without it they answer `503`.

## Auth model

One rule decides if a route needs the admin token. A route is gated if it
changes state, or if it reads identity, money, or request data. All other
routes are open to any caller that can reach the admin port.

**Warning.** The admin port has no other access control. Bind it to a
loopback address, or put it behind a network you trust. Open routes such as
`/config_dump` answer any caller.

### TLS on the admin port

Use the object form of `admin` to serve the admin API over TLS. The shorthand
string `host:port` is plain HTTP.

```yaml
admin:
  address: 0.0.0.0:9901
  tls:
    cert_file: /etc/llmproxy/admin.crt
    key_file: /etc/llmproxy/admin.key
```

```sh
curl --max-time 5 --cacert /etc/llmproxy/ca.crt https://localhost:9901/ready
```

- The port speaks only TLS. A plaintext request gets no HTTP answer.
- The port offers TLS 1.2 and TLS 1.3, and ALPN `http/1.1`. It does not ask
  clients for a certificate.
- A certificate or key file that cannot be read at start stops the process.
- A `SIGHUP` reload reads the files again on the next accepted admin
  connection, the same as `listen.tls`. If a file cannot be read then, the
  admin port closes every new connection until a later reload succeeds. It
  never falls back to plain HTTP. See
  [Rotate the certificate](/docs/llm-proxy/operations/tls/#rotate-the-certificate).

If `LLMPROXY_ADMIN_TOKEN` is set, `admin.address` is not a loopback address,
and `admin.tls` is not set, the token crosses the network in clear text. The
proxy still serves the admin API, and it logs this warning once at start:

```text
admin.address 0.0.0.0:9901 is not a loopback address and the admin API has no TLS: ...
```

A reload that removes `admin.tls` logs the warning again. A loopback address
does not log it.

A gated route passes two checks in this order:

1. The proxy must have the `LLMPROXY_ADMIN_TOKEN` environment variable set. If
   it is unset, empty, or only whitespace, the route answers `403` with the
   body `admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is
   not set`. An unset token never means open.
2. The request must carry `Authorization: Bearer <token>` with the same
   token. If it does not, the route answers `401` with a `www-authenticate`
   challenge and the body `missing or invalid bearer token`.

The proxy compares the token with a constant-time check. The router answers
`404` for an unknown path and `405` for a wrong method before it checks the
token.

**Caution.** After 10 missing or wrong bearer tokens from one peer IP within 60
seconds, the proxy refuses that peer's gated requests with `429` and a
`Retry-After` header (in seconds). This lasts until the 60-second window ends,
even if the peer then sends the right token. The limit covers all write
endpoints and the gated reads, such as `GET /keys`, spend reads, and the
ledger routes. A correct token before the limit clears the count for that
peer. The proxy logs each refusal at warn with the peer IP and the endpoint.
It never logs the presented token.

| Route class | Routes | Gated |
|---|---|---|
| Probes and dumps | `GET /ready`, `/config_dump`, `/clusters`, `/server_info`, `/models` | No |
| Metrics | `GET /stats`, `/stats/prometheus` | No |
| Rate card read | `GET /pricing` | No |
| Admin UI | `GET /`, `GET /ui`, `GET /ui/...` | No |
| Spend reads | `GET .../spend` for keys and tenants | Yes |
| Billing ledger | `GET /ledger/entries`, `POST /ledger/ack` | Yes |
| Trace-export switch | `GET /traces/capture`, `POST /traces/capture` | Yes |
| Identity reads | `GET /keys`, `GET /tenants/{id}/provider_credentials`, `GET /tenants/{id}/trace_export`, `GET /tenants/{id}/objects/{object_id}` | Yes |
| All writes | `POST`, `PUT`, `DELETE` routes, and the lifecycle commands | Yes |

The proxy gates the spend and key-list reads because they expose money and
identity. `GET /pricing` is open, because its handler runs before the gate.
`PUT /pricing` passes the gate.

### Body size limits

| Route | Maximum request body |
|---|---|
| `PUT /pricing` | 4 MiB (4,194,304 bytes) |
| All other routes that read a body | 64 KiB (65,536 bytes) |

A body over the limit gets `413` with the body `request body exceeds the
<cap>-byte cap for this endpoint`. The gate runs before the body is read, so
only a caller with the token can send a large body.

### Common errors

| Status | When |
|---|---|
| `400` | The body is not valid JSON, or it has an unknown field. The body starts with `malformed request body:`. |
| `404` | The path is unknown. The body lists the available endpoints. |
| `405` | The path exists but the method is wrong. The body is `<path> only accepts <METHOD>`. |
| `409` | The write would be stored and never enforced. The body is `{"error":"not_enforced", ...}`. See below. |
| `503` | A key, tenant, or spend route, and the config has no `auth` section. |
| `503` | A key or tenant write reached the store, but this replica could not reload it. |

For a missing `auth` section, the `503` body is `the auth control plane is
not initialized yet: ...`.

For a write that this replica could not reload, the `503` body starts with
`written to the control-plane store, but not yet applied on this replica`.
The write is stored. This replica serves the previous policy until its next
successful poll, so for example a revoked key still works here until then.
Other replicas that share the store apply the write on their own poll. A
retry is safe.

A `409` `not_enforced` answer means the matching control is off. These
writes need the matching `auth.enforce` field to stay `true` (the default):

| Write | Needs |
|---|---|
| `PUT /tenants/{id}/policy`, `PUT /keys/{id}/policy` | `auth.enforce.model_policy` |
| `PUT /tenants/{id}/budget` | `auth.enforce.spend` |
| `PUT /tenants/{id}/limits`, `PUT /keys/{id}/limits` | `auth.enforce.limits` |
| `PUT /tenants/{id}/objects/{object_id}` | `auth.enforce.object_ownership` |

The proxy stores nothing when it answers `409`. The dialect logs a load-time
warning for each control that you turn off. See
[Configuration reference](/docs/llm-proxy/configuration/reference/#authenforce).

## Read endpoints

| Route | Method | Answer |
|---|---|---|
| `/ready` | GET | `200 LIVE`, `503 INITIALIZING`, or `503 DRAINING` |
| `/config_dump` | GET | JSON of the loaded config snapshot |
| `/clusters` | GET | JSON list of clusters, sorted by name |
| `/models` | GET | JSON list of the models that the routes match on the `x-llmproxy-model` header, each with its `target` cluster, and `path_routes`: the routes that match on the path only, so they serve any model |
| `/server_info` | GET | JSON with `version` and `uptime_seconds` |
| `/stats` | GET | Plain-text counters and histograms |
| `/stats/prometheus` | GET | Prometheus text format |
| `/` | GET | `302` to `/ui/` if the UI is loaded. Otherwise `404` with the list of endpoints. |

`/stats` and `/stats/prometheus` answer `404` if no stats registry exists.
The proxy does not return an empty `200`. See
[Metrics and /stats](/docs/llm-proxy/observability/metrics-and-stats/) for
the counters.

```sh
curl --max-time 5 http://127.0.0.1:53422/server_info
```

## Billing ledger endpoints

Two routes read and acknowledge the billing ledger. Both are gated. Without a
`ledger` block in the config, both answer `404`. The parameters, the answers,
and the status codes are on
[Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/#pull-and-acknowledge-entries).

| Route | Method | Answer |
|---|---|---|
| `/ledger/entries?after=<cursor>&limit=<1-1000>` | GET | Committed entries above the cursor, `next_after`, and `committed_through` |
| `/ledger/ack?through=<cursor>` | POST | `acknowledged_through` and `admitting` |

## Lifecycle commands

Each command is a `POST` and is gated. Without lifecycle control wired in, a
command answers `404` with `lifecycle control is not configured for this
admin server instance`.

| Route | Effect |
|---|---|
| `POST /healthcheck/fail` | `/ready` answers `503 DRAINING` |
| `POST /healthcheck/ok` | Restores the health check. A drain that has started is not undone. |
| `POST /drain_listeners` | Starts a graceful drain |

`/drain_listeners` accepts the query parameters `graceful` and `inboundonly`.
They have no extra effect, because the drain is always the full graceful one.
Any other parameter gives `400` with `unsupported query parameter '<name>' on
/drain_listeners; accepted: graceful, inboundonly`. On success the answer is
`200 OK`. See
[Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/).

## Keys and tenants

All routes in this section are gated. Request fields are strict: an unknown
field gives `400`. See [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/)
for the key model and examples.

| Route | Method | Success | What it does |
|---|---|---|---|
| `/keys` | GET | `200` | Lists keys: `key_id`, `tenant`, `revoked`, `policy`, `budget`, `limits`, `tags`. Sorted by tenant, then key id. |
| `/keys` | POST | `201` | Mints a key. Body: `tenant`, `key_id`, optional `tags`. The answer holds the key text `key` once, and the key's `tags`. |
| `/keys/{id}` | DELETE | `204` | Revokes a key. |
| `/keys/{id}/budget` | PUT | `204` | Sets or clears a key budget. |
| `/keys/{id}/policy` | PUT | `204` | Sets the model allow-list of one key. The key can only narrow its tenant grant. See "Key model policy". |
| `/keys/{id}/limits` | PUT | `204` | Sets or clears the rate limits of one key. The key can only narrow its tenant limits. See "Tenant and key limits". |
| `/keys/{id}/tags` | PUT | `204` | Replaces the chargeback tags of one key. Body: `tags`. See [Chargeback tags](/docs/llm-proxy/limits-and-budgets/chargeback-tags/). |
| `/keys/{id}/spend` | GET | `200` | Reads the spend of a key, with the key's `tags`. |
| `/tenants` | POST | `201` | Creates a tenant. Body: `tenant`. |
| `/tenants/{id}` | DELETE | `204` | Deletes a tenant and revokes every key that authenticates as it. Minted keys are revoked and their rows stay. Config-file `auth.keys` entries for the tenant are revoked by a revoked store row with the same key id. That row wins on every replica that shares the store, and across restarts. Revoked key ids are permanent. The next request with any of those keys gets `401`. |
| `/tenants/{id}/policy` | PUT | `204` | Sets the model-access policy. Body: `access` (`all` or `{"only": [...]}`) and optional `deny`. An invalid pattern gives `400`. |
| `/tenants/{id}/budget` | PUT | `204` | Sets or clears the spend ceiling. |
| `/tenants/{id}/limits` | PUT | `204` | Sets or clears the rate limits of a tenant. See "Tenant and key limits". |
| `/tenants/{id}/spend` | GET | `200` | Reads the spend of a tenant. |
| `/tenants/{id}/trace_export` | PUT, GET | `204`, `200` | Sets or reads the trace-export opt-in of a tenant. Body: `{"schema_version": 1, "enabled": true}`. See [Request and response body export](/docs/llm-proxy/observability/trace-export/). |
| `/tenants/{id}/objects/{object_id}` | PUT | `204` | Assigns a provider object that no tenant owns to the tenant. No body. See "Object ownership". |
| `/tenants/{id}/objects/{object_id}` | GET | `200` | Reads whether the store records the tenant as the owner. See "Object ownership". |
| `/traces/capture` | POST, GET | `200` | Closes or opens the trace-export emergency switch, or reads it. Body: `{"disabled": true, "expected_generation": N}`. A stale generation gives `409`. Without trace export configured, both answer `404`. See [Request and response body export](/docs/llm-proxy/observability/trace-export/). |

The mint answer is the only time the proxy returns the key text. The store
keeps a digest only. Thus, if the key is stored but this replica cannot
reload it, the mint answers `202` and not `503`. The `202` body holds the
key text and `"applied": false`. The key gets `401` on this replica until
its next successful poll. A second `POST /keys` with the same `tenant` and
`key_id` replaces the key text. The old text stops working on the next
request. If the body leaves out `tags`, the key keeps its tags.

| Status | Cause on `POST /keys` |
|---|---|
| `400` | `tenant` or `key_id` is empty or not valid, a field is unknown, `schema_version` is not `2`, or the tenant is reserved. The tenant `default` is reserved. |
| `409` | `key ownership is immutable` (the `key_id` belongs to another tenant), or `revoked key IDs cannot be reused`. |

`DELETE /keys/{id}` revokes a key that has a row in the store. A key that
exists only in `auth.keys` has no row, and the call answers `404` with the
body `not found`. To revoke such a key, delete its tenant, or set
`revoked: true` in the config file and restart the proxy. A reload that
removes or revokes a configured key is refused. `PUT /keys/{id}/tags` answers
`409` for a key defined in the config file or a revoked key.

The budget body is `{"budget": {"max_usd": "500.00", "period": "monthly"}}`
to set a ceiling, or `{"budget": null}` to clear it. The key budget and the
tenant budget use the same body shape, with one extra field for each:

- A tenant budget takes `credential_source`: `platform` (default) or
  `tenant`. A key budget with this field gives `400`.
- A key budget takes `include_byok_in_limit` (default `false`). A tenant
  budget with this field gives `400`.

The spend reads answer `503` with `llmproxy.spend_limit is not configured on
this chain, so there is no spend accumulator to report from` when
`auth.enforce.spend` is `false`. `GET /keys/{id}/spend` answers `404` for an
unknown key. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/) for
periods, the spend response, and how the proxy counts spend.

## Object ownership

`auth.enforce.object_ownership` keeps provider objects to the tenant that
created them. The objects are files, batches, responses, stored chat
completions, uploads, vector stores, fine-tuning jobs, assistants, threads,
containers, and conversations. See
[Configuration reference](/docs/llm-proxy/configuration/reference/#authenforce).
The proxy records the owner of each object that a tenant creates. It refuses
a request for an object that the tenant does not own, or that no tenant owns.
An object created outside the proxy, or before the proxy recorded owners, has
no owner. Assign it with the admin API:

```sh
curl --max-time 5 -X PUT http://127.0.0.1:53422/tenants/acme/objects/file-abc123 \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN"
```

| Call | Answer |
|---|---|
| `PUT` | `204` when the tenant owns the object after the call, also when it owned it before. |
| `PUT` | `409` `object_owned` when another tenant owns the object. An owner is never replaced. |
| `PUT` | `404` `tenant_not_found` for an unknown tenant. |
| `PUT` | `409` `not_enforced` when `auth.enforce.object_ownership` is `false`. |
| `GET` | `200` with `{"tenant": "...", "object_id": "...", "owned": true, "expires_at": ...}`. `expires_at` is the expiry of the owner in Unix seconds, or `null` when the owner never expires. |
| `GET` | `404` `object_not_owned` in any other case. The answer does not say whether another tenant owns the object. |

An object whose owner expired has no owner, so it can be assigned again. An
assignment never expires. Both methods need the admin bearer token. The `GET`
reads the store, not the cache of one replica. It shows whether the owner
survives a restart (`persistent` store) and whether every replica sees it
(`shared` store).

The owner of a stored response or a stored chat completion expires after
`auth.stored_output_owner_ttl` (default `720h`). After that time the proxy
refuses the object to every tenant, the creator included. Assign the object
again with the `PUT` to give it back.

The proxy writes the owner to the store just after it sends the create
response. If the process stops in that instant, the object has no owner. Assign
it with the `PUT`.

Known limit: without a model in the body, `llmproxy.model_authz` refuses
multipart file uploads and bodyless `GET` requests to these endpoints with
`403`. Assign objects that were created outside the proxy with the `PUT`.

## Key model policy

`PUT /keys/{id}/policy` sets a model allow-list on one key. The call needs the
admin token, like the other writes. The body is the same as the body of
`PUT /tenants/{id}/policy`.

```bash
curl --max-time 5 -X PUT http://127.0.0.1:53422/keys/k1/policy \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -d '{"access":{"only":["gpt-4o"]},"deny":["gpt-4-old"]}'
```

| Status | Cause |
|---|---|
| `204` | The proxy stored the policy. |
| `400` | A pattern in `access.only` or `deny` is not an exact model name or one trailing `*`. The proxy stores nothing. |
| `404` | The key does not exist. The proxy stores nothing. |
| `409` | `auth.enforce.model_policy` is `false`. The body is `{"error":"not_enforced", ...}`. The proxy stores nothing. |

The effective models of a request are the tenant grant intersected with the
key list. These rules apply:

- A key only narrows. It never widens the grant of its tenant.
- A key with no policy keeps the grant of its tenant.
- `{"access":"all"}` returns the key to the grant of its tenant.
- A key policy also narrows when `tenants_without_policy` is `allow`.
- A refusal by a key policy is the same `403` as a refusal by a tenant
  policy. The `response_code_details` value is `model_not_permitted`.
- The change applies to the next request. No reload is needed.
- The policy persists with the configured store. It survives a restart on
  the persistent store.

`GET /keys` reports the policy of each key in the `policy` field. The value
is `null` when the key has no policy. Otherwise it has the shape of the
request body:

```json
{"key_id": "k1", "tenant": "tenant-a", "revoked": false,
 "policy": {"access": {"only": ["gpt-4o"]}, "deny": ["gpt-4-old"]},
 "budget": null}
```

A key set to `{"access":"all"}` lists as `{"access":"all"}`, not `null`.

## Tenant and key limits

`PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits` set rate limits. Both
calls need the admin token.

The body has one required key, `limits`. It can have the optional key
`schema_version`, which must be `1`.

```bash
curl --max-time 5 -X PUT http://127.0.0.1:53422/tenants/acme/limits \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -d '{"limits":{"tokens_per_minute":100000,"requests_per_minute":600,"concurrent_streams":20}}'
```

| Field in `limits` | Type | Default | What it limits |
|---|---|---|---|
| `tokens_per_minute` | integer, 0 or more | no limit | Tokens in one minute. |
| `requests_per_minute` | integer, 0 or more | no limit | Requests in one minute. |
| `concurrent_streams` | integer, 0 or more | no limit | Requests in flight at the same time. |

A field that you omit sets no limit of that kind. A value of `0` refuses
every request that the counter measures. To clear the limits, send
`{"limits": null}` or `{"limits": {}}`. A `limits` object with no limit
fields clears the stored row.

| Status | Cause |
|---|---|
| `204` | The proxy stored the limits, or cleared them. |
| `400` | The body is not valid. The `limits` key is missing, a field is unknown, or `schema_version` is not `1`. The proxy stores nothing. |
| `404` | The key does not exist (`PUT /keys/{id}/limits` only). The proxy stores nothing. |
| `409` | `auth.enforce.limits` is `false` and no `limits` entry adds the limiter. The body is `{"error":"not_enforced", ...}`. The proxy stores nothing. |

These rules apply:

- A request must pass the limits of its tenant and the limits of its key.
  The tenant sets the ceiling. A key only narrows it.
- A key with no limits is bound by its tenant alone.
- A window is one minute. Windows start on whole minutes (they are aligned to
  the Unix epoch), so the first window can be shorter than a minute. See
  [Configure rate limits](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/#windows).
- A write applies to the next request. No reload is needed.
- The limits persist with the configured store. They survive a restart on
  the persistent store.
- The proxy holds a concurrent-stream slot until the stream ends.
- The proxy checks token limits when the request arrives. It charges the
  actual usage when the stream ends. A stream in flight is never cut.

When a limit refuses a request, the proxy answers `429`. The body names the
limit, and the response has the headers `x-ratelimit-limit`,
`x-ratelimit-remaining`, `x-ratelimit-reset`, and `retry-after`:

| Limit | `429` body |
|---|---|
| `tokens_per_minute` | `token budget exceeded` |
| `requests_per_minute` | `request rate exceeded` |
| `concurrent_streams` | `too many concurrent streams` |

The dialect adds `llmproxy.token_limit` for you when `auth` is set. See
`auth.enforce.limits` in the
[Configuration reference](/docs/llm-proxy/configuration/reference/#authenforce).

**Caution.** Token and request counts are shared between replicas only when
`auth.store` is `shared`. They reconcile about once a second, so the fleet
can admit a little over a limit between reconciles. With the `in_memory` or
`persistent` store each replica counts alone, so N replicas can admit up to
N times a limit. Concurrent-stream slots follow the same rule: with the
`shared` store, the replicas share them through lease rows that expire 5
seconds after a replica stops.

`GET /v1/usage` does not report these limits. It reports only the `limits`
rule of the route in the config file.

`GET /keys` reports the limits of each key in the `limits` field. The value
is `null` when the key has no limits.

```json
{"key_id": "k1", "tenant": "tenant-a", "revoked": false,
 "policy": null, "budget": null,
 "limits": {"requests_per_minute": 60}}
```

## Tenant provider credentials

All routes are gated. The list route returns metadata only.

| Route | Method | What it does |
|---|---|---|
| `/tenants/{id}/provider_credentials` | GET | Lists the stored credentials of a tenant (metadata only) |
| `/tenants/{id}/provider_credentials/{provider}` | PUT | Stores or replaces a credential |
| `/tenants/{id}/provider_credentials/{provider}` | DELETE | Removes a credential |

Any method other than `DELETE` on the `{provider}` path routes to the `PUT`
handler, so a wrong method answers `405` with `... only accepts PUT`. Without
`auth.tenant_credentials` in the config, the `PUT` answers `503` with the code
`tenant_credentials_not_configured`. See
[Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/)
for setup, the save-time check, and error codes.

## Pricing

| Route | Method | Gated | What it does |
|---|---|---|---|
| `/pricing` | GET | No | Shows the active rate card |
| `/pricing` | PUT | Yes | Publishes a new rate card (up to 4 MiB) |

A successful `PUT` answers `200` with `rate_card_version`, `persisted`, and
`note`. The `note` says if the card survives a restart and if other replicas
see it. The `PUT` answers `400` for an invalid card, and for a card with an
`effective_from` in the future. It answers `503` with `the rate card was not
changed: the control-plane store refused it: ...` if the store refuses the
card. Without `auth`, the `PUT` still works, for this process only, and the
answer says so in `note`. `GET` answers `503` with `llmproxy.usage has no
active pricing rate card` if no card is active. See
[Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/).

## Limitations

- `admin.tls` takes one certificate. The admin port does not check client
  certificates.
- One token has full admin rights. There are no roles.
- The admin API has no audit log. The proxy writes an info log line for most
  writes.
- An id that contains `/` cannot be addressed. The proxy does not decode
  percent escapes.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. Route table, handlers, gate, and limits are in
`crates/proxy-admin/src/server.rs`.

- Admin TLS: `TransportCache` in `crates/proxy-admin/src/server/transport.rs`
  builds the acceptor from `ConfigSnapshot.admin_tls`
  (`node.metadata["io.llmproxy.admin_tls"]`) and owns the exposure warning.
  Tests: `crates/proxy/tests/admin_tls_e2e.rs`.

- Gate: `admin_gate` and `secrets_match`. Failure limiter:
  `crates/proxy-admin/src/server/auth_limit.rs` (`MAX_FAILURES`, `WINDOW`).
  Body limits: `MAX_PRICING_BODY_BYTES`, `MAX_ADMIN_BODY_BYTES`, and
  `read_limited_body`.
- Routing: `match_write_route` and `WriteRoute::expected_method`. Routing runs
  before the gate, so a wrong method gets `405`.
- Handlers: `handle_lifecycle`, `handle_mint_key`, `handle_set_key_budget`,
  `handle_set_budget`, `handle_set_key_policy`, `handle_set_tenant_limits`,
  `handle_set_key_limits`, `handle_set_pricing`, `handle_list_keys`,
  `parse_model_policy`, `store_error_response`, `render_model_access`,
  `render_limits`, and `LimitSpec::into_policy`.
- Key policy: `ControlPlane::set_key_policy` in
  `crates/proxy-control/src/control.rs` and `authorize_model` in
  `crates/proxy-filters/src/model_authz_filter.rs`. Tests:
  `put_key_policy_invalid_pattern_is_400_and_stores_nothing`,
  `put_key_policy_unknown_key_is_404_and_stores_nothing`,
  `put_key_policy_without_model_authz_is_409_and_stores_nothing`,
  `put_key_policy_all_lists_as_inherit_equivalent_all`,
  `key_only_narrows_tenant_all`, `key_policy_never_widens_tenant_grant`,
  `sibling_key_without_policy_inherits_tenant_all`,
  `key_all_inherits_restricted_tenant_grant`,
  `key_policy_narrows_tenants_without_policy_allow`, and
  `key_policy_write_changes_next_request_without_reload`. End-to-end:
  `a_key_policy_narrows_its_tenant_grant_and_never_widens_it` in `admin_e2e.rs`
  and `a_key_policy_survives_a_restart_with_a_persistent_store` in
  `auth_store_e2e.rs`.
- Limits: `SetLimitsRequest` and `LimitSpec` use `deny_unknown_fields`.
  `token_limit_enforced` decides the `409`. Tests in
  `crates/proxy-admin/src/server/tests/limits.rs`:
  `put_limits_unknown_key_and_unknown_fields_do_not_write` and
  `put_limits_without_token_limit_is_409_and_stores_nothing`. The test
  `limits_survive_a_restart_with_a_persistent_store` is in
  `tenant_enforcement_e2e.rs`. `POLICY_WINDOW`, `Refusal::body`, and `refuse`
  are in `crates/proxy-filters/src/token_limit_filter.rs`.
- Tests for other groups are in `crates/proxy-admin/src/server/tests/`:
  `object_owners.rs`, `credentials.rs`, `key_tags.rs`, `budget_scope.rs`,
  `ledger.rs`, `trace_export.rs`, `pricing.rs`, and `admin_rate_limit.rs`.
- UI: `admin-ui/src/App.tsx` defines the tab order. `scripts/install.sh` sets
  `LLMPROXY_ADMIN_UI_DIR` and prints the token.
