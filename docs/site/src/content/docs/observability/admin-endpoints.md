---
title: Admin endpoints
summary: Reference for every route the admin server answers, which routes
  need the admin token, the request body limits, and the admin UI.
last_updated: 2026-10-13
related:
  - ../authentication/virtual-keys/
  - ../authentication/tenant-provider-credentials/
  - ../limits-and-budgets/spend-policies/
  - ../operations/draining-and-shutdown/
  - ../observability/metrics-and-stats/
  - ../observability/request-capture/
---

# Admin endpoints

The admin server is an HTTP listener bound with the top-level `admin` field of
the config. See the [configuration file](../../configuration/configuration-file/)
reference. It serves read endpoints, a write API for keys, tenants, budgets,
credentials, and pricing, three lifecycle commands, and the admin UI.

This page lists each route and its auth rule. It does not repeat the request
and response details that other pages already own. Source of truth: the route
table and handlers in `crates/proxy-admin/src/server.rs`.

## Auth model

One rule decides if a route needs the admin token. A route is gated if it
changes state, or if it reads identity, money, or request data. All other
routes are open to any caller that can reach the admin port.

**Warning.** The admin port has no other access control. Bind it to a
loopback address, or put it behind a network you trust. Open routes such as
`/config_dump` answer any caller.

A gated route passes two checks in this order
(`server.rs`, `admin_gate`, line 1400):

1. The proxy must have the `LLMPROXY_ADMIN_TOKEN` environment variable set. If
   it is unset, empty, or only whitespace, the route answers `403` with the
   body `admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is
   not set`. An unset token never means open.
2. The request must carry `Authorization: Bearer <token>` with the same
   token. If it does not, the route answers `401` with a `www-authenticate`
   challenge and the body `missing or invalid bearer token`.

The proxy compares the token with a constant-time check (`secrets_match`).

**Caution.** After 10 missing or wrong bearer tokens from one peer IP within 60
seconds, the proxy refuses that peer's gated requests with `429` and a
`Retry-After` header (in seconds). This lasts until the 60-second window ends,
even if the peer then sends the right token. The limit covers all write
endpoints and the gated reads, such as `GET /keys`, spend reads, and capture
records. A correct token before the limit clears the count for that peer. The
proxy logs each refusal at warn with the peer IP and the endpoint. It never logs
the presented token.

| Route class | Routes | Gated |
|---|---|---|
| Probes and dumps | `GET /ready`, `/config_dump`, `/clusters`, `/server_info`, `/models` | No |
| Metrics | `GET /stats`, `/stats/prometheus` | No |
| Capture counters | `GET /capture/spool/stats` | No |
| Rate card read | `GET /pricing`, `GET /chains/{stat_prefix}/pricing` | No |
| Admin UI | `GET /ui`, `GET /ui/...` | No |
| Capture records | `GET /capture/spool/records` | Yes |
| Spend reads | `GET .../spend` for keys and tenants | Yes |
| Identity reads | `GET /keys`, `GET /tenants/{id}/provider_credentials` | Yes |
| All writes | `POST`, `PUT`, `DELETE` routes, and the lifecycle commands | Yes |

The proxy gates `/capture/spool/records` because records are end-user
metadata (`server.rs:1460`). It gates the spend and key-list reads because
they expose money and identity (`server.rs:641-649`).

Evidence for the open `GET /pricing`: the handler runs before the gate in
`handle` (`server.rs:538-547`). `PUT /pricing` passes the gate.

### Body size limits

| Route | Maximum request body | Source |
|---|---|---|
| `PUT /pricing`, `PUT /chains/{stat_prefix}/pricing` | 4 MiB (4,194,304 bytes) | `MAX_PRICING_BODY_BYTES`, `server.rs:142` |
| All other routes that read a body | 64 KiB (65,536 bytes) | `MAX_ADMIN_BODY_BYTES`, `server.rs:129` |

A body over the limit gets `413` with the body `request body exceeds the
<cap>-byte cap for this endpoint` (`read_limited_body`). The gate runs before
the body is read, so only a caller with the token can send a large body.

### Common errors

| Status | When |
|---|---|
| `404` | The path is unknown. The body lists the available endpoints. |
| `405` | The path exists but the method is wrong. The body is `<path> only accepts <METHOD>`. |
| `503` | Unscoped keys, tenants, or spend route, and no `llmproxy.auth` filter is built yet. |
| `500` | Unscoped route, and more than one chain configures `llmproxy.auth`. Use a `/chains/...` route. |

The `503` body is `the auth control plane is not initialized yet: ...`. The
`500` body starts with `the unscoped admin write API cannot resolve a single
auth control plane`.

## Scoped routes: `/chains/{stat_prefix}/...`

Each key, tenant, and pricing route has a second form that starts with
`/chains/{stat_prefix}`. The `stat_prefix` is the name of one HTTP connection
manager in the config. Use the scoped form when more than one filter chain
configures `llmproxy.auth`. The unscoped form then answers `500`.

A scoped route with an unknown `stat_prefix` answers `404` with the body
`no chain named '<name>' registers an llmproxy.auth control plane ...`
(`server.rs:721`). The auth, gate, and body rules are the same as for the
unscoped route.

## Read endpoints

| Route | Method | Answer |
|---|---|---|
| `/ready` | GET | `200 LIVE`, `503 INITIALIZING`, or `503 DRAINING` |
| `/config_dump` | GET | JSON of the loaded config snapshot |
| `/clusters` | GET | JSON list of clusters, sorted by name |
| `/models` | GET | JSON list of the models that the routes match on the `x-llmproxy-model` header |
| `/server_info` | GET | JSON with `version` and `uptime_seconds` |
| `/stats` | GET | Plain-text counters and histograms |
| `/stats/prometheus` | GET | Prometheus text format |

Without a probe wired in, `/ready` always answers `200 LIVE`
(`server.rs:557-565`). `/stats` and `/stats/prometheus` answer `404` if no
stats registry exists. The proxy does not return an empty `200`. See
[Metrics and /stats](../metrics-and-stats/) for the counters.

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
/drain_listeners; accepted: graceful, inboundonly` (`handle_lifecycle`,
`server.rs:853`). On success the answer is `200 OK`. See
[Draining and shutdown](../../operations/draining-and-shutdown/).

## Keys and tenants

All routes in this section are gated. Each also exists under
`/chains/{stat_prefix}`. Request fields are strict: an unknown field gives
`400`. See [Virtual keys](../../authentication/virtual-keys/) for the key
model and examples.

| Route | Method | Success | What it does |
|---|---|---|---|
| `/keys` | GET | `200` | Lists keys: `key_id`, `tenant`, `revoked`, `policy`, `budget`, `limits`. Sorted by tenant, then key id. |
| `/keys` | POST | `201` | Mints a key. Body: `tenant`, `key_id`. The answer holds the key text `key` once. |
| `/keys/{id}` | DELETE | `204` | Revokes a key. |
| `/keys/{id}/budget` | PUT | `204` | Sets or clears a key budget. |
| `/keys/{id}/policy` | PUT | `204` | Sets the model allow-list of one key. The key can only narrow its tenant grant. See "Key model policy". |
| `/keys/{id}/limits` | PUT | `204` | Sets or clears the rate limits of one key. The key can only narrow its tenant limits. See "Tenant and key limits". |
| `/keys/{id}/spend` | GET | `200` | Reads the spend of a key. |
| `/tenants` | POST | `201` | Creates a tenant. Body: `tenant`. |
| `/tenants/{id}` | DELETE | `204` | Deletes a tenant and revokes every key that authenticates as it. Minted keys are revoked and their rows stay. Config-file `auth.keys` entries for the tenant are revoked by a revoked store row with the same key id. That row wins on every replica that shares the store, and across restarts. Revoked key ids are permanent. The next request with any of those keys gets `401`. |
| `/tenants/{id}/policy` | PUT | `204` | Sets the model-access policy. Body: `access` (`all` or `{"only": [...]}`) and optional `deny`. An invalid pattern gives `400`. |
| `/tenants/{id}/budget` | PUT | `204` | Sets or clears the spend ceiling. |
| `/tenants/{id}/limits` | PUT | `204` | Sets or clears the rate limits of a tenant. See "Tenant and key limits". |
| `/tenants/{id}/spend` | GET | `200` | Reads the spend of a tenant. |
| `/tenants/{id}/trace_export` | PUT, GET | `204`, `200` | Sets or reads the trace-export opt-in of a tenant. Body: `{"schema_version": 1, "enabled": true}`. See [Trace export](../trace-export/). |
| `/traces/capture` | POST, GET | `200` | Closes or opens the trace-export emergency switch, or reads it. Body: `{"disabled": true, "expected_generation": N}`. A stale generation gives `409`. See [Trace export](../trace-export/). |

The mint answer is the only time the proxy returns the key text. The store
keeps a digest only (`handle_mint_key`, `server.rs:1846`).

The budget body is `{"budget": {"max_usd": "500.00", "period": "monthly"}}`
to set a ceiling, or `{"budget": null}` to clear it. The key budget and the
tenant budget use the same body shape (`handle_set_key_budget`,
`handle_set_budget`). See
[Spend policies](../../limits-and-budgets/spend-policies/) for periods, the
spend response, and how the proxy counts spend.

## Key model policy

`PUT /keys/{id}/policy` sets a model allow-list on one key. The scoped form
is `PUT /chains/{stat_prefix}/keys/{id}/policy`. The call needs the admin
token, like the other writes. The body is the same as the body of
`PUT /tenants/{id}/policy` (`parse_model_policy`, `server.rs:2489`).

```bash
curl -X PUT http://$ADMIN_ADDR/keys/k1/policy \
  -H "authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -d '{"access":{"only":["gpt-4o"]},"deny":["gpt-4-old"]}'
```

| Status | Cause |
|---|---|
| `204` | The proxy stored the policy. |
| `400` | A pattern in `access.only` or `deny` is not an exact model name or one trailing `*`. The proxy stores nothing. |
| `404` | The key does not exist. The proxy stores nothing. |
| `409` | No chain runs `llmproxy.model_authz`. The body is `{"error":"not_enforced", ...}`. The proxy stores nothing. |

Proof: `handle_set_key_policy` (`server.rs:2521`), `store_error_response`
(`server.rs:1759`), `ControlPlane::set_key_policy` (`control.rs:3377`), and the
tests `put_key_policy_invalid_pattern_is_400_and_stores_nothing`,
`put_key_policy_unknown_key_is_404_and_stores_nothing`, and
`put_key_policy_without_model_authz_is_409_and_stores_nothing`.

The effective models of a request are the tenant grant intersected with the
key list. These rules apply:

- A key only narrows. It never widens the grant of its tenant.
- A key with no policy keeps the grant of its tenant.
- `{"access":"all"}` returns the key to the grant of its tenant.
- A key policy also narrows when `tenants_without_policy` is `ALLOW`.
- A refusal by a key policy is the same `403` as a refusal by a tenant
  policy. The `response_code_details` value is `model_not_permitted`.
- The change applies to the next request. No reload is needed.
- The policy persists with the configured store. It survives a restart on
  the persistent store.

Proof: `authorize_model` (`model_authz_filter.rs:535`), the unit tests
`key_only_narrows_tenant_all`, `key_policy_never_widens_tenant_grant`,
`sibling_key_without_policy_inherits_tenant_all`,
`key_all_inherits_restricted_tenant_grant`,
`key_policy_narrows_tenants_without_policy_allow`, and
`key_policy_write_changes_next_request_without_reload`. The end-to-end tests
are `a_key_policy_narrows_its_tenant_grant_and_never_widens_it`
(`admin_e2e.rs:987`) and `a_key_policy_survives_a_restart_with_a_persistent_store`
(`auth_store_e2e.rs:52`).

`GET /keys` reports the policy of each key in the `policy` field. The value
is `null` when the key has no policy. Otherwise it has the shape of the
request body:

```json
{"key_id": "k1", "tenant": "tenant-a", "revoked": false,
 "policy": {"access": {"only": ["gpt-4o"]}, "deny": ["gpt-4-old"]},
 "budget": null}
```

A key set to `{"access":"all"}` lists as `{"access":"all"}`, not `null`
(`render_model_access`, `server.rs:1941`, and the test
`put_key_policy_all_lists_as_inherit_equivalent_all`).

## Tenant and key limits

`PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits` set rate limits. The
scoped forms are `PUT /chains/{stat_prefix}/tenants/{id}/limits` and
`PUT /chains/{stat_prefix}/keys/{id}/limits`. Both calls need the admin token
(`handle_set_tenant_limits`, `handle_set_key_limits`, `server.rs`).

The body has one required key, `limits`. It can have the optional key
`schema_version`, which must be `1`.

```bash
curl -X PUT http://$ADMIN_ADDR/tenants/acme/limits \
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
fields clears the stored row (`LimitSpec::into_policy`, `server.rs`).

| Status | Cause |
|---|---|
| `204` | The proxy stored the limits, or cleared them. |
| `400` | The body is not valid. The `limits` key is missing, a field is unknown, or `schema_version` is not `1`. The proxy stores nothing. |
| `404` | The key does not exist (`PUT /keys/{id}/limits` only). The proxy stores nothing. |
| `409` | No chain runs `llmproxy.token_limit`. The body is `{"error":"not_enforced", ...}`. The proxy stores nothing. |

Proof: `SetLimitsRequest` and `LimitSpec` (`deny_unknown_fields`),
`token_limit_enforced`, and `store_error_response` in `server.rs`. The test
`put_limits_unknown_key_and_unknown_fields_do_not_write` covers `400` and
`404`. The test `put_limits_without_token_limit_is_409_and_stores_nothing`
covers `409`. The test `scoped_put_limits_uses_named_chain_and_legacy_type_url`
covers the scoped route (`server/tests/limits.rs`).

These rules apply:

- A request must pass the limits of its tenant and the limits of its key.
  The tenant sets the ceiling. A key only narrows it.
- A key with no limits is bound by its tenant alone.
- A window is one minute (`POLICY_WINDOW`, `token_limit_filter.rs`). Windows
  start on whole minutes (they are aligned to the Unix epoch), so the first
  window can be shorter than a minute. See
  [Token rate limiting](../../limits-and-budgets/token-rate-limiting/#windows).
- A write applies to the next request. No reload is needed.
- The limits persist with the configured store. They survive a restart on
  the persistent store (test `limits_survive_a_restart_with_a_persistent_store`,
  `tenant_enforcement_e2e.rs`).
- The proxy holds a concurrent-stream slot until the stream ends.
- The proxy checks token limits when the request arrives. It charges the
  actual usage when the stream ends. A stream in flight is never cut.

When a limit refuses a request, the proxy answers `429`. The body names the
limit, and the response has the headers `x-ratelimit-limit`,
`x-ratelimit-remaining`, `x-ratelimit-reset`, and `retry-after`
(`Refusal::body` and `refuse`, `token_limit_filter.rs`):

| Limit | `429` body |
|---|---|
| `tokens_per_minute` | `token budget exceeded` |
| `requests_per_minute` | `request rate exceeded` |
| `concurrent_streams` | `too many concurrent streams` |

The dialect adds `llmproxy.token_limit` for you when `auth` is set. See
`auth.enforce.limits` in
[Configuration file](../../configuration/configuration-file/).

Caution: token and request counts are shared between replicas only when
`auth.store` is `shared`. They reconcile about once a second, so the fleet
can admit a little over a limit between reconciles. With the `in_memory` or
`persistent` store each replica counts alone, so N replicas can admit up to
N times a limit. Concurrent-stream slots follow the same rule: with the
`shared` store, the replicas share them through lease rows that expire 5
seconds after a replica stops.

`GET /v1/usage` does not report these limits. It reports only the `limits`
rule of the route in the config file (`token_limit_filter.rs`, module doc).

`GET /keys` reports the limits of each key in the `limits` field. The value
is `null` when the key has no limits (`render_limits`, `handle_list_keys`).

```json
{"key_id": "k1", "tenant": "tenant-a", "revoked": false,
 "policy": null, "budget": null,
 "limits": {"requests_per_minute": 60}}
```

## Tenant provider credentials

All routes are gated and also exist under `/chains/{stat_prefix}`. The list
route returns metadata only.

| Route | Method | What it does |
|---|---|---|
| `/tenants/{id}/provider_credentials` | GET | Lists the stored credentials of a tenant (metadata only) |
| `/tenants/{id}/provider_credentials/{provider}` | PUT | Stores or replaces a credential |
| `/tenants/{id}/provider_credentials/{provider}` | DELETE | Removes a credential |

Any method other than `DELETE` on the `{provider}` path routes to the `PUT`
handler, so a wrong method answers `405` with `... only accepts PUT`
(`server.rs:1086-1093`). Without `tenant_credentials` on the auth filter, the
`PUT` answers `503` with the code `tenant_credentials_not_configured`. See
[Tenant provider credentials](../../authentication/tenant-provider-credentials/)
for setup, the save-time check, and error codes.

## Pricing

| Route | Method | Gated | What it does |
|---|---|---|---|
| `/pricing` | GET | No | Shows the active rate card |
| `/pricing` | PUT | Yes | Publishes a new rate card (up to 4 MiB) |

Both routes also exist as `/chains/{stat_prefix}/pricing`. A successful `PUT`
answers `200` with `rate_card_version`, `persisted`, and `note`
(`handle_set_pricing`, `server.rs:1217`). The `PUT` answers `400` for an
invalid card. It answers `503` with `llmproxy.usage is not initialized on this
chain` if the chain has no usage filter. Without `llmproxy.auth`, the `PUT`
still works, for this process only, and the answer says so in `note`
(comment at `server.rs:687-690`). `GET` answers `503` with `llmproxy.usage
has no active pricing rate card` if no card is active.

## Capture endpoints

These routes inspect the spool of the capture agent. Both answer `404` with
`no capture agent is configured for this proxy; /capture/spool/* needs a
capture agent endpoint` if no capture agent is configured. See
[Request capture](../request-capture/) for the agent and its setup.

| Route | Gated | What it does |
|---|---|---|
| `GET /capture/spool/stats` | No | Counters of the spool. No record content. |
| `GET /capture/spool/records?after=<n>&limit=<n>` | Yes | One page of stored records |

For `records`, `after` is an unsigned integer and defaults to `0`. `limit`
is from 1 to 100 and defaults to `50`. An unknown or repeated parameter
gives `400` (`parse_records_query`, `server.rs:1500`). The answer holds
`records`, `next_after_sequence`, and `durable_through_sequence`. The stats
answer is cached for a short time.

When the agent refuses the query, the answer is `403` and the hint says that
the proxy grant needs `"inspect": true`. For an agent that does not support
inspection, the answer is `501`. For an unreachable agent, the answer is
`503 capture agent unavailable` (`capture_error`).

## Admin UI

The admin server serves a single-page UI at `/ui`. It needs no token to
load, because the page and its assets are static. The UI calls the same admin
API, so any gated action needs the admin token.

- **Address.** `http://<admin address>/ui/`. `GET /ui`, `GET /ui/`, and
  `GET /ui/<asset>` serve files. An unknown sub-path returns `index.html`.
  Other methods answer `405` (`server.rs:509-537`).
- **Tabs.** Overview, Clusters, Tenants, Keys, Pricing, and Capture, in this
  order (`admin-ui/src/App.tsx:14-19`).
- **Source.** `admin-ui/src`. Build it with `make ui-build`. The output is
  `admin-ui/dist/`.
- **Load.** Set `LLMPROXY_ADMIN_UI_DIR` to the build output directory and
  restart the proxy. If it is not set, `/ui` answers `404` with `the admin UI
  is not loaded for this server instance`.

The installer (`scripts/install.sh`) sets `LLMPROXY_ADMIN_UI_DIR` in the
service runner. It writes a generated admin token to the env file, and it
prints the line `Admin UI:   http://<host>:<port>/ui/` and the token. The
token is printed only for a new install (`install.sh:276-291`, `:504-513`).
Paste the token into the UI to make changes.

**Caution.** The admin port uses plain HTTP. The admin token crosses the
network unencrypted if you bind the port to a non-loopback address.
