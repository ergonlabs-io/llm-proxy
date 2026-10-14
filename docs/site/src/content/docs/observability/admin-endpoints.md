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
| `/keys` | GET | `200` | Lists keys: `key_id`, `tenant`, `revoked`, `budget`. Sorted by tenant, then key id. |
| `/keys` | POST | `201` | Mints a key. Body: `tenant`, `key_id`. The answer holds the key text `key` once. |
| `/keys/{id}` | DELETE | `204` | Revokes a key. |
| `/keys/{id}/budget` | PUT | `204` | Sets or clears a key budget. |
| `/keys/{id}/spend` | GET | `200` | Reads the spend of a key. |
| `/tenants` | POST | `201` | Creates a tenant. Body: `tenant`. |
| `/tenants/{id}` | DELETE | `204` | Deletes a tenant and revokes every key that authenticates as it. Minted keys are revoked and their rows stay. Config-file `auth.keys` entries for the tenant are revoked by a revoked store row with the same key id. That row wins on every replica that shares the store, and across restarts. Revoked key ids are permanent. The next request with any of those keys gets `401`. |
| `/tenants/{id}/policy` | PUT | `204` | Sets the model-access policy. Body: `access` (`all` or `{"only": [...]}`) and optional `deny`. |
| `/tenants/{id}/budget` | PUT | `204` | Sets or clears the spend ceiling. |
| `/tenants/{id}/spend` | GET | `200` | Reads the spend of a tenant. |

The mint answer is the only time the proxy returns the key text. The store
keeps a digest only (`handle_mint_key`, `server.rs:1846`).

The budget body is `{"budget": {"max_usd": "500.00", "period": "monthly"}}`
to set a ceiling, or `{"budget": null}` to clear it. The key budget and the
tenant budget use the same body shape (`handle_set_key_budget`,
`handle_set_budget`). See
[Spend policies](../../limits-and-budgets/spend-policies/) for periods, the
spend response, and how the proxy counts spend.

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
