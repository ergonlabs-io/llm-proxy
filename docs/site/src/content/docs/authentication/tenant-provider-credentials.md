---
title: Tenant provider credentials
summary: Let a tenant send its traffic on its own provider key. Covers strict
  tenant mode, Envoy-mode setup with the key-encryption key file and the
  cluster slot, the admin API and its save-time key check, access-log and
  counter attribution, budget scope, and what does not work yet.
last_updated: 2026-10-13
related:
  - ../authentication/virtual-keys/
  - ../authentication/managing-secrets/
  - ../providers-and-routing/providers-and-clusters/
  - ../providers-and-routing/failover-and-aggregates/
  - ../limits-and-budgets/spend-policies/
  - ../observability/access-logs/
  - ../observability/metrics-and-stats/
---

# Tenant provider credentials

A tenant can store its own provider key. When that tenant calls llm-proxy with
its virtual key, the proxy sends the tenant's key to the provider. The operator
key is not used for that tenant. The proxy stores the tenant key encrypted at
rest.

This page uses these terms:

- **Platform credential**: the provider key the operator configures on a
  cluster.
- **Tenant credential**: one provider key that one tenant stores.
- **Provider label**: the `provider` name in a cluster's `tenant_credential`
  slot. A tenant stores its key under this name. A tenant never picks a
  provider. Routes still pick aggregates.
- **Platform mode**: the tenant holds no stored credential. Requests use the
  platform credential. This is the default.
- **Tenant mode**: the tenant holds at least one stored credential. No attempt
  uses the platform credential.

Tenant credentials apply only to requests that carry a virtual key. A JWT
principal always uses the platform credential. See
[Limitations](#limitations).

## Strict tenant mode

Tenant mode is strict. A tenant in tenant mode never sends the platform
credential to any provider. Each attempt uses one of the outcomes below.

| Situation for one attempt | What the client gets | What the provider receives |
|---|---|---|
| Platform mode (no stored credential) | The provider's response | The platform credential, as before |
| Tenant mode, the cluster has a slot, and the tenant holds a usable key for the slot's provider | The provider's response | The tenant key, in the slot header |
| Tenant mode, the cluster has no slot, or the tenant holds no key for the slot's provider | `403`, error type `tenant_credential_missing` | Nothing. The provider is not dialled |
| Tenant mode, the stored key cannot be decrypted | `503`, body `provider credential failure` | Nothing. The provider is not dialled |
| Tenant mode, the provider answers `401` to the tenant key | The provider's `401`, passed through | The tenant key, on one attempt. No retry and no fallback |

The `403` reply has this body (`crates/proxy-http/src/router.rs`,
`tenant_credential_missing_reply`):

```json
{"error":{"message":"no tenant credential for provider openrouter","type":"tenant_credential_missing"}}
```

If the refused cluster has no slot, the message is `no tenant credential for
any provider this route can use`.

The `403` and the `503` from this step are final for the request. The proxy
does not retry them.

Aggregates follow the same rule. An aggregate skips each member that has no
slot, and each member whose provider the tenant does not hold. The proxy never
dials a skipped member. If no member is eligible, the reply is the `403` above.
Tests: `aggregate_skips_member_without_a_slot`,
`aggregate_skips_member_whose_provider_the_tenant_lacks`, and
`aggregate_with_no_eligible_member_is_403_and_dials_nothing` in
`crates/proxy-http/tests/router_tenant_credentials.rs`.

When a tenant credential applies, the proxy first applies the cluster's static
headers. Then it removes the `authorization`, `x-api-key`, and `api-key`
headers from the request. Then it sets the slot header to the tenant value. A
client header with one of those three names is removed too. The removal covers
only those three names. A cluster that places its platform key on another
header keeps that header (`crates/proxy-http/src/credential_provider.rs`,
`ProviderCredentials::apply`).

Deleting the last stored key for a tenant returns that tenant to platform mode
(`a_stored_tenant_key_replaces_the_operator_key_and_survives_a_restart` in
`crates/proxy/tests/tenant_credentials_e2e.rs`).

## Setup

You can set up tenant credentials in the `llmproxy` config file (`--config`) or
in an Envoy-mode bootstrap (`-c`). Both front ends load the same key ring and
the same slot. Step 1 is the same for both. Step 2 and step 3 show each front
end. The config file derives the slot for you, so it skips step 3.

### 1. Create the key-encryption key file

The proxy seals every stored tenant key with a 32-byte AES-256 key. Store that
key in a file. The file must meet these rules. The proxy refuses to load a
file that breaks any of them.

- It is a regular file. A symbolic link fails, because the check reads the
  link's own metadata (`crates/proxy-filters/src/tenant_credential_crypto.rs`,
  `CredentialKek::load`).
- It has no group or other permission bits. Mode `0600` passes. Mode `0644`
  fails with `credential key file must not be group- or world-accessible`.
- It holds exactly 32 raw bytes. Any other length fails with `credential key
  file must contain exactly 32 bytes`.

Create a file that meets these rules:

```sh
head -c 32 /dev/urandom > /etc/llmproxy/credential-kek
chmod 600 /etc/llmproxy/credential-kek
```

Check the size with `wc -c` and the mode with `ls -l`. The output of `ls -l`
starts with `-rw-------`.

### 2. Enable the key ring

#### In the `llmproxy` config file

Set `auth.tenant_credentials` and turn the feature on for each provider with
`tenant_credentials: true`. A provider that opts in without the key ring is a
load error. A key ring with no opted-in provider loads and adds no slot
(`key_ring_without_an_opted_in_provider_adds_no_slot` in
`crates/proxy-simple-config/tests/tenant_credentials.rs`).

Tenant credentials require a durable store: `persistent` (redb, one replica) or
`shared` (Redis, several replicas). Setting `auth.tenant_credentials` with
`auth.store` absent or `in_memory` is a load error at `auth.tenant_credentials`,
and the proxy does not start. Without that check, tenant keys would be lost on
restart, and tenants would fall back to the operator key.

With `shared`, every replica reads the same encrypted rows from Redis. A key
stored through one replica's admin API reaches the other replicas at their next
policy poll. Every replica must have the same key-encryption key files: a replica
that cannot decrypt a row answers that tenant's requests with `503` and never
uses the operator key.

```yaml
version: 0
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  store:
    persistent:
      path: /var/lib/llmproxy/control.redb
  tenant_credentials:
    encryption_key_file: /etc/llmproxy/credential-kek
    encryption_key_id: kek-2026-10
providers:
  openrouter:
    type: openrouter
    api_key: ${OPENROUTER_PLATFORM_KEY}
    tenant_credentials: true
routes:
  - model: "*"
    provider: openrouter
```

The field reference is in
[Configuration file](../../configuration/configuration-file/), section
`auth.tenant_credentials`.
The header is derived from the provider type. `anthropic` uses `x-api-key`,
`azure-openai` uses `api-key`, and the other header types use `Authorization:
Bearer`. `vertex` and `bedrock` are rejected at `tenant_credentials`.

#### In Envoy mode

Add the block to the `llmproxy.auth` filter's `typed_config`. The filter also
needs a durable store, `persistent` or `shared`. With `tenant_credentials` set,
an absent or `in_memory` store is a load error at `typed_config.tenant_credentials`.

```yaml
http_filters:
  - name: llmproxy.auth
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
      hmac_secret: { inline_string: "replace-with-your-hmac-secret" }
      persistent:
        path: /var/lib/llmproxy/control.redb
      tenant_credentials:
        encryption_key_file: /etc/llmproxy/credential-kek
        encryption_key_id: kek-2026-10
        previous_keys: []
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

| Field | Type | Required | What it does |
|---|---|---|---|
| `encryption_key_file` | string (path) | yes | The key file from step 1. New keys are sealed under this key. |
| `encryption_key_id` | string | yes | Names this key. The id is stored in plaintext beside each sealed key, so the proxy can pick the right key to open it. |
| `previous_keys` | list of `{id, file}` | no | Retired keys. Each one opens rows sealed before a rotation. It never seals new rows. Each `id` and `file` is required. |

Every id must be unique across `encryption_key_id` and `previous_keys[].id`.
A duplicate fails the load. The proxy reads the key files once per serve,
when it first builds the filter chain. Restart the proxy to load a changed
key file or a changed list.

The `tenant_credentials` block does not change the `auth` store. Keys minted
through the admin API still live in the store the filter selects.

### 3. Add the slot to each cluster that a tenant may use (Envoy mode only)

The slot tells the router which provider a cluster belongs to and where the
tenant key goes. Add it under the cluster's `io.llmproxy.provider_auth`
metadata, beside any platform `headers`. The config file does this for each
provider with `tenant_credentials: true`:

```yaml
clusters:
  - name: openrouter
    type: STATIC
    connect_timeout: 2s
    metadata:
      filter_metadata:
        io.llmproxy.provider_auth:
          headers:
            - { key: authorization, value: "Bearer replace-with-platform-key" }
          tenant_credential: { provider: openrouter, header: authorization, prefix: "Bearer ", verify_path: /api/v1/key }
    load_assignment:
      cluster_name: openrouter
      endpoints:
        - lb_endpoints:
            - endpoint:
                address:
                  socket_address: { address: openrouter.example, port_value: 443 }
```

The endpoint and the transport settings above are placeholders. Use the
transport settings your provider needs.

| Slot field | Required | What it does |
|---|---|---|
| `provider` | yes, non-empty | The provider label. Tenants store keys under this name. |
| `header` | yes | The request header that carries the key. Stored in lowercase. Must be a valid HTTP header name. |
| `prefix` | no, default empty | Text put before the key in the header value. `Bearer ` for `Authorization`. Must not contain CR, LF, or control characters. |
| `verify_path` | no, no default | The path of the `GET` that checks a key when it is saved. Must start with `/`. Without it, `PUT` with `verify` set to `true` returns `422 credential_verification_not_configured`. See [Save-time check](#save-time-check). |

Rules for the slot:

- Only header API-key shapes are supported. A cluster with Vertex OAuth2 or
  Bedrock SigV4 credentials cannot carry a slot. The load fails
  (`tenant_credential_with_vertex_or_bedrock_is_a_hard_error` in
  `crates/proxy-config/tests/provider_auth_metadata.rs`).
- An unknown key inside the slot is a load error that names its full path.
  A typo such as `provder` fails. Test:
  `tenant_credential_unknown_key_names_the_full_dotted_path`.
- A cluster with a slot and no platform headers loads. Test:
  `tenant_credential_slot_alone_lowers_to_provider_runtime`.

### 4. Start the proxy

```sh
llm-proxy --config /etc/llmproxy/llmproxy.yaml
```

or, in Envoy mode:

```sh
llm-proxy -c /etc/llmproxy/bootstrap.yaml
```

The proxy runs in `serve` mode by default. Restart it after any change to the
key files, `previous_keys`, or the store.

### 5. Create the tenant, its virtual key, and its stored key

Create the tenant and a virtual key as described in
[Virtual keys](../../authentication/virtual-keys/#managing-keys-and-tenants-at-runtime).
Then store the tenant key. The proxy checks the key with the provider before it
stores it. The next request from that tenant uses the key.

```sh
curl --max-time 10 -X PUT \
  -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"schema_version":1,"api_key":"<the tenant key>","verify":true}' \
  http://127.0.0.1:9901/tenants/acme/provider_credentials/openrouter
```

Replace `127.0.0.1:9901` with the `admin.address` in your bootstrap. `verify`
is optional. Leave it out to check the key. A successful call returns `200`
and metadata. The response never includes the key:

```json
{"tenant":"acme","provider":"openrouter","last4":"9f2K","fingerprint":"3c1a7e0b5d8f2a94","created_at":"2026-10-11T08:00:00Z","updated_at":"2026-10-11T08:00:00Z","verified_at":"2026-10-11T08:00:00Z","policy_generation":7}
```

The values above are examples. `verified_at` is set because the provider
accepted the key during the check. A key stored with `"verify": false` has
`verified_at` set to `null`.

### Save-time check

`PUT` checks the key with the provider before it stores the key. This is the
save-time check. It runs when `verify` is `true`, which is the default. Send
`"verify": false` to store the key without the check.

The check sends one request to the provider:

- **Method and path.** `GET` to the slot's `verify_path`, as is. The cluster's
  path rewrite does not apply.
- **Headers.** The cluster's static headers. Then the proxy removes
  `authorization`, `x-api-key`, and `api-key`. Then it sets the slot header to
  the candidate key. The check does not forward any header from the admin
  request.
- **Connection.** The cluster's own endpoints, transport, TLS settings, and
  upstream protocol.
- **Time limit.** 5 seconds, from connect to the response head.
- **Body.** The proxy never reads the response body. It keeps only the status.

If more than one cluster has a slot for the provider with a `verify_path`, the
proxy uses the cluster whose name sorts first.

The path is set in each front end:

| Front end | Where the path is set | Default |
|---|---|---|
| `llmproxy` config file | `providers.<name>.tenant_credential_verify_path`. Requires `tenant_credentials: true`. | `/api/v1/key` for `openrouter`. `/v1/models` for `openai` and `anthropic`. None for the other types. None when `base_url` is set. |
| Envoy mode | `verify_path` in the `tenant_credential` slot under `io.llmproxy.provider_auth`. | None. Set it in the slot. |

A path must start with `/`. It must be at most 2048 bytes. It must contain only
printable ASCII, no `#`, and it must be a valid URI path with an optional
query. The proxy refuses any other value when it loads the config.

Each result of the check, and the response that `PUT` returns:

| Result of the check | `PUT` status | Error type | `upstream_status` | Key stored |
|---|---|---|---|---|
| `2xx` | `200` | none | none | Yes, with `verified_at` set |
| `401` or `403` | `422` | `credential_rejected` | `401` or `403` | No |
| Any other status, such as `3xx`, `429`, or `5xx` | `502` | `credential_verification_unavailable` | The status | No |
| No response within 5 seconds | `502` | `credential_verification_unavailable` | none | No |
| Connect failure, TLS failure, protocol error, or no healthy host | `502` | `credential_verification_unavailable` | none | No |
| No cluster slot has a `verify_path` for this provider, or the admin server has no probe | `422` | `credential_verification_not_configured` | none | No |

The proxy checks the key-encryption keys before it sends the key. With no
key-encryption keys, `PUT` returns `503` and the key does not reach the
provider.

The checks run in this order. The first failure ends the request:

1. The request body. Returns `400`.
2. The tenant. Returns `404`.
3. The provider label on a cluster. Returns `422 provider_not_enabled`.
4. The key-encryption keys. Returns `503 tenant_credentials_not_configured`.
5. The save-time check, when `verify` is `true`. Returns the `422` or `502` above.
6. The store.

On any failure, the proxy stores nothing. A key that was already stored stays
as it was. A `PUT` that replaces a key sets `verified_at` only when the new key
passes the check. The old key's `verified_at` does not carry over.

Example `PUT` error when the provider rejects the key:

```json
{"error":{"message":"the provider rejected this API key","type":"credential_rejected","upstream_status":401}}
```

### Rotate the key-encryption key

1. Create a new key file that meets the rules in step 1.
2. Move the current key into `previous_keys`, with its current id and file.
   Set `encryption_key_id` and `encryption_key_file` to the new key.
3. Restart the proxy.

New keys are sealed under the new key. Existing rows still open under the
previous key. The proxy does not re-seal existing rows. Only a new `PUT` seals
a row under the new key (`rotation_opens_old_rows_and_reseals_under_the_new_key`
in `crates/proxy-filters/src/tenant_credential_crypto.rs`). The metadata does
not show which key sealed a row. Keep each previous key listed while any tenant
might still hold a row sealed under it.

If you remove a key from the list and a row still needs it, that row fails
closed. The tenant then gets `503` until it stores the key again
(`rotation_keeps_old_rows_openable_only_while_the_old_key_is_listed` in
`crates/proxy-filters/src/control.rs`).

## Admin API

Three routes manage a tenant's stored keys. They sit under the same bearer
token as the other admin write routes. Set `LLMPROXY_ADMIN_TOKEN` and send it
as `Authorization: Bearer`. The routes also accept the scoped
`/chains/{stat_prefix}/...` form. See
[Virtual keys](../../authentication/virtual-keys/#managing-keys-and-tenants-at-runtime).

| Method and path | Request body | Success |
|---|---|---|
| `PUT /tenants/{id}/provider_credentials/{provider}` | `{"schema_version":1,"api_key":"...","verify":true}`. `verify` is optional and defaults to `true`. | `200` with the metadata shown in step 5 |
| `GET /tenants/{id}/provider_credentials` | none | `200` with `{"schema_version":1,"tenant":"...","credentials":[...]}`, sorted by provider |
| `DELETE /tenants/{id}/provider_credentials/{provider}` | none | `204`, empty body |

`{provider}` is the provider label from a cluster's slot. A `PUT` for a
tenant and provider replaces the stored key. The `created_at` value stays the
same, and `updated_at` changes.

The API never returns the key. It returns only `last4` (the last four
characters) and `fingerprint`. The fingerprint is a keyed HMAC of the key. It
uses a key derived from `hmac_secret`, so it changes if `hmac_secret` changes.
Decryption does not depend on `hmac_secret`.

Status codes for `PUT`, from `crates/proxy-admin/src/server.rs`
(`put_tenant_credential_inner`). The order of the checks is in
[Save-time check](#save-time-check).

| Status | Body | When |
|---|---|---|
| `200` | Metadata JSON | The key is stored. `verified_at` is set when the save-time check got a `2xx`. It is `null` when `verify` is `false`. |
| `400` | `{"error":{"type":"invalid_request",...}}` | The body is not JSON. Or it has an unknown field, a `verify` that is not a boolean, a `schema_version` other than `1`, an empty or whitespace-only `api_key`, an `api_key` over 4096 bytes, or bytes that cannot go in an HTTP header. Also an empty tenant or provider. |
| `401` | Empty, with `www-authenticate` | The bearer token is missing or wrong. |
| `403` | Text | `LLMPROXY_ADMIN_TOKEN` is unset, empty, or whitespace-only. |
| `404` | `{"error":{"type":"tenant_not_found","message":"unknown tenant"}}` | The tenant does not exist. |
| `422` | `{"error":{"type":"provider_not_enabled",...}}` | No cluster has a slot with this provider label. |
| `422` | `{"error":{"type":"credential_rejected","upstream_status":401,...}}` | The save-time check got `401` or `403`. `upstream_status` is that status. Nothing is stored. |
| `422` | `{"error":{"type":"credential_verification_not_configured",...}}` | No cluster slot has a `verify_path` for this provider, or the admin server has no probe. Nothing is stored. Send `"verify": false` to store the key unchecked. |
| `500` | `{"error":{"type":"credential_seal_failed",...}}` | The key could not be sealed. |
| `500` | Text | The store refused the write, for example Redis was not reachable. |
| `502` | `{"error":{"type":"credential_verification_unavailable",...}}` | The save-time check got another status, timed out, or could not connect. `upstream_status` is present only when the provider answered. Nothing is stored. |
| `503` | `{"error":{"type":"tenant_credentials_not_configured",...}}` | The auth filter has no `tenant_credentials` block, so no key-encryption keys are loaded. Checked before the save-time check, so the key is not sent to the provider. |

Status codes for `GET` and `DELETE`:

| Method | Status | When |
|---|---|---|
| `GET` | `200` | Lists the tenant's credentials. Nothing is decrypted. |
| `GET`, `DELETE` | `401`, `403` | As for `PUT`. |
| `GET`, `DELETE` | `404` JSON `tenant_not_found` | The tenant does not exist. |
| `DELETE` | `404` text `not found` | The tenant exists, but holds no key for this provider. |
| `DELETE` | `204` | The key is deleted. The tenant's next request uses the platform credential if it holds no other key. |

Error messages carry fixed text. A client never sees the key in a response,
in a log line, or in an error message. The admin tests check this for every
status above (`crates/proxy-admin/src/server/tests/credentials.rs`).

## Observability

### Access log

Two access-log operators show the attribution:

| Operator | Renders |
|---|---|
| `%LLM_TENANT%` | The authenticated tenant id. `-` when the request is not authenticated. |
| `%LLM_CREDENTIAL_SOURCE%` | `platform` or `tenant`. The source of the last provider credential applied to this request. `-` when no credential was applied, for example after a `403 tenant_credential_missing`. |

Both operators are in the [access log reference](../../observability/access-logs/#the-operator-set).
Test: `access_log_renders_the_credential_source_the_router_chose` in
`crates/proxy-http/tests/router_tenant_credentials.rs`.

The fixed access-log formats of the `llmproxy` config file include
`%LLM_TENANT%` but not `%LLM_CREDENTIAL_SOURCE%`. To log the credential
source, use Envoy mode and set `log_format` on the access logger
(`crates/proxy-simple-config/src/lower.rs`, `ACCESS_LOG_TEXT_FORMAT` and
`lower_access_log`).

### Counter

The router counts each tenant-mode decision in
`llmproxy_tenant_credential_requests_total`, with the labels `provider` and
`outcome`. Platform-mode requests do not touch the counter.

| `outcome` | Meaning | Status |
|---|---|---|
| `applied` | The tenant's key was applied to the attempt. | Continues to the provider |
| `missing` | No slot on the cluster, or the tenant holds no key for the slot's provider. | `403` |
| `unusable` | The stored key cannot be decrypted. | `503` |

`provider` is the slot's provider label. It is `-` when the refused cluster
has no slot. The counter has no tenant label, because tenant ids are not
bounded. Each `provider` value must come from configuration. The counter
stops adding new series at 256, and later provider values fold into
`-cardinality-overflow-`.

The counter appears only on `/stats/prometheus`, and the rendered name is
`envoy_llmproxy_tenant_credential_requests_total`. The flat `/stats` output
omits it (`crates/proxy-observability/src/stats.rs`,
`TENANT_CREDENTIAL_REQUESTS`; `crates/proxy-observability/src/stats/prometheus_render.rs`).

### Request records

Each request record has a `credential_source` field. Each attempt record has
one too. The field is optional under schema version 1
(`crates/proxy-observability/src/records.rs`, `RequestRecord` and
`AttemptRecord`). A record written before this field existed has no value.
Read a missing value as `platform`. A `null` value on a new record means that
no attempt reached a credential. It does not mean `platform`. A `403` or a
`503` from this step can produce `null`.

Records leave the proxy only when you start it with `--request-records-file`
or `--request-records-agent` (`crates/proxy/src/main.rs`, the
`capture_destination` group).

## Budgets

Each spend budget has one credential scope, `platform` or `tenant`. A budget
is enforced and charged only for requests in its scope.

- A **platform-scoped** budget applies to platform-mode requests. In tenant
  mode the budget is ignored. It sets no ceiling and records no spend.
- A **tenant-scoped** budget applies to tenant-mode requests only.
- A subject with no budget records all of its spend, in both modes.
- A subject with a budget records only the spend in the budget's scope. Its
  spend report shows that scope only.

The admin API sets the scope. Send `credential_source` with the budget. The
tenant and key budget routes take the same body:

```sh
curl --max-time 10 -X PUT \
  -H "Authorization: Bearer $LLMPROXY_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"budget":{"max_usd":"10.00","period":"monthly","credential_source":"tenant"}}' \
  http://127.0.0.1:9901/tenants/acme/budget
```

`credential_source` takes `"platform"` or `"tenant"`. Leave it out for
`platform`, which keeps the meaning that existing budgets had. Any other value
returns `400` and stores nothing. The `400` message does not echo the value
(`budget_from_spec` in `crates/proxy-admin/src/server.rs`, and
`crates/proxy-admin/src/server/tests/budget_scope.rs`).

The scope shows in three places. The key listing (`GET /keys`) returns it inside
each `budget` object, and `budget` is `null` when the key has no budget. Both
spend reads, `GET /tenants/{id}/spend` and `GET /keys/{id}/spend`, return it at
the top level. It is `null` when there is no budget.

A tenant with a platform-scoped budget and its own stored key is not limited
by that budget. Its tenant-mode spend is not recorded against it. Budget rows written before the scope existed read as
platform-scoped (`crates/proxy-filters/src/spend_limit_filter.rs`, the module
doc and `on_request_headers`; `crates/proxy-filters/src/control.rs`,
`legacy_credential_source`).


## Limitations

- **Virtual-key principals only.** A JWT principal reads no control-plane
  snapshot, so it always uses the platform credential. Its records show
  `platform` (`crates/proxy-filters/src/jwt_auth.rs`, which sets
  `tenant_credentials: None`).
- **One check, at save time.** `PUT` checks the key once, before it stores the
  key. The proxy does not check the key again. If the provider revokes the key
  later, `verified_at` does not change. The tenant's next request then gets the
  provider's `401`, passed through as in the strict tenant mode table.
- **No mixed mode.** A tenant in tenant mode uses only its own keys. A request
  that needs a provider the tenant lacks gets a `403`. It does not use the
  platform credential for that provider.
- **Durable store only.** With tenant credentials configured, the default
  `in_memory` store is a load error, because it loses the keys on restart and
  tenants would then silently use the platform credential. Use `persistent` or
  `shared`. A config that sets `auth.tenant_credentials` or Envoy's
  `tenant_credentials` with another store fails at load and names the field
  path (`crates/proxy-filters/src/auth_filter.rs`, `parse_config`).
- **Header shapes.** Only the `Authorization`, `x-api-key`, and `api-key` shapes
  work. A cluster with Vertex OAuth2 or Bedrock SigV4 cannot carry a slot.
- **Three header names are cleared.** In tenant mode the proxy clears only
  `authorization`, `x-api-key`, and `api-key`. A platform key on another header
  is still sent with the tenant key.
- **Lost key-encryption keys.** If you lose every key-encryption key, the stored
  keys cannot be recovered. Those rows fail closed (`503`). Each tenant must
  store its key again. Keep a copy of the key file.
- **Key files are read at start.** A changed key file takes effect only after a
  restart.
- **Plaintext in memory.** Each replica holds the tenant keys it uses as
  plaintext in memory while the rows are current.
- **Key-file errors name the Envoy path.** In the `llmproxy` config file, a bad
  key file, a bad permission, or a duplicate id fails the load with the path
  `typed_config.tenant_credentials.…`, not `auth.tenant_credentials.…`. The
  rejection is the same. Only the path differs. Presence and empty-value checks
  in the config file use the `auth.tenant_credentials.…` path
  (`crates/proxy-simple-config/src/lower.rs`, `lower_tenant_credentials`).
- **Rollback.** A build from before budget scopes has no scope field. It
  ignores `credential_source` on a budget row. It then applies that budget to
  all traffic, and charges all spend to it
  (`crates/proxy-filters/src/control.rs`, `EncodedTenantBudget`, which has no
  `deny_unknown_fields`). Remove tenant-scoped budgets before a rollback. No
  test covers this rollback path.

## Troubleshooting

### `403` with `"type":"tenant_credential_missing"`

- **Cause.** The cluster that the request reached has no slot, or the tenant
  holds no key for the slot's provider. Every refusal increments
  `llmproxy_tenant_credential_requests_total` with `outcome="missing"`. Some
  refusal paths also log `tenant has no credential slot match for the selected
  cluster` at `warn`. Do not rely on that line alone.
- **Fix.** Compare the slot's `provider` with the `{provider}` in the `PUT`
  path. Check the stored keys with `GET /tenants/{id}/provider_credentials`.
  Store the missing key under the provider label.

### `503` with the body `provider credential failure`

- **Cause.** The stored key for the tenant and provider cannot be decrypted.
  The proxy logs one of two warnings. `stored tenant credential cannot be
  decrypted; this tenant's requests fail closed (503)` names a `reason` of
  `unknown_key_id` (the key that sealed the row is no longer listed) or
  `decrypt_failed` (the row does not match the key, or the row was changed).
  The router also logs `tenant credential is unusable (decryption failed);
  failing closed`.
- **Fix.** Restore the old key file and list it in `previous_keys` with its
  original id. Restart. Or ask the tenant to store its key again.

### The log says `tenant_credentials` is not configured

- **Cause.** The store holds tenant keys, but the auth filter has no
  `tenant_credentials` block. The log line is `tenant credentials are stored
  but tenant_credentials is not configured on the auth filter; this tenant's
  requests fail closed (503)`.
- **Fix.** Add the block from step 2 and restart. Until you do, every tenant
  with a stored key gets `503`.

### `PUT` returns `503` with `tenant_credentials_not_configured`

- **Cause.** The auth filter has no `tenant_credentials` block.
- **Fix.** Add the block from step 2 and restart.

### `PUT` returns `422` with `provider_not_enabled`

- **Cause.** No cluster has a slot whose `provider` equals the `{provider}` in
  the path. The check is exact.
- **Fix.** Use the slot's `provider` value in the path.

### `PUT` returns `422` with `credential_rejected`

- **Cause.** The provider answered the save-time check with `401` or `403`.
  The `upstream_status` field holds that status. The proxy logs `admin:
  provider rejected a tenant credential at save time` at `info`. Nothing is
  stored.
- **Fix.** Check the key at the provider. Send the key again with `PUT`. Use
  `"verify": false` only when you accept a key that the proxy did not check.

### `PUT` returns `502` with `credential_verification_unavailable`

- **Cause.** The provider answered with a status other than `2xx`, `401`, or
  `403`. Or it did not answer within 5 seconds. Or the proxy could not connect.
  `upstream_status` is present only in the first case. A connect failure logs
  `admin: could not reach the provider to verify a tenant credential` at `warn`,
  with a `reason`. A timeout and a status error log no line. Nothing is stored.
- **Fix.** Check that the cluster's endpoint and transport settings match the
  provider. Check the provider's status. Then send the `PUT` again. If the
  provider is down and you must store the key now, send `"verify": false`.

### `PUT` returns `422` with `credential_verification_not_configured`

- **Cause.** No cluster slot for this provider has a `verify_path`. Envoy mode
  has no default path. Or the admin server has no probe.
- **Fix.** Set `verify_path` in the slot (Envoy mode). Or set
  `tenant_credential_verify_path` on the provider (`llmproxy` config file). Or
  send `"verify": false` to store the key unchecked.

### The tenant's key stops applying after a restart

- **Cause.** The `persistent.path` changed, or its redb file was deleted. Keys
  live only in that file. With `shared`, the Redis data or the store namespace
  changed.
- **Fix.** Keep `persistent.path` on the same file, or `shared` on the same
  Redis data and namespace, across restarts. The proxy refuses to start with
  tenant credentials on an absent or `in_memory` store, so the keys cannot be
  dropped that way. Keys stored against the old store must be stored again.
