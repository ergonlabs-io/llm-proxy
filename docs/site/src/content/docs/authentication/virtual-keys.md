---
title: Virtual keys
description: "How llm-proxy authenticates callers with virtual keys or JWTs and decides which models each tenant may use."
summary: How downstream authentication works. The `auth:` block, the
  `llmp_`-prefixed bearer credential, keyed HMAC-SHA256 verification, JWT
  providers, and why the token limiter buckets on the resolved tenant rather
  than the client's header.
lastUpdated: 2026-10-21
related:
  - authentication/managing-secrets
  - authentication/tenant-provider-credentials
  - configuration/configuration-file
  - providers/overview
  - administration/admin-api
  - limits-and-budgets/chargeback-tags
---

Use virtual keys to make callers prove who they are before a request reaches
a provider. A virtual key is an opaque bearer token that llm-proxy issues. It
is not a provider API key. It identifies a caller to llm-proxy. The provider
credential is a separate value on the provider. See
[Providers overview](/docs/llm-proxy/providers/overview/).

To enable virtual keys, add an `auth:` block to the config file. Without
`auth:`, the proxy does no application-level authentication. After the proxy
authenticates a request, it removes the `Authorization` header. A provider
never receives the virtual key.

## At a glance

- **Default when unset:** no `auth:` block means no authentication. Every
  caller reaches every route.
- **Failure mode:** with an `auth:` block, authentication and model access
  fail closed. A request with no valid credential gets `401`. A tenant with no
  model policy gets `403`.
- **Credentials:** a virtual key (`llmp_...`) or, with `auth.jwt`, a JWT.
- **Changes:** `auth` is fixed at startup. A `SIGHUP` reload that changes it is
  refused. Use the admin API to change keys and policies on a running proxy.

## Configure `auth:`

```yaml
version: 1
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  keys:
    - id: alice-laptop
      tenant: acme
      digest: 3f2a1e9c7b4d5f6a8e0c2b1d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a
      revoked: false
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
```

Set exactly one of `hmac_secret` or `hmac_secret_file`. To generate the
`digest` value, see
[Manage configured virtual keys](/docs/llm-proxy/authentication/managing-secrets/).

An empty `keys: []` list is valid. If no other source supplies keys, it
refuses every request because nothing authenticates, and the config format
emits a load-time warning for it. Keys minted through the admin API are
another source, so there is no warning when `auth.store` is `shared` or
`persistent`, when `admin` is set, or when `auth.jwt` is set.

A client sends the key as a bearer token:

```text
Authorization: Bearer llmp_<the key>
```

Generate a key with `llm-proxy --mode keygen`. The key is `llmp_` followed by
32 random bytes from the OS random generator, base64url-encoded without
padding. The config never holds the plaintext key. It holds only the digest
`hex(HMAC-SHA256(hmac_secret, <plaintext key>))`. A keyed hash means that read
access to the configured key set does not let someone compute matching keys
offline.

### Fields of `auth`

| Field | Type | Default | Description |
|---|---|---|---|
| `hmac_secret` | string | none | Secret that keys the digest. Set this or `hmac_secret_file`. |
| `hmac_secret_file` | string | none | File that holds the secret. Trailing whitespace is trimmed. |
| `keys` | list | `[]` | Configured virtual keys: `id`, `tenant`, `digest`, `revoked`, `tags`. |
| `store` | object | `in_memory` | Where minted keys and tenant policy live. See "Where keys and policies are stored". |
| `tenant_credentials` | object | none | Key ring for tenant provider credentials. See [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/). |
| `enforce` | object | all `true` | Which tenant controls the proxy enforces. |
| `max_policy_staleness` | duration | `4m` | How old a replica's copy may get. See "Policy staleness". |
| `stored_output_owner_ttl` | duration | `720h` | How long the proxy keeps the owner of a stored response or chat completion. |
| `jwt` | list | `[]` | JWT providers. See "JWT authentication". |
| `chargeback_tags` | object | none | Tag allow-list. See [Chargeback tags](/docs/llm-proxy/limits-and-budgets/chargeback-tags/). |

The [field reference](/docs/llm-proxy/configuration/reference/) lists every
sub-field. It is generated from the schema.

## Authentication and authorization fail closed

With an `auth:` block, both checks refuse by default:

- **Authentication** ("who is this?") fails closed. A request with no
  recognized credential gets a `401`. The proxy never admits it anonymously.
- **Authorization** ("what may they do?") fails closed for models. A tenant
  with no stored model policy gets a `403` with the response-code detail
  `model_not_permitted`. A tenant that has only a budget also gets the `403`.
  The proxy logs the first refusal for each tenant once at warn.
- **Provider authorization** does not exist. A tenant that may use a model
  may use every provider that serves it. The only per-provider rule is for
  tenants that store their own provider keys. See
  [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

The starter config is an exception. `llm-proxy init` writes
`auth.enforce.tenants_without_policy: allow`, so the key it prints can use
every model without a stored policy. Remove that line before you issue keys
to other people.

To let a tenant use models, set its policy with `PUT /tenants/{id}/policy`.
The body `{"access":"all"}` grants every model. To grant every model to all
tenants without a policy, set `auth.enforce.tenants_without_policy: allow`
(default `deny`). The proxy then logs a warning at load. Setting it together
with `model_policy: false` is a load error at
`auth.enforce.tenants_without_policy`.

> **Warning:** Fine-tuned models are not protected by object ownership. Every
> tenant reaches the provider through one provider account. A tenant with
> `{"access":"all"}`, or with a `*` grant, can use the fine-tuned models of
> every tenant. Grant each fine-tuned model name to the tenants that own it.

### Checks that `auth:` turns on

An `auth:` block turns on these checks:

- Model access (`llmproxy.model_authz`).
- Spend limits (`llmproxy.spend_limit`).
- Tenant and key rate limits (`llmproxy.token_limit`).
- Object ownership (`llmproxy.object_ownership`).

You do not list these filters. The config file has no allow-list or budget
field, because policies and budgets live in the control-plane store and change
at runtime. A tenant with no spend ceiling is unlimited.

To turn a check off, set `auth.enforce.model_policy: false`,
`auth.enforce.spend: false`, `auth.enforce.limits: false`, or
`auth.enforce.object_ownership: false`. All four default to `true`. The proxy
then logs a warning at load that names what is not enforced. The admin API
answers `PUT /tenants/{id}/policy` or `PUT /tenants/{id}/budget` with `409`
and `{"error":"not_enforced", ...}` instead of storing a rule that nothing
reads.

Spend budgets need a `pricing` rate card. Without one, every request costs $0,
a budget never fires, and the proxy warns at load.

## Authentication failures

No credential, an unknown key, and a revoked key all produce the same
response. The status is `401`, the body is `unauthorized`, and the response has
a `www-authenticate: Bearer` header. A caller cannot learn from the response
whether a key it guessed was ever valid.

The proxy records the three reasons separately in the response-code details:
`auth_no_credential`, `auth_unknown_key`, and `auth_revoked_key`. The access
log shows them as `response_code_details` (`%RESPONSE_CODE_DETAILS%`). See
[Access logs](/docs/llm-proxy/observability/access-logs/).

The authenticator treats two cases differently:

- **No credential of this kind.** The request has no `authorization` header,
  uses a different auth scheme, or has a bearer value without the `llmp_`
  prefix (for example, a JWT). The virtual-key authenticator does not refuse
  it. If `auth.jwt` is set, the JWT authenticator can take it. See
  [JWT authentication](#jwt-authentication).
- **A bad credential of this kind.** The value has the `llmp_` prefix and its
  digest matches no configured key, or it matches a key marked `revoked`. The
  proxy refuses the request. No later authenticator runs.

A later authenticator does not run after a bad virtual key. If it did, a
caller could learn, one probe at a time, whether a guessed value was a known
virtual key.

## Token limits use the tenant, not the header

If a `limits:` entry uses `key: tenant`, the token-rate limiter counts each
request against the tenant that the proxy resolved. It does not use the raw
`authorization` header. Two virtual keys of one tenant share one budget, and a
caller cannot reset the budget with a different key. When the shared budget is
spent, a request with the second key also gets a `429`.

A `limits:` entry with `key: header:authorization` counts each credential
apart. With `auth:` configured, each virtual key gets its own bucket, so a
tenant with two keys gets two buckets. Use `key: tenant` for a limit that all
keys of a tenant share.

The limiter reads the tenant that `llmproxy.auth` sets. The config file always
puts `llmproxy.auth` first when an `auth:` block is present, so you do not
set the order.

## Policy staleness

Each replica polls the store for key, revocation, and policy changes every 48
seconds (jittered up to 60 seconds). If the store cannot be read, the replica
keeps serving its last copy until the copy is older than
`auth.max_policy_staleness` (default `4m`, whole seconds, at least `96s`).
Past that bound, every `Bearer llmp_...` request gets `503` with the
response-code detail `auth_policy_stale` until a poll succeeds. A JWT request
gets the same `503` if its tenant holds stored provider credentials.
Authentication fails closed. The poller logs at error once when this starts
and at warn once when it recovers.

The gauge `envoy_llmproxy_policy_snapshot_age_seconds` on `/stats/prometheus`
shows the age of the copy. See
[Metrics and stats](/docs/llm-proxy/observability/metrics-and-stats/).

## Managing keys and tenants at runtime

Use the admin server to mint and revoke keys, manage tenants, and set model
allow-lists, budgets, and rate limits. These are bearer-gated HTTP calls, not
config-file edits:

- `POST /keys` and `DELETE /keys/{id}`
- `POST /tenants` and `DELETE /tenants/{id}`
- `PUT /tenants/{id}/policy` and `PUT /keys/{id}/policy`
- `PUT /keys/{id}/budget`
- `PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits`
- `PUT /keys/{id}/tags`
- `GET /keys`, which lists every key (id, tenant, revocation, policy, budget,
  limits; no plaintext).
- `GET /keys/{id}/spend`.

See [Admin API](/docs/llm-proxy/administration/admin-api/) for the bodies and
status codes.

Each call writes the store first and then republishes at once. Every worker
sees the change on its next request. The change does not wait for a periodic
refresh.

`DELETE /tenants/{id}` revokes every key that authenticates as the tenant and
answers `204`. Keys minted through `POST /keys` are revoked and their rows
stay, as with `DELETE /keys/{id}`. A key from `auth.keys` for that tenant is
revoked by a revoked row in the store under the same key id. That row wins over
the config entry on every replica that shares the store, and across restarts.
Revoked key ids are permanent.

On the replica that took the call, the next request with any of those keys
gets `401`. Other replicas that share the store apply the change at their next
policy poll, 48 to 60 seconds later. A request that the proxy admitted before
the revocation is not stopped. It runs to completion.

The tenant names `default` and `unauthenticated` are reserved. `POST /tenants`
and `POST /keys` refuse them with `400`. Request records use `default` for a
request without a tenant and `unauthenticated` for a request that the auth
filter refused. A tenant with either name could not be told apart from them.

For example, `PUT /tenants/acme/policy` with
`{"access":{"only":["gpt-*"]},"deny":["gpt-5*"]}` permits the `gpt-*` models
except those that match `gpt-5*`. Omit `deny` or send `[]` for no exclusions.
Both lists accept exact names or one trailing `*`. A deny match always wins.
`{"access":"all","deny":["gpt-5*"]}` grants every other model.

The admin API fails closed. If `LLMPROXY_ADMIN_TOKEN` is unset, empty, or
whitespace-only, every bearer-gated call returns `403` and the proxy logs a
line that names the endpoint. The gated set is every write plus two reads that
expose money or identity: `GET .../spend` and `GET /keys`. The config-shaped
reads (`/ready`, `/config_dump`, `/clusters`, `/models`, `/server_info`, and
`/stats*`) ignore the token.

For rotation, permanent revocation tombstones, API versioning, and migration,
see [Spend policies and recovery](/docs/llm-proxy/limits-and-budgets/spend-policies/).

### Per-user controls inside a tenant

To control each user separately, issue one key for each user. Use the key as
the user identity. Then set a spend budget, a model policy, and rate limits
on each key:

- `PUT /keys/{id}/budget` sets the spend ceiling of the key.
- `PUT /keys/{id}/policy` sets the model allow-list of the key.
- `PUT /keys/{id}/limits` sets the rate limits of the key: tokens per
  minute, requests per minute, and concurrent streams.

A key policy only narrows the model grant of its tenant. It never widens
it. A key with no policy keeps the grant of its tenant. For the body, the
status codes, and the rules, see "Key model policy" in the
[Admin API](/docs/llm-proxy/administration/admin-api/).

Rate limits follow the same rule. `PUT /tenants/{id}/limits` sets the
ceiling. A request must pass the limits of its tenant and the limits of its
key. A key with no limits is bound by its tenant alone. The limits persist
with the configured store. With `auth.store: shared`, the replicas share the
counters and the concurrent streams, so a limit applies to the fleet. With
another store, each replica counts alone, and N replicas can admit up to N
times a limit. For the body, the `429` responses, and the rules, see "Tenant
and key limits" in the
[Admin API](/docs/llm-proxy/administration/admin-api/).

### Tenant provider credentials

A tenant can store its own provider key, so its requests use that key instead
of the platform credential. The routes are `PUT`, `GET`, and `DELETE` under
`/tenants/{id}/provider_credentials/{provider}`, with the same bearer-token gate
as the other write routes. The full setup, the status codes, and the rules for
tenant mode are in
[Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

### Where keys and policies are stored

Keys and tenant policy live in one of three stores:

- `in_memory` (default) holds everything for the life of the process.
- `persistent` (with a `path`) uses an embedded `redb` file. It survives a
  restart of that one process.
- `shared` (a Redis `url` or `url_file`, and an optional `namespace`) uses
  Redis, which every replica shares. A `shared` store requires a node id. Start
  each replica with `--service-node <name>`, or the config does not load. See
  [Run in production](/docs/llm-proxy/operations/running-in-production/#node-identity-service_node).

Set `auth.store` to one of those shapes. See
[Configuration file](/docs/llm-proxy/configuration/configuration-file/).

## Reload and restart

A `SIGHUP` reload does not change authentication. The HMAC secret, the
`auth.keys` list, the store selection, the credential key ring and the
policy-poll interval are fixed when the proxy starts. A reload that changes
one of them is refused whole: the proxy logs `SIGHUP: config reload refused`
with the field and keeps the previous configuration. A key that you add to
`auth.keys`, remove from it, or set to `revoked: true` keeps its old state
until a restart. A removed or revoked configured key still authenticates until
then. Use the admin write API
to change keys, allow-lists, and budgets on a running process. See the reload
table in
[Reload configuration](/docs/llm-proxy/operations/config-reload/#what-a-reload-applies).

## Limitations

- **Model allow-lists and budgets are not config-file fields.** The `Auth` type
  in `schema/llmproxy-v1.schema.json` has no such field. The `auth:` block
  enforces them, and you set them through the admin write API. See "Managing
  keys and tenants at runtime".
- **JWT accepts RS256 only.** The filter rejects other algorithms.
- **Configured keys change only at restart.** Use the admin API for changes on
  a running proxy.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Related tools

The admin server has a web UI for keys and tenants. See
[Admin UI](/docs/llm-proxy/administration/admin-ui/).

## JWT authentication

The `llmproxy.auth` filter can also accept a JWT as the bearer value. Set
`auth.jwt` in the config file. The filter tries the virtual-key authenticator
first. A bearer value with the `llmp_` prefix stays with it. The filter gives
every other bearer value to the JWT providers. It verifies the token against
the first entry whose `issuer` equals the `iss` of the token.

```yaml
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  keys: []          # optional; virtual keys and JWTs can be used together
  jwt:
    - issuer: https://login.microsoftonline.com/<directory-id>/v2.0
      audience: api://llm-proxy
      jwks:
        discovery_url: https://login.microsoftonline.com/<directory-id>/v2.0/.well-known/openid-configuration
        refresh_interval: 10m
      tenant:
        claim: tid
        values:
          "<directory-id>": acme
      user:
        claim: oid
```

| Field | Required | Default | What it does |
|---|---|---|---|
| `issuer` | yes | none | The token `iss` must equal it. Must be unique in `auth.jwt`. |
| `audience` | yes | none | The token `aud` must contain it. A token with no `aud` is refused. |
| `jwks.discovery_url` | one of the two | none | OIDC discovery URL. Must use `https`. |
| `jwks.keys` | one of the two | none | Static RSA keys: `kid`, `n`, `e` (base64url, no padding). Never refreshed. |
| `jwks.refresh_interval` | no | `10m` | Whole seconds, at least `1s`. Only with `discovery_url`. |
| `jwks.trusted_ca_file` | no | system roots | PEM bundle for the fetches. Only with `discovery_url`. |
| `tenant.claim` | yes | none | The claim that selects the tenant. |
| `tenant.values` | yes | none | Claim value to tenant. Must not be empty. |
| `user.claim` | yes | none | The claim that names the user. |
| `claim_tags` | no | none | Verified claims that set chargeback tags. See [Chargeback tags](/docs/llm-proxy/limits-and-budgets/chargeback-tags/). |

These rules are load errors, and each error names its dotted path, for example
`auth.jwt[0].tenant.values`:

- `issuer` and `audience` are required. Without an audience, a token that the
  identity provider issued for any other application would be accepted.
- `tenant.values` is required. The proxy never uses a claim value as a tenant
  name directly, so the identity provider cannot select a tenant that you did
  not list.
- A tenant in `tenant.values` must not be `default`, and must not contain `:`.
- The user id is `jwt:<issuer>:<tenant>:<user claim>`, and a request record
  holds at most 128 bytes of it. The tenant must be short enough to leave 36
  bytes for the user claim. If a user claim is longer than what is left, the
  proxy drops the usage record of that request. Entra's `oid` is 36 bytes.

A token gets no models from its claims. Its tenant gets the model policy,
budget, limits and object ownership that you set through the admin API, the
same as for a virtual key of that tenant. A mapped tenant with no stored model
policy is refused with `403` under the default
`enforce.tenants_without_policy: deny`.

A JWT user has no key record, so no per-user policy narrows it. To narrow one
user, mint a key with `POST /keys` whose `key_id` is that user's id
(`jwt:<issuer>:<tenant>:<user claim>`) under the same tenant, and set
`/keys/{id}/policy`, `/budget` or `/limits` on it.

A JWT caller uses its tenant's stored provider credentials exactly as a
virtual key of that tenant does. See
[Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

The filter accepts RS256 only, and the token needs a `kid` header. A token
with another `alg` is rejected, including `none` and `HS256`. The clock
leeway for `exp` and `nbf` is 60 seconds, and no field changes it.

### Key refresh with `discovery_url`

If you set `discovery_url`, a background thread fetches the discovery
document, follows its `jwks_uri`, and publishes the key set again at each
interval. Request workers never fetch.

- The URL must use `https`. There is no exception for loopback.
- Until the first refresh succeeds, every JWT for that provider is rejected.
- A failed refresh logs a warning and keeps the last good key set. It never
  clears the set.
- The filter refuses a key set that is older than six refresh intervals. The
  token is rejected as `auth_jwt_jwks_stale`. With the default interval, this
  is one hour.
- One fetch times out after 15 seconds, and the filter refuses a response over
  1 MiB.
- The refresh uses TLS 1.2 only.

### What the client sees

A rejected JWT gets the same `401`, body, and `www-authenticate: Bearer`
header as a rejected virtual key. Only the response-code details differ:
`auth_jwt_malformed`, `auth_jwt_unknown_kid`, `auth_jwt_invalid_signature`,
`auth_jwt_expired`, `auth_jwt_not_yet_valid`, `auth_jwt_issuer_mismatch`,
`auth_jwt_audience_mismatch`, `auth_jwt_missing_tenant_claim`,
`auth_jwt_tenant_not_mapped`, and `auth_jwt_jwks_stale`.

## Implementation notes

For maintainers. These entries name the code and tests behind the behavior
above.

- Key generation: `generate_plaintext_key` and `KEY_ENTROPY_BYTES` in
  `crates/proxy/src/keygen.rs`.
- Digest comparison: `KeySet::find` in `crates/proxy-control/src/auth.rs`
  calls `ring::hmac::verify` once, on the single digest that a table lookup
  selected. The module doc, "Why keyed HMAC-SHA256", gives the reason. A
  `KeyRecord` has only `key_id`, `tenant`, and `revoked`.
- Authenticator chain: `AuthenticatorChain::authenticate` stops at the first
  `Rejected` result. The test
  `a_rejected_first_authenticator_short_circuits_a_chain_that_would_otherwise_authenticate`
  in `crates/proxy-filters/src/auth_filter.rs` covers it.
- Identical 401: `AuthFilterInstance::deny` in
  `crates/proxy-filters/src/auth_filter.rs`. Tests:
  `all_three_failure_reasons_produce_an_identical_downstream_response` (same
  file) and `all_three_failure_modes_are_byte_identical_on_the_wire` in
  `testing/diffrig/tests/auth_e2e.rs`.
- Token limiter key: the limiter reads the resolved tenant in
  `crates/proxy-filters/src/token_limit_filter.rs`. The test
  `two_virtual_keys_on_the_same_tenant_share_one_token_budget` in
  `testing/diffrig/tests/auth_e2e.rs` covers the shared budget.
- Filter order: the dialect lowering in `crates/proxy-simple-config/src/lower.rs`
  emits `llmproxy.auth` first.
- Admin routes: `AVAILABLE_ENDPOINTS` and `WriteRoute::expected_method` in
  `crates/proxy-admin/src/server.rs`. Token handling: `normalize_admin_token`
  in the same file.
- Republish after each write: `ControlPlane::mint_key`, `revoke_key`,
  `set_policy`, and `set_budget` in `crates/proxy-control/src/control.rs`.
- JWT: `crates/proxy-filters/src/jwt_auth.rs` (algorithms, leeway, tenant
  mapping), `parse_jwt_providers` in `crates/proxy-filters/src/auth_filter.rs`,
  and `crates/proxy-filters/src/jwks_refresh.rs` (refresh, `STALE_AFTER_MISSED`,
  `FETCH_TIMEOUT`, `MAX_BODY_BYTES`). Tests include `alg_none_is_rejected` and
  `algorithm_confusion_hmac_signed_with_the_rsa_public_key_is_rejected`.
