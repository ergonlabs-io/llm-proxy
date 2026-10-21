---
title: Virtual keys
description: "How llm-proxy authenticates callers with virtual keys and decides which models each tenant may use."
summary: How downstream authentication works — the `auth:` block, the
  `llmp_`-prefixed bearer credential, keyed HMAC-SHA256 verification, JWT
  providers, and why the token limiter buckets on the
  resolved tenant rather than the client's header.
lastUpdated: 2026-10-19
related:
  - authentication/managing-secrets
  - authentication/tenant-provider-credentials
  - configuration/configuration-file
  - providers-and-routing/providers-and-clusters
  - authentication/external-authorization
  - observability/admin-endpoints
---

# Virtual keys

Use virtual keys to make callers prove who they are before a request reaches
a provider. A virtual key is an opaque bearer token that llm-proxy issues. It
is not a provider API key. It identifies a caller to llm-proxy. The provider
credential is a separate value on the provider. See
[Providers and clusters](../../providers-and-routing/providers-and-clusters/).

To enable virtual keys, add an `auth:` block to the config file. Without
`auth:`, the proxy does no application-level authentication. After the proxy
authenticates a request, it removes the `Authorization` header. A provider
never receives the virtual key.

Sections that apply only to an Envoy-mode bootstrap are labeled
"Envoy mode only". All other sections apply to the `llmproxy` dialect.

## Configure `auth:`

```yaml
version: 0
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
[Manage configured virtual keys](../../authentication/managing-secrets/).

An empty `keys: []` list is valid, but it refuses every request because nothing
authenticates. The config format emits a load-time warning for it.

A client sends the key as a bearer token:

```
Authorization: Bearer llmp_<the key>
```

Generate a key with `llm-proxy --mode keygen`. The key is `llmp_` followed by
32 random bytes from the OS random generator, base64url-encoded without
padding. The config never holds the plaintext key. It holds only the digest
`hex(HMAC-SHA256(hmac_secret, <plaintext key>))`. A keyed hash means that read
access to the configured key set does not let someone compute matching keys
offline.

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
  [Tenant provider credentials](../../authentication/tenant-provider-credentials/).

The starter config is an exception. `llm-proxy init` writes
`auth.enforce.tenants_without_policy: allow`, so the key it prints can use
every model without a stored policy. Remove that line before you issue keys
to other people.

To let a tenant use models, set its policy with `PUT /tenants/{id}/policy`.
The body `{"access":"all"}` grants every model. To grant every model to all
tenants without a policy, set `auth.enforce.tenants_without_policy: allow`
(default `deny`). The proxy then logs a warning at load. Setting it together
with `model_policy: false` is a load error at
`auth.enforce.tenants_without_policy`. In Envoy mode the field is
`llmproxy.filters.v0.ModelAuthz.tenants_without_policy`: `DENY` (0, default)
or `ALLOW` (1).

> **Warning:** Fine-tuned models are not protected by object ownership. Every
> tenant reaches the provider through one provider account. A tenant with
> `{"access":"all"}`, or with a `*` grant, can use the fine-tuned models of
> every tenant. Grant each fine-tuned model name to the tenants that own it.

### Checks that `auth:` turns on

In the `llmproxy` dialect, an `auth:` block turns on three checks:

- Model access (`llmproxy.model_authz`).
- Spend limits (`llmproxy.spend_limit`).
- Tenant and key rate limits (`llmproxy.token_limit`).

You do not list these filters. The config file has no allow-list or budget
field, because policies and budgets live in the control-plane store and change
at runtime. A tenant with no spend ceiling is unlimited.

To turn a check off, set `auth.enforce.model_policy: false`,
`auth.enforce.spend: false`, or `auth.enforce.limits: false`. All three
default to `true`. The proxy then logs a warning at load that names what is
not enforced. The admin API answers `PUT /tenants/{id}/policy` or
`PUT /tenants/{id}/budget` with `409` and `{"error":"not_enforced", ...}`
instead of storing a rule that nothing reads.

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
[Access logs](../../observability/access-logs/).

The authenticator treats two cases differently:

- **No credential of this kind.** The request has no `authorization` header,
  uses a different auth scheme, or has a bearer value without the `llmp_`
  prefix (for example, a JWT). The virtual-key authenticator does not refuse
  it. In Envoy mode, the JWT authenticator can take it. See
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

The limiter reads the tenant that `llmproxy.auth` sets. So `llmproxy.auth` must
come before `llmproxy.token_limit` in the filter chain. The wrong order is a
load-time error that names both filters. The `llmproxy` dialect always puts
`llmproxy.auth` first when an `auth:` block is present. A bootstrap config that
hand-writes `http_filters` must set the order itself.

## Policy staleness

Each replica polls the store for key, revocation, and policy changes every 48
seconds (jittered up to 60 seconds). If the store cannot be read, the replica
keeps serving its last copy until the copy is older than
`auth.max_policy_staleness` (default `4m`, whole seconds, at least `96s`).
Past that bound, every `Bearer llmp_...` request gets `503` with the
response-code detail `auth_policy_stale` until a poll succeeds. Authentication
fails closed. The poller logs at error once when this starts and at warn once
when it recovers.

In Envoy mode, set
`llmproxy.filters.v0.Authentication.max_policy_staleness_seconds` (uint32).
`0` or unset means 5 x `poll_interval_seconds`, which is 240 seconds at the
48-second default. An explicit value below 2 x `poll_interval_seconds` is a
load error. The gauge `envoy_llmproxy_policy_snapshot_age_seconds` on
`/stats/prometheus` shows the age. See
[Metrics and stats](../../observability/metrics-and-stats/).

## Managing keys and tenants at runtime

Use the admin server to mint and revoke keys, manage tenants, and set model
allow-lists, budgets, and rate limits. These are bearer-gated HTTP calls, not
config-file edits:

- `POST /keys` and `DELETE /keys/{id}`
- `POST /tenants` and `DELETE /tenants/{id}`
- `PUT /tenants/{id}/policy` and `PUT /keys/{id}/policy`
- `PUT /keys/{id}/budget`
- `PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits`
- `GET /keys`, which lists every key (id, tenant, revocation, policy, budget,
  limits; no plaintext).
- `GET /keys/{id}/spend`.

Each of these paths also has a scoped form, `/chains/{stat_prefix}/...`. It
names the target HTTP connection manager by its own `stat_prefix`. Use the
scoped form when more than one chain in the serve config sets
`llmproxy.auth`. The unscoped paths work only when exactly one chain does. If
more than one does, the proxy refuses the call.

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
see [Spend policies and recovery](../../limits-and-budgets/spend-policies/).

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
status codes, and the rules, see "Key model policy" in
[Admin endpoints](../../observability/admin-endpoints/#key-model-policy).

Rate limits follow the same rule. `PUT /tenants/{id}/limits` sets the
ceiling. A request must pass the limits of its tenant and the limits of its
key. A key with no limits is bound by its tenant alone. The limits persist
with the configured store. With `auth.store: shared`, the replicas share the
counters and the concurrent streams, so a limit applies to the fleet. With
another store, each replica counts alone, and N replicas can admit up to N
times a limit. For the body, the `429` responses, and the rules, see "Tenant
and key limits" in
[Admin endpoints](../../observability/admin-endpoints/#tenant-and-key-limits).

### Tenant provider credentials

A tenant can store its own provider key, so its requests use that key instead
of the platform credential. The routes are `PUT`, `GET`, and `DELETE` under
`/tenants/{id}/provider_credentials/{provider}`, with the same bearer-token gate
as the other write routes. The full setup, the status codes, and the rules for
tenant mode are in
[Tenant provider credentials](../../authentication/tenant-provider-credentials/).

### Where keys and policies are stored

Keys and tenant policy live in one of three stores:

- `in_memory` (default) holds everything for the life of the process.
- `persistent` (with a `path`) uses an embedded `redb` file. It survives a
  restart of that one process.
- `shared` (a Redis `url` or `url_file`, and an optional `namespace`) uses
  Redis, which every replica shares. A `shared` store requires a node id. Start
  each replica with `--service-node <name>`, or the config does not load. See
  [Share state across replicas](../../operations/running-in-production/#node-identity-service_node).

In the `llmproxy` dialect, set `auth.store` to one of those shapes. See
[Configuration file](../../configuration/configuration-file/). In Envoy mode
the same choice is the `store` oneof on the `llmproxy.auth` filter
(`in_memory`, `persistent.path`, `shared.url`). The admin write API works the
same way in both modes, because it talks to the store that the chain built.

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
[Reload configuration](../../operations/config-reload/#what-a-reload-applies).

## Limits of the `llmproxy` dialect

- **Model allow-lists and budgets are not config-file fields.** The `Auth` type
  in `schema/llmproxy-v0.schema.json` has no such field. The `auth:` block
  enforces them, and you set them through the admin write API. See "Managing
  keys and tenants at runtime".
- **JWT fields are stricter than in Envoy mode.** `auth.jwt` requires
  `issuer`, `audience`, `tenant.values` and `user.claim`. See
  [JWT authentication](#jwt-authentication).
- **JWT accepts RS256 only.** The filter rejects other algorithms.

## Related tools

- The admin server has a web UI for keys and tenants. See
  [Admin UI](../../observability/admin-endpoints/#admin-ui).
- To let a separate service decide on each request, see
  [External authorization](../../authentication/external-authorization/).
  That filter checks headers and does not set the tenant.

## Bootstrap configuration (Envoy mode only)

In an Envoy-mode bootstrap, the filter is `llmproxy.auth`
(`type.llmproxy.dev/llmproxy.filters.v0.Authentication`). Its config carries
`hmac_secret` (a standard `DataSource`, `filename` or `inline_string` only) and
a `virtual_keys` list of `{key_id, tenant, digest_hex, revoked}`:

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
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

Place `llmproxy.auth` before any other `llmproxy.*` filter in `http_filters`.
See "Token limits use the tenant, not the header" for the reason.

## JWT authentication

The `llmproxy.auth` filter can also accept a JWT as the bearer value. In the
config file, set `auth.jwt`. In an Envoy-mode bootstrap, set
`typed_config.jwt_providers` on the filter. Each `auth.jwt` entry becomes one
`jwt_providers` entry. The design is in ADR-0014.

### JWT in the config file

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

| Field | Required | Envoy-mode field | What it does |
|---|---|---|---|
| `issuer` | yes | `issuer` | The token `iss` must equal it. Must be unique in `auth.jwt`. |
| `audience` | yes | `audience` | The token `aud` must contain it. |
| `jwks.discovery_url` | one of the two | `discovery_url` | OIDC discovery URL. Must use `https`. |
| `jwks.keys` | one of the two | `keys` | Static RSA keys: `kid`, `n`, `e` (base64url, no padding). |
| `jwks.refresh_interval` | no | `refresh_interval_seconds` | Whole seconds. Only with `discovery_url`. Default `10m`. |
| `jwks.trusted_ca_file` | no | `trusted_ca.filename` | PEM bundle for the fetches. Only with `discovery_url`. |
| `tenant.claim` | yes | `tenant_claim` | The claim that selects the tenant. |
| `tenant.values` | yes | `tenant_values` | Claim value to tenant. Must not be empty. |
| `user.claim` | yes | `subject_claim` | The claim that names the user. |

The config file is stricter than Envoy mode. These rules are load errors, and
each error names its dotted path, for example `auth.jwt[0].tenant.values`:

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
[Tenant provider credentials](../../authentication/tenant-provider-credentials/).

### JWT in an Envoy-mode bootstrap

The filter tries the virtual-key authenticator first. A bearer value with
the `llmp_` prefix stays with it. The filter gives every other bearer value
to the JWT providers in config order. Absent or empty `jwt_providers` means
the filter accepts no JWT.

```yaml
http_filters:
  - name: llmproxy.auth
    typed_config:
      "@type": type.llmproxy.dev/llmproxy.filters.v0.Authentication
      hmac_secret:
        inline_string: ${LLMPROXY_AUTH_SECRET}
      jwt_providers:
        - tenant_claim: tid
          issuer: https://login.microsoftonline.com/<directory-id>/v2.0
          audience: api://llm-proxy
          subject_claim: oid
          tenant_values:
            "<directory-id>": acme
          discovery_url: https://login.microsoftonline.com/<directory-id>/v2.0/.well-known/openid-configuration
          refresh_interval_seconds: 600
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

### Provider fields

Strict mode rejects an unknown field with its dotted path.

| Field | Default | What it does |
|---|---|---|
| `tenant_claim` | none | Required. The claim that becomes the tenant. An empty value is a load error. |
| `issuer` | unset | If set, the token `iss` must equal it. A token with no `iss` is rejected. If unset, there is no issuer check. |
| `audience` | unset | If set, the token `aud` must contain it. A token with no `aud` is rejected. |
| `keys` | none | Static RSA public keys: `kid`, `n`, `e` (base64url, no padding). `kid` values must be unique. Needs at least one key unless `discovery_url` is set. |
| `tenant_values` | empty | Maps a claim value to a tenant. If the map is not empty, a claim value that is not in it is rejected. |
| `subject_claim` | unset | The claim that names the caller. See "How a JWT maps to a tenant and a key identity". |
| `discovery_url` | unset | OIDC discovery URL. Must use `https`. |
| `refresh_interval_seconds` | `600` | How often the background refresh runs. `0` means the default. Read only if `discovery_url` is set. |
| `trusted_ca` | system roots | PEM bundle (`filename` or `inline_string`) for the discovery and key fetches. The PEM must hold at least one certificate. |

The filter accepts RS256 only. A token with another `alg` is rejected,
including `none` and `HS256`. The clock leeway for `exp` and `nbf` is 60
seconds, and no field changes it.

### How a JWT maps to a tenant and a key identity

After the signature and claims pass, the filter sets the tenant like this:

1. The filter reads the claim named by `tenant_claim`. A missing or empty
   claim, or a claim that is not a string, is rejected as
   `auth_jwt_missing_tenant_claim`. The filter never uses a default tenant.
2. If `tenant_values` is not empty, the filter looks up the claim value in
   the map and uses the mapped tenant. A value that is not in the map is
   rejected as `auth_jwt_tenant_not_mapped`.
3. If `tenant_values` is empty, the claim value is the tenant name.

The key identity (`auth.key_id`) is the `kid` of the signing key, unless you
set `subject_claim`. With `subject_claim`, it is
`jwt:<issuer>:<tenant>:<subject>`. `<issuer>` is `issuerless` if you set no
`issuer`. A token with no value in the `subject_claim` claim is rejected as
`auth_jwt_missing_tenant_claim`. Use Entra's `oid` claim for people.

Set `issuer` if you configure more than one provider. A provider with an
`issuer` hands a token to the next provider, without an error, if the
unverified `iss` of the token differs. A provider without `issuer` decides
every JWT it receives. All other outcomes end the check.

A JWT principal carries the default tenant policy, and it does not use
tenant provider credentials. It stays in platform mode. See
[Tenant provider credentials](../../authentication/tenant-provider-credentials/).
The model allow-list filter looks up its policy by the tenant name. A JWT
tenant therefore meets the same allow-list as a virtual-key tenant with that
name.

### Key refresh with `discovery_url`

If you set `discovery_url`, a background thread fetches the discovery
document, follows its `jwks_uri`, and publishes the key set again at each
interval. Request workers never fetch.

- The URL must use `https`. The config load fails with the reason
  "must be an https URL with a host" otherwise. There is no exception for
  loopback.
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
- Filter order: `check_lane_h_filter_order` in
  `crates/proxy-config/src/lower.rs` enforces it. The dialect lowering in
  `crates/proxy-simple-config/src/lower.rs` emits `llmproxy.auth` first.
- Admin routes: `AVAILABLE_ENDPOINTS` and `WriteRoute::expected_method` in
  `crates/proxy-admin/src/server.rs`. Scoped routes: `resolve_control_plane`
  in the same file. Token handling: `normalize_admin_token` in the same file.
- Republish after each write: `ControlPlane::mint_key`, `revoke_key`,
  `set_policy`, and `set_budget` in `crates/proxy-control/src/control.rs`.
- JWT: `crates/proxy-filters/src/jwt_auth.rs` (algorithms, leeway, tenant
  mapping), `parse_jwt_providers` in `crates/proxy-filters/src/auth_filter.rs`,
  and `crates/proxy-filters/src/jwks_refresh.rs` (refresh, `STALE_AFTER_MISSED`,
  `FETCH_TIMEOUT`, `MAX_BODY_BYTES`). Tests include `alg_none_is_rejected` and
  `algorithm_confusion_hmac_signed_with_the_rsa_public_key_is_rejected`.
- Proto: `crates/proxy-api/vendor/llmproxy/filters/v0/auth.proto`.
