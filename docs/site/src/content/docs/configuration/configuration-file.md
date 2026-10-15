---
title: Configuration file reference
summary: Field-by-field reference for the llm-proxy configuration file
  (--config), derived from schema/llmproxy-v0.schema.json, the normative
  source. Covers what each field does, its default, and whether it is
  enforced yet.
last_updated: 2026-10-13
related:
  - ../getting-started/introduction/
  - ../getting-started/quickstart/
---

# Configuration file reference

This page documents `schema/llmproxy-v0.schema.json` — the normative schema
for the file passed with `--config`. If this page and the schema disagree,
the schema is right; report the difference.

## Strict parsing

Parsing is strict. An unknown or misspelled field is a load error naming its
full dotted path (for example `routes[0].fallback` if you typo `fallbacks`),
never a silent ignore. This applies to every file loaded with `--config`; it
is not configurable. A handful of top-level keys are reserved for future
schema versions and rejected in v0.

Every string field accepts `${VAR_NAME}` environment-variable interpolation,
applied before parsing.

## Top-level fields

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `version` | integer (const `0`) | yes | — | Schema version. llm-proxy refuses a config whose version it does not understand. |
| `listen` | `HostPort` string, or `Listener` object | no | `0.0.0.0:8080` | Where the proxy accepts client traffic. The object form adds TLS termination. |
| `admin` | `HostPort` string | no | disabled | Admin/observability endpoint. Binds nothing unless set. |
| `auth` | `Auth` object | no | disabled (no authentication) | Downstream authentication. Fails closed once present: an unrecognized credential gets a 401, never anonymous admission. |
| `providers` | object of `Provider`, keyed by name | yes | — | Named upstream LLM APIs. Keys match `^[a-z0-9][a-z0-9-]*$`. At least one entry is required. |
| `models` | object of `ModelDef`, keyed by name | no | `{}` | A client-facing model name mapped to an ordered list of providers. See "The `models` catalogue" below. The first provider is the primary. Later providers are fallbacks. The proxy also serves `GET /v1/models` from this table. |
| `routes` | array of `Route` | yes | — | Ordered routing rules. The first rule whose `model` pattern matches wins; there is no specificity reordering. At least one route is required. |
| `auto` | `AutoModel` object | no | none (`auto` is an ordinary model name) | Resolves the reserved model `auto` to a real model per tenant. Has `default` and `tenants`; set at least one. `tenants` needs an `auth` block. While set, a `models` key or `routes[].model` of `auto` is a load error. See [The auto model](../../providers-and-routing/auto-model/). |
| `limits` | array of `Limit` | no | `[]` | Rate limits and quotas. See "What `limits` actually enforces" below — most combinations are recorded but not enforced. |
| `observability` | `Observability` object | no | none (no access log, no OTLP export) | Access logging, OTLP metric export, and OTLP trace export. See "`observability` (`Observability`)" below. |
| `pricing` | `Pricing` object | no | none (no request has a price) | The rate card. It prices each completed request in integer nanodollars, using all four token buckets. A `SIGHUP` reload installs a change, unless an `auth` store holds the rate card. See "`pricing` (`Pricing`)" below. |

A request matching no `routes` entry and no `models` entry gets a 404 with a
JSON error body listing known models.

## `providers.<name>` (`Provider`)

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `type` | enum: `openai`, `anthropic`, `openai-compatible`, `openrouter`, `azure-openai`, `vertex`, `bedrock` | no | `openai-compatible`, unless the provider's name is `openai`, `anthropic`, or `openrouter` | The wire shape. `openai-compatible` covers vLLM, Ollama, TGI, Together, and most self-hosted servers. `openrouter` sends OpenAI-shaped requests and rewrites the `/v1` path prefix to `/api/v1`. `azure-openai`, `vertex`, and `bedrock` need the extra fields in "Provider-specific fields" below. |
| `base_url` | string (URI) | only if the name/type does not imply one | `https://api.openai.com` for `openai`, `https://api.anthropic.com` for `anthropic`, `https://openrouter.ai` for `openrouter`. No default for `openai-compatible`, `azure-openai`, `vertex`, or `bedrock`. | The API base URL. Host and port only — a path prefix (e.g. `/openai` for Groq) is a load error in this schema version, not a silent truncation. |
| `api_key` | string | no (mutually exclusive with `api_key_file`) | none | The API key. The proxy sends it as `Authorization: Bearer` for OpenAI-shaped APIs, `x-api-key` for Anthropic, and `api-key` for `azure-openai`. Omit both `api_key` and `api_key_file` for an unauthenticated local backend. A `vertex` or `bedrock` provider rejects both fields: use its own credential fields. |
| `api_key_file` | string (path) | no (mutually exclusive with `api_key`) | none | Read the API key from a file, trimmed of trailing whitespace. Read once at startup — despite the schema's own field description, this is **not** watched or hot-reloaded automatically; the lowering step emits a load-time warning on `providers.<name>.api_key_file` saying so. A `SIGHUP` config reload does re-read it, since a reload re-parses the whole config file from scratch — see [Config reload](../../operations/config-reload/). |
| `extra_headers` | object of string | no | `{}` | Extra headers sent on every request to this provider. An Anthropic provider also gets a default `anthropic-version` header; setting it here overrides that default. |
| `ca_file` | string (path) | no | system roots | PEM CA bundle for verifying this provider's TLS certificate. Only needed for a self-hosted backend with a private CA. |
| `connect_timeout` | `Duration` | no | `5s` | TCP/TLS connection establishment timeout for this provider. |
| `protocol` | enum: `http1`, `http2` | no | `http1` | Upstream HTTP protocol for this provider's cluster. `http2` enables upstream connection reuse — each worker keeps up to 4 multiplexed connections to each address of this provider (it dials another connection when each open one carries 100 streams) instead of connecting fresh on every request. Most hosted providers support it; many local/self-hosted plaintext servers do not. |
| `tenant_credentials` | boolean | no | `false` | Lets a tenant that stored its own key for this provider send that key instead of the operator key. Requires `auth.tenant_credentials`. Only header API-key types qualify: `openai`, `anthropic`, `openai-compatible`, `openrouter`, and `azure-openai`. `vertex` and `bedrock` are rejected at this field. The key goes in `x-api-key` for `anthropic`, in `api-key` for `azure-openai`, and in `Authorization: Bearer` for the rest. See [Tenant provider credentials](../../authentication/tenant-provider-credentials/). |
| `tenant_credential_verify_path` | string (path, starts with `/`) | no | `/api/v1/key` for `openrouter`; `/v1/models` for `openai` and `anthropic`; none for other types, and none when `base_url` is set | The path of the `GET` that checks a tenant key when `PUT` saves it. Sent as is. Requires `tenant_credentials: true`. Set it to use another path. Must be at most 2048 bytes, printable ASCII, no `#`. See [Save-time check](../../authentication/tenant-provider-credentials/#save-time-check). |
| `request_fields` | object: `deny` and `strip`, each a list of non-empty strings | no | none | A generic policy on top-level request-body fields, for this provider. See "Request field policy" below. |

A `Provider` config rejects setting both `api_key` and `api_key_file`.

### Provider-specific fields

The fields in this table are valid for one provider type only. A field on
another type is a load error such as `is only valid for vertex providers`
(`parse.rs`, `validate_provider_specific_fields`). A missing required field is
a load error such as `region is required for bedrock providers`. Each of these
provider types also needs a `base_url`, because none has a default.

| Type | Field | Required | What it does |
|---|---|---|---|
| `azure-openai` | `deployment` | yes | The Azure deployment name. The proxy rewrites the `/v1` path prefix to `/openai/deployments/<deployment>`. Letters, digits, `-`, `.`, `_`, and `~` only. |
| `azure-openai` | `api_version` | yes | Sent as the `api-version` query parameter. The same character set as `deployment`. |
| `vertex` | `project` | yes | The Google Cloud project ID. |
| `vertex` | `location` | yes | The Google Cloud location. |
| `vertex` | `publisher` | yes | The Vertex publisher, for example `google` or `anthropic`. |
| `vertex` | `access_token` or `access_token_file` | exactly one | An OAuth access token. The proxy sends it as `Authorization: Bearer <token>` and replaces any `Authorization` header from the client. |
| `bedrock` | `region` | yes | The AWS region. |
| `bedrock` | `access_key_id` or `access_key_id_file` | exactly one | The AWS access key ID. |
| `bedrock` | `secret_access_key` or `secret_access_key_file` | exactly one | The AWS secret access key. |
| `bedrock` | `session_token` or `session_token_file` | no, at most one | An AWS session token. |

For `vertex`, the proxy rewrites the request path to
`/v1/projects/<project>/locations/<location>/publishers/<publisher>/models/<model>:streamRawPredict`.
For `bedrock`, it rewrites the path to `/model/<model>/invoke` and signs the
request with AWS SigV4 for the service name `bedrock`, using the region and
keys above. The signature adds the
`authorization`, `x-amz-date`, and `x-amz-content-sha256` headers. A session
token adds the `x-amz-security-token` header.

Rules for these types:

- The token and the AWS keys are static values. The proxy reads them when it
  loads the configuration. It does not mint or refresh them. A `*_file` field
  is read once at startup and again on a `SIGHUP` reload, and the load emits a
  warning that says so.
- A `vertex` or `bedrock` provider serves more than one wire format. A
  `routes[].provider` reference cannot say which one. Add a `models` entry
  for the provider in the object form, and set `dialect` there.
- `tenant_credentials: true` is a load error on `vertex` and `bedrock`.

Proof: `validate_vertex_provider`, `validate_bedrock_provider`, and
`validate_azure_provider` in `crates/proxy-simple-config/src/parse.rs`; the
lowering in `crates/proxy-simple-config/src/lower.rs` (`lower_provider`);
`ProviderCredentials::apply` in `crates/proxy-http/src/credential_provider.rs`;
`apply_cluster_provider_path_template` in `crates/proxy-http/src/router.rs`.
The tests are `vertex_and_bedrock_runtime_settings_survive_ir_lowering`,
`azure_openai_lowers_auth_and_provider_path_rewrite`,
`vertex_and_bedrock_credentials_require_valid_sources`, and
`vertex_and_bedrock_fields_are_rejected_on_other_provider_types` in
`crates/proxy-simple-config/tests/dialect.rs`, plus
`bedrock_signature_uses_final_body_and_required_headers` and
`vertex_credential_replaces_any_client_authorization` in `credential_provider.rs`.

### Request field policy

`providers.<name>.request_fields` names top-level JSON body keys the proxy
checks on every request before it goes to this provider:

- `deny`: a request that carries any listed key gets `400` with error code
  `request_field_not_permitted`, and nothing is sent upstream.
- `strip`: the listed keys are removed and the rest of the body is sent.

The policy is generic. The proxy has no built-in list for any provider. It
exists because some providers accept body fields that change what the gateway
runs or bills, for example a field that lists other models to try or a field
that turns on paid plugins. Those fields can also bypass model authorization,
because the proxy authorizes the `model` the client names, not models named
elsewhere in the body. Deny what you do not want clients to reach. Use `strip`
when the field is harmless to drop and you would rather not fail the request.

The check runs per attempt against the provider that is actually dialled, so
it holds on failover: if the primary provider has no policy and the fallback
has one, a request that reaches the fallback is checked against the fallback's
policy. Every cluster lowered from the provider gets the policy, including
aggregate members. A name must not be empty and must not appear in both lists.
Errors name the dialect path, for example `providers.openrouter.request_fields.deny[0]`.

Example for an OpenRouter provider. This is operator config, not a default:

```yaml
providers:
  openrouter:
    api_key: ${OPENROUTER_API_KEY}
    request_fields:
      deny: [models, route, plugins, transforms]
```

### OpenRouter

A provider named `openrouter` has type `openrouter` without a `type` field. A
provider with any other name needs `type: openrouter`. The base URL defaults to
`https://openrouter.ai`. The proxy sends the key as `Authorization: Bearer`.
The cluster rewrites the request path prefix `/v1` to `/api/v1`. A `base_url`
with a path is a load error that names `providers.<name>.base_url`. The file
`examples/llmproxy-openrouter.yaml` is a full example with a `models`
catalogue. Proof: `openrouter_example_builds_cluster_owned_auth_and_path_rewrite`,
`explicit_openrouter_type_works_with_custom_provider_name`, and
`openrouter_rejects_endpoint_path_in_base_url` in
`crates/proxy-simple-config/tests/openrouter.rs`.

## `routes[]` (`Route`)

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `model` | `ModelPattern` (glob) | yes | — | Matched against the request's `model` body field (or the `model` query parameter for realtime WebSocket endpoints). `*` matches any run of characters and matching is case-sensitive. |
| `provider` | `ProviderModelRef` | yes | — | Where a matching request goes: `provider-name`, or `provider-name/model-name` to rewrite the model name before forwarding. |
| `fallbacks` | array of `ProviderModelRef` | no | `[]` | Providers tried in order when the primary fails: a connection failure, a 429, or a 5xx received before any response byte — never after the client has started receiving a stream. Every provider in the chain must speak the same wire dialect as the primary; a cross-dialect entry is a load error naming the route and fallback index. |
| `retries.attempts` | integer, 0–5 | no | `1` | Extra attempts against the *same* provider before moving to `fallbacks`. `0` disables same-provider retries. |
| `idle_timeout` | `Duration` | no | `90s` | Maximum time with no bytes flowing (between chunks, SSE events, or WebSocket frames). There is deliberately no total-duration timeout — LLM generations are long-lived, so an idle-based guard is used instead. |
| `streaming` | enum: `strict` | no | absent | Asserts that every HTTP filter on this route passes response bytes through without holding them. With `strict`, the configuration fails to load if any installed filter can buffer a response. `strict` is the only legal value. With the field absent, the proxy streams as normal and checks nothing. |

A `streaming: strict` failure is a load error. Its path is the lowered route,
not `routes[n]`, and the text is `route requires `streaming: strict`, but HTTP
filter '<name>' can buffer response bytes`. Proof: the lowering in
`crates/proxy-simple-config/src/lower.rs` (`io.llmproxy.streaming`), the check
in `build_per_route_table` in `crates/proxy-http/src/filter_manager.rs`, and the
tests `strict_streaming_rejects_a_filter_without_flush_through_capability` and
`strict_streaming_accepts_an_explicit_flush_through_filter` in
`crates/proxy-http/src/filter_manager/tests.rs`.

The model-rewrite form (`provider/model`) is recorded but not yet applied:
substituting the rewritten name into the request body needs a body rewriter
not yet built, so a route or fallback using this form produces a
load-time warning naming its exact path, and the client's original model
name is forwarded unchanged. The `model` field of a `models` entry works
differently: the proxy applies it. See "The `models` catalogue".

### Route redirects are bootstrap-only

Every route this configuration format produces is a `Forward` action — it
always names a provider to reach. A raw bootstrap configuration's route can
instead be a `Redirect` action, replying with a `3xx` and a `Location`
header instead of forwarding anything; there is no dialect field to produce one.
It is worth naming here since `routes[]` above cannot reach it:

| `RedirectAction` field | Type | Default | What it does |
|---|---|---|---|
| `host_redirect` | string | the request's own `Host`/authority | Replaces the authority in the `Location`. |
| `path_redirect` | string | the request's own path and query | Replaces the *entire* path — not a prefix rewrite, so the original query string is dropped along with it when set. |
| `https_redirect` | boolean | `false` | Forces the `Location` scheme to `https`. When `false`, the scheme is always `http` — llm-proxy does not track a downstream listener's own TLS state at this point in the pipeline, so it cannot echo "redirect to the same scheme the client used" (`crates/proxy-http/src/router.rs`'s `redirect_response`, its Rust-note comment). |
| `response_code` | one of `301`, `302`, `303`, `307`, `308` | `301` | The status code of the redirect response. |

Proven by `redirect_https_redirect_forces_scheme_and_preserves_host_and_path`
and `redirect_host_and_path_redirect_replace_the_whole_target` in
`crates/proxy-http/src/router.rs`'s test module. The response body is always
empty, `Content-Length: 0`.

## `auth` (`Auth`) and `auth.keys[]` (`AuthKey`)

Exactly one of `hmac_secret` / `hmac_secret_file` is required if `auth` is
present at all.

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `hmac_secret` | string | one of `hmac_secret`/`hmac_secret_file` | — | The operator secret that keys the HMAC over virtual-key digests. Use `${ENV_VAR}` rather than inlining it. |
| `hmac_secret_file` | string (path) | one of `hmac_secret`/`hmac_secret_file` | — | Read the HMAC secret from a file, trimmed of trailing whitespace. Not watched automatically, but re-read on a `SIGHUP` config reload, same as `providers.<name>.api_key_file` above. |
| `keys` | array of `AuthKey` | no | `[]` | Configured virtual keys. An empty list authenticates nothing, so `auth` present with no keys refuses every request — legal, and almost certainly a mistake, so it produces a load-time warning. |
| `store` | `AuthStore` | no | `in_memory` | Where keys minted through the admin API and tenant policy live. Exactly one of `in_memory: {}`, `persistent: {path}`, or `shared: {url \| url_file, namespace}`. Fixed at startup: changing it takes a restart. |
| `tenant_credentials` | `AuthTenantCredentials` | required when any `providers` entry sets `tenant_credentials: true`; otherwise no | absent | The key ring that seals tenant provider credentials at rest. Absent means the proxy cannot seal or open them. Requires a durable store, `store.persistent` or `store.shared`: with `store` absent or `in_memory`, this block is a load error at `auth.tenant_credentials`. See the table below. |

| `max_policy_staleness` | duration | no | `4m` | How old the replica's copy of keys, revocations, and policies may get when the store cannot be read. Whole seconds, at least `96s`. Past it, every `Bearer llmp_...` request gets `503` with response-code detail `auth_policy_stale` until a poll succeeds. Any other value is a load error at `auth.max_policy_staleness`. See "Policy staleness" below. |
| `enforce` | `AuthEnforce` | no | all `true` | Which tenant controls the proxy enforces. See "`auth.enforce`" below. |

`store.persistent.path` is an embedded `redb` file, created if missing; an empty
path is an error. `store.shared` is Redis: exactly one of `url` (inline, use
`${ENV_VAR}` for any password) or `url_file` (read at load time, trailing
newlines trimmed); `namespace` prefixes every Redis key. Config-file `keys` are
re-seeded on every start and are not written to the store.

### `auth.enforce` (`AuthEnforce`)

With `auth` present, the proxy adds `llmproxy.model_authz`,
`llmproxy.spend_limit`, and `llmproxy.token_limit` to the filter chain.
Tenant allow-lists, budgets, and rate limits are not in the config file; you
set them through the admin API (`PUT /tenants/{id}/policy`,
`PUT /tenants/{id}/budget`, `PUT /tenants/{id}/limits`). Unknown keys here are
a load error that names the full path, for example `auth.enforce.model_polcy`.

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `model_policy` | boolean | no | `true` | Enforce tenant model allow-lists. A tenant with no stored policy is refused (`403`, response-code detail `model_not_permitted`) unless `tenants_without_policy` is `allow`. `false` omits `llmproxy.model_authz`. |
| `tenants_without_policy` | `deny` or `allow` | no | `deny` | What `llmproxy.model_authz` does for a tenant with no stored policy. `deny` refuses the request. `allow` grants every model and logs a load-time warning. Setting it with `model_policy: false` is a load error at `auth.enforce.tenants_without_policy`. |
| `spend` | boolean | no | `true` | Enforce tenant and key spend budgets. Cost comes from `pricing`. `false` omits `llmproxy.spend_limit`. |
| `limits` | boolean | no | `true` | Enforce tenant and key rate limits set with `PUT /tenants/{id}/limits` and `PUT /keys/{id}/limits`. A key only narrows its tenant. Counters are per process. `false` with no top-level `limits` entry omits `llmproxy.token_limit`. A top-level `limits` entry still adds it, and it then enforces these limits too. |

Setting one to `false` logs a load-time warning that names what is not
enforced. The matching admin write then returns `409` with
`{"error":"not_enforced","detail":"..."}` instead of storing a rule nothing
reads. For `limits`, the warning and the `409` apply only when the config has
no top-level `limits` entry.

With `spend` on and no `pricing`, every request costs $0 and a budget never
fires. The proxy warns about that too.

| `AuthKey` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `id` | string | yes | — | Names this credential in audit logs and the access log's response-code detail. Must be unique within `auth.keys`. |
| `tenant` | string | yes | — | The tenant (account/team) this key authenticates as. Several keys may share a tenant — that is the normal case, so revoking one leaked key does not revoke the whole account. |
| `digest` | string, 64 lowercase hex chars | yes | — | `HMAC-SHA256(hmac_secret, <plaintext key>)`. The plaintext key is shown once, at creation, and is never recoverable from configuration. Generate it with `llm-proxy --mode keygen --tenant <tenant> --key-id <id> --hmac-secret-file <path>`. |
| `revoked` | boolean | no | `false` | A revoked key is refused, distinguished from an unknown key in the access log's response-code detail (`auth_revoked_key` vs. `auth_unknown_key`) but not on the wire — both produce an identical 401. |

### `auth.tenant_credentials` (`AuthTenantCredentials`)

Key-encryption keys that seal tenant provider credentials at rest. Each key is
a `0600` file holding exactly 32 raw bytes. The key bytes never appear in
configuration.

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `encryption_key_file` | string (path) | yes | — | The key that new tenant credentials are sealed under. Read at startup. |
| `encryption_key_id` | string | yes | — | Names that key. The id is stored in plaintext beside each sealed credential. |
| `previous_keys` | array of `{id, file}` | no | `[]` | Retired keys. Each one opens credentials sealed before a rotation, and never seals a new one. Each `id` and `file` is required. |

Ids must be unique across `encryption_key_id` and `previous_keys[].id`.

Only presence and non-emptiness are checked at this level. The key files are
checked when the auth filter opens the ring. A bad file or a duplicate id fails
the load, but the error names the Envoy-mode field path,
`typed_config.tenant_credentials.…`, not `auth.tenant_credentials.…`. This is a
known gap in the error path, and it does not change what is rejected. The
file rules and the rotation procedure are in
[Tenant provider credentials](../../authentication/tenant-provider-credentials/#1-create-the-key-encryption-key-file).

Example:

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
  openai:
    api_key: ${OPENAI_API_KEY}
    tenant_credentials: true
routes:
  - model: "*"
    provider: openai
```

Authentication fails closed, and so does authorization. An authenticated
tenant with no stored policy is refused with `403` and the response-code detail
`model_not_permitted`. A tenant that has only a budget is also refused. The
proxy logs the first refusal for each tenant once at warn, with the tenant and
the fix. Set a policy with `PUT /tenants/{id}/policy`. The body
`{"access":"all"}` grants every model. To grant every model to tenants without
a policy, set `auth.enforce.tenants_without_policy: allow`.

### Policy staleness

Each replica polls the store for key, revocation, and policy changes every 48
seconds (jittered up to 60 seconds). If the store cannot be read, the replica
keeps its last copy until the copy is older than `auth.max_policy_staleness`.
Past that bound, every `Bearer llmp_...` request gets `503` with the
response-code detail `auth_policy_stale`. The poller logs at error once when
this starts and at warn once when it recovers. The gauge
`envoy_llmproxy_policy_snapshot_age_seconds{scope="<stat_prefix>"}` on
`/stats/prometheus` shows the age. In Envoy mode the field is
`llmproxy.filters.v0.Authentication.max_policy_staleness_seconds`. A value of
`0` or unset means 5 x `poll_interval_seconds` (240 seconds at the default).
An explicit value below 2 x `poll_interval_seconds` is a load error.

## `limits[]` (`Limit`)

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `key` | string matching `global`, `client-ip`, `tenant`, or `header:<name>` | yes | — | What the limit is counted against. See "What `limits` actually enforces" below. |
| `tokens_per_minute` | `TokenAmount` | no | — | Total (input + output) tokens allowed per minute per bucket. |
| `requests_per_minute` | `TokenAmount` | no | — | Requests allowed per minute per bucket. |
| `concurrent_sessions` | integer, ≥1 | no | — | Maximum simultaneous long-lived sessions (WebSocket or active SSE streams) per bucket. |
| `models` | array of `ModelPattern` | no | applies to all traffic | Restricts this limit to requests whose model matches one of these patterns. |

### What `limits` actually enforces

Only one combination is enforced today: `key: header:authorization` with
`tokens_per_minute` set. That combination returns a 429 with `x-ratelimit-*`
headers before the request reaches a provider; a request already admitted
and in flight is never truncated, and streamed responses still contribute
their usage to the budget. When `auth:` is configured, the bucket key
automatically prefers the authenticated tenant instead of the raw header
value, so `key: tenant` is the form to use alongside `auth:`.

If a request's usage cannot be read from the provider's response — most
commonly because the configured `dialect` does not match that provider's
actual response shape — the request is still allowed and nothing is charged
against the budget for it: the proxy fails open on a metering gap rather
than refusing traffic. This is logged as a warning (at most once per budget
key per minute, so a busy route does not flood the log) rather than
happening silently, so it is visible to an operator even though it does not
change the request's outcome.

Every other combination is accepted, recorded, and produces a
load-time warning naming the exact field: `key: global`, `key:
client-ip`, any other `header:<name>`, `requests_per_minute`,
`concurrent_sessions`, and per-model scoping via `models`. A config using
one of these still loads and serves traffic — it is not rejected — but the
limit itself does nothing until a later schema version implements it.

Limits are enforced per proxy instance in this schema version. Two replicas
each admit up to `tokens_per_minute`, so the fleet admits twice that.

The shared `ControlPlaneStore` that llm-proxy has does not change this. That
store reconciles currency *spend* for the Envoy-mode `llmproxy.spend_limit`
filter. It holds no token-rate-limit counters, and this schema version cannot
reach it.

## `observability` (`Observability`)

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `access_logs.output` | string: `stdout`, `stderr`, or a file path | no | `stdout` | Where per-request access-log lines are written. Not written at all unless `observability.access_logs` is present. |
| `access_logs.format` | enum: `text`, `json` | no | `text` | `json` emits one structured object per line, recommended for log pipelines. |
| `force_usage_reporting` | boolean | no | `true` | Forces `stream_options.include_usage` onto every streaming OpenAI-dialect request, including ones where the client asked for no usage, so streamed responses always report token usage. Set `false` for strict passthrough if a hand-rolled client trips over the extra frame. |
| `metrics.otlp_endpoint` | string | yes, if `metrics` is set | — | The OTLP/gRPC collector endpoint for metrics. It may differ from the tracing endpoint. Empty or missing is a load error: `is required and must not be empty when `observability.metrics` is set`. |
| `metrics.service_name` | string | no | `llm-proxy` | The OTLP resource attribute `service.name`. |
| `metrics.export_interval` | `Duration` | no | `15s` | How often the proxy exports a full cumulative snapshot of its metrics. The range is `1s` to `1h`. |
| `metrics.export_deadline` | `Duration` | no | `10s` | The deadline for one export. A collector that accepts a connection and stops answering costs one deadline, not a stall. At least `100ms`, and it must be less than `export_interval`. |
| `tracing.otlp_endpoint` | string | yes, if `tracing` is set | — | The OTLP/gRPC collector endpoint for traces. Empty or missing is a load error: `is required and must not be empty when `observability.tracing` is set`. |
| `tracing.service_name` | string | no | `llm-proxy` | The OTLP resource attribute `service.name`. |
| `tracing.export_deadline` | `Duration` | no | `5s` | The deadline for one trace-batch export. The range is `100ms` to `60s`. |
| `tracing.sample_ratio` | number, 0.0 to 1.0 | no | `1.0` | The share of new root traces that the proxy samples. A value outside the range is a load error at `observability.tracing.sample_ratio`. |

`metrics` and `tracing` are independent. Set `metrics` alone to export
metrics with tracing off. Set `tracing` alone to export spans with no OTLP
metrics. With neither, nothing is sent to a collector. The Prometheus
endpoint `/stats/prometheus` works in every case: it needs no OTLP
configuration.

`export_deadline >= export_interval` is a load error. The error names a path
that starts at `node.metadata["io.llmproxy.metrics"]`, not at
`observability.metrics`, because the Envoy-mode loader checks the rule. The text
is `must be less than `export_interval` (<n>s), got <n>s -- otherwise every
export is abandoned as a timeout before the next one is due`.

Tracing exports spans. This differs from the schema's description of
`observability.tracing`, which says "nothing exports a span yet". The proxy
starts an OTLP trace exporter when `tracing` is set and logs `OTLP trace
export enabled`. When a request carries a valid `traceparent` header, the
proxy joins that trace as a child span and keeps the sampled decision of the
caller, whatever `sample_ratio` says. Without one, the proxy starts a new trace
and samples it with probability `sample_ratio`. A clean shutdown sends a final
batch. Proof: `traceparent_join_and_fallback_produce_the_right_span_tree`,
`tracing_without_metrics_exports_spans_and_no_metrics`,
`metrics_export_with_tracing_disabled_exports_metrics_and_no_spans`,
`a_hung_trace_export_is_bounded_and_its_batch_counted_as_dropped`, and
`a_clean_shutdown_delivers_a_final_trace_batch` in
`crates/proxy/tests/otlp_trace_e2e.rs`; the bounds in
`crates/proxy-config/src/lower.rs` (`convert_tracing_metadata`,
`convert_metrics_metadata`). The tests configure OTLP through Envoy-mode
bootstrap metadata. The lowering of the `llmproxy` dialect fields into that
metadata is tested in `crates/proxy-simple-config/tests/dialect.rs`.

A streamed response and a realtime session are both logged once, at stream
end, with usage totals — not per chunk. See
[Getting started](../../getting-started/quickstart/) for what one line actually
contains.

## `pricing` (`Pricing`)

`pricing` is the rate card. With it, the proxy prices each completed request in
integer nanodollars, using all four token buckets: input, cache read, cache
write, and output. One nanodollar is one billionth of a US dollar, so a price of
2.50 USD per million tokens is `2500` nanodollars per token. Without `pricing`,
no request has a price, `%LLM_LIST_COST%` is `-`, and `GET /pricing` returns
`503`.

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `price_list` | `PriceList` | one of `price_list`/`price_list_file` | — | The price list, written inline. |
| `price_list_file` | string (path) | one of `price_list`/`price_list_file` | — | A file that holds one price list, in YAML or JSON, with the same fields as `price_list`. The proxy reads it at startup and on each reload, and the load emits a warning that says so. |
| `catalog` | object | no | none | Public source information, such as where the prices came from. `GET /pricing` returns it. The proxy never uses it to price a request. |

Set exactly one of `price_list` and `price_list_file`. Setting neither, or both,
is a load error at `pricing`: `set exactly one of price_list_file or
price_list`, or the same text with `, not both`. A field error names the full
path of the field, for example `pricing.price_list.entries[0].tier_mode`. A
`price_list_file` that the proxy cannot read is a load error that names the file.

| `PriceList` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `version` | string | no | none | A label for the list. The recorded version is the label, a `+`, and 12 hex digits of a hash of the entries and of the map from cluster to provider type, for example `2026-10+3c2805867b2e`. With no label, the recorded version is the hash alone. Editing a price, or the provider that a cluster is priced as, changes the hash, so the version changes even when you keep the label. |
| `effective_from` | string, RFC 3339 timestamp | yes | — | A date for the list. The proxy checks the format and shows the value in `GET /pricing`. It does not compare the value with the time of a request: a list applies from the moment the proxy installs it. A date in the future is an error, at load, in `PUT /pricing`, and for a rate card read from the store, because the list would otherwise apply early. |
| `entries` | array of `PriceEntry`, at least 1 | yes | — | The prices. Each pair of `provider_type` and `model` may appear once. A duplicate pair is a load error. |

| `PriceEntry` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `provider_type` | string | yes | — | The provider type that the price applies to, for example `openai`, `anthropic`, or `openrouter`. It matches the `type` of the provider that served the request, whether you set the `type` or the proxy inferred it from the provider name (see `providers.<name>`). Must not be empty. |
| `model` | string | yes | — | The model name. The match is exact and case-sensitive, with no globs. The proxy checks it against the selected model: the upstream model name for the provider that served the request, or the requested model when no mapping applies (`%LLM_SELECTED_MODEL%`). Must not be empty. |
| `tier_mode` | enum: `whole_request`, `graduated` | yes | — | How `tiers` price a request. There is no default, because the two modes give different prices for the same request. See "Tiers" below. |
| `tiers` | array of `PricingTier`, at least 1 | yes | — | The price bands. |
| `cached_input_unpriced` | boolean | no | `false` | When `true`, a request that reports cache-read tokens has no price. When `false`, those tokens cost `cached_input_nanodollars_per_token` each, even when that rate is `0`. |
| `cache_write_unpriced` | boolean | no | `false` | The same, for cache-write tokens. |

| `PricingTier` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `up_to` | integer, 0 or more | no | open-ended | The largest input context size, in tokens, that this band covers. The value is inclusive. Leave it out on the last band. |
| `input_nanodollars_per_token` | integer, 0 or more | yes | — | The price of one input token. |
| `cached_input_nanodollars_per_token` | integer, 0 or more | yes | — | The price of one cache-read token. |
| `cache_write_nanodollars_per_token` | integer, 0 or more | yes | — | The price of one cache-write token. |
| `output_nanodollars_per_token` | integer, 0 or more | yes | — | The price of one output token. |

### Tiers

The proxy picks a band from the input context size of the request: the input
tokens plus the cache-read tokens plus the cache-write tokens. Output tokens do
not count. The first band whose `up_to` is at least the context size is the
selected band. The band with no `up_to` takes every larger size. A load error
names the path when the `up_to` values do not strictly increase, or when the
open-ended band is missing, repeated, or not last.

- `whole_request`: The selected band prices every token bucket of the whole
  request.
- `graduated`: The proxy lays the context out in prompt order: cache-read tokens
  first, then cache-write tokens, then input tokens. It cuts that sequence into
  the bands. Each token costs its own rate in the band that holds its position,
  so every token is priced once. Output tokens are not part of the context. They
  cost the output rate of the band that the whole context size selects. For
  example, with a band up to 1000 tokens and then an open band, 800 cache-read
  tokens and 500 input tokens put the cache-read tokens and the first 200 input
  tokens in the first band, and the last 300 input tokens in the second band.

### Example

```yaml
version: 0
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
pricing:
  price_list:
    version: "2026-10"
    effective_from: "2026-10-01T00:00:00Z"
    entries:
      - provider_type: openai
        model: example-model
        tier_mode: whole_request
        tiers:
          - up_to: 200000
            input_nanodollars_per_token: 1000
            cached_input_nanodollars_per_token: 100
            cache_write_nanodollars_per_token: 1250
            output_nanodollars_per_token: 4000
          - input_nanodollars_per_token: 2000
            cached_input_nanodollars_per_token: 200
            cache_write_nanodollars_per_token: 2500
            output_nanodollars_per_token: 8000
```

A request for `example-model` with 2000 input tokens and 500 output tokens falls
in the first band. It costs 2000 × 1000 + 500 × 4000 = 4,000,000 nanodollars,
and `%LLM_LIST_COST%` shows `4000000`. A request with 250000 input tokens and
1000 output tokens falls in the second band, which prices the whole request:
250000 × 2000 + 1000 × 8000 = 508,000,000 nanodollars.

A request for any other model has no price: `%LLM_LIST_COST%` and
`%LLM_RATE_CARD_VERSION%` show `-`. Both operators are in the
[access log reference](../../observability/access-logs/#the-operator-set).

### Unpriced requests under a dollar budget

A dollar budget cannot count a request that has no price. The proxy charges
such a request $0, so the budget does not count it, and the request is not
refused. This is a deliberate fail-open choice. The proxy makes it visible: it
writes one `warn` log line the first time a model is unpriced under a budget,
and it writes no further line for that model. The line starts with
`spend_limit: a request under a dollar budget was charged $0 because no price
applies to it`. It names the chain, the cluster, the model, and the reason. A
request with no budget on its tenant or key writes no line.

The proxy keeps one set of model names for each filter chain, and the set
holds at most 256 names. A name is cut to 128 characters. When a new name
arrives and the set is full, the proxy logs one summary line for the chain
(`more distinct unpriced model names than this chain remembers`). It names no
further model. These requests are still charged $0 and still counted in the
`unpriced_requests` counter. To remove the warning, add the model to the rate
card with `PUT /pricing`. See [Spend policies](../../limits-and-budgets/spend-policies/).
Proof: `UnpricedWarner` in `crates/proxy-filters/src/spend_limit_filter.rs`, and
the tests `an_unpriced_model_under_a_budget_warns_once_per_model` and
`an_unpriced_model_without_a_budget_stays_silent` in the same file.

### When a change takes effect

Where the rate card lives depends on whether the filter chain has a
control-plane store: an `auth` section in the dialect, or `llmproxy.auth` in
bootstrap mode. The rate card is stored per chain, under the chain's
`stat_prefix`.

Without a store, the configuration is the only durable source:

- At start, the proxy loads `pricing`, including `price_list_file`.
- A `SIGHUP` reload installs `pricing` when it changed. A listener rebuilds its
  filter chain when the next connection arrives, so the new rate card applies
  from that connection. A reload that did not change `pricing` leaves a rate
  card that `PUT /pricing` installed. A reload that removes `pricing` clears the
  rate card and logs a warning.
- `PUT /pricing` replaces the rate card of the one proxy that receives it,
  without a restart. A restart loads the configured rate card again. The
  response says `"persisted": false`.

With a store, the store holds the rate card and wins:

- At start, `pricing` seeds a store that has no rate card for the chain. If the
  store already has one, the stored rate card stays in force, and the proxy logs
  once that `pricing` differs from it.
- A `SIGHUP` reload never replaces a stored rate card. It logs once when the
  changed `pricing` differs from it.
- `PUT /pricing` writes the store. It does not install the rate card itself.
  The receiving replica installs the rate card that the store's watcher
  delivers right after the write. Every other replica that shares the store
  installs it on its next policy poll, which is 48 to 60 seconds at the default
  `poll_interval_seconds`. The response says `"persisted": true` when the store
  is `persistent` or `shared`. The default `in_memory` store keeps the rate card
  only for the life of the process, and the response says `"persisted": false`.
  If the store refuses the write, the response is `503` and no replica changes.
- A second replica can write to the same store between your write and the
  watcher delivery. The later write wins. The receiving replica then serves the
  store's rate card, not yours. The `note` in the response says `written, but a
  concurrent publish to the same store superseded it; this replica now serves
  the store's card`. Read `GET /pricing` to see which rate card is active. Proof:
  `a_concurrent_publish_from_another_replica_wins_on_the_publishing_replica` in
  `crates/proxy-filters/src/usage_filter/rate_card_tests.rs`, and
  `PricingRegistry::publish_json` in `crates/proxy-filters/src/usage_filter.rs`.
- To replace a stored rate card, send it with `PUT /pricing`. Editing `pricing`
  does not replace it.

A request that has started keeps the rate card that was active when it started.
The new rate card replaces the whole old one, so a model that the new card does
not list has no price.

`PUT /pricing` has these limits:

- It needs the admin token (`LLMPROXY_ADMIN_TOKEN`) as a bearer token.
- It does not need an `auth` section.
- It accepts a request body up to 4 MiB, and returns `413` above that. The rate
  card in `examples/llmproxy-openrouter.yaml` is 268 KB with its catalog, so it
  fits. The other admin writes keep a 64 KiB limit.
- It returns `400` for invalid JSON, an invalid rate card, or an `effective_from`
  in the future.

`GET /pricing` needs no token. It returns the active rate card, its
`rate_card_version`, and the `catalog` if one is set.

## The `models` catalogue

`models.<name>` maps a client-facing model name to an ordered list of
providers able to serve it. Each entry gets an implicit route matching its
name exactly, evaluated after `routes` and before the 404 backstop.

| `ModelDef` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `providers` | array of `ProviderModelRef` string or `ModelProvider` object | yes, ≥1 item | — | Providers able to serve this model, in priority order. |
| `max_output_tokens` | integer, 1 to 4294967295 | no | no cap | Largest output-token limit a request for this model may ask for. See [Output token cap](#output-token-cap). |

**The first provider is the primary. Later providers are fallbacks.** An
entry with more than one provider lowers to an ordered aggregate cluster named
`fallback:model-<name>`. The route retries `count - 1` times, on a connection
failure, a `429`, a `500`, a `502`, or a `503`. Each retry moves to the next
provider. Every provider in the list must speak the same wire dialect as the
first. A different dialect is a load error at `models.<name>.providers[<n>]`:
`cross-dialect model fallback needs request/response translation and is not
supported`. A `models` entry has no `retries` or `idle_timeout` field: the idle
timeout is always `90s`. Proof: `lower_model` in
`crates/proxy-simple-config/src/lower.rs` and
`models_multiple_providers_lower_to_ordered_fallback` in
`crates/proxy-simple-config/tests/dialect.rs`.

> **Schema conflict.** The schema descriptions of `models` and
> `models.<name>.providers` say that only `providers[0]` serves traffic and
> that later entries produce a load-time warning. The code does not do this:
> `lower_model` builds the fallback chain, and the test above asserts that
> lowering produces no warnings. This page follows the code.

Use the object form (`ModelProvider`) only when you need to set `dialect`
explicitly — the shorthand string form cannot carry it:

| `ModelProvider` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `provider` | string, key into `providers` | yes | — | Which provider serves this entry. |
| `model` | string | no | the catalogue's own name | The upstream model ID at this provider, if different (e.g. Anthropic's dated model IDs). The proxy writes it into the `model` field of the request body for the provider that serves the attempt, and into the path for `vertex` and `bedrock`. After a fallback, the next provider gets its own `model`. The value is stored on the provider's cluster, so it never follows the route to another provider. Proof: `selected_provider_model_rewrite_changes_only_the_upstream_body` in `crates/proxy-http/src/router.rs`. |
| `dialect` | enum: `openai`, `anthropic` | required for `vertex`/`bedrock`; derived otherwise | derived from the provider's `type` | The wire format this provider entry speaks. Required for `vertex`/`bedrock` because a single provider type there can serve more than one wire format (e.g. Vertex hosts Anthropic-shaped Claude and OpenAI-shaped Kimi under one provider). Omitting it where required is a load error, never a guess. |

### Output token cap

`models.<name>.max_output_tokens` refuses requests that ask for more output
than you allow. The proxy never rewrites the body for it. A request is refused
with `400` before any provider is dialled, and it is not retried on a fallback.
The refusal is counted in `llmproxy_router_max_output_tokens_rejected_total`
(no labels; `/stats/prometheus` only).

The field that is checked follows the request path:

| Path ends with | Field checked |
|---|---|
| `/responses` | `max_output_tokens` |
| `/messages` | `max_tokens` |
| anything else (chat completions, completions) | `max_completion_tokens` and `max_tokens`, each if present |

A `400` is returned when a checked field:

- is larger than the cap (the message names the field and the cap),
- is not a non-negative integer (`-1`, `1.5`, `"100"`, `null`), or
- appears more than once in the body, including under an escaped spelling such
  as `"max\u005ftokens"`, because decoders disagree on which repeat wins.

The cap applies to a limit the client sends; a request with no limit is
forwarded unchanged and the provider's own limit applies. A body that is not a JSON object is also forwarded unchanged, unless the
model check already refuses it.

The cap comes from the model route, so it cannot be combined with the `auto`
block. That combination is a load error at
`models.<name>.max_output_tokens`, because `auto` resolves to a model after the
cap is chosen. `0` is also a load error at the same path. In Envoy mode the same
cap is the optional `max_output_tokens` field of `llmproxy.filters.v0.BodyRewrite`,
valid in the filter config and in its `typed_per_filter_config` override. Proof:
`cap_refuses_a_larger_limit_naming_the_field_and_the_cap` in
`crates/proxy-http/src/router.rs` and the end-to-end tests in
`crates/proxy/tests/max_output_tokens_e2e.rs`.

### `GET /v1/models`

When `models` is not empty, the proxy answers `GET /v1/models` itself. It does
not call a provider. The body is a fixed JSON list built at load time, with one
entry for each `models` key that has no `*`:
`{"id": "<name>", "object": "model", "created": 0, "owned_by": "llm-proxy"}`.
Wildcard keys are routing rules, so they are not listed. The route matches the
path `/v1/models` and sits before the first catch-all route (a `routes` rule
with `model: "*"`, a `models` key `*`, or the 404 backstop). I did not verify
whether the `auth` filter gates this route. Proof:
`configured_catalog_lists_aliases_and_excludes_wildcards` in
`crates/proxy-simple-config/tests/openrouter.rs`, and the lowering in
`crates/proxy-simple-config/src/lower.rs` (`llmproxy_model_catalog`).

## Shared value shapes

| Shape | Form | Example |
|---|---|---|
| `HostPort` | `host:port`; IPv6 hosts use brackets | `0.0.0.0:8080`, `[::1]:8080` |
| `Duration` | integer + unit: `ms`, `s`, `m`, `h` | `500ms`, `30s`, `5m`, `1h` |
| `TokenAmount` | integer, or a string with a `k` (thousand) or `m` (million) suffix | `8000`, `"100k"`, `"2m"` |
| `ModelPattern` | a glob matched against the request's model name; `*` matches any run of characters | `gpt-5*`, `claude-*`, `*` |
| `ProviderModelRef` | `provider-name`, or `provider-name/model-name` to rewrite the model | `openai`, `anthropic/claude-sonnet-5` |

## `listen` as an object (`Listener`)

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `address` | `HostPort` | yes | — | Where the proxy binds. |
| `tls.cert_file` | string (path) | yes, if `tls` is set | — | PEM certificate chain. |
| `tls.key_file` | string (path) | yes, if `tls` is set | — | PEM private key. |
| `tls` (handshake) | — | — | 10 s deadline | The proxy gives each client 10 seconds to finish the TLS handshake. See "What happens at a limit" below. The dialect has no field to change this deadline. |
| `max_request_body_bytes` | integer, 1 to 4294967295 | no | `1048576` (1 MiB) | The largest request body the listener accepts, in bytes. See [Request body size limit](#request-body-size-limit). |
| `max_connections` | integer, at least 1 | no | `50000` | The most client connections held open at once, across the whole proxy. The proxy closes a connection over the limit as soon as it accepts it. |
| `request_headers_timeout` | `Duration` | no | `10s` | Time allowed from a request's first byte to its complete headers. `0s` disables it. Enforced for HTTP/1 only. |
| `request_timeout` | `Duration` | no | `60s` | Time allowed to receive the whole request, headers and body. Does not bound the response. `0s` disables it. |
| `stream_idle_timeout` | `Duration` | no | `10m` | How long a request may go with no activity: the wait for the provider's response headers (`408`, flag `SI`) and, on a route with no `idle_timeout`, gaps between response chunks. `0s` disables it. |
| `max_stream_duration` | `Duration` | no | none | The longest a request may live, however active the stream is. Before response headers the proxy answers `504` (flag `UMSDR`); after, the stream ends without a clean finish. `0s` also means no limit. |

The first three limits above default to Envoy's edge-proxy guidance and apply even
when `listen` is the shorthand `host:port` form. Envoy-mode config keeps
Envoy's defaults, which are disabled.

### What happens at a limit

| Limit | On breach |
|---|---|
| `max_connections` | The proxy closes the new connection without a response. It adds 1 to the `listener.<name>.downstream_global_cx_overflow` stat. The connection is not counted in `downstream_cx_total`. A closed connection frees its slot. |
| `request_headers_timeout` | On HTTP/1, the proxy closes a connection that has not sent complete headers in time. The limit does not apply to a response that is still streaming. On HTTP/2, the proxy does not enforce this limit. It logs one `warn` line per process when an HTTP/2 connection meets a listener that sets it: `request_headers_timeout is not enforced on HTTP/2 connections`. |
| `request_timeout` | If the request body is not complete in time, the proxy answers `408` with the body `request timeout`, and closes the connection. The response code detail is `request_overall_timeout`. The request never reaches the provider. A response that streams past the deadline is not cut. |
| TLS handshake (10 s) | The proxy closes the connection and counts it in `listener.<name>.downstream_cx_transport_socket_connect_timeout`. The slot is freed. Before this limit, a client that connected and stalled held a connection slot for ever. |

Proof: `connection_cap_closes_the_overflow_and_frees_the_slot_when_a_connection_ends`,
`request_headers_timeout_closes_a_stalled_http1_connection_but_not_a_long_response`,
`request_timeout_answers_408_on_a_stalled_body_and_closes_the_connection`, and
`request_timeout_does_not_cut_a_response_that_streams_past_the_deadline` in
`crates/proxy-core/src/listener_admission_tests.rs`;
`warn_h2_header_timeout_not_enforced_once` in
`crates/proxy-core/src/listener.rs`;
`stalled_tls_handshake_is_closed_at_the_deadline_and_frees_the_slot` in the
same file; the defaults in `crates/proxy-simple-config/tests/admission_limits.rs`.
The handshake deadline is a default of the engine: the dialect leaves
`transport_socket_connect_timeout` unset, and an unset value gets 10 s
(`tls_handshake_deadline` in `listener.rs`). Envoy applies none; see
`internal-docs/envoy-divergences.md`, row 27. The terms for certificates and
the handshake are in [TLS](../../operations/tls/).

### Request body size limit

Every HTTP request body is capped at the listener's
`per_connection_buffer_limit_bytes` (default 1 MiB). The cap applies before
any HTTP filter runs. A larger body gets a `413` and the connection is closed.

To raise it, write `listen` as an object and set `max_request_body_bytes`.
It lowers to the listener's `per_connection_buffer_limit_bytes`. The value
must be greater than 0. Raise it for long-context requests and for
multimodal requests with inline base64 images:

```yaml
listen:
  address: 0.0.0.0:8080
  max_request_body_bytes: 20971520   # 20 MiB
```

The same value is the largest body that can be retried or fail over to
another provider. Each in-flight request can hold up to this many bytes in
memory, so a higher limit increases the memory that concurrent requests can
use. The shorthand `listen: host:port` form always uses the 1 MiB default.

The proxy reads the certificate files once at startup. No file watcher
exists, so a renewed certificate needs a process restart, as for every other
file this configuration reads once. The code can swap a certificate at run
time (`update_certificates` in `crates/proxy-core/src/tls/`), but only when an
xDS secret (SDS) delivers the new certificate
(`crates/proxy-core/src/tls/secret_registry.rs`). The `--config` format has no
SDS field. See [TLS](../../operations/tls/).

## Schema and code differences

The schema and the code disagree in these places. This page follows the code,
and the list is a request to correct the schema descriptions.

- `observability.tracing` says "nothing exports a span yet". The proxy exports
  spans. See [`observability`](#observability-observability).
- The top-level `observability` description says two instruments are "defined
  but NOT yet recorded". For the current list of instruments, see
  [Metrics and /stats](../../observability/metrics-and-stats/) and
  [Admin endpoints](../../observability/admin-endpoints/). Both endpoints are
  read-only and take no configuration beyond the `admin` bind address.
- `models` and `models.<name>.providers` say that only `providers[0]` serves
  traffic. See "The `models` catalogue".
- `ModelProvider.model` says the upstream model ID is not substituted. See
  "The `models` catalogue".
- `Provider.protocol` says `http2` keeps one connection per worker. The code
  keeps up to 4 per address. See
  [Providers and clusters](../../providers-and-routing/providers-and-clusters/).
