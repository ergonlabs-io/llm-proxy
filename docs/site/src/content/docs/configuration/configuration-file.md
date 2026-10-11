---
title: Configuration file reference
summary: Field-by-field reference for the llm-proxy configuration file
  (--config), derived from schema/llmproxy-v0.schema.json, the normative
  source. Covers what each field does, its default, and whether it is
  enforced yet.
last_updated: 2026-08-26
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
| `models` | object of `ModelDef`, keyed by name | no | `{}` | A client-facing model name mapped to an ordered list of providers. See "The `models` catalogue" below — only the first provider in each entry is used to serve traffic in this schema version. |
| `routes` | array of `Route` | yes | — | Ordered routing rules. The first rule whose `model` pattern matches wins; there is no specificity reordering. At least one route is required. |
| `limits` | array of `Limit` | no | `[]` | Rate limits and quotas. See "What `limits` actually enforces" below — most combinations are recorded but not enforced. |
| `observability` | `Observability` object | no | none (no access log) | Access logging. See "A schema/code note worth knowing" below for the current state of admin-endpoint metrics. |

A request matching no `routes` entry and no `models` entry gets a 404 with a
JSON error body listing known models.

## `providers.<name>` (`Provider`)

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `type` | enum: `openai`, `anthropic`, `openai-compatible`, `azure-openai`, `vertex`, `bedrock` | no | `openai-compatible`, unless the provider's name is `openai` or `anthropic` | The wire shape. `openai-compatible` covers vLLM, Ollama, TGI, Together, and most self-hosted servers. `azure-openai`/`vertex`/`bedrock` are named for the model catalogue but are not yet loadable as a `providers` entry — their credential scheme is not implemented, and configuring one is a load error naming the gap. |
| `base_url` | string (URI) | only if the name/type does not imply one | `https://api.openai.com` for `openai`, `https://api.anthropic.com` for `anthropic` | The API base URL. Host and port only — a path prefix (e.g. `/openai` for Groq) is a load error in this schema version, not a silent truncation. |
| `api_key` | string | no (mutually exclusive with `api_key_file`) | none | The API key, sent as `Authorization: Bearer` for OpenAI-shaped APIs or `x-api-key` for Anthropic. Omit both `api_key` and `api_key_file` for an unauthenticated local backend. |
| `api_key_file` | string (path) | no (mutually exclusive with `api_key`) | none | Read the API key from a file, trimmed of trailing whitespace. Read once at startup — despite the schema's own field description, this is **not** watched or hot-reloaded automatically; the lowering step emits a load-time warning on `providers.<name>.api_key_file` saying so. A `SIGHUP` config reload does re-read it, since a reload re-parses the whole config file from scratch — see [Config reload](../operations/config-reload/). |
| `extra_headers` | object of string | no | `{}` | Extra headers sent on every request to this provider. An Anthropic provider also gets a default `anthropic-version` header; setting it here overrides that default. |
| `ca_file` | string (path) | no | system roots | PEM CA bundle for verifying this provider's TLS certificate. Only needed for a self-hosted backend with a private CA. |
| `connect_timeout` | `Duration` | no | `5s` | TCP/TLS connection establishment timeout for this provider. |
| `protocol` | enum: `http1`, `http2` | no | `http1` | Upstream HTTP protocol for this provider's cluster. `http2` enables upstream connection reuse — the proxy keeps one multiplexed connection per worker to this provider instead of connecting fresh on every request. Most hosted providers support it; many local/self-hosted plaintext servers do not. |
| `tenant_credentials` | boolean | no | `false` | Lets a tenant that stored its own key for this provider send that key instead of the operator key. Requires `auth.tenant_credentials`. Only header API-key types qualify: `openai`, `anthropic`, `openai-compatible`, `openrouter`, and `azure-openai`. `vertex` and `bedrock` are rejected at this field. The key goes in `x-api-key` for `anthropic`, in `api-key` for `azure-openai`, and in `Authorization: Bearer` for the rest. See [Tenant provider credentials](../authentication/tenant-provider-credentials/). |

A `Provider` config rejects setting both `api_key` and `api_key_file`.

## `routes[]` (`Route`)

| Field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `model` | `ModelPattern` (glob) | yes | — | Matched against the request's `model` body field (or the `model` query parameter for realtime WebSocket endpoints). `*` matches any run of characters and matching is case-sensitive. |
| `provider` | `ProviderModelRef` | yes | — | Where a matching request goes: `provider-name`, or `provider-name/model-name` to rewrite the model name before forwarding. |
| `fallbacks` | array of `ProviderModelRef` | no | `[]` | Providers tried in order when the primary fails: a connection failure, a 429, or a 5xx received before any response byte — never after the client has started receiving a stream. Every provider in the chain must speak the same wire dialect as the primary; a cross-dialect entry is a load error naming the route and fallback index. |
| `retries.attempts` | integer, 0–5 | no | `1` | Extra attempts against the *same* provider before moving to `fallbacks`. `0` disables same-provider retries. |
| `idle_timeout` | `Duration` | no | `90s` | Maximum time with no bytes flowing (between chunks, SSE events, or WebSocket frames). There is deliberately no total-duration timeout — LLM generations are long-lived, so an idle-based guard is used instead. |

The model-rewrite form (`provider/model`) is recorded but not yet applied:
substituting the rewritten name into the request body needs a body rewriter
not yet built, so a route or fallback using this form produces a
load-time warning naming its exact path, and the client's original model
name is forwarded unchanged.

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
| `tenant_credentials` | `AuthTenantCredentials` | required when any `providers` entry sets `tenant_credentials: true`; otherwise no | absent | The key ring that seals tenant provider credentials at rest. Absent means the proxy cannot seal or open them. Requires `store.persistent`: with `store` absent, `in_memory`, or `shared`, this block is a load error at `auth.tenant_credentials`. See the table below. |

`store.persistent.path` is an embedded `redb` file, created if missing; an empty
path is an error. `store.shared` is Redis: exactly one of `url` (inline, use
`${ENV_VAR}` for any password) or `url_file` (read at load time, trailing
newlines trimmed); `namespace` prefixes every Redis key. Config-file `keys` are
re-seeded on every start and are not written to the store.

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
[Tenant provider credentials](../authentication/tenant-provider-credentials/#1-create-the-key-encryption-key-file).

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

Authentication fails closed; authorization does not. An authenticated tenant
with no configured policy may use every model and provider.

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
| `force_usage_reporting` | boolean | no | `true` | Forces `stream_options.include_usage` onto streaming OpenAI-dialect requests that did not already ask for it, so streamed responses still report token usage. Set `false` for strict passthrough if a hand-rolled client trips over the extra frame. |

A streamed response and a realtime session are both logged once, at stream
end, with usage totals — not per chunk. See
[Getting started](../getting-started/quickstart/) for what one line actually
contains.

## The `models` catalogue

`models.<name>` maps a client-facing model name to an ordered list of
providers able to serve it. Each entry gets an implicit route matching its
name exactly, evaluated after `routes` and before the 404 backstop.

| `ModelDef` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `providers` | array of `ProviderModelRef` string or `ModelProvider` object | yes, ≥1 item | — | Providers able to serve this model, in priority order. |

**Only `providers[0]` is used to serve traffic in this schema version.**
Every later entry is still validated at load time — a bad one still fails to
load — but produces a load-time warning naming its exact path instead
of being selected. Picking among them (fallback, weighted split, cost-aware
routing) is not implemented yet.

Use the object form (`ModelProvider`) only when you need to set `dialect`
explicitly — the shorthand string form cannot carry it:

| `ModelProvider` field | Type | Required | Default | What it does |
|---|---|---|---|---|
| `provider` | string, key into `providers` | yes | — | Which provider serves this entry. |
| `model` | string | no | the catalogue's own name | The upstream model ID at this provider, if different (e.g. Anthropic's dated model IDs). Recorded but not yet substituted into the request body — the client's original model name is forwarded as-is, and this produces a load-time warning. |
| `dialect` | enum: `openai`, `anthropic` | required for `vertex`/`bedrock`; derived otherwise | derived from the provider's `type` | The wire format this provider entry speaks. Required for `vertex`/`bedrock` because a single provider type there can serve more than one wire format (e.g. Vertex hosts Anthropic-shaped Claude and OpenAI-shaped Kimi under one provider). Omitting it where required is a load error, never a guess. |

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

### Request body size limit

Every HTTP request body is capped at the listener's
`per_connection_buffer_limit_bytes` (default 1 MiB). The cap applies before
any HTTP filter runs. A larger body gets a `413` and the connection is closed.

This file format has no field for the limit, so it is always 1 MiB here. To
raise it, use Envoy mode (`-c`) and set `per_connection_buffer_limit_bytes` on
the listener. Raise it on listeners that serve multimodal requests with
inline base64 images. The value must be greater than 0.

The schema's description says certificate files under `tls` are "watched and
hot-reloaded on change." The mechanism for a live swap exists internally
(`SwapCertResolver`/`update_certificates` in `crates/proxy-core/src/tls/`,
backed by an atomic pointer swap), but nothing in the running proxy calls it
on a filesystem change today — there is no file watcher wired up, and the
repository has no file-watching dependency at all. `update_certificates` is
exercised only by a test (`crates/proxy-core/tests/tls.rs`). In practice, a
renewed certificate needs a process restart, the same as every other file
this configuration reads once at startup.

## A schema/code note worth knowing

The `observability` field's schema description says metrics "are always
computed and exposed on the admin endpoint when `admin` is configured." As
implemented today, `/stats` and `/stats/prometheus` both report real
per-cluster request counts and latencies, but not every metric a reader might
expect from that sentence exists yet — see
[Metrics and /stats](../observability/metrics-and-stats/) for exactly which
counters are wired to real traffic and which are defined but never
incremented. Both endpoints are read-only and take no configuration beyond
the `admin` bind address itself.
