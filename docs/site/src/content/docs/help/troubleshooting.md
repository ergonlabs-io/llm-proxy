---
title: Troubleshooting
description: "Find the cause of a startup error, a 401, 403, 404, 413, 429, 502, or 503, or a missing token count. Each entry gives the symptom, the cause, and the fix."
summary: Symptom-first fixes for llm-proxy. Entries are grouped by area -
  startup and config, authentication and access, routing, limits and budgets,
  provider errors, streaming and usage, admin, TLS, reload, and storage.
  Error strings are the ones the proxy prints.
lastUpdated: 2026-10-21
related:
  - api-compatibility/errors
  - reference/response-flags
  - observability/access-logs
  - help/limitations
---

Start with the status code or the log line that you see. Find it below, read
the cause, and apply the fix. When a request fails, the access log shows the
response flag in the `response_flags` field and the proxy reason in
`response_code_details`. See [Response flags](/docs/llm-proxy/reference/response-flags/)
and [Errors from the proxy](/docs/llm-proxy/api-compatibility/errors/).

## First checks

Run these three checks before you go further.

1. Validate the config with the same binary that fails:

   ```sh
   llm-proxy --config llmproxy.yaml --mode validate
   ```

   ```text
   configuration 'llmproxy.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
   ```

2. Read the warnings. The proxy prints each one to standard error as
   ``warning: `<field.path>`: <message>``. A warning often names a setting that
   is off or not safe.
3. Check readiness. This needs `admin` in the config:

   ```sh
   curl --max-time 2 -i http://127.0.0.1:53422/ready
   ```

## Startup and config

### The proxy exits and says that a config is required

```text
a config is required: pass -c/--config-path or --config (only --mode keygen runs without one)
```

**Cause.** You started `serve` or `validate` with no config.

**Fix.** Pass `--config <PATH>`. Only `--mode keygen` and `init` run without
one.

### `configuration '<path>' INVALID` and `unknown field at`

```text
configuration 'llmproxy.yaml' INVALID
  unknown field at `routes[0].fallback`: not a recognized llm-proxy configuration field at this position (the configuration is always strict; see schema/llmproxy-v0.schema.json for valid fields)
```

**Cause.** The parser is always strict. A misspelled or unsupported field is
an error with its full dotted path.

**Fix.** Correct the field named in the path. Compare it with the
[Configuration reference](/docs/llm-proxy/configuration/reference/).

### `unsupported field` for `envoy`, `tracing`, or `clusters`

**Cause.** These top-level keys are reserved. Version 0 of the file rejects
them. The message ends with `(strict mode; see
internal-docs/envoy-divergences.md)`. That file is not part of the release.

**Fix.** Remove the key. To export traces, use `observability.tracing`.

### `failed to read` the config file

```text
configuration 'llmproxy.yaml' INVALID
  failed to read `llmproxy.yaml`: <operating system error>
```

**Cause.** The path is wrong, or the proxy user cannot read the file.

**Fix.** Check the path and the file mode. The proxy resolves a relative path
from the working directory.

### `environment variable ... is not set`

```text
invalid value at `providers.openai.api_key`: environment variable `OPENAI_API_KEY` is not set (referenced as ${OPENAI_API_KEY})
```

**Cause.** The config uses `${OPENAI_API_KEY}`, and the process has no such
variable. The proxy never substitutes an empty string for a missing variable.

**Fix.** Export the variable before you start the proxy. With systemd, put it
in the `EnvironmentFile`. To write a literal `${`, write `$${`. See
[Environment variables](/docs/llm-proxy/reference/environment-variables/).

### `unknown provider` in a route or model

**Cause.** A route, a fallback, or a `models` entry names a provider that
`providers` does not define. The message ends with
``unknown provider `x` (defined providers: a, b)``.

**Fix.** Fix the name, or add the provider.

### `a shared store requires a configured node id`

```text
invalid value at `auth.store.shared`: a shared store requires a configured node id: pass --service-node <name> with a name unique to this replica and stable across its restarts (the dialect has no node id field)
```

**Cause.** `auth.store.shared` is set and `--service-node` is not.

**Fix.** Start each replica with its own `--service-node <name>`. Use the same
name after a restart. Pass the flag to `--mode validate` too. See
[CLI reference](/docs/llm-proxy/reference/cli/#the---service-node-flag).

### The proxy exits at start and the message names the ledger or trace export

**Cause.** `ledger` and `observability.traces` also need `--service-node`.
`--mode validate` does not check this. `serve` stops with a message that
begins `node.metadata["io.llmproxy.ledger"]: the ledger requires a configured
node id` or `trace export requires a node id`. Trace export also needs the
`auth` block.

**Fix.** Pass `--service-node <name>`. The ledger name must be at most 128
bytes.

### `listener ... failed to bind`

```text
listener 'llmproxy_listener' failed to bind 0.0.0.0:53421: Address already in use (os error 98)
```

**Cause.** Another process uses the port. A bind failure at start is fatal.

**Fix.** Stop the other process, or change `listen`. The starter config from
`llm-proxy init` uses `53421` for traffic and `53422` for admin. Look for
orphaned proxy processes with `pgrep llm-proxy`.

### `failed to start admin server`

```text
failed to start admin server: admin server failed to bind 127.0.0.1:53422: Address already in use (os error 98)
```

**Cause.** The `admin` address cannot bind.

**Fix.** Choose a free port. Keep the admin address on loopback unless a
network policy restricts access.

## Authentication and access

### `401` with the body `unauthorized` and the header `www-authenticate: Bearer`

**Cause.** The `auth` block is on, and the request has no accepted
credential. A missing, unknown, or revoked key gets the same response, so a
caller cannot tell which one failed. The log field `response_code_details`
tells you: `auth_no_credential`, `auth_unknown_key`, or `auth_revoked_key`.
A rejected JWT gets the same `401` with a detail that starts `auth_jwt_`.

**Fix.** Send the key as `Authorization: Bearer <key>`. The proxy does not
read `x-api-key`. The Anthropic SDK must use `auth_token`, not `api_key`.
Check that the digest in the config matches the key and the HMAC secret. If
you changed the HMAC secret, every old digest stops matching. Make a new key
with `llm-proxy --mode keygen`. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

### `403` with the body `forbidden` right after you add a tenant

**Cause.** The tenant has no model policy, and `auth.enforce.tenants_without_policy`
is `deny` (the default). The detail is `model_not_permitted`. The proxy logs
this warning once for each tenant:

```text
model request refused: this tenant has no model policy, and llmproxy.model_authz denies tenants without one; grant models with PUT /tenants/{id}/policy, or set tenants_without_policy: ALLOW (dialect: auth.enforce.tenants_without_policy: allow)
```

A model that the tenant policy does not list gets the same `403`.

**Fix.** Grant models with `PUT /tenants/{id}/policy`. The body
`{"access":"all"}` grants every model. For a trial, set
`auth.enforce.tenants_without_policy: allow`. Remove it before you issue keys
to other people.

### `503` with `auth_policy_stale`

**Cause.** The replica could not read the key store for longer than
`auth.max_policy_staleness` (default `4m`). Virtual-key requests fail closed
until a read succeeds. The same applies to JWT requests of a tenant that holds
stored provider credentials.

**Fix.** Restore the store, for example Redis for `auth.store.shared`. Check
that the store keeps its data. Then wait for the next poll.

### Every virtual key gets `401` after a Redis restart

**Cause.** The shared store lost its data. The proxy logs this at `error`:

```text
control-plane store is now EMPTY of keys or tenants it held; every virtual key it held now gets 401. Unless an operator removed them, the store lost its data: a Redis restarted without persistence (AOF or RDB) or flushed revokes every key fleet-wide
```

**Fix.** Turn on persistence in Redis. Restore the keys, or mint them again
with the admin API. Alert on the gauge `llmproxy_policy_store_rows`.

### `403` with `"type":"tenant_credential_missing"`, or `503` with `provider credential failure`

**Cause.** The tenant needs its own provider key and has none, or the proxy
cannot decrypt the stored key.

**Fix.** See the Troubleshooting section of
[Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

### `403` with the body `this endpoint cannot be metered, so it is refused under a spend budget or token limit`

**Cause.** A spend budget or token limit applies to the caller. The request
used a path that the proxy cannot meter, such as `/v1/files`, `/v1/batches`, or
`/v1/images/variations`. The detail is `endpoint_not_metered`.

**Fix.** Send these requests with a key that has no budget or limit. Or use
an endpoint that the proxy meters. See
[API compatibility](/docs/llm-proxy/api-compatibility/overview/).

### `404` with `{"error":{"message":"object not found"}}`

**Cause.** A request named a provider file or batch ID that another tenant
owns, or an ID that the proxy does not know. Listing a collection such as
`GET /v1/files` gets the same `404`.

**Fix.** Use the tenant that created the object. See
[API compatibility](/docs/llm-proxy/api-compatibility/overview/).

### `403` with `request denied by guardrail`

**Cause.** Your guardrail check answered `deny`. The reason, if any, follows
the colon. The detail is `guardrail_denied`. The proxy did not send the
request to a provider.

**Fix.** Read the reason. Change the prompt, or change the check. If the
check is down and `failure_mode` is `closed`, the client gets `503`. See
[Guardrails](/docs/llm-proxy/authentication/guardrails/).

## Models and routing

### `404` with `no route matched the requested model`

```json
{"error":{"message":"no route matched the requested model","type":"model_not_found"}}
```

**Cause.** No `routes` entry and no `models` entry matches the `model` in the
request body. The config has no catch-all (`model: "*"`).

**Fix.** Add the model to `models`, or add a route with a matching pattern.
`routes` use first match. `models` use the exact name, then the longest
prefix, then `*`. See
[Models and routes](/docs/llm-proxy/configuration/models-and-routes/).

### A `models` entry never takes traffic

**Cause.** A `routes` rule with `model: "*"` matches first. The proxy always
checks `routes` before `models`.

**Fix.** Move the broad rule into `models`, or remove it.

### `400` with `no model is configured for` `auto`

**Cause.** The request used the model `auto`. The `auto` block has no entry
for the tenant and no `default`.

**Fix.** Add `auto.default` or an entry in `auto.tenants`. See
[The auto model](/docs/llm-proxy/providers-and-routing/auto-model/).

### A fallback provider never takes traffic

**Cause.** One of these:

- The failure is not retryable. The proxy fails over on a connection failure,
  a refused stream, a reset before any response byte, and the statuses `429`,
  `500`, `502`, and `503`. It never fails over after the first response byte
  reaches the client.
- The retry count is too low. `routes[].retries.attempts` and the fallback
  chain share one count.
- The chain mixes dialects. That is a load error, so you would have seen it at
  start.

**Fix.** Read the access log and the request record to see which provider
served the request. See
[Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

## Limits and budgets

### `429` with a plain-text body

| Body | Cause | Fix |
|---|---|---|
| `token budget exceeded` | The caller used its `tokens_per_minute` allowance. | Wait `retry-after` seconds, or raise the limit. |
| `request rate exceeded` | The caller used its `requests_per_minute` allowance. | Wait `retry-after` seconds, or raise the limit. |
| `too many concurrent streams` | The caller reached `concurrent_sessions`. | Wait for a stream to end, or raise the limit. |
| `spend budget exceeded` | A key or tenant reached its budget for the period. | Raise the budget, or wait for the period to reset. |

Each response carries `x-ratelimit-limit`, `x-ratelimit-remaining`,
`x-ratelimit-reset`, and `retry-after`. The access log flag is `RL`. For a
spend refusal, the `x-ratelimit-*` values are in micro-dollars, not in
requests. The proxy checks limits at admission, so a stream that is already
running is never cut. See
[Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/)
and [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

### A spend budget never fires

**Cause.** The config has no `pricing` rate card, or the card has no price for
the model. The request then costs `$0`. The proxy warns at load: ``spend
budgets are enforced but no `pricing` rate card is set, so every request costs
zero and a budget never fires``. Or `auth.enforce.spend` is `false`.

**Fix.** Set `pricing`, and price every model on every provider. See
[Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/).

### A `PUT` to `/tenants/{id}/budget` or `/policy` returns `409`

**Cause.** The matching `auth.enforce` control is `false`. The body is
`{"error":"not_enforced", ...}`. The proxy refuses to store a rule that
nothing reads.

**Fix.** Remove `auth.enforce.spend: false` or `auth.enforce.model_policy:
false`, and restart.

### Two replicas let a tenant exceed a limit

**Cause.** Without `auth.store: shared`, each replica counts alone. With it,
the replicas reconcile about once a second, so the fleet can pass a limit by a
small amount.

**Fix.** Use `auth.store: shared`. See
[Running in production](/docs/llm-proxy/operations/running-in-production/).

## Provider errors

The proxy makes the bodies below. The body is plain text. Any other error
body comes from the provider.

| Status | Body | Flag | Cause | Fix |
|---|---|---|---|---|
| 503 | `no healthy upstream` | `UH` | The provider has no endpoint to use, for example because the proxy ejected it. | Check `/clusters` and the host name in `base_url`. |
| 503 | `upstream connect failure` | `UF` | TCP connect failed or timed out, or the TLS handshake to the provider failed. | Check DNS, the egress firewall, `base_url`, and `ca_file`. Raise `connect_timeout` (default `5s`) on a slow network. |
| 503 | `upstream reset` | `UR` | The provider reset the stream before it sent headers. | Retry. If it persists, check the provider status page. |
| 503 | `upstream overloaded` | `UO` | The provider reached a `circuit_breakers` ceiling. The response has `x-envoy-overloaded: true`. | Raise `max_requests`, `max_pending_requests`, or `max_connections` on that provider. |
| 503 | `cluster not warmed` | `NC` | The provider is still resolving its host. | Wait, then check the host name. |

### A stream ends early with response flag `SI`

**Cause.** The route `idle_timeout` (default `90s`) is the longest gap between
response bytes. A stream that is silent for longer ends. The status is the one
that the proxy already sent. A reasoning model can go quiet for that long.

**Fix.** Raise `idle_timeout` on the route. `0s` turns it off. See
[Timeouts and retries](/docs/llm-proxy/providers-and-routing/timeouts-and-retries/).

### Upstream TLS failures

**Cause.** The proxy checks an `https://` provider against the platform trust
store, or against `ca_file`. The certificate must name the host in `base_url`.
A private CA, a wrong host name, or a container with no CA certificates fails
the handshake. The client sees `503 upstream connect failure`.

**Fix.** For a private CA, set `ca_file`. In a container, install
`ca-certificates`. With `protocol: http2`, the provider must support HTTP/2.
See [TLS](/docs/llm-proxy/operations/tls/).

### `503` with `billing ledger unavailable`

```text
billing ledger unavailable: disk_full
```

**Cause.** The ledger has no free slot, and `ledger.on_unavailable` is
`reject` (the default). The word after the colon is the reason. The detail is
`ledger_unavailable_<reason>`.

**Fix.** Free disk space, or raise `max_disk_bytes` or `max_reservations`.
Choose `on_unavailable: admit` only if you accept requests without an entry.
See [Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/).

### `413` with `request body exceeds buffer limit`

**Cause.** The request body is larger than `listen.max_request_body_bytes`
(default `1048576`).

**Fix.** Raise the limit. Each request in flight can hold that many bytes.

## Streaming and usage

### A hand-written client breaks on the last streaming chunk

**Cause.** `observability.force_usage_reporting` defaults to `true`. The proxy
adds `stream_options.include_usage` to streaming OpenAI-dialect requests. The
provider then sends one extra final chunk with `usage` and an empty `choices`
list.

**Fix.** Guard against an empty `choices` list, or set
`force_usage_reporting: false`. With it off, a streamed request that did not
ask for usage has no token counts.

### Token counts are zero or missing for a streamed request

**Cause.** The provider did not send usage in the stream, and the request did
not ask for it. Or `force_usage_reporting` is `false`.

**Fix.** Leave `force_usage_reporting` at `true`, or send
`stream_options: {include_usage: true}` from the client.

### Token metrics are missing from `/stats`

**Cause.** Token, latency, health, and ledger metrics render on
`/stats/prometheus` and over OTLP only.

**Fix.** Scrape `/stats/prometheus`. See
[Metrics and stats](/docs/llm-proxy/observability/metrics-and-stats/).

## Admin API and UI

### The admin API returns `403` with `admin write endpoints are disabled`

```text
admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is not set
```

**Cause.** The proxy started without `LLMPROXY_ADMIN_TOKEN`. It refuses
writes and sensitive reads, and the admin UI cannot change anything. The proxy
logs a warning at start.

**Fix.** Set the variable and restart. After `llm-proxy init`, start the proxy
with `LLMPROXY_ADMIN_TOKEN="$(cat admin-token)"`.

### The admin API returns `401` or `429`

**Cause.** `401` with `missing or invalid bearer token` means the token is
wrong or absent. After repeated wrong tokens, one address gets `429` with the
text `too many invalid admin bearer tokens from this address; retry later`.

**Fix.** Send `Authorization: Bearer <token>`. Wait for `retry-after` seconds
after a `429`.

### `/ui` returns `404`

**Cause.** `LLMPROXY_ADMIN_UI_DIR` is unset, or it points to a directory that
the proxy cannot load. The API still works. The proxy logs `admin UI not
loaded` at start.

**Fix.** Set the variable to the `admin-ui-dist` directory of the release
archive, and restart.

### `/ready` returns `503 INITIALIZING` or `503 DRAINING`

**Cause.** `INITIALIZING` means at least one provider has not resolved its
host. `DRAINING` means a drain started.

**Fix.** For `INITIALIZING`, check the provider host names and DNS. After the
warming deadline, `/ready` reports `LIVE` anyway, so a `200` does not prove
that every provider resolved. For `DRAINING`, see
[Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/).

## TLS

### Clients fail to connect to the TLS listener and the log is quiet

**Cause.** The proxy logs a client handshake failure at `debug` only:
`TLS handshake failed; dropping connection`.

**Fix.** Start with `-l debug`. Check that the client trusts the issuing CA
and asks for the right host name. Test with
`openssl s_client -connect host:53421 -servername host`.

### After `SIGHUP`, TLS connections reset

**Cause.** The reload could not read or parse the new certificate or key. The
log shows `failed to rebuild TLS factories after config change; TLS-requiring
chains on this listener will reset connections until fixed`.

**Fix.** Put a valid pair in place and send `SIGHUP` again. Check the pair
before you signal. See [TLS](/docs/llm-proxy/operations/tls/).

## Reload and signals

### `SIGHUP` changed nothing

**Cause.** A broken config leaves the previous config in service. The log
shows `SIGHUP: config reload failed; continuing to serve the previous
snapshot` with the field path.

**Fix.** Read the error, correct the file, and send `SIGHUP` again. Success
logs `SIGHUP: config reload succeeded`.

### `SIGHUP: config reload refused`

**Cause.** The edit changed a setting that is fixed at start: the HMAC secret,
`auth.keys`, `auth.store`, `auth.tenant_credentials`, `ledger`,
`observability.traces`, `observability.tracing`, or `observability.metrics`.
The proxy refuses the whole reload. For the last four, the message names the
setting. Its wording uses internal names such as `node.metadata[...]`.

**Fix.** Restart the proxy to apply the change. See
[Reload configuration](/docs/llm-proxy/operations/config-reload/).

### The process is killed before streams finish at shutdown

**Cause.** The drain waits up to 600 seconds (`--drain-time-s`). Your
supervisor sent `SIGKILL` sooner.

**Fix.** Set the stop timeout above `--drain-time-s`. See
[Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/).

## Still stuck

Collect these items before you ask for help:

1. The output of `llm-proxy --version`.
2. The config with the secrets removed.
3. The `--mode validate` output, warnings included.
4. The access-log line for one failing request, with its response flags.
5. The log lines around the failure, at `-l debug`.

## Related

- [Errors from the proxy](/docs/llm-proxy/api-compatibility/errors/)
- [Response flags](/docs/llm-proxy/reference/response-flags/)
- [Access logs](/docs/llm-proxy/observability/access-logs/)
- [Limitations](/docs/llm-proxy/help/limitations/)
