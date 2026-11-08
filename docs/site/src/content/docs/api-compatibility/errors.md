---
title: Errors from the proxy
description: "Every reply that llm-proxy makes itself: status, body, headers, cause, and fix, and how to tell a proxy reply from a provider reply."
summary: Reference for proxy-made error replies - authentication, model
  access, limits and budgets, request checks, credentials, and upstream
  failures - with the exact body text of each.
lastUpdated: 2026-10-21
related:
  - api-compatibility/overview
  - authentication/virtual-keys
  - limits-and-budgets/token-rate-limiting
  - limits-and-budgets/spend-policies
  - reference/response-flags
  - help/troubleshooting
---

The proxy makes some replies itself. It forwards every other error from the
provider, with the status and body the provider sent. The proxy does not
rewrite a provider error body.

Proxy-made replies do not use the OpenAI or Anthropic error JSON. Most have a
plain-text body. Some have a JSON body of the shape
`{"error":{"message":"...","type":"..."}}`. The tables mark each JSON body.
Write client code that checks the HTTP status first.

## At a glance

- **Default behavior:** a proxy-made reply has the status and body in the
  tables below.
- **Failure mode:** authentication, model access, request checks and
  credential errors fail closed. The proxy refuses the request. A token limit
  fails open when it cannot read usage. A guardrail fails open or closed as
  its `failure_mode` setting says.

## How to tell a proxy reply from a provider reply

| Signal | Proxy-made | Provider-made |
| --- | --- | --- |
| Body | Plain text, or one of the JSON bodies in the tables. | The provider error JSON. |
| `content-type` | `text/plain; charset=utf-8` for most replies. `application/json` for the JSON replies. None for upstream-failure replies and for the `model_not_found` reply. | `application/json`. |
| Body end | A reply from a filter, or from the stream manager, ends with a newline. A reply from the router does not. | The provider decides. |
| Access log | `response_code_details` holds a reason string, and `response_flags` often holds a flag. | `response_flags` is `-`. |

To see why the proxy replied, read `response_code_details` and
`response_flags` in the access log. See
[Access logs](/docs/llm-proxy/observability/access-logs/) and
[Response flags](/docs/llm-proxy/reference/response-flags/).

## Authentication

Available when you set `auth:`.

| Status | Body | Header | Cause | Fix |
| --- | --- | --- | --- | --- |
| 401 | `unauthorized` | `www-authenticate: Bearer` | The request has no `Authorization: Bearer ...` header. | Send the virtual key as a Bearer token. The Anthropic SDK needs `auth_token`, not `api_key`. |
| 401 | `unauthorized` | `www-authenticate: Bearer` | The key matches no configured digest. | Check the key, the `hmac_secret`, and the `digest`. |
| 401 | `unauthorized` | `www-authenticate: Bearer` | The key has `revoked: true`. | Issue a new key. |
| 401 | `unauthorized` | `www-authenticate: Bearer` | A JWT is expired, not yet valid, or has the wrong issuer or audience. It can also lack the tenant claim, map to no tenant, or need a JWKS the proxy cannot refresh. | Get a new token. Check the `auth.jwt` settings. |
| 503 | `service unavailable` | none | The proxy policy data is stale. | Retry. Tell the operator if the error continues. |

Every 401 is identical on the wire: same status, same body, same header. A
caller cannot learn from the reply whether a key was ever valid. The access
log differs. `response_code_details` holds one of these values:

| `response_code_details` | Meaning |
| --- | --- |
| `auth_no_credential` | No usable `Authorization: Bearer` header. |
| `auth_unknown_key` | The key matches no digest. |
| `auth_revoked_key` | The key is revoked. |
| `auth_jwt_expired`, `auth_jwt_not_yet_valid` | The JWT time claims fail. |
| `auth_jwt_issuer_mismatch`, `auth_jwt_audience_mismatch` | The JWT issuer or audience is not accepted. |
| `auth_jwt_missing_tenant_claim`, `auth_jwt_tenant_not_mapped` | The JWT has no tenant, or no tenant maps. |
| `auth_jwt_jwks_stale` | The proxy has no fresh key set for the JWT. |
| `auth_policy_stale` | The `503` above. |

The proxy reads the virtual key from the `Authorization` header only. It
never reads `x-api-key`. See
[Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

## Model access

Available when `auth.enforce.model_policy` is on. It is on by default.

| Status | Body | Cause | Fix |
| --- | --- | --- | --- |
| 403 | `forbidden` | The tenant or key may not use the model, the request has no model, or the tenant has no stored policy and `tenants_without_policy` is `deny`. | Ask the operator to grant the model. Send a JSON body with a `model`. |

All reasons give the same reply. The access log shows
`response_code_details` `model_not_permitted`. The first refusal for a tenant
with no policy writes a warning in the proxy log.

## Token limits

Available when you set `limits`. See
[Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/).

| Status | Message | Code | Flag | Cause |
| --- | --- | --- | --- | --- |
| 429 | `token budget exceeded` | `token_limit_exceeded` | `RL` | A token limit is spent. |
| 429 | `request rate exceeded` | `request_limit_exceeded` | `RL` | A `requests_per_minute` limit is spent. |
| 429 | `too many concurrent streams` | `concurrency_limit_exceeded` | `RL` | A `concurrent_sessions` limit is full. |
| 429 | `request rate exceeded (daily limit)` | `request_limit_exceeded` | `RL` | A `requests_per_day` limit is spent. `retry-after` counts to 00:00 UTC. |
| 429 | `token budget exceeded (daily limit)` | `token_limit_exceeded` | `RL` | A `tokens_per_day` limit is spent. `retry-after` counts to 00:00 UTC. |

Every proxy-made 429 has a JSON body and `content-type: application/json`.
The shape follows the endpoint the client called. A request to
`/v1/messages` gets the Anthropic shape. Every other request gets the OpenAI
shape:

```json
{"error":{"message":"request rate exceeded","type":"rate_limit_error","code":"request_limit_exceeded"}}
```

```json
{"type":"error","error":{"type":"rate_limit_error","message":"request rate exceeded","code":"request_limit_exceeded"}}
```

The `code` is stable. The Anthropic shape has no `code` in its public
definition. The proxy adds it inside `error`. The same code is the
`response_code_details` value in the access log.

Each 429 carries these headers:

| Header | Value |
| --- | --- |
| `x-ratelimit-limit-requests`, `x-ratelimit-remaining-requests`, `x-ratelimit-reset-requests` | The limit, what is left, and the seconds until the window resets. Sent when a request limit refused. |
| `x-ratelimit-limit-tokens`, `x-ratelimit-remaining-tokens`, `x-ratelimit-reset-tokens` | The same three values. Sent when a token limit refused. |
| `retry-after` | Seconds to wait before a retry. |
| `x-should-retry` | `true`, or `false` when `retry-after` is more than 60 seconds. |
| `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-reset` | Deprecated. The same values without a dimension. Sent for one more minor release, then removed. Use the suffixed headers. |

A `concurrent_sessions` refusal has no suffixed headers, because it counts
streams, not requests or tokens. The official OpenAI and Anthropic SDKs ignore
a `retry-after` of more than 60 seconds and read `x-should-retry` instead.

Fix: wait for `retry-after` seconds, or ask the operator to raise the limit.
The proxy checks the limit before it forwards the request. It adds the tokens
of a request after the response ends. An admitted request is never cut short.

If the proxy cannot read usage from a response, it admits the request, charges
nothing, and logs a warning. That is the fail-open path.

### GET /v1/usage

When a token limit is configured, the proxy answers `GET /v1/usage` itself
and never forwards it.

| Status | Body | Cause |
| --- | --- | --- |
| 200 | JSON | Normal reply. |
| 401 | `unauthorized` | The request has no authenticated tenant. |
| 503 | `usage unavailable` | The proxy cannot read the counters. The reply has `retry-after: 1`. |

## Spend budgets

Available when you set a spend budget. See
[Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

| Status | Message | Cause | Fix |
| --- | --- | --- | --- |
| 429 | `spend budget exceeded` (code `spend_budget_exceeded`) | The budget for the period is used. Flag `RL`. | Wait for `retry-after` seconds, or ask the operator to raise the budget. |
| 403 | `authenticated key identity required for spend policy` | A key budget applies and the request has no authenticated key. | Send a valid virtual key. |
| 403 | `authenticated tenant identity required for spend policy` | A tenant budget applies and the request has no authenticated tenant. | Send a valid virtual key. |

The spend 429 has the same JSON body shapes and the same `retry-after` and
`x-should-retry` headers as the token 429. It does not send `x-ratelimit-*`
headers, whose names mean requests or tokens. It sends:

| Header | Value |
| --- | --- |
| `x-llmproxy-budget-limit-usd` | The ceiling, in USD, for example `10.000000`. |
| `x-llmproxy-budget-remaining-usd` | What is left, in USD. `0.000000` when the budget is used. |
| `x-llmproxy-budget-reset` | Seconds until the period resets. Equal to `retry-after`. |

Before this change a spend 429 sent `x-ratelimit-*` headers with values in
micro-dollars. Clients that read them must move to the headers above.

### When every provider answers 429

A failover chain tries the next provider on a provider `429`. When every
provider answers `429`, the client gets the last provider's response
unchanged. This includes the provider's own `x-ratelimit-*` and `retry-after`
headers and its body. Those headers describe the operator's account with that
provider, not a limit of the tenant.

## Refusals for paths that cannot be metered

| Status | Body | Cause | Fix |
| --- | --- | --- | --- |
| 403 | `this endpoint cannot be metered, so it is refused under a spend budget or token limit` | A budget or token limit applies to the caller, and the proxy cannot count the request. | Use a metered endpoint. See [API compatibility](/docs/llm-proxy/api-compatibility/overview/#supported-api-families). |

The access log shows `response_code_details` `endpoint_not_metered`. The same
`403` covers a request whose cost the proxy cannot count from its shape, for
example a translation without `response_format: verbose_json`. A WebSocket on
a path that does not end in `/realtime` also gets it. See
[Realtime](/docs/llm-proxy/api-compatibility/realtime/).

## Model and request checks

| Status | Body | Cause | Fix |
| --- | --- | --- | --- |
| 404 | JSON: `{"error":{"message":"no route matched the requested model","type":"model_not_found"}}` | No `routes` or `models` entry matches the `model` value, the body has no readable `model`, and the config has no `*` rule. | Use a name the config matches, or add a `*` rule. |
| 400 | ``no model is configured for `auto` `` | The request names `auto`, and the operator set no model for the tenant. | Ask the operator to set the `auto` model. See [The auto model](/docs/llm-proxy/providers-and-routing/auto-model/). |
| 400 | `request body is not a JSON object` | The proxy routed on a model, but the body is not a JSON object. | Send a JSON object. |
| 400 | `request body has duplicate model keys` | The body repeats the `model` key. | Send one `model` key. |
| 400 | `request model disagrees with routed model` | The `model` in the whole body differs from the model the proxy routed on. | Send one consistent `model`. |
| 400 | `request field not permitted: <field>` | The body has a top-level key that the provider `request_fields.deny` list names. | Remove the field. |
| 400 | `tool type not permitted: <type>` | A `tools` array element has a `type` that the provider `request_fields.deny_tool_types` list names. `response_code_details` is `request_tool_type_not_permitted`. | Remove the tool. |
| 400 | `provider-side MCP is not permitted for this provider: <what>` | The body has a top-level `mcp_servers` key, or a `tools` element of type `mcp` or `mcp_toolset`, and the provider does not set `request_fields.provider_mcp: forward`. `response_code_details` is `provider_mcp_refused`. | Remove the MCP server from the request, or ask the operator. See [Provider-side MCP](/docs/llm-proxy/providers/overview/#provider-side-mcp). |
| 400 | `provider model rewrite failed` | The proxy could not write the provider model name into the body. | Check the `provider/model` entry and the JSON body. |
| 400 | `` `max_tokens` 9000 exceeds the maximum of 4096 output tokens for this model `` | The output limit is above the `max_output_tokens` of the model. The field name and numbers change. | Lower the limit. |
| 400 | ``` `max_tokens` must be a non-negative integer ``` or ``` request body has duplicate `max_tokens` keys ``` | The output limit is not a non-negative integer, or the key repeats. The field name changes. | Send one integer. |
| 413 | `request body exceeds buffer limit` | The body is larger than `listen.max_request_body_bytes`. | Send a smaller body, or raise the limit. The default is 1 MiB. |
| 400 | `invalid request body` | The proxy could not read the request body. | Check the client. |
| 400 | `request body uses a reserved key` | The body has the key `$serde_json::private::RawValue` at any depth, in any escaped spelling. No client API uses this key. The proxy refuses it because its JSON reader would read such a body differently from the provider. `response_code_details` is `request_body_reserved_json_key`. | Remove the key. |
| 408 | `request timeout` | The client did not send the whole request within `listen.request_timeout`. | Send the request faster, or raise the timeout. |

## Provider objects (files and batches)

Available when `auth:` is on and `auth.enforce.object_ownership` is on. Each
reply is JSON with a `message` and no `type`.

| Status | Body | Cause | Fix |
| --- | --- | --- | --- |
| 404 | `{"error":{"message":"object not found"}}` | The file or batch ID belongs to another tenant, or is unknown. Listing a collection gets it too. | Use an ID that your tenant created. |
| 400 | `{"error":{"message":"request body references an object but is not valid JSON"}}` | The body names a provider object but is not valid JSON. | Send valid JSON. |
| 503 | `{"error":{"message":"object ownership is unavailable"}}` | The proxy could not read the object owners. | Retry. Tell the operator if the error continues. |

## Guardrails

Available when you set `guardrails`. See
[Guardrails](/docs/llm-proxy/authentication/guardrails/). All replies are JSON.

| Status | Body | Cause |
| --- | --- | --- |
| 403 | `{"error":{"message":"request denied by guardrail","type":"guardrail_denied"}}` | The check denied the request. If the check gave a reason, the message is `request denied by guardrail: <reason>`. |
| 413 | `{"error":{"message":"request body exceeds the guardrail limit","type":"guardrail_over_limit"}}` | The body is larger than the check accepts, and `failure_mode` is closed. |
| 503 | `{"error":{"message":"the guardrail check is unavailable","type":"guardrail_timeout"}}` | The check timed out, and `failure_mode` is closed. |
| 503 | `{"error":{"message":"the guardrail check is unavailable","type":"guardrail_error"}}` | The check failed, and `failure_mode` is closed. |

With `failure_mode` open, the proxy admits the request and logs a warning.

## Tenant provider credentials

Available when a provider sets `tenant_credentials: true`. See
[Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

| Status | Body | Cause | Fix |
| --- | --- | --- | --- |
| 403 | JSON, type `tenant_credential_missing`. The message is `no tenant credential for provider <name>`, or `no tenant credential for any provider this route can use`. | The tenant has no stored key for the provider the route selects. | Store the tenant key. |
| 503 | `provider credential failure` | The proxy cannot use a provider credential. For a tenant key, decryption failed. For other providers, the proxy could not build the credential. Flag `UF`. | Check the credential source. The proxy log has the reason. |
| 503 | `provider token unavailable` | The proxy has no valid OAuth2 token for the provider. | Check the token endpoint and the credential source. |

When a failover chain has another member, the proxy sends the request to the
next member instead of replying. See
[Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

## Billing ledger

Available when you set `ledger` with `on_unavailable: reject`.

| Status | Body | Cause |
| --- | --- | --- |
| 503 | `billing ledger unavailable: <reason>` | The ledger cannot take an entry. `<reason>` is `queue_full`, `writer_failed` or `disk_full`. |

See [Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/).

## Upstream failures

These replies come from the proxy. They have plain-text bodies and no
`content-type` header. Each sets a response flag.

| Status | Body | Flag | Cause | Fix |
| --- | --- | --- | --- | --- |
| 503 | `upstream connect failure` | `UF` | The TCP connect failed or timed out, or the TLS handshake failed. | Check `base_url`, DNS, and the provider TLS. |
| 503 | `upstream overloaded` | `UO` | The provider reached its concurrency ceiling. The reply has `x-envoy-overloaded: true`. | Retry. Ask the operator to raise the ceiling or add a failover provider. |
| 503 | `upstream reset` | `UR` | The provider reset the stream before it sent headers. | Check the provider. Add a failover provider. |
| 503 | `upstream connection failure` | `UR` or `UC` | The connection to the provider closed or reset after the request began. | Check the provider. |
| 502 | `upstream connection failure` | `UPE` | The provider broke the HTTP protocol. | Check the provider. |
| 503 | `no healthy upstream` | `UH` | No host of the provider is healthy. | Check the provider. |
| 504 | `upstream request timeout` | `UT` | No response headers arrived in time. | Retry, or raise the route timeout. See [Timeouts and retries](/docs/llm-proxy/providers-and-routing/timeouts-and-retries/). |

When a model has more than one provider, the proxy tries the next provider on
a connection failure, a reset, and a `429`, `500`, `502` or `503` from the
provider. If every provider fails, the client gets the final failure.

### Errors after the stream starts

After the proxy sends response headers, it cannot send a new status. If the
provider fails later, the response ends without a clean finish. The client
sees a broken stream, not an error reply. The proxy never retries on another
provider after the first response byte.

Two listener timeouts can also end a request before the provider answers:

| Status | Body | Cause |
| --- | --- | --- |
| 408 | `stream timeout` | The request had no activity for `listen.stream_idle_timeout`. Flag `SI`. |
| 504 | `stream max duration reached` | The request lived longer than `listen.max_stream_duration`. |

## Realtime upgrades

| Status | Body | Cause |
| --- | --- | --- |
| 403 | `upgrade not allowed` | `realtime.enabled` is not `true`. |
| 502 | `cross-protocol websocket bridging (h1<->h2) is not supported` | The client and the provider use different HTTP versions. |
| 503 | `upstream connect failure`, `upstream TLS handshake failure`, `upstream overloaded` or `upstream reset` | The proxy could not open the connection to the provider. |

See [Realtime](/docs/llm-proxy/api-compatibility/realtime/).

## Limitations

- Proxy-made replies are not in the OpenAI or Anthropic error JSON format.
  Clients cannot read an `error.code` field from them.
- A 401 reply does not say why the key failed. Only the access log does.
- See [Limitations](/docs/llm-proxy/help/limitations/).

## Related

- [API compatibility](/docs/llm-proxy/api-compatibility/overview/)
- [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/)
- [Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/)
- [Troubleshooting](/docs/llm-proxy/help/troubleshooting/)
