---
title: Request guardrails
description: "Send each request body to an HTTP check that allows or denies the request before the proxy dials a provider."
summary: How the top-level `guardrails` block sends request bodies to an
  external HTTP check, the wire format, the failure modes, the status codes
  the client sees, and what the check can and cannot do.
lastUpdated: 2026-10-19
related:
  - configuration/configuration-file
  - authentication/virtual-keys
  - observability/access-logs
  - observability/metrics-and-stats
---

# Request guardrails

A guardrail is an external HTTP service that reads a request body and
answers `allow` or `deny`. The proxy asks the service before it dials a
provider. A denied request never reaches a provider.

To enable guardrails in the `llmproxy` dialect, add a top-level `guardrails`
block. The block has a required `default` check. It can also have a check for
each tenant. The schema is `schema/llmproxy-v0.schema.json` (property
`guardrails`, and `$defs/Guardrails`, `$defs/GuardrailCheck`,
`$defs/HttpGuardrail`).

The block lowers to the `llmproxy.guardrail` HTTP filter
(`type.llmproxy.dev/llmproxy.filters.v0.Guardrail`). In Envoy mode, configure
that filter directly; its fields are in
`crates/proxy-api/vendor/llmproxy/filters/v0/guardrail.proto`.

## Read this first

**Warning.** A check receives the full body of every request that it checks.
This discloses every prompt to the check service. Set `url` only to a service
that you trust with all prompts. The URL is explicit config: the proxy never
picks a check for you.

**Warning.** A check has no default failure mode. You must set `failure_mode`
for each check. The value `open` admits a request when the check fails. The
value `closed` refuses it.

What a guardrail does and does not do:

- A check only allows or denies. It cannot change the request. There is no
  redaction.
- A check adds one round trip to each checked request.
- The proxy sends only a request that authentication and model authorization
  admit. An unauthenticated request gets 401 and the check never sees it.
- The proxy checks the request only. It does not check the response. Response
  checks are not supported.
- The proxy does not check a request with an empty body.
- Only an `http` check exists. `http` is the only backend.

## Simple config

```yaml
version: 0
providers:
  openai:
    type: openai
    api_key: ${OPENAI_API_KEY}
routes:
  - model: gpt-4o
    provider: openai
auth:
  hmac_secret: ${AUTH_HMAC_SECRET}
  keys:
    - id: acme-prod
      tenant: acme
      # HMAC-SHA256 of the virtual key under hmac_secret, in hex.
      digest: "3f1c9e0d7b2a4c6e8f0a1b3d5c7e9f1a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e"
guardrails:
  default:
    http:
      url: http://127.0.0.1:9000/check
      timeout: 500ms
      max_body_bytes: 1048576
    failure_mode: closed
  tenants:
    acme:
      http:
        url: https://guard.example.com/acme
        timeout: 1s
        max_body_bytes: 262144
      failure_mode: open
```

Tenant `acme` uses its own check. Every other tenant uses `default`. A
request with no authenticated tenant also uses `default`. The `tenants`
entry replaces `default` for that tenant. The two checks do not combine.

| Field | Type | Default | Required | What it does |
|---|---|---|---|---|
| `guardrails.default` | check | none | yes | The check for a tenant with no entry, and for a request with no tenant. |
| `guardrails.tenants` | object, tenant to check | none | no | A check for each named tenant. Needs an `auth` block. |
| `<check>.http.url` | string | none | yes | An absolute `http` or `https` URL with no user information. `https` verifies the server against the platform root certificates. |
| `<check>.http.timeout` | duration | none | yes | The limit for the whole check: connect, request, and response. At least `1ms`. |
| `<check>.http.max_body_bytes` | integer | none | yes | The largest request body that the proxy sends. At least 1. |
| `<check>.failure_mode` | `closed` or `open` | none | yes | What happens when the check fails. See [Failure modes](#failure-modes). |

`<check>` is `guardrails.default` or `guardrails.tenants.<tenant>`. The
proxy never writes the `url` path or query to a log. A token in the path or
query is safe from the logs.

## The check protocol

The proxy sends `POST <url>` with a JSON object.

| Key | Value |
|---|---|
| `tenant` | The authenticated tenant, or `null`. |
| `requested_model` | The `model` from the request body, or `null`. |
| `resolved_model` | The model that [the auto model](../../providers-and-routing/auto-model/) chose, or `null`. |
| `body` | The request body as text. |
| `body_base64` | The request body in base64. The proxy sends this key instead of `body` when the body is not UTF-8. |

The service answers status 200 with one of these bodies:

```json
{"decision": "allow"}
```

```json
{"decision": "deny", "reason": "contains a forbidden topic"}
```

Any other answer is an error. Examples are a status other than 200, a body
that is not JSON, a `decision` other than `allow` or `deny`, and a body over
64 KiB.

## What the client sees

| Case | Status | Body `error.message` | `response_code_details` |
|---|---|---|---|
| The check denies | 403 | `request denied by guardrail: <reason>` | `guardrail_denied` |
| Error, fail closed | 503 | `the guardrail check is unavailable` | `guardrail_error` |
| Timeout, fail closed | 503 | `the guardrail check is unavailable` | `guardrail_timeout` |
| Body over `max_body_bytes`, fail closed | 413 | `request body exceeds the guardrail limit` | `guardrail_over_limit` |

The proxy returns the first 256 bytes of the reason. It drops control
characters from the reason. If the check gives no reason, the message is
`request denied by guardrail`.

A denied request is not dialled and is not charged. It does not count
against a limit. It gets no ledger entry. The test
`a_denied_request_is_not_dialled_charged_or_ledgered` proves this.

## Failure modes

The check fails when it errors, times out, or the body is longer than
`max_body_bytes`. A body over the limit is not sent to the check.

- `closed`: the proxy refuses the request. See the table above for the status
  code.
- `open`: the proxy admits the request without a decision. It counts the
  request as `failure_mode_allowed`. It also counts the cause (`error`,
  `timeout`, or `over_limit`).

For `open`, the proxy writes a warning to its log at most once a minute. The
warning names the check as `host:port`, and the cause. It never contains the
body, a credential, or the URL path or query. The test
`fail_open_admits_counts_and_logs_once_without_the_body_or_a_credential`
proves this.

## Where the check runs

The check runs after authentication and model authorization. It runs before
the token limit, the spend limit, and usage accounting. This order is why a
denied request is never counted or charged.

## Load errors

The proxy checks the block at load time. Each error names its field path.

| Field path | Cause |
|---|---|
| `guardrails.default` | The block has no `default`. |
| `guardrails.tenants` | The block has `tenants` and the file has no `auth` block. |
| `guardrails.tenants` | A tenant name is empty. |
| `<check>` | The check has no `http` backend. |
| `<check>.failure_mode` | `failure_mode` is not set. |
| `<check>.http.url` | The URL is not absolute `http` or `https`, has no host, or has user information. |
| `<check>.http.timeout` | The timeout is not set, is zero, or is more than 32 bits of milliseconds. |
| `<check>.http.max_body_bytes` | The value is not set or is 0. |

## Observe the checks

Each request that a check decides sets `%LLM_GUARDRAIL%` in the
[access log](../../observability/access-logs/). The counter
`llmproxy_guardrail_checks_total{scope,outcome}` counts the outcomes. See
[Metrics and /stats](../../observability/metrics-and-stats/).
