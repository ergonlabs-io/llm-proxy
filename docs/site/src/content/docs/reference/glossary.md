---
title: Glossary
description: "Definitions of the terms that the llm-proxy docs use, in alphabetical order, with one meaning for each term."
summary: Alphabetical glossary of llm-proxy terms, including provider, model,
  route, fallback, dialect, virtual key, tenant, principal, rate card,
  nanodollar, budget, ledger, request record, trace export, and drain.
lastUpdated: 2026-10-21
related:
  - getting-started/core-concepts
  - configuration/reference
  - reference/response-flags
---

Each term has one meaning in these docs. The config has two nouns for what
serves a request: `providers` and `models`. The docs do not use the word
"backend". For how the terms fit together, read
[Core concepts](/docs/llm-proxy/getting-started/core-concepts/).

## A

**Access log**
: One text or JSON line that the proxy writes when a response stream ends.
  See [Access logs](/docs/llm-proxy/observability/access-logs/).

**Admin address**
: The optional `admin` listener. It serves `/ready`, `/config_dump`,
  `/clusters`, `/server_info`, `/stats`, `/stats/prometheus`, and the admin
  API. See [Admin API](/docs/llm-proxy/administration/admin-api/).

**Admin token**
: The bearer token that protects the admin API writes and sensitive reads. The
  proxy reads it from `LLMPROXY_ADMIN_TOKEN`. See
  [Environment variables](/docs/llm-proxy/reference/environment-variables/).

**Aggregate**
: The internal name of the fallback chain that the proxy builds for a route
  with `fallbacks` or for a `models` entry with several providers. The proxy
  counts it as a cluster in the `--mode validate` summary. You do not name
  an aggregate in the config. See
  [Failover and aggregates](/docs/llm-proxy/providers-and-routing/failover-and-aggregates/).

**Alias**
: Informal word for a client-facing model name in the `models` catalog. The
  docs say *model* for the config term. See **Model**.

**Attempt**
: One try to send a request to a provider. A retry or a fallback is a new
  attempt. A request record lists the attempts.

**`auto`**
: A reserved model name. The `auto` block replaces it with the model that
  you select for the tenant. See
  [The auto model](/docs/llm-proxy/providers-and-routing/auto-model/).

## B

**Budget**
: A spend ceiling for a key or a tenant in one UTC period. You set it with
  the admin API. A missing budget means unlimited. A budget of zero denies the
  first request. See [Spend policies](/docs/llm-proxy/limits-and-budgets/spend-policies/).

**BYOK**
: Bring your own key. A tenant stores its own key for a provider, and the
  proxy sends that key for the tenant instead of the operator key. The docs
  call the feature *tenant provider credentials*. See
  [Tenant provider credentials](/docs/llm-proxy/authentication/tenant-provider-credentials/).

## C

**Cardinality limit**
: The most label values that a metric can hold. When a limit is reached, new
  values share one `-cardinality-overflow-` series. See
  [Metrics and stats](/docs/llm-proxy/observability/metrics-and-stats/).

**Chargeback tag**
: A `key=value` pair that attributes spend to a project, a team, or a cost
  centre. The proxy writes accepted tags to the request record and to the
  ledger entry. See [Chargeback tags](/docs/llm-proxy/limits-and-budgets/chargeback-tags/).

**Circuit breakers**
: The `providers.<name>.circuit_breakers` ceilings on requests in flight,
  waiting requests, and open connections for one provider. A request over a
  ceiling gets `503` and the `UO` response flag. See
  [Providers](/docs/llm-proxy/providers/overview/).

## D

**Dialect**
: The wire format of a provider: OpenAI-shaped or Anthropic-shaped. It
  decides how the proxy reads token usage. The docs use *wire dialect* where
  the meaning is not clear. Do not confuse it with the *`llmproxy` dialect*,
  which is the config file format (`version: 0`).

**Digest**
: The 64-character hex value `HMAC-SHA256(secret, key)` of a virtual key. The
  config holds the digest. It never holds the plaintext key.

**Drain**
: The period after `SIGTERM`, `SIGINT`, or `POST /drain_listeners` in which the
  proxy waits for open connections to close. `--drain-time-s` sets the length.
  See [Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/).

## F

**Fallback**
: A provider that the proxy tries after the primary provider fails. The proxy
  never tries one after the first byte of a response reaches the client.

## G

**Guardrail**
: A check that you run. The proxy sends each request body to it before any
  provider is dialled. The check allows or denies. See
  [Guardrails](/docs/llm-proxy/authentication/guardrails/).

## H

**HMAC secret**
: The operator secret that keys the digest of every virtual key. Set it with
  `auth.hmac_secret` or `auth.hmac_secret_file`.

## I

**Idle timeout**
: The longest time with no bytes in flight on a response. The route field
  `idle_timeout` defaults to 90 seconds. The listener field
  `stream_idle_timeout` defaults to 10 minutes and bounds the wait for
  response headers. See
  [Timeouts and retries](/docs/llm-proxy/providers-and-routing/timeouts-and-retries/).

## J

**JWT principal**
: A caller that sends a signed JWT from an issuer in `auth.jwt`, instead of a
  virtual key. See [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).

## K

**Key ID**
: The `id` of a virtual key. It names the key in logs and request records. It
  is not secret.

## L

**Ledger**
: The billing ledger. One durable, encrypted entry for every request that the
  proxy dials to a provider. The `ledger` block turns it on. See
  [Billing ledger](/docs/llm-proxy/limits-and-budgets/billing-ledger/).

**List cost**
: The price of a request from the rate card, in nanodollars. It is the
  catalog price, not a bill.

**Listener**
: The address where the proxy accepts client connections. The `listen` key
  sets it.

## M

**Micro-dollar**
: One millionth of a US dollar. Budgets and the `x-ratelimit-*` headers of a
  spend refusal use micro-dollars.

**Model**
: A client-facing model name in the `models` catalog. It maps to an ordered
  list of providers. A route can also match a model name from the request,
  without a catalog entry.

## N

**Nanodollar**
: One billionth of a US dollar (10^-9 USD). The rate card and the cost fields
  of logs and records use integer nanodollars, so sums have no rounding error.

**Node ID**
: The identity of one replica. Set it with `--service-node`. A shared store,
  the ledger, and trace export need one. See
  [CLI reference](/docs/llm-proxy/reference/cli/#the-service-node-flag).

## O

**Outlier detection**
: The `providers.<name>.outlier_detection` block. After consecutive failures,
  the proxy ejects the provider for a time, and a `models` entry passes it
  over while another provider is not ejected.

## P

**Principal**
: The authenticated caller of a request: a virtual key or a JWT. The principal
  decides the tenant and the user.

**Provider**
: One upstream LLM API, for example OpenAI or a vLLM server. Each key under
  `providers` is a provider. Users and tenants never choose a provider. Routes
  and models do.

## R

**Rate card**
: A versioned price list. Each entry has a provider type, a model, and prices
  per token, per image, per character, or per second. The `pricing` block
  sets it. See [Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/).

**Realtime session**
: One WebSocket session on a path that ends in `/realtime`. The `realtime`
  block turns it on. The proxy meters the session and writes one access-log
  line, one request record, and one ledger entry when it closes. See
  [Realtime](/docs/llm-proxy/api-compatibility/realtime/).

**Request record**
: A JSON object for one finished request: tenant, user, models, provider,
  status, usage, cost, and attempts. It holds no bodies and no headers.
  `--request-records-file` turns it on. See
  [Request capture](/docs/llm-proxy/observability/request-capture/).

**Response flag**
: A short code, such as `UF` or `RL`, that tells why a request ended as it
  did. See [Response flags](/docs/llm-proxy/reference/response-flags/).

**Route**
: A rule that matches the `model` of a request and names a provider. The
  proxy checks routes from top to bottom, and the first match wins.

## S

**Session affinity**
: The `models.<name>.session_affinity` setting. It keeps one session on one
  provider of a weighted `models` entry, so the provider cache stays warm. See
  [Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/).

**Spend scope**
: What a budget counts. A key budget counts the spend of one key. A tenant
  budget counts the spend of every key of the tenant. The proxy enforces both
  when both are set. There is no budget for a user.

**Strict mode**
: The load mode of a `--config` file. An unknown field is an error with its
  full dotted path. No option turns it off.

## T

**Tenant**
: The account or team that a virtual key belongs to. Many keys can share one
  tenant. Limits, budgets, and model access apply to the tenant. A request
  with a missing tenant uses the reserved tenant `default`.

**TPOT**
: Time per output token. In the access log, `llm_tpot_ms` is the duration
  minus TTFT, divided by the output tokens, in milliseconds.

**Trace export**
: The export of request and response bodies to compressed JSON-lines files,
  for tenants that opt in. The `observability.traces` block turns it on. It is
  not OTLP distributed tracing, which is `observability.tracing`. See
  [Trace export](/docs/llm-proxy/observability/trace-export/).

**TTFT**
: Time to first token. In the access log, `llm_ttft_ms` is the time from the
  response headers to the first body byte, in milliseconds.

## U

**Usage**
: The token counts that a provider reports in a response: input, cached
  input, cache creation, and output. A missing report is not the same as
  zero.

**User**
: A person under a tenant. A virtual key's id names its user. A JWT user is
  `jwt:<issuer>:<tenant>:<user claim>`. A user setting only narrows what the
  tenant allows.

## V

**Virtual key**
: A key that the proxy issues, with the prefix `llmp_`. A client sends it as a
  bearer token instead of a provider key. The proxy removes it before it
  dials the provider. Make one with `llm-proxy --mode keygen`.

## W

**Weight**
: The `weight` of a provider entry in a `models` list. The proxy picks the
  first provider of each request in proportion to the weights. The other
  entries are the fallbacks, in list order.

## Related

- [Core concepts](/docs/llm-proxy/getting-started/core-concepts/)
- [Configuration reference](/docs/llm-proxy/configuration/reference/)
- [Response flags](/docs/llm-proxy/reference/response-flags/)
