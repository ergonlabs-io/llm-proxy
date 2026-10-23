---
title: Realtime sessions
description: "Proxy WebSocket realtime sessions to a provider with the realtime block, with authentication, limits, usage metering, and drain behavior."
summary: How llm-proxy runs a WebSocket session on a path that ends in
  /realtime - what decides if the session opens, how usage is metered from
  response.done events, what the tunnel does not do, and what happens on drain.
lastUpdated: 2026-10-21
related:
  - api-compatibility/overview
  - api-compatibility/errors
  - limits-and-budgets/spend-policies
  - limits-and-budgets/token-rate-limiting
  - limits-and-budgets/pricing-and-cost-tracking
  - operations/draining-and-shutdown
---

Use a realtime session to reach the WebSocket API of an OpenAI-compatible
provider through llm-proxy. The proxy checks the client when the session
opens. It then tunnels the WebSocket bytes to the provider and reads token
usage from the `response.done` events that pass through.

## At a glance

- **Default behavior:** the proxy refuses every WebSocket upgrade with `403`
  and the body `upgrade not allowed`. Set `realtime.enabled: true` to accept
  upgrades.
- **Failure mode:** authentication, model access, limits, and spend budgets
  fail closed. They refuse the session with an HTTP status before the proxy
  dials the provider. A response with no readable usage fails open: the
  session continues, the proxy charges nothing for that response, counts it,
  and logs a warning.

## Example

Save this file as `realtime.yaml`. The client asks for the model `voice`. The
proxy asks the provider for `gpt-realtime-2026`.

```yaml title="realtime.yaml"
version: 1
listen: 127.0.0.1:53421
admin: 127.0.0.1:53422

realtime:
  enabled: true

providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes: []
models:
  voice:
    providers: [openai/gpt-realtime-2026]
```

Check the file, then start the proxy.

```bash
llm-proxy --config realtime.yaml --mode validate
llm-proxy --config realtime.yaml > /tmp/llm-proxy.log 2>&1 &
```

A client connects to `ws://127.0.0.1:53421/v1/realtime?model=voice`. The proxy
sends the provider request to `/v1/realtime?model=gpt-realtime-2026` with the
provider key. The client key does not reach the provider.

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `realtime.enabled` | boolean | none (the `realtime` block is absent) | Accept WebSocket upgrades. Required when the `realtime` block is present. Absent or `false`: every upgrade gets `403`. |
| `limits[].concurrent_sessions` | integer, at least 1 | none | The most streams in flight for each bucket. A realtime session counts for its whole life. An ordinary request or SSE stream also counts. |

The field reference is generated from the schema. See
[Configuration reference](/docs/llm-proxy/configuration/reference/).

## What decides if a session opens

The proxy runs the same checks as for an ordinary request, before it dials
the provider. A refusal is an HTTP status on the upgrade request:

| Check | Refusal |
| --- | --- |
| `auth` | `401 unauthorized`. |
| Model access (`auth.enforce`) | `403 forbidden`. |
| `limits` | `429`. A `concurrent_sessions` limit that is full gives `too many concurrent streams`. |
| Spend budgets | `429 spend budget exceeded`. |
| `realtime.enabled` is not `true` | `403 upgrade not allowed`. |

The proxy reads the model from the `model` query parameter. It matches the
model against `routes[].model` and `models`, and it writes the provider model
name into the query of the provider request. The proxy makes one provider
choice for a session. It does not fail over to another provider.

A refused session never reaches the provider. The reply bodies are in
[Errors](/docs/llm-proxy/api-compatibility/errors/).

## How the proxy meters a session

Only a session on a path that ends in `/realtime` is metered. The proxy reads
the `usage` of each `response.done` event and adds the values over the whole
session. It reads text, cached, and audio tokens. The cost uses the rate card
for the provider that the proxy dialled, at the audio rates where the card
sets them. See
[Pricing and cost tracking](/docs/llm-proxy/limits-and-budgets/pricing-and-cost-tracking/).

Each session writes one access-log line, one request record, and one ledger
entry, when it closes. The `response_code` is `101`.

| Case | What the proxy does |
| --- | --- |
| A `response.done` has readable usage. | Adds it to the session total. |
| A `response.done` has no usage, is not valid JSON, or is larger than 1 MiB. | Charges nothing for it. Counts it in `llmproxy_realtime_usage_missing_total` with the reason `no_usage` or `unreadable`. Logs a warning, at most once a minute. |
| A message is compressed. | Counts it with the reason `compressed`. The proxy removes the client offer of `Sec-WebSocket-Extensions`, so a compliant server sends no compressed frame. |
| The session ends while a response is in flight. | Charges what the finished events reported. Counts the open response with the reason `cut`. Records the usage as `partial`. |

The proxy never estimates tokens from the audio bytes.

## What the tunnel does not do

- **No retries.** A session is one attempt on one provider.
- **No filters on client frames.** After the upgrade, no filter reads the
  frames that the client sends. The controls above run when the session opens.
- **No compression.** The proxy removes the `Sec-WebSocket-Extensions` offer
  from the client request.
- **No mixed HTTP versions.** The client and the provider must use the same
  HTTP version, h1 with h1 or h2 with h2. Providers use h1 by default. A
  mismatch gets `502` with the body `cross-protocol websocket bridging (h1<->h2) is not supported`.
- **A fixed idle limit.** The proxy closes a session when no byte moves in
  either direction for 300 seconds. A ping or pong frame restarts the timer.
  No field changes this value.

## Other WebSockets

A WebSocket upgrade on a path that does not end in `/realtime` is tunnelled
but not metered. Where a spend budget or token limit applies to the caller,
the proxy refuses it with `403` and the body `this endpoint cannot be
metered, so it is refused under a spend budget or token limit`. Where none
applies, the proxy tunnels it to the provider that the route selects.

## Draining

When a drain starts, the proxy sends each open session a WebSocket Close frame
with code 1001 (going away), with the reason `server draining`. The proxy then
stops forwarding frames from the provider. The client answers the Close frame,
and the session ends. The proxy logs the session once, with the usage it
reported. The drain does not finish while a session is open. The drain
deadline (`--drain-time-s`) still ends the process. See
[Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/).

## Failure modes

| Status | Body | Cause | Fix |
| --- | --- | --- | --- |
| `403` | `upgrade not allowed` | `realtime.enabled` is not `true`. | Set `realtime.enabled: true`. |
| `401` | `unauthorized` | `auth` is on and the upgrade has no valid virtual key. | Send `Authorization: Bearer llmp_...` on the upgrade request. |
| `403` | `forbidden` | The key may not use the model, or the URL has no `model` parameter and model policy is on. | Grant the model. Add `?model=<name>`. |
| `429` | `too many concurrent streams` | A `concurrent_sessions` limit is full. | Close a session. Retry after `retry-after` seconds. |
| `502` | `cross-protocol websocket bridging (h1<->h2) is not supported` | The client and the provider use different HTTP versions. | Use the same version on both sides. |
| `503` | `upstream connect failure`, `upstream TLS handshake failure`, `upstream overloaded`, `upstream reset` | The proxy could not open the connection to the provider. | Check the provider. |

## Limitations

- The dialect has one switch, `realtime.enabled`. It allows the `websocket`
  upgrade type only. It has no field for the idle limit or for other upgrade
  types. See [Limitations](/docs/llm-proxy/help/limitations/).
- A browser cannot set an `Authorization` header on a WebSocket, and the
  proxy has no CORS support. Connect from a server.

## Implementation notes

- Endpoint class `Realtime`, the `model` query parameter, and its rewrite:
  `crates/proxy-http/src/endpoint.rs`. The router applies the rewrite in
  `crates/proxy-http/src/router.rs`.
- Usage scanner: `crates/proxy-filters/src/realtime_usage.rs`. Metering and the
  missing-usage warning: `crates/proxy-filters/src/usage_filter.rs`.
- Drain Close frame: `crates/proxy-http/src/tunnel.rs`. Idle limit:
  `WEBSOCKET_TUNNEL_IDLE_TIMEOUT` in `crates/proxy-http/src/codec.rs`.
- Tests in `crates/proxy/tests/realtime_e2e.rs`:
  `a_realtime_session_is_metered_from_its_events_and_logged_at_its_close`,
  `a_refused_upgrade_never_reaches_the_provider`,
  `a_concurrent_session_limit_refuses_the_session_over_it`, and
  `drain_closes_an_open_session_with_1001`.
