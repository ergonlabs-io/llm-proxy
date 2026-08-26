---
title: WebSocket and other HTTP upgrades
summary: How the HTTP connection manager tunnels an HTTP/1.1 `Upgrade`
  request (WebSocket included) to a provider, what gates it, and the real
  limits of today's transparent tunnel — bootstrap configuration only, not
  yet reachable from the plain configuration format.
last_updated: 2026-08-26
related:
  - ../providers-and-routing/providers-and-clusters/
  - ../providers-and-routing/timeouts-and-retries/
  - ../configuration/configuration-file/
---

# WebSocket and other HTTP upgrades

llm-proxy can tunnel an HTTP/1.1 `Upgrade` request — WebSocket is the
practical case, since several providers' realtime APIs use it — straight
through to a provider, byte for byte, once the upstream accepts it. This page
covers `upgrade_configs`, the gate that decides whether a request is even
allowed to ask, and exactly what the tunnel does and does not do once it is
open.

## Bootstrap configuration only

Read this first. `upgrade_configs` is a field on `HttpConnectionManager`, set
directly in a raw bootstrap configuration. `schema/llmproxy-v0.schema.json` —
the plain `--config` format — has no field for it: a route written with
`routes[].provider` always produces an ordinary `Forward` action, never an
upgrade-enabled one, and there is no dialect key to change that. If you need
WebSocket tunneling today, write it against a bootstrap configuration.

## `upgrade_configs`: the allow-list

`HttpConnectionManager.upgrade_configs` is a list of entries, each naming one
upgrade type:

| Field | Type | Default | What it does |
|---|---|---|---|
| `upgrade_type` | string | — | The value expected in the request's `Upgrade` header, matched case-insensitively. Stored lowercased. An empty string is a load error. Two entries whose types collide case-insensitively are a load error naming the second entry's path (`crates/proxy-config/tests/upgrade_configs.rs`'s `duplicate_upgrade_type_is_rejected`). |
| `enabled` | boolean | `true` | Whether this upgrade type is actually allowed. `false` records the type as declared but refused — not the same as omitting it, though both currently refuse the same way (see below). |

**No `upgrade_configs` at all — the default — means no upgrades of any kind.**
This matches Envoy's own default. A request that sends `Upgrade: websocket`
against an HCM with an empty (or absent) `upgrade_configs` is refused, not
silently forwarded as a plain request
(`crates/proxy-config/src/ir.rs`'s `HttpConnectionManagerConfig::upgrade_configs`
doc comment; proven by `absent_upgrade_configs_is_empty` in
`crates/proxy-config/tests/upgrade_configs.rs`).

```yaml
route_config:
  name: rc
  virtual_hosts:
    - name: vh
      domains: ["*"]
      routes:
        - match: { prefix: "/realtime" }
          route: { cluster: "provider:openai" }
upgrade_configs:
  - upgrade_type: websocket
```

## What happens to a request that asks for an upgrade

1. **The requested type must be enabled.** llm-proxy reads the first token of
   the `Upgrade` header, lowercases it, and checks it against
   `upgrade_configs`. No `Upgrade` header, an unlisted type, or a type whose
   entry sets `enabled: false` are all refused identically: **`403`**, body
   `upgrade not allowed`, and the upstream is never dialed
   (`disallowed_upgrade_returns_403_and_never_dials_upstream` and
   `upgrade_type_present_but_disabled_returns_403` in
   `crates/proxy-http/tests/router_upgrade_e2e.rs`).
2. **An allowed request still has to match a route with a `Forward` action.**
   A `DirectResponse` or `Redirect` route has nothing to tunnel to; the
   request falls through to whatever that action normally does, and the
   client's upgrade attempt is left unfulfilled — correctly telling the
   client that no upgrade happened
   (`router.rs`'s `route_and_forward`, the comment on its `on_upgrade`
   branch).
3. **llm-proxy dials the picked cluster fresh** — a new connection, never one
   drawn from the ordinary connection-reuse caches (see
   [Providers and clusters](../providers-and-routing/providers-and-clusters/)),
   because an upgraded connection is consumed whole by the tunnel and can
   never be handed back for a later request to reuse.
4. **If the upstream answers `101 Switching Protocols`**, llm-proxy bridges
   the two connections transparently and bidirectionally: every byte the
   client writes goes to the provider, every byte the provider writes goes to
   the client, until either side closes
   (`websocket_upgrade_tunnel_echoes_bytes_end_to_end` in
   `crates/proxy-http/tests/router_upgrade_e2e.rs`, which proves a real byte
   round-trip, not just the handshake).
5. **If the upstream answers anything else**, that response is passed
   straight through to the client with no tunnel — the request does not hang
   waiting for an upgrade that is never coming
   (`upstream_declining_upgrade_passes_the_response_through` in the same
   file).

## What the tunnel does not do

- **HTTP/1.1 upstreams only.** If the picked host's cluster is configured for
  `http2`, the upgrade is refused before any dial: `502`, body `websocket
  upstream must be http/1.1` (`crates/proxy-http/src/router.rs`'s
  `handle_upgrade`). h2's extended CONNECT (RFC 8441 — WebSocket carried
  inside an h2 stream) is a later increment, not implemented, and so is
  `Upgrade: h2c` on the downstream side.
- **No retries.** A tunnel is a single attempt against a single host. Once a
  `101` has gone out, the client may already be writing tunnel bytes; there
  is no well-defined way to replay a byte stream already in flight, so
  llm-proxy does not try a second host on failure the way an ordinary
  request retries (`handle_upgrade`'s own doc comment).
- **The tunnel is transparent.** Once bridging starts, no HTTP filter reads
  or transforms the bytes flowing through it — no auth re-check, no usage
  metering, nothing. Filters still run on the initial upgrade *request* (the
  one carrying the `Upgrade` header) exactly as they would for any other
  request, since the router is the last filter in the chain; it is only the
  post-`101` payload that bypasses filters. A per-upgrade filter chain
  (Envoy's `UpgradeConfig.filters`) is not implemented: setting one is a load
  error naming the field, not a silent no-op
  (`per_upgrade_filters_are_rejected` in
  `crates/proxy-config/tests/upgrade_configs.rs`).
- **Nothing bounds an idle tunnel.** The route's own `idle_timeout` (see
  [Timeouts and retries](../providers-and-routing/timeouts-and-retries/))
  wraps an ordinary forwarded response body, but the tunnel bridges the two
  raw `Upgraded` streams directly with `tokio::io::copy_bidirectional`
  (`crates/proxy-http/src/codec.rs`'s `bridge_upgrade`), which has no
  timeout of its own and is never wrapped in one. A WebSocket connection
  that both sides simply stop writing to — no close frame, no FIN — stays
  open until one side's OS-level connection eventually drops it, not until
  `idle_timeout` fires. This is the WebSocket-tunnel version of the same gap
  [Timeouts and retries](../providers-and-routing/timeouts-and-retries/)
  documents for a silent ordinary response: an idle-based guard only ever
  bounds a body it is actually wrapping, and the tunnel's raw byte stream is
  never handed to it.

## Failure modes and what they mean

| Response | Body | Cause |
|---|---|---|
| `403` | `upgrade not allowed` | No `Upgrade` header, an unlisted type, or `enabled: false`. |
| `502` | `websocket upstream must be http/1.1` | The picked cluster is `protocol: http2`. |
| `503` | `no cluster` / `unknown cluster` / `no healthy upstream` | Ordinary routing/cluster-health failures, same as a non-upgrade request. |
| `502` | `upgrade handshake failed` | The upstream answered `101` but llm-proxy's own downstream/upstream upgrade handles were unexpectedly missing — an internal-invariant failure, not a client-caused one. |
| `502` | `upstream connection failure` | The upstream connection broke while sending the upgrade request. |

Every one of these responses is a plain-text body, not the JSON error shape
chat/completions error responses use — an upgrade failure happens before any
LLM-specific request handling begins.
