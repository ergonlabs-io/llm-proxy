---
title: WebSocket and other HTTP upgrades
summary: How the HTTP connection manager tunnels an HTTP/1.1 `Upgrade`
  request or an HTTP/2 extended CONNECT request (WebSocket included) to a
  provider, what gates it, and the real limits of today's transparent tunnel
  — bootstrap configuration only, not yet reachable from the plain
  configuration format.
last_updated: 2026-10-13
related:
  - ../providers-and-routing/providers-and-clusters/
  - ../providers-and-routing/timeouts-and-retries/
  - ../configuration/configuration-file/
---

# WebSocket and other HTTP upgrades

llm-proxy can tunnel an HTTP/1.1 `Upgrade` request or an HTTP/2 extended
CONNECT request (RFC 8441) — WebSocket is the practical case, since several
providers' realtime APIs use it — straight through to a provider, byte for
byte, once the upstream accepts it. Both sides of one tunnel must use the same
protocol: h1 to h1, or h2 to h2. This page
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
   [Providers and clusters](../../providers-and-routing/providers-and-clusters/)),
   because an upgraded connection is consumed whole by the tunnel and can
   never be handed back for a later request to reuse.
4. **The protocol of the client and the protocol of the provider must
   match.** An h1 client with an `Upgrade` header can reach only a cluster
   with `protocol: http1`. An h2 client with extended CONNECT can reach only a
   cluster with `protocol: http2`. Any other pair is refused before any dial:
   **`502`**, body `cross-protocol websocket bridging (h1<->h2) is not
   supported` (`h2_downstream_to_h1_upstream_is_rejected_as_cross_protocol` and
   `h1_downstream_to_h2_upstream_is_rejected_as_cross_protocol` in
   `crates/proxy-http/tests/router_h2_upgrade_e2e.rs`). For h2, the proxy turns
   the `:protocol` pseudo-header into an `Upgrade` header, so the same
   `upgrade_configs` gate in step 1 applies.
5. **If the upstream accepts**, llm-proxy bridges the two connections
   transparently and bidirectionally. The accept status is `101 Switching
   Protocols` for h1 and exactly `200` for h2. Every byte the client writes
   goes to the provider, every byte the provider writes goes to the client,
   until either side closes
   (`websocket_upgrade_tunnel_echoes_bytes_end_to_end` in
   `crates/proxy-http/tests/router_upgrade_e2e.rs` for h1, and
   `h2_websocket_tunnel_echoes_bytes_end_to_end` in
   `router_h2_upgrade_e2e.rs` for h2. Both prove a real byte round-trip, not
   just the handshake).
6. **If the upstream answers anything else**, that response is passed
   straight through to the client with no tunnel — the request does not hang
   waiting for an upgrade that is never coming
   (`upstream_declining_upgrade_passes_the_response_through` in the same
   file).

## What the tunnel does not do

- **No protocol bridging.** The client side and the provider side must use the
  same protocol, as step 4 above describes. An h1 client cannot reach an h2
  provider, and an h2 client cannot reach an h1 provider. The proxy would have
  to build the WebSocket handshake itself, and it does not. Setting
  `protocol: http2` on a provider does not stop h2 tunnels: it stops h1
  clients from tunneling to that provider.
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
- **The idle limit is fixed at 300 seconds.** The tunnel closes when no byte
  moves in either direction for 300 seconds. Any byte in either direction, such
  as a ping or pong frame, restarts the timer. The route's own `idle_timeout`
  (see [Timeouts and retries](../../providers-and-routing/timeouts-and-retries/))
  does not apply to a tunnel, and no field changes the 300 seconds
  (`WEBSOCKET_TUNNEL_IDLE_TIMEOUT` and `pump_with_idle_timeout` in
  `crates/proxy-http/src/codec.rs`; the tests are `idle_tunnel_is_torn_down_after_idle_window`
  and `activity_resets_idle_timer` in the same file). A clean close from one side
  closes the other side's write half and ends the tunnel when both sides are done.

## Hop-by-hop headers on an upgrade

The proxy removes the headers that describe one connection (`connection`,
`transfer-encoding`, `keep-alive`, `proxy-connection`, and `te` unless its
value is `trailers`) from every request and every response, as
[Providers and clusters](../../providers-and-routing/providers-and-clusters/#hop-by-hop-headers)
describes. An upgrade keeps one extra header: `Upgrade`, because it names the
protocol and the router reads it.

For h1, the proxy adds `Connection: upgrade` back on both hops. It sends
`Connection: upgrade` to the provider with the upgrade request, and it sends
`Connection: upgrade` to the client with the `101` response. Extra tokens in the
client's `Connection` header, such as `keep-alive`, do not reach the provider.
An h2 tunnel has no `Connection` header: the proxy uses the `:protocol`
pseudo-header on each hop. Proof: `sanitize_upgrade_hop_by_hop` in
`crates/proxy-http/src/headers.rs`, `send_upstream_http1_upgrade` and
`serve_one` in `crates/proxy-http/src/codec.rs`, and
`websocket_upgrade_tunnel_echoes_bytes_end_to_end`, which sends
`Connection: keep-alive, Upgrade` and checks both hops.

## Draining

A live tunnel keeps the connection open for drain. When a drain starts, the
proxy does not cut the tunnel, and the drain does not finish while a tunnel
still carries bytes. The tunnel ends when a peer closes it, when the 300 second
idle limit passes, or when the drain deadline (`--drain-time-s`, default 600)
ends the process. See
[Draining and shutdown](../../operations/draining-and-shutdown/). Proof:
`an_upgraded_tunnel_survives_drain_start_and_holds_drain_open_until_it_closes` in
`crates/proxy-core/src/listener_drain_tests.rs`.

## Load balancing

A tunnel counts as one active request on its host for as long as it is open.
`LEAST_REQUEST` reads that count. See
[Load balancing](../../providers-and-routing/load-balancing/#what-least_request-counts).

## Failure modes and what they mean

| Response | Body | Cause |
|---|---|---|
| `403` | `upgrade not allowed` | No `Upgrade` header, an unlisted type, or `enabled: false`. |
| `502` | `cross-protocol websocket bridging (h1<->h2) is not supported` | The client and the picked cluster use different protocols (h1 client with an `http2` cluster, or h2 client with an `http1` cluster). |
| `503` | `no cluster` / `unknown cluster` / `cluster not warmed` / `no healthy upstream` | Ordinary routing/cluster-health failures, same as a non-upgrade request. |
| `503` | `upstream overloaded` / `upstream connect failure` / `upstream TLS handshake failure` / `upstream reset` | The dial of the fresh connection failed. These bodies are in `handle_upgrade` in `crates/proxy-http/src/router.rs`. |
| `503` | `upstream connection failure` | The send of the upgrade request failed before response headers, and the cause was a connection close or an upstream reset. The response flag is `UC` or `UR`. |
| `502` | `upstream connection failure` | The send of the upgrade request failed because the upstream broke the protocol (hyper could not parse the response). The response flag is `UPE`. |
| `502` | `upgrade handshake failed` | The upstream accepted, but llm-proxy's own downstream/upstream upgrade handles were unexpectedly missing — an internal-invariant failure, not a client-caused one. |

The `503` and `502` rows for `upstream connection failure` come from
`codec_error_reply` in `crates/proxy-http/src/router.rs`. The ordinary
request path uses the same helper, and `crates/proxy-http/tests/response_flags.rs`
pins its results there: `502 UPE`, `503 UC`, and `503 UR`. I found no test that
drives these three results through an upgrade request.

Every one of these responses is a plain-text body, not the JSON error shape
chat/completions error responses use — an upgrade failure happens before any
LLM-specific request handling begins.
