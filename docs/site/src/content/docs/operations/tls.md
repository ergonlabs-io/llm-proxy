---
title: Listener TLS and downstream admission
description: "Terminate TLS on a listener and limit the downstream connections the proxy admits."
summary: How to terminate TLS on the listener in both config front-ends, how
  to encrypt the xDS control-plane channel, and
  the limits that decide whether a client connection is admitted - the TLS
  handshake deadline, the global connection cap, and the request header and
  request timeouts.
lastUpdated: 2026-10-14
related:
  - configuration/configuration-file
  - providers-and-routing/timeouts-and-retries
  - observability/metrics-and-stats
  - operations/running-in-production
---

# Listener TLS and downstream admission

This page covers the client side of the proxy. First it shows how to
terminate TLS. Then it describes the limits that protect the listener from
slow or numerous clients. The provider side is on
[Timeouts and retries](../../providers-and-routing/timeouts-and-retries/).

## Terminate TLS on the listener

### `llmproxy` dialect

Use the object form of `listen`. The shorthand string `host:port` is
plaintext (`schema/llmproxy-v0.schema.json`, `listen`).

```yaml
version: 0
listen:
  address: 0.0.0.0:8443
  tls:
    cert_file: /etc/llmproxy/tls.crt
    key_file: /etc/llmproxy/tls.key
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
routes:
  - model: "*"
    provider: openai
```

`tls.cert_file` is the PEM certificate chain. `tls.key_file` is the PEM
private key. Both are required.

The proxy reads the certificate files once at startup. A renewed
certificate needs a restart. The schema states that nothing watches the
files (`listen.tls` description).

The dialect lowers `tls` to one filter chain with an
`envoy.transport_sockets.tls` transport socket
(`crates/proxy-simple-config/src/lower.rs:2506-2519`).

### Envoy mode

Set `transport_socket` on the filter chain. The type is
`DownstreamTlsContext`.

```yaml
filter_chains:
  - transport_socket:
      name: envoy.transport_sockets.tls
      typed_config:
        '@type': type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
        common_tls_context:
          tls_certificates:
            - certificate_chain: { filename: /etc/llmproxy/tls.crt }
              private_key: { filename: /etc/llmproxy/tls.key }
    filters:
      - name: envoy.filters.network.http_connection_manager
        # typed_config as in your existing listener
```

The IR also holds certificates that arrive over SDS and client-certificate
checks (`DownstreamTlsSpec`, `crates/proxy-config/src/ir.rs:1776-1830`).
Setting both `tls_certificates` and `tls_certificate_sds_secret_configs`
is a load error. Envoy ignores the second field instead
(`internal-docs/envoy-divergences.md` row 5).

## TLS to the xDS control plane

This applies to Envoy mode only. The `llmproxy` dialect has no
`dynamic_resources`.

The control plane can send provider credentials in cluster headers. Thus
the proxy encrypts the ADS channel with the `transport_socket` of the ADS
cluster. The type is `UpstreamTlsContext`, the same as for a provider
cluster.

```yaml
static_resources:
  clusters:
    - name: xds_cluster
      type: STRICT_DNS
      transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          '@type': type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
          sni: xds.example.internal
          common_tls_context:
            validation_context:
              trusted_ca: { filename: /etc/llmproxy/xds-ca.pem }
            # Optional: a client certificate for mTLS.
            tls_certificates:
              - certificate_chain: { filename: /etc/llmproxy/xds-client.crt }
                private_key: { filename: /etc/llmproxy/xds-client.key }
      load_assignment:
        cluster_name: xds_cluster
        endpoints:
          - lb_endpoints:
              - endpoint:
                  address:
                    socket_address: { address: xds.example.internal, port_value: 18000 }
```

The proxy offers ALPN `h2` if `alpn_protocols` is empty. If the handshake
fails, the proxy logs a warning with the cause, for example an unknown
issuer. Then it tries again with backoff.

If you do not set `validation_context`, the proxy accepts all server
certificates. This is the same as Envoy. The proxy logs a warning at
startup.

### Plaintext

Plaintext is permitted only when all endpoints of the ADS cluster are
loopback addresses (`127.0.0.0/8`, `::1`, or `localhost`). For other
addresses, the load fails with this path:
`static_resources.clusters[N].transport_socket`. Envoy does not do this
check (`internal-docs/envoy-divergences.md` row 33).

To permit plaintext to a remote control plane, set this key:

```yaml
node:
  id: proxy-1
  metadata:
    io.llmproxy.ads: { allow_plaintext: true }
```

The proxy then logs a warning at startup that names the target. Other keys
in `io.llmproxy.ads` cause a load error. The key also causes a load error if
the bootstrap has no ADS gRPC service.

## TLS handshake deadline

A client that connects and then sends nothing holds a connection slot.
HTTP timeouts do not help, because they start after the handshake. The
proxy bounds the handshake instead.

| Setting | Behavior |
|---|---|
| `transport_socket_connect_timeout` unset | The handshake deadline is 10 seconds. |
| `transport_socket_connect_timeout: 5s` | The deadline is 5 seconds. |
| `transport_socket_connect_timeout: 0s` | No deadline. The proxy logs a warning when it builds the TLS factories. |

Source: `tls_handshake_deadline`
(`crates/proxy-core/src/listener.rs:197-212`). The warning text is
`transport_socket_connect_timeout is 0s, so the TLS handshake is unbounded
and a stalled client holds a connection slot until it disconnects`
(`crates/proxy-core/src/listener.rs:218-221`).

The default is a deliberate departure from Envoy. Envoy applies no
handshake deadline when the field is unset
(`internal-docs/envoy-divergences.md` row 27).

The field is `FilterChain.transport_socket_connect_timeout`. It is Envoy
mode only (`crates/proxy-config/src/lower.rs:1697-1700`). The dialect has no
field for it. The dialect `listen.tls` listener always gets the 10 second
default, because the dialect does not lower the field.

When the deadline expires, the proxy closes the connection. It logs at debug
level and counts the event in the stat
`listener.<name>.downstream_cx_transport_socket_connect_timeout`. The
`<name>` is the listener name. A completed handshake is not counted. A
connection refused at the connection cap is not counted either
(`crates/proxy-core/src/listener.rs:1165`;
`crates/proxy-observability/src/stats/envoy_render.rs:246-249`). Tests:
`stalled_tls_handshake_is_closed_at_the_deadline_and_frees_the_slot`,
`handshake_deadline_defaults_when_unset_and_zero_disables_it`
(`crates/proxy-core/src/listener.rs`).

## Admission limits

### Global connection cap

The proxy counts open client connections in one process-wide counter.
When the count reaches the limit, the proxy closes the new socket at once
and counts it in `listener.<name>.downstream_global_cx_overflow`. A
rejected socket is not counted in `downstream_cx_total`.
Connections that are already open stay open
(`crates/proxy-core/src/admission.rs:60-70`;
`internal-docs/envoy-divergences.md` row 15). The tests are
`connection_cap_closes_the_overflow_and_frees_the_slot_when_a_connection_ends`
and `a_reloaded_limit_applies_to_the_next_accept`
(`crates/proxy-core/src/listener_admission_tests.rs:327`, `:406`).

A config reload changes the limit for the next accepted connection.

**`llmproxy` dialect.** Set `listen.max_connections`. The default is
`50000`. The value must be at least `1`. The dialect always emits the
`overload_manager` monitor, so the default applies without any setting
(`crates/proxy-simple-config/src/lower.rs:326-334`).

```yaml
listen:
  address: 0.0.0.0:8080
  max_connections: 10000
```

**Envoy mode.** Add the resource monitor to the bootstrap. The proxy
accepts only this monitor type. Envoy mode has no limit by default.

```yaml
overload_manager:
  resource_monitors:
    - name: envoy.resource_monitors.global_downstream_max_connections
      typed_config:
        '@type': type.googleapis.com/envoy.extensions.resource_monitors.downstream_connections.v3.DownstreamConnectionsConfig
        max_active_downstream_connections: 10000
```

To exempt one listener, set `Listener.ignore_global_conn_limit: true`. The
proxy neither checks nor counts the connections of that listener
(`crates/proxy-config/src/ir.rs:92`, `:362-366`;
`listener_that_ignores_the_global_limit_bypasses_a_full_cap`).
The dialect has no field for this setting.

If no limit is set, the proxy accepts the connection and logs one warning
for the whole process: `there is no configured limit to the number of
allowed active downstream connections; configure
max_active_downstream_connections on the
envoy.resource_monitors.global_downstream_max_connections overload resource
monitor`. The proxy logs it when a non-exempt listener accepts a connection
(`crates/proxy-core/src/admission.rs:77-86`).

When `accept()` fails, for example when the process has no free file
descriptors, the accept loop waits 100 ms before it tries again
(`ACCEPT_ERROR_BACKOFF`, `crates/proxy-core/src/listener.rs:972`).

### Request headers timeout

This is the time from the first byte of a request to its complete
headers.

| Front-end | Field | Default |
|---|---|---|
| Dialect | `listen.request_headers_timeout` | `10s` |
| Envoy mode | HCM `request_headers_timeout` | Disabled |

Set `0s` to disable it. The dialect always writes the value into the HCM
(`crates/proxy-simple-config/src/lower.rs:2499-2500`).

Caution: this timeout works on HTTP/1 only.

- On HTTP/1 the timer starts when the codec waits for a request head. A new
  connection that sends nothing is closed after this time. An idle
  keep-alive connection is also closed after this time. Expiry closes the
  connection without a `408` and without a stat count
  (`internal-docs/envoy-divergences.md` row 16).
- HTTP/2 does not enforce the timeout. The proxy logs one warning for the
  process: `request_headers_timeout is not enforced on HTTP/2 connections;
  it applies to HTTP/1 only`
  (`crates/proxy-core/src/listener.rs:966`; row 17).

Test: `request_headers_timeout_closes_a_stalled_http1_connection_but_not_a_long_response`
(`crates/proxy-core/src/listener_admission_tests.rs:448`).

### Request timeout

This is the time allowed to receive the whole request, headers and body.

| Front-end | Field | Default |
|---|---|---|
| Dialect | `listen.request_timeout` | `60s` |
| Envoy mode | HCM `request_timeout` | Disabled |

Set `0s` to disable it. If the timeout expires, the proxy answers `408`
with response-code details `request_overall_timeout` and closes the
HTTP/1 connection (`crates/proxy-http/src/filter_manager.rs:1421`;
`request_timeout_answers_408_on_a_stalled_body_and_closes_the_connection`,
`crates/proxy-core/src/listener_admission_tests.rs:515`).

The deadline starts when the stream handler receives the parsed request
head. It stops when the request body is complete. It does not bound the
response, so a long generation or stream is not cut
(`request_timeout_does_not_cut_a_response_that_streams_past_the_deadline`;
row 18). The proxy does not count `downstream_rq_timeout` for this
expiry.

Raise `listen.request_timeout` if clients upload large bodies slowly.

## Dialect defaults in one table

Source: `schema/llmproxy-v0.schema.json` (`Listener`) and
`crates/proxy-simple-config/src/model.rs:182-184`.

| Field | Type | Default | What it does |
|---|---|---|---|
| `listen.address` | `host:port` | `0.0.0.0:8080` | Where the proxy accepts clients. Required in the object form. |
| `listen.tls.cert_file` | string | none | PEM certificate chain. Required if `tls` is set. |
| `listen.tls.key_file` | string | none | PEM private key. Required if `tls` is set. |
| `listen.max_connections` | integer, at least 1 | `50000` | Global cap on open client connections. |
| `listen.request_headers_timeout` | duration | `10s` | Time to receive complete headers. `0s` disables. |
| `listen.request_timeout` | duration | `60s` | Time to receive the whole request. `0s` disables. |
| `listen.max_request_body_bytes` | integer, at least 1 | `1048576` | Largest request body. A larger body gets `413`. |

The shorthand string form of `listen` gets the same three admission
defaults. Envoy mode keeps Envoy's defaults, which are all disabled
(`crates/proxy-simple-config/src/lower.rs:2534-2559`).

## Not verified

I did not run the proxy to see the log lines or the stats. The text and
names above come from the code. The behavior that Envoy shows for rows 15
to 18 of the divergence list was not compared with a running Envoy.
