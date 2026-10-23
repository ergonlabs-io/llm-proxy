---
title: Listener TLS and downstream admission
description: "Terminate TLS on the listener, verify provider certificates, renew certificates, and limit the client connections the proxy admits."
summary: How the proxy handles TLS in both directions and which limits decide
  whether a client connection is admitted. It terminates client TLS with one
  certificate, verifies the certificate of each https provider, and serves a
  renewed certificate after a SIGHUP reload. The admission limits are the TLS
  handshake deadline, the global connection cap, and the request header and
  request timeouts.
lastUpdated: 2026-10-21
related:
  - configuration/configuration-file
  - providers-and-routing/timeouts-and-retries
  - observability/metrics-and-stats
  - operations/running-in-production
  - operations/config-reload
  - operations/deployment
---

The proxy handles TLS on two sides. The downstream side faces your clients.
The upstream side faces your providers. The two sides are set in different
places and have different defaults. Read both sections before you go to
production.

## At a glance

- **Client-side TLS:** off. Set `listen.tls` with `cert_file` and `key_file`
  to turn it on. The shorthand `listen: host:port` is plaintext.
- **Admin TLS:** off. Set `admin.tls` with `cert_file` and `key_file` to turn
  it on. See [TLS on the admin port](/docs/llm-proxy/administration/admin-api/#tls-on-the-admin-port).
- **Provider certificate check:** on for every `https://` provider. No
  setting turns it off.
- **Failure mode:** a certificate or key file that cannot be read at start
  stops the process. A file that cannot be read at a reload makes the
  listener reset new TLS connections until a later reload succeeds.
- **Admission limits:** have defaults and need no setting to start.

## Terminate TLS on the listener

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

Check the file. Then test the handshake:

```bash
llm-proxy --config llmproxy.yaml --mode validate
llm-proxy --config llmproxy.yaml > /tmp/llm-proxy.log 2>&1 &
curl --max-time 5 --cacert /etc/llmproxy/ca.crt https://localhost:8443/v1/models
kill %1
```

`listen.tls` takes one certificate and nothing else:

- The listener does not ask clients for a certificate.
- The listener offers ALPN `h2` and then `http/1.1`. A client that offers
  h2 gets HTTP/2. You cannot change the list.
- The listener offers TLS 1.2 and TLS 1.3.
- You cannot serve different certificates by SNI.

Set the key file mode to `0600`. Give the proxy user read access only.

If the proxy cannot read or parse a file at start, it does not start. The
error names the listener.

## Rotate the certificate

Nothing watches the certificate files. The proxy reads `cert_file` and
`key_file` at start and after each `SIGHUP` reload.

> **Warning:** A reload does not check the files. If a file cannot be read,
> the listener resets every new TLS connection until a later reload
> succeeds. Do step 2 before you send `SIGHUP`.

1. Write the new certificate and key to the paths in `listen.tls`. Replace
   each file atomically: write a temporary file, then `mv` it.
2. Check that the pair matches. The two commands must print the same value:
   `openssl x509 -noout -pubkey -in tls.crt | openssl md5` and
   `openssl pkey -pubout -in tls.key | openssl md5`.
3. Send `SIGHUP`: `kill -HUP <pid>`. A restart also works.
4. Check the served certificate:
   `openssl s_client -connect localhost:8443 -servername localhost </dev/null 2>/dev/null | openssl x509 -noout -enddate`.

After the reload, the next accepted connection gets the new certificate.
Existing connections keep the old one. `admin.tls` rotates the same way. See
[Reload configuration](/docs/llm-proxy/operations/config-reload/#what-a-reload-applies).

## Provider TLS

A provider whose `base_url` starts with `https://` gets verified TLS with no
setting. For each connection the proxy:

1. Sends the host name of `base_url` as SNI.
2. Verifies the certificate chain against the platform trust store, or
   against `ca_file` if you set it.
3. Requires a DNS subject alternative name that exactly equals the host of
   `base_url`.

Step 3 matters. Chain trust alone does not prove the identity of the host.
The name check rejects a valid certificate for a different domain.

| Field | Type | Default | Description |
|---|---|---|---|
| `providers.<name>.ca_file` | string (path) | none | PEM CA bundle that replaces the platform trust store for this provider. Use it for a self-hosted provider with a private CA. |
| `providers.<name>.connect_timeout` | duration | `5s` | Time limit to set up the TCP and TLS connection. |
| `providers.<name>.protocol` | `http1` or `http2` | `http1` | The proxy offers ALPN `http/1.1` for `http1` and `h2` for `http2`. It offers one protocol only. |

Rules to know:

- **`ca_file` on an `http://` provider has no effect.** The load warning is
  `ca_file is ignored for plaintext (http://) providers`.
- **The platform trust store must exist on the host.** In a container,
  install CA certificates. If the proxy finds no native root certificates,
  the provider fails to build.
- **`protocol: http2` has no downgrade.** A provider that cannot speak
  HTTP/2 fails the handshake.
- **The proxy connects to providers with TLS 1.2.** The dialect has no field
  to change this. A provider that accepts only TLS 1.3 fails the handshake.
- **Plaintext is allowed.** An `http://` provider sends the API key in clear
  text. Use it only on a loopback or private network, for example a local
  Ollama.

## TLS handshake deadline

A client that connects and then sends nothing holds a connection slot.
HTTP timeouts do not help, because they start after the handshake. The
proxy bounds the handshake instead.

The deadline for `listen.tls` is 10 seconds. The dialect has no field to
change it. When the deadline expires, the proxy closes the connection. It
logs at debug level and counts the event in the stat
`listener.<name>.downstream_cx_transport_socket_connect_timeout`. The
`<name>` is the listener name. A completed handshake is not counted. A
connection refused at the connection cap is not counted either.

A handshake failure on the client side is logged at `debug` only, as
`TLS handshake failed; dropping connection`. Start the proxy with
`-l debug` to diagnose a client.

## Admission limits

### Global connection cap

The proxy counts open client connections in one process-wide counter.
When the count reaches the limit, the proxy closes the new socket at once
and counts it in `listener.<name>.downstream_global_cx_overflow`. A
rejected socket is not counted in `downstream_cx_total`. Connections that
are already open stay open.

Set `listen.max_connections`. The default is `50000`. The value must be at
least `1`. A config reload changes the limit for the next accepted
connection.

```yaml
listen:
  address: 0.0.0.0:8080
  max_connections: 10000
```

When `accept()` fails, for example when the process has no free file
descriptors, the accept loop waits 100 ms before it tries again.

### Request headers timeout

This is the time from the first byte of a request to its complete headers.
Set `listen.request_headers_timeout`. The default is `10s`. Set `0s` to
disable it.

> **Caution:** This timeout works on HTTP/1 only.

- On HTTP/1 the timer starts when the codec waits for a request head. A new
  connection that sends nothing is closed after this time. An idle
  keep-alive connection is also closed after this time. Expiry closes the
  connection without a `408` and without a stat count.
- HTTP/2 does not enforce the timeout. The proxy logs one warning for the
  process: `request_headers_timeout is not enforced on HTTP/2 connections;
  it applies to HTTP/1 only`.

### Request timeout

This is the time allowed to receive the whole request, headers and body.
Set `listen.request_timeout`. The default is `60s`. Set `0s` to disable it.
If the timeout expires, the proxy answers `408` with response-code details
`request_overall_timeout` and closes the HTTP/1 connection.

The deadline starts when the stream handler receives the parsed request
head. It stops when the request body is complete. It does not bound the
response, so a long generation or stream is not cut. The proxy does not
count `downstream_rq_timeout` for this expiry.

Raise `listen.request_timeout` if clients upload large bodies slowly.

## Listener fields

Source: `schema/llmproxy-v0.schema.json` (`Listener`).

| Field | Type | Default | Description |
|---|---|---|---|
| `listen.address` | `host:port` | `0.0.0.0:8080` | Where the proxy accepts clients. Required in the object form. |
| `listen.tls.cert_file` | string | none | PEM certificate chain. Required if `tls` is set. |
| `listen.tls.key_file` | string | none | PEM private key. Required if `tls` is set. |
| `listen.max_connections` | integer, at least 1 | `50000` | Global cap on open client connections. |
| `listen.request_headers_timeout` | duration | `10s` | Time to receive complete headers. `0s` disables. HTTP/1 only. |
| `listen.request_timeout` | duration | `60s` | Time to receive the whole request. `0s` disables. |
| `listen.stream_idle_timeout` | duration | `10m` | Time a request may go with no activity before the proxy cuts it. `0s` disables. |
| `listen.max_stream_duration` | duration | none | Longest life of a request. `0s` also means no limit. |
| `listen.max_request_body_bytes` | integer, at least 1 | `1048576` | Largest request body. A larger body gets `413`. |
| `listen.max_request_headers_kb` | integer, 1 to 8192 | `60` | Largest request head, in KiB. |
| `listen.max_request_headers_count` | integer, at least 1 | `100` | Most headers a request may carry. |
| `listen.trusted_hops` | integer | `0` | Number of proxies in front of llm-proxy that append to `x-forwarded-for`. |

The shorthand string form of `listen` gets the same admission defaults.

## Limitations

- **One certificate.** There is no SNI-based selection and no second key
  type.
- **No client certificate check.** The listener does not ask clients for a
  certificate. Use [virtual keys](/docs/llm-proxy/authentication/virtual-keys/).
- **No file watching.** A renewed certificate needs a `SIGHUP` reload.
- **No TLS 1.0 or 1.1.** The TLS library does not offer them.
- **No ACME or automatic certificate issue.** Use cert-manager, certbot, or a
  load balancer that terminates TLS in front of the proxy.
- **No TLS version setting, no SAN matcher, and no provider client
  certificate.**
- **No handshake deadline setting.** The deadline is 10 seconds.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

This section is for maintainers.

- Dialect lowering: `crates/proxy-simple-config/src/lower.rs` (listener TLS
  chain, provider TLS with exact SAN match, HCM timeouts). Dialect defaults:
  `crates/proxy-simple-config/src/model.rs`.
- Provider TLS version: `convert_tls_version` in
  `crates/proxy-config/src/lower.rs` (upstream maximum is TLS 1.2).
- A TLS build failure at start is fatal: `initial_bind_propagates_a_tls_build_failure_as_fatal`
  in `crates/proxy-core/src/listener.rs`.
- Handshake deadline: `tls_handshake_deadline` in
  `crates/proxy-core/src/listener.rs`. Tests in the same file:
  `stalled_tls_handshake_is_closed_at_the_deadline_and_frees_the_slot` and
  `handshake_deadline_defaults_when_unset_and_zero_disables_it`.
- Connection cap: `crates/proxy-core/src/admission.rs`. Tests in
  `crates/proxy-core/src/listener_admission_tests.rs`:
  `connection_cap_closes_the_overflow_and_frees_the_slot_when_a_connection_ends`,
  `a_reloaded_limit_applies_to_the_next_accept`,
  `request_headers_timeout_closes_a_stalled_http1_connection_but_not_a_long_response`,
  `request_timeout_answers_408_on_a_stalled_body_and_closes_the_connection`, and
  `request_timeout_does_not_cut_a_response_that_streams_past_the_deadline`.
- Accept error backoff: `ACCEPT_ERROR_BACKOFF` in
  `crates/proxy-core/src/listener.rs`. The `408` for the request timeout:
  `crates/proxy-http/src/filter_manager.rs`.
