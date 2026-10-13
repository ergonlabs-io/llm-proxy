---
title: External authorization
summary: How the `envoy.filters.http.ext_authz` filter asks a gRPC service
  to allow or deny each request, what the filter does when that service
  fails, and which fields the strict-mode subset accepts. Envoy mode and
  bootstrap only.
last_updated: 2026-10-13
related:
  - ../authentication/virtual-keys/
  - ../configuration/configuration-file/
  - ../observability/access-logs/
  - ../observability/metrics-and-stats/
---

# External authorization

The `envoy.filters.http.ext_authz` filter sends the headers of each request
to an authorization service. The service answers allow or deny. The proxy
forwards an allowed request and answers a denied request itself.

This page describes a limited subset of Envoy's filter. The subset is
Envoy mode only. The `llmproxy` dialect has no field for it
(`schema/llmproxy-v0.schema.json` has no `ext_authz` property).

## What the subset does

- The filter uses gRPC. It does not support the HTTP service variant.
  `convert_ext_authz` requires `grpc_service.envoy_grpc` and rejects the
  config with `gRPC service is required` otherwise
  (`crates/proxy-config/src/lower.rs:1163-1168`).
- The filter checks headers only. The proxy does not send the request body
  to the service (`crates/proxy-filters/src/ext_authz.rs:1`).
- The filter must be first in `http_filters`. Any other position is a load
  error (`crates/proxy-config/src/lower.rs:2022-2027`).
- The proxy does not import an identity from the decision. The decision
  does not set the tenant or the key that `llmproxy.auth` sets
  (`crates/proxy-filters/src/ext_authz.rs:1`).

## Bootstrap only

Set `ext_authz` in the bootstrap file. A listener delivered over LDS that
contains `ext_authz` is rejected with the reason `ext_authz is
bootstrap-only until authorization cluster warming is implemented`
(`crates/proxy-config/src/lower.rs:284-285`).

The authorization cluster must also be a bootstrap cluster. It must meet
all of these rules (`ext_authz_endpoint`,
`crates/proxy-config/src/lower.rs:1273-1292`):

- Type `STATIC`, with exactly one endpoint.
- The endpoint address is an IP address.
- HTTP/2 upstream, and no transport socket (no TLS).
- No health check, no outlier detection, and no circuit-breaker settings.
- Default `per_connection_buffer_limit_bytes`.

A cluster that breaks a rule fails the load with the message
`authorization requires one STATIC plaintext HTTP/2 endpoint without
health, outlier or provider behavior`. A name that matches no cluster fails
with `authorization cluster is not defined`
(`crates/proxy-config/src/lower.rs:1313-1322`).

## Example

`examples/ext-authz.yaml` is the complete file. The filter section is:

```yaml
http_filters:
  - name: envoy.filters.http.ext_authz
    typed_config:
      '@type': type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
      grpc_service:
        envoy_grpc: { cluster_name: authorization }
        timeout: 0.2s
      transport_api_version: V3
      encode_raw_headers: true
      validate_mutations: true
      enable_dynamic_metadata_ingestion: false
      charge_cluster_response_stats: false
  - name: envoy.filters.http.router
    typed_config:
      '@type': type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

The `authorization` cluster in the same file is a `STATIC` cluster on
`127.0.0.1:9001` with `explicit_http_config.http2_protocol_options: {}`.

## Fields the subset accepts

Strict mode rejects every other field with its dotted path. The accepted
list is in `crates/proxy-config/src/lower.rs:732-739`.

| Field | Default | Rule |
|---|---|---|
| `grpc_service.envoy_grpc.cluster_name` | none | Required. Must be non-empty. |
| `grpc_service.timeout` | `200ms` | Whole milliseconds, from `1ms` to `30s`. |
| `transport_api_version` | none | Must be `V3`. |
| `encode_raw_headers` | `false` in the proto | Must be `true`. |
| `validate_mutations` | `false` in the proto | Must be `true`. |
| `enable_dynamic_metadata_ingestion` | unset | Must be set to `false`. |
| `charge_cluster_response_stats` | unset | Must be set to `false`. |
| `failure_mode_allow` | `false` | If `true`, the filter admits a request when the check fails. |
| `failure_mode_allow_header_add` | `false` | If `true`, an admitted request gets `x-envoy-auth-failure-mode-allowed: true`. |
| `status_on_error.code` | `403` | Range `200` to `511`. |
| `clear_route_cache` | `false` | If `true`, the proxy clears the route cache after an allow that changes request headers (`ext_authz.rs:333-335`). |
| `stat_prefix` | empty | At most 64 bytes of letters, digits, `_` and `-`. |

Defaults and rules are from `convert_ext_authz`
(`crates/proxy-config/src/lower.rs:1120-1231`).

The accepted per-route fields are `disabled` and
`check_settings.context_extensions`. Set them in `typed_per_filter_config`
(`crates/proxy-config/src/lower.rs:738-739`). Set `disabled: true` to skip the
check on a route. Otherwise set `check_settings` with at most 64 context
extensions and at most 16 KiB of keys and values in total
(`crates/proxy-config/src/lower.rs:1234-1268`). A skipped check counts
as `disabled`. Disabling the check on a route is an explicit exemption.

## What the filter does with each answer

| Answer from the service | Client sees | Counter outcome | Response-code details |
|---|---|---|---|
| Allow | The request continues. | `ok` | none |
| Deny | The status, headers and body from the service. | `denied` | `ext_authz_denied` |
| Deny with an invalid status, header or body | `500` | `invalid` | `ext_authz_invalid` |
| Allow with an invalid header mutation | `500` | `invalid` | `ext_authz_invalid` |
| Check error (timeout, transport, saturation), fail closed | `status_on_error` (`403` by default) | `error` | `ext_authz_error` |
| Check error, `failure_mode_allow: true` | The request continues. | `error` and `failure_mode_allowed` | none |
| Check request over 64 KiB | `431` | `error` | `ext_authz_request_too_large` |

Source: `crates/proxy-filters/src/ext_authz.rs:339-440`. The `431` rule
is in `internal-docs/envoy-divergences.md` row 6 and the test
`ext_authz_oversized_headers_are_denied_when_fail_open`
(`testing/diffrig/tests/ext_authz_e2e.rs:923`).

The filter sets the response flag `UAEX` on a denial and on a fail-closed
error (`crates/proxy-observability/src/flags.rs:140`, `:195`). An admitted
failure does not set `UAEX`.

## Failure mode

The filter fails closed by default. If the service is down, slow, or
returns a transport error, the client gets `status_on_error` (`403`) and
the request does not reach the provider.

A call that runs past `grpc_service.timeout` counts as a timeout, also when
the service answers `CANCELLED` at the same moment
(`crates/proxy-xds/src/authorization.rs`, commit 55e20d1). A client that
sends a check request over 64 KiB always gets `431`. This rule does not
depend on `failure_mode_allow`, so a client cannot skip the check by
padding headers.

The proxy limits each worker to 256 concurrent checks. The next check
fails with a saturation error. That error follows `failure_mode_allow`
like any other error (`internal-docs/envoy-divergences.md` row 7).

### Caution: failure_mode_allow turns authorization off during an outage

Set `failure_mode_allow: true` only if you accept that requests pass
without a check while the service is unavailable. The proxy makes this
visible in two ways:

- The proxy logs one `warn` line for the whole process: `external
  authorization failed; explicit failure_mode_allow admitted the request;
  repeats suppressed`. A config reload does not repeat the line. The warn
  flag is in process-wide state keyed by stat scope
  (`crates/proxy-filters/src/ext_authz.rs:403-405`;
  `crates/proxy-core/src/listener.rs:1495-1520`). The test is
  `ext_authz_fail_open_warning_is_not_repeated_after_reload`
  (`testing/diffrig/tests/ext_authz_e2e.rs:792`).
- The `failure_mode_allowed` counter increases for each admitted request.
  Alert on this counter.

## Counter

The filter records the counter `ext_authz` with the attributes `scope` and
`outcome` (`crates/proxy-filters/src/ext_authz.rs:17-31`). The scope is
`<HCM stat_prefix>.ext_authz`, or `<HCM stat_prefix>.ext_authz.<stat_prefix>`
if you set the filter `stat_prefix`
(`crates/proxy-core/src/listener.rs:1495-1499`). The proxy keeps at most
1024 scopes. More scopes share the scope `overflow`.

| Outcome | Meaning |
|---|---|
| `ok` | The service allowed the request. |
| `denied` | The service denied the request. |
| `error` | The check failed (timeout, transport, saturation, or over 64 KiB). |
| `invalid` | The answer had an invalid status, header, body or mutation. |
| `disabled` | A route set `disabled: true`. |
| `failure_mode_allowed` | A failed check was admitted by `failure_mode_allow`. |
| `ignored_dynamic_metadata` | The service sent dynamic metadata and the proxy ignored it. |

## Not verified

I did not run the proxy against an authorization service. The log text,
counter names and status codes above come from the code and from test names.
I did not read the bodies of the end-to-end tests.
