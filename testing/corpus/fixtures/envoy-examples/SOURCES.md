# Sources

All fixtures in this directory are real Envoy v3 static bootstrap configs
fetched verbatim (byte-for-byte, no edits) from the `envoyproxy/envoy` repo at
the pinned tag `v1.38.0`. They are not edited to make them pass the loader —
a rejection is data, not a bug to work around.

Pinned ref: `v1.38.0`
Base URL: `https://raw.githubusercontent.com/envoyproxy/envoy/v1.38.0/configs/`

| fixture | source path |
|---|---|
| `admin-interface.yaml` | `configs/admin-interface.yaml` |
| `ads.yaml` | `configs/ads.yaml` |
| `csrf-filter.yaml` | `configs/csrf.yaml` |
| `demo.yaml` | `configs/envoy-demo.yaml` |
| `deprecated-fields.yaml` | `configs/using_deprecated_config.yaml` |
| `envoyproxy-io-proxy.yaml` | `configs/envoyproxy_io_proxy.yaml` |
| `freebind.yaml` | `configs/freebind/freebind.yaml` |
| `front-proxy-edge.yaml` | `configs/front-proxy_envoy.yaml` |
| `front-proxy-service.yaml` | `configs/front-proxy_service-envoy.yaml` |
| `grpc-bridge.yaml` | `configs/grpc-bridge_server_envoy-proxy.yaml` |
| `http3-downstream.yaml` | `configs/envoyproxy_io_proxy_http3_downstream.yaml` |
| `http3-upstream-proxy.yaml` | `configs/google_com_http3_upstream_proxy.yaml` |
| `jwt-authn.yaml` | `configs/jwt_authn.yaml` |
| `original-dst-cluster.yaml` | `configs/original-dst-cluster/proxy_config.yaml` |
| `proxy-protocol.yaml` | `configs/proxy_protocol.yaml` |
| `tap-config.yaml` | `configs/envoy-tap-config.yaml` |
| `udp-listener.yaml` | `configs/udp.yaml` |

Fetched with, e.g.:

```
curl -fsSL https://raw.githubusercontent.com/envoyproxy/envoy/v1.38.0/configs/csrf.yaml
```

Note: the `envoyproxy/envoy` repo no longer ships an `examples/` tree at this
tag (examples moved to a separate `envoyproxy/examples` repo in recent
releases); this corpus only draws from `configs/`, which still contains
full static bootstraps covering a good spread of listener/cluster/filter
features (HTTP/3, gRPC bridging, JWT auth, PROXY protocol, tap, ADS,
deprecated-field usage, freebind, original-dst clustering, etc.).
