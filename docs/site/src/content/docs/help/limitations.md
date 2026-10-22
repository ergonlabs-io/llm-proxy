---
title: Limitations
description: "What llm-proxy does not do with a --config file, grouped by area, with the behavior you get instead and a workaround where one exists."
summary: One list of what is not built, partly built, or deliberately
  different, and a list of the capabilities that only an Envoy bootstrap
  reaches. Each entry says what the proxy does today.
lastUpdated: 2026-10-21
related:
  - getting-started/introduction
  - help/faq
  - help/troubleshooting
  - configuration/strict-config-mode
---

This page lists what the proxy does not do when you start it with `--config`.
The project is before 1.0, and the config surface can still change. The
entries describe the current code in the repository. The proxy is strict by design. A field that parses
but does nothing produces a load warning, never silence.

Use the status words this way:

- **Not built**: no code exists. The request or the config fails, or the
  request passes through.
- **Partly built**: some of it works. The entry says which part.
- **By design**: the proxy does this on purpose.
- **Envoy mode only**: code exists, and only an Envoy bootstrap can reach it.
  See [Available only in Envoy mode](#available-only-in-envoy-mode).

## API compatibility and translation

| Gap | Status | What happens today | Workaround |
|---|---|---|---|
| Translation between dialects | Not built | A fallback chain that mixes dialects fails at load. The error ends with `cross-dialect fallback needs request/response translation, which is not supported yet`. A `models` entry gives a similar error. | Keep each chain in one dialect. Use two models and let the client choose. |
| Model rewrite in `routes[].provider` | Not built | `provider/model` on a route, or in `fallbacks`, loads with a warning. The proxy forwards the original model name. | Use a `models` entry. The `model` field of `models.<name>.providers[]` sets the upstream model for each provider. |
| Provider-native `/v1/models` | Not built | The proxy answers `GET /v1/models` from its own catalog. It never asks a provider. | List models in `routes` and `models`. |
| Metering of batches, files, and image variations | Not built | The proxy forwards these paths. Where a spend budget or token limit applies, it refuses them with `403` and the text `this endpoint cannot be metered, so it is refused under a spend budget or token limit`. | Send these requests to a caller that has no budget or limit. |
| Browser clients | Not built | The `--config` file has no CORS setting. Browser calls to the proxy fail the CORS check. | Call the proxy from a server. |
| Response or semantic cache | Not built | No cache exists. Every request reaches a provider. | Cache in the client, or in a layer in front of the proxy. |
| Large request bodies | By design | The proxy buffers the whole request body. A body over `listen.max_request_body_bytes` (default `1048576`) gets `413`. The same value is the largest body that the proxy can retry or fail over. | Raise `listen.max_request_body_bytes`. Each request in flight can hold that many bytes. |
| Other WebSocket paths | Partly built | `realtime.enabled: true` meters a session on a path that ends in `/realtime`. A WebSocket on another path is tunnelled but not metered. It is refused where a spend budget or token limit applies. | Use the `/realtime` path. |
| Image and audio in token limits | Partly built | Image and audio endpoints count toward spend budgets but not toward token limits. | Use a spend budget for image and audio traffic. |

## Routing and reliability

| Gap | Status | What happens today | Workaround |
|---|---|---|---|
| Cost-based routing | Not built | Failover is ordered. A `models` entry with `weight` splits first picks by weight. With `selection: latency`, the proxy also scales the weights by measured latency. It never uses cost. | Order providers or set weights yourself. See [Load balancing](/docs/llm-proxy/providers-and-routing/load-balancing/). |
| Nested fallback chains | Not built | A chain has one level. | Put all fallbacks in one list. |
| Replay after a stream starts | By design | The proxy never replays a request after bytes reach the client. | Retry in the client. |
| Retry rules | Partly built | `routes[].retries.attempts` sets the count, from 0 to 5. The trigger set is fixed: connection failure, refused stream, reset before any response byte, and the statuses `429`, `500`, `502`, `503`. | None in the `--config` file. See [Timeouts and retries](/docs/llm-proxy/providers-and-routing/timeouts-and-retries/). |
| Active health checks | Not built | The file has no field for them. `outlier_detection` ejects a provider after consecutive failures, which is passive. A provider outage does not turn `/ready` red. | Watch the metrics and the access-log response flags. |
| Several endpoints for one provider | Not built | A provider has exactly one endpoint: the host in `base_url`. | Put a load balancer in front of the endpoints. |
| HTTP/2 to a provider that does not support it | By design | `protocol: http2` selects HTTP/2 for that provider. Many local plaintext servers do not support it. | Leave `protocol` at the default `http1` for those servers. |
| Hot restart | Not built | `--base-id` is parsed and ignored. A new binary needs a new process. | Replace replicas one at a time. See [Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/). |

## Access control

| Gap | Status | What happens today | Workaround |
|---|---|---|---|
| Per-provider authorization | Not built | A tenant that may use a model may use every provider that serves it. | Control the provider with `routes` and `models`. |
| Per-user budget | Not built | A budget exists for a key and for a tenant. No budget exists for a user. | Issue one key for each user, and set a key budget. |
| Virtual key in `x-api-key` | Not built | The proxy reads the virtual key only from `Authorization: Bearer llmp_...`. An Anthropic SDK must pass it as `auth_token`, not `api_key`. | Send the key in the `Authorization` header. |
| JWT algorithms | Partly built | `auth.jwt` accepts RS256 only. | Sign tokens with RS256. |
| Tenant provider credentials for Vertex and Bedrock | Not built | `providers.<name>.tenant_credentials` is a load error for `vertex` and `bedrock`. Only header API-key provider types qualify. | Use the operator credential for those providers. |
| Rule for `auto` | Partly built | The `auto` model picks a model by tenant only. It does not read the user, the prompt, or a header. | None. |
| Guardrail on responses | Not built | A guardrail checks the request body only. It can allow or deny. It never changes a request. | Filter responses in the client. |

## Reload and credentials

| Gap | Status | What happens today | Workaround |
|---|---|---|---|
| Config file watching | Not built | A reload happens only on `SIGHUP`. | Send `SIGHUP` from your deploy tool. |
| Reload of auth settings | By design | A `SIGHUP` that changes `auth.hmac_secret`, `auth.hmac_secret_file`, `auth.keys`, `auth.store`, or `auth.tenant_credentials` is refused whole. The proxy logs `SIGHUP: config reload refused; continuing to serve the previous snapshot`. | Restart the proxy. Use the admin API to change keys and policies at run time. |
| Reload of OTLP, ledger, and trace export settings | By design | A `SIGHUP` that changes `observability.tracing`, `observability.metrics`, `ledger`, or `observability.traces` is refused whole. | Restart the proxy. |
| Credential files | Partly built | The proxy reads a credential file at start and again at each `SIGHUP`. It does not watch the file. | Send `SIGHUP` after you change a provider credential file. |
| Automatic certificate renewal | Not built | No file watching and no ACME. A renewed certificate needs a `SIGHUP`. | See [TLS](/docs/llm-proxy/operations/tls/). |
| Client certificates (mTLS) | Not built | `listen.tls` takes `cert_file` and `key_file` only. | End mTLS in a layer in front of the proxy. |
| TLS on the admin address | Not built | The admin listener is plain HTTP. The admin token crosses it in clear text. | Bind it to loopback, or put a TLS proxy in front. |
| Rate card from a changed file | By design | With an `auth` block, the store holds the rate card. A changed `pricing` block does not replace a stored card. | Use `PUT /pricing`. |

## Limits and spend

| Gap | Status | What happens today | Workaround |
|---|---|---|---|
| Exact fleet-wide limits | Partly built | With `auth.store: shared`, replicas share limit counts. The fleet can admit a little over a limit between reconciles, about once a second. Without a shared store, each replica counts alone. | Use `auth.store: shared`. |
| A request with no price | By design | If the rate card has no price for the model, the proxy serves the request and adds `$0` to the budget. It logs a warning. | Price every model on every provider of a route. |
| Spend without a rate card | By design | With `auth` and no `pricing`, every request costs `$0` and a budget never fires. The load warns. | Set `pricing`. |
| Token limits and unreadable usage | By design | When the proxy cannot read usage from a response, a token limit fails open and logs a warning. | Check the provider dialect. See [Token rate limiting](/docs/llm-proxy/limits-and-budgets/token-rate-limiting/). |

## Operations and platforms

| Gap | Status | What happens today | Workaround |
|---|---|---|---|
| Docker image, Helm chart, Kubernetes controller | Not built | The repository ships release archives and `scripts/install.sh`. It ships no Dockerfile or chart for the proxy. | Build your own image from the archive. |
| Other platforms | Not built | Release builds exist for Linux amd64 and macOS arm64 only (`.github/workflows/release.yml`). `install.sh` accepts Linux arm64, but no archive exists, so the download fails. It stops with `Intel macOS has no prebuilt release; build from source with cargo` on Intel macOS, and with `unsupported operating system` on other systems. | Build from source. |
| More than one listener | Not built | The file has one `listen` address and one `admin` address. | Run a second process. |

## Observability and data

| Gap | Status | What happens today | Workaround |
|---|---|---|---|
| Token metrics on `/stats` | Not built | Token, latency, health, and ledger metrics render on `/stats/prometheus` and over OTLP only. | Scrape `/stats/prometheus`. |
| Custom access-log format | Not built | `observability.access_logs.format` is `text` or `json`. The output is `stdout`, `stderr`, or a file. | Parse the JSON format in your log pipeline. |
| Request record upload | Not built | `--request-records-file` writes a local file. The proxy has no uploader and no query service. The capture agent that earlier releases offered is removed. | Ship the file with your own agent. For bodies, use trace export. |
| Redaction of exported bodies | Not built | Trace export writes the raw body of a request and of its response. | Protect the directory and the bucket. |
| Billing ledger after a crash | By design | A crash loses the entries that are not yet committed, normally the last `group_commit_interval`. | Set a shorter `group_commit_interval`. |

## Available only in Envoy mode

Some code in the repository is reachable only through an Envoy bootstrap
(`llm-proxy -c bootstrap.yaml`). The `--config` file has no field for it. The
schema `schema/llmproxy-v0.schema.json` is the proof: none of these names
appear in it. This site does not document Envoy mode.

| Capability | Why the `--config` file lacks it | What to do |
|---|---|---|
| Envoy bootstrap input (`-c`, `--permissive`) | The file format is a different front end. `--config` is always strict. | Use `--config`. |
| xDS dynamic configuration (`dynamic_resources`, ADS, CDS, LDS) | The file has no field for a control plane. The file is the only config source, and `SIGHUP` reloads it. | Edit the file and send `SIGHUP`. |
| External authorization (`ext_authz`) | The file has no field for an authorization service. | Use virtual keys, `auth.jwt`, or a `guardrails` check. |
| Several endpoints per provider, with priorities and the panic threshold | The loader gives each provider one endpoint, the host in `base_url`. `weight` on a `models` entry balances across providers instead. | Use `weight` and `session_affinity` on a `models` entry. |
| Load-balancing policy (`ROUND_ROBIN`, `LEAST_REQUEST`, `RANDOM`) | The loader fixes the policy at round robin. | None. |
| EDS and xDS endpoint updates | The file has no field for them. | Edit the file and send `SIGHUP`. |
| Active health checks | The file offers `outlier_detection`, which is passive. | Use `outlier_detection`. |
| Circuit-breaker `max_retries` and `retry_budget` | The file offers three ceilings: `max_requests`, `max_pending_requests`, `max_connections`. | Use those fields. |
| Retry tuning: `per_try_timeout`, `retry_on`, retriable status codes, backoff, the `previous_hosts` predicate | The file offers `routes[].retries.attempts` and a fixed trigger set. | Use `attempts`. |
| The `x-envoy-attempt-count` headers | The file has no field for them. | None. |
| Cluster DNS tuning (`dns_refresh_rate`, `dns_jitter`, `respect_dns_ttl`, strict or logical DNS) | The loader fixes the refresh at 5 seconds and uses logical DNS for a host name. | None. |
| Raw aggregate clusters and `weighted_clusters` | The loader builds them from `fallbacks` and `models`. You cannot write them. | Use `fallbacks`, `models`, and `weight`. |
| The `--mode translate` output as input | `translate` prints an Envoy bootstrap. Loading that output needs `-c`. | Keep the `--config` file as the source. |
| HTTP upgrades other than the realtime WebSocket | `realtime.enabled` is the only upgrade switch. It allows `websocket`. | None. |
| Redirect routes | Every route in the file forwards to a provider. | Redirect in a layer in front of the proxy. |
| Custom access-log `log_format` and other access-log sinks | The file offers `text` and `json`. | Use `json`. |
| CORS and the local rate-limit filter | The file has no field for either filter. | Terminate CORS in a layer in front. Use `limits`. |
| Listener tuning: `transport_socket_connect_timeout`, `ignore_global_conn_limit`, several listeners and filter chains | The file has one listener with fixed handshake defaults. | Use the `listen` fields. |
| Hash policies other than `session_affinity`, including `filter_state` | `models.<name>.session_affinity` (`header` or `identity`) is the only hash policy. | Use `session_affinity`. |
| xDS conformance check (`make xds-conformance`) | It tests the xDS client, which the file does not use. | None. It is contributor material. |

Envoy-mode material is kept for contributors in `internal-docs/envoy-mode/`
in the repository.

## What to do next

If your plan depends on a gap above, check two things first:

1. Does the entry say that the proxy warns? Run `--mode validate` and read the
   warnings.
2. Does a layer in front of the proxy solve it? Caching, TLS renewal, and
   several listeners often live in a separate service.

## Related

- [Introduction](/docs/llm-proxy/getting-started/introduction/)
- [FAQ](/docs/llm-proxy/help/faq/)
- [Troubleshooting](/docs/llm-proxy/help/troubleshooting/)
- [Strict config mode](/docs/llm-proxy/configuration/strict-config-mode/)
