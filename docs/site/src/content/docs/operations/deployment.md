---
title: Deployment
description: "Run llm-proxy as one process under a supervisor, check readiness with /ready, run several replicas, and upgrade without dropping requests."
summary: How to run llm-proxy in production. The ports the proxy opens, the
  service the installer writes, an example systemd unit and container recipe,
  the readiness endpoint, a published capacity data point, what changes with
  more than one replica, and how to upgrade.
lastUpdated: 2026-10-21
related:
  - getting-started/installation
  - operations/running-in-production
  - operations/draining-and-shutdown
  - operations/config-reload
  - operations/tls
  - help/troubleshooting
---

llm-proxy is one process. It reads one config file, opens a listener for
client traffic, and optionally opens an admin listener. It needs no sidecar
and no control plane. The default `auth.store` is in memory, so it needs no
database. This page shows how to supervise the process, how to check that it
is ready, and what to plan when you run more than one copy.

## At a glance

- **Default when unset:** with no `listen`, the proxy binds `0.0.0.0:8080`
  in plaintext. With no `admin`, no admin listener exists.
- **Failure mode:** a config that fails to load stops the process at start.
  A config that fails on `SIGHUP` leaves the previous config in service.
- **Shipped artifacts:** a release archive for each platform,
  `scripts/install.sh`, a container image and a Helm chart. The installer
  writes a service. For Kubernetes, see
  [Kubernetes and Helm](/docs/llm-proxy/operations/kubernetes/). The project
  does not ship a Compose file. The systemd unit below is an example that you
  adapt.

## What you run

The release archive is `llm-proxy-linux-amd64.tar.gz`,
`llm-proxy-linux-arm64.tar.gz`, or `llm-proxy-darwin-arm64.tar.gz`. The
workflow does not build other platforms. The archive holds two items:

| File | Purpose |
|---|---|
| `llm-proxy` | The proxy binary. |
| `admin-ui-dist/` | The static files for the Admin UI. |

The checksum file `<archive>.sha256` sits beside each archive. See
[Installation](/docs/llm-proxy/getting-started/installation/) for the install
steps.

## Install as a service

`scripts/install.sh` installs the binary and starts the proxy as a service.
Re-run it to upgrade. It keeps the existing config, secrets, and admin token.
The service depends on how you run the script:

| Run as | Service | Data directory |
|---|---|---|
| Normal user on macOS | A launchd agent, label `io.ergonlabs.llm-proxy` | `~/.config/llm-proxy` |
| Normal user on Linux | A systemd user unit, `llm-proxy` | `~/.config/llm-proxy` |
| Root on Linux | A systemd system unit, `llm-proxy`, that runs as the `llm-proxy` system user | `/var/lib/llm-proxy` |
| Any user, no systemd or `--no-service` | A background process | as above |

Every service starts the proxy through `run.sh` in the data directory. That
script changes to the data directory, loads `service.env` (which holds
`LLMPROXY_ADMIN_TOKEN`), sets `LLMPROXY_ADMIN_UI_DIR`, and runs
`llm-proxy --config <data directory>/llmproxy.yaml`.

The system unit sets `Restart=on-failure`, `RestartSec=2`,
`LimitNOFILE=65536`, `NoNewPrivileges=yes`, `PrivateTmp=yes`,
`ProtectSystem=full`, and `ProtectHome=yes`. The data directory is the only
writable path. The user unit sets `Restart=on-failure`, `RestartSec=2`, and
`LimitNOFILE=65536`.

The installer unit sets no `TimeoutStopSec`, so systemd applies its own stop
timeout. The default drain is 600 seconds. A stream that is still open when
systemd stops waiting is cut by `SIGKILL`. To raise the timeout, add a drop-in
with `systemctl edit llm-proxy`:

```ini title="override.conf (example)"
[Service]
TimeoutStopSec=660
```

The installer unit has no reload command. To reload the config, send
`SIGHUP`: `systemctl kill --signal=HUP llm-proxy`. Use `systemctl --user` for
a user unit.

## Ports

| Listener | Config key | Default | Notes |
|---|---|---|---|
| Client traffic | `listen` | `0.0.0.0:8080` | Plaintext unless you set `listen.tls`. See [TLS](/docs/llm-proxy/operations/tls/). |
| Admin | `admin` | off | Enabled only when you set `admin: host:port`. |

The starter config from `llm-proxy init` and the installer uses
`0.0.0.0:53421` for traffic and `127.0.0.1:53422` for admin.

The proxy also opens outbound connections to each provider. Allow them
through your firewall or egress policy. The `base_url` of each provider gives
the host and port.

### Protect the admin listener

The admin listener serves `/ready`, `/config_dump`, `/clusters`, `/models`,
`/server_info`, `/stats`, and `/stats/prometheus` without a token. Writes and
two reads that expose money or identity need the bearer token in
`LLMPROXY_ADMIN_TOKEN`: `GET /keys` and the `.../spend` reads. See
[Admin API](/docs/llm-proxy/administration/admin-api/).

Bind the admin listener to loopback unless you have a reason not to. If you
bind it to another address, restrict it with a network policy or a firewall.
`/config_dump` shows credential values as `[redacted]`, but it still shows
your routes and provider names. The admin API is plain HTTP, so the token
crosses the network unencrypted.

## Run under your own supervisor

Run the proxy under a supervisor that restarts it on exit and sends
`SIGTERM` to stop it. The proxy installs its signal handlers before it binds
any listener.

| Signal | Effect |
|---|---|
| `SIGTERM`, `SIGINT` | Start the drain, then exit. See [Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/). |
| `SIGHUP` | Reload the config file. See [Reload configuration](/docs/llm-proxy/operations/config-reload/). |

The drain waits up to 600 seconds by default (`--drain-time-s`). Set the stop
timeout of your supervisor above that value.

### Example: systemd unit

This is an example that you write yourself. The project does not ship it.
Adjust the paths and the user.

```ini title="/etc/systemd/system/llm-proxy.service (example)"
[Unit]
Description=llm-proxy
After=network-online.target
Wants=network-online.target

[Service]
User=llmproxy
EnvironmentFile=/etc/llm-proxy/env
ExecStart=/usr/local/bin/llm-proxy --config /etc/llm-proxy/llmproxy.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
# The default drain is 600 s. Leave room after it.
TimeoutStopSec=660
KillSignal=SIGTERM
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Put secrets in `/etc/llm-proxy/env` with mode `0600`. For example,
`OPENAI_API_KEY=...` and `LLMPROXY_ADMIN_TOKEN=...`. The config file reads
`${VAR}` references from the environment at load time. A variable that is not
set is a load error.

Check the config before you start the unit:

```bash
llm-proxy --config /etc/llm-proxy/llmproxy.yaml --mode validate
```

Reload after a config change:

```bash
sudo systemctl reload llm-proxy
```

### Container image

Each release publishes `ghcr.io/ergonlabs-io/llm-proxy:<version>` for
`linux/amd64` and `linux/arm64`. The image holds the release binary, the
admin UI bundle (`LLMPROXY_ADMIN_UI_DIR` is set) and CA certificates, on a
distroless base with no shell. It runs as user `65532`. Its Dockerfile is
`deploy/container/Dockerfile`.

The image runs `llm-proxy --config /etc/llm-proxy/llmproxy.yaml`. Mount
your config there and pass secrets as environment variables:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/llmproxy.yaml:/etc/llm-proxy/llmproxy.yaml:ro" \
  -e OPENAI_API_KEY \
  ghcr.io/ergonlabs-io/llm-proxy:1.0.0
```

Set `listen` in the config to an address on all interfaces, such as
`0.0.0.0:8080`. The container runtime sends `SIGTERM` on stop. Set the stop
grace period above `--drain-time-s`, for example
`docker stop --time 660`. On Kubernetes, use the Helm chart, which sets the
grace period for you.

## Readiness and health checks

`GET /ready` on the admin listener is the health endpoint. It needs no token.

| Status | Body | Meaning |
|---|---|---|
| `200` | `LIVE` | A listener is bound, and every provider has resolved, or the warming limit has passed. |
| `503` | `INITIALIZING` | No listener is bound yet, or a provider has not resolved yet. |
| `503` | `DRAINING` | The drain has started, or `POST /healthcheck/fail` was called. |

```bash
curl --max-time 2 -i http://127.0.0.1:53422/ready
```

```text
HTTP/1.1 200 OK

LIVE
```

Read these limits before you rely on `/ready`:

- **The warming limit fails open.** The proxy waits 15 seconds for
  providers that are still resolving. Then `/ready` reports `LIVE` and logs
  one warning: `cluster warming deadline (initial_fetch_timeout) expired with
  clusters still unresolved`.
- **`/ready` does not test providers.** It does not call any provider. A
  provider outage does not turn `/ready` red. Use the `/stats` counters to
  watch provider health.
- **There is no separate liveness endpoint.** Do not use `/ready` for
  liveness: it answers `503` for the whole drain. Use `GET /server_info`,
  which answers `200` while the admin server runs, or a TCP check.
- **The probe must reach the admin listener.** If admin stays on loopback,
  run the probe inside the container or on the host. The published image has
  no shell or curl, so the Helm chart binds admin to `0.0.0.0` and probes it
  over HTTP.

## Sizing

The project measured capacity on a dedicated host: a DigitalOcean droplet with
16 vCPU (Intel Xeon Platinum 8168) and no CPU steal. One proxy replica ran on 4
pinned cores. The mock upstream and the load generator ran on other cores. The
driver was open-loop, with 128-token chat completions, 250 ms time to first
token and 25 ms between tokens. The latency gate was p99 at or below 6900 ms
and time-to-first-token p99 at or below 1000 ms. `circuit_breakers` allowed
16384 requests and 16384 connections. The proxy had no TLS.

| Upstream protocol | Highest concurrency within the gate | Memory per stream | CPU per stream |
|---|---|---|---|
| HTTP/2 | 7,927 concurrent streams | 72 KB | 2.0 ms |
| HTTP/1.1 | 3,608 concurrent streams | 131 KB | 4.8 ms |

At both limits the proxy used all 4 cores. The error rate was 0 at every level
within the gate.

On the same type of host, at a fixed request rate, the proxy added less than
5 ms at p99 up to 20,000 requests/s for each replica on 4 cores. At
5,000 requests/s it added 0.44 ms at p50 and 2.34 ms at p99. A 30-minute soak
of 225,000 streams had no errors, and memory stayed flat.

What this means for planning:

- **CPU sets the limit.** Plan about 2 ms of CPU and 72 KB of memory for each
  HTTP/2 stream, and about twice that for HTTP/1.1.
- **Workers equal cores by default.** `--concurrency N` sets the number of
  worker runtimes. The default is the number of available cores. In a
  container with a CPU limit, check that the proxy sees the limit, or set
  `--concurrency`.
- **Overload queues.** Past the limit, latency increases before errors occur.
- **Use HTTP/2 to providers that support it.** Set `protocol: http2` on the
  provider so the proxy reuses connections.

A real provider adds its own latency and rate limits. Run `make sweep` from
the source tree on your hardware to repeat the test.

## Run more than one replica

A load balancer in front of the replicas needs no session affinity for
normal requests. What the replicas share depends on `auth.store`.

| Concern | Behavior |
|---|---|
| Config | Each replica reads its own file. Deploy the same file to every replica. |
| Virtual keys in `auth.keys` | Identical files give identical keys. |
| Keys, tenants, policy, and budgets from the admin API | Shared only with `auth.store: shared`. With another store, they exist on one replica only. |
| Token and request limits (`limits:`) | Shared through `auth.store: shared`. With another store, each replica counts alone, so N replicas admit up to N times a limit. |
| Rate card (`pricing`) | Shared through `auth.store: shared`. |
| Long-lived connections | A WebSocket or SSE stream stays on the replica that accepted it. It ends when the client closes or the drain completes. |

To share state, set `auth.store` to `shared` with a Redis URL. Start each
replica with its own `--service-node <name>`. Without the flag, a config with
a shared store does not load.

```yaml title="llmproxy.yaml (fragment)"
auth:
  hmac_secret: ${LLMPROXY_AUTH_SECRET}
  store:
    shared:
      url_file: /run/secrets/redis-url
      namespace: llmproxy-production
```

```bash
llm-proxy --config llmproxy.yaml --service-node replica-a
```

Use the same namespace and HMAC secret on every replica. Use a stable node
name, such as a pod name or a host name. See
[Share state across replicas](/docs/llm-proxy/operations/running-in-production/)
for the propagation bounds and for what happens when Redis is not reachable.

## Upgrade procedure

`SIGHUP` reloads the config only. It does not load a new binary. The proxy
has no hot restart. Upgrade by replacing replicas.

1. Download the new release archive. Check it against the `.sha256` file.
2. Validate your config with the new binary:
   `llm-proxy --config llmproxy.yaml --mode validate`. A strict-mode error
   means the new version rejects a field. Fix it before you continue.
3. Start one new replica. Wait until `/ready` returns `200`.
4. Send a test request through the new replica with `curl --max-time 30`.
5. Add the new replica to the load balancer.
6. Remove one old replica from the load balancer. Send `SIGTERM` to it. The
   drain lets in-flight streams finish.
7. Wait for the old process to exit. Repeat steps 3 to 7 for the next replica.

To roll back, use the same steps with the old binary.

On one host that the installer manages, re-run `scripts/install.sh`. The
script stops the service, replaces the binary, and starts the service again.
Requests that arrive between the stop and the start fail. Use the replica
procedure above if you cannot accept that gap.

Read the [changelog](https://github.com/ergonlabs-io/llm-proxy/blob/main/CHANGELOG.md)
before an upgrade. Changes to the config surface are listed there.

## Limitations

- The project ships no Compose file.
- The proxy has no hot restart. Replace the process to change the binary.
- `/ready` has no provider-level check.
- The installer unit does not set `TimeoutStopSec`. Set it yourself.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.
