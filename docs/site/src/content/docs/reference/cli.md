---
title: CLI reference
description: "Every llm-proxy mode and flag: serve, validate, translate, keygen, and init."
summary: The llm-proxy modes and flags that this site documents, with
  defaults, required flags, and the error text for a missing config.
lastUpdated: 2026-10-18
related:
  - getting-started/quickstart
  - operations/draining-and-shutdown
  - operations/config-reload
  - observability/request-capture
---

# CLI reference

Use `llm-proxy` to serve traffic, check a config, translate a config, generate
a key, or write a starter setup. Run `llm-proxy --help` for the full list of
flags. This page documents the modes and flags that the other pages of this
site use.

## Modes

`--mode` selects what `llm-proxy` does. It defaults to `serve`.

| Mode | What it does |
|---|---|
| `serve` | Runs the proxy: binds every listener and serves traffic until `SIGTERM`/`SIGINT`. |
| `validate` | Loads and checks the config, prints a one-line summary, and exits — binds no listener. |
| `translate` | Prints the Envoy bootstrap generated from a `--config` file, then exits. |
| `keygen` | Generates a virtual key and its digest for `auth.keys[]`. Needs no config at all. |

A config is required for `serve` and `validate`. Pass either `--config
<PATH>` (the `llmproxy` dialect) or `-c`/`--config-path <PATH>` (an Envoy
bootstrap). `keygen` and `init` run without one.

```sh
llm-proxy --config llmproxy.yaml --mode validate
```

```text
configuration 'llmproxy.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

## `--mode translate`

Inspect how the compact dialect lowers to Envoy resources:

```sh
llm-proxy --config llmproxy.yaml --mode translate > bootstrap.yaml
```

Translation requires `--config`; `-c` already takes an Envoy bootstrap.
Provider keys, the auth HMAC secret, and the store URL are redacted as
`[REDACTED]` by default. `--reveal-secrets` includes their configured values;
protect that output as a secret. Redacted output is for inspection and needs
real credentials before use as a serving bootstrap. Use `--mode validate`
to check the configuration for serving; translation does not require the
shared store's `--service-node` identity.

## `--mode keygen`

Generates a fresh virtual key and the digest that goes in `auth.keys[]` —
see [Configuration file reference](../../configuration/configuration-file/)
for the `auth` block this feeds.

| Flag | Required | Default | What it does |
|---|---|---|---|
| `--tenant <TENANT>` | yes | — | The tenant the generated key authenticates as. |
| `--key-id <ID>` | no | `REPLACE_ME` | Names this credential in audit logs and `auth.keys[].id`. |
| `--hmac-secret-file <PATH>` | no* | — | Derive the digest's HMAC secret from this file. Takes precedence over `$LLMPROXY_AUTH_SECRET` if both are set. |

\* One of `--hmac-secret-file` or the `LLMPROXY_AUTH_SECRET` environment
variable is required; `keygen` refuses to run with neither.

```sh
llm-proxy --mode keygen --tenant acme --key-id ci-key --hmac-secret-file secret.txt
```

```text
Key (shown once -- store it now; it cannot be recovered from the config):

  llmp_gi8rOx9_phFE8YhCyudzMgDPrsJHpFn9jQrbarGxdTE

Add to your llmproxy.yaml:

  auth:
    keys:
      - id: ci-key
        tenant: acme
        digest: 23c22dd8c317d5090cdff77f045c5f83f3b1aa139a8d4989b43285c46922914e
```

The plaintext key is printed exactly once and cannot be recovered from the
digest. Store it immediately.

## Flags for `serve`

| Flag | Default | What it does |
|---|---|---|
| `--config <PATH>` | — | Path to an `llmproxy` dialect config. Required unless you pass `-c`. |
| `-c`, `--config-path <PATH>` | — | Path to an Envoy bootstrap (`.yaml`, `.yml`, `.json`, or `.pb`). Required unless you pass `--config`. |
| `--permissive` | off | Warn on unknown fields in a `-c` bootstrap instead of failing. It has no effect on `--config`, which is always strict. |
| `--concurrency <N>` | number of available CPU cores | Number of worker runtimes. |
| `--drain-time-s <SECS>` | `600` | Seconds to wait for connections to close during shutdown — see [Draining and shutdown](../../operations/draining-and-shutdown/). |
| `--drain-strategy <gradual\|immediate>` | none | Accepted for Envoy compatibility. Both values behave the same and the proxy warns at startup when the flag is given. See [Draining and shutdown](../../operations/draining-and-shutdown/). |
| `--base-id <N>` | — | Accepted for compatibility with tooling that always passes it. llm-proxy has no hot-restart implementation, so this is parsed and ignored. |
| `-l`, `--log-level <LEVEL>` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `critical`, or `off`. `critical` maps to `error`. |
| `--service-node <NAME>` | — | Overrides the bootstrap `node.id`. The proxy uses it as the node ID sent to an xDS control plane and as the writer identity for spend limits. Set a stable value for each replica. See [Share state across replicas](../../operations/running-in-production/). |
| `--service-cluster <NAME>` | — | Overrides the bootstrap `node.cluster`. The proxy sends it to an xDS control plane. |

`--config` and `-c` conflict. Pass only one of them. The `llmproxy` dialect
has no field for the node, so `--service-node` is the only way to set it with
`--config`.

### Capture flags

These flags turn on request capture. All are off by default. See
[Request capture](../../observability/request-capture/) for the agent setup, the
limits, and the metrics.

| Flag | Default | What it does |
|---|---|---|
| `--request-records-file <PATH>` | — | Append one JSON line for each request to this file. Conflicts with `--request-records-agent`. |
| `--request-records-agent <SOCKET>` | — | Send records to the `llm-capture-agent` on this Unix socket. Requires the next three flags. |
| `--request-records-agent-uid <UID>` | — | The OS UID the agent must run as. |
| `--request-records-agent-node <ID>` | — | The node ID the agent must report. |
| `--request-records-producer <ID>` | — | The producer ID in the agent grant for this proxy. |
| `--request-record-max-attempts <N>` | `64` | Attempt summaries to keep for each record, from 1 to 64. Needs a destination flag. |

## `init`

`llm-proxy init [DIRECTORY]` writes a starter setup. `DIRECTORY` defaults to
`.`. The command creates the directory if it does not exist and writes two
files:

- `llmproxy.yaml`: a starter `llmproxy` config that routes every model to a
  local Ollama at `127.0.0.1:11434`, with `listen: 0.0.0.0:53421` and
  `admin: 127.0.0.1:53422`. It sets
  `auth.enforce.tenants_without_policy: allow`, so the printed key works
  before any tenant policy is stored. Remove that block before you issue
  keys to other people.
- `auth-secret`: a random HMAC secret, with mode `0600` on Unix.

The command also prints a key for the `default` tenant (key ID
`default-admin`). The key is shown once and cannot be recovered. The config
names `./auth-secret` and `./llmproxy-access.log` relative to the working
directory, so start the proxy from `DIRECTORY`.

If either file exists, `init` writes nothing and exits with an error:

```text
refusing to overwrite existing file <path>; move it or choose another directory
```

A running `serve` process also responds to `SIGHUP` (config reload — see
[Reload configuration](../../operations/config-reload/)) and `SIGTERM`/`SIGINT`
(graceful shutdown).

## Every mode

| Flag | What it does |
|---|---|
| `-h`, `--help` | Print the full flag list. |
| `-V`, `--version` | Print the version. |

## Errors this site's other pages reference

Running `serve` or `validate` with neither `--config` nor `-c` is refused.
The program has no default config:

```text
a config is required: pass -c/--config-path or --config (only --mode keygen runs without one)
```

Running `keygen` without `--tenant`:

```text
--mode keygen requires --tenant <TENANT>
```

## Implementation notes

For maintainers. The `init` command is in `crates/proxy/src/init.rs`.
