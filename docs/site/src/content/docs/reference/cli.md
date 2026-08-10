---
title: CLI reference
summary: Every llm-proxy flag documented on this site, verified against
  --help and the real argument parser.
last_updated: 2026-08-09
related:
  - /getting-started/quickstart/
  - /operations/draining-and-shutdown/
  - /operations/config-reload/
---

# CLI reference

Run `llm-proxy --help` for the authoritative list. This page documents the
subset this site's other pages rely on.

## Modes

`--mode` selects what `llm-proxy` does. It defaults to `serve`.

| Mode | What it does |
|---|---|
| `serve` | Runs the proxy: binds every listener and serves traffic until `SIGTERM`/`SIGINT`. |
| `validate` | Loads and checks the config, prints a one-line summary, and exits — binds no listener. |
| `keygen` | Generates a virtual key and its digest for `auth.keys[]`. Needs no config at all. |

A config is required for `serve` and `validate` (`--config <PATH>`); only
`keygen` runs without one.

```sh
llm-proxy --config llmproxy.yaml --mode validate
```

```text
configuration 'llmproxy.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

**A fourth mode, `--mode translate`, exists in the binary's own `--help`
output but is intentionally not documented on this page.** It prints a
lowered form of the config in a different, more verbose format than this
site's configuration reference covers. Describing what that output actually
is, without going further than this site's current scope, was not possible
without either naming what it is or writing around it — so it is left out
here entirely rather than described vaguely.

## `--mode keygen`

Generates a fresh virtual key and the digest that goes in `auth.keys[]` —
see [Configuration file reference](/configuration/configuration-file/)
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
| `--config <PATH>` | — | Path to the config file. Required. |
| `--concurrency <N>` | number of available CPU cores | Number of worker runtimes. |
| `--drain-time-s <SECS>` | `600` | Seconds to wait for connections to close during shutdown — see [Draining and shutdown](/operations/draining-and-shutdown/). |
| `--drain-strategy <gradual\|immediate>` | `gradual` | How shutdown encourages connections to close. See [Draining and shutdown](/operations/draining-and-shutdown/) for what these do and do not affect today. |
| `--base-id <N>` | — | Accepted for compatibility with tooling that always passes it. llm-proxy has no hot-restart implementation, so this is parsed and ignored. |
| `-l`, `--log-level <LEVEL>` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `critical`, or `off`. `critical` maps to `error`. |
| `--service-node <NAME>` | — | Reserved for future dynamic-configuration support; not consumed by anything today. |
| `--service-cluster <NAME>` | — | Reserved for future dynamic-configuration support; not consumed by anything today. |

A running `serve` process also responds to `SIGHUP` (config reload — see
[Config reload](/operations/config-reload/)) and `SIGTERM`/`SIGINT`
(graceful shutdown).

## Every mode

| Flag | What it does |
|---|---|
| `-h`, `--help` | Print the full flag list. |
| `-V`, `--version` | Print the version. |

## Errors this site's other pages reference

Running `serve` or `validate` with no `--config` at all is refused rather
than silently defaulting to anything.

Running `keygen` without `--tenant`:

```text
--mode keygen requires --tenant <TENANT>
```
