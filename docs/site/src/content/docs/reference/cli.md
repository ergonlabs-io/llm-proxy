---
title: CLI reference
description: "Every llm-proxy mode, flag, and subcommand for a --config file: serve, validate, translate, keygen, and init."
summary: The llm-proxy command line for the llmproxy dialect. Modes, flags
  with defaults, the init subcommand, the admin token, and the error text for
  the common mistakes.
lastUpdated: 2026-10-21
related:
  - getting-started/quickstart
  - reference/environment-variables
  - operations/draining-and-shutdown
  - operations/config-reload
  - observability/request-capture
---

The binary is `llm-proxy`. Run `llm-proxy --help` for the list that matches
your build. This page covers the flags that you use with a `--config` file.

## At a glance

| Item | Value |
|---|---|
| Default mode | `serve` |
| Config input | `--config <PATH>`. No default file exists. |
| Needs a config | `serve`, `validate`, `translate`. `keygen` and `init` need none. |
| Log output | Standard error, in every mode. |
| Result output | Standard output for `validate`, `translate`, `keygen`, and `init`. |
| Exit status | `0` on success. `1` on any error. |

## Synopsis

```text
llm-proxy [OPTIONS] [COMMAND]

COMMAND:
  init [DIRECTORY]    Create a starter config, authentication secret, and default-tenant key
```

Source: `Args` and `Command` in `crates/proxy/src/main.rs`.

## Config input flag

| Flag | Value | Default | Description |
|---|---|---|---|
| `--config` | `PATH` | none | Path to an `llmproxy` dialect file. The field reference is [Configuration reference](/docs/llm-proxy/configuration/reference/). |

If you pass no config to `serve`, `validate`, or `translate`, the proxy exits
with status 1 and prints this to standard error:

```text
a config is required: pass -c/--config-path or --config (only --mode keygen runs without one)
```

The proxy also accepts Envoy bootstrap files with `-c`. This site does not
cover that input. The `-c` text in the error above is a fixed string. See
[Limitations](/docs/llm-proxy/help/limitations/#available-only-in-envoy-mode).

## Modes

`--mode` selects what `llm-proxy` does. The default is `serve`.

| Mode | What it does |
|---|---|
| `serve` | Binds every listener and serves traffic until `SIGTERM` or `SIGINT`. |
| `validate` | Loads and checks the config, prints one summary line, and exits. It binds no listener. |
| `translate` | Prints the Envoy bootstrap that the proxy generates from the config, then exits. It is a diagnostic. |
| `keygen` | Generates a virtual key and its digest for `auth.keys[]`. It needs no config. |

### serve

```sh
llm-proxy --config llmproxy.yaml
```

A running `serve` process handles `SIGHUP` (config reload), `SIGTERM` or
`SIGINT` (graceful shutdown), and `SIGUSR1` (reopen the access-log and
request-records files). See
[Reload configuration](/docs/llm-proxy/operations/config-reload/),
[Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/), and
[Rotating the file](/docs/llm-proxy/observability/access-logs/#rotating-the-file).

If a listener cannot bind, `serve` exits with status 1. The message has this
form:

```text
listener 'llmproxy_listener' failed to bind 0.0.0.0:53421: Address already in use (os error 98)
```

### validate

`validate` runs the load steps of `serve` and builds the same internal
config. A config that `validate` accepts also loads in `serve`, with two
exceptions. The ledger and trace export checks for `--service-node` run only
at `serve` start. Other start-time failures, such as a port that is in use,
also appear only in `serve`.

```sh
llm-proxy --config llmproxy.yaml --mode validate
```

```text
configuration 'llmproxy.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

The proxy prints each load warning to standard error before the summary:

```text
warning: `auth.enforce.tenants_without_policy`: every authenticated tenant without a stored model policy may use every model; remove this to refuse them until PUT /tenants/{id}/policy grants models
```

If the config is not valid, the proxy exits with status 1 and prints this to
standard error. The reason carries the full dotted path of the field:

```text
configuration 'llmproxy.yaml' INVALID
  <reason, with the full dotted path of the field>
```

In the summary, `cluster(s)` counts the providers and the internal
fallback chains.

### translate

`translate` prints the Envoy bootstrap that the proxy generates from your
`--config` file. Use it to inspect how the proxy reads the file.

```sh
llm-proxy --config llmproxy.yaml --mode translate > bootstrap.yaml
```

By default, `translate` prints provider keys, the auth HMAC secret, and the
store URL as `[REDACTED]`. It prints a note on standard error when it hides
a secret. `--reveal-secrets` prints the configured values. Protect that
output as a secret. Redacted output needs real credentials before you can
use it as a bootstrap.

| Flag | Default | Description |
|---|---|---|
| `--reveal-secrets` | off | Print provider keys, the auth HMAC secret, and the store URL as configured. Only `--mode translate` reads this flag. |

`translate` does not check the `--service-node` rule for a shared store. Use
`--mode validate` to check a config for serving.

### keygen

`keygen` makes a virtual key and the digest that goes in `auth.keys[]`. The
proxy prints the plaintext key once. It cannot recover the key from the
digest. See [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/) for
the `auth` block.

| Flag | Value | Default | Required | Description |
|---|---|---|---|---|
| `--tenant` | `TENANT` | none | yes | The tenant that the key authenticates as. An empty value is an error. |
| `--key-id` | `ID` | `REPLACE_ME` | no | The name of the key in audit logs and `auth.keys[].id`. |
| `--hmac-secret-file` | `PATH` | none | one of two | File that holds the HMAC secret. |

You must supply the HMAC secret. Use `--hmac-secret-file`, or set
`LLMPROXY_AUTH_SECRET`. If you set both, the file wins. The proxy removes
trailing whitespace from the file contents. It does not trim the environment
value. See [Environment variables](/docs/llm-proxy/reference/environment-variables/).

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

These errors come from the code:

```text
--mode keygen requires --tenant <TENANT>
no HMAC secret: pass --hmac-secret-file <PATH>, or set $LLMPROXY_AUTH_SECRET
$LLMPROXY_AUTH_SECRET is set but empty (an empty secret would make every digest effectively unkeyed)
```

`keygen` reads `--hmac-secret-file` only in this mode. The running proxy
reads the secret from `auth.hmac_secret` or `auth.hmac_secret_file`.

## Flags for serve

| Flag | Value | Default | Description |
|---|---|---|---|
| `--concurrency` | `N` | number of available CPU cores | Number of worker runtimes. |
| `--drain-time-s` | `SECS` | `600` | Seconds to wait for connections to close during shutdown. See [Draining and shutdown](/docs/llm-proxy/operations/draining-and-shutdown/). |
| `--drain-strategy` | `gradual` or `immediate` | `immediate` | When the proxy tells each connection to close during a drain. `immediate` closes them all at drain start. `gradual` spreads the closes over the first quarter of `--drain-time-s`. See [Gradual drain](/docs/llm-proxy/operations/draining-and-shutdown/#gradual-drain). |
| `-l`, `--log-level` | level | `info` | `trace`, `debug`, `info`, `warn`, `error`, `critical`, or `off`. `critical` maps to `error`. |
| `--service-node` | `NAME` | none | The identity of this replica. See [The --service-node flag](#the-service-node-flag). |

The log level sets the filter directly. The proxy does not read `RUST_LOG`.

### The --service-node flag

The `llmproxy` dialect has no field for the identity of a replica. Set it
with `--service-node`. Use a value that is unique to the replica and stable
across restarts. Three settings need it:

- `auth.store.shared`. Without the flag, `validate` and `serve` fail with an
  error at `auth.store.shared`: `a shared store requires a configured node id:
  pass --service-node <name> with a name unique to this replica and stable
  across its restarts (the dialect has no node id field)`.
- `ledger`. Without the flag, `serve` does not start. The name must be at
  most 128 bytes.
- `observability.traces`. Without the flag, `serve` does not start.

With any other store, a missing name does not stop the proxy. It makes a name
for that run, and the name changes at each restart. See
[Running in production](/docs/llm-proxy/operations/running-in-production/).

### Request record flags

These flags turn on request records. Both are off by default. See
[Request capture](/docs/llm-proxy/observability/request-capture/) for the
record format, the limits, and the metrics.

| Flag | Value | Default | Description |
|---|---|---|---|
| `--request-records-file` | `PATH` | none | Append one JSON line for each request to this file. |
| `--request-record-max-attempts` | `1` to `64` | `64` | The most attempt summaries to keep for each record. A value outside the range, or the flag without `--request-records-file`, is a command-line error. |

A reload does not change these flags. The capture agent and its flags
(`--request-records-agent`, `--request-records-agent-uid`,
`--request-records-agent-node`, `--request-records-producer`) are removed.

## The init subcommand

`llm-proxy init [DIRECTORY]` writes a starter setup. `DIRECTORY` defaults to
`.`. The command creates the directory if it does not exist and writes three
files:

| File | What it holds |
|---|---|
| `llmproxy.yaml` | A starter config. It routes every model to a local Ollama at `127.0.0.1:11434`. It sets `listen: 0.0.0.0:53421` and `admin: 127.0.0.1:53422`. |
| `auth-secret` | A random HMAC secret (32 bytes, hex). Mode `0600` on Unix. |
| `admin-token` | A random admin token (32 bytes, hex). Mode `0600` on Unix. |

The starter config sets `auth.enforce.tenants_without_policy: allow`. The
printed key works before any tenant policy exists. The proxy warns about this
at start. Remove that block before you issue keys to other people.

The command also prints a key for the `default` tenant (key ID
`default-admin`). The key is shown once and cannot be recovered. It prints the
command to start the proxy:

```text
LLMPROXY_ADMIN_TOKEN="$(cat admin-token)" llm-proxy --config llmproxy.yaml
```

The config names `./auth-secret` and `./llmproxy-access.log` relative to the
working directory. Start the proxy from `DIRECTORY`.

```sh
llm-proxy init ./llm-proxy-home
cd ./llm-proxy-home
LLMPROXY_ADMIN_TOKEN="$(cat admin-token)" llm-proxy --config llmproxy.yaml
```

If any of the three files exists, `init` writes nothing and exits with
status 1:

```text
refusing to overwrite existing file <path>; move it or choose another directory
```

## Admin token

The admin server needs a bearer token for writes and for sensitive reads. The
proxy reads the token from the `LLMPROXY_ADMIN_TOKEN` environment variable
once, at start. There is no flag for it. The proxy never reads it from the
config.

- If the variable is unset, empty, or only whitespace, the admin API refuses
  those requests with status 403. The proxy logs a warning at start.
- If a caller sends a missing or wrong token, the admin API answers 401.
  After repeated wrong tokens from one address, it answers 429.
- To change the token, restart the proxy.

See [Admin API](/docs/llm-proxy/administration/admin-api/) for the endpoints
that the token protects.

## Every mode

| Flag | Description |
|---|---|
| `-h`, `--help` | Print the full flag list. |
| `-V`, `--version` | Print the version. |

## Not covered here

`llm-proxy --help` also lists flags for Envoy bootstrap files (`-c`,
`--permissive`, `--base-id`, `--service-cluster`). These flags do not apply to
a `--config` file. This site does not document them.

## Limitations

- `--hmac-secret-file` works only with `--mode keygen`. The running proxy
  reads `auth.hmac_secret_file` from the config.
- `--mode validate` does not check the `--service-node` rule for `ledger` or
  `observability.traces`.
- The proxy has no file watcher. A config change needs `SIGHUP`.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

For maintainers. The clap definitions and the mode dispatch are in
`crates/proxy/src/main.rs`. The `init` command is in
`crates/proxy/src/init.rs` and `keygen` is in `crates/proxy/src/keygen.rs`.
Tests: `init_writes_an_admin_token_file_and_refuses_to_overwrite_it` in
`init.rs`, and the `effective_node_*` tests in `main.rs`.
