---
title: Environment variables
description: "Every environment variable that llm-proxy and its install script read, and the ${VAR} rule for config files."
summary: The three variables the llm-proxy binary reads, the variables of the
  install script, the ${VAR} syntax in a config file, and the variables the
  proxy does not read.
lastUpdated: 2026-10-21
related:
  - reference/cli
  - authentication/managing-secrets
  - administration/admin-api
  - administration/admin-ui
  - configuration/configuration-file
---

The `llm-proxy` binary reads three environment variables of its own. A config
file can also read any variable with `${VAR}`. The install script reads five
more.

## At a glance

| Variable | Read by | Default | Fails open or closed |
|---|---|---|---|
| `LLMPROXY_ADMIN_TOKEN` | `serve` | unset | Closed. Unset means the admin API refuses writes and sensitive reads. |
| `LLMPROXY_ADMIN_UI_DIR` | `serve` | unset | Not a security control. Unset means `/ui` returns `404`. |
| `LLMPROXY_AUTH_SECRET` | `--mode keygen` | unset | Closed. Unset or empty means `keygen` refuses to run. |

## Binary variables

The proxy reads `LLMPROXY_ADMIN_TOKEN` and `LLMPROXY_ADMIN_UI_DIR` once, when
the admin server starts. A `SIGHUP` reload does not read them again. To change
a value, restart the proxy.

### LLMPROXY_ADMIN_TOKEN

This variable holds the bearer token for the admin API. It protects the
write endpoints and the sensitive read endpoints. A caller sends it as
`Authorization: Bearer <token>`.

An unset, empty, or whitespace-only value means "not configured". The
protected endpoints then fail closed. They return status 403 with this body:

```text
admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is not set
```

At start, the proxy logs this warning when the admin server is on and the
token is not set:

```text
LLMPROXY_ADMIN_TOKEN is not set: admin writes (keys, tenants, budgets, pricing) and key and spend reads are refused with 403, in the admin UI too
```

A missing or wrong token returns status 401 with the body `missing or invalid
bearer token`. After repeated wrong tokens from one address, the admin API
returns 429 with a `retry-after` header.

`llm-proxy init` writes a token to the file `admin-token`. The installer keeps
the token in `service.env`. See [Admin API](/docs/llm-proxy/administration/admin-api/).

### LLMPROXY_ADMIN_UI_DIR

This variable holds the path of the built admin UI. The directory must hold
`index.html` and the UI assets. The release archive ships it as
`admin-ui-dist`. The proxy loads the files into memory at start and serves them
under `/ui/` on the admin address.

If the variable is unset or empty, `/ui` returns `404`, and the proxy logs
an info line that names the variable. If the directory cannot be loaded, the
proxy logs a warning and `/ui` returns `404`. The admin API still works. The
proxy does not stop. See [Admin UI](/docs/llm-proxy/administration/admin-ui/).

### LLMPROXY_AUTH_SECRET

`--mode keygen` needs an HMAC secret. If you do not pass `--hmac-secret-file`,
`keygen` reads this variable. The proxy does not trim the value. An empty
value is an error:

```text
$LLMPROXY_AUTH_SECRET is set but empty (an empty secret would make every digest effectively unkeyed)
```

The running proxy does not read this variable by name. Set `auth.hmac_secret`
or `auth.hmac_secret_file` in the config. To use the same value, write
`hmac_secret: ${LLMPROXY_AUTH_SECRET}`. See the next section.

## Interpolation in config files

A `--config` file can contain `${VAR_NAME}`. The proxy replaces each reference
with the value of the variable before it parses the YAML. The value keeps its
YAML type, so `port: ${PORT}` works for a number. The proxy reads the
variables of its own process. A reload does not read them again from outside.

| Rule | Behavior |
|---|---|
| Name characters | Letters, digits, and `_` only. |
| Unset variable | The load fails. The error names the variable and, when it can, the field. |
| Empty variable | The value is the empty string. A field can then fail its own check. |
| Literal `${` | Write `$${`. |
| Missing `}` | The load fails with ``unterminated `${` environment reference``. |
| Bad name | The load fails with ``is not a valid environment variable reference``. |
| YAML comment | The proxy leaves a `${...}` in a comment alone. |

An unset variable gives an error of this form:

```text
invalid value at `providers.openai.api_key`: environment variable `OPENAI_API_KEY` is not set (referenced as ${OPENAI_API_KEY})
```

```yaml title="llmproxy.yaml (fragment)"
providers:
  openai:
    api_key: ${OPENAI_API_KEY}
```

Interpolation applies to the config file only. It does not apply to files that
the config names, such as `api_key_file` or `price_list_file`.

## Install script variables

`scripts/install.sh` reads these variables. The binary does not.

| Variable | Default | Description |
|---|---|---|
| `LLM_PROXY_VERSION` | latest release | Release tag to install, for example `v0.7.0`. The `--version` option does the same. |
| `LLM_PROXY_INSTALL_DIR` | `$HOME/.local/bin`; `/usr/local/bin` as root on Linux | Where the script puts `llm-proxy`. |
| `LLM_PROXY_DATA_DIR` | `$HOME/.config/llm-proxy`; `/var/lib/llm-proxy` as root on Linux | Where the script puts the config, the secrets, `service.env`, and `admin-ui-dist`. |
| `LLM_PROXY_DOWNLOAD_URL` | GitHub release URL | Full archive URL. It replaces the computed URL. The script also fetches `<url>.sha256`. |
| `LLM_PROXY_REPO` | `ergonlabs-io/llm-proxy` | GitHub repository for release downloads. |

The service that the script installs starts the proxy through `run.sh` in the
data directory. That file loads `service.env` (`LLMPROXY_ADMIN_TOKEN`) and sets
`LLMPROXY_ADMIN_UI_DIR` before it starts `llm-proxy --config`. See
[Installation](/docs/llm-proxy/getting-started/installation/).

## Variables the proxy does not read

- `RUST_LOG`. Use `-l` or `--log-level`. See [CLI reference](/docs/llm-proxy/reference/cli/).
- Provider key variables such as `OPENAI_API_KEY`. The proxy reads them only if
  your config names them with `${...}`.
- A proxy setting such as `HTTP_PROXY`. The proxy dials providers directly.

## Variables for contributors

These variables are for the test suite and are not part of the product:
`LLM_PROXY_TEST_REDIS` (a Redis URL for the ignored shared-store tests) and
`LLM_PROXY_BIN` (the binary that the install and QA tests run).

## Limitations

- The proxy reads `LLMPROXY_ADMIN_TOKEN` and `LLMPROXY_ADMIN_UI_DIR` once. To
  change them, restart the proxy.
- A `${VAR}` value comes from the environment of the process. A `SIGHUP` reload
  cannot give the running process a new environment.

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.

## Implementation notes

- Admin variables: `ADMIN_TOKEN_ENV_VAR` and `ADMIN_UI_DIR_ENV_VAR` in
  `crates/proxy/src/main.rs`. Gate: `admin_gate` in
  `crates/proxy-admin/src/server.rs`. Tests that pin the `403` text are in
  `crates/proxy-admin/src/server/tests.rs`.
- `keygen` variable: `SECRET_ENV_VAR` in `crates/proxy/src/keygen.rs`.
- Interpolation: `interpolate_env` in
  `crates/proxy-simple-config/src/parse.rs`.
- Install variables: `scripts/install.sh`.
