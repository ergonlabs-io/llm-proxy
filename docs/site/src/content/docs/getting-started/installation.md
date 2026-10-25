---
title: Install llm-proxy
description: "Install llm-proxy from a release archive, a container image, or source. Send a first request in about five minutes, then run it as a service."
lastUpdated: 2026-10-25
related:
  - getting-started/quickstart
  - reference/cli
  - operations/running-in-production
  - operations/kubernetes
---

This page has two parts. The quick start gets you to one proxied request in
about five minutes, with no authentication. The service section installs the
proxy with a script and runs it in the background.

## Quick start

You need a provider API key, or a local Ollama. The quick start uses one
OpenAI-compatible provider and sends every model to it. The config file has
no `auth` section, so the proxy does not check callers. Run it on your own
machine only.

### Step 1: Get llm-proxy

Choose one option.

#### Option A: Release binary

Release archives exist for Linux x86-64, Linux arm64, and macOS Apple
silicon. Intel macOS and Windows have no archive. Use option C on those
platforms.

:::caution
Releases before v0.7.0 have no Linux arm64 archive. On Linux arm64 the
download fails for those releases. Use option C instead.
:::

Download and unpack the archive. It holds `llm-proxy` and `admin-ui-dist/`.

```sh
os=$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -fsSLO "https://github.com/ergonlabs-io/llm-proxy/releases/latest/download/llm-proxy-$os-$arch.tar.gz"
tar -xzf "llm-proxy-$os-$arch.tar.gz"
./llm-proxy --version
```

Then download the quick-start config:

```sh
curl -fsSLO https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/examples/llmproxy-quickstart.yaml
```

Each archive has a `.sha256` file next to it on the release page. Use it to
check the download.

#### Option B: Container image

:::caution
The image is published from v0.7.0.
:::

The image is `ghcr.io/ergonlabs-io/llm-proxy`. It has two kinds of tag: the
version without `v` (for example `0.7.0`) and `latest`. A pre-release does
not move `latest`. The image supports `linux/amd64` and `linux/arm64`.

The image runs `llm-proxy --config /etc/llm-proxy/llmproxy.yaml` as user
`65532`. It exposes ports `8080` and `9901`. It has no shell.

Download the container config. It listens on `0.0.0.0:8080` inside the
container. The admin address stays on `127.0.0.1`.

```sh
curl -fsSLO https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/examples/llmproxy-quickstart-container.yaml
```

Set the two variables from step 2. Then run the container:

```sh
docker run --rm -p 127.0.0.1:8080:8080 -e UPSTREAM_BASE_URL -e UPSTREAM_API_KEY \
  -v "$PWD/llmproxy-quickstart-container.yaml:/etc/llm-proxy/llmproxy.yaml:ro" \
  ghcr.io/ergonlabs-io/llm-proxy:latest
```

When the container runs, go to step 4. Publish the port on `127.0.0.1` only, as the command does. The config has no
authentication. For Ollama on the Docker host, set
`UPSTREAM_BASE_URL=http://host.docker.internal:11434`. For Kubernetes, see
[Kubernetes and Helm](/docs/llm-proxy/operations/kubernetes/).

#### Option C: Build from source

You need [rustup](https://rustup.rs), a C toolchain, and `protoc`. The file
`rust-toolchain.toml` pins Rust 1.99.0, and `rustup` installs that version on
the first build. Rust needs the C toolchain to link. Without it, the build
fails with ``error: linker `cc` not found``. Install the C toolchain and
`protoc` first:

```sh
xcode-select --install; brew install protobuf        # macOS
sudo apt install build-essential protobuf-compiler   # Debian and Ubuntu
```

Then build. A clean release build takes a few minutes.

```sh
git clone https://github.com/ergonlabs-io/llm-proxy.git
cd llm-proxy
cargo build --release -p proxy
```

The binary is `target/release/llm-proxy`. The config is
`examples/llmproxy-quickstart.yaml` in the checkout. Run the commands below
from the checkout, and use `./target/release/llm-proxy` in place of
`./llm-proxy`.

### Step 2: Set the provider

The config reads two environment variables. Set both in the terminal where
you run the proxy.

```sh
export UPSTREAM_BASE_URL=https://api.openai.com   # scheme, host and port only, no /v1
export UPSTREAM_API_KEY=sk-...                     # your provider key
```

Do not add `/v1` to `UPSTREAM_BASE_URL`. The OpenAI SDK variable
`OPENAI_BASE_URL` includes `/v1`, so this config uses its own names.

For a local Ollama, set `UPSTREAM_BASE_URL=http://127.0.0.1:11434`. Set
`UPSTREAM_API_KEY` to any value. Ollama ignores it.

### Step 3: Validate and start the proxy

Validate the config:

```sh
./llm-proxy --config llmproxy-quickstart.yaml --mode validate
```

Expected output:

```text
configuration 'llmproxy-quickstart.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

Start the proxy. It runs in the foreground. Press Ctrl+C to stop it.

```sh
./llm-proxy --config llmproxy-quickstart.yaml
```

The proxy listens on `127.0.0.1:8080`. The admin address is
`127.0.0.1:9901`. To check readiness, run
`curl http://127.0.0.1:9901/ready` in a second terminal.

The start-up log has some lines that you can ignore in the quick start:

- On macOS, one `failed to pin workers to cores` warning. macOS does not
  let a process pin threads to cores, so the workers run unpinned.
- A warning that `LLMPROXY_ADMIN_TOKEN` is not set. The admin API then
  refuses writes.
- An info line `admin UI not loaded`. The admin UI is off.

If validation fails, the message names the field. Two common errors:

```text
invalid value at `providers.upstream.base_url`: environment variable `UPSTREAM_BASE_URL` is not set (referenced as ${UPSTREAM_BASE_URL})
```

Export the variable in the same terminal and run the command again.

```text
invalid value at `providers.upstream.base_url`: `https://api.openai.com/v1` has a path prefix; v0 does not support base_url paths
```

Remove `/v1` from `UPSTREAM_BASE_URL`.

### Step 4: Send a request

Open a second terminal. Use a model name that your provider serves. For
Ollama, use a model that you have pulled.

```sh
curl --max-time 60 http://127.0.0.1:8080/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

The request needs no `Authorization` header. The proxy sends
`UPSTREAM_API_KEY` to the provider as `Authorization: Bearer`.

Expected outcome: an HTTP 200 response with a JSON body from the provider.
The proxy also prints one JSON access-log line on standard output. The line
has the fields `llm_input_tokens`, `llm_output_tokens`, and
`llm_total_tokens`. Each value is a string.

### Next steps

- Add virtual keys before you expose the proxy. See
  [Virtual keys](/docs/llm-proxy/authentication/virtual-keys/).
- Run `llm-proxy init` for a starter config with authentication and an admin
  UI. See [Quickstart](/docs/llm-proxy/getting-started/quickstart/).
- Point your application at the proxy. See
  [Connect your application](/docs/llm-proxy/getting-started/connect-your-application/).
- Run the proxy as a service. Continue with the next section.

## Install as a service

The install script installs the binary and starts the proxy as a service.
Intel macOS has no prebuilt release. Build from source on that platform.

### At a glance

- Prebuilt platforms: Linux x86-64, Linux arm64, and macOS Apple Silicon.
- Default binary path: `~/.local/bin/llm-proxy`.
- Default data directory: `~/.config/llm-proxy`.
- The script refuses to continue if the SHA-256 sum of the archive does not
  match.

:::caution
Releases before v0.7.0 have no Linux arm64 archive. On Linux arm64 the script
asks for `llm-proxy-linux-arm64.tar.gz`, and for those releases the download
fails with `There may be no linux/arm64 build in this release.`
:::

### Install with the script

Run the script from any directory:

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh
```

The script needs `curl`, `tar`, `od`, and `sed`. It does these steps:

1. It downloads the release archive and its `.sha256` file.
2. It stops if the sums do not match.
3. It runs the new binary with `--version`. It stops if the binary does not run.
4. It installs `llm-proxy`.
5. It runs `llm-proxy init` on the data directory, if no `llmproxy.yaml` is
   there.
6. It creates an admin token in `service.env`, if that file does not exist.
7. It validates the config, starts the service, and waits until `/ready`
   answers.

The script then prints the admin UI address, the proxy API address, and the
config path. For a new install, it also prints the admin token and an API
key. The token and the key are shown once.

To pass options, add them after `sh -s --`:

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh -s -- --version v0.5.0 --port 8080
```

#### Options

| Option | Default | What it does |
|---|---|---|
| `--version TAG` | latest release | Install this release, for example `v0.3.1`. |
| `--port N` | `53421` | Set the proxy port. Applies to a new config only. |
| `--admin-port N` | `53422` | Set the admin and UI port on `127.0.0.1`. Applies to a new config only. |
| `--admin-address HOST:PORT` | `127.0.0.1:53422` | Set the admin and UI address, for example `0.0.0.0:53422`. Applies to a new config only. Do not use with `--admin-port`. |
| `--no-start` | off | Install the binary and the config. Do not start anything. |
| `--no-service` | off | Start a background process instead of a service. |
| `--uninstall` | off | Stop and remove the service and the binaries. Keep the data. |
| `--purge` | off | With `--uninstall`, also delete the data directory. |
| `-h`, `--help` | | Print the options. |

The script reads these environment variables:

| Variable | What it does |
|---|---|
| `LLM_PROXY_VERSION` | Same as `--version`. |
| `LLM_PROXY_INSTALL_DIR` | Directory for the binaries. |
| `LLM_PROXY_DATA_DIR` | Directory for the config, secret, and token. |
| `LLM_PROXY_DOWNLOAD_URL` | URL of a release archive. The script also fetches `<url>.sha256`. |
| `LLM_PROXY_REPO` | GitHub repository to download from. Default: `ergonlabs-io/llm-proxy`. |

If a config already exists in the data directory, the script keeps it and
ignores `--port`, `--admin-port`, and `--admin-address`. It prints a warning.
Edit the config instead.

**Warning: the admin API is plain HTTP.** With `--admin-address
0.0.0.0:53422`, the admin token crosses the network unencrypted. Anyone who can
reach the port can read `/config_dump`, `/stats`, and `/clusters` without the
token. Use this address only on a network you trust. The script prints this
warning on every run.

#### Where the files go

| Item | Normal user | Root on Linux |
|---|---|---|
| Binary | `~/.local/bin/llm-proxy` | `/usr/local/bin/llm-proxy` |
| Data directory | `~/.config/llm-proxy` | `/var/lib/llm-proxy` |

The data directory holds `llmproxy.yaml`, `auth-secret`, `service.env`, and
`run.sh`. The service starts the proxy through `run.sh`. That file changes to
the data directory first, because the starter config names `./auth-secret` and
`./llmproxy-access.log` relative to the working directory. If `~/.local/bin`
is not on your `PATH`, the script tells you to add it.

On macOS, you must run the script as your own user. It refuses to run as root.

#### The service on each platform

| Platform | Service | Logs |
|---|---|---|
| macOS | A launchd agent, label `io.ergonlabs.llm-proxy` | `llm-proxy.log` in the data directory |
| Linux, normal user | A systemd user unit, `llm-proxy` | `journalctl --user -u llm-proxy` |
| Linux, root | A systemd system unit that runs as the `llm-proxy` system user | `journalctl -u llm-proxy` |
| No systemd, or `--no-service` | A background process | `llm-proxy.log` in the data directory |

A background process does not start at boot. To restart it, run the script
again.

On Linux, a user unit stops at logout unless the account lingers. The script
runs `loginctl enable-linger` for you. If that fails, it prints the command to
run with `sudo`.

To restart after a config change, run one of these commands:

```sh
launchctl kickstart -k gui/$(id -u)/io.ergonlabs.llm-proxy   # macOS
systemctl --user restart llm-proxy                           # Linux, normal user
sudo systemctl restart llm-proxy                             # Linux, root
```

#### Upgrade

Run the same install command again. The script replaces the binary and keeps
the existing config, secret, and admin token. It restarts the service.

#### Uninstall

Run the script with `--uninstall`. It stops the service and removes the
service file and the binaries. It keeps the data directory.

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh -s -- --uninstall
```

Add `--purge` to also delete the data directory. This deletes your config and
your authentication secret. Keys that you issued stop working.

## Build from source

Option C of the quick start shows the build. This section adds a debug build
and the `init` command.

Run the build from the repository root:

```sh
cargo build -p proxy
```

The binary is `target/debug/llm-proxy`. For an optimized binary, add
`--release`. The binary is then `target/release/llm-proxy`.

```sh
./target/release/llm-proxy --version
```

A source build does not start a service. To create a config with
authentication, run `./target/release/llm-proxy init ./llmproxy-home`. Then
continue at step 3 of the
[Quickstart](/docs/llm-proxy/getting-started/quickstart/), with this binary
path in place of `llm-proxy`. For the command-line flags, see the
[CLI reference](/docs/llm-proxy/reference/cli/).

## Verify the install

Print the version. Then validate a config file.

```sh
llm-proxy --version
llm-proxy --config ./llmproxy.yaml --mode validate
```

For a valid file, the second command prints
`configuration '...' OK (N listener(s), N cluster(s), N warning(s))`. A load
error names the dotted path of the field at fault.

## Limitations

- No prebuilt release for Intel macOS or Windows.
- For Kubernetes, use the container image and the Helm chart instead of an
  archive. See [Kubernetes and Helm](/docs/llm-proxy/operations/kubernetes/).

See [Limitations](/docs/llm-proxy/help/limitations/) for the full list.
