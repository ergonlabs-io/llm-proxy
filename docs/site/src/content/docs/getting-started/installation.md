---
title: Install llm-proxy
description: "Install llm-proxy with the install script or from source, run it as a service, and upgrade or remove it."
lastUpdated: 2026-10-18
related:
  - getting-started/quickstart
  - reference/cli
  - operations/running-in-production
---

# Install llm-proxy

You can install llm-proxy with the install script or build it from source.
The script supports macOS on Apple Silicon and Linux on x86-64 or arm64. It
installs the binary and starts the proxy as a service. Intel macOS has no
prebuilt release. Build from source on that platform.

## Install with the script

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

### Options

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

### Where the files go

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

### The service on each platform

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

### Upgrade

Run the same install command again. The script replaces the binary and keeps
the existing config, secret, and admin token. It restarts the service.

### Uninstall

Run the script with `--uninstall`. It stops the service and removes the
service file and the binaries. It keeps the data directory.

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh -s -- --uninstall
```

Add `--purge` to also delete the data directory. This deletes your config and
your authentication secret. Keys that you issued stop working.

## Build from source

Install a Rust toolchain and `protoc`. The `proxy-api` crate compiles bundled
protobuf definitions at build time, so the build fails without `protoc`.

```sh
brew install protobuf          # macOS
apt install protobuf-compiler  # Debian and Ubuntu
```

Run the build from the repository root:

```sh
git clone https://github.com/ergonlabs-io/llm-proxy.git
cd llm-proxy
cargo build -p proxy
```

The binary is `target/debug/llm-proxy`. For an optimized binary, add
`--release`. The binary is then `target/release/llm-proxy`.

```sh
./target/debug/llm-proxy --version
```

A source build does not start a service. To create a config, run
`./target/debug/llm-proxy init ./llmproxy-home`. Then continue at step 3 of the
[Quickstart](../quickstart/), with this binary path in place of `llm-proxy`.
For the command-line flags, see the [CLI reference](../../reference/cli/).
