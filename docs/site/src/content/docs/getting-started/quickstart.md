---
title: Getting started with llm-proxy
summary: Build the llm-proxy binary, validate a config, serve it against an
  OpenAI-compatible provider, and read the access log line it writes for the
  request.
last_updated: 2026-10-13
related:
  - ../getting-started/introduction/
  - ../configuration/configuration-file/
---

# Getting started

This guide has two paths. [Install a release](#install-a-release) gives you a
running service with a starter config. [Build from source](#prerequisites)
takes you from a checkout to a served request. The build commands below were
run against this repository; the exact output follows each one.

## Install a release

`scripts/install.sh` downloads the latest release for macOS (Apple Silicon) or
Linux (x86_64 or arm64), checks its SHA-256 sum, and starts it as a service.
Intel macOS has no prebuilt release; build from source.

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh
```

As a normal user, the script installs `llm-proxy` and `llm-capture-agent` in
`~/.local/bin`, and the data in `~/.config/llm-proxy`. As root on Linux, it
uses `/usr/local/bin` and `/var/lib/llm-proxy`. The service is a launchd agent
on macOS, a systemd user unit on Linux, or a system unit when you run as root.
Without systemd, the proxy runs as a background process and does not start at
boot.

The script runs `llm-proxy init` on the data directory, creates an admin token
in `service.env`, and prints the admin UI address, the proxy API address, the
admin token, and an API key. The token and the key are shown once. Run the
script again to upgrade the binary. An upgrade keeps the existing config,
secret, and token.

| Option | Default | What it does |
|---|---|---|
| `--version TAG` | latest release | Install this release, for example `v0.3.1`. |
| `--port N` | `53421` | Proxy port. Applies to a new config only. |
| `--admin-port N` | `53422` | Admin and UI port on `127.0.0.1`. Applies to a new config only. |
| `--admin-address HOST:PORT` | `127.0.0.1:53422` | Admin and UI address, for example `0.0.0.0:53422`. Do not use with `--admin-port`. |
| `--no-start` | off | Install the binary and the config. Do not start. |
| `--no-service` | off | Start a background process instead of a service. |
| `--uninstall` | off | Stop and remove the service and the binaries. Keep the data. |
| `--purge` | off | With `--uninstall`, also delete the data directory. |

**The admin API is plain HTTP.** With `--admin-address 0.0.0.0:53422`, the
admin token crosses the network unencrypted. Use it only on a network you
trust. Source: `scripts/install.sh` usage block.

### Create a starter config without the script

`llm-proxy init [DIRECTORY]` writes the same starter config and secret. See
[CLI reference](../../reference/cli/) for the files it creates.

```sh
llm-proxy init ./llmproxy-home
cd ./llmproxy-home
llm-proxy --config llmproxy.yaml
```

Run the proxy from that directory. The config names `./auth-secret` relative
to the working directory. From another directory, validation fails with
`failed to read ./auth-secret: No such file or directory`.

### Use OpenAI instead of Ollama

The starter config sends every model to a local Ollama. To use OpenAI, edit
`llmproxy.yaml`. Uncomment the `openai` provider, refer to your key through
an environment variable, and point the route at it:

```yaml
providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes:
  - model: "*"
    provider: openai
```

Start the proxy with the key in its environment. Then send a streaming request
with the key that `init` printed:

```sh
export OPENAI_API_KEY=sk-...
llm-proxy --config llmproxy.yaml
```

```sh
curl -N http://127.0.0.1:53421/v1/chat/completions \
  -H "authorization: Bearer llmp_<the key init printed>" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"hi"}]}'
```

The response streams back as `data:` lines. The proxy writes one access log
line per request to `./llmproxy-access.log`.

The starter config sets `auth.enforce.tenants_without_policy: allow`, so the
printed key can use every model without a stored tenant policy. The proxy
warns about this at startup. Before you issue keys to other people, grant
models per tenant with `PUT /tenants/{id}/policy` and remove the `enforce`
block. See [Virtual keys](../../authentication/virtual-keys/).

## Prerequisites

Install `protoc` before you build. llm-proxy compiles bundled protobuf
definitions at build time, in the `proxy-api` crate.

```sh
brew install protobuf        # macOS
apt install protobuf-compiler  # Debian/Ubuntu
```

## Step 1: Build the binary

Run the debug build from the repository root.

```sh
cargo build -p proxy
```

This produces `target/debug/llm-proxy`. `make build` builds the whole
workspace instead, which is slower and not required just to run the proxy.

## Step 2: Check the CLI

Run `--help` to see the full flag list.

```sh
./target/debug/llm-proxy --help
```

`serve` is the default mode. `validate` takes a config and exits without
binding a listener, reporting whether the config loads. `keygen` generates a
virtual key for downstream authentication and needs no config at all — see
[Configuration file reference](../../configuration/configuration-file/).

## Step 3: Validate a config

`--config` takes a path to a config file
(`schema/llmproxy-v0.schema.json`). `examples/llmproxy-ollama.yaml` is the
smallest example in the repository: one provider, one route, no API key.

```sh
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml --mode validate
```

```text
configuration 'examples/llmproxy-ollama.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))
```

## Step 4: Serve it and send a request

`examples/llmproxy-ollama.yaml` points `base_url` at `http://ollama.internal:11434`
— a placeholder host, so it validates but has nothing to connect to. To serve
a request for real, point `base_url` at a provider you can actually reach: a
local Ollama, vLLM, or any other OpenAI-compatible server. The config below
is that same example with the placeholder host, listener, and admin address
replaced by reachable local addresses:

```yaml
version: 0

listen: 127.0.0.1:18080
admin: 127.0.0.1:19901

providers:
  ollama:
    base_url: http://127.0.0.1:18999

routes:
  - model: "*"
    provider: ollama

observability:
  access_logs:
    output: /tmp/llmproxy-access.log
    format: json
```

Save it as `llmproxy-local.yaml`, start your OpenAI-compatible server on
`127.0.0.1:18999`, then start llm-proxy:

```sh
./target/debug/llm-proxy --config llmproxy-local.yaml --mode serve
```

```text
INFO llm_proxy: admin server listening addr=127.0.0.1:19901
INFO llm_proxy: llm-proxy started, waiting for SIGTERM/SIGINT/SIGHUP workers=8 ... listeners=llmproxy_listener@127.0.0.1:18080
INFO proxy_core::listener: listener bound listener=llmproxy_listener addr=127.0.0.1:18080
```

Check readiness on the admin port, then send a chat-completion request to the
proxy's listener:

```sh
curl -s http://127.0.0.1:19901/ready
curl -s -i -X POST http://127.0.0.1:18080/v1/chat/completions \
  -H "content-type: application/json" \
  -d '{"model":"llama3.1:8b","messages":[{"role":"user","content":"hi"}]}'
```

```text
LIVE
HTTP/1.1 200 OK
content-type: application/json
content-length: 283

{"id": "chatcmpl-mock1", "object": "chat.completion", "model": "llama3.1:8b",
 "choices": [{"index": 0, "message": {"role": "assistant",
 "content": "Hello from the mock provider."}, "finish_reason": "stop"}],
 "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18}}
```

(The response body above came from a minimal local test server used to write
this guide, not a real model — the point is the round trip, not the reply.
Against a real Ollama or vLLM instance the shape is the same.)

## Step 5: Read the access log

With `observability.access_logs` configured, llm-proxy writes one JSON line
per completed request. This is the line the request above produced:

```json
{"authority":"127.0.0.1:48080","bytes_received":"67","bytes_sent":"283",
 "duration_ms":"13","llm_cache_creation_tokens":"0","llm_cached_tokens":"0",
 "llm_input_tokens":"12","llm_key_id":"-","llm_list_cost_nanodollars":"-",
 "llm_max_stall_ms":"-","llm_output_tokens":"6","llm_rate_card_version":"-",
 "llm_requested_model":"llama3.1:8b","llm_response_chunks":"1",
 "llm_selected_model":"llama3.1:8b","llm_tenant":"-","llm_total_tokens":"18",
 "llm_tpot_ms":"2.245","llm_ttft_ms":"0","llm_user_id":"-","method":"POST",
 "path":"/v1/chat/completions","protocol":"HTTP/1.1",
 "request_id":"b856029f-798f-4925-a3bd-3e89e80bef1d","response_code":"200",
 "response_flags":"-","selected_provider":"provider:ollama",
 "start_time":"2026-10-13T22:44:32.563Z","upstream_host":"127.0.0.1:48999"}
```

`llm_input_tokens` and `llm_output_tokens` are the counts llm-proxy extracted
from the provider's own `usage` block — 12 and 6 here, matching the response
above exactly. `llm_tenant`, `llm_key_id`, and `llm_user_id` are `"-"`
because this config has no `auth` block. `llm_list_cost_nanodollars` and
`llm_rate_card_version` are `"-"` in this run, which configures no pricing.
(The line was produced with ports `48080` and `48999`; yours show the ports
from your config.) Every field renders as a JSON string, including numbers; a
field with no value (`llm_max_stall_ms` on a single-chunk response) renders
as `"-"`, not `null` or `0`. If `observability.access_logs` is omitted, no
access log is written at all.

## Two likely failure points

**A provider sets both `api_key` and `api_key_file`.** llm-proxy refuses to
load the config:

```text
configuration 'llmproxy-local.yaml' INVALID
  invalid value at `providers.ollama`: set either api_key or api_key_file, not both
```

Pick one.

**A `fallbacks` entry speaks a different wire dialect than the route's
primary provider** (for example, an `anthropic` fallback under an `openai`
primary). llm-proxy refuses to load the config and prints:

```text
invalid value at `routes[0].fallbacks[0]`: `anthropic` speaks the
`anthropic` dialect, but this route's primary provider `openai` speaks
`openai` -- a `openai`-shaped request body is not valid for a `anthropic`
upstream, and its response would be parsed for tokens by the wrong
dialect's parser (silently wrong billing numbers); cross-dialect fallback
needs request/response translation, which is not built yet.
Same-dialect fallbacks (e.g. openai -> an openai-compatible provider) are
supported.
```

Same-dialect fallbacks (`openai` falling back to another `openai`-compatible
provider) are supported; this is a load-time error, not a warning.
