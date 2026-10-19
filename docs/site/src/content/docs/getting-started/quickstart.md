---
title: Quickstart
description: "Install llm-proxy, create a starter config, send one request to OpenAI through the proxy, and read the token counts in the access log."
lastUpdated: 2026-10-18
related:
  - getting-started/introduction
  - getting-started/installation
  - reference/cli
  - observability/access-logs
---

# Quickstart

This page takes you from nothing to one served request. You install the
binary, create a starter config, send a request, and read the token counts.
The whole path takes about five minutes.

## Prerequisites

- macOS on Apple Silicon, or Linux on x86-64 or arm64. For Intel macOS or
  another platform, see [Install llm-proxy](../installation/).
- `curl`, `tar`, and `sed`. The installer needs them.
- An OpenAI API key in the `OPENAI_API_KEY` environment variable.

Without an OpenAI key, the starter config also works with a local Ollama at
`127.0.0.1:11434`. If you use Ollama, skip step 3.

## Step 1: Install the binary

Run this from any directory. The command downloads the latest release,
checks its SHA-256 sum, and installs `llm-proxy` in `~/.local/bin`.

```sh
curl -fsSL https://raw.githubusercontent.com/ergonlabs-io/llm-proxy/main/scripts/install.sh | sh -s -- --no-start
```

The `--no-start` option stops the installer from starting a service. Your
foreground run in step 5 then does not compete with a service for the same
port. The installer also writes its own starter config in
`~/.config/llm-proxy`. This quickstart does not use that config.

Make sure the binary is on your `PATH`, and check the version:

```sh
export PATH="$HOME/.local/bin:$PATH"
llm-proxy --version
```

Expected output: one line that starts with `llm-proxy`, for example
`llm-proxy 0.5.0`. For all installer options, upgrade, and source builds, see
[Install llm-proxy](../installation/).

## Step 2: Create a starter config

Run this from the directory where you want the config. It creates the
`llmproxy-home` directory.

```sh
llm-proxy init ./llmproxy-home
cd ./llmproxy-home
```

The command writes `llmproxy.yaml` and `auth-secret`. It refuses to
overwrite existing files. It prints a key that starts with `llmp_`.

**Copy the key now. The proxy shows it once and cannot recover it.**

```sh
export LLMP_KEY=llmp_...
```

The starter config sets `auth.enforce.tenants_without_policy: allow`. With
this setting, the printed key can use every model. The proxy warns about the
setting at startup. Before you give keys to other people, remove it and grant
models per tenant. See [Virtual keys](../../authentication/virtual-keys/).

## Step 3: Choose OpenAI as the provider

The starter config sends every model to a local Ollama. To use OpenAI, edit
`llmproxy.yaml` in two places.

1. Uncomment the `openai` provider and its `api_key` line, so that they read:

   ```yaml
   providers:
     openai:
       api_key: ${OPENAI_API_KEY}
   ```

2. In `routes`, change `provider: ollama` to `provider: openai`.

The config reads the key from the environment. It does not store the key.
Export the key in the shell where you run the proxy:

```sh
export OPENAI_API_KEY=sk-...
```

## Step 4: Validate the config

Run this from the `llmproxy-home` directory. The config names `./auth-secret`
relative to the working directory. From another directory, validation fails
with ``failed to read `./auth-secret`: No such file or directory``.

```sh
llm-proxy --config llmproxy.yaml --mode validate
```

Expected output: some `warning:` lines, then one line that starts with
`configuration 'llmproxy.yaml' OK`.

```text
configuration 'llmproxy.yaml' OK (1 listener(s), 2 cluster(s), 3 warning(s))
```

The starter config gives three warnings. They are about the secret file
(no hot reload), `tenants_without_policy`, and a missing `pricing` rate card.
They do not stop the proxy.

If `OPENAI_API_KEY` is not set in this shell, validation fails:

```text
configuration 'llmproxy.yaml' INVALID
  invalid value at `providers.openai.api_key`: environment variable `OPENAI_API_KEY` is not set (referenced as ${OPENAI_API_KEY})
```

Export the variable and run the command again.

## Step 5: Start the proxy

Run this from the `llmproxy-home` directory, in a terminal that has
`OPENAI_API_KEY` set. The proxy runs in the foreground and listens on
port `53421`. The admin address is `127.0.0.1:53422`.

```sh
llm-proxy --config llmproxy.yaml
```

Expected outcome: log lines that end with a `listener bound` line. Leave the
proxy running. To stop it, press Ctrl+C.

If the port is in use, the proxy fails to bind. Stop the other process, or
change `listen` in `llmproxy.yaml`.

## Step 6: Send one request

Open a second terminal. This command does not need the `llmproxy-home`
directory. It needs the `LLMP_KEY` variable from step 2.

```sh
curl --max-time 60 http://127.0.0.1:53421/v1/chat/completions \
  -H "authorization: Bearer $LLMP_KEY" \
  -H "content-type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}'
```

Expected outcome: an HTTP 200 response with a JSON body from OpenAI. The body
has a `usage` object with token counts.

A `401` response means the key is wrong. Check that `LLMP_KEY` holds the full
key that `init` printed.

## Step 7: Check the token counts

The proxy writes one JSON line for each request to `./llmproxy-access.log`,
in the directory where it runs. Run this in the `llmproxy-home` directory:

```sh
tail -n 1 llmproxy-access.log
```

The line has many fields. These are the fields for token counts. The values
are an illustration. Yours differ.

```json
{"llm_input_tokens":"8","llm_output_tokens":"9","llm_total_tokens":"17",
 "llm_requested_model":"gpt-4o-mini","response_code":"200", ...}
```

`llm_input_tokens` and `llm_output_tokens` come from the `usage` object in the
provider response. They must match the `usage` object in the curl output. Every
field is a JSON string, and a field with no value is `"-"`. For all fields, see
[Access logs](../../observability/access-logs/).

## Next steps

- [Connect your application](../connect-your-application/): point an SDK at
  the proxy.
- [Manage configured virtual keys](../../authentication/managing-secrets/):
  create keys and grant model access.
- [Virtual keys](../../authentication/virtual-keys/): issue keys to other
  people and grant models per tenant.
- [Install llm-proxy](../installation/): run the proxy as a service, upgrade,
  or build from source.
