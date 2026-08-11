# llm-proxy

A proxy for LLM inference APIs, written in Rust. One static binary and one YAML
file sit between your applications and your model providers, so token metering,
rate limiting, authentication, failover and access logging happen in one place
instead of in every service that calls a model.

**Status: pre-1.0 and moving quickly.** The data plane serves real traffic and
is covered by 1141 tests. Interfaces may still change between releases, and
there are no backports to earlier tags. Read [What is not built yet](#what-is-not-built-yet)
before you depend on it — that section is deliberately specific.

## What it does today

**Speaks your provider's API.** OpenAI Chat Completions, OpenAI Responses, and
Anthropic Messages. Point an existing client at llm-proxy by changing its base
URL; requests and responses pass through unchanged.

**Streams properly.** Server-sent events are forwarded as they arrive, and the
proxy never injects frames of its own into a stream. An unclean end of stream
stays unclean, because inventing a well-formed ending would hide a real failure
from the client.

**Meters tokens.** Input, output, and separately-priced buckets are read from
provider responses, for streaming and non-streaming requests alike, and land in
the access log.

**Enforces token budgets.** A tenant over its limit gets a 429 with
`x-ratelimit-*` headers before the request reaches a provider. A request already
in flight is never cut short. Limits are keyed to the authenticated tenant, so
changing a header does not buy a fresh quota.

**Authenticates callers.** Virtual keys verified with HMAC-SHA256 in constant
time. Authentication fails closed: with an `auth` block configured, a request
with no recognised credential is refused rather than admitted anonymously.

**Fails over between providers.** A route can name an ordered list; if the
primary fails, the next is tried. Every provider in a chain must speak the same
wire format, and a chain that mixes formats is rejected when the configuration
loads rather than at request time.

**Tells you what it is doing.** Access logs with token counts, time-to-first-token
and time-per-output-token. An admin endpoint serving `/ready`, `/config_dump`,
`/clusters`, `/server_info`, `/stats` and `/stats/prometheus`.

**Survives operations.** Configuration reloads on SIGHUP — and a configuration
that fails to parse leaves the previous one serving, with the error logged
against its exact field path. SIGTERM drains connections instead of dropping
them. Configuration parsing is strict: an unknown or misspelled field is an
error carrying its full dotted path, never a silent no-op.

## Build

Requires a Rust toolchain and `protoc` (`brew install protobuf`, or
`apt install protobuf-compiler`).

```sh
cargo build --workspace
```

## Try it

`examples/llmproxy-ollama.yaml` runs against a local Ollama and needs no API
keys or environment variables:

```sh
# Check the configuration without starting anything.
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml --mode validate
# configuration 'examples/llmproxy-ollama.yaml' OK (1 listener(s), 1 cluster(s), 0 warning(s))

# Serve.
cargo run -p proxy -- --config examples/llmproxy-ollama.yaml
```

Then send it an ordinary OpenAI-shaped request on the port the file lists.
`examples/` also has multi-provider and OpenAI/Anthropic configurations; those
read API keys from the environment.

A minimal configuration is small:

```yaml
version: 0
listen: 0.0.0.0:8080
admin: 127.0.0.1:9901

providers:
  openai:
    api_key: ${OPENAI_API_KEY}

routes:
  - model: "*"
    provider: openai
```

`schema/llmproxy-v0.schema.json` is the authority on every field, and editors
that understand `yaml-language-server` will autocomplete against it.

## Modes

| Command | What it does |
|---|---|
| `--mode serve` | Run the proxy. The default. |
| `--mode validate` | Check a configuration and exit. |
| `--mode keygen` | Print a fresh virtual key and its digest. Needs `--tenant` and `--hmac-secret-file`; touches no configuration file. |

## Documentation

Full documentation lives in `docs/site/` — an Astro Starlight site covering
getting started, the configuration reference, observability and operations.
Build it with `make docs-build`, or run it locally with `make docs-dev`. It is
not published to a public URL yet.

## What is not built yet

Stated plainly, because a feature list without this is not much use:

- **HTTP/1.1 upstream connections are not pooled.** HTTP/2 upstreams are
  multiplexed over one connection; HTTP/1.1 still dials per request.
- **Credential and certificate files are read once at startup.** A rotated key
  or renewed certificate takes effect after a restart or a configuration reload,
  not automatically — nothing watches the files.
- **No credential revocation store.** Virtual keys come from configuration, so
  revoking one means editing the configuration and reloading.
- **Authorization defaults open.** Authentication fails closed, but an
  authenticated tenant with no configured policy may use every model and
  provider.
- **Two metrics are defined but never recorded** — downstream connection counts
  and GenAI token usage — so they never appear in `/stats`. Do not build
  alerting on those two.
- **`--drain-strategy` has no effect.** It is accepted and warns at startup.
- **No performance numbers are published.** The benchmark harness exists; the
  capacity report does not, so treat any performance expectation as unverified.
- **No dynamic configuration**, no Kubernetes controller or CRDs, and no
  realtime WebSocket sessions.

## Contributing and security

Vulnerability reports: see [SECURITY.md](SECURITY.md). Please report privately
rather than in a public issue — note that the private contact is not filled in
yet.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
