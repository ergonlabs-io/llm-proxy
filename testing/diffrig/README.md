# diffrig

Side-by-side differential test harness against the pinned real Envoy image.

## Landed: config-validation differential

`cargo run -p diffrig -- config-validate-diff` runs a curated set of Envoy
bootstrap configs (`configs/`) through both real Envoy's `--mode validate`
(inside a throwaway `docker run --rm` container) and llm-proxy's own
`--mode validate`, and classifies each as one of:

- `agree-accept` — both accept.
- `agree-reject` — both reject.
- `gap-we-reject` — Envoy accepts, we reject: a known compat gap (strict mode's _good_
  failure mode — a real gap named with a field path, not silently
  dropped).
- `BUG-we-accept` — Envoy rejects, we accept: we are dangerously lenient where
  Envoy is strict. A P1 finding; the CLI exits nonzero if any show up.

Pinned Envoy image: `envoyproxy/envoy:v1.38.0` (see `config_diff::ENVOY_IMAGE`
— chosen because it pulls cleanly; other v1.38.x tags weren't needed).

Requires `cargo build -p proxy` first (to produce the `llm-proxy` binary) and
a reachable docker daemon. The docker-backed tests in `config_diff.rs` are
`#[ignore]`d and additionally skip (not fail) if `DIFFRIG_DOCKER` isn't set or
the daemon is unreachable, so `cargo test -p diffrig` stays green without
docker and `make ci` (no docker daemon there) is unaffected. Run them
explicitly with `cargo test -p diffrig -- --ignored` (with `DIFFRIG_DOCKER=1`
and docker up).

## Live provider smoke tests

`make smoke-live` runs `tests/live_smoke.rs`: the real binary, loaded with a
`--config` dialect file, sends a minimal request to each real provider. Every
other test runs against mocks, so this is where a provider-side wire or auth
change shows up. Each test is `#[ignore]`d, so `make tq` and `make ci` never
run it.

| Provider | Variables | Tests |
|---|---|---|
| OpenRouter | `OPENROUTER_API_KEY`; optional `OPENROUTER_SMOKE_MODEL` | non-streaming, streaming, bad key (needs no key) |
| Vertex AI (Claude) | `VERTEX_PROJECT`, `VERTEX_ACCESS_TOKEN`; optional `VERTEX_LOCATION` (default `us-east5`), `VERTEX_SMOKE_MODEL` | non-streaming |
| Amazon Bedrock (Claude) | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`; optional `AWS_SESSION_TOKEN`, `BEDROCK_SMOKE_MODEL` | non-streaming |
| OpenAI | `OPENAI_API_KEY` | non-streaming, streaming |
| Anthropic | `ANTHROPIC_API_KEY` | non-streaming, streaming |

```sh
OPENROUTER_API_KEY=... make smoke-live
```

- **Cost.** OpenRouter uses a free model (`:free`), so it costs nothing. Free
  models are retired without notice; when the default one returns 404 or 429,
  pick a current one from `https://openrouter.ai/api/v1/models` and set
  `OPENROUTER_SMOKE_MODEL`. The other providers bill; every request uses a
  one-line prompt and `max_tokens` of 24 or less.
- **What is asserted.** A 200, non-empty content, and a JSON access-log line
  that names the provider cluster (`selected_provider`), shows an upstream was
  dialled (`upstream_host`), and carries the usage the proxy extracted
  (`llm_input_tokens`, `llm_output_tokens`). The bad-key test asserts the
  provider's own 401 reaches the client, not a local 5xx.
- **Skips.** A test whose variables are unset prints
  `LIVE-SKIP live_smoke::<test>: <VAR> is not set` and passes. Read those
  lines before you treat a run as coverage. `LIVE_SMOKE_STRICT=1` turns every
  skip into a failure.
- **CI.** `.github/workflows/live-smoke.yml` runs the target weekly and on
  manual dispatch, never on pull requests. It reads the variables above from
  repository secrets of the same names and copies the `LIVE-SKIP` lines to
  the job summary.
- **Never run live yet:** the Vertex and Bedrock tests. Treat their first
  failure as a finding, not as flakiness.

## Landed: hermetic reload-under-LLM-traffic topology

`cargo test -p diffrig --test swap_under_load` drives the real proxy against
two paced, in-process OpenAI-shaped upstreams over loopback. While concurrent
SSE and non-streaming traffic is active, it rewrites the bootstrap and sends
SIGHUP. The test proves that streams were in flight before the reload, the new
upstream serves post-reload traffic, and every stream — especially the cohort
that crossed the reload boundary — reaches `data: [DONE]`. A clean EOF is not
treated as success. It is deterministic, hermetic, and needs neither Docker,
xDS, nor provider credentials.

## Landed: rename-churn acceptance drill

`cargo test -p diffrig --test rename_churn -- --ignored` runs eight listener/cluster
renames while an explicit 5,000-request/second open-loop load is active, then sends
a malformed generation and proves last-good serving remains live. It is an
acceptance drill, not a passing CI test: dedicated capacity-host execution is
required, and broader Envoy side-by-side comparison remains open.

### Capacity-host setup

On a fresh Ubuntu host, run the repository setup script as root before either
of the host-only drills:

```text
sudo scripts/setup-test-machine.sh --user "$USER"
```

It installs the Rust/native/protobuf build prerequisites, verifies Docker, and
sets a `65535` login-session descriptor limit. Log out and back in before the
rename-churn run so the new limit applies. Docker is intentionally only checked
by default; use `--install-docker` when the host does not already provide it.

The setup script does not make a 2-vCPU machine a valid 5k-rps host. The
rename-churn test's `driver_saturated` assertion remains the authority: a
saturated driver is an invalid capacity result, not a proxy failure.

## Side-by-side Envoy HTTP replay/capture topology

`access_log_diff` defines normalized HTTP captures and field-level comparison.
`replay` replays a parsed `Scenario` against two already-running targets:

```text
cargo run -p diffrig -- replay --scenario testing/diffrig/scenarios/echo-basic.yaml \
  --left 127.0.0.1:10000 --right 127.0.0.1:10001
```

Optional `--left-log` and `--right-log` paths include normalized JSON access-log
fields in the comparison. `replay-managed` now owns target lifecycle for one
llm-proxy process and one Docker Envoy process:

```text
cargo run -p diffrig -- replay-managed --scenario testing/diffrig/scenarios/echo-basic.yaml \
  --proxy-bin target/debug/llm-proxy \
  --proxy-config proxy.yaml --envoy-config envoy.yaml \
  --left 127.0.0.1:10000 --right 127.0.0.1:10001 \
  --proxy-log proxy.log --envoy-log envoy.log
```

The configs are separate intentionally: each target must bind a distinct
listener port while receiving the same request script.

Every scenario will run in BOTH config modes: static/file-watch and gRPC xDS
(architecture.md §12.3 rule 6, the anti-rot rule).

Divergences are either failures or pinned with justification in
`internal-docs/envoy-divergences.md`.
