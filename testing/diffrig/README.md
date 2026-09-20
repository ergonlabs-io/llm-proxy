# diffrig (WP-26)

Side-by-side differential test harness against the pinned real Envoy image.

## Landed: config-validation differential (WP-26 chunk B)

`cargo run -p diffrig -- config-validate-diff` runs a curated set of Envoy
bootstrap configs (`configs/`) through both real Envoy's `--mode validate`
(inside a throwaway `docker run --rm` container) and llm-proxy's own
`--mode validate`, and classifies each as one of:

- `agree-accept` — both accept.
- `agree-reject` — both reject.
- `gap-we-reject` — Envoy accepts, we reject: a known compat gap (ground rule
  #2's _good_ failure mode — a real gap named with a field path, not silently
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

## Side-by-side Envoy HTTP replay/capture topology (increment 1)

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
(PLAN.md Part 9.6 anti-rot rule).

Divergences are either failures or pinned with justification in
`internal-docs/envoy-divergences.md`.
