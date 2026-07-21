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
  #2's *good* failure mode — a real gap named with a field path, not silently
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

## Deferred: HTTP traffic-replay topology

The docker-compose topology, proxy drivers, and capture/compare engine that
turn a `Scenario` (`scenario.rs`, already parsed) into a pass/fail — replaying
requests against both proxies and diffing status/headers/body/access-log
fields/stats — wait on WP-10 landing llm-proxy's HTTP data plane (today it's
config-loading plus an L4 `tcp_proxy`/TLS data plane only) and a follow-up
llm-proxy Docker image to run it in-topology alongside Envoy's.

Every scenario will run in BOTH config modes: static/file-watch and gRPC xDS
(PLAN.md Part 9.6 anti-rot rule).

Divergences are either failures or pinned with justification in
`docs/envoy-divergences.md`.
