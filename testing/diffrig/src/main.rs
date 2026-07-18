//! Differential test rig (WP-26): runs llm-proxy and the pinned Envoy image
//! side-by-side against shared scriptable upstreams, replays scenarios, and
//! asserts behavioral equality (status, headers modulo allowlist, body,
//! access-log fields, stats deltas, upstream-observed attempt sequences).
//!
//! TODO(WP-26): docker-compose topology management, scenario format (bootstrap
//! config + request script + upstream script), capture/compare engine,
//! deterministic vs chaos modes, `envoy-divergences.md` pinning. Every scenario
//! runs in BOTH config modes: static/file-watch and gRPC xDS (PLAN.md Part 9.6).

fn main() -> anyhow::Result<()> {
    anyhow::bail!("diffrig scaffold: implementation is WP-26 (see IMPLEMENTATION_PLAN.md)")
}
