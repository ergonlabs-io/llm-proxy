//! The `llm-proxy` binary: CLI parsing, runtime wiring, main().
//!
//! TODO(WP-06): Envoy-compatible CLI (`-c`, `--concurrency`, `--mode validate`,
//! `--log-level`, `--service-node`, `--service-cluster`; `--base-id` parsed and
//! warned), control + worker runtime bootstrap, config propagation, drain manager,
//! SIGTERM graceful shutdown, SO_REUSEPORT-overlap restart (PLAN.md Part 9.2).

fn main() {
    eprintln!(
        "llm-proxy: scaffold only — implementation starts at WP-01..WP-06 \
         (see IMPLEMENTATION_PLAN.md)"
    );
    std::process::exit(2);
}
