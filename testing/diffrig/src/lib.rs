//! diffrig library: shared building blocks for WP-26's differential test
//! rig — in-process scriptable upstreams (`upstreams`), the scenario file
//! model (`scenario`), and the config-validation differential engine
//! (`config_diff`, WP-26 chunk B) that runs bootstrap configs through both
//! real Envoy and llm-proxy. The docker-compose HTTP traffic-replay topology
//! that turns a `Scenario` into a pass/fail is deferred until WP-10 lands an
//! HTTP data plane (see `main.rs` and `IMPLEMENTATION_PLAN.md`).

pub mod config_diff;
pub mod harness;
pub mod scenario;
pub mod upstreams;
