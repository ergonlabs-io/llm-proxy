//! diffrig library: shared building blocks for WP-26's differential test
//! rig — in-process scriptable upstreams (`upstreams`) and the scenario file
//! model (`scenario`). The docker-compose topology, proxy drivers, and the
//! capture/compare engine that turn a `Scenario` into a pass/fail come in a
//! later WP-26 chunk (see `main.rs` and `IMPLEMENTATION_PLAN.md`).

pub mod scenario;
pub mod upstreams;
