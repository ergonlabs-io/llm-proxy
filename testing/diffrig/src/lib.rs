//! diffrig library: shared building blocks for WP-26's differential test
//! rig — in-process scriptable upstreams (`upstreams`), the scenario file
//! model (`scenario`), and the config-validation differential engine
//! (`config_diff`, WP-26 chunk B) that runs bootstrap configs through both
//! real Envoy and llm-proxy. `tests/swap_under_load.rs` is the first hermetic
//! HTTP topology: paced LLM SSE traffic continues across a real SIGHUP reload
//! and every terminal frame is asserted. The broader Envoy side-by-side
//! request replay/capture topology remains deferred (see `main.rs`).

pub mod config_diff;
pub mod harness;
pub mod scenario;
pub mod upstreams;
