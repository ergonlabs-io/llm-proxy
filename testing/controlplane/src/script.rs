//! The script a [`crate::server::ScriptedAds`] plays back: an ordered list of
//! responses to send, each gated on the client's next request for the
//! matching `type_url`. This is deliberately dumb — no resource diffing, no
//! version bookkeeping beyond echoing what the script author wrote.

use prost_types::Any;

/// One scripted action. Only `Send` exists in this chunk; later WP-28 work
/// adds things like `DropStream` / `Wait` for reconnect and warming-race
/// scenarios.
#[derive(Debug, Clone)]
pub enum Step {
    /// Send a `DiscoveryResponse` once the client has sent a
    /// `DiscoveryRequest` whose `type_url` matches this step's `type_url`.
    /// Requests of other types arriving first are recorded but otherwise
    /// skipped over while waiting.
    Send {
        type_url: String,
        version_info: String,
        nonce: String,
        resources: Vec<Any>,
    },
}
