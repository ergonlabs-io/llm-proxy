//! The script a [`crate::server::ScriptedAds`] plays back: an ordered list of
//! steps, played out against a **cursor shared across every stream the
//! server accepts** (see `ScriptedAds::next_step`). This is deliberately
//! dumb — no resource diffing, no version bookkeeping beyond echoing what
//! the script author wrote.

use std::time::Duration;

use prost_types::Any;

/// One scripted action.
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
    /// Send a `DiscoveryResponse` without waiting for another request. Real
    /// control planes may push an update at any time after a subscription is
    /// established; requiring an ACK to trigger every later update makes it
    /// impossible to model ordinary SotW churn.
    Push {
        type_url: String,
        version_info: String,
        nonce: String,
        resources: Vec<Any>,
    },
    /// Wait until the client sends a request for `type_url`, recording it,
    /// without sending a response. This models control-plane ordering such as
    /// "do not send the next generation until the previous one was ACKed".
    WaitForRequest { type_url: String },
    /// Wait for an ACK of one exact response. Requests for other resource
    /// types, initial subscriptions, and ACKs carrying another nonce remain
    /// recorded but do not advance the script.
    WaitForAck {
        type_url: String,
        version_info: String,
        response_nonce: String,
    },
    /// Wait for a NACK of one exact response. `version_info` is deliberately
    /// not matched: SotW NACKs carry the last accepted version, not the
    /// rejected response's version.
    WaitForNack {
        type_url: String,
        response_nonce: String,
    },
    /// End the current `StreamAggregatedResources` stream from the server
    /// side, the way a control plane going away does. The next stream the
    /// server accepts resumes the script at the step after this one — it
    /// does not replay from the start, which is what makes a
    /// reconnect-resync scenario expressible as a single flat script (see
    /// `ScriptedAds::next_step`).
    DropStream,
    /// Sleep before the next step, without consuming a client request.
    /// Used to prove a warming race or a client's reconnect backoff.
    Wait { duration: Duration },
}
