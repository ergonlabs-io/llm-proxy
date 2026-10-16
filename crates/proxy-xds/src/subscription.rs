//! The per-type xDS subscription state machine (S8). Pure logic: no I/O, no
//! gRPC, no protobuf. `client.rs` owns the stream that carries these requests.
//!
//! S8 per type: `state = {subscribed, acked_version, last_nonce}`. On response,
//! all resources are validated and applied, then ACK(version, nonce). Any
//! failure is NACK(previous version, nonce, error_detail), and the entire
//! response is discarded. Four rules, each with a test:
//!
//! 1. **A NACK carries the PREVIOUS acked version.** Echoing the rejected
//!    version would tell the control plane we accepted it.
//! 2. **A NACK changes nothing else.** Neither the acked version nor the
//!    subscription set moves.
//! 3. **The nonce advances on ACK and NACK alike**, so the next request echoes
//!    the latest one.
//! 4. **Across a reconnect the version persists and the nonce does not.** The
//!    first request on a new stream carries no nonce.

use std::collections::BTreeSet;

/// What a subscription covers. LDS/CDS use a wildcard. RDS/EDS use names taken
/// from accepted LDS/CDS resources. An empty name list means "everything" on
/// the wire, so the two must not be confused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subscription {
    /// Every resource of this type -- the LDS/CDS form. On the wire this is an
    /// empty `resource_names` list (legacy wildcard).
    Wildcard,
    /// Exactly these names -- the RDS/EDS form.
    ///
    /// Rust note: a `BTreeSet` keeps the rendered names in a stable order.
    Names(BTreeSet<String>),
}

impl Subscription {
    /// The `resource_names` field this subscription renders to. Wildcard is an
    /// empty list, which is what makes the two forms indistinguishable on the
    /// wire when a name set happens to be empty -- see
    /// [`SubscriptionState::has_nothing_to_request`].
    pub fn resource_names(&self) -> Vec<String> {
        match self {
            Subscription::Wildcard => Vec::new(),
            Subscription::Names(names) => names.iter().cloned().collect(),
        }
    }
}

/// The verdict on one `DiscoveryResponse`, after validating **all** of its
/// resources. S8 is all-or-nothing, so this is deliberately not per-resource:
/// there is no shape here that can express "accepted three of four".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every resource validated and was applied.
    Accept,
    /// At least one resource failed. The string becomes the NACK's
    /// `error_detail` message -- in practice a dotted-path config error.
    Reject(String),
}

/// What the client should send next for one resource type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub type_url: String,
    /// ACK: the version just accepted. NACK: the version last accepted, which
    /// may be `None` if nothing ever has been.
    pub version_info: Option<String>,
    /// The nonce of the response being answered; `None` only on the first
    /// request of a stream.
    pub response_nonce: Option<String>,
    pub resource_names: Vec<String>,
    /// `Some` iff this is a NACK.
    pub error_detail: Option<String>,
}

impl Request {
    pub fn is_nack(&self) -> bool {
        self.error_detail.is_some()
    }
}

/// One resource type's subscription state (S8's
/// `{subscribed, acked_version, last_nonce}`).
#[derive(Debug, Clone)]
pub struct SubscriptionState {
    type_url: String,
    subscribed: Subscription,
    acked_version: Option<String>,
    last_nonce: Option<String>,
}

impl SubscriptionState {
    pub fn new(type_url: impl Into<String>, subscribed: Subscription) -> Self {
        Self {
            type_url: type_url.into(),
            subscribed,
            acked_version: None,
            last_nonce: None,
        }
    }

    pub fn type_url(&self) -> &str {
        &self.type_url
    }

    /// The last version this client ACCEPTED. Never the version of a rejected
    /// response -- see this module's rule 1.
    pub fn acked_version(&self) -> Option<&str> {
        self.acked_version.as_deref()
    }

    pub fn last_nonce(&self) -> Option<&str> {
        self.last_nonce.as_deref()
    }

    pub fn subscription(&self) -> &Subscription {
        &self.subscribed
    }

    /// True for a name-based subscription with no names. On the wire that is
    /// identical to a wildcard, so the caller must skip the request rather than
    /// ask for every resource of the type.
    pub fn has_nothing_to_request(&self) -> bool {
        matches!(&self.subscribed, Subscription::Names(n) if n.is_empty())
    }

    /// Replace the subscribed name set (RDS/EDS, after an LDS/CDS response
    /// named new resources). Returns whether it changed, so a caller can send
    /// a request only when there is something new to ask for.
    ///
    /// Panics on a wildcard subscription: LDS/CDS name sets are not derived
    /// from anything, so reaching here with one is a caller bug, not a
    /// runtime condition to tolerate.
    pub fn set_names(&mut self, names: BTreeSet<String>) -> bool {
        match &mut self.subscribed {
            Subscription::Names(current) => {
                if *current == names {
                    false
                } else {
                    *current = names;
                    true
                }
            }
            Subscription::Wildcard => {
                panic!(
                    "set_names on a wildcard subscription for {}: LDS/CDS subscribe to \
                     everything and have no derived name set",
                    self.type_url
                )
            }
        }
    }

    /// The first request on a stream: subscriptions plus the last ACCEPTED
    /// version, and **no nonce** (there is no prior response on this stream to
    /// echo). S8: "re-send all subscriptions with acked versions ... versions
    /// persist across streams for same server."
    pub fn initial_request(&self) -> Request {
        Request {
            type_url: self.type_url.clone(),
            version_info: self.acked_version.clone(),
            response_nonce: None,
            resource_names: self.subscribed.resource_names(),
            error_detail: None,
        }
    }

    /// Record a response and produce the ACK or NACK that answers it.
    ///
    /// The `verdict` is the caller's all-or-nothing validation result; this
    /// function does not inspect resources, which is what keeps it free of
    /// protobuf and testable in isolation.
    pub fn on_response(&mut self, version_info: &str, nonce: &str, verdict: Verdict) -> Request {
        // Rule 3: the nonce advances whatever the verdict, because the next
        // request must echo the LATEST nonce. Done before the match so no
        // branch can forget it.
        self.last_nonce = Some(nonce.to_string());

        match verdict {
            Verdict::Accept => {
                self.acked_version = Some(version_info.to_string());
                Request {
                    type_url: self.type_url.clone(),
                    version_info: self.acked_version.clone(),
                    response_nonce: self.last_nonce.clone(),
                    resource_names: self.subscribed.resource_names(),
                    error_detail: None,
                }
            }
            Verdict::Reject(message) => {
                // Rules 1 and 2: `acked_version` is deliberately NOT touched,
                // and the NACK echoes it rather than the rejected version.
                // Sending `version_info` here would tell the control plane we
                // accepted a config we just discarded.
                Request {
                    type_url: self.type_url.clone(),
                    version_info: self.acked_version.clone(),
                    response_nonce: self.last_nonce.clone(),
                    resource_names: self.subscribed.resource_names(),
                    error_detail: Some(message),
                }
            }
        }
    }

    /// Drop the per-stream state at a reconnect. Rule 4: the nonce belongs to
    /// the stream that issued it and is cleared; the acked version belongs to
    /// the server and persists.
    pub fn reset_stream(&mut self) {
        self.last_nonce = None;
    }
}
