//! WP-22 delta xDS subscription bookkeeping.
//!
//! Delta responses version resources independently. Reconnect state is
//! therefore a resource-name-to-version map, not SotW's one version per type.
//! This module stays free of protobuf and transport code so ACK/NACK,
//! subscribe/unsubscribe, and reconnect rules can be tested directly.

use std::collections::{BTreeMap, BTreeSet};

use crate::subscription::{Subscription, Verdict};

/// One outbound `DeltaDiscoveryRequest`, before protobuf conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRequest {
    pub type_url: String,
    pub initial_resource_versions: BTreeMap<String, String>,
    pub response_nonce: Option<String>,
    pub resource_names_subscribe: Vec<String>,
    pub resource_names_unsubscribe: Vec<String>,
    pub error_detail: Option<String>,
}

impl DeltaRequest {
    pub fn is_nack(&self) -> bool {
        self.error_detail.is_some()
    }
}

/// Per-resource version carried by an accepted delta response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceVersion {
    pub name: String,
    pub version: String,
}

/// One resource type's delta subscription state.
#[derive(Debug, Clone)]
pub struct DeltaSubscriptionState {
    type_url: String,
    subscribed: Subscription,
    resource_versions: BTreeMap<String, String>,
    last_nonce: Option<String>,
}

impl DeltaSubscriptionState {
    pub fn new(type_url: impl Into<String>, subscribed: Subscription) -> Self {
        Self {
            type_url: type_url.into(),
            subscribed,
            resource_versions: BTreeMap::new(),
            last_nonce: None,
        }
    }

    pub fn type_url(&self) -> &str {
        &self.type_url
    }

    pub fn resource_versions(&self) -> &BTreeMap<String, String> {
        &self.resource_versions
    }

    pub fn last_nonce(&self) -> Option<&str> {
        self.last_nonce.as_deref()
    }

    /// An empty named subscription is indistinguishable from wildcard on
    /// delta wire too. Transport must skip it until at least one name exists.
    pub fn has_nothing_to_request(&self) -> bool {
        matches!(&self.subscribed, Subscription::Names(names) if names.is_empty())
    }

    /// First request on a stream. Cached per-resource versions survive a
    /// reconnect; nonce never does. Named subscriptions are re-declared so a
    /// replacement management server sees complete client intent.
    pub fn initial_request(&self) -> DeltaRequest {
        let initial_resource_versions = match &self.subscribed {
            Subscription::Wildcard => self.resource_versions.clone(),
            Subscription::Names(names) => self
                .resource_versions
                .iter()
                .filter(|(name, _)| names.contains(*name))
                .map(|(name, version)| (name.clone(), version.clone()))
                .collect(),
        };
        DeltaRequest {
            type_url: self.type_url.clone(),
            initial_resource_versions,
            response_nonce: None,
            resource_names_subscribe: self.subscribed.resource_names(),
            resource_names_unsubscribe: Vec::new(),
            error_detail: None,
        }
    }

    /// Replace a named subscription and produce only its set difference.
    /// Versions for unsubscribed resources are discarded, so a later
    /// reconnect cannot claim stale interest in them.
    pub fn set_names(&mut self, names: BTreeSet<String>) -> Option<DeltaRequest> {
        let Subscription::Names(current) = &mut self.subscribed else {
            panic!(
                "set_names on a wildcard delta subscription for {}",
                self.type_url
            );
        };
        let subscribe: Vec<String> = names.difference(current).cloned().collect();
        let unsubscribe: Vec<String> = current.difference(&names).cloned().collect();
        if subscribe.is_empty() && unsubscribe.is_empty() {
            return None;
        }
        for name in &unsubscribe {
            self.resource_versions.remove(name);
        }
        *current = names;
        Some(DeltaRequest {
            type_url: self.type_url.clone(),
            initial_resource_versions: BTreeMap::new(),
            // Subscription changes are not ACKs. Only `on_response` echoes
            // a response nonce.
            response_nonce: None,
            resource_names_subscribe: subscribe,
            resource_names_unsubscribe: unsubscribe,
            error_detail: None,
        })
    }

    /// Apply one all-or-nothing response verdict and build its ACK or NACK.
    /// Rejected responses update only nonce; accepted responses atomically
    /// install every supplied version and removal.
    pub fn on_response(
        &mut self,
        resources: impl IntoIterator<Item = ResourceVersion>,
        removed_resources: impl IntoIterator<Item = String>,
        nonce: &str,
        verdict: Verdict,
    ) -> DeltaRequest {
        self.last_nonce = Some(nonce.to_string());
        let error_detail = match verdict {
            Verdict::Accept => {
                for resource in resources {
                    self.resource_versions
                        .insert(resource.name, resource.version);
                }
                for name in removed_resources {
                    self.resource_versions.remove(&name);
                }
                None
            }
            Verdict::Reject(message) => Some(message),
        };
        DeltaRequest {
            type_url: self.type_url.clone(),
            initial_resource_versions: BTreeMap::new(),
            response_nonce: self.last_nonce.clone(),
            resource_names_subscribe: Vec::new(),
            resource_names_unsubscribe: Vec::new(),
            error_detail,
        }
    }

    pub fn reset_stream(&mut self) {
        self.last_nonce = None;
    }
}
