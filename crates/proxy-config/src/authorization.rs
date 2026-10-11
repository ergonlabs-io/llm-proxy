//! Protobuf-free WP-32 authorization boundary.
use std::{
    collections::BTreeMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    time::{Duration, SystemTime},
};

pub const TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz";
pub const PER_ROUTE_TYPE_URL: &str =
    "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthzPerRoute";
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
pub const MAX_MUTATION_BYTES: usize = 16 * 1024;
pub const MAX_IN_FLIGHT: usize = 256;

#[derive(Debug, Clone)]
pub struct ExtAuthzConfig {
    pub cluster: String,
    pub endpoint: Option<SocketAddr>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub failure_mode_allow: bool,
    pub failure_mode_allow_header_add: bool,
    pub status_on_error: u16,
    pub clear_route_cache: bool,
    pub stat_prefix: String,
    /// Full config path retained for cross-resource validation.
    pub field_path: String,
}

#[derive(Debug, Clone)]
pub enum ExtAuthzPerRoute {
    Disabled,
    Check {
        context_extensions: BTreeMap<String, String>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizationRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub authority: String,
    pub scheme: String,
    pub protocol: String,
    pub remote: Option<SocketAddr>,
    pub time: Option<SystemTime>,
    pub headers: Vec<(String, Vec<u8>)>,
    pub context_extensions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationAction {
    Set,
    Add,
    Append,
    AddIfAbsent,
    OverwriteIfPresent,
}

#[derive(Debug, Clone)]
pub struct AuthorizationHeader {
    pub name: String,
    pub value: Vec<u8>,
    pub action: MutationAction,
}

#[derive(Debug, Clone, Default)]
pub struct AuthorizationAllow {
    pub headers: Vec<AuthorizationHeader>,
    pub remove: Vec<String>,
    pub response_headers: Vec<AuthorizationHeader>,
}

#[derive(Debug, Clone)]
pub struct AuthorizationDenied {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<AuthorizationHeader>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationError {
    Timeout,
    Transport,
    Protocol,
    /// Availability condition: no admission permit. Admitted under
    /// `failure_mode_allow` (our own behavior; see envoy-divergences.md).
    Saturation,
    /// The locally encoded request is too large to send. Client-controlled,
    /// so it is never an availability condition: the filter always denies it.
    RequestTooLarge,
    InvalidMutation,
}

#[derive(Debug, Clone)]
pub enum AuthorizationDecision {
    Allow(AuthorizationAllow),
    Denied(AuthorizationDenied),
    Error(AuthorizationError),
}

#[derive(Debug, Clone)]
pub struct AuthorizationResult {
    pub decision: AuthorizationDecision,
    pub ignored_metadata: bool,
}

pub type AuthorizationFuture = Pin<Box<dyn Future<Output = AuthorizationResult> + Send>>;

/// Dropping a check future cancels its RPC and releases admission capacity.
pub trait AuthorizationClient: Send + Sync {
    fn check(&self, request: AuthorizationRequest) -> AuthorizationFuture;
}
