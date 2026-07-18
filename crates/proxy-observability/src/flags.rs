//! Envoy response flags (`%RESPONSE_FLAGS%`). Short codes must match Envoy's
//! access-log vocabulary exactly — the differential rig compares them (WP-24, S9).

/// Why a request ended the way it did. Every variant must be reachable by at
/// least one differential test (WP-24 acceptance).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseFlag {
    /// UH: no healthy upstream host in the cluster.
    NoHealthyUpstream,
    /// UF: upstream connection failure.
    UpstreamConnectionFailure,
    /// UO: upstream overflow (circuit breaker open).
    UpstreamOverflow,
    /// NR: no route matched.
    NoRouteFound,
    /// URX: upstream retry limit exceeded.
    UpstreamRetryLimitExceeded,
    /// NC: matched route's cluster not found.
    NoClusterFound,
    /// DC: downstream connection terminated.
    DownstreamConnectionTermination,
    /// LH: local service failed health check (maintenance).
    FailedLocalHealthCheck,
    /// UT: upstream request timeout.
    UpstreamRequestTimeout,
    /// LR: connection local reset.
    LocalReset,
    /// UR: upstream remote reset.
    UpstreamRemoteReset,
    /// UC: upstream connection termination.
    UpstreamConnectionTermination,
    /// RL: rate limited locally.
    RateLimited,
    /// UAEX: unauthorized by external authorization service.
    UnauthorizedExternalService,
    /// RLSE: rate limit service error.
    RateLimitServiceError,
    /// IH: invalid Envoy request header (strict header check).
    InvalidEnvoyRequestHeaders,
    /// SI: stream idle timeout.
    StreamIdleTimeout,
    /// DPE: downstream protocol error.
    DownstreamProtocolError,
    /// UPE: upstream protocol error.
    UpstreamProtocolError,
    /// UMSDR: upstream request reached max stream duration.
    UpstreamMaxStreamDurationReached,
}

impl ResponseFlag {
    /// The short code as it appears in `%RESPONSE_FLAGS%`.
    pub fn code(self) -> &'static str {
        match self {
            Self::NoHealthyUpstream => "UH",
            Self::UpstreamConnectionFailure => "UF",
            Self::UpstreamOverflow => "UO",
            Self::NoRouteFound => "NR",
            Self::UpstreamRetryLimitExceeded => "URX",
            Self::NoClusterFound => "NC",
            Self::DownstreamConnectionTermination => "DC",
            Self::FailedLocalHealthCheck => "LH",
            Self::UpstreamRequestTimeout => "UT",
            Self::LocalReset => "LR",
            Self::UpstreamRemoteReset => "UR",
            Self::UpstreamConnectionTermination => "UC",
            Self::RateLimited => "RL",
            Self::UnauthorizedExternalService => "UAEX",
            Self::RateLimitServiceError => "RLSE",
            Self::InvalidEnvoyRequestHeaders => "IH",
            Self::StreamIdleTimeout => "SI",
            Self::DownstreamProtocolError => "DPE",
            Self::UpstreamProtocolError => "UPE",
            Self::UpstreamMaxStreamDurationReached => "UMSDR",
        }
    }
}
