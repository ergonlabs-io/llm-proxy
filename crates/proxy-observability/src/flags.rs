//! Envoy response flags (`%RESPONSE_FLAGS%`). Short codes must match Envoy's
//! access-log vocabulary exactly, since the differential rig compares them (S9).
//! Deliberate departures are in `internal-docs/envoy-divergences.md`.
//!
//! Each variant is either reachable, with a test that drives the real condition
//! and asserts on the rendered line, or documented as unreachable with the
//! reason. A `grep` for `set_response_flag` does not prove reachability, and
//! neither does a test that fabricates the error. The test must reach the
//! condition through the real path.

/// Why a request ended the way it did. Each variant notes whether it is
/// reachable (and where its test lives) or unreachable, and why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseFlag {
    /// UH: no healthy upstream host in the cluster. Reachable: a cluster
    /// with zero endpoints (or every host filtered out) makes `select_host`
    /// return `None`. See `proxy_http`'s
    /// `response_flags::zero_endpoints_records_and_renders_the_uh_flag`.
    NoHealthyUpstream,
    /// UF: upstream connection failure. Reachable: a refused TCP connect (or
    /// a TLS handshake failure, folded into the same code -- see
    /// `router.rs`'s `PoolError::TlsHandshake` arm). See `proxy_http`'s
    /// `response_flags::a_refused_connection_records_and_renders_the_uf_flag`.
    UpstreamConnectionFailure,
    /// UO: upstream overflow (circuit breaker open). Reachable via the S5
    /// `max_requests` breaker (`PoolError::Overflow` is declared but never
    /// actually constructed by either pool implementation today -- the
    /// circuit-breaker path is the only live producer of this flag). See
    /// `proxy_http`'s `response_flags::max_requests_zero_records_and_renders_the_uo_flag`.
    UpstreamOverflow,
    /// NR: no route matched. Reachable: a request whose path matches no
    /// configured route. See `proxy_http`'s
    /// `response_flags::no_route_matched_records_and_renders_the_nr_flag`.
    NoRouteFound,
    /// URX: upstream retry limit exceeded. Set by the S3 retry engine when the
    /// trigger table would retry but the S3.1 attempt budget is spent. See
    /// `RetryState::retry_limit_exceeded` in `proxy_http::retry`. Tested by
    /// `proxy_http`'s `router_retry::retry_limit_exceeded_renders_the_urx_response_flag`,
    /// with the negative case `router_retry::a_successful_retry_never_renders_urx`.
    UpstreamRetryLimitExceeded,
    /// NC: matched route's cluster not found. Reachable: a route forwarding
    /// to a cluster name absent from the cluster manager's snapshot. See
    /// `proxy_http`'s `router_access_log::unknown_cluster_records_and_renders_the_nc_flag`.
    NoClusterFound,
    /// DC: downstream connection terminated, meaning the client's request body
    /// failed mid-stream. Tested by
    /// `response_flags::a_client_that_dies_mid_upload_records_and_renders_the_dc_flag`,
    /// which sends a short body through the real codec.
    DownstreamConnectionTermination,
    /// LH: local service failed health check (maintenance mode). Unreachable:
    /// there is no downstream health-check filter or admin/maintenance-mode
    /// surface in this codebase at all -- this flag models Envoy's own
    /// health-check-filter responding "unhealthy" to a caller, which we
    /// have nothing corresponding to.
    FailedLocalHealthCheck,
    /// UT: upstream request timeout. Reachable both as the route-level
    /// `timeout` (whole attempt loop) and as a `per_try_timeout` (single
    /// attempt). See `proxy_http`'s
    /// `response_flags::a_route_timeout_records_and_renders_the_ut_flag`.
    UpstreamRequestTimeout,
    /// LR: connection local reset. Unreachable: there is no code path where
    /// this proxy resets a connection on its own initiative outside the
    /// cases already modeled by other flags (a client disconnect is `DC`'s
    /// condition, an idle upstream is `SI`, an upstream failure is
    /// `UF`/`UC`/`UR`) -- Envoy's own uses of `LR` (e.g. an internal error
    /// aborting a stream) have no analog here.
    LocalReset,
    /// UR: upstream remote reset. The peer reset the stream between connect and
    /// the first response byte. Set for an h2 `REFUSED_STREAM`. Tested by
    /// `response_flags::a_refused_h2_stream_records_and_renders_the_ur_flag`.
    ///
    /// A post-connect TCP reset is not yet classified as `UR`. It reports as
    /// `UF` (see `internal-docs/envoy-divergences.md`).
    UpstreamRemoteReset,
    /// UC: upstream connection termination. Reachable: a hyper-level
    /// failure sending the request or reading the response that is neither
    /// a remote reset (`UR`) nor a protocol error (`UPE`), such as an
    /// upstream that closes before sending headers. Answered with `503`, as
    /// Envoy does. See `proxy_http`'s
    /// `response_flags::an_upstream_that_closes_before_headers_records_503_and_the_uc_flag`.
    UpstreamConnectionTermination,
    /// RL: rate limited locally. Set by `proxy_filters::token_limit_filter` when
    /// its budget is exhausted. It is not set on that filter's fail-open paths,
    /// since those admit the request and `RL` would claim a refusal that never
    /// happened. Tested by `tests::a_denied_request_renders_the_rl_response_flag`.
    RateLimited,
    /// UAEX: external authorization denial, fail-closed service error, or
    /// invalid mutation. Explicit fail-open admission does not set this flag.
    UnauthorizedExternalService,
    /// RLSE: rate limit service error. Unreachable: no external gRPC
    /// rate-limit service (Envoy's RLS protocol) is implemented --
    /// `token_limit_filter` (`RateLimited`, above) is a local/in-process
    /// limiter with no remote service to fail.
    RateLimitServiceError,
    /// IH: invalid Envoy request header (strict header check). Unreachable:
    /// no strict-header-validation feature (rejecting `headers_with_underscores`,
    /// missing pseudo-headers under strict mode, etc.) exists in this
    /// codebase.
    InvalidEnvoyRequestHeaders,
    /// SI: stream idle timeout. Reachable: a route's `idle_timeout` firing
    /// while an upstream response body has gone quiet past the deadline.
    /// See `proxy_http`'s
    /// `response_flags::an_idle_response_body_records_and_renders_the_si_flag`.
    StreamIdleTimeout,
    /// DPE: downstream protocol error. Unreachable: a malformed downstream
    /// request fails at connection level in `codec.rs`, before any `StreamInfo`
    /// exists to carry the flag.
    DownstreamProtocolError,
    /// UPE: upstream protocol error. Reachable: hyper could not parse the
    /// upstream response (`hyper::Error::is_parse`: a malformed status line,
    /// header, or version), classified by `proxy_http::codec::is_protocol_error`.
    /// Answered with `502`, as Envoy answers a codec protocol error. See
    /// `proxy_http`'s
    /// `response_flags::a_garbled_upstream_response_records_and_renders_the_upe_flag`.
    UpstreamProtocolError,
    /// UMSDR: upstream request reached max stream duration. Unreachable: no
    /// `max_stream_duration` feature (distinct from the route `timeout` and
    /// `idle_timeout` this codebase does have) is implemented.
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

    /// Reverse of [`Self::code`] — used to decode
    /// `ResponseFlagFilter.flags`. `None` for a code Envoy
    /// defines but we don't model as a distinct flag yet (e.g. `DI`, `FI`);
    /// the lowering pass turns that into a strict-mode config error rather
    /// than silently dropping the filter entry (AGENTS.md invariant 1).
    pub fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "UH" => Self::NoHealthyUpstream,
            "UF" => Self::UpstreamConnectionFailure,
            "UO" => Self::UpstreamOverflow,
            "NR" => Self::NoRouteFound,
            "URX" => Self::UpstreamRetryLimitExceeded,
            "NC" => Self::NoClusterFound,
            "DC" => Self::DownstreamConnectionTermination,
            "LH" => Self::FailedLocalHealthCheck,
            "UT" => Self::UpstreamRequestTimeout,
            "LR" => Self::LocalReset,
            "UR" => Self::UpstreamRemoteReset,
            "UC" => Self::UpstreamConnectionTermination,
            "RL" => Self::RateLimited,
            "UAEX" => Self::UnauthorizedExternalService,
            "RLSE" => Self::RateLimitServiceError,
            "IH" => Self::InvalidEnvoyRequestHeaders,
            "SI" => Self::StreamIdleTimeout,
            "DPE" => Self::DownstreamProtocolError,
            "UPE" => Self::UpstreamProtocolError,
            "UMSDR" => Self::UpstreamMaxStreamDurationReached,
            _ => return None,
        })
    }
}

/// Render `%RESPONSE_FLAGS%`: Envoy joins every flag that fired on a request
/// with `,`, in the order they were recorded (e.g. `UF,URX`). An empty slice
/// renders as `-` (no flags fired) — that's the caller's job, not this
/// function's, since callers also need to special-case "no flags" for the
/// dash *before* deciding to call this at all in some formatters; here we
/// just join what's given.
pub fn render_flags(flags: &[ResponseFlag]) -> String {
    flags.iter().map(|f| f.code()).collect::<Vec<_>>().join(",")
}
