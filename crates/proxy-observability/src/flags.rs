//! Envoy response flags (`%RESPONSE_FLAGS%`). Short codes must match Envoy's
//! access-log vocabulary exactly — the differential rig compares them (WP-24, S9).
//!
//! # WP-24 acceptance audit (2026-08-22)
//!
//! "Every variant must be reachable by at least one differential test" was
//! re-audited flag by flag against what this codebase actually builds, not
//! against the enum's names. Two buckets, exactly one per flag:
//!
//! - **Reachable and tested**: the condition can occur, is wired to
//!   `StreamInfo::set_response_flag`, and at least one test drives the real
//!   condition and asserts on the RENDERED `%RESPONSE_FLAGS%` line (never on
//!   the enum directly — see `render_flags`'s callers). See each variant's
//!   doc below for its test.
//! - **Unreachable**: the condition cannot occur in what's built today. Each
//!   such variant's doc says why, so the next audit doesn't start from
//!   scratch. `internal-docs/envoy-divergences.md` carries the same table with the
//!   fuller narrative.
//!
//! That audit found two flags declared, apparently wired, and yet **dead
//! code**: `UpstreamRemoteReset` and `DownstreamConnectionTermination`. Both
//! matched on an error variant nothing ever constructed. Both have since
//! been fixed — the h2 refused-stream decode gave `UR` a producer, and
//! `collect_request` stopped discarding its body error, giving `DC` one.
//!
//! Keep the lesson even though the instances are closed: a `grep` for
//! `set_response_flag` is not a reachability proof, and neither is a passing
//! test. Both of those flags had one. A flag is reachable when something can
//! construct the *condition*, so a test that fabricates the error proves the
//! mapping and nothing else.

/// Why a request ended the way it did. See the module doc's WP-24 audit for
/// which variants are reachable (and where their test lives) versus
/// documented-unreachable.
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
    /// URX: upstream retry limit exceeded. Reachable via the S3 retry
    /// engine, but was NOT wired until this audit found the gap (this is
    /// the "found a real defect" instance of the four flags this pass
    /// discovered are neither trivially reachable-and-tested nor a plain
    /// missing feature) -- see `RetryState::retry_limit_exceeded`'s doc in
    /// `proxy_http::retry` for the exact condition (the trigger table would
    /// have retried, but the S3.1 attempt budget was already spent) and
    /// `router.rs`'s `record_retry_limit_exceeded_if_applicable`, its one
    /// call site pattern. Tested by `proxy_http`'s
    /// `router_retry::retry_limit_exceeded_renders_the_urx_response_flag`
    /// (and the negative case,
    /// `router_retry::a_successful_retry_never_renders_urx`).
    UpstreamRetryLimitExceeded,
    /// NC: matched route's cluster not found. Reachable: a route forwarding
    /// to a cluster name absent from the cluster manager's snapshot. See
    /// `proxy_http`'s `router_access_log::unknown_cluster_records_and_renders_the_nc_flag`.
    NoClusterFound,
    /// DC: downstream connection terminated -- the client's own request body
    /// read failed mid-stream. **Reachable and tested**; it was not always.
    /// `filter_manager.rs`'s `collect_request` used to flatten its body error
    /// to `()` before any `StreamInfo` existed to flag, so the resulting 400
    /// carried nothing; it now propagates the real `BodyError` and flags a
    /// `Downstream` one here.
    /// `response_flags::a_client_that_dies_mid_upload_records_and_renders_the_dc_flag`
    /// drives the genuine condition (announce `Content-Length: 100`, send 10
    /// bytes, close the write half) through the real downstream codec.
    ///
    /// Worth remembering how this hid: `access_logging.rs`'s
    /// `LoggingBody::classify` mapped the variant and had a passing unit
    /// test the whole time -- but that test hand-constructs the error, and
    /// the response-body pipeline it wraps only ever carries
    /// `BodyError::Upstream`. A test that fabricates its condition proves the
    /// mapping, never the reachability.
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
    /// UR: upstream remote reset -- the peer deliberately reset the stream
    /// between connect and the first response byte. **Reachable and tested**
    /// since the h2 codec learned to decode RST_STREAM reasons: an
    /// `UpstreamCodecError::RefusedStream` (h2 `REFUSED_STREAM`) is a remote
    /// reset, and `router.rs` flags it `UR` rather than `UC`.
    /// `response_flags::a_refused_h2_stream_records_and_renders_the_ur_flag`.
    ///
    /// The *other* route to this flag is still dead:
    /// `PoolError::ResetBeforeHeaders` is constructed by neither
    /// `ConnectPool::new_stream` (h1) nor the h2 connection cache, so a
    /// post-connect TCP reset is still indistinguishable from a connect
    /// failure and reports as `UF`. Distinguishing it (matching `ECONNRESET`
    /// specifically after a successful connect) remains a classification
    /// decision -- see `internal-docs/envoy-divergences.md`.
    UpstreamRemoteReset,
    /// UC: upstream connection termination. Reachable: any hyper-level
    /// failure sending the request or parsing the response (a malformed
    /// response is the simplest reproduction). See `proxy_http`'s
    /// `response_flags::a_garbled_upstream_response_records_and_renders_the_uc_flag`.
    UpstreamConnectionTermination,
    /// RL: rate limited locally. Reachable: `proxy_filters::token_limit_filter`
    /// denies a request once its budget is exhausted (WP-24 found this was
    /// wired nowhere -- zero occurrences of `ResponseFlag` in that file --
    /// despite being that filter's entire reason to exist). Fixed; see its
    /// `tests::a_denied_request_renders_the_rl_response_flag`. Deliberately
    /// NOT set on that filter's fail-open paths (a store error, or
    /// unreadable usage) -- those admit the request, and `RL` would claim a
    /// refusal that never happened.
    RateLimited,
    /// UAEX: unauthorized by external authorization service. Unreachable: no
    /// `ext_authz` filter exists (WP-32, not yet built) to ever produce this
    /// outcome.
    UnauthorizedExternalService,
    /// RLSE: rate limit service error. Unreachable: no external gRPC
    /// rate-limit service (Envoy's RLS protocol, WP-32) is implemented --
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
    /// DPE: downstream protocol error. Unreachable in the current
    /// architecture: a malformed downstream request is a CONNECTION-level
    /// failure inside `codec.rs`'s `serve_http1`/`serve_http2`
    /// (`CodecError`), returned before any per-request `HttpRequestParts`/
    /// `StreamInfo` is ever constructed -- there is no stream to attach a
    /// flag to at the point this failure occurs.
    DownstreamProtocolError,
    /// UPE: upstream protocol error. Unreachable today: `codec.rs`'s
    /// `UpstreamCodecError` does not classify `hyper::Error` by kind -- a
    /// genuine protocol violation (a malformed status line, bad chunked
    /// framing) and a plain connection drop both collapse into the same
    /// `Send`/`Connection` variants, which `router.rs` already maps
    /// uniformly to `UC`. Distinguishing them is buildable (`hyper::Error`
    /// exposes `is_parse()`), but deciding exactly which hyper error kinds
    /// count as "protocol" versus "connection" (matching Envoy's own
    /// `UPE`/`UC` split) is a classification design decision, not a wiring
    /// fix -- see `internal-docs/envoy-divergences.md`.
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
    /// `ResponseFlagFilter.flags` (WP-24 lowering). `None` for a code Envoy
    /// defines but we don't model as a distinct flag yet (e.g. `DI`, `FI`);
    /// the lowering pass turns that into a strict-mode config error rather
    /// than silently dropping the filter entry (ground rule #1).
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
