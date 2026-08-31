//! The admin HTTP server: binds a socket (control runtime, ADR-0003) and
//! answers the read-only endpoints, plus (WP-50 increment 3b-ii, W4) a
//! bearer-gated write API for the control plane, over real hyper
//! connections.
//!
//! # The write API's `ControlPlane` is resolved PER REQUEST, never cached
//!
//! `run_serve` (`crates/proxy/src/main.rs`) calls [`serve`] *before* the
//! worker pool spawns -- so at the moment this module's socket binds, no
//! worker has run its `AuthFilterFactory::create` yet, and therefore no
//! [`proxy_filters::control::ControlPlane`] has been registered into the
//! shared [`proxy_http::filter::SharedFactoryState`] slot. Caching a
//! `ControlPlane` (or `None`) at `serve()` time would freeze that boot race
//! into a permanent 503, or panic the first mint request. Every write
//! request instead calls [`resolve_control_plane`] fresh -- see that
//! function's doc for what a miss means, and for the SEPARATE case where more
//! than one filter chain configures `llmproxy.auth`: this server has no chain
//! scope of its own (it isn't part of any filter chain), so it cannot pick
//! one of several `ControlPlane`s without guessing -- that case is a loud,
//! explicit error, never a silent pick.
//!
//! # The admin bearer token: a `serve()` parameter, never read from the
//! environment here
//!
//! The owner's convention (mirroring `keygen`'s `LLMPROXY_AUTH_SECRET`) is
//! an env var, `LLMPROXY_ADMIN_TOKEN` -- but `std::env::var` is
//! process-global and racy across parallel tests, so this module never reads
//! it. `crates/proxy/src/main.rs`'s `start_admin` reads the env var once and
//! passes the result in; every test in `server/tests.rs` passes a literal.
//! [`serve`] normalizes `None`/empty/whitespace-only to `None` in exactly one
//! place ([`normalize_admin_token`]) so both callers get identical
//! fail-closed behavior -- **unset never means open**, see the gate inside
//! [`handle`] for the rest of the semantics.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_core::WorkerConfigHandle;
use proxy_filters::auth::{KeyId, TenantId};
use proxy_filters::control::{ControlPlane, StoreError};
use proxy_filters::model_authz::{ModelAccess, ModelPattern};
use proxy_http::filter::SharedFactoryState;
use proxy_observability::stats::{envoy_render, prometheus_render, Registry};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::dump::{ClusterDump, ConfigDump};

/// The endpoints this crate serves, used both to route requests and to list
/// "available endpoints" in a 404 body. `{id}` segments are literal in this
/// list (documentation only) -- routing itself is done by
/// [`match_write_route`] for the write API, not by matching against these
/// strings.
const AVAILABLE_ENDPOINTS: &[&str] = &[
    "/ready",
    "/config_dump",
    "/clusters",
    "/server_info",
    "/keys",
    "/keys/{id}",
    "/tenants",
    "/tenants/{id}",
    "/tenants/{id}/policy",
];

/// Hard cap on a write request's body. An admin write endpoint has no
/// legitimate reason to receive a multi-megabyte body (the largest real
/// payload, a `PUT .../policy`, is a handful of glob strings); without a
/// cap, reading `Incoming` to completion would buffer an attacker-controlled
/// body of unbounded size in memory -- a trivial DoS against a port that is,
/// deliberately, reachable without a config file naming an operator's IP
/// allowlist.
const MAX_ADMIN_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("admin server failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

/// A running admin server. Dropping this does not stop the server -- see
/// [`AdminServer::abort`] -- so callers that care about shutdown (none do
/// yet in this read-only increment) must call it explicitly.
pub struct AdminServer {
    local_addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

impl AdminServer {
    /// The address actually bound -- callers pass port 0 in tests and read
    /// the OS-assigned port back from here.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting new connections. In-flight requests on already
    /// accepted connections may still complete (each runs on its own
    /// spawned task, independent of this handle).
    pub fn abort(&self) {
        self.accept_task.abort();
    }
}

/// Collapses `None` and an empty/whitespace-only token to `None` -- see the
/// module doc's "admin bearer token" section for why this lives here rather
/// than at either caller. An operator who sets `LLMPROXY_ADMIN_TOKEN=""` (or
/// leaves it exported-but-empty in a script) gets the same fail-closed 403
/// as an operator who never set it at all, rather than a token that is
/// trivially "guessed" by presenting an empty bearer value.
fn normalize_admin_token(token: Option<String>) -> Option<String> {
    match token {
        Some(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// Binds `addr` and starts answering admin requests on the control runtime.
///
/// `config` is read (never owned) per request via `load()` -- an `Arc`
/// clone of whatever the control side last published, per ADR-0005's
/// "control computes, workers read" split applied to this reader too.
/// `registry` is the WP-23 stats registry, `Some` once a caller has one to
/// offer -- see `/stats`'s route in [`handle`] for what happens when it
/// doesn't. `started_at` backs `/server_info`'s uptime. `factory_state` is
/// the per-serve [`SharedFactoryState`] a worker's `AuthFilterFactory`
/// registers its `ControlPlane` singleton into -- see the module doc's
/// "resolved PER REQUEST" section for why `serve` itself never reads out of
/// it at startup. `admin_token` gates every WRITE endpoint (`/keys`,
/// `/tenants`, ...); see [`normalize_admin_token`] and [`handle`]'s gate for
/// the fail-closed semantics -- READ endpoints are unaffected by it.
///
/// Rust note: `TcpListener::accept` runs in a loop inside a `tokio::spawn`led
/// task; each accepted connection gets its own further-spawned task running
/// one `hyper::server::conn::http1` connection, the standard hyper-on-tokio
/// shape. Nothing here needs `!Send`/`Rc` -- this is ordinary control-plane
/// code, never the worker-local data plane (ADR-0003).
pub async fn serve(
    addr: SocketAddr,
    config: Arc<WorkerConfigHandle>,
    registry: Option<Arc<Registry>>,
    started_at: Instant,
    factory_state: Arc<SharedFactoryState>,
    admin_token: Option<String>,
) -> Result<AdminServer, AdminError> {
    let admin_token = normalize_admin_token(admin_token);
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| AdminError::Bind { addr, source })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| AdminError::Bind { addr, source })?;

    let accept_task = tokio::spawn(async move {
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    tracing::warn!(error = %err, "admin server: accept failed, continuing");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let config = config.clone();
            let registry = registry.clone();
            let factory_state = factory_state.clone();
            let admin_token = admin_token.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let config = config.clone();
                    let registry = registry.clone();
                    let factory_state = factory_state.clone();
                    let admin_token = admin_token.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            handle(
                                req,
                                &config,
                                registry.as_deref(),
                                started_at,
                                &factory_state,
                                admin_token.as_deref(),
                            )
                            .await,
                        )
                    }
                });
                if let Err(err) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .await
                {
                    tracing::debug!(error = %err, "admin server: connection error");
                }
            });
        }
    });

    Ok(AdminServer {
        local_addr,
        accept_task,
    })
}

async fn handle(
    req: Request<Incoming>,
    config: &WorkerConfigHandle,
    registry: Option<&Registry>,
    started_at: Instant,
    factory_state: &SharedFactoryState,
    admin_token: Option<&str>,
) -> Response<Full<Bytes>> {
    // ---- Read endpoints: byte-for-byte the read-only increment's behavior,
    // no gate, matched on path alone (as before -- these never distinguished
    // method). ----
    match req.uri().path() {
        "/ready" => return text(StatusCode::OK, "LIVE"),
        "/config_dump" => {
            let snapshot = config.load();
            return json(StatusCode::OK, &ConfigDump::from_snapshot(&snapshot));
        }
        "/clusters" => {
            let snapshot = config.load();
            let mut clusters: Vec<ClusterDump> = snapshot
                .clusters
                .values()
                .map(|c| ClusterDump::from_ir(c))
                .collect();
            clusters.sort_by(|a, b| a.name.cmp(&b.name));
            return json(StatusCode::OK, &clusters);
        }
        "/server_info" => {
            let uptime_seconds = started_at.elapsed().as_secs();
            return json(
                StatusCode::OK,
                &ServerInfo {
                    version: env!("CARGO_PKG_VERSION"),
                    uptime_seconds,
                },
            );
        }
        // WP-23 increment 3: rendering is `envoy_render::render`, which only
        // reads atomics already resolved/incremented elsewhere and formats
        // a string -- no I/O, no blocking, safe on this request path (see
        // `envoy_render::render`'s own doc). When no registry has been
        // wired for this server instance (e.g. a test standing up `serve`
        // without one), this deliberately keeps the pre-existing honest
        // 404 rather than fabricating an empty `200` -- an operator who
        // trusts an empty `/stats` believes there is no traffic.
        "/stats" => {
            return match registry {
                Some(registry) => text(StatusCode::OK, &envoy_render::render(registry)),
                None => text(
                    StatusCode::NOT_FOUND,
                    "the stats registry (WP-23) is not configured for this admin server instance; \
                     this proxy does not fake an empty /stats",
                ),
            };
        }
        // WP-23 increment 4: same shape as `/stats` above.
        "/stats/prometheus" => {
            return match registry {
                Some(registry) => text(StatusCode::OK, &prometheus_render::render(registry)),
                None => text(
                    StatusCode::NOT_FOUND,
                    "the stats registry (WP-23) is not configured for this admin server instance; \
                     this proxy does not fake an empty /stats/prometheus",
                ),
            };
        }
        _ => {}
    }

    // ---- Write endpoints (WP-50 3b-ii W4): gated, resolved per request. ----
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Rust note: leading `/` stripped, then split on `/` WITHOUT filtering
    // empty segments -- a trailing slash (`/keys/`) must produce a distinct,
    // empty final segment (`["keys", ""]`) rather than silently collapsing
    // to `["keys"]`, or `DELETE /keys/` would be routed as the no-id `/keys`
    // shape (which only accepts `POST`) instead of hitting the empty-id
    // validation `match_write_route`'s doc describes.
    let trimmed = path.strip_prefix('/').unwrap_or(path.as_str());
    let segments: Vec<&str> = trimmed.split('/').collect();

    let Some(route) = match_write_route(&segments) else {
        return unknown_endpoint(&path);
    };

    if method != route.expected_method() {
        return text(
            StatusCode::METHOD_NOT_ALLOWED,
            &format!("{path} only accepts {}", route.expected_method()),
        );
    }

    // Gate 1: is the write API enabled at all? Unset (or empty/whitespace)
    // `LLMPROXY_ADMIN_TOKEN` means "not configured", never "open" -- see
    // CLAUDE.md rule 17 ("a security control that fails open must be
    // loud"). This is the fail-CLOSED default, and it must never be
    // reachable by falling through any other branch above it.
    let Some(token) = admin_token else {
        tracing::warn!(
            endpoint = %path,
            "admin write refused: LLMPROXY_ADMIN_TOKEN is not set, so admin write endpoints are disabled"
        );
        return text(
            StatusCode::FORBIDDEN,
            "admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is not set",
        );
    };

    // Gate 2: does the caller present the configured token? RFC 7235
    // requires a `www-authenticate` challenge on a 401 -- `auth_filter.rs`'s
    // `AuthFilterInstance::deny` does the same thing for the exact same
    // reason.
    let presented = extract_bearer(req.headers());
    let authorized = match &presented {
        Some(candidate) => secrets_match(candidate.as_bytes(), token.as_bytes()),
        None => false,
    };
    if !authorized {
        tracing::warn!(endpoint = %path, "admin write refused: missing or invalid bearer token");
        return unauthorized("missing or invalid bearer token");
    }

    // Gate 3: does the control plane exist, and is it unambiguous which one
    // this write means? See `resolve_control_plane`'s doc for the two 503
    // situations that don't need telling apart, and for the third case below
    // -- more than one `llmproxy.auth`-configured chain -- which does.
    let control_plane = match resolve_control_plane(factory_state) {
        Ok(Some(cp)) => cp,
        Ok(None) => {
            return text(
                StatusCode::SERVICE_UNAVAILABLE,
                "the auth control plane is not initialized yet: either no llmproxy.auth filter \
                 is configured, or the workers have not finished building their filter chains \
                 yet -- retry shortly",
            );
        }
        Err(scopes) => {
            // Loud, not a guess (CLAUDE.md rule 17's shape applied here too):
            // picking one of several ControlPlanes at random would risk
            // writing a key into the wrong tenant's control plane.
            tracing::error!(
                endpoint = %path,
                scopes = ?scopes,
                "admin write refused: more than one llmproxy.auth-configured filter chain is \
                 registered, so the admin API cannot tell which ControlPlane this write means"
            );
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "the admin write API cannot resolve a single auth control plane: {} filter \
                     chains each configure llmproxy.auth ({}) -- this admin API supports \
                     writes only when exactly one chain in this serve configures llmproxy.auth",
                    scopes.len(),
                    scopes.join(", "),
                ),
            );
        }
    };

    let body = match read_limited_body(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(resp) => return resp,
    };

    match route {
        WriteRoute::Keys => handle_mint_key(&control_plane, &body),
        WriteRoute::KeyById(id) => handle_revoke_key(&control_plane, id),
        WriteRoute::Tenants => handle_create_tenant(&control_plane, &body),
        WriteRoute::TenantById(id) => handle_delete_tenant(&control_plane, id),
        WriteRoute::TenantPolicy(id) => handle_set_policy(&control_plane, id, &body),
    }
}

/// One of the write-capable paths this server recognizes, with the path
/// parameter (if any) borrowed straight out of the request's path segments.
/// Kept separate from method matching ([`WriteRoute::expected_method`]) so
/// "known path, wrong method" can answer 405 rather than falling through to
/// the generic 404 an unrecognized path gets.
enum WriteRoute<'a> {
    Keys,
    KeyById(&'a str),
    Tenants,
    TenantById(&'a str),
    TenantPolicy(&'a str),
}

impl WriteRoute<'_> {
    fn expected_method(&self) -> Method {
        match self {
            WriteRoute::Keys | WriteRoute::Tenants => Method::POST,
            WriteRoute::KeyById(_) | WriteRoute::TenantById(_) => Method::DELETE,
            WriteRoute::TenantPolicy(_) => Method::PUT,
        }
    }
}

/// Matches `segments` (the request path, leading slash stripped, split on
/// `/` -- empty segments kept, see the call site) against the known
/// write-endpoint shapes.
///
/// Percent-decoding is deliberately NOT performed: an id containing a
/// literal `/` simply cannot be addressed through this API -- it splits
/// into extra segments and matches no shape below, landing on the generic
/// 404. No caller has a reason to mint a `key_id`/tenant containing a
/// slash, so this is a documented limitation, not a bug.
///
/// An id segment that is present but EMPTY (`/keys/`, a trailing slash)
/// still matches its shape here -- the per-route handlers in [`handle`]
/// reject an empty id with 400, the same way an empty `tenant`/`key_id` in a
/// JSON body is rejected, rather than this function silently treating an
/// empty-id path as "not a route" (404) for what is really a validation
/// failure, not a routing one.
fn match_write_route<'a>(segments: &[&'a str]) -> Option<WriteRoute<'a>> {
    match segments {
        ["keys"] => Some(WriteRoute::Keys),
        ["keys", id] => Some(WriteRoute::KeyById(id)),
        ["tenants"] => Some(WriteRoute::Tenants),
        ["tenants", id] => Some(WriteRoute::TenantById(id)),
        ["tenants", id, "policy"] => Some(WriteRoute::TenantPolicy(id)),
        _ => None,
    }
}

/// Resolves the live [`ControlPlane`] a worker's `AuthFilterFactory`
/// registered into `factory_state`, keyed on that filter's own
/// `auth_filter::TYPE_URL` ACROSS EVERY CHAIN'S SCOPE -- the admin server has
/// no chain of its own to scope by (it isn't part of any filter chain), so
/// this reads [`SharedFactoryState::get_across_scopes`] rather than the
/// scoped `get` a filter factory uses; see that method's doc for the
/// singleton-slot mechanism and why a `type_url`-only read is unsafe in
/// general.
///
/// `Ok(None)` covers two situations this function cannot (and need not)
/// distinguish, both mapped to the same 503 by the caller:
/// - **A genuine boot race.** `serve()` is called before the worker pool
///   spawns (see the module doc), so a request that lands before any
///   worker's `create()` has run finds nothing here yet. This resolves
///   itself within the time it takes the first worker to build its filter
///   chain -- a 503 (retryable, "come back shortly") is the correct
///   response, not a 500 ("something is broken").
/// - **No `llmproxy.auth` filter in this config at all.** A deployment with
///   no virtual-key auth configured has no `ControlPlane` to mint keys
///   into, ever -- also a 503, since from the caller's perspective "not
///   ready yet" and "will never exist" are both "the write cannot be served
///   right now," and inventing a third status code here would not give the
///   caller anything actionable to do differently.
///
/// `Err(scopes)` is a THIRD, genuinely different situation: more than one
/// filter chain in this serve configures `llmproxy.auth` (e.g. two listeners,
/// each with its own keys). The write API is one endpoint (`/keys`), not one
/// per chain, so there is no scope to route this write to -- and guessing
/// (e.g. "the first one registered") would silently write a key into the
/// wrong tenant's control plane, exactly the class of bug this whole task
/// exists to close. The honest answer, and what the caller does with it: an
/// explicit error naming every ambiguous scope, never a guess.
fn resolve_control_plane(
    factory_state: &SharedFactoryState,
) -> Result<Option<Arc<ControlPlane>>, Vec<String>> {
    let singleton = factory_state.get_across_scopes(proxy_filters::auth_filter::TYPE_URL)?;
    Ok(singleton.and_then(|s| s.downcast::<ControlPlane>().ok()))
}

/// Reads `body` up to [`MAX_ADMIN_BODY_BYTES`], returning the collected
/// bytes or a ready-to-send 413.
///
/// Rust note: `http_body_util::Limited` wraps any `Body` and turns "read
/// past the cap" into an error rather than continuing to buffer -- the
/// standard way to bound an otherwise-unbounded `Incoming::collect()`. Its
/// error type is a boxed `dyn Error`; `downcast_ref::<LengthLimitError>`
/// tells "the cap was hit" apart from "the connection died mid-body" so the
/// former reports 413 and the latter reports 400 instead of one masquerading
/// as the other.
// This admin write path runs a handful of times per operator action, never
// per data-plane request -- the `Response<Full<Bytes>>` `Err` variant clippy
// flags as "large" (a ready-to-send error response, by design) costs nothing
// worth boxing for on a path this cold.
#[allow(clippy::result_large_err)]
async fn read_limited_body(body: Incoming) -> Result<Bytes, Response<Full<Bytes>>> {
    match Limited::new(body, MAX_ADMIN_BODY_BYTES).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(err) => {
            if err
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                Err(text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!(
                        "request body exceeds the {MAX_ADMIN_BODY_BYTES}-byte admin write cap"
                    ),
                ))
            } else {
                Err(text(
                    StatusCode::BAD_REQUEST,
                    &format!("failed to read request body: {err}"),
                ))
            }
        }
    }
}

/// Extracts the bearer credential from `Authorization: Bearer <token>`.
/// `None` for a missing header, a header that isn't valid UTF-8/ASCII, or
/// any scheme other than exactly `Bearer ` (matching
/// `proxy_filters::auth`'s own `BEARER_PREFIX` convention).
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

/// Constant-time equality for two secrets, by the double-HMAC compare.
///
/// **Not `==`**, which short-circuits on the first differing byte and leaks
/// a matching prefix's length through timing -- the whole point of this
/// function. It is also **not**
/// `ring::constant_time::verify_slices_are_equal`, even though that reads
/// like the obvious primitive: in the `ring` version this workspace pins
/// (0.17.14) it is deprecated with the note "Internal function not intended
/// for external use with **no promises regarding side channels**", i.e.
/// `ring` no longer documents it as constant-time for callers outside the
/// crate -- which is the entire property being bought here.
/// `proxy_filters::auth`'s module doc records that same finding and the same
/// decision for the data plane's key check; this is the control plane
/// reaching the same conclusion, so both sides of the product use the one
/// primitive `ring` still documents as constant-time.
///
/// `ring::hmac::verify` DOES apply to a plain secret-vs-secret comparison,
/// contrary to how it first reads: HMAC both values under one key and the
/// digests are equal exactly when the inputs are (collision resistance), and
/// `hmac::verify` performs that digest comparison in constant time. The key
/// is freshly random per call and never leaves this function -- it is not a
/// secret being authenticated with, it is a blinding value, and generating a
/// new one each time additionally randomizes what an attacker can observe
/// across attempts. Cost is one 32-byte RNG read and two SHA-256s of a short
/// string, on a path that runs at operator rate, not per data-plane request.
///
/// Fails CLOSED if the RNG fails: no random key, no comparison, no match.
fn secrets_match(presented: &[u8], configured: &[u8]) -> bool {
    let mut key_bytes = [0u8; 32];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut key_bytes).is_err() {
        tracing::error!(
            "admin write refused: the system RNG failed, so the bearer token could not be compared"
        );
        return false;
    }
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key_bytes);
    let expected = ring::hmac::sign(&key, configured);
    ring::hmac::verify(&key, presented, expected.as_ref()).is_ok()
}

/// A 401 carrying the RFC 7235-mandated `www-authenticate` challenge --
/// `auth_filter.rs`'s `AuthFilterInstance::deny` does the same thing on the
/// data plane, for the same reason.
fn unauthorized(message: &str) -> Response<Full<Bytes>> {
    let mut response = text(StatusCode::UNAUTHORIZED, message);
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        hyper::header::HeaderValue::from_static("Bearer"),
    );
    response
}

fn bad_request(message: &str) -> Response<Full<Bytes>> {
    text(StatusCode::BAD_REQUEST, message)
}

fn no_content() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .expect("static response is always valid")
}

fn unknown_endpoint(path: &str) -> Response<Full<Bytes>> {
    text(
        StatusCode::NOT_FOUND,
        &format!(
            "unknown admin endpoint '{path}'; available endpoints: {}",
            AVAILABLE_ENDPOINTS.join(", ")
        ),
    )
}

/// Parses a JSON request body into `T`, rejecting any unknown field (every
/// request struct in this module carries `#[serde(deny_unknown_fields)]` --
/// see ground rule #1: a silently ignored field in a security-write API is
/// the same class of bug as a silently ignored config field) and mapping
/// any parse failure to 400. The error `Display` from `serde_json` names
/// only the JSON shape problem (missing/wrong-typed field, unknown field,
/// malformed syntax) -- these request bodies never carry a token or a
/// plaintext key (the one plaintext key this API ever produces is a
/// RESPONSE, from `POST /keys`, never a request field), so there is nothing
/// sensitive to leak by including it in the message.
// See `read_limited_body`'s identical `#[allow]` -- same cold admin-write
// path, same "large" `Err` variant by design.
#[allow(clippy::result_large_err)]
fn parse_json_body<T: serde::de::DeserializeOwned>(
    body: &[u8],
) -> Result<T, Response<Full<Bytes>>> {
    serde_json::from_slice(body)
        .map_err(|err| bad_request(&format!("malformed request body: {err}")))
}

/// Maps a [`StoreError`] to a response. `NotFound` (e.g. revoking a `key_id`
/// the store has never seen) is a 404; anything else is a 500 carrying the
/// error's `Display` -- safe to expose because [`StoreError`]'s own doc
/// states it carries only a store-failure reason (redb/I/O error text) or
/// "not found", never key material.
fn store_error_response(endpoint: &str, err: StoreError) -> Response<Full<Bytes>> {
    match err {
        StoreError::NotFound => text(StatusCode::NOT_FOUND, "not found"),
        other => {
            tracing::warn!(endpoint, error = %other, "admin write failed: control-plane store error");
            text(StatusCode::INTERNAL_SERVER_ERROR, &other.to_string())
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MintKeyRequest {
    tenant: String,
    key_id: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateTenantRequest {
    tenant: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetPolicyRequest {
    access: AccessSpec,
}

/// External representation of [`ModelAccess`] over the wire: `"all"` (a bare
/// string) or `{"only": [...]}` -- the default externally-tagged shape
/// `#[derive(Deserialize)]` produces for an enum, which is exactly the two
/// shapes the task's request examples use.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AccessSpec {
    All,
    Only(Vec<String>),
}

fn handle_mint_key(control_plane: &ControlPlane, body: &[u8]) -> Response<Full<Bytes>> {
    let MintKeyRequest { tenant, key_id } = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if tenant.trim().is_empty() {
        return bad_request("tenant must not be empty");
    }
    if key_id.trim().is_empty() {
        return bad_request("key_id must not be empty");
    }

    match control_plane.mint_key(&TenantId::new(tenant), &KeyId::new(key_id)) {
        Ok(minted) => {
            tracing::info!(
                endpoint = "/keys",
                key_id = minted.key_id.as_str(),
                tenant = minted.tenant.as_str(),
                "admin: minted a virtual key"
            );
            // `minted.plaintext` is handed back here EXACTLY ONCE -- the
            // store persists only its digest (see `MintedKey`'s doc), so
            // this response body is the only place this value will ever
            // exist again after this call returns.
            json(
                StatusCode::CREATED,
                &serde_json::json!({
                    "key_id": minted.key_id.as_str(),
                    "tenant": minted.tenant.as_str(),
                    "key": minted.plaintext,
                }),
            )
        }
        Err(err) => store_error_response("/keys", err),
    }
}

fn handle_revoke_key(control_plane: &ControlPlane, key_id: &str) -> Response<Full<Bytes>> {
    if key_id.is_empty() {
        return bad_request("key_id must not be empty");
    }
    match control_plane.revoke_key(&KeyId::new(key_id)) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/keys/{id}",
                key_id,
                "admin: revoked a virtual key"
            );
            no_content()
        }
        Err(err) => store_error_response("/keys/{id}", err),
    }
}

fn handle_create_tenant(control_plane: &ControlPlane, body: &[u8]) -> Response<Full<Bytes>> {
    let CreateTenantRequest { tenant } = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if tenant.trim().is_empty() {
        return bad_request("tenant must not be empty");
    }
    match control_plane.create_tenant(&TenantId::new(tenant.clone())) {
        Ok(()) => {
            tracing::info!(endpoint = "/tenants", tenant = %tenant, "admin: created a tenant");
            json(
                StatusCode::CREATED,
                &serde_json::json!({ "tenant": tenant }),
            )
        }
        Err(err) => store_error_response("/tenants", err),
    }
}

fn handle_delete_tenant(control_plane: &ControlPlane, tenant: &str) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    match control_plane.delete_tenant(&TenantId::new(tenant)) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/tenants/{id}",
                tenant,
                "admin: deleted a tenant"
            );
            no_content()
        }
        Err(err) => store_error_response("/tenants/{id}", err),
    }
}

fn handle_set_policy(
    control_plane: &ControlPlane,
    tenant: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let request: SetPolicyRequest = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let access = match request.access {
        AccessSpec::All => ModelAccess::All,
        // An empty `only: []` is a legitimate, deliberate policy -- "deny
        // every model for this tenant" -- and MUST stay `Only(vec![])`
        // rather than collapsing to `All`. Doing so would be a silent
        // privilege escalation: an operator meaning to lock a tenant out of
        // every model until patterns are added would instead grant it
        // access to everything. See `ModelAccess`'s own doc for the same
        // point made from the type's side.
        AccessSpec::Only(patterns) => {
            ModelAccess::Only(patterns.into_iter().map(ModelPattern::new).collect())
        }
    };
    match control_plane.set_policy(&TenantId::new(tenant), &access) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/tenants/{id}/policy",
                tenant,
                "admin: set a tenant's model-access policy"
            );
            no_content()
        }
        Err(err) => store_error_response("/tenants/{id}/policy", err),
    }
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .expect("static response is always valid")
}

fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(value) {
        Ok(bytes) => Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(bytes)))
            .expect("static response is always valid"),
        Err(err) => {
            tracing::error!(error = %err, "admin server: failed to serialize response");
            text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to serialize response",
            )
        }
    }
}

#[derive(serde::Serialize)]
struct ServerInfo {
    version: &'static str,
    uptime_seconds: u64,
}

#[cfg(test)]
mod tests;
