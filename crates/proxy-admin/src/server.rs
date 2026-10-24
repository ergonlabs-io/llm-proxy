//! The admin HTTP server: binds a socket on the control runtime (ADR-0003) and answers the read-only
//! endpoints, plus a bearer-gated write API for the control plane, over real hyper connections.
//!
//! # The write API's `ControlPlane` is resolved per request
//!
//! `run_serve` (`crates/proxy/src/main.rs`) calls [`serve`] before the worker pool spawns, so no worker has
//! run `AuthFilterFactory::create` when this socket binds. Caching a `ControlPlane` (or `None`) at `serve()`
//! time would freeze that boot race into a permanent 503. Each write request therefore calls
//! [`resolve_control_plane`] fresh. See that function for what a miss means, and for the case where more than
//! one filter chain configures `llmproxy.auth`: this server has no chain scope, so it errors loudly rather
//! than guess.
//!
//! # The admin bearer token is a `serve()` parameter
//!
//! The convention mirrors `keygen`'s `LLMPROXY_AUTH_SECRET` with an env var, `LLMPROXY_ADMIN_TOKEN`. But
//! `std::env::var` is process-global and racy across parallel tests, so this module never reads it.
//! `start_admin` in `crates/proxy/src/main.rs` reads it once and passes it in. [`serve`] normalizes `None`,
//! empty, and whitespace-only to `None` in one place ([`normalize_admin_token`]), so both callers fail closed
//! the same way. **Unset never means open**; see the gate inside [`handle`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_control::auth::{KeyId, TenantId};
use proxy_control::control::{ControlPlane, CredentialStoreError, LimitPolicy, StoreError};
use proxy_control::model_authz::{ModelAccess, ModelPattern};
use proxy_control::spend::{
    parse_micro_usd, KeyBudget, MicroUsd, Period, SpendAccumulator, TenantBudget,
};
use proxy_control::tenant_credential_crypto::TenantSecret;
use proxy_core::lifecycle::LifecycleState;
use proxy_core::WorkerConfigHandle;
use proxy_credentials::CredentialSource;
use proxy_filters::spend_limit_filter::SharedSpendLimitState;
use proxy_filters::usage_filter::{PricingRegistry, PublishError};
use proxy_http::credential_probe::{
    CredentialProbeOutcome, CredentialProbeRequest, TenantCredentialProbe,
};
use proxy_http::filter::SharedFactoryState;
use proxy_observability::chargeback::{validate_key_tags, ChargebackTags};
use proxy_observability::ledger::{Ledger, LedgerQueryError, MAX_PAGE_ENTRIES};
use proxy_observability::records::LedgerEntry;
use proxy_observability::stats::{envoy_render, prometheus_render, Registry};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

mod auth_limit;
mod json_object;
use auth_limit::{AuthFailureLimiter, Verdict};
mod transport;
use transport::{AdminTransport, TransportCache, HANDSHAKE_TIMEOUT};

use crate::dump::{
    clusters_from_snapshot_and_live, models_from_snapshot, ClusterDump, ConfigDump, LiveCluster,
};

/// The endpoints this crate serves, used to route requests and to list them in a 404 body. `{id}` segments
/// are documentation only; routing is done by [`match_write_route`].
const AVAILABLE_ENDPOINTS: &[&str] = &[
    "/ready",
    // Gated lifecycle writes (POST); see `handle_lifecycle`.
    "/healthcheck/fail",
    "/healthcheck/ok",
    "/drain_listeners",
    "/config_dump",
    "/clusters",
    "/server_info",
    "/stats",
    "/stats/prometheus",
    "/ui",
    // Gated list reads live next to their write shapes below; `/models` is a
    // plain read (config data, like `/config_dump`).
    "/models",
    "/keys",
    "/keys/{id}",
    "/keys/{id}/budget",
    "/keys/{id}/limits",
    "/keys/{id}/policy",
    "/keys/{id}/tags",
    "/keys/{id}/spend",
    "/tenants",
    "/tenants/{id}",
    "/tenants/{id}/policy",
    "/tenants/{id}/budget",
    "/tenants/{id}/limits",
    "/tenants/{id}/trace_export",
    "/tenants/{id}/objects/{object_id}",
    "/tenants/{id}/provider_credentials",
    "/tenants/{id}/provider_credentials/{provider}",
    // A READ, but gated like a write -- see
    // `handle`'s route table and `lib.rs`'s module doc for why.
    "/tenants/{id}/spend",
    "/chains/{stat_prefix}/keys",
    "/chains/{stat_prefix}/keys/{id}",
    "/chains/{stat_prefix}/keys/{id}/budget",
    "/chains/{stat_prefix}/keys/{id}/limits",
    "/chains/{stat_prefix}/keys/{id}/policy",
    "/chains/{stat_prefix}/keys/{id}/tags",
    "/chains/{stat_prefix}/keys/{id}/spend",
    "/chains/{stat_prefix}/tenants",
    "/chains/{stat_prefix}/tenants/{id}",
    "/chains/{stat_prefix}/tenants/{id}/policy",
    "/chains/{stat_prefix}/tenants/{id}/budget",
    "/chains/{stat_prefix}/tenants/{id}/limits",
    "/chains/{stat_prefix}/tenants/{id}/trace_export",
    "/chains/{stat_prefix}/tenants/{id}/objects/{object_id}",
    "/chains/{stat_prefix}/tenants/{id}/provider_credentials",
    "/chains/{stat_prefix}/tenants/{id}/provider_credentials/{provider}",
    "/chains/{stat_prefix}/tenants/{id}/spend",
    "/pricing",
    "/chains/{stat_prefix}/pricing",
    // The billing ledger (ADR-0009 decision 8). Entries carry tenant and
    // user identity and charges, so both are bearer-gated.
    "/ledger/entries?after=<cursor>&limit=<1..=1000> (bearer-gated page of committed entries)",
    "/ledger/ack?through=<cursor> (bearer-gated POST that removes entries through the cursor)",
    // Trace export's emergency switch (ADR-0008 decision 2). Both gated.
    "/traces/capture (bearer-gated GET status; POST {disabled, expected_generation})",
];

/// Hard cap on a write request's body. No legitimate admin write is large (the biggest, a `PUT .../policy`,
/// is a handful of glob strings). Without a cap, reading `Incoming` would buffer an unbounded body. The port
/// is deliberately reachable without an IP allowlist, so this matters.
pub(super) const MAX_ADMIN_BODY_BYTES: usize = 64 * 1024;

/// Body cap for `PUT /pricing` alone. A rate card is machine-generated and large: the shipped OpenRouter card
/// is 401 KB pretty-printed. 4 MiB leaves about ten times that. The cap stays finite because only a token
/// holder reaches this read, and the buffer is released when the request ends. Every other route keeps
/// [`MAX_ADMIN_BODY_BYTES`].
pub(super) const MAX_PRICING_BODY_BYTES: usize = 4 * 1024 * 1024;

/// What `/ready` reports, as decided by whoever injects the [`ReadinessProbe`]. This crate never asks a
/// `ClusterManager` itself, so it takes no data-plane or generated-proto dependency (AGENTS.md invariant 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Serve traffic: `/ready` returns `200 "LIVE"`.
    Live,
    /// At least one cluster is still unresolved and the caller's warming deadline has not passed: `/ready`
    /// returns `503 "INITIALIZING"`. `warming` lists the unresolved clusters for the probe's owner to log. This
    /// module does not log: `/ready` is polled tightly, so a log per call would become the incident.
    Initializing { warming: Vec<String> },
    /// The process is out of rotation: `/healthcheck/fail` was called, or a drain started (SIGTERM or
    /// `POST /drain_listeners`). `/ready` returns `503 "DRAINING"`, Envoy's server-state text.
    Draining,
}

/// Where `/ready` gets its answer. A plain synchronous closure, since the real one only reads atomics.
/// `Arc<dyn Fn..>` because every accepted connection's task clones it, and a `dyn Fn` cannot be `Clone`.
/// With `None` (no probe wired, mostly tests), `/ready` returns `200 "LIVE"` unconditionally.
pub type ReadinessProbe = Arc<dyn Fn() -> Readiness + Send + Sync>;

/// Supplies a runtime host-set snapshot for one config snapshot. Injecting it keeps this crate free of
/// data-plane and generated-proto dependencies.
pub type ClusterStateProvider =
    Arc<dyn Fn(&proxy_config::ir::ConfigSnapshot) -> Vec<LiveCluster> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("admin server failed to bind {addr}: {source}")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    /// `admin_tls` names a certificate or key that cannot be loaded.
    #[error("admin server: {0}")]
    Tls(#[from] proxy_core::tls::TlsBuildError),
}

/// A running admin server. Dropping it does not stop the server; call [`AdminServer::abort`].
pub struct AdminServer {
    local_addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

/// Dependencies shared by every connection one admin server accepts. Cloning it clones only `Arc` handles and
/// optional closures.
#[derive(Clone)]
pub struct AdminRuntime {
    pub config: Arc<WorkerConfigHandle>,
    pub registry: Option<Arc<Registry>>,
    pub started_at: Instant,
    pub factory_state: Arc<SharedFactoryState>,
    pub admin_token: Option<String>,
    pub readiness: Option<ReadinessProbe>,
    pub cluster_state: Option<ClusterStateProvider>,
    /// Static files for the single-page admin UI under `/ui/`, loaded once
    /// at startup from the directory `make ui-build` produces
    /// (`admin-ui/dist/`). `None` keeps the API-only behavior and `/ui`
    /// answers 404 with a hint instead of an empty 200 -- the same honesty
    /// rule as the unwired-`/stats` 404 above.
    pub ui: Option<Arc<UiAssets>>,
    /// Shared lifecycle state behind `POST /healthcheck/fail`,
    /// `/healthcheck/ok`, and `/drain_listeners`. `None` makes those three
    /// answer 404 (after the token gate), the same honesty rule as the
    /// unwired `/stats`. The admin server only WRITES this state; `/ready`
    /// is still answered solely by [`ReadinessProbe`].
    pub lifecycle: Option<Arc<LifecycleState>>,
    /// Sends the save-time credential probe for
    /// `PUT /tenants/{id}/provider_credentials/{provider}` (ADR-0007
    /// decision 10). `None` refuses every save that asks for verification,
    /// so an unwired probe never reports a key as verified.
    pub credential_probe: Option<Arc<dyn proxy_http::credential_probe::TenantCredentialProbe>>,
    /// The billing ledger behind `/ledger/*` (ADR-0009 decision 8). `None`
    /// makes those endpoints answer 404 after the bearer gate.
    pub ledger: Option<Arc<Ledger>>,
    /// Trace export's emergency gate behind `/traces/capture`. `None` makes
    /// that endpoint answer 404 after the bearer gate.
    pub trace_gate: Option<Arc<proxy_observability::traces::gate::TraceGate>>,
}

/// One static file served under `/ui/`.
#[derive(Clone, Debug)]
struct UiFile {
    bytes: Vec<u8>,
    content_type: &'static str,
}

/// In-memory static assets for the admin UI, loaded once at startup -- never
/// read from disk per request, so request workers never touch the filesystem
/// (the same "control computes, workers read" split as the config snapshot).
///
/// Keys are paths relative to `/ui/` (`"index.html"`, `"assets/index-*.js"`);
/// `""` is never a key -- the handler maps an empty remainder to
/// `"index.html"` explicitly.
#[derive(Clone, Debug, Default)]
pub struct UiAssets {
    files: HashMap<String, UiFile>,
}

impl UiAssets {
    /// Loads every regular file under `dir` (recursively, so any vite output
    /// shape works) into memory. `dir/index.html` is required -- without it
    /// there is no SPA entry point and this returns an error naming the dir.
    pub fn load_from_dir(dir: &Path) -> std::io::Result<Self> {
        fn visit(
            base: &Path,
            dir: &Path,
            out: &mut HashMap<String, UiFile>,
        ) -> std::io::Result<()> {
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit(base, &path, out)?;
                } else if path.is_file() {
                    let rel = path
                        .strip_prefix(base)
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("unrelatable path {}", path.display()),
                            )
                        })?
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.insert(
                        rel.clone(),
                        UiFile {
                            bytes: std::fs::read(&path)?,
                            content_type: ui_content_type(&rel),
                        },
                    );
                }
            }
            Ok(())
        }

        let mut files = HashMap::new();
        visit(dir, dir, &mut files)?;
        if !files.contains_key("index.html") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "{}/index.html not found -- run `make ui-build` first",
                    dir.display()
                ),
            ));
        }
        Ok(Self { files })
    }

    /// Resolves a `/ui/` remainder to a file. Unknown remainders fall back to `index.html`, so client-side
    /// routes survive a refresh.
    fn lookup(&self, remainder: &str) -> Option<&UiFile> {
        let key = remainder.trim_start_matches('/');
        if key.is_empty() {
            return self.files.get("index.html");
        }
        self.files.get(key).or_else(|| self.files.get("index.html"))
    }
}

/// Content type by extension for `/ui/` assets. Unknown extensions get `application/octet-stream`, never a
/// guessed text type: serving attacker-influenced bytes as HTML or JS is how stored XSS rides a static server.
fn ui_content_type(path: &str) -> &'static str {
    match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

impl AdminServer {
    /// The address actually bound. Tests pass port 0 and read the OS-assigned port back from here.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stops accepting new connections. In-flight requests on accepted connections may still complete.
    pub fn abort(&self) {
        self.accept_task.abort();
    }
}

/// Collapses `None` and an empty or whitespace-only token to `None`, so an empty `LLMPROXY_ADMIN_TOKEN` fails
/// closed (403) like an unset one, instead of accepting an empty bearer value.
fn normalize_admin_token(token: Option<String>) -> Option<String> {
    match token {
        Some(value) if !value.trim().is_empty() => Some(value),
        _ => None,
    }
}

/// Pause after a failed admin `accept()`.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// At most one accept-failure warning per interval, so fd exhaustion cannot
/// flood the log (AGENTS.md "Fail-open controls").
const ACCEPT_WARN_INTERVAL: Duration = Duration::from_secs(10);

/// Rate limit for the admin accept-failure warning. Touched only after an
/// accept fails.
#[derive(Default)]
struct AcceptWarnings {
    last: Option<Instant>,
    suppressed: u64,
}

impl AcceptWarnings {
    /// `Some(n)` when a warning is due now, `n` being the failures suppressed
    /// since the previous one; `None` inside the interval.
    fn should_warn(&mut self, now: Instant) -> Option<u64> {
        match self.last {
            Some(last) if now.saturating_duration_since(last) < ACCEPT_WARN_INTERVAL => {
                self.suppressed += 1;
                None
            }
            _ => {
                self.last = Some(now);
                Some(std::mem::take(&mut self.suppressed))
            }
        }
    }
}

/// Binds `addr` and starts answering admin requests on the control runtime.
///
/// `config` is read per request via `load()`, an `Arc` clone of the last published snapshot (ADR-0005's
/// "control computes, workers read"). `registry` backs `/stats`, which returns 404 when `None` rather than an
/// empty `200`, since an empty `/stats` reads as no traffic. `started_at` backs `/server_info`'s uptime.
/// `factory_state` is the per-serve [`SharedFactoryState`] that `ControlPlane`s register into; `serve` never
/// reads it at startup (see the module doc). `admin_token` gates every WRITE endpoint (see
/// [`normalize_admin_token`]); READ endpoints are not gated by it. `readiness` answers `/ready`, and `None`
/// keeps the unconditional `200 "LIVE"`. `cluster_state` supplies `/clusters`, and `None` gives the
/// config-only view that older embedders and tests use.
///
/// Rust note: each accepted connection gets its own spawned task running one `hyper` `http1` connection.
/// Nothing here is `!Send`: this is ordinary control-plane code, not the worker-local data plane (ADR-0003).
pub async fn serve(addr: SocketAddr, runtime: AdminRuntime) -> Result<AdminServer, AdminError> {
    // One limiter per server, shared by every connection.
    let auth_limiter = Arc::new(AuthFailureLimiter::default());
    let admin_token = normalize_admin_token(runtime.admin_token.clone());
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|source| AdminError::Bind { addr, source })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| AdminError::Bind { addr, source })?;
    // Built before the first accept, so a certificate that cannot be loaded
    // fails the start instead of the first connection.
    let mut transports =
        TransportCache::new(&runtime.config.load(), local_addr, admin_token.is_some())?;

    let accept_task = tokio::spawn(async move {
        let mut accept_warnings = AcceptWarnings::default();
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    if let Some(suppressed) = accept_warnings.should_warn(Instant::now()) {
                        tracing::warn!(
                            error = %err,
                            suppressed,
                            "admin server: accept failed; retrying after a pause, and repeats in \
                             the next {}s are suppressed",
                            ACCEPT_WARN_INTERVAL.as_secs()
                        );
                    }
                    // A persistent error (EMFILE/ENFILE) leaves the listener
                    // readable, so an immediate retry would spin the control
                    // runtime. Same pause as the data-plane accept loop.
                    tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    continue;
                }
            };
            let transport = transports.current(&runtime.config.load());
            let mut runtime = runtime.clone();
            runtime.admin_token = admin_token.clone();
            let gate = GatePeer {
                ip: peer.ip(),
                limiter: Arc::clone(&auth_limiter),
            };
            tokio::spawn(async move {
                match transport {
                    AdminTransport::Plain => serve_connection(stream, runtime, gate).await,
                    AdminTransport::Tls(factory) => {
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, factory.wrap(stream)).await {
                            Ok(Ok(tls)) => serve_connection(tls, runtime, gate).await,
                            Ok(Err(err)) => {
                                tracing::debug!(error = %err, "admin server: TLS handshake failed");
                            }
                            Err(_) => tracing::debug!("admin server: TLS handshake timed out"),
                        }
                    }
                    AdminTransport::Unavailable => drop(stream),
                }
            });
        }
    });

    Ok(AdminServer {
        local_addr,
        accept_task,
    })
}

/// Answers admin requests on one accepted connection, plain or TLS.
async fn serve_connection<IO>(io: IO, runtime: AdminRuntime, gate: GatePeer)
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let runtime = runtime.clone();
        let gate = gate.clone();
        async move { Ok::<_, std::convert::Infallible>(handle(req, &runtime, &gate).await) }
    });
    if let Err(err) = hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(io), service)
        .await
    {
        tracing::debug!(error = %err, "admin server: connection error");
    }
}

async fn handle(
    req: Request<Incoming>,
    runtime: &AdminRuntime,
    peer: &GatePeer,
) -> Response<Full<Bytes>> {
    let config = &runtime.config;
    let registry = runtime.registry.as_deref();
    let started_at = runtime.started_at;
    let factory_state = &runtime.factory_state;
    let admin_token = runtime.admin_token.as_deref();
    let readiness = runtime.readiness.as_ref();
    let cluster_state = runtime.cluster_state.as_ref();
    // ---- Single-page admin UI (optional, in-memory, same-origin, so no CORS is needed): `GET /ui`, `GET /ui/`,
    // `GET /ui/<asset>`. Unknown sub-paths fall back to index.html. Matching is exact-prefix: `/uix` must not match.
    let path_str = req.uri().path();
    // The bare admin address is what a new user types first. With the UI loaded, send them to it; without it,
    // the 404 below lists the endpoints instead.
    if path_str == "/" && req.method() == Method::GET && runtime.ui.is_some() {
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(hyper::header::LOCATION, "/ui/")
            .body(Full::new(Bytes::new()))
            .expect("static response is always valid");
    }
    let ui_remainder = if path_str == "/ui" {
        Some("")
    } else {
        path_str.strip_prefix("/ui/")
    };
    if let Some(remainder) = ui_remainder {
        if req.method() != Method::GET {
            return text(StatusCode::METHOD_NOT_ALLOWED, "/ui only accepts GET");
        }
        return match runtime.ui.as_deref().and_then(|ui| ui.lookup(remainder)) {
            Some(file) => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", file.content_type)
                .header("cache-control", "no-store")
                .body(Full::new(Bytes::copy_from_slice(&file.bytes)))
                .expect("static response is always valid"),
            None => text(
                StatusCode::NOT_FOUND,
                "the admin UI is not loaded for this server instance; set \
                 LLMPROXY_ADMIN_UI_DIR to the UI bundle and restart: the \
                 `admin-ui-dist` directory of the release archive (the installer \
                 copies it next to the config), or `admin-ui/dist/` after \
                 `make ui-build` in a source checkout",
            ),
        };
    }
    if req.method() == Method::GET {
        let path = req.uri().path();
        let stat_prefix = path
            .strip_prefix("/chains/")
            .and_then(|rest| rest.strip_suffix("/pricing"))
            .filter(|name| !name.is_empty() && !name.contains('/'));
        if path == "/pricing" || stat_prefix.is_some() {
            return handle_get_pricing(factory_state, stat_prefix);
        }
    }
    // ---- Read endpoints. No gate; matched on path alone. ----
    match req.uri().path() {
        // With no probe wired, `200 "LIVE"` stays unconditional. See `ReadinessProbe`.
        "/ready" => {
            return match readiness.map(|probe| probe()) {
                None | Some(Readiness::Live) => text(StatusCode::OK, "LIVE"),
                Some(Readiness::Initializing { .. }) => {
                    text(StatusCode::SERVICE_UNAVAILABLE, "INITIALIZING")
                }
                Some(Readiness::Draining) => text(StatusCode::SERVICE_UNAVAILABLE, "DRAINING"),
            };
        }
        "/config_dump" => {
            let snapshot = config.load();
            return json(StatusCode::OK, &ConfigDump::from_snapshot(&snapshot));
        }
        "/clusters" => {
            let snapshot = config.load();
            let clusters = match cluster_state {
                Some(provider) => clusters_from_snapshot_and_live(&snapshot, &provider(&snapshot)),
                None => {
                    let mut clusters: Vec<ClusterDump> = snapshot
                        .clusters
                        .values()
                        .map(|c| ClusterDump::from_ir(c))
                        .collect();
                    clusters.sort_by(|a, b| a.name.cmp(&b.name));
                    clusters
                }
            };
            return json(StatusCode::OK, &clusters);
        }
        // Model inventory: every route this snapshot matches on the model header, rendered as the operator
        // configured it. Ungated like `/config_dump`, since it is config shape with no identity or spend. See
        // `dump::models_from_snapshot`.
        "/models" => {
            let snapshot = config.load();
            return json(StatusCode::OK, &models_from_snapshot(&snapshot));
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
        // Rendering only formats atomics already updated elsewhere, so it is safe on this path. With no registry
        // wired, keep the honest 404 rather than an empty `200`.
        "/stats" => {
            return match registry {
                Some(registry) => text(StatusCode::OK, &envoy_render::render(registry)),
                None => text(
                    StatusCode::NOT_FOUND,
                    "the stats registry is not configured for this admin server instance; \
                     this proxy does not fake an empty /stats",
                ),
            };
        }
        // Same shape as `/stats` above.
        "/stats/prometheus" => {
            return match registry {
                Some(registry) => text(StatusCode::OK, &prometheus_render::render(registry)),
                None => text(
                    StatusCode::NOT_FOUND,
                    "the stats registry is not configured for this admin server instance; \
                     this proxy does not fake an empty /stats/prometheus",
                ),
            };
        }
        _ => {}
    }

    // ---- Write endpoints, plus two gated reads: `.../spend` and `GET .../keys`. All go through the SAME three
    // gates. A GET on either renders per-tenant spend or the key inventory, which an unauthenticated caller must
    // not read. The other literal-path reads above are ungated. ----
    match req.uri().path() {
        "/ledger/entries" => return handle_ledger_entries(&req, runtime, peer).await,
        "/ledger/ack" => return handle_ledger_ack(req, runtime, peer).await,
        "/traces/capture" => return handle_traces_capture(req, runtime, peer).await,
        _ => {}
    }
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    // Rust note: split on `/` WITHOUT dropping empty segments. A trailing slash (`/keys/`) must yield a distinct
    // empty final segment, or `DELETE /keys/` would route as `/keys` (POST only) instead of hitting the empty-id
    // validation in `match_write_route`.
    let trimmed = path.strip_prefix('/').unwrap_or(path.as_str());
    let segments: Vec<&str> = trimmed.split('/').collect();

    let Some(route) = match_write_route(&segments, &method) else {
        return unknown_endpoint(&path);
    };

    if method != route.expected_method() {
        return text(
            StatusCode::METHOD_NOT_ALLOWED,
            &format!("{path} only accepts {}", route.expected_method()),
        );
    }

    // Gates 1 and 2: see `admin_gate`.
    if let Some(refusal) = admin_gate(&path, admin_token, req.headers(), peer) {
        return refusal;
    }

    // Lifecycle routes need no ControlPlane, so they leave after the same two
    // gates every other write passes (one gate, not a second copy of it).
    if let Some(action) = route.lifecycle_action() {
        return handle_lifecycle(action, runtime.lifecycle.as_deref(), req.uri().query());
    }

    // `PUT /pricing` needs the chain's rate card registry, not a control plane. It works without `llmproxy.auth`
    // (for this process only, and it says so). It has its own body cap, so it leaves before the control-plane
    // gate and the generic body read.
    if matches!(route, WriteRoute::Pricing | WriteRoute::ScopedPricing(_)) {
        let body = match read_limited_body(req.into_body(), MAX_PRICING_BODY_BYTES).await {
            Ok(bytes) => bytes,
            Err(resp) => return resp,
        };
        return handle_set_pricing(factory_state, route.stat_prefix(), &body);
    }

    // Gate 3: does the control plane exist, and is it unambiguous which one this write means?
    //
    // A SCOPED route names its chain and resolves through `SharedFactoryState::get_by_name`. Ambiguity is
    // impossible there (lowering rejects duplicate `stat_prefix`es), and an unknown name is a 404: an operator
    // typo, not a boot race.
    //
    // An UNSCOPED route falls back to `resolve_control_plane` (`get_across_scopes`), a single-chain convenience.
    // See that function for its 503 cases and for the multi-chain case it refuses.
    let stat_prefix_opt = route.stat_prefix();
    let control_plane = if let Some(stat_prefix) = stat_prefix_opt {
        match resolve_control_plane_by_name(factory_state, stat_prefix) {
            Some(cp) => cp,
            None => {
                return text(
                    StatusCode::NOT_FOUND,
                    &format!(
                        "no chain named '{stat_prefix}' registers an llmproxy.auth control \
                         plane -- check the HCM's stat_prefix in the config, or that its \
                         worker has finished building its filter chain"
                    ),
                );
            }
        }
    } else {
        match resolve_control_plane(factory_state) {
            Ok(Some(cp)) => cp,
            Ok(None) => {
                return text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the auth control plane is not initialized yet: either no llmproxy.auth \
                     filter is configured, or the workers have not finished building their \
                     filter chains yet -- retry shortly",
                );
            }
            Err(scopes) => {
                // Loud, not a guess (AGENTS.md "Fail-open controls"). Picking one of several ControlPlanes could
                // write a key into the wrong tenant's control plane.
                tracing::error!(
                    endpoint = %path,
                    scopes = ?scopes,
                    "admin write refused: more than one llmproxy.auth-configured filter chain \
                     is registered, so the unscoped admin API cannot tell which ControlPlane \
                     this write means -- use /chains/{{stat_prefix}}/... instead"
                );
                return text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "the unscoped admin write API cannot resolve a single auth control \
                         plane: {} filter chains each configure llmproxy.auth ({}) -- use \
                         /chains/{{stat_prefix}}/... to address one of them explicitly",
                        scopes.len(),
                        scopes.join(", "),
                    ),
                );
            }
        }
    };

    let body = match read_limited_body(req.into_body(), MAX_ADMIN_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(resp) => return resp,
    };

    // `body` moves into the handler so the handler can wipe the buffer holding the plaintext key. It stays async
    // for its save-time probe and offloads its own store calls.
    //
    // Rust note: `Option<Arc<dyn Trait>>::as_deref()` borrows the trait object out of the `Arc` without cloning it.
    if let WriteRoute::TenantCredentialPut(id, provider)
    | WriteRoute::ScopedTenantCredentialPut(_, id, provider) = route
    {
        return handle_put_tenant_credential(
            &control_plane,
            config,
            runtime.credential_probe.as_deref(),
            id,
            provider,
            body,
        )
        .await;
    }

    // Every other route here reads or writes the store, so it runs off the control runtime. The closure must own
    // what it uses, and `route` borrows `path`, so it moves `path` in and matches it again.
    let factory_state = Arc::clone(factory_state);
    run_store(move || {
        let trimmed = path.strip_prefix('/').unwrap_or(path.as_str());
        let segments: Vec<&str> = trimmed.split('/').collect();
        let route =
            match_write_route(&segments, &method).expect("the same path matched a route above");
        dispatch_store_route(route, &factory_state, &control_plane, &body, &path)
    })
    .await
}

/// Runs a handler that does blocking store I/O (a Redis round trip, a redb fsync, a full policy load) on tokio's
/// blocking pool. The admin server shares the 2-thread control runtime with ADS, the signal loop and `/ready`; a
/// slow store answered inline would stall all of them.
async fn run_store<F>(handler: F) -> Response<Full<Bytes>>
where
    F: FnOnce() -> Response<Full<Bytes>> + Send + 'static,
{
    off_runtime(handler)
        .await
        .unwrap_or_else(|response| response)
}

/// [`run_store`] for a step inside an async handler: the value, or the 500 to answer if the step panicked.
#[allow(clippy::result_large_err)]
async fn off_runtime<T, F>(step: F) -> Result<T, Response<Full<Bytes>>>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(step).await.map_err(|err| {
        tracing::error!(error = %err, "admin handler panicked");
        text(StatusCode::INTERNAL_SERVER_ERROR, "admin handler failed")
    })
}

/// The control-plane routes [`handle`] runs through [`run_store`]: everything except the credential `PUT`.
fn dispatch_store_route(
    route: WriteRoute<'_>,
    factory_state: &SharedFactoryState,
    control_plane: &ControlPlane,
    body: &[u8],
    path: &str,
) -> Response<Full<Bytes>> {
    let stat_prefix_opt = route.stat_prefix();
    match route {
        // `GET /keys` and `GET /chains/{p}/keys`: the gated list read, through the same three gates as the writes.
        WriteRoute::KeyList | WriteRoute::ScopedKeyList(_) => handle_list_keys(control_plane),
        WriteRoute::Keys | WriteRoute::ScopedKeys(_) => handle_mint_key(control_plane, body),
        WriteRoute::KeyById(id) | WriteRoute::ScopedKeyById(_, id) => {
            handle_revoke_key(control_plane, id)
        }
        WriteRoute::KeyBudget(id) | WriteRoute::ScopedKeyBudget(_, id) => {
            handle_set_key_budget(control_plane, id, body)
        }
        WriteRoute::KeyLimits(id) | WriteRoute::ScopedKeyLimits(_, id) => {
            handle_set_key_limits(factory_state, stat_prefix_opt, control_plane, id, body)
        }
        WriteRoute::KeyTags(id) | WriteRoute::ScopedKeyTags(_, id) => {
            handle_set_key_tags(control_plane, id, body)
        }
        WriteRoute::KeyPolicy(id) | WriteRoute::ScopedKeyPolicy(_, id) => {
            handle_set_key_policy(factory_state, stat_prefix_opt, control_plane, id, body)
        }
        WriteRoute::KeySpend(id) | WriteRoute::ScopedKeySpend(_, id) => {
            handle_get_key_spend_route(factory_state, stat_prefix_opt, control_plane, id, path)
        }
        WriteRoute::Tenants | WriteRoute::ScopedTenants(_) => {
            handle_create_tenant(control_plane, body)
        }
        WriteRoute::TenantById(id) | WriteRoute::ScopedTenantById(_, id) => {
            handle_delete_tenant(control_plane, id)
        }
        WriteRoute::TenantPolicy(id) | WriteRoute::ScopedTenantPolicy(_, id) => {
            handle_set_policy(factory_state, stat_prefix_opt, control_plane, id, body)
        }
        WriteRoute::TenantBudget(id) | WriteRoute::ScopedTenantBudget(_, id) => {
            handle_set_budget(factory_state, stat_prefix_opt, control_plane, id, body)
        }
        WriteRoute::TenantLimits(id) | WriteRoute::ScopedTenantLimits(_, id) => {
            handle_set_tenant_limits(factory_state, stat_prefix_opt, control_plane, id, body)
        }
        WriteRoute::TenantTraceExport(id) | WriteRoute::ScopedTenantTraceExport(_, id) => {
            handle_set_trace_export(control_plane, id, body)
        }
        WriteRoute::TenantTraceExportGet(id) | WriteRoute::ScopedTenantTraceExportGet(_, id) => {
            handle_get_trace_export(control_plane, id)
        }
        WriteRoute::TenantObject(id, object) | WriteRoute::ScopedTenantObject(_, id, object) => {
            handle_assign_object(factory_state, stat_prefix_opt, control_plane, id, object)
        }
        WriteRoute::TenantObjectGet(id, object)
        | WriteRoute::ScopedTenantObjectGet(_, id, object) => {
            handle_get_object(control_plane, id, object)
        }
        WriteRoute::TenantSpend(id) | WriteRoute::ScopedTenantSpend(_, id) => {
            handle_get_spend_route(factory_state, stat_prefix_opt, control_plane, id, path)
        }
        WriteRoute::TenantCredentials(id) | WriteRoute::ScopedTenantCredentials(_, id) => {
            handle_list_tenant_credentials(control_plane, id)
        }
        WriteRoute::TenantCredentialPut(..) | WriteRoute::ScopedTenantCredentialPut(..) => {
            unreachable!("the credential PUT returns before the store dispatch")
        }
        WriteRoute::TenantCredentialDelete(id, provider)
        | WriteRoute::ScopedTenantCredentialDelete(_, id, provider) => {
            handle_delete_tenant_credential(control_plane, id, provider)
        }
        WriteRoute::HealthCheckFail | WriteRoute::HealthCheckOk | WriteRoute::DrainListeners => {
            unreachable!("lifecycle routes return before the control-plane gate")
        }
        WriteRoute::Pricing | WriteRoute::ScopedPricing(_) => {
            unreachable!("pricing routes return before the control-plane gate")
        }
    }
}

/// The three lifecycle writes, split out of [`WriteRoute`] so
/// [`handle_lifecycle`] matches on a type with no control-plane variants.
#[derive(Clone, Copy)]
enum LifecycleAction {
    FailHealthCheck,
    RestoreHealthCheck,
    DrainListeners,
}

/// `POST /healthcheck/fail`, `/healthcheck/ok`, `/drain_listeners`. Callers have already passed the token gate.
///
/// `/drain_listeners` accepts the Envoy flags `graceful` and `inboundonly` (istio sends `?inboundonly&graceful`)
/// with no extra effect, since the drain is always graceful. Any other query parameter is a 400 that names it,
/// so a typo is never silently dropped. Logs carry only the action and whether state changed, never credentials.
fn handle_lifecycle(
    action: LifecycleAction,
    lifecycle: Option<&LifecycleState>,
    query: Option<&str>,
) -> Response<Full<Bytes>> {
    let Some(lifecycle) = lifecycle else {
        return text(
            StatusCode::NOT_FOUND,
            "lifecycle control is not configured for this admin server instance",
        );
    };
    match action {
        LifecycleAction::FailHealthCheck => {
            lifecycle.fail_health_check();
            tracing::info!("admin: health check set to fail; /ready now answers DRAINING");
        }
        LifecycleAction::RestoreHealthCheck => {
            lifecycle.restore_health_check();
            tracing::info!("admin: health check restored (a started drain is not undone)");
        }
        LifecycleAction::DrainListeners => {
            for param in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
                let name = param.split('=').next().unwrap_or(param);
                if name != "graceful" && name != "inboundonly" {
                    return bad_request(&format!(
                        "unsupported query parameter '{name}' on /drain_listeners; \
                         accepted: graceful, inboundonly"
                    ));
                }
            }
            if lifecycle.request_drain() {
                tracing::info!("admin: drain requested via /drain_listeners");
            } else {
                tracing::info!("admin: /drain_listeners called while already draining");
            }
        }
    }
    text(StatusCode::OK, "OK")
}

/// One write-capable path this server recognizes, with its path parameters borrowed from the request. It is
/// separate from method matching ([`WriteRoute::expected_method`]), so a known path with the wrong method gets
/// a 405, not the generic 404.
///
/// The `Scoped*` variants (`/chains/{stat_prefix}/...`) sit beside the unscoped ones. [`Self::stat_prefix`]
/// tells the two families apart for [`handle`]'s control-plane gate.
///
/// The `TenantSpend` and `KeyList` families (and their `Scoped` forms) are GETs, despite the name. They share
/// this type because they need the same gate and control-plane resolution as the writes. A key inventory is
/// identity data (which keys exist, which tenant owns them, what ceiling they run against), and spend is money.
/// Neither is answerable to an unauthenticated caller just because the verb is GET.
enum WriteRoute<'a> {
    /// `PUT` and `GET /tenants/{id}/trace_export`: a tenant's trace-export
    /// opt-in (ADR-0008 decision 2). Split by method like the key collection.
    TenantTraceExport(&'a str),
    TenantTraceExportGet(&'a str),
    ScopedTenantTraceExport(&'a str, &'a str),
    ScopedTenantTraceExportGet(&'a str, &'a str),
    /// `PUT /tenants/{id}/objects/{object_id}`: assigns a provider object no
    /// tenant owns yet to the tenant. `GET` reads whether it owns one.
    TenantObject(&'a str, &'a str),
    TenantObjectGet(&'a str, &'a str),
    ScopedTenantObject(&'a str, &'a str, &'a str),
    ScopedTenantObjectGet(&'a str, &'a str, &'a str),
    /// `GET /keys` -- the gated list read. Distinct from [`Self::Keys`]
    /// (POST, mint) so a GET is never answered with a 405 and a POST never
    /// with a listing.
    KeyList,
    Keys,
    KeyById(&'a str),
    KeyBudget(&'a str),
    KeyLimits(&'a str),
    KeyPolicy(&'a str),
    /// `PUT /keys/{id}/tags`: replaces the key's chargeback tags.
    KeyTags(&'a str),
    KeySpend(&'a str),
    Tenants,
    TenantById(&'a str),
    TenantPolicy(&'a str),
    TenantBudget(&'a str),
    TenantLimits(&'a str),
    TenantSpend(&'a str),
    /// `GET /tenants/{id}/provider_credentials` -- metadata only, gated like
    /// the other identity reads (ADR-0007 decision 9).
    TenantCredentials(&'a str),
    /// `PUT /tenants/{id}/provider_credentials/{provider}`.
    TenantCredentialPut(&'a str, &'a str),
    /// `DELETE /tenants/{id}/provider_credentials/{provider}`.
    TenantCredentialDelete(&'a str, &'a str),
    ScopedTenantCredentials(&'a str, &'a str),
    ScopedTenantCredentialPut(&'a str, &'a str, &'a str),
    ScopedTenantCredentialDelete(&'a str, &'a str, &'a str),
    /// `GET /chains/{stat_prefix}/keys` -- the scoped listing.
    ScopedKeyList(&'a str),
    ScopedKeys(&'a str),
    ScopedKeyById(&'a str, &'a str),
    ScopedKeyBudget(&'a str, &'a str),
    ScopedKeyLimits(&'a str, &'a str),
    ScopedKeyPolicy(&'a str, &'a str),
    ScopedKeyTags(&'a str, &'a str),
    ScopedKeySpend(&'a str, &'a str),
    ScopedTenants(&'a str),
    ScopedTenantById(&'a str, &'a str),
    ScopedTenantPolicy(&'a str, &'a str),
    ScopedTenantBudget(&'a str, &'a str),
    ScopedTenantLimits(&'a str, &'a str),
    ScopedTenantSpend(&'a str, &'a str),
    Pricing,
    ScopedPricing(&'a str),
    /// `POST /healthcheck/fail`, `/healthcheck/ok`, `/drain_listeners`: gated
    /// like a write but they touch no `ControlPlane`; see
    /// [`Self::lifecycle_action`].
    HealthCheckFail,
    HealthCheckOk,
    DrainListeners,
}

impl<'a> WriteRoute<'a> {
    fn expected_method(&self) -> Method {
        match self {
            WriteRoute::Keys | WriteRoute::Tenants => Method::POST,
            WriteRoute::KeyById(_) | WriteRoute::TenantById(_) => Method::DELETE,
            WriteRoute::KeyBudget(_)
            | WriteRoute::KeyLimits(_)
            | WriteRoute::KeyPolicy(_)
            | WriteRoute::KeyTags(_) => Method::PUT,
            WriteRoute::KeySpend(_) => Method::GET,
            // The gated list read: GET on the collection path.
            WriteRoute::KeyList | WriteRoute::ScopedKeyList(_) => Method::GET,
            WriteRoute::TenantPolicy(_) => Method::PUT,
            WriteRoute::TenantTraceExport(_) | WriteRoute::ScopedTenantTraceExport(..) => {
                Method::PUT
            }
            WriteRoute::TenantTraceExportGet(_) | WriteRoute::ScopedTenantTraceExportGet(..) => {
                Method::GET
            }
            WriteRoute::TenantObject(..) | WriteRoute::ScopedTenantObject(..) => Method::PUT,
            WriteRoute::TenantObjectGet(..) | WriteRoute::ScopedTenantObjectGet(..) => Method::GET,
            WriteRoute::TenantBudget(_) | WriteRoute::TenantLimits(_) => Method::PUT,
            WriteRoute::TenantSpend(_) | WriteRoute::ScopedTenantSpend(..) => Method::GET,
            WriteRoute::TenantCredentials(_) | WriteRoute::ScopedTenantCredentials(..) => {
                Method::GET
            }
            WriteRoute::TenantCredentialPut(..) | WriteRoute::ScopedTenantCredentialPut(..) => {
                Method::PUT
            }
            WriteRoute::TenantCredentialDelete(..)
            | WriteRoute::ScopedTenantCredentialDelete(..) => Method::DELETE,
            WriteRoute::Pricing | WriteRoute::ScopedPricing(_) => Method::PUT,
            WriteRoute::HealthCheckFail
            | WriteRoute::HealthCheckOk
            | WriteRoute::DrainListeners => Method::POST,
            WriteRoute::ScopedKeys(_) | WriteRoute::ScopedTenants(_) => Method::POST,
            WriteRoute::ScopedKeyById(..) | WriteRoute::ScopedTenantById(..) => Method::DELETE,
            WriteRoute::ScopedKeyBudget(..)
            | WriteRoute::ScopedKeyLimits(..)
            | WriteRoute::ScopedKeyPolicy(..)
            | WriteRoute::ScopedKeyTags(..) => Method::PUT,
            WriteRoute::ScopedKeySpend(..) => Method::GET,
            WriteRoute::ScopedTenantPolicy(..) => Method::PUT,
            WriteRoute::ScopedTenantBudget(..) | WriteRoute::ScopedTenantLimits(..) => Method::PUT,
        }
    }

    fn lifecycle_action(&self) -> Option<LifecycleAction> {
        match self {
            WriteRoute::HealthCheckFail => Some(LifecycleAction::FailHealthCheck),
            WriteRoute::HealthCheckOk => Some(LifecycleAction::RestoreHealthCheck),
            WriteRoute::DrainListeners => Some(LifecycleAction::DrainListeners),
            _ => None,
        }
    }

    /// `Some(stat_prefix)` for a `/chains/{stat_prefix}/...` route, `None`
    /// for an unscoped one -- `handle`'s single branch point between
    /// `get_by_name` (scoped, always-correct) and `get_across_scopes`
    /// (unscoped, the convenience alias).
    fn stat_prefix(&self) -> Option<&'a str> {
        match self {
            WriteRoute::KeyList
            | WriteRoute::Keys
            | WriteRoute::KeyById(_)
            | WriteRoute::KeyBudget(_)
            | WriteRoute::KeyLimits(_)
            | WriteRoute::KeyPolicy(_)
            | WriteRoute::KeyTags(_)
            | WriteRoute::KeySpend(_)
            | WriteRoute::Tenants
            | WriteRoute::TenantById(_)
            | WriteRoute::TenantPolicy(_)
            | WriteRoute::TenantBudget(_)
            | WriteRoute::TenantLimits(_)
            | WriteRoute::TenantTraceExport(_)
            | WriteRoute::TenantTraceExportGet(_)
            | WriteRoute::TenantObject(..)
            | WriteRoute::TenantObjectGet(..)
            | WriteRoute::TenantSpend(_)
            | WriteRoute::TenantCredentials(_)
            | WriteRoute::TenantCredentialPut(..)
            | WriteRoute::TenantCredentialDelete(..)
            | WriteRoute::HealthCheckFail
            | WriteRoute::HealthCheckOk
            | WriteRoute::DrainListeners => None,
            WriteRoute::ScopedKeyList(s)
            | WriteRoute::ScopedKeys(s)
            | WriteRoute::ScopedTenants(s)
            | WriteRoute::ScopedKeyById(s, _)
            | WriteRoute::ScopedKeyBudget(s, _)
            | WriteRoute::ScopedKeyLimits(s, _)
            | WriteRoute::ScopedKeyPolicy(s, _)
            | WriteRoute::ScopedKeyTags(s, _)
            | WriteRoute::ScopedKeySpend(s, _)
            | WriteRoute::ScopedTenantById(s, _)
            | WriteRoute::ScopedTenantPolicy(s, _)
            | WriteRoute::ScopedTenantBudget(s, _)
            | WriteRoute::ScopedTenantLimits(s, _)
            | WriteRoute::ScopedTenantTraceExport(s, _)
            | WriteRoute::ScopedTenantTraceExportGet(s, _)
            | WriteRoute::ScopedTenantObject(s, ..)
            | WriteRoute::ScopedTenantObjectGet(s, ..)
            | WriteRoute::ScopedTenantSpend(s, _)
            | WriteRoute::ScopedTenantCredentials(s, _)
            | WriteRoute::ScopedTenantCredentialPut(s, ..)
            | WriteRoute::ScopedTenantCredentialDelete(s, ..) => Some(s),
            WriteRoute::Pricing => None,
            WriteRoute::ScopedPricing(s) => Some(s),
        }
    }
}

/// Matches `segments` (the request path with the leading slash stripped, split on `/`, empty segments kept)
/// against the write-endpoint shapes.
///
/// Percent-decoding is deliberately not performed. An id containing a literal `/` cannot be addressed through
/// this API: it splits into extra segments, matches nothing, and gets the generic 404. No caller mints such an
/// id, so this is a known limitation.
///
/// An empty id segment (`/keys/`) still matches its shape. The handlers in [`handle`] reject it with 400, a
/// validation failure rather than a routing one.
///
/// `method` matters for one kind of shape: the key collection paths (`/keys` and `/chains/{stat_prefix}/keys`),
/// where `GET` is the gated listing and every other verb is the mint. Elsewhere the path decides, and
/// [`WriteRoute::expected_method`] answers a wrong verb with 405. Reading `method` here, before the gate, means
/// a wrong verb on a real path gets 405 rather than a forbidden response, since routing precedes authorization.
fn match_write_route<'a>(segments: &[&'a str], method: &Method) -> Option<WriteRoute<'a>> {
    match segments {
        ["keys"] if *method == Method::GET => Some(WriteRoute::KeyList),
        ["keys"] => Some(WriteRoute::Keys),
        ["keys", id] => Some(WriteRoute::KeyById(id)),
        ["keys", id, "budget"] => Some(WriteRoute::KeyBudget(id)),
        ["keys", id, "limits"] => Some(WriteRoute::KeyLimits(id)),
        ["keys", id, "policy"] => Some(WriteRoute::KeyPolicy(id)),
        ["keys", id, "tags"] => Some(WriteRoute::KeyTags(id)),
        ["keys", id, "spend"] => Some(WriteRoute::KeySpend(id)),
        ["tenants"] => Some(WriteRoute::Tenants),
        ["tenants", id] => Some(WriteRoute::TenantById(id)),
        ["tenants", id, "policy"] => Some(WriteRoute::TenantPolicy(id)),
        ["tenants", id, "budget"] => Some(WriteRoute::TenantBudget(id)),
        ["tenants", id, "limits"] => Some(WriteRoute::TenantLimits(id)),
        ["tenants", id, "trace_export"] if *method == Method::GET => {
            Some(WriteRoute::TenantTraceExportGet(id))
        }
        ["tenants", id, "trace_export"] => Some(WriteRoute::TenantTraceExport(id)),
        ["tenants", id, "objects", object] if *method == Method::GET => {
            Some(WriteRoute::TenantObjectGet(id, object))
        }
        ["tenants", id, "objects", object] => Some(WriteRoute::TenantObject(id, object)),
        // A GET, gated like a write -- see `WriteRoute`'s doc.
        ["tenants", id, "spend"] => Some(WriteRoute::TenantSpend(id)),
        ["tenants", id, "provider_credentials"] => Some(WriteRoute::TenantCredentials(id)),
        // DELETE is the only other verb with a route here; any non-DELETE verb
        // maps to the PUT shape so a wrong verb answers 405 "only accepts PUT".
        ["tenants", id, "provider_credentials", provider] if *method == Method::DELETE => {
            Some(WriteRoute::TenantCredentialDelete(id, provider))
        }
        ["tenants", id, "provider_credentials", provider] => {
            Some(WriteRoute::TenantCredentialPut(id, provider))
        }
        ["chains", stat_prefix, "tenants", id, "provider_credentials"] => {
            Some(WriteRoute::ScopedTenantCredentials(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants", id, "provider_credentials", provider]
            if *method == Method::DELETE =>
        {
            Some(WriteRoute::ScopedTenantCredentialDelete(
                stat_prefix,
                id,
                provider,
            ))
        }
        ["chains", stat_prefix, "tenants", id, "provider_credentials", provider] => Some(
            WriteRoute::ScopedTenantCredentialPut(stat_prefix, id, provider),
        ),
        // The scoped forms, addressed by the chain's
        // operator-chosen `stat_prefix` -- see `WriteRoute`'s doc.
        ["chains", stat_prefix, "keys"] if *method == Method::GET => {
            Some(WriteRoute::ScopedKeyList(stat_prefix))
        }
        ["chains", stat_prefix, "keys"] => Some(WriteRoute::ScopedKeys(stat_prefix)),
        ["chains", stat_prefix, "keys", id] => Some(WriteRoute::ScopedKeyById(stat_prefix, id)),
        ["chains", stat_prefix, "keys", id, "budget"] => {
            Some(WriteRoute::ScopedKeyBudget(stat_prefix, id))
        }
        ["chains", stat_prefix, "keys", id, "limits"] => {
            Some(WriteRoute::ScopedKeyLimits(stat_prefix, id))
        }
        ["chains", stat_prefix, "keys", id, "policy"] => {
            Some(WriteRoute::ScopedKeyPolicy(stat_prefix, id))
        }
        ["chains", stat_prefix, "keys", id, "tags"] => {
            Some(WriteRoute::ScopedKeyTags(stat_prefix, id))
        }
        ["chains", stat_prefix, "keys", id, "spend"] => {
            Some(WriteRoute::ScopedKeySpend(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants"] => Some(WriteRoute::ScopedTenants(stat_prefix)),
        ["chains", stat_prefix, "tenants", id] => {
            Some(WriteRoute::ScopedTenantById(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants", id, "policy"] => {
            Some(WriteRoute::ScopedTenantPolicy(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants", id, "budget"] => {
            Some(WriteRoute::ScopedTenantBudget(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants", id, "limits"] => {
            Some(WriteRoute::ScopedTenantLimits(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants", id, "trace_export"] if *method == Method::GET => {
            Some(WriteRoute::ScopedTenantTraceExportGet(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants", id, "trace_export"] => {
            Some(WriteRoute::ScopedTenantTraceExport(stat_prefix, id))
        }
        ["chains", stat_prefix, "tenants", id, "objects", object] if *method == Method::GET => {
            Some(WriteRoute::ScopedTenantObjectGet(stat_prefix, id, object))
        }
        ["chains", stat_prefix, "tenants", id, "objects", object] => {
            Some(WriteRoute::ScopedTenantObject(stat_prefix, id, object))
        }
        ["chains", stat_prefix, "tenants", id, "spend"] => {
            Some(WriteRoute::ScopedTenantSpend(stat_prefix, id))
        }
        ["pricing"] => Some(WriteRoute::Pricing),
        ["healthcheck", "fail"] => Some(WriteRoute::HealthCheckFail),
        ["healthcheck", "ok"] => Some(WriteRoute::HealthCheckOk),
        ["drain_listeners"] => Some(WriteRoute::DrainListeners),
        ["chains", stat_prefix, "pricing"] => Some(WriteRoute::ScopedPricing(stat_prefix)),
        _ => None,
    }
}

/// Resolves the live [`ControlPlane`] that a worker's `AuthFilterFactory` registered, keyed on the filter's
/// `TYPE_URL` across every chain's scope. The admin server belongs to no chain, so it reads
/// [`SharedFactoryState::get_across_scopes`] rather than a scoped `get`.
///
/// `Ok(None)` covers two cases, both mapped to 503 by the caller: a boot race (`serve()` runs before the
/// workers build their chains, so an early request finds nothing yet), and a config with no `llmproxy.auth` at
/// all. Both mean "the write cannot be served right now".
///
/// `Err(scopes)` is a different case: more than one chain configures `llmproxy.auth`. No single scope is what
/// this endpoint means, and guessing (for example "the first registered") could write a key into the wrong
/// tenant's control plane. The caller therefore gets an explicit error naming every scope.
fn resolve_control_plane(
    factory_state: &SharedFactoryState,
) -> Result<Option<Arc<ControlPlane>>, Vec<String>> {
    let singleton = factory_state.get_across_scopes(proxy_filters::auth_filter::TYPE_URL)?;
    Ok(singleton.and_then(|s| s.downcast::<ControlPlane>().ok()))
}

/// Resolves the [`ControlPlane`] registered under the chain named `stat_prefix`, the scoped counterpart of
/// [`resolve_control_plane`]. `None` means no chain with that name has registered one. [`handle`] reports that
/// as 404: there is no ambiguity to report, and the name is either a typo or its worker has not finished
/// building the chain yet.
fn resolve_control_plane_by_name(
    factory_state: &SharedFactoryState,
    stat_prefix: &str,
) -> Option<Arc<ControlPlane>> {
    factory_state
        .get_by_name(stat_prefix, proxy_filters::auth_filter::TYPE_URL)
        .and_then(|s| s.downcast::<ControlPlane>().ok())
}

fn resolve_pricing_registry(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
) -> Result<Option<Arc<PricingRegistry>>, Vec<String>> {
    let singleton = match stat_prefix {
        Some(name) => factory_state.get_by_name(name, proxy_filters::usage_filter::TYPE_URL),
        None => factory_state
            .get_across_scopes(proxy_filters::usage_filter::TYPE_URL)?
            .as_ref()
            .map(Arc::clone),
    };
    Ok(singleton.and_then(|s| s.downcast::<PricingRegistry>().ok()))
}

fn handle_set_pricing(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    body: &[u8],
) -> Response<Full<Bytes>> {
    let Ok(registry) = resolve_pricing_registry(factory_state, stat_prefix) else {
        return text(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the unscoped pricing API cannot resolve a single usage filter chain",
        );
    };
    let Some(registry) = registry else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "llmproxy.usage is not initialized on this chain",
        );
    };
    let Ok(document) = std::str::from_utf8(body) else {
        return text(StatusCode::BAD_REQUEST, "the rate card is not valid UTF-8");
    };
    match registry.publish_json(document) {
        Ok(published) => json(
            StatusCode::OK,
            &serde_json::json!({
                "rate_card_version": published.rate_card_version,
                "persisted": published.persisted,
                "note": published.note,
            }),
        ),
        Err(PublishError::Invalid(error)) => text(StatusCode::BAD_REQUEST, &error),
        // The store did not take the card, so nothing changed anywhere.
        Err(PublishError::Store(error)) => text(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("the rate card was not changed: the control-plane store refused it: {error}"),
        ),
    }
}

fn handle_get_pricing(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
) -> Response<Full<Bytes>> {
    let registry = match resolve_pricing_registry(factory_state, stat_prefix) {
        Ok(Some(registry)) => registry,
        Ok(None) => {
            return text(
                StatusCode::SERVICE_UNAVAILABLE,
                "llmproxy.usage is not initialized on this chain",
            );
        }
        Err(scopes) => {
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                &format!(
                    "the unscoped pricing API cannot resolve a single usage filter chain: {}",
                    scopes.join(", ")
                ),
            );
        }
    };
    match registry.json_view() {
        Some(view) => json(StatusCode::OK, &view),
        None => text(
            StatusCode::SERVICE_UNAVAILABLE,
            "llmproxy.usage has no active pricing rate card",
        ),
    }
}

/// Resolves the [`SpendAccumulator`] singleton that `llmproxy.spend_limit` registers, across every chain's
/// scope. The counterpart of [`resolve_control_plane`], for the unscoped `GET /tenants/{id}/spend` alias.
///
/// What is registered under [`proxy_filters::spend_limit_filter::TYPE_URL`] is a [`SharedSpendLimitState`]
/// wrapper, never a bare `Arc<SpendAccumulator>`. The factory bundles the accumulator with its usage-missing
/// warner behind one slot (see that type's doc). Downcasting straight to `SpendAccumulator` would fail on every
/// real chain.
///
/// `Ok(None)` covers a boot race and "no chain configures `llmproxy.spend_limit`"; both map to 503. `Err(scopes)`
/// cannot happen in practice: `llmproxy.spend_limit` requires `llmproxy.auth` in the same chain, and the
/// control-plane gate has already refused ambiguity. It is kept for parity with [`resolve_control_plane`].
fn resolve_spend_state(
    factory_state: &SharedFactoryState,
) -> Result<Option<Arc<SpendAccumulator>>, Vec<String>> {
    let singleton = factory_state.get_across_scopes(proxy_filters::spend_limit_filter::TYPE_URL)?;
    Ok(singleton
        .and_then(|s| s.downcast::<SharedSpendLimitState>().ok())
        .map(|shared| Arc::clone(shared.accumulator())))
}

/// The chain's spend filter state, scoped when `stat_prefix` is given and
/// across scopes otherwise. `None` covers "no spend filter on this chain" and
/// the unscoped ambiguity case, which the control-plane gate has already
/// refused by the time a handler asks.
fn resolve_spend_shared(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
) -> Option<Arc<SharedSpendLimitState>> {
    let singleton = match stat_prefix {
        Some(name) => factory_state.get_by_name(name, proxy_filters::spend_limit_filter::TYPE_URL),
        None => factory_state
            .get_across_scopes(proxy_filters::spend_limit_filter::TYPE_URL)
            .ok()
            .flatten(),
    };
    singleton.and_then(|s| s.downcast::<SharedSpendLimitState>().ok())
}

/// The scoped (`/chains/{stat_prefix}/...`) counterpart of
/// [`resolve_spend_state`] -- see that function's doc for the wrapper-type
/// downcast this also performs, and [`resolve_control_plane_by_name`]'s doc
/// for why a `stat_prefix` lookup carries no ambiguity to report.
fn resolve_spend_state_by_name(
    factory_state: &SharedFactoryState,
    stat_prefix: &str,
) -> Option<Arc<SpendAccumulator>> {
    factory_state
        .get_by_name(stat_prefix, proxy_filters::spend_limit_filter::TYPE_URL)
        .and_then(|s| s.downcast::<SharedSpendLimitState>().ok())
        .map(|shared| Arc::clone(shared.accumulator()))
}

/// Reads `body` up to `cap` bytes ([`MAX_ADMIN_BODY_BYTES`] for every route but pricing), returning the bytes
/// or a ready-to-send 413.
///
/// Rust note: `http_body_util::Limited` turns "read past the cap" into an error, instead of unbounded
/// buffering. `downcast_ref::<LengthLimitError>` tells "cap hit" (413) apart from "connection died mid-body"
/// (400).
// Cold admin path: the large `Err` variant is a ready-to-send response, so boxing it buys nothing.
#[allow(clippy::result_large_err)]
async fn read_limited_body(body: Incoming, cap: usize) -> Result<Bytes, Response<Full<Bytes>>> {
    match Limited::new(body, cap).collect().await {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(err) => {
            if err
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                Err(text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &format!("request body exceeds the {cap}-byte cap for this endpoint"),
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

/// The shared admin gate, for every write and every sensitive read. `Some` is the refusal; `None` means proceed.
///
/// Gate 1: is the API enabled? An unset, empty, or whitespace-only `LLMPROXY_ADMIN_TOKEN` means "not
/// configured", never "open" (AGENTS.md "Fail-open controls"). This fail-closed default must not be reachable
/// from any other branch.
///
/// Gate 2: does the caller present the configured token? A 401 carries a `www-authenticate` challenge
/// (RFC 7235), as `auth_filter.rs`'s `AuthFilterInstance::deny` does on the data plane.
fn admin_gate(
    path: &str,
    admin_token: Option<&str>,
    headers: &HeaderMap,
    peer: &GatePeer,
) -> Option<Response<Full<Bytes>>> {
    let Some(token) = admin_token else {
        tracing::warn!(
            endpoint = %path,
            peer = %peer.ip,
            "admin request refused: LLMPROXY_ADMIN_TOKEN is not set, so admin write endpoints are disabled"
        );
        return Some(text(
            StatusCode::FORBIDDEN,
            "admin write endpoints are disabled because LLMPROXY_ADMIN_TOKEN is not set",
        ));
    };
    // Gate 2a: a peer past its failed-token budget is refused before its
    // token is even compared (see `auth_limit`'s module doc).
    let now = Instant::now();
    if let Verdict::Limited { retry_after, first } = peer.limiter.check(peer.ip, now) {
        if first {
            tracing::warn!(
                endpoint = %path,
                peer = %peer.ip,
                max_failures = auth_limit::MAX_FAILURES,
                window_seconds = auth_limit::WINDOW.as_secs(),
                retry_after_seconds = retry_after.as_secs(),
                "admin requests from this peer are refused (429) after repeated invalid \
                 bearer tokens"
            );
        }
        let mut response = text(
            StatusCode::TOO_MANY_REQUESTS,
            "too many invalid admin bearer tokens from this address; retry later",
        );
        // Whole seconds, rounded up, so a client that honours it is not
        // refused again for the remaining fraction.
        let seconds = retry_after.as_secs() + u64::from(retry_after.subsec_nanos() > 0);
        response.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from(seconds),
        );
        return Some(response);
    }
    let authorized = match extract_bearer(headers) {
        Some(candidate) => secrets_match(candidate.as_bytes(), token.as_bytes()),
        None => false,
    };
    if !authorized {
        peer.limiter.record_failure(peer.ip, now);
        // The peer and the endpoint only: never the presented value, which
        // may be a near-miss of the real token.
        tracing::warn!(
            endpoint = %path,
            peer = %peer.ip,
            "admin request refused: missing or invalid bearer token"
        );
        return Some(unauthorized("missing or invalid bearer token"));
    }
    peer.limiter.record_success(peer.ip);
    None
}

/// The connection a request arrived on, as the admin gate needs it: the peer
/// address it logs and limits by, and the server's shared limiter.
#[derive(Clone)]
struct GatePeer {
    ip: IpAddr,
    limiter: Arc<AuthFailureLimiter>,
}

const TRACES_NOT_CONFIGURED: &str = "no trace export is configured for this proxy; \
     /traces/capture needs observability.traces (node.metadata[\"io.llmproxy.traces\"] in Envoy mode)";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetTraceCaptureRequest {
    disabled: bool,
    expected_generation: u64,
}

/// `GET /traces/capture` reports the emergency gate; `POST` closes or opens
/// it with a compare-and-set on its generation (ADR-0008 decision 2). A
/// disable always takes effect, and the answer's `persisted` says whether it
/// will survive a restart.
async fn handle_traces_capture(
    req: Request<Incoming>,
    runtime: &AdminRuntime,
    peer: &GatePeer,
) -> Response<Full<Bytes>> {
    if req.method() != Method::GET && req.method() != Method::POST {
        return text(
            StatusCode::METHOD_NOT_ALLOWED,
            "/traces/capture accepts GET and POST",
        );
    }
    if let Some(refusal) = admin_gate(
        req.uri().path(),
        runtime.admin_token.as_deref(),
        req.headers(),
        peer,
    ) {
        return refusal;
    }
    let Some(gate) = runtime.trace_gate.clone() else {
        return text(StatusCode::NOT_FOUND, TRACES_NOT_CONFIGURED);
    };
    if req.method() == Method::GET {
        return json(StatusCode::OK, &gate.status());
    }
    let body = match read_limited_body(req.into_body(), MAX_ADMIN_BODY_BYTES).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let request: SetTraceCaptureRequest = match parse_json_body(&body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    use proxy_observability::traces::gate::GateError;
    match gate.set_disabled(request.disabled, request.expected_generation) {
        Ok(change) => {
            tracing::warn!(
                disabled = change.status.disabled,
                generation = change.status.generation,
                persisted = change.persisted,
                "admin: trace capture gate changed"
            );
            json(StatusCode::OK, &change)
        }
        Err(GateError::Stale { current }) => json(
            StatusCode::CONFLICT,
            &serde_json::json!({"error": "stale_generation", "generation": current}),
        ),
        Err(error @ GateError::Exhausted) => text(StatusCode::CONFLICT, &error.to_string()),
        Err(error @ GateError::Marker { .. }) => {
            text(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
        }
    }
}

/// How long a ledger read or acknowledgement waits for the writer thread,
/// which answers between group commits.
const LEDGER_QUERY_DEADLINE: Duration = Duration::from_secs(5);

const LEDGER_NOT_CONFIGURED: &str = "no billing ledger is configured for this proxy; /ledger/* \
     needs a `ledger` block (node.metadata[\"io.llmproxy.ledger\"] in Envoy mode)";

/// One entry as `GET /ledger/entries` renders it: the entry's own fields
/// (`instance_id`, `epoch`, `seq`, the charge, the record) plus the `cursor`
/// that `after` and `through` take.
#[derive(serde::Serialize)]
struct LedgerItem<'a> {
    cursor: u64,
    #[serde(flatten)]
    entry: &'a LedgerEntry,
}

/// `GET /ledger/entries?after=&limit=`: committed entries above `after`, in
/// cursor order (ADR-0009 decision 8). Gated like the spend read.
async fn handle_ledger_entries(
    req: &Request<Incoming>,
    runtime: &AdminRuntime,
    peer: &GatePeer,
) -> Response<Full<Bytes>> {
    if req.method() != Method::GET {
        return text(
            StatusCode::METHOD_NOT_ALLOWED,
            "/ledger/entries only accepts GET",
        );
    }
    if let Some(refusal) = admin_gate(
        req.uri().path(),
        runtime.admin_token.as_deref(),
        req.headers(),
        peer,
    ) {
        return refusal;
    }
    let (after, limit) = match parse_ledger_entries_query(req.uri().query()) {
        Ok(parsed) => parsed,
        Err(message) => return bad_request(message),
    };
    let Some(ledger) = runtime.ledger.clone() else {
        return text(StatusCode::NOT_FOUND, LEDGER_NOT_CONFIGURED);
    };
    // The writer thread answers; the wait blocks a pool thread, never this
    // runtime's workers or the data plane.
    let page = tokio::task::spawn_blocking(move || {
        ledger.read_committed(after, limit, LEDGER_QUERY_DEADLINE)
    })
    .await;
    match page {
        // Entry contents go to the authorized caller only, never to a log.
        Ok(Ok(page)) => {
            let next_after = page.entries.last().map_or(after, |e| e.cursor);
            let entries: Vec<LedgerItem<'_>> = page
                .entries
                .iter()
                .map(|e| LedgerItem {
                    cursor: e.cursor,
                    entry: &e.entry,
                })
                .collect();
            json(
                StatusCode::OK,
                &serde_json::json!({
                    "entries": entries,
                    "next_after": next_after,
                    "committed_through": page.committed_through,
                    "epochs": page.epochs,
                }),
            )
        }
        Ok(Err(error)) => ledger_error(error),
        Err(_) => ledger_error(LedgerQueryError::Stopped),
    }
}

/// `POST /ledger/ack?through=<cursor>`: the spool removes every entry at or
/// below `through`. Space it frees clears a disk-cap hold, so admission
/// resumes without a restart.
async fn handle_ledger_ack(
    req: Request<Incoming>,
    runtime: &AdminRuntime,
    peer: &GatePeer,
) -> Response<Full<Bytes>> {
    if req.method() != Method::POST {
        return text(
            StatusCode::METHOD_NOT_ALLOWED,
            "/ledger/ack only accepts POST",
        );
    }
    if let Some(refusal) = admin_gate(
        req.uri().path(),
        runtime.admin_token.as_deref(),
        req.headers(),
        peer,
    ) {
        return refusal;
    }
    let through = match parse_ledger_ack_query(req.uri().query()) {
        Ok(through) => through,
        Err(message) => return bad_request(message),
    };
    match read_limited_body(req.into_body(), MAX_ADMIN_BODY_BYTES).await {
        Ok(body) if body.is_empty() => {}
        Ok(_) => {
            return bad_request("/ledger/ack takes no body; pass through as a query parameter")
        }
        Err(response) => return response,
    }
    let Some(ledger) = runtime.ledger.clone() else {
        return text(StatusCode::NOT_FOUND, LEDGER_NOT_CONFIGURED);
    };
    let outcome =
        tokio::task::spawn_blocking(move || ledger.acknowledge(through, LEDGER_QUERY_DEADLINE))
            .await;
    match outcome {
        Ok(Ok(ack)) => json(
            StatusCode::OK,
            &serde_json::json!({
                "acknowledged_through": ack.acknowledged_through,
                "admitting": ack.admitting,
            }),
        ),
        Ok(Err(error)) => ledger_error(error),
        Err(_) => ledger_error(LedgerQueryError::Stopped),
    }
}

/// `after` (default 0) and `limit` (1..=1000, default 100). Unknown, repeated
/// or malformed parameters are a 400, not ignored.
fn parse_ledger_entries_query(query: Option<&str>) -> Result<(u64, usize), &'static str> {
    let (mut after, mut limit) = (None, None);
    for param in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (name, value) = param.split_once('=').unwrap_or((param, ""));
        match name {
            "after" if after.is_none() => {
                after = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "after must be an unsigned integer cursor")?,
                );
            }
            "limit" if limit.is_none() => {
                limit = Some(
                    value
                        .parse::<usize>()
                        .ok()
                        .filter(|n| (1..=MAX_PAGE_ENTRIES).contains(n))
                        .ok_or("limit must be an integer from 1 to 1000")?,
                );
            }
            _ => return Err("unsupported or repeated query parameter; use after and limit"),
        }
    }
    Ok((after.unwrap_or(0), limit.unwrap_or(100)))
}

/// `through`, required, exactly once.
fn parse_ledger_ack_query(query: Option<&str>) -> Result<u64, &'static str> {
    let mut through = None;
    for param in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (name, value) = param.split_once('=').unwrap_or((param, ""));
        match name {
            "through" if through.is_none() => {
                through = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "through must be an unsigned integer cursor")?,
                );
            }
            _ => return Err("unsupported or repeated query parameter; use through"),
        }
    }
    through.ok_or("through is required: the cursor of the last entry to acknowledge")
}

fn ledger_error(error: LedgerQueryError) -> Response<Full<Bytes>> {
    let status = match error {
        LedgerQueryError::BeyondCommitted { .. } => StatusCode::CONFLICT,
        LedgerQueryError::AcknowledgementFull => StatusCode::INSUFFICIENT_STORAGE,
        LedgerQueryError::Stopped | LedgerQueryError::Timeout | LedgerQueryError::Storage => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    };
    json(status, &serde_json::json!({ "error": error.to_string() }))
}

/// Extracts the bearer credential from `Authorization: Bearer <token>`.
/// `None` for a missing header, a header that isn't valid UTF-8/ASCII, or
/// any scheme other than exactly `Bearer ` (matching
/// `proxy_control::auth`'s own `BEARER_PREFIX` convention).
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(str::to_string)
}

/// Constant-time equality for two secrets, via a double-HMAC compare.
///
/// **Not `==`**, which short-circuits on the first differing byte and leaks the length of a matching prefix
/// through timing. Also not `ring::constant_time::verify_slices_are_equal`: `ring` 0.17 deprecates it with the
/// note that it makes no side-channel promises. `proxy_control::auth` reached the same conclusion for the
/// data-plane key check.
///
/// `ring::hmac::verify` does apply to a plain comparison. HMAC both values under one random key, and the
/// digests match exactly when the inputs do, and `hmac::verify` compares digests in constant time. The key is a
/// blinding value, freshly random per call, so attempts cannot be correlated.
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

/// 409 for a write the proxy would store but never enforce.
fn not_enforced(detail: &str) -> Response<Full<Bytes>> {
    json(
        StatusCode::CONFLICT,
        &serde_json::json!({ "error": "not_enforced", "detail": detail }),
    )
}

/// Whether the addressed chain (scoped) or any chain (unscoped) runs
/// `llmproxy.model_authz`, which registers a marker in `factory_state`.
fn model_authz_enforced(factory_state: &SharedFactoryState, stat_prefix: Option<&str>) -> bool {
    let type_url = proxy_filters::model_authz_filter::TYPE_URL;
    match stat_prefix {
        Some(name) => factory_state.get_by_name(name, type_url).is_some(),
        // `Err` means several chains registered it, so it is enforced somewhere.
        None => !matches!(factory_state.get_across_scopes(type_url), Ok(None)),
    }
}

/// Whether the addressed chain (scoped) or any chain (unscoped) runs
/// `llmproxy.object_ownership`, which registers its owners under its type URL.
fn object_ownership_enforced(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
) -> bool {
    let type_url = proxy_filters::object_ownership_filter::TYPE_URL;
    match stat_prefix {
        Some(name) => factory_state.get_by_name(name, type_url).is_some(),
        None => !matches!(factory_state.get_across_scopes(type_url), Ok(None)),
    }
}

/// `PUT /tenants/{id}/objects/{object_id}`: assigns a provider object that
/// no tenant owns (created before ownership was recorded, or outside the
/// proxy) to the tenant, so its requests stop being refused. No body. 204
/// when the tenant owns the object afterwards, including when it already
/// did; 409 when another tenant owns it, since a live owner is never
/// replaced. An owner row past its expiry is no owner, so such an object is
/// assignable again; an assignment never expires (ADR-0013 §6).
fn handle_assign_object(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    tenant: &str,
    object_id: &str,
) -> Response<Full<Bytes>> {
    const ENDPOINT: &str = "/tenants/{id}/objects/{object_id}";
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    if !object_ownership_enforced(factory_state, stat_prefix) {
        return not_enforced(
            "no listener chain runs llmproxy.object_ownership; the owner would not be enforced",
        );
    }
    let tenant_id = TenantId::new(tenant);
    match tenant_exists(control_plane, &tenant_id) {
        Ok(true) => {}
        Ok(false) => return tenant_not_found(),
        Err(err) => return store_error_response(ENDPOINT, err),
    }
    // An admin assignment never expires (ADR-0013 §6). A live row the tenant
    // already holds is kept as it is, expiry included.
    match control_plane
        .store()
        .claim_object(object_id, &tenant_id, None)
    {
        Ok(owner) if owner.tenant == tenant_id => {
            tracing::info!(
                endpoint = ENDPOINT,
                tenant,
                object_id,
                "admin: assigned a provider object to a tenant"
            );
            no_content()
        }
        Ok(_) => error_json(
            StatusCode::CONFLICT,
            "object_owned",
            "another tenant owns this object; an owner is never replaced",
        ),
        Err(err) => store_error_response(ENDPOINT, err),
    }
}

/// `GET /tenants/{id}/objects/{object_id}`: whether the store records the
/// tenant as the object's owner. 200 when it does; 404 when another tenant or
/// none does, without saying which. The store is read directly, so a 200 also
/// says the owner survives a restart with a durable store, and every replica
/// sees it with a shared one; a create's owner is written just after its
/// response, so this is how to confirm it has landed. `expires_at` is the
/// row's expiry in Unix seconds, or null when it never expires.
fn handle_get_object(
    control_plane: &ControlPlane,
    tenant: &str,
    object_id: &str,
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    match control_plane.store().object_owner(object_id) {
        Ok(Some(owner)) if owner.tenant.as_str() == tenant => json(
            StatusCode::OK,
            &serde_json::json!({
                "tenant": tenant,
                "object_id": object_id,
                "owned": true,
                "expires_at": owner.expires_at,
            }),
        ),
        Ok(_) | Err(StoreError::InvalidInput(_)) => error_json(
            StatusCode::NOT_FOUND,
            "object_not_owned",
            "the tenant does not own this object",
        ),
        Err(err) => store_error_response("/tenants/{id}/objects/{object_id}", err),
    }
}

/// The addressed chain must register either token-limit config type URL.
/// Counters remain per process, so N replicas can admit up to N times a
/// configured limit until a shared counter backend is available.
fn token_limit_enforced(factory_state: &SharedFactoryState, stat_prefix: Option<&str>) -> bool {
    [
        proxy_filters::token_limit_filter::TYPE_URL,
        proxy_filters::token_limit_filter::LEGACY_TYPE_URL,
    ]
    .iter()
    .any(|type_url| match stat_prefix {
        Some(name) => factory_state.get_by_name(name, type_url).is_some(),
        None => !matches!(factory_state.get_across_scopes(type_url), Ok(None)),
    })
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

/// Parses a JSON request body into `T`, rejecting unknown fields (`#[serde(deny_unknown_fields)]` on every
/// request struct; AGENTS.md invariant 1 applies to security writes too) and any body that is not a JSON object
/// (see [`json_object`]), and maps any parse failure to 400.
/// The `serde_json` message names only the shape problem, never a token or key: none of these bodies carries a
/// plaintext key, since `POST /keys` only returns one.
// See `read_limited_body`'s identical `#[allow]` -- same cold admin-write
// path, same "large" `Err` variant by design.
#[allow(clippy::result_large_err)]
fn parse_json_body<T: serde::de::DeserializeOwned>(
    body: &[u8],
) -> Result<T, Response<Full<Bytes>>> {
    json_object::from_slice(body)
        .map_err(|err| bad_request(&format!("malformed request body: {err}")))
}

/// Maps a [`StoreError`] to a response. `NotFound` (for example, revoking an unknown `key_id`) is a 404.
/// `NotApplied` is a 503 that says the write is durable but not yet live on this replica, so a revoke whose
/// reload failed is never reported as done. Anything else is a 500 with the error's `Display`, which
/// [`StoreError`] documents as store-failure text, never key material.
fn store_error_response(endpoint: &str, err: StoreError) -> Response<Full<Bytes>> {
    match err {
        StoreError::NotFound => text(StatusCode::NOT_FOUND, "not found"),
        StoreError::Conflict(reason) => text(StatusCode::CONFLICT, &reason),
        StoreError::InvalidInput(reason) => bad_request(&reason),
        StoreError::NotApplied(_) => {
            tracing::error!(
                endpoint,
                error = %err,
                "admin write stored but not applied on this replica; it serves the previous policy until \
                 its next successful poll"
            );
            text(StatusCode::SERVICE_UNAVAILABLE, &err.to_string())
        }
        other => {
            tracing::warn!(endpoint, error = %other, "admin write failed: control-plane store error");
            text(StatusCode::INTERNAL_SERVER_ERROR, &other.to_string())
        }
    }
}

fn read_api_schema_version<'de, D: serde::Deserializer<'de>>(de: D) -> Result<(), D::Error> {
    let version = <u32 as serde::Deserialize>::deserialize(de)?;
    if version == proxy_control::control::SPEND_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported spend API schema version {version}"
        )))
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MintKeyRequest {
    #[serde(
        default,
        rename = "schema_version",
        deserialize_with = "read_api_schema_version"
    )]
    _schema_version: (),
    tenant: String,
    key_id: String,
    /// Chargeback tags stored as the key's metadata. Absent keeps a
    /// re-minted key's tags; a new key then has none.
    #[serde(default)]
    tags: Option<ChargebackTags>,
}

/// `PUT /keys/{id}/tags`. `tags` is required: `{}` clears them.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyTagsRequest {
    #[serde(
        default,
        rename = "schema_version",
        deserialize_with = "read_api_schema_version"
    )]
    _schema_version: (),
    tags: ChargebackTags,
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
    #[serde(default)]
    deny: Vec<String>,
}

/// `PUT /tenants/{id}/budget`'s body.
///
/// # Shape: one optional field expresses both "set" and "clear" unambiguously
///
/// `{"budget": {"max_usd": "500.00", "period": "monthly"}}` sets a ceiling;
/// `{"budget": null}` clears it (reverts to unlimited) -- see
/// [`proxy_control::spend::TenantBudget`]'s doc for why "unlimited" and "a
/// configured zero" must stay distinguishable. A flat two-shape body (a bare
/// `{"max_usd": ..., "period": ...}` for set,
/// vs. some other top-level shape for clear) would need its OWN sentinel to
/// tell "set" from "clear" apart, which is exactly the ambiguity this single
/// `Option` field avoids: `serde`'s ordinary `null`-means-`None` handles both
/// cases with no additional convention to invent or document.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetBudgetRequest {
    #[serde(
        default,
        rename = "schema_version",
        deserialize_with = "read_api_schema_version"
    )]
    _schema_version: (),
    #[serde(default, deserialize_with = "json_object::nullable_object")]
    budget: Option<BudgetSpec>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetLimitsRequest {
    #[serde(
        default,
        rename = "schema_version",
        deserialize_with = "read_limits_api_schema_version"
    )]
    _schema_version: (),
    // `deserialize_with` without `default` keeps the field required: a
    // missing `limits` is a 400, while an explicit `null` clears the row.
    // A bare `Option` field would treat a missing key as `null`.
    #[serde(deserialize_with = "nullable_limits")]
    limits: Option<LimitSpec>,
}

fn read_limits_api_schema_version<'de, D: serde::Deserializer<'de>>(de: D) -> Result<(), D::Error> {
    let version = <u32 as serde::Deserialize>::deserialize(de)?;
    if version == 1 {
        Ok(())
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported limits API schema version {version}"
        )))
    }
}

fn nullable_limits<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Option<LimitSpec>, D::Error> {
    json_object::nullable_object(de)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitSpec {
    tokens_per_minute: Option<u64>,
    requests_per_minute: Option<u64>,
    concurrent_streams: Option<u32>,
}

impl LimitSpec {
    fn into_policy(self) -> Option<LimitPolicy> {
        let policy = LimitPolicy {
            tokens_per_minute: self.tokens_per_minute,
            requests_per_minute: self.requests_per_minute,
            concurrent_streams: self.concurrent_streams,
        };
        (policy != LimitPolicy::default()).then_some(policy)
    }
}

// See `parse_json_body`'s identical `#[allow]`: a cold admin-write path
// whose `Err` is the ready-made response.
#[allow(clippy::result_large_err)]
fn parse_limits(body: &[u8]) -> Result<Option<LimitPolicy>, Response<Full<Bytes>>> {
    let request: SetLimitsRequest = parse_json_body(body)?;
    Ok(request.limits.and_then(LimitSpec::into_policy))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetSpec {
    /// A decimal-string ceiling, e.g. `"500.00"`, parsed by [`parse_micro_usd`] (the same parser a price uses), so
    /// a budget cannot be more precise than a price.
    max_usd: String,
    period: PeriodSpec,
    /// Tenant budgets only: `"platform"` or `"tenant"`; absent means
    /// `"platform"`. Kept a plain string so an unknown value gets this
    /// module's fixed 400 message instead of serde's, which would echo the
    /// rejected input back.
    #[serde(default)]
    credential_source: Option<String>,
    /// Key budgets only: also count the tenant's own-credential (BYOK)
    /// spend (ADR-0007 amendment 1). Absent means `false`.
    #[serde(default)]
    include_byok_in_limit: Option<bool>,
}

/// Wire form of [`Period`]: `"daily"` or `"monthly"`. The same spelling is used for requests and responses, so
/// a `PUT` and a `GET` agree.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum PeriodSpec {
    Daily,
    Monthly,
}

impl From<PeriodSpec> for Period {
    fn from(spec: PeriodSpec) -> Self {
        match spec {
            PeriodSpec::Daily => Period::Daily,
            PeriodSpec::Monthly => Period::Monthly,
        }
    }
}

impl From<Period> for PeriodSpec {
    fn from(period: Period) -> Self {
        match period {
            Period::Daily => PeriodSpec::Daily,
            Period::Monthly => PeriodSpec::Monthly,
        }
    }
}

/// Wire form of [`ModelAccess`]: `"all"`, or `{"only": [...]}` (the default externally tagged enum shape).
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum AccessSpec {
    All,
    Only(Vec<String>),
}

/// `GET /keys` and `GET /chains/{stat_prefix}/keys`: the key inventory (key id, owning tenant, revocation state,
/// configured ceiling), sorted by `(tenant, key_id)`.
///
/// Gated like `.../spend` despite being a GET: it is identity data, and nothing about it should be enumerable
/// by an unauthenticated caller. It carries no digest and no plaintext. The plaintext appears only in the
/// `POST /keys` response, once (see `lib.rs`'s redaction section).
fn handle_list_keys(control_plane: &ControlPlane) -> Response<Full<Bytes>> {
    let keys = control_plane.list_keys();
    let rendered: Vec<serde_json::Value> = keys
        .iter()
        .map(|listing| {
            serde_json::json!({
                "key_id": listing.key_id.as_str(),
                "tenant": listing.tenant.as_str(),
                "revoked": listing.revoked,
                "policy": listing.model_access.as_ref().map(render_model_access),
                // `null` means no ceiling configured. An explicit zero serializes as a real number, so the two never
                // collapse. Both integer micro-dollars and a rendered decimal string are reported, as in the spend read.
                "budget": listing.budget.map(|budget| serde_json::json!({
                    "max_micro_usd": budget.max_micros.as_micros(),
                    "max_usd": render_micro_usd(budget.max_micros.as_micros()),
                    "period": PeriodSpec::from(budget.period),
                    "include_byok_in_limit": budget.include_byok_in_limit,
                })),
                "limits": listing.limits.map(render_limits),
                "tags": &*listing.tags,
            })
        })
        .collect();
    let count = rendered.len();
    json(
        StatusCode::OK,
        &serde_json::json!({ "schema_version": proxy_control::control::SPEND_SCHEMA_VERSION, "keys": rendered, "count": count }),
    )
}

fn render_limits(limits: LimitPolicy) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    if let Some(value) = limits.tokens_per_minute {
        fields.insert("tokens_per_minute".into(), serde_json::json!(value));
    }
    if let Some(value) = limits.requests_per_minute {
        fields.insert("requests_per_minute".into(), serde_json::json!(value));
    }
    if let Some(value) = limits.concurrent_streams {
        fields.insert("concurrent_streams".into(), serde_json::json!(value));
    }
    serde_json::Value::Object(fields)
}

fn render_model_access(access: &ModelAccess) -> serde_json::Value {
    let allow = match access {
        ModelAccess::All => serde_json::json!("all"),
        ModelAccess::Only(patterns) => serde_json::json!({
            "only": patterns.iter().map(ModelPattern::as_str).collect::<Vec<_>>()
        }),
        ModelAccess::WithDeny { allow, deny } => {
            let mut rendered = render_model_access(allow);
            rendered["deny"] =
                serde_json::json!(deny.iter().map(ModelPattern::as_str).collect::<Vec<_>>());
            return rendered;
        }
    };
    serde_json::json!({ "access": allow })
}

fn handle_mint_key(control_plane: &ControlPlane, body: &[u8]) -> Response<Full<Bytes>> {
    let MintKeyRequest {
        tenant,
        key_id,
        tags,
        ..
    } = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if tenant.trim().is_empty() {
        return bad_request("tenant must not be empty");
    }
    if key_id.trim().is_empty() {
        return bad_request("key_id must not be empty");
    }
    // Checked here for a 400 that names the field, and again in `ControlPlane::mint_key` for every other caller.
    if let Err(reason) = proxy_control::auth::check_principal_id("tenant", &tenant)
        .and_then(|()| proxy_control::auth::check_principal_id("key_id", &key_id))
    {
        return bad_request(&reason);
    }

    if let Some(Err(reason)) = tags.as_ref().map(validate_key_tags) {
        return bad_request(&format!("invalid `tags`: {reason}"));
    }

    match control_plane.mint_key_with_tags(
        &TenantId::new(tenant),
        &KeyId::new(key_id),
        tags.as_ref(),
    ) {
        Ok(minted) => {
            tracing::info!(
                endpoint = "/keys",
                key_id = minted.key_id.as_str(),
                tenant = minted.tenant.as_str(),
                applied = minted.applied,
                "admin: minted a virtual key"
            );
            // `minted.plaintext` is returned here exactly once. The store keeps only its digest (see `MintedKey`), so
            // this body is the only place the value will ever exist. That is why a mint whose reload failed still
            // answers with the key: a 202 with `applied: false`, since the key 401s on this replica until its next
            // successful poll.
            let mut body = serde_json::json!({
                "schema_version": proxy_control::control::SPEND_SCHEMA_VERSION,
                "key_id": minted.key_id.as_str(),
                "tenant": minted.tenant.as_str(),
                "tags": &minted.tags,
                "key": minted.plaintext,
            });
            if minted.applied {
                json(StatusCode::CREATED, &body)
            } else {
                tracing::error!(
                    endpoint = "/keys",
                    key_id = minted.key_id.as_str(),
                    "admin: minted key stored but not applied on this replica; it is refused here until the \
                     next successful poll"
                );
                body["applied"] = serde_json::Value::Bool(false);
                json(StatusCode::ACCEPTED, &body)
            }
        }
        Err(err) => store_error_response("/keys", err),
    }
}

/// `PUT /keys/{id}/tags` and its scoped form: replaces a store key's chargeback tags (key metadata). The auth
/// filter's tag policy decides at request time which of them are attributed; a key tag always wins over the
/// client's tag header. A key defined in the configuration, or a revoked key, answers 409.
fn handle_set_key_tags(
    control_plane: &ControlPlane,
    key_id: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if key_id.is_empty() {
        return bad_request("key_id must not be empty");
    }
    let KeyTagsRequest { tags, .. } = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if let Err(reason) = validate_key_tags(&tags) {
        return bad_request(&format!("invalid `tags`: {reason}"));
    }
    match control_plane.set_key_tags(&KeyId::new(key_id), &tags) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/keys/{id}/tags",
                key_id,
                tags = tags.len(),
                "admin: set a key's chargeback tags"
            );
            no_content()
        }
        Err(err) => store_error_response("/keys/{id}/tags", err),
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
        Ok(revoked_keys) => {
            tracing::info!(
                endpoint = "/tenants/{id}",
                tenant,
                revoked_keys,
                "admin: deleted a tenant and revoked its keys"
            );
            no_content()
        }
        Err(err) => store_error_response("/tenants/{id}", err),
    }
}

/// Longest API key `PUT .../provider_credentials/{provider}` accepts. Real keys are well under 300 bytes; the cap
/// bounds the header value the router later builds.
const MAX_TENANT_API_KEY_BYTES: usize = 4096;

/// The only `schema_version` this endpoint speaks.
const TENANT_CREDENTIALS_API_VERSION: u32 = 1;

/// JSON error in the router's own reply shape (`{"error":{"message":..,"type":..}}`). Callers pass a fixed
/// message and never format request-body content into it.
fn error_json(status: StatusCode, error_type: &str, message: &str) -> Response<Full<Bytes>> {
    json(
        status,
        &serde_json::json!({ "error": { "message": message, "type": error_type } }),
    )
}

/// [`error_json`] plus `upstream_status`, for save-time probe failures where the provider did answer. The status
/// is a bare code, so it carries nothing from the request or response body.
fn error_json_with_upstream(
    status: StatusCode,
    error_type: &str,
    message: &str,
    upstream: StatusCode,
) -> Response<Full<Bytes>> {
    json(
        status,
        &serde_json::json!({
            "error": {
                "message": message,
                "type": error_type,
                "upstream_status": upstream.as_u16(),
            }
        }),
    )
}

/// Deserializes straight into a [`TenantSecret`], so the plaintext lives in a zeroize-on-drop buffer from its
/// first owned form onward.
///
/// Rust note: `deserialize_with` points serde at this function, since `TenantSecret` has no `Deserialize` impl.
fn deserialize_tenant_secret<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<TenantSecret, D::Error> {
    <String as serde::Deserialize>::deserialize(de).map(TenantSecret::new)
}

/// `verify` defaults to `true`: a key is checked against the provider unless the caller opts out (ADR-0007).
fn default_verify() -> bool {
    true
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PutTenantCredentialRequest {
    schema_version: u32,
    #[serde(deserialize_with = "deserialize_tenant_secret")]
    api_key: TenantSecret,
    #[serde(default = "default_verify")]
    verify: bool,
}

/// Whether `tenant` exists: created through the store, or implied by a bootstrap or minted key or a stored
/// policy. Reads the store, since a tenant with no key or policy yet appears only there.
fn tenant_exists(control_plane: &ControlPlane, tenant: &TenantId) -> Result<bool, StoreError> {
    {
        let snapshot = control_plane.handle().load();
        if snapshot.policies.contains_key(tenant.as_str())
            || snapshot.key_tenants.values().any(|t| t == tenant)
        {
            return Ok(true);
        }
    }
    Ok(control_plane.store().load()?.tenants.contains(tenant))
}

fn tenant_not_found() -> Response<Full<Bytes>> {
    error_json(StatusCode::NOT_FOUND, "tenant_not_found", "unknown tenant")
}

/// Wipes `body` when this handle is the only reference. Best effort: if hyper still shares the buffer, the bytes
/// live until the allocator reuses them.
fn wipe_body(body: Bytes) {
    if let Ok(mut unique) = body.try_into_mut() {
        zeroize::Zeroize::zeroize(&mut unique[..]);
    }
}

/// `PUT /tenants/{id}/provider_credentials/{provider}`.
///
/// Check order: body shape (400), tenant (404), provider enabled on some cluster (422), then, when `verify` is
/// true, the save-time probe (422 or 502, nothing stored on failure), then the store (503 when
/// `tenant_credentials` is not configured). The body is never logged or echoed. serde errors can quote input,
/// so this handler maps them to fixed text by [`serde_json::Error::classify`].
async fn handle_put_tenant_credential(
    control_plane: &Arc<ControlPlane>,
    config: &WorkerConfigHandle,
    probe: Option<&dyn TenantCredentialProbe>,
    tenant: &str,
    provider: &str,
    body: Bytes,
) -> Response<Full<Bytes>> {
    let response =
        put_tenant_credential_inner(control_plane, config, probe, tenant, provider, &body).await;
    wipe_body(body);
    response
}

fn tenant_credentials_not_configured() -> Response<Full<Bytes>> {
    error_json(
        StatusCode::SERVICE_UNAVAILABLE,
        "tenant_credentials_not_configured",
        "tenant credentials are not enabled: `tenant_credentials` is not configured on the auth filter",
    )
}

async fn put_tenant_credential_inner(
    control_plane: &Arc<ControlPlane>,
    config: &WorkerConfigHandle,
    probe: Option<&dyn TenantCredentialProbe>,
    tenant: &str,
    provider: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    const INVALID: &str = "invalid_request";
    if tenant.is_empty() {
        return error_json(StatusCode::BAD_REQUEST, INVALID, "tenant must not be empty");
    }
    if provider.is_empty() {
        return error_json(
            StatusCode::BAD_REQUEST,
            INVALID,
            "provider must not be empty",
        );
    }
    let request: PutTenantCredentialRequest = match json_object::from_slice(body) {
        Ok(request) => request,
        Err(err) => {
            let message = match err.classify() {
                serde_json::error::Category::Data => {
                    "body must be {\"schema_version\":1,\"api_key\":\"...\",\"verify\":true} with no other fields; verify is optional"
                }
                _ => "request body is not valid JSON",
            };
            return error_json(StatusCode::BAD_REQUEST, INVALID, message);
        }
    };
    if request.schema_version != TENANT_CREDENTIALS_API_VERSION {
        return error_json(
            StatusCode::BAD_REQUEST,
            INVALID,
            "unsupported schema_version; expected 1",
        );
    }
    let key = request.api_key.expose();
    if key.trim().is_empty() {
        return error_json(
            StatusCode::BAD_REQUEST,
            INVALID,
            "api_key must not be empty",
        );
    }
    if key.len() > MAX_TENANT_API_KEY_BYTES {
        return error_json(
            StatusCode::BAD_REQUEST,
            INVALID,
            "api_key exceeds 4096 bytes",
        );
    }
    // `HeaderValue::from_str` refuses CR/LF and other control bytes but allows obs-text (0x80..=0xFF), which no
    // provider key uses, so `is_ascii` closes that gap.
    if !key.is_ascii() || hyper::header::HeaderValue::from_str(key).is_err() {
        return error_json(
            StatusCode::BAD_REQUEST,
            INVALID,
            "api_key contains bytes that are not valid in an HTTP header value",
        );
    }

    let tenant_id = TenantId::new(tenant);
    let exists = {
        let (control_plane, tenant_id) = (Arc::clone(control_plane), tenant_id.clone());
        off_runtime(move || tenant_exists(&control_plane, &tenant_id)).await
    };
    match exists {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => return tenant_not_found(),
        Ok(Err(err)) => return store_error_response("/tenants/{id}/provider_credentials", err),
        Err(response) => return response,
    }

    // A credential no cluster slot would use is a typo the operator should hear about now, not an inert row.
    // The snapshot guard is dropped before any `.await`.
    let verify_target = {
        let snapshot = config.load();
        let enabled = snapshot.clusters.values().any(|cluster| {
            cluster
                .provider_runtime
                .as_ref()
                .and_then(|runtime| runtime.tenant_credential.as_ref())
                .is_some_and(|slot| slot.provider == provider)
        });
        if !enabled {
            return error_json(
                StatusCode::UNPROCESSABLE_ENTITY,
                "provider_not_enabled",
                "no configured cluster accepts tenant credentials for this provider",
            );
        }
        // The probe goes to the first slot cluster, by name, that has a `verify_path`. `min_by` over names keeps the
        // choice independent of map iteration order.
        snapshot
            .clusters
            .iter()
            .filter_map(|(name, cluster)| {
                let slot = cluster
                    .provider_runtime
                    .as_ref()?
                    .tenant_credential
                    .as_ref()?;
                (slot.provider == provider && slot.verify_path.is_some())
                    .then(|| (name.to_string(), slot.clone()))
            })
            .min_by(|a, b| a.0.cmp(&b.0))
    };

    // ADR-0007: a key is stored as verified only after the provider answers 2xx. Every failure returns before the store.
    let verified = if request.verify {
        // Without key-encryption keys the store refuses the key, so do not send it to the provider first.
        if !control_plane.tenant_credentials_configured() {
            return tenant_credentials_not_configured();
        }
        let (Some(probe), Some((cluster, slot))) = (probe, verify_target) else {
            return error_json(
                StatusCode::UNPROCESSABLE_ENTITY,
                "credential_verification_not_configured",
                "no provider cluster has a verify_path for this provider, or the credential probe is not wired; pass \"verify\": false to store the key unverified",
            );
        };
        // The probe owns its secret and the store still needs the key, so this is the one extra plaintext copy.
        // Both copies are zeroize-on-drop.
        let probe_request = CredentialProbeRequest {
            cluster: cluster.clone(),
            slot,
            secret: TenantSecret::new(key.to_owned()),
        };
        match probe.probe(probe_request).await {
            CredentialProbeOutcome::Status(status) if status.is_success() => true,
            CredentialProbeOutcome::Status(status)
                if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN =>
            {
                tracing::info!(
                    endpoint = "/tenants/{id}/provider_credentials/{provider}",
                    tenant,
                    provider,
                    cluster = %cluster,
                    upstream_status = status.as_u16(),
                    "admin: provider rejected a tenant credential at save time"
                );
                return error_json_with_upstream(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "credential_rejected",
                    "the provider rejected this API key",
                    status,
                );
            }
            CredentialProbeOutcome::Status(status) => {
                return error_json_with_upstream(
                    StatusCode::BAD_GATEWAY,
                    "credential_verification_unavailable",
                    "the provider answered the verification probe with an unexpected status",
                    status,
                );
            }
            CredentialProbeOutcome::TimedOut => {
                return error_json(
                    StatusCode::BAD_GATEWAY,
                    "credential_verification_unavailable",
                    "the provider did not answer the verification probe in time",
                );
            }
            CredentialProbeOutcome::Unreachable(reason) => {
                // The reason names the failure only, so it is safe for the log but not for the reply.
                tracing::warn!(
                    endpoint = "/tenants/{id}/provider_credentials/{provider}",
                    tenant,
                    provider,
                    cluster = %cluster,
                    reason = %reason,
                    "admin: could not reach the provider to verify a tenant credential"
                );
                return error_json(
                    StatusCode::BAD_GATEWAY,
                    "credential_verification_unavailable",
                    "the provider could not be reached to verify this API key",
                );
            }
        }
    } else {
        false
    };

    // The secret moves into the blocking task and is dropped there.
    let stored = {
        let (control_plane, provider) = (Arc::clone(control_plane), provider.to_string());
        off_runtime(move || {
            control_plane.store_tenant_secret(&tenant_id, &provider, &request.api_key, verified)
        })
        .await
    };
    let stored = match stored {
        Ok(stored) => stored,
        Err(response) => return response,
    };
    match stored {
        Ok(metadata) => {
            tracing::info!(
                endpoint = "/tenants/{id}/provider_credentials/{provider}",
                tenant,
                provider,
                "admin: stored a tenant provider credential"
            );
            json(StatusCode::OK, &metadata)
        }
        Err(CredentialStoreError::NotConfigured) => tenant_credentials_not_configured(),
        Err(CredentialStoreError::Store(err)) => {
            store_error_response("/tenants/{id}/provider_credentials/{provider}", err)
        }
        Err(CredentialStoreError::Crypto(err)) => {
            tracing::warn!(error = %err, "admin write failed: could not seal tenant credential");
            error_json(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credential_seal_failed",
                "could not seal the credential",
            )
        }
    }
}

/// `GET /tenants/{id}/provider_credentials`: metadata for every credential the
/// tenant holds. Never decrypts anything.
fn handle_list_tenant_credentials(
    control_plane: &ControlPlane,
    tenant: &str,
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let tenant_id = TenantId::new(tenant);
    match tenant_exists(control_plane, &tenant_id) {
        Ok(true) => {}
        Ok(false) => return tenant_not_found(),
        Err(err) => return store_error_response("/tenants/{id}/provider_credentials", err),
    }
    match control_plane.tenant_credential_metadata(&tenant_id) {
        Ok(credentials) => json(
            StatusCode::OK,
            &serde_json::json!({
                "schema_version": TENANT_CREDENTIALS_API_VERSION,
                "tenant": tenant,
                "credentials": credentials,
            }),
        ),
        Err(err) => store_error_response("/tenants/{id}/provider_credentials", err),
    }
}

/// `DELETE /tenants/{id}/provider_credentials/{provider}`: 204 if the row
/// existed, 404 if the tenant or the row did not (as `DELETE /keys/{id}` does
/// for an unknown key).
fn handle_delete_tenant_credential(
    control_plane: &ControlPlane,
    tenant: &str,
    provider: &str,
) -> Response<Full<Bytes>> {
    if tenant.is_empty() || provider.is_empty() {
        return bad_request("tenant and provider must not be empty");
    }
    let tenant_id = TenantId::new(tenant);
    match tenant_exists(control_plane, &tenant_id) {
        Ok(true) => {}
        Ok(false) => return tenant_not_found(),
        Err(err) => return store_error_response("/tenants/{id}/provider_credentials", err),
    }
    match control_plane.delete_tenant_credential(&tenant_id, provider) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/tenants/{id}/provider_credentials/{provider}",
                tenant,
                provider,
                "admin: deleted a tenant provider credential"
            );
            no_content()
        }
        Err(err) => store_error_response("/tenants/{id}/provider_credentials/{provider}", err),
    }
}

fn handle_set_policy(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    tenant: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let access = match parse_model_policy(body) {
        Ok(access) => access,
        Err(response) => return response,
    };
    // A policy no filter reads is a silent hole: the write succeeds and the operator believes the tenant is
    // restricted. Refuse it, naming why.
    if !model_authz_enforced(factory_state, stat_prefix) {
        return not_enforced(
            "no listener chain runs llmproxy.model_authz; tenant policies would not be enforced",
        );
    }
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

// See `parse_json_body`'s identical `#[allow]`: a cold admin-write path
// whose `Err` is the ready-made response.
#[allow(clippy::result_large_err)]
fn parse_model_policy(body: &[u8]) -> Result<ModelAccess, Response<Full<Bytes>>> {
    let request: SetPolicyRequest = parse_json_body(body)?;
    let allow = match request.access {
        AccessSpec::All => ModelAccess::All,
        // An empty `only: []` is a deliberate "deny every model" and MUST stay `Only(vec![])`. Collapsing it to
        // `All` would silently grant access to everything.
        AccessSpec::Only(patterns) => {
            for (index, pattern) in patterns.iter().enumerate() {
                if !ModelPattern::is_valid(pattern) {
                    return Err(bad_request(&format!(
                        "access.only[{index}] must be an exact model name or a single trailing `*` glob"
                    )));
                }
            }
            ModelAccess::Only(patterns.into_iter().map(ModelPattern::new).collect())
        }
    };
    for (index, pattern) in request.deny.iter().enumerate() {
        if !ModelPattern::is_valid(pattern) {
            return Err(bad_request(&format!(
                "deny[{index}] must be an exact model name or a single trailing `*` glob"
            )));
        }
    }
    Ok(allow.with_deny(request.deny.into_iter().map(ModelPattern::new).collect()))
}

fn handle_set_key_policy(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    key_id: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if key_id.is_empty() {
        return bad_request("key_id must not be empty");
    }
    let access = match parse_model_policy(body) {
        Ok(access) => access,
        Err(response) => return response,
    };
    if !model_authz_enforced(factory_state, stat_prefix) {
        return not_enforced(
            "no listener chain runs llmproxy.model_authz; key policies would not be enforced",
        );
    }
    match control_plane.set_key_policy(&KeyId::new(key_id), &access) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/keys/{id}/policy",
                key_id,
                "admin: set a key's model-access policy"
            );
            no_content()
        }
        Err(err) => store_error_response("/keys/{id}/policy", err),
    }
}

/// The ceiling both budget writes share, so their validation cannot drift
/// apart.
#[allow(clippy::result_large_err)]
fn max_micros_from_spec(spec: &BudgetSpec) -> Result<MicroUsd, Response<Full<Bytes>>> {
    parse_micro_usd(&spec.max_usd).map_err(|err| bad_request(&format!("invalid `max_usd`: {err}")))
}

/// Turns a `PUT /tenants/{id}/budget` [`BudgetSpec`] into the stored [`TenantBudget`].
#[allow(clippy::result_large_err)]
fn budget_from_spec(spec: BudgetSpec) -> Result<TenantBudget, Response<Full<Bytes>>> {
    let max_micros = max_micros_from_spec(&spec)?;
    if spec.include_byok_in_limit.is_some() {
        return Err(bad_request(
            "`include_byok_in_limit` applies to key budgets (PUT /keys/{id}/budget); \
             a tenant budget is scoped by `credential_source`",
        ));
    }
    let credential_source = match spec.credential_source.as_deref() {
        // Absent means platform, so existing budgets keep their meaning (ADR-0007).
        None | Some("platform") => CredentialSource::Platform,
        Some("tenant") => CredentialSource::Tenant,
        Some(_) => {
            return Err(bad_request(
                "invalid `credential_source`: expected \"platform\" or \"tenant\"",
            ))
        }
    };
    Ok(TenantBudget {
        max_micros,
        period: spec.period.into(),
        credential_source,
    })
}

/// Turns a `PUT /keys/{id}/budget` [`BudgetSpec`] into the stored [`KeyBudget`].
#[allow(clippy::result_large_err)]
fn key_budget_from_spec(spec: BudgetSpec) -> Result<KeyBudget, Response<Full<Bytes>>> {
    let max_micros = max_micros_from_spec(&spec)?;
    if spec.credential_source.is_some() {
        return Err(bad_request(
            "`credential_source` applies to tenant budgets; a key budget counts operator \
             spend, and BYOK spend too with `include_byok_in_limit: true`",
        ));
    }
    Ok(KeyBudget {
        max_micros,
        period: spec.period.into(),
        include_byok_in_limit: spec.include_byok_in_limit.unwrap_or(false),
    })
}

/// `PUT /tenants/{id}/budget`. `{"budget": null}` clears the ceiling; `{"budget": {...}}` sets it. `max_usd`
/// goes through [`parse_micro_usd`], the same parser a configured price uses, so a malformed decimal is a 400.
fn handle_set_budget(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    tenant: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let request: SetBudgetRequest = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };

    let budget = match request.budget {
        None => None,
        Some(spec) => match budget_from_spec(spec) {
            Ok(budget) => Some(budget),
            Err(response) => return response,
        },
    };

    // The start-up check in `llmproxy.spend_limit` refuses to start on any tenant budget in the store that
    // predates the cutover. A budget written here would pass now and crash-loop every replica on the next
    // rolling restart, so refuse it at write time. Clearing is always fine. A budget no spend filter reads is
    // the same silent hole as an unread policy, so setting one is refused without `llmproxy.spend_limit`.
    if budget.is_some() {
        let Some(shared) = resolve_spend_shared(factory_state, stat_prefix) else {
            return not_enforced(
                "no listener chain runs llmproxy.spend_limit; tenant budgets would not be enforced",
            );
        };
        if !shared.legacy_tenant_budget_cutover() {
            return text(
                StatusCode::CONFLICT,
                "this chain's llmproxy.spend_limit does not set \
                 `typed_config.legacy_tenant_budget_cutover`, and without it the next start \
                 refuses to load a stored tenant budget. Set it to START_KEYS_FRESH on the \
                 spend filter first (key budgets, PUT /keys/{id}/budget, need no cutover). \
                 Nothing was changed.",
            );
        }
    }

    match control_plane.set_budget(&TenantId::new(tenant), budget.as_ref()) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/tenants/{id}/budget",
                tenant,
                cleared = budget.is_none(),
                "admin: set a tenant's spend budget"
            );
            no_content()
        }
        Err(err) => store_error_response("/tenants/{id}/budget", err),
    }
}

/// `PUT /keys/{id}/budget`. A budget belongs to the logical key identity, not its secret, so rotating the
/// secret leaves this row and its spend ledger in place.
fn handle_set_key_budget(
    control_plane: &ControlPlane,
    key_id: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if key_id.is_empty() {
        return bad_request("key_id must not be empty");
    }
    let request: SetBudgetRequest = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let budget = match request.budget {
        None => None,
        Some(spec) => match key_budget_from_spec(spec) {
            Ok(budget) => Some(budget),
            Err(response) => return response,
        },
    };
    match control_plane.set_key_budget(&KeyId::new(key_id), budget.as_ref()) {
        Ok(()) => no_content(),
        Err(err) => store_error_response("/keys/{id}/budget", err),
    }
}

/// `PUT /tenants/{id}/limits`: absent fields impose no limit at this level;
/// explicit zero refuses all traffic measured by that counter.
fn handle_set_tenant_limits(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    tenant: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let limits = match parse_limits(body) {
        Ok(limits) => limits,
        Err(response) => return response,
    };
    if !token_limit_enforced(factory_state, stat_prefix) {
        return not_enforced(
            "no listener chain runs llmproxy.token_limit; limits would not be enforced",
        );
    }
    match control_plane.set_tenant_limits(&TenantId::new(tenant), limits.as_ref()) {
        Ok(()) => no_content(),
        Err(err) => store_error_response("/tenants/{id}/limits", err),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetTraceExportRequest {
    #[serde(
        rename = "schema_version",
        deserialize_with = "read_trace_export_api_schema_version"
    )]
    _schema_version: (),
    enabled: bool,
}

fn read_trace_export_api_schema_version<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<(), D::Error> {
    let version = <u32 as serde::Deserialize>::deserialize(de)?;
    if version == 1 {
        Ok(())
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported trace_export API schema version {version}"
        )))
    }
}

/// `PUT /tenants/{id}/trace_export`: the tenant's consent to raw capture of
/// its request and response bodies (ADR-0008 decision 2). Unset is not
/// consent. The tenant must exist, and its id must make a valid segment
/// directory name, so every opted-in tenant can actually be written.
fn handle_set_trace_export(
    control_plane: &ControlPlane,
    tenant: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let request: SetTraceExportRequest = match parse_json_body(body) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let tenant_id = TenantId::new(tenant);
    match tenant_exists(control_plane, &tenant_id) {
        Ok(true) => {}
        Ok(false) => return tenant_not_found(),
        Err(err) => return store_error_response("/tenants/{id}/trace_export", err),
    }
    if request.enabled
        && proxy_observability::traces::tenant_dir(tenant).len()
            > proxy_observability::traces::MAX_TENANT_DIR_BYTES
    {
        return error_json(
            StatusCode::BAD_REQUEST,
            "tenant_id_too_long",
            "id: too long to name a trace segment directory once percent-encoded",
        );
    }
    match control_plane.set_trace_export(&tenant_id, request.enabled) {
        Ok(()) => {
            tracing::info!(
                endpoint = "/tenants/{id}/trace_export",
                tenant,
                enabled = request.enabled,
                "admin: set a tenant's trace export opt-in"
            );
            no_content()
        }
        Err(err) => store_error_response("/tenants/{id}/trace_export", err),
    }
}

/// `GET /tenants/{id}/trace_export`: the opt-in as this replica's snapshot
/// holds it.
fn handle_get_trace_export(control_plane: &ControlPlane, tenant: &str) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let tenant_id = TenantId::new(tenant);
    match tenant_exists(control_plane, &tenant_id) {
        Ok(true) => {}
        Ok(false) => return tenant_not_found(),
        Err(err) => return store_error_response("/tenants/{id}/trace_export", err),
    }
    json(
        StatusCode::OK,
        &serde_json::json!({
            "schema_version": 1,
            "tenant": tenant,
            "enabled": control_plane.trace_export(&tenant_id),
        }),
    )
}

/// `PUT /keys/{id}/limits`: a key's counters narrow its tenant's counters.
fn handle_set_key_limits(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    key_id: &str,
    body: &[u8],
) -> Response<Full<Bytes>> {
    if key_id.is_empty() {
        return bad_request("key_id must not be empty");
    }
    let limits = match parse_limits(body) {
        Ok(limits) => limits,
        Err(response) => return response,
    };
    if !token_limit_enforced(factory_state, stat_prefix) {
        return not_enforced(
            "no listener chain runs llmproxy.token_limit; limits would not be enforced",
        );
    }
    match control_plane.set_key_limits(&KeyId::new(key_id), limits.as_ref()) {
        Ok(()) => no_content(),
        Err(err) => store_error_response("/keys/{id}/limits", err),
    }
}

/// Resolves the spend accumulator (scoped or unscoped, matching `stat_prefix`'s presence as [`handle`]'s
/// control-plane gate already did) and dispatches to [`handle_get_spend`]. A tenant's spend read needs a
/// second singleton beyond the `ControlPlane`, so it gets its own resolution step.
fn handle_get_spend_route(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    tenant: &str,
    path: &str,
) -> Response<Full<Bytes>> {
    let accumulator = match stat_prefix {
        Some(stat_prefix) => resolve_spend_state_by_name(factory_state, stat_prefix),
        None => match resolve_spend_state(factory_state) {
            Ok(accumulator) => accumulator,
            Err(scopes) => {
                // See `resolve_spend_state`'s doc. Defensive: the control-plane gate has already refused ambiguity.
                tracing::error!(
                    endpoint = %path,
                    scopes = ?scopes,
                    "admin spend read refused: more than one llmproxy.spend_limit-configured \
                     filter chain is registered, so the unscoped admin API cannot tell which \
                     accumulator this read means -- use /chains/{{stat_prefix}}/... instead"
                );
                return text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "the unscoped admin spend read cannot resolve a single spend \
                         accumulator: {} filter chains each configure llmproxy.spend_limit \
                         ({}) -- use /chains/{{stat_prefix}}/... to address one of them \
                         explicitly",
                        scopes.len(),
                        scopes.join(", "),
                    ),
                );
            }
        },
    };
    handle_get_spend(control_plane, accumulator, tenant)
}

fn handle_get_key_spend_route(
    factory_state: &SharedFactoryState,
    stat_prefix: Option<&str>,
    control_plane: &ControlPlane,
    key_id: &str,
    path: &str,
) -> Response<Full<Bytes>> {
    let accumulator = match stat_prefix {
        Some(stat_prefix) => resolve_spend_state_by_name(factory_state, stat_prefix),
        None => match resolve_spend_state(factory_state) {
            Ok(accumulator) => accumulator,
            Err(scopes) => {
                return text(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!(
                        "the unscoped admin spend read cannot resolve a single spend accumulator: \
                         {} filter chains each configure llmproxy.spend_limit ({}) -- use \
                         /chains/{{stat_prefix}}/... to address one explicitly",
                        scopes.len(),
                        scopes.join(", "),
                    ),
                );
            }
        },
    };
    let _ = path;
    handle_get_key_spend(control_plane, accumulator, key_id)
}

/// `GET /tenants/{id}/spend` (and its scoped form).
///
/// Reads two singletons, either of which can legitimately be missing on a live chain:
/// - the tenant's [`TenantBudget`] (period and ceiling), from the already-resolved `control_plane`'s snapshot.
///   A tenant with no budget is not an error; `budget_micro_usd` and `remaining_micro_usd` render `null`.
/// - the spend accumulator, resolved by the caller and passed as `None` when `llmproxy.spend_limit` is not
///   configured on this chain. That is the one missing-singleton case answered with 503.
///
/// **Which period?** The tenant's own `TenantBudget::period` if set, else [`SpendAccumulator::default_period`].
/// This matches `spend_limit_filter`'s `decode_headers`, so the read reports the period enforcement checks.
///
/// `spend_usd` comes from the integer `total_micros` via [`render_micro_usd`], never an `f64`. See
/// `proxy_control::spend`'s module doc.
fn handle_get_spend(
    control_plane: &ControlPlane,
    accumulator: Option<Arc<SpendAccumulator>>,
    tenant: &str,
) -> Response<Full<Bytes>> {
    if tenant.is_empty() {
        return bad_request("tenant must not be empty");
    }
    let Some(accumulator) = accumulator else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "llmproxy.spend_limit is not configured on this chain, so there is no spend \
             accumulator to report from",
        );
    };

    let tenant_id = TenantId::new(tenant);
    // Rust note: `TenantPolicyMap` is keyed on the tenant's plain `&str` name, not `TenantId`, matching
    // `spend_limit_filter`'s own lookup.
    let budget = control_plane
        .handle()
        .load()
        .policies
        .get(tenant)
        .and_then(|policy| policy.budget);

    let period = budget
        .map(|b| b.period)
        .unwrap_or_else(|| accumulator.default_period());
    let period_key = period.key_for_now();
    // Rust note: `Period::window_now` hands back `DateTime<Utc>`; rendering
    // them as RFC 3339 is this layer's job, not the money module's.
    let (period_start, period_end) = period.window_now();
    let (period_started_at, period_ends_at) = (period_start.to_rfc3339(), period_end.to_rfc3339());
    let report = accumulator.report(&tenant_id, &period_key);

    let (budget_micros, remaining_micros) = match budget {
        Some(b) => {
            let limit = b.max_micros.as_micros();
            // Saturating, never wrapping. `total_micros` can exceed `limit`, since the check and record are split and
            // the request that crosses a ceiling is admitted. A wrapped `remaining` would read as a huge positive.
            (Some(limit), Some(limit.saturating_sub(report.total_micros)))
        }
        None => (None, None),
    };

    json(
        StatusCode::OK,
        &serde_json::json!({
            "tenant": tenant,
            "period": period_key.as_str(),
            "period_started_at": period_started_at,
            "period_ends_at": period_ends_at,
            "spend_micro_usd": report.total_micros,
            "spend_usd": render_micro_usd(report.total_micros),
            "budget_micro_usd": budget_micros,
            "remaining_micro_usd": remaining_micros,
            // `null` with no budget, like the two fields above: there is no
            // scope to report for an unlimited subject.
            "credential_source": budget.map(|b| b.credential_source.as_str()),
            "last_flush_at": report.last_flush_at.map(|dt| dt.to_rfc3339()),
            "journal_checkpoint_at": report.journal_checkpoint_at.map(|dt| dt.to_rfc3339()),
            "journal_pending_micro_usd": report.journal_pending_micro_usd,
            "journal_pending_rows": report.journal_pending_rows,
            // ADR-0006 §5. `last_flush_at` answers "when", which forces every reader to subtract and to know the
            // configured bound. These three answer "is this replica's number trustworthy right now". A replica that
            // has never flushed reports its age since start, not `null`, so "never reached the store" cannot read as
            // "fine". See `SpendAccumulator::reconciliation_age`.
            "reconciliation_age_seconds": report.reconciliation_age_seconds,
            "reconciliation_expired": report.reconciliation_expired,
            "unreconciled_admissions": report.unreconciled_admissions,
            "unpriced_requests": report.unpriced_requests,
            "unpriced_pairs": report.unpriced_pairs,
            "unpriced_pairs_truncated": report.unpriced_pairs_truncated,
        }),
    )
}

fn handle_get_key_spend(
    control_plane: &ControlPlane,
    accumulator: Option<Arc<SpendAccumulator>>,
    key_id: &str,
) -> Response<Full<Bytes>> {
    if key_id.is_empty() {
        return bad_request("key_id must not be empty");
    }
    let Some(accumulator) = accumulator else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "llmproxy.spend_limit is not configured on this chain, so there is no spend accumulator to report from",
        );
    };
    let key_id = KeyId::new(key_id);
    let snapshot = control_plane.handle().load();
    let Some(tenant) = snapshot.key_tenants.get(&key_id) else {
        return store_error_response("/keys/{id}/spend", StoreError::NotFound);
    };
    let budget = snapshot.key_budgets.get(&key_id).copied();
    // The key's chargeback tags (key metadata), so a consumer of the key's
    // spend can attribute it without a second call. Spend is not split by
    // tag: there is no tag budget level.
    let tags = snapshot
        .keys
        .iter()
        .find(|(_, record)| record.key_id == key_id)
        .map(|(_, record)| record.tags.clone())
        .unwrap_or_default();
    let period = budget
        .map(|budget| budget.period)
        .unwrap_or_else(|| accumulator.default_period());
    let period_key = period.key_for_now();
    let (period_start, period_end) = period.window_now();
    let report = accumulator.report_key(&key_id, &period_key);
    let (budget_micros, remaining_micros) = match budget {
        Some(budget) => {
            let limit = budget.max_micros.as_micros();
            (Some(limit), Some(limit.saturating_sub(report.total_micros)))
        }
        None => (None, None),
    };
    json(
        StatusCode::OK,
        &serde_json::json!({
            "schema_version": proxy_control::control::SPEND_SCHEMA_VERSION,
            "key_id": key_id.as_str(),
            "tenant": tenant.as_str(),
            "tags": &*tags,
            "period": period_key.as_str(),
            "period_started_at": period_start.to_rfc3339(),
            "period_ends_at": period_end.to_rfc3339(),
            "spend_micro_usd": report.total_micros,
            "spend_usd": render_micro_usd(report.total_micros),
            "budget_micro_usd": budget_micros,
            "remaining_micro_usd": remaining_micros,
            // `null` with no budget, like the two fields above: an
            // unlimited key counts every source for reporting.
            "include_byok_in_limit": budget.map(|b| b.include_byok_in_limit),
            "last_flush_at": report.last_flush_at.map(|dt| dt.to_rfc3339()),
            "journal_checkpoint_at": report.journal_checkpoint_at.map(|dt| dt.to_rfc3339()),
            "journal_pending_micro_usd": report.journal_pending_micro_usd,
            "journal_pending_rows": report.journal_pending_rows,
            "reconciliation_age_seconds": report.reconciliation_age_seconds,
            "reconciliation_expired": report.reconciliation_expired,
            "unreconciled_admissions": report.unreconciled_admissions,
            "unpriced_requests": report.unpriced_requests,
            "unpriced_pairs": report.unpriced_pairs,
            "unpriced_pairs_truncated": report.unpriced_pairs_truncated,
        }),
    )
}

/// Renders integer micro-dollars as a decimal string, e.g. `1_234` -> `"0.001234"`. Never goes through `f64`:
/// `proxy_control::spend` is integer-only by design (see its module doc), and this read must not be the first
/// place that breaks.
fn render_micro_usd(micros: u64) -> String {
    format!("{}.{:06}", micros / 1_000_000, micros % 1_000_000)
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

// Compiled under `test` too, so `make tq` keeps the seam building even though
// only the nightly-only fuzz crate enables the feature.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub mod fuzzing;
