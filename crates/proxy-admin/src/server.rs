//! The admin HTTP server: binds a socket (control runtime, ADR-0003) and
//! answers the read-only endpoints, plus a
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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::service::service_fn;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use proxy_core::lifecycle::LifecycleState;
use proxy_core::WorkerConfigHandle;
use proxy_filters::auth::{KeyId, TenantId};
use proxy_filters::control::{ControlPlane, CredentialStoreError, StoreError};
use proxy_filters::model_authz::{ModelAccess, ModelPattern};
use proxy_filters::spend::{parse_micro_usd, Period, SpendAccumulator, TenantBudget};
use proxy_filters::spend_limit_filter::SharedSpendLimitState;
use proxy_filters::tenant_credential_crypto::TenantSecret;
use proxy_filters::usage_filter::{PricingRegistry, PublishError};
use proxy_http::credential_probe::{
    CredentialProbeOutcome, CredentialProbeRequest, TenantCredentialProbe,
};
use proxy_http::filter::SharedFactoryState;
use proxy_http::tenant_credentials::CredentialSource;
use proxy_observability::stats::{envoy_render, prometheus_render, Registry};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::dump::{
    clusters_from_snapshot_and_live, models_from_snapshot, ClusterDump, ConfigDump, LiveCluster,
};

/// The endpoints this crate serves, used both to route requests and to list
/// "available endpoints" in a 404 body. `{id}` segments are literal in this
/// list (documentation only) -- routing itself is done by
/// [`match_write_route`] for the write API, not by matching against these
/// strings.
const AVAILABLE_ENDPOINTS: &[&str] = &[
    "/ready",
    // Gated lifecycle writes (POST); see `handle_lifecycle`.
    "/healthcheck/fail",
    "/healthcheck/ok",
    "/drain_listeners",
    "/config_dump",
    "/clusters",
    "/server_info",
    "/ui",
    // Gated list reads live next to their write shapes below; `/models` is a
    // plain read (config data, like `/config_dump`).
    "/models",
    "/keys",
    "/keys/{id}",
    "/keys/{id}/budget",
    "/keys/{id}/spend",
    "/tenants",
    "/tenants/{id}",
    "/tenants/{id}/policy",
    "/tenants/{id}/budget",
    "/tenants/{id}/provider_credentials",
    "/tenants/{id}/provider_credentials/{provider}",
    // A READ, but gated like a write -- see
    // `handle`'s route table and `lib.rs`'s module doc for why.
    "/tenants/{id}/spend",
    "/chains/{stat_prefix}/keys",
    "/chains/{stat_prefix}/keys/{id}",
    "/chains/{stat_prefix}/keys/{id}/budget",
    "/chains/{stat_prefix}/keys/{id}/spend",
    "/chains/{stat_prefix}/tenants",
    "/chains/{stat_prefix}/tenants/{id}",
    "/chains/{stat_prefix}/tenants/{id}/policy",
    "/chains/{stat_prefix}/tenants/{id}/budget",
    "/chains/{stat_prefix}/tenants/{id}/provider_credentials",
    "/chains/{stat_prefix}/tenants/{id}/provider_credentials/{provider}",
    "/chains/{stat_prefix}/tenants/{id}/spend",
    "/pricing",
    "/chains/{stat_prefix}/pricing",
];

/// Hard cap on a write request's body. An admin write endpoint has no
/// legitimate reason to receive a multi-megabyte body (the largest real
/// payload, a `PUT .../policy`, is a handful of glob strings); without a
/// cap, reading `Incoming` to completion would buffer an attacker-controlled
/// body of unbounded size in memory -- a trivial DoS against a port that is,
/// deliberately, reachable without a config file naming an operator's IP
/// allowlist.
pub(super) const MAX_ADMIN_BODY_BYTES: usize = 64 * 1024;

/// Body cap for `PUT /pricing` alone. A rate card is machine-generated and
/// large: the shipped OpenRouter card (438 entries) is 142 KB as compact JSON,
/// 268 KB with its source catalog, and 401 KB pretty-printed, which is what the
/// admin UI's upload box and a hand-edited file send. The generic cap above
/// rejected all of them. 4 MiB leaves about ten times the largest of those, so
/// a catalog several times today's size still fits.
///
/// The cap stays finite for the reason the generic one exists: the bearer
/// gate has already passed by the time the body is read, so only a token
/// holder can make the server buffer this much, and the buffer is released
/// when the request ends. Every other route keeps [`MAX_ADMIN_BODY_BYTES`].
pub(super) const MAX_PRICING_BODY_BYTES: usize = 4 * 1024 * 1024;

/// What `/ready` should report, as decided by whoever injects the
/// [`ReadinessProbe`] -- this crate never asks a `ClusterManager` itself
/// (AGENTS.md invariant 2: generated protos and their consuming crates stay out
/// of `proxy-admin`; the analogous discipline here is "no data-plane crate
/// dependency", matching `proxy-xds::apply::Publish`'s seam).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Serve traffic: `/ready` returns `200 "LIVE"`.
    Live,
    /// At least one cluster has not resolved yet and the caller's warming
    /// deadline (if any) has not passed: `/ready` returns `503
    /// "INITIALIZING"`. `warming` names the still-unresolved clusters, for
    /// logging by whoever built the probe -- this module does not log it
    /// itself (`/ready` is polled on a tight loop
    /// by orchestrators, so logging on every call would become the
    /// incident; the one-shot "deadline expired" warning belongs to the
    /// probe's owner, `crates/proxy/src/main.rs`, which knows when the
    /// deadline fires and can suppress repeats).
    Initializing { warming: Vec<String> },
    /// The process is out of rotation, either because `/healthcheck/fail`
    /// was called or because a drain started (SIGTERM or
    /// `POST /drain_listeners`): `/ready` returns `503 "DRAINING"`, Envoy's
    /// server-state text for the same condition.
    Draining,
}

/// Where `/ready` gets its answer. A plain synchronous closure (not `async`,
/// unlike [`proxy_xds::apply::Publish`]) because the real implementation
/// (`crates/proxy/src/main.rs`) only reads atomics off a `ClusterManager` --
/// no I/O, nothing to await. `Arc<dyn Fn...>` rather than a `Box` because it
/// is cloned into every accepted connection's task alongside `config` and
/// `registry` (see [`serve`]'s accept loop) -- an `Arc` clone is a refcount
/// bump; a `Box` would need to be reconstructed or the closure would need to
/// be `Clone` itself, which a `dyn Fn` cannot be.
///
/// This crate never depends on `proxy-cluster` to build one -- see this
/// module's doc and [`Readiness`]'s doc for why. When `serve` is called with
/// `None` (no probe wired), `/ready` keeps its default behavior, `200
/// "LIVE"` unconditionally, rather than inventing a new failure mode for
/// callers (mostly tests) that never had a `ClusterManager` to ask.
pub type ReadinessProbe = Arc<dyn Fn() -> Readiness + Send + Sync>;

/// Supplies a runtime host-set snapshot for one config snapshot. Keeping this
/// as an injected closure preserves the admin crate's control-plane-only
/// dependency direction: the binary can adapt `ClusterManager` state without
/// making this crate depend on the data plane or on generated protos.
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
}

/// A running admin server. Dropping this does not stop the server -- see
/// [`AdminServer::abort`] -- so callers that care about shutdown (none do
/// yet) must call it explicitly.
pub struct AdminServer {
    local_addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

/// Dependencies shared by every connection accepted by one admin server.
///
/// This is one server-level capability bundle, not a request payload: cloning
/// it only clones `Arc` handles and optional closures for the next task.
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

    /// Resolves a `/ui/` remainder to a file. Unknown remainders fall back
    /// to `index.html` (a single-page app owns its own sub-routes; a 404
    /// here would break a refresh on any client-side route).
    fn lookup(&self, remainder: &str) -> Option<&UiFile> {
        let key = remainder.trim_start_matches('/');
        if key.is_empty() {
            return self.files.get("index.html");
        }
        self.files.get(key).or_else(|| self.files.get("index.html"))
    }
}

/// Content type by file extension for `/ui/` assets. Unknown extensions get
/// `application/octet-stream` rather than a guessed text type -- serving an
/// attacker-influenced byte stream as scriptable HTML/JS is exactly how a
/// stored-XSS rides a static file server, and these bytes come from a build
/// directory, not a vetted allowlist.
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
/// `registry` is the stats registry, `Some` once a caller has one to
/// offer -- see `/stats`'s route in [`handle`] for what happens when it
/// doesn't. `started_at` backs `/server_info`'s uptime. `factory_state` is
/// the per-serve [`SharedFactoryState`] a worker's `AuthFilterFactory`
/// registers its `ControlPlane` singleton into -- see the module doc's
/// "resolved PER REQUEST" section for why `serve` itself never reads out of
/// it at startup. `admin_token` gates every WRITE endpoint (`/keys`,
/// `/tenants`, ...); see [`normalize_admin_token`] and [`handle`]'s gate for
/// the fail-closed semantics -- READ endpoints are unaffected by it.
/// `readiness` answers `/ready`; see [`ReadinessProbe`]'s
/// doc for why it is an injected closure and what `None` means.
/// `cluster_state` supplies the current host sets for `/clusters`.
/// Passing `None` preserves the standalone config-only view used by older
/// embedders and tests; the shipped binary always passes the real provider.
///
/// Rust note: `TcpListener::accept` runs in a loop inside a `tokio::spawn`led
/// task; each accepted connection gets its own further-spawned task running
/// one `hyper::server::conn::http1` connection, the standard hyper-on-tokio
/// shape. Nothing here needs `!Send`/`Rc` -- this is ordinary control-plane
/// code, never the worker-local data plane (ADR-0003).
pub async fn serve(addr: SocketAddr, runtime: AdminRuntime) -> Result<AdminServer, AdminError> {
    let admin_token = normalize_admin_token(runtime.admin_token.clone());
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
            let mut runtime = runtime.clone();
            let admin_token = admin_token.clone();
            runtime.admin_token = admin_token;
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let runtime = runtime.clone();
                    async move { Ok::<_, std::convert::Infallible>(handle(req, &runtime).await) }
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

async fn handle(req: Request<Incoming>, runtime: &AdminRuntime) -> Response<Full<Bytes>> {
    let config = &runtime.config;
    let registry = runtime.registry.as_deref();
    let started_at = runtime.started_at;
    let factory_state = &runtime.factory_state;
    let admin_token = runtime.admin_token.as_deref();
    let readiness = runtime.readiness.as_ref();
    let cluster_state = runtime.cluster_state.as_ref();
    // ---- Single-page admin UI (optional, in-memory, same-origin so no CORS
    // is ever needed): `GET /ui`, `GET /ui/`, and `GET /ui/<asset>`. Unknown
    // sub-paths fall back to index.html -- the SPA owns its own routes.
    // Exact-prefix matching only (`/ui` + `/` or end): `/uix` must not match.
    let path_str = req.uri().path();
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
                 LLMPROXY_ADMIN_UI_DIR to the `make ui-build` output directory \
                 (admin-ui/dist/) and restart",
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
    // ---- Read endpoints: unchanged by the write API,
    // no gate, matched on path alone (as before -- these never distinguished
    // method). ----
    match req.uri().path() {
        // No probe wired keeps the pre-existing
        // unconditional `200 "LIVE"` -- see `ReadinessProbe`'s doc for why
        // that is a deliberate "no new failure mode" default rather than an
        // invented one for callers (mostly tests) with no `ClusterManager`
        // to ask.
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
        // Model inventory: every route this snapshot matches on the model
        // header (`x-llmproxy-model`), rendered as the patterns an operator
        // configured. Ungated like every other read in this block -- it is
        // config shape, exactly like `/config_dump` above, and carries no
        // identity and no spend. See `dump::models_from_snapshot` for what
        // counts as a model and what is deliberately left out.
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
        // Rendering is `envoy_render::render`, which only
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

    // ---- Write endpoints, PLUS two gated reads: `.../spend`, and
    // `GET .../keys` (the key listing). All are
    // resolved per request through the SAME three gates. A GET on either
    // renders data an unauthenticated caller has no business reading --
    // per-tenant spend, or the tenant/key inventory -- unlike every endpoint
    // matched by literal path above (`/config_dump`, `/clusters`, `/models`,
    // `/stats`, ...), which is why they are routed here instead of there.
    // See `lib.rs`'s module doc for the one-line rule and `WriteRoute`'s doc
    // for how a GET fits a type named for writes. ----
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

    let Some(route) = match_write_route(&segments, &method) else {
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
    // AGENTS.md "Fail-open controls" ("a security control that fails open must be
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

    // Lifecycle routes need no ControlPlane, so they leave after the same two
    // gates every other write passes (one gate, not a second copy of it).
    if let Some(action) = route.lifecycle_action() {
        return handle_lifecycle(action, runtime.lifecycle.as_deref(), req.uri().query());
    }

    // `PUT /pricing` needs the chain's rate card registry, not a control
    // plane: without `llmproxy.auth` it still works, for this process only,
    // and says so. It also has its own body cap, so it leaves before the
    // control-plane gate and the generic body read below.
    if matches!(route, WriteRoute::Pricing | WriteRoute::ScopedPricing(_)) {
        let body = match read_limited_body(req.into_body(), MAX_PRICING_BODY_BYTES).await {
            Ok(bytes) => bytes,
            Err(resp) => return resp,
        };
        return handle_set_pricing(factory_state, route.stat_prefix(), &body);
    }

    // Gate 3: does the control plane exist, and is it unambiguous which one
    // this write means?
    //
    // A SCOPED route (`route.stat_prefix()` is `Some`) names
    // exactly which chain it means, so it resolves through
    // `SharedFactoryState::get_by_name` -- no ambiguity is possible there
    // (the lowering check rejects a duplicate `stat_prefix` among
    // `llmproxy.auth`-configuring chains before this server ever runs), and
    // an unknown name is a 404, not a 503: it names an operator error
    // (typo'd or never-configured `stat_prefix`), not a boot race.
    //
    // An UNSCOPED route falls back to `resolve_control_plane`
    // (`get_across_scopes`) exactly as it did before scoped routes existed -- kept
    // as a convenience for the single-chain case; see that function's doc
    // for the two 503 situations it does not need to tell apart, and for the
    // third case below (more than one `llmproxy.auth`-configured chain) that
    // it does.
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
                // Loud, not a guess (AGENTS.md "Fail-open controls"'s shape applied here
                // too): picking one of several ControlPlanes at random would
                // risk writing a key into the wrong tenant's control plane.
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

    match route {
        // `GET /keys` / `GET /chains/{p}/keys` -- the gated LIST read, same
        // three gates as every write below (see `WriteRoute::KeyList`'s doc).
        WriteRoute::KeyList | WriteRoute::ScopedKeyList(_) => handle_list_keys(&control_plane),
        WriteRoute::Keys | WriteRoute::ScopedKeys(_) => handle_mint_key(&control_plane, &body),
        WriteRoute::KeyById(id) | WriteRoute::ScopedKeyById(_, id) => {
            handle_revoke_key(&control_plane, id)
        }
        WriteRoute::KeyBudget(id) | WriteRoute::ScopedKeyBudget(_, id) => {
            handle_set_key_budget(&control_plane, id, &body)
        }
        WriteRoute::KeySpend(id) | WriteRoute::ScopedKeySpend(_, id) => {
            handle_get_key_spend_route(factory_state, stat_prefix_opt, &control_plane, id, &path)
        }
        WriteRoute::Tenants | WriteRoute::ScopedTenants(_) => {
            handle_create_tenant(&control_plane, &body)
        }
        WriteRoute::TenantById(id) | WriteRoute::ScopedTenantById(_, id) => {
            handle_delete_tenant(&control_plane, id)
        }
        WriteRoute::TenantPolicy(id) | WriteRoute::ScopedTenantPolicy(_, id) => {
            handle_set_policy(&control_plane, id, &body)
        }
        WriteRoute::TenantBudget(id) | WriteRoute::ScopedTenantBudget(_, id) => {
            handle_set_budget(factory_state, stat_prefix_opt, &control_plane, id, &body)
        }
        WriteRoute::TenantSpend(id) | WriteRoute::ScopedTenantSpend(_, id) => {
            handle_get_spend_route(factory_state, stat_prefix_opt, &control_plane, id, &path)
        }
        WriteRoute::TenantCredentials(id) | WriteRoute::ScopedTenantCredentials(_, id) => {
            handle_list_tenant_credentials(&control_plane, id)
        }
        // `body` moves into the handler (unlike every arm above, which
        // borrows it) so the handler can wipe the buffer holding the
        // plaintext key. Only one arm runs, so the move is fine.
        //
        // Rust note: `Option<Arc<dyn Trait>>::as_deref()` borrows the trait
        // object out of the `Arc` without cloning it, giving the handler an
        // `Option<&dyn Trait>` it can call through.
        WriteRoute::TenantCredentialPut(id, provider)
        | WriteRoute::ScopedTenantCredentialPut(_, id, provider) => {
            handle_put_tenant_credential(
                &control_plane,
                config,
                runtime.credential_probe.as_deref(),
                id,
                provider,
                body,
            )
            .await
        }
        WriteRoute::TenantCredentialDelete(id, provider)
        | WriteRoute::ScopedTenantCredentialDelete(_, id, provider) => {
            handle_delete_tenant_credential(&control_plane, id, provider)
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

/// `POST /healthcheck/fail`, `/healthcheck/ok`, `/drain_listeners`. Callers
/// have already passed the token gate.
///
/// `/drain_listeners` accepts the Envoy flags `graceful` and `inboundonly`
/// (istio sends `?inboundonly&graceful`); both are accepted with no extra
/// effect because the drain is always the full graceful one. Any other query
/// parameter is a 400 naming it, so a typo'd flag is never silently dropped.
/// Logs carry no credentials: only the action and whether it changed state.
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

/// One of the write-capable paths this server recognizes, with the path
/// parameter(s) (if any) borrowed straight out of the request's path
/// segments. Kept separate from method matching
/// ([`WriteRoute::expected_method`]) so "known path, wrong method" can
/// answer 405 rather than falling through to the generic 404 an unrecognized
/// path gets.
///
/// The `Scoped*` variants (`/chains/{stat_prefix}/...`) sit alongside the
/// original unscoped ones rather than replacing them --
/// [`Self::stat_prefix`] is the single place that tells the two families
/// apart for [`handle`]'s control-plane resolution gate.
///
/// `TenantSpend`/`ScopedTenantSpend` are a GET, despite the
/// type's name. It shares this type (rather than getting a parallel
/// `ReadRoute` enum) precisely because it needs the exact same gate and the
/// exact same scoped/unscoped `ControlPlane` resolution every other variant
/// here already has; see [`handle`]'s doc for why it is gated at all.
///
/// `KeyList`/`ScopedKeyList` are the same story for a second reason worth
/// stating separately: a key inventory is IDENTITY data -- which key ids
/// exist, which tenant owns each, whether it was revoked, what ceiling it
/// runs against. Nothing about it should be answerable to an unauthenticated
/// caller just because the verb is `GET`, exactly as the spend read's doc
/// says for money.
enum WriteRoute<'a> {
    /// `GET /keys` -- the gated list read. Distinct from [`Self::Keys`]
    /// (POST, mint) so a GET is never answered with a 405 and a POST never
    /// with a listing.
    KeyList,
    Keys,
    KeyById(&'a str),
    KeyBudget(&'a str),
    KeySpend(&'a str),
    Tenants,
    TenantById(&'a str),
    TenantPolicy(&'a str),
    TenantBudget(&'a str),
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
    ScopedKeySpend(&'a str, &'a str),
    ScopedTenants(&'a str),
    ScopedTenantById(&'a str, &'a str),
    ScopedTenantPolicy(&'a str, &'a str),
    ScopedTenantBudget(&'a str, &'a str),
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
            WriteRoute::KeyBudget(_) => Method::PUT,
            WriteRoute::KeySpend(_) => Method::GET,
            // The gated list read: GET on the collection path.
            WriteRoute::KeyList | WriteRoute::ScopedKeyList(_) => Method::GET,
            WriteRoute::TenantPolicy(_) => Method::PUT,
            WriteRoute::TenantBudget(_) => Method::PUT,
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
            WriteRoute::ScopedKeyBudget(..) => Method::PUT,
            WriteRoute::ScopedKeySpend(..) => Method::GET,
            WriteRoute::ScopedTenantPolicy(..) => Method::PUT,
            WriteRoute::ScopedTenantBudget(..) => Method::PUT,
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
            | WriteRoute::KeySpend(_)
            | WriteRoute::Tenants
            | WriteRoute::TenantById(_)
            | WriteRoute::TenantPolicy(_)
            | WriteRoute::TenantBudget(_)
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
            | WriteRoute::ScopedKeySpend(s, _)
            | WriteRoute::ScopedTenantById(s, _)
            | WriteRoute::ScopedTenantPolicy(s, _)
            | WriteRoute::ScopedTenantBudget(s, _)
            | WriteRoute::ScopedTenantSpend(s, _)
            | WriteRoute::ScopedTenantCredentials(s, _)
            | WriteRoute::ScopedTenantCredentialPut(s, ..)
            | WriteRoute::ScopedTenantCredentialDelete(s, ..) => Some(s),
            WriteRoute::Pricing => None,
            WriteRoute::ScopedPricing(s) => Some(s),
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
///
/// `method` participates for exactly TWO shapes: the key collection paths
/// (`/keys` and `/chains/{stat_prefix}/keys`), where `GET` is the gated
/// listing and every other verb is the mint (POST). Every other shape here
/// is decided by the path alone, with [`WriteRoute::expected_method`]
/// answering a wrong verb with 405 -- but on a collection path the path
/// cannot decide, because two legitimate endpoints (mint and list) share it
/// and are told apart only by the verb. Reading `method` here rather than
/// after the gate keeps both from landing on 405: routing happens before
/// authorization, as it must (a caller with the wrong verb on the right path
/// should learn the path exists, not that it was forbidden).
fn match_write_route<'a>(segments: &[&'a str], method: &Method) -> Option<WriteRoute<'a>> {
    match segments {
        ["keys"] if *method == Method::GET => Some(WriteRoute::KeyList),
        ["keys"] => Some(WriteRoute::Keys),
        ["keys", id] => Some(WriteRoute::KeyById(id)),
        ["keys", id, "budget"] => Some(WriteRoute::KeyBudget(id)),
        ["keys", id, "spend"] => Some(WriteRoute::KeySpend(id)),
        ["tenants"] => Some(WriteRoute::Tenants),
        ["tenants", id] => Some(WriteRoute::TenantById(id)),
        ["tenants", id, "policy"] => Some(WriteRoute::TenantPolicy(id)),
        ["tenants", id, "budget"] => Some(WriteRoute::TenantBudget(id)),
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

/// Resolves the [`ControlPlane`] registered under the chain named
/// `stat_prefix` -- the scoped (`/chains/{stat_prefix}/...`) counterpart of
/// [`resolve_control_plane`]. `None` means no chain
/// by that name has registered an `llmproxy.auth` control plane, which
/// [`handle`] reports as 404: unlike the unscoped path, there is no
/// ambiguity to report here (`get_by_name` cannot find two chains at once,
/// since `proxy-config`'s lowering rejects a duplicate `stat_prefix`
/// among `llmproxy.auth`-configuring chains before this server ever starts),
/// so a caller-facing 404 naming the unknown `stat_prefix` is honest: either
/// it was typo'd, or that chain's worker has not finished building its
/// filter chain yet.
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

/// Resolves the [`SpendAccumulator`] singleton `llmproxy.spend_limit`
/// registers, ACROSS EVERY CHAIN'S SCOPE -- the counterpart of
/// [`resolve_control_plane`], for the unscoped `GET /tenants/{id}/spend`
/// alias.
///
/// **What is registered under [`proxy_filters::spend_limit_filter::TYPE_URL`]
/// is [`SharedSpendLimitState`], a WRAPPER -- never a bare
/// `Arc<SpendAccumulator>`.** `SpendLimitFilterFactory::create` bundles the
/// accumulator together with its usage-missing warner behind one singleton
/// slot (see that type's own doc for why); downcasting straight to
/// `SpendAccumulator` here would silently fail on every real chain, which is
/// exactly the trap this function's doc exists to name before a future
/// caller re-adds it.
///
/// `Ok(None)`/`Err(scopes)` mirror [`resolve_control_plane`]'s exact
/// semantics, restated for this singleton: `Ok(None)` covers both a boot
/// race and "no chain configures `llmproxy.spend_limit` at all" (both a 503
/// to the caller -- "not configured" and "not ready yet" are equally
/// unactionable to distinguish); `Err(scopes)` is more than one chain
/// registering the singleton, which cannot actually happen for an unscoped
/// caller that already resolved a SINGLE, unambiguous `ControlPlane` above
/// (`llmproxy.spend_limit` requires `llmproxy.auth` earlier in the SAME
/// chain, so two spend-configured chains would already have failed the
/// control-plane gate) -- kept here defensively, mirroring
/// `resolve_control_plane`'s shape, rather than assumed.
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

/// Reads `body` up to `cap` bytes ([`MAX_ADMIN_BODY_BYTES`] for every route
/// but pricing), returning the collected bytes or a ready-to-send 413.
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
/// see AGENTS.md invariant 1: a silently ignored field in a security-write API is
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
        StoreError::Conflict(reason) => text(StatusCode::CONFLICT, &reason),
        other => {
            tracing::warn!(endpoint, error = %other, "admin write failed: control-plane store error");
            text(StatusCode::INTERNAL_SERVER_ERROR, &other.to_string())
        }
    }
}

fn read_api_schema_version<'de, D: serde::Deserializer<'de>>(de: D) -> Result<(), D::Error> {
    let version = <u32 as serde::Deserialize>::deserialize(de)?;
    if version == proxy_filters::control::SPEND_SCHEMA_VERSION {
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
/// [`proxy_filters::spend::TenantBudget`]'s doc for why "unlimited" and "a
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
    budget: Option<BudgetSpec>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetSpec {
    /// A decimal-string ceiling, e.g. `"500.00"` -- parsed by
    /// [`parse_micro_usd`], the SAME parser a configured price uses (see
    /// that function's doc), so an operator cannot express a budget more
    /// precisely than a price.
    max_usd: String,
    period: PeriodSpec,
    /// `"platform"` or `"tenant"`; absent means `"platform"`. Kept a plain
    /// string so an unknown value gets this module's fixed 400 message
    /// instead of serde's, which would echo the rejected input back.
    #[serde(default)]
    credential_source: Option<String>,
}

/// External representation of [`Period`] over the wire -- `"daily"` or
/// `"monthly"`, matching the proto/config convention this admin API already
/// uses elsewhere (lowercase, snake_case wire names for a Rust enum).
///
/// Serializable as well as deserializable, so the SAME wire spelling is used
/// in both directions: a `PUT .../budget` accepts `"daily"` and
/// `GET /keys` reports `"daily"`, rather than two spellings an operator has
/// to remember belong together.
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

/// `GET /keys` and `GET /chains/{stat_prefix}/keys`: the key inventory --
/// key id, owning tenant, revocation state, and configured ceiling, sorted
/// by `(tenant, key_id)` (the sort is `ControlPlane::list_keys`'s, so the
/// same state always answers the same bytes).
///
/// Routed through the write API's three gates despite being a GET, for the
/// same reason `.../spend` is (see [`handle`]): this is IDENTITY data -- it
/// answers which keys exist, which tenant owns each, and what each may spend
/// -- and nothing about that should be enumerable by an unauthenticated
/// caller just because the verb is `GET`.
///
/// It returns nothing a credential could be derived from: no digest, and no
/// plaintext. The plaintext exists only in `POST /keys`'s own response body,
/// exactly once (see `lib.rs`'s redaction section) -- `list_keys` reads the
/// published snapshot, which never held it in the first place.
fn handle_list_keys(control_plane: &ControlPlane) -> Response<Full<Bytes>> {
    let keys = control_plane.list_keys();
    let rendered: Vec<serde_json::Value> = keys
        .iter()
        .map(|listing| {
            serde_json::json!({
                "key_id": listing.key_id.as_str(),
                "tenant": listing.tenant.as_str(),
                "revoked": listing.revoked,
                // `null` means "no ceiling configured" (unlimited); an
                // explicitly configured zero ceiling serializes as its own
                // real number -- see `proxy_filters::spend::TenantBudget`'s
                // doc for why those two must not collapse into one value.
                // Both integer micro-dollars (exact) and a rendered decimal
                // string (readable) are reported, mirroring the spend read.
                "budget": listing.budget.map(|budget| serde_json::json!({
                    "max_micro_usd": budget.max_micros.as_micros(),
                    "max_usd": render_micro_usd(budget.max_micros.as_micros()),
                    "period": PeriodSpec::from(budget.period),
                    "credential_source": budget.credential_source.as_str(),
                })),
            })
        })
        .collect();
    let count = rendered.len();
    json(
        StatusCode::OK,
        &serde_json::json!({ "schema_version": proxy_filters::control::SPEND_SCHEMA_VERSION, "keys": rendered, "count": count }),
    )
}

fn handle_mint_key(control_plane: &ControlPlane, body: &[u8]) -> Response<Full<Bytes>> {
    let MintKeyRequest { tenant, key_id, .. } = match parse_json_body(body) {
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
                    "schema_version": proxy_filters::control::SPEND_SCHEMA_VERSION,
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

/// Longest API key `PUT .../provider_credentials/{provider}` accepts. Real
/// provider keys are well under 300 bytes; the cap bounds what a header value
/// the router later builds can be.
const MAX_TENANT_API_KEY_BYTES: usize = 4096;

/// The only `schema_version` this endpoint speaks.
const TENANT_CREDENTIALS_API_VERSION: u32 = 1;

/// JSON error in the shape the router's own local replies use
/// (`{"error":{"message":..,"type":..}}`), so a client has one error shape to
/// parse. Callers pass a fixed message: never format request-body content into
/// it.
fn error_json(status: StatusCode, error_type: &str, message: &str) -> Response<Full<Bytes>> {
    json(
        status,
        &serde_json::json!({ "error": { "message": message, "type": error_type } }),
    )
}

/// [`error_json`] plus `upstream_status` inside the `error` object, for the
/// save-time probe's failures where the provider did answer. The status is a
/// bare code, so it carries nothing from the request or the response body.
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

/// Deserializes straight into a [`TenantSecret`] so the parsed plaintext
/// lives in a zeroize-on-drop buffer from its first owned form onward.
///
/// Rust note: `deserialize_with` points serde at a function instead of the
/// field type's own `Deserialize` impl; `TenantSecret` deliberately has none.
fn deserialize_tenant_secret<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<TenantSecret, D::Error> {
    <String as serde::Deserialize>::deserialize(de).map(TenantSecret::new)
}

/// `verify` defaults to `true`: a key is checked against the provider unless
/// the caller opts out (ADR-0007 decision 10).
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

/// Whether `tenant` exists: created through the store, or implied by a
/// bootstrap/minted key or a stored policy. Reads the store, not only the
/// snapshot, because a created tenant with no key or policy yet appears only
/// there.
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

/// Wipes `body` when this handle is the only reference to its buffer.
/// Best effort: if hyper still shares the buffer, `try_into_mut` fails and the
/// bytes live until the allocator reuses them.
fn wipe_body(body: Bytes) {
    if let Ok(mut unique) = body.try_into_mut() {
        zeroize::Zeroize::zeroize(&mut unique[..]);
    }
}

/// `PUT /tenants/{id}/provider_credentials/{provider}`.
///
/// Check order: body shape (400), tenant (404), provider enabled on some
/// cluster (422), then, when `verify` is true, the save-time probe (422 or 502,
/// nothing stored on failure), then the store (503 when `tenant_credentials` is
/// not configured). The request body is never logged, echoed, or formatted into
/// an error message: serde's own errors can quote input, so this handler maps
/// them to fixed text by [`serde_json::Error::classify`].
async fn handle_put_tenant_credential(
    control_plane: &ControlPlane,
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
    control_plane: &ControlPlane,
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
    let request: PutTenantCredentialRequest = match serde_json::from_slice(body) {
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
    // The key is later written into an upstream header. `HeaderValue::from_str`
    // refuses CR/LF and other control bytes but allows obs-text (0x80..=0xFF),
    // which no provider key uses, so `is_ascii` closes that gap.
    if !key.is_ascii() || hyper::header::HeaderValue::from_str(key).is_err() {
        return error_json(
            StatusCode::BAD_REQUEST,
            INVALID,
            "api_key contains bytes that are not valid in an HTTP header value",
        );
    }

    let tenant_id = TenantId::new(tenant);
    match tenant_exists(control_plane, &tenant_id) {
        Ok(true) => {}
        Ok(false) => return tenant_not_found(),
        Err(err) => return store_error_response("/tenants/{id}/provider_credentials", err),
    }

    // A credential no cluster slot would ever use is a typo the operator wants
    // to hear about now, not an inert row. The snapshot guard is dropped before
    // any `.await` below.
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
        // The probe goes to the first slot cluster, by name, that has a
        // `verify_path`. `min_by` over the names keeps that choice independent
        // of the map's iteration order.
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

    // ADR-0007 decision 10: a key is stored as verified only after a probe
    // got a 2xx from the provider. Every failure path returns before the store.
    let verified = if request.verify {
        // Without key-encryption keys the store refuses the key below, so do
        // not send it to the provider first.
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
        // The probe owns its secret, and the store still needs the key, so
        // this is the one extra plaintext copy the save path makes. Both
        // copies are zeroize-on-drop.
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
                // The reason names the failure only (see the probe trait's
                // doc), so it is safe for the log but not for the reply.
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

    match control_plane.store_tenant_secret(&tenant_id, provider, &request.api_key, verified) {
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
    let allow = match request.access {
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
    for (index, pattern) in request.deny.iter().enumerate() {
        if !ModelPattern::is_valid(pattern) {
            return bad_request(&format!(
                "deny[{index}] must be an exact model name or a single trailing `*` glob"
            ));
        }
    }
    let access = allow.with_deny(request.deny.into_iter().map(ModelPattern::new).collect());
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

/// Turns a request's [`BudgetSpec`] into the stored [`TenantBudget`]. Both
/// budget writes use it, so their validation cannot drift apart.
// See `parse_json_body`'s identical `#[allow]` -- same cold admin-write path,
// same "large" `Err` variant by design.
#[allow(clippy::result_large_err)]
fn budget_from_spec(spec: BudgetSpec) -> Result<TenantBudget, Response<Full<Bytes>>> {
    let max_micros = parse_micro_usd(&spec.max_usd)
        .map_err(|err| bad_request(&format!("invalid `max_usd`: {err}")))?;
    let credential_source = match spec.credential_source.as_deref() {
        // Absent means platform so existing budgets keep their meaning
        // (ADR-0007 decision 8).
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

/// `PUT /tenants/{id}/budget`. `{"budget": null}`
/// clears the tenant's ceiling (reverts to unlimited); `{"budget": {...}}`
/// sets it, parsing `max_usd` with [`parse_micro_usd`] -- the SAME parser a
/// configured price uses -- so a malformed decimal string is a 400 naming
/// the problem, not a silently-truncated ceiling.
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

    // The start-up check in `llmproxy.spend_limit` treats any tenant budget in
    // the store as a legacy one and refuses to start without the cutover. A
    // budget written here would pass now and stop the next restart, and a
    // rolling restart would crash-loop every replica, so refuse it at write
    // time, where the operator is looking. Clearing a budget is always fine,
    // and rows already in the store behave as they did.
    if budget.is_some() {
        if let Some(shared) = resolve_spend_shared(factory_state, stat_prefix) {
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

/// `PUT /keys/{id}/budget`. A budget belongs to the logical key identity,
/// never its secret, so rotating a secret leaves this row and its spend
/// ledger in place.
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
        Some(spec) => match budget_from_spec(spec) {
            Ok(budget) => Some(budget),
            Err(response) => return response,
        },
    };
    match control_plane.set_key_budget(&KeyId::new(key_id), budget.as_ref()) {
        Ok(()) => no_content(),
        Err(err) => store_error_response("/keys/{id}/budget", err),
    }
}

/// Resolves the spend accumulator (scoped or unscoped, matching
/// `stat_prefix`'s presence exactly the way [`handle`]'s own `ControlPlane`
/// gate already did just above this call) and dispatches to
/// [`handle_get_spend`]. Split out of [`handle`]'s final `match` so that
/// match's other arms stay one-liners; this one needs its own resolution
/// step because a tenant's spend read needs a SECOND singleton beyond the
/// `ControlPlane` every other write/read here already resolved.
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
                // See `resolve_spend_state`'s doc: defensive, mirrors
                // `resolve_control_plane`'s ambiguity handling, but cannot
                // actually be reached given the control-plane gate that
                // already ran above this call.
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
/// Reads TWO singletons, both of which can legitimately be missing on a
/// live, otherwise-healthy chain:
/// - the tenant's [`TenantBudget`] (period + ceiling), read off the
///   ALREADY-RESOLVED `control_plane`'s published snapshot -- a tenant with
///   no configured budget is not an error (see `TenantBudget`'s own doc);
///   `budget_micro_usd`/`remaining_micro_usd` render `null` for one;
/// - the spend accumulator itself, resolved by the caller
///   ([`handle_get_spend_route`]) and handed in as `None` when
///   `llmproxy.spend_limit` is not configured on this chain at all -- THAT
///   is the one genuinely missing-singleton case this function answers with
///   a 503, matching the shape of the missing-`ControlPlane` 503 elsewhere
///   in this file (never a fourth status code for "half configured").
///
/// **Which period?** The tenant's own `TenantBudget::period` if one is
/// configured, else [`SpendAccumulator::default_period`] -- exactly
/// `spend_limit_filter`'s own `decode_headers` resolution, restated here so
/// the read reports the SAME period the enforcement filter would check.
///
/// `spend_usd` is rendered from the integer `total_micros` by
/// [`render_micro_usd`] -- never through an `f64`; see `proxy_filters::spend`'s
/// module doc for why introducing one anywhere in the money path is a bug.
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
    // Rust note: `TenantPolicyMap` is keyed on the tenant's plain `&str`
    // name, not `TenantId` -- same lookup `spend_limit_filter`'s own
    // `decode_headers` performs against this exact snapshot.
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
            // Saturating, never wrapping: `total_micros` can exceed `limit`
            // (the check/record split means the request that crosses a
            // ceiling is always admitted -- see `spend_limit_filter`'s own
            // module doc), and an operator reading a wrapped-around
            // `remaining` as a huge positive number instead of `0` would be
            // told the opposite of the truth.
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
            // ADR-0006 §5. `last_flush_at` alone answers "when",
            // which forces every reader to do the subtraction and to know
            // what bound this deployment configured; these three answer
            // "is this replica's number trustworthy right now", which is
            // what an operator reading a spend figure during an incident
            // actually needs. A replica that has NEVER flushed reports its
            // age since start here rather than `null`, so "never reached the
            // store" cannot be misread as "fine" -- see
            // `SpendAccumulator::reconciliation_age`.
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
            "schema_version": proxy_filters::control::SPEND_SCHEMA_VERSION,
            "key_id": key_id.as_str(),
            "tenant": tenant.as_str(),
            "period": period_key.as_str(),
            "period_started_at": period_start.to_rfc3339(),
            "period_ends_at": period_end.to_rfc3339(),
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
            "reconciliation_age_seconds": report.reconciliation_age_seconds,
            "reconciliation_expired": report.reconciliation_expired,
            "unreconciled_admissions": report.unreconciled_admissions,
            "unpriced_requests": report.unpriced_requests,
            "unpriced_pairs": report.unpriced_pairs,
            "unpriced_pairs_truncated": report.unpriced_pairs_truncated,
        }),
    )
}

/// Renders integer micro-dollars as a decimal-string dollar amount, e.g.
/// `1_234` -> `"0.001234"`, `500_000_000` -> `"500.000000"`. Never goes
/// through `f64` -- `proxy_filters::spend`'s entire module is integer-only by
/// design (see its module doc's "Money is integer, never `f64`" section),
/// and this admin read must not be the first place that property breaks.
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
