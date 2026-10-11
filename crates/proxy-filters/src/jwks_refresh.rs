//! OIDC discovery + background JWKS refresh.
//!
//! [`crate::jwt_auth::JwtAuthenticator`] verifies against a cached key set;
//! this module is what keeps that cache fresh without ever touching the
//! request path. Shape (OIDC fits the static-JWKS design without reshaping it):
//!
//! ```text
//! refresher thread (one per discovery-configured provider)
//!   GET discovery_url -> { jwks_uri } -> GET jwks_uri -> JwtKeySet
//!   -> ArcSwap::store (atomic publish; workers see the new set on next load)
//! ```
//!
//! # What runs where
//!
//! - [`parse_discovery_doc`] / [`parse_jwks_doc`] / [`parse_ca_pem`] are pure
//!   functions over bytes: no I/O, unit-tested directly.
//! - [`refresh_once`] composes them with one injected `fetch`: the production
//!   thread passes [`fetch_bytes`] (real HTTPS via hyper + rustls), tests
//!   pass a stub or a localhost server.
//! - [`start_jwks_refresher`] spawns a named `std::thread` (mirroring
//!   [`crate::control::ControlPlane::start_policy_poller`'s] `Weak` design:
//!   the thread holds a `Weak` to the snapshot and exits once the last
//!   filter is dropped, so SIGHUP reloads retire old threads) with its own
//!   single-threaded tokio runtime -- no ambient runtime is assumed at
//!   filter-build time.
//!
//! # Failure semantics (fail closed, bounded staleness)
//!
//! A failed refresh keeps serving the last-good snapshot and logs at WARN;
//! it never clears the set (an empty fetch that replaced good keys would be
//! a self-inflicted outage). A snapshot older than
//! [`STALE_AFTER_MISSED`] consecutive missed intervals is refused outright
//! ([`crate::auth::AuthError::JwtJwksStale`]) -- the same bounded-staleness
//! rule that applies to credential snapshots: serving
//! indefinitely old keys turns a rotation into silent acceptance.
//!
//! # TLS
//!
//! `https` only, enforced at config parse AND re-checked in [`fetch_bytes`].
//! HTTP JWKS fetch would be an auth bypass (a MITM swaps the key set, then
//! forges tokens with its own key), so there is no plaintext exception, not
//! even for loopback. Trust roots are the system roots unless the provider
//! configures `trusted_ca` (a TLS-intercepting enterprise proxy, or a test
//! CA). Only TLS 1.2 is available: the workspace pins rustls without the
//! `tls13` feature, and Entra negotiates 1.2.

use std::fmt;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::jwt_auth::{JwkRsaKey, JwtKeySet};

/// Default `refresh_interval_seconds` when the provider leaves it `0`.
/// Entra signing keys rotate infrequently and with overlap; ten minutes
/// bounds the worst case without polling on every request's behalf.
pub const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// A snapshot is refused once it is older than this many consecutive missed
/// refresh intervals. Six at the default interval is one hour: long enough
/// to ride out an IdP outage, short enough that a rotation is never trusted
/// a day later.
pub const STALE_AFTER_MISSED: u32 = 6;

/// Per-attempt network timeout covering discovery + JWKS fetches together.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// Largest accepted discovery/JWKS body. A JWKS is kilobytes; a megabyte cap
/// stops a malicious endpoint from ballooning the refresher thread's memory.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The atomically-published value [`crate::jwt_auth::JwtAuthenticator`]
/// reads on every request: the current key set plus when it was last
/// successfully refreshed.
pub struct JwksSnapshot {
    keys: JwtKeySet,
    /// `None` means a static seed that never refreshes and therefore never
    /// goes stale. Discovery-configured snapshots are born `Some(now)` so a
    /// provider whose very first fetch never succeeds still fails closed
    /// after [`STALE_AFTER_MISSED`] intervals instead of serving an empty
    /// set forever.
    refreshed_at: Option<Instant>,
}

impl JwksSnapshot {
    /// A static seed: never stale by construction.
    pub fn seeded(keys: JwtKeySet) -> Self {
        JwksSnapshot {
            keys,
            refreshed_at: None,
        }
    }

    /// A discovery-configured snapshot, born now: populated by the first
    /// refresh, refused as stale if that refresh never lands.
    pub fn discovering(keys: JwtKeySet) -> Self {
        JwksSnapshot {
            keys,
            refreshed_at: Some(Instant::now()),
        }
    }

    /// A refreshed snapshot: replaces the whole key set and resets the age.
    pub fn refreshed(keys: JwtKeySet) -> Self {
        JwksSnapshot {
            keys,
            refreshed_at: Some(Instant::now()),
        }
    }

    pub fn keys(&self) -> &JwtKeySet {
        &self.keys
    }

    /// Age of the snapshot, or `None` for static seeds (never stale).
    pub fn age(&self) -> Option<Duration> {
        self.refreshed_at.map(|t| t.elapsed())
    }

    /// Whether this snapshot is too old to serve given the provider's
    /// refresh interval. Static seeds (`refreshed_at: None`) never are.
    pub fn is_stale(&self, interval: Duration, now: Instant) -> bool {
        match self.refreshed_at {
            None => false,
            Some(t) => now
                .checked_duration_since(t)
                .map(|age| age > interval * STALE_AFTER_MISSED)
                .unwrap_or(false),
        }
    }
}

impl fmt::Debug for JwksSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Same convention as `JwtKeySet`'s own `Debug`: identifiers only.
        f.debug_struct("JwksSnapshot")
            .field("keys", &self.keys)
            .field("refreshed", &self.refreshed_at.is_some())
            .finish()
    }
}

/// Why one refresh attempt failed. Carries no key material -- at most a URL,
/// a `kid`, or a parser message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshError {
    /// Network/TLS/HTTP failure fetching either document.
    Fetch(String),
    /// The discovery document was missing `jwks_uri`, or its `issuer`
    /// disagreed with the configured one.
    Discovery(String),
    /// The JWKS document yielded no usable RSA key.
    Jwks(String),
}

impl fmt::Display for RefreshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RefreshError::Fetch(reason) => write!(f, "fetch failed: {reason}"),
            RefreshError::Discovery(reason) => write!(f, "discovery document: {reason}"),
            RefreshError::Jwks(reason) => write!(f, "JWKS document: {reason}"),
        }
    }
}

/// Extracts `jwks_uri` from an OIDC discovery document.
///
/// When `expected_issuer` is `Some` and the document carries its own
/// `issuer`, the two must agree: following a `jwks_uri` from a document
/// that does not claim to be our issuer would let a mispointed URL (or a
/// compromised discovery endpoint) silently re-anchor trust.
pub fn parse_discovery_doc(
    body: &[u8],
    expected_issuer: Option<&str>,
) -> Result<String, RefreshError> {
    let doc: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| RefreshError::Discovery(format!("not JSON: {e}")))?;
    if let Some(expected) = expected_issuer {
        let Some(present) = doc.get("issuer").and_then(|v| v.as_str()) else {
            return Err(RefreshError::Discovery("missing `issuer`".to_string()));
        };
        if present != expected {
            return Err(RefreshError::Discovery(format!(
                "issuer mismatch: document claims {present:?}, expected {expected:?}"
            )));
        }
    }
    doc.get("jwks_uri")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| RefreshError::Discovery("missing `jwks_uri`".to_string()))
}

/// Builds a [`JwtKeySet`] from a JWKS document's bytes.
///
/// Only `kty == "RSA"` entries with a non-empty `kid` and decodable `n`/`e`
/// are admitted; anything else (EC keys, `kid`-less entries) is skipped and
/// counted. A document yielding zero usable keys is an error -- publishing
/// it would replace good keys with nothing, the self-inflicted outage the
/// module doc forbids.
pub fn parse_jwks_doc(body: &[u8]) -> Result<JwtKeySet, RefreshError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| RefreshError::Jwks(format!("not JSON: {e}")))?;
    let keys = doc
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| RefreshError::Jwks("missing `keys` array".to_string()))?;

    let mut set = JwtKeySet::new();
    let mut skipped = 0u32;
    for entry in keys {
        let is_rsa = entry.get("kty").and_then(|v| v.as_str()) == Some("RSA");
        let kid = entry
            .get("kid")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let (Some(kid), true) = (kid, is_rsa) else {
            skipped += 1;
            continue;
        };
        let n = entry.get("n").and_then(|v| v.as_str()).unwrap_or_default();
        let e = entry.get("e").and_then(|v| v.as_str()).unwrap_or_default();
        let Ok(n) = URL_SAFE_NO_PAD.decode(n) else {
            return Err(RefreshError::Jwks(format!(
                "key {kid:?} has undecodable `n`"
            )));
        };
        let Ok(e) = URL_SAFE_NO_PAD.decode(e) else {
            return Err(RefreshError::Jwks(format!(
                "key {kid:?} has undecodable `e`"
            )));
        };
        if n.is_empty() || e.is_empty() {
            return Err(RefreshError::Jwks(format!(
                "key {kid:?} has empty `n` or `e`"
            )));
        }
        set.insert(JwkRsaKey {
            kid: kid.to_string(),
            n,
            e,
        });
    }
    if set.is_empty() {
        return Err(RefreshError::Jwks(format!(
            "no usable RSA key (skipped {skipped})"
        )));
    }
    Ok(set)
}

/// Parses an optional PEM CA bundle into rustls roots. `None` (no
/// `trusted_ca` configured) means the system roots. An empty or
/// cert-less bundle is an error, not a fallback -- silently downgrading to
/// system roots because of a typo'd CA file would trust CAs the operator
/// explicitly tried to replace.
pub fn tls_roots(ca_pem: Option<&[u8]>) -> Result<rustls::RootCertStore, String> {
    let mut store = rustls::RootCertStore::empty();
    match ca_pem {
        Some(pem) => {
            let certs: Vec<_> = rustls_pemfile::certs(&mut &pem[..])
                .collect::<Result<_, _>>()
                .map_err(|e| format!("trusted_ca is not valid PEM: {e}"))?;
            if certs.is_empty() {
                return Err("trusted_ca contains no certificates".to_string());
            }
            store.add_parsable_certificates(certs);
        }
        None => {
            let native = rustls_native_certs::load_native_certs();
            if native.certs.is_empty() {
                return Err(format!(
                    "no system root certificates loaded: {:?}",
                    native.errors
                ));
            }
            store.add_parsable_certificates(native.certs);
        }
    }
    Ok(store)
}

fn tls_connector(ca_pem: Option<Vec<u8>>) -> Result<tokio_rustls::TlsConnector, RefreshError> {
    let roots = tls_roots(ca_pem.as_deref()).map_err(RefreshError::Fetch)?;
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS12])
    .map_err(|e| RefreshError::Fetch(format!("TLS setup: {e:?}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(std::sync::Arc::new(
        config,
    )))
}

/// GETs one `https` URL and returns its body (capped at 1 MiB, 200 only).
/// The `https` re-check here is defense in depth: config parse already
/// rejects anything else, so reaching this branch means a bug, and a bug
/// must fail closed rather than fetch credentials material over plaintext.
pub async fn fetch_bytes(url: String, ca_pem: Option<Vec<u8>>) -> Result<Vec<u8>, RefreshError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|e| RefreshError::Fetch(format!("unparseable URL {url:?}: {e}")))?;
    if uri.scheme_str() != Some("https") {
        return Err(RefreshError::Fetch(format!(
            "refusing non-https fetch of {url:?}"
        )));
    }
    let host = uri
        .host()
        .ok_or_else(|| RefreshError::Fetch(format!("URL has no host: {url:?}")))?
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());

    let work = async {
        let tcp = tokio::net::TcpStream::connect(format!("{host}:{port}"))
            .await
            .map_err(|e| RefreshError::Fetch(format!("connect {host}:{port}: {e}")))?;
        let server_name = match host.parse::<std::net::IpAddr>() {
            Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
            // A host `http::Uri` accepted but rustls rejects (e.g. an
            // underscore) is a config error, not a panic: a panic here
            // would silently kill the refresher thread and freeze the key
            // set with nothing but a panic log to explain it.
            Err(_) => rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                RefreshError::Fetch(format!("URL host is not a valid DNS name: {host:?}"))
            })?,
        };
        let connector = tls_connector(ca_pem)?;
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| RefreshError::Fetch(format!("TLS to {host}: {e}")))?;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls))
                .await
                .map_err(|e| RefreshError::Fetch(format!("HTTP handshake with {host}: {e}")))?;
        tokio::task::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .uri(path)
            .header(http::header::HOST, &host)
            .header(http::header::USER_AGENT, "llm-proxy")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .map_err(|e| RefreshError::Fetch(format!("request build: {e}")))?;
        let res = sender
            .send_request(req)
            .await
            .map_err(|e| RefreshError::Fetch(format!("GET {url:?}: {e}")))?;
        if res.status() != http::StatusCode::OK {
            return Err(RefreshError::Fetch(format!(
                "GET {url:?}: status {}",
                res.status()
            )));
        }
        let body = http_body_util::BodyExt::collect(res.into_body())
            .await
            .map_err(|e| RefreshError::Fetch(format!("reading {url:?}: {e}")))?
            .to_bytes();
        if body.len() > MAX_BODY_BYTES {
            return Err(RefreshError::Fetch(format!(
                "GET {url:?}: body exceeds 1 MiB cap"
            )));
        }
        Ok(body.to_vec())
    };
    tokio::time::timeout(FETCH_TIMEOUT, work)
        .await
        .map_err(|_| RefreshError::Fetch(format!("GET {url:?}: timed out")))?
}

/// What [`start_jwks_refresher`] needs beyond the snapshot itself. Built
/// once per discovery-configured provider at config load.
pub struct RefreshSpec {
    /// OIDC discovery URL (`https`).
    pub discovery_url: String,
    /// The provider's configured `issuer`, if any (cross-checked against
    /// the discovery document's own `issuer`).
    pub expected_issuer: Option<String>,
    /// Tick interval (`refresh_interval_seconds`, defaulted).
    pub interval: Duration,
    /// PEM bytes of `trusted_ca`, if configured (`None` = system roots).
    pub ca_pem: Option<Vec<u8>>,
    /// Log label (provider index), so N providers' threads are tellable apart.
    pub label: String,
}

/// What a `fetch` closure handed to [`refresh_once`] returns: a boxed,
/// sendable future over the raw bytes or the refresh failure. A `type`
/// alias because the shape recurs in every fetcher and clippy's
/// `type_complexity` would otherwise flag each one.
type FetchFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, RefreshError>> + Send>>;

/// One refresh attempt: discovery -> `jwks_uri` -> key set -> atomic
/// publish. The `fetch` indirection is what lets tests drive this without a
/// network: production passes [`fetch_bytes`], tests pass a stub or a
/// localhost server's fetcher.
pub async fn refresh_once<F>(
    snapshot: &ArcSwap<JwksSnapshot>,
    spec: &RefreshSpec,
    fetch: F,
) -> Result<(), RefreshError>
where
    // Rust note: boxed future rather than `F: Fn(String) -> impl Future`,
    // so the closure may move owned captures (URL, CA bytes) into the
    // fetch without borrowing them past the call.
    F: Fn(String) -> FetchFuture,
{
    let discovery = fetch(spec.discovery_url.clone()).await?;
    let jwks_uri = parse_discovery_doc(&discovery, spec.expected_issuer.as_deref())?;
    let jwks = fetch(jwks_uri).await?;
    let keys = parse_jwks_doc(&jwks)?;
    let count = keys.len();
    snapshot.store(Arc::new(JwksSnapshot::refreshed(keys)));
    tracing::info!(label = %spec.label, keys = count, "JWKS refresh published");
    Ok(())
}

/// Spawns the per-provider background refresher: immediate first attempt,
/// then [`RefreshSpec::interval`] ticks with up to 25% jitter (so N
/// replicas don't thunder the IdP in lockstep -- same reasoning as the
/// policy poller's jitter).
///
/// The thread holds only a [`Weak`] to the snapshot: when the last filter
/// drops it (SIGHUP reload, shutdown), the thread notices on its next
/// wake and exits. No join handle is kept -- these threads are
/// per-serve-lifetime by construction, like the snapshot they publish to.
pub fn start_jwks_refresher(snapshot: Arc<ArcSwap<JwksSnapshot>>, spec: RefreshSpec) {
    std::thread::Builder::new()
        .name(format!("jwks-refresh-{}", spec.label))
        .spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("a current-thread runtime for JWKS refresh");
            let weak: Weak<ArcSwap<JwksSnapshot>> = Arc::downgrade(&snapshot);
            drop(snapshot);
            rt.block_on(async move {
                // Immediate first attempt: a fresh provider should serve
                // within seconds of boot, not after one full interval.
                refresh_if_alive(&weak, &spec).await;
                loop {
                    sleep_checked(spec.interval, &weak).await;
                    if refresh_if_alive(&weak, &spec).await.is_none() {
                        return;
                    }
                }
            });
        })
        .expect("spawning the JWKS refresher thread must not fail");
}

/// One tick that degrades to a no-op (returning `None`) once the snapshot
/// is gone. Failures keep last-good and WARN; only owner-loss stops the loop.
async fn refresh_if_alive(weak: &Weak<ArcSwap<JwksSnapshot>>, spec: &RefreshSpec) -> Option<()> {
    let snapshot = weak.upgrade()?;
    let ca_pem = spec.ca_pem.clone();
    if let Err(e) = refresh_once(&snapshot, spec, |url| {
        Box::pin(fetch_bytes(url, ca_pem.clone())) as FetchFuture
    })
    .await
    {
        tracing::warn!(label = %spec.label, error = %e, "JWKS refresh failed; keeping last-good snapshot");
    }
    Some(())
}

/// Sleeps `interval` plus up to 25% jitter, in 5-second slices so owner
/// loss is noticed promptly rather than after a full (default 10-minute)
/// sleep.
async fn sleep_checked(interval: Duration, weak: &Weak<ArcSwap<JwksSnapshot>>) {
    use rand::Rng as _;

    let jittered = interval + interval.mul_f32(rand::thread_rng().gen_range(0.0..0.25));
    let mut remaining = jittered;
    while remaining > Duration::ZERO {
        if weak.upgrade().is_none() {
            return;
        }
        let slice = remaining.min(Duration::from_secs(5));
        tokio::time::sleep(slice).await;
        remaining = remaining.saturating_sub(slice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Authenticator;

    fn fetch_ok(discovery_body: Vec<u8>, jwks_body: Vec<u8>) -> impl Fn(String) -> FetchFuture {
        move |url| {
            let body = if url.contains("openid-configuration") {
                discovery_body.clone()
            } else {
                jwks_body.clone()
            };
            Box::pin(async move { Ok(body) }) as FetchFuture
        }
    }

    fn test_spec() -> RefreshSpec {
        RefreshSpec {
            discovery_url: "https://issuer.example/.well-known/openid-configuration".to_string(),
            expected_issuer: Some("https://issuer.example".to_string()),
            interval: Duration::from_secs(600),
            ca_pem: None,
            label: "test".to_string(),
        }
    }

    fn jwks_body(n_b64: &str, e_b64: &str) -> Vec<u8> {
        serde_json::json!({
            "keys": [{"kty": "RSA", "kid": "key-1", "n": n_b64, "e": e_b64}]
        })
        .to_string()
        .into_bytes()
    }

    fn discovery_body(jwks_uri: &str) -> Vec<u8> {
        serde_json::json!({
            "issuer": "https://issuer.example",
            "jwks_uri": jwks_uri,
        })
        .to_string()
        .into_bytes()
    }

    // Valid base64url components only -- signature verification is
    // `jwt_auth`'s suite; these tests pin DOCUMENT parsing, not crypto.
    // (`DecodingKey::from_rsa_raw_components` is infallible, so any
    // decodable bytes build a set here.)
    const N_B64: &str = "AQAB";
    const E_B64: &str = "AQAB";

    #[test]
    fn discovery_doc_yields_its_jwks_uri() {
        let uri = parse_discovery_doc(
            &discovery_body("https://issuer.example/jwks"),
            Some("https://issuer.example"),
        )
        .expect("valid document must parse");
        assert_eq!(uri, "https://issuer.example/jwks");
    }

    #[test]
    fn discovery_doc_without_jwks_uri_is_an_error() {
        let err = parse_discovery_doc(b"{}", None).expect_err("no jwks_uri must fail");
        assert_eq!(
            err,
            RefreshError::Discovery("missing `jwks_uri`".to_string())
        );
    }

    #[test]
    fn discovery_doc_with_a_foreign_issuer_is_an_error() {
        let err = parse_discovery_doc(
            &discovery_body("https://issuer.example/jwks"),
            Some("https://someone-else.example"),
        )
        .expect_err("issuer mismatch must fail");
        assert!(
            matches!(err, RefreshError::Discovery(_)),
            "wrong variant: {err:?}"
        );
    }

    #[test]
    fn discovery_doc_without_an_issuer_claim_is_rejected_when_an_issuer_is_configured() {
        let body = serde_json::json!({"jwks_uri": "https://issuer.example/jwks"})
            .to_string()
            .into_bytes();
        let err = parse_discovery_doc(&body, Some("https://issuer.example"))
            .expect_err("a document omitting a configured issuer must fail");
        assert!(matches!(err, RefreshError::Discovery(_)));
    }

    #[test]
    fn jwks_doc_builds_a_key_set_and_skips_non_rsa() {
        let body = serde_json::json!({
            "keys": [
                {"kty": "RSA", "kid": "key-1", "n": N_B64, "e": E_B64},
                {"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": "abc", "y": "def"},
                {"kty": "RSA", "n": N_B64, "e": E_B64},
            ]
        })
        .to_string()
        .into_bytes();
        let set = parse_jwks_doc(&body).expect("one good RSA key must parse");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn jwks_doc_with_no_usable_key_is_an_error_not_an_empty_set() {
        let body = serde_json::json!({"keys": [
            {"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": "abc", "y": "def"},
        ]})
        .to_string()
        .into_bytes();
        let err = parse_jwks_doc(&body).expect_err("zero RSA keys must fail");
        assert!(
            matches!(err, RefreshError::Jwks(_)),
            "wrong variant: {err:?}"
        );
    }

    #[test]
    fn jwks_doc_with_bad_base64_is_an_error() {
        let body = serde_json::json!({"keys": [
            {"kty": "RSA", "kid": "key-1", "n": "!!!", "e": E_B64},
        ]})
        .to_string()
        .into_bytes();
        let err = parse_jwks_doc(&body).expect_err("bad base64 must fail");
        assert!(
            matches!(err, RefreshError::Jwks(_)),
            "wrong variant: {err:?}"
        );
    }

    #[test]
    fn empty_ca_bundle_is_an_error_not_a_fallback() {
        let err = tls_roots(Some(b"")).expect_err("empty bundle must fail");
        assert!(err.contains("no certificates"), "wrong message: {err}");
    }

    #[test]
    fn garbage_ca_bundle_is_an_error() {
        let err = tls_roots(Some(b"this is not pem at all")).expect_err("garbage must fail");
        assert!(!err.is_empty());
    }

    #[tokio::test]
    async fn successful_refresh_publishes_the_new_key_set() {
        let snapshot = Arc::new(ArcSwap::new(Arc::new(JwksSnapshot::discovering(
            JwtKeySet::new(),
        ))));
        let spec = test_spec();
        refresh_once(
            &snapshot,
            &spec,
            fetch_ok(
                discovery_body("https://issuer.example/jwks"),
                jwks_body(N_B64, E_B64),
            ),
        )
        .await
        .expect("refresh must succeed");
        assert_eq!(snapshot.load().keys().len(), 1);
        assert!(snapshot.load().age().is_some());
    }

    #[tokio::test]
    async fn failed_refresh_keeps_last_good_and_issuer_mismatch_fails() {
        // Seed with one good key via a successful refresh first.
        let snapshot = Arc::new(ArcSwap::new(Arc::new(JwksSnapshot::discovering(
            JwtKeySet::new(),
        ))));
        let spec = test_spec();
        refresh_once(
            &snapshot,
            &spec,
            fetch_ok(
                discovery_body("https://issuer.example/jwks"),
                jwks_body(N_B64, E_B64),
            ),
        )
        .await
        .expect("seed refresh must succeed");

        // A foreign-issuer discovery document must NOT replace the set.
        let foreign = serde_json::json!({
            "issuer": "https://someone-else.example",
            "jwks_uri": "https://issuer.example/jwks",
        })
        .to_string()
        .into_bytes();
        let err = refresh_once(&snapshot, &spec, fetch_ok(foreign, jwks_body(N_B64, E_B64)))
            .await
            .expect_err("foreign issuer must fail");
        assert!(matches!(err, RefreshError::Discovery(_)));
        assert_eq!(
            snapshot.load().keys().len(),
            1,
            "a failed refresh must keep last-good keys"
        );
    }

    #[test]
    fn staleness_is_bounded_by_missed_intervals() {
        let snapshot = JwksSnapshot::discovering(JwtKeySet::new());
        let interval = Duration::from_secs(600);
        let now = Instant::now();
        assert!(!snapshot.is_stale(interval, now));
        assert!(snapshot.is_stale(interval, now + interval * (STALE_AFTER_MISSED + 1)));
        // Static seeds never go stale, however old the process is.
        assert!(!JwksSnapshot::seeded(JwtKeySet::new()).is_stale(interval, now + interval * 100));
    }

    // --- end to end: real HTTPS (rcgen localhost cert), real discovery ->
    // JWKS fetch, real JWT authentication against the published snapshot ---
    //
    // The TLS cert is generated at test time: no committed key material.
    // The JWT-signing RSA key is generated once per test process behind a
    // `OnceLock` (see `jwt_auth.rs`'s rationale for why it is not per-test).

    struct E2eRsaKey {
        der: Vec<u8>,
        n_b64: String,
        e_b64: String,
    }

    fn e2e_rsa_key() -> &'static E2eRsaKey {
        use base64::Engine as _;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;

        static KEY: std::sync::OnceLock<E2eRsaKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = rand::thread_rng();
            let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("test RSA keygen");
            let public_key = private_key.to_public_key();
            E2eRsaKey {
                der: private_key
                    .to_pkcs1_der()
                    .expect("PKCS#1 DER")
                    .as_bytes()
                    .to_vec(),
                n_b64: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e_b64: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }
        })
    }

    fn e2e_sign(key: &E2eRsaKey, payload_json: &str) -> String {
        let header_b64 = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"key-1"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json);
        let message = format!("{header_b64}.{payload_b64}");
        let key_pair =
            ring::signature::RsaKeyPair::from_der(&key.der).expect("parse test PKCS#1 DER");
        let mut signature = vec![0u8; key_pair.public().modulus_len()];
        key_pair
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &ring::rand::SystemRandom::new(),
                message.as_bytes(),
                &mut signature,
            )
            .expect("RS256 sign");
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(&signature))
    }

    #[tokio::test]
    async fn discovery_refresh_end_to_end_over_real_tls() {
        use hyper::service::service_fn;

        // `ring` is deliberately NOT a direct dependency of these tests'
        // parent crate surface... it IS (`ring` signs virtual keys too), so
        // signing through it here exercises the real verification path.
        let rsa = e2e_rsa_key();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("localhost cert");
        let cert_pem = certified.cert.pem();
        let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("TLS1.2")
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                certified.cert.der().to_vec(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
                certified.key_pair.serialize_der(),
            )),
        )
        .expect("server cert");
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind localhost");
        let port = listener.local_addr().expect("local addr").port();
        let jwks = serde_json::json!({
            "keys": [{"kty": "RSA", "kid": "key-1", "n": rsa.n_b64, "e": rsa.e_b64}]
        })
        .to_string();
        let discovery = serde_json::json!({
            "issuer": "https://issuer.example",
            "jwks_uri": format!("https://localhost:{port}/jwks"),
        })
        .to_string();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let jwks = jwks.clone();
                let discovery = discovery.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let body = if req.uri().path() == "/jwks" {
                            jwks.clone()
                        } else {
                            discovery.clone()
                        };
                        async move {
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(body)),
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                        .await;
                });
            }
        });

        let snapshot = Arc::new(ArcSwap::new(Arc::new(JwksSnapshot::discovering(
            JwtKeySet::new(),
        ))));
        let spec = RefreshSpec {
            discovery_url: format!("https://localhost:{port}/.well-known/openid-configuration"),
            expected_issuer: Some("https://issuer.example".to_string()),
            interval: Duration::from_secs(600),
            ca_pem: Some(cert_pem.into_bytes()),
            label: "e2e".to_string(),
        };
        // Before any refresh: empty seed, so the kid is unknown (fail
        // closed), not admitted.
        assert!(snapshot.load().keys().is_empty());
        let ca = spec.ca_pem.clone();
        refresh_once(&snapshot, &spec, move |url| {
            Box::pin(fetch_bytes(url, ca.clone())) as FetchFuture
        })
        .await
        .expect("refresh over real TLS must succeed");
        assert_eq!(snapshot.load().keys().len(), 1);

        // And a token signed by the served key now authenticates.
        let auth = crate::jwt_auth::JwtAuthenticator::new_shared(
            Arc::clone(&snapshot),
            crate::jwt_auth::JwtValidationConfig {
                tenant_claim: "tenant".to_string(),
                issuer: Some("https://issuer.example".to_string()),
                audience: None,
                leeway_seconds: None,
                tenant_map: std::collections::HashMap::new(),
                subject_claim: None,
            },
            Some(Duration::from_secs(3600)),
        );
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let token = e2e_sign(
            rsa,
            &format!(r#"{{"tenant":"tenant-a","iss":"https://issuer.example","exp":{exp}}}"#),
        );
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            http::HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        match auth.authenticate(&headers) {
            crate::auth::AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-a");
                assert_eq!(principal.key_id.as_str(), "key-1");
            }
            other => panic!(
                "expected Authenticated after a real refresh; Rejected={}",
                matches!(other, crate::auth::AuthOutcome::Rejected(_))
            ),
        }
    }
}
