//! Minted provider credentials: an OAuth2 access token that a provider cluster
//! mints with the JWT-bearer grant (RFC 7523) and refreshes off the request
//! path (ADR-0005, amendment 2026-10-17). Workers read the published token and
//! never fetch, mint or wait for one.
//!
//! The token endpoint is dialled through a named cluster, the Envoy
//! `HttpUri { uri, cluster }` shape, so a mint gets the proxy's own host
//! selection, connect timeout, circuit breaker and upstream TLS.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use proxy_config::ir::OAuth2JwtBearer;
use ring::rand::SystemRandom;
use ring::signature::{RsaKeyPair, RSA_PKCS1_SHA256};

use crate::{ClusterEntry, ClusterName, LoadBalancerContext, UpstreamProtocol};

/// At most one warning per window for a repeated failure; the rest are counted.
const WARN_WINDOW: Duration = Duration::from_secs(60);
/// Largest token response read. A token response is a few hundred bytes.
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// First retry delay after a failed mint; it doubles per consecutive failure.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// Longest wait between failed mints, before jitter.
const BACKOFF_CAP: Duration = Duration::from_secs(60);
/// Shortest wait before a scheduled refresh, so a token that lives shorter
/// than the refresh margin cannot spin the refresher.
const MIN_REFRESH_WAIT: Duration = Duration::from_secs(1);

/// One published access token. The header value is marked sensitive, and no
/// `Debug` impl prints it.
struct MintedToken {
    bearer: http::HeaderValue,
    expires_at: Instant,
}

/// The cluster-owned state behind an `OAuth2JwtBearer` credential: the parsed
/// signing key, the last published token and log suppression.
pub struct MintedCredential {
    cluster: ClusterName,
    config: OAuth2JwtBearer,
    key: RsaKeyPair,
    current: ArcSwapOption<MintedToken>,
    /// Consecutive failed mints. Only the refresher (one task) takes the lock.
    failures: Mutex<u32>,
    mint_warnings: WarnLimiter,
}

/// Why one mint failed. Carries no key, assertion or token.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("token cluster `{0}` is not configured")]
    NoTokenCluster(ClusterName),
    #[error("token cluster has no host to dial")]
    NoHost,
    #[error("connecting to the token endpoint failed: {0}")]
    Connect(String),
    #[error("token request failed: {0}")]
    Http(String),
    #[error("token endpoint answered {status}{}", .error.as_deref().map(|e| format!(" ({e})")).unwrap_or_default())]
    Status { status: u16, error: Option<String> },
    #[error("token response is unusable: {0}")]
    BadResponse(&'static str),
    #[error("token request timed out after {0:?}")]
    Timeout(Duration),
    #[error("signing the assertion failed")]
    Signing,
}

impl std::fmt::Debug for MintedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedCredential")
            .field("cluster", &self.cluster)
            .field("token_url", &self.config.token_url)
            .field("has_token", &self.current.load().is_some())
            .finish_non_exhaustive()
    }
}

impl MintedCredential {
    pub(crate) fn new(cluster: &str, config: &OAuth2JwtBearer) -> Self {
        // `RsaSigningKey` is only built by `from_pkcs8_pem`, which already ran
        // this exact `ring` check on these bytes.
        let key = RsaKeyPair::from_pkcs8(config.private_key.pkcs8_der())
            .expect("RsaSigningKey holds a key ring accepted at load");
        Self {
            cluster: cluster.to_string(),
            config: config.clone(),
            key,
            current: ArcSwapOption::empty(),
            failures: Mutex::new(0),
            mint_warnings: WarnLimiter::new(),
        }
    }

    /// The cluster the token endpoint is dialled through.
    pub(crate) fn token_cluster(&self) -> &str {
        &self.config.token_cluster
    }

    /// The `authorization` value for a request sent at `now`, or `None` when no
    /// token has been minted or the last one has expired. Lock-free; never
    /// blocks and never fetches.
    pub fn bearer(&self, now: Instant) -> Option<http::HeaderValue> {
        let token = self.current.load();
        let token = token.as_ref()?;
        (now < token.expires_at).then(|| token.bearer.clone())
    }
}

impl MintedCredential {
    /// Mints one token through `token_cluster` (`None`: not configured),
    /// publishes it, and returns how long to wait before the next mint. A
    /// failure keeps the last token, which serves until it expires.
    pub(crate) async fn mint_and_publish(
        &self,
        token_cluster: Option<&dyn ClusterEntry>,
    ) -> Duration {
        let result = match token_cluster {
            Some(token_cluster) => {
                let timeout = self.config.request_timeout;
                tokio::time::timeout(timeout, self.mint(token_cluster))
                    .await
                    .unwrap_or(Err(MintError::Timeout(timeout)))
            }
            None => Err(MintError::NoTokenCluster(self.config.token_cluster.clone())),
        };
        self.publish(result)
    }

    /// Signs one RFC 7523 assertion issued at `now`.
    fn assertion(&self, now: SystemTime) -> Result<String, MintError> {
        let iat = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MintError::Signing)?
            .as_secs();
        let mut header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
        if let Some(kid) = &self.config.key_id {
            header["kid"] = kid.as_str().into();
        }
        let mut claims = serde_json::json!({
            "iss": self.config.issuer,
            "aud": self.config.audience,
            "scope": self.config.scopes.join(" "),
            "iat": iat,
            "exp": iat + self.config.assertion_lifetime.as_secs(),
        });
        if let Some(sub) = &self.config.subject {
            claims["sub"] = sub.as_str().into();
        }
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string())
        );
        let mut signature = vec![0; self.key.public().modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .map_err(|_| MintError::Signing)?;
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    async fn mint(&self, token_cluster: &dyn ClusterEntry) -> Result<MintedToken, MintError> {
        let started = Instant::now();
        let assertion = self.assertion(SystemTime::now())?;
        let selection = token_cluster
            .select_host(&LoadBalancerContext::default())
            .ok_or(MintError::NoHost)?;
        // An aggregate token cluster dials the member that owns the host.
        let owner: &dyn ClusterEntry = match &selection.member {
            Some(member) => member.entry.as_ref(),
            None => token_cluster,
        };
        let stream = owner
            .http_pool(&selection.host, UpstreamProtocol::Http1)
            .new_stream()
            .await
            .map_err(|e| MintError::Connect(e.to_string()))?;
        // Rust note: the guard holds the token cluster's connection slot; it
        // must live until the response is read, so it is bound, not dropped.
        let _connection_slot = stream.cb_guard;
        let (mut sender, conn) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream.io))
                .await
                .map_err(|e| MintError::Http(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let uri: http::Uri = self
            .config
            .token_url
            .parse()
            .map_err(|_| MintError::Http("token URL does not parse".to_string()))?;
        let authority = uri
            .authority()
            .ok_or_else(|| MintError::Http("token URL has no host".to_string()))?
            .to_string();
        let target = uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), |pq| pq.as_str().to_string());
        // The assertion is base64url and dots, so it needs no form escaping.
        let body = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );
        let request = http::Request::post(target)
            .header(http::header::HOST, authority)
            .header(
                http::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .header(http::header::ACCEPT, "application/json")
            .header(http::header::USER_AGENT, "llm-proxy")
            .body(Full::new(Bytes::from(body)))
            .map_err(|e| MintError::Http(e.to_string()))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| MintError::Http(e.to_string()))?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|_| MintError::BadResponse("body unreadable or over 64 KiB"))?
            .to_bytes();
        if status != 200 {
            return Err(MintError::Status {
                status,
                error: error_code(&body),
            });
        }
        parse_token_response(&body, started)
    }

    fn publish(&self, result: Result<MintedToken, MintError>) -> Duration {
        let mut failures = self.failures.lock().unwrap_or_else(|e| e.into_inner());
        match result {
            Ok(token) => {
                if *failures > 0 {
                    tracing::info!(
                        cluster = %self.cluster,
                        failed_attempts = *failures,
                        "OAuth2 token mint recovered"
                    );
                }
                *failures = 0;
                let wait = token
                    .expires_at
                    .saturating_duration_since(Instant::now())
                    .saturating_sub(self.config.refresh_before)
                    .max(MIN_REFRESH_WAIT);
                self.current.store(Some(Arc::new(token)));
                wait
            }
            Err(error) => {
                *failures = failures.saturating_add(1);
                // Logs fail open by design: the request path is closed, the
                // log says so loudly once a minute (AGENTS.md "Fail-open controls").
                if let Some(suppressed) = self.mint_warnings.check() {
                    let token_valid_for = self
                        .current
                        .load()
                        .as_ref()
                        .map(|t| t.expires_at.saturating_duration_since(Instant::now()));
                    tracing::warn!(
                        cluster = %self.cluster,
                        token_url = %self.config.token_url,
                        failed_attempts = *failures,
                        suppressed,
                        ?token_valid_for,
                        error = %error,
                        "OAuth2 token mint failed; requests to this provider are refused once the current token expires"
                    );
                }
                backoff(*failures)
            }
        }
    }
}

/// The endpoint's `error` code from an RFC 6749 error body, when it is a short
/// identifier. Nothing else from the body is kept.
fn error_code(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let code = value.get("error")?.as_str()?;
    (code.len() <= 64
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
    .then(|| code.to_string())
}

fn parse_token_response(body: &[u8], started: Instant) -> Result<MintedToken, MintError> {
    let value: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| MintError::BadResponse("not JSON"))?;
    let token = value
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|t| !t.is_empty())
        .ok_or(MintError::BadResponse("no access_token"))?;
    if let Some(kind) = value.get("token_type") {
        if !kind
            .as_str()
            .is_some_and(|k| k.eq_ignore_ascii_case("bearer"))
        {
            return Err(MintError::BadResponse("token_type is not bearer"));
        }
    }
    let expires_in = value
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .filter(|seconds| *seconds > 0)
        .ok_or(MintError::BadResponse("no positive integer expires_in"))?;
    let mut bearer = http::HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|_| MintError::BadResponse("access_token is not a valid header value"))?;
    bearer.set_sensitive(true);
    Ok(MintedToken {
        bearer,
        // Counted from when the request started, so network time shortens the
        // token's use rather than stretching it past the real expiry.
        expires_at: started + Duration::from_secs(expires_in),
    })
}

/// Jittered exponential backoff: 1 s doubling to 60 s, plus up to 25%.
fn backoff(failures: u32) -> Duration {
    use rand::Rng as _;
    let exponent = failures.saturating_sub(1).min(6);
    let base = (BACKOFF_BASE * 2u32.pow(exponent)).min(BACKOFF_CAP);
    base + base.mul_f64(rand::thread_rng().gen_range(0.0..0.25))
}

/// Allows one warning per [`WARN_WINDOW`] and counts the rest. Touched only on
/// failure paths, so it costs a healthy request nothing.
struct WarnLimiter {
    origin: Instant,
    /// Milliseconds after `origin` of the last warning, or `u64::MAX` before
    /// the first.
    last_ms: AtomicU64,
    suppressed: AtomicU64,
}

impl WarnLimiter {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_ms: AtomicU64::new(u64::MAX),
            suppressed: AtomicU64::new(0),
        }
    }

    fn check(&self) -> Option<u64> {
        let now = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX - 1);
        let last = self.last_ms.load(Ordering::Relaxed);
        let due = last == u64::MAX || now.saturating_sub(last) >= WARN_WINDOW.as_millis() as u64;
        // Rust note: `compare_exchange` lets exactly one of several workers that
        // see the window open at once win the warning; the others count.
        if due
            && self
                .last_ms
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            return Some(self.suppressed.swap(0, Ordering::Relaxed));
        }
        self.suppressed.fetch_add(1, Ordering::Relaxed);
        None
    }
}
