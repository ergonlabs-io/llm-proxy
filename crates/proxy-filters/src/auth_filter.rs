//! Wires the [`crate::auth`] core into a real
//! `HttpFilter`.
//!
//! **Library only** in `auth.rs`; this module is the seam that actually sits
//! in the decode path. The core's design rationale lives in its module doc.
//!
//! # Config: a vendored proto, not a borrowed Envoy message
//!
//! `llmproxy.filters.v0.Authentication` (`proxy-api/vendor/llmproxy/filters/v0/auth.proto`)
//! is the first LLM-layer proto vendored for its own sake — see that file's
//! header comment for why the earlier "borrow an unrelated Envoy message
//! whose field names happen to fit" convention (`usage_filter`,
//! `body_rewrite_filter`, `token_limit_filter`) does not extend to
//! authentication: the config here carries an operator secret and a set of
//! credential digests, and neither belongs in a field nothing validates.
//!
//! # Only `decode_headers` does anything
//!
//! Authentication is entirely a request-time decision; there is no encode-side
//! bookkeeping (contrast [`crate::token_limit_filter`], which checks on
//! decode and records on encode). Every other [`proxy_http::filter::HttpFilter`]
//! callback takes the trait default.
//!
//! # The wire response is identical for every failure reason; the access log
//! is not
//!
//! **On the wire**, "no credential presented", "credential unknown", and
//! "credential revoked" produce the exact same 401: status, body
//! (`"unauthorized"`), and a `www-authenticate: Bearer` header (RFC 7235
//! requires a challenge on a 401; leaving it off is a protocol bug, not a
//! nicety). A caller must not be able to learn from the response alone
//! whether a key they guessed was ever valid.
//!
//! **In the access log**, the three cases DO differ: `send_local_reply`'s
//! `details` argument reaches `%RESPONSE_CODE_DETAILS%` (never the client) as
//! `auth_no_credential`, `auth_unknown_key`, or `auth_revoked_key`. That
//! asymmetry is deliberate — the operator needs to tell a compromised
//! credential still being tried apart from a caller who simply typed the
//! wrong thing, and only the operator-facing side of the response is allowed
//! to say so.
//!
//! # The verified credential is removed before forwarding
//!
//! On success the filter removes every `authorization` header from the
//! request. Both authenticators in the chain read that header, and the value
//! is a proxy-local credential (a virtual key, or a JWT issued for this
//! proxy) that no provider can use. Leaving it in place relied on the
//! cluster's `request_headers_to_add` (AGENTS.md invariant 6) to overwrite it, which
//! only happens for providers that carry their own key in `authorization`:
//! an `anthropic` cluster sends `x-api-key`, and a keyless
//! `openai-compatible` cluster (Ollama, vLLM) sends nothing, so both received
//! the tenant's key. This is Envoy's `jwt_authn` default (`forward: false`);
//! there is no knob to forward the credential, because no upstream can
//! verify it. Cluster headers are applied after this filter, so a provider
//! credential in `authorization` is unaffected. Requests this filter rejects
//! never reach the router, so there is nothing to remove on those paths.

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::Duration;

use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, StatusCode};
use prost_reflect::DynamicMessage;

use proxy_config::ConfigError;
use proxy_http::filter::{
    DecoderCallbacks, FactoryContext, FilterHeadersStatus, FilterInstanceFactory, HttpFilter,
    HttpFilterFactory, RequestHeaders,
};
use proxy_http::stream_info::AuthInfo;

use crate::auth::{
    AuthError, AuthOutcome, Authenticator, AuthenticatorChain, HmacSecret, KeyId, KeyRecord,
    KeySet, TenantId, VirtualKeyAuthenticator,
};
use crate::control::{
    ControlPlane, ControlPlaneStore, InMemoryControlPlaneStore, RedbControlPlaneStore,
};
use crate::control_redis::RedisControlPlaneStore;
use crate::jwks_refresh::{
    JwksSnapshot, RefreshSpec, DEFAULT_REFRESH_INTERVAL, STALE_AFTER_MISSED,
};
use crate::jwt_auth::{JwkRsaKey, JwtAuthenticator, JwtKeySet, JwtValidationConfig};

/// Type URL this filter is registered under.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Authentication";

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
    }
}

/// Reads an `envoy.config.core.v3.DataSource` message's bytes -- shared by
/// [`parse_hmac_secret`]'s `hmac_secret` and [`parse_store`]'s
/// `shared.url`. `field_path` is the CALLER's own dotted path (e.g.
/// `typed_config.hmac_secret`, `typed_config.store.shared.url`) so every
/// error below still names exactly where the offending value came from --
/// this function itself never sees the full path to the `DataSource`
/// message, only the field one level up.
///
/// Only `filename` and `inline_string` specifiers are supported -- not
/// because either call site could not read the others, but because
/// `DataSource`'s supported surface is declared once for the whole project
/// (`proxy-config`'s `allowed_fields`), and `environment_variable` /
/// `inline_bytes` are not implemented at the other sites `DataSource`
/// already appears (TLS certificates, `direct_response` bodies). Widening
/// it here would silently claim support at those sites too.
fn read_data_source_bytes(
    data_source: &DynamicMessage,
    field_path: &str,
) -> Result<Vec<u8>, ConfigError> {
    if data_source.has_field_by_name("filename") {
        let filename = data_source
            .get_field_by_name("filename")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        // The io::Error's Display never includes file contents -- only the
        // path and a kernel-level reason (e.g. "No such file or
        // directory") -- so it is safe to fold straight into the reason
        // string. Never read the file again for logging purposes.
        let raw = fs::read(&filename)
            .map_err(|e| invalid(format!("{field_path}.filename"), format!("{e}")))?;
        // Trailing whitespace is stripped -- see `auth::secret_bytes_from_file`
        // for why this is load-bearing rather than tidy (`echo secret > file`
        // adds a newline that would otherwise silently become part of the
        // value). `--mode keygen` reads `hmac_secret`'s file through the
        // same function, so the generator and this verifier cannot disagree;
        // a `shared.url` file gets the identical treatment for the identical
        // reason (`echo redis://... > file` appends a newline too).
        Ok(crate::auth::secret_bytes_from_file(&raw).to_vec())
    } else if data_source.has_field_by_name("inline_string") {
        Ok(data_source
            .get_field_by_name("inline_string")
            .and_then(|v| v.as_str().map(|s| s.as_bytes().to_vec()))
            .unwrap_or_default())
    } else {
        Err(invalid(
            field_path,
            "only `filename` and `inline_string` data source specifiers are supported",
        ))
    }
}

/// Reads `typed_config.hmac_secret` (an `envoy.config.core.v3.DataSource`)
/// and returns the raw secret bytes. See the proto's own doc for why only
/// `filename` and `inline_string` are supported here.
fn parse_hmac_secret(config: &DynamicMessage) -> Result<Vec<u8>, ConfigError> {
    if !config.has_field_by_name("hmac_secret") {
        return Err(invalid(
            "typed_config.hmac_secret",
            "the `hmac_secret` field is required",
        ));
    }
    let data_source = config
        .get_field_by_name("hmac_secret")
        .and_then(|v| v.as_message().cloned())
        .ok_or_else(|| invalid("typed_config.hmac_secret", "must be a DataSource message"))?;

    let bytes = read_data_source_bytes(&data_source, "typed_config.hmac_secret")?;

    if bytes.is_empty() {
        // `ring::hmac::Key::new` happily accepts a zero-length key, which
        // would make every digest effectively unkeyed -- reject explicitly
        // rather than silently degrading to a plain (unkeyed) SHA-256.
        return Err(invalid(
            "typed_config.hmac_secret",
            "must not be empty (an empty secret would make every credential digest \
             effectively unkeyed)",
        ));
    }

    Ok(bytes)
}

/// Validates and decodes `typed_config.virtual_keys[i].digest_hex`. Every
/// error names what was wrong (length, case, alphabet) WITHOUT echoing the
/// value itself back in the reason -- the digest is credential-adjacent
/// material, not something to fold into an error string.
fn parse_digest_hex(raw: &str, index: usize) -> Result<Vec<u8>, ConfigError> {
    let field_path = format!("typed_config.virtual_keys[{index}].digest_hex");
    if raw.is_empty() {
        return Err(invalid(&field_path, "digest_hex is required"));
    }
    if raw.len() != 64 {
        return Err(invalid(
            &field_path,
            format!("must be exactly 64 hex characters, got {}", raw.len()),
        ));
    }
    if raw.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(invalid(&field_path, "must be lowercase hex"));
    }
    if !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(invalid(
            &field_path,
            "must contain only hex characters (0-9, a-f)",
        ));
    }

    // Every remaining character is a lowercase hex digit and the length is
    // even (64), so this can never fail -- `?` here is defensive, not
    // reachable.
    let mut bytes = Vec::with_capacity(32);
    for pair in raw.as_bytes().as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16).unwrap();
        let lo = (pair[1] as char).to_digit(16).unwrap();
        bytes.push(((hi << 4) | lo) as u8);
    }
    Ok(bytes)
}

/// Which [`crate::control::ControlPlaneStore`] backs this filter's
/// [`ControlPlane`] -- the parsed shape of `typed_config.store`, before it is
/// turned into an actual store instance. Kept separate from the store types
/// themselves so `parse_config` (config parsing) does not have to also decide
/// WHEN to build one -- see [`AuthFilterFactory::create`], which builds the
/// real store only inside the shared-singleton closure, so a persistent
/// store's file is opened exactly once per serve.
enum StoreSpec {
    InMemory,
    Persistent(String),
    /// The Redis-backed shared store. `url` may embed a
    /// Redis password (`redis://:password@host:6379/0`) -- see the hand-
    /// written [`std::fmt::Debug`] impl below for why this variant does
    /// NOT derive it.
    Shared {
        url: String,
        namespace: Option<String>,
    },
}

// Rust note: `StoreSpec` does NOT derive `Debug` -- a derived one would print
// `Shared`'s `url` verbatim, and that url may carry a Redis password. This
// hand-written impl prints every other variant exactly as the derive would,
// but replaces `Shared`'s url with a fixed placeholder and prints only its
// namespace. `AuthConfig` (below) holds a `StoreSpec` and itself derives
// `Debug`; a derive only ever calls through to each field's own `Debug`
// impl, so the redaction here is what keeps that derive safe too. If this
// impl is ever "tidied" back into a derive, the password comes back with it.
impl std::fmt::Debug for StoreSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreSpec::InMemory => write!(f, "InMemory"),
            StoreSpec::Persistent(path) => f.debug_tuple("Persistent").field(path).finish(),
            StoreSpec::Shared { namespace, .. } => f
                .debug_struct("Shared")
                .field("url", &"<redacted>")
                .field("namespace", namespace)
                .finish(),
        }
    }
}

/// Reads `typed_config.store` (the `oneof` on `llmproxy.filters.v0.Authentication`).
/// Unset and `in_memory` are indistinguishable here on purpose -- both mean
/// [`StoreSpec::InMemory`] -- see the proto's doc for why unset defaults to
/// in-memory rather than erroring.
fn parse_store(config: &DynamicMessage) -> Result<StoreSpec, ConfigError> {
    if config.has_field_by_name("persistent") {
        let persistent = config
            .get_field_by_name("persistent")
            .and_then(|v| v.as_message().cloned())
            .ok_or_else(|| invalid("typed_config.store.persistent", "must be a message"))?;
        let path = persistent
            .get_field_by_name("path")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if path.is_empty() {
            return Err(invalid(
                "typed_config.store.persistent.path",
                "is required and must not be empty",
            ));
        }
        Ok(StoreSpec::Persistent(path))
    } else if config.has_field_by_name("shared") {
        let shared = config
            .get_field_by_name("shared")
            .and_then(|v| v.as_message().cloned())
            .ok_or_else(|| invalid("typed_config.store.shared", "must be a message"))?;
        if !shared.has_field_by_name("url") {
            return Err(invalid(
                "typed_config.store.shared.url",
                "is required and must not be empty",
            ));
        }
        let data_source = shared
            .get_field_by_name("url")
            .and_then(|v| v.as_message().cloned())
            .ok_or_else(|| {
                invalid(
                    "typed_config.store.shared.url",
                    "must be a DataSource message",
                )
            })?;
        let bytes = read_data_source_bytes(&data_source, "typed_config.store.shared.url")?;
        // A non-UTF-8 file (or inline_string, though prost-reflect cannot
        // produce non-UTF-8 bytes from a proto `string` field) is a named
        // error, not a lossy conversion -- `String::from_utf8_lossy` would
        // silently mangle a malformed URL into one that then fails to parse
        // somewhere else, with nothing here to explain why.
        let url = String::from_utf8(bytes)
            .map_err(|_| invalid("typed_config.store.shared.url", "must be valid UTF-8"))?;
        if url.is_empty() {
            return Err(invalid(
                "typed_config.store.shared.url",
                "is required and must not be empty",
            ));
        }
        let namespace = shared
            .get_field_by_name("namespace")
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty());
        Ok(StoreSpec::Shared { url, namespace })
    } else {
        // Covers both `in_memory` explicitly set and the oneof left unset --
        // the proto's doc makes unset's default explicit.
        Ok(StoreSpec::InMemory)
    }
}

/// Reads `typed_config.poll_interval_seconds` -- `0` (proto3's implicit
/// default for an unset `uint32`) means "use the built-in 48-second default",
/// per the proto's own doc. Modeled exactly on `spend_limit_filter`'s
/// `parse_flush_interval`, with one difference worth stating: THIS knob is a
/// correctness bound, not just a durability one (see the proto doc) -- 48
/// seconds, jittered by up to a quarter, is where the owner's "a revoked key
/// stops working within 60 seconds" bound comes from
/// (`48 * 1.25 == 60`).
fn parse_poll_interval(config: &DynamicMessage) -> Duration {
    let secs = config
        .get_field_by_name("poll_interval_seconds")
        .and_then(|v| v.as_u32())
        .unwrap_or(0);
    if secs == 0 {
        Duration::from_secs(48)
    } else {
        Duration::from_secs(u64::from(secs))
    }
}

/// [`parse_config`]'s return value -- a named struct rather than a growing
/// tuple, purely to keep clippy's `type_complexity` quiet now that there are
/// several fields; see each field's doc (mirroring [`parse_config`]'s own) for
/// why every one of these crosses this boundary in this particular shape.
#[derive(Debug)]
struct AuthConfig {
    /// Raw secret **bytes**, not an [`HmacSecret`] -- [`AuthFilterFactory::create`] needs TWO independent
    /// `HmacSecret`s from the same bytes (one for the request-time
    /// authenticator, one retained by [`crate::control::ControlPlane`] for a
    /// future key-mint endpoint), and `HmacSecret` deliberately has no
    /// accessor back to its bytes once constructed (see its doc) -- so the
    /// bytes have to be the thing that crosses this boundary, and each
    /// caller constructs its own `HmacSecret`.
    secret_bytes: Vec<u8>,
    bootstrap_keys: KeySet,
    store_spec: StoreSpec,
    /// How often the policy poller re-checks the store's generation
    /// stamp -- see [`parse_poll_interval`].
    poll_interval: Duration,
    /// One entry per `typed_config.jwt_providers[i]`,
    /// in config order. Each becomes one `JwtAuthenticator` appended to the
    /// chain after the virtual-key authenticator.
    jwt_providers: Vec<JwtProviderConfig>,
}

/// One parsed `typed_config.jwt_providers[i]` -- the pieces
/// [`JwtAuthenticator::new_shared`] takes, kept split here so `parse_config`
/// (config parsing) stays separate from the constructor that consumes them.
struct JwtProviderConfig {
    keys: JwtKeySet,
    validation: JwtValidationConfig,
    /// `Some` when `discovery_url` is set: the background refresh spec.
    /// `max_stale` for the authenticator is `interval * STALE_AFTER_MISSED`;
    /// static providers (`None`) never go stale.
    discovery: Option<DiscoveryConfig>,
}

/// The parsed shape of one provider's `discovery_url` /
/// `refresh_interval_seconds` / `trusted_ca`.
struct DiscoveryConfig {
    url: String,
    interval: Duration,
    /// Raw PEM bytes of `trusted_ca` (`None` = system roots). Validated as
    /// parseable PEM-with-certs at load; the refresher parses them again
    /// into roots on its own thread.
    ca_pem: Option<Vec<u8>>,
}

// Rust note: hand-written because `JwtValidationConfig`/`JwtKeySet` do not
// derive `Debug` (key-adjacent types in this crate spell it out explicitly).
// Prints identifiers only; `JwtKeySet`'s own `Debug` already prints kids.
impl std::fmt::Debug for JwtProviderConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtProviderConfig")
            .field("keys", &self.keys)
            .field("tenant_claim", &self.validation.tenant_claim)
            .field("issuer", &self.validation.issuer)
            .field("audience", &self.validation.audience)
            .finish()
    }
}

/// Decodes one base64url-no-pad component (`n` or `e`) of a
/// `typed_config.jwt_providers[i].keys[j]` entry. Every error names its
/// dotted path without echoing the value (key-adjacent material, same rule
/// as [`parse_digest_hex`]).
fn parse_jwk_component(raw: &str, field_path: &str) -> Result<Vec<u8>, ConfigError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;

    if raw.is_empty() {
        return Err(invalid(field_path, "is required and must not be empty"));
    }
    URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| invalid(field_path, "must be valid base64url without padding"))
        .and_then(|bytes| {
            if bytes.is_empty() {
                Err(invalid(field_path, "must not decode to empty"))
            } else {
                Ok(bytes)
            }
        })
}

/// Reads `typed_config.jwt_providers` into per-provider configs. Absent and
/// empty are both legal and mean "no JWT accepted". Strict mode: every field
/// either maps in or errors with its dotted path (AGENTS.md invariant 1).
fn parse_jwt_providers(config: &DynamicMessage) -> Result<Vec<JwtProviderConfig>, ConfigError> {
    let providers: Vec<prost_reflect::Value> = config
        .get_field_by_name("jwt_providers")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();

    let mut out = Vec::with_capacity(providers.len());
    for (i, entry) in providers.iter().enumerate() {
        let base = format!("typed_config.jwt_providers[{i}]");
        let msg = entry
            .as_message()
            .ok_or_else(|| invalid(&base, "must be a message"))?;

        let tenant_claim = msg
            .get_field_by_name("tenant_claim")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if tenant_claim.is_empty() {
            return Err(invalid(format!("{base}.tenant_claim"), "must not be empty"));
        }

        // Optional: empty/unset means "no check". A present-but-empty string
        // is the same as unset (proto3 cannot distinguish them); only a
        // non-empty value enables the check.
        let issuer = msg
            .get_field_by_name("issuer")
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty());
        let audience = msg
            .get_field_by_name("audience")
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty());
        let subject_claim = msg
            .get_field_by_name("subject_claim")
            .and_then(|v| v.as_str().map(str::to_string))
            .filter(|s| !s.is_empty());

        let keys: Vec<prost_reflect::Value> = msg
            .get_field_by_name("keys")
            .and_then(|v| v.as_list().map(<[_]>::to_vec))
            .unwrap_or_default();
        // Empty is legal only with discovery (the first refresh populates
        // the set); without it, a provider with no keys verifies nothing.
        let discovery = parse_discovery(msg, &base)?;
        if keys.is_empty() && discovery.is_none() {
            return Err(invalid(
                format!("{base}.keys"),
                "must contain at least one key without `discovery_url` \
                 (a provider with no keys verifies nothing)",
            ));
        }

        let mut key_set = JwtKeySet::new();
        let mut seen_kids: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for (j, key_entry) in keys.iter().enumerate() {
            let key_base = format!("{base}.keys[{j}]");
            let key_msg = key_entry
                .as_message()
                .ok_or_else(|| invalid(&key_base, "must be a message"))?;

            let kid = key_msg
                .get_field_by_name("kid")
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            if kid.is_empty() {
                return Err(invalid(format!("{key_base}.kid"), "must not be empty"));
            }
            if let Some(&first) = seen_kids.get(&kid) {
                return Err(invalid(
                    format!("{key_base}.kid"),
                    format!("duplicate `kid`; already used at index {first}"),
                ));
            }
            seen_kids.insert(kid.clone(), j);

            let n_raw = key_msg
                .get_field_by_name("n")
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            let e_raw = key_msg
                .get_field_by_name("e")
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            let n = parse_jwk_component(&n_raw, &format!("{key_base}.n"))?;
            let e = parse_jwk_component(&e_raw, &format!("{key_base}.e"))?;
            key_set.insert(JwkRsaKey { kid, n, e });
        }

        out.push(JwtProviderConfig {
            keys: key_set,
            validation: JwtValidationConfig {
                tenant_claim,
                issuer,
                audience,
                leeway_seconds: None,
                tenant_map: parse_tenant_values(msg, &base)?,
                subject_claim,
            },
            discovery,
        });
    }
    Ok(out)
}

/// Reads one provider's `discovery_url` / `refresh_interval_seconds` /
/// `trusted_ca`. Returns `None` when `discovery_url` is unset (static
/// provider). Strict mode: `http` is rejected (JWKS over plaintext is an
/// auth bypass -- see `jwks_refresh`'s module doc), and `trusted_ca` must
/// parse as a PEM bundle with at least one certificate NOW, not on the
/// first refresh tick months later.
fn parse_discovery(
    msg: &DynamicMessage,
    base: &str,
) -> Result<Option<DiscoveryConfig>, ConfigError> {
    let url = msg
        .get_field_by_name("discovery_url")
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default();
    if url.is_empty() {
        return Ok(None);
    }
    let uri: http::Uri = url.parse().map_err(|_| {
        invalid(
            format!("{base}.discovery_url"),
            "must be a valid absolute URL",
        )
    })?;
    if uri.scheme_str() != Some("https") || uri.host().is_none() {
        return Err(invalid(
            format!("{base}.discovery_url"),
            "must be an `https` URL with a host",
        ));
    }
    let interval_secs = msg
        .get_field_by_name("refresh_interval_seconds")
        .and_then(|v| v.as_u32())
        .unwrap_or(0);
    let interval = if interval_secs == 0 {
        DEFAULT_REFRESH_INTERVAL
    } else {
        Duration::from_secs(u64::from(interval_secs))
    };
    let ca_pem = if msg.has_field_by_name("trusted_ca") {
        let ds = msg
            .get_field_by_name("trusted_ca")
            .and_then(|v| v.as_message().cloned())
            .ok_or_else(|| invalid(format!("{base}.trusted_ca"), "must be a DataSource message"))?;
        let bytes = read_data_source_bytes(&ds, &format!("{base}.trusted_ca"))?;
        if bytes.is_empty() {
            return Err(invalid(format!("{base}.trusted_ca"), "must not be empty"));
        }
        // Fail fast: a CA file that parses to zero certs must not pass
        // config load only to break every refresh at runtime.
        crate::jwks_refresh::tls_roots(Some(&bytes))
            .map_err(|reason| invalid(format!("{base}.trusted_ca"), reason))?;
        Some(bytes)
    } else {
        None
    };
    Ok(Some(DiscoveryConfig {
        url,
        interval,
        ca_pem,
    }))
}

/// Reads `typed_config.jwt_providers[i].tenant_values` (a
/// `map<string, string>`) into the lookup [`JwtAuthenticator`] enforces.
/// Absent and empty both mean "use the claim value directly". A mapped value
/// must not be empty (it would admit a caller as a tenant named `""`);
/// duplicates are impossible (proto maps have unique keys).
fn parse_tenant_values(
    msg: &DynamicMessage,
    base: &str,
) -> Result<HashMap<String, String>, ConfigError> {
    let Some(map) = msg
        .get_field_by_name("tenant_values")
        .and_then(|v| v.as_map().cloned())
    else {
        return Ok(HashMap::new());
    };
    let mut out = HashMap::with_capacity(map.len());
    for (key, value) in map.iter() {
        let key = match key {
            prost_reflect::MapKey::String(s) => s.clone(),
            _ => {
                return Err(invalid(
                    format!("{base}.tenant_values"),
                    "map keys must be strings",
                ));
            }
        };
        let value = match value {
            prost_reflect::Value::String(s) => s.clone(),
            _ => {
                return Err(invalid(
                    format!("{base}.tenant_values"),
                    "map values must be strings",
                ));
            }
        };
        if value.is_empty() {
            return Err(invalid(
                format!("{base}.tenant_values"),
                "mapped tenant must not be empty",
            ));
        }
        out.insert(key, value);
    }
    Ok(out)
}

/// Reads `typed_config` (an `llmproxy.filters.v0.Authentication`) into the
/// secret bytes + bootstrap key set + store selection + poll interval the
/// filter needs at request time. Strict mode: every field either maps in or
/// errors with its dotted path (AGENTS.md invariant 1).
fn parse_config(config: &DynamicMessage) -> Result<AuthConfig, ConfigError> {
    let secret_bytes = parse_hmac_secret(config)?;
    let store_spec = parse_store(config)?;
    let poll_interval = parse_poll_interval(config);

    let mut key_set = KeySet::new();
    // Rust note: `HashMap<String, usize>` / `HashMap<Vec<u8>, usize>` remember
    // which earlier index first used a given `key_id`/digest, so the
    // duplicate error can name the SECOND (offending) index precisely, per
    // the duplicate-detection rule.
    let mut seen_key_ids: HashMap<String, usize> = HashMap::new();
    let mut seen_digests: HashMap<Vec<u8>, usize> = HashMap::new();

    // Absent `virtual_keys` and an empty `virtual_keys` are indistinguishable
    // here (both yield `&[]`), and that's correct: the proto doc says empty
    // is legal -- it authenticates nothing and therefore refuses everything.
    let virtual_keys: Vec<prost_reflect::Value> = config
        .get_field_by_name("virtual_keys")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();

    for (i, entry) in virtual_keys.iter().enumerate() {
        let msg = entry.as_message().ok_or_else(|| {
            invalid(
                format!("typed_config.virtual_keys[{i}]"),
                "must be a message",
            )
        })?;

        let key_id = msg
            .get_field_by_name("key_id")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if key_id.is_empty() {
            return Err(invalid(
                format!("typed_config.virtual_keys[{i}].key_id"),
                "must not be empty",
            ));
        }

        let tenant = msg
            .get_field_by_name("tenant")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        if tenant.is_empty() {
            return Err(invalid(
                format!("typed_config.virtual_keys[{i}].tenant"),
                "must not be empty",
            ));
        }

        let digest_hex = msg
            .get_field_by_name("digest_hex")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        let digest = parse_digest_hex(&digest_hex, i)?;

        let revoked = msg
            .get_field_by_name("revoked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if let Some(&first) = seen_key_ids.get(&key_id) {
            return Err(invalid(
                format!("typed_config.virtual_keys[{i}].key_id"),
                format!("duplicate `key_id`; already used at index {first}"),
            ));
        }
        if let Some(&first) = seen_digests.get(&digest) {
            return Err(invalid(
                format!("typed_config.virtual_keys[{i}].digest_hex"),
                format!(
                    "duplicate `digest_hex`; already used at index {first} \
                     (two records for one digest means one is unreachable, \
                     and which one wins would depend on config order)"
                ),
            ));
        }
        seen_key_ids.insert(key_id.clone(), i);
        seen_digests.insert(digest.clone(), i);

        key_set.insert_digest(
            digest,
            KeyRecord {
                key_id: KeyId::new(key_id),
                tenant: TenantId::new(tenant),
                revoked,
            },
        );
    }

    Ok(AuthConfig {
        secret_bytes,
        bootstrap_keys: key_set,
        store_spec,
        poll_interval,
        jwt_providers: parse_jwt_providers(config)?,
    })
}

/// [`HttpFilterFactory`] for [`TYPE_URL`]. No `parse_per_route` override —
/// this filter has no per-route config; the trait default
/// (`ConfigError::Unimplemented`) is correct.
#[derive(Default)]
pub struct AuthFilterFactory;

impl HttpFilterFactory for AuthFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn may_buffer_response(&self) -> bool {
        false
    }

    fn create(
        &self,
        config: &DynamicMessage,
        ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let AuthConfig {
            secret_bytes,
            bootstrap_keys,
            store_spec,
            poll_interval,
            jwt_providers,
        } = parse_config(config)?;

        // One shared JWKS snapshot per JWT provider,
        // built here (outside the singleton closure) so every worker's
        // authenticator loads the same `Arc`. Static providers seed once and
        // never change; discovery providers seed (possibly empty) and are
        // republished by a background thread spawned exactly once inside the
        // closure below -- per-serve, not per-worker, so N workers don't
        // launch N refresh loops against the IdP.
        let mut jwt_snapshots = Vec::with_capacity(jwt_providers.len());
        let mut jwt_validations = Vec::with_capacity(jwt_providers.len());
        let mut jwt_refreshes = Vec::new();
        for (i, provider) in jwt_providers.into_iter().enumerate() {
            let JwtProviderConfig {
                keys,
                validation,
                discovery,
            } = provider;
            match discovery {
                Some(d) => {
                    let snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(
                        JwksSnapshot::discovering(keys),
                    )));
                    jwt_refreshes.push((
                        Arc::clone(&snapshot),
                        RefreshSpec {
                            discovery_url: d.url,
                            expected_issuer: validation.issuer.clone(),
                            interval: d.interval,
                            ca_pem: d.ca_pem,
                            label: format!("jwt_providers[{i}]"),
                        },
                    ));
                    jwt_snapshots.push((snapshot, Some(d.interval * STALE_AFTER_MISSED)));
                }
                None => {
                    let snapshot =
                        Arc::new(arc_swap::ArcSwap::new(Arc::new(JwksSnapshot::seeded(keys))));
                    jwt_snapshots.push((snapshot, None));
                }
            }
            jwt_validations.push(validation);
        }

        // The `ControlPlane` is now the ONE
        // per-serve instance shared across every worker BUILDING THIS SAME
        // CHAIN, resolved through `ctx.get_or_try_init` (`FactoryContext`'s
        // thin wrapper over `SharedFactoryState`, keyed on `(ctx.scope, this
        // filter's own TYPE_URL)` -- see `SharedFactoryState`'s doc for why
        // `scope` is part of the key: two DIFFERENT chains each configuring
        // `llmproxy.auth` must never share a `ControlPlane`). The HTTP filter
        // chain is rebuilt per worker (ADR-0003), so `create` runs once per
        // worker -- without this
        // slot each of those runs would build (and immediately drop) its own
        // `ControlPlane`, and a mint/revoke through one worker would be
        // invisible to every other. The closure below runs only on the FIRST
        // worker for this chain's `(scope, type_url)`; every later worker's `create` call
        // reads the same `Arc<ControlPlane>` back out instead of rebuilding
        // it. The store itself is
        // SELECTABLE (`typed_config.store`) and is built inside this closure
        // for exactly that reason -- a `persistent` store opens a `redb` file
        // that takes a file lock, so it must be opened once for the whole
        // serve, not once per worker (a second, per-worker open of the same
        // path would fail outright).
        //
        // Corollary, and a real limitation worth knowing: because the slot is
        // per-SERVE and a SIGHUP reload reuses the same `SharedFactoryState`,
        // the store -- like the HMAC secret and the bootstrap keys -- is
        // fixed at the first build. Editing `typed_config.store` and
        // reloading does NOT reopen anything; changing it takes a restart.
        //
        // Rust note: two independent `HmacSecret`s built from the SAME bytes
        // -- see `parse_config`'s doc for why bytes (not an `HmacSecret`)
        // cross that function's boundary. `ControlPlane` retains one for the
        // key-mint endpoint (3b-ii); the authenticator below keeps the other
        // for verifying every request. Neither is derivable from the other.
        // `bootstrap_keys` and `store_spec` are moved into the closure
        // (consumed by `ControlPlane::new`/matched to build the store) since
        // they only ever need to exist once, on the first worker;
        // `secret_bytes` is only borrowed there, so it is still available
        // afterward to build the authenticator's own `HmacSecret`.
        let control_plane = ctx
            .get_or_try_init(TYPE_URL, || {
                // 2c-iv: discovery refreshers start here, inside the
                // once-per-serve closure, for the same reason the store is
                // built here: one loop per provider per serve, not one per
                // worker. Each thread holds only a `Weak` to its snapshot
                // (see `start_jwks_refresher`), so a reload retires the old
                // threads when their snapshots drop.
                for (snapshot, spec) in jwt_refreshes {
                    crate::jwks_refresh::start_jwks_refresher(snapshot, spec);
                }
                let store: Box<dyn ControlPlaneStore> = match store_spec {
                    StoreSpec::InMemory => Box::new(InMemoryControlPlaneStore::default()),
                    StoreSpec::Persistent(path) => {
                        // `StoreError`'s `Display` carries only the redb/io
                        // reason -- never key material (see its doc) -- so
                        // folding it straight into the reason string here is
                        // safe. The path is not echoed back either: the
                        // dotted field path above already names where the
                        // offending value came from.
                        Box::new(RedbControlPlaneStore::open(&path).map_err(|e| {
                            invalid(
                                "typed_config.store.persistent.path",
                                format!("could not open the control-plane store: {e}"),
                            )
                        })?)
                    }
                    StoreSpec::Shared { url, namespace } => {
                        // Verified against redis 0.27.6's `connection.rs`
                        // (the version pinned in the workspace `Cargo.toml`):
                        // `RedisControlPlaneStore::open`/`open_with_namespace`
                        // call ONLY `redis::Client::open`, which performs no
                        // I/O -- it parses the URL into a `ConnectionInfo`
                        // and nothing more. Every `fail!` reachable from that
                        // parse (`IntoConnectionInfo for &str`,
                        // `url_to_tcp_connection_info`) carries a FIXED,
                        // static description -- "Redis URL did not parse",
                        // "Missing hostname", "Invalid database number", and
                        // so on -- with no case that interpolates the URL,
                        // host, username, or password. `StoreError::Unavailable`'s
                        // `Display` (`store_err`) is therefore safe to fold
                        // into the reason string here, exactly as the
                        // `persistent` arm above does for its own
                        // `StoreError`. The dotted path already names where
                        // the URL came from, so the URL itself is still
                        // never echoed.
                        let store = match namespace {
                            Some(ns) => RedisControlPlaneStore::open_with_namespace(&url, ns),
                            None => RedisControlPlaneStore::open(&url),
                        };
                        Box::new(store.map_err(|e| {
                            invalid(
                                "typed_config.store.shared.url",
                                format!("could not open the shared control-plane store: {e}"),
                            )
                        })?)
                    }
                };
                let secret = HmacSecret::new(&secret_bytes);
                let cp = ControlPlane::new(store, secret, bootstrap_keys).map_err(|e| {
                    invalid(
                        "typed_config",
                        format!("control-plane snapshot could not be built: {e}"),
                    )
                })?;
                // Start the policy poller HERE, not in `main.rs` --
                // `main.rs` never holds a `ControlPlane` handle at all (this
                // `get_or_try_init` closure is the one place a fresh
                // `ControlPlane` gets built, per (scope, TYPE_URL) singleton,
                // for the whole serve), and `start_policy_poller` needs an
                // `Arc<ControlPlane>` to hand its background thread a `Weak`
                // -- so `cp` is wrapped in `Arc` here, one line earlier than
                // it otherwise would be, purely to make that call possible.
                //
                // Same per-serve-pinning caveat as the store and the secret
                // above: because this slot is built once and reused across a
                // SIGHUP reload, changing `poll_interval_seconds` and
                // reloading does NOT restart the poller with the new
                // interval -- that takes a restart, same as `typed_config.store`.
                let cp = Arc::new(cp);
                cp.start_policy_poller(poll_interval);
                Ok(cp as Arc<dyn std::any::Any + Send + Sync>)
            })?
            .downcast::<ControlPlane>()
            .expect("auth control-plane singleton is always a ControlPlane");
        let authenticator: Box<dyn Authenticator> = Box::new(VirtualKeyAuthenticator::new(
            HmacSecret::new(&secret_bytes),
            control_plane.handle(),
        ));
        // One chain per (filter config, listener), shared by every per-stream
        // instance below via `Arc::clone` -- see `token_limit_filter`'s
        // `TokenLimitFilterFactory::create` for the same one-store-per-listener
        // shape. The virtual-key authenticator is always first
        // (`Bearer llmp_...` is its territory); each configured JWT provider
        // follows in config order and claims every other `Bearer` value as a
        // JWT, so the first JWT provider in order decides every JWT outcome.
        let mut authenticators: Vec<Box<dyn Authenticator>> = Vec::new();
        authenticators.push(authenticator);
        for ((snapshot, max_stale), validation) in jwt_snapshots.into_iter().zip(jwt_validations) {
            authenticators.push(Box::new(JwtAuthenticator::new_shared(
                snapshot, validation, max_stale,
            )));
        }
        let chain = Arc::new(AuthenticatorChain::new(authenticators));
        Ok(Box::new(AuthFilterInstanceFactory { chain }))
    }
}

struct AuthFilterInstanceFactory {
    chain: Arc<AuthenticatorChain>,
}

impl FilterInstanceFactory for AuthFilterInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(AuthFilterInstance {
            chain: Arc::clone(&self.chain),
        })
    }
}

/// Per-stream instance. Holds only the shared chain -- there is no
/// per-request state to carry between callbacks, because (unlike
/// `token_limit_filter`) authentication has no encode-side half.
struct AuthFilterInstance {
    chain: Arc<AuthenticatorChain>,
}

impl AuthFilterInstance {
    /// The single call site for the identical-on-the-wire 401 -- see the
    /// module doc's "wire response is identical" section. `details` is the
    /// only thing allowed to vary between callers of this function.
    fn deny(&self, cb: &mut dyn DecoderCallbacks, details: &str) {
        cb.send_local_reply(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            Some(Box::new(|headers: &mut HeaderMap| {
                // RFC 7235 requires a challenge on a 401 response; omitting
                // it is a real protocol bug, not a nicety.
                headers.insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            })),
            details,
        );
    }
}

impl HttpFilter for AuthFilterInstance {
    fn decode_headers(
        &mut self,
        cb: &mut dyn DecoderCallbacks,
        headers: &mut RequestHeaders,
        _end_stream: bool,
    ) -> FilterHeadersStatus {
        match self.chain.authenticate(&headers.headers) {
            AuthOutcome::Authenticated(principal) => {
                // Rust note: `stream_info()` returns a `RefMut` guard over the
                // stream's single `StreamInfo` (see its doc); it must not be
                // held across another call on `cb`, so this block ends (and
                // drops the guard) before `decode_headers` returns -- same
                // pattern as `token_limit_filter::record_if_present`.
                {
                    let mut info = cb.stream_info();
                    info.auth = AuthInfo {
                        tenant: Some(principal.tenant.as_str().to_string()),
                        key_id: Some(principal.key_id.as_str().to_string()),
                    };
                }
                // The credential has been consumed; see the module doc's
                // "removed before forwarding" section. `remove` drops every
                // value, not just the first one `authenticate` read.
                headers.headers.remove(AUTHORIZATION);
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::UnknownKey) => {
                self.deny(cb, "auth_unknown_key");
                // Rust note: the returned status is irrelevant once
                // `send_local_reply` has set `ctx.local_reply` --
                // `drive_decode` checks that and stops the chain
                // unconditionally regardless of what this function returns
                // (see `token_limit_filter::decode_headers`'s identical Rust
                // note and `filter_manager.rs`). `Continue` is returned only
                // because the trait requires *a* value.
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::RevokedKey) => {
                self.deny(cb, "auth_revoked_key");
                FilterHeadersStatus::Continue
            }
            // `crate::jwt_auth::JwtAuthenticator`'s
            // rejection reasons. No `JwtAuthenticator` is pushed onto this
            // filter's chain yet (that wiring is 2c-ii), so these arms are
            // unreachable today -- they exist only because `AuthError` is
            // matched exhaustively here, and each still gets its own
            // `details` string now so the wiring step does not also have to
            // touch this match.
            AuthOutcome::Rejected(AuthError::JwtMalformed) => {
                self.deny(cb, "auth_jwt_malformed");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtUnknownKid) => {
                self.deny(cb, "auth_jwt_unknown_kid");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtInvalidSignature) => {
                self.deny(cb, "auth_jwt_invalid_signature");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtExpired) => {
                self.deny(cb, "auth_jwt_expired");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtNotYetValid) => {
                self.deny(cb, "auth_jwt_not_yet_valid");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtIssuerMismatch) => {
                self.deny(cb, "auth_jwt_issuer_mismatch");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtAudienceMismatch) => {
                self.deny(cb, "auth_jwt_audience_mismatch");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtMissingTenantClaim) => {
                self.deny(cb, "auth_jwt_missing_tenant_claim");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtTenantNotMapped) => {
                self.deny(cb, "auth_jwt_tenant_not_mapped");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::Rejected(AuthError::JwtJwksStale) => {
                self.deny(cb, "auth_jwt_jwks_stale");
                FilterHeadersStatus::Continue
            }
            AuthOutcome::NoCredential => {
                self.deny(cb, "auth_no_credential");
                FilterHeadersStatus::Continue
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::{RefCell, RefMut};

    use bytes::Bytes;
    use http::{HeaderValue, Method, Uri};
    use proxy_config::ir::RouteEntry;
    use proxy_http::filter::{BufferedBody, EncoderCallbacks, HeaderMutationFn, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    use crate::control::test_snapshot_handle;
    use proxy_http::filter::SharedFactoryState;

    // --- config-message scaffolding ------------------------------------------

    fn data_source_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("envoy.config.core.v3.DataSource")
            .expect("DataSource is compiled into proxy-api")
    }

    fn inline_secret(value: &str) -> DynamicMessage {
        let mut ds = DynamicMessage::new(data_source_desc());
        ds.set_field_by_name(
            "inline_string",
            prost_reflect::Value::String(value.to_string()),
        );
        ds
    }

    fn filename_secret(path: &std::path::Path) -> DynamicMessage {
        let mut ds = DynamicMessage::new(data_source_desc());
        ds.set_field_by_name(
            "filename",
            prost_reflect::Value::String(path.to_string_lossy().to_string()),
        );
        ds
    }

    fn environment_variable_secret(value: &str) -> DynamicMessage {
        let mut ds = DynamicMessage::new(data_source_desc());
        ds.set_field_by_name(
            "environment_variable",
            prost_reflect::Value::String(value.to_string()),
        );
        ds
    }

    fn authentication_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.Authentication")
            .expect("Authentication is compiled into proxy-api")
    }

    fn virtual_key_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.VirtualKey")
            .expect("VirtualKey is compiled into proxy-api")
    }

    fn digest_hex(secret: &[u8], plaintext: &str) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
        let digest = ring::hmac::sign(&key, plaintext.as_bytes());
        digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }

    fn virtual_key(key_id: &str, tenant: &str, digest_hex: &str, revoked: bool) -> DynamicMessage {
        let mut vk = DynamicMessage::new(virtual_key_desc());
        vk.set_field_by_name("key_id", prost_reflect::Value::String(key_id.to_string()));
        vk.set_field_by_name("tenant", prost_reflect::Value::String(tenant.to_string()));
        vk.set_field_by_name(
            "digest_hex",
            prost_reflect::Value::String(digest_hex.to_string()),
        );
        vk.set_field_by_name("revoked", prost_reflect::Value::Bool(revoked));
        vk
    }

    fn authentication(
        hmac_secret: DynamicMessage,
        virtual_keys: Vec<DynamicMessage>,
    ) -> DynamicMessage {
        let mut msg = DynamicMessage::new(authentication_desc());
        msg.set_field_by_name("hmac_secret", prost_reflect::Value::Message(hmac_secret));
        msg.set_field_by_name(
            "virtual_keys",
            prost_reflect::Value::List(
                virtual_keys
                    .into_iter()
                    .map(prost_reflect::Value::Message)
                    .collect(),
            ),
        );
        msg
    }

    fn in_memory_store_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.InMemoryStore")
            .expect("InMemoryStore is compiled into proxy-api")
    }

    fn persistent_store_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.PersistentStore")
            .expect("PersistentStore is compiled into proxy-api")
    }

    /// Sets `typed_config.store` to `in_memory {}` -- explicit, as opposed to
    /// leaving the oneof unset entirely (every earlier test's `authentication`
    /// already covers the unset case).
    fn with_in_memory_store(mut config: DynamicMessage) -> DynamicMessage {
        let store = DynamicMessage::new(in_memory_store_desc());
        config.set_field_by_name("in_memory", prost_reflect::Value::Message(store));
        config
    }

    /// Sets `typed_config.store` to `persistent { path }`.
    fn with_persistent_store(mut config: DynamicMessage, path: &str) -> DynamicMessage {
        let mut store = DynamicMessage::new(persistent_store_desc());
        store.set_field_by_name("path", prost_reflect::Value::String(path.to_string()));
        config.set_field_by_name("persistent", prost_reflect::Value::Message(store));
        config
    }

    fn shared_store_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.SharedStore")
            .expect("SharedStore is compiled into proxy-api")
    }

    /// Sets `typed_config.store` to `shared { url: <inline_string> }`.
    fn with_shared_store(mut config: DynamicMessage, url: &str) -> DynamicMessage {
        let mut store = DynamicMessage::new(shared_store_desc());
        store.set_field_by_name("url", prost_reflect::Value::Message(inline_secret(url)));
        config.set_field_by_name("shared", prost_reflect::Value::Message(store));
        config
    }

    /// As [`with_shared_store`], but the url comes from a `filename`
    /// `DataSource` instead of `inline_string`.
    fn with_shared_store_filename(
        mut config: DynamicMessage,
        path: &std::path::Path,
    ) -> DynamicMessage {
        let mut store = DynamicMessage::new(shared_store_desc());
        store.set_field_by_name("url", prost_reflect::Value::Message(filename_secret(path)));
        config.set_field_by_name("shared", prost_reflect::Value::Message(store));
        config
    }

    /// Same convention as `control.rs`'s `temp_db_path` -- this crate has no
    /// `tempfile` dependency and must not gain one.
    fn temp_db_path(name_hint: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "llm-proxy-auth-filter-test-store-{name_hint}-{}-{}.redb",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    // --- descriptor pool ------------------------------------------------------

    #[test]
    fn authentication_resolves_in_the_descriptor_pool() {
        // Pins the type-URL choice: see `token_limit_filter`'s and
        // `body_rewrite_filter`'s equivalent tests for why this matters (an
        // unresolvable message fails every bootstrap using this filter with
        // an opaque `UnknownTypeUrl`, not here where the reason is obvious).
        let resolved =
            proxy_api::descriptor_pool().get_message_by_name("llmproxy.filters.v0.Authentication");
        assert!(resolved.is_some(), "{TYPE_URL} must resolve");
    }

    // --- config parsing ---------------------------------------------------------

    // The poll interval is the revocation bound, so pin both ends of
    // it -- the unset/`0` default AND an explicit value. `48 * 1.25 == 60`
    // is the owner's stated "a revoked key stops working within 60 seconds";
    // if the default here ever moves, that sentence moves with it.
    #[test]
    fn an_unset_poll_interval_falls_back_to_the_48_second_default() {
        let config = authentication(inline_secret("secret"), vec![]);
        assert_eq!(
            parse_poll_interval(&config),
            Duration::from_secs(48),
            "an unset poll_interval_seconds must mean the built-in default, not zero"
        );

        let mut explicit = authentication(inline_secret("secret"), vec![]);
        explicit.set_field_by_name("poll_interval_seconds", prost_reflect::Value::U32(90));
        assert_eq!(parse_poll_interval(&explicit), Duration::from_secs(90));
    }

    // 1: valid config parses AND the resulting filter authenticates a key
    // built with that same secret, end to end through `parse_config`.
    #[test]
    fn a_valid_config_parses_and_authenticates_a_key_built_with_the_same_secret() {
        let secret_bytes = b"operator-hmac-secret";
        let digest = digest_hex(secret_bytes, "llmp_test-key");
        let config = authentication(
            inline_secret(std::str::from_utf8(secret_bytes).unwrap()),
            vec![virtual_key("key-1", "tenant-a", &digest, false)],
        );

        let AuthConfig {
            secret_bytes,
            bootstrap_keys: key_set,
            ..
        } = parse_config(&config).expect("valid config must parse");
        let authenticator = VirtualKeyAuthenticator::new(
            HmacSecret::new(&secret_bytes),
            test_snapshot_handle(key_set),
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer llmp_test-key"),
        );
        match authenticator.authenticate(&headers) {
            AuthOutcome::Authenticated(principal) => {
                assert_eq!(principal.tenant.as_str(), "tenant-a");
                assert_eq!(principal.key_id.as_str(), "key-1");
            }
            other => panic!(
                "expected Authenticated; got Rejected={} NoCredential={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::NoCredential)
            ),
        }
    }

    // 2: missing hmac_secret -> InvalidValue, exact field_path.
    #[test]
    fn missing_hmac_secret_is_rejected_with_its_field_path() {
        let msg = DynamicMessage::new(authentication_desc());
        let err = parse_config(&msg).expect_err("missing hmac_secret must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.hmac_secret");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 3: empty hmac_secret -> rejected.
    #[test]
    fn empty_hmac_secret_is_rejected() {
        let config = authentication(inline_secret(""), vec![]);
        let err = parse_config(&config).expect_err("empty hmac_secret must be rejected");
        assert!(matches!(err, ConfigError::InvalidValue { .. }));
    }

    // 4: an unsupported DataSource specifier -> rejected, assert field_path.
    #[test]
    fn unsupported_data_source_specifier_is_rejected_with_its_field_path() {
        let config = authentication(environment_variable_secret("SECRET_ENV"), vec![]);
        let err = parse_config(&config).expect_err("environment_variable must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.hmac_secret");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 5: filename secret parses and authenticates; a nonexistent path errors
    // with the `.filename` field path.
    #[test]
    fn filename_secret_parses_and_authenticates_and_a_missing_file_is_rejected() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "llm-proxy-auth-filter-test-secret-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"operator-hmac-secret").expect("write temp secret file");

        let digest = digest_hex(b"operator-hmac-secret", "llmp_test-key");
        let config = authentication(
            filename_secret(&path),
            vec![virtual_key("key-1", "tenant-a", &digest, false)],
        );
        let AuthConfig {
            secret_bytes,
            bootstrap_keys: key_set,
            ..
        } = parse_config(&config).expect("valid filename config must parse");
        let authenticator = VirtualKeyAuthenticator::new(
            HmacSecret::new(&secret_bytes),
            test_snapshot_handle(key_set),
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer llmp_test-key"),
        );
        assert!(matches!(
            authenticator.authenticate(&headers),
            AuthOutcome::Authenticated(_)
        ));

        std::fs::remove_file(&path).ok();

        let missing = dir.join("llm-proxy-auth-filter-test-secret-does-not-exist");
        let config = authentication(filename_secret(&missing), vec![]);
        let err = parse_config(&config).expect_err("nonexistent file must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.hmac_secret.filename");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    /// A secret file with a TRAILING NEWLINE must key the HMAC on the secret
    /// alone.
    ///
    /// `echo "s3cret" > /etc/llmproxy/auth-secret` is the most obvious way an
    /// operator creates this file, and it appends a newline. Before
    /// 2026-08-08 that newline silently became part of the key, so the digest
    /// this code computed matched only a tool that also included it — and the
    /// documented `openssl dgst -hmac "$(cat file)"` fallback does not,
    /// because shell command substitution strips trailing newlines. Every key
    /// then failed with a bare 401 carrying nothing to explain why.
    ///
    /// The digest here is deliberately computed over the UNTRIMMED secret
    /// (`b"operator-hmac-secret"`, no newline) while the file on disk has one:
    /// the two match only if `parse_hmac_secret` trims. `--mode keygen` reads
    /// the same file through the same `auth::secret_bytes_from_file`, so the
    /// generator cannot drift from this verifier.
    #[test]
    fn a_secret_file_with_a_trailing_newline_keys_on_the_secret_alone() {
        let path = std::env::temp_dir().join(format!(
            "llm-proxy-auth-filter-test-secret-newline-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"operator-hmac-secret\n").expect("write temp secret file");

        let digest = digest_hex(b"operator-hmac-secret", "llmp_test-key");
        let config = authentication(
            filename_secret(&path),
            vec![virtual_key("key-1", "tenant-a", &digest, false)],
        );
        let AuthConfig {
            secret_bytes,
            bootstrap_keys: key_set,
            ..
        } = parse_config(&config).expect("valid filename config must parse");
        let authenticator = VirtualKeyAuthenticator::new(
            HmacSecret::new(&secret_bytes),
            test_snapshot_handle(key_set),
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer llmp_test-key"),
        );
        let outcome = authenticator.authenticate(&headers);
        std::fs::remove_file(&path).ok();

        assert!(
            matches!(outcome, AuthOutcome::Authenticated(_)),
            "a secret file's trailing newline must not become part of the HMAC key -- \
             untrimmed, every key an operator generates fails with an unexplained 401"
        );
    }

    /// A file of nothing but whitespace is an empty secret, not a secret made
    /// of spaces — it must be rejected like any other empty one rather than
    /// silently keying the HMAC on zero bytes.
    #[test]
    fn a_whitespace_only_secret_file_is_rejected_as_empty() {
        let path = std::env::temp_dir().join(format!(
            "llm-proxy-auth-filter-test-secret-blank-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"   \n\t\n").expect("write temp secret file");

        let config = authentication(filename_secret(&path), vec![]);
        let result = parse_config(&config);
        std::fs::remove_file(&path).ok();

        match result {
            Err(ConfigError::InvalidValue { field_path, .. }) => {
                assert_eq!(field_path, "typed_config.hmac_secret");
            }
            Err(other) => panic!("expected InvalidValue, got {other:?}"),
            Ok(_) => panic!("a whitespace-only secret file must be rejected as empty"),
        }
    }

    // 6: digest_hex of the wrong length, non-hex, and UPPERCASE -> each
    // rejected with the same field_path.
    #[test]
    fn malformed_digest_hex_variants_are_each_rejected() {
        let good_digest = digest_hex(b"secret", "llmp_x");
        for bad in [
            &good_digest[..good_digest.len() - 1], // wrong length
            "not-hex-at-all-and-way-too-short",    // non-hex, wrong length too
            &good_digest.to_ascii_uppercase(),     // uppercase
        ] {
            let config = authentication(
                inline_secret("secret"),
                vec![virtual_key("key-1", "tenant-a", bad, false)],
            );
            let err = parse_config(&config).expect_err(&format!("{bad:?} must be rejected"));
            match err {
                ConfigError::InvalidValue { field_path, .. } => {
                    assert_eq!(field_path, "typed_config.virtual_keys[0].digest_hex");
                }
                other => panic!("expected InvalidValue for {bad:?}, got {other:?}"),
            }
        }

        // A same-length, non-hex string, distinct from the "wrong length"
        // case above.
        let non_hex_same_length: String = "z".repeat(64);
        let config = authentication(
            inline_secret("secret"),
            vec![virtual_key(
                "key-1",
                "tenant-a",
                &non_hex_same_length,
                false,
            )],
        );
        let err = parse_config(&config).expect_err("non-hex digest must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.virtual_keys[0].digest_hex");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 7: duplicate key_id -> rejected, naming index 1.
    #[test]
    fn duplicate_key_id_is_rejected_naming_index_1() {
        let digest_a = digest_hex(b"secret", "llmp_a");
        let digest_b = digest_hex(b"secret", "llmp_b");
        let config = authentication(
            inline_secret("secret"),
            vec![
                virtual_key("dup-id", "tenant-a", &digest_a, false),
                virtual_key("dup-id", "tenant-b", &digest_b, false),
            ],
        );
        let err = parse_config(&config).expect_err("duplicate key_id must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.virtual_keys[1].key_id");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 8: duplicate digest_hex -> rejected, naming index 1.
    #[test]
    fn duplicate_digest_hex_is_rejected_naming_index_1() {
        let digest = digest_hex(b"secret", "llmp_shared");
        let config = authentication(
            inline_secret("secret"),
            vec![
                virtual_key("key-1", "tenant-a", &digest, false),
                virtual_key("key-2", "tenant-b", &digest, false),
            ],
        );
        let err = parse_config(&config).expect_err("duplicate digest_hex must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.virtual_keys[1].digest_hex");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 9: empty virtual_keys parses fine AND the resulting filter 401s a
    // well-formed llmp_ key -- assert the behaviour, not just parse success.
    #[test]
    fn empty_virtual_keys_parses_and_the_filter_401s_every_key() {
        let config = authentication(inline_secret("secret"), vec![]);
        let AuthConfig {
            secret_bytes,
            bootstrap_keys: key_set,
            ..
        } = parse_config(&config).expect("empty virtual_keys is legal");
        let authenticator = VirtualKeyAuthenticator::new(
            HmacSecret::new(&secret_bytes),
            test_snapshot_handle(key_set),
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer llmp_anything-well-formed"),
        );
        match authenticator.authenticate(&headers) {
            AuthOutcome::Rejected(AuthError::UnknownKey) => {}
            other => panic!(
                "an empty key set must reject every llmp_ credential as unknown; got {}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // 10: no parse_config error message ever contains the secret or a digest.
    #[test]
    fn no_parse_config_error_contains_the_secret_or_a_digest() {
        let distinctive_secret = "very-distinctive-operator-secret-value";
        let distinctive_digest = digest_hex(distinctive_secret.as_bytes(), "llmp_distinctive-key");

        let mut errors = Vec::new();

        // Missing hmac_secret.
        errors.push(
            parse_config(&DynamicMessage::new(authentication_desc()))
                .expect_err("missing hmac_secret"),
        );

        // Malformed digest_hex, with a secret + digest both present in the
        // config so a leak has something distinctive to leak.
        errors.push(
            parse_config(&authentication(
                inline_secret(distinctive_secret),
                vec![virtual_key(
                    "key-1",
                    "tenant-a",
                    &distinctive_digest[..distinctive_digest.len() - 1],
                    false,
                )],
            ))
            .expect_err("malformed digest_hex"),
        );

        // Duplicate digest_hex, using the distinctive digest twice.
        errors.push(
            parse_config(&authentication(
                inline_secret(distinctive_secret),
                vec![
                    virtual_key("key-1", "tenant-a", &distinctive_digest, false),
                    virtual_key("key-2", "tenant-b", &distinctive_digest, false),
                ],
            ))
            .expect_err("duplicate digest_hex"),
        );

        for err in &errors {
            let rendered = format!("{err}");
            assert!(
                !rendered.contains(distinctive_secret),
                "error message must never contain the secret: {rendered}"
            );
            assert!(
                !rendered.contains(&distinctive_digest),
                "error message must never contain the digest: {rendered}"
            );
        }
    }

    // --- test scaffolding for filter-behaviour tests ---------------------------

    fn route_named(name: &str) -> Arc<RouteEntry> {
        Arc::new(RouteEntry {
            name: Some(name.to_string()),
            matcher: proxy_config::ir::RouteMatcher {
                path: proxy_config::ir::PathMatch::Prefix("/".to_string()),
                case_sensitive: true,
                headers: vec![],
            },
            action: proxy_config::ir::RouteActionIR::DirectResponse {
                status: 200,
                body: None,
            },
            request_headers_to_add: vec![],
            streaming_strict: false,
            typed_per_filter_config: Default::default(),
            route_index: 0,
            include_request_attempt_count: false,
            include_attempt_count_in_response: false,
        })
    }

    /// What one `send_local_reply` call produced, including `details` --
    /// `token_limit_filter`'s `TestCallbacks` double drops `details`; this
    /// filter's whole "identical wire response, different access-log detail"
    /// contract needs it captured.
    struct LocalReply {
        status: StatusCode,
        body: String,
        headers: HeaderMap,
        details: String,
    }

    /// A `DecoderCallbacks` + `EncoderCallbacks` double, copied from
    /// `token_limit_filter`'s `TestCallbacks` (duplicated deliberately, not
    /// shared -- see this crate's convention). Every method this filter
    /// doesn't use panics loudly.
    struct TestCallbacks {
        route: Option<Arc<RouteEntry>>,
        stream_info: RefCell<StreamInfo>,
        local_reply: Option<LocalReply>,
    }

    impl TestCallbacks {
        fn new(route: Option<Arc<RouteEntry>>) -> Self {
            TestCallbacks {
                route,
                stream_info: RefCell::new(StreamInfo::default()),
                local_reply: None,
            }
        }
    }

    impl DecoderCallbacks for TestCallbacks {
        fn send_local_reply(
            &mut self,
            code: StatusCode,
            body: &str,
            modify_headers: Option<HeaderMutationFn>,
            details: &str,
        ) {
            let mut headers = HeaderMap::new();
            if let Some(f) = modify_headers {
                f(&mut headers);
            }
            self.local_reply = Some(LocalReply {
                status: code,
                body: body.to_string(),
                headers,
                details: details.to_string(),
            });
        }
        fn continue_decoding(&mut self) {
            unimplemented!("auth_filter never stops iteration")
        }
        fn add_decoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("auth_filter never buffers request data")
        }
        fn inject_decoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("auth_filter never injects data")
        }
        fn decoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("auth_filter never consults the decoding buffer")
        }
        fn modify_decoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("auth_filter never touches request bytes")
        }
        fn route(&mut self) -> Option<Arc<RouteEntry>> {
            self.route.clone()
        }
        fn clear_route_cache(&mut self) {
            unimplemented!("auth_filter never rewrites routing headers")
        }
        fn per_route_config(&mut self) -> Option<Arc<dyn PerRouteConfig>> {
            None
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    impl EncoderCallbacks for TestCallbacks {
        fn continue_encoding(&mut self) {
            unimplemented!("auth_filter has no encode-side callbacks")
        }
        fn add_encoded_data(&mut self, _data: Bytes, _streaming: bool) {
            unimplemented!("auth_filter has no encode-side callbacks")
        }
        fn inject_encoded_data_to_filter_chain(&mut self, _data: Bytes, _end_stream: bool) {
            unimplemented!("auth_filter has no encode-side callbacks")
        }
        fn encoding_buffer(&self) -> Option<&BufferedBody> {
            unimplemented!("auth_filter has no encode-side callbacks")
        }
        fn modify_encoding_buffer(&mut self, _f: &mut dyn FnMut(&mut bytes::BytesMut)) {
            unimplemented!("auth_filter has no encode-side callbacks")
        }
        fn stream_info(&mut self) -> RefMut<'_, StreamInfo> {
            self.stream_info.borrow_mut()
        }
    }

    fn request_headers(authorization: Option<&str>) -> RequestHeaders {
        let mut headers = HeaderMap::new();
        if let Some(a) = authorization {
            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(a).unwrap(),
            );
        }
        RequestHeaders {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers,
        }
    }

    fn filter_with_one_key(
        secret_bytes: &[u8],
        plaintext_key: &str,
        key_id: &str,
        tenant: &str,
        revoked: bool,
    ) -> AuthFilterInstance {
        let secret = HmacSecret::new(secret_bytes);
        let mut key_set = KeySet::new();
        key_set.insert(
            &secret,
            plaintext_key,
            KeyRecord {
                key_id: KeyId::new(key_id),
                tenant: TenantId::new(tenant),
                revoked,
            },
        );
        let authenticator: Box<dyn Authenticator> = Box::new(VirtualKeyAuthenticator::new(
            HmacSecret::new(secret_bytes),
            test_snapshot_handle(key_set),
        ));
        AuthFilterInstance {
            chain: Arc::new(AuthenticatorChain::new(vec![authenticator])),
        }
    }

    // 11: a valid key -> Continue, no local reply, stream_info().auth carries
    // tenant AND key_id.
    #[test]
    fn a_valid_key_continues_and_sets_stream_info_auth() {
        let mut filter =
            filter_with_one_key(b"secret", "llmp_good-key", "key-1", "tenant-a", false);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_good-key"));

        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(cb.local_reply.is_none());
        let info = cb.stream_info.borrow();
        assert_eq!(info.auth.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(info.auth.key_id.as_deref(), Some("key-1"));
    }

    // 12: an unknown llmp_ key -> 401.
    #[test]
    fn an_unknown_key_is_401ed() {
        let mut filter =
            filter_with_one_key(b"secret", "llmp_good-key", "key-1", "tenant-a", false);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_wrong-key"));

        filter.decode_headers(&mut cb, &mut head, true);

        let reply = cb.local_reply.expect("unknown key must be denied");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    // 13: no authorization header at all -> 401 (fail closed).
    #[test]
    fn no_authorization_header_is_401ed() {
        let mut filter =
            filter_with_one_key(b"secret", "llmp_good-key", "key-1", "tenant-a", false);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(None);

        filter.decode_headers(&mut cb, &mut head, true);

        let reply = cb
            .local_reply
            .expect("an absent credential must be refused, not admitted -- fail closed");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    // 14: a revoked key -> 401.
    #[test]
    fn a_revoked_key_is_401ed() {
        let mut filter =
            filter_with_one_key(b"secret", "llmp_revoked-key", "key-1", "tenant-a", true);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_revoked-key"));

        filter.decode_headers(&mut cb, &mut head, true);

        let reply = cb.local_reply.expect("a revoked key must be denied");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    // 15: all three failure reasons produce a byte-identical downstream
    // response (status, body, headers).
    #[test]
    fn all_three_failure_reasons_produce_an_identical_downstream_response() {
        // no credential
        let mut filter =
            filter_with_one_key(b"secret", "llmp_good-key", "key-1", "tenant-a", false);
        let mut cb_none = TestCallbacks::new(Some(route_named("r1")));
        let mut head_none = request_headers(None);
        filter.decode_headers(&mut cb_none, &mut head_none, true);
        let none_reply = cb_none.local_reply.expect("no-credential must be denied");

        // unknown key
        let mut cb_unknown = TestCallbacks::new(Some(route_named("r1")));
        let mut head_unknown = request_headers(Some("Bearer llmp_wrong-key"));
        filter.decode_headers(&mut cb_unknown, &mut head_unknown, true);
        let unknown_reply = cb_unknown.local_reply.expect("unknown key must be denied");

        // revoked key
        let mut revoked_filter =
            filter_with_one_key(b"secret", "llmp_revoked-key", "key-1", "tenant-a", true);
        let mut cb_revoked = TestCallbacks::new(Some(route_named("r1")));
        let mut head_revoked = request_headers(Some("Bearer llmp_revoked-key"));
        revoked_filter.decode_headers(&mut cb_revoked, &mut head_revoked, true);
        let revoked_reply = cb_revoked.local_reply.expect("revoked key must be denied");

        for (name, reply) in [
            ("no-credential", &none_reply),
            ("unknown", &unknown_reply),
            ("revoked", &revoked_reply),
        ] {
            assert_eq!(
                reply.status,
                StatusCode::UNAUTHORIZED,
                "{name}: status must be 401"
            );
            assert_eq!(reply.body, "unauthorized", "{name}: body must be identical");
            assert_eq!(
                reply.headers.get(WWW_AUTHENTICATE),
                Some(&HeaderValue::from_static("Bearer")),
                "{name}: must carry a www-authenticate challenge"
            );
        }
        assert_eq!(none_reply.headers, unknown_reply.headers);
        assert_eq!(unknown_reply.headers, revoked_reply.headers);
    }

    // 16: the three failure reasons produce three DIFFERENT `details`
    // strings -- the operator-facing half of #15.
    #[test]
    fn the_three_failure_reasons_produce_three_different_details_strings() {
        let mut filter =
            filter_with_one_key(b"secret", "llmp_good-key", "key-1", "tenant-a", false);

        let mut cb_none = TestCallbacks::new(Some(route_named("r1")));
        let mut head_none = request_headers(None);
        filter.decode_headers(&mut cb_none, &mut head_none, true);
        let none_details = cb_none.local_reply.unwrap().details;

        let mut cb_unknown = TestCallbacks::new(Some(route_named("r1")));
        let mut head_unknown = request_headers(Some("Bearer llmp_wrong-key"));
        filter.decode_headers(&mut cb_unknown, &mut head_unknown, true);
        let unknown_details = cb_unknown.local_reply.unwrap().details;

        let mut revoked_filter =
            filter_with_one_key(b"secret", "llmp_revoked-key", "key-1", "tenant-a", true);
        let mut cb_revoked = TestCallbacks::new(Some(route_named("r1")));
        let mut head_revoked = request_headers(Some("Bearer llmp_revoked-key"));
        revoked_filter.decode_headers(&mut cb_revoked, &mut head_revoked, true);
        let revoked_details = cb_revoked.local_reply.unwrap().details;

        assert_eq!(none_details, "auth_no_credential");
        assert_eq!(unknown_details, "auth_unknown_key");
        assert_eq!(revoked_details, "auth_revoked_key");
        assert_ne!(none_details, unknown_details);
        assert_ne!(unknown_details, revoked_details);
        assert_ne!(none_details, revoked_details);
    }

    // 17: a valid key sets stream_info().auth AND removes the request's
    // authorization header -- the virtual key must never reach a provider.
    // `crates/proxy/tests/credential_forwarding_e2e.rs` proves the same thing
    // end to end for each provider type.
    #[test]
    fn a_valid_key_removes_the_authorization_header() {
        let mut filter =
            filter_with_one_key(b"secret", "llmp_good-key", "key-1", "tenant-a", false);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_good-key"));
        head.headers.append(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer llmp_second-value"),
        );

        filter.decode_headers(&mut cb, &mut head, true);

        assert!(
            !head.headers.contains_key(http::header::AUTHORIZATION),
            "every authorization value must be removed after authentication -- an \
             anthropic or keyless openai-compatible cluster never overwrites it, so \
             anything left here is forwarded to the provider: {:?}",
            head.headers.get_all(http::header::AUTHORIZATION)
        );
        let info = cb.stream_info.borrow();
        assert_eq!(info.auth.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(info.auth.key_id.as_deref(), Some("key-1"));
    }

    // 18: chain behaviour -- the probing-oracle test. A `Rejected` from the
    // first authenticator must stop the chain even though a later
    // authenticator would have authenticated.
    struct AlwaysAuthenticates;

    impl Authenticator for AlwaysAuthenticates {
        fn authenticate(&self, _headers: &HeaderMap) -> AuthOutcome {
            AuthOutcome::Authenticated(crate::auth::Principal {
                tenant: TenantId::new("should-never-be-reached"),
                key_id: KeyId::new("should-never-be-reached"),
                policy: Arc::new(Default::default()),
            })
        }
    }

    struct AlwaysRejects;

    impl Authenticator for AlwaysRejects {
        fn authenticate(&self, _headers: &HeaderMap) -> AuthOutcome {
            AuthOutcome::Rejected(AuthError::RevokedKey)
        }
    }

    #[test]
    fn a_rejected_first_authenticator_short_circuits_a_chain_that_would_otherwise_authenticate() {
        let chain =
            AuthenticatorChain::new(vec![Box::new(AlwaysRejects), Box::new(AlwaysAuthenticates)]);

        match chain.authenticate(&HeaderMap::new()) {
            AuthOutcome::Rejected(AuthError::RevokedKey) => {}
            other => panic!(
                "a Rejected from the first authenticator must stop the chain, even \
                 though a later authenticator would authenticate -- this is the \
                 probing-oracle test; got Authenticated={}",
                matches!(other, AuthOutcome::Authenticated(_))
            ),
        }
    }

    // 19: the shared-singleton property.
    // `create` resolves ONE `ControlPlane` through `ctx.get_or_try_init`, a write
    // through it is visible to what the factory wired, and a SECOND `create`
    // over the same `ctx` does not build a second instance.
    #[test]
    fn create_resolves_one_shared_control_plane_through_the_slot() {
        let config = authentication(inline_secret("operator-hmac-secret"), vec![]);
        let ctx = FactoryContext::default();

        AuthFilterFactory
            .create(&config, &ctx)
            .expect("first create must succeed");

        let control_plane = ctx
            .get(TYPE_URL)
            .expect("create must register the control plane in the shared slot")
            .downcast::<ControlPlane>()
            .expect("the auth control-plane singleton is always a ControlPlane");

        // A write through the slot-resolved ControlPlane...
        let minted = control_plane
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .expect("mint_key must succeed");

        // ...is visible to what the factory wired: a fresh authenticator over
        // the SAME control plane's published handle.
        let authenticator = VirtualKeyAuthenticator::new(
            HmacSecret::new(b"operator-hmac-secret"),
            control_plane.handle(),
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", minted.plaintext)).unwrap(),
        );
        assert!(
            matches!(
                authenticator.authenticate(&headers),
                AuthOutcome::Authenticated(_)
            ),
            "a write through the slot-resolved ControlPlane must be visible to what \
             the factory wired"
        );

        // A second `create` over the SAME ctx must not build a second
        // ControlPlane -- the minted key from the first must still be
        // present afterward.
        AuthFilterFactory
            .create(&config, &ctx)
            .expect("second create must succeed");

        match authenticator.authenticate(&headers) {
            AuthOutcome::Authenticated(_) => {}
            other => panic!(
                "a second create() over the same ctx must reuse the same ControlPlane, \
                 not build a fresh (empty) one -- the first mint must still authenticate; \
                 got Rejected={} NoCredential={}",
                matches!(other, AuthOutcome::Rejected(_)),
                matches!(other, AuthOutcome::NoCredential)
            ),
        }
    }

    // --- store selection -----------------------

    // 20: the oneof left UNSET builds successfully -- back-compat, this is
    // what every config written before `store` existed still does.
    #[test]
    fn an_unset_store_builds_with_the_default_in_memory_store() {
        let config = authentication(inline_secret("operator-hmac-secret"), vec![]);
        let ctx = FactoryContext::default();

        AuthFilterFactory
            .create(&config, &ctx)
            .expect("an unset `store` oneof must default to in_memory and build successfully");
    }

    // 21: `in_memory` set explicitly builds the same way.
    #[test]
    fn an_explicit_in_memory_store_builds() {
        let config = with_in_memory_store(authentication(
            inline_secret("operator-hmac-secret"),
            vec![],
        ));
        let ctx = FactoryContext::default();

        AuthFilterFactory
            .create(&config, &ctx)
            .expect("an explicit `in_memory` store must build successfully");
    }

    // 22: `persistent` with an empty path is a config error naming the exact
    // field path, not just any error.
    #[test]
    fn a_persistent_store_with_an_empty_path_is_rejected_with_its_field_path() {
        let config = with_persistent_store(
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            "",
        );
        let ctx = FactoryContext::default();

        // Rust note: not `.expect_err` -- that requires the `Ok` type
        // (`Box<dyn FilterInstanceFactory>`) to implement `Debug`, which it
        // deliberately does not (it is a trait object with no derive). A
        // plain `match` sidesteps that bound entirely.
        let err = match AuthFilterFactory.create(&config, &ctx) {
            Err(e) => e,
            Ok(_) => panic!("an empty `persistent.path` must be rejected"),
        };
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.store.persistent.path");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 23: the acceptance test -- a `persistent` store actually persists
    // across two independent factories/`FactoryContext`s pointed at the same
    // path. An in-memory store would make this fail.
    #[test]
    fn a_persistent_store_survives_a_fresh_factory_context_over_the_same_path() {
        let path = temp_db_path("survives-fresh-context");
        let path_str = path.to_string_lossy().to_string();

        {
            let config = with_persistent_store(
                authentication(inline_secret("operator-hmac-secret"), vec![]),
                &path_str,
            );
            let ctx = FactoryContext::default();
            AuthFilterFactory
                .create(&config, &ctx)
                .expect("first create over a persistent store must succeed");

            let control_plane = ctx
                .get(TYPE_URL)
                .expect("create must register the control plane in the shared slot")
                .downcast::<ControlPlane>()
                .expect("the auth control-plane singleton is always a ControlPlane");

            control_plane
                .mint_key(&TenantId::new("tenant-a"), &KeyId::new("persisted-key"))
                .expect("mint_key must succeed against a healthy persistent store");

            // Everything above -- factory, ctx, control plane, and the redb
            // `Database` handle it owns -- is dropped at the end of this
            // block, before the second factory below opens the same file.
        }

        let config = with_persistent_store(
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            &path_str,
        );
        let ctx2 = FactoryContext::default();
        AuthFilterFactory
            .create(&config, &ctx2)
            .expect("a second, fresh factory/context over the same path must succeed");

        let control_plane2 = ctx2
            .get(TYPE_URL)
            .expect("the second create must also register a control plane")
            .downcast::<ControlPlane>()
            .expect("the auth control-plane singleton is always a ControlPlane");

        let snapshot = control_plane2.handle().load();
        let found = snapshot
            .keys
            .iter()
            .any(|(_, record)| record.key_id.as_str() == "persisted-key");

        std::fs::remove_file(&path).ok();

        assert!(
            found,
            "a key minted through a persistent store must still be present after \
             reopening the same path from a fresh factory + FactoryContext -- an \
             in-memory store would lose it"
        );
    }

    // 24: a persistent path that cannot be opened is a config error, not a
    // panic.
    #[test]
    fn a_persistent_store_with_an_unopenable_path_is_a_config_error_not_a_panic() {
        // A path inside a directory that does not exist -- `Database::create`
        // cannot create the parent directory for us.
        let bad_path = std::env::temp_dir()
            .join("llm-proxy-auth-filter-test-store-nonexistent-dir-does-not-exist")
            .join("store.redb");
        let config = with_persistent_store(
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            &bad_path.to_string_lossy(),
        );
        let ctx = FactoryContext::default();

        let err = match AuthFilterFactory.create(&config, &ctx) {
            Err(e) => e,
            Ok(_) => panic!("a persistent path inside a nonexistent directory must be rejected"),
        };
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.store.persistent.path");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // --- the `shared` (Redis) store -------------------------

    // 27: an inline-string url parses to `StoreSpec::Shared` with no namespace.
    #[test]
    fn parse_store_returns_shared_for_an_inline_url() {
        let config = with_shared_store(
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            "redis://127.0.0.1:6390/0",
        );
        match parse_store(&config).expect("a shared store with an inline url must parse") {
            StoreSpec::Shared { url, namespace } => {
                assert_eq!(url, "redis://127.0.0.1:6390/0");
                assert_eq!(namespace, None);
            }
            other => panic!("expected StoreSpec::Shared, got {other:?}"),
        }
    }

    // 28: a `filename`-sourced url has its trailing newline stripped, exactly
    // like `hmac_secret` -- `echo redis://... > file` appends one.
    #[test]
    fn parse_store_reads_a_url_from_a_filename_and_strips_a_trailing_newline() {
        let path = std::env::temp_dir().join(format!(
            "llm-proxy-auth-filter-test-shared-url-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"redis://127.0.0.1:6390/0\n").expect("write temp url file");

        let config = with_shared_store_filename(
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            &path,
        );
        let result = parse_store(&config);
        std::fs::remove_file(&path).ok();

        match result.expect("a shared store with a filename url must parse") {
            StoreSpec::Shared { url, .. } => {
                assert_eq!(
                    url, "redis://127.0.0.1:6390/0",
                    "the file's trailing newline must not become part of the url"
                );
            }
            other => panic!("expected StoreSpec::Shared, got {other:?}"),
        }
    }

    // 29: an empty url is InvalidValue at the exact dotted path, like an empty
    // `persistent.path`.
    #[test]
    fn parse_store_rejects_an_empty_shared_url_with_its_field_path() {
        let config = with_shared_store(
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            "",
        );
        let err = parse_store(&config).expect_err("an empty shared.url must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.store.shared.url");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 30: an unsupported DataSource specifier under `shared.url` is rejected
    // with its dotted path, same as `hmac_secret`.
    #[test]
    fn parse_store_rejects_an_unsupported_data_source_specifier_under_shared_url() {
        let mut store = DynamicMessage::new(shared_store_desc());
        store.set_field_by_name(
            "url",
            prost_reflect::Value::Message(environment_variable_secret("REDIS_URL")),
        );
        let mut config = authentication(inline_secret("operator-hmac-secret"), vec![]);
        config.set_field_by_name("shared", prost_reflect::Value::Message(store));

        let err = parse_store(&config).expect_err("environment_variable must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.store.shared.url");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 31: THE redaction test -- the whole point of `StoreSpec`'s hand-written
    // `Debug` impl. A Redis URL can carry a password
    // (`redis://:password@host/`); the `Debug` render of a `StoreSpec::Shared`
    // holding one must never contain it.
    #[test]
    fn shared_store_spec_debug_never_contains_the_password() {
        let spec = StoreSpec::Shared {
            url: "redis://:hunter2@127.0.0.1:6390/0".to_string(),
            namespace: Some("my-namespace".to_string()),
        };
        let rendered = format!("{spec:?}");
        assert!(
            !rendered.contains("hunter2"),
            "StoreSpec::Shared's Debug render must never contain the url's password: \
             {rendered}"
        );
        assert!(
            rendered.contains("my-namespace"),
            "the namespace is not secret and should still be visible for debugging: \
             {rendered}"
        );
    }

    // --- SharedFactoryState scope fix: two chains must never collide -----------

    // 25: THE regression test. Two chains (two different `FactoryContext::scope`
    // strings), two different auth configs (different `hmac_secret`, different
    // `virtual_keys`), over ONE `SharedFactoryState` -- the exact shape
    // `build_hcm_handler` produces for two listeners (or two filter chains)
    // that both configure `llmproxy.auth`. Each scope's `ControlPlane` must
    // reflect ITS OWN config: a key valid in scope A must not authenticate in
    // scope B, and vice versa.
    //
    // Before this fix (`SharedFactoryState` keyed on `type_url` alone), scope
    // B's `create()` would silently find scope A's slot already filled, skip
    // running its own `init`, and hand scope B's filter scope A's
    // `ControlPlane` -- so scope A's key would ALSO authenticate against
    // scope B (a real cross-tenant key acceptance), and scope B's own key
    // would be rejected by ITS OWN filter (scope B's `ControlPlane` was never
    // built at all). Both assertions below catch that: the first would fail
    // silently-wrong (falsely `Authenticated`), the second would fail with
    // the wrong REASON (scope B's own valid key rejected).
    #[test]
    fn two_scopes_over_one_shared_state_get_independent_control_planes() {
        let shared = Arc::new(SharedFactoryState::default());

        let secret_a = b"scope-a-secret";
        let digest_a = digest_hex(secret_a, "llmp_key-a");
        let config_a = authentication(
            inline_secret(std::str::from_utf8(secret_a).unwrap()),
            vec![virtual_key("key-a", "tenant-a", &digest_a, false)],
        );
        let ctx_a = FactoryContext {
            shared: Arc::clone(&shared),
            scope: "listener 'a' filter_chains[0]".to_string(),
            stat_prefix: "a".to_string(),
        };
        let mut filter_a = AuthFilterFactory
            .create(&config_a, &ctx_a)
            .expect("scope A create must succeed")
            .create_filter();

        let secret_b = b"scope-b-secret";
        let digest_b = digest_hex(secret_b, "llmp_key-b");
        let config_b = authentication(
            inline_secret(std::str::from_utf8(secret_b).unwrap()),
            vec![virtual_key("key-b", "tenant-b", &digest_b, false)],
        );
        let ctx_b = FactoryContext {
            shared: Arc::clone(&shared),
            scope: "listener 'b' filter_chains[0]".to_string(),
            stat_prefix: "b".to_string(),
        };
        let mut filter_b = AuthFilterFactory
            .create(&config_b, &ctx_b)
            .expect("scope B create must succeed")
            .create_filter();

        // Scope A's own key authenticates against scope A's own filter.
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_key-a"));
        filter_a.decode_headers(&mut cb, &mut head, true);
        assert!(
            cb.local_reply.is_none(),
            "scope A's own key must authenticate against scope A's own filter"
        );

        // Scope A's key must NOT authenticate against scope B's filter -- a
        // pass here means scope B silently inherited scope A's ControlPlane.
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_key-a"));
        filter_b.decode_headers(&mut cb, &mut head, true);
        let reply = cb.local_reply.expect(
            "scope A's key authenticated against scope B's filter -- scope B silently \
             reused scope A's ControlPlane/keys instead of building its own",
        );
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);

        // The reverse: scope B's own key authenticates against scope B's own
        // filter, and must NOT authenticate against scope A's.
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_key-b"));
        filter_b.decode_headers(&mut cb, &mut head, true);
        assert!(
            cb.local_reply.is_none(),
            "scope B's own key must authenticate against scope B's own filter -- if this \
             fails, scope B's create() never registered its own ControlPlane (it silently \
             read back scope A's slot instead)"
        );

        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_key-b"));
        filter_a.decode_headers(&mut cb, &mut head, true);
        let reply = cb.local_reply.expect(
            "scope B's key authenticated against scope A's filter -- scope A silently \
             reused scope B's ControlPlane/keys instead of its own",
        );
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    }

    // 26: the per-worker case (W1/W2, `create_resolves_one_shared_control_plane_through_the_slot`'s
    // property) must not regress: the SAME scope across two independent
    // `FactoryContext`s -- exactly what happens when `build_hcm_handler` runs
    // once per worker over the same `context` string -- still yields ONE
    // shared `ControlPlane`, not two independent ones.
    #[test]
    fn same_scope_twice_still_yields_one_shared_control_plane() {
        let shared = Arc::new(SharedFactoryState::default());
        let config = authentication(inline_secret("operator-hmac-secret"), vec![]);

        let ctx1 = FactoryContext {
            shared: Arc::clone(&shared),
            scope: "listener 'a' filter_chains[0]".to_string(),
            stat_prefix: "a".to_string(),
        };
        AuthFilterFactory
            .create(&config, &ctx1)
            .expect("first create over the shared scope must succeed");
        let control_plane = ctx1
            .get(TYPE_URL)
            .expect("create must register the control plane in the shared slot")
            .downcast::<ControlPlane>()
            .expect("the auth control-plane singleton is always a ControlPlane");
        control_plane
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .expect("mint_key must succeed");

        // A second "worker"'s create -- a fresh FactoryContext, same scope
        // string, same underlying SharedFactoryState.
        let ctx2 = FactoryContext {
            shared: Arc::clone(&shared),
            scope: "listener 'a' filter_chains[0]".to_string(),
            stat_prefix: "a".to_string(),
        };
        AuthFilterFactory
            .create(&config, &ctx2)
            .expect("second create over the same scope must succeed");
        let control_plane2 = ctx2
            .get(TYPE_URL)
            .expect("second create must resolve the SAME singleton, not build a new one")
            .downcast::<ControlPlane>()
            .expect("the auth control-plane singleton is always a ControlPlane");

        assert!(
            Arc::ptr_eq(&control_plane, &control_plane2),
            "the same scope across two independent FactoryContexts must resolve to the SAME \
             ControlPlane Arc -- this is the W1/W2 per-worker property and must not regress"
        );
    }

    // --- JWT wiring ------------------------------------
    //
    // These tests prove the `jwt_providers` config surface parses into live
    // chain entries: a valid token authenticates end to end through the real
    // filter, and failures stay terminal with their own access-log details.
    // Full signature/expiry/issuer semantics already have their own suite in
    // `jwt_auth.rs`; these tests pin the WIRING, not the crypto.

    fn jwt_provider_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.JwtProvider")
            .expect("JwtProvider is compiled into proxy-api")
    }

    fn jwt_key_desc() -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name("llmproxy.filters.v0.JwtKey")
            .expect("JwtKey is compiled into proxy-api")
    }

    fn jwt_key(kid: &str, n: &str, e: &str) -> DynamicMessage {
        let mut msg = DynamicMessage::new(jwt_key_desc());
        msg.set_field_by_name("kid", prost_reflect::Value::String(kid.to_string()));
        msg.set_field_by_name("n", prost_reflect::Value::String(n.to_string()));
        msg.set_field_by_name("e", prost_reflect::Value::String(e.to_string()));
        msg
    }

    fn jwt_provider(
        tenant_claim: &str,
        issuer: Option<&str>,
        audience: Option<&str>,
        keys: Vec<DynamicMessage>,
    ) -> DynamicMessage {
        let mut msg = DynamicMessage::new(jwt_provider_desc());
        msg.set_field_by_name(
            "tenant_claim",
            prost_reflect::Value::String(tenant_claim.to_string()),
        );
        if let Some(iss) = issuer {
            msg.set_field_by_name("issuer", prost_reflect::Value::String(iss.to_string()));
        }
        if let Some(aud) = audience {
            msg.set_field_by_name("audience", prost_reflect::Value::String(aud.to_string()));
        }
        msg.set_field_by_name(
            "keys",
            prost_reflect::Value::List(
                keys.into_iter()
                    .map(prost_reflect::Value::Message)
                    .collect(),
            ),
        );
        msg
    }

    fn authentication_with_jwt(
        hmac_secret: DynamicMessage,
        providers: Vec<DynamicMessage>,
    ) -> DynamicMessage {
        let mut msg = authentication(hmac_secret, vec![]);
        msg.set_field_by_name(
            "jwt_providers",
            prost_reflect::Value::List(
                providers
                    .into_iter()
                    .map(prost_reflect::Value::Message)
                    .collect(),
            ),
        );
        msg
    }

    /// Test RSA keypair, generated once per test process. `ring` can SIGN
    /// with RSA but cannot GENERATE a keypair (see `jwt_auth.rs`'s own test
    /// rationale), so generation uses the `rsa` dev-dependency; parsing and
    /// signing are microseconds, generation (~1s for 2048 bits) happens once
    /// behind this `OnceLock`, not once per assertion.
    struct JwtTestKey {
        der: Vec<u8>,
        n_b64: String,
        e_b64: String,
    }

    fn jwt_test_key() -> &'static JwtTestKey {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;

        static KEY: std::sync::OnceLock<JwtTestKey> = std::sync::OnceLock::new();
        KEY.get_or_init(|| {
            let mut rng = rand::thread_rng();
            let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("test RSA keygen");
            let public_key = private_key.to_public_key();
            JwtTestKey {
                der: private_key
                    .to_pkcs1_der()
                    .expect("PKCS#1 DER encoding")
                    .as_bytes()
                    .to_vec(),
                n_b64: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
                e_b64: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
            }
        })
    }

    fn sign_test_jwt(key: &JwtTestKey, kid: &str, payload_json: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let header_b64 = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"RS256","kid":"{kid}"}}"#));
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

    fn jwt_payload(fields: &str) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        format!(r#"{{"exp":{exp}{fields}}}"#)
    }

    fn jwt_claims(tenant: &str, extra: &str) -> String {
        jwt_payload(&format!(r#","tenant":"{tenant}"{extra}"#))
    }

    fn jwt_filter(tenant_claim: &str) -> (Box<dyn FilterInstanceFactory>, &'static JwtTestKey) {
        let key = jwt_test_key();
        let config = authentication_with_jwt(
            inline_secret("operator-hmac-secret"),
            vec![jwt_provider(
                tenant_claim,
                Some("https://issuer.example"),
                Some("llm-proxy"),
                vec![jwt_key("key-1", &key.n_b64, &key.e_b64)],
            )],
        );
        let ctx = FactoryContext::default();
        let factory = AuthFilterFactory
            .create(&config, &ctx)
            .expect("valid JWT provider config must build");
        (factory, key)
    }

    fn jwt_bearer(token: &str) -> String {
        format!("Bearer {token}")
    }

    fn jwt_provider_mapped(
        tenant_claim: &str,
        entries: Vec<(&str, &str)>,
        key: &JwtTestKey,
    ) -> DynamicMessage {
        use prost_reflect::{MapKey, Value};

        let mut msg = jwt_provider(
            tenant_claim,
            Some("https://issuer.example"),
            Some("llm-proxy"),
            vec![jwt_key("key-1", &key.n_b64, &key.e_b64)],
        );
        msg.set_field_by_name(
            "tenant_values",
            Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| (MapKey::String(k.to_string()), Value::String(v.to_string())))
                    .collect(),
            ),
        );
        msg
    }

    // 2c-ii/1: a valid JWT authenticates end to end through the real filter,
    // with the configured tenant claim and the JWKS kid as key_id.
    #[test]
    fn a_valid_jwt_authenticates_through_the_filter_chain() {
        let (factory, key) = jwt_filter("tenant");
        let mut filter = factory.create_filter();
        let token = sign_test_jwt(
            key,
            "key-1",
            &jwt_claims(
                "tenant-a",
                r#","iss":"https://issuer.example","aud":"llm-proxy""#,
            ),
        );
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some(&jwt_bearer(&token)));

        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(cb.local_reply.is_none());
        let info = cb.stream_info.borrow();
        assert_eq!(info.auth.tenant.as_deref(), Some("tenant-a"));
        assert_eq!(info.auth.key_id.as_deref(), Some("key-1"));
    }

    // 2c-ii/2: a tampered JWT is 401ed with its own access-log detail -- the
    // JWT outcome is terminal, exactly like the virtual-key outcomes above.
    #[test]
    fn a_tampered_jwt_is_401ed_with_jwt_details() {
        let (factory, key) = jwt_filter("tenant");
        let mut filter = factory.create_filter();
        let mut token = sign_test_jwt(
            key,
            "key-1",
            &jwt_claims(
                "tenant-a",
                r#","iss":"https://issuer.example","aud":"llm-proxy""#,
            ),
        );
        // Flip one interior character of the signature segment: still
        // decodable base64, no longer a valid signature.
        let (message, signature) = token.rsplit_once('.').expect("three segments");
        let mut chars: Vec<char> = signature.chars().collect();
        let idx = chars.len() / 2;
        chars[idx] = if chars[idx] == 'A' { 'B' } else { 'A' };
        token = format!("{message}.{}", chars.into_iter().collect::<String>());
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some(&jwt_bearer(&token)));

        filter.decode_headers(&mut cb, &mut head, true);

        let reply = cb.local_reply.expect("a bad JWT must be denied");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.details, "auth_jwt_invalid_signature");
        assert_eq!(reply.body, "unauthorized");
    }

    // 2c-ii/3: chain order is preserved -- an invalid llmp_ key is still the
    // virtual-key authenticator's terminal Rejected, never retried as a JWT.
    #[test]
    fn an_invalid_virtual_key_does_not_fall_through_to_jwt() {
        let (factory, _key) = jwt_filter("tenant");
        let mut filter = factory.create_filter();
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_no-such-key"));

        filter.decode_headers(&mut cb, &mut head, true);

        let reply = cb.local_reply.expect("an unknown key must be denied");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.details, "auth_unknown_key");
    }

    // config validation -- every malformed jwt_providers entry fails
    // with its dotted path, never silently ignored (AGENTS.md invariant 1).
    #[test]
    fn malformed_jwt_provider_entries_are_rejected_with_dotted_paths() {
        let key = jwt_test_key();
        let good_key = jwt_key("key-1", &key.n_b64, &key.e_b64);

        // Missing tenant_claim.
        let err = parse_config(&authentication_with_jwt(
            inline_secret("secret"),
            vec![jwt_provider("", None, None, vec![good_key.clone()])],
        ))
        .expect_err("empty tenant_claim must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.jwt_providers[0].tenant_claim");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }

        // No keys at all.
        let err = parse_config(&authentication_with_jwt(
            inline_secret("secret"),
            vec![jwt_provider("tenant", None, None, vec![])],
        ))
        .expect_err("a provider with no keys must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.jwt_providers[0].keys");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }

        // Non-base64url modulus.
        let err = parse_config(&authentication_with_jwt(
            inline_secret("secret"),
            vec![jwt_provider(
                "tenant",
                None,
                None,
                vec![jwt_key("key-1", "!!!not-base64!!!", &key.e_b64)],
            )],
        ))
        .expect_err("non-base64url n must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.jwt_providers[0].keys[0].n");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }

        // Duplicate kid within one provider.
        let err = parse_config(&authentication_with_jwt(
            inline_secret("secret"),
            vec![jwt_provider(
                "tenant",
                None,
                None,
                vec![good_key.clone(), good_key],
            )],
        ))
        .expect_err("a duplicate kid must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.jwt_providers[0].keys[1].kid");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }

        // Empty mapped tenant.
        let key = jwt_test_key();
        let mut msg = jwt_provider(
            "tenant",
            None,
            None,
            vec![jwt_key("key-1", &key.n_b64, &key.e_b64)],
        );
        msg.set_field_by_name(
            "tenant_values",
            prost_reflect::Value::Map(HashMap::from([(
                prost_reflect::MapKey::String("entra-tid-1".to_string()),
                prost_reflect::Value::String(String::new()),
            )])),
        );
        let err = parse_config(&authentication_with_jwt(inline_secret("secret"), vec![msg]))
            .expect_err("an empty mapped tenant must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.jwt_providers[0].tenant_values");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 2c-iii/1: a mapped claim value authenticates as the CONFIGURED tenant,
    // end to end through the real filter.
    #[test]
    fn a_mapped_claim_value_authenticates_as_the_configured_tenant() {
        let key = jwt_test_key();
        let config = authentication_with_jwt(
            inline_secret("operator-hmac-secret"),
            vec![jwt_provider_mapped(
                "tid",
                vec![("entra-tid-1", "acme")],
                key,
            )],
        );
        let ctx = FactoryContext::default();
        let factory = AuthFilterFactory
            .create(&config, &ctx)
            .expect("valid mapped provider must build");
        let mut filter = factory.create_filter();
        let token = sign_test_jwt(
            key,
            "key-1",
            &jwt_payload(
                r#","tid":"entra-tid-1","iss":"https://issuer.example","aud":"llm-proxy""#,
            ),
        );
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some(&jwt_bearer(&token)));

        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        assert!(cb.local_reply.is_none());
        let info = cb.stream_info.borrow();
        assert_eq!(info.auth.tenant.as_deref(), Some("acme"));
    }

    // 2c-iv/1: discovery parse -- http is rejected, empty keys are legal
    // with discovery, bad trusted_ca fails fast with its dotted path.
    #[test]
    fn discovery_config_parses_strictly() {
        let key = jwt_test_key();

        // http discovery URL: rejected (plaintext JWKS is an auth bypass).
        let mut http_provider = jwt_provider(
            "tenant",
            None,
            None,
            vec![jwt_key("key-1", &key.n_b64, &key.e_b64)],
        );
        http_provider.set_field_by_name(
            "discovery_url",
            prost_reflect::Value::String(
                "http://issuer.example/.well-known/openid-configuration".to_string(),
            ),
        );
        let err = parse_config(&authentication_with_jwt(
            inline_secret("secret"),
            vec![http_provider],
        ))
        .expect_err("http discovery_url must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.jwt_providers[0].discovery_url");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }

        // Empty keys WITH discovery: legal (first refresh populates).
        let mut seeded = DynamicMessage::new(jwt_provider_desc());
        seeded.set_field_by_name(
            "tenant_claim",
            prost_reflect::Value::String("tenant".to_string()),
        );
        seeded.set_field_by_name(
            "discovery_url",
            prost_reflect::Value::String(
                "https://issuer.example/.well-known/openid-configuration".to_string(),
            ),
        );
        seeded.set_field_by_name("keys", prost_reflect::Value::List(vec![]));
        let parsed = parse_config(&authentication_with_jwt(
            inline_secret("secret"),
            vec![seeded],
        ))
        .expect("empty keys with discovery must parse");
        assert!(parsed.jwt_providers[0].discovery.is_some());

        // Garbage trusted_ca: fails at load, not on the first tick.
        let mut bad_ca = jwt_provider(
            "tenant",
            None,
            None,
            vec![jwt_key("key-1", &key.n_b64, &key.e_b64)],
        );
        bad_ca.set_field_by_name(
            "discovery_url",
            prost_reflect::Value::String(
                "https://issuer.example/.well-known/openid-configuration".to_string(),
            ),
        );
        bad_ca.set_field_by_name(
            "trusted_ca",
            prost_reflect::Value::Message(inline_secret("not pem at all")),
        );
        let err = parse_config(&authentication_with_jwt(
            inline_secret("secret"),
            vec![bad_ca],
        ))
        .expect_err("garbage trusted_ca must be rejected");
        match err {
            ConfigError::InvalidValue { field_path, .. } => {
                assert_eq!(field_path, "typed_config.jwt_providers[0].trusted_ca");
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    // 2c-iii/2: an unmapped claim value is 401ed with its own detail -- never
    // admitted under the raw issuer-side value.
    #[test]
    fn an_unmapped_claim_value_is_401ed_never_passed_through() {
        let key = jwt_test_key();
        let config = authentication_with_jwt(
            inline_secret("operator-hmac-secret"),
            vec![jwt_provider_mapped(
                "tid",
                vec![("entra-tid-1", "acme")],
                key,
            )],
        );
        let ctx = FactoryContext::default();
        let factory = AuthFilterFactory
            .create(&config, &ctx)
            .expect("valid mapped provider must build");
        let mut filter = factory.create_filter();
        let token = sign_test_jwt(
            key,
            "key-1",
            &jwt_payload(
                r#","tid":"some-other-tid","iss":"https://issuer.example","aud":"llm-proxy""#,
            ),
        );
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some(&jwt_bearer(&token)));

        filter.decode_headers(&mut cb, &mut head, true);

        let reply = cb.local_reply.expect("an unmapped value must be denied");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(reply.details, "auth_jwt_tenant_not_mapped");
    }
}
