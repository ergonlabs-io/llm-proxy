//! WP-50 increment 2a-ii, part 1 — wires the [`crate::auth`] core into a real
//! `HttpFilter`.
//!
//! **Library only** in `auth.rs`; this module is the seam that actually sits
//! in the decode path. See `docs/wp-50-auth-design-brief.md` (normative,
//! agreed with the repo owner) for the full design; this file implements the
//! filter half of increment 2a ("virtual keys, in-memory") exactly as scoped
//! there.
//!
//! # Config: a vendored proto, not a borrowed Envoy message
//!
//! `llmproxy.filters.v0.Authentication` (`proxy-api/vendor/llmproxy/filters/v0/auth.proto`)
//! is the first Lane-H proto vendored for its own sake — see that file's
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

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use http::header::WWW_AUTHENTICATE;
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
use crate::control::{ControlPlane, InMemoryControlPlaneStore};

/// Type URL this filter is registered under.
pub const TYPE_URL: &str = "type.llmproxy.dev/llmproxy.filters.v0.Authentication";

fn invalid(field_path: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue {
        field_path: field_path.into(),
        reason: reason.into(),
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

    let bytes = if data_source.has_field_by_name("filename") {
        let filename = data_source
            .get_field_by_name("filename")
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        // The io::Error's Display never includes file contents -- only the
        // path and a kernel-level reason (e.g. "No such file or
        // directory") -- so it is safe to fold straight into the reason
        // string. Never read the file again for logging purposes.
        let raw = fs::read(&filename)
            .map_err(|e| invalid("typed_config.hmac_secret.filename", format!("{e}")))?;
        // Trailing whitespace is stripped -- see `auth::secret_bytes_from_file`
        // for why this is load-bearing rather than tidy (`echo secret > file`
        // adds a newline that would otherwise silently become part of the
        // key). `--mode keygen` reads the same file through the same
        // function, so the generator and this verifier cannot disagree.
        crate::auth::secret_bytes_from_file(&raw).to_vec()
    } else if data_source.has_field_by_name("inline_string") {
        data_source
            .get_field_by_name("inline_string")
            .and_then(|v| v.as_str().map(|s| s.as_bytes().to_vec()))
            .unwrap_or_default()
    } else {
        return Err(invalid(
            "typed_config.hmac_secret",
            "only `filename` and `inline_string` data source specifiers are supported",
        ));
    };

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
    for pair in raw.as_bytes().chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16).unwrap();
        let lo = (pair[1] as char).to_digit(16).unwrap();
        bytes.push(((hi << 4) | lo) as u8);
    }
    Ok(bytes)
}

/// Reads `typed_config` (an `llmproxy.filters.v0.Authentication`) into the
/// secret bytes + bootstrap key set the filter needs at request time. Strict
/// mode: every field either maps in or errors with its dotted path (ground
/// rule #1).
///
/// Returns raw secret **bytes**, not an [`HmacSecret`] -- as of WP-50
/// increment 3b-i, [`AuthFilterFactory::create`] needs TWO independent
/// `HmacSecret`s from the same bytes (one for the request-time authenticator,
/// one retained by [`crate::control::ControlPlane`] for a future key-mint
/// endpoint), and `HmacSecret` deliberately has no accessor back to its bytes
/// once constructed (see its doc) -- so the bytes have to be the thing that
/// crosses this boundary, and each caller constructs its own `HmacSecret`.
fn parse_config(config: &DynamicMessage) -> Result<(Vec<u8>, KeySet), ConfigError> {
    let secret_bytes = parse_hmac_secret(config)?;

    let mut key_set = KeySet::new();
    // Rust note: `HashMap<String, usize>` / `HashMap<Vec<u8>, usize>` remember
    // which earlier index first used a given `key_id`/digest, so the
    // duplicate error can name the SECOND (offending) index precisely, per
    // the design brief's dedup rule.
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

    Ok((secret_bytes, key_set))
}

/// [`HttpFilterFactory`] for [`TYPE_URL`]. No `parse_per_route` override —
/// this increment has no per-route config; the trait default
/// (`ConfigError::Unimplemented`) is correct.
#[derive(Default)]
pub struct AuthFilterFactory;

impl HttpFilterFactory for AuthFilterFactory {
    fn type_url(&self) -> &'static str {
        TYPE_URL
    }

    fn create(
        &self,
        config: &DynamicMessage,
        _ctx: &FactoryContext,
    ) -> Result<Box<dyn FilterInstanceFactory>, ConfigError> {
        let (secret_bytes, bootstrap_keys) = parse_config(config)?;

        // WP-50 increment 3b-i: config keys now flow through the same
        // published-snapshot machinery a future store will use, rather than
        // sitting in a static `KeySet` the authenticator owns outright. The
        // store here is an empty `InMemoryControlPlaneStore` -- there is no
        // admin write API or persistent backend wired up yet (3b-ii); its
        // `load()` never fails, so the merged snapshot is exactly the
        // bootstrap keys, but it now runs through `ControlPlane::rebuild`'s
        // real merge/publish path instead of a shortcut. See
        // `crate::control`'s module doc.
        //
        // Rust note: two independent `HmacSecret`s built from the SAME bytes
        // -- see `parse_config`'s doc for why bytes (not an `HmacSecret`)
        // cross that function's boundary. `ControlPlane` retains one for a
        // future key-mint endpoint (3b-ii); the authenticator below keeps the
        // other for verifying every request. Neither is derivable from the
        // other.
        let control_plane = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::default()),
            HmacSecret::new(&secret_bytes),
            bootstrap_keys,
        )
        .map_err(|e| {
            invalid(
                "typed_config",
                format!("control-plane snapshot could not be built: {e}"),
            )
        })?;
        let authenticator: Box<dyn Authenticator> = Box::new(VirtualKeyAuthenticator::new(
            HmacSecret::new(&secret_bytes),
            control_plane.handle(),
        ));
        // One chain per (filter config, listener), shared by every per-stream
        // instance below via `Arc::clone` -- see `token_limit_filter`'s
        // `TokenLimitFilterFactory::create` for the same one-store-per-listener
        // shape. Built with exactly one authenticator today; a future
        // `JwtAuthenticator` (increment 2c) is meant to be pushed onto this
        // same `Vec` without this factory changing shape -- see the design
        // brief and `AuthenticatorChain`'s doc.
        let chain = Arc::new(AuthenticatorChain::new(vec![authenticator]));
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

        let (secret_bytes, key_set) = parse_config(&config).expect("valid config must parse");
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
        let (secret_bytes, key_set) =
            parse_config(&config).expect("valid filename config must parse");
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
        let (secret_bytes, key_set) =
            parse_config(&config).expect("valid filename config must parse");
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
        let (secret_bytes, key_set) = parse_config(&config).expect("empty virtual_keys is legal");
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

    // 17: a valid key leaves stream_info().auth set AND the request's
    // authorization header untouched -- this filter authenticates, it does
    // not strip.
    #[test]
    fn a_valid_key_leaves_the_authorization_header_untouched() {
        let mut filter =
            filter_with_one_key(b"secret", "llmp_good-key", "key-1", "tenant-a", false);
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_good-key"));

        filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(
            head.headers.get(http::header::AUTHORIZATION),
            Some(&HeaderValue::from_static("Bearer llmp_good-key")),
            "the client credential must still be present -- replacing it with the \
             provider credential is the cluster's request_headers_to_add, which runs \
             later (ground rule #6)"
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
}
