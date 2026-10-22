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
use std::sync::{Arc, Weak};
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
    ControlPlane, ControlPlaneStore, CredentialKeys, InMemoryControlPlaneStore,
    RedbControlPlaneStore,
};
use crate::control_redis::RedisControlPlaneStore;
use crate::jwks_refresh::{
    JwksSnapshot, RefreshSpec, DEFAULT_REFRESH_INTERVAL, STALE_AFTER_MISSED,
};
use crate::jwt_auth::{JwkRsaKey, JwtAuthenticator, JwtKeySet, JwtValidationConfig};
use crate::tenant_credential_crypto::{CredentialKek, KekError, KeyRing};
use crate::window_counter::LeaseStore;

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
        let hi = (pair[0] as char)
            .to_digit(16)
            .expect("validated as hex above");
        let lo = (pair[1] as char)
            .to_digit(16)
            .expect("validated as hex above");
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

impl StoreSpec {
    /// The `auth.store` variant name, as the dialect spells it.
    fn kind(&self) -> &'static str {
        match self {
            StoreSpec::InMemory => "in_memory",
            StoreSpec::Persistent(_) => "persistent",
            StoreSpec::Shared { .. } => "shared",
        }
    }
}

/// Makes N replicas on a per-replica store visible (ADR-0006 addendum
/// "Admission stays local" §5). The rate card rides the same store, so the
/// warning names it too: `persistent` survives a restart but is still one
/// replica's file. The proxy never knows the replica count, so
/// it cannot detect the mistake; it warns where a configured node id
/// suggests a fleet, and exports the store kind so the fleet can be checked
/// from metrics alone. Called once per chain, from the closure that builds
/// the chain's control plane, so a reload does not repeat either.
///
/// This fails open loudly (AGENTS.md "Fail-open controls"): the config
/// still loads and each replica enforces its own limits.
fn report_store_kind(
    store: &'static str,
    node_id: &str,
    stat_prefix: &str,
    registry: Option<&Arc<proxy_observability::stats::Registry>>,
) {
    let configured = node_id_is_configured(node_id);
    if configured && store != "shared" {
        tracing::warn!(
            stat_prefix = %stat_prefix,
            node_id = %node_id,
            store = %store,
            "llmproxy.auth: a node id is configured, which suggests more than one replica, \
             but auth.store is not shared: limits and budgets apply per replica, so N \
             replicas admit up to N times each limit, and a rate card published with \
             PUT /pricing reaches only the replica that receives it. Set auth.store to \
             shared to enforce them and share the rate card across the fleet"
        );
    }
    if let Some(registry) = registry {
        let node_label = if configured { node_id } else { "-" };
        let handle = registry.resolve_capped(
            &proxy_observability::stats::instruments::CONTROL_PLANE_STORE_INFO,
            &[
                ("scope", stat_prefix),
                ("store", store),
                ("node_id", node_label),
            ],
            STORE_INFO_SERIES_CEILING,
            &[
                ("scope", "overflow"),
                ("store", store),
                ("node_id", node_label),
            ],
        );
        registry.add(proxy_observability::stats::WorkerId(0), handle, 1);
    }
}

/// One series per chain, so the ceiling bounds the number of chains.
const STORE_INFO_SERIES_CEILING: usize = 256;

/// Whether the effective node id names this replica. Empty is unset, and `-`
/// is what an unset id renders as; `spend_limit` treats both as unset too.
fn node_id_is_configured(node_id: &str) -> bool {
    !node_id.is_empty() && node_id != "-"
}

/// Why `store: shared` needs a configured node id (ADR-0006 addendum
/// "Admission stays local" §5). Without one each boot writes under a fresh
/// per-boot id, and the shared store keeps that boot's dedup state: spend
/// rows for periods that never end keep it forever. `proxy-simple-config`
/// returns the dialect's own wording, which can name only `--service-node`.
const SHARED_STORE_NEEDS_NODE_ID: &str = "a shared store requires a configured node id: pass \
     --service-node <name> (or set the bootstrap node.id) to a name unique to this replica and \
     stable across its restarts";

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

/// Reason for the durable-store requirement. [`parse_config`] returns it
/// for Envoy mode, and `proxy-simple-config`'s `lower.rs` returns the same
/// words for the dialect, so an operator sees one message either way.
const TENANT_CREDENTIALS_NEED_DURABLE_STORE: &str = "tenant credentials require a durable store (`persistent` or `shared`): in_memory loses them on restart";

/// Reads `typed_config.tenant_credentials` and loads its key-encryption keys
/// (ADR-0007 decision 2). Unset is `Ok(None)`: the proxy then cannot seal or
/// open tenant credentials, and stored rows fail closed. Any problem with the
/// block or a key file is a config load error naming the dotted path, so a
/// proxy meant to protect tenant credentials refuses to start rather than
/// running without its keys. Errors never carry key bytes: `KekError`
/// renders only fixed text or an I/O reason.
fn parse_tenant_credentials(config: &DynamicMessage) -> Result<Option<KeyRing>, ConfigError> {
    const BASE: &str = "typed_config.tenant_credentials";
    if !config.has_field_by_name("tenant_credentials") {
        return Ok(None);
    }
    let block = config
        .get_field_by_name("tenant_credentials")
        .and_then(|v| v.as_message().cloned())
        .ok_or_else(|| invalid(BASE, "must be a message"))?;
    let string_field = |msg: &DynamicMessage, name: &str| {
        msg.get_field_by_name(name)
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    };
    let current_file = string_field(&block, "encryption_key_file");
    if current_file.is_empty() {
        return Err(invalid(
            format!("{BASE}.encryption_key_file"),
            "is required and must not be empty",
        ));
    }
    let current_id = string_field(&block, "encryption_key_id");
    if current_id.is_empty() {
        return Err(invalid(
            format!("{BASE}.encryption_key_id"),
            "is required and must not be empty",
        ));
    }
    let previous_entries: Vec<prost_reflect::Value> = block
        .get_field_by_name("previous_keys")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();
    let mut previous_specs = Vec::with_capacity(previous_entries.len());
    for (i, entry) in previous_entries.iter().enumerate() {
        let msg = entry
            .as_message()
            .ok_or_else(|| invalid(format!("{BASE}.previous_keys[{i}]"), "must be a message"))?;
        let id = string_field(msg, "id");
        if id.is_empty() {
            return Err(invalid(
                format!("{BASE}.previous_keys[{i}].id"),
                "is required and must not be empty",
            ));
        }
        let file = string_field(msg, "file");
        if file.is_empty() {
            return Err(invalid(
                format!("{BASE}.previous_keys[{i}].file"),
                "is required and must not be empty",
            ));
        }
        previous_specs.push((id, file));
    }

    let kek_error = |path: String, err: KekError| invalid(path, err.to_string());
    let current = CredentialKek::load(&current_id, std::path::Path::new(&current_file))
        .map_err(|e| kek_error(format!("{BASE}.encryption_key_file"), e))?;
    let mut previous = Vec::with_capacity(previous_specs.len());
    for (i, (id, file)) in previous_specs.iter().enumerate() {
        previous.push(
            CredentialKek::load(id, std::path::Path::new(file))
                .map_err(|e| kek_error(format!("{BASE}.previous_keys[{i}].file"), e))?,
        );
    }
    KeyRing::new(current, previous).map(Some).map_err(|e| {
        // `KeyRing::new` only ever reports a duplicate among the previous
        // keys (the current key is checked first), so the id locates the
        // offending entry.
        let path = match &e {
            KekError::DuplicateId(id) => previous_specs
                .iter()
                .position(|(prev_id, _)| prev_id == id)
                .map(|i| format!("{BASE}.previous_keys[{i}].id"))
                .unwrap_or_else(|| BASE.to_string()),
            _ => BASE.to_string(),
        };
        invalid(path, e.to_string())
    })
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

/// Reads `typed_config.max_policy_staleness_seconds` (review H4): how old the
/// policy snapshot may get before virtual-key authentication fails closed.
/// `0` means 5 x `poll_interval`. An explicit value under 2 x `poll_interval`
/// is rejected, because a healthy replica's snapshot already ages up to
/// 1.25 x the interval between polls and would refuse traffic between them.
/// There is no "no bound" value: unset never means open.
fn parse_max_policy_staleness(
    config: &DynamicMessage,
    poll_interval: Duration,
) -> Result<Duration, ConfigError> {
    let secs = config
        .get_field_by_name("max_policy_staleness_seconds")
        .and_then(|v| v.as_u32())
        .unwrap_or(0);
    if secs == 0 {
        return Ok(poll_interval * 5);
    }
    let bound = Duration::from_secs(u64::from(secs));
    if bound < poll_interval * 2 {
        return Err(invalid(
            "typed_config.max_policy_staleness_seconds",
            format!(
                "must be at least 2 x poll_interval_seconds ({}s), or a healthy replica \
                 would refuse requests between two polls",
                (poll_interval * 2).as_secs()
            ),
        ));
    }
    Ok(bound)
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
    /// See [`parse_max_policy_staleness`].
    max_policy_staleness: Duration,
    /// One entry per `typed_config.jwt_providers[i]`,
    /// in config order. Each becomes one `JwtAuthenticator` appended to the
    /// chain after the virtual-key authenticator.
    jwt_providers: Vec<JwtProviderConfig>,
    /// Loaded `typed_config.tenant_credentials` key ring, if configured.
    credential_ring: Option<KeyRing>,
    /// What the per-serve [`ControlPlane`] is built from, as one-way digests.
    /// See [`BootInputs`].
    boot_inputs: BootInputs,
    /// `typed_config.chargeback_tags`; `None` attributes no tags. Not a boot
    /// input: each chain build applies its own, so a reload changes it.
    tag_policy: Option<proxy_observability::chargeback::TagPolicy>,
}

/// The singleton key under which each chain records the [`BootInputs`] its
/// [`ControlPlane`] was built from, beside the `ControlPlane` itself.
pub const BOOT_INPUTS_KEY: &str = "llmproxy.auth/boot_inputs";

/// The inputs the per-serve [`ControlPlane`] singleton fixes at its first
/// build: the HMAC secret it mints with, the bootstrap keys, the store, the
/// poll interval and the credential key ring. A reload reuses the singleton,
/// so a change to any of these cannot apply. Before this record existed the
/// request authenticator took a changed secret and the control plane did
/// not, which refused every key with 401 after a reload that logged success.
///
/// Each value is a SHA-256, so the record holds no second copy of a secret.
/// [`check_reload`] compares a reloaded config with it and refuses the whole
/// reload on a difference (AGENTS.md invariant 1).
#[derive(Clone, PartialEq, Eq)]
pub struct BootInputs {
    hmac_secret: [u8; 32],
    virtual_keys: [u8; 32],
    store: [u8; 32],
    poll_interval: Duration,
    tenant_credentials: Option<[u8; 32]>,
}

// Rust note: hand-written, not derived. A digest of a short HMAC secret can
// be brute-forced offline, so no digest is ever rendered.
impl std::fmt::Debug for BootInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootInputs")
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

impl BootInputs {
    /// The refusal for the first field `self` (reloaded) differs from
    /// `running` in, at its Envoy field path; the reason names the dialect
    /// field too. `None` when equal.
    fn refusal(&self, running: &BootInputs) -> Option<ConfigError> {
        let (field, dialect) = if self.hmac_secret != running.hmac_secret {
            (
                "typed_config.hmac_secret",
                " (the dialect's `auth.hmac_secret` / `auth.hmac_secret_file`)",
            )
        } else if self.virtual_keys != running.virtual_keys {
            ("typed_config.virtual_keys", " (the dialect's `auth.keys`)")
        } else if self.store != running.store {
            ("typed_config.store", " (the dialect's `auth.store`)")
        } else if self.poll_interval != running.poll_interval {
            ("typed_config.poll_interval_seconds", "")
        } else if self.tenant_credentials != running.tenant_credentials {
            (
                "typed_config.tenant_credentials",
                " (the dialect's `auth.tenant_credentials`)",
            )
        } else {
            return None;
        };
        Some(invalid(
            field,
            format!(
                "this field{dialect} is fixed at startup and cannot change on reload; restart \
                 the process to apply it"
            ),
        ))
    }
}

/// SHA-256 over `parts`, each length-prefixed so two different splits of
/// the same bytes cannot collide.
fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    for part in parts {
        context.update(&(part.len() as u64).to_be_bytes());
        context.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    out
}

fn store_digest(store: &StoreSpec) -> [u8; 32] {
    match store {
        StoreSpec::InMemory => digest_parts([b"in_memory".as_slice()]),
        StoreSpec::Persistent(path) => digest_parts([b"persistent".as_slice(), path.as_bytes()]),
        StoreSpec::Shared { url, namespace } => digest_parts([
            b"shared".as_slice(),
            url.as_bytes(),
            if namespace.is_some() { b"ns" } else { b"no-ns" },
            namespace.as_deref().unwrap_or_default().as_bytes(),
        ]),
    }
}

/// Refuses a reloaded `llmproxy.auth` config for the chain `scope` when it
/// would change an input the running [`ControlPlane`] fixed at startup (see
/// [`BootInputs`]), or when it no longer parses. Called before a snapshot is
/// published, so a refused reload leaves every worker on the previous one. A
/// `scope` with no running control plane yet is new and has nothing to
/// conflict with.
pub fn check_reload(
    config: &DynamicMessage,
    scope: &str,
    shared: &proxy_http::filter::SharedFactoryState,
) -> Result<(), ConfigError> {
    let reloaded = parse_config(config)?.boot_inputs;
    let Some(running) = shared
        .get(scope, BOOT_INPUTS_KEY)
        .and_then(|any| any.downcast::<BootInputs>().ok())
    else {
        return Ok(());
    };
    reloaded.refusal(&running).map_or(Ok(()), Err)
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
    /// `claim_tags` as `(claim, tag)` pairs; see
    /// [`JwtAuthenticator::with_claim_tags`].
    claim_tags: Vec<(String, String)>,
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
    /// The configured seed keys as `(kid, n, e)`, sorted by `kid`. Public
    /// key material, kept only so [`JwksSlotKey`] can tell two seeds apart.
    seed: Vec<(String, Vec<u8>, Vec<u8>)>,
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
        let mut discovery = parse_discovery(msg, &base)?;
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
            if let Some(d) = discovery.as_mut() {
                d.seed.push((kid.clone(), n.clone(), e.clone()));
            }
            key_set.insert(JwkRsaKey { kid, n, e });
        }
        if let Some(d) = discovery.as_mut() {
            d.seed.sort();
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
            claim_tags: parse_claim_tags(msg, &base)?,
        });
    }
    Ok(out)
}

/// Reads one provider's `claim_tags`. Each claim must be named and each tag
/// key valid and unique; [`check_claim_tags`] checks the keys against the
/// tag policy once both are parsed.
fn parse_claim_tags(
    msg: &DynamicMessage,
    base: &str,
) -> Result<Vec<(String, String)>, ConfigError> {
    let entries: Vec<prost_reflect::Value> = msg
        .get_field_by_name("claim_tags")
        .and_then(|v| v.as_list().map(<[_]>::to_vec))
        .unwrap_or_default();
    let mut out: Vec<(String, String)> = Vec::with_capacity(entries.len());
    for (j, entry) in entries.iter().enumerate() {
        let path = format!("{base}.claim_tags[{j}]");
        let entry = entry
            .as_message()
            .ok_or_else(|| invalid(&path, "must be a message"))?;
        let field = |name: &str| {
            entry
                .get_field_by_name(name)
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        };
        let (claim, tag) = (field("claim"), field("tag"));
        if claim.is_empty() {
            return Err(invalid(format!("{path}.claim"), "must not be empty"));
        }
        proxy_observability::chargeback::validate_key(&tag)
            .map_err(|reason| invalid(format!("{path}.tag"), reason))?;
        if let Some(first) = out.iter().position(|(_, t)| *t == tag) {
            return Err(invalid(
                format!("{path}.tag"),
                format!("duplicate tag `{tag}`; already set at index {first}"),
            ));
        }
        out.push((claim, tag));
    }
    Ok(out)
}

/// Refuses a claim tag the policy would always drop, and claim tags without
/// a policy, which would attribute nothing (AGENTS.md invariant 1).
fn check_claim_tags(
    providers: &[JwtProviderConfig],
    policy: Option<&proxy_observability::chargeback::TagPolicy>,
) -> Result<(), ConfigError> {
    for (i, provider) in providers.iter().enumerate() {
        let base = format!("typed_config.jwt_providers[{i}].claim_tags");
        if provider.claim_tags.is_empty() {
            continue;
        }
        let Some(policy) = policy else {
            return Err(invalid(
                base,
                "requires `chargeback_tags`; without it no tag is attributed",
            ));
        };
        for (j, (_, tag)) in provider.claim_tags.iter().enumerate() {
            if !policy.allows_key(tag) {
                return Err(invalid(
                    format!("{base}[{j}].tag"),
                    format!(
                        "tag `{tag}` is not in `chargeback_tags.allowed`, so it would always be dropped"
                    ),
                ));
            }
        }
    }
    Ok(())
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
        seed: Vec::new(),
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
/// One bootstrap key as [`BootInputs::virtual_keys`] digests it:
/// `(key_id, tenant, digest, revoked, tags as "key=value")`.
type BootKeyEntry = (String, String, Vec<u8>, bool, Vec<String>);

fn parse_config(config: &DynamicMessage) -> Result<AuthConfig, ConfigError> {
    let secret_bytes = parse_hmac_secret(config)?;
    let store_spec = parse_store(config)?;
    let poll_interval = parse_poll_interval(config);
    let max_policy_staleness = parse_max_policy_staleness(config, poll_interval)?;

    let mut key_set = KeySet::new();
    // Rust note: `HashMap<String, usize>` / `HashMap<Vec<u8>, usize>` remember
    // which earlier index first used a given `key_id`/digest, so the
    // duplicate error can name the SECOND (offending) index precisely, per
    // the duplicate-detection rule.
    let mut seen_key_ids: HashMap<String, usize> = HashMap::new();
    let mut seen_digests: HashMap<Vec<u8>, usize> = HashMap::new();
    // Every entry, for `BootInputs::virtual_keys`. Tags are flattened to
    // `key=value` strings, sorted (the map is ordered).
    let mut key_entries: Vec<BootKeyEntry> = Vec::new();

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

        if let Err(reason) = crate::auth::check_principal_id("key_id", &key_id) {
            return Err(invalid(
                format!("typed_config.virtual_keys[{i}].key_id"),
                reason,
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

        if let Err(reason) = crate::auth::check_principal_id("tenant", &tenant) {
            return Err(invalid(
                format!("typed_config.virtual_keys[{i}].tenant"),
                reason,
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

        let tags = crate::chargeback_tags::parse_key_tags(
            msg,
            &format!("typed_config.virtual_keys[{i}]"),
        )?;

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
        key_entries.push((
            key_id.clone(),
            tenant.clone(),
            digest.clone(),
            revoked,
            tags.iter().map(|(k, v)| format!("{k}={v}")).collect(),
        ));

        key_set.insert_digest(
            digest,
            KeyRecord {
                key_id: KeyId::new(key_id),
                tenant: TenantId::new(tenant),
                revoked,
                tags: Arc::new(tags),
            },
        );
    }

    let credential_ring = parse_tenant_credentials(config)?;
    // Tenant credentials are sealed rows in the control-plane store, so they
    // need a store that survives restarts: `persistent` (redb) or `shared`
    // (Redis). `in_memory` drops every row on restart, which would leave
    // tenants silently on the operator key (ADR-0007 decision 2), so it is
    // refused here, before any store is opened.
    if credential_ring.is_some()
        && !matches!(
            store_spec,
            StoreSpec::Persistent(_) | StoreSpec::Shared { .. }
        )
    {
        return Err(invalid(
            "typed_config.tenant_credentials",
            TENANT_CREDENTIALS_NEED_DURABLE_STORE,
        ));
    }

    // Sorted so reordering the same keys is not a change; `key_id` is unique.
    key_entries.sort();
    let boot_inputs = BootInputs {
        hmac_secret: digest_parts([secret_bytes.as_slice()]),
        // Bootstrap tags live in the per-serve control plane's key set, so a
        // reload that changes them is refused like any other key change.
        virtual_keys: digest_parts(key_entries.iter().flat_map(
            |(key_id, tenant, digest, revoked, tags)| {
                [
                    key_id.as_bytes(),
                    tenant.as_bytes(),
                    digest.as_slice(),
                    if *revoked { b"revoked" } else { b"live" },
                ]
                .into_iter()
                .chain(tags.iter().map(String::as_bytes))
            },
        )),
        store: store_digest(&store_spec),
        poll_interval,
        tenant_credentials: credential_ring.as_ref().map(KeyRing::fingerprint),
    };

    let jwt_providers = parse_jwt_providers(config)?;
    let tag_policy = crate::chargeback_tags::parse_policy(config)?;
    check_claim_tags(&jwt_providers, tag_policy.as_ref())?;
    Ok(AuthConfig {
        secret_bytes,
        bootstrap_keys: key_set,
        store_spec,
        poll_interval,
        max_policy_staleness,
        jwt_providers,
        credential_ring,
        boot_inputs,
        tag_policy,
    })
}

/// The singleton key under which each chain keeps its [`JwksRegistry`].
const JWKS_REGISTRY_KEY: &str = "llmproxy.auth/jwks";

/// Everything that decides what a discovery provider's snapshot holds. Two
/// builds with equal keys share one snapshot; the log label is left out, so
/// reordering providers on a reload keeps their snapshots.
#[derive(PartialEq, Eq, Hash)]
struct JwksSlotKey {
    discovery_url: String,
    expected_issuer: Option<String>,
    interval: Duration,
    ca_pem: Option<Vec<u8>>,
    seed: Vec<(String, Vec<u8>, Vec<u8>)>,
}

/// One chain's discovery snapshots. The filter chain is built once per
/// worker and again on every reload, and each build must read the snapshot
/// that the one refresher thread for that provider publishes to; a snapshot
/// built per `create` reaches only the build that started the refresher.
///
/// Entries are `Weak`, like the refresher's own handle: a snapshot lives as
/// long as some built chain uses it. A reload that keeps the provider finds
/// the live snapshot (the old chains are still built while the new ones are),
/// so its keys and its refresher carry over. A reload that changes or drops
/// the provider lets the old snapshot go with the old chains, and its
/// refresher stops (see `start_jwks_refresher`), so reloads do not pile up
/// refresher threads.
#[derive(Default)]
struct JwksRegistry {
    slots: std::sync::Mutex<HashMap<JwksSlotKey, Weak<arc_swap::ArcSwap<JwksSnapshot>>>>,
}

impl JwksRegistry {
    /// The live snapshot for `key`, or a new one seeded with `seed` and fed
    /// by a newly started refresher.
    fn snapshot(
        &self,
        key: JwksSlotKey,
        seed: JwtKeySet,
        spec: RefreshSpec,
    ) -> Arc<arc_swap::ArcSwap<JwksSnapshot>> {
        let mut slots = self.slots.lock().expect("JWKS registry mutex poisoned");
        if let Some(live) = slots.get(&key).and_then(Weak::upgrade) {
            return live;
        }
        slots.retain(|_, slot| slot.strong_count() > 0);
        let snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(JwksSnapshot::discovering(
            seed,
        ))));
        crate::jwks_refresh::start_jwks_refresher(Arc::clone(&snapshot), spec);
        slots.insert(key, Arc::downgrade(&snapshot));
        snapshot
    }
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
            max_policy_staleness,
            jwt_providers,
            credential_ring,
            boot_inputs,
            tag_policy,
        } = parse_config(config)?;

        // A reload is refused before publish when these differ (see
        // `check_reload`); this is the backstop for a build that skipped that
        // check. Failing the chain build is loud, where reusing the running
        // control plane would refuse every key under a split secret.
        if let Some(running) = ctx
            .get(BOOT_INPUTS_KEY)
            .and_then(|any| any.downcast::<BootInputs>().ok())
        {
            if let Some(refusal) = boot_inputs.refusal(&running) {
                return Err(refusal);
            }
        }

        if matches!(store_spec, StoreSpec::Shared { .. }) && !node_id_is_configured(ctx.node_id()) {
            return Err(invalid(
                "typed_config.store.shared",
                SHARED_STORE_NEEDS_NODE_ID,
            ));
        }

        // The stats registry a shared store exports its policy-load cost to.
        // Looked up before `get_or_try_init`: its closure runs under the
        // singleton map's lock, which `get` also takes.
        let stats_registry = ctx
            .shared
            .get("", crate::usage_filter::STATS_REGISTRY_KEY)
            .and_then(|any| any.downcast::<proxy_observability::stats::Registry>().ok());

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
        // Corollary: because the slot is per-SERVE and a SIGHUP reload reuses
        // the same `SharedFactoryState`, the store -- like the HMAC secret,
        // the bootstrap keys, the poll interval and the key ring -- is fixed
        // at the first build. A reload that changes one is refused before
        // publish (`check_reload`, against the `BootInputs` recorded below);
        // changing it takes a restart.
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
                report_store_kind(
                    store_spec.kind(),
                    ctx.node_id(),
                    &ctx.stat_prefix,
                    stats_registry.as_ref(),
                );
                let mut lease_store: Option<Arc<dyn LeaseStore>> = None;
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
                        let open = || match &namespace {
                            Some(ns) => RedisControlPlaneStore::open_with_namespace(&url, ns),
                            None => RedisControlPlaneStore::open(&url),
                        };
                        // Stream leases go to the same Redis and namespace as
                        // the counters (ADR-0006 amendment E). A second
                        // handle, so the lease publisher only ever opens its
                        // own lane's connection.
                        lease_store = open()
                            .ok()
                            .map(|leases| Arc::new(leases) as Arc<dyn LeaseStore>);
                        let store = open().map(|store| match &stats_registry {
                            Some(registry) => {
                                store.with_load_stats(Arc::clone(registry), &ctx.stat_prefix)
                            }
                            None => store,
                        });
                        Box::new(store.map_err(|e| {
                            invalid(
                                "typed_config.store.shared.url",
                                format!("could not open the shared control-plane store: {e}"),
                            )
                        })?)
                    }
                };
                let secret = HmacSecret::new(&secret_bytes);
                // The fingerprint key derives from `hmac_secret` (ADR-0007
                // decision 2), so the ring and the secret bytes travel together.
                let credential_keys =
                    credential_ring.map(|ring| CredentialKeys::new(ring, &secret_bytes));
                let cp = ControlPlane::new_with_credential_keys(
                    store,
                    secret,
                    bootstrap_keys,
                    credential_keys,
                )
                .map_err(|e| {
                    invalid(
                        "typed_config",
                        format!("control-plane snapshot could not be built: {e}"),
                    )
                })?;
                let cp = match lease_store {
                    Some(leases) => cp.with_lease_store(leases),
                    None => cp,
                };
                // Start the policy poller HERE, not in `main.rs` --
                // `main.rs` never holds a `ControlPlane` handle at all (this
                // `get_or_try_init` closure is the one place a fresh
                // `ControlPlane` gets built, per (scope, TYPE_URL) singleton,
                // for the whole serve), and `start_policy_poller` needs an
                // `Arc<ControlPlane>` to hand its background thread a `Weak`
                // -- so `cp` is wrapped in `Arc` here, one line earlier than
                // it otherwise would be, purely to make that call possible.
                //
                // Same per-serve pinning as the store and the secret above:
                // the poller keeps this interval for the whole serve, so a
                // reload that changes `poll_interval_seconds` is refused.
                let cp = Arc::new(cp);
                cp.start_policy_poller(poll_interval);
                Ok(cp as Arc<dyn std::any::Any + Send + Sync>)
            })?
            .downcast::<ControlPlane>()
            .expect("auth control-plane singleton is always a ControlPlane");
        // Recorded on the first build only, after the control plane exists,
        // so a failed first build leaves nothing for a later reload to be
        // compared against.
        ctx.get_or_try_init(BOOT_INPUTS_KEY, || {
            Ok(Arc::new(boot_inputs) as Arc<dyn std::any::Any + Send + Sync>)
        })?;
        // The chain's rate card lives in this store. If the usage filter was
        // built before this one (the lowering does not fix their relative
        // order), it could not find the store, so link it from this side.
        // Idempotent: a registry that is already linked ignores the call.
        if let Some(registry) = ctx.get(crate::usage_filter::TYPE_URL).and_then(|registry| {
            registry
                .downcast::<crate::usage_filter::PricingRegistry>()
                .ok()
        }) {
            registry.attach_control_plane(&control_plane, "typed_config")?;
        }
        // Every worker's build sets the bound, so a reload that changes it
        // takes effect; they all write the same value.
        control_plane
            .freshness()
            .set_max_staleness(max_policy_staleness);
        // Looked up outside `get_or_try_init`'s closure: that closure runs
        // under the singleton map's lock, which `get` also takes.
        let stats_registry = ctx
            .shared
            .get("", crate::usage_filter::STATS_REGISTRY_KEY)
            .and_then(|any| any.downcast::<proxy_observability::stats::Registry>().ok());
        if let Some(registry) = &stats_registry {
            control_plane.export_snapshot_age(Arc::clone(registry), &ctx.stat_prefix);
        }
        // JWT principals do not verify against the control-plane snapshot,
        // so their trace-export opt-in and provider credentials are read
        // through this, from the same snapshot and under the same staleness
        // bound as virtual keys.
        let tenant_facts = Arc::new(crate::auth::TenantFacts::new(
            control_plane.handle(),
            control_plane.freshness(),
            stats_registry,
        ));
        let authenticator: Box<dyn Authenticator> = Box::new(
            VirtualKeyAuthenticator::new(HmacSecret::new(&secret_bytes), control_plane.handle())
                .with_freshness(control_plane.freshness()),
        );
        // Static providers seed once and never change, so each build may
        // hold its own copy. Discovery providers share one snapshot per
        // provider through the chain's registry: built after the control
        // plane so a failed build starts no refresher.
        let jwks_registry = ctx
            .get_or_try_init(JWKS_REGISTRY_KEY, || {
                Ok(Arc::new(JwksRegistry::default()) as Arc<dyn std::any::Any + Send + Sync>)
            })?
            .downcast::<JwksRegistry>()
            .expect("the JWKS registry singleton is always a JwksRegistry");
        let mut jwt_snapshots = Vec::with_capacity(jwt_providers.len());
        let mut jwt_validations = Vec::with_capacity(jwt_providers.len());
        for (i, provider) in jwt_providers.into_iter().enumerate() {
            let JwtProviderConfig {
                keys,
                validation,
                discovery,
                claim_tags,
            } = provider;
            match discovery {
                Some(d) => {
                    let key = JwksSlotKey {
                        discovery_url: d.url.clone(),
                        expected_issuer: validation.issuer.clone(),
                        interval: d.interval,
                        ca_pem: d.ca_pem.clone(),
                        seed: d.seed,
                    };
                    let spec = RefreshSpec {
                        discovery_url: d.url,
                        expected_issuer: validation.issuer.clone(),
                        interval: d.interval,
                        ca_pem: d.ca_pem,
                        label: format!("jwt_providers[{i}]"),
                    };
                    let snapshot = jwks_registry.snapshot(key, keys, spec);
                    jwt_snapshots.push((snapshot, Some(d.interval * STALE_AFTER_MISSED)));
                }
                None => {
                    let snapshot =
                        Arc::new(arc_swap::ArcSwap::new(Arc::new(JwksSnapshot::seeded(keys))));
                    jwt_snapshots.push((snapshot, None));
                }
            }
            jwt_validations.push((validation, claim_tags));
        }
        // One chain per (filter config, listener), shared by every per-stream
        // instance below via `Arc::clone` -- see `token_limit_filter`'s
        // `TokenLimitFilterFactory::create` for the same one-store-per-listener
        // shape. The virtual-key authenticator is always first
        // (`Bearer llmp_...` is its territory); each configured JWT provider
        // follows in config order and claims every other `Bearer` value as a
        // JWT, so the first JWT provider in order decides every JWT outcome.
        let mut authenticators: Vec<Box<dyn Authenticator>> = Vec::new();
        authenticators.push(authenticator);
        for ((snapshot, max_stale), (validation, claim_tags)) in
            jwt_snapshots.into_iter().zip(jwt_validations)
        {
            authenticators.push(Box::new(
                JwtAuthenticator::new_shared(snapshot, validation, max_stale)
                    .with_tenant_facts(Arc::clone(&tenant_facts))
                    .with_claim_tags(claim_tags),
            ));
        }
        let chain = Arc::new(AuthenticatorChain::new(authenticators));
        let tagging = tag_policy.map(|policy| {
            Arc::new(crate::chargeback_tags::Tagging::new(
                policy,
                ctx.shared
                    .get("", crate::usage_filter::STATS_REGISTRY_KEY)
                    .and_then(|any| any.downcast::<proxy_observability::stats::Registry>().ok()),
            ))
        });
        Ok(Box::new(AuthFilterInstanceFactory { chain, tagging }))
    }
}

struct AuthFilterInstanceFactory {
    chain: Arc<AuthenticatorChain>,
    tagging: Option<Arc<crate::chargeback_tags::Tagging>>,
}

impl FilterInstanceFactory for AuthFilterInstanceFactory {
    fn create_filter(&self) -> Box<dyn HttpFilter> {
        Box::new(AuthFilterInstance {
            chain: Arc::clone(&self.chain),
            tagging: self.tagging.clone(),
        })
    }
}

/// Per-stream instance. Holds only the shared chain -- there is no
/// per-request state to carry between callbacks, because (unlike
/// `token_limit_filter`) authentication has no encode-side half.
struct AuthFilterInstance {
    chain: Arc<AuthenticatorChain>,
    /// `typed_config.chargeback_tags`; `None` attributes no tags and never
    /// reads the tag header.
    tagging: Option<Arc<crate::chargeback_tags::Tagging>>,
}

impl AuthFilterInstance {
    /// The single call site for the identical-on-the-wire 401 -- see the
    /// module doc's "wire response is identical" section. `details` is the
    /// only thing allowed to vary between callers of this function.
    fn deny(&self, cb: &mut dyn DecoderCallbacks, details: &str) {
        cb.stream_info().auth.denied = true;
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
                // Tags are resolved only for an authenticated request, and
                // from this principal's own key metadata, so a request can
                // carry only tags its own tenant's key or its own header set.
                let tags = match &self.tagging {
                    Some(tagging) => tagging.resolve(
                        &principal.key_tags,
                        &principal.withheld_tags,
                        &mut headers.headers,
                    ),
                    None => Default::default(),
                };
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
                        user_id: principal.user_id.clone(),
                        policy_generation: principal.policy_generation,
                        trace_export: principal.trace_export,
                        denied: false,
                        tags,
                    };
                    // Hand-off of the set the key was verified against, so the
                    // router never reads the snapshot itself. A request keeps
                    // the set it was admitted with (ADR-0007 decision 4).
                    info.tenant_credentials = principal.tenant_credentials.clone();
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
            // `crate::jwt_auth::JwtAuthenticator`'s rejection reasons. Each
            // configured JWT provider is pushed onto this filter's chain
            // after the virtual-key authenticator (see the factory above), so
            // each reason gets its own `details` string.
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
            // Fail closed on a stale policy snapshot (review H4). 503, not
            // 401: the store is the problem, not necessarily the credential,
            // and a client should retry rather than discard its key.
            AuthOutcome::Rejected(AuthError::PolicyStale) => {
                // No identity was established either (ADR-0011 decision 3).
                cb.stream_info().auth.denied = true;
                cb.send_local_reply(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "service unavailable",
                    None,
                    "auth_policy_stale",
                );
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
    use proxy_credentials::{TenantCredential, TenantCredentialSet, TenantSecret};
    use proxy_http::filter::{BufferedBody, EncoderCallbacks, HeaderMutationFn, PerRouteConfig};
    use proxy_http::stream_info::StreamInfo;

    use crate::control::test_snapshot_handle;

    mod chargeback;
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

    #[test]
    fn over_long_key_id_or_tenant_is_rejected_naming_its_path() {
        let digest = digest_hex(b"secret", "llmp_x");
        let at_bound = "a".repeat(128);
        parse_config(&authentication(
            inline_secret("secret"),
            vec![virtual_key(&at_bound, &at_bound, &digest, false)],
        ))
        .expect("ids at the bound load");
        for (key, tenant, path) in [
            (
                "k".repeat(129),
                "t".to_string(),
                "typed_config.virtual_keys[0].key_id",
            ),
            (
                "k".to_string(),
                "t".repeat(129),
                "typed_config.virtual_keys[0].tenant",
            ),
        ] {
            let err = parse_config(&authentication(
                inline_secret("secret"),
                vec![virtual_key(&key, &tenant, &digest, false)],
            ))
            .expect_err("over-long id must be rejected");
            match err {
                ConfigError::InvalidValue { field_path, .. } => assert_eq!(field_path, path),
                other => panic!("expected InvalidValue, got {other:?}"),
            }
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
            include_routing_headers_in_response: false,
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
                tags: Default::default(),
            },
        );
        let authenticator: Box<dyn Authenticator> = Box::new(VirtualKeyAuthenticator::new(
            HmacSecret::new(secret_bytes),
            test_snapshot_handle(key_set),
        ));
        AuthFilterInstance {
            chain: Arc::new(AuthenticatorChain::new(vec![authenticator])),
            tagging: None,
        }
    }

    // 11: a valid key -> Continue, no local reply, stream_info().auth carries
    // tenant, key_id and user.
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
        // The virtual key is the user identity (one key per user).
        assert_eq!(info.auth.user_id.as_deref(), Some("key-1"));
    }

    // 11a: the request is stamped with the policy generation of the snapshot
    // that verified its key, so its record names the policy it was admitted
    // under. A second write must move the stamp: a constant would also pass a
    // single request.
    #[test]
    fn an_admitted_request_carries_the_policy_generation_that_verified_it() {
        let cp = ControlPlane::new(
            Box::new(crate::control::InMemoryControlPlaneStore::new()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let tenant = TenantId::new("tenant-a");
        cp.create_tenant(&tenant).unwrap();
        let minted = cp.mint_key(&tenant, &KeyId::new("key-1")).unwrap();
        let mut filter = AuthFilterInstance {
            chain: Arc::new(AuthenticatorChain::new(vec![Box::new(
                VirtualKeyAuthenticator::new(HmacSecret::new(b"secret"), cp.handle()),
            )])),
            tagging: None,
        };
        let admit = |filter: &mut AuthFilterInstance| {
            let mut cb = TestCallbacks::new(Some(route_named("r1")));
            let bearer = format!("Bearer {}", minted.plaintext);
            let mut head = request_headers(Some(&bearer));
            assert_eq!(
                filter.decode_headers(&mut cb, &mut head, true),
                FilterHeadersStatus::Continue
            );
            let generation = cb.stream_info.borrow().auth.policy_generation;
            generation
        };

        let first = admit(&mut filter);
        assert_eq!(first, Some(cp.store().policy_generation().unwrap()));

        cp.create_tenant(&TenantId::new("tenant-b")).unwrap();
        let second = admit(&mut filter);
        assert_eq!(second, Some(cp.store().policy_generation().unwrap()));
        assert_ne!(first, second, "a policy write must move the stamp");
    }

    /// ADR-0008 decision 2: the tenant's trace-export opt-in reaches the
    /// request from the snapshot that verified its key. Only the opted-in
    /// tenant's request carries it, an opt-out reaches the next request
    /// without any other write, and a tenant with no row is not opted in.
    #[test]
    fn a_tenants_trace_export_opt_in_is_pinned_on_its_requests() {
        let cp = ControlPlane::new(
            Box::new(crate::control::InMemoryControlPlaneStore::new()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        let (a, b) = (TenantId::new("tenant-a"), TenantId::new("tenant-b"));
        cp.create_tenant(&a).unwrap();
        cp.create_tenant(&b).unwrap();
        let key_a = cp.mint_key(&a, &KeyId::new("key-a")).unwrap().plaintext;
        let key_b = cp.mint_key(&b, &KeyId::new("key-b")).unwrap().plaintext;
        let mut filter = AuthFilterInstance {
            chain: Arc::new(AuthenticatorChain::new(vec![Box::new(
                VirtualKeyAuthenticator::new(HmacSecret::new(b"secret"), cp.handle()),
            )])),
            tagging: None,
        };
        let opted_in = |filter: &mut AuthFilterInstance, key: &str| {
            let mut cb = TestCallbacks::new(Some(route_named("r1")));
            let mut head = request_headers(Some(&format!("Bearer {key}")));
            filter.decode_headers(&mut cb, &mut head, true);
            assert!(cb.local_reply.is_none());
            let pinned = cb.stream_info.borrow().auth.trace_export;
            pinned
        };

        assert!(!opted_in(&mut filter, &key_a), "no row is not consent");
        cp.set_trace_export(&a, true).unwrap();
        assert!(opted_in(&mut filter, &key_a));
        assert!(!opted_in(&mut filter, &key_b), "consent is per tenant");
        cp.set_trace_export(&a, false).unwrap();
        assert!(
            !opted_in(&mut filter, &key_a),
            "an opt-out reaches the next request"
        );
    }

    /// One snapshot with a key for `tenant-t` (which holds an `openrouter`
    /// credential) and a key for `tenant-u` (which holds none). Built by hand
    /// so these tests cover only the hand-off from snapshot to `StreamInfo`.
    /// The decrypt path that fills `tenant_credentials` in a real snapshot is
    /// covered in `control.rs`.
    fn filter_with_tenant_credentials() -> AuthFilterInstance {
        let secret = HmacSecret::new(b"secret");
        let mut keys = KeySet::new();
        keys.insert(
            &secret,
            "llmp_key-t",
            KeyRecord {
                key_id: KeyId::new("key-t"),
                tenant: TenantId::new("tenant-t"),
                revoked: false,
                tags: Default::default(),
            },
        );
        keys.insert(
            &secret,
            "llmp_key-u",
            KeyRecord {
                key_id: KeyId::new("key-u"),
                tenant: TenantId::new("tenant-u"),
                revoked: false,
                tags: Default::default(),
            },
        );
        let set = TenantCredentialSet::new(std::collections::HashMap::from([(
            "openrouter".to_string(),
            TenantCredential::Usable(TenantSecret::new("sk-or-test-secret".to_string())),
        )]));
        let snapshot = crate::control::ControlPlaneSnapshot {
            keys,
            policies: crate::model_authz::TenantPolicyMap::new(),
            key_budgets: std::collections::HashMap::new(),
            tenant_limits: std::collections::HashMap::new(),
            key_limits: std::collections::HashMap::new(),
            key_policies: std::collections::HashMap::new(),
            key_tenants: std::collections::HashMap::new(),
            tenant_credentials: std::collections::HashMap::from([(
                TenantId::new("tenant-t"),
                Arc::new(set),
            )]),
            generation: None,
            trace_export: std::collections::HashSet::new(),
        };
        let handle = Arc::new(arc_swap::ArcSwap::new(Arc::new(snapshot)));
        let authenticator: Box<dyn Authenticator> = Box::new(VirtualKeyAuthenticator::new(
            HmacSecret::new(b"secret"),
            handle,
        ));
        AuthFilterInstance {
            chain: Arc::new(AuthenticatorChain::new(vec![authenticator])),
            tagging: None,
        }
    }

    // 11b: a request authenticated as tenant-t gets tenant-t's credential set on
    // stream_info, taken from the snapshot that verified its key (ADR-0007 4).
    #[test]
    fn an_authenticated_tenant_gets_its_credential_set_on_stream_info() {
        let mut filter = filter_with_tenant_credentials();
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_key-t"));

        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        let info = cb.stream_info.borrow();
        assert_eq!(info.auth.tenant.as_deref(), Some("tenant-t"));
        let set = info
            .tenant_credentials
            .as_ref()
            .expect("tenant-t holds a credential set");
        assert!(matches!(
            set.get("openrouter"),
            Some(TenantCredential::Usable(_))
        ));
    }

    // 11c: a request authenticated as tenant-u, who has no credentials, gets
    // no set, so it stays in platform mode.
    #[test]
    fn another_tenant_gets_no_credential_set_on_stream_info() {
        let mut filter = filter_with_tenant_credentials();
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_key-u"));

        let status = filter.decode_headers(&mut cb, &mut head, true);

        assert_eq!(status, FilterHeadersStatus::Continue);
        let info = cb.stream_info.borrow();
        assert_eq!(info.auth.tenant.as_deref(), Some("tenant-u"));
        assert!(info.tenant_credentials.is_none());
    }

    // 11d: a rejected request never reaches stream_info with a credential set.
    #[test]
    fn a_rejected_request_leaves_tenant_credentials_none() {
        let mut filter = filter_with_tenant_credentials();
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        let mut head = request_headers(Some("Bearer llmp_wrong-key"));

        filter.decode_headers(&mut cb, &mut head, true);

        let reply = cb.local_reply.as_ref().expect("unknown key must be denied");
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert!(cb.stream_info.borrow().tenant_credentials.is_none());
    }

    // 11e: a JWT principal follows the virtual-key rule for its tenant
    // (ADR-0014 decision 2): tenant-t's JWT gets the very set tenant-t's key
    // gets, tenant-u's JWT stays in platform mode, and on a stale snapshot
    // tenant-t's JWT is refused with 503 like its key, never admitted with the
    // operator credential, while tenant-u's JWT is admitted as before.
    #[test]
    fn a_jwt_tenant_gets_the_credential_set_its_virtual_key_gets() {
        use crate::control::{ControlPlane, InMemoryControlPlaneStore};
        use crate::jwt_auth::{JwkRsaKey, JwtAuthenticator, JwtKeySet, JwtValidationConfig};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        let secret = HmacSecret::new(b"secret");
        let mut keys = KeySet::new();
        keys.insert(
            &secret,
            "llmp_key-t",
            KeyRecord {
                key_id: KeyId::new("key-t"),
                tenant: TenantId::new("tenant-t"),
                revoked: false,
                tags: Default::default(),
            },
        );
        let set = Arc::new(TenantCredentialSet::new(std::collections::HashMap::from([
            (
                "openrouter".to_string(),
                TenantCredential::Usable(TenantSecret::new("sk-or-test-secret".to_string())),
            ),
        ])));
        let snapshot = crate::control::ControlPlaneSnapshot {
            keys,
            policies: crate::model_authz::TenantPolicyMap::new(),
            key_budgets: std::collections::HashMap::new(),
            tenant_limits: std::collections::HashMap::new(),
            key_limits: std::collections::HashMap::new(),
            key_policies: std::collections::HashMap::new(),
            key_tenants: std::collections::HashMap::new(),
            tenant_credentials: std::collections::HashMap::from([(
                TenantId::new("tenant-t"),
                Arc::clone(&set),
            )]),
            generation: None,
            trace_export: std::collections::HashSet::new(),
        };
        let snapshot = Arc::new(arc_swap::ArcSwap::new(Arc::new(snapshot)));
        let virtual_key: Box<dyn Authenticator> = Box::new(VirtualKeyAuthenticator::new(
            HmacSecret::new(b"secret"),
            Arc::clone(&snapshot),
        ));
        let cp = ControlPlane::new(
            Box::new(InMemoryControlPlaneStore::new()),
            HmacSecret::new(b"secret"),
            KeySet::new(),
        )
        .unwrap();
        cp.freshness()
            .set_max_staleness(std::time::Duration::from_secs(3600));
        let key = jwt_test_key();
        let mut jwks = JwtKeySet::new();
        jwks.insert(JwkRsaKey {
            kid: "key-1".to_string(),
            n: URL_SAFE_NO_PAD.decode(&key.n_b64).expect("n"),
            e: URL_SAFE_NO_PAD.decode(&key.e_b64).expect("e"),
        });
        let jwt: Box<dyn Authenticator> = Box::new(
            JwtAuthenticator::new(
                jwks,
                JwtValidationConfig {
                    tenant_claim: "tenant".to_string(),
                    issuer: None,
                    audience: None,
                    leeway_seconds: None,
                    tenant_map: std::collections::HashMap::new(),
                    subject_claim: None,
                },
            )
            .with_tenant_facts(Arc::new(crate::auth::TenantFacts::new(
                snapshot,
                cp.freshness(),
                None,
            ))),
        );
        let mut filter = AuthFilterInstance {
            chain: Arc::new(AuthenticatorChain::new(vec![virtual_key, jwt])),
            tagging: None,
        };
        let send_as = |filter: &mut AuthFilterInstance, bearer: &str| {
            let mut cb = TestCallbacks::new(Some(route_named("r1")));
            let mut head = request_headers(Some(bearer));
            filter.decode_headers(&mut cb, &mut head, true);
            cb
        };
        let send = |filter: &mut AuthFilterInstance, tenant: &str| {
            let token = sign_test_jwt(key, "key-1", &jwt_claims(tenant, ""));
            send_as(filter, &jwt_bearer(&token))
        };

        let keyed = send_as(&mut filter, "Bearer llmp_key-t");
        let keyed_set = keyed.stream_info.borrow().tenant_credentials.clone();
        assert!(keyed_set.is_some_and(|keyed| Arc::ptr_eq(&keyed, &set)));
        let cb = send(&mut filter, "tenant-t");
        assert!(cb.local_reply.is_none());
        let jwt_set = cb
            .stream_info
            .borrow()
            .tenant_credentials
            .clone()
            .expect("tenant-t's JWT gets its set");
        assert!(Arc::ptr_eq(&jwt_set, &set), "the same set its key gets");
        let cb = send(&mut filter, "tenant-u");
        assert!(cb.local_reply.is_none());
        assert!(cb.stream_info.borrow().tenant_credentials.is_none());

        cp.freshness()
            .set_max_staleness(std::time::Duration::from_millis(1));
        std::thread::sleep(std::time::Duration::from_millis(5));
        let cb = send(&mut filter, "tenant-t");
        let reply = cb
            .local_reply
            .as_ref()
            .expect("refused on a stale snapshot");
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reply.details, "auth_policy_stale");
        assert!(cb.stream_info.borrow().tenant_credentials.is_none());
        let cb = send(&mut filter, "tenant-u");
        assert!(
            cb.local_reply.is_none(),
            "platform mode is admitted as before"
        );
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
                user_id: None,
                policy: Arc::new(Default::default()),
                tenant_credentials: None,
                policy_generation: None,
                trace_export: false,
                key_tags: Default::default(),
                withheld_tags: Vec::new(),
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

    // --- the policy staleness bound (review H4) ------------------------------

    /// Unset means 5 x the poll interval; an explicit value under 2 x the poll
    /// interval is refused with its dotted path; one at the floor is taken.
    #[test]
    fn max_policy_staleness_defaults_to_five_polls_and_refuses_less_than_two() {
        let mut config = authentication(inline_secret("secret"), vec![]);
        assert_eq!(
            parse_config(&config).unwrap().max_policy_staleness,
            Duration::from_secs(240)
        );
        config.set_field_by_name(
            "max_policy_staleness_seconds",
            prost_reflect::Value::U32(95),
        );
        match parse_config(&config) {
            Err(ConfigError::InvalidValue { field_path, .. }) => {
                assert_eq!(field_path, "typed_config.max_policy_staleness_seconds")
            }
            other => panic!("expected InvalidValue, got {other:?}"),
        }
        config.set_field_by_name(
            "max_policy_staleness_seconds",
            prost_reflect::Value::U32(96),
        );
        assert_eq!(
            parse_config(&config).unwrap().max_policy_staleness,
            Duration::from_secs(96)
        );
    }

    /// Through the real factory: the bound reaches the control plane, the age
    /// gauge is exported under the chain's `stat_prefix`, and once the
    /// snapshot is older than the bound a valid key gets 503
    /// `auth_policy_stale` instead of being admitted (fail closed).
    #[test]
    fn a_snapshot_past_the_bound_makes_the_filter_answer_503() {
        let config = authentication(inline_secret("operator-hmac-secret"), vec![]);
        let ctx = FactoryContext {
            stat_prefix: "ingress".to_string(),
            ..FactoryContext::default()
        };
        let registry = proxy_observability::stats::StatsControl::new(1).registry();
        ctx.shared
            .get_or_try_init("", "", crate::usage_filter::STATS_REGISTRY_KEY, || {
                Ok(Arc::clone(&registry) as Arc<dyn std::any::Any + Send + Sync>)
            })
            .unwrap();
        let factory = match AuthFilterFactory.create(&config, &ctx) {
            Ok(factory) => factory,
            Err(e) => panic!("valid config must build: {e:?}"),
        };
        let control_plane = ctx
            .get(TYPE_URL)
            .unwrap()
            .downcast::<ControlPlane>()
            .unwrap();
        assert_eq!(
            control_plane.freshness().max_staleness(),
            Some(Duration::from_secs(240))
        );
        assert!(
            proxy_observability::stats::prometheus_render::render(&registry)
                .contains("envoy_llmproxy_policy_snapshot_age_seconds{scope=\"ingress\"}"),
            "the age gauge is exported for the chain"
        );
        let minted = control_plane
            .mint_key(&TenantId::new("tenant-a"), &KeyId::new("k1"))
            .unwrap();
        let bearer = format!("Bearer {}", minted.plaintext);

        let mut filter = factory.create_filter();
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        filter.decode_headers(&mut cb, &mut request_headers(Some(&bearer)), true);
        assert!(cb.local_reply.is_none(), "a fresh snapshot admits the key");
        assert!(!cb.stream_info.borrow().auth.denied);

        // Stand in for an outage longer than the bound.
        control_plane
            .freshness()
            .set_max_staleness(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        let mut cb = TestCallbacks::new(Some(route_named("r1")));
        filter.decode_headers(&mut cb, &mut request_headers(Some(&bearer)), true);
        assert!(
            cb.stream_info.borrow().auth.denied,
            "no identity was established, so the record names `unauthenticated`"
        );
        let reply = cb
            .local_reply
            .expect("a stale snapshot must refuse the key");
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(reply.details, "auth_policy_stale");
    }

    // --- N replicas on a per-replica store (ADR-0006 addendum §5) ----------

    /// A context carrying `node_id` as the effective node id, the way
    /// `main.rs` builds one from `--service-node` or the bootstrap `node.id`.
    fn ctx_for_node(node_id: &str) -> FactoryContext {
        FactoryContext {
            shared: Arc::new(SharedFactoryState::for_node(node_id.to_string())),
            stat_prefix: "ingress".to_string(),
            ..FactoryContext::default()
        }
    }

    fn store_warnings(capture: &crate::control::log_capture::Capture) -> Vec<String> {
        capture
            .rendered_at_or_above(tracing::Level::WARN)
            .into_iter()
            .filter(|line| line.contains("auth.store is not shared"))
            .collect()
    }

    /// A configured node id with `in_memory` or `persistent` warns once per
    /// chain, naming the effect, and a second build of the chain (another
    /// worker, or a reload) does not repeat it.
    #[test]
    fn a_node_id_on_a_per_replica_store_warns_once_naming_the_effect() {
        let path = temp_db_path("store-warning");
        let path_str = path.to_str().unwrap().to_string();
        let base = || authentication(inline_secret("operator-hmac-secret"), vec![]);
        for (store, config) in [
            ("in_memory", with_in_memory_store(base())),
            ("persistent", with_persistent_store(base(), &path_str)),
        ] {
            let ctx = ctx_for_node("replica-a");
            let (capture, _guard) = crate::control::log_capture::Capture::start();
            for _ in 0..2 {
                if let Err(e) = AuthFilterFactory.create(&config, &ctx) {
                    panic!("{store}: valid config must build: {e:?}");
                }
            }
            let warnings = store_warnings(&capture);
            assert_eq!(
                warnings.len(),
                1,
                "{store}: exactly one warning: {warnings:?}"
            );
            let line = &warnings[0];
            assert!(
                line.contains("N replicas admit up to N times each limit"),
                "{store}: the warning names the effect: {line}"
            );
            assert!(
                line.contains("reaches only the replica that receives it"),
                "{store}: the warning names the rate card: {line}"
            );
            assert!(line.contains("node_id=replica-a"), "{store}: {line}");
            assert!(line.contains(&format!("store={store}")), "{store}: {line}");
            assert!(line.contains("stat_prefix=ingress"), "{store}: {line}");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// No node id configured: a single replica is the likely deployment, so
    /// the store warning stays silent (AGENTS.md "Fail-open controls": warn
    /// only where the control was meant to apply).
    #[test]
    fn no_node_id_means_no_store_warning() {
        let config = authentication(inline_secret("operator-hmac-secret"), vec![]);
        let (capture, _guard) = crate::control::log_capture::Capture::start();
        for ctx in [FactoryContext::default(), ctx_for_node("-")] {
            if let Err(e) = AuthFilterFactory.create(&config, &ctx) {
                panic!("valid config must build: {e:?}");
            }
        }
        assert!(store_warnings(&capture).is_empty());
    }

    /// A shared store is what a fleet should run, so a node id with it is
    /// silent. Called directly: building a shared store needs a Redis.
    #[test]
    fn a_node_id_on_the_shared_store_does_not_warn() {
        let (capture, _guard) = crate::control::log_capture::Capture::start();
        report_store_kind("shared", "replica-a", "ingress", None);
        assert!(store_warnings(&capture).is_empty());
    }

    /// `store: shared` with no configured node id is a load error at the
    /// store's dotted path, naming the fix. With a node id the refusal does
    /// not fire: the build gets as far as dialling the (unreachable) Redis.
    #[test]
    fn a_shared_store_without_a_node_id_is_refused() {
        let config = with_shared_store(
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            "redis://127.0.0.1:1/0",
        );
        for ctx in [FactoryContext::default(), ctx_for_node("-")] {
            match AuthFilterFactory.create(&config, &ctx) {
                Err(ConfigError::InvalidValue { field_path, reason }) => {
                    assert_eq!(field_path, "typed_config.store.shared");
                    assert!(reason.contains("--service-node"), "{reason}");
                    assert!(reason.contains("node.id"), "{reason}");
                }
                Err(other) => panic!("expected InvalidValue, got {other:?}"),
                Ok(_) => panic!("a shared store without a node id must be refused"),
            }
            assert!(ctx.get(TYPE_URL).is_none(), "no control plane is built");
        }
        if let Err(ConfigError::InvalidValue { field_path, reason }) =
            AuthFilterFactory.create(&config, &ctx_for_node("replica-a"))
        {
            assert!(
                !reason.contains("--service-node"),
                "a configured node id passes the check: {field_path}: {reason}"
            );
        }
    }

    /// The store kind is exported once per chain, labelled by node id, so an
    /// operator can see from metrics alone that a fleet's replicas each run
    /// their own store. An unconfigured id renders as `-`, never as the
    /// per-boot id, which would leave a new series after every restart.
    #[test]
    fn the_store_kind_is_exported_labelled_by_node_id() {
        let config = authentication(inline_secret("operator-hmac-secret"), vec![]);
        for (ctx, node_label) in [
            (ctx_for_node("replica-a"), "replica-a"),
            (
                FactoryContext {
                    stat_prefix: "ingress".to_string(),
                    ..FactoryContext::default()
                },
                "-",
            ),
        ] {
            let registry = proxy_observability::stats::StatsControl::new(1).registry();
            ctx.shared
                .get_or_try_init("", "", crate::usage_filter::STATS_REGISTRY_KEY, || {
                    Ok(Arc::clone(&registry) as Arc<dyn std::any::Any + Send + Sync>)
                })
                .unwrap();
            for _ in 0..2 {
                if let Err(e) = AuthFilterFactory.create(&config, &ctx) {
                    panic!("valid config must build: {e:?}");
                }
            }
            let rendered = proxy_observability::stats::prometheus_render::render(&registry);
            let series: Vec<&str> = rendered
                .lines()
                .filter(|line| line.starts_with("envoy_llmproxy_control_plane_store_info{"))
                .collect();
            assert_eq!(
                series,
                vec![format!(
                    "envoy_llmproxy_control_plane_store_info{{node_id=\"{node_label}\",\
                     scope=\"ingress\",store=\"in_memory\"}} 1"
                )
                .as_str()],
                "one series at 1, however many workers build the chain"
            );
        }
    }

    /// The JWKS registry keeps no snapshot alive on its own: once every
    /// chain using a discovery snapshot is gone, the next build gets a new
    /// one and the dead entry is pruned. A registry holding strong handles
    /// would keep every refresher a reload retired running for the life of
    /// the process. Builds that share a key share the snapshot; the
    /// multi-worker and reload e2e tests in `dialect_jwt_e2e.rs` own that.
    #[test]
    fn the_jwks_registry_releases_snapshots_no_chain_uses() {
        let registry = JwksRegistry::default();
        // Port 1 refuses at once, so the refreshers started here fail their
        // fetches quietly and stop once their snapshot is dropped.
        let slot = |interval_secs: u64| {
            let interval = Duration::from_secs(interval_secs);
            let url = "https://127.0.0.1:1/.well-known/openid-configuration".to_string();
            let key = JwksSlotKey {
                discovery_url: url.clone(),
                expected_issuer: None,
                interval,
                ca_pem: None,
                seed: Vec::new(),
            };
            let spec = RefreshSpec {
                discovery_url: url,
                expected_issuer: None,
                interval,
                ca_pem: None,
                label: "registry-test".to_string(),
            };
            (key, spec)
        };
        let live_slots = |registry: &JwksRegistry| registry.slots.lock().unwrap().len();

        let (key, spec) = slot(600);
        let retired = registry.snapshot(key, JwtKeySet::new(), spec);
        let retired_weak = Arc::downgrade(&retired);
        drop(retired);
        // The refresher upgrades its own `Weak` while a fetch runs, so wait
        // out the first (refused) fetch. Generous bound: only a handle held
        // forever fails this.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while retired_weak.strong_count() > 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "the registry must not keep a snapshot alive"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // A reload that changed the interval: a new slot, and the dead one
        // is pruned rather than left to accumulate.
        let (key, spec) = slot(300);
        let current = registry.snapshot(key, JwtKeySet::new(), spec);
        assert_eq!(live_slots(&registry), 1, "the dead slot was pruned");

        // The original config again, after its chains are gone: a fresh
        // snapshot, not the dropped one.
        let (key, spec) = slot(600);
        let rebuilt = registry.snapshot(key, JwtKeySet::new(), spec);
        assert!(!Arc::ptr_eq(&rebuilt, &current));
        assert_eq!(live_slots(&registry), 2);
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

    // --- `tenant_credentials` (ADR-0007 decision 2) -------------------------

    /// Writes a key file with the given mode and returns its path. This crate
    /// has no `tempfile` dependency; the name is process- and test-unique.
    fn key_file(name: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "llm-proxy-auth-filter-test-kek-{name}-{}",
            std::process::id()
        ));
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn descriptor(name: &str) -> prost_reflect::MessageDescriptor {
        proxy_api::descriptor_pool()
            .get_message_by_name(name)
            .unwrap_or_else(|| panic!("{name} is compiled into proxy-api"))
    }

    fn str_val(value: &str) -> prost_reflect::Value {
        prost_reflect::Value::String(value.to_string())
    }

    fn previous_key(id: &str, file: &str) -> prost_reflect::Value {
        let mut msg = DynamicMessage::new(descriptor("llmproxy.filters.v0.PreviousCredentialKey"));
        msg.set_field_by_name("id", str_val(id));
        msg.set_field_by_name("file", str_val(file));
        prost_reflect::Value::Message(msg)
    }

    /// `Authentication` with a `tenant_credentials` block; empty strings are
    /// left unset, as proto3 would.
    fn with_tenant_credentials(
        file: &str,
        id: &str,
        previous: Vec<prost_reflect::Value>,
    ) -> DynamicMessage {
        let mut block = DynamicMessage::new(descriptor("llmproxy.filters.v0.TenantCredentials"));
        block.set_field_by_name("encryption_key_file", str_val(file));
        block.set_field_by_name("encryption_key_id", str_val(id));
        block.set_field_by_name("previous_keys", prost_reflect::Value::List(previous));
        let mut config = authentication(inline_secret("operator-hmac-secret"), vec![]);
        config.set_field_by_name("tenant_credentials", prost_reflect::Value::Message(block));
        config
    }

    fn credentials_error_path(config: &DynamicMessage) -> String {
        match parse_tenant_credentials(config).expect_err("config must be rejected") {
            ConfigError::InvalidValue { field_path, .. } => field_path,
            other => panic!("expected InvalidValue, got {other:?}"),
        }
    }

    const KEK_BYTES: &[u8; 32] = b"0123456789abcdef0123456789abcdef";

    #[test]
    fn unset_tenant_credentials_parses_to_no_key_ring() {
        let config = authentication(inline_secret("s"), vec![]);
        assert!(parse_tenant_credentials(&config).unwrap().is_none());
    }

    #[test]
    fn a_valid_tenant_credentials_block_loads_current_and_previous_keys() {
        let current = key_file("valid-cur", KEK_BYTES, 0o600);
        let previous = key_file("valid-prev", b"fedcba9876543210fedcba9876543210", 0o400);
        let config = with_tenant_credentials(
            current.to_str().unwrap(),
            "kek-new",
            vec![previous_key("kek-old", previous.to_str().unwrap())],
        );
        let ring = parse_tenant_credentials(&config).unwrap().expect("ring");
        std::fs::remove_file(&current).ok();
        std::fs::remove_file(&previous).ok();
        // Seal under the current key, then check the ring also names both ids
        // through its Debug (which never prints key bytes).
        let sealed = crate::tenant_credential_crypto::seal(
            &ring,
            "t",
            "p",
            &crate::tenant_credential_crypto::TenantSecret::new("x".to_string()),
        )
        .unwrap();
        assert_eq!(sealed.key_id, "kek-new");
        assert!(format!("{ring:?}").contains("previous_count: 1"));
    }

    #[test]
    fn tenant_credentials_missing_or_empty_fields_fail_with_their_dotted_paths() {
        let file = key_file("fields", KEK_BYTES, 0o600);
        let f = file.to_str().unwrap();
        let base = "typed_config.tenant_credentials";
        assert_eq!(
            credentials_error_path(&with_tenant_credentials("", "kek", vec![])),
            format!("{base}.encryption_key_file")
        );
        assert_eq!(
            credentials_error_path(&with_tenant_credentials(f, "", vec![])),
            format!("{base}.encryption_key_id")
        );
        assert_eq!(
            credentials_error_path(&with_tenant_credentials(
                f,
                "kek",
                vec![previous_key("", f)]
            )),
            format!("{base}.previous_keys[0].id")
        );
        assert_eq!(
            credentials_error_path(&with_tenant_credentials(
                f,
                "kek",
                vec![previous_key("old", f), previous_key("older", "")]
            )),
            format!("{base}.previous_keys[1].file")
        );
        std::fs::remove_file(&file).ok();
    }

    #[test]
    fn tenant_credentials_key_file_problems_fail_at_load_without_echoing_bytes() {
        let base = "typed_config.tenant_credentials";
        let loose = key_file("loose", KEK_BYTES, 0o644);
        let short = key_file("short", &KEK_BYTES[..31], 0o600);
        let good = key_file("good", KEK_BYTES, 0o600);

        let config = with_tenant_credentials(loose.to_str().unwrap(), "kek", vec![]);
        assert_eq!(
            credentials_error_path(&config),
            format!("{base}.encryption_key_file")
        );
        let config = with_tenant_credentials(short.to_str().unwrap(), "kek", vec![]);
        let err = parse_tenant_credentials(&config).unwrap_err();
        assert!(!format!("{err:?}").contains("0123456789abcdef"));
        assert!(matches!(
            err,
            ConfigError::InvalidValue { ref field_path, .. }
                if field_path == &format!("{base}.encryption_key_file")
        ));
        let config = with_tenant_credentials("/nonexistent/llm-proxy-kek", "kek", vec![]);
        assert_eq!(
            credentials_error_path(&config),
            format!("{base}.encryption_key_file")
        );
        // A bad previous key names its own index.
        let config = with_tenant_credentials(
            good.to_str().unwrap(),
            "kek",
            vec![previous_key("old", loose.to_str().unwrap())],
        );
        assert_eq!(
            credentials_error_path(&config),
            format!("{base}.previous_keys[0].file")
        );
        for path in [loose, short, good] {
            std::fs::remove_file(path).ok();
        }
    }

    #[test]
    fn tenant_credentials_duplicate_key_id_fails_naming_the_previous_entry() {
        let a = key_file("dup-a", KEK_BYTES, 0o600);
        let b = key_file("dup-b", b"fedcba9876543210fedcba9876543210", 0o600);
        let config = with_tenant_credentials(
            a.to_str().unwrap(),
            "same",
            vec![previous_key("same", b.to_str().unwrap())],
        );
        assert_eq!(
            credentials_error_path(&config),
            "typed_config.tenant_credentials.previous_keys[0].id"
        );
        std::fs::remove_file(&a).ok();
        std::fs::remove_file(&b).ok();
    }

    #[test]
    fn parse_config_carries_the_key_ring_and_a_bad_block_stops_the_config() {
        let good = key_file("cfg-good", KEK_BYTES, 0o600);
        let config = with_persistent_store(
            with_tenant_credentials(good.to_str().unwrap(), "kek", vec![]),
            "/var/lib/llm-proxy/control-plane.redb",
        );
        assert!(parse_config(&config).unwrap().credential_ring.is_some());
        std::fs::remove_file(&good).ok();

        let config = with_persistent_store(
            with_tenant_credentials("/nonexistent/llm-proxy-kek", "kek", vec![]),
            "/var/lib/llm-proxy/control-plane.redb",
        );
        assert!(parse_config(&config).is_err());
    }

    // A key ring with no store, or with a store that loses credentials on
    // restart, is a load error at the block's own path.
    #[test]
    fn tenant_credentials_without_a_persistent_store_is_a_load_error() {
        let key = key_file("store-absent", KEK_BYTES, 0o600);
        let file = key.to_str().unwrap();

        let absent = with_tenant_credentials(file, "kek", vec![]);
        let explicit_in_memory = with_in_memory_store(with_tenant_credentials(file, "kek", vec![]));
        for (label, config) in [
            ("an absent store", absent),
            ("an explicit in_memory store", explicit_in_memory),
        ] {
            let err = match parse_config(&config) {
                Err(err) => err,
                Ok(_) => panic!("{label} must be rejected"),
            };
            match &err {
                ConfigError::InvalidValue { field_path, reason } => {
                    assert_eq!(
                        field_path, "typed_config.tenant_credentials",
                        "{label} must be rejected at the tenant_credentials block"
                    );
                    assert!(
                        reason.contains("require a durable store"),
                        "{label}: the reason must name the requirement; got {reason}"
                    );
                }
                other => panic!("{label}: expected InvalidValue, got {other:?}"),
            }
        }
        std::fs::remove_file(&key).ok();
    }

    #[test]
    fn tenant_credentials_with_a_persistent_store_loads() {
        let key = key_file("store-persistent", KEK_BYTES, 0o600);
        let config = with_persistent_store(
            with_tenant_credentials(key.to_str().unwrap(), "kek", vec![]),
            "/var/lib/llm-proxy/control-plane.redb",
        );
        let loaded = parse_config(&config).expect("a persistent store must load");
        std::fs::remove_file(&key).ok();
        assert!(loaded.credential_ring.is_some());
        assert!(matches!(loaded.store_spec, StoreSpec::Persistent(_)));
    }

    // `parse_config` only parses the URL and never opens a connection, so
    // this runs with no Redis.
    #[test]
    fn tenant_credentials_with_a_shared_store_loads() {
        let key = key_file("store-shared", KEK_BYTES, 0o600);
        let config = with_shared_store(
            with_tenant_credentials(key.to_str().unwrap(), "kek", vec![]),
            "redis://127.0.0.1:6390/0",
        );
        let loaded = parse_config(&config).expect("a shared store must load");
        std::fs::remove_file(&key).ok();
        assert!(loaded.credential_ring.is_some());
        assert!(matches!(loaded.store_spec, StoreSpec::Shared { .. }));
    }

    #[test]
    fn a_store_without_tenant_credentials_is_unaffected_by_the_check() {
        // No key ring means no credential rows, so no store is refused.
        for config in [
            authentication(inline_secret("operator-hmac-secret"), vec![]),
            with_in_memory_store(authentication(
                inline_secret("operator-hmac-secret"),
                vec![],
            )),
            with_shared_store(
                authentication(inline_secret("operator-hmac-secret"), vec![]),
                "redis://127.0.0.1:6390/0",
            ),
        ] {
            let loaded = parse_config(&config).expect("no tenant_credentials must load");
            assert!(loaded.credential_ring.is_none());
        }
    }

    // --- reload against the startup-fixed control plane ----------------------

    const RELOAD_SCOPE: &str = "listener 'l' filter_chains[0]";

    fn reload_ctx(shared: &Arc<SharedFactoryState>) -> FactoryContext {
        FactoryContext {
            shared: Arc::clone(shared),
            scope: RELOAD_SCOPE.to_string(),
            stat_prefix: "l".to_string(),
        }
    }

    fn two_key_config(secret: &str, revoked_b: bool, reversed: bool) -> DynamicMessage {
        let mut keys = vec![
            virtual_key(
                "key-a",
                "tenant-a",
                &digest_hex(secret.as_bytes(), "llmp_a"),
                false,
            ),
            virtual_key(
                "key-b",
                "tenant-b",
                &digest_hex(secret.as_bytes(), "llmp_b"),
                revoked_b,
            ),
        ];
        if reversed {
            keys.reverse();
        }
        authentication(inline_secret(secret), keys)
    }

    fn refused_field(result: Result<(), ConfigError>) -> String {
        match result {
            Err(ConfigError::InvalidValue { field_path, reason }) => {
                assert!(
                    reason.contains("restart"),
                    "reason must say to restart: {reason}"
                );
                field_path
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn check_reload_refuses_a_changed_secret_or_key_list_and_accepts_the_rest() {
        let shared = Arc::new(SharedFactoryState::default());
        let running = two_key_config("reload-secret", false, false);
        AuthFilterFactory
            .create(&running, &reload_ctx(&shared))
            .expect("first build must succeed");

        check_reload(&running, RELOAD_SCOPE, &shared).expect("an unchanged config reloads");
        check_reload(
            &two_key_config("reload-secret", false, true),
            RELOAD_SCOPE,
            &shared,
        )
        .expect("reordering the same keys is not a change");

        let secret = refused_field(check_reload(
            &two_key_config("rotated-secret", false, false),
            RELOAD_SCOPE,
            &shared,
        ));
        assert!(secret.starts_with("typed_config.hmac_secret"), "{secret}");
        let keys = refused_field(check_reload(
            &two_key_config("reload-secret", true, false),
            RELOAD_SCOPE,
            &shared,
        ));
        assert!(keys.starts_with("typed_config.virtual_keys"), "{keys}");
        let fewer = authentication(
            inline_secret("reload-secret"),
            vec![virtual_key(
                "key-a",
                "tenant-a",
                &digest_hex(b"reload-secret", "llmp_a"),
                false,
            )],
        );
        let removed = refused_field(check_reload(&fewer, RELOAD_SCOPE, &shared));
        assert!(
            removed.starts_with("typed_config.virtual_keys"),
            "{removed}"
        );

        // A chain with no running control plane has nothing to conflict with.
        check_reload(
            &two_key_config("rotated-secret", false, false),
            "listener 'new' filter_chains[0]",
            &shared,
        )
        .expect("a new chain builds its own control plane");
    }

    #[test]
    fn create_refuses_a_changed_secret_on_a_chain_that_is_already_built() {
        let shared = Arc::new(SharedFactoryState::default());
        AuthFilterFactory
            .create(
                &two_key_config("reload-secret", false, false),
                &reload_ctx(&shared),
            )
            .expect("first build must succeed");
        let rebuilt = AuthFilterFactory
            .create(
                &two_key_config("rotated-secret", false, false),
                &reload_ctx(&shared),
            )
            .map(|_| ());
        let field = refused_field(rebuilt);
        assert!(field.starts_with("typed_config.hmac_secret"), "{field}");
    }

    #[test]
    fn boot_inputs_debug_renders_no_digest() {
        let inputs = parse_config(&two_key_config("reload-secret", false, false))
            .expect("parses")
            .boot_inputs;
        let rendered = format!("{inputs:?}");
        let digest = inputs
            .hmac_secret
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert!(!rendered.contains(&digest), "{rendered}");
        assert!(
            !rendered.contains(&format!("{:?}", inputs.hmac_secret)),
            "{rendered}"
        );
    }
}
