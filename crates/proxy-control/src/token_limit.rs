//! Shared types for `llmproxy.token_limit`: who a limit applies to
//! ([`LimitKey`]), what it measures ([`LimitOn`], [`LimitRule`]), and the
//! admission outcome the filter turns into response headers
//! ([`LimitDecision`]).
//!
//! The counters themselves live in [`crate::window_counter`]: tier-3 window
//! counters that accumulate locally and reconcile through the configured
//! `auth.store` backend, and tier-4 stream gauges with per-replica leases
//! (ADR-0006, amendment of 2026-10-15). There is no per-request store call
//! on the admission path.
//!
//! # The central semantic: retrospective enforcement, never mid-stream cutoff
//!
//! Token usage is not known until a response completes — `proxy_filters::usage`'s
//! extractors only produce a [`TokenUsage`] at the end of a (possibly
//! streaming) exchange. So token limits are *retrospective*: a request is
//! admitted against usage **already accumulated**, and only once it finishes
//! is its own usage recorded. A request already in flight when its budget
//! runs out is never cut off; over-limit means the *next* request is denied.
//! Envoy AI Gateway's token-based rate limiting has the same shape, for the
//! same reason.
//!
//! # Fixed, epoch-aligned windows
//!
//! Limits reset on a fixed window boundary rather than draining continuously,
//! which matches provider `x-ratelimit-reset` semantics. Windows are aligned
//! to the Unix epoch (`floor(unix_time / length)`), so every replica names the
//! same window the same way; a caller's first window can be shorter than the
//! configured length.
//!
//! # Saturating arithmetic
//!
//! This is a billing path. Every combination of usage and accumulated totals
//! saturates, so an overflow can never wrap a customer's count to near zero.

use std::sync::Arc;
use std::time::Duration;

use crate::control::{WindowDimension, WindowKey};
use crate::token_usage::TokenUsage;

/// The identity a budget is tracked against: which route, and who the budget
/// belongs to (see [`LimitSubject`]).
///
/// Named fields let per-tenant usage queries enumerate keys across routes.
/// The subject type also ensures credentials are hashed before entering a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LimitKey {
    route: String,
    subject: LimitSubject,
}

/// Who a [`LimitKey`]'s budget belongs to. The variants are disjoint key
/// spaces enforced by the type. See
/// `token_limit_filter`'s module doc ("The two key spaces never overlap")
/// for why that separation is a security property, not a preference.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LimitSubject {
    /// An identity the proxy itself assigned (virtual keys).
    Tenant(String),
    /// No auth filter authenticated the stream, so the bucket is keyed on a
    /// digest of the credential the caller presented. See
    /// [`CredentialDigest`] -- a digest is the only thing this variant can
    /// hold; there is no way to construct it from a raw, unhashed value.
    Credential(CredentialDigest),
    /// The one bucket per route that unauthenticated credentials share once
    /// [`MAX_CLIENT_KEYED_WINDOWS`] client-keyed subjects are already tracked.
    CredentialOverflow,
    /// A tenant's control-plane limit (`PUT /tenants/{id}/limits`). One
    /// bucket per tenant across every route, and a key space separate from
    /// [`Self::Tenant`], whose buckets belong to a configured per-route rule
    /// and are what `GET /v1/usage` reports.
    TenantPolicy(String),
    /// A key's control-plane limit (`PUT /keys/{id}/limits`). Enforced in
    /// addition to its tenant's bucket, so a key only narrows.
    KeyPolicy(String),
    /// A keyed rule from `TokenLimit.rules`, route-independent. The string is
    /// the rule's canonical subject (key kind, key value, model scope);
    /// header values in it are already hashed.
    Rule(String),
    /// A keyed rule whose value the client chose (its address, or a header's
    /// hashed value). Rendered and stored like [`Self::Rule`], but capped
    /// like [`Self::Credential`]: past [`MAX_CLIENT_KEYED_WINDOWS`], new
    /// values share the rule's `overflow` bucket, itself a [`Self::Rule`].
    ClientRule { subject: String, overflow: String },
}

impl LimitKey {
    /// Build a key for an identity the proxy itself assigned -- see
    /// [`LimitSubject::Tenant`].
    pub fn for_tenant(route: &str, tenant: &str) -> Self {
        LimitKey {
            route: route.to_string(),
            subject: LimitSubject::Tenant(tenant.to_string()),
        }
    }

    /// Build a key for the fallback path: no authenticated tenant, so the
    /// bucket is keyed on a digest of the credential the caller presented.
    /// Takes the RAW credential and hashes it internally -- unlike the old
    /// `from_descriptors(&[("cred", hash_credential(..))])` shape, the call
    /// site cannot forget to hash before constructing the key. See
    /// [`CredentialDigest::hash`].
    pub fn for_credential(route: &str, raw_credential: &str) -> Self {
        LimitKey {
            route: route.to_string(),
            subject: LimitSubject::Credential(CredentialDigest::hash(raw_credential)),
        }
    }

    /// The bucket for a tenant's control-plane limit; see
    /// [`LimitSubject::TenantPolicy`]. Route-independent.
    pub fn for_tenant_policy(tenant: &str) -> Self {
        LimitKey {
            route: String::new(),
            subject: LimitSubject::TenantPolicy(tenant.to_string()),
        }
    }

    /// The bucket for a key's control-plane limit; see
    /// [`LimitSubject::KeyPolicy`]. Route-independent.
    pub fn for_key_policy(key_id: &str) -> Self {
        LimitKey {
            route: String::new(),
            subject: LimitSubject::KeyPolicy(key_id.to_string()),
        }
    }

    /// The bucket for a keyed rule's canonical `subject`; see
    /// [`LimitSubject::Rule`]. The caller hashes any secret-shaped part.
    pub fn for_rule(subject: String) -> Self {
        LimitKey {
            route: String::new(),
            subject: LimitSubject::Rule(subject),
        }
    }

    /// The bucket for a keyed rule's `subject` when the client chose its
    /// value; see [`LimitSubject::ClientRule`]. `overflow` names the bucket
    /// the rule's values share once the cap is full, and must be distinct
    /// from every `subject` the rule can produce.
    pub fn for_client_rule(subject: String, overflow: String) -> Self {
        LimitKey {
            route: String::new(),
            subject: LimitSubject::ClientRule { subject, overflow },
        }
    }

    /// The route name this key was bucketed under.
    pub fn route(&self) -> &str {
        &self.route
    }

    /// Who this key's budget belongs to.
    pub fn subject(&self) -> &LimitSubject {
        &self.subject
    }

    /// Whether this key is a [`LimitSubject::Tenant`] matching `tenant`
    /// exactly -- the shape the per-tenant usage query needs
    /// (enumerating every key belonging to one tenant, across routes)
    /// without building that query here.
    pub fn is_for_tenant(&self, tenant: &str) -> bool {
        matches!(&self.subject, LimitSubject::Tenant(t) if t == tenant)
    }
}

impl std::fmt::Display for LimitKey {
    /// Renders `route=<route>|tenant=<id>` or `route=<route>|cred=<hex
    /// digest>` -- unchanged from the pre-struct flattened-string rendering,
    /// because log lines and at least one test assert on this exact shape.
    /// Safe to log in both cases: a tenant id is an identifier the operator
    /// chose, not a secret, and [`LimitSubject::Credential`] can only ever
    /// hold an already-hashed [`CredentialDigest`] -- see that type's doc.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "route={}|", self.route)?;
        match &self.subject {
            LimitSubject::Tenant(tenant) => write!(f, "tenant={tenant}"),
            LimitSubject::Credential(digest) => write!(f, "cred={digest}"),
            LimitSubject::CredentialOverflow => f.write_str("cred=overflow"),
            // Key ids, like tenant ids, are operator-chosen identifiers.
            LimitSubject::TenantPolicy(tenant) => write!(f, "tenant-policy={tenant}"),
            LimitSubject::KeyPolicy(key_id) => write!(f, "key-policy={key_id}"),
            LimitSubject::Rule(subject) | LimitSubject::ClientRule { subject, .. } => {
                write!(f, "rule={subject}")
            }
        }
    }
}

/// A hashed credential. Constructible ONLY by hashing -- there is no
/// `From<String>`, no public tuple constructor, and no `new` that accepts an
/// unhashed value, so a raw credential cannot become a
/// [`LimitSubject::Credential`] without going through [`Self::hash`] first.
/// Callers must use [`Self::hash`] before a credential can become a subject.
///
/// `Debug` is derived rather than hand-rolled: it prints the hex digest, not
/// anything a raw credential could be recovered from, since a `CredentialDigest`
/// never holds anything but a digest to begin with.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialDigest(String);

impl CredentialDigest {
    /// A stable, non-cryptographic hash of a raw credential value, rendered
    /// as hex.
    ///
    /// This is not a security control against an attacker who already has the
    /// credential value — that isn't the threat model, and the value becomes
    /// neither more nor less usable for auth by being hashed. It exists so the
    /// credential never appears in cleartext anywhere a [`LimitKey`] could end
    /// up: a debug log, a metrics label, a future `%DYNAMIC_METADATA%`-style
    /// access-log field.
    ///
    /// # Why FNV-1a rather than `std`'s `DefaultHasher`
    ///
    /// `DefaultHasher` would be the obvious zero-dependency choice, and it is
    /// what this function used first. It is wrong here for one reason: `std`
    /// explicitly does **not** guarantee its algorithm is stable across Rust
    /// releases. That is harmless while every key is computed and compared
    /// inside one process — but a key's rendering is the subject of a window
    /// row in the shared store (`crate::window_counter`). Once a budget is
    /// shared, two proxies built against
    /// different toolchains would hash the same credential to different keys
    /// and each be handed a full budget — a quota silently multiplied by the
    /// fleet size, which is the exact failure the shared store was chosen to
    /// avoid in the first place.
    ///
    /// FNV-1a 64 is a frozen, published specification: same input, same
    /// output, forever, on any machine and any compiler. It costs about eight
    /// lines and no new crate — relevant because this workspace's dependency
    /// tree is already slated for review. Collision resistance is irrelevant
    /// here; stability is the requirement, and it is the one `DefaultHasher`
    /// does not offer.
    pub fn hash(raw: &str) -> Self {
        // FNV-1a, 64-bit. Rust note: `wrapping_mul` is the defined behavior of
        // the algorithm (it is specified modulo 2^64), not a guard against a
        // bug -- a plain `*` would panic on overflow in debug builds on the
        // first byte.
        const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut hash = FNV_OFFSET_BASIS;
        for byte in raw.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        CredentialDigest(format!("{hash:016x}"))
    }
}

impl std::fmt::Display for CredentialDigest {
    /// Renders the hex digest -- safe to log; see [`Self::hash`]'s doc for
    /// why this is FNV-1a rather than a reversible encoding.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which bucket of [`TokenUsage`] a [`LimitRule`] is measured against.
///
/// `Total` is not simply "the sum of `Input` and `Output`" as a matter of
/// convenience — it is defined, deliberately, as [`TokenUsage::total`], which
/// includes the cached and cache-creation buckets too. Those buckets are
/// priced differently from plain input/output but still consume the same
/// per-key budget; a limiter that dropped them from `Total` would let a
/// heavy-cache workload evade the cap it was supposed to enforce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitOn {
    /// [`TokenUsage::input_tokens`] only (excludes cached/cache-creation).
    Input,
    /// [`TokenUsage::output_tokens`] only.
    Output,
    /// [`TokenUsage::total`] — every bucket.
    Total,
}

/// One configured budget: how many (weighted) tokens are allowed on a given
/// [`LimitOn`] bucket per fixed [`window`](Self::window).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitRule {
    pub on: LimitOn,
    pub max_tokens: u64,
    pub window: Duration,
}

impl LimitKey {
    /// Whether the client chose this key's value (an unauthenticated
    /// credential digest, an address, a header value): the side of the key
    /// space that is capped.
    pub(crate) fn is_client_keyed(&self) -> bool {
        matches!(
            self.subject,
            LimitSubject::Credential(_) | LimitSubject::ClientRule { .. }
        )
    }

    /// The shared bucket this key folds into past the cap: the route's for a
    /// credential, the rule's for a client-keyed rule. Any other key is its
    /// own bucket.
    pub(crate) fn client_overflow(&self) -> LimitKey {
        let subject = match &self.subject {
            LimitSubject::Credential(_) => LimitSubject::CredentialOverflow,
            LimitSubject::ClientRule { overflow, .. } => LimitSubject::Rule(overflow.clone()),
            other => other.clone(),
        };
        LimitKey {
            route: self.route.clone(),
            subject,
        }
    }
}

impl LimitOn {
    /// The window-counter dimension this bucket is counted in.
    pub fn dimension(self) -> WindowDimension {
        match self {
            LimitOn::Input => WindowDimension::InputTokens,
            LimitOn::Output => WindowDimension::OutputTokens,
            LimitOn::Total => WindowDimension::TotalTokens,
        }
    }

    /// How much of `usage` this bucket counts. `Total` is
    /// [`TokenUsage::total`], cached and cache-creation buckets included.
    pub fn amount(self, usage: &TokenUsage) -> u64 {
        match self {
            LimitOn::Input => usage.input_tokens,
            LimitOn::Output => usage.output_tokens,
            LimitOn::Total => usage.total(),
        }
    }
}

impl LimitRule {
    /// The window this rule counts `now_secs` (Unix seconds) in.
    pub fn window_at(&self, now_secs: u64) -> WindowKey {
        WindowKey::containing(now_secs, self.window.as_secs().max(1))
    }
}

/// The outcome of an admission check.
///
/// Both variants carry the same "how does this look to the caller" shape a
/// provider-style rate limiter publishes (`limit` / `remaining` /
/// `reset_after`), plus `retry_after` on `Deny` — the HTTP header mapping lives in the filter, and the fields are named to make that
/// mapping mechanical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitDecision {
    Allow {
        limit: u64,
        remaining: u64,
        reset_after: Duration,
    },
    Deny {
        limit: u64,
        remaining: u64,
        reset_after: Duration,
        retry_after: Duration,
    },
}

impl LimitDecision {
    /// The decision for a window whose total is `used` against `limit`:
    /// admitted while `used < limit`. `reset_after` is the time left in
    /// `window` at `now_secs`, and a refusal's `retry_after` equals it.
    pub fn for_window(used: u64, limit: u64, window: WindowKey, now_secs: u64) -> Self {
        let reset_after = Duration::from_secs(window.end_secs().saturating_sub(now_secs));
        let remaining = limit.saturating_sub(used);
        if used < limit {
            LimitDecision::Allow {
                limit,
                remaining,
                reset_after,
            }
        } else {
            LimitDecision::Deny {
                limit,
                remaining,
                reset_after,
                retry_after: reset_after,
            }
        }
    }
}

/// Releases one admitted stream when dropped. The release handle remains
/// independent of a held lock while the stream is alive.
pub struct StreamLease {
    release: Arc<dyn LeaseRelease>,
    key: LimitKey,
}

/// Backend hook invoked exactly once when an admitted stream ends.
pub trait LeaseRelease: Send + Sync {
    fn release(&self, key: &LimitKey);
}

impl StreamLease {
    /// Build a lease from a backend release hook without holding its lock.
    pub fn new(key: LimitKey, release: Arc<dyn LeaseRelease>) -> Self {
        Self { release, key }
    }
}

impl Drop for StreamLease {
    fn drop(&mut self) {
        self.release.release(&self.key);
    }
}

/// One [`LimitKey`]'s current-window standing, shaped for the `GET
/// /v1/usage` endpoint.
///
/// This is a read-only *rendering* of the same numbers [`LimitDecision::Allow`]
/// already carries; it deliberately does NOT hold a [`LimitKey`] or anything
/// built from one — `token_limit_filter`'s usage endpoint renders this
/// straight into a JSON response body, and the module doc's rule ("never
/// echo a `LimitKey`... into the response body") is easiest to keep if the
/// type handed to that response can't violate it in the first place.
#[derive(Debug, Clone, PartialEq)]
pub struct TenantUsage {
    /// The route this budget is bucketed under — see [`LimitKey::route`].
    /// Safe to expose: a route name is operator-chosen config, not a secret.
    pub route: String,
    /// Weighted tokens consumed in the current window.
    pub used: f64,
    /// The configured cap for this window.
    pub limit: f64,
    /// `limit - used`, floored at zero — never negative, matching
    /// [`LimitDecision`]'s own `remaining` fields.
    pub remaining: f64,
    /// How long until the current window rolls over.
    pub reset_after: Duration,
}

/// The most distinct client-keyed keys ([`LimitSubject::Credential`] and
/// [`LimitSubject::ClientRule`], together) one counter tracks at once. A
/// bucket is a few hundred bytes, so this bounds the client-chosen side of
/// the map to a few megabytes.
pub const MAX_CLIENT_KEYED_WINDOWS: usize = 10_000;

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: u64, output: u64) -> TokenUsage {
        TokenUsage {
            input_tokens: input,
            output_tokens: output,
            ..Default::default()
        }
    }

    #[test]
    fn each_bucket_counts_only_its_own_tokens() {
        let usage = TokenUsage {
            input_tokens: 10,
            cached_tokens: 3,
            cache_creation_tokens: 2,
            output_tokens: 5,
        };
        assert_eq!(LimitOn::Input.amount(&usage), 10);
        assert_eq!(LimitOn::Output.amount(&usage), 5);
        // Cached and cache-creation tokens still count against a total cap,
        // so a heavy-cache workload cannot evade it.
        assert_eq!(LimitOn::Total.amount(&usage), usage.total());
        assert!(LimitOn::Total.amount(&usage) >= 20);
    }

    #[test]
    fn each_bucket_has_its_own_dimension() {
        assert_eq!(LimitOn::Input.dimension(), WindowDimension::InputTokens);
        assert_eq!(LimitOn::Output.dimension(), WindowDimension::OutputTokens);
        assert_eq!(LimitOn::Total.dimension(), WindowDimension::TotalTokens);
    }

    #[test]
    fn a_huge_usage_saturates_instead_of_wrapping() {
        let usage = TokenUsage {
            input_tokens: u64::MAX,
            output_tokens: u64::MAX,
            ..Default::default()
        };
        assert_eq!(LimitOn::Total.amount(&usage), u64::MAX);
    }

    #[test]
    fn rule_windows_are_epoch_aligned() {
        let rule = LimitRule {
            on: LimitOn::Total,
            max_tokens: 10,
            window: Duration::from_secs(60),
        };
        // 125 s past the epoch is 5 s into the window that starts at 120 s.
        let window = rule.window_at(125);
        assert_eq!(window.start_secs(), 120);
        assert_eq!(window.end_secs(), 180);
        assert_eq!(rule.window_at(179), window);
        assert_ne!(rule.window_at(180), window);
    }

    #[test]
    fn the_decision_admits_below_the_limit_and_refuses_at_it() {
        let window = WindowKey::containing(125, 60);
        assert_eq!(
            LimitDecision::for_window(20, 25, window, 125),
            LimitDecision::Allow {
                limit: 25,
                remaining: 5,
                reset_after: Duration::from_secs(55),
            }
        );
        assert_eq!(
            LimitDecision::for_window(30, 25, window, 125),
            LimitDecision::Deny {
                limit: 25,
                remaining: 0,
                reset_after: Duration::from_secs(55),
                retry_after: Duration::from_secs(55),
            }
        );
        assert!(matches!(
            LimitDecision::for_window(0, 0, window, 125),
            LimitDecision::Deny { .. }
        ));
    }

    #[test]
    fn a_credential_key_hashes_and_folds_into_its_route_overflow() {
        let key = LimitKey::for_credential("r1", "sk-secret");
        assert!(key.is_client_keyed());
        assert!(!key.to_string().contains("sk-secret"));
        let overflow = key.client_overflow();
        assert_eq!(overflow.route(), "r1");
        assert_eq!(overflow.to_string(), "route=r1|cred=overflow");
        assert!(!LimitKey::for_tenant("r1", "t").is_client_keyed());
        let _ = usage(1, 1);
    }
}
