//! A tenant's own provider credentials, as the request path sees them
//! (ADR-0007).
//!
//! The control plane decrypts stored rows into a [`TenantCredentialSet`] once
//! per snapshot rebuild. The auth filter hands the authenticated tenant's set
//! to the router through `StreamInfo::tenant_credentials`. The router never
//! reads the snapshot or the store.
//!
//! These types have their own crate because the router (`proxy-http`) and
//! the store (`proxy-control`) both name them, and neither of those crates
//! may depend on the other.

use std::collections::HashMap;
use std::sync::Arc;

pub use proxy_observability::records::CredentialSource;
use zeroize::Zeroizing;

/// Plaintext of one tenant credential.
///
/// No `Serialize`, and `Debug`/`Display` print `<redacted>`, so the value
/// cannot reach `config_dump`, admin responses, logs or records through a
/// derive. The buffer is zeroized on drop.
pub struct TenantSecret(Zeroizing<String>);

impl TenantSecret {
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The plaintext, for writing into the upstream request header only.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Debug for TenantSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::fmt::Display for TenantSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One stored credential after the snapshot rebuild tried to decrypt it.
#[derive(Debug)]
pub enum TenantCredential {
    Usable(TenantSecret),
    /// The row exists but could not be decrypted (unknown key id or a bad
    /// tag). It is kept rather than dropped so that the tenant fails closed
    /// with a local 503 instead of falling back to the platform credential.
    Unusable,
}

/// Every credential one tenant holds, keyed by provider name.
///
/// A tenant with at least one entry, usable or not, is in tenant mode, where no
/// attempt may use an operator credential.
#[derive(Debug)]
pub struct TenantCredentialSet {
    by_provider: HashMap<String, TenantCredential>,
    providers: Arc<[String]>,
}

impl TenantCredentialSet {
    pub fn new(by_provider: HashMap<String, TenantCredential>) -> Self {
        let mut providers: Vec<String> = by_provider.keys().cloned().collect();
        providers.sort();
        Self {
            by_provider,
            providers: providers.into(),
        }
    }

    pub fn get(&self, provider: &str) -> Option<&TenantCredential> {
        self.by_provider.get(provider)
    }

    /// Provider names this tenant holds a credential for, usable or not.
    /// The router passes this to host selection, so an aggregate never picks
    /// a member the tenant has no credential for.
    pub fn providers(&self) -> &Arc<[String]> {
        &self.providers
    }

    pub fn is_empty(&self) -> bool {
        self.by_provider.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SENTINEL: &str = "sk-or-v1-SENTINEL-do-not-print";

    #[test]
    fn secret_never_formats_its_plaintext() {
        let secret = TenantSecret::new(SENTINEL.to_owned());
        assert_eq!(secret.expose(), SENTINEL);
        assert!(!format!("{secret:?}").contains("SENTINEL"));
        assert!(!format!("{secret}").contains("SENTINEL"));
    }

    #[test]
    fn set_debug_hides_secrets_and_lists_providers_sorted() {
        let set = TenantCredentialSet::new(HashMap::from([
            (
                "openrouter".to_owned(),
                TenantCredential::Usable(TenantSecret::new(SENTINEL.to_owned())),
            ),
            ("anthropic".to_owned(), TenantCredential::Unusable),
        ]));
        assert!(!format!("{set:?}").contains("SENTINEL"));
        assert_eq!(&set.providers()[..], ["anthropic", "openrouter"]);
        assert!(matches!(
            set.get("anthropic"),
            Some(TenantCredential::Unusable)
        ));
        assert!(set.get("openai").is_none());
    }
}
