//! Pure per-tenant model authorization. HTTP integration and config decoding
//! live in [`crate::model_authz_filter`].
//!
//! # Matching rule: exact match, or one trailing `*` glob — no regex
//!
//! A pattern is an exact name or a prefix ending in one `*`; the wildcard may
//! match zero characters. Config parsing rejects other wildcard forms, while
//! [`ModelPattern::matches`] remains total for directly constructed values.
//!
//! # `ModelAccess::All` vs `Only(vec![])`, restated
//!
//! The explicit enum distinguishes granting all models from denying all with
//! `Only(vec![])`; an absent tenant policy remains a separate state.

use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::TenantPolicy;

/// One configured model-name pattern. See the module doc's "Matching rule"
/// section.
///
/// Rust note: a newtype around `String`, not a bare `String` passed around --
/// same reasoning as [`crate::auth::TenantId`]/[`crate::auth::KeyId`]: a
/// pattern and a plain model name are easy to swap by accident at a call
/// site, and the newtype makes the compiler catch it instead of a reviewer.
#[derive(Clone, PartialEq, Eq)]
pub struct ModelPattern(String);

impl std::fmt::Debug for ModelPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ModelPattern").field(&self.0).finish()
    }
}

impl ModelPattern {
    /// Rust note: takes an owned `String`-like value rather than borrowing —
    /// every caller (config parsing, in `model_authz_filter`) already has an
    /// owned `String` handed back by `prost_reflect`, so there is nothing to
    /// avoid copying.
    pub fn new(pattern: impl Into<String>) -> Self {
        ModelPattern(pattern.into())
    }

    pub fn is_valid(pattern: &str) -> bool {
        !pattern.is_empty()
            && (pattern.matches('*').count() == 0
                || (pattern.matches('*').count() == 1 && pattern.ends_with('*')))
    }

    /// Exact match, or -- if this pattern ends in `*` -- a prefix match
    /// against everything before that `*`. See the module doc's "Matching
    /// rule" section.
    pub fn matches(&self, model: &str) -> bool {
        match self.0.strip_suffix('*') {
            Some(prefix) => model.starts_with(prefix),
            None => self.0 == model,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Per-tenant model authorization policy. See [`crate::auth::TenantPolicy`]'s
/// doc for why this is an explicit enum rather than a bare `Vec`, and the
/// module doc above for the `All` vs `Only(vec![])` distinction.
#[derive(Clone, PartialEq, Eq)]
pub enum ModelAccess {
    /// Every model is permitted. An explicit grant, never a default: "no
    /// policy configured" is `TenantPolicy::model_access == None`, which
    /// `llmproxy.model_authz` denies unless configured otherwise (review H4).
    All,
    /// Only a model matching at least one of these patterns is permitted. An
    /// EMPTY `Vec` here is not the same as `All` -- it denies every model for
    /// this tenant, which is a legitimate, deliberate policy.
    Only(Vec<ModelPattern>),
    /// The effective grant is `allow - deny`. Deny patterns take precedence.
    WithDeny {
        allow: Box<ModelAccess>,
        deny: Vec<ModelPattern>,
    },
}

impl std::fmt::Debug for ModelAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelAccess::All => write!(f, "All"),
            ModelAccess::Only(patterns) => f.debug_tuple("Only").field(patterns).finish(),
            ModelAccess::WithDeny { allow, deny } => f
                .debug_struct("WithDeny")
                .field("allow", allow)
                .field("deny", deny)
                .finish(),
        }
    }
}

impl ModelAccess {
    pub fn with_deny(self, deny: Vec<ModelPattern>) -> Self {
        if deny.is_empty() {
            self
        } else {
            Self::WithDeny {
                allow: Box::new(self),
                deny,
            }
        }
    }

    /// Whether `model` is permitted under this policy.
    pub fn permits(&self, model: &str) -> bool {
        match self {
            ModelAccess::All => true,
            ModelAccess::Only(patterns) => patterns.iter().any(|p| p.matches(model)),
            ModelAccess::WithDeny { allow, deny } => {
                allow.permits(model) && !deny.iter().any(|p| p.matches(model))
            }
        }
    }
}

/// tenant id -> that tenant's configured policy.
///
/// Built once, at filter-config time, from `typed_config` -- see
/// `model_authz_filter::parse_config` -- and shared via one `Arc` per
/// (filter config, listener) across every stream, exactly like
/// `token_limit_filter`'s `Arc<dyn BudgetStore>`. Keyed on a plain `String`,
/// not `crate::auth::TenantId`: the tenant identity crossing from the auth
/// filter arrives via `StreamInfo::auth.tenant: Option<String>` (see that
/// field's doc for why `proxy_http::StreamInfo` cannot carry the richer
/// type), so this map's key type matches what a lookup actually has in hand
/// at request time rather than requiring a pointless `TenantId::new` wrap.
///
/// Values are `Arc<TenantPolicy>`, not `TenantPolicy`, for the same reason
/// `Principal::policy` is: the hot path clones a pointer, not a `Vec` of
/// patterns, on every request.
pub type TenantPolicyMap = HashMap<String, Arc<TenantPolicy>>;

#[cfg(test)]
mod tests {
    use super::*;

    // --- ModelPattern::matches ------------------------------------------

    #[test]
    fn exact_pattern_matches_only_the_exact_name() {
        let p = ModelPattern::new("gpt-4o");
        assert!(p.matches("gpt-4o"));
        assert!(!p.matches("gpt-4o-mini"));
        assert!(!p.matches("gpt-4"));
    }

    #[test]
    fn trailing_glob_matches_the_prefix_and_the_bare_prefix_itself() {
        let p = ModelPattern::new("gpt-4*");
        assert!(p.matches("gpt-4o"));
        assert!(p.matches("gpt-4-turbo"));
        assert!(
            p.matches("gpt-4"),
            "the `*` also matches zero characters -- the bare prefix itself must match"
        );
        assert!(!p.matches("gpt-3.5-turbo"));
        assert!(!p.matches("claude-3"));
    }

    #[test]
    fn a_bare_star_matches_every_model() {
        let p = ModelPattern::new("*");
        assert!(p.matches("gpt-4o"));
        assert!(p.matches(""));
    }

    // --- ModelAccess::permits --------------------------------------------

    #[test]
    fn all_permits_every_model() {
        assert!(ModelAccess::All.permits("gpt-4o"));
        assert!(ModelAccess::All.permits("anything-at-all"));
    }

    #[test]
    fn only_permits_a_matching_pattern_and_denies_the_rest() {
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-4*")]);
        assert!(access.permits("gpt-4o"));
        assert!(!access.permits("claude-3"));
    }

    #[test]
    fn only_with_an_empty_pattern_list_denies_every_model() {
        let access = ModelAccess::Only(vec![]);
        assert!(!access.permits("gpt-4o"));
        assert!(
            !access.permits("anything"),
            "Only(vec![]) must deny everything -- it is NOT the same as All"
        );
    }

    #[test]
    fn deny_overrides_an_exact_or_glob_allow() {
        let access = ModelAccess::Only(vec![ModelPattern::new("gpt-*")]).with_deny(vec![
            ModelPattern::new("gpt-4o"),
            ModelPattern::new("gpt-5*"),
        ]);
        assert!(access.permits("gpt-4o-mini"));
        assert!(!access.permits("gpt-4o"));
        assert!(!access.permits("gpt-5"));
        assert!(!access.permits("claude-3"));
        assert_eq!(ModelAccess::All.with_deny(vec![]), ModelAccess::All);
    }
}
