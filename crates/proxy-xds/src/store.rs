//! WP-20 increment 4a: SotW resource-set semantics (S8).
//!
//! **Pure logic. No protobuf, no I/O, no `proxy-config` edge.** Increment 2
//! isolated the ACK/NACK state machine because S8 conformance is testable
//! without a socket; this module is the same move for the other half of S8
//! that PLAN.md calls "the single likeliest place to write a plausible bug":
//! what a response's resource list actually *does* to the set already held.
//!
//! # The rule this encodes, quoting S8
//!
//! > SotW: LDS/CDS full-set semantics (absence = removal); **EDS/RDS absence
//! > != removal**.
//!
//! Five consequences that are easy to get subtly wrong, and each has its own
//! test below:
//!
//! 1. **`FullState` (LDS/CDS): a name the response does not carry is
//!    REMOVED.** An empty response removes everything already held.
//! 2. **`PerName` (RDS/EDS): a name the response does not carry is LEFT
//!    ALONE.** An empty response removes nothing -- the explicit mirror of
//!    rule 1, over the same fixture.
//! 3. **Static names are immune.** A name in `static_names` is never applied,
//!    never stored, and is reported in `shadowed_by_static` instead. Static
//!    and dynamic are two disjoint namespaces -- xDS manages only its own --
//!    so refusing a shadowed name must not disturb any other dynamic entry,
//!    including under a `FullState` response that removes everything else.
//!    Envoy's CDS reference draws the same line: "Any clusters that are
//!    statically defined within the Envoy configuration cannot be modified or
//!    removed via the CDS API."
//! 4. **`unchanged` vs `updated`.** A name already present whose value
//!    compares equal is `unchanged`, not `updated` -- a resource that did not
//!    change must not churn, which is what makes increment 4b's
//!    make-before-break swap cheap.
//! 5. **A duplicate name within one response is an error, and nothing is
//!    applied.** All-or-nothing, the same shape as S8's "discard entire
//!    response". Envoy's own tracker carries crashes on duplicate cluster
//!    names in a CDS response (issues #3214, #3987); refusing loudly is the
//!    deliberate improvement here.
//!
//! # Ordering is increment 4b's job, not this module's
//!
//! S8's apply ordering is `CDS -> EDS -> LDS -> RDS -> removes`: a caller
//! sequencing from an [`ApplyOutcome`] must apply `added`/`updated` before
//! `removed`, so a resource in flight between two types is never dropped by a
//! removal that runs first. This module does not sequence anything -- it only
//! produces the outcome that increment 4b sequences from.

use std::collections::{BTreeMap, BTreeSet};

/// Whether a response for this type is the complete set (missing name =
/// delete) or a per-name delivery (missing name = untouched). See this
/// module's rules 1 and 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetSemantics {
    /// LDS/CDS: the response is the entire set. A name not present is
    /// removed.
    FullState,
    /// RDS/EDS: the response carries only the names being (re)declared. A
    /// name not present is left exactly as it was.
    PerName,
}

/// One resource type's SotW state: which names are statically owned (immune
/// to xDS) and which are currently held dynamically.
///
/// Rust note: `T: PartialEq` on the impl block, not the struct, is what lets
/// `SotwSet<T>` exist for any `T` while `apply`'s unchanged/updated distinction
/// (rule 4) requires comparing values -- so only the method that needs
/// equality demands it.
#[derive(Debug, Clone)]
pub struct SotwSet<T> {
    semantics: SetSemantics,
    static_names: BTreeSet<String>,
    // Rust note: `BTreeMap` rather than `HashMap` so `names()` and every
    // `ApplyOutcome` vector are deterministically sorted -- the same
    // reasoning `subscription.rs` gives for its own `BTreeSet`.
    dynamic: BTreeMap<String, T>,
    /// Alternate xDS resource names, resolved to canonical names. Aliases
    /// never appear in `names()` or apply outcomes, so downstream sinks see
    /// one update per delivered resource.
    aliases: BTreeMap<String, String>,
    /// Per-resource expiry deadlines. Kept in store so TTL state follows the
    /// same atomic resource mutation as payload state.
    expirations: BTreeMap<String, std::time::Instant>,
}

/// The result of applying one response's resource list to a [`SotwSet`].
/// Every vector is sorted, so two runs over the same input compare equal and
/// a diff reads the same way twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// Names newly present that were not held before.
    pub added: Vec<String>,
    /// Names already held whose value changed.
    pub updated: Vec<String>,
    /// Names already held whose value compared equal -- rule 4, not
    /// reported as `updated` so a caller can skip re-applying them.
    pub unchanged: Vec<String>,
    /// Names removed because `semantics` is `FullState` and the response did
    /// not carry them. Always empty under `PerName`.
    pub removed: Vec<String>,
    /// Named in the response but refused because a static resource owns the
    /// name (rule 3). The static resource keeps serving; nothing in the
    /// dynamic set changed for this name.
    pub shadowed_by_static: Vec<String>,
}

/// Why an `apply` was refused. S8's all-or-nothing discipline: this is the
/// only case, and refusing it must leave the set byte-for-byte unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyError {
    /// The response named the same resource twice. Nothing was applied.
    DuplicateName(String),
    AliasConflict(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaApplyError {
    /// Delta response supplied same resource more than once.
    DuplicateName(String),
    /// Delta response listed same explicit removal more than once.
    DuplicateRemoval(String),
    /// Delta response both supplied and removed same name.
    ConflictingName(String),
    AliasConflict(String),
}

impl<T> SotwSet<T> {
    /// A fresh set with no dynamic resources held yet. `static_names` is
    /// fixed for the set's lifetime -- these are the config-file resources
    /// that xDS may never touch.
    pub fn new(semantics: SetSemantics, static_names: BTreeSet<String>) -> Self {
        Self {
            semantics,
            static_names,
            dynamic: BTreeMap::new(),
            aliases: BTreeMap::new(),
            expirations: BTreeMap::new(),
        }
    }

    /// The dynamic value stored for `name`, if any. A static name is never
    /// stored here even if the caller supplied one at construction time only
    /// as a name reservation -- `static_names` names an exclusion, not a
    /// value, since static resources live in `proxy-config`'s IR, not here.
    pub fn get(&self, name: &str) -> Option<&T> {
        self.dynamic.get(name).or_else(|| {
            self.aliases
                .get(name)
                .and_then(|canonical| self.dynamic.get(canonical))
        })
    }

    /// Names currently held dynamically, sorted.
    pub fn names(&self) -> Vec<&str> {
        self.dynamic.keys().map(String::as_str).collect()
    }

    /// Count of dynamic resources currently held.
    pub fn len(&self) -> usize {
        self.dynamic.len()
    }

    /// Whether no dynamic resources are currently held.
    pub fn is_empty(&self) -> bool {
        self.dynamic.is_empty()
    }

    /// Discard the named dynamic entries as though `apply` had never stored
    /// them. A name not currently held is a silent no-op.
    ///
    /// WP-21 increment 2b-ii (`apply.rs`'s EDS path) is the reason this
    /// exists: `apply` records a resource in the store BEFORE its caller gets
    /// a chance to hand it to a downstream sink, so a sink that then fails
    /// leaves the store believing the resource is installed. Left alone, an
    /// identical retransmission of that resource would compare equal
    /// (rule 4's `unchanged`) and never reach the sink again -- a resource
    /// stuck permanently uninstalled while the store reports it fine.
    /// Forgetting it here makes the next delivery of the same bytes read as
    /// `added` again, so the sink is retried instead of skipped.
    pub fn forget(&mut self, names: &BTreeSet<String>) {
        for name in names {
            self.dynamic.remove(name);
            self.aliases.retain(|_, canonical| canonical != name);
            self.expirations.remove(name);
        }
    }

    pub fn set_expiration(&mut self, name: String, deadline: std::time::Instant) {
        if self.dynamic.contains_key(&name) {
            self.expirations.insert(name, deadline);
        }
    }

    pub fn clear_expiration(&mut self, name: &str) {
        let canonical = self.aliases.get(name).map(String::as_str).unwrap_or(name);
        self.expirations.remove(canonical);
    }

    pub fn expired(&self, now: std::time::Instant) -> Vec<String> {
        self.expirations
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

impl<T: PartialEq> SotwSet<T> {
    /// Apply one response's resource list.
    ///
    /// Order of operations, each tied to a numbered rule above: reject a
    /// duplicate name outright (rule 5) before touching anything; then for
    /// each remaining `(name, value)`, either shelve it in
    /// `shadowed_by_static` (rule 3) or add/update/leave-unchanged it in the
    /// dynamic map (rule 4); then, only under `FullState`, remove whatever
    /// dynamic name the response did not mention (rule 1) -- `PerName` skips
    /// this step entirely (rule 2).
    pub fn apply(&mut self, resources: Vec<(String, T)>) -> Result<ApplyOutcome, ApplyError> {
        self.apply_named(
            resources
                .into_iter()
                .map(|(name, value)| (name, value, Vec::new()))
                .collect(),
        )
    }

    /// Apply resources with alternate names. Aliases resolve to the
    /// canonical resource and therefore never create a second outcome entry.
    pub fn apply_named(
        &mut self,
        resources: Vec<(String, T, Vec<String>)>,
    ) -> Result<ApplyOutcome, ApplyError> {
        // Rule 5: validate before mutating anything, so a rejected response
        // leaves the set byte-for-byte as it was.
        let mut seen = BTreeSet::new();
        for (name, _, aliases) in &resources {
            if !seen.insert(name.clone()) {
                return Err(ApplyError::DuplicateName(name.clone()));
            }
            for alias in aliases {
                if alias == name || !seen.insert(alias.clone()) {
                    return Err(ApplyError::DuplicateName(alias.clone()));
                }
            }
        }

        let incoming_names: BTreeSet<String> =
            resources.iter().map(|(name, _, _)| name.clone()).collect();
        if resources.iter().any(|(_, _, aliases)| {
            aliases
                .iter()
                .any(|alias| self.static_names.contains(alias))
        }) {
            return Err(ApplyError::DuplicateName(
                "resource name or alias is statically owned".to_string(),
            ));
        }
        for alias in seen.iter().filter(|name| !incoming_names.contains(*name)) {
            if let Some(existing) = self.aliases.get(alias) {
                if !incoming_names.contains(existing)
                    && !(self.semantics == SetSemantics::FullState
                        && !self.dynamic.contains_key(existing))
                {
                    return Err(ApplyError::AliasConflict(alias.clone()));
                }
            }
            if self.dynamic.contains_key(alias) && !incoming_names.contains(alias) {
                return Err(ApplyError::DuplicateName(alias.clone()));
            }
        }

        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut unchanged = Vec::new();
        let mut shadowed_by_static = Vec::new();
        // The names this response actually declares into the dynamic
        // namespace -- excludes anything shadowed by a static resource,
        // since rule 3 keeps the two namespaces disjoint: a static name was
        // never in `self.dynamic` and a `FullState` removal pass must not
        // treat its absence here as removing something that was never
        // dynamic to begin with.
        let mut declared = BTreeSet::new();

        for (name, value, aliases) in resources {
            if self.static_names.contains(&name) {
                shadowed_by_static.push(name);
                continue;
            }
            declared.insert(name.clone());
            self.aliases.retain(|_, canonical| canonical != &name);
            match self.dynamic.get(&name) {
                Some(existing) if *existing == value => unchanged.push(name.clone()),
                Some(_) => {
                    self.dynamic.insert(name.clone(), value);
                    updated.push(name.clone());
                }
                None => {
                    self.dynamic.insert(name.clone(), value);
                    added.push(name.clone());
                }
            }
            for alias in aliases {
                self.aliases.insert(alias, name.clone());
            }
        }

        // Rule 1 / rule 2: only a `FullState` response treats an un-declared
        // name as a removal. Collect the names first so we are not mutating
        // `self.dynamic` while iterating its keys.
        let mut removed = Vec::new();
        if self.semantics == SetSemantics::FullState {
            let stale: Vec<String> = self
                .dynamic
                .keys()
                .filter(|name| !declared.contains(*name))
                .cloned()
                .collect();
            for name in stale {
                self.dynamic.remove(&name);
                self.aliases.retain(|_, canonical| canonical != &name);
                self.expirations.remove(&name);
                removed.push(name);
            }
        }

        // `added`/`updated`/`unchanged` were pushed in the response's own
        // order, not sorted order; `shadowed_by_static` likewise. `removed`
        // already came out of a `BTreeMap::keys()` iterator sorted. Sort the
        // rest so every vector in the outcome is deterministic.
        added.sort();
        updated.sort();
        unchanged.sort();
        shadowed_by_static.sort();

        Ok(ApplyOutcome {
            added,
            updated,
            unchanged,
            removed,
            shadowed_by_static,
        })
    }

    /// Apply one delta response. Missing names always remain untouched;
    /// only `removed_names` delete entries, regardless of SotW semantics.
    pub fn apply_delta(
        &mut self,
        resources: Vec<(String, T)>,
        removed_names: &[String],
    ) -> Result<ApplyOutcome, DeltaApplyError> {
        self.apply_delta_named(
            resources
                .into_iter()
                .map(|(name, value)| (name, value, Vec::new()))
                .collect(),
            removed_names,
        )
    }

    /// Delta variant of [`Self::apply_named`]. Removals may name either the
    /// canonical resource or one of its aliases.
    pub fn apply_delta_named(
        &mut self,
        resources: Vec<(String, T, Vec<String>)>,
        removed_names: &[String],
    ) -> Result<ApplyOutcome, DeltaApplyError> {
        let mut supplied = BTreeSet::new();
        for (name, _, aliases) in &resources {
            if !supplied.insert(name.clone()) {
                return Err(DeltaApplyError::DuplicateName(name.clone()));
            }
            for alias in aliases {
                if alias == name || !supplied.insert(alias.clone()) {
                    return Err(DeltaApplyError::DuplicateName(alias.clone()));
                }
            }
        }
        let mut removals = BTreeSet::new();
        for name in removed_names {
            if !removals.insert(name.clone()) {
                return Err(DeltaApplyError::DuplicateRemoval(name.clone()));
            }
            if supplied.contains(name) {
                return Err(DeltaApplyError::ConflictingName(name.clone()));
            }
        }
        let canonical_names: BTreeSet<String> =
            resources.iter().map(|(name, _, _)| name.clone()).collect();
        if resources.iter().any(|(_, _, aliases)| {
            aliases
                .iter()
                .any(|alias| self.static_names.contains(alias))
        }) {
            return Err(DeltaApplyError::DuplicateName(
                "resource name or alias is statically owned".to_string(),
            ));
        }
        for alias in supplied
            .iter()
            .filter(|name| !canonical_names.contains(*name))
        {
            if self.dynamic.contains_key(alias) && !self.aliases.contains_key(alias) {
                return Err(DeltaApplyError::DuplicateName(alias.clone()));
            }
            if let Some(existing) = self.aliases.get(alias) {
                if !canonical_names.contains(existing) {
                    return Err(DeltaApplyError::AliasConflict(alias.clone()));
                }
            }
        }

        let mut added = Vec::new();
        let mut updated = Vec::new();
        let mut unchanged = Vec::new();
        let mut shadowed_by_static = Vec::new();
        for (name, value, aliases) in resources {
            if self.static_names.contains(&name) {
                shadowed_by_static.push(name);
                continue;
            }
            self.aliases.retain(|_, canonical| canonical != &name);
            match self.dynamic.get(&name) {
                Some(existing) if *existing == value => unchanged.push(name.clone()),
                Some(_) => {
                    self.dynamic.insert(name.clone(), value);
                    updated.push(name.clone());
                }
                None => {
                    self.dynamic.insert(name.clone(), value);
                    added.push(name.clone());
                }
            }
            for alias in aliases {
                self.aliases.insert(alias, name.clone());
            }
        }

        let mut removed = Vec::new();
        for name in removals {
            if self.static_names.contains(&name) {
                shadowed_by_static.push(name);
            } else {
                let canonical = self.aliases.get(&name).cloned().unwrap_or(name.clone());
                if self.dynamic.remove(&canonical).is_some() {
                    self.aliases.retain(|_, value| value != &canonical);
                    self.expirations.remove(&canonical);
                    removed.push(canonical);
                }
            }
        }
        added.sort();
        updated.sort();
        unchanged.sort();
        shadowed_by_static.sort();
        shadowed_by_static.dedup();

        Ok(ApplyOutcome {
            added,
            updated,
            unchanged,
            removed,
            shadowed_by_static,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn res(pairs: &[(&str, i32)]) -> Vec<(String, i32)> {
        pairs.iter().map(|(n, v)| (n.to_string(), *v)).collect()
    }

    fn no_statics() -> BTreeSet<String> {
        BTreeSet::new()
    }

    // --- Rule 1: FullState absence = removal ---------------------------

    #[test]
    fn full_state_removes_a_name_the_response_does_not_carry() {
        let mut s = SotwSet::new(SetSemantics::FullState, no_statics());
        s.apply(res(&[("a", 1), ("b", 2)])).unwrap();

        let outcome = s.apply(res(&[("a", 1)])).unwrap();
        assert_eq!(outcome.removed, vec!["b".to_string()]);
        assert_eq!(s.names(), vec!["a"]);
    }

    #[test]
    fn full_state_empty_response_removes_everything() {
        let mut s = SotwSet::new(SetSemantics::FullState, no_statics());
        s.apply(res(&[("a", 1), ("b", 2)])).unwrap();

        let outcome = s.apply(Vec::new()).unwrap();
        assert_eq!(outcome.removed, vec!["a".to_string(), "b".to_string()]);
        assert!(s.is_empty());
    }

    // --- Rule 2: PerName absence != removal, same fixtures as rule 1 ---

    #[test]
    fn per_name_leaves_alone_a_name_the_response_does_not_carry() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        s.apply(res(&[("a", 1), ("b", 2)])).unwrap();

        let outcome = s.apply(res(&[("a", 1)])).unwrap();
        assert!(outcome.removed.is_empty());
        assert_eq!(s.names(), vec!["a", "b"]);
        assert_eq!(*s.get("b").unwrap(), 2);
    }

    #[test]
    fn delta_changes_only_supplied_and_explicitly_removed_names() {
        let mut set = SotwSet::new(SetSemantics::FullState, no_statics());
        set.apply(res(&[("a", 1), ("b", 2)])).unwrap();

        let outcome = set
            .apply_delta(res(&[("a", 3), ("c", 4)]), &["b".to_string()])
            .unwrap();

        assert_eq!(outcome.updated, vec!["a"]);
        assert_eq!(outcome.added, vec!["c"]);
        assert_eq!(outcome.removed, vec!["b"]);
        assert_eq!(set.names(), vec!["a", "c"]);
    }

    #[test]
    fn rejected_delta_is_atomic() {
        let mut set = SotwSet::new(SetSemantics::PerName, no_statics());
        set.apply(res(&[("held", 1)])).unwrap();
        let before = set.clone();

        assert_eq!(
            set.apply_delta(res(&[("same", 2)]), &["same".to_string()]),
            Err(DeltaApplyError::ConflictingName("same".to_string()))
        );
        assert_eq!(set.names(), before.names());
        assert_eq!(set.get("held"), before.get("held"));
    }

    #[test]
    fn per_name_empty_response_removes_nothing() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        s.apply(res(&[("a", 1), ("b", 2)])).unwrap();

        let outcome = s.apply(Vec::new()).unwrap();
        assert!(outcome.removed.is_empty());
        assert_eq!(s.names(), vec!["a", "b"]);
    }

    // --- Rule 3: static names are immune --------------------------------

    #[test]
    fn a_static_name_is_reported_shadowed_and_never_stored() {
        let mut s = SotwSet::new(SetSemantics::FullState, set(&["a"]));
        let outcome = s.apply(res(&[("a", 1), ("b", 2)])).unwrap();

        assert_eq!(outcome.shadowed_by_static, vec!["a".to_string()]);
        assert_eq!(outcome.added, vec!["b".to_string()]);
        assert!(s.get("a").is_none());
        assert_eq!(s.names(), vec!["b"]);
    }

    #[test]
    fn refusing_a_shadowed_name_does_not_disturb_other_dynamic_entries() {
        let mut s = SotwSet::new(SetSemantics::FullState, set(&["a"]));
        s.apply(res(&[("b", 1)])).unwrap();

        // A later response re-declares the static name alongside the
        // existing dynamic one. `b` must survive untouched even though this
        // is a FullState response and `a` is refused rather than applied.
        let outcome = s.apply(res(&[("a", 99), ("b", 1)])).unwrap();
        assert_eq!(outcome.shadowed_by_static, vec!["a".to_string()]);
        assert_eq!(outcome.unchanged, vec!["b".to_string()]);
        assert!(outcome.removed.is_empty());
        assert_eq!(*s.get("b").unwrap(), 1);
    }

    #[test]
    fn full_state_removal_does_not_treat_a_shadowed_names_absence_as_removing_it() {
        // `a` is static and was never dynamic, so a FullState response that
        // simply never mentions it must not appear in `removed` -- there was
        // nothing dynamic under that name to remove.
        let mut s = SotwSet::new(SetSemantics::FullState, set(&["a"]));
        let outcome = s.apply(res(&[("b", 1)])).unwrap();
        assert!(!outcome.removed.contains(&"a".to_string()));
        assert!(outcome.shadowed_by_static.is_empty());
    }

    // --- Rule 4: unchanged vs updated ------------------------------------

    #[test]
    fn an_equal_value_is_reported_unchanged_not_updated() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        s.apply(res(&[("a", 1)])).unwrap();

        let outcome = s.apply(res(&[("a", 1)])).unwrap();
        assert_eq!(outcome.unchanged, vec!["a".to_string()]);
        assert!(outcome.updated.is_empty());
        assert!(outcome.added.is_empty());
    }

    #[test]
    fn a_different_value_is_reported_updated_not_unchanged() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        s.apply(res(&[("a", 1)])).unwrap();

        let outcome = s.apply(res(&[("a", 2)])).unwrap();
        assert_eq!(outcome.updated, vec!["a".to_string()]);
        assert!(outcome.unchanged.is_empty());
        assert_eq!(*s.get("a").unwrap(), 2);
    }

    #[test]
    fn a_brand_new_name_is_reported_added() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        let outcome = s.apply(res(&[("a", 1)])).unwrap();
        assert_eq!(outcome.added, vec!["a".to_string()]);
        assert!(outcome.updated.is_empty());
        assert!(outcome.unchanged.is_empty());
    }

    // --- Rule 5: duplicate name within one response ----------------------

    #[test]
    fn a_duplicate_name_in_one_response_is_rejected() {
        let mut s = SotwSet::new(SetSemantics::FullState, no_statics());
        let err = s.apply(res(&[("a", 1), ("a", 2)])).unwrap_err();
        assert_eq!(err, ApplyError::DuplicateName("a".to_string()));
    }

    #[test]
    fn a_rejected_response_leaves_the_set_byte_for_byte_unchanged() {
        let mut s = SotwSet::new(SetSemantics::FullState, no_statics());
        s.apply(res(&[("a", 1), ("b", 2)])).unwrap();
        let before: Vec<String> = s.names().into_iter().map(str::to_string).collect();
        let before_a = *s.get("a").unwrap();
        let before_b = *s.get("b").unwrap();

        let err = s.apply(res(&[("a", 9), ("a", 10), ("c", 3)])).unwrap_err();
        assert_eq!(err, ApplyError::DuplicateName("a".to_string()));

        assert_eq!(s.names(), before);
        assert_eq!(*s.get("a").unwrap(), before_a);
        assert_eq!(*s.get("b").unwrap(), before_b);
        assert!(s.get("c").is_none());
    }

    // --- Outcome ordering / general shape --------------------------------

    #[test]
    fn every_outcome_vector_is_sorted() {
        let mut s = SotwSet::new(SetSemantics::FullState, set(&["z"]));
        s.apply(res(&[("m", 1), ("n", 2)])).unwrap();

        let outcome = s
            .apply(res(&[("z", 0), ("n", 2), ("m", 99), ("x", 5)]))
            .unwrap();
        assert_eq!(outcome.shadowed_by_static, vec!["z".to_string()]);
        assert_eq!(outcome.unchanged, vec!["n".to_string()]);
        assert_eq!(outcome.updated, vec!["m".to_string()]);
        assert_eq!(outcome.added, vec!["x".to_string()]);
    }

    #[test]
    fn names_len_and_is_empty_reflect_only_the_dynamic_set() {
        let mut s = SotwSet::new(SetSemantics::FullState, set(&["static-only"]));
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);

        s.apply(res(&[("static-only", 1), ("a", 2), ("b", 3)]))
            .unwrap();
        assert_eq!(s.len(), 2);
        assert_eq!(s.names(), vec!["a", "b"]);
        assert!(!s.is_empty());
    }

    // --- WP-21 increment 2b-ii: `forget` -----------------------------------

    #[test]
    fn forgetting_a_name_makes_a_later_identical_apply_report_it_added_again() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        s.apply(res(&[("a", 1)])).unwrap();
        assert_eq!(*s.get("a").unwrap(), 1);

        s.forget(&set(&["a"]));
        assert!(s.get("a").is_none());

        // Same bytes as before `forget` -- without it this would come back
        // `unchanged` (rule 4) and never look like a fresh apply again.
        let outcome = s.apply(res(&[("a", 1)])).unwrap();
        assert_eq!(outcome.added, vec!["a".to_string()]);
        assert!(outcome.unchanged.is_empty());
    }

    #[test]
    fn forgetting_an_unheld_name_is_a_silent_no_op() {
        let mut s: SotwSet<i32> = SotwSet::new(SetSemantics::PerName, no_statics());
        s.forget(&set(&["nope"]));
        assert!(s.is_empty());
    }

    #[test]
    fn get_on_an_unknown_name_is_none() {
        let s: SotwSet<i32> = SotwSet::new(SetSemantics::PerName, no_statics());
        assert!(s.get("nope").is_none());
    }

    #[test]
    fn aliases_resolve_to_one_canonical_resource_and_remove_by_alias() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        s.apply_named(vec![(
            "canonical".to_string(),
            7,
            vec!["alias-a".to_string(), "alias-b".to_string()],
        )])
        .unwrap();

        assert_eq!(s.names(), vec!["canonical"]);
        assert_eq!(s.get("alias-a"), Some(&7));
        let outcome = s
            .apply_delta_named(Vec::new(), &["alias-b".to_string()])
            .unwrap();
        assert_eq!(outcome.removed, vec!["canonical"]);
        assert!(s.is_empty());
    }

    #[test]
    fn aliases_cannot_collide_with_another_resource() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        let error = s
            .apply_named(vec![
                ("one".to_string(), 1, vec!["shared".to_string()]),
                ("two".to_string(), 2, vec!["shared".to_string()]),
            ])
            .unwrap_err();
        assert_eq!(error, ApplyError::DuplicateName("shared".to_string()));
        assert!(s.is_empty());
    }

    #[test]
    fn expiration_tracks_canonical_name_and_clears_on_removal() {
        let mut s = SotwSet::new(SetSemantics::PerName, no_statics());
        s.apply_named(vec![(
            "canonical".to_string(),
            7,
            vec!["alias".to_string()],
        )])
        .unwrap();
        let now = std::time::Instant::now();
        s.set_expiration("canonical".to_string(), now + Duration::from_secs(1));
        assert!(s.expired(now).is_empty());
        assert_eq!(s.expired(now + Duration::from_secs(1)), vec!["canonical"]);
        s.apply_delta_named(Vec::new(), &["alias".to_string()])
            .unwrap();
        assert!(s.expired(now + Duration::from_secs(2)).is_empty());
    }
}
