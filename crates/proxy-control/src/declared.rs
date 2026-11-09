//! Tenant policy declared in the config file and reconciled into the store.
//!
//! A declared tenant owns up to five store rows: the tenant itself, its model
//! policy, its budget, its scoped budgets and its limits. Each row records
//! its [`RowSource`]. The file creates, updates and deletes only rows whose
//! source is [`RowSource::File`]; an admin write stores the row as
//! [`RowSource::Admin`], and the file no longer touches it until an explicit
//! hand-back ([`crate::control::ControlPlaneStore::hand_back_to_file`]).
//!
//! Replicas sharing one store order their files by [`DeclaredPolicy::revision`]:
//! the store records the revision and digest it last applied, and refuses an
//! older revision, or the same revision with other content.

use std::collections::HashMap;

use crate::auth::TenantId;
use crate::control::{
    encode_limits_row, encode_policy_row, encode_scoped_budgets_row, encode_tenant_budget_row,
    LimitPolicy,
};
use crate::model_authz::ModelAccess;
use crate::spend::{ScopedBudget, TenantBudget};

/// Who last wrote a stored row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowSource {
    /// An admin API write, or a row written before rows recorded a source.
    /// The file never changes or deletes it.
    Admin,
    /// The config file's reconcile. The next reconcile may update or delete it.
    File,
}

/// The kinds of row a declared tenant owns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RowKind {
    Tenant,
    Policy,
    Budget,
    ScopedBudgets,
    Limits,
}

impl RowKind {
    /// Every kind, in the order reports list them.
    pub const ALL: [RowKind; 5] = [
        RowKind::Tenant,
        RowKind::Policy,
        RowKind::Budget,
        RowKind::ScopedBudgets,
        RowKind::Limits,
    ];

    /// The field of a declared tenant entry that declares this row, or
    /// `None` for the tenant row, which the entry itself declares.
    pub fn field(self) -> Option<&'static str> {
        match self {
            RowKind::Tenant => None,
            RowKind::Policy => Some("policy"),
            RowKind::Budget => Some("budget"),
            RowKind::ScopedBudgets => Some("scoped_budgets"),
            RowKind::Limits => Some("limits"),
        }
    }
}

/// One tenant as the config file declares it. A `None` (or empty) member
/// declares no row of that kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredTenant {
    pub tenant: TenantId,
    pub policy: Option<ModelAccess>,
    pub budget: Option<TenantBudget>,
    pub scoped_budgets: Vec<ScopedBudget>,
    pub limits: Option<LimitPolicy>,
}

/// The whole declared block of one config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredPolicy {
    /// Orders files across replicas; see the module doc.
    pub revision: u64,
    /// Sorted by tenant id, unique.
    pub tenants: Vec<DeclaredTenant>,
    /// SHA-256 over the canonical rows, so two files with the same revision
    /// and different content are told apart.
    pub digest: [u8; 32],
}

/// One declared row an admin-owned row shadows: the file declares it, and
/// the store keeps the admin value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowedRow {
    pub tenant: TenantId,
    pub kind: RowKind,
}

/// What one reconcile wrote.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    /// File rows created or changed.
    pub written: usize,
    /// File rows deleted.
    pub deleted: usize,
    /// Declared rows left alone because an admin owns them, sorted by
    /// tenant, then kind.
    pub shadowed: Vec<ShadowedRow>,
    /// Tenants whose file-owned tenant row this reconcile deleted, sorted.
    pub removed_tenants: Vec<TenantId>,
}

/// The result of [`crate::control::ControlPlaneStore::reconcile_declared`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileOutcome {
    /// The store now matches the file, except for shadowed rows.
    Applied(ReconcileReport),
    /// The store already applied a newer revision; nothing was written.
    StaleRevision { stored: u64 },
    /// The store applied this revision with other content; nothing was
    /// written.
    RevisionConflict,
}

impl DeclaredPolicy {
    /// Builds the policy, sorting `tenants` by id and computing the digest.
    /// Duplicate tenant ids are the caller's to refuse, with their config
    /// path; here a later duplicate would replace nothing and the digest
    /// would still differ, so two files cannot collide through one.
    pub fn new(revision: u64, mut tenants: Vec<DeclaredTenant>) -> Self {
        tenants.sort_by(|a, b| a.tenant.as_str().cmp(b.tenant.as_str()));
        let digest = digest_tenants(revision, &tenants);
        DeclaredPolicy {
            revision,
            tenants,
            digest,
        }
    }

    /// The declared entry for `tenant`, if the file declares it.
    pub fn tenant(&self, tenant: &TenantId) -> Option<&DeclaredTenant> {
        self.tenants
            .binary_search_by(|entry| entry.tenant.as_str().cmp(tenant.as_str()))
            .ok()
            .map(|i| &self.tenants[i])
    }
}

/// SHA-256 over every declared row in its stored file encoding, each part
/// length-prefixed so two different splits cannot collide.
fn digest_tenants(revision: u64, tenants: &[DeclaredTenant]) -> [u8; 32] {
    let mut context = ring::digest::Context::new(&ring::digest::SHA256);
    let mut part = |bytes: &[u8]| {
        context.update(&(bytes.len() as u64).to_be_bytes());
        context.update(bytes);
    };
    part(&revision.to_be_bytes());
    for entry in tenants {
        part(entry.tenant.as_str().as_bytes());
        part(
            &entry
                .policy
                .as_ref()
                .map(|p| encode_policy_row(p, RowSource::File))
                .unwrap_or_default(),
        );
        part(
            &entry
                .budget
                .as_ref()
                .map(|b| encode_tenant_budget_row(b, RowSource::File))
                .unwrap_or_default(),
        );
        part(&encode_scoped_budgets_row(
            &entry.scoped_budgets,
            RowSource::File,
        ));
        part(
            &entry
                .limits
                .as_ref()
                .map(|l| encode_limits_row(l, RowSource::File))
                .unwrap_or_default(),
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(context.finish().as_ref());
    out
}

/// The revision and digest a store last applied, kept beside the rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AppliedMarker {
    pub(crate) revision: u64,
    pub(crate) digest: [u8; 32],
}

/// Every row a reconcile may touch, with its source, as one store holds them.
#[derive(Default)]
pub(crate) struct CurrentRows {
    pub(crate) tenants: HashMap<TenantId, RowSource>,
    pub(crate) policies: HashMap<TenantId, (RowSource, ModelAccess)>,
    pub(crate) budgets: HashMap<TenantId, (RowSource, TenantBudget)>,
    pub(crate) scoped_budgets: HashMap<TenantId, (RowSource, Vec<ScopedBudget>)>,
    pub(crate) limits: HashMap<TenantId, (RowSource, LimitPolicy)>,
}

/// One row a store must write (`Some`) or delete (`None`).
pub(crate) enum RowWrite {
    Tenant(TenantId, Option<RowSource>),
    Policy(TenantId, Option<(RowSource, ModelAccess)>),
    Budget(TenantId, Option<(RowSource, TenantBudget)>),
    ScopedBudgets(TenantId, Option<(RowSource, Vec<ScopedBudget>)>),
    Limits(TenantId, Option<(RowSource, LimitPolicy)>),
}

/// What a store does for one reconcile.
pub(crate) enum ReconcilePlan {
    /// Write nothing, not even the marker, and answer this.
    Refuse(ReconcileOutcome),
    /// Apply `writes`, record `marker`, bump the generation iff `writes` is
    /// not empty, and answer `Applied(report)`.
    Apply {
        writes: Vec<RowWrite>,
        marker: AppliedMarker,
        report: ReconcileReport,
    },
}

/// The step for one data row.
enum Step<T> {
    Write(T),
    Delete,
    Shadowed,
    Keep,
}

fn step<T: PartialEq + Clone>(current: Option<&(RowSource, T)>, declared: Option<&T>) -> Step<T> {
    match (current, declared) {
        (None, Some(value)) => Step::Write(value.clone()),
        (Some((RowSource::File, stored)), Some(value)) => {
            if stored == value {
                Step::Keep
            } else {
                Step::Write(value.clone())
            }
        }
        (Some((RowSource::Admin, _)), Some(_)) => Step::Shadowed,
        (Some((RowSource::File, _)), None) => Step::Delete,
        (Some((RowSource::Admin, _)), None) | (None, None) => Step::Keep,
    }
}

/// Decides one reconcile from what the store holds. Pure: every store calls
/// it inside its own transaction and applies the result there.
pub(crate) fn plan_reconcile(
    current: &CurrentRows,
    applied: Option<AppliedMarker>,
    declared: &DeclaredPolicy,
) -> ReconcilePlan {
    if let Some(applied) = applied {
        if declared.revision < applied.revision {
            return ReconcilePlan::Refuse(ReconcileOutcome::StaleRevision {
                stored: applied.revision,
            });
        }
        if declared.revision == applied.revision && declared.digest != applied.digest {
            return ReconcilePlan::Refuse(ReconcileOutcome::RevisionConflict);
        }
    }
    let mut writes = Vec::new();
    let mut report = ReconcileReport::default();

    // Rust note: a macro rather than a generic function because each kind
    // reads a different map and builds a different `RowWrite` variant; a
    // function would need both passed in as closures for no clarity gained.
    macro_rules! data_row {
        ($tenant:expr, $map:ident, $declared:expr, $variant:ident, $kind:expr) => {
            match step(current.$map.get($tenant), $declared) {
                Step::Write(value) => {
                    report.written += 1;
                    writes.push(RowWrite::$variant(
                        $tenant.clone(),
                        Some((RowSource::File, value)),
                    ));
                }
                Step::Delete => {
                    report.deleted += 1;
                    writes.push(RowWrite::$variant($tenant.clone(), None));
                }
                Step::Shadowed => report.shadowed.push(ShadowedRow {
                    tenant: $tenant.clone(),
                    kind: $kind,
                }),
                Step::Keep => {}
            }
        };
    }

    for entry in &declared.tenants {
        let tenant = &entry.tenant;
        match current.tenants.get(tenant) {
            None => {
                report.written += 1;
                writes.push(RowWrite::Tenant(tenant.clone(), Some(RowSource::File)));
            }
            Some(RowSource::File) => {}
            Some(RowSource::Admin) => report.shadowed.push(ShadowedRow {
                tenant: tenant.clone(),
                kind: RowKind::Tenant,
            }),
        }
        let scoped = (!entry.scoped_budgets.is_empty()).then_some(&entry.scoped_budgets);
        data_row!(
            tenant,
            policies,
            entry.policy.as_ref(),
            Policy,
            RowKind::Policy
        );
        data_row!(
            tenant,
            budgets,
            entry.budget.as_ref(),
            Budget,
            RowKind::Budget
        );
        data_row!(
            tenant,
            scoped_budgets,
            scoped,
            ScopedBudgets,
            RowKind::ScopedBudgets
        );
        data_row!(
            tenant,
            limits,
            entry.limits.as_ref(),
            Limits,
            RowKind::Limits
        );
    }

    // File rows of tenants the file no longer declares. Collected and sorted
    // so the writes, and the report, do not depend on hash order.
    let mut undeclared: Vec<&TenantId> = current
        .tenants
        .keys()
        .chain(current.policies.keys())
        .chain(current.budgets.keys())
        .chain(current.scoped_budgets.keys())
        .chain(current.limits.keys())
        .filter(|tenant| declared.tenant(tenant).is_none())
        .collect();
    undeclared.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    undeclared.dedup();
    for tenant in undeclared {
        if current.tenants.get(tenant) == Some(&RowSource::File) {
            report.deleted += 1;
            report.removed_tenants.push(tenant.clone());
            writes.push(RowWrite::Tenant(tenant.clone(), None));
        }
        data_row!(tenant, policies, None, Policy, RowKind::Policy);
        data_row!(tenant, budgets, None, Budget, RowKind::Budget);
        data_row!(
            tenant,
            scoped_budgets,
            None,
            ScopedBudgets,
            RowKind::ScopedBudgets
        );
        data_row!(tenant, limits, None, Limits, RowKind::Limits);
    }

    ReconcilePlan::Apply {
        writes,
        marker: AppliedMarker {
            revision: declared.revision,
            digest: declared.digest,
        },
        report,
    }
}

/// The writes that hand every admin-owned row of `tenant` back to the file,
/// with the kinds they cover, in [`RowKind`] order.
pub(crate) fn plan_hand_back(
    current: &CurrentRows,
    tenant: &TenantId,
) -> (Vec<RowWrite>, Vec<RowKind>) {
    let mut writes = Vec::new();
    let mut kinds = Vec::new();
    if current.tenants.get(tenant) == Some(&RowSource::Admin) {
        writes.push(RowWrite::Tenant(tenant.clone(), Some(RowSource::File)));
        kinds.push(RowKind::Tenant);
    }
    macro_rules! hand_back {
        ($map:ident, $variant:ident, $kind:expr) => {
            if let Some((RowSource::Admin, value)) = current.$map.get(tenant) {
                writes.push(RowWrite::$variant(
                    tenant.clone(),
                    Some((RowSource::File, value.clone())),
                ));
                kinds.push($kind);
            }
        };
    }
    hand_back!(policies, Policy, RowKind::Policy);
    hand_back!(budgets, Budget, RowKind::Budget);
    hand_back!(scoped_budgets, ScopedBudgets, RowKind::ScopedBudgets);
    hand_back!(limits, Limits, RowKind::Limits);
    (writes, kinds)
}

#[cfg(test)]
mod tests;
