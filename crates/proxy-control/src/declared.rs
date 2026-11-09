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

use crate::auth::TenantId;
use crate::control::LimitPolicy;
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
