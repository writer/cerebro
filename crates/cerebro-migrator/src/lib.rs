#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Deterministic discovery and deletion-first planning for Cerebro's Rust migration.
//!
//! Discovery and planning are non-mutating: the crate ingests the package graph
//! emitted by `go list -deps -json`, condenses cycles into atomic components, binds
//! migration units to canonical content digests, and selects a maximum-weight
//! prerequisite-closed batch. The separately exposed deletion boundary accepts only
//! eligible content-bound manifests, fully preflights every exact regular-file target,
//! and then removes those files without interpreting paths as patterns.

mod deletion;
mod digest;
mod error;
mod go_graph;
mod migration_unit;
mod planner;
mod strong_components;
mod validation;

pub use deletion::{
    DeletionManifest, DeletionManifestBuildRequest, DeletionPreflight, DeletionReceipt,
    ManifestPathDeletion, apply_deletion_manifest, bind_deletion_manifest,
    verify_deletion_manifest,
};
pub use error::MigratorError;
pub use go_graph::{GoPackage, GoPackageGraph};
pub use migration_unit::{
    DeletionBenefit, DeletionTarget, MigrationStatus, MigrationUnit, MigrationUnitKind,
    MigrationUnitSpec,
};
pub use planner::{
    BatchPlan, BatchTotals, ExcludedUnit, PlanObjective, PlanRequest, plan_maximum_deletion,
};
pub use strong_components::{CondensedGoGraph, StrongComponent};
