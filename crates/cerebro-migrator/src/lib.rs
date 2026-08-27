#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Deterministic discovery and deletion-first planning for Cerebro's Rust migration.
//!
//! This crate is deliberately non-mutating. It ingests the package graph emitted by
//! `go list -deps -json`, condenses cycles into atomic components, binds migration
//! units to canonical content digests, and selects a maximum-weight prerequisite-
//! closed batch. Deletion and repository mutation belong to a later, separately
//! qualified execution boundary.

mod digest;
mod error;
mod go_graph;
mod migration_unit;
mod planner;
mod strong_components;

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
