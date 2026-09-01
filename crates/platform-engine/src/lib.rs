#![forbid(unsafe_code)]

//! Deterministic, storage-neutral engines for Cerebro platform capabilities.
//!
//! This crate contains pure compilation, evaluation, filtering, planning, and
//! state-transition logic. It deliberately has no persistence or network
//! implementation and therefore cannot act as a production fallback.

mod action;
mod assertion;
mod canonical;
mod context;
mod incident;
mod plugin;
mod provenance;
mod query;
mod recovery;
mod simulation;
mod subscription;
mod temporal;
mod view;

pub use action::{ActionCommand, transition_action};
pub use assertion::{
    CompiledAssertion, assertion_definition_digest, compile_assertion, evaluate_assertion,
};
pub use context::evaluate_context_binding;
pub use incident::{incident_manifest_digest, package_incident_snapshot};
pub use plugin::validate_plugin_execution;
pub use provenance::assemble_provenance;
pub use query::{QueryExecutionPlan, QueryStrategy, plan_query};
pub use recovery::build_recovery_report;
pub use simulation::{SimulationRelationship, SimulationTopology, simulate_topology};
pub use subscription::event_matches;
pub use temporal::{RevisionSnapshot, SnapshotKey, SnapshotValue, diff_snapshots};
pub use view::materialize_view;
