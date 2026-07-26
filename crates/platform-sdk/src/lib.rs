#![forbid(unsafe_code)]

//! Reusable, transport-neutral contracts for Cerebro platform capabilities.
//!
//! This crate owns validation and stable request and response shapes. It does
//! not own networking, persistence, provider access, graph writes, scheduling,
//! or model execution. Adapters implement [`PlatformApi`] against the existing
//! JetStream, Postgres, Neo4j, HTTP, Connect, Go, TypeScript, and Python
//! boundaries.

mod action;
mod assertion;
mod budget;
mod diagnostics;
mod error;
mod identity;
mod incident;
mod plugin;
mod provenance;
mod recovery;
mod simulation;
mod subscription;
mod temporal;
mod traits;
mod view;

pub use action::{
    ActionEffect, ActionOperation, ActionProposal, ActionReceipt, ActionState, VerificationState,
};
pub use assertion::{
    AssertionCondition, AssertionDefinition, AssertionEvaluation, AssertionState, EvaluationTrigger,
};
pub use budget::{BudgetError, ResourceBudget, ResourceUsage};
pub use cerebro_agent_context::{
    FactQuery, QueryAbsentEdge, QueryDirection, QueryEdge, QueryMatch, QueryNode, QueryResult,
};
pub use cerebro_control_kernel::{
    AuthorizationDecision, AuthorizationRequest, CapabilityGrant, DecisionReceipt, Mandate,
    Mission, MissionEvent, MissionEventEnvelope, VerificationReceipt,
};
pub use cerebro_organizational_model::{
    AssertionId, EntityId, EntityKind, RelationKind, SourceRuntimeId, TenantId,
};
pub use diagnostics::{CapabilityHealth, CapabilityState, OperationalDiagnostics, ProjectionLag};
pub use error::SdkError;
pub use identity::{
    ActionOperationId, AssertionDefinitionId, ContentDigest, IncidentSnapshotId, OpaqueId,
    PluginId, SimulationId, SubscriptionId, ViewId,
};
pub use incident::{IncidentSnapshot, IncidentSnapshotManifest};
pub use plugin::{AnalysisPluginManifest, PluginCapability, PluginLimits};
pub use provenance::{
    EvidenceAuthority, EvidenceQuality, EvidenceReference, ProvenanceExplanation,
};
pub use recovery::{RecoveryCheck, RecoveryReport, RecoveryState};
pub use simulation::{ProposedChange, SimulationFinding, SimulationRequest, SimulationResult};
pub use subscription::{
    DurableCursor, PlatformEvent, PlatformEventKind, SubscriptionDefinition,
    SubscriptionEventFilter, SubscriptionPage,
};
pub use temporal::{
    GraphChange, GraphChangeKind, GraphDiff, GraphDiffRequest, GraphRevision, RevisionSelector,
};
pub use traits::PlatformApi;
pub use view::{MaterializedViewDefinition, MaterializedViewSnapshot, ViewRefreshState};

/// Stable schema revision for the reusable SDK contracts.
pub const SCHEMA_VERSION: &str = "cerebro.platform-sdk.v1";
