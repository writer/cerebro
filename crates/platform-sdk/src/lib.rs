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
mod finding;
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
mod wire;

pub use action::{
    ActionEffect, ActionOperation, ActionProposal, ActionReceipt, ActionState,
    ActionVerificationReceipt, MAX_ACTION_CLAIM_LEASE_MS, VerificationState,
};
pub use assertion::{
    AssertionCondition, AssertionDefinition, AssertionEvaluation, AssertionState, EvaluationTrigger,
};
pub use budget::{BudgetError, ResourceBudget, ResourceUsage};
pub use cerebro_agent_context::{
    CONTEXT_SNAPSHOT_SCHEMA_V1, ContextAccessEdgeV1, ContextContradictionKindV1,
    ContextContradictionV1, ContextCoverageCompletenessV1, ContextCoverageV1, ContextFactV1,
    ContextSelectorV1, ContextSnapshotRequestV1, ContextSnapshotV1, ContextSubjectRefV1,
    ContextSubjectResolutionStateV1, ContextSubjectResolutionV1, ContextUnknownReasonV1,
    ContextUnknownV1, FactQuery, QueryAbsentEdge, QueryDirection, QueryEdge, QueryMatch, QueryNode,
    QueryResult, SnapshotError,
};
pub use cerebro_control_kernel::{
    ActorId, AuthorizationDecision, AuthorizationRequest, CapabilityGrant, DecisionId,
    DecisionReceipt, Mandate, Mission, MissionEvent, MissionEventEnvelope, VerificationId,
    VerificationReceipt,
};
pub use cerebro_organizational_model::{
    AssertionId, EntityId, EntityKind, RelationKind, SourceRuntimeId, TenantId,
};
pub use diagnostics::{CapabilityHealth, CapabilityState, OperationalDiagnostics, ProjectionLag};
pub use error::SdkError;
pub use finding::{FindingValidationDecision, FindingValidationReceipt};
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
pub use wire::{
    AGENT_ACTIVITY_SCHEMA_V1, AGENT_CAPABILITY_SCHEMA_V1, AgentActionStage, AgentActivity,
    AgentCapability, CONNECTOR_MANIFEST_SCHEMA_V1, ConnectorManifest, DecodedWirePayload,
    ENDPOINT_SESSION_LEASE_SCHEMA_V1, ENDPOINT_TELEMETRY_SCHEMA_V1, EXTERNAL_EVENT_ATTRIBUTE_KEYS,
    EXTERNAL_EVENT_SCHEMA_V1, EndpointNetworkProfile, EndpointOwnership, EndpointSessionLease,
    EndpointTelemetry, EvidenceCompleteness, EvidenceFreshness, ExternalEventEnvelope,
    MAX_EXTERNAL_EVENT_ATTRIBUTE_VALUE_BYTES, METRIC_SNAPSHOT_SCHEMA_V1, MetricSnapshot,
    REMEDIATION_OUTCOME_SCHEMA_V1, RemediationOutcome, SCANNER_FINDING_SCHEMA_V1, ScannerFinding,
    ScannerSeverity, ScannerValidationState, THREAT_INTELLIGENCE_SCHEMA_V1, ThreatIndicatorKind,
    ThreatIntelligenceObservation, ThreatPromotionReason, ThreatVerdict, WireContractFamily,
    WireEvidenceState, WireIngestOutcome, WireIngestReason, WireIngestReceipt, WireSignature,
};

/// Stable schema revision for the reusable SDK contracts.
pub const SCHEMA_VERSION: &str = "cerebro.platform-sdk.v1";
