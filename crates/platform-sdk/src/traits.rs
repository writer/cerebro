//! Asynchronous capability boundary shared by platform transports.
//!
//! The trait defines portable request and response contracts, not a universal
//! implementation. Each adapter remains responsible for authentication,
//! authorization, tenant isolation, persistence, deadlines, redaction, and the
//! stronger invariants documented by the value types it accepts and returns.

use async_trait::async_trait;

use crate::{
    ActionOperation, ActionOperationId, ActionProposal, ActionReceipt, AssertionDefinition,
    AssertionDefinitionId, AssertionEvaluation, DurableCursor, EntityId, GraphDiff,
    GraphDiffRequest, IncidentSnapshot, IncidentSnapshotId, MaterializedViewDefinition,
    MaterializedViewSnapshot, OperationalDiagnostics, PlatformEvent, ProvenanceExplanation,
    RecoveryReport, SdkError, SimulationRequest, SimulationResult, SubscriptionDefinition,
    SubscriptionId, SubscriptionPage, TenantId, ViewId,
};

/// Transport-neutral capability surface implemented by in-process, Connect,
/// HTTP, and test adapters. Implementations may expose only capabilities their
/// deployment owns; unsupported calls return [`SdkError::CapabilityUnavailable`].
///
/// Methods are safe to invoke concurrently through `Send + Sync`; that bound
/// does not imply ordering or transactionality across separate calls. Callers
/// must use operation IDs, cursors, revisions, and receipts according to the
/// individual capability contract rather than relying on invocation order.
#[async_trait]
pub trait PlatformApi: Send + Sync {
    /// Returns one bounded, digest-bound page of changes after a graph revision.
    ///
    /// Implementations resolve a `current` ending selector, load authoritative
    /// tenant snapshots, and validate any continuation against the same diff.
    async fn graph_diff(&self, request: GraphDiffRequest) -> Result<GraphDiff, SdkError>;

    /// Returns bounded provenance supporting one tenant-scoped entity.
    ///
    /// The adapter must authorize the tenant/entity pair and bind the returned
    /// explanation to the applicable graph revision and evidence records.
    async fn explain_entity(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ProvenanceExplanation, SdkError>;

    /// Validates and stores an assertion definition.
    ///
    /// The returned value is the accepted canonical definition. Implementations
    /// own tenant authorization, digest verification, and create/update conflict
    /// behavior for an existing assertion identity.
    async fn put_assertion(
        &self,
        definition: AssertionDefinition,
    ) -> Result<AssertionDefinition, SdkError>;

    /// Evaluates one stored assertion against authorized tenant graph state.
    ///
    /// Implementations bind the evaluation to a concrete graph revision and
    /// return an indeterminate state when required evidence cannot be established.
    async fn evaluate_assertion(
        &self,
        tenant_id: &TenantId,
        assertion_id: &AssertionDefinitionId,
    ) -> Result<AssertionEvaluation, SdkError>;

    /// Projects a bounded change sequence without mutating durable graph state.
    ///
    /// The implementation must load the declared base revision and bind any
    /// supplied assertion results to the projected topology.
    async fn simulate(&self, request: SimulationRequest) -> Result<SimulationResult, SdkError>;

    /// Validates and stores a tenant-scoped event subscription definition.
    ///
    /// The returned value is the accepted definition, including its verified
    /// content digest and deployment-specific create/update outcome.
    async fn put_subscription(
        &self,
        definition: SubscriptionDefinition,
    ) -> Result<SubscriptionDefinition, SdkError>;

    /// Reads the next bounded matching event page from a durable cursor.
    ///
    /// Implementations must scope both subscription and cursor to `tenant_id`,
    /// preserve stream order, and return a resumable next cursor on empty pages.
    async fn poll_subscription(
        &self,
        tenant_id: &TenantId,
        subscription_id: &SubscriptionId,
        cursor: DurableCursor,
    ) -> Result<SubscriptionPage, SdkError>;

    /// Records delivery acknowledgement for one subscription event.
    ///
    /// The adapter must reject tenant, subscription, or event mismatches and
    /// define replay-safe duplicate acknowledgement behavior without advancing
    /// cursor state for another subscription.
    async fn acknowledge_event(
        &self,
        tenant_id: &TenantId,
        subscription_id: &SubscriptionId,
        event: &PlatformEvent,
    ) -> Result<(), SdkError>;

    /// Validates and stores a materialized-view definition.
    ///
    /// Implementations verify the definition digest and schedule or perform the
    /// initial refresh according to the capability they own.
    async fn put_materialized_view(
        &self,
        definition: MaterializedViewDefinition,
    ) -> Result<MaterializedViewDefinition, SdkError>;

    /// Returns the latest authorized snapshot metadata for a materialized view.
    ///
    /// The response reports refresh state and result identity, not necessarily
    /// the materialized rows themselves.
    async fn get_materialized_view(
        &self,
        tenant_id: &TenantId,
        view_id: &ViewId,
    ) -> Result<MaterializedViewSnapshot, SdkError>;

    /// Creates a signed incident snapshot covering selected tenant entities.
    ///
    /// Implementations bound and authorize the entity set, construct canonical
    /// payload bytes, bind the manifest, and invoke a trusted signing boundary.
    async fn create_incident_snapshot(
        &self,
        tenant_id: &TenantId,
        entity_ids: Vec<EntityId>,
    ) -> Result<IncidentSnapshot, SdkError>;

    /// Retrieves an authorized incident snapshot by stable identity.
    ///
    /// Importing adapters must verify manifest and payload digests plus the
    /// signature before treating the returned package as trusted evidence.
    async fn get_incident_snapshot(
        &self,
        tenant_id: &TenantId,
        snapshot_id: &IncidentSnapshotId,
    ) -> Result<IncidentSnapshot, SdkError>;

    /// Admits an action proposal and returns its durable operation state.
    ///
    /// The implementation owns proposal-digest verification, authorization,
    /// idempotency, durable recording, and the transition to executable state.
    async fn propose_action(&self, proposal: ActionProposal) -> Result<ActionOperation, SdkError>;

    /// Reads one tenant-scoped action operation without advancing it.
    async fn get_action(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionOperation, SdkError>;

    /// Reconciles an action operation with observed external state.
    ///
    /// Implementations must preserve the operation's authority and idempotency
    /// contracts while returning a content-bound verification receipt.
    async fn reconcile_action(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionReceipt, SdkError>;

    /// Collects a coherent, authorized operational snapshot for one tenant.
    async fn diagnostics(&self, tenant_id: &TenantId) -> Result<OperationalDiagnostics, SdkError>;

    /// Runs bounded recovery checks and returns their deterministic aggregate report.
    ///
    /// Verification reports state only; callers require separate authority to
    /// repair a projection or replay durable records.
    async fn verify_recovery(&self, tenant_id: &TenantId) -> Result<RecoveryReport, SdkError>;
}
