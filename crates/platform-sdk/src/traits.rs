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
#[async_trait]
pub trait PlatformApi: Send + Sync {
    async fn graph_diff(&self, request: GraphDiffRequest) -> Result<GraphDiff, SdkError>;

    async fn explain_entity(
        &self,
        tenant_id: &TenantId,
        entity_id: &EntityId,
    ) -> Result<ProvenanceExplanation, SdkError>;

    async fn put_assertion(
        &self,
        definition: AssertionDefinition,
    ) -> Result<AssertionDefinition, SdkError>;

    async fn evaluate_assertion(
        &self,
        tenant_id: &TenantId,
        assertion_id: &AssertionDefinitionId,
    ) -> Result<AssertionEvaluation, SdkError>;

    async fn simulate(&self, request: SimulationRequest) -> Result<SimulationResult, SdkError>;

    async fn put_subscription(
        &self,
        definition: SubscriptionDefinition,
    ) -> Result<SubscriptionDefinition, SdkError>;

    async fn poll_subscription(
        &self,
        tenant_id: &TenantId,
        subscription_id: &SubscriptionId,
        cursor: DurableCursor,
    ) -> Result<SubscriptionPage, SdkError>;

    async fn acknowledge_event(
        &self,
        tenant_id: &TenantId,
        subscription_id: &SubscriptionId,
        event: &PlatformEvent,
    ) -> Result<(), SdkError>;

    async fn put_materialized_view(
        &self,
        definition: MaterializedViewDefinition,
    ) -> Result<MaterializedViewDefinition, SdkError>;

    async fn get_materialized_view(
        &self,
        tenant_id: &TenantId,
        view_id: &ViewId,
    ) -> Result<MaterializedViewSnapshot, SdkError>;

    async fn create_incident_snapshot(
        &self,
        tenant_id: &TenantId,
        entity_ids: Vec<EntityId>,
    ) -> Result<IncidentSnapshot, SdkError>;

    async fn get_incident_snapshot(
        &self,
        tenant_id: &TenantId,
        snapshot_id: &IncidentSnapshotId,
    ) -> Result<IncidentSnapshot, SdkError>;

    async fn propose_action(&self, proposal: ActionProposal) -> Result<ActionOperation, SdkError>;

    async fn get_action(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionOperation, SdkError>;

    async fn reconcile_action(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionReceipt, SdkError>;

    async fn diagnostics(&self, tenant_id: &TenantId) -> Result<OperationalDiagnostics, SdkError>;

    async fn verify_recovery(&self, tenant_id: &TenantId) -> Result<RecoveryReport, SdkError>;
}
