#![forbid(unsafe_code)]

//! Durable organizational ledger and Neo4j current-state projection.

mod cutover;
mod neo4j;
mod parity;
mod postgres;

pub use cutover::{
    CutoverDecision, CutoverGate, CutoverPolicy, ProjectionAuthority, ProjectionAuthorityRecord,
    ProjectionPromotionRequest,
};
pub use neo4j::{Neo4jProjector, ResolvedLifecycleFinding};
pub use parity::{
    MismatchSide, ParityError, ParityReceipt, ParityStatus, SemanticFact, SemanticFactKind,
    SemanticMismatch, SemanticSnapshot,
};
pub use postgres::{
    LegacyProjectionReceipt, POSTGRES_SCHEMA, PostgresLedger, SourceCollectionReceipt,
    SourceEventReceipt,
};

use std::{error::Error, fmt};

use async_trait::async_trait;
use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{GraphDelta, TenantId};
use cerebro_source_runtime_next::{
    CollectedBatch, FencedGraphSink, GraphSink, SourceRuntimeLeaseFence,
};

#[derive(Debug)]
pub enum StoreError {
    Postgres(tokio_postgres::Error),
    Neo4j(::neo4rs::Error),
    Serialization(serde_json::Error),
    Conflict(String),
    LifecycleProjectionUnavailable {
        graph_revision: u64,
        projection_revision: Option<u64>,
    },
    ProjectionPending {
        receipt: GraphWriteReceipt,
        message: String,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(error) => write!(formatter, "organizational ledger failed: {error}"),
            Self::Neo4j(error) => write!(formatter, "organizational projection failed: {error}"),
            Self::Serialization(error) => write!(formatter, "serialize graph commit: {error}"),
            Self::Conflict(message) => formatter.write_str(message),
            Self::LifecycleProjectionUnavailable {
                graph_revision,
                projection_revision,
            } => write!(
                formatter,
                "lifecycle projection is not ready at graph revision {graph_revision} (projection revision: {})",
                projection_revision
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned())
            ),
            Self::ProjectionPending { receipt, message } => write!(
                formatter,
                "ledger revision {} committed but graph projection is pending: {message}",
                receipt.graph_revision
            ),
        }
    }
}

impl Error for StoreError {}

impl StoreError {
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Postgres(_)
                | Self::Neo4j(_)
                | Self::LifecycleProjectionUnavailable { .. }
                | Self::ProjectionPending { .. }
        )
    }
}

impl From<tokio_postgres::Error> for StoreError {
    fn from(value: tokio_postgres::Error) -> Self {
        Self::Postgres(value)
    }
}

impl From<::neo4rs::Error> for StoreError {
    fn from(value: ::neo4rs::Error) -> Self {
        Self::Neo4j(value)
    }
}

impl From<serde_json::Error> for StoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

/// The ledger is authoritative. Neo4j is a rebuildable projection. A failed
/// projection leaves an outbox row and returns a receipt-bearing error so the
/// caller never retries the provider collection as if nothing committed.
pub struct DurableGraphStore {
    ledger: PostgresLedger,
    projector: Neo4jProjector,
}

impl DurableGraphStore {
    pub fn new(ledger: PostgresLedger, projector: Neo4jProjector) -> Self {
        Self { ledger, projector }
    }

    pub async fn replay_pending(&self, tenant_id: &str, limit: usize) -> Result<usize, StoreError> {
        let pending = self.ledger.pending(tenant_id, limit).await?;
        let mut projected = 0;
        for commit in pending {
            self.projector.project_wire(&commit).await?;
            self.ledger
                .mark_projected(&commit.tenant_id, commit.graph_revision)
                .await?;
            projected += 1;
        }
        Ok(projected)
    }

    /// Returns an existing collection receipt and, when necessary, projects
    /// the exact durable outbox payload originally committed with it.
    pub async fn resume_collection(
        &self,
        tenant_id: &TenantId,
        collection_id: &str,
    ) -> Result<Option<GraphWriteReceipt>, StoreError> {
        let Some(committed) = self
            .ledger
            .committed_collection(tenant_id, collection_id)
            .await?
        else {
            return Ok(None);
        };
        if let Some(projection) = committed.pending_projection {
            self.projector.project_wire(&projection).await?;
            self.ledger
                .mark_projected(tenant_id.as_str(), projection.graph_revision)
                .await?;
        }
        Ok(Some(committed.receipt))
    }

    async fn project_commit(
        &self,
        commit: postgres::StoredCommit,
    ) -> Result<GraphWriteReceipt, StoreError> {
        if let Err(error) = self.projector.project_wire(&commit.projection).await {
            return Err(StoreError::ProjectionPending {
                receipt: commit.receipt,
                message: error.to_string(),
            });
        }
        self.ledger
            .mark_projected(
                commit.receipt.tenant_id.as_str(),
                commit.receipt.graph_revision,
            )
            .await?;
        Ok(commit.receipt)
    }
}

#[async_trait]
impl GraphSink for DurableGraphStore {
    type Error = StoreError;

    async fn apply(
        &mut self,
        batch: &CollectedBatch,
        delta: GraphDelta,
    ) -> Result<GraphWriteReceipt, Self::Error> {
        let commit = self.ledger.commit(batch, &delta).await?;
        self.project_commit(commit).await
    }
}

#[async_trait]
impl FencedGraphSink for DurableGraphStore {
    async fn apply_fenced(
        &mut self,
        batch: &CollectedBatch,
        delta: GraphDelta,
        fence: &SourceRuntimeLeaseFence,
    ) -> Result<GraphWriteReceipt, Self::Error> {
        let commit = self.ledger.commit_fenced(batch, &delta, fence).await?;
        self.project_commit(commit).await
    }
}

#[cfg(test)]
mod tests {
    use cerebro_organizational_graph::GraphWriteReceipt;
    use cerebro_organizational_model::TenantId;

    use super::StoreError;

    #[test]
    fn retryability_separates_transient_backends_from_permanent_data_errors() {
        let serialization =
            serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON");
        assert!(!StoreError::Serialization(serialization).is_retryable());
        assert!(!StoreError::Conflict("identity conflict".to_owned()).is_retryable());
        assert!(
            StoreError::ProjectionPending {
                receipt: GraphWriteReceipt {
                    tenant_id: TenantId::parse("tenant-a").unwrap(),
                    graph_revision: 1,
                    delta_digest: "digest".to_owned(),
                    entities_upserted: 1,
                    assertions_upserted: 1,
                    assertions_retracted: 0,
                },
                message: "neo4j unavailable".to_owned(),
            }
            .is_retryable()
        );
    }
}
