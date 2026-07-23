#![forbid(unsafe_code)]

//! Durable organizational ledger and Neo4j current-state projection.

mod cutover;
mod neo4j;
mod postgres;

pub use cutover::{CutoverDecision, CutoverGate, CutoverPolicy, ParityReceipt, ParityStatus};
pub use neo4j::Neo4jProjector;
pub use postgres::{POSTGRES_SCHEMA, PostgresLedger};

use std::{error::Error, fmt};

use async_trait::async_trait;
use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::GraphDelta;
use cerebro_source_runtime_next::{CollectedBatch, GraphSink};

#[derive(Debug)]
pub enum StoreError {
    Postgres(tokio_postgres::Error),
    Neo4j(::neo4rs::Error),
    Serialization(serde_json::Error),
    Conflict(String),
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
            Self::ProjectionPending { receipt, message } => write!(
                formatter,
                "ledger revision {} committed but graph projection is pending: {message}",
                receipt.graph_revision
            ),
        }
    }
}

impl Error for StoreError {}

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
