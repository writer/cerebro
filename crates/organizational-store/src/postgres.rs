use std::collections::BTreeSet;

use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{
    CollectionCompleteness, GraphAssertion, GraphDelta, IdentityBindingState,
};
use cerebro_source_runtime_next::CollectedBatch;
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_postgres::Client;

use crate::StoreError;

pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS organizational_graph_revisions (
  tenant_id TEXT PRIMARY KEY,
  revision BIGINT NOT NULL CHECK (revision >= 0)
);
CREATE TABLE IF NOT EXISTS organizational_collections (
  tenant_id TEXT NOT NULL,
  collection_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  completeness TEXT NOT NULL,
  observed_at_unix_ms BIGINT NOT NULL,
  delta_digest TEXT NOT NULL,
  graph_revision BIGINT NOT NULL,
  receipt_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, collection_id),
  UNIQUE (tenant_id, graph_revision)
);
CREATE TABLE IF NOT EXISTS organizational_observations (
  tenant_id TEXT NOT NULL,
  collection_id TEXT NOT NULL,
  observation_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  family TEXT NOT NULL,
  provider_kind TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  fields_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, collection_id, observation_id),
  FOREIGN KEY (tenant_id, collection_id)
    REFERENCES organizational_collections (tenant_id, collection_id)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS organizational_entities (
  tenant_id TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  entity_json JSONB NOT NULL,
  last_graph_revision BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, entity_id)
);
CREATE TABLE IF NOT EXISTS organizational_assertions (
  tenant_id TEXT NOT NULL,
  assertion_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  from_entity_id TEXT NOT NULL,
  to_entity_id TEXT NOT NULL,
  relation TEXT NOT NULL,
  assertion_json JSONB NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  last_graph_revision BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, assertion_id),
  FOREIGN KEY (tenant_id, from_entity_id)
    REFERENCES organizational_entities (tenant_id, entity_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, to_entity_id)
    REFERENCES organizational_entities (tenant_id, entity_id)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS organizational_identity_bindings (
  tenant_id TEXT NOT NULL,
  provider_identity_id TEXT NOT NULL,
  canonical_identity_id TEXT NOT NULL,
  assertion_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, provider_identity_id),
  UNIQUE (tenant_id, assertion_id),
  FOREIGN KEY (tenant_id, provider_identity_id)
    REFERENCES organizational_entities (tenant_id, entity_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, canonical_identity_id)
    REFERENCES organizational_entities (tenant_id, entity_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, assertion_id)
    REFERENCES organizational_assertions (tenant_id, assertion_id)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS organizational_identity_claims (
  tenant_id TEXT NOT NULL,
  claim_kind TEXT NOT NULL,
  claim_value TEXT NOT NULL,
  canonical_identity_id TEXT NOT NULL,
  assertion_id TEXT NOT NULL,
  PRIMARY KEY (tenant_id, claim_kind, claim_value),
  UNIQUE (tenant_id, assertion_id),
  FOREIGN KEY (tenant_id, canonical_identity_id)
    REFERENCES organizational_entities (tenant_id, entity_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, assertion_id)
    REFERENCES organizational_assertions (tenant_id, assertion_id)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS organizational_projection_outbox (
  tenant_id TEXT NOT NULL,
  graph_revision BIGINT NOT NULL,
  delta_digest TEXT NOT NULL,
  projection_json JSONB NOT NULL,
  projected_at TIMESTAMPTZ,
  PRIMARY KEY (tenant_id, graph_revision)
);
CREATE INDEX IF NOT EXISTS organizational_projection_pending_idx
  ON organizational_projection_outbox (graph_revision)
  WHERE projected_at IS NULL;
ALTER TABLE organizational_graph_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_graph_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_collections FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_entities FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_assertions FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_identity_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_identity_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_identity_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_identity_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_projection_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_projection_outbox FORCE ROW LEVEL SECURITY;
DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'organizational_graph_revisions',
    'organizational_collections',
    'organizational_observations',
    'organizational_entities',
    'organizational_assertions',
    'organizational_identity_bindings',
    'organizational_identity_claims',
    'organizational_projection_outbox'
  ] LOOP
    BEGIN
      EXECUTE format(
        'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''cerebro.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''cerebro.tenant_id'', true))',
        table_name
      );
    EXCEPTION WHEN duplicate_object THEN NULL;
    END;
  END LOOP;
END $$;
"#;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectionEntity {
    pub entity_id: String,
    pub entity_kind: String,
    pub authority_json: String,
    pub label: String,
    pub properties_json: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectionAssertion {
    pub assertion_id: String,
    pub from_entity_id: String,
    pub to_entity_id: String,
    pub relation: String,
    pub source_runtime_id: String,
    pub state: String,
    pub provenance_json: String,
    pub observed_at_unix_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectionRetraction {
    pub assertion_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectionCommit {
    pub tenant_id: String,
    pub graph_revision: u64,
    pub delta_digest: String,
    pub entities: Vec<ProjectionEntity>,
    pub assertions: Vec<ProjectionAssertion>,
    pub retractions: Vec<ProjectionRetraction>,
}

pub(crate) struct StoredCommit {
    pub receipt: GraphWriteReceipt,
    pub projection: ProjectionCommit,
}

pub struct PostgresLedger {
    client: Mutex<Client>,
}

impl PostgresLedger {
    /// The platform owns TLS and credential construction; the ledger only
    /// accepts an already-connected client.
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }

    pub async fn connect_tls(connection_string: &str) -> Result<Self, StoreError> {
        let tls = native_tls::TlsConnector::builder()
            .build()
            .map_err(|error| StoreError::Conflict(format!("build PostgreSQL TLS: {error}")))?;
        let (client, connection) =
            tokio_postgres::connect(connection_string, MakeTlsConnector::new(tls)).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("organizational PostgreSQL connection closed: {error}");
            }
        });
        Ok(Self::from_client(client))
    }

    pub async fn migrate(&self) -> Result<(), StoreError> {
        self.client
            .lock()
            .await
            .batch_execute(POSTGRES_SCHEMA)
            .await?;
        Ok(())
    }

    pub(crate) async fn commit(
        &self,
        batch: &CollectedBatch,
        delta: &GraphDelta,
    ) -> Result<StoredCommit, StoreError> {
        let tenant_id = delta.collection().tenant_id().as_str();
        if batch.scope.receipt() != delta.collection() {
            return Err(StoreError::Conflict(
                "collected batch and graph delta receipts differ".to_owned(),
            ));
        }
        validate_observations(batch, delta)?;

        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;

        if let Some(row) = transaction
            .query_opt(
                "SELECT delta_digest, graph_revision FROM organizational_collections WHERE tenant_id = $1 AND collection_id = $2",
                &[&tenant_id, &delta.collection().collection_id().as_str()],
            )
            .await?
        {
            let existing_digest: String = row.get(0);
            let revision: i64 = row.get(1);
            if existing_digest != delta.digest() {
                return Err(StoreError::Conflict(format!(
                    "collection {} was already committed with another digest",
                    delta.collection().collection_id()
                )));
            }
            let receipt = GraphWriteReceipt {
                tenant_id: delta.collection().tenant_id().clone(),
                graph_revision: u64::try_from(revision).map_err(|_| {
                    StoreError::Conflict("stored graph revision is negative".to_owned())
                })?,
                delta_digest: delta.digest().to_owned(),
                entities_upserted: delta.entities().len(),
                assertions_upserted: delta.assertions().len(),
                assertions_retracted: delta.retractions().len(),
            };
            let projection = projection_commit(delta, receipt.graph_revision)?;
            transaction.commit().await?;
            return Ok(StoredCommit { receipt, projection });
        }

        transaction
            .execute(
                "INSERT INTO organizational_graph_revisions (tenant_id, revision) VALUES ($1, 0) ON CONFLICT (tenant_id) DO NOTHING",
                &[&tenant_id],
            )
            .await?;
        let row = transaction
            .query_one(
                "SELECT revision FROM organizational_graph_revisions WHERE tenant_id = $1 FOR UPDATE",
                &[&tenant_id],
            )
            .await?;
        let current_revision: i64 = row.get(0);
        let revision = current_revision
            .checked_add(1)
            .ok_or_else(|| StoreError::Conflict("graph revision overflow".to_owned()))?;

        for retraction in delta.retractions() {
            let row = transaction
                .query_opt(
                    "SELECT source_runtime_id FROM organizational_assertions WHERE tenant_id = $1 AND assertion_id = $2 AND active = TRUE",
                    &[&tenant_id, &retraction.assertion_id().as_str()],
                )
                .await?;
            if let Some(row) = row {
                let owner: String = row.get(0);
                if owner != delta.collection().source_runtime_id().as_str() {
                    return Err(StoreError::Conflict(format!(
                        "source runtime cannot retract assertion {} owned by {owner}",
                        retraction.assertion_id()
                    )));
                }
                transaction
                    .execute(
                        "UPDATE organizational_assertions SET active = FALSE, last_graph_revision = $3 WHERE tenant_id = $1 AND assertion_id = $2",
                        &[&tenant_id, &retraction.assertion_id().as_str(), &revision],
                    )
                    .await?;
                transaction
                    .execute(
                        "DELETE FROM organizational_identity_bindings WHERE tenant_id = $1 AND assertion_id = $2",
                        &[&tenant_id, &retraction.assertion_id().as_str()],
                    )
                    .await?;
                transaction
                    .execute(
                        "DELETE FROM organizational_identity_claims WHERE tenant_id = $1 AND assertion_id = $2",
                        &[&tenant_id, &retraction.assertion_id().as_str()],
                    )
                    .await?;
            }
        }

        for entity in delta.entities() {
            let entity_json = serde_json::to_value(entity)?;
            let row = transaction
                .query_opt(
                    "INSERT INTO organizational_entities (tenant_id, entity_id, entity_json, last_graph_revision) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, entity_id) DO UPDATE SET last_graph_revision = EXCLUDED.last_graph_revision WHERE organizational_entities.entity_json = EXCLUDED.entity_json RETURNING entity_id",
                    &[&tenant_id, &entity.id().as_str(), &entity_json, &revision],
                )
                .await?;
            if row.is_none() {
                return Err(StoreError::Conflict(format!(
                    "entity {} conflicts with stored identity",
                    entity.id()
                )));
            }
        }

        for assertion in delta.assertions() {
            if let GraphAssertion::IdentityBinding(binding) = assertion
                && binding.state() == IdentityBindingState::Confirmed
            {
                let row = transaction
                    .query_opt(
                        "INSERT INTO organizational_identity_bindings (tenant_id, provider_identity_id, canonical_identity_id, assertion_id) VALUES ($1, $2, $3, $4) ON CONFLICT (tenant_id, provider_identity_id) DO UPDATE SET assertion_id = EXCLUDED.assertion_id WHERE organizational_identity_bindings.canonical_identity_id = EXCLUDED.canonical_identity_id RETURNING canonical_identity_id",
                        &[
                            &tenant_id,
                            &binding.provider_identity().as_str(),
                            &binding.canonical_identity().as_str(),
                            &binding.id().as_str(),
                        ],
                    )
                    .await?;
                if row.is_none() {
                    return Err(StoreError::Conflict(format!(
                        "provider identity {} already has another canonical identity",
                        binding.provider_identity()
                    )));
                }
                if let Some(claim) = binding.claim() {
                    let claim_kind = enum_name(&claim.kind())?;
                    let row = transaction
                        .query_opt(
                            "INSERT INTO organizational_identity_claims (tenant_id, claim_kind, claim_value, canonical_identity_id, assertion_id) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, claim_kind, claim_value) DO UPDATE SET assertion_id = EXCLUDED.assertion_id WHERE organizational_identity_claims.canonical_identity_id = EXCLUDED.canonical_identity_id RETURNING canonical_identity_id",
                            &[
                                &tenant_id,
                                &claim_kind,
                                &claim.value(),
                                &binding.canonical_identity().as_str(),
                                &binding.id().as_str(),
                            ],
                        )
                        .await?;
                    if row.is_none() {
                        return Err(StoreError::Conflict(format!(
                            "identity claim {claim_kind}:{} already resolves to another canonical identity",
                            claim.value()
                        )));
                    }
                }
            }
            let (from, to, relation) = assertion_endpoints(assertion);
            let assertion_json = serde_json::to_value(assertion)?;
            let row = transaction
                .query_opt(
                    "INSERT INTO organizational_assertions (tenant_id, assertion_id, source_runtime_id, from_entity_id, to_entity_id, relation, assertion_json, active, last_graph_revision) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8) ON CONFLICT (tenant_id, assertion_id) DO UPDATE SET active = TRUE, last_graph_revision = EXCLUDED.last_graph_revision WHERE organizational_assertions.assertion_json = EXCLUDED.assertion_json RETURNING assertion_id",
                    &[
                        &tenant_id,
                        &assertion.id().as_str(),
                        &assertion.provenance().source_runtime_id().as_str(),
                        &from,
                        &to,
                        &relation,
                        &assertion_json,
                        &revision,
                    ],
                )
                .await?;
            if row.is_none() {
                return Err(StoreError::Conflict(format!(
                    "assertion {} conflicts with stored evidence",
                    assertion.id()
                )));
            }
        }

        let graph_revision = u64::try_from(revision)
            .map_err(|_| StoreError::Conflict("graph revision is negative".to_owned()))?;
        let receipt = GraphWriteReceipt {
            tenant_id: delta.collection().tenant_id().clone(),
            graph_revision,
            delta_digest: delta.digest().to_owned(),
            entities_upserted: delta.entities().len(),
            assertions_upserted: delta.assertions().len(),
            assertions_retracted: delta.retractions().len(),
        };
        let receipt_json = serde_json::to_value(&receipt)?;
        transaction
            .execute(
                "INSERT INTO organizational_collections (tenant_id, collection_id, source_runtime_id, scope, completeness, observed_at_unix_ms, delta_digest, graph_revision, receipt_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &tenant_id,
                    &delta.collection().collection_id().as_str(),
                    &delta.collection().source_runtime_id().as_str(),
                    &delta.collection().scope(),
                    &completeness(delta.collection().completeness()),
                    &delta.collection().observed_at_unix_ms(),
                    &delta.digest(),
                    &revision,
                    &receipt_json,
                ],
            )
            .await?;
        for record in &batch.records {
            let fields_json = serde_json::to_value(&record.fields)?;
            transaction
                .execute(
                    "INSERT INTO organizational_observations (tenant_id, collection_id, observation_id, source_runtime_id, family, provider_kind, provider_id, payload_json, fields_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                    &[
                        &tenant_id,
                        &delta.collection().collection_id().as_str(),
                        &record.observation_id.as_str(),
                        &delta.collection().source_runtime_id().as_str(),
                        &record.family,
                        &record.provider_kind,
                        &record.provider_id,
                        &record.payload,
                        &fields_json,
                    ],
                )
                .await?;
        }
        let projection = projection_commit(delta, graph_revision)?;
        let projection_json = serde_json::to_value(&projection)?;
        transaction
            .execute(
                "INSERT INTO organizational_projection_outbox (tenant_id, graph_revision, delta_digest, projection_json) VALUES ($1, $2, $3, $4)",
                &[&tenant_id, &revision, &delta.digest(), &projection_json],
            )
            .await?;
        transaction
            .execute(
                "UPDATE organizational_graph_revisions SET revision = $2 WHERE tenant_id = $1",
                &[&tenant_id, &revision],
            )
            .await?;
        transaction.commit().await?;
        Ok(StoredCommit {
            receipt,
            projection,
        })
    }

    pub(crate) async fn pending(
        &self,
        tenant_id: &str,
        limit: usize,
    ) -> Result<Vec<ProjectionCommit>, StoreError> {
        let limit = i64::try_from(limit.min(1_000))
            .map_err(|_| StoreError::Conflict("pending limit overflow".to_owned()))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let rows = transaction
            .query(
                "SELECT projection_json FROM organizational_projection_outbox WHERE tenant_id = $1 AND projected_at IS NULL ORDER BY graph_revision LIMIT $2",
                &[&tenant_id, &limit],
            )
            .await?;
        transaction.commit().await?;
        rows.into_iter()
            .map(|row| {
                serde_json::from_value::<ProjectionCommit>(row.get::<_, Value>(0))
                    .map_err(Into::into)
            })
            .collect()
    }

    pub(crate) async fn mark_projected(
        &self,
        tenant_id: &str,
        graph_revision: u64,
    ) -> Result<(), StoreError> {
        let revision = i64::try_from(graph_revision)
            .map_err(|_| StoreError::Conflict("graph revision overflow".to_owned()))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        transaction
            .execute(
                "UPDATE organizational_projection_outbox SET projected_at = NOW() WHERE tenant_id = $1 AND graph_revision = $2",
                &[&tenant_id, &revision],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

async fn set_tenant(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
) -> Result<(), tokio_postgres::Error> {
    transaction
        .query_one(
            "SELECT set_config('cerebro.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await?;
    Ok(())
}

fn validate_observations(batch: &CollectedBatch, delta: &GraphDelta) -> Result<(), StoreError> {
    let available: BTreeSet<_> = batch
        .records
        .iter()
        .map(|record| record.observation_id.as_str())
        .collect();
    for assertion in delta.assertions() {
        for observation in assertion.provenance().observations() {
            if !available.contains(observation.observation_id().as_str()) {
                return Err(StoreError::Conflict(format!(
                    "assertion {} references observation {} missing from its collected batch",
                    assertion.id(),
                    observation.observation_id()
                )));
            }
        }
    }
    Ok(())
}

fn assertion_endpoints(assertion: &GraphAssertion) -> (&str, &str, &str) {
    match assertion {
        GraphAssertion::Relationship(value) => (
            value.from().as_str(),
            value.to().as_str(),
            value.relation().as_str(),
        ),
        GraphAssertion::IdentityBinding(value) => (
            value.provider_identity().as_str(),
            value.canonical_identity().as_str(),
            "represents",
        ),
    }
}

fn completeness(value: &CollectionCompleteness) -> &'static str {
    match value {
        CollectionCompleteness::Partial => "partial",
        CollectionCompleteness::Incremental => "incremental",
        CollectionCompleteness::Complete => "complete",
    }
}

pub(crate) fn projection_commit(
    delta: &GraphDelta,
    revision: u64,
) -> Result<ProjectionCommit, StoreError> {
    let entities = delta
        .entities()
        .iter()
        .map(|entity| {
            Ok(ProjectionEntity {
                entity_id: entity.id().as_str().to_owned(),
                entity_kind: enum_name(entity.kind())?,
                authority_json: serde_json::to_string(entity.authority())?,
                label: entity.label().to_owned(),
                properties_json: serde_json::to_string(entity.properties())?,
            })
        })
        .collect::<Result<_, StoreError>>()?;
    let assertions = delta
        .assertions()
        .iter()
        .map(|assertion| {
            let (from, to, relation) = assertion_endpoints(assertion);
            let (state, observed_at_unix_ms) = match assertion {
                GraphAssertion::Relationship(value) => {
                    ("confirmed".to_owned(), value.observed_at_unix_ms())
                }
                GraphAssertion::IdentityBinding(value) => {
                    (enum_name(&value.state())?, value.observed_at_unix_ms())
                }
            };
            Ok(ProjectionAssertion {
                assertion_id: assertion.id().as_str().to_owned(),
                from_entity_id: from.to_owned(),
                to_entity_id: to.to_owned(),
                relation: relation.to_owned(),
                source_runtime_id: assertion
                    .provenance()
                    .source_runtime_id()
                    .as_str()
                    .to_owned(),
                state,
                provenance_json: serde_json::to_string(assertion.provenance())?,
                observed_at_unix_ms,
            })
        })
        .collect::<Result<_, StoreError>>()?;
    let retractions = delta
        .retractions()
        .iter()
        .map(|retraction| ProjectionRetraction {
            assertion_id: retraction.assertion_id().as_str().to_owned(),
            reason: retraction.reason().to_owned(),
        })
        .collect();
    Ok(ProjectionCommit {
        tenant_id: delta.collection().tenant_id().as_str().to_owned(),
        graph_revision: revision,
        delta_digest: delta.digest().to_owned(),
        entities,
        assertions,
        retractions,
    })
}

fn enum_name<T: Serialize>(value: &T) -> Result<String, StoreError> {
    match serde_json::to_value(value)? {
        Value::String(value) => Ok(value),
        Value::Object(value) if value.len() == 1 => {
            Ok(value.keys().next().cloned().unwrap_or_default())
        }
        _ => Err(StoreError::Conflict(
            "domain enum has no stable storage name".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_enforces_tenant_scope_identity_uniqueness_and_outbox() {
        for required in [
            "FORCE ROW LEVEL SECURITY",
            "PRIMARY KEY (tenant_id, provider_identity_id)",
            "PRIMARY KEY (tenant_id, claim_kind, claim_value)",
            "organizational_projection_outbox",
            "current_setting(''cerebro.tenant_id'', true)",
            "DEFERRABLE INITIALLY DEFERRED",
        ] {
            assert!(POSTGRES_SCHEMA.contains(required), "missing {required}");
        }
    }
}
