use std::collections::BTreeSet;

use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{
    CanonicalIdentityId, CollectionCompleteness, GraphAssertion, GraphDelta,
    IdentityBindingAssertion, IdentityBindingState, IdentityResolutionMethod, TenantId,
};
use cerebro_source_catalog::SourceCatalog;
use cerebro_source_runtime_next::{CollectedBatch, IdentityResolutionSnapshot};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_postgres::Client;

use crate::StoreError;
use crate::{
    CutoverDecision, CutoverGate, ParityReceipt, ParityStatus, ProjectionAuthority,
    ProjectionAuthorityRecord, ProjectionPromotionRequest,
};

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
CREATE TABLE IF NOT EXISTS organizational_parity_receipts (
  tenant_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  collection_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('match', 'mismatch', 'incomplete')),
  mismatch_count BIGINT NOT NULL CHECK (mismatch_count >= 0),
  projection_lag BIGINT NOT NULL CHECK (projection_lag >= 0),
  compared_at_unix_ms BIGINT NOT NULL CHECK (compared_at_unix_ms > 0),
  receipt_digest TEXT NOT NULL,
  receipt_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, receipt_digest)
);
CREATE TABLE IF NOT EXISTS organizational_projection_authority (
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  authority TEXT NOT NULL CHECK (authority IN ('legacy', 'rust')),
  evidence_digest TEXT NOT NULL,
  decision_json JSONB NOT NULL,
  promoted_at_unix_ms BIGINT,
  PRIMARY KEY (tenant_id, source_id, family_id),
  CHECK (
    (authority = 'legacy' AND promoted_at_unix_ms IS NULL) OR
    (authority = 'rust' AND promoted_at_unix_ms > 0)
  )
);
CREATE INDEX IF NOT EXISTS organizational_projection_pending_idx
  ON organizational_projection_outbox (graph_revision)
  WHERE projected_at IS NULL;
CREATE INDEX IF NOT EXISTS organizational_parity_latest_idx
  ON organizational_parity_receipts
    (tenant_id, source_id, family_id, compared_at_unix_ms DESC);
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
ALTER TABLE organizational_parity_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_parity_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_projection_authority ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_projection_authority FORCE ROW LEVEL SECURITY;
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
    'organizational_projection_outbox',
    'organizational_parity_receipts',
    'organizational_projection_authority'
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
    #[serde(default)]
    pub external_id: Option<String>,
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

    pub async fn record_parity(&self, receipt: &ParityReceipt) -> Result<(), StoreError> {
        let mismatch_count = i64::try_from(receipt.mismatch_count())
            .map_err(|_| StoreError::Conflict("parity mismatch count overflow".to_owned()))?;
        let projection_lag = i64::try_from(receipt.projection_lag())
            .map_err(|_| StoreError::Conflict("parity projection lag overflow".to_owned()))?;
        let receipt_json = serde_json::to_value(receipt)?;
        let status = match receipt.status() {
            ParityStatus::Match => "match",
            ParityStatus::Mismatch => "mismatch",
            ParityStatus::Incomplete => "incomplete",
        };
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, receipt.tenant_id()).await?;
        let row = transaction
            .query_opt(
                "INSERT INTO organizational_parity_receipts (tenant_id, source_runtime_id, source_id, family_id, collection_id, status, mismatch_count, projection_lag, compared_at_unix_ms, receipt_digest, receipt_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (tenant_id, receipt_digest) DO UPDATE SET receipt_digest = EXCLUDED.receipt_digest WHERE organizational_parity_receipts.receipt_json = EXCLUDED.receipt_json RETURNING receipt_digest",
                &[
                    &receipt.tenant_id(),
                    &receipt.source_runtime_id(),
                    &receipt.source_id(),
                    &receipt.family_id(),
                    &receipt.collection_id(),
                    &status,
                    &mismatch_count,
                    &projection_lag,
                    &receipt.compared_at_unix_ms(),
                    &receipt.receipt_digest(),
                    &receipt_json,
                ],
            )
            .await?;
        if row.is_none() {
            return Err(StoreError::Conflict(format!(
                "parity receipt {} conflicts with stored evidence",
                receipt.receipt_digest()
            )));
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn parity_receipt_count(
        &self,
        tenant_id: &str,
        source_id: &str,
        family_id: &str,
    ) -> Result<u64, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let row = transaction
            .query_one(
                "SELECT COUNT(*) FROM organizational_parity_receipts WHERE tenant_id = $1 AND source_id = $2 AND family_id = $3",
                &[&tenant_id, &source_id, &family_id],
            )
            .await?;
        transaction.commit().await?;
        let count: i64 = row.get(0);
        u64::try_from(count)
            .map_err(|_| StoreError::Conflict("parity receipt count is negative".to_owned()))
    }

    pub async fn parity_receipts(
        &self,
        tenant_id: &str,
        source_id: &str,
        family_id: &str,
    ) -> Result<Vec<ParityReceipt>, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let rows = transaction
            .query(
                "SELECT receipt_json FROM organizational_parity_receipts WHERE tenant_id = $1 AND source_id = $2 AND family_id = $3 ORDER BY compared_at_unix_ms, receipt_digest",
                &[&tenant_id, &source_id, &family_id],
            )
            .await?;
        transaction.commit().await?;
        rows.into_iter()
            .map(|row| serde_json::from_value(row.get::<_, Value>(0)).map_err(Into::into))
            .collect()
    }

    pub async fn projection_authority(
        &self,
        tenant_id: &str,
        source_id: &str,
        family_id: &str,
    ) -> Result<ProjectionAuthorityRecord, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let row = transaction
            .query_opt(
                "SELECT authority, evidence_digest, promoted_at_unix_ms FROM organizational_projection_authority WHERE tenant_id = $1 AND source_id = $2 AND family_id = $3",
                &[&tenant_id, &source_id, &family_id],
            )
            .await?;
        transaction.commit().await?;
        let Some(row) = row else {
            return Ok(ProjectionAuthorityRecord {
                tenant_id: tenant_id.to_owned(),
                source_id: source_id.to_owned(),
                family_id: family_id.to_owned(),
                authority: ProjectionAuthority::Legacy,
                evidence_digest: String::new(),
                promoted_at_unix_ms: None,
            });
        };
        let authority: String = row.get(0);
        Ok(ProjectionAuthorityRecord {
            tenant_id: tenant_id.to_owned(),
            source_id: source_id.to_owned(),
            family_id: family_id.to_owned(),
            authority: match authority.as_str() {
                "legacy" => ProjectionAuthority::Legacy,
                "rust" => ProjectionAuthority::Rust,
                _ => {
                    return Err(StoreError::Conflict(format!(
                        "stored projection authority {authority} is invalid"
                    )));
                }
            },
            evidence_digest: row.get(1),
            promoted_at_unix_ms: row.get(2),
        })
    }

    pub async fn evaluate_and_promote_projection_authority(
        &self,
        catalog: &SourceCatalog,
        request: &ProjectionPromotionRequest,
    ) -> Result<ProjectionAuthorityRecord, StoreError> {
        let receipts = self
            .parity_receipts(
                request.tenant_id(),
                request.source_id(),
                request.family_id(),
            )
            .await?;
        let decision = CutoverGate::new(request.policy())
            .evaluate(
                catalog,
                request.source_id(),
                request.family_id(),
                &receipts,
                request.projection_lag(),
            )
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        self.promote_projection_authority(
            request.tenant_id(),
            &decision,
            request.promoted_at_unix_ms(),
        )
        .await
    }

    async fn promote_projection_authority(
        &self,
        tenant_id: &str,
        decision: &CutoverDecision,
        promoted_at_unix_ms: i64,
    ) -> Result<ProjectionAuthorityRecord, StoreError> {
        if !decision.is_allowed() {
            return Err(StoreError::Conflict(format!(
                "projection cutover is blocked: {}",
                decision.reasons().join("; ")
            )));
        }
        if promoted_at_unix_ms <= 0 {
            return Err(StoreError::Conflict(
                "projection promotion time must be positive".to_owned(),
            ));
        }
        let decision_json = serde_json::to_value(decision)?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let row = transaction
            .query_opt(
                "INSERT INTO organizational_projection_authority (tenant_id, source_id, family_id, authority, evidence_digest, decision_json, promoted_at_unix_ms) VALUES ($1, $2, $3, 'rust', $4, $5, $6) ON CONFLICT (tenant_id, source_id, family_id) DO UPDATE SET authority = 'rust', evidence_digest = EXCLUDED.evidence_digest, decision_json = EXCLUDED.decision_json, promoted_at_unix_ms = EXCLUDED.promoted_at_unix_ms WHERE organizational_projection_authority.authority = 'legacy' OR (organizational_projection_authority.authority = 'rust' AND organizational_projection_authority.evidence_digest = EXCLUDED.evidence_digest) RETURNING evidence_digest, promoted_at_unix_ms",
                &[
                    &tenant_id,
                    &decision.source_id(),
                    &decision.family_id(),
                    &decision.evidence_digest(),
                    &decision_json,
                    &promoted_at_unix_ms,
                ],
            )
            .await?;
        let Some(row) = row else {
            return Err(StoreError::Conflict(
                "projection authority was already promoted with different evidence".to_owned(),
            ));
        };
        transaction.commit().await?;
        Ok(ProjectionAuthorityRecord {
            tenant_id: tenant_id.to_owned(),
            source_id: decision.source_id().to_owned(),
            family_id: decision.family_id().to_owned(),
            authority: ProjectionAuthority::Rust,
            evidence_digest: row.get(0),
            promoted_at_unix_ms: row.get(1),
        })
    }

    pub async fn identity_resolution_snapshot(
        &self,
        tenant_id: &TenantId,
    ) -> Result<IdentityResolutionSnapshot, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let rows = transaction
            .query(
                "SELECT claims.claim_value, claims.canonical_identity_id, entities.entity_json->>'label' FROM organizational_identity_claims claims JOIN organizational_entities entities ON entities.tenant_id = claims.tenant_id AND entities.entity_id = claims.canonical_identity_id WHERE claims.tenant_id = $1 AND claims.claim_kind = 'verified_email' ORDER BY claims.claim_value",
                &[&tenant_id.as_str()],
            )
            .await?;
        transaction.commit().await?;
        let mut snapshot = IdentityResolutionSnapshot::new(tenant_id.clone());
        for row in rows {
            let email: String = row.get(0);
            let stored_id: String = row.get(1);
            let label: String = row.get(2);
            let canonical_id = stored_id.strip_prefix("person:canonical:").ok_or_else(|| {
                StoreError::Conflict(format!(
                    "stored canonical identity {stored_id} has an invalid identifier"
                ))
            })?;
            snapshot
                .add_verified_email(
                    email,
                    CanonicalIdentityId::parse(canonical_id).map_err(|error| {
                        StoreError::Conflict(format!(
                            "stored canonical identity {stored_id} is invalid: {error}"
                        ))
                    })?,
                    label,
                )
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
        }
        Ok(snapshot)
    }

    /// Commits authoritative current state and its projection outbox entry.
    /// The caller must subsequently project or replay the pending revision.
    pub async fn commit_pending(
        &self,
        batch: &CollectedBatch,
        delta: &GraphDelta,
    ) -> Result<GraphWriteReceipt, StoreError> {
        Ok(self.commit(batch, delta).await?.receipt)
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
                    "SELECT source_runtime_id, from_entity_id, to_entity_id, relation FROM organizational_assertions WHERE tenant_id = $1 AND assertion_id = $2 AND active = TRUE",
                    &[&tenant_id, &retraction.assertion_id().as_str()],
                )
                .await?;
            if let Some(row) = row {
                let owner: String = row.get(0);
                let from_entity_id: String = row.get(1);
                let to_entity_id: String = row.get(2);
                let relation: String = row.get(3);
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
                if relation == "represents" {
                    transaction
                        .execute(
                            "UPDATE organizational_identity_bindings SET assertion_id = replacement.assertion_id FROM (SELECT assertion_id FROM organizational_assertions WHERE tenant_id = $1 AND from_entity_id = $2 AND to_entity_id = $3 AND relation = 'represents' AND active = TRUE ORDER BY assertion_id LIMIT 1) replacement WHERE organizational_identity_bindings.tenant_id = $1 AND organizational_identity_bindings.provider_identity_id = $2",
                            &[&tenant_id, &from_entity_id, &to_entity_id],
                        )
                        .await?;
                    transaction
                        .execute(
                            "DELETE FROM organizational_identity_bindings WHERE tenant_id = $1 AND provider_identity_id = $2 AND NOT EXISTS (SELECT 1 FROM organizational_assertions WHERE tenant_id = $1 AND from_entity_id = $2 AND relation = 'represents' AND active = TRUE)",
                            &[&tenant_id, &from_entity_id],
                        )
                        .await?;
                }
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

        for method in [
            IdentityResolutionMethod::AuthoritativeEmployeeId,
            IdentityResolutionMethod::HumanDecision,
            IdentityResolutionMethod::VerifiedEmail,
            IdentityResolutionMethod::ExistingClaimMatch,
        ] {
            for binding in delta.assertions().iter().filter_map(|assertion| {
                let GraphAssertion::IdentityBinding(binding) = assertion else {
                    return None;
                };
                (binding.state() == IdentityBindingState::Confirmed && binding.method() == method)
                    .then_some(binding)
            }) {
                upsert_identity_binding(&transaction, tenant_id, binding).await?;
                match method {
                    IdentityResolutionMethod::AuthoritativeEmployeeId
                    | IdentityResolutionMethod::HumanDecision => {
                        if binding.claim().is_some() {
                            upsert_identity_claim(&transaction, tenant_id, binding).await?;
                        }
                    }
                    IdentityResolutionMethod::VerifiedEmail => {
                        require_employee_anchor(&transaction, tenant_id, binding).await?;
                        upsert_identity_claim(&transaction, tenant_id, binding).await?;
                    }
                    IdentityResolutionMethod::ExistingClaimMatch => {
                        require_identity_claim(&transaction, tenant_id, binding).await?;
                    }
                    IdentityResolutionMethod::AgentProposal => {}
                }
            }
        }

        for assertion in delta.assertions() {
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

async fn upsert_identity_binding(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    binding: &IdentityBindingAssertion,
) -> Result<(), StoreError> {
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
    Ok(())
}

async fn upsert_identity_claim(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    binding: &IdentityBindingAssertion,
) -> Result<(), StoreError> {
    let claim = binding
        .claim()
        .ok_or_else(|| StoreError::Conflict("identity claim is required".to_owned()))?;
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
    Ok(())
}

async fn require_employee_anchor(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    binding: &IdentityBindingAssertion,
) -> Result<(), StoreError> {
    let exists = transaction
        .query_opt(
            "SELECT 1 FROM organizational_identity_claims WHERE tenant_id = $1 AND canonical_identity_id = $2 AND claim_kind = 'employee_id'",
            &[&tenant_id, &binding.canonical_identity().as_str()],
        )
        .await?
        .is_some();
    if !exists {
        return Err(StoreError::Conflict(format!(
            "canonical identity {} has no authoritative employee anchor",
            binding.canonical_identity()
        )));
    }
    Ok(())
}

async fn require_identity_claim(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    binding: &IdentityBindingAssertion,
) -> Result<(), StoreError> {
    let claim = binding
        .claim()
        .ok_or_else(|| StoreError::Conflict("identity claim match is required".to_owned()))?;
    let claim_kind = enum_name(&claim.kind())?;
    let row = transaction
        .query_opt(
            "SELECT canonical_identity_id FROM organizational_identity_claims WHERE tenant_id = $1 AND claim_kind = $2 AND claim_value = $3",
            &[&tenant_id, &claim_kind, &claim.value()],
        )
        .await?;
    let Some(row) = row else {
        return Err(StoreError::Conflict(format!(
            "identity claim {claim_kind}:{} is not authoritative",
            claim.value()
        )));
    };
    let canonical_identity_id: String = row.get(0);
    if canonical_identity_id != binding.canonical_identity().as_str() {
        return Err(StoreError::Conflict(format!(
            "identity claim {claim_kind}:{} belongs to another canonical identity",
            claim.value()
        )));
    }
    Ok(())
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
                external_id: entity
                    .properties()
                    .get("resource_urn")
                    .or_else(|| entity.properties().get("entity_urn"))
                    .or_else(|| entity.properties().get("urn"))
                    .cloned(),
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
            "organizational_parity_receipts",
            "current_setting(''cerebro.tenant_id'', true)",
            "DEFERRABLE INITIALLY DEFERRED",
        ] {
            assert!(POSTGRES_SCHEMA.contains(required), "missing {required}");
        }
    }
}
