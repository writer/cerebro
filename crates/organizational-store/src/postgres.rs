use std::collections::BTreeSet;

use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{
    CanonicalIdentityId, CollectionCompleteness, GraphAssertion, GraphDelta,
    IdentityBindingAssertion, IdentityBindingState, IdentityResolutionMethod, TenantId,
};
use cerebro_source_catalog::SourceCatalog;
use cerebro_source_runtime_next::{
    CollectedBatch, CommittedSourceEvent, IdentityResolutionSnapshot, SourceRuntimeLeaseFence,
};
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

const MAX_SOURCE_RUNTIME_LEASE_TTL_MILLIS: u64 = 24 * 60 * 60 * 1_000;

pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS source_runtimes (
  id TEXT PRIMARY KEY,
  runtime_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE source_runtimes ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE source_runtimes ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE source_runtimes
  ADD COLUMN IF NOT EXISTS lease_generation BIGINT NOT NULL DEFAULT 0
  CHECK (lease_generation >= 0);
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
CREATE TABLE IF NOT EXISTS organizational_source_event_receipts (
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  event_kind TEXT NOT NULL,
  schema_ref TEXT NOT NULL,
  observed_at_unix_ms BIGINT NOT NULL CHECK (observed_at_unix_ms > 0),
  attributes_digest TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  record_digest TEXT NOT NULL,
  PRIMARY KEY (tenant_id, event_id)
);
CREATE TABLE IF NOT EXISTS organizational_legacy_projection_receipts (
  tenant_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  observed_at_unix_ms BIGINT NOT NULL CHECK (observed_at_unix_ms > 0),
  entity_count BIGINT NOT NULL CHECK (entity_count >= 0),
  link_count BIGINT NOT NULL CHECK (link_count >= 0),
  entity_retraction_count BIGINT NOT NULL CHECK (entity_retraction_count >= 0),
  link_retraction_count BIGINT NOT NULL CHECK (link_retraction_count >= 0),
  cleanup_request_count BIGINT NOT NULL CHECK (cleanup_request_count >= 0),
  delta_digest TEXT NOT NULL,
  delta_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, event_id),
  FOREIGN KEY (tenant_id, event_id)
    REFERENCES organizational_source_event_receipts (tenant_id, event_id)
    DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE IF NOT EXISTS organizational_source_collection_receipts (
  tenant_id TEXT NOT NULL,
  collection_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  started_at_unix_ms BIGINT NOT NULL CHECK (started_at_unix_ms > 0),
  completed_at_unix_ms BIGINT NOT NULL CHECK (completed_at_unix_ms >= started_at_unix_ms),
  status TEXT NOT NULL CHECK (status IN ('complete', 'incomplete')),
  pages_read BIGINT NOT NULL CHECK (pages_read >= 0),
  records_scanned BIGINT NOT NULL CHECK (records_scanned >= 0),
  records_accepted BIGINT NOT NULL CHECK (records_accepted >= 0),
  records_rejected BIGINT NOT NULL CHECK (records_rejected >= 0),
  entities_projected BIGINT NOT NULL CHECK (entities_projected >= 0),
  links_projected BIGINT NOT NULL CHECK (links_projected >= 0),
  manifest_digest TEXT NOT NULL,
  manifest_json JSONB NOT NULL,
  PRIMARY KEY (tenant_id, collection_id)
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
CREATE INDEX IF NOT EXISTS organizational_source_collection_latest_idx
  ON organizational_source_collection_receipts
    (tenant_id, source_runtime_id, completed_at_unix_ms DESC);
ALTER TABLE organizational_graph_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_graph_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_collections ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_collections FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_source_event_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_source_event_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_legacy_projection_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_legacy_projection_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE organizational_source_collection_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizational_source_collection_receipts FORCE ROW LEVEL SECURITY;
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
    'organizational_source_event_receipts',
    'organizational_legacy_projection_receipts',
    'organizational_source_collection_receipts',
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

const IDENTITY_CLAIM_REPLACEMENT_QUERY: &str = r#"
SELECT assertion_id
FROM organizational_assertions
WHERE tenant_id = $1
  AND to_entity_id = $2
  AND relation = 'represents'
  AND active = TRUE
  AND assertion_json->>'assertion_type' = 'identity_binding'
  AND assertion_json->>'state' = 'confirmed'
  AND assertion_json->>'method' IN (
    'authoritative_employee_id',
    'verified_email',
    'human_decision'
  )
  AND assertion_json->'claim'->>'kind' = $3
  AND assertion_json->'claim'->>'value' = $4
ORDER BY assertion_id
LIMIT 1
"#;

const POSTGRES_WRITE_BATCH_SIZE: usize = 1_000;

const UPSERT_ENTITIES_QUERY: &str = r#"
WITH input AS MATERIALIZED (
  SELECT entity_id, entity_json
  FROM jsonb_to_recordset($2::jsonb)
    AS row(entity_id TEXT, entity_json JSONB)
),
upserted AS (
  INSERT INTO organizational_entities (
    tenant_id,
    entity_id,
    entity_json,
    last_graph_revision
  )
  SELECT $1, entity_id, entity_json, $3
  FROM input
  ON CONFLICT (tenant_id, entity_id) DO UPDATE
  SET entity_json = EXCLUDED.entity_json,
      last_graph_revision = EXCLUDED.last_graph_revision
  WHERE organizational_entities.entity_json->'kind' = EXCLUDED.entity_json->'kind'
    AND organizational_entities.entity_json->'authority' = EXCLUDED.entity_json->'authority'
  RETURNING entity_id
)
SELECT input.entity_id
FROM input
LEFT JOIN upserted USING (entity_id)
WHERE upserted.entity_id IS NULL
ORDER BY input.entity_id
LIMIT 1
"#;

const UPSERT_ASSERTIONS_QUERY: &str = r#"
WITH input AS MATERIALIZED (
  SELECT
    assertion_id,
    source_runtime_id,
    from_entity_id,
    to_entity_id,
    relation,
    assertion_json
  FROM jsonb_to_recordset($2::jsonb) AS row(
    assertion_id TEXT,
    source_runtime_id TEXT,
    from_entity_id TEXT,
    to_entity_id TEXT,
    relation TEXT,
    assertion_json JSONB
  )
),
upserted AS (
  INSERT INTO organizational_assertions (
    tenant_id,
    assertion_id,
    source_runtime_id,
    from_entity_id,
    to_entity_id,
    relation,
    assertion_json,
    active,
    last_graph_revision
  )
  SELECT
    $1,
    assertion_id,
    source_runtime_id,
    from_entity_id,
    to_entity_id,
    relation,
    assertion_json,
    TRUE,
    $3
  FROM input
  ON CONFLICT (tenant_id, assertion_id) DO UPDATE
  SET assertion_json = EXCLUDED.assertion_json,
      active = TRUE,
      last_graph_revision = EXCLUDED.last_graph_revision
  WHERE organizational_assertions.source_runtime_id = EXCLUDED.source_runtime_id
    AND organizational_assertions.from_entity_id = EXCLUDED.from_entity_id
    AND organizational_assertions.to_entity_id = EXCLUDED.to_entity_id
    AND organizational_assertions.relation = EXCLUDED.relation
  RETURNING assertion_id
)
SELECT input.assertion_id
FROM input
LEFT JOIN upserted USING (assertion_id)
WHERE upserted.assertion_id IS NULL
ORDER BY input.assertion_id
LIMIT 1
"#;

const INSERT_OBSERVATIONS_QUERY: &str = r#"
INSERT INTO organizational_observations (
  tenant_id,
  collection_id,
  observation_id,
  source_runtime_id,
  family,
  provider_kind,
  provider_id,
  payload_json,
  fields_json
)
SELECT
  $1,
  $2,
  observation_id,
  $3,
  family,
  provider_kind,
  provider_id,
  payload_json,
  fields_json
FROM jsonb_to_recordset($4::jsonb) AS row(
  observation_id TEXT,
  family TEXT,
  provider_kind TEXT,
  provider_id TEXT,
  payload_json JSONB,
  fields_json JSONB
)
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

pub(crate) struct CommittedCollection {
    pub receipt: GraphWriteReceipt,
    pub pending_projection: Option<ProjectionCommit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceEventReceipt {
    pub tenant_id: String,
    pub event_id: String,
    pub record_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyProjectionReceipt {
    pub tenant_id: String,
    pub event_id: String,
    pub delta_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceCollectionReceipt {
    pub tenant_id: String,
    pub collection_id: String,
    pub manifest_digest: String,
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

    /// Acquire the shared source-runtime lease and return its durable fencing
    /// generation. A missing runtime, tenant mismatch, or active competing
    /// owner all return `None` without disclosing which condition matched.
    pub async fn acquire_source_runtime_lease(
        &self,
        tenant_id: &TenantId,
        source_runtime_id: &cerebro_organizational_model::SourceRuntimeId,
        owner: &str,
        ttl_millis: u64,
    ) -> Result<Option<SourceRuntimeLeaseFence>, StoreError> {
        validate_lease_request(owner, ttl_millis)?;
        let ttl_millis = i64::try_from(ttl_millis)
            .map_err(|_| StoreError::Conflict("source runtime lease TTL overflow".to_owned()))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                r#"
UPDATE source_runtimes
SET lease_generation = CASE
      WHEN lease_owner = $3
       AND lease_expires_at > NOW()
       AND lease_generation > 0
      THEN lease_generation
      ELSE lease_generation + 1
    END,
    lease_owner = $3,
    lease_expires_at = NOW() + ($4::BIGINT * INTERVAL '1 millisecond'),
    updated_at = NOW()
WHERE id = $1
  AND runtime_json->>'tenant_id' = $2
  AND (
    lease_expires_at IS NULL
    OR lease_expires_at <= NOW()
    OR lease_owner = $3
  )
RETURNING lease_generation
"#,
                &[
                    &source_runtime_id.as_str(),
                    &tenant_id.as_str(),
                    &owner,
                    &ttl_millis,
                ],
            )
            .await?;
        transaction.commit().await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let generation = positive_generation(row.get(0))?;
        Ok(Some(
            SourceRuntimeLeaseFence::new(
                tenant_id.clone(),
                source_runtime_id.clone(),
                owner,
                generation,
            )
            .map_err(|message| StoreError::Conflict(message.to_owned()))?,
        ))
    }

    /// Renew only the exact, still-live fencing generation.
    pub async fn renew_source_runtime_lease(
        &self,
        fence: &SourceRuntimeLeaseFence,
        ttl_millis: u64,
    ) -> Result<bool, StoreError> {
        validate_lease_request(fence.owner(), ttl_millis)?;
        let generation = storage_generation(fence.generation())?;
        let ttl_millis = i64::try_from(ttl_millis)
            .map_err(|_| StoreError::Conflict("source runtime lease TTL overflow".to_owned()))?;
        let changed = self
            .client
            .lock()
            .await
            .execute(
                r#"
UPDATE source_runtimes
SET lease_expires_at = NOW() + ($5::BIGINT * INTERVAL '1 millisecond')
WHERE id = $1
  AND runtime_json->>'tenant_id' = $2
  AND lease_owner = $3
  AND lease_generation = $4
  AND lease_expires_at > NOW()
"#,
                &[
                    &fence.source_runtime_id().as_str(),
                    &fence.tenant_id().as_str(),
                    &fence.owner(),
                    &generation,
                    &ttl_millis,
                ],
            )
            .await?;
        Ok(changed == 1)
    }

    /// Release only the exact fencing generation. A stale worker cannot
    /// release a successor's lease.
    pub async fn release_source_runtime_lease(
        &self,
        fence: &SourceRuntimeLeaseFence,
    ) -> Result<bool, StoreError> {
        let generation = storage_generation(fence.generation())?;
        let changed = self
            .client
            .lock()
            .await
            .execute(
                r#"
UPDATE source_runtimes
SET lease_owner = NULL,
    lease_expires_at = NULL,
    updated_at = NOW()
WHERE id = $1
  AND runtime_json->>'tenant_id' = $2
  AND lease_owner = $3
  AND lease_generation = $4
"#,
                &[
                    &fence.source_runtime_id().as_str(),
                    &fence.tenant_id().as_str(),
                    &fence.owner(),
                    &generation,
                ],
            )
            .await?;
        Ok(changed == 1)
    }

    /// Records the rebuildable PostgreSQL receipt for one source event already
    /// committed to JetStream. Replays are idempotent; an event ID reused for
    /// different content fails closed.
    pub async fn record_source_event(
        &self,
        event: &CommittedSourceEvent,
    ) -> Result<SourceEventReceipt, StoreError> {
        let tenant_id = event.tenant_id().as_str();
        let event_id = event.observation_id().as_str();
        let record_digest = event.record_digest();
        let attributes_digest = event.attributes_digest();
        let payload_digest = event.payload_digest();
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let row = transaction
            .query_opt(
                "INSERT INTO organizational_source_event_receipts (tenant_id, event_id, source_runtime_id, source_id, family_id, event_kind, schema_ref, observed_at_unix_ms, attributes_digest, payload_digest, record_digest) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT (tenant_id, event_id) DO UPDATE SET record_digest = EXCLUDED.record_digest WHERE organizational_source_event_receipts.record_digest = EXCLUDED.record_digest RETURNING record_digest",
                &[
                    &tenant_id,
                    &event_id,
                    &event.source_runtime_id().as_str(),
                    &event.source_id(),
                    &event.family_id(),
                    &event.event_kind(),
                    &event.schema_ref(),
                    &event.observed_at_unix_ms(),
                    &attributes_digest,
                    &payload_digest,
                    &record_digest,
                ],
            )
            .await?;
        if row.is_none() {
            return Err(StoreError::Conflict(format!(
                "source event {event_id} conflicts with the stored record"
            )));
        }
        transaction.commit().await?;
        Ok(SourceEventReceipt {
            tenant_id: tenant_id.to_owned(),
            event_id: event_id.to_owned(),
            record_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_legacy_projection(
        &self,
        tenant_id: &str,
        event_id: &str,
        source_runtime_id: &str,
        source_id: &str,
        family_id: &str,
        observed_at_unix_ms: i64,
        entity_count: usize,
        link_count: usize,
        entity_retraction_count: usize,
        link_retraction_count: usize,
        cleanup_request_count: usize,
        delta_digest: &str,
        delta_json: &Value,
    ) -> Result<LegacyProjectionReceipt, StoreError> {
        let entity_count = i64::try_from(entity_count)
            .map_err(|_| StoreError::Conflict("legacy entity count overflow".to_owned()))?;
        let link_count = i64::try_from(link_count)
            .map_err(|_| StoreError::Conflict("legacy link count overflow".to_owned()))?;
        let entity_retraction_count = i64::try_from(entity_retraction_count).map_err(|_| {
            StoreError::Conflict("legacy entity retraction count overflow".to_owned())
        })?;
        let link_retraction_count = i64::try_from(link_retraction_count).map_err(|_| {
            StoreError::Conflict("legacy link retraction count overflow".to_owned())
        })?;
        let cleanup_request_count = i64::try_from(cleanup_request_count).map_err(|_| {
            StoreError::Conflict("legacy cleanup request count overflow".to_owned())
        })?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let row = transaction
            .query_opt(
                "INSERT INTO organizational_legacy_projection_receipts (tenant_id, event_id, source_runtime_id, source_id, family_id, observed_at_unix_ms, entity_count, link_count, entity_retraction_count, link_retraction_count, cleanup_request_count, delta_digest, delta_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (tenant_id, event_id) DO UPDATE SET delta_digest = EXCLUDED.delta_digest WHERE organizational_legacy_projection_receipts.delta_digest = EXCLUDED.delta_digest AND organizational_legacy_projection_receipts.delta_json = EXCLUDED.delta_json RETURNING delta_digest",
                &[
                    &tenant_id,
                    &event_id,
                    &source_runtime_id,
                    &source_id,
                    &family_id,
                    &observed_at_unix_ms,
                    &entity_count,
                    &link_count,
                    &entity_retraction_count,
                    &link_retraction_count,
                    &cleanup_request_count,
                    &delta_digest,
                    &delta_json,
                ],
            )
            .await?;
        if row.is_none() {
            return Err(StoreError::Conflict(format!(
                "legacy projection for source event {event_id} conflicts with the stored record"
            )));
        }
        transaction.commit().await?;
        Ok(LegacyProjectionReceipt {
            tenant_id: tenant_id.to_owned(),
            event_id: event_id.to_owned(),
            delta_digest: delta_digest.to_owned(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_source_collection(
        &self,
        tenant_id: &str,
        collection_id: &str,
        source_runtime_id: &str,
        source_id: &str,
        started_at_unix_ms: i64,
        completed_at_unix_ms: i64,
        status: &str,
        pages_read: u32,
        records_scanned: u32,
        records_accepted: u32,
        records_rejected: u32,
        entities_projected: u32,
        links_projected: u32,
        manifest_digest: &str,
        manifest_json: &Value,
    ) -> Result<SourceCollectionReceipt, StoreError> {
        let pages_read = i64::from(pages_read);
        let records_scanned = i64::from(records_scanned);
        let records_accepted = i64::from(records_accepted);
        let records_rejected = i64::from(records_rejected);
        let entities_projected = i64::from(entities_projected);
        let links_projected = i64::from(links_projected);
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let row = transaction
            .query_opt(
                "INSERT INTO organizational_source_collection_receipts (tenant_id, collection_id, source_runtime_id, source_id, started_at_unix_ms, completed_at_unix_ms, status, pages_read, records_scanned, records_accepted, records_rejected, entities_projected, links_projected, manifest_digest, manifest_json) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) ON CONFLICT (tenant_id, collection_id) DO UPDATE SET manifest_digest = EXCLUDED.manifest_digest WHERE organizational_source_collection_receipts.manifest_digest = EXCLUDED.manifest_digest AND organizational_source_collection_receipts.manifest_json = EXCLUDED.manifest_json RETURNING manifest_digest",
                &[
                    &tenant_id,
                    &collection_id,
                    &source_runtime_id,
                    &source_id,
                    &started_at_unix_ms,
                    &completed_at_unix_ms,
                    &status,
                    &pages_read,
                    &records_scanned,
                    &records_accepted,
                    &records_rejected,
                    &entities_projected,
                    &links_projected,
                    &manifest_digest,
                    &manifest_json,
                ],
            )
            .await?;
        if row.is_none() {
            return Err(StoreError::Conflict(format!(
                "source collection {collection_id} conflicts with the stored record"
            )));
        }
        transaction.commit().await?;
        Ok(SourceCollectionReceipt {
            tenant_id: tenant_id.to_owned(),
            collection_id: collection_id.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
        })
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
        let decision = self.evaluate_projection_authority(catalog, request).await?;
        self.promote_projection_authority(
            request.tenant_id(),
            &decision,
            request.promoted_at_unix_ms(),
        )
        .await
    }

    /// Evaluate the durable cutover evidence without changing projection
    /// authority. Operators use this before the irreversible promotion step.
    pub async fn evaluate_projection_authority(
        &self,
        catalog: &SourceCatalog,
        request: &ProjectionPromotionRequest,
    ) -> Result<CutoverDecision, StoreError> {
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
        Ok(decision)
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

    /// Commit current state under the exact source-runtime lease generation
    /// without applying the rebuildable Neo4j projection.
    pub async fn commit_pending_fenced(
        &self,
        batch: &CollectedBatch,
        delta: &GraphDelta,
        fence: &SourceRuntimeLeaseFence,
    ) -> Result<GraphWriteReceipt, StoreError> {
        Ok(self.commit_fenced(batch, delta, fence).await?.receipt)
    }

    pub(crate) async fn commit(
        &self,
        batch: &CollectedBatch,
        delta: &GraphDelta,
    ) -> Result<StoredCommit, StoreError> {
        self.commit_with_fence(batch, delta, None).await
    }

    pub(crate) async fn commit_fenced(
        &self,
        batch: &CollectedBatch,
        delta: &GraphDelta,
        fence: &SourceRuntimeLeaseFence,
    ) -> Result<StoredCommit, StoreError> {
        self.commit_with_fence(batch, delta, Some(fence)).await
    }

    async fn commit_with_fence(
        &self,
        batch: &CollectedBatch,
        delta: &GraphDelta,
        fence: Option<&SourceRuntimeLeaseFence>,
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
        if let Some(fence) = fence {
            require_source_runtime_lease(&transaction, delta, fence).await?;
        }

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
                    replace_or_delete_identity_claim(
                        &transaction,
                        tenant_id,
                        retraction.assertion_id().as_str(),
                    )
                    .await?;
                }
            }
        }

        upsert_entities(&transaction, tenant_id, revision, delta).await?;

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

        upsert_assertions(&transaction, tenant_id, revision, delta).await?;

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
        insert_observations(&transaction, tenant_id, batch, delta).await?;
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

    pub(crate) async fn committed_collection(
        &self,
        tenant_id: &TenantId,
        collection_id: &str,
    ) -> Result<Option<CommittedCollection>, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let row = transaction
            .query_opt(
                "SELECT collection.graph_revision, collection.delta_digest, (collection.receipt_json->>'entities_upserted')::BIGINT, (collection.receipt_json->>'assertions_upserted')::BIGINT, (collection.receipt_json->>'assertions_retracted')::BIGINT, outbox.projection_json, outbox.projected_at IS NULL, outbox.graph_revision IS NOT NULL FROM organizational_collections collection LEFT JOIN organizational_projection_outbox outbox ON outbox.tenant_id = collection.tenant_id AND outbox.graph_revision = collection.graph_revision WHERE collection.tenant_id = $1 AND collection.collection_id = $2",
                &[&tenant_id.as_str(), &collection_id],
            )
            .await?;
        transaction.commit().await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let revision: i64 = row.get(0);
        let graph_revision = u64::try_from(revision)
            .map_err(|_| StoreError::Conflict("stored graph revision is negative".to_owned()))?;
        let delta_digest: String = row.get(1);
        let outbox_exists: bool = row.get(7);
        if !outbox_exists {
            return Err(StoreError::Conflict(
                "committed collection is missing its projection outbox entry".to_owned(),
            ));
        }
        let receipt = GraphWriteReceipt {
            tenant_id: tenant_id.clone(),
            graph_revision,
            delta_digest: delta_digest.clone(),
            entities_upserted: stored_count(&row, 2, "entities_upserted")?,
            assertions_upserted: stored_count(&row, 3, "assertions_upserted")?,
            assertions_retracted: stored_count(&row, 4, "assertions_retracted")?,
        };
        let projection = serde_json::from_value::<ProjectionCommit>(row.get::<_, Value>(5))?;
        if projection.tenant_id != tenant_id.as_str()
            || projection.graph_revision != graph_revision
            || projection.delta_digest != delta_digest
        {
            return Err(StoreError::Conflict(
                "stored collection and projection outbox do not match".to_owned(),
            ));
        }
        let pending: bool = row.get(6);
        let pending_projection = pending.then_some(projection);
        Ok(Some(CommittedCollection {
            receipt,
            pending_projection,
        }))
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

async fn replace_or_delete_identity_claim(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    retracted_assertion_id: &str,
) -> Result<(), StoreError> {
    let claim = transaction
        .query_opt(
            "SELECT claim_kind, claim_value, canonical_identity_id FROM organizational_identity_claims WHERE tenant_id = $1 AND assertion_id = $2",
            &[&tenant_id, &retracted_assertion_id],
        )
        .await?;
    let Some(claim) = claim else {
        return Ok(());
    };
    let claim_kind: String = claim.get(0);
    let claim_value: String = claim.get(1);
    let canonical_identity_id: String = claim.get(2);
    let replacement = transaction
        .query_opt(
            IDENTITY_CLAIM_REPLACEMENT_QUERY,
            &[
                &tenant_id,
                &canonical_identity_id,
                &claim_kind,
                &claim_value,
            ],
        )
        .await?;
    if let Some(replacement) = replacement {
        let replacement_assertion_id: String = replacement.get(0);
        transaction
            .execute(
                "UPDATE organizational_identity_claims SET assertion_id = $3 WHERE tenant_id = $1 AND assertion_id = $2",
                &[&tenant_id, &retracted_assertion_id, &replacement_assertion_id],
            )
            .await?;
    } else {
        transaction
            .execute(
                "DELETE FROM organizational_identity_claims WHERE tenant_id = $1 AND assertion_id = $2",
                &[&tenant_id, &retracted_assertion_id],
            )
            .await?;
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

async fn upsert_entities(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    revision: i64,
    delta: &GraphDelta,
) -> Result<(), StoreError> {
    for chunk in delta.entities().chunks(POSTGRES_WRITE_BATCH_SIZE) {
        let rows = serde_json::Value::Array(
            chunk
                .iter()
                .map(|entity| {
                    serde_json::json!({
                        "entity_id": entity.id().as_str(),
                        "entity_json": entity,
                    })
                })
                .collect(),
        );
        if let Some(conflict) = transaction
            .query_opt(UPSERT_ENTITIES_QUERY, &[&tenant_id, &rows, &revision])
            .await?
        {
            let entity_id: String = conflict.get(0);
            return Err(StoreError::Conflict(format!(
                "entity {entity_id} conflicts with stored identity"
            )));
        }
    }
    Ok(())
}

async fn upsert_assertions(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    revision: i64,
    delta: &GraphDelta,
) -> Result<(), StoreError> {
    for chunk in delta.assertions().chunks(POSTGRES_WRITE_BATCH_SIZE) {
        let rows = serde_json::Value::Array(
            chunk
                .iter()
                .map(|assertion| {
                    let (from, to, relation) = assertion_endpoints(assertion);
                    serde_json::json!({
                        "assertion_id": assertion.id().as_str(),
                        "source_runtime_id": assertion.provenance().source_runtime_id().as_str(),
                        "from_entity_id": from,
                        "to_entity_id": to,
                        "relation": relation,
                        "assertion_json": assertion,
                    })
                })
                .collect(),
        );
        if let Some(conflict) = transaction
            .query_opt(UPSERT_ASSERTIONS_QUERY, &[&tenant_id, &rows, &revision])
            .await?
        {
            let assertion_id: String = conflict.get(0);
            return Err(StoreError::Conflict(format!(
                "assertion {assertion_id} conflicts with stored evidence"
            )));
        }
    }
    Ok(())
}

async fn insert_observations(
    transaction: &tokio_postgres::Transaction<'_>,
    tenant_id: &str,
    batch: &CollectedBatch,
    delta: &GraphDelta,
) -> Result<(), StoreError> {
    for chunk in batch.records.chunks(POSTGRES_WRITE_BATCH_SIZE) {
        let rows = serde_json::Value::Array(
            chunk
                .iter()
                .map(|record| {
                    serde_json::json!({
                        "observation_id": record.observation_id.as_str(),
                        "family": record.family,
                        "provider_kind": record.provider_kind,
                        "provider_id": record.provider_id,
                        "payload_json": record.payload,
                        "fields_json": record.fields,
                    })
                })
                .collect(),
        );
        transaction
            .execute(
                INSERT_OBSERVATIONS_QUERY,
                &[
                    &tenant_id,
                    &delta.collection().collection_id().as_str(),
                    &delta.collection().source_runtime_id().as_str(),
                    &rows,
                ],
            )
            .await?;
    }
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
            let agent_key = entity.agent_key();
            let mut properties = entity.properties().clone();
            properties.insert("entity_urn".to_owned(), agent_key.clone());
            Ok(ProjectionEntity {
                entity_id: entity.id().as_str().to_owned(),
                entity_kind: enum_name(entity.kind())?,
                authority_json: serde_json::to_string(entity.authority())?,
                label: entity.label().to_owned(),
                properties_json: serde_json::to_string(&properties)?,
                external_id: Some(agent_key),
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

fn validate_lease_request(owner: &str, ttl_millis: u64) -> Result<(), StoreError> {
    if owner.is_empty()
        || owner.trim() != owner
        || owner.len() > 255
        || owner.chars().any(char::is_control)
    {
        return Err(StoreError::Conflict(
            "source runtime lease owner is invalid".to_owned(),
        ));
    }
    if ttl_millis == 0 || ttl_millis > MAX_SOURCE_RUNTIME_LEASE_TTL_MILLIS {
        return Err(StoreError::Conflict(
            "source runtime lease TTL is outside the supported range".to_owned(),
        ));
    }
    Ok(())
}

fn positive_generation(value: i64) -> Result<u64, StoreError> {
    let generation = u64::try_from(value).map_err(|_| {
        StoreError::Conflict("source runtime lease generation is invalid".to_owned())
    })?;
    if generation == 0 {
        return Err(StoreError::Conflict(
            "source runtime lease generation is invalid".to_owned(),
        ));
    }
    Ok(generation)
}

fn storage_generation(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::Conflict("source runtime lease generation overflow".to_owned()))
}

async fn require_source_runtime_lease(
    transaction: &tokio_postgres::Transaction<'_>,
    delta: &GraphDelta,
    fence: &SourceRuntimeLeaseFence,
) -> Result<(), StoreError> {
    if fence.tenant_id() != delta.collection().tenant_id()
        || fence.source_runtime_id() != delta.collection().source_runtime_id()
    {
        return Err(StoreError::Conflict(
            "source runtime lease does not match the collected scope".to_owned(),
        ));
    }
    let generation = storage_generation(fence.generation())?;
    let row = transaction
        .query_opt(
            r#"
SELECT lease_owner, lease_generation, lease_expires_at > NOW()
FROM source_runtimes
WHERE id = $1
  AND runtime_json->>'tenant_id' = $2
FOR UPDATE
"#,
            &[
                &fence.source_runtime_id().as_str(),
                &fence.tenant_id().as_str(),
            ],
        )
        .await?;
    let valid = row.is_some_and(|row| {
        row.get::<_, Option<String>>(0).as_deref() == Some(fence.owner())
            && row.get::<_, i64>(1) == generation
            && row.get::<_, Option<bool>>(2) == Some(true)
    });
    if !valid {
        return Err(StoreError::Conflict(
            "source runtime lease was lost before commit".to_owned(),
        ));
    }
    Ok(())
}

fn stored_count(row: &tokio_postgres::Row, index: usize, field: &str) -> Result<usize, StoreError> {
    let value: i64 = row.get(index);
    usize::try_from(value)
        .map_err(|_| StoreError::Conflict(format!("stored {field} count is invalid")))
}

#[cfg(test)]
mod tests {
    use std::env;

    use tokio_postgres::NoTls;

    use super::*;

    #[test]
    fn schema_enforces_tenant_scope_identity_uniqueness_and_outbox() {
        for required in [
            "CREATE TABLE IF NOT EXISTS source_runtimes",
            "lease_generation BIGINT NOT NULL DEFAULT 0",
            "FORCE ROW LEVEL SECURITY",
            "PRIMARY KEY (tenant_id, provider_identity_id)",
            "PRIMARY KEY (tenant_id, claim_kind, claim_value)",
            "organizational_projection_outbox",
            "organizational_parity_receipts",
            "organizational_source_event_receipts",
            "organizational_legacy_projection_receipts",
            "organizational_source_collection_receipts",
            "organizational_source_collection_latest_idx",
            "current_setting(''cerebro.tenant_id'', true)",
            "DEFERRABLE INITIALLY DEFERRED",
        ] {
            assert!(POSTGRES_SCHEMA.contains(required), "missing {required}");
        }
        let source_receipt_schema = POSTGRES_SCHEMA
            .split("CREATE TABLE IF NOT EXISTS organizational_source_event_receipts")
            .nth(1)
            .and_then(|schema| schema.split("CREATE TABLE IF NOT EXISTS").next())
            .expect("source event receipt schema");
        assert!(source_receipt_schema.contains("attributes_digest TEXT NOT NULL"));
        assert!(source_receipt_schema.contains("payload_digest TEXT NOT NULL"));
        assert!(!source_receipt_schema.contains("attributes_json"));
        assert!(!source_receipt_schema.contains("payload_json"));
        for required in [
            "entity_json = EXCLUDED.entity_json",
            "entity_json->'kind' = EXCLUDED.entity_json->'kind'",
            "entity_json->'authority' = EXCLUDED.entity_json->'authority'",
            "assertion_json = EXCLUDED.assertion_json",
            "source_runtime_id = EXCLUDED.source_runtime_id",
            "from_entity_id = EXCLUDED.from_entity_id",
            "to_entity_id = EXCLUDED.to_entity_id",
            "relation = EXCLUDED.relation",
        ] {
            assert!(
                include_str!("postgres.rs").contains(required),
                "refresh upsert missing {required}"
            );
        }
        for required in [
            "active = TRUE",
            "assertion_json->>'state' = 'confirmed'",
            "'authoritative_employee_id'",
            "'verified_email'",
            "'human_decision'",
            "assertion_json->'claim'->>'kind'",
            "assertion_json->'claim'->>'value'",
        ] {
            assert!(
                IDENTITY_CLAIM_REPLACEMENT_QUERY.contains(required),
                "claim replacement query missing {required}"
            );
        }
    }

    #[test]
    fn high_cardinality_writes_are_bounded_and_set_based() {
        assert_eq!(POSTGRES_WRITE_BATCH_SIZE, 1_000);
        for statement in [
            UPSERT_ENTITIES_QUERY,
            UPSERT_ASSERTIONS_QUERY,
            INSERT_OBSERVATIONS_QUERY,
        ] {
            assert!(statement.contains("jsonb_to_recordset"));
        }
        for statement in [UPSERT_ENTITIES_QUERY, UPSERT_ASSERTIONS_QUERY] {
            assert!(statement.contains("ON CONFLICT"));
            assert!(statement.contains("LEFT JOIN upserted"));
            assert!(statement.contains("LIMIT 1"));
        }
        for invariant in [
            "entity_json->'kind' = EXCLUDED.entity_json->'kind'",
            "entity_json->'authority' = EXCLUDED.entity_json->'authority'",
        ] {
            assert!(UPSERT_ENTITIES_QUERY.contains(invariant));
        }
        for invariant in [
            "source_runtime_id = EXCLUDED.source_runtime_id",
            "from_entity_id = EXCLUDED.from_entity_id",
            "to_entity_id = EXCLUDED.to_entity_id",
            "relation = EXCLUDED.relation",
        ] {
            assert!(UPSERT_ASSERTIONS_QUERY.contains(invariant));
        }
    }

    #[tokio::test]
    #[ignore = "requires disposable PostgreSQL"]
    async fn retracting_one_assertion_keeps_a_claim_backed_by_another_active_assertion() {
        let postgres_dsn = env::var("CEREBRO_TEST_POSTGRES_DSN").unwrap();
        let (client, connection) = tokio_postgres::connect(&postgres_dsn, NoTls).await.unwrap();
        tokio::spawn(async move {
            connection.await.expect("PostgreSQL test connection");
        });
        let ledger = PostgresLedger::from_client(client);
        ledger.migrate().await.unwrap();

        let mut client = ledger.client.lock().await;
        let transaction = client.transaction().await.unwrap();
        let tenant_id = "tenant-claim-retraction";
        set_tenant(&transaction, tenant_id).await.unwrap();
        for entity_id in ["provider-old", "provider-new", "person:canonical:person-1"] {
            transaction
                .execute(
                    "INSERT INTO organizational_entities (tenant_id, entity_id, entity_json, last_graph_revision) VALUES ($1, $2, $3, 1) ON CONFLICT (tenant_id, entity_id) DO NOTHING",
                    &[&tenant_id, &entity_id, &serde_json::json!({"label": entity_id})],
                )
                .await
                .unwrap();
        }
        for (assertion_id, provider_id) in [
            ("identity-binding-old", "provider-old"),
            ("identity-binding-new", "provider-new"),
        ] {
            let source_runtime_id = format!("runtime-{provider_id}");
            let assertion_json = serde_json::json!({
                "assertion_type": "identity_binding",
                "state": "confirmed",
                "method": "verified_email",
                "claim": {
                    "kind": "verified_email",
                    "value": "person@example.com"
                }
            });
            transaction
                .execute(
                    "INSERT INTO organizational_assertions (tenant_id, assertion_id, source_runtime_id, from_entity_id, to_entity_id, relation, assertion_json, active, last_graph_revision) VALUES ($1, $2, $3, $4, $5, 'represents', $6, TRUE, 1) ON CONFLICT (tenant_id, assertion_id) DO UPDATE SET active = TRUE",
                    &[
                        &tenant_id,
                        &assertion_id,
                        &source_runtime_id,
                        &provider_id,
                        &"person:canonical:person-1",
                        &assertion_json,
                    ],
                )
                .await
                .unwrap();
        }
        transaction
            .execute(
                "INSERT INTO organizational_identity_claims (tenant_id, claim_kind, claim_value, canonical_identity_id, assertion_id) VALUES ($1, 'verified_email', 'person@example.com', 'person:canonical:person-1', 'identity-binding-new') ON CONFLICT (tenant_id, claim_kind, claim_value) DO UPDATE SET assertion_id = EXCLUDED.assertion_id",
                &[&tenant_id],
            )
            .await
            .unwrap();
        transaction
            .execute(
                "UPDATE organizational_assertions SET active = FALSE WHERE tenant_id = $1 AND assertion_id = 'identity-binding-new'",
                &[&tenant_id],
            )
            .await
            .unwrap();

        replace_or_delete_identity_claim(&transaction, tenant_id, "identity-binding-new")
            .await
            .unwrap();
        let replacement: String = transaction
            .query_one(
                "SELECT assertion_id FROM organizational_identity_claims WHERE tenant_id = $1 AND claim_value = 'person@example.com'",
                &[&tenant_id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(replacement, "identity-binding-old");

        transaction
            .execute(
                "UPDATE organizational_assertions SET active = FALSE WHERE tenant_id = $1 AND assertion_id = 'identity-binding-old'",
                &[&tenant_id],
            )
            .await
            .unwrap();
        replace_or_delete_identity_claim(&transaction, tenant_id, "identity-binding-old")
            .await
            .unwrap();
        assert!(
            transaction
                .query_opt(
                    "SELECT assertion_id FROM organizational_identity_claims WHERE tenant_id = $1 AND claim_value = 'person@example.com'",
                    &[&tenant_id],
                )
                .await
                .unwrap()
                .is_none()
        );
        transaction.rollback().await.unwrap();
    }
}
