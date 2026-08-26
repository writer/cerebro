use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cerebro_organizational_graph::GraphWriteReceipt;
use cerebro_organizational_model::{
    CanonicalIdentityId, CollectionCompleteness, GraphAssertion, GraphDelta,
    IdentityBindingAssertion, IdentityBindingState, IdentityResolutionMethod, SourceRuntimeId,
    TenantId,
};
use cerebro_source_catalog::SourceCatalog;
use cerebro_source_runtime_next::{
    CollectedBatch, CommittedSourceEvent, IdentityResolutionSnapshot, SourceRuntimeLeaseFence,
    parse_credential_reference,
};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_postgres::{Client, error::SqlState, types::ToSql};
use zeroize::Zeroize;

use crate::{
    CutoverDecision, CutoverGate, ParityReceipt, ParityStatus, ProjectionAuthority,
    ProjectionAuthorityRecord, ProjectionPromotionRequest,
};
use crate::{
    StoreError,
    credential_vault::{ConnectorVaultKey, CredentialVaultRecord},
};

const MAX_SOURCE_RUNTIME_LEASE_TTL_MILLIS: u64 = 24 * 60 * 60 * 1_000;
static CREDENTIAL_AUDIT_SEQUENCE: AtomicU64 = AtomicU64::new(1);

struct SensitiveValues(BTreeMap<String, String>);

impl SensitiveValues {
    fn new(values: &BTreeMap<String, String>) -> Self {
        Self(values.clone())
    }

    fn insert(&mut self, key: String, value: String) {
        if let Some(mut replaced) = self.0.insert(key, value) {
            replaced.zeroize();
        }
    }

    fn into_inner(mut self) -> BTreeMap<String, String> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for SensitiveValues {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS source_runtimes (
  id TEXT PRIMARY KEY,
  runtime_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS finding_evaluation_runs (
  id TEXT PRIMARY KEY,
  runtime_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TIMESTAMPTZ NOT NULL,
  finished_at TIMESTAMPTZ,
  finding_evaluation_run_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS finding_evaluation_runs_runtime_idx
  ON finding_evaluation_runs (runtime_id, started_at DESC);
ALTER TABLE source_runtimes ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE source_runtimes ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
ALTER TABLE source_runtimes
  ADD COLUMN IF NOT EXISTS lease_generation BIGINT NOT NULL DEFAULT 0
  CHECK (lease_generation >= 0);
CREATE TABLE IF NOT EXISTS connector_credentials (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  credential_store_id TEXT NOT NULL DEFAULT 'cerebro_vault',
  auth_method TEXT NOT NULL DEFAULT 'encrypted_submission',
  status TEXT NOT NULL DEFAULT 'valid',
  key_id TEXT NOT NULL,
  fields_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  sealed BYTEA NOT NULL,
  created_by TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  revoked_by TEXT NOT NULL DEFAULT '',
  previous_credential_id TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  last_validated_at TIMESTAMPTZ
);
ALTER TABLE connector_credentials
  ADD COLUMN IF NOT EXISTS credential_store_id TEXT NOT NULL DEFAULT 'cerebro_vault';
ALTER TABLE connector_credentials
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'valid';
ALTER TABLE connector_credentials
  ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS connector_credentials_runtime_idx
  ON connector_credentials (runtime_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS connector_credential_audit_events (
  id TEXT PRIMARY KEY,
  credential_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  runtime_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  actor TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS connector_credential_audit_credential_idx
  ON connector_credential_audit_events (credential_id, created_at DESC);
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
CREATE TABLE IF NOT EXISTS source_runtime_page_publications (
  tenant_id TEXT NOT NULL,
  logical_page_id TEXT NOT NULL,
  source_runtime_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN (
    'prepared',
    'publishing',
    'published',
    'projected',
    'committed',
    'superseded',
    'quarantined'
  )),
  revision BIGINT NOT NULL CHECK (revision > 0),
  publication_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, logical_page_id)
);
CREATE INDEX IF NOT EXISTS source_runtime_page_publications_recovery_idx
  ON source_runtime_page_publications
    (tenant_id, source_runtime_id, state, updated_at, logical_page_id);
CREATE TABLE IF NOT EXISTS source_runtime_page_events (
  tenant_id TEXT NOT NULL,
  logical_page_id TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  event_id TEXT NOT NULL,
  envelope_sha256 TEXT NOT NULL,
  message_id TEXT NOT NULL,
  envelope BYTEA NOT NULL,
  PRIMARY KEY (tenant_id, logical_page_id, ordinal),
  UNIQUE (tenant_id, logical_page_id, event_id),
  UNIQUE (tenant_id, logical_page_id, message_id),
  FOREIGN KEY (tenant_id, logical_page_id)
    REFERENCES source_runtime_page_publications (tenant_id, logical_page_id)
    ON DELETE CASCADE
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
CREATE TABLE IF NOT EXISTS organizational_consumer_runs (
  consumer_name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('forward', 'replay')),
  start_sequence BIGINT NOT NULL CHECK (start_sequence > 0),
  end_sequence BIGINT,
  last_delivered_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_delivered_sequence >= 0),
  covered_sequence BIGINT NOT NULL DEFAULT 0 CHECK (covered_sequence >= 0),
  messages_seen BIGINT NOT NULL DEFAULT 0 CHECK (messages_seen >= 0),
  messages_projected BIGINT NOT NULL DEFAULT 0 CHECK (messages_projected >= 0),
  messages_skipped BIGINT NOT NULL DEFAULT 0 CHECK (messages_skipped >= 0),
  messages_rejected BIGINT NOT NULL DEFAULT 0 CHECK (messages_rejected >= 0),
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'stopped', 'failed')),
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  PRIMARY KEY (consumer_name, run_id),
  CHECK (end_sequence IS NULL OR end_sequence >= start_sequence),
  CHECK (
    (mode = 'forward' AND end_sequence IS NULL) OR
    (mode = 'replay' AND end_sequence IS NOT NULL)
  )
);
CREATE TABLE IF NOT EXISTS organizational_consumer_family_progress (
  consumer_name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  family_id TEXT NOT NULL,
  messages_seen BIGINT NOT NULL DEFAULT 0 CHECK (messages_seen >= 0),
  messages_projected BIGINT NOT NULL DEFAULT 0 CHECK (messages_projected >= 0),
  messages_skipped BIGINT NOT NULL DEFAULT 0 CHECK (messages_skipped >= 0),
  messages_rejected BIGINT NOT NULL DEFAULT 0 CHECK (messages_rejected >= 0),
  last_sequence BIGINT NOT NULL CHECK (last_sequence > 0),
  latest_graph_revision BIGINT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (consumer_name, run_id, source_id, family_id),
  FOREIGN KEY (consumer_name, run_id)
    REFERENCES organizational_consumer_runs (consumer_name, run_id)
    ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS organizational_consumer_skip_categories (
  consumer_name TEXT NOT NULL,
  run_id TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN (
    'subject_outside_projection_contract',
    'source_outside_compiled_catalog',
    'legacy_missing_source_owned_kind',
    'legacy_invalid_observation_id',
    'legacy_catalog_canary_without_source_envelope',
    'legacy_retired_family_projection_incompatible'
  )),
  messages_skipped BIGINT NOT NULL DEFAULT 0 CHECK (messages_skipped > 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (consumer_name, run_id, category),
  FOREIGN KEY (consumer_name, run_id)
    REFERENCES organizational_consumer_runs (consumer_name, run_id)
    ON DELETE CASCADE
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
CREATE INDEX IF NOT EXISTS organizational_consumer_runs_readiness_idx
  ON organizational_consumer_runs
    (consumer_name, status, covered_sequence DESC, updated_at DESC);
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
ALTER TABLE source_runtime_page_publications ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_runtime_page_publications FORCE ROW LEVEL SECURITY;
ALTER TABLE source_runtime_page_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_runtime_page_events FORCE ROW LEVEL SECURITY;
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
    'source_runtime_page_publications',
    'source_runtime_page_events',
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

const START_CONSUMER_RUN_QUERY: &str = "INSERT INTO organizational_consumer_runs (consumer_name, run_id, mode, start_sequence, end_sequence, status) VALUES ($1, $2, $3, $4, $5, 'running') ON CONFLICT (consumer_name, run_id) DO UPDATE SET status = 'running', updated_at = NOW(), completed_at = NULL WHERE organizational_consumer_runs.mode = EXCLUDED.mode AND (organizational_consumer_runs.mode = 'replay' OR (organizational_consumer_runs.mode = 'forward' AND organizational_consumer_runs.end_sequence IS NULL AND EXCLUDED.end_sequence IS NULL)) AND organizational_consumer_runs.status IN ('running', 'stopped', 'failed') RETURNING start_sequence, end_sequence";

const SOURCE_COLLECTION_MANIFEST_QUERY: &str = "SELECT manifest_json FROM organizational_source_collection_receipts WHERE tenant_id = $1 AND source_runtime_id = $2 AND collection_id = $3";

const RECORD_SOURCE_EVENT_QUERY: &str = r#"
INSERT INTO organizational_source_event_receipts (
  tenant_id, event_id, source_runtime_id, source_id, family_id, event_kind,
  schema_ref, observed_at_unix_ms, attributes_digest, payload_digest, record_digest
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
ON CONFLICT (tenant_id, event_id) DO UPDATE
SET record_digest = EXCLUDED.record_digest
WHERE organizational_source_event_receipts.record_digest = EXCLUDED.record_digest
RETURNING record_digest
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
    #[serde(default)]
    pub lifecycle: Option<LifecycleProjectionEntity>,
    #[serde(default)]
    pub lifecycle_finding_urn: Option<String>,
    #[serde(default)]
    pub lifecycle_source_runtime_id: Option<String>,
    #[serde(default)]
    pub lifecycle_source_collection_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LifecycleProjectionEntity {
    pub subject_urn: String,
    pub subject_kind: String,
    pub observed_state: String,
    pub owner_urn: Option<String>,
    pub observed_at_unix_ms: i64,
    pub expires_at_unix_ms: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct ProjectionAssertion {
    pub assertion_id: String,
    pub from_entity_id: String,
    pub to_entity_id: String,
    pub relation: String,
    pub source_runtime_id: String,
    #[serde(default)]
    pub application_workspace_id: String,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerMessageOutcome {
    Projected,
    Skipped(ConsumerSkipCategory),
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumerSkipCategory {
    SubjectOutsideProjectionContract,
    SourceOutsideCompiledCatalog,
    LegacyMissingSourceOwnedKind,
    LegacyInvalidObservationId,
    LegacyCatalogCanaryWithoutSourceEnvelope,
    LegacyRetiredFamilyProjectionIncompatible,
}

impl ConsumerSkipCategory {
    pub const ALL: [Self; 6] = [
        Self::SubjectOutsideProjectionContract,
        Self::SourceOutsideCompiledCatalog,
        Self::LegacyMissingSourceOwnedKind,
        Self::LegacyInvalidObservationId,
        Self::LegacyCatalogCanaryWithoutSourceEnvelope,
        Self::LegacyRetiredFamilyProjectionIncompatible,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubjectOutsideProjectionContract => "subject_outside_projection_contract",
            Self::SourceOutsideCompiledCatalog => "source_outside_compiled_catalog",
            Self::LegacyMissingSourceOwnedKind => "legacy_missing_source_owned_kind",
            Self::LegacyInvalidObservationId => "legacy_invalid_observation_id",
            Self::LegacyCatalogCanaryWithoutSourceEnvelope => {
                "legacy_catalog_canary_without_source_envelope"
            }
            Self::LegacyRetiredFamilyProjectionIncompatible => {
                "legacy_retired_family_projection_incompatible"
            }
        }
    }

    fn parse(value: &str) -> Result<Self, StoreError> {
        match value {
            "subject_outside_projection_contract" => Ok(Self::SubjectOutsideProjectionContract),
            "source_outside_compiled_catalog" => Ok(Self::SourceOutsideCompiledCatalog),
            "legacy_missing_source_owned_kind" => Ok(Self::LegacyMissingSourceOwnedKind),
            "legacy_invalid_observation_id" => Ok(Self::LegacyInvalidObservationId),
            "legacy_catalog_canary_without_source_envelope" => {
                Ok(Self::LegacyCatalogCanaryWithoutSourceEnvelope)
            }
            "legacy_retired_family_projection_incompatible" => {
                Ok(Self::LegacyRetiredFamilyProjectionIncompatible)
            }
            _ => Err(StoreError::Conflict(
                "stored consumer skip category is invalid".to_owned(),
            )),
        }
    }
}

fn validate_skip_categories(
    messages_skipped: u64,
    rows: Vec<(String, u64)>,
) -> Result<BTreeMap<String, u64>, StoreError> {
    if rows.len() > ConsumerSkipCategory::ALL.len() {
        return Err(StoreError::Conflict(
            "stored consumer skip category cardinality exceeds the closed catalog".to_owned(),
        ));
    }
    let mut categories = BTreeMap::new();
    let mut categorized = 0_u64;
    for (name, count) in rows {
        let category = ConsumerSkipCategory::parse(&name)?;
        if count == 0
            || categories
                .insert(category.as_str().to_owned(), count)
                .is_some()
        {
            return Err(StoreError::Conflict(
                "stored consumer skip category counter is invalid".to_owned(),
            ));
        }
        categorized = categorized.checked_add(count).ok_or_else(|| {
            StoreError::Conflict("stored consumer skip category total overflowed".to_owned())
        })?;
    }
    if categorized != messages_skipped {
        return Err(StoreError::Conflict(
            "stored consumer skip categories do not reconcile with messages_skipped".to_owned(),
        ));
    }
    Ok(categories)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConsumerRunFence {
    pub start_sequence: u64,
    pub end_sequence: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsumerRunProgress {
    pub last_delivered_sequence: u64,
    pub covered_sequence: u64,
    pub messages_seen: u64,
    pub messages_projected: u64,
    pub messages_skipped: u64,
    pub messages_rejected: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConsumerRunReceiptState {
    pub progress: ConsumerRunProgress,
    pub skip_categories: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsumerFamilyProgress {
    pub source_id: String,
    pub family_id: String,
    pub messages_seen: u64,
    pub messages_projected: u64,
    pub messages_skipped: u64,
    pub messages_rejected: u64,
    pub last_sequence: u64,
    pub latest_graph_revision: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConsumerRunInspection {
    pub consumer_name: String,
    pub run_id: String,
    pub mode: String,
    pub start_sequence: u64,
    pub end_sequence: Option<u64>,
    pub status: String,
    pub started_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub completed_at_unix_ms: Option<u64>,
    pub progress: ConsumerRunProgress,
    pub skip_categories: BTreeMap<String, u64>,
    pub families: Vec<ConsumerFamilyProgress>,
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

/// A tenant-scoped, secret-free source-runtime observation for operator reads.
///
/// The stored runtime JSON can contain connector configuration and secret
/// references. This projection deliberately exposes only health and progress
/// fields that are safe for an agent tool result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRuntimeObservation {
    pub runtime_id: String,
    pub source_id: String,
    pub enabled_state: String,
    pub last_failure_category: Option<String>,
    pub last_synced_at: Option<String>,
    pub cursor_pending: bool,
    pub checkpoint_cursor_present: bool,
    pub stale_after_seconds: Option<u64>,
    pub expected_cadence_seconds: Option<u64>,
    pub contract_probe_state: String,
    pub latest_finding_evaluation_status: Option<String>,
    pub latest_collection: Option<SourceRuntimeCollectionObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceRuntimeCollectionObservation {
    pub collection_id: String,
    pub status: String,
    pub completed_at_unix_ms: u64,
    pub pages_read: u64,
    pub records_scanned: u64,
    pub records_accepted: u64,
    pub records_rejected: u64,
}

/// One stored source-runtime definition admitted from the shared PostgreSQL
/// current-state table. The config may contain unresolved secret references,
/// so this type deliberately does not implement `Debug` or `Serialize`.
#[derive(Clone)]
pub struct StoredSourceRuntime {
    runtime_id: SourceRuntimeId,
    tenant_id: TenantId,
    source_id: String,
    config: BTreeMap<String, String>,
    checkpoint: Option<Value>,
    next_cursor: Option<Value>,
    last_synced_at: Option<String>,
    cursor: Option<String>,
}

fn sequence_i64(sequence: u64) -> Result<i64, StoreError> {
    if sequence == 0 {
        return Err(StoreError::Conflict(
            "consumer stream sequence must be greater than zero".to_owned(),
        ));
    }
    i64::try_from(sequence)
        .map_err(|_| StoreError::Conflict("consumer stream sequence overflow".to_owned()))
}

impl StoredSourceRuntime {
    pub fn new(
        runtime_id: SourceRuntimeId,
        tenant_id: TenantId,
        source_id: String,
        config: BTreeMap<String, String>,
        checkpoint: Option<Value>,
        next_cursor: Option<Value>,
        last_synced_at: Option<String>,
    ) -> Result<Self, StoreError> {
        validate_source_runtime_source_id(&source_id)?;
        validate_source_runtime_config(&config)?;
        validate_source_runtime_json_field("checkpoint", checkpoint.as_ref())?;
        validate_source_runtime_json_field("next cursor", next_cursor.as_ref())?;
        if last_synced_at.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        }) {
            return Err(StoreError::Conflict(
                "source runtime last-synced timestamp is invalid".to_owned(),
            ));
        }
        let cursor = next_cursor
            .as_ref()
            .and_then(|value| value.get("opaque"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                checkpoint
                    .as_ref()
                    .and_then(|value| value.get("cursor_opaque"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| resumable_checkpoint_cursor(value))
                    .map(str::to_owned)
            });
        if cursor
            .as_ref()
            .is_some_and(|cursor| cursor.len() > 64 * 1024)
        {
            return Err(StoreError::Conflict(
                "stored source runtime cursor is too large".to_owned(),
            ));
        }
        Ok(Self {
            runtime_id,
            tenant_id,
            source_id,
            config,
            checkpoint,
            next_cursor,
            last_synced_at,
            cursor,
        })
    }

    pub fn runtime_id(&self) -> &SourceRuntimeId {
        &self.runtime_id
    }

    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn config(&self) -> &BTreeMap<String, String> {
        &self.config
    }

    pub fn checkpoint(&self) -> Option<&Value> {
        self.checkpoint.as_ref()
    }

    pub fn next_cursor(&self) -> Option<&Value> {
        self.next_cursor.as_ref()
    }

    pub fn last_synced_at(&self) -> Option<&str> {
        self.last_synced_at.as_deref()
    }

    pub fn cursor(&self) -> Option<&str> {
        self.cursor.as_deref()
    }
}

#[derive(Deserialize, Serialize)]
struct StoredSourceRuntimeWire {
    id: String,
    source_id: String,
    tenant_id: String,
    #[serde(default)]
    config: BTreeMap<String, String>,
    checkpoint: Option<Value>,
    next_cursor: Option<Value>,
    last_synced_at: Option<String>,
}

pub struct PostgresLedger {
    pub(crate) client: Mutex<Client>,
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

    pub async fn start_consumer_run(
        &self,
        consumer_name: &str,
        run_id: &str,
        mode: &str,
        start_sequence: u64,
        end_sequence: Option<u64>,
    ) -> Result<ConsumerRunFence, StoreError> {
        let start_sequence = sequence_i64(start_sequence)?;
        let end_sequence = end_sequence.map(sequence_i64).transpose()?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                START_CONSUMER_RUN_QUERY,
                &[
                    &consumer_name,
                    &run_id,
                    &mode,
                    &start_sequence,
                    &end_sequence,
                ],
            )
            .await?;
        let Some(row) = row else {
            return Err(StoreError::Conflict(format!(
                "consumer run {consumer_name}/{run_id} is complete or has another fence"
            )));
        };
        transaction.commit().await?;
        let stored_start: i64 = row.get(0);
        let stored_end: Option<i64> = row.get(1);
        Ok(ConsumerRunFence {
            start_sequence: u64::try_from(stored_start).map_err(|_| {
                StoreError::Conflict("stored consumer start sequence is invalid".to_owned())
            })?,
            end_sequence: stored_end.map(u64::try_from).transpose().map_err(|_| {
                StoreError::Conflict("stored consumer end sequence is invalid".to_owned())
            })?,
        })
    }

    pub async fn record_consumer_progress(
        &self,
        consumer_name: &str,
        run_id: &str,
        stream_sequence: u64,
        outcome: ConsumerMessageOutcome,
        source_family: Option<(&str, &str)>,
        graph_revision: Option<u64>,
    ) -> Result<(), StoreError> {
        let stream_sequence = sequence_i64(stream_sequence)?;
        let graph_revision = graph_revision.map(sequence_i64).transpose()?;
        let (projected, skipped, rejected, skip_category): (i64, i64, i64, Option<&str>) =
            match outcome {
                ConsumerMessageOutcome::Projected => (1, 0, 0, None),
                ConsumerMessageOutcome::Skipped(category) => (0, 1, 0, Some(category.as_str())),
                ConsumerMessageOutcome::Rejected => (0, 0, 1, None),
            };
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE organizational_consumer_runs SET last_delivered_sequence = $3, covered_sequence = $3, messages_seen = messages_seen + 1, messages_projected = messages_projected + $4, messages_skipped = messages_skipped + $5, messages_rejected = messages_rejected + $6, updated_at = NOW() WHERE consumer_name = $1 AND run_id = $2 AND status = 'running' AND last_delivered_sequence < $3 AND (end_sequence IS NULL OR $3 <= end_sequence)",
                &[
                    &consumer_name,
                    &run_id,
                    &stream_sequence,
                    &projected,
                    &skipped,
                    &rejected,
                ],
            )
            .await?;
        if changed == 0 {
            let already_covered = transaction
                .query_opt(
                    "SELECT 1 FROM organizational_consumer_runs WHERE consumer_name = $1 AND run_id = $2 AND status = 'running' AND last_delivered_sequence >= $3",
                    &[&consumer_name, &run_id, &stream_sequence],
                )
                .await?
                .is_some();
            if !already_covered {
                return Err(StoreError::Conflict(format!(
                    "consumer run {consumer_name}/{run_id} rejected sequence {stream_sequence}"
                )));
            }
        } else {
            if let Some((source_id, family_id)) = source_family {
                transaction
                    .execute(
                    "INSERT INTO organizational_consumer_family_progress (consumer_name, run_id, source_id, family_id, messages_seen, messages_projected, messages_skipped, messages_rejected, last_sequence, latest_graph_revision) VALUES ($1, $2, $3, $4, 1, $5, $6, $7, $8, $9) ON CONFLICT (consumer_name, run_id, source_id, family_id) DO UPDATE SET messages_seen = organizational_consumer_family_progress.messages_seen + 1, messages_projected = organizational_consumer_family_progress.messages_projected + EXCLUDED.messages_projected, messages_skipped = organizational_consumer_family_progress.messages_skipped + EXCLUDED.messages_skipped, messages_rejected = organizational_consumer_family_progress.messages_rejected + EXCLUDED.messages_rejected, last_sequence = EXCLUDED.last_sequence, latest_graph_revision = COALESCE(EXCLUDED.latest_graph_revision, organizational_consumer_family_progress.latest_graph_revision), updated_at = NOW() WHERE organizational_consumer_family_progress.last_sequence < EXCLUDED.last_sequence",
                    &[
                        &consumer_name,
                        &run_id,
                        &source_id,
                        &family_id,
                        &projected,
                        &skipped,
                        &rejected,
                        &stream_sequence,
                        &graph_revision,
                    ],
                    )
                    .await?;
            }
            if let Some(category) = skip_category {
                transaction
                    .execute(
                        "INSERT INTO organizational_consumer_skip_categories (consumer_name, run_id, category, messages_skipped) VALUES ($1, $2, $3, 1) ON CONFLICT (consumer_name, run_id, category) DO UPDATE SET messages_skipped = organizational_consumer_skip_categories.messages_skipped + 1, updated_at = NOW()",
                        &[&consumer_name, &run_id, &category],
                    )
                    .await?;
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn finish_consumer_run(
        &self,
        consumer_name: &str,
        run_id: &str,
        status: &str,
        covered_sequence: Option<u64>,
    ) -> Result<(), StoreError> {
        if !matches!(status, "completed" | "stopped" | "failed") {
            return Err(StoreError::Conflict(
                "consumer terminal status is invalid".to_owned(),
            ));
        }
        let covered_sequence = covered_sequence.map(sequence_i64).transpose()?;
        let changed = self
            .client
            .lock()
            .await
            .execute(
                "UPDATE organizational_consumer_runs SET status = $3, covered_sequence = GREATEST(covered_sequence, COALESCE($4, covered_sequence)), updated_at = NOW(), completed_at = CASE WHEN $3 = 'completed' THEN NOW() ELSE NULL END WHERE consumer_name = $1 AND run_id = $2 AND status = 'running' AND ($3 <> 'completed' OR ((end_sequence IS NULL OR $4 >= end_sequence) AND messages_projected > 0 AND messages_rejected = 0))",
                &[&consumer_name, &run_id, &status, &covered_sequence],
            )
            .await?;
        if changed == 0 {
            return Err(StoreError::Conflict(format!(
                "consumer run {consumer_name}/{run_id} cannot transition to {status}"
            )));
        }
        Ok(())
    }

    pub async fn consumer_run_progress(
        &self,
        consumer_name: &str,
        run_id: &str,
    ) -> Result<ConsumerRunProgress, StoreError> {
        Ok(self
            .consumer_run_receipt_state(consumer_name, run_id)
            .await?
            .progress)
    }

    pub async fn consumer_run_receipt_state(
        &self,
        consumer_name: &str,
        run_id: &str,
    ) -> Result<ConsumerRunReceiptState, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT last_delivered_sequence, covered_sequence, messages_seen, messages_projected, messages_skipped, messages_rejected FROM organizational_consumer_runs WHERE consumer_name = $1 AND run_id = $2",
                &[&consumer_name, &run_id],
            )
            .await?
            .ok_or_else(|| StoreError::Conflict("consumer run was not found".to_owned()))?;
        let skip_rows = transaction
            .query(
                "SELECT category, messages_skipped FROM organizational_consumer_skip_categories WHERE consumer_name = $1 AND run_id = $2 ORDER BY category",
                &[&consumer_name, &run_id],
            )
            .await?;
        transaction.commit().await?;
        let progress = ConsumerRunProgress {
            last_delivered_sequence: stored_u64(&row, 0, "last_delivered_sequence")?,
            covered_sequence: stored_u64(&row, 1, "covered_sequence")?,
            messages_seen: stored_u64(&row, 2, "messages_seen")?,
            messages_projected: stored_u64(&row, 3, "messages_projected")?,
            messages_skipped: stored_u64(&row, 4, "messages_skipped")?,
            messages_rejected: stored_u64(&row, 5, "messages_rejected")?,
        };
        let skip_categories = validate_skip_categories(
            progress.messages_skipped,
            skip_rows
                .into_iter()
                .map(|row| {
                    Ok((
                        row.get::<_, String>(0),
                        stored_u64(&row, 1, "category messages_skipped")?,
                    ))
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
        )?;
        Ok(ConsumerRunReceiptState {
            progress,
            skip_categories,
        })
    }

    pub async fn inspect_consumer_run(
        &self,
        consumer_name: &str,
        run_id: &str,
    ) -> Result<ConsumerRunInspection, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        let row = transaction
            .query_opt(
                "SELECT mode, start_sequence, end_sequence, status, (EXTRACT(EPOCH FROM started_at) * 1000)::BIGINT, (EXTRACT(EPOCH FROM updated_at) * 1000)::BIGINT, (EXTRACT(EPOCH FROM completed_at) * 1000)::BIGINT, last_delivered_sequence, covered_sequence, messages_seen, messages_projected, messages_skipped, messages_rejected FROM organizational_consumer_runs WHERE consumer_name = $1 AND run_id = $2",
                &[&consumer_name, &run_id],
            )
            .await?
            .ok_or_else(|| StoreError::Conflict("consumer run was not found".to_owned()))?;
        let family_rows = transaction
            .query(
                "SELECT source_id, family_id, messages_seen, messages_projected, messages_skipped, messages_rejected, last_sequence, latest_graph_revision FROM organizational_consumer_family_progress WHERE consumer_name = $1 AND run_id = $2 ORDER BY source_id, family_id",
                &[&consumer_name, &run_id],
            )
            .await?;
        let skip_rows = transaction
            .query(
                "SELECT category, messages_skipped FROM organizational_consumer_skip_categories WHERE consumer_name = $1 AND run_id = $2 ORDER BY category",
                &[&consumer_name, &run_id],
            )
            .await?;
        transaction.commit().await?;
        let families = family_rows
            .into_iter()
            .map(|family| {
                let revision: Option<i64> = family.get(7);
                Ok(ConsumerFamilyProgress {
                    source_id: family.get(0),
                    family_id: family.get(1),
                    messages_seen: stored_u64(&family, 2, "family messages_seen")?,
                    messages_projected: stored_u64(&family, 3, "family messages_projected")?,
                    messages_skipped: stored_u64(&family, 4, "family messages_skipped")?,
                    messages_rejected: stored_u64(&family, 5, "family messages_rejected")?,
                    last_sequence: stored_u64(&family, 6, "family last_sequence")?,
                    latest_graph_revision: revision.map(u64::try_from).transpose().map_err(
                        |_| {
                            StoreError::Conflict(
                                "stored family graph revision is invalid".to_owned(),
                            )
                        },
                    )?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        let end_sequence: Option<i64> = row.get(2);
        let progress = ConsumerRunProgress {
            last_delivered_sequence: stored_u64(&row, 7, "last_delivered_sequence")?,
            covered_sequence: stored_u64(&row, 8, "covered_sequence")?,
            messages_seen: stored_u64(&row, 9, "messages_seen")?,
            messages_projected: stored_u64(&row, 10, "messages_projected")?,
            messages_skipped: stored_u64(&row, 11, "messages_skipped")?,
            messages_rejected: stored_u64(&row, 12, "messages_rejected")?,
        };
        let skip_categories = validate_skip_categories(
            progress.messages_skipped,
            skip_rows
                .into_iter()
                .map(|row| {
                    Ok((
                        row.get::<_, String>(0),
                        stored_u64(&row, 1, "category messages_skipped")?,
                    ))
                })
                .collect::<Result<Vec<_>, StoreError>>()?,
        )?;
        Ok(ConsumerRunInspection {
            consumer_name: consumer_name.to_owned(),
            run_id: run_id.to_owned(),
            mode: row.get(0),
            start_sequence: stored_u64(&row, 1, "start_sequence")?,
            end_sequence: end_sequence
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StoreError::Conflict("stored end sequence is invalid".to_owned()))?,
            status: row.get(3),
            started_at_unix_ms: stored_u64(&row, 4, "started_at_unix_ms")?,
            updated_at_unix_ms: stored_u64(&row, 5, "updated_at_unix_ms")?,
            completed_at_unix_ms: row
                .get::<_, Option<i64>>(6)
                .map(u64::try_from)
                .transpose()
                .map_err(|_| {
                    StoreError::Conflict("stored completed timestamp is invalid".to_owned())
                })?,
            progress,
            skip_categories,
            families,
        })
    }

    /// Load one durable runtime definition. Runtime identity comes only from
    /// the stored record; callers cannot override its tenant or source.
    pub async fn load_source_runtime(
        &self,
        source_runtime_id: &SourceRuntimeId,
    ) -> Result<StoredSourceRuntime, StoreError> {
        self.find_source_runtime(source_runtime_id)
            .await?
            .ok_or_else(|| StoreError::Conflict("source runtime is not stored".to_owned()))
    }

    /// Find one durable runtime definition without collapsing absence into a
    /// stored-contract conflict. Tenant-bound callers can keep a missing or
    /// foreign runtime indistinguishable without parsing error text.
    pub async fn find_source_runtime(
        &self,
        source_runtime_id: &SourceRuntimeId,
    ) -> Result<Option<StoredSourceRuntime>, StoreError> {
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                "SELECT runtime_json FROM source_runtimes WHERE id = $1",
                &[&source_runtime_id.as_str()],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        decode_stored_source_runtime(source_runtime_id, row.get(0)).map(Some)
    }

    /// Upsert one already-admitted, unresolved source-runtime definition.
    /// Credential resolution remains outside storage, and lease columns are
    /// deliberately preserved across definition updates.
    pub async fn put_source_runtime(
        &self,
        runtime: &StoredSourceRuntime,
        expected: Option<&StoredSourceRuntime>,
    ) -> Result<bool, StoreError> {
        let runtime_json = stored_source_runtime_json(runtime)?;
        let client = self.client.lock().await;
        let changed = if let Some(expected) = expected {
            let expected_json = stored_source_runtime_json(expected)?;
            client
                .execute(
                    r#"
UPDATE source_runtimes
SET runtime_json = $2, updated_at = NOW()
WHERE id = $1
  AND runtime_json->>'tenant_id' = $3
  AND runtime_json = $4
  AND (lease_expires_at IS NULL OR lease_expires_at <= NOW())
"#,
                    &[
                        &runtime.runtime_id.as_str(),
                        &runtime_json,
                        &runtime.tenant_id.as_str(),
                        &expected_json,
                    ],
                )
                .await?
        } else {
            client
                .execute(
                    r#"
INSERT INTO source_runtimes (id, runtime_json)
VALUES ($1, $2)
ON CONFLICT (id) DO NOTHING
"#,
                    &[&runtime.runtime_id.as_str(), &runtime_json],
                )
                .await?
        };
        Ok(changed == 1)
    }

    /// List source-runtime definitions within one authenticated tenant. All
    /// predicates are applied in PostgreSQL so cross-tenant rows never enter
    /// the application response path.
    pub async fn list_source_runtimes(
        &self,
        tenant_id: &TenantId,
        source_id: Option<&str>,
        runtime_ids: &[SourceRuntimeId],
        limit: u16,
    ) -> Result<Vec<StoredSourceRuntime>, StoreError> {
        if limit == 0 || limit > 500 {
            return Err(StoreError::Conflict(
                "source runtime list limit must be between 1 and 500".to_owned(),
            ));
        }
        let source_id = source_id.filter(|value| !value.is_empty());
        if let Some(source_id) = source_id {
            validate_source_runtime_source_id(source_id)?;
        }
        let runtime_ids = runtime_ids
            .iter()
            .map(|runtime_id| runtime_id.as_str().to_owned())
            .collect::<Vec<_>>();
        let rows = self
            .client
            .lock()
            .await
            .query(
                r#"
SELECT id, runtime_json
FROM source_runtimes
WHERE runtime_json->>'tenant_id' = $1
  AND ($2::TEXT IS NULL OR runtime_json->>'source_id' = $2)
  AND (cardinality($3::TEXT[]) = 0 OR id = ANY($3::TEXT[]))
ORDER BY updated_at ASC, id ASC
LIMIT $4
"#,
                &[
                    &tenant_id.as_str(),
                    &source_id,
                    &runtime_ids,
                    &i64::from(limit),
                ],
            )
            .await?;
        rows.into_iter()
            .map(|row| {
                let runtime_id = SourceRuntimeId::parse(row.get::<_, String>(0)).map_err(|_| {
                    StoreError::Conflict("stored source runtime id is invalid".to_owned())
                })?;
                decode_stored_source_runtime(&runtime_id, row.get(1))
            })
            .collect()
    }

    /// Resolve connector-vault references against the exact durable runtime
    /// scope. The database lookup binds credential ID, tenant, source, runtime,
    /// store, and usable status in one predicate, so a foreign or revoked
    /// record cannot be distinguished from a missing record.
    pub async fn resolve_connector_credential_references(
        &self,
        runtime: &StoredSourceRuntime,
        values: &BTreeMap<String, String>,
        key_material: &str,
    ) -> Result<BTreeMap<String, String>, StoreError> {
        let mut references = BTreeMap::<String, Vec<(String, String)>>::new();
        for (config_key, value) in values {
            let Some((credential_id, field)) = parse_credential_reference(value) else {
                continue;
            };
            references
                .entry(credential_id.to_owned())
                .or_default()
                .push((config_key.clone(), field.to_owned()));
        }
        if references.is_empty() {
            return Ok(values.clone());
        }

        let vault_key = ConnectorVaultKey::parse(key_material)?;
        let client = self.client.lock().await;
        let mut resolved = SensitiveValues::new(values);
        let mut used_credentials = Vec::with_capacity(references.len());
        for (credential_id, requested_fields) in references {
            let row = client
                .query_opt(
                    "SELECT id, tenant_id, source_id, runtime_id, key_id, sealed
                     FROM connector_credentials
                     WHERE id = $1
                       AND tenant_id = $2
                       AND source_id = $3
                       AND runtime_id = $4
                       AND credential_store_id = 'cerebro_vault'
                       AND status IN ('valid', 'rotating')",
                    &[
                        &credential_id,
                        &runtime.tenant_id.as_str(),
                        &runtime.source_id,
                        &runtime.runtime_id.as_str(),
                    ],
                )
                .await?;
            let Some(row) = row else {
                return Err(StoreError::Conflict(
                    "connector credential is unavailable for this runtime".to_owned(),
                ));
            };
            let record = CredentialVaultRecord {
                id: row.get(0),
                tenant_id: row.get(1),
                source_id: row.get(2),
                runtime_id: row.get(3),
                key_id: row.get(4),
                sealed: row.get(5),
            };
            let fields = vault_key.open(&record)?;
            for (config_key, field) in requested_fields {
                let Some(secret) = fields.get(&field) else {
                    return Err(StoreError::Conflict(
                        "connector credential field is unavailable".to_owned(),
                    ));
                };
                resolved.insert(config_key, secret.to_owned());
            }
            used_credentials.push(credential_id);
        }

        for credential_id in used_credentials {
            track_connector_credential_use(
                &client,
                &credential_id,
                runtime.tenant_id.as_str(),
                &runtime.source_id,
                runtime.runtime_id.as_str(),
            )
            .await?;
        }
        Ok(resolved.into_inner())
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
  AND lease_expires_at > clock_timestamp()
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
                RECORD_SOURCE_EVENT_QUERY,
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

    pub async fn source_collection_manifest(
        &self,
        tenant_id: &str,
        source_runtime_id: &str,
        collection_id: &str,
    ) -> Result<Option<Value>, StoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let row = transaction
            .query_opt(
                SOURCE_COLLECTION_MANIFEST_QUERY,
                &[&tenant_id, &source_runtime_id, &collection_id],
            )
            .await?;
        transaction.commit().await?;
        Ok(row.map(|row| row.get("manifest_json")))
    }

    /// Search current source runtimes and join the latest collection receipt.
    ///
    /// The query is a literal case-insensitive substring, not a SQL pattern.
    /// Tenant scope is applied both to the shared runtime registry and through
    /// the receipt table's row-level-security context.
    pub async fn source_runtime_observations(
        &self,
        tenant_id: &str,
        query: &str,
        limit: usize,
    ) -> Result<Vec<SourceRuntimeObservation>, StoreError> {
        if tenant_id.trim().is_empty() || limit == 0 || limit > 500 {
            return Err(StoreError::Conflict(
                "source runtime observation scope is invalid".to_owned(),
            ));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| StoreError::Conflict("source runtime limit overflow".to_owned()))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let rows = transaction
            .query(
                r#"
SELECT
  runtime.id,
  COALESCE(runtime.runtime_json->>'source_id', ''),
  CASE
    WHEN LOWER(COALESCE(runtime.runtime_json->'config'->>'enabled', '')) IN ('false', '0', 'disabled')
    THEN 'disabled'
    ELSE 'enabled'
  END,
  NULLIF(runtime.runtime_json->'config'->>'__cerebro_runtime_last_failure_category', ''),
  NULLIF(runtime.runtime_json->>'last_synced_at', ''),
  COALESCE(NULLIF(runtime.runtime_json->'next_cursor'->>'opaque', ''), '') <> '',
  COALESCE(NULLIF(runtime.runtime_json->'checkpoint'->>'cursor_opaque', ''), '') <> '',
  NULLIF(runtime.runtime_json->'config'->>'stale_after_seconds', ''),
  latest.collection_id,
  latest.status,
  latest.completed_at_unix_ms,
  latest.pages_read,
  latest.records_scanned,
  latest.records_accepted,
  latest.records_rejected,
  COALESCE(NULLIF(runtime.runtime_json->'config'->>'__cerebro_runtime_contract_probe_state', ''), 'unknown'),
  NULLIF(runtime.runtime_json->'config'->>'expected_cadence_seconds', ''),
  finding.status
FROM source_runtimes AS runtime
LEFT JOIN LATERAL (
  SELECT
    collection_id,
    status,
    completed_at_unix_ms,
    pages_read,
    records_scanned,
    records_accepted,
    records_rejected
  FROM organizational_source_collection_receipts
  WHERE tenant_id = $1
    AND source_runtime_id = runtime.id
  ORDER BY completed_at_unix_ms DESC, collection_id DESC
  LIMIT 1
) AS latest ON TRUE
LEFT JOIN LATERAL (
  SELECT status
  FROM finding_evaluation_runs
  WHERE runtime_id = runtime.id
  ORDER BY started_at DESC, id DESC
  LIMIT 1
) AS finding ON TRUE
WHERE runtime.runtime_json->>'tenant_id' = $1
  AND (
    $2 = ''
    OR POSITION(LOWER($2) IN LOWER(runtime.id)) > 0
    OR POSITION(LOWER($2) IN LOWER(COALESCE(runtime.runtime_json->>'source_id', ''))) > 0
  )
ORDER BY
  CASE
    WHEN LOWER(runtime.id) = LOWER($2)
      OR LOWER(COALESCE(runtime.runtime_json->>'source_id', '')) = LOWER($2)
    THEN 0
    ELSE 1
  END,
  runtime.id
LIMIT $3
"#,
                &[&tenant_id, &query.trim(), &limit],
            )
            .await?;
        transaction.commit().await?;
        rows.into_iter()
            .map(|row| {
                let stale_after_seconds = row
                    .get::<_, Option<String>>(7)
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|value| *value > 0);
                let expected_cadence_seconds = row
                    .get::<_, Option<String>>(16)
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|value| *value > 0);
                let latest_collection = match row.get::<_, Option<String>>(8) {
                    Some(collection_id) => Some(SourceRuntimeCollectionObservation {
                        collection_id,
                        status: row.get(9),
                        completed_at_unix_ms: stored_u64(&row, 10, "completed_at_unix_ms")?,
                        pages_read: stored_u64(&row, 11, "pages_read")?,
                        records_scanned: stored_u64(&row, 12, "records_scanned")?,
                        records_accepted: stored_u64(&row, 13, "records_accepted")?,
                        records_rejected: stored_u64(&row, 14, "records_rejected")?,
                    }),
                    None => None,
                };
                Ok(SourceRuntimeObservation {
                    runtime_id: row.get(0),
                    source_id: row.get(1),
                    enabled_state: row.get(2),
                    last_failure_category: row.get(3),
                    last_synced_at: row.get(4),
                    cursor_pending: row.get(5),
                    checkpoint_cursor_present: row.get(6),
                    stale_after_seconds,
                    expected_cadence_seconds,
                    contract_probe_state: row.get(15),
                    latest_finding_evaluation_status: row.get(17),
                    latest_collection,
                })
            })
            .collect()
    }

    /// Return one deterministic descending keyset page of projected audit
    /// events for a single tenant and immutable time window, mirroring the Go
    /// `ListAuditEvents` reader semantics (tenant scope, lowered exact filters,
    /// escaped substring search, `occurred_at DESC, event_id COLLATE "C" DESC`
    /// ordering, and a limit+1 has-more probe).
    ///
    /// The Go reader creates the `platform_audit_events` projection table on
    /// demand before reading it; this surface must not run DDL, so a database
    /// without the projection serves the same observable result: an empty
    /// window.
    pub async fn list_audit_events(
        &self,
        query: &AuditEventPageQuery,
    ) -> Result<StoredAuditEventPage, StoreError> {
        if query.tenant_id.trim().is_empty()
            || query.limit == 0
            || query.limit > 500
            || query.after.trim().is_empty()
            || query.before.trim().is_empty()
            || (query.page_before_occurred_at.is_some() && query.page_before_id.trim().is_empty())
        {
            return Err(StoreError::Conflict(
                "audit event query scope is invalid".to_owned(),
            ));
        }
        let mut clauses = vec![
            "tenant_id = $1".to_owned(),
            "occurred_at >= $2::timestamptz".to_owned(),
            "occurred_at <= $3::timestamptz".to_owned(),
        ];
        let mut values = vec![
            query.tenant_id.trim().to_owned(),
            query.after.trim().to_owned(),
            query.before.trim().to_owned(),
        ];
        audit_event_exact_filter(&mut clauses, &mut values, "action", &query.action);
        audit_event_actor_filter(&mut clauses, &mut values, &query.actor);
        audit_event_exact_filter(&mut clauses, &mut values, "outcome", &query.outcome);
        audit_event_exact_filter(
            &mut clauses,
            &mut values,
            "resource_type",
            &query.resource_type,
        );
        audit_event_exact_filter(&mut clauses, &mut values, "service", &query.service);
        audit_event_exact_filter(&mut clauses, &mut values, "trace_id", &query.trace_id);
        audit_event_text_filter(&mut clauses, &mut values, &query.text);
        if let Some(boundary) = &query.page_before_occurred_at {
            values.push(boundary.trim().to_owned());
            let time_index = values.len();
            values.push(query.page_before_id.trim().to_owned());
            clauses.push(format!(
                "(occurred_at < ${time_index}::timestamptz OR (occurred_at = ${time_index}::timestamptz AND event_id COLLATE \"C\" < ${}))",
                values.len()
            ));
        }
        let limit = i64::from(query.limit) + 1;
        let mut params: Vec<&(dyn ToSql + Sync)> = values
            .iter()
            .map(|value| value as &(dyn ToSql + Sync))
            .collect();
        params.push(&limit);
        let statement = format!(
            "SELECT event_id, tenant_id, action, actor_id, actor_kind, actor_label, category, \
             duration_ms, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), \
             outcome, request_id, resource_id, resource_type, resource_label, service, summary, trace_id \
             FROM platform_audit_events WHERE {} \
             ORDER BY occurred_at DESC, event_id COLLATE \"C\" DESC LIMIT ${}",
            clauses.join(" AND "),
            params.len()
        );
        let rows = match self.client.lock().await.query(&statement, &params).await {
            Ok(rows) => rows,
            Err(error) if error.code() == Some(&SqlState::UNDEFINED_TABLE) => {
                return Ok(StoredAuditEventPage::default());
            }
            Err(error) => return Err(StoreError::Postgres(error)),
        };
        let mut events: Vec<StoredAuditEvent> = rows
            .iter()
            .map(|row| StoredAuditEvent {
                id: row.get(0),
                tenant_id: row.get(1),
                action: row.get(2),
                actor_id: row.get(3),
                actor_kind: row.get(4),
                actor_label: row.get(5),
                category: row.get(6),
                duration_ms: row.get(7),
                occurred_at: row.get(8),
                outcome: row.get(9),
                request_id: row.get(10),
                resource_id: row.get(11),
                resource_type: row.get(12),
                resource_label: row.get(13),
                service: row.get(14),
                summary: row.get(15),
                trace_id: row.get(16),
            })
            .collect();
        let has_more = events.len() > query.limit as usize;
        if has_more {
            events.truncate(query.limit as usize);
        }
        Ok(StoredAuditEventPage {
            events,
            has_more,
            partial: false,
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
                request.tenant_id(),
                request.source_id(),
                request.family_id(),
                &receipts,
                request.projection_lag(),
                request.qualification(),
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
        if decision.tenant_id() != tenant_id {
            return Err(StoreError::Conflict(
                "projection promotion tenant does not match decision evidence".to_owned(),
            ));
        }
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
        if fence.is_some() {
            validate_source_runtime_cursor(batch.next_cursor.as_deref())?;
        }

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
        if let Some(fence) = fence {
            advance_source_runtime_progress(&transaction, batch, fence).await?;
        }
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

    /// Upserts one saved ask query, mirroring the Go store's SQL semantics.
    ///
    /// The `ON CONFLICT` update is additionally fenced on the tenant so a
    /// colliding identifier can never move a row across tenants.
    pub async fn put_ask_query(&self, query: &AskQueryWrite<'_>) -> Result<(), StoreError> {
        let id = query.id.trim();
        let tenant_id = query.tenant_id.trim();
        let name = query.name.trim();
        let question = query.question.trim();
        if id.is_empty() || tenant_id.is_empty() || name.is_empty() || question.is_empty() {
            return Err(StoreError::Conflict(
                "ask query id, tenant_id, name, and question are required".to_owned(),
            ));
        }
        self.client
            .lock()
            .await
            .execute(
                "INSERT INTO ask_queries (id, tenant_id, name, question, scope_urn, model, pinned)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (id) DO UPDATE SET
                   name = EXCLUDED.name,
                   question = EXCLUDED.question,
                   scope_urn = EXCLUDED.scope_urn,
                   model = EXCLUDED.model,
                   pinned = EXCLUDED.pinned,
                   updated_at = NOW()
                 WHERE ask_queries.tenant_id = EXCLUDED.tenant_id",
                &[
                    &id,
                    &tenant_id,
                    &name,
                    &question,
                    &query.scope_urn.trim(),
                    &query.model.trim(),
                    &query.pinned,
                ],
            )
            .await
            .map_err(StoreError::Postgres)?;
        Ok(())
    }

    /// Loads one saved ask query within the tenant scope.
    ///
    /// A missing `ask_queries` relation maps to `Ok(None)`: the Go store
    /// auto-creates the table on first use, so its steady-state answer for an
    /// unknown identifier is "not found".
    pub async fn get_ask_query(
        &self,
        tenant_id: &str,
        query_id: &str,
    ) -> Result<Option<AskQueryRecord>, StoreError> {
        let id = query_id.trim();
        let tenant_id = tenant_id.trim();
        if id.is_empty() || tenant_id.is_empty() {
            return Err(StoreError::Conflict(
                "ask query id and tenant_id are required".to_owned(),
            ));
        }
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                &format!(
                    "SELECT {ASK_QUERY_COLUMNS} FROM ask_queries WHERE id = $1 AND tenant_id = $2"
                ),
                &[&id, &tenant_id],
            )
            .await;
        match row {
            Ok(Some(row)) => Ok(Some(scan_ask_query(&row)?)),
            Ok(None) => Ok(None),
            Err(error) if undefined_ask_query_table(&error) => Ok(None),
            Err(error) => Err(StoreError::Postgres(error)),
        }
    }

    /// Returns saved ask queries for one tenant, pinned first then
    /// newest-first, mirroring the Go store's ordering and limit bounds.
    pub async fn list_ask_queries(
        &self,
        tenant_id: &str,
        limit: u32,
    ) -> Result<Vec<AskQueryRecord>, StoreError> {
        let tenant_id = tenant_id.trim();
        if tenant_id.is_empty() {
            return Err(StoreError::Conflict(
                "ask query tenant_id is required".to_owned(),
            ));
        }
        let rows = self
            .client
            .lock()
            .await
            .query(
                &format!(
                    "SELECT {ASK_QUERY_COLUMNS} FROM ask_queries
                     WHERE tenant_id = $1
                     ORDER BY pinned DESC, created_at DESC
                     LIMIT $2"
                ),
                &[&tenant_id, &ask_query_list_limit(limit)],
            )
            .await;
        match rows {
            Ok(rows) => rows.iter().map(scan_ask_query).collect(),
            Err(error) if undefined_ask_query_table(&error) => Ok(Vec::new()),
            Err(error) => Err(StoreError::Postgres(error)),
        }
    }

    /// Removes one saved ask query within the tenant scope. Returns whether a
    /// row was deleted; a missing relation reads as "nothing to delete".
    pub async fn delete_ask_query(
        &self,
        tenant_id: &str,
        query_id: &str,
    ) -> Result<bool, StoreError> {
        let id = query_id.trim();
        let tenant_id = tenant_id.trim();
        if id.is_empty() || tenant_id.is_empty() {
            return Err(StoreError::Conflict(
                "ask query id and tenant_id are required".to_owned(),
            ));
        }
        let deleted = self
            .client
            .lock()
            .await
            .execute(
                "DELETE FROM ask_queries WHERE id = $1 AND tenant_id = $2",
                &[&id, &tenant_id],
            )
            .await;
        match deleted {
            Ok(count) => Ok(count > 0),
            Err(error) if undefined_ask_query_table(&error) => Ok(false),
            Err(error) => Err(StoreError::Postgres(error)),
        }
    }
}

/// One stored saved ask query, timestamps already rendered as the RFC 3339
/// UTC strings the product surface serves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AskQueryRecord {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub question: String,
    pub scope_urn: String,
    pub model: String,
    pub pinned: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Write-side view of one saved ask query. Timestamps are owned by Postgres.
#[derive(Clone, Copy, Debug)]
pub struct AskQueryWrite<'a> {
    pub id: &'a str,
    pub tenant_id: &'a str,
    pub name: &'a str,
    pub question: &'a str,
    pub scope_urn: &'a str,
    pub model: &'a str,
    pub pinned: bool,
}

/// Column list shared by ask-query reads. Timestamps are rendered in SQL so
/// the wire format matches Go's `time.RFC3339` (second precision, `Z` suffix).
const ASK_QUERY_COLUMNS: &str = "id, tenant_id, name, question, scope_urn, model, pinned, \
     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'), \
     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";

/// Mirrors the Go store's list bounds: default 100, hard cap 500.
fn ask_query_list_limit(limit: u32) -> i64 {
    const DEFAULT_LIMIT: i64 = 100;
    const MAX_LIMIT: i64 = 500;
    match i64::from(limit) {
        0 => DEFAULT_LIMIT,
        value if value > MAX_LIMIT => MAX_LIMIT,
        value => value,
    }
}

/// The Go store creates `ask_queries` on first use; until a Go write has run,
/// the relation may not exist. SQLSTATE 42P01 therefore maps to the Go
/// steady-state read result instead of an error.
fn undefined_ask_query_table(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&tokio_postgres::error::SqlState::UNDEFINED_TABLE)
}

fn scan_ask_query(row: &tokio_postgres::Row) -> Result<AskQueryRecord, StoreError> {
    Ok(AskQueryRecord {
        id: row.get(0),
        tenant_id: row.get(1),
        name: row.get(2),
        question: row.get(3),
        scope_urn: row.get(4),
        model: row.get(5),
        pinned: row.get(6),
        created_at: row.get(7),
        updated_at: row.get(8),
    })
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

/// One bounded, already-validated audit-event read scope. Timestamps are
/// RFC 3339 UTC text so the read stays on the stable text protocol; the
/// platform layer owns parsing, clamping, and cursor semantics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditEventPageQuery {
    pub tenant_id: String,
    /// Inclusive RFC 3339 UTC lower bound of the immutable window.
    pub after: String,
    /// Inclusive RFC 3339 UTC upper bound of the immutable window.
    pub before: String,
    /// Page size; the reader probes one extra row to report `has_more`.
    pub limit: u32,
    pub action: String,
    pub actor: String,
    pub outcome: String,
    pub resource_type: String,
    pub service: String,
    pub trace_id: String,
    /// Escaped substring search over action, actor label, resource label, and
    /// summary.
    pub text: String,
    /// RFC 3339 UTC keyset boundary; requires `page_before_id`.
    pub page_before_occurred_at: Option<String>,
    pub page_before_id: String,
}

/// One projected audit-event row in the fixed persistence allowlist.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoredAuditEvent {
    pub id: String,
    pub tenant_id: String,
    pub action: String,
    pub actor_id: String,
    pub actor_kind: String,
    pub actor_label: String,
    pub category: String,
    pub duration_ms: Option<i64>,
    /// RFC 3339 UTC with microsecond precision.
    pub occurred_at: String,
    pub outcome: String,
    pub request_id: String,
    pub resource_id: String,
    pub resource_type: String,
    pub resource_label: String,
    pub service: String,
    pub summary: String,
    pub trace_id: String,
}

/// One deterministic keyset page of projected audit events. `partial` is
/// reserved for readers that can prove only a subset of durable inputs was
/// available; the Postgres reader returns complete pages or an error.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoredAuditEventPage {
    pub events: Vec<StoredAuditEvent>,
    pub has_more: bool,
    pub partial: bool,
}

fn audit_event_exact_filter(
    clauses: &mut Vec<String>,
    values: &mut Vec<String>,
    column: &str,
    value: &str,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    values.push(value.to_owned());
    clauses.push(format!("LOWER({column}) = LOWER(${})", values.len()));
}

fn audit_event_actor_filter(clauses: &mut Vec<String>, values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    values.push(value.to_owned());
    let index = values.len();
    clauses.push(format!(
        "(LOWER(actor_id) = LOWER(${index}) OR LOWER(actor_label) = LOWER(${index}))"
    ));
}

fn audit_event_text_filter(clauses: &mut Vec<String>, values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    let escaped = value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    values.push(format!("%{escaped}%"));
    let index = values.len();
    clauses.push(format!(
        "(action ILIKE ${index} ESCAPE '\\' OR actor_label ILIKE ${index} ESCAPE '\\' \
         OR resource_label ILIKE ${index} ESCAPE '\\' OR summary ILIKE ${index} ESCAPE '\\')"
    ));
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
            let entity_kind = enum_name(entity.kind())?;
            let lifecycle = lifecycle_projection(
                delta.collection().tenant_id(),
                &agent_key,
                entity.label(),
                &properties,
            )?;
            let lifecycle_finding_urn = lifecycle_finding_projection(
                delta.collection().tenant_id(),
                &entity_kind,
                &properties,
            )?;
            let lifecycle_source_runtime_id = (lifecycle.is_some()
                || lifecycle_finding_urn.is_some())
            .then(|| delta.collection().source_runtime_id().as_str().to_owned());
            let lifecycle_source_collection_id = (lifecycle.is_some()
                || lifecycle_finding_urn.is_some())
            .then(|| properties.get("source_collection_id").cloned())
            .flatten();
            Ok(ProjectionEntity {
                entity_id: entity.id().as_str().to_owned(),
                entity_kind,
                authority_json: serde_json::to_string(entity.authority())?,
                label: entity.label().to_owned(),
                properties_json: serde_json::to_string(&properties)?,
                external_id: Some(agent_key),
                lifecycle,
                lifecycle_finding_urn,
                lifecycle_source_runtime_id,
                lifecycle_source_collection_id,
            })
        })
        .collect::<Result<_, StoreError>>()?;
    let assertions = delta
        .assertions()
        .iter()
        .map(|assertion| {
            let (from, to, relation) = assertion_endpoints(assertion);
            let (state, observed_at_unix_ms, application_workspace_id) = match assertion {
                GraphAssertion::Relationship(value) => (
                    "confirmed".to_owned(),
                    value.observed_at_unix_ms(),
                    value.application_workspace_id(),
                ),
                GraphAssertion::IdentityBinding(value) => {
                    (enum_name(&value.state())?, value.observed_at_unix_ms(), "")
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
                application_workspace_id: application_workspace_id.to_owned(),
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

pub(crate) fn lifecycle_projection(
    tenant_id: &TenantId,
    agent_key: &str,
    label: &str,
    properties: &BTreeMap<String, String>,
) -> Result<Option<LifecycleProjectionEntity>, StoreError> {
    let resource = cerebro_security_lifecycle::ProjectedResource {
        agent_key: agent_key.to_owned(),
        label: label.to_owned(),
        properties: properties.clone(),
    };
    let Some(observation) = cerebro_security_lifecycle::Observation::from_graph(resource)
        .map_err(|error| StoreError::Conflict(format!("invalid lifecycle projection: {error}")))?
    else {
        return Ok(None);
    };
    observation
        .validate(tenant_id)
        .map_err(|error| StoreError::Conflict(format!("invalid lifecycle projection: {error}")))?;
    Ok(Some(LifecycleProjectionEntity {
        subject_urn: observation.subject_ref.id,
        subject_kind: observation.subject_kind.as_str().to_owned(),
        observed_state: cerebro_security_lifecycle::lifecycle_state_name(observation.state)
            .to_owned(),
        owner_urn: observation.owner_urn,
        observed_at_unix_ms: cerebro_security_lifecycle::timestamp_millis_from_rfc3339(
            &observation.observed_at,
        )
        .map_err(|error| StoreError::Conflict(format!("invalid lifecycle projection: {error}")))?,
        expires_at_unix_ms: observation
            .expires_at
            .as_deref()
            .map(cerebro_security_lifecycle::timestamp_millis_from_rfc3339)
            .transpose()
            .map_err(|error| {
                StoreError::Conflict(format!("invalid lifecycle projection: {error}"))
            })?,
    }))
}

pub(crate) fn lifecycle_finding_projection(
    tenant_id: &TenantId,
    entity_kind: &str,
    properties: &BTreeMap<String, String>,
) -> Result<Option<String>, StoreError> {
    if entity_kind != "finding"
        || properties.get("policy_id").map(String::as_str)
            != Some(cerebro_security_lifecycle::EXPIRY_POLICY_ID)
        || properties.get("status").map(String::as_str) != Some("open")
    {
        return Ok(None);
    }
    let finding_urn = properties
        .get("resource_urn")
        .ok_or_else(|| StoreError::Conflict("lifecycle finding has no stable URN".to_owned()))?;
    let subject_urn = properties
        .get("subject_urn")
        .ok_or_else(|| StoreError::Conflict("lifecycle finding has no subject URN".to_owned()))?;
    let expected =
        cerebro_security_lifecycle::canonical_finding_urn(tenant_id.as_str(), subject_urn)
            .map_err(|error| StoreError::Conflict(format!("invalid lifecycle finding: {error}")))?;
    if finding_urn != &expected {
        return Err(StoreError::Conflict(
            "lifecycle finding stable URN does not match its subject".to_owned(),
        ));
    }
    Ok(Some(finding_urn.clone()))
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

fn decode_stored_source_runtime(
    expected_runtime_id: &SourceRuntimeId,
    value: Value,
) -> Result<StoredSourceRuntime, StoreError> {
    let wire: StoredSourceRuntimeWire = serde_json::from_value(value).map_err(|_| {
        StoreError::Conflict("stored source runtime definition is invalid".to_owned())
    })?;
    let runtime_id = SourceRuntimeId::parse(wire.id)
        .map_err(|_| StoreError::Conflict("stored source runtime id is invalid".to_owned()))?;
    if &runtime_id != expected_runtime_id {
        return Err(StoreError::Conflict(
            "stored source runtime id does not match its row".to_owned(),
        ));
    }
    let tenant_id = TenantId::parse(wire.tenant_id)
        .map_err(|_| StoreError::Conflict("stored source runtime tenant is invalid".to_owned()))?;
    StoredSourceRuntime::new(
        runtime_id,
        tenant_id,
        wire.source_id,
        wire.config,
        wire.checkpoint,
        wire.next_cursor,
        wire.last_synced_at,
    )
}

fn stored_source_runtime_json(runtime: &StoredSourceRuntime) -> Result<Value, StoreError> {
    Ok(serde_json::to_value(StoredSourceRuntimeWire {
        id: runtime.runtime_id.as_str().to_owned(),
        source_id: runtime.source_id.clone(),
        tenant_id: runtime.tenant_id.as_str().to_owned(),
        config: runtime.config.clone(),
        checkpoint: runtime.checkpoint.clone(),
        next_cursor: runtime.next_cursor.clone(),
        last_synced_at: runtime.last_synced_at.clone(),
    })?)
}

fn validate_source_runtime_source_id(source_id: &str) -> Result<(), StoreError> {
    if source_id.is_empty()
        || source_id.trim() != source_id
        || source_id.len() > 128
        || source_id.chars().any(char::is_control)
    {
        return Err(StoreError::Conflict(
            "stored source runtime source is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_source_runtime_config(config: &BTreeMap<String, String>) -> Result<(), StoreError> {
    if config.len() > 256 {
        return Err(StoreError::Conflict(
            "source runtime config has too many entries".to_owned(),
        ));
    }
    for (key, value) in config {
        if key.is_empty()
            || key.trim() != key
            || key.len() > 256
            || key.chars().any(char::is_control)
            || value.len() > 64 * 1024
            || value.chars().any(|character| character == '\0')
        {
            return Err(StoreError::Conflict(
                "source runtime config is invalid".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_source_runtime_json_field(
    field: &str,
    value: Option<&Value>,
) -> Result<(), StoreError> {
    if value.is_some_and(|value| {
        serde_json::to_vec(value)
            .map(|encoded| encoded.len() > 64 * 1024)
            .unwrap_or(true)
    }) {
        return Err(StoreError::Conflict(format!(
            "source runtime {field} is invalid"
        )));
    }
    Ok(())
}

async fn track_connector_credential_use(
    client: &Client,
    credential_id: &str,
    tenant_id: &str,
    source_id: &str,
    runtime_id: &str,
) -> Result<(), StoreError> {
    let sequence = CREDENTIAL_AUDIT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let unix_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let audit_id = format!(
        "credential-audit-rust-{}-{unix_nanos}-{sequence}",
        std::process::id()
    );
    client
        .execute(
            "WITH used AS (
               UPDATE connector_credentials
               SET last_used_at = NOW(), updated_at = NOW()
               WHERE id = $1
                 AND tenant_id = $2
                 AND source_id = $3
                 AND runtime_id = $4
                 AND credential_store_id = 'cerebro_vault'
                 AND status IN ('valid', 'rotating')
                 AND (last_used_at IS NULL OR last_used_at <= NOW() - INTERVAL '1 hour')
               RETURNING status
             )
             INSERT INTO connector_credential_audit_events (
               id, credential_id, tenant_id, source_id, runtime_id,
               event_type, actor, status, detail, created_at
             )
             SELECT $5, $1, $2, $3, $4, 'used', '', status, '', NOW()
             FROM used",
            &[
                &credential_id,
                &tenant_id,
                &source_id,
                &runtime_id,
                &audit_id,
            ],
        )
        .await?;
    Ok(())
}

fn resumable_checkpoint_cursor(cursor: &str) -> bool {
    serde_json::from_str::<Value>(cursor)
        .ok()
        .and_then(|value| value.as_object()?.get("resumable_checkpoint")?.as_bool())
        .unwrap_or(false)
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
SELECT lease_owner, lease_generation, lease_expires_at > clock_timestamp()
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

fn validate_source_runtime_cursor(cursor: Option<&str>) -> Result<(), StoreError> {
    if cursor.is_some_and(|cursor| cursor.trim().is_empty() || cursor.len() > 64 * 1024) {
        return Err(StoreError::Conflict(
            "source runtime continuation cursor is invalid".to_owned(),
        ));
    }
    Ok(())
}

async fn advance_source_runtime_progress(
    transaction: &tokio_postgres::Transaction<'_>,
    batch: &CollectedBatch,
    fence: &SourceRuntimeLeaseFence,
) -> Result<(), StoreError> {
    let generation = storage_generation(fence.generation())?;
    let next_cursor = batch
        .next_cursor
        .as_ref()
        .map(|cursor| serde_json::json!({"opaque": cursor}));
    let checkpoint_row = transaction
        .query_opt(
            "SELECT runtime_json->'checkpoint'->>'cursor_opaque'
             FROM source_runtimes
             WHERE id = $1 AND runtime_json->>'tenant_id' = $2",
            &[
                &fence.source_runtime_id().as_str(),
                &fence.tenant_id().as_str(),
            ],
        )
        .await?;
    let Some(checkpoint_row) = checkpoint_row else {
        return Err(StoreError::Conflict(
            "source runtime was removed before progress commit".to_owned(),
        ));
    };
    let checkpoint_cursor: Option<String> = checkpoint_row.get(0);
    let clear_checkpoint_cursor = next_cursor.is_none()
        && checkpoint_cursor
            .as_deref()
            .is_some_and(resumable_checkpoint_cursor);
    let updated = transaction
        .execute(
            r#"
UPDATE source_runtimes
SET runtime_json = jsonb_set(
      CASE
        WHEN $5::jsonb IS NULL THEN
          CASE
            WHEN $6::BOOLEAN
              AND jsonb_typeof(runtime_json->'checkpoint') = 'object' THEN
              jsonb_set(
                runtime_json - 'next_cursor',
                '{checkpoint,cursor_opaque}',
                '""'::jsonb,
                TRUE
              )
            ELSE runtime_json - 'next_cursor'
          END
        ELSE jsonb_set(runtime_json, '{next_cursor}', $5::jsonb, TRUE)
      END,
      '{last_synced_at}',
      to_jsonb(clock_timestamp()),
      TRUE
    ),
    updated_at = clock_timestamp()
WHERE id = $1
  AND runtime_json->>'tenant_id' = $2
  AND lease_owner = $3
  AND lease_generation = $4
  AND lease_expires_at > clock_timestamp()
"#,
            &[
                &fence.source_runtime_id().as_str(),
                &fence.tenant_id().as_str(),
                &fence.owner(),
                &generation,
                &next_cursor,
                &clear_checkpoint_cursor,
            ],
        )
        .await?;
    if updated != 1 {
        return Err(StoreError::Conflict(
            "source runtime lease was lost before progress commit".to_owned(),
        ));
    }
    Ok(())
}

fn stored_count(row: &tokio_postgres::Row, index: usize, field: &str) -> Result<usize, StoreError> {
    let value: i64 = row.get(index);
    usize::try_from(value)
        .map_err(|_| StoreError::Conflict(format!("stored {field} count is invalid")))
}

fn stored_u64(row: &tokio_postgres::Row, index: usize, field: &str) -> Result<u64, StoreError> {
    let value: i64 = row.get(index);
    u64::try_from(value).map_err(|_| StoreError::Conflict(format!("stored {field} is invalid")))
}

#[cfg(test)]
mod tests {
    use std::env;

    use tokio_postgres::NoTls;

    use super::*;

    #[test]
    fn ask_query_list_limit_mirrors_go_bounds() {
        assert_eq!(ask_query_list_limit(0), 100, "default when unset");
        assert_eq!(ask_query_list_limit(1), 1);
        assert_eq!(ask_query_list_limit(100), 100);
        assert_eq!(ask_query_list_limit(500), 500);
        assert_eq!(ask_query_list_limit(501), 500, "hard cap");
        assert_eq!(ask_query_list_limit(u32::MAX), 500, "hard cap");
    }

    #[test]
    fn ask_query_statements_stay_tenant_scoped() {
        let source = include_str!("postgres.rs");
        assert!(
            source.contains("WHERE ask_queries.tenant_id = EXCLUDED.tenant_id"),
            "the upsert must fence its conflict update on the tenant"
        );
        assert!(
            source.contains("FROM ask_queries WHERE id = $1 AND tenant_id = $2"),
            "reads must stay tenant-scoped"
        );
        assert!(
            source.contains("DELETE FROM ask_queries WHERE id = $1 AND tenant_id = $2"),
            "deletes must stay tenant-scoped"
        );
        assert!(
            ASK_QUERY_COLUMNS.contains("YYYY-MM-DD\"T\"HH24:MI:SS\"Z\""),
            "timestamps must render as second-precision RFC 3339 UTC, matching Go"
        );
    }

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
            "source_runtime_page_publications",
            "source_runtime_page_publications_recovery_idx",
            "source_runtime_page_events",
            "organizational_source_collection_latest_idx",
            "organizational_consumer_runs",
            "organizational_consumer_family_progress",
            "organizational_consumer_skip_categories",
            "last_delivered_sequence BIGINT NOT NULL DEFAULT 0",
            "current_setting(''cerebro.tenant_id'', true)",
            "DEFERRABLE INITIALLY DEFERRED",
        ] {
            assert!(POSTGRES_SCHEMA.contains(required), "missing {required}");
        }
        assert!(include_str!("postgres.rs").contains("messages_projected > 0"));
        assert!(include_str!("postgres.rs").contains("messages_rejected = 0"));
        assert!(
            START_CONSUMER_RUN_QUERY.contains(
                "organizational_consumer_runs.mode = 'forward' AND organizational_consumer_runs.end_sequence IS NULL AND EXCLUDED.end_sequence IS NULL"
            ),
            "unbounded forward runs must resume their stored fence after restart"
        );
        assert!(
            START_CONSUMER_RUN_QUERY.contains("RETURNING start_sequence, end_sequence"),
            "consumer restart must return the stored fence"
        );
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
    fn consumer_skip_categories_are_closed_and_reconciled() {
        let categories = validate_skip_categories(
            7,
            vec![
                (
                    "legacy_catalog_canary_without_source_envelope".to_owned(),
                    1,
                ),
                ("legacy_invalid_observation_id".to_owned(), 2),
                ("legacy_missing_source_owned_kind".to_owned(), 1),
                (
                    "legacy_retired_family_projection_incompatible".to_owned(),
                    1,
                ),
                ("source_outside_compiled_catalog".to_owned(), 1),
                ("subject_outside_projection_contract".to_owned(), 1),
            ],
        )
        .unwrap();
        assert_eq!(categories.values().sum::<u64>(), 7);
        assert_eq!(categories.len(), ConsumerSkipCategory::ALL.len());

        for rows in [
            Vec::new(),
            vec![(
                "legacy_catalog_canary_without_source_envelope".to_owned(),
                1,
            )],
            vec![("unknown".to_owned(), 2)],
            vec![
                (
                    "legacy_catalog_canary_without_source_envelope".to_owned(),
                    1,
                ),
                ("legacy_invalid_observation_id".to_owned(), 1),
                ("legacy_missing_source_owned_kind".to_owned(), 1),
                (
                    "legacy_retired_family_projection_incompatible".to_owned(),
                    1,
                ),
                ("source_outside_compiled_catalog".to_owned(), 1),
                ("subject_outside_projection_contract".to_owned(), 1),
                ("subject_outside_projection_contract".to_owned(), 1),
            ],
        ] {
            assert!(validate_skip_categories(2, rows).is_err());
        }
        assert!(validate_skip_categories(0, Vec::new()).is_ok());
    }

    #[test]
    fn consumer_run_inspection_serializes_durable_skip_categories() {
        let inspection = ConsumerRunInspection {
            consumer_name: "organizational-graph-replay".to_owned(),
            run_id: "replay-proof".to_owned(),
            mode: "replay".to_owned(),
            start_sequence: 1,
            end_sequence: Some(50),
            status: "completed".to_owned(),
            started_at_unix_ms: 1,
            updated_at_unix_ms: 2,
            completed_at_unix_ms: Some(2),
            progress: ConsumerRunProgress {
                last_delivered_sequence: 50,
                covered_sequence: 50,
                messages_seen: 3,
                messages_projected: 1,
                messages_skipped: 2,
                messages_rejected: 0,
            },
            skip_categories: BTreeMap::from([
                (
                    "legacy_catalog_canary_without_source_envelope".to_owned(),
                    1,
                ),
                ("legacy_missing_source_owned_kind".to_owned(), 1),
            ]),
            families: Vec::new(),
        };
        let value = serde_json::to_value(inspection).unwrap();
        assert_eq!(
            value["skip_categories"],
            serde_json::json!({
                "legacy_catalog_canary_without_source_envelope": 1,
                "legacy_missing_source_owned_kind": 1,
            })
        );
        assert_eq!(
            value["progress"]["messages_skipped"],
            value["skip_categories"]
                .as_object()
                .unwrap()
                .values()
                .map(|count| count.as_u64().unwrap())
                .sum::<u64>()
        );
    }

    #[test]
    fn stored_source_runtime_identity_and_cursor_come_from_the_durable_record() {
        let runtime_id = SourceRuntimeId::parse("runtime-a").unwrap();
        let stored = decode_stored_source_runtime(
            &runtime_id,
            serde_json::json!({
                "id": "runtime-a",
                "source_id": "github",
                "tenant_id": "tenant-a",
                "config": {
                    "family": "repository",
                    "token": "env:CEREBRO_SOURCE_GITHUB_TOKEN"
                },
                "checkpoint": {"cursor_opaque": "checkpoint"},
                "next_cursor": {"opaque": "next"}
            }),
        )
        .unwrap();
        assert_eq!(stored.runtime_id(), &runtime_id);
        assert_eq!(stored.tenant_id().as_str(), "tenant-a");
        assert_eq!(stored.source_id(), "github");
        assert_eq!(stored.cursor(), Some("next"));
        assert_eq!(
            stored.config().get("token").map(String::as_str),
            Some("env:CEREBRO_SOURCE_GITHUB_TOKEN")
        );

        assert!(
            decode_stored_source_runtime(
                &runtime_id,
                serde_json::json!({
                    "id": "runtime-b",
                    "source_id": "github",
                    "tenant_id": "tenant-a"
                }),
            )
            .is_err()
        );

        let checkpoint_only = decode_stored_source_runtime(
            &runtime_id,
            serde_json::json!({
                "id": "runtime-a",
                "source_id": "github",
                "tenant_id": "tenant-a",
                "checkpoint": {
                    "cursor_opaque": "{\"token\":\"page:2\",\"resumable_checkpoint\":true}"
                }
            }),
        )
        .unwrap();
        assert_eq!(
            checkpoint_only.cursor(),
            Some("{\"token\":\"page:2\",\"resumable_checkpoint\":true}")
        );

        let non_resumable = decode_stored_source_runtime(
            &runtime_id,
            serde_json::json!({
                "id": "runtime-a",
                "source_id": "github",
                "tenant_id": "tenant-a",
                "checkpoint": {"cursor_opaque": "{\"token\":\"page:2\"}"}
            }),
        )
        .unwrap();
        assert_eq!(non_resumable.cursor(), None);
    }

    #[test]
    fn source_collection_manifest_lookup_requires_exact_provenance_tuple() {
        for required in [
            "tenant_id = $1",
            "source_runtime_id = $2",
            "collection_id = $3",
        ] {
            assert!(
                SOURCE_COLLECTION_MANIFEST_QUERY.contains(required),
                "source collection lookup omitted {required}"
            );
        }
    }

    #[test]
    fn source_event_receipts_remain_fail_closed_on_conflicting_records() {
        assert!(RECORD_SOURCE_EVENT_QUERY.contains("ON CONFLICT (tenant_id, event_id)"));
        assert!(RECORD_SOURCE_EVENT_QUERY.contains(
            "WHERE organizational_source_event_receipts.record_digest = EXCLUDED.record_digest"
        ));
        assert!(RECORD_SOURCE_EVENT_QUERY.contains("RETURNING record_digest"));
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
