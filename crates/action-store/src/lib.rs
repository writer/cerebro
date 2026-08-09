#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Authoritative, tenant-scoped persistence for Action operations.
//!
//! The ledger stores the current validated operation and an append-only copy
//! of every committed version. State transitions remain owned by
//! `cerebro-platform-engine`; this crate makes them atomic and durable.

use std::{error::Error, fmt};

use cerebro_action_catalog::{ActionCatalogError, lookup, validate_proposal};
use cerebro_platform_engine::{ActionCommand, transition_action};
use cerebro_platform_sdk::{
    ActionOperation, ActionOperationId, ActionProposal, ActionState, ActorId, ContentDigest,
    FindingValidationReceipt, GraphRevision, SdkError, TenantId, VerificationState,
};
use cerebro_policy_catalog::{PolicyCatalogError, validate_finding_receipt};
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_postgres::{Client, Row, Transaction};

/// PostgreSQL schema for tenant-isolated current operations, immutable event
/// history, provider dispatches, and reconciliation leases.
pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS finding_validation_receipts (
  tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  receipt_digest TEXT NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
  finding_id TEXT NOT NULL CHECK (char_length(finding_id) BETWEEN 1 AND 256),
  finding_revision_digest TEXT NOT NULL CHECK (finding_revision_digest ~ '^[0-9a-f]{64}$'),
  graph_revision BIGINT NOT NULL CHECK (graph_revision > 0),
  policy_id TEXT,
  policy_definition_digest TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('confirmed', 'rejected')),
  validated_by TEXT NOT NULL CHECK (char_length(validated_by) BETWEEN 1 AND 256),
  receipt_json JSONB NOT NULL CHECK (jsonb_typeof(receipt_json) = 'object'),
  validated_at_unix_ms BIGINT NOT NULL CHECK (validated_at_unix_ms > 0),
  expires_at_unix_ms BIGINT NOT NULL CHECK (expires_at_unix_ms > validated_at_unix_ms),
  committed_at_unix_ms BIGINT NOT NULL CHECK (
    committed_at_unix_ms >= validated_at_unix_ms
    AND committed_at_unix_ms < expires_at_unix_ms
  ),
  PRIMARY KEY (tenant_id, receipt_digest),
  CHECK ((receipt_json->>'tenant_id') IS NOT DISTINCT FROM tenant_id),
  CHECK ((receipt_json->>'receipt_digest') IS NOT DISTINCT FROM receipt_digest),
  CHECK ((receipt_json->>'finding_id') IS NOT DISTINCT FROM finding_id),
  CHECK ((receipt_json->>'finding_revision_digest') IS NOT DISTINCT FROM finding_revision_digest),
  CHECK ((receipt_json->>'graph_revision')::BIGINT IS NOT DISTINCT FROM graph_revision),
  CHECK (policy_id IS NULL OR (receipt_json->>'policy_id') IS NOT DISTINCT FROM policy_id),
  CHECK (policy_definition_digest IS NULL OR (receipt_json->>'policy_definition_digest') IS NOT DISTINCT FROM policy_definition_digest),
  CHECK ((receipt_json->>'decision') IS NOT DISTINCT FROM decision),
  CHECK ((receipt_json->>'validated_by') IS NOT DISTINCT FROM validated_by),
  CHECK ((receipt_json->>'validated_at_unix_ms')::BIGINT IS NOT DISTINCT FROM validated_at_unix_ms),
  CHECK ((receipt_json->>'expires_at_unix_ms')::BIGINT IS NOT DISTINCT FROM expires_at_unix_ms)
);
ALTER TABLE finding_validation_receipts
  ADD COLUMN IF NOT EXISTS policy_id TEXT;
ALTER TABLE finding_validation_receipts
  ADD COLUMN IF NOT EXISTS policy_definition_digest TEXT;
DO $$
BEGIN
  ALTER TABLE finding_validation_receipts
    ADD CONSTRAINT finding_validation_receipts_policy_binding
    CHECK (
      policy_id IS NOT NULL
      AND char_length(policy_id) BETWEEN 1 AND 255
      AND policy_definition_digest ~ '^[0-9a-f]{64}$'
      AND (receipt_json->>'policy_id') IS NOT DISTINCT FROM policy_id
      AND (receipt_json->>'policy_definition_digest')
        IS NOT DISTINCT FROM policy_definition_digest
    ) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS action_operations (
  tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  operation_id TEXT NOT NULL CHECK (char_length(operation_id) BETWEEN 1 AND 256),
  idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 256),
  proposal_digest TEXT NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
  finding_validation_receipt_digest TEXT,
  state TEXT NOT NULL CHECK (state IN (
    'proposed',
    'simulated',
    'waiting_for_approval',
    'approved',
    'claimed',
    'executing',
    'dispatched',
    'outcome_unknown',
    'completed',
    'reconciled',
    'verified',
    'failed',
    'rolled_back'
  )),
  version BIGINT NOT NULL CHECK (version > 0),
  operation_json JSONB NOT NULL CHECK (jsonb_typeof(operation_json) = 'object'),
  created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms > 0),
  updated_at_unix_ms BIGINT NOT NULL CHECK (updated_at_unix_ms >= created_at_unix_ms),
  PRIMARY KEY (tenant_id, operation_id),
  UNIQUE (tenant_id, idempotency_key),
  CHECK ((operation_json->'proposal'->>'tenant_id') IS NOT DISTINCT FROM tenant_id),
  CHECK ((operation_json->'proposal'->>'operation_id') IS NOT DISTINCT FROM operation_id),
  CHECK ((operation_json->'proposal'->>'idempotency_key') IS NOT DISTINCT FROM idempotency_key),
  CHECK ((operation_json->'proposal'->>'proposal_digest') IS NOT DISTINCT FROM proposal_digest),
  CHECK ((operation_json->>'version')::BIGINT IS NOT DISTINCT FROM version),
  CHECK ((operation_json->>'state') IS NOT DISTINCT FROM state)
);
ALTER TABLE action_operations
  ADD COLUMN IF NOT EXISTS finding_validation_receipt_digest TEXT;
ALTER TABLE action_operations
  DROP CONSTRAINT IF EXISTS action_operations_state_check;
DO $$
BEGIN
  ALTER TABLE action_operations
    ADD CONSTRAINT action_operations_state_values
    CHECK (state IN (
      'proposed',
      'simulated',
      'waiting_for_approval',
      'approved',
      'claimed',
      'executing',
      'dispatched',
      'outcome_unknown',
      'completed',
      'reconciled',
      'verified',
      'failed',
      'rolled_back'
    )) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
ALTER TABLE action_operations
  VALIDATE CONSTRAINT action_operations_state_values;
DO $$
BEGIN
  ALTER TABLE action_operations
    ADD CONSTRAINT action_operations_finding_validation_digest_format
    CHECK (
      finding_validation_receipt_digest IS NULL
      OR finding_validation_receipt_digest ~ '^[0-9a-f]{64}$'
    ) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
  ALTER TABLE action_operations
    ADD CONSTRAINT action_operations_finding_validation_json
    CHECK (
      finding_validation_receipt_digest IS NULL
      OR (operation_json->'proposal'->>'finding_validation_receipt_digest')
        IS NOT DISTINCT FROM finding_validation_receipt_digest
    ) NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
  ALTER TABLE action_operations
    ADD CONSTRAINT action_operations_finding_validation_receipt_fk
    FOREIGN KEY (tenant_id, finding_validation_receipt_digest)
    REFERENCES finding_validation_receipts (tenant_id, receipt_digest)
    NOT VALID;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE TABLE IF NOT EXISTS action_operation_events (
  tenant_id TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  version BIGINT NOT NULL CHECK (version > 0),
  actor_id TEXT NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 256),
  event_kind TEXT NOT NULL CHECK (char_length(event_kind) BETWEEN 1 AND 64),
  command_digest TEXT CHECK (command_digest IS NULL OR command_digest ~ '^[0-9a-f]{64}$'),
  operation_digest TEXT NOT NULL CHECK (operation_digest ~ '^[0-9a-f]{64}$'),
  command_json JSONB CHECK (command_json IS NULL OR jsonb_typeof(command_json) = 'object'),
  operation_json JSONB NOT NULL CHECK (jsonb_typeof(operation_json) = 'object'),
  committed_at_unix_ms BIGINT NOT NULL CHECK (committed_at_unix_ms > 0),
  PRIMARY KEY (tenant_id, operation_id, version),
  FOREIGN KEY (tenant_id, operation_id)
    REFERENCES action_operations (tenant_id, operation_id)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK ((version = 1 AND event_kind = 'proposed' AND command_digest IS NULL AND command_json IS NULL)
    OR (version > 1 AND event_kind <> 'proposed' AND command_digest IS NOT NULL AND command_json IS NOT NULL)),
  CHECK ((operation_json->'proposal'->>'tenant_id') IS NOT DISTINCT FROM tenant_id),
  CHECK ((operation_json->'proposal'->>'operation_id') IS NOT DISTINCT FROM operation_id),
  CHECK ((operation_json->>'version')::BIGINT IS NOT DISTINCT FROM version)
);
CREATE TABLE IF NOT EXISTS action_dispatches (
  tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  operation_id TEXT NOT NULL CHECK (char_length(operation_id) BETWEEN 1 AND 256),
  operation_version BIGINT NOT NULL CHECK (operation_version > 1),
  proposal_digest TEXT NOT NULL CHECK (proposal_digest ~ '^[0-9a-f]{64}$'),
  finding_id TEXT NOT NULL CHECK (char_length(finding_id) BETWEEN 1 AND 256),
  finding_revision_digest TEXT NOT NULL CHECK (finding_revision_digest ~ '^[0-9a-f]{64}$'),
  finding_validation_receipt_digest TEXT NOT NULL CHECK (finding_validation_receipt_digest ~ '^[0-9a-f]{64}$'),
  graph_revision BIGINT NOT NULL CHECK (graph_revision > 0),
  action_definition_digest TEXT NOT NULL CHECK (action_definition_digest ~ '^[0-9a-f]{64}$'),
  dispatch_digest TEXT NOT NULL CHECK (dispatch_digest ~ '^[0-9a-f]{64}$'),
  provider TEXT NOT NULL CHECK (char_length(provider) BETWEEN 1 AND 128),
  provider_action TEXT NOT NULL CHECK (char_length(provider_action) BETWEEN 1 AND 128),
  target_id TEXT NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 256),
  idempotency_key TEXT NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 256),
  requested_by TEXT NOT NULL CHECK (char_length(requested_by) BETWEEN 1 AND 256),
  dispatch_json JSONB NOT NULL CHECK (jsonb_typeof(dispatch_json) = 'object'),
  requested_at_unix_ms BIGINT NOT NULL CHECK (requested_at_unix_ms > 0),
  PRIMARY KEY (tenant_id, operation_id),
  UNIQUE (tenant_id, dispatch_digest),
  FOREIGN KEY (tenant_id, operation_id)
    REFERENCES action_operations (tenant_id, operation_id)
    DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY (tenant_id, operation_id, operation_version)
    REFERENCES action_operation_events (tenant_id, operation_id, version)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK ((dispatch_json->>'tenant_id') IS NOT DISTINCT FROM tenant_id),
  CHECK ((dispatch_json->>'operation_id') IS NOT DISTINCT FROM operation_id),
  CHECK ((dispatch_json->>'operation_version')::BIGINT IS NOT DISTINCT FROM operation_version),
  CHECK ((dispatch_json->>'proposal_digest') IS NOT DISTINCT FROM proposal_digest),
  CHECK ((dispatch_json->>'finding_id') IS NOT DISTINCT FROM finding_id),
  CHECK ((dispatch_json->>'finding_revision_digest') IS NOT DISTINCT FROM finding_revision_digest),
  CHECK ((dispatch_json->>'finding_validation_receipt_digest') IS NOT DISTINCT FROM finding_validation_receipt_digest),
  CHECK ((dispatch_json->>'graph_revision')::BIGINT IS NOT DISTINCT FROM graph_revision),
  CHECK ((dispatch_json->>'action_definition_digest') IS NOT DISTINCT FROM action_definition_digest),
  CHECK ((dispatch_json->>'dispatch_digest') IS NOT DISTINCT FROM dispatch_digest),
  CHECK ((dispatch_json->>'provider') IS NOT DISTINCT FROM provider),
  CHECK ((dispatch_json->>'provider_action') IS NOT DISTINCT FROM provider_action),
  CHECK ((dispatch_json->>'target_id') IS NOT DISTINCT FROM target_id),
  CHECK ((dispatch_json->>'idempotency_key') IS NOT DISTINCT FROM idempotency_key),
  CHECK ((dispatch_json->>'requested_by') IS NOT DISTINCT FROM requested_by),
  CHECK ((dispatch_json->>'requested_at_unix_ms')::BIGINT IS NOT DISTINCT FROM requested_at_unix_ms)
);
CREATE TABLE IF NOT EXISTS action_reconciliation_jobs (
  tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  operation_id TEXT NOT NULL CHECK (char_length(operation_id) BETWEEN 1 AND 256),
  dispatch_digest TEXT NOT NULL CHECK (dispatch_digest ~ '^[0-9a-f]{64}$'),
  state TEXT NOT NULL CHECK (state IN ('scheduled', 'leased', 'terminal')),
  next_attempt_at_unix_ms BIGINT,
  attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  lease_owner TEXT CHECK (lease_owner IS NULL OR char_length(lease_owner) BETWEEN 1 AND 256),
  lease_expires_at_unix_ms BIGINT,
  terminal_provider_status TEXT CHECK (
    terminal_provider_status IS NULL
    OR char_length(terminal_provider_status) BETWEEN 1 AND 64
  ),
  updated_at_unix_ms BIGINT NOT NULL CHECK (updated_at_unix_ms > 0),
  PRIMARY KEY (tenant_id, operation_id),
  FOREIGN KEY (tenant_id, operation_id)
    REFERENCES action_dispatches (tenant_id, operation_id)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK (
    (state = 'scheduled'
      AND next_attempt_at_unix_ms IS NOT NULL
      AND lease_owner IS NULL
      AND lease_expires_at_unix_ms IS NULL
      AND terminal_provider_status IS NULL)
    OR
    (state = 'leased'
      AND next_attempt_at_unix_ms IS NOT NULL
      AND lease_owner IS NOT NULL
      AND lease_expires_at_unix_ms IS NOT NULL
      AND terminal_provider_status IS NULL)
    OR
    (state = 'terminal'
      AND next_attempt_at_unix_ms IS NULL
      AND lease_owner IS NULL
      AND lease_expires_at_unix_ms IS NULL
      AND terminal_provider_status IS NOT NULL)
  )
);
CREATE INDEX IF NOT EXISTS action_operation_events_committed_idx
  ON action_operation_events (tenant_id, committed_at_unix_ms DESC);
CREATE INDEX IF NOT EXISTS action_operations_queue_idx
  ON action_operations (tenant_id, updated_at_unix_ms DESC, operation_id);
CREATE INDEX IF NOT EXISTS action_operations_dispatch_queue_idx
  ON action_operations (tenant_id, state, updated_at_unix_ms, operation_id);
CREATE INDEX IF NOT EXISTS action_dispatches_requested_idx
  ON action_dispatches (tenant_id, requested_at_unix_ms, operation_id);
CREATE INDEX IF NOT EXISTS action_dispatches_finding_idx
  ON action_dispatches (tenant_id, finding_id, requested_at_unix_ms, operation_id);
CREATE INDEX IF NOT EXISTS action_reconciliation_jobs_due_idx
  ON action_reconciliation_jobs (
    tenant_id,
    state,
    next_attempt_at_unix_ms,
    operation_id
  );
CREATE INDEX IF NOT EXISTS finding_validation_receipts_finding_idx
  ON finding_validation_receipts (tenant_id, finding_id, validated_at_unix_ms DESC);
CREATE INDEX IF NOT EXISTS finding_validation_receipts_policy_idx
  ON finding_validation_receipts (tenant_id, policy_id, validated_at_unix_ms DESC);
CREATE OR REPLACE FUNCTION reject_finding_validation_receipt_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Finding validation receipts are append-only';
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
  CREATE TRIGGER finding_validation_receipts_append_only
    BEFORE UPDATE OR DELETE ON finding_validation_receipts
    FOR EACH ROW EXECUTE FUNCTION reject_finding_validation_receipt_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE OR REPLACE FUNCTION reject_action_operation_event_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Action operation events are append-only';
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
  CREATE TRIGGER action_operation_events_append_only
    BEFORE UPDATE OR DELETE ON action_operation_events
    FOR EACH ROW EXECUTE FUNCTION reject_action_operation_event_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE OR REPLACE FUNCTION reject_action_dispatch_mutation()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'Action dispatches are append-only';
END;
$$ LANGUAGE plpgsql;
DO $$
BEGIN
  CREATE TRIGGER action_dispatches_append_only
    BEFORE UPDATE OR DELETE ON action_dispatches
    FOR EACH ROW EXECUTE FUNCTION reject_action_dispatch_mutation();
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
ALTER TABLE finding_validation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_validation_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE action_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE action_operation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_operation_events FORCE ROW LEVEL SECURITY;
ALTER TABLE action_dispatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_dispatches FORCE ROW LEVEL SECURITY;
ALTER TABLE action_reconciliation_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_reconciliation_jobs FORCE ROW LEVEL SECURITY;
DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'finding_validation_receipts',
    'action_operations',
    'action_operation_events',
    'action_dispatches',
    'action_reconciliation_jobs'
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

#[derive(Debug)]
/// Durable action-ledger failures.
pub enum ActionStoreError {
    /// PostgreSQL rejected or could not complete an operation.
    Postgres(tokio_postgres::Error),
    /// A durable record could not be encoded or decoded.
    Serialization(serde_json::Error),
    /// A platform SDK value failed validation.
    Invalid(SdkError),
    /// A proposal violated the closed action catalog.
    Catalog(ActionCatalogError),
    /// A finding validation receipt violated the policy catalog.
    PolicyCatalog(PolicyCatalogError),
    /// Current state, optimistic version, authority time, or identity conflicts.
    Conflict(String),
    /// The requested tenant-scoped record does not exist.
    NotFound(String),
    /// Stored content, history, or a cross-record binding failed validation.
    Corrupt(String),
    /// A pagination cursor could not be decoded or validated.
    InvalidPageToken,
    /// A numeric request cannot be represented within the storage contract.
    OutOfRange(&'static str),
}

impl fmt::Display for ActionStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(error) => write!(formatter, "Action ledger failed: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "Action ledger serialization failed: {error}")
            }
            Self::Invalid(error) => write!(formatter, "Action is invalid: {error}"),
            Self::Catalog(error) => write!(formatter, "Action definition is invalid: {error}"),
            Self::PolicyCatalog(error) => {
                write!(formatter, "Policy definition is invalid: {error}")
            }
            Self::Conflict(message) => write!(formatter, "Action ledger conflict: {message}"),
            Self::NotFound(message) => write!(formatter, "Action was not found: {message}"),
            Self::Corrupt(message) => {
                write!(formatter, "Action ledger record is corrupt: {message}")
            }
            Self::InvalidPageToken => write!(formatter, "Action page token is invalid"),
            Self::OutOfRange(field) => write!(formatter, "{field} is outside its storage range"),
        }
    }
}

impl Error for ActionStoreError {}

impl From<tokio_postgres::Error> for ActionStoreError {
    fn from(value: tokio_postgres::Error) -> Self {
        Self::Postgres(value)
    }
}

impl From<serde_json::Error> for ActionStoreError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value)
    }
}

impl From<SdkError> for ActionStoreError {
    fn from(value: SdkError) -> Self {
        match value {
            SdkError::Conflict(message) => Self::Conflict(message),
            other => Self::Invalid(other),
        }
    }
}

impl From<ActionCatalogError> for ActionStoreError {
    fn from(value: ActionCatalogError) -> Self {
        match value {
            ActionCatalogError::InvalidProposal(SdkError::Conflict(message)) => {
                Self::Conflict(message)
            }
            ActionCatalogError::InvalidProposal(error) => Self::Invalid(error),
            other => Self::Catalog(other),
        }
    }
}

impl From<PolicyCatalogError> for ActionStoreError {
    fn from(value: PolicyCatalogError) -> Self {
        Self::PolicyCatalog(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// One immutable version in an action operation's append-only history.
pub struct ActionEvent {
    /// Authenticated actor responsible for the version transition.
    pub actor_id: ActorId,
    /// Stable command name, or `proposed` for the initial version.
    pub event_kind: String,
    /// Digest of the transition command, absent for the initial proposal.
    pub command_digest: Option<ContentDigest>,
    /// Digest of the complete resulting operation state.
    pub operation_digest: ContentDigest,
    /// Authority commit time in Unix milliseconds.
    pub committed_at_unix_ms: u64,
    /// Validated operation snapshot at this version.
    pub operation: ActionOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Stable page of current action operations.
pub struct ActionPage {
    /// Operations in descending update-time and ascending operation-ID order.
    pub actions: Vec<ActionOperation>,
    /// Opaque continuation token for the next page, when more records exist.
    pub next_page_token: Option<String>,
}

const ACTION_DISPATCH_DIGEST_SCHEMA: &str = "cerebro.action-dispatch.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Immutable provider request derived from a start-execution transition.
///
/// Every authority and routing field is copied from the validated proposal and
/// closed catalog definition. Providers receive this record rather than raw
/// caller input so a later adapter cannot widen the authorized target or effect.
pub struct ActionDispatch {
    /// Tenant authority inherited from the proposal.
    pub tenant_id: String,
    /// Durable operation identifier.
    pub operation_id: String,
    /// Operation version that created this dispatch.
    pub operation_version: u64,
    /// Digest of the admitted proposal.
    pub proposal_digest: String,
    /// Finding that authorized the operation.
    pub finding_id: String,
    /// Exact finding revision considered during authorization.
    pub finding_revision_digest: String,
    /// Committed validation receipt used to admit the proposal.
    pub finding_validation_receipt_digest: String,
    /// Graph revision against which authorization was evaluated.
    pub graph_revision: u64,
    /// Catalog action kind.
    pub action_kind: String,
    /// Exact catalog definition digest bound by the proposal.
    pub action_definition_digest: String,
    /// Registered provider adapter.
    pub provider: String,
    /// Provider-native mutation name.
    pub provider_action: String,
    /// Registered target identifier kind.
    pub target_kind: String,
    /// Finding-authorized provider target.
    pub target_id: String,
    /// Expected effect kind.
    pub effect: String,
    /// Stable provider idempotency key.
    pub idempotency_key: String,
    /// Authenticated execution claimant.
    pub requested_by: String,
    /// Authority time at which execution began, in Unix milliseconds.
    pub requested_at_unix_ms: u64,
    /// Digest binding every preceding dispatch field.
    pub dispatch_digest: String,
}

impl ActionDispatch {
    fn from_started_operation(
        operation: &ActionOperation,
        requested_by: &ActorId,
        requested_at_unix_ms: u64,
    ) -> Result<Self, ActionStoreError> {
        if operation.state != ActionState::Executing
            || operation
                .claimed_by
                .as_ref()
                .is_none_or(|worker| worker.as_str() != requested_by.as_str())
        {
            return Err(ActionStoreError::Conflict(
                "Action dispatch requires the authenticated execution claimant".to_owned(),
            ));
        }
        let definition = validate_proposal(&operation.proposal)?;
        let mut dispatch = Self {
            tenant_id: operation.proposal.tenant_id.to_string(),
            operation_id: operation.proposal.operation_id.to_string(),
            operation_version: operation.version,
            proposal_digest: operation.proposal.proposal_digest.to_string(),
            finding_id: operation.proposal.finding_id.to_string(),
            finding_revision_digest: operation.proposal.finding_revision_digest.to_string(),
            finding_validation_receipt_digest: operation
                .proposal
                .finding_validation_receipt_digest
                .to_string(),
            graph_revision: operation.proposal.graph_revision.get(),
            action_kind: definition.id.to_owned(),
            action_definition_digest: operation.proposal.action_definition_digest.to_string(),
            provider: definition.provider.to_owned(),
            provider_action: definition.provider_action.to_owned(),
            target_kind: definition.target_kind.to_owned(),
            target_id: operation.proposal.target_id.to_string(),
            effect: definition.effect.to_owned(),
            idempotency_key: operation.proposal.idempotency_key.to_string(),
            requested_by: requested_by.to_string(),
            requested_at_unix_ms,
            dispatch_digest: ContentDigest::of_bytes("unbound Action dispatch").to_string(),
        };
        dispatch.dispatch_digest = dispatch.computed_digest()?.to_string();
        dispatch.validate()?;
        Ok(dispatch)
    }

    /// Recomputes the content digest that seals every routing and authority field.
    pub fn computed_digest(&self) -> Result<ContentDigest, ActionStoreError> {
        #[derive(Serialize)]
        struct DigestMaterial<'a> {
            schema: &'static str,
            tenant_id: &'a str,
            operation_id: &'a str,
            operation_version: u64,
            proposal_digest: &'a str,
            finding_id: &'a str,
            finding_revision_digest: &'a str,
            finding_validation_receipt_digest: &'a str,
            graph_revision: u64,
            action_kind: &'a str,
            action_definition_digest: &'a str,
            provider: &'a str,
            provider_action: &'a str,
            target_kind: &'a str,
            target_id: &'a str,
            effect: &'a str,
            idempotency_key: &'a str,
            requested_by: &'a str,
            requested_at_unix_ms: u64,
        }

        let material = DigestMaterial {
            schema: ACTION_DISPATCH_DIGEST_SCHEMA,
            tenant_id: &self.tenant_id,
            operation_id: &self.operation_id,
            operation_version: self.operation_version,
            proposal_digest: &self.proposal_digest,
            finding_id: &self.finding_id,
            finding_revision_digest: &self.finding_revision_digest,
            finding_validation_receipt_digest: &self.finding_validation_receipt_digest,
            graph_revision: self.graph_revision,
            action_kind: &self.action_kind,
            action_definition_digest: &self.action_definition_digest,
            provider: &self.provider,
            provider_action: &self.provider_action,
            target_kind: &self.target_kind,
            target_id: &self.target_id,
            effect: &self.effect,
            idempotency_key: &self.idempotency_key,
            requested_by: &self.requested_by,
            requested_at_unix_ms: self.requested_at_unix_ms,
        };
        Ok(ContentDigest::of_bytes(serde_json::to_vec(&material)?))
    }

    /// Validates field shapes, the closed catalog binding, and the content digest.
    pub fn validate(&self) -> Result<(), ActionStoreError> {
        if self.operation_version <= 1
            || self.requested_at_unix_ms == 0
            || TenantId::parse(self.tenant_id.clone()).is_err()
            || ActionOperationId::parse(self.operation_id.clone()).is_err()
            || ContentDigest::parse(self.proposal_digest.clone()).is_err()
            || cerebro_platform_sdk::OpaqueId::parse(self.finding_id.clone()).is_err()
            || ContentDigest::parse(self.finding_revision_digest.clone()).is_err()
            || ContentDigest::parse(self.finding_validation_receipt_digest.clone()).is_err()
            || GraphRevision::new(self.graph_revision).is_err()
            || ContentDigest::parse(self.action_definition_digest.clone()).is_err()
            || ContentDigest::parse(self.dispatch_digest.clone()).is_err()
            || cerebro_platform_sdk::OpaqueId::parse(self.target_id.clone()).is_err()
            || cerebro_platform_sdk::OpaqueId::parse(self.idempotency_key.clone()).is_err()
            || ActorId::parse(self.requested_by.clone()).is_err()
        {
            return Err(ActionStoreError::Corrupt(
                "Action dispatch version or request time is invalid".to_owned(),
            ));
        }
        let definition = lookup(&self.action_kind)?;
        if self.action_definition_digest != definition.definition_digest
            || self.provider != definition.provider
            || self.provider_action != definition.provider_action
            || self.target_kind != definition.target_kind
            || self.effect != definition.effect
        {
            return Err(ActionStoreError::Corrupt(
                "Action dispatch does not match its closed definition".to_owned(),
            ));
        }
        if self.dispatch_digest != self.computed_digest()?.as_str() {
            return Err(ActionStoreError::Corrupt(
                "Action dispatch digest does not match its content".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_against_operation(
        &self,
        operation: &ActionOperation,
    ) -> Result<(), ActionStoreError> {
        if operation.state != ActionState::Executing
            || operation.version != self.operation_version
            || operation.proposal.tenant_id.as_str() != self.tenant_id
            || operation.proposal.operation_id.as_str() != self.operation_id
            || operation.proposal.proposal_digest.as_str() != self.proposal_digest
            || operation.proposal.finding_id.as_str() != self.finding_id
            || operation.proposal.finding_revision_digest.as_str() != self.finding_revision_digest
            || operation
                .proposal
                .finding_validation_receipt_digest
                .as_str()
                != self.finding_validation_receipt_digest
            || operation.proposal.graph_revision.get() != self.graph_revision
            || operation.proposal.action_kind != self.action_kind
            || operation.proposal.action_definition_digest.as_str() != self.action_definition_digest
            || operation.proposal.target_id.as_str() != self.target_id
            || operation.proposal.idempotency_key.as_str() != self.idempotency_key
            || operation
                .claimed_by
                .as_ref()
                .is_none_or(|worker| worker.as_str() != self.requested_by)
        {
            return Err(ActionStoreError::Corrupt(
                "Action dispatch does not match its start-execution event".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Bounded set of provider dispatches that still require work.
pub struct ActionDispatchPage {
    /// Validated dispatch records.
    pub dispatches: Vec<ActionDispatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// One exclusively leased provider-reconciliation unit.
pub struct ActionReconciliationJob {
    /// Current durable operation state.
    pub operation: ActionOperation,
    /// Immutable dispatch whose receipt must be observed.
    pub dispatch: ActionDispatch,
    /// Number of times this job has been leased, including the current lease.
    pub attempt_count: u64,
    /// Exclusive lease deadline in Unix milliseconds.
    pub lease_expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Scheduler decision recorded after one reconciliation attempt.
pub enum ActionReconciliationDisposition {
    /// Release the lease and make the job eligible at a future authority time.
    PollAgain {
        /// Earliest next claim time in Unix milliseconds.
        next_attempt_at_unix_ms: u64,
    },
    /// Stop polling because the provider reached a terminal status.
    Terminal {
        /// Normalized provider status already recorded on the operation.
        provider_status: String,
    },
}

const MAX_RECONCILIATION_LEASE_MS: u64 = 5 * 60 * 1_000;

/// PostgreSQL authority for validated action state, history, and reconciliation.
///
/// Every public operation opens a tenant-scoped transaction. Mutations lock the
/// current operation, apply optimistic-version and authority-time checks, append
/// immutable history, and update current state in the same commit.
pub struct PostgresActionLedger {
    client: Mutex<Client>,
}

struct CurrentAction {
    operation: ActionOperation,
    updated_at_unix_ms: u64,
}

impl PostgresActionLedger {
    /// Connection credentials and TLS policy are constructed by the platform.
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Mutex::new(client),
        }
    }

    /// Connects with native TLS and starts the PostgreSQL connection driver.
    pub async fn connect_tls(connection_string: &str) -> Result<Self, ActionStoreError> {
        let tls = native_tls::TlsConnector::builder()
            .build()
            .map_err(|error| {
                ActionStoreError::Conflict(format!("build PostgreSQL TLS: {error}"))
            })?;
        let (client, connection) =
            tokio_postgres::connect(connection_string, MakeTlsConnector::new(tls)).await?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("Action PostgreSQL connection closed: {error}");
            }
        });
        Ok(Self::from_client(client))
    }

    /// Applies the idempotent action-ledger schema and tenant-isolation policies.
    pub async fn migrate(&self) -> Result<(), ActionStoreError> {
        self.client
            .lock()
            .await
            .batch_execute(POSTGRES_SCHEMA)
            .await?;
        Ok(())
    }

    /// Verifies that the configured PostgreSQL connection can execute a query.
    pub async fn health(&self) -> Result<(), ActionStoreError> {
        self.client.lock().await.simple_query("SELECT 1").await?;
        Ok(())
    }

    /// Commits an immutable finding-validation receipt while it is current at
    /// authority commit time. A reused digest must contain identical content.
    pub async fn record_finding_validation(
        &self,
        receipt: FindingValidationReceipt,
        committed_at_unix_ms: u64,
    ) -> Result<FindingValidationReceipt, ActionStoreError> {
        validate_finding_receipt(&receipt)?;
        if committed_at_unix_ms < receipt.validated_at_unix_ms
            || committed_at_unix_ms >= receipt.expires_at_unix_ms
        {
            return Err(ActionStoreError::Conflict(
                "Finding validation receipt is not current at authority commit time".to_owned(),
            ));
        }
        let graph_revision = storage_i64(receipt.graph_revision.get(), "Finding graph revision")?;
        let validated_at = storage_i64(receipt.validated_at_unix_ms, "Finding validation time")?;
        let expires_at = storage_i64(receipt.expires_at_unix_ms, "Finding validation expiry")?;
        let committed_at = storage_i64(committed_at_unix_ms, "Finding validation commit time")?;
        let receipt_json = serde_json::to_value(&receipt)?;
        let tenant_id = receipt.tenant_id.as_str();
        let receipt_digest = receipt.receipt_digest.as_str();

        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let inserted = transaction
            .execute(
                "INSERT INTO finding_validation_receipts (tenant_id, receipt_digest, finding_id, finding_revision_digest, graph_revision, policy_id, policy_definition_digest, decision, validated_by, receipt_json, validated_at_unix_ms, expires_at_unix_ms, committed_at_unix_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT DO NOTHING",
                &[
                    &tenant_id,
                    &receipt_digest,
                    &receipt.finding_id.as_str(),
                    &receipt.finding_revision_digest.as_str(),
                    &graph_revision,
                    &receipt.policy_id,
                    &receipt.policy_definition_digest.as_str(),
                    &finding_validation_decision(&receipt),
                    &receipt.validated_by.as_str(),
                    &receipt_json,
                    &validated_at,
                    &expires_at,
                    &committed_at,
                ],
            )
            .await?;
        let stored = select_finding_validation(&transaction, tenant_id, receipt_digest)
            .await?
            .ok_or_else(|| {
                ActionStoreError::Conflict(
                    "Finding validation receipt was not committed".to_owned(),
                )
            })?;
        if inserted == 0 && stored != receipt {
            return Err(ActionStoreError::Conflict(
                "Finding validation receipt digest already stores different content".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(stored)
    }

    /// Reads one tenant-scoped finding-validation receipt by content digest.
    pub async fn get_finding_validation(
        &self,
        tenant_id: &TenantId,
        receipt_digest: &ContentDigest,
    ) -> Result<FindingValidationReceipt, ActionStoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let receipt =
            select_finding_validation(&transaction, tenant_id.as_str(), receipt_digest.as_str())
                .await?
                .ok_or_else(|| ActionStoreError::NotFound(receipt_digest.to_string()))?;
        transaction.commit().await?;
        Ok(receipt)
    }

    /// Admits a catalog-bound action proposal as version one.
    ///
    /// The referenced finding-validation receipt must already be committed,
    /// match the proposal, and remain valid at `committed_at_unix_ms`.
    pub async fn propose(
        &self,
        proposal: ActionProposal,
        committed_at_unix_ms: u64,
    ) -> Result<ActionOperation, ActionStoreError> {
        validate_proposal(&proposal)?;
        if !proposal_valid_at(
            proposal.proposed_at_unix_ms,
            proposal.proposal_expires_at_unix_ms,
            committed_at_unix_ms,
        ) {
            return Err(ActionStoreError::Conflict(
                "Action proposal is not valid at the authority commit time".to_owned(),
            ));
        }
        let committed_at = storage_i64(committed_at_unix_ms, "Action commit time")?;
        let operation = ActionOperation {
            proposal,
            state: ActionState::Proposed,
            version: 1,
            approval_receipt: None,
            claimed_by: None,
            claimed_at_unix_ms: None,
            claim_expires_at_unix_ms: None,
            executor_actor_id: None,
            provider_receipt_digest: None,
            provider_status: None,
            provider_observed_at_unix_ms: None,
            executed_at_unix_ms: None,
            external_receipt_ref: None,
            observed_effect_digest: None,
            verification_state: VerificationState::Pending,
            verification_receipt: None,
        };
        operation.validate()?;
        let operation_json = serde_json::to_value(&operation)?;
        let operation_digest = digest_json(&operation_json)?;
        let tenant_id = operation.proposal.tenant_id.as_str();
        let operation_id = operation.proposal.operation_id.as_str();
        let idempotency_key = operation.proposal.idempotency_key.as_str();
        let proposal_digest = operation.proposal.proposal_digest.as_str();

        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id).await?;
        let validation = select_finding_validation(
            &transaction,
            tenant_id,
            operation
                .proposal
                .finding_validation_receipt_digest
                .as_str(),
        )
        .await?
        .ok_or_else(|| {
            ActionStoreError::Conflict(
                "The Action proposal has no committed finding validation receipt".to_owned(),
            )
        })?;
        validation.authorizes_action(&operation.proposal, committed_at_unix_ms)?;
        let existing =
            select_proposal_aliases(&transaction, tenant_id, operation_id, idempotency_key).await?;
        if !existing.is_empty() {
            let stored =
                exact_proposal_replay(existing, operation_id, idempotency_key, proposal_digest)?;
            transaction.commit().await?;
            return Ok(stored);
        }

        let inserted = transaction
            .query_opt(
                "INSERT INTO action_operations (tenant_id, operation_id, idempotency_key, proposal_digest, finding_validation_receipt_digest, state, version, operation_json, created_at_unix_ms, updated_at_unix_ms) VALUES ($1, $2, $3, $4, $5, 'proposed', 1, $6, $7, $7) ON CONFLICT DO NOTHING RETURNING operation_id",
                &[
                    &tenant_id,
                    &operation_id,
                    &idempotency_key,
                    &proposal_digest,
                    &operation
                        .proposal
                        .finding_validation_receipt_digest
                        .as_str(),
                    &operation_json,
                    &committed_at,
                ],
            )
            .await?;
        if inserted.is_none() {
            let existing =
                select_proposal_aliases(&transaction, tenant_id, operation_id, idempotency_key)
                    .await?;
            let stored =
                exact_proposal_replay(existing, operation_id, idempotency_key, proposal_digest)?;
            transaction.commit().await?;
            return Ok(stored);
        }
        transaction
            .execute(
                "INSERT INTO action_operation_events (tenant_id, operation_id, version, actor_id, event_kind, command_digest, operation_digest, command_json, operation_json, committed_at_unix_ms) VALUES ($1, $2, 1, $3, 'proposed', NULL, $4, NULL, $5, $6)",
                &[
                    &tenant_id,
                    &operation_id,
                    &operation.proposal.proposed_by.as_str(),
                    &operation_digest.as_str(),
                    &operation_json,
                    &committed_at,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(operation)
    }

    /// Reads and validates the current version of one action operation.
    pub async fn get(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionOperation, ActionStoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let row = transaction
            .query_opt(
                "SELECT operation_id, idempotency_key, proposal_digest, state, version, operation_json, created_at_unix_ms, updated_at_unix_ms FROM action_operations WHERE tenant_id = $1 AND operation_id = $2",
                &[&tenant_id.as_str(), &operation_id.as_str()],
            )
            .await?;
        let operation = row
            .as_ref()
            .map(validate_current_row)
            .transpose()?
            .ok_or_else(|| ActionStoreError::NotFound(operation_id.to_string()))?;
        transaction.commit().await?;
        Ok(operation.operation)
    }

    /// Lists current operations using a stable keyset cursor.
    pub async fn list(
        &self,
        tenant_id: &TenantId,
        limit: usize,
        page_token: Option<&str>,
    ) -> Result<ActionPage, ActionStoreError> {
        if !(1..=100).contains(&limit) {
            return Err(ActionStoreError::OutOfRange("Action page limit"));
        }
        let anchor = page_token.map(decode_page_token).transpose()?;
        let (anchor_updated_at, anchor_operation_id) = match anchor.as_ref() {
            Some((updated_at, operation_id)) => (
                Some(storage_i64(*updated_at, "Action page token timestamp")?),
                Some(operation_id.as_str()),
            ),
            None => (None, None),
        };
        let fetch_limit = i64::try_from(limit + 1)
            .map_err(|_| ActionStoreError::OutOfRange("Action page limit"))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let rows = transaction
            .query(
                "SELECT operation_id, idempotency_key, proposal_digest, state, version, operation_json, created_at_unix_ms, updated_at_unix_ms FROM action_operations WHERE tenant_id = $1 AND ($2::BIGINT IS NULL OR updated_at_unix_ms < $2 OR (updated_at_unix_ms = $2 AND operation_id > $3)) ORDER BY updated_at_unix_ms DESC, operation_id ASC LIMIT $4",
                &[
                    &tenant_id.as_str(),
                    &anchor_updated_at,
                    &anchor_operation_id,
                    &fetch_limit,
                ],
            )
            .await?;
        let truncated = rows.len() > limit;
        let mut current = rows
            .iter()
            .map(validate_current_row)
            .collect::<Result<Vec<_>, _>>()?;
        current.truncate(limit);
        let next_page_token = truncated.then(|| current.last()).flatten().map(|action| {
            encode_page_token(
                action.updated_at_unix_ms,
                &action.operation.proposal.operation_id,
            )
        });
        let actions = current.into_iter().map(|action| action.operation).collect();
        transaction.commit().await?;
        Ok(ActionPage {
            actions,
            next_page_token,
        })
    }

    /// Applies one authenticated, optimistic state transition atomically.
    ///
    /// Starting execution also seals the provider dispatch. Recording the first
    /// provider receipt schedules reconciliation in the same transaction.
    pub async fn transition(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
        actor_id: &ActorId,
        expected_version: u64,
        command: ActionCommand,
        committed_at_unix_ms: u64,
    ) -> Result<ActionOperation, ActionStoreError> {
        let expected_version_i64 = storage_i64(expected_version, "Action expected version")?;
        let committed_at = storage_i64(committed_at_unix_ms, "Action commit time")?;
        let schedules_provider_reconciliation =
            matches!(&command, ActionCommand::RecordProviderReceipt { .. });
        let command_json = serde_json::to_value(&command)?;
        let command_digest = digest_json(&command_json)?;
        let event_kind = command_json
            .get("command")
            .and_then(Value::as_str)
            .ok_or_else(|| ActionStoreError::Corrupt("command has no stable kind".to_owned()))?
            .to_owned();
        if command_observed_at(&command)
            .is_some_and(|observed_at| observed_at == 0 || observed_at > committed_at_unix_ms)
        {
            return Err(ActionStoreError::Conflict(
                "Action command receipt time exceeds the authority commit time".to_owned(),
            ));
        }

        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let row = transaction
            .query_opt(
                "SELECT operation_id, idempotency_key, proposal_digest, state, version, operation_json, created_at_unix_ms, updated_at_unix_ms FROM action_operations WHERE tenant_id = $1 AND operation_id = $2 FOR UPDATE",
                &[&tenant_id.as_str(), &operation_id.as_str()],
            )
            .await?;
        let current = row
            .as_ref()
            .map(validate_current_row)
            .transpose()?
            .ok_or_else(|| ActionStoreError::NotFound(operation_id.to_string()))?;
        if committed_at_unix_ms < current.updated_at_unix_ms {
            return Err(ActionStoreError::Conflict(
                "Action commit time predates the current version".to_owned(),
            ));
        }
        if !command_valid_at_authority_time(
            current.operation.proposal.proposal_expires_at_unix_ms,
            current.operation.claim_expires_at_unix_ms,
            &command,
            committed_at_unix_ms,
        ) {
            return Err(ActionStoreError::Conflict(
                "Action command is not valid at the authority commit time".to_owned(),
            ));
        }
        if !command_actor_matches(actor_id, current.operation.claimed_by.as_ref(), &command) {
            return Err(ActionStoreError::Conflict(
                "authenticated actor does not own the Action command".to_owned(),
            ));
        }
        let dispatch_requested_at = match &command {
            ActionCommand::StartExecution { started_at_unix_ms } => Some(*started_at_unix_ms),
            _ => None,
        };
        let next = transition_action(&current.operation, expected_version, command)?;
        next.validate()?;
        let dispatch = dispatch_requested_at
            .map(|requested_at| {
                ActionDispatch::from_started_operation(&next, actor_id, requested_at)
            })
            .transpose()?;
        let next_version = storage_i64(next.version, "Action operation version")?;
        let next_json = serde_json::to_value(&next)?;
        let operation_digest = digest_json(&next_json)?;
        let state = enum_name(&next.state)?;
        let updated = transaction
            .execute(
                "UPDATE action_operations SET state = $1, version = $2, operation_json = $3, updated_at_unix_ms = $4 WHERE tenant_id = $5 AND operation_id = $6 AND version = $7",
                &[
                    &state,
                    &next_version,
                    &next_json,
                    &committed_at,
                    &tenant_id.as_str(),
                    &operation_id.as_str(),
                    &expected_version_i64,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(ActionStoreError::Conflict(
                "stale Action operation version".to_owned(),
            ));
        }
        if let Some(dispatch) = dispatch.as_ref() {
            let dispatch_json = serde_json::to_value(dispatch)?;
            let graph_revision =
                storage_i64(dispatch.graph_revision, "Action dispatch graph revision")?;
            let requested_at = storage_i64(
                dispatch.requested_at_unix_ms,
                "Action dispatch request time",
            )?;
            transaction
                .execute(
                    "INSERT INTO action_dispatches (tenant_id, operation_id, operation_version, proposal_digest, finding_id, finding_revision_digest, finding_validation_receipt_digest, graph_revision, action_definition_digest, dispatch_digest, provider, provider_action, target_id, idempotency_key, requested_by, dispatch_json, requested_at_unix_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
                    &[
                        &dispatch.tenant_id.as_str(),
                        &dispatch.operation_id.as_str(),
                        &next_version,
                        &dispatch.proposal_digest.as_str(),
                        &dispatch.finding_id.as_str(),
                        &dispatch.finding_revision_digest.as_str(),
                        &dispatch.finding_validation_receipt_digest.as_str(),
                        &graph_revision,
                        &dispatch.action_definition_digest.as_str(),
                        &dispatch.dispatch_digest.as_str(),
                        &dispatch.provider,
                        &dispatch.provider_action,
                        &dispatch.target_id.as_str(),
                        &dispatch.idempotency_key.as_str(),
                        &dispatch.requested_by.as_str(),
                        &dispatch_json,
                        &requested_at,
                    ],
                )
                .await?;
        }
        transaction
            .execute(
                "INSERT INTO action_operation_events (tenant_id, operation_id, version, actor_id, event_kind, command_digest, operation_digest, command_json, operation_json, committed_at_unix_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &tenant_id.as_str(),
                    &operation_id.as_str(),
                    &next_version,
                    &actor_id.as_str(),
                    &event_kind,
                    &command_digest.as_str(),
                    &operation_digest.as_str(),
                    &command_json,
                    &next_json,
                    &committed_at,
                ],
            )
            .await?;
        if schedules_provider_reconciliation {
            let scheduled = transaction
                .execute(
                    "INSERT INTO action_reconciliation_jobs (tenant_id, operation_id, dispatch_digest, state, next_attempt_at_unix_ms, attempt_count, lease_owner, lease_expires_at_unix_ms, terminal_provider_status, updated_at_unix_ms) SELECT tenant_id, operation_id, dispatch_digest, 'scheduled', $3, 0, NULL, NULL, NULL, $3 FROM action_dispatches WHERE tenant_id = $1 AND operation_id = $2 ON CONFLICT DO NOTHING",
                    &[&tenant_id.as_str(), &operation_id.as_str(), &committed_at],
                )
                .await?;
            if scheduled != 1 {
                return Err(ActionStoreError::Conflict(
                    "Action provider reconciliation was not scheduled".to_owned(),
                ));
            }
        }
        transaction.commit().await?;
        Ok(next)
    }

    /// Reads a dispatch and revalidates it against the start-execution event.
    pub async fn get_dispatch(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<ActionDispatch, ActionStoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let dispatch = transaction
            .query_opt(
                "SELECT dispatch.dispatch_json, event.actor_id AS event_actor_id, event.event_kind, event.command_json, event.operation_json FROM action_dispatches AS dispatch INNER JOIN action_operation_events AS event ON event.tenant_id = dispatch.tenant_id AND event.operation_id = dispatch.operation_id AND event.version = dispatch.operation_version WHERE dispatch.tenant_id = $1 AND dispatch.operation_id = $2",
                &[&tenant_id.as_str(), &operation_id.as_str()],
            )
            .await?
            .as_ref()
            .map(decode_dispatch_row)
            .transpose()?
            .ok_or_else(|| ActionStoreError::NotFound(operation_id.to_string()))?;
        transaction.commit().await?;
        Ok(dispatch)
    }

    /// Lists dispatches whose operations may still require provider work.
    pub async fn list_open_dispatches(
        &self,
        tenant_id: &TenantId,
        limit: usize,
    ) -> Result<ActionDispatchPage, ActionStoreError> {
        if !(1..=100).contains(&limit) {
            return Err(ActionStoreError::OutOfRange("Action dispatch page limit"));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| ActionStoreError::OutOfRange("Action dispatch page limit"))?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let rows = transaction
            .query(
                "SELECT dispatch.dispatch_json, event.actor_id AS event_actor_id, event.event_kind, event.command_json, event.operation_json FROM action_dispatches AS dispatch INNER JOIN action_operations AS operation ON operation.tenant_id = dispatch.tenant_id AND operation.operation_id = dispatch.operation_id INNER JOIN action_operation_events AS event ON event.tenant_id = dispatch.tenant_id AND event.operation_id = dispatch.operation_id AND event.version = dispatch.operation_version WHERE dispatch.tenant_id = $1 AND operation.state IN ('executing', 'dispatched', 'outcome_unknown') ORDER BY dispatch.requested_at_unix_ms, dispatch.operation_id LIMIT $2",
                &[&tenant_id.as_str(), &limit],
            )
            .await?;
        let dispatches = rows
            .iter()
            .map(decode_dispatch_row)
            .collect::<Result<Vec<_>, _>>()?;
        transaction.commit().await?;
        Ok(ActionDispatchPage { dispatches })
    }

    /// Exclusively leases the next due reconciliation job.
    ///
    /// PostgreSQL `SKIP LOCKED` lets concurrent workers claim different jobs.
    /// Expired leases may be reclaimed; a lease may not exceed five minutes.
    pub async fn claim_due_reconciliation(
        &self,
        tenant_id: &TenantId,
        worker_id: &ActorId,
        claimed_at_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    ) -> Result<Option<ActionReconciliationJob>, ActionStoreError> {
        if lease_expires_at_unix_ms <= claimed_at_unix_ms
            || lease_expires_at_unix_ms - claimed_at_unix_ms > MAX_RECONCILIATION_LEASE_MS
        {
            return Err(ActionStoreError::OutOfRange("Action reconciliation lease"));
        }
        let claimed_at = storage_i64(claimed_at_unix_ms, "Action reconciliation claim time")?;
        let lease_expires = storage_i64(
            lease_expires_at_unix_ms,
            "Action reconciliation lease expiry",
        )?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let candidate = transaction
            .query_opt(
                "SELECT job.operation_id, job.dispatch_digest FROM action_reconciliation_jobs AS job INNER JOIN action_operations AS operation ON operation.tenant_id = job.tenant_id AND operation.operation_id = job.operation_id WHERE job.tenant_id = $1 AND operation.state = 'dispatched' AND ((job.state = 'scheduled' AND job.next_attempt_at_unix_ms <= $2) OR (job.state = 'leased' AND job.lease_expires_at_unix_ms <= $2)) ORDER BY job.next_attempt_at_unix_ms, job.operation_id FOR UPDATE OF job SKIP LOCKED LIMIT 1",
                &[&tenant_id.as_str(), &claimed_at],
            )
            .await?;
        let Some(candidate) = candidate else {
            transaction.commit().await?;
            return Ok(None);
        };
        let operation_id = ActionOperationId::parse(candidate.get::<_, String>(0))
            .map_err(|error| ActionStoreError::Corrupt(error.to_string()))?;
        let scheduled_dispatch_digest = ContentDigest::parse(candidate.get::<_, String>(1))
            .map_err(|error| ActionStoreError::Corrupt(error.to_string()))?;
        let leased = transaction
            .query_one(
                "UPDATE action_reconciliation_jobs SET state = 'leased', attempt_count = attempt_count + 1, lease_owner = $3, lease_expires_at_unix_ms = $4, updated_at_unix_ms = $2 WHERE tenant_id = $1 AND operation_id = $5 RETURNING attempt_count",
                &[
                    &tenant_id.as_str(),
                    &claimed_at,
                    &worker_id.as_str(),
                    &lease_expires,
                    &operation_id.as_str(),
                ],
            )
            .await?;
        let attempt_count = u64::try_from(leased.get::<_, i64>(0)).map_err(|_| {
            ActionStoreError::Corrupt("Action reconciliation attempt count is invalid".to_owned())
        })?;
        let operation = transaction
            .query_one(
                "SELECT operation_id, idempotency_key, proposal_digest, state, version, operation_json, created_at_unix_ms, updated_at_unix_ms FROM action_operations WHERE tenant_id = $1 AND operation_id = $2 FOR SHARE",
                &[&tenant_id.as_str(), &operation_id.as_str()],
            )
            .await
            .map_err(ActionStoreError::from)
            .and_then(|row| validate_current_row(&row).map(|current| current.operation))?;
        let dispatch = transaction
            .query_one(
                "SELECT dispatch.dispatch_json, event.actor_id AS event_actor_id, event.event_kind, event.command_json, event.operation_json FROM action_dispatches AS dispatch INNER JOIN action_operation_events AS event ON event.tenant_id = dispatch.tenant_id AND event.operation_id = dispatch.operation_id AND event.version = dispatch.operation_version WHERE dispatch.tenant_id = $1 AND dispatch.operation_id = $2",
                &[&tenant_id.as_str(), &operation_id.as_str()],
            )
            .await
            .map_err(ActionStoreError::from)
            .and_then(|row| decode_dispatch_row(&row))?;
        if dispatch.dispatch_digest != scheduled_dispatch_digest.as_str() {
            return Err(ActionStoreError::Corrupt(
                "Action reconciliation job does not match its dispatch".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(Some(ActionReconciliationJob {
            operation,
            dispatch,
            attempt_count,
            lease_expires_at_unix_ms,
        }))
    }

    /// Completes a reconciliation lease if worker, lease, operation version,
    /// and terminal provider status still match current durable state.
    pub async fn finish_reconciliation(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
        worker_id: &ActorId,
        expected_operation_version: u64,
        finished_at_unix_ms: u64,
        disposition: ActionReconciliationDisposition,
    ) -> Result<(), ActionStoreError> {
        let expected_version =
            storage_i64(expected_operation_version, "Action reconciliation version")?;
        let finished_at =
            storage_i64(finished_at_unix_ms, "Action reconciliation completion time")?;
        let (state, next_attempt, terminal_status) = match disposition {
            ActionReconciliationDisposition::PollAgain {
                next_attempt_at_unix_ms,
            } => {
                if next_attempt_at_unix_ms <= finished_at_unix_ms {
                    return Err(ActionStoreError::OutOfRange(
                        "Action reconciliation next attempt",
                    ));
                }
                (
                    "scheduled",
                    Some(storage_i64(
                        next_attempt_at_unix_ms,
                        "Action reconciliation next attempt",
                    )?),
                    None,
                )
            }
            ActionReconciliationDisposition::Terminal { provider_status } => {
                if provider_status.is_empty()
                    || provider_status.len() > 64
                    || !provider_status
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                {
                    return Err(ActionStoreError::Corrupt(
                        "Action reconciliation terminal status is invalid".to_owned(),
                    ));
                }
                ("terminal", None, Some(provider_status))
            }
        };
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let updated = transaction
            .execute(
                "UPDATE action_reconciliation_jobs AS job SET state = $1, next_attempt_at_unix_ms = $2, lease_owner = NULL, lease_expires_at_unix_ms = NULL, terminal_provider_status = $3, updated_at_unix_ms = $4 FROM action_operations AS operation WHERE job.tenant_id = $5 AND job.operation_id = $6 AND job.state = 'leased' AND job.lease_owner = $7 AND job.lease_expires_at_unix_ms >= $4 AND operation.tenant_id = job.tenant_id AND operation.operation_id = job.operation_id AND operation.version = $8 AND ($3::TEXT IS NULL OR operation.operation_json->>'provider_status' = $3)",
                &[
                    &state,
                    &next_attempt,
                    &terminal_status,
                    &finished_at,
                    &tenant_id.as_str(),
                    &operation_id.as_str(),
                    &worker_id.as_str(),
                    &expected_version,
                ],
            )
            .await?;
        if updated != 1 {
            return Err(ActionStoreError::Conflict(
                "Action reconciliation lease or operation version changed".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Returns the complete validated operation history in version order.
    ///
    /// Gaps, non-monotonic commit times, digest mismatches, or a final event that
    /// differs from current state are reported as corruption.
    pub async fn history(
        &self,
        tenant_id: &TenantId,
        operation_id: &ActionOperationId,
    ) -> Result<Vec<ActionEvent>, ActionStoreError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await?;
        set_tenant(&transaction, tenant_id.as_str()).await?;
        let current = transaction
            .query_opt(
                "SELECT operation_id, idempotency_key, proposal_digest, state, version, operation_json, created_at_unix_ms, updated_at_unix_ms FROM action_operations WHERE tenant_id = $1 AND operation_id = $2 FOR SHARE",
                &[&tenant_id.as_str(), &operation_id.as_str()],
            )
            .await?
            .as_ref()
            .map(validate_current_row)
            .transpose()?
            .ok_or_else(|| ActionStoreError::NotFound(operation_id.to_string()))?;
        let rows = transaction
            .query(
                "SELECT version, actor_id, event_kind, command_digest, operation_digest, command_json, operation_json, committed_at_unix_ms FROM action_operation_events WHERE tenant_id = $1 AND operation_id = $2 ORDER BY version",
                &[&tenant_id.as_str(), &operation_id.as_str()],
            )
            .await?;
        if rows.is_empty() {
            return Err(ActionStoreError::NotFound(operation_id.to_string()));
        }
        let mut events = Vec::with_capacity(rows.len());
        let mut previous_committed_at = 0;
        for (index, row) in rows.iter().enumerate() {
            let version: i64 = row.get(0);
            let expected_version = i64::try_from(index + 1)
                .map_err(|_| ActionStoreError::OutOfRange("Action event version"))?;
            if version != expected_version {
                return Err(ActionStoreError::Corrupt(format!(
                    "Action event history skips version {}",
                    index + 1
                )));
            }
            let actor_id = ActorId::parse(row.get::<_, String>(1))
                .map_err(|error| ActionStoreError::Corrupt(error.to_string()))?;
            let command_json: Option<Value> = row.get(5);
            let operation_json: Value = row.get(6);
            let operation = decode_operation(operation_json.clone())?;
            if operation.version != u64::try_from(version).unwrap_or_default() {
                return Err(ActionStoreError::Corrupt(
                    "Action event version does not match its record".to_owned(),
                ));
            }
            let stored_operation_digest: String = row.get(4);
            let operation_digest = ContentDigest::parse(stored_operation_digest)
                .map_err(|error| ActionStoreError::Corrupt(error.to_string()))?;
            if operation_digest != digest_json(&operation_json)? {
                return Err(ActionStoreError::Corrupt(
                    "Action event operation digest does not match".to_owned(),
                ));
            }
            let command_digest = row
                .get::<_, Option<String>>(3)
                .map(ContentDigest::parse)
                .transpose()
                .map_err(|error| ActionStoreError::Corrupt(error.to_string()))?;
            let event_kind: String = row.get(2);
            match (&command_json, &command_digest) {
                (None, None) if version == 1 && event_kind == "proposed" => {}
                (Some(command), Some(digest))
                    if version > 1
                        && digest_json(command)? == *digest
                        && command.get("command").and_then(Value::as_str)
                            == Some(event_kind.as_str()) => {}
                _ => {
                    return Err(ActionStoreError::Corrupt(
                        "Action event command does not match its receipt".to_owned(),
                    ));
                }
            }
            let committed_at: i64 = row.get(7);
            let committed_at = u64::try_from(committed_at).map_err(|_| {
                ActionStoreError::Corrupt("Action event commit time is invalid".to_owned())
            })?;
            if committed_at < previous_committed_at {
                return Err(ActionStoreError::Corrupt(
                    "Action event commit time moves backwards".to_owned(),
                ));
            }
            previous_committed_at = committed_at;
            events.push(ActionEvent {
                actor_id,
                event_kind,
                command_digest,
                operation_digest,
                committed_at_unix_ms: committed_at,
                operation,
            });
        }
        if events
            .last()
            .is_none_or(|event| event.operation != current.operation)
        {
            return Err(ActionStoreError::Corrupt(
                "Action current version does not match its event history".to_owned(),
            ));
        }
        transaction.commit().await?;
        Ok(events)
    }
}

async fn select_proposal_aliases(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    operation_id: &str,
    idempotency_key: &str,
) -> Result<Vec<Row>, ActionStoreError> {
    Ok(transaction
        .query(
            "SELECT operation_id, idempotency_key, proposal_digest, state, version, operation_json, created_at_unix_ms, updated_at_unix_ms FROM action_operations WHERE tenant_id = $1 AND (operation_id = $2 OR idempotency_key = $3) FOR UPDATE",
            &[&tenant_id, &operation_id, &idempotency_key],
        )
        .await?)
}

fn exact_proposal_replay(
    rows: Vec<Row>,
    operation_id: &str,
    idempotency_key: &str,
    proposal_digest: &str,
) -> Result<ActionOperation, ActionStoreError> {
    if rows.len() != 1 {
        return Err(ActionStoreError::Conflict(
            "operation ID and idempotency key resolve to different Actions".to_owned(),
        ));
    }
    let row = &rows[0];
    let stored = validate_current_row(row)?;
    if stored.operation.proposal.operation_id.as_str() != operation_id
        || stored.operation.proposal.idempotency_key.as_str() != idempotency_key
        || stored.operation.proposal.proposal_digest.as_str() != proposal_digest
    {
        return Err(ActionStoreError::Conflict(
            "operation ID or idempotency key was reused for different Action content".to_owned(),
        ));
    }
    Ok(stored.operation)
}

fn validate_current_row(row: &Row) -> Result<CurrentAction, ActionStoreError> {
    let operation_id: String = row.get(0);
    let idempotency_key: String = row.get(1);
    let proposal_digest: String = row.get(2);
    let state: String = row.get(3);
    let version: i64 = row.get(4);
    let operation = decode_operation(row.get(5))?;
    let created_at: i64 = row.get(6);
    let updated_at: i64 = row.get(7);
    let created_at = u64::try_from(created_at)
        .map_err(|_| ActionStoreError::Corrupt("Action creation time is invalid".to_owned()))?;
    let updated_at = u64::try_from(updated_at)
        .map_err(|_| ActionStoreError::Corrupt("Action update time is invalid".to_owned()))?;
    if operation.proposal.operation_id.as_str() != operation_id
        || operation.proposal.idempotency_key.as_str() != idempotency_key
        || operation.proposal.proposal_digest.as_str() != proposal_digest
        || enum_name(&operation.state)? != state
        || i64::try_from(operation.version).ok() != Some(version)
    {
        return Err(ActionStoreError::Corrupt(
            "Action columns do not match the stored operation".to_owned(),
        ));
    }
    if created_at == 0 || updated_at < created_at {
        return Err(ActionStoreError::Corrupt(
            "Action ledger timestamps are invalid".to_owned(),
        ));
    }
    Ok(CurrentAction {
        operation,
        updated_at_unix_ms: updated_at,
    })
}

fn decode_operation(value: Value) -> Result<ActionOperation, ActionStoreError> {
    serde_json::from_value(value)
        .map_err(|error| ActionStoreError::Corrupt(format!("invalid Action operation: {error}")))
}

fn decode_dispatch_row(row: &Row) -> Result<ActionDispatch, ActionStoreError> {
    let value: Value = row.get("dispatch_json");
    let dispatch: ActionDispatch = serde_json::from_value(value)
        .map_err(|error| ActionStoreError::Corrupt(format!("invalid Action dispatch: {error}")))?;
    dispatch.validate()?;
    let event_kind: String = row.get("event_kind");
    let event_actor_id: String = row.get("event_actor_id");
    let command_json: Option<Value> = row.get("command_json");
    let operation = decode_operation(row.get("operation_json"))?;
    let command_json = command_json.ok_or_else(|| {
        ActionStoreError::Corrupt("Action dispatch event has no execution command".to_owned())
    })?;
    if event_kind != "start_execution"
        || event_actor_id != dispatch.requested_by
        || command_json.get("command").and_then(Value::as_str) != Some("start_execution")
        || command_json
            .get("started_at_unix_ms")
            .and_then(Value::as_u64)
            != Some(dispatch.requested_at_unix_ms)
    {
        return Err(ActionStoreError::Corrupt(
            "Action dispatch does not match its execution command".to_owned(),
        ));
    }
    dispatch.validate_against_operation(&operation)?;
    Ok(dispatch)
}

fn digest_json(value: &Value) -> Result<ContentDigest, ActionStoreError> {
    let encoded = serde_json::to_vec(value)?;
    Ok(ContentDigest::of_bytes(encoded))
}

fn finding_validation_decision(receipt: &FindingValidationReceipt) -> &'static str {
    match receipt.decision {
        cerebro_platform_sdk::FindingValidationDecision::Confirmed => "confirmed",
        cerebro_platform_sdk::FindingValidationDecision::Rejected => "rejected",
    }
}

async fn select_finding_validation(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    receipt_digest: &str,
) -> Result<Option<FindingValidationReceipt>, ActionStoreError> {
    transaction
        .query_opt(
            "SELECT receipt_json FROM finding_validation_receipts WHERE tenant_id = $1 AND receipt_digest = $2 FOR SHARE",
            &[&tenant_id, &receipt_digest],
        )
        .await?
        .map(|row| {
            let value: Value = row.get("receipt_json");
            serde_json::from_value(value).map_err(|error| {
                ActionStoreError::Corrupt(format!(
                    "finding validation receipt {receipt_digest}: {error}"
                ))
            })
        })
        .transpose()
}

fn command_actor_matches(
    actor_id: &ActorId,
    claimed_by: Option<&cerebro_platform_sdk::OpaqueId>,
    command: &ActionCommand,
) -> bool {
    let owns_claim = || claimed_by.is_some_and(|worker_id| worker_id.as_str() == actor_id.as_str());
    match command {
        ActionCommand::RecordApproval { receipt } => receipt.decided_by == *actor_id,
        ActionCommand::Claim { worker_id, .. } => worker_id.as_str() == actor_id.as_str(),
        ActionCommand::Complete {
            executor_actor_id, ..
        } => owns_claim() && executor_actor_id == actor_id,
        ActionCommand::RecordProviderReceipt {
            executor_actor_id, ..
        } => owns_claim() && executor_actor_id == actor_id,
        // Reconciliation is the recovery path after an original claimant has
        // lost execution authority, so its signed executor may differ.
        ActionCommand::Reconcile {
            executor_actor_id, ..
        } => executor_actor_id == actor_id,
        ActionCommand::ObserveProviderReceipt {
            reconciler_actor_id,
            ..
        } => reconciler_actor_id == actor_id,
        ActionCommand::Verify { receipt } => receipt.receipt.verifier_actor_id == *actor_id,
        ActionCommand::RenewClaim { .. }
        | ActionCommand::StartExecution { .. }
        | ActionCommand::MarkOutcomeUnknown => owns_claim(),
        // Any signed executor may recover an unstarted claim after the engine
        // verifies its recorded lease has expired. The releasing actor remains
        // part of the append-only event history.
        ActionCommand::RecordSimulation
        | ActionCommand::RequestApproval
        | ActionCommand::ReleaseExpiredClaim { .. }
        | ActionCommand::RejectVerification
        | ActionCommand::Fail
        | ActionCommand::RollBack => true,
    }
}

fn command_valid_at_authority_time(
    proposal_expires_at_unix_ms: u64,
    claim_expires_at_unix_ms: Option<u64>,
    command: &ActionCommand,
    committed_at_unix_ms: u64,
) -> bool {
    match command {
        ActionCommand::Claim { .. } => committed_at_unix_ms < proposal_expires_at_unix_ms,
        ActionCommand::RenewClaim { .. } | ActionCommand::StartExecution { .. } => {
            claim_expires_at_unix_ms
                .is_some_and(|claim_expires_at| committed_at_unix_ms < claim_expires_at)
        }
        ActionCommand::ReleaseExpiredClaim { .. } => claim_expires_at_unix_ms
            .is_some_and(|claim_expires_at| committed_at_unix_ms >= claim_expires_at),
        ActionCommand::RecordSimulation
        | ActionCommand::RequestApproval
        | ActionCommand::RecordApproval { .. }
        | ActionCommand::RecordProviderReceipt { .. }
        | ActionCommand::ObserveProviderReceipt { .. }
        | ActionCommand::MarkOutcomeUnknown
        | ActionCommand::Complete { .. }
        | ActionCommand::Reconcile { .. }
        | ActionCommand::Verify { .. }
        | ActionCommand::RejectVerification
        | ActionCommand::Fail
        | ActionCommand::RollBack => true,
    }
}

fn proposal_valid_at(
    proposed_at_unix_ms: u64,
    proposal_expires_at_unix_ms: u64,
    committed_at_unix_ms: u64,
) -> bool {
    committed_at_unix_ms >= proposed_at_unix_ms
        && committed_at_unix_ms < proposal_expires_at_unix_ms
}

fn command_observed_at(command: &ActionCommand) -> Option<u64> {
    match command {
        ActionCommand::RecordApproval { receipt } => Some(receipt.decided_at_unix_ms),
        ActionCommand::Claim {
            claimed_at_unix_ms, ..
        } => Some(*claimed_at_unix_ms),
        ActionCommand::RenewClaim {
            renewed_at_unix_ms, ..
        } => Some(*renewed_at_unix_ms),
        ActionCommand::ReleaseExpiredClaim {
            observed_at_unix_ms,
        } => Some(*observed_at_unix_ms),
        ActionCommand::StartExecution { started_at_unix_ms } => Some(*started_at_unix_ms),
        ActionCommand::RecordProviderReceipt {
            observed_at_unix_ms,
            ..
        }
        | ActionCommand::ObserveProviderReceipt {
            observed_at_unix_ms,
            ..
        } => Some(*observed_at_unix_ms),
        ActionCommand::Complete {
            executed_at_unix_ms,
            ..
        }
        | ActionCommand::Reconcile {
            executed_at_unix_ms,
            ..
        } => Some(*executed_at_unix_ms),
        ActionCommand::Verify { receipt } => Some(receipt.receipt.verified_at_unix_ms),
        ActionCommand::RecordSimulation
        | ActionCommand::RequestApproval
        | ActionCommand::MarkOutcomeUnknown
        | ActionCommand::RejectVerification
        | ActionCommand::Fail
        | ActionCommand::RollBack => None,
    }
}

fn enum_name<T: serde::Serialize>(value: &T) -> Result<String, ActionStoreError> {
    match serde_json::to_value(value)? {
        Value::String(value) => Ok(value),
        _ => Err(ActionStoreError::Corrupt(
            "Action enum has no stable storage name".to_owned(),
        )),
    }
}

fn storage_i64(value: u64, field: &'static str) -> Result<i64, ActionStoreError> {
    if value == 0 {
        return Err(ActionStoreError::OutOfRange(field));
    }
    i64::try_from(value).map_err(|_| ActionStoreError::OutOfRange(field))
}

fn encode_page_token(updated_at_unix_ms: u64, operation_id: &ActionOperationId) -> String {
    let raw = format!("{updated_at_unix_ms}\0{}", operation_id.as_str());
    let mut encoded = String::with_capacity(3 + raw.len() * 2);
    encoded.push_str("v1.");
    for byte in raw.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn decode_page_token(token: &str) -> Result<(u64, ActionOperationId), ActionStoreError> {
    let encoded = token
        .strip_prefix("v1.")
        .filter(|encoded| !encoded.is_empty() && encoded.len() <= 554 && encoded.len() % 2 == 0)
        .ok_or(ActionStoreError::InvalidPageToken)?;
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|value| u8::from_str_radix(value, 16).ok())
                .ok_or(ActionStoreError::InvalidPageToken)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let raw = String::from_utf8(bytes).map_err(|_| ActionStoreError::InvalidPageToken)?;
    let (updated_at, operation_id) = raw
        .split_once('\0')
        .ok_or(ActionStoreError::InvalidPageToken)?;
    let updated_at = updated_at
        .parse::<u64>()
        .ok()
        .filter(|updated_at| *updated_at > 0 && *updated_at <= i64::MAX as u64)
        .ok_or(ActionStoreError::InvalidPageToken)?;
    let operation_id = ActionOperationId::parse(operation_id.to_owned())
        .map_err(|_| ActionStoreError::InvalidPageToken)?;
    Ok((updated_at, operation_id))
}

async fn set_tenant(
    transaction: &Transaction<'_>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_validation_preserves_proposal_error_classes() {
        let conflict = ActionStoreError::from(ActionCatalogError::InvalidProposal(
            SdkError::Conflict("duplicate action expected effect".to_owned()),
        ));
        assert!(
            matches!(conflict, ActionStoreError::Conflict(message) if message == "duplicate action expected effect")
        );

        let invalid = ActionStoreError::from(ActionCatalogError::InvalidProposal(
            SdkError::Invalid("action proposal digest"),
        ));
        assert!(matches!(
            invalid,
            ActionStoreError::Invalid(SdkError::Invalid("action proposal digest"))
        ));
    }

    #[test]
    fn schema_enforces_tenant_isolation_idempotency_and_append_only_versions() {
        for required in [
            "PRIMARY KEY (tenant_id, receipt_digest)",
            "action_operations_finding_validation_receipt_fk",
            "FOREIGN KEY (tenant_id, finding_validation_receipt_digest)",
            "PRIMARY KEY (tenant_id, operation_id)",
            "UNIQUE (tenant_id, idempotency_key)",
            "PRIMARY KEY (tenant_id, operation_id, version)",
            "PRIMARY KEY (tenant_id, operation_id)",
            "UNIQUE (tenant_id, dispatch_digest)",
            "FOREIGN KEY (tenant_id, operation_id, operation_version)",
            "actor_id TEXT NOT NULL",
            "FORCE ROW LEVEL SECURITY",
            "current_setting(''cerebro.tenant_id'', true)",
            "(operation_json->'proposal'->>'tenant_id') IS NOT DISTINCT FROM tenant_id",
            "(operation_json->'proposal'->>'proposal_digest') IS NOT DISTINCT FROM proposal_digest",
            "version > 1 AND event_kind <> 'proposed'",
            "CREATE TRIGGER action_operation_events_append_only",
            "CREATE TRIGGER finding_validation_receipts_append_only",
            "CREATE TRIGGER action_dispatches_append_only",
            "BEFORE UPDATE OR DELETE ON action_operation_events",
            "BEFORE UPDATE OR DELETE ON finding_validation_receipts",
            "BEFORE UPDATE OR DELETE ON action_dispatches",
            "finding_validation_receipts_finding_idx",
            "finding_validation_receipts_policy_binding",
            "finding_validation_receipts_policy_idx",
            "action_operations_queue_idx",
            "action_operations_dispatch_queue_idx",
            "action_operations_state_values",
            "'dispatched'",
            "VALIDATE CONSTRAINT action_operations_state_values",
            "action_dispatches_requested_idx",
            "action_dispatches_finding_idx",
            "CREATE TABLE IF NOT EXISTS action_reconciliation_jobs",
            "action_reconciliation_jobs_due_idx",
            "FOREIGN KEY (tenant_id, operation_id)\n    REFERENCES action_dispatches",
            "'scheduled', 'leased', 'terminal'",
        ] {
            assert!(POSTGRES_SCHEMA.contains(required), "missing {required}");
        }
        assert!(!POSTGRES_SCHEMA.contains("UPDATE action_operation_events"));
        assert!(!POSTGRES_SCHEMA.contains("DELETE FROM action_operation_events"));
        assert!(!POSTGRES_SCHEMA.contains("UPDATE finding_validation_receipts"));
        assert!(!POSTGRES_SCHEMA.contains("DELETE FROM finding_validation_receipts"));
        assert!(!POSTGRES_SCHEMA.contains("UPDATE action_dispatches"));
        assert!(!POSTGRES_SCHEMA.contains("DELETE FROM action_dispatches"));
        let event_table = POSTGRES_SCHEMA
            .find("CREATE TABLE IF NOT EXISTS action_operation_events")
            .expect("event table");
        let dispatch_table = POSTGRES_SCHEMA
            .find("CREATE TABLE IF NOT EXISTS action_dispatches")
            .expect("dispatch table");
        let dispatch_indexes = POSTGRES_SCHEMA
            .find("CREATE INDEX IF NOT EXISTS action_operation_events_committed_idx")
            .expect("indexes after dispatch table");
        assert!(
            !POSTGRES_SCHEMA[event_table..dispatch_table]
                .contains("FOREIGN KEY (tenant_id, operation_id, operation_version)"),
            "the event table cannot reference a dispatch-only column"
        );
        assert!(
            POSTGRES_SCHEMA[dispatch_table..dispatch_indexes]
                .contains("FOREIGN KEY (tenant_id, operation_id, operation_version)"),
            "the immutable dispatch must reference its exact start-execution event"
        );
    }

    #[test]
    fn storage_bounds_reject_zero_and_values_postgres_cannot_represent() {
        assert!(storage_i64(0, "test").is_err());
        assert!(storage_i64(u64::MAX, "test").is_err());
        assert_eq!(storage_i64(i64::MAX as u64, "test").unwrap(), i64::MAX);
    }

    #[test]
    fn dispatches_reject_tampered_provider_definition_and_content() {
        let definition = lookup("endpoint.cerebro.revoke_device").unwrap();
        let mut dispatch = ActionDispatch {
            tenant_id: "tenant:dispatch:one".to_owned(),
            operation_id: "operation:dispatch:one".to_owned(),
            operation_version: 6,
            proposal_digest: ContentDigest::of_bytes("proposal").to_string(),
            finding_id: "finding:dispatch:one".to_owned(),
            finding_revision_digest: ContentDigest::of_bytes("finding revision").to_string(),
            finding_validation_receipt_digest: ContentDigest::of_bytes("finding validation")
                .to_string(),
            graph_revision: 7,
            action_kind: definition.id.to_owned(),
            action_definition_digest: definition.definition_digest.to_owned(),
            provider: definition.provider.to_owned(),
            provider_action: definition.provider_action.to_owned(),
            target_kind: definition.target_kind.to_owned(),
            target_id: "device:dispatch:one".to_owned(),
            effect: definition.effect.to_owned(),
            idempotency_key: "idempotency:dispatch:one".to_owned(),
            requested_by: "worker:dispatch:one".to_owned(),
            requested_at_unix_ms: 42,
            dispatch_digest: ContentDigest::of_bytes("unbound").to_string(),
        };
        dispatch.dispatch_digest = dispatch.computed_digest().unwrap().to_string();
        dispatch.validate().unwrap();

        let mut changed_provider = dispatch.clone();
        changed_provider.provider = "attacker-provider".to_owned();
        changed_provider.dispatch_digest = changed_provider.computed_digest().unwrap().to_string();
        assert!(matches!(
            changed_provider.validate(),
            Err(ActionStoreError::Corrupt(_))
        ));

        let mut changed_target = dispatch;
        changed_target.target_id = "device:dispatch:other".to_owned();
        assert!(matches!(
            changed_target.validate(),
            Err(ActionStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn queue_page_tokens_are_bounded_composite_cursors() {
        let operation_id = ActionOperationId::parse("operation:queue:one").unwrap();
        let token = encode_page_token(42, &operation_id);
        assert_ne!(token, operation_id.as_str());
        assert_eq!(
            decode_page_token(&token).unwrap(),
            (42, operation_id.clone())
        );
        for invalid in [
            "",
            "v2.00",
            "v1.not-hex",
            "v1.00",
            &encode_page_token(0, &operation_id),
        ] {
            assert!(matches!(
                decode_page_token(invalid),
                Err(ActionStoreError::InvalidPageToken)
            ));
        }
        assert!(matches!(
            decode_page_token(&format!("v1.{}", "00".repeat(278))),
            Err(ActionStoreError::InvalidPageToken)
        ));
    }

    #[test]
    fn authority_time_rejects_future_or_expired_evidence() {
        assert!(!proposal_valid_at(10, 20, 9));
        assert!(proposal_valid_at(10, 20, 10));
        assert!(proposal_valid_at(10, 20, 19));
        assert!(!proposal_valid_at(10, 20, 20));

        assert_eq!(
            command_observed_at(&ActionCommand::Claim {
                worker_id: cerebro_platform_sdk::OpaqueId::parse("worker:one").unwrap(),
                claimed_at_unix_ms: 21,
                claim_expires_at_unix_ms: 30,
            }),
            Some(21)
        );
        assert_eq!(
            command_observed_at(&ActionCommand::StartExecution {
                started_at_unix_ms: 22,
            }),
            Some(22)
        );
    }

    #[test]
    fn command_receipt_actors_must_match_the_authenticated_actor() {
        let actor = ActorId::parse("operator:one").unwrap();
        let other = ActorId::parse("operator:other").unwrap();
        assert!(command_actor_matches(
            &actor,
            None,
            &ActionCommand::RecordSimulation
        ));
        assert!(command_actor_matches(
            &actor,
            None,
            &ActionCommand::Claim {
                worker_id: cerebro_platform_sdk::OpaqueId::parse(actor.as_str()).unwrap(),
                claimed_at_unix_ms: 10,
                claim_expires_at_unix_ms: 20,
            }
        ));
        assert!(!command_actor_matches(
            &other,
            None,
            &ActionCommand::Claim {
                worker_id: cerebro_platform_sdk::OpaqueId::parse(actor.as_str()).unwrap(),
                claimed_at_unix_ms: 10,
                claim_expires_at_unix_ms: 20,
            }
        ));
        let claim = cerebro_platform_sdk::OpaqueId::parse(actor.as_str()).unwrap();
        assert!(command_actor_matches(
            &actor,
            Some(&claim),
            &ActionCommand::StartExecution {
                started_at_unix_ms: 11,
            }
        ));
        assert!(!command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::StartExecution {
                started_at_unix_ms: 11,
            }
        ));
        assert!(command_actor_matches(
            &actor,
            Some(&claim),
            &ActionCommand::RenewClaim {
                renewed_at_unix_ms: 11,
                claim_expires_at_unix_ms: 20,
            }
        ));
        assert!(!command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::RenewClaim {
                renewed_at_unix_ms: 11,
                claim_expires_at_unix_ms: 20,
            }
        ));
        assert!(command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::ReleaseExpiredClaim {
                observed_at_unix_ms: 20,
            }
        ));
        assert!(!command_actor_matches(
            &actor,
            None,
            &ActionCommand::MarkOutcomeUnknown
        ));
        assert!(command_actor_matches(
            &actor,
            Some(&claim),
            &ActionCommand::RecordProviderReceipt {
                external_receipt_ref: cerebro_platform_sdk::OpaqueId::parse("receipt:queued")
                    .unwrap(),
                provider_receipt_digest: ContentDigest::of_bytes("queued"),
                provider_status: "queued".to_owned(),
                executor_actor_id: actor.clone(),
                observed_at_unix_ms: 11,
            }
        ));
        assert!(!command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::RecordProviderReceipt {
                external_receipt_ref: cerebro_platform_sdk::OpaqueId::parse("receipt:queued")
                    .unwrap(),
                provider_receipt_digest: ContentDigest::of_bytes("queued"),
                provider_status: "queued".to_owned(),
                executor_actor_id: other.clone(),
                observed_at_unix_ms: 11,
            }
        ));
        assert!(command_actor_matches(
            &actor,
            Some(&claim),
            &ActionCommand::ObserveProviderReceipt {
                provider_receipt_digest: ContentDigest::of_bytes("running"),
                provider_status: "running".to_owned(),
                reconciler_actor_id: actor.clone(),
                observed_at_unix_ms: 12,
            }
        ));
        assert!(!command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::ObserveProviderReceipt {
                provider_receipt_digest: ContentDigest::of_bytes("running"),
                provider_status: "running".to_owned(),
                reconciler_actor_id: actor.clone(),
                observed_at_unix_ms: 12,
            }
        ));
        assert!(command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::ObserveProviderReceipt {
                provider_receipt_digest: ContentDigest::of_bytes("running"),
                provider_status: "running".to_owned(),
                reconciler_actor_id: other.clone(),
                observed_at_unix_ms: 12,
            }
        ));
        assert!(command_actor_matches(
            &actor,
            Some(&claim),
            &ActionCommand::Complete {
                external_receipt_ref: cerebro_platform_sdk::OpaqueId::parse("receipt:one").unwrap(),
                provider_receipt_digest: ContentDigest::of_bytes("provider succeeded"),
                observed_effect_digest: ContentDigest::of_bytes("effect"),
                executor_actor_id: actor.clone(),
                executed_at_unix_ms: 11,
            }
        ));
        assert!(!command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::Complete {
                external_receipt_ref: cerebro_platform_sdk::OpaqueId::parse("receipt:one").unwrap(),
                provider_receipt_digest: ContentDigest::of_bytes("provider succeeded"),
                observed_effect_digest: ContentDigest::of_bytes("effect"),
                executor_actor_id: actor,
                executed_at_unix_ms: 11,
            }
        ));
        assert!(!command_actor_matches(
            &other,
            Some(&claim),
            &ActionCommand::Complete {
                external_receipt_ref: cerebro_platform_sdk::OpaqueId::parse("receipt:two").unwrap(),
                provider_receipt_digest: ContentDigest::of_bytes("provider succeeded"),
                observed_effect_digest: ContentDigest::of_bytes("effect"),
                executor_actor_id: other.clone(),
                executed_at_unix_ms: 11,
            }
        ));
    }

    #[test]
    fn authority_commit_time_cannot_revive_an_expired_claim() {
        let start = ActionCommand::StartExecution {
            started_at_unix_ms: 19,
        };
        assert!(command_valid_at_authority_time(30, Some(20), &start, 19));
        assert!(
            !command_valid_at_authority_time(30, Some(20), &start, 20),
            "a backdated start must fail at the exclusive authority deadline"
        );

        let renew = ActionCommand::RenewClaim {
            renewed_at_unix_ms: 19,
            claim_expires_at_unix_ms: 30,
        };
        assert!(command_valid_at_authority_time(30, Some(20), &renew, 19));
        assert!(
            !command_valid_at_authority_time(30, Some(20), &renew, 21),
            "a backdated renewal must not revive an expired claim"
        );

        let release = ActionCommand::ReleaseExpiredClaim {
            observed_at_unix_ms: 20,
        };
        assert!(!command_valid_at_authority_time(30, Some(20), &release, 19));
        assert!(command_valid_at_authority_time(30, Some(20), &release, 20));

        let claim = ActionCommand::Claim {
            worker_id: cerebro_platform_sdk::OpaqueId::parse("worker:one").unwrap(),
            claimed_at_unix_ms: 29,
            claim_expires_at_unix_ms: 30,
        };
        assert!(command_valid_at_authority_time(30, None, &claim, 29));
        assert!(
            !command_valid_at_authority_time(30, None, &claim, 30),
            "a backdated claim must not commit after proposal expiry"
        );
    }
}
