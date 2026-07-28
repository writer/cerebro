#![forbid(unsafe_code)]

//! Authoritative, tenant-scoped persistence for Action operations.
//!
//! The ledger stores the current validated operation and an append-only copy
//! of every committed version. State transitions remain owned by
//! `cerebro-platform-engine`; this crate makes them atomic and durable.

use std::{error::Error, fmt};

use cerebro_action_catalog::{ActionCatalogError, validate_proposal};
use cerebro_platform_engine::{ActionCommand, transition_action};
use cerebro_platform_sdk::{
    ActionOperation, ActionOperationId, ActionProposal, ActionState, ActorId, ContentDigest,
    FindingValidationReceipt, SdkError, TenantId, VerificationState,
};
use postgres_native_tls::MakeTlsConnector;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::Mutex;
use tokio_postgres::{Client, Row, Transaction};

pub const POSTGRES_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS finding_validation_receipts (
  tenant_id TEXT NOT NULL CHECK (char_length(tenant_id) BETWEEN 1 AND 256),
  receipt_digest TEXT NOT NULL CHECK (receipt_digest ~ '^[0-9a-f]{64}$'),
  finding_id TEXT NOT NULL CHECK (char_length(finding_id) BETWEEN 1 AND 256),
  finding_revision_digest TEXT NOT NULL CHECK (finding_revision_digest ~ '^[0-9a-f]{64}$'),
  graph_revision BIGINT NOT NULL CHECK (graph_revision > 0),
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
  CHECK ((receipt_json->>'decision') IS NOT DISTINCT FROM decision),
  CHECK ((receipt_json->>'validated_by') IS NOT DISTINCT FROM validated_by),
  CHECK ((receipt_json->>'validated_at_unix_ms')::BIGINT IS NOT DISTINCT FROM validated_at_unix_ms),
  CHECK ((receipt_json->>'expires_at_unix_ms')::BIGINT IS NOT DISTINCT FROM expires_at_unix_ms)
);
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
CREATE INDEX IF NOT EXISTS action_operation_events_committed_idx
  ON action_operation_events (tenant_id, committed_at_unix_ms DESC);
CREATE INDEX IF NOT EXISTS action_operations_queue_idx
  ON action_operations (tenant_id, updated_at_unix_ms DESC, operation_id);
CREATE INDEX IF NOT EXISTS finding_validation_receipts_finding_idx
  ON finding_validation_receipts (tenant_id, finding_id, validated_at_unix_ms DESC);
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
ALTER TABLE finding_validation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_validation_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE action_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE action_operation_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_operation_events FORCE ROW LEVEL SECURITY;
DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'finding_validation_receipts',
    'action_operations',
    'action_operation_events'
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
pub enum ActionStoreError {
    Postgres(tokio_postgres::Error),
    Serialization(serde_json::Error),
    Invalid(SdkError),
    Catalog(ActionCatalogError),
    Conflict(String),
    NotFound(String),
    Corrupt(String),
    InvalidPageToken,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionEvent {
    pub actor_id: ActorId,
    pub event_kind: String,
    pub command_digest: Option<ContentDigest>,
    pub operation_digest: ContentDigest,
    pub committed_at_unix_ms: u64,
    pub operation: ActionOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionPage {
    pub actions: Vec<ActionOperation>,
    pub next_page_token: Option<String>,
}

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

    pub async fn migrate(&self) -> Result<(), ActionStoreError> {
        self.client
            .lock()
            .await
            .batch_execute(POSTGRES_SCHEMA)
            .await?;
        Ok(())
    }

    pub async fn health(&self) -> Result<(), ActionStoreError> {
        self.client.lock().await.simple_query("SELECT 1").await?;
        Ok(())
    }

    pub async fn record_finding_validation(
        &self,
        receipt: FindingValidationReceipt,
        committed_at_unix_ms: u64,
    ) -> Result<FindingValidationReceipt, ActionStoreError> {
        receipt.validate()?;
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
                "INSERT INTO finding_validation_receipts (tenant_id, receipt_digest, finding_id, finding_revision_digest, graph_revision, decision, validated_by, receipt_json, validated_at_unix_ms, expires_at_unix_ms, committed_at_unix_ms) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) ON CONFLICT DO NOTHING",
                &[
                    &tenant_id,
                    &receipt_digest,
                    &receipt.finding_id.as_str(),
                    &receipt.finding_revision_digest.as_str(),
                    &graph_revision,
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
        let next = transition_action(&current.operation, expected_version, command)?;
        next.validate()?;
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
        transaction.commit().await?;
        Ok(next)
    }

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
        // Reconciliation is the recovery path after an original claimant has
        // lost execution authority, so its signed executor may differ.
        ActionCommand::Reconcile {
            executor_actor_id, ..
        } => executor_actor_id == actor_id,
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
            "actor_id TEXT NOT NULL",
            "FORCE ROW LEVEL SECURITY",
            "current_setting(''cerebro.tenant_id'', true)",
            "(operation_json->'proposal'->>'tenant_id') IS NOT DISTINCT FROM tenant_id",
            "(operation_json->'proposal'->>'proposal_digest') IS NOT DISTINCT FROM proposal_digest",
            "version > 1 AND event_kind <> 'proposed'",
            "CREATE TRIGGER action_operation_events_append_only",
            "CREATE TRIGGER finding_validation_receipts_append_only",
            "BEFORE UPDATE OR DELETE ON action_operation_events",
            "BEFORE UPDATE OR DELETE ON finding_validation_receipts",
            "finding_validation_receipts_finding_idx",
            "action_operations_queue_idx",
        ] {
            assert!(POSTGRES_SCHEMA.contains(required), "missing {required}");
        }
        assert!(!POSTGRES_SCHEMA.contains("UPDATE action_operation_events"));
        assert!(!POSTGRES_SCHEMA.contains("DELETE FROM action_operation_events"));
        assert!(!POSTGRES_SCHEMA.contains("UPDATE finding_validation_receipts"));
        assert!(!POSTGRES_SCHEMA.contains("DELETE FROM finding_validation_receipts"));
    }

    #[test]
    fn storage_bounds_reject_zero_and_values_postgres_cannot_represent() {
        assert!(storage_i64(0, "test").is_err());
        assert!(storage_i64(u64::MAX, "test").is_err());
        assert_eq!(storage_i64(i64::MAX as u64, "test").unwrap(), i64::MAX);
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
            &ActionCommand::Complete {
                external_receipt_ref: cerebro_platform_sdk::OpaqueId::parse("receipt:one").unwrap(),
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
