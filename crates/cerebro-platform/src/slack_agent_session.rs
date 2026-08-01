use async_trait::async_trait;
use cerebro_agent_runtime::{
    AgentRuntimeError,
    session::{
        AgentSession, CommitmentStatus, SessionEventRecord, SessionJournal, SessionStore,
        WorkOwner, apply_session_events, message_digest,
    },
};
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tokio_postgres::Client;

pub const POSTGRES_AGENT_SESSION_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS cerebro_agent_sessions (
  session_ref TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  thread_ref TEXT NOT NULL,
  snapshot_json JSONB NOT NULL,
  last_sequence BIGINT NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (tenant_id, thread_ref)
);
ALTER TABLE cerebro_agent_sessions ADD COLUMN IF NOT EXISTS active_request_id TEXT;
ALTER TABLE cerebro_agent_sessions ADD COLUMN IF NOT EXISTS lease_owner TEXT;
ALTER TABLE cerebro_agent_sessions ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ;
CREATE TABLE IF NOT EXISTS cerebro_agent_session_events (
  session_ref TEXT NOT NULL REFERENCES cerebro_agent_sessions(session_ref) ON DELETE CASCADE,
  sequence BIGINT NOT NULL CHECK (sequence > 0),
  event_json JSONB NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (session_ref, sequence)
);
CREATE INDEX IF NOT EXISTS cerebro_agent_session_events_occurred_idx
  ON cerebro_agent_session_events (session_ref, occurred_at);
CREATE TABLE IF NOT EXISTS cerebro_agent_wakes (
  session_ref TEXT NOT NULL REFERENCES cerebro_agent_sessions(session_ref) ON DELETE CASCADE,
  commitment_ref TEXT NOT NULL,
  wake_at TIMESTAMPTZ NOT NULL,
  state TEXT NOT NULL DEFAULT 'scheduled',
  schedule_generation BIGINT NOT NULL DEFAULT 1 CHECK (schedule_generation > 0),
  occurrence_ref TEXT,
  request_id TEXT,
  commitment_digest TEXT,
  lease_owner TEXT,
  lease_token TEXT,
  fence BIGINT NOT NULL DEFAULT 0 CHECK (fence >= 0),
  lease_expires_at TIMESTAMPTZ,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  pending_payload_digest TEXT,
  delivery_ref TEXT,
  delivery_attempt_ref TEXT,
  last_error TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (session_ref, commitment_ref)
);
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS schedule_generation BIGINT NOT NULL DEFAULT 1;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS occurrence_ref TEXT;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS request_id TEXT;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS commitment_digest TEXT;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS lease_token TEXT;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS fence BIGINT NOT NULL DEFAULT 0;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS pending_payload_digest TEXT;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS delivery_ref TEXT;
ALTER TABLE cerebro_agent_wakes ADD COLUMN IF NOT EXISTS delivery_attempt_ref TEXT;
ALTER TABLE cerebro_agent_wakes DROP CONSTRAINT IF EXISTS cerebro_agent_wakes_state_check;
ALTER TABLE cerebro_agent_wakes ADD CONSTRAINT cerebro_agent_wakes_state_check
  CHECK (state IN ('scheduled', 'leased', 'awaiting_delivery', 'completed', 'cancelled', 'failed'));
CREATE INDEX IF NOT EXISTS cerebro_agent_wakes_due_idx
  ON cerebro_agent_wakes (state, wake_at);
CREATE TABLE IF NOT EXISTS cerebro_agent_memories (
  session_ref TEXT NOT NULL REFERENCES cerebro_agent_sessions(session_ref) ON DELETE CASCADE,
  memory_ref TEXT NOT NULL,
  memory_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (session_ref, memory_ref)
);
"#;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWakeClaim {
    pub commitment_ref: String,
    pub fence: u64,
    pub lease_expires_at: String,
    pub lease_owner: String,
    pub lease_token: String,
    pub occurrence_ref: String,
    pub request_id: String,
    pub schedule_generation: u64,
    pub session_ref: String,
    pub wake_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWakeDeliveryLease {
    pub commitment_ref: String,
    pub delivery_attempt_ref: String,
    pub delivery_ref: String,
    pub fence: u64,
    pub lease_expires_at: String,
    pub lease_owner: String,
    pub lease_token: String,
    pub payload_digest: String,
    pub request_id: String,
    pub schedule_generation: u64,
    pub session_ref: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentWakeDeliveryMode {
    Reconcile,
    Send,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentPendingWakeDelivery {
    pub lease: AgentWakeDeliveryLease,
    pub markdown: String,
    pub mode: AgentWakeDeliveryMode,
    pub tenant_id: String,
    pub thread_ref: String,
}

fn wake_identity(parts: &[&str]) -> String {
    Sha256::digest(parts.join("\0").as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub struct PostgresAgentSessionStore {
    client: Mutex<Client>,
}

impl PostgresAgentSessionStore {
    pub async fn connect(connection_string: &str) -> Result<Self, AgentRuntimeError> {
        let connector = TlsConnector::builder()
            .build()
            .map(MakeTlsConnector::new)
            .map_err(store_unavailable)?;
        let (client, connection) = tokio_postgres::connect(connection_string, connector)
            .await
            .map_err(store_unavailable)?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "component": "rust-slack-agent-session-store",
                        "error_kind": "postgres_connection_closed",
                        "message": error.to_string(),
                        "state": "failed",
                    })
                );
            }
        });
        let store = Self {
            client: Mutex::new(client),
        };
        store.initialize().await?;
        Ok(store)
    }

    async fn initialize(&self) -> Result<(), AgentRuntimeError> {
        self.client
            .lock()
            .await
            .batch_execute(POSTGRES_AGENT_SESSION_SCHEMA)
            .await
            .map_err(store_unavailable)
    }

    pub async fn load_by_thread(
        &self,
        tenant_id: &str,
        thread_ref: &str,
    ) -> Result<Option<AgentSession>, AgentRuntimeError> {
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                "SELECT snapshot_json FROM cerebro_agent_sessions WHERE tenant_id = $1 AND thread_ref = $2",
                &[&tenant_id, &thread_ref],
            )
            .await
            .map_err(store_unavailable)?;
        row.map(|row| decode_session(row.get(0))).transpose()
    }

    pub async fn acquire_turn(
        &self,
        session_ref: &str,
        request_id: &str,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<bool, AgentRuntimeError> {
        if lease_seconds <= 0 || lease_seconds > 3_600 {
            return Err(AgentRuntimeError::InvalidRequest(
                "turn lease duration is invalid".into(),
            ));
        }
        let changed = self
            .client
            .lock()
            .await
            .execute(
                "UPDATE cerebro_agent_sessions SET active_request_id = $2, lease_owner = $3, lease_expires_at = NOW() + make_interval(secs => $4::bigint), updated_at = NOW() WHERE session_ref = $1 AND (lease_expires_at IS NULL OR lease_expires_at <= NOW() OR (active_request_id = $2 AND lease_owner = $3))",
                &[&session_ref, &request_id, &lease_owner, &lease_seconds],
            )
            .await
            .map_err(store_unavailable)?;
        Ok(changed == 1)
    }

    pub async fn release_turn(
        &self,
        session_ref: &str,
        request_id: &str,
        lease_owner: &str,
    ) -> Result<(), AgentRuntimeError> {
        self.client
            .lock()
            .await
            .execute(
                "UPDATE cerebro_agent_sessions SET active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3",
                &[&session_ref, &request_id, &lease_owner],
            )
            .await
            .map_err(store_unavailable)?;
        Ok(())
    }

    pub async fn claim_due_wake(
        &self,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<AgentWakeClaim>, AgentRuntimeError> {
        if lease_owner.trim().is_empty() || lease_seconds <= 0 || lease_seconds > 3_600 {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake lease identity or duration is invalid".into(),
            ));
        }
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        let Some(row) = transaction
            .query_opt(
                "SELECT w.session_ref, w.commitment_ref, to_char(w.wake_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), w.schedule_generation, w.occurrence_ref, w.request_id, w.fence FROM cerebro_agent_wakes w JOIN cerebro_agent_sessions s ON s.session_ref = w.session_ref WHERE (w.state = 'scheduled' OR (w.state = 'leased' AND w.lease_expires_at <= NOW())) AND w.wake_at <= NOW() AND w.occurrence_ref IS NOT NULL AND w.request_id IS NOT NULL AND (s.lease_expires_at IS NULL OR s.lease_expires_at <= NOW()) AND ((s.snapshot_json->'pending_delivery' IS NULL OR s.snapshot_json->'pending_delivery' = 'null'::jsonb) OR s.snapshot_json#>>'{pending_delivery,request_id}' = w.request_id) ORDER BY w.wake_at, w.session_ref, w.commitment_ref FOR UPDATE OF w, s SKIP LOCKED LIMIT 1",
                &[],
            )
            .await
            .map_err(store_unavailable)?
        else {
            transaction.commit().await.map_err(store_unavailable)?;
            return Ok(None);
        };
        let session_ref: String = row.get(0);
        let commitment_ref: String = row.get(1);
        let wake_at: String = row.get(2);
        let generation: i64 = row.get(3);
        let occurrence_ref: String = row.get(4);
        let request_id: String = row.get(5);
        let prior_fence: i64 = row.get(6);
        let fence = prior_fence.checked_add(1).ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("wake fence exceeds storage range".into())
        })?;
        let lease_token = format!(
            "wake-lease://sha256/{}",
            wake_identity(&[
                &session_ref,
                &commitment_ref,
                &generation.to_string(),
                &fence.to_string(),
                lease_owner,
            ])
        );
        let lease_row = transaction
            .query_one(
                "UPDATE cerebro_agent_wakes SET state = 'leased', lease_owner = $3, lease_token = $4, lease_expires_at = NOW() + make_interval(secs => $5::bigint), fence = $6, attempt_count = attempt_count + 1, last_error = NULL, updated_at = NOW() WHERE session_ref = $1 AND commitment_ref = $2 RETURNING to_char(lease_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
                &[&session_ref, &commitment_ref, &lease_owner, &lease_token, &lease_seconds, &fence],
            )
            .await
            .map_err(store_unavailable)?;
        transaction
            .execute(
                "UPDATE cerebro_agent_sessions SET active_request_id = $2, lease_owner = $3, lease_expires_at = NOW() + make_interval(secs => $4::bigint), updated_at = NOW() WHERE session_ref = $1",
                &[&session_ref, &request_id, &lease_owner, &lease_seconds],
            )
            .await
            .map_err(store_unavailable)?;
        transaction.commit().await.map_err(store_unavailable)?;
        Ok(Some(AgentWakeClaim {
            commitment_ref,
            fence: u64::try_from(fence)
                .map_err(|_| AgentRuntimeError::InvalidRequest("wake fence is invalid".into()))?,
            lease_expires_at: lease_row.get(0),
            lease_owner: lease_owner.into(),
            lease_token,
            occurrence_ref,
            request_id,
            schedule_generation: u64::try_from(generation).map_err(|_| {
                AgentRuntimeError::InvalidRequest("wake generation is invalid".into())
            })?,
            session_ref,
            wake_at,
        }))
    }

    pub async fn prepare_wake_delivery(
        &self,
        claim: &AgentWakeClaim,
        payload_digest: &str,
    ) -> Result<(), AgentRuntimeError> {
        let fence = i64::try_from(claim.fence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("wake fence exceeds storage range".into())
        })?;
        let generation = i64::try_from(claim.schedule_generation).map_err(|_| {
            AgentRuntimeError::InvalidRequest("wake generation exceeds storage range".into())
        })?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        let wake_changed = transaction
            .execute(
                "UPDATE cerebro_agent_wakes SET state = 'awaiting_delivery', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, pending_payload_digest = $7, delivery_ref = NULL, delivery_attempt_ref = NULL, updated_at = NOW() WHERE session_ref = $1 AND commitment_ref = $2 AND schedule_generation = $3 AND fence = $4 AND lease_owner = $5 AND lease_token = $6 AND request_id = $8 AND state = 'leased' AND lease_expires_at > NOW()",
                &[&claim.session_ref, &claim.commitment_ref, &generation, &fence, &claim.lease_owner, &claim.lease_token, &payload_digest, &claim.request_id],
            )
            .await
            .map_err(store_unavailable)?;
        if wake_changed != 1 {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake claim was lost before delivery preparation".into(),
            ));
        }
        let session_changed = transaction
            .execute(
                "UPDATE cerebro_agent_sessions SET active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3",
                &[&claim.session_ref, &claim.request_id, &claim.lease_owner],
            )
            .await
            .map_err(store_unavailable)?;
        if session_changed != 1 {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake session lease was lost before delivery preparation".into(),
            ));
        }
        transaction.commit().await.map_err(store_unavailable)
    }

    pub async fn claim_pending_wake_delivery(
        &self,
        lease_owner: &str,
        lease_seconds: i64,
    ) -> Result<Option<AgentPendingWakeDelivery>, AgentRuntimeError> {
        if lease_owner.trim().is_empty() || lease_seconds <= 0 || lease_seconds > 3_600 {
            return Err(AgentRuntimeError::InvalidRequest(
                "delivery lease identity or duration is invalid".into(),
            ));
        }
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        let Some(row) = transaction
            .query_opt(
                "SELECT w.session_ref, w.commitment_ref, w.schedule_generation, w.request_id, w.pending_payload_digest, w.fence, COALESCE(w.lease_owner = $1 AND w.lease_expires_at > NOW(), FALSE), w.lease_owner, w.lease_token, to_char(w.lease_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"'), w.delivery_ref, w.delivery_attempt_ref, s.snapshot_json FROM cerebro_agent_wakes w JOIN cerebro_agent_sessions s ON s.session_ref = w.session_ref WHERE w.state = 'awaiting_delivery' AND w.request_id IS NOT NULL AND w.pending_payload_digest IS NOT NULL AND s.snapshot_json#>>'{pending_delivery,request_id}' = w.request_id AND (w.lease_expires_at IS NULL OR w.lease_expires_at <= NOW() OR w.lease_owner = $1) ORDER BY w.updated_at, w.session_ref, w.commitment_ref FOR UPDATE OF w, s SKIP LOCKED LIMIT 1",
                &[&lease_owner],
            )
            .await
            .map_err(store_unavailable)?
        else {
            transaction.commit().await.map_err(store_unavailable)?;
            return Ok(None);
        };
        let session_ref: String = row.get(0);
        let commitment_ref: String = row.get(1);
        let generation: i64 = row.get(2);
        let request_id: String = row.get(3);
        let payload_digest: String = row.get(4);
        let prior_fence: i64 = row.get(5);
        let reusable: bool = row.get(6);
        let existing_delivery_ref: Option<String> = row.get(10);
        let existing_attempt_ref: Option<String> = row.get(11);
        let session = decode_session(row.get(12))?;
        let pending = session.pending_delivery.as_ref().ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("wake has no pending delivery payload".into())
        })?;
        if pending.request_id != request_id
            || message_digest(&pending.draft.message) != payload_digest
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake delivery identity does not match the durable payload".into(),
            ));
        }
        let mode = if existing_attempt_ref.is_some() {
            AgentWakeDeliveryMode::Reconcile
        } else {
            AgentWakeDeliveryMode::Send
        };
        let delivery_ref = existing_delivery_ref.unwrap_or_else(|| {
            format!(
                "wake-delivery://sha256/{}",
                wake_identity(&[
                    &session_ref,
                    &commitment_ref,
                    &generation.to_string(),
                    &request_id,
                    &payload_digest,
                ])
            )
        });
        let delivery_attempt_ref = existing_attempt_ref.unwrap_or_else(|| {
            format!(
                "wake-delivery-attempt://sha256/{}",
                wake_identity(&[&delivery_ref, "attempt:1"])
            )
        });
        let (fence, lease_token, lease_expires_at) = if reusable {
            (
                prior_fence,
                row.get::<_, Option<String>>(8).ok_or_else(|| {
                    AgentRuntimeError::InvalidRequest(
                        "reusable wake delivery lease has no token".into(),
                    )
                })?,
                row.get::<_, Option<String>>(9).ok_or_else(|| {
                    AgentRuntimeError::InvalidRequest(
                        "reusable wake delivery lease has no expiry".into(),
                    )
                })?,
            )
        } else {
            let fence = prior_fence.checked_add(1).ok_or_else(|| {
                AgentRuntimeError::InvalidRequest("wake fence exceeds storage range".into())
            })?;
            let lease_token = format!(
                "wake-delivery-lease://sha256/{}",
                wake_identity(&[
                    &session_ref,
                    &commitment_ref,
                    &generation.to_string(),
                    &fence.to_string(),
                    lease_owner,
                ])
            );
            let lease_row = transaction
                .query_one(
                    "UPDATE cerebro_agent_wakes SET lease_owner = $3, lease_token = $4, lease_expires_at = NOW() + make_interval(secs => $5::bigint), fence = $6, delivery_ref = COALESCE(delivery_ref, $7), delivery_attempt_ref = COALESCE(delivery_attempt_ref, $8), updated_at = NOW() WHERE session_ref = $1 AND commitment_ref = $2 AND state = 'awaiting_delivery' RETURNING to_char(lease_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')",
                    &[&session_ref, &commitment_ref, &lease_owner, &lease_token, &lease_seconds, &fence, &delivery_ref, &delivery_attempt_ref],
                )
                .await
                .map_err(store_unavailable)?;
            (fence, lease_token, lease_row.get(0))
        };
        transaction.commit().await.map_err(store_unavailable)?;
        Ok(Some(AgentPendingWakeDelivery {
            lease: AgentWakeDeliveryLease {
                commitment_ref,
                delivery_attempt_ref,
                delivery_ref,
                fence: u64::try_from(fence).map_err(|_| {
                    AgentRuntimeError::InvalidRequest("wake fence is invalid".into())
                })?,
                lease_expires_at,
                lease_owner: lease_owner.into(),
                lease_token,
                payload_digest,
                request_id,
                schedule_generation: u64::try_from(generation).map_err(|_| {
                    AgentRuntimeError::InvalidRequest("wake generation is invalid".into())
                })?,
                session_ref,
            },
            markdown: pending.draft.message.clone(),
            mode,
            tenant_id: session.tenant_id,
            thread_ref: session.thread_ref,
        }))
    }

    pub async fn fail_wake(
        &self,
        claim: &AgentWakeClaim,
        error: &str,
    ) -> Result<(), AgentRuntimeError> {
        let fence = i64::try_from(claim.fence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("wake fence exceeds storage range".into())
        })?;
        let generation = i64::try_from(claim.schedule_generation).map_err(|_| {
            AgentRuntimeError::InvalidRequest("wake generation exceeds storage range".into())
        })?;
        let error = error.chars().take(2_048).collect::<String>();
        let changed = self
            .client
            .lock()
            .await
            .execute(
                "UPDATE cerebro_agent_wakes SET state = CASE WHEN attempt_count >= 5 THEN 'failed' ELSE 'scheduled' END, lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, last_error = $7, updated_at = NOW() WHERE session_ref = $1 AND commitment_ref = $2 AND schedule_generation = $3 AND fence = $4 AND lease_owner = $5 AND lease_token = $6 AND state = 'leased'",
                &[&claim.session_ref, &claim.commitment_ref, &generation, &fence, &claim.lease_owner, &claim.lease_token, &error],
            )
            .await
            .map_err(store_unavailable)?;
        if changed != 1 {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake claim was lost before failure recording".into(),
            ));
        }
        self.release_turn(&claim.session_ref, &claim.request_id, &claim.lease_owner)
            .await
    }

    pub async fn append_wake_fenced(
        &self,
        claim: &AgentWakeClaim,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError> {
        self.append_checked(
            &claim.session_ref,
            expected_sequence,
            events,
            Some(claim),
            None,
        )
        .await
    }

    pub async fn append_wake_delivery_fenced(
        &self,
        lease: &AgentWakeDeliveryLease,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError> {
        self.append_checked(
            &lease.session_ref,
            expected_sequence,
            events,
            None,
            Some(lease),
        )
        .await
    }

    async fn append_checked(
        &self,
        session_ref: &str,
        expected_sequence: u64,
        events: &[SessionEventRecord],
        wake_claim: Option<&AgentWakeClaim>,
        wake_delivery_lease: Option<&AgentWakeDeliveryLease>,
    ) -> Result<(), AgentRuntimeError> {
        if events.is_empty() {
            return Ok(());
        }
        let expected_sequence = i64::try_from(expected_sequence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("session sequence exceeds storage range".into())
        })?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        if let Some(claim) = wake_claim {
            let generation = i64::try_from(claim.schedule_generation).map_err(|_| {
                AgentRuntimeError::InvalidRequest("wake generation exceeds storage range".into())
            })?;
            let fence = i64::try_from(claim.fence).map_err(|_| {
                AgentRuntimeError::InvalidRequest("wake fence exceeds storage range".into())
            })?;
            let current = transaction
                .query_opt(
                    "SELECT 1 FROM cerebro_agent_wakes WHERE session_ref = $1 AND commitment_ref = $2 AND schedule_generation = $3 AND fence = $4 AND lease_owner = $5 AND lease_token = $6 AND request_id = $7 AND state = 'leased' AND lease_expires_at > NOW() FOR UPDATE",
                    &[&claim.session_ref, &claim.commitment_ref, &generation, &fence, &claim.lease_owner, &claim.lease_token, &claim.request_id],
                )
                .await
                .map_err(store_unavailable)?;
            if current.is_none() {
                return Err(AgentRuntimeError::InvalidRequest(
                    "wake fence or lease is no longer current".into(),
                ));
            }
        }
        if let Some(lease) = wake_delivery_lease {
            let generation = i64::try_from(lease.schedule_generation).map_err(|_| {
                AgentRuntimeError::InvalidRequest("wake generation exceeds storage range".into())
            })?;
            let current = transaction
                .query_opt(
                    "SELECT 1 FROM cerebro_agent_wakes WHERE session_ref = $1 AND commitment_ref = $2 AND schedule_generation = $3 AND request_id = $4 AND pending_payload_digest = $5 AND delivery_ref = $6 AND delivery_attempt_ref = $7 AND state = 'awaiting_delivery' FOR UPDATE",
                    &[&lease.session_ref, &lease.commitment_ref, &generation, &lease.request_id, &lease.payload_digest, &lease.delivery_ref, &lease.delivery_attempt_ref],
                )
                .await
                .map_err(store_unavailable)?;
            if current.is_none() {
                return Err(AgentRuntimeError::InvalidRequest(
                    "wake delivery identity is no longer current".into(),
                ));
            }
        }
        let row = transaction
            .query_opt(
                "SELECT snapshot_json, last_sequence FROM cerebro_agent_sessions WHERE session_ref = $1 FOR UPDATE",
                &[&session_ref],
            )
            .await
            .map_err(store_unavailable)?
            .ok_or_else(|| AgentRuntimeError::InvalidRequest("session does not exist".into()))?;
        let stored_sequence: i64 = row.get(1);
        if stored_sequence != expected_sequence {
            return Err(AgentRuntimeError::InvalidRequest(
                "session changed while this turn was running".into(),
            ));
        }
        let session = decode_session(row.get(0))?;
        let updated = apply_session_events(&session, events)?;
        for event in events {
            insert_event(&transaction, event).await?;
            if let cerebro_agent_runtime::session::SessionEvent::DeliveryRecorded {
                request_id,
                payload_digest,
                ..
            } = &event.event
            {
                let wake_completions = transaction
                    .execute(
                        "UPDATE cerebro_agent_wakes SET state = 'completed', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND request_id = $2 AND pending_payload_digest = $3 AND state = 'awaiting_delivery'",
                        &[&session_ref, request_id, payload_digest],
                    )
                    .await
                    .map_err(store_unavailable)?;
                if wake_delivery_lease.is_some() && wake_completions != 1 {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "wake delivery did not complete its exact pending occurrence".into(),
                    ));
                }
                if wake_delivery_lease.is_none() && wake_completions != 0 {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "wake delivery requires an exact delivery lease".into(),
                    ));
                }
            }
        }
        let snapshot = serde_json::to_value(&updated).map_err(invalid_snapshot)?;
        let last_sequence = updated.events.last().map_or(0, |event| event.sequence);
        let last_sequence = i64::try_from(last_sequence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("session sequence exceeds storage range".into())
        })?;
        transaction
            .execute(
                "UPDATE cerebro_agent_sessions SET snapshot_json = $2, last_sequence = $3, updated_at = NOW() WHERE session_ref = $1",
                &[&session_ref, &snapshot, &last_sequence],
            )
            .await
            .map_err(store_unavailable)?;
        project_session_state(&transaction, &updated).await?;
        transaction.commit().await.map_err(store_unavailable)
    }
}

pub struct PostgresTurnJournal {
    store: std::sync::Arc<PostgresAgentSessionStore>,
    session_ref: String,
    sequence: Mutex<u64>,
    wake_claim: Option<AgentWakeClaim>,
}

impl PostgresTurnJournal {
    pub fn new(
        store: std::sync::Arc<PostgresAgentSessionStore>,
        session_ref: String,
        sequence: u64,
    ) -> Self {
        Self {
            store,
            session_ref,
            sequence: Mutex::new(sequence),
            wake_claim: None,
        }
    }

    pub fn new_wake(
        store: std::sync::Arc<PostgresAgentSessionStore>,
        claim: AgentWakeClaim,
        sequence: u64,
    ) -> Self {
        Self {
            session_ref: claim.session_ref.clone(),
            store,
            sequence: Mutex::new(sequence),
            wake_claim: Some(claim),
        }
    }
}

#[async_trait]
impl SessionJournal for PostgresTurnJournal {
    async fn record(&self, event: &SessionEventRecord) -> Result<(), AgentRuntimeError> {
        let mut sequence = self.sequence.lock().await;
        if event.session_ref != self.session_ref || event.sequence != sequence.saturating_add(1) {
            return Err(AgentRuntimeError::InvalidRequest(
                "turn journal received a non-contiguous event".into(),
            ));
        }
        if let Some(claim) = &self.wake_claim {
            self.store
                .append_wake_fenced(claim, *sequence, std::slice::from_ref(event))
                .await?;
        } else {
            self.store
                .append(&self.session_ref, *sequence, std::slice::from_ref(event))
                .await?;
        }
        *sequence = event.sequence;
        Ok(())
    }
}

#[async_trait]
impl SessionStore for PostgresAgentSessionStore {
    async fn create(&self, session: &AgentSession) -> Result<(), AgentRuntimeError> {
        let snapshot = serde_json::to_value(session).map_err(invalid_snapshot)?;
        let last_sequence = session.events.last().map_or(0, |event| event.sequence);
        let last_sequence = i64::try_from(last_sequence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("session sequence exceeds storage range".into())
        })?;
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        transaction
            .execute(
                "INSERT INTO cerebro_agent_sessions (session_ref, tenant_id, thread_ref, snapshot_json, last_sequence) VALUES ($1, $2, $3, $4, $5)",
                &[&session.session_ref, &session.tenant_id, &session.thread_ref, &snapshot, &last_sequence],
            )
            .await
            .map_err(store_unavailable)?;
        for event in &session.events {
            insert_event(&transaction, event).await?;
        }
        project_session_state(&transaction, session).await?;
        transaction.commit().await.map_err(store_unavailable)
    }

    async fn load(&self, session_ref: &str) -> Result<Option<AgentSession>, AgentRuntimeError> {
        let row = self
            .client
            .lock()
            .await
            .query_opt(
                "SELECT snapshot_json FROM cerebro_agent_sessions WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .map_err(store_unavailable)?;
        row.map(|row| decode_session(row.get(0))).transpose()
    }

    async fn append(
        &self,
        session_ref: &str,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError> {
        self.append_checked(session_ref, expected_sequence, events, None, None)
            .await
    }
}

async fn project_session_state(
    transaction: &tokio_postgres::Transaction<'_>,
    session: &AgentSession,
) -> Result<(), AgentRuntimeError> {
    let active_commitments = session
        .mission
        .commitments
        .iter()
        .filter(|commitment| {
            commitment.owner == WorkOwner::Cerebro
                && !matches!(
                    commitment.status,
                    CommitmentStatus::Completed | CommitmentStatus::Cancelled
                )
                && commitment.wake_at.is_some()
        })
        .collect::<Vec<_>>();
    let active_refs = active_commitments
        .iter()
        .map(|commitment| commitment.commitment_ref.clone())
        .collect::<Vec<_>>();
    transaction
        .execute(
            "UPDATE cerebro_agent_wakes SET state = 'cancelled', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, pending_payload_digest = NULL, delivery_ref = NULL, delivery_attempt_ref = NULL, updated_at = NOW() WHERE session_ref = $1 AND state IN ('scheduled', 'leased', 'awaiting_delivery', 'failed') AND NOT (commitment_ref = ANY($2))",
            &[&session.session_ref, &active_refs],
        )
        .await
        .map_err(store_unavailable)?;
    for commitment in active_commitments {
        let wake_at = commitment
            .wake_at
            .as_deref()
            .expect("active scheduled commitments have a wake time");
        let commitment_bytes = serde_json::to_vec(commitment).map_err(invalid_snapshot)?;
        let commitment_digest = format!(
            "sha256:{}",
            Sha256::digest(&commitment_bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let identity = wake_identity(&[
            &session.session_ref,
            &commitment.commitment_ref,
            wake_at,
            &commitment_digest,
        ]);
        let occurrence_ref = format!("agent-wake://sha256/{identity}");
        let request_id = format!("agent-wake-request-{identity}");
        transaction
            .execute(
                "INSERT INTO cerebro_agent_wakes (session_ref, commitment_ref, wake_at, state, schedule_generation, occurrence_ref, request_id, commitment_digest) VALUES ($1, $2, ($3::text)::timestamptz, 'scheduled', 1, $4, $5, $6) ON CONFLICT (session_ref, commitment_ref) DO UPDATE SET wake_at = EXCLUDED.wake_at, schedule_generation = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN cerebro_agent_wakes.schedule_generation + 1 ELSE cerebro_agent_wakes.schedule_generation END, occurrence_ref = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN EXCLUDED.occurrence_ref ELSE cerebro_agent_wakes.occurrence_ref END, request_id = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN EXCLUDED.request_id ELSE cerebro_agent_wakes.request_id END, commitment_digest = EXCLUDED.commitment_digest, state = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN 'scheduled' ELSE cerebro_agent_wakes.state END, lease_owner = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN NULL ELSE cerebro_agent_wakes.lease_owner END, lease_token = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN NULL ELSE cerebro_agent_wakes.lease_token END, lease_expires_at = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN NULL ELSE cerebro_agent_wakes.lease_expires_at END, pending_payload_digest = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN NULL ELSE cerebro_agent_wakes.pending_payload_digest END, delivery_ref = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN NULL ELSE cerebro_agent_wakes.delivery_ref END, delivery_attempt_ref = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN NULL ELSE cerebro_agent_wakes.delivery_attempt_ref END, last_error = CASE WHEN cerebro_agent_wakes.commitment_digest IS DISTINCT FROM EXCLUDED.commitment_digest OR cerebro_agent_wakes.wake_at IS DISTINCT FROM EXCLUDED.wake_at THEN NULL ELSE cerebro_agent_wakes.last_error END, updated_at = NOW()",
                &[&session.session_ref, &commitment.commitment_ref, &wake_at, &occurrence_ref, &request_id, &commitment_digest],
            )
            .await
            .map_err(store_unavailable)?;
    }
    for memory in &session.memories {
        let memory_json = serde_json::to_value(memory).map_err(invalid_snapshot)?;
        transaction
            .execute(
                "INSERT INTO cerebro_agent_memories (session_ref, memory_ref, memory_json) VALUES ($1, $2, $3) ON CONFLICT (session_ref, memory_ref) DO UPDATE SET memory_json = EXCLUDED.memory_json, updated_at = NOW()",
                &[&session.session_ref, &memory.memory_ref, &memory_json],
            )
            .await
            .map_err(store_unavailable)?;
    }
    Ok(())
}

async fn insert_event(
    transaction: &tokio_postgres::Transaction<'_>,
    event: &SessionEventRecord,
) -> Result<(), AgentRuntimeError> {
    let sequence = i64::try_from(event.sequence).map_err(|_| {
        AgentRuntimeError::InvalidRequest("session sequence exceeds storage range".into())
    })?;
    let event_json = serde_json::to_value(event).map_err(invalid_snapshot)?;
    transaction
        .execute(
            "INSERT INTO cerebro_agent_session_events (session_ref, sequence, event_json, occurred_at) VALUES ($1, $2, $3, ($4::text)::timestamptz)",
            &[&event.session_ref, &sequence, &event_json, &event.occurred_at],
        )
        .await
        .map_err(store_unavailable)?;
    Ok(())
}

fn decode_session(value: Value) -> Result<AgentSession, AgentRuntimeError> {
    serde_json::from_value(value).map_err(invalid_snapshot)
}

fn invalid_snapshot(error: serde_json::Error) -> AgentRuntimeError {
    AgentRuntimeError::InvalidRequest(format!("stored agent session is invalid: {error}"))
}

fn store_unavailable(error: impl std::fmt::Display) -> AgentRuntimeError {
    AgentRuntimeError::ModelUnavailable(format!("agent session store unavailable: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_agent_runtime::{
        FinalState,
        session::{
            Commitment, GroundedDraft, MissionState, SessionEvent, SessionMessage,
            SessionMessageRole, SessionStatus,
        },
    };

    #[test]
    fn schema_has_isolated_event_and_wake_records() {
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("UNIQUE (tenant_id, thread_ref)"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("PRIMARY KEY (session_ref, sequence)"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("lease_expires_at TIMESTAMPTZ"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("CHECK (state IN"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("'awaiting_delivery'"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("schedule_generation BIGINT"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("fence BIGINT"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("lease_token TEXT"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("delivery_ref TEXT"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("delivery_attempt_ref TEXT"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("cerebro_agent_memories"));
    }

    #[tokio::test]
    #[ignore = "requires CEREBRO_TEST_POSTGRES_DSN"]
    async fn postgres_wake_claim_is_fenced_until_exact_delivery() {
        let Ok(dsn) = std::env::var("CEREBRO_TEST_POSTGRES_DSN") else {
            return;
        };
        let store = PostgresAgentSessionStore::connect(&dsn).await.unwrap();
        let session_ref = "agent-session:postgres-wake-fence-test";
        store
            .client
            .lock()
            .await
            .execute(
                "DELETE FROM cerebro_agent_sessions WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .unwrap();
        let commitment = Commitment {
            commitment_ref: "commitment:postgres-wake".into(),
            summary: "Run the persisted Postgres wake check.".into(),
            owner: WorkOwner::Cerebro,
            status: CommitmentStatus::Waiting,
            next_action: Some("Read the current state.".into()),
            blocker: None,
            acceptance_criteria: vec!["A current state is observed.".into()],
            artifact_refs: Vec::new(),
            required_tool_ids: Vec::new(),
            wake_at: Some("2020-01-01T00:00:00Z".into()),
            verification: Some("The current observation is recorded.".into()),
        };
        let session = AgentSession {
            schema_version: cerebro_agent_runtime::session::AGENT_SESSION_V2.into(),
            session_ref: session_ref.into(),
            tenant_id: "tenant:postgres-wake".into(),
            thread_ref: "thread:postgres-wake".into(),
            mission: MissionState {
                mission_ref: "mission:postgres-wake".into(),
                objective: "Verify durable wake fencing.".into(),
                desired_outcome: "One claimed and delivered wake.".into(),
                resolved_scope: Vec::new(),
                scope_assumptions: Vec::new(),
                acceptance_criteria: vec!["Delivery is acknowledged.".into()],
                commitments: vec![commitment],
                open_loops: Vec::new(),
                status: SessionStatus::WaitingForExternal,
            },
            messages: vec![SessionMessage {
                role: SessionMessageRole::User,
                message_ref: "message:postgres-wake".into(),
                actor_ref: "user:postgres-wake".into(),
                text: "Keep watching this boundary.".into(),
                received_at: "2020-01-01T00:00:00Z".into(),
            }],
            events: Vec::new(),
            effect_authorizations: Vec::new(),
            pending_delivery: None,
            memories: Vec::new(),
        };
        store.create(&session).await.unwrap();

        let claim = store
            .claim_due_wake("worker:postgres-wake", 60)
            .await
            .unwrap()
            .expect("the due wake should be claimed");
        assert!(
            store
                .claim_due_wake("worker:competing", 60)
                .await
                .unwrap()
                .is_none()
        );
        let wake_event = SessionEventRecord {
            schema_version: cerebro_agent_runtime::session::AGENT_SESSION_EVENT_V2.into(),
            session_ref: session_ref.into(),
            sequence: 1,
            occurred_at: "2020-01-01T00:01:00Z".into(),
            event: SessionEvent::WakeTriggered {
                request_id: claim.request_id.clone(),
                commitment_ref: claim.commitment_ref.clone(),
                occurrence_ref: claim.occurrence_ref.clone(),
                scheduled_for: claim.wake_at.clone(),
            },
        };
        let mut stale = claim.clone();
        stale.fence = stale.fence.saturating_sub(1);
        assert!(
            store
                .append_wake_fenced(&stale, 0, std::slice::from_ref(&wake_event))
                .await
                .is_err()
        );
        store
            .append_wake_fenced(&claim, 0, std::slice::from_ref(&wake_event))
            .await
            .unwrap();

        let mut completed_mission = session.mission.clone();
        completed_mission.commitments[0].status = CommitmentStatus::Completed;
        completed_mission.commitments[0].next_action = None;
        completed_mission.commitments[0].wake_at = None;
        completed_mission.status = SessionStatus::Completed;
        let draft = GroundedDraft {
            state: FinalState::Answered,
            message: "The scheduled check completed.".into(),
            claims: Vec::new(),
            coverage_notice: None,
            question: None,
            mission: completed_mission,
            memory_updates: Vec::new(),
            presentation_ready: true,
        };
        let draft_event = SessionEventRecord {
            schema_version: cerebro_agent_runtime::session::AGENT_SESSION_EVENT_V2.into(),
            session_ref: session_ref.into(),
            sequence: 2,
            occurred_at: "2020-01-01T00:02:00Z".into(),
            event: SessionEvent::DraftProduced {
                request_id: claim.request_id.clone(),
                draft,
            },
        };
        store
            .append_wake_fenced(&claim, 1, std::slice::from_ref(&draft_event))
            .await
            .unwrap();
        let payload_digest =
            cerebro_agent_runtime::session::message_digest("The scheduled check completed.");
        store
            .prepare_wake_delivery(&claim, &payload_digest)
            .await
            .unwrap();
        let pending_delivery = store
            .claim_pending_wake_delivery("delivery-worker:postgres-wake", 60)
            .await
            .unwrap()
            .expect("the pending wake payload should be claimable without rerunning the turn");
        assert_eq!(pending_delivery.markdown, "The scheduled check completed.");
        assert_eq!(pending_delivery.thread_ref, session.thread_ref);
        assert_eq!(pending_delivery.lease.payload_digest, payload_digest);
        assert_eq!(pending_delivery.mode, AgentWakeDeliveryMode::Send);
        let replayed_delivery = store
            .claim_pending_wake_delivery("delivery-worker:postgres-wake", 60)
            .await
            .unwrap()
            .expect("the same delivery worker should recover its exact lease");
        assert_eq!(replayed_delivery.lease, pending_delivery.lease);
        assert_eq!(replayed_delivery.mode, AgentWakeDeliveryMode::Reconcile);
        assert!(
            store
                .claim_pending_wake_delivery("delivery-worker:competing", 60)
                .await
                .unwrap()
                .is_none()
        );
        store
            .client
            .lock()
            .await
            .execute(
                "UPDATE cerebro_agent_wakes SET lease_expires_at = NOW() - INTERVAL '1 second' WHERE session_ref = $1 AND commitment_ref = $2",
                &[&session_ref, &claim.commitment_ref],
            )
            .await
            .unwrap();
        let recovered_delivery = store
            .claim_pending_wake_delivery("delivery-worker:competing", 60)
            .await
            .unwrap()
            .expect("an expired possible send must remain available for reconciliation");
        assert_eq!(recovered_delivery.mode, AgentWakeDeliveryMode::Reconcile);
        assert_eq!(
            recovered_delivery.lease.delivery_attempt_ref,
            pending_delivery.lease.delivery_attempt_ref
        );
        assert_eq!(
            recovered_delivery.lease.delivery_ref,
            pending_delivery.lease.delivery_ref
        );
        assert!(recovered_delivery.lease.fence > pending_delivery.lease.fence);
        let delivery_events = vec![
            SessionEventRecord {
                schema_version: cerebro_agent_runtime::session::AGENT_SESSION_EVENT_V2.into(),
                session_ref: session_ref.into(),
                sequence: 3,
                occurred_at: "2020-01-01T00:03:00Z".into(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: claim.request_id.clone(),
                    transport: "test".into(),
                    delivery_ref: "delivery:postgres-wake".into(),
                    payload_digest: payload_digest.clone(),
                },
            },
            SessionEventRecord {
                schema_version: cerebro_agent_runtime::session::AGENT_SESSION_EVENT_V2.into(),
                session_ref: session_ref.into(),
                sequence: 4,
                occurred_at: "2020-01-01T00:03:00Z".into(),
                event: SessionEvent::TurnCompleted {
                    request_id: claim.request_id.clone(),
                    state: FinalState::Answered,
                },
            },
        ];
        assert!(
            store
                .append(session_ref, 2, &delivery_events)
                .await
                .is_err()
        );
        let mut changed_delivery = pending_delivery.lease.clone();
        changed_delivery.delivery_attempt_ref.push_str(":changed");
        assert!(
            store
                .append_wake_delivery_fenced(&changed_delivery, 2, &delivery_events)
                .await
                .is_err()
        );
        // An exact Slack acceptance receipt can arrive after its delivery lease expires.
        store
            .append_wake_delivery_fenced(&pending_delivery.lease, 2, &delivery_events)
            .await
            .unwrap();
        let row = store
            .client
            .lock()
            .await
            .query_one(
                "SELECT state, schedule_generation, fence FROM cerebro_agent_wakes WHERE session_ref = $1 AND commitment_ref = $2",
                &[&session_ref, &claim.commitment_ref],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "completed");
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(
            u64::try_from(row.get::<_, i64>(2)).unwrap(),
            recovered_delivery.lease.fence
        );
        store
            .client
            .lock()
            .await
            .execute(
                "DELETE FROM cerebro_agent_sessions WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .unwrap();
    }
}
