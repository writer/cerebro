use async_trait::async_trait;
use cerebro_agent_runtime::{
    AgentRuntimeError, FinalState,
    session::{
        AGENT_SESSION_EVENT_V2, AgentSession, CommitmentStatus, DeliveryDisposition, GroundedDraft,
        MemoryKind, MemoryUpdate, SessionEvent, SessionEventRecord, SessionJournal, SessionMessage,
        SessionMessageRole, SessionStatus, SessionStore, WorkOwner, apply_session_events,
        message_digest,
    },
};
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Mutex;
use tokio_postgres::{Client, GenericClient};

use super::slack_mrkdwn::render_slack_mrkdwn;

const POSTGRES_AGENT_SESSION_SCHEMA_LOCK_KEY: i64 = 0x4342_524f_5345_5353;

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
CREATE TABLE IF NOT EXISTS cerebro_agent_thread_contexts (
  session_ref TEXT NOT NULL REFERENCES cerebro_agent_sessions(session_ref) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  actor_ref TEXT NOT NULL,
  context_scope_ref TEXT NOT NULL,
  thread_ref TEXT NOT NULL,
  context_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (session_ref, actor_ref)
);
CREATE INDEX IF NOT EXISTS cerebro_agent_thread_contexts_recall_idx
  ON cerebro_agent_thread_contexts (tenant_id, actor_ref, context_scope_ref, updated_at DESC);
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentWakeFailureDisposition {
    RetryScheduled,
    ExhaustedAwaitingDelivery,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentThreadTranscriptMessage {
    pub actor_ref: String,
    pub message_ref: String,
    pub received_at: String,
    pub role: SessionMessageRole,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentThreadTranscriptPage {
    pub messages: Vec<AgentThreadTranscriptMessage>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AgentPriorThreadContext {
    pub context: Value,
    pub thread_ref: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AgentPriorThreadContextPage {
    pub next_cursor: Option<String>,
    pub threads: Vec<AgentPriorThreadContext>,
}

pub struct AgentPriorThreadSearch<'a> {
    pub actor_ref: &'a str,
    pub context_scope_ref: &'a str,
    pub cursor: Option<&'a str>,
    pub exclude_session_ref: &'a str,
    pub limit: usize,
    pub query: &'a str,
    pub tenant_id: &'a str,
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

#[derive(Clone, Copy)]
struct OperatorTurnFence<'a> {
    request_id: &'a str,
    lease_owner: &'a str,
    lease_seconds: i64,
}

#[derive(Clone, Copy, Default)]
enum SessionAppendFence<'a> {
    Operator(OperatorTurnFence<'a>),
    OperatorFinal(OperatorTurnFence<'a>),
    DeliveryCompletion(&'a str),
    WakeClaim(&'a AgentWakeClaim),
    WakeDelivery(&'a AgentWakeDeliveryLease),
    #[default]
    None,
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
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&POSTGRES_AGENT_SESSION_SCHEMA_LOCK_KEY],
            )
            .await
            .map_err(store_unavailable)?;
        transaction
            .batch_execute(POSTGRES_AGENT_SESSION_SCHEMA)
            .await
            .map_err(store_unavailable)?;
        transaction.commit().await.map_err(store_unavailable)
    }

    pub async fn load_by_thread(
        &self,
        tenant_id: &str,
        thread_ref: &str,
    ) -> Result<Option<AgentSession>, AgentRuntimeError> {
        let client = self.client.lock().await;
        let row = client
            .query_opt(
                "SELECT session_ref, snapshot_json, last_sequence FROM cerebro_agent_sessions WHERE tenant_id = $1 AND thread_ref = $2",
                &[&tenant_id, &thread_ref],
            )
            .await
            .map_err(store_unavailable)?;
        match row {
            Some(row) => {
                let session_ref: String = row.get(0);
                hydrate_session_events(&*client, &session_ref, row.get(1), row.get(2))
                    .await
                    .map(|(session, _)| Some(session))
            }
            None => Ok(None),
        }
    }

    pub async fn read_owned_thread_transcript(
        &self,
        tenant_id: &str,
        thread_ref: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<AgentThreadTranscriptPage, AgentRuntimeError> {
        let session = self
            .load_by_thread(tenant_id, thread_ref)
            .await?
            .ok_or_else(|| {
                AgentRuntimeError::InvalidRequest("Slack thread session does not exist".into())
            })?;
        thread_transcript_page(&session.messages, cursor, limit)
    }

    pub async fn search_prior_thread_contexts(
        &self,
        search: AgentPriorThreadSearch<'_>,
    ) -> Result<AgentPriorThreadContextPage, AgentRuntimeError> {
        if search.actor_ref.trim().is_empty()
            || search.context_scope_ref.trim().is_empty()
            || search.query.len() > 256
            || !(1..=4).contains(&search.limit)
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "prior Slack thread search input is invalid".into(),
            ));
        }
        let normalized_query = search.query.trim();
        let requested = i64::try_from(search.limit.saturating_add(1)).map_err(|_| {
            AgentRuntimeError::InvalidRequest("prior Slack thread limit is invalid".into())
        })?;
        let parsed_cursor = search.cursor.map(parse_prior_thread_cursor).transpose()?;
        let rows = if let Some((updated_at, session_ref)) = parsed_cursor.as_ref() {
            self.client
                .lock()
                .await
                .query(
                    "SELECT session_ref, thread_ref, context_json, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM cerebro_agent_thread_contexts WHERE tenant_id = $1 AND actor_ref = $2 AND context_scope_ref = $3 AND session_ref <> $4 AND ($5 = '' OR position(lower($5) in lower(context_json::text)) > 0) AND (updated_at, session_ref) < (($6::text)::timestamptz, $7) ORDER BY updated_at DESC, session_ref DESC LIMIT $8",
                    &[&search.tenant_id, &search.actor_ref, &search.context_scope_ref, &search.exclude_session_ref, &normalized_query, &updated_at, &session_ref, &requested],
                )
                .await
                .map_err(store_unavailable)?
        } else {
            self.client
                .lock()
                .await
                .query(
                    "SELECT session_ref, thread_ref, context_json, to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM cerebro_agent_thread_contexts WHERE tenant_id = $1 AND actor_ref = $2 AND context_scope_ref = $3 AND session_ref <> $4 AND ($5 = '' OR position(lower($5) in lower(context_json::text)) > 0) ORDER BY updated_at DESC, session_ref DESC LIMIT $6",
                    &[&search.tenant_id, &search.actor_ref, &search.context_scope_ref, &search.exclude_session_ref, &normalized_query, &requested],
                )
                .await
                .map_err(store_unavailable)?
        };
        let has_more = rows.len() > search.limit;
        let mut threads = rows
            .into_iter()
            .take(search.limit)
            .map(|row| {
                let session_ref: String = row.get(0);
                let thread = AgentPriorThreadContext {
                    context: row.get(2),
                    thread_ref: row.get(1),
                    updated_at: row.get(3),
                };
                (session_ref, thread)
            })
            .collect::<Vec<_>>();
        let next_cursor = if has_more {
            threads
                .last()
                .map(|(session_ref, thread)| prior_thread_cursor(&thread.updated_at, session_ref))
                .transpose()?
        } else {
            None
        };
        for (_, thread) in &mut threads {
            bound_prior_thread_context(&mut thread.context);
        }
        Ok(AgentPriorThreadContextPage {
            next_cursor,
            threads: threads.into_iter().map(|(_, thread)| thread).collect(),
        })
    }

    pub async fn bind_context_scope(
        &self,
        session_ref: &str,
        context_scope_ref: &str,
    ) -> Result<(), AgentRuntimeError> {
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT snapshot_json, last_sequence FROM cerebro_agent_sessions WHERE session_ref = $1 FOR UPDATE",
                &[&session_ref],
            )
            .await
            .map_err(store_unavailable)?
            .ok_or_else(|| AgentRuntimeError::InvalidRequest("session does not exist".into()))?;
        let (mut session, legacy_events_need_backfill) =
            hydrate_session_events(&transaction, session_ref, row.get(0), row.get(1)).await?;
        if session
            .context_scope_ref
            .as_deref()
            .is_some_and(|stored| stored != context_scope_ref)
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "conversation scope does not match the stored Slack session".into(),
            ));
        }
        if legacy_events_need_backfill {
            backfill_legacy_events(&transaction, &session.events).await?;
        }
        session.context_scope_ref = Some(context_scope_ref.into());
        let snapshot = encode_session_snapshot(&session)?;
        transaction
            .execute(
                "UPDATE cerebro_agent_sessions SET snapshot_json = $2, updated_at = NOW() WHERE session_ref = $1",
                &[&session_ref, &snapshot],
            )
            .await
            .map_err(store_unavailable)?;
        transaction.commit().await.map_err(store_unavailable)
    }

    pub async fn recall_thread_contexts(
        &self,
        tenant_id: &str,
        actor_ref: &str,
        context_scope_ref: &str,
        exclude_session_ref: &str,
        limit: i64,
    ) -> Result<Vec<MemoryUpdate>, AgentRuntimeError> {
        if !(1..=24).contains(&limit) {
            return Err(AgentRuntimeError::InvalidRequest(
                "prior-thread recall limit is invalid".into(),
            ));
        }
        let rows = self
            .client
            .lock()
            .await
            .query(
                "SELECT session_ref, context_json FROM cerebro_agent_thread_contexts WHERE tenant_id = $1 AND actor_ref = $2 AND context_scope_ref = $3 AND session_ref <> $4 ORDER BY updated_at DESC, session_ref DESC LIMIT $5",
                &[&tenant_id, &actor_ref, &context_scope_ref, &exclude_session_ref, &limit],
            )
            .await
            .map_err(store_unavailable)?;
        rows.into_iter()
            .map(|row| {
                let session_ref: String = row.get(0);
                let context: Value = row.get(1);
                let digest = Sha256::digest(session_ref.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let statement = bounded_context_text(
                    &serde_json::to_string(&context).map_err(invalid_snapshot)?,
                    3_500,
                );
                Ok(MemoryUpdate {
                    memory_ref: format!("recalled-thread:{digest}"),
                    kind: MemoryKind::Handoff,
                    statement: format!(
                        "Prior Slack thread context from the same operator and channel: {statement}"
                    ),
                    evidence_atom_refs: Vec::new(),
                    promotion_requested: false,
                })
            })
            .collect()
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
        let changed = self
            .client
            .lock()
            .await
            .execute(
                "UPDATE cerebro_agent_sessions SET active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3",
                &[&session_ref, &request_id, &lease_owner],
            )
            .await
            .map_err(store_unavailable)?;
        if changed != 1 {
            return Err(AgentRuntimeError::InvalidRequest(
                "turn lease release did not match the exact active request and owner".into(),
            ));
        }
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

    pub async fn complete_wake_silently(
        &self,
        claim: &AgentWakeClaim,
        payload_digest: &str,
        final_state: FinalState,
    ) -> Result<(), AgentRuntimeError> {
        let session = self.load(&claim.session_ref).await?.ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("wake session does not exist".into())
        })?;
        let pending = session.pending_delivery.as_ref().ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("silent wake has no pending draft".into())
        })?;
        if pending.request_id != claim.request_id
            || pending.draft.delivery != DeliveryDisposition::Silent
            || message_digest(&render_slack_mrkdwn(pending.draft.message.trim())) != payload_digest
            || pending.draft.state != final_state
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "silent wake completion does not match its exact pending draft".into(),
            ));
        }
        let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
        let occurred_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidRequest(error.to_string()))?;
        let events = [
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: claim.session_ref.clone(),
                sequence: expected_sequence + 1,
                occurred_at: occurred_at.clone(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: claim.request_id.clone(),
                    transport: "internal_scheduler".into(),
                    delivery_ref: claim.occurrence_ref.clone(),
                    payload_digest: payload_digest.into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: claim.session_ref.clone(),
                sequence: expected_sequence + 2,
                occurred_at,
                event: SessionEvent::TurnCompleted {
                    request_id: claim.request_id.clone(),
                    state: final_state,
                },
            },
        ];
        self.append_checked(
            &claim.session_ref,
            expected_sequence,
            &events,
            SessionAppendFence::WakeClaim(claim),
            true,
        )
        .await
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
            || message_digest(&render_slack_mrkdwn(pending.draft.message.trim())) != payload_digest
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
            markdown: render_slack_mrkdwn(pending.draft.message.trim()),
            mode,
            tenant_id: session.tenant_id,
            thread_ref: session.thread_ref,
        }))
    }

    pub async fn fail_wake(
        &self,
        claim: &AgentWakeClaim,
        failure_class: &str,
    ) -> Result<AgentWakeFailureDisposition, AgentRuntimeError> {
        let fence = i64::try_from(claim.fence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("wake fence exceeds storage range".into())
        })?;
        let generation = i64::try_from(claim.schedule_generation).map_err(|_| {
            AgentRuntimeError::InvalidRequest("wake generation exceeds storage range".into())
        })?;
        let failure_class = failure_class.chars().take(160).collect::<String>();
        let mut client = self.client.lock().await;
        let transaction = client.transaction().await.map_err(store_unavailable)?;
        let row = transaction
            .query_opt(
                "SELECT w.attempt_count, s.snapshot_json, s.last_sequence FROM cerebro_agent_wakes w JOIN cerebro_agent_sessions s ON s.session_ref = w.session_ref WHERE w.session_ref = $1 AND w.commitment_ref = $2 AND w.schedule_generation = $3 AND w.fence = $4 AND w.lease_owner = $5 AND w.lease_token = $6 AND w.request_id = $7 AND w.state = 'leased' AND w.lease_expires_at > NOW() AND s.active_request_id = $7 AND s.lease_owner = $5 AND s.lease_expires_at > NOW() FOR UPDATE OF w, s",
                &[&claim.session_ref, &claim.commitment_ref, &generation, &fence, &claim.lease_owner, &claim.lease_token, &claim.request_id],
            )
            .await
            .map_err(store_unavailable)?;
        let Some(row) = row else {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake claim or session lease was lost before failure recording".into(),
            ));
        };
        let attempt_count: i32 = row.get(0);
        if attempt_count < 5 {
            let changed = transaction
                .execute(
                    "UPDATE cerebro_agent_wakes SET state = 'scheduled', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, last_error = $8, updated_at = NOW() WHERE session_ref = $1 AND commitment_ref = $2 AND schedule_generation = $3 AND fence = $4 AND lease_owner = $5 AND lease_token = $6 AND request_id = $7 AND state = 'leased' AND lease_expires_at > NOW()",
                    &[&claim.session_ref, &claim.commitment_ref, &generation, &fence, &claim.lease_owner, &claim.lease_token, &claim.request_id, &failure_class],
                )
                .await
                .map_err(store_unavailable)?;
            let released = transaction
                .execute(
                    "UPDATE cerebro_agent_sessions SET active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3 AND lease_expires_at > NOW()",
                    &[&claim.session_ref, &claim.request_id, &claim.lease_owner],
                )
                .await
                .map_err(store_unavailable)?;
            if changed != 1 || released != 1 {
                return Err(AgentRuntimeError::InvalidRequest(
                    "wake retry could not release its exact leases".into(),
                ));
            }
            transaction.commit().await.map_err(store_unavailable)?;
            return Ok(AgentWakeFailureDisposition::RetryScheduled);
        }

        let (session, legacy_events_need_backfill) =
            hydrate_session_events(&transaction, &claim.session_ref, row.get(1), row.get(2))
                .await?;
        if session.pending_delivery.is_some() {
            return Err(AgentRuntimeError::InvalidRequest(
                "exhausted wake cannot replace a pending delivery".into(),
            ));
        }
        let stored_sequence: i64 = row.get(2);
        let expected_sequence = i64::try_from(
            session.events.last().map_or(0, |event| event.sequence),
        )
        .map_err(|_| {
            AgentRuntimeError::InvalidRequest("session sequence exceeds storage range".into())
        })?;
        if stored_sequence != expected_sequence {
            return Err(AgentRuntimeError::InvalidRequest(
                "session snapshot sequence is inconsistent".into(),
            ));
        }
        let mut mission = session.mission.clone();
        let commitment = mission
            .commitments
            .iter_mut()
            .find(|commitment| commitment.commitment_ref == claim.commitment_ref)
            .ok_or_else(|| {
                AgentRuntimeError::InvalidRequest(
                    "exhausted wake has no matching durable commitment".into(),
                )
            })?;
        commitment.status = CommitmentStatus::Blocked;
        commitment.blocker = Some(format!(
            "Scheduled continuation exhausted five attempts: {failure_class}"
        ));
        commitment.next_action = None;
        commitment.wake_at = None;
        let commitment_summary = commitment.summary.clone();
        mission.status = SessionStatus::Blocked;
        let message = format!(
            "Cerebro could not complete the scheduled check for {commitment_summary} after five attempts. The commitment is blocked because the runtime could not finish the check ({failure_class}). No further checks are scheduled."
        );
        let draft = GroundedDraft {
            state: FinalState::Blocked,
            delivery: DeliveryDisposition::Visible,
            message: message.clone(),
            claims: Vec::new(),
            coverage_notice: Some(format!(
                "Scheduled continuation exhausted five attempts: {failure_class}"
            )),
            question: None,
            mission,
            memory_updates: Vec::new(),
            presentation_ready: true,
        };
        let payload_digest = message_digest(&message);
        let occurred_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidRequest(error.to_string()))?;
        let event = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: claim.session_ref.clone(),
            sequence: u64::try_from(expected_sequence).map_err(|_| {
                AgentRuntimeError::InvalidRequest("session sequence is invalid".into())
            })? + 1,
            occurred_at,
            event: SessionEvent::WakeExhausted {
                request_id: claim.request_id.clone(),
                commitment_ref: claim.commitment_ref.clone(),
                occurrence_ref: claim.occurrence_ref.clone(),
                schedule_generation: claim.schedule_generation,
                failure_class: failure_class.clone(),
                draft,
            },
        };
        let updated = apply_session_events(&session, std::slice::from_ref(&event))?;
        if legacy_events_need_backfill {
            backfill_legacy_events(&transaction, &session.events).await?;
        }
        let snapshot = encode_session_snapshot(&updated)?;
        let changed = transaction
            .execute(
                "UPDATE cerebro_agent_wakes SET state = 'awaiting_delivery', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, pending_payload_digest = $8, delivery_ref = NULL, delivery_attempt_ref = NULL, last_error = $9, updated_at = NOW() WHERE session_ref = $1 AND commitment_ref = $2 AND schedule_generation = $3 AND fence = $4 AND lease_owner = $5 AND lease_token = $6 AND request_id = $7 AND state = 'leased' AND lease_expires_at > NOW() AND attempt_count = 5",
                &[&claim.session_ref, &claim.commitment_ref, &generation, &fence, &claim.lease_owner, &claim.lease_token, &claim.request_id, &payload_digest, &failure_class],
            )
            .await
            .map_err(store_unavailable)?;
        insert_event(&transaction, &event).await?;
        let released = transaction
            .execute(
                "UPDATE cerebro_agent_sessions SET snapshot_json = $4, last_sequence = $5, active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3 AND lease_expires_at > NOW()",
                &[&claim.session_ref, &claim.request_id, &claim.lease_owner, &snapshot, &(expected_sequence + 1)],
            )
            .await
            .map_err(store_unavailable)?;
        if changed != 1 || released != 1 {
            return Err(AgentRuntimeError::InvalidRequest(
                "exhausted wake could not commit its exact blocked delivery".into(),
            ));
        }
        project_session_state(&transaction, &updated).await?;
        transaction.commit().await.map_err(store_unavailable)?;
        Ok(AgentWakeFailureDisposition::ExhaustedAwaitingDelivery)
    }

    pub async fn append_operator_fenced(
        &self,
        session_ref: &str,
        request_id: &str,
        lease_owner: &str,
        lease_seconds: i64,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError> {
        if request_id.trim().is_empty()
            || lease_owner.trim().is_empty()
            || lease_seconds <= 0
            || lease_seconds > 3_600
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "operator turn fence identity or duration is invalid".into(),
            ));
        }
        self.append_checked(
            session_ref,
            expected_sequence,
            events,
            SessionAppendFence::Operator(OperatorTurnFence {
                request_id,
                lease_owner,
                lease_seconds,
            }),
            false,
        )
        .await
    }

    pub async fn append_operator_finalized(
        &self,
        session_ref: &str,
        request_id: &str,
        lease_owner: &str,
        lease_seconds: i64,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError> {
        if request_id.trim().is_empty()
            || lease_owner.trim().is_empty()
            || lease_seconds <= 0
            || lease_seconds > 3_600
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "operator turn fence identity or duration is invalid".into(),
            ));
        }
        self.append_checked(
            session_ref,
            expected_sequence,
            events,
            SessionAppendFence::OperatorFinal(OperatorTurnFence {
                request_id,
                lease_owner,
                lease_seconds,
            }),
            false,
        )
        .await
    }

    pub async fn append_delivery_completion(
        &self,
        session_ref: &str,
        request_id: &str,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError> {
        if request_id.trim().is_empty() {
            return Err(AgentRuntimeError::InvalidRequest(
                "delivery completion request identity is invalid".into(),
            ));
        }
        self.append_checked(
            session_ref,
            expected_sequence,
            events,
            SessionAppendFence::DeliveryCompletion(request_id),
            false,
        )
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
            SessionAppendFence::WakeClaim(claim),
            false,
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
            SessionAppendFence::WakeDelivery(lease),
            false,
        )
        .await
    }

    async fn append_checked(
        &self,
        session_ref: &str,
        expected_sequence: u64,
        events: &[SessionEventRecord],
        fence: SessionAppendFence<'_>,
        release_wake_turn: bool,
    ) -> Result<(), AgentRuntimeError> {
        if events.is_empty() {
            return Ok(());
        }
        let operator_fence = match fence {
            SessionAppendFence::Operator(fence) | SessionAppendFence::OperatorFinal(fence) => {
                Some(fence)
            }
            _ => None,
        };
        let finalize_operator = matches!(fence, SessionAppendFence::OperatorFinal(_));
        let delivery_completion = match fence {
            SessionAppendFence::DeliveryCompletion(request_id) => Some(request_id),
            _ => None,
        };
        let wake_claim = match fence {
            SessionAppendFence::WakeClaim(claim) => Some(claim),
            _ => None,
        };
        let wake_delivery_lease = match fence {
            SessionAppendFence::WakeDelivery(lease) => Some(lease),
            _ => None,
        };
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
            let fence = i64::try_from(lease.fence).map_err(|_| {
                AgentRuntimeError::InvalidRequest("wake fence exceeds storage range".into())
            })?;
            let current = transaction
                .query_opt(
                    "SELECT 1 FROM cerebro_agent_wakes WHERE session_ref = $1 AND commitment_ref = $2 AND schedule_generation = $3 AND request_id = $4 AND pending_payload_digest = $5 AND delivery_ref = $6 AND delivery_attempt_ref = $7 AND fence = $8 AND lease_owner = $9 AND lease_token = $10 AND state = 'awaiting_delivery' AND lease_expires_at > NOW() FOR UPDATE",
                    &[&lease.session_ref, &lease.commitment_ref, &generation, &lease.request_id, &lease.payload_digest, &lease.delivery_ref, &lease.delivery_attempt_ref, &fence, &lease.lease_owner, &lease.lease_token],
                )
                .await
                .map_err(store_unavailable)?;
            if current.is_none() {
                return Err(AgentRuntimeError::InvalidRequest(
                    "wake delivery identity is no longer current".into(),
                ));
            }
        }
        let row = match (operator_fence, delivery_completion) {
            (Some(fence), _) => transaction
                .query_opt(
                    "SELECT snapshot_json, last_sequence FROM cerebro_agent_sessions WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3 AND lease_expires_at > NOW() FOR UPDATE",
                    &[&session_ref, &fence.request_id, &fence.lease_owner],
                )
                .await
                .map_err(store_unavailable)?
                .ok_or_else(|| {
                    AgentRuntimeError::InvalidRequest(
                        "operator turn lease is no longer current".into(),
                    )
                })?,
            (None, Some(request_id)) => transaction
                .query_opt(
                    "SELECT snapshot_json, last_sequence FROM cerebro_agent_sessions WHERE session_ref = $1 AND (active_request_id IS NULL OR active_request_id = $2) FOR UPDATE",
                    &[&session_ref, &request_id],
                )
                .await
                .map_err(store_unavailable)?
                .ok_or_else(|| {
                    AgentRuntimeError::InvalidRequest(
                        "delivery completion conflicts with another active request".into(),
                    )
                })?,
            (None, None) => transaction
                .query_opt(
                    "SELECT snapshot_json, last_sequence FROM cerebro_agent_sessions WHERE session_ref = $1 FOR UPDATE",
                    &[&session_ref],
                )
                .await
                .map_err(store_unavailable)?
                .ok_or_else(|| {
                    AgentRuntimeError::InvalidRequest("session does not exist".into())
                })?,
        };
        let stored_sequence: i64 = row.get(1);
        if stored_sequence != expected_sequence {
            return Err(AgentRuntimeError::InvalidRequest(
                "session changed while this turn was running".into(),
            ));
        }
        let (session, legacy_events_need_backfill) =
            hydrate_session_events(&transaction, session_ref, row.get(0), stored_sequence).await?;
        let updated = apply_session_events(&session, events)?;
        if legacy_events_need_backfill {
            backfill_legacy_events(&transaction, &session.events).await?;
        }
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
        let snapshot = encode_session_snapshot(&updated)?;
        let last_sequence = updated.events.last().map_or(0, |event| event.sequence);
        let last_sequence = i64::try_from(last_sequence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("session sequence exceeds storage range".into())
        })?;
        let session_changes = match (operator_fence, finalize_operator, delivery_completion) {
            (Some(fence), true, _) => transaction
                .execute(
                    "UPDATE cerebro_agent_sessions SET snapshot_json = $4, last_sequence = $5, active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3 AND lease_expires_at > NOW()",
                    &[&session_ref, &fence.request_id, &fence.lease_owner, &snapshot, &last_sequence],
                )
                .await
                .map_err(store_unavailable)?,
            (Some(fence), false, _) => transaction
                .execute(
                    "UPDATE cerebro_agent_sessions SET snapshot_json = $4, last_sequence = $5, lease_expires_at = NOW() + make_interval(secs => $6::bigint), updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3 AND lease_expires_at > NOW()",
                    &[&session_ref, &fence.request_id, &fence.lease_owner, &snapshot, &last_sequence, &fence.lease_seconds],
                )
                .await
                .map_err(store_unavailable)?,
            (None, _, Some(request_id)) => transaction
                .execute(
                    "UPDATE cerebro_agent_sessions SET snapshot_json = $3, last_sequence = $4, active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND (active_request_id IS NULL OR active_request_id = $2)",
                    &[&session_ref, &request_id, &snapshot, &last_sequence],
                )
                .await
                .map_err(store_unavailable)?,
            (None, _, None) => transaction
                .execute(
                    "UPDATE cerebro_agent_sessions SET snapshot_json = $2, last_sequence = $3, updated_at = NOW() WHERE session_ref = $1",
                    &[&session_ref, &snapshot, &last_sequence],
                )
                .await
                .map_err(store_unavailable)?,
        };
        if session_changes != 1 {
            return Err(AgentRuntimeError::InvalidRequest(
                "session lease or sequence changed before the append committed".into(),
            ));
        }
        project_session_state(&transaction, &updated).await?;
        if release_wake_turn {
            let claim = wake_claim.ok_or_else(|| {
                AgentRuntimeError::InvalidRequest(
                    "silent wake completion requires an exact wake claim".into(),
                )
            })?;
            let session_changed = transaction
                .execute(
                    "UPDATE cerebro_agent_sessions SET active_request_id = NULL, lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND active_request_id = $2 AND lease_owner = $3",
                    &[&claim.session_ref, &claim.request_id, &claim.lease_owner],
                )
                .await
                .map_err(store_unavailable)?;
            if session_changed != 1 {
                return Err(AgentRuntimeError::InvalidRequest(
                    "silent wake session lease was lost before completion".into(),
                ));
            }
        }
        transaction.commit().await.map_err(store_unavailable)
    }
}

pub struct PostgresTurnJournal {
    store: std::sync::Arc<PostgresAgentSessionStore>,
    session_ref: String,
    sequence: Mutex<u64>,
    operator_request_id: Option<String>,
    operator_lease_owner: Option<String>,
    operator_lease_seconds: Option<i64>,
    wake_claim: Option<AgentWakeClaim>,
}

impl PostgresTurnJournal {
    pub fn new(
        store: std::sync::Arc<PostgresAgentSessionStore>,
        session_ref: String,
        request_id: String,
        lease_owner: String,
        lease_seconds: i64,
        sequence: u64,
    ) -> Self {
        Self {
            store,
            session_ref,
            sequence: Mutex::new(sequence),
            operator_request_id: Some(request_id),
            operator_lease_owner: Some(lease_owner),
            operator_lease_seconds: Some(lease_seconds),
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
            operator_request_id: None,
            operator_lease_owner: None,
            operator_lease_seconds: None,
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
        } else if let (Some(request_id), Some(lease_owner), Some(lease_seconds)) = (
            self.operator_request_id.as_deref(),
            self.operator_lease_owner.as_deref(),
            self.operator_lease_seconds,
        ) {
            self.store
                .append_operator_fenced(
                    &self.session_ref,
                    request_id,
                    lease_owner,
                    lease_seconds,
                    *sequence,
                    std::slice::from_ref(event),
                )
                .await?;
        } else {
            return Err(AgentRuntimeError::InvalidRequest(
                "turn journal has no durable lease fence".into(),
            ));
        }
        *sequence = event.sequence;
        Ok(())
    }

    async fn finalize(&self, events: &[SessionEventRecord]) -> Result<(), AgentRuntimeError> {
        let mut sequence = self.sequence.lock().await;
        if events.is_empty()
            || events.iter().enumerate().any(|(index, event)| {
                event.session_ref != self.session_ref
                    || event.sequence != sequence.saturating_add(index as u64 + 1)
            })
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "turn journal received a non-contiguous final event batch".into(),
            ));
        }
        if let Some(claim) = &self.wake_claim {
            self.store
                .append_wake_fenced(claim, *sequence, events)
                .await?;
        } else if let (Some(request_id), Some(lease_owner), Some(lease_seconds)) = (
            self.operator_request_id.as_deref(),
            self.operator_lease_owner.as_deref(),
            self.operator_lease_seconds,
        ) {
            self.store
                .append_operator_finalized(
                    &self.session_ref,
                    request_id,
                    lease_owner,
                    lease_seconds,
                    *sequence,
                    events,
                )
                .await?;
        } else {
            return Err(AgentRuntimeError::InvalidRequest(
                "turn journal has no durable lease fence".into(),
            ));
        }
        *sequence = events
            .last()
            .expect("a non-empty final batch has a last event")
            .sequence;
        Ok(())
    }
}

#[async_trait]
impl SessionStore for PostgresAgentSessionStore {
    async fn create(&self, session: &AgentSession) -> Result<(), AgentRuntimeError> {
        let snapshot = encode_session_snapshot(session)?;
        let last_sequence = session.events.last().map_or(0, |event| event.sequence);
        validate_stored_event_stream(&session.session_ref, last_sequence, &session.events)?;
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
        let client = self.client.lock().await;
        let row = client
            .query_opt(
                "SELECT snapshot_json, last_sequence FROM cerebro_agent_sessions WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .map_err(store_unavailable)?;
        match row {
            Some(row) => hydrate_session_events(&*client, session_ref, row.get(0), row.get(1))
                .await
                .map(|(session, _)| Some(session)),
            None => Ok(None),
        }
    }

    async fn append(
        &self,
        session_ref: &str,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError> {
        self.append_checked(
            session_ref,
            expected_sequence,
            events,
            SessionAppendFence::None,
            false,
        )
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
                    CommitmentStatus::Blocked
                        | CommitmentStatus::Completed
                        | CommitmentStatus::Cancelled
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
            "UPDATE cerebro_agent_wakes SET state = 'cancelled', lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, pending_payload_digest = NULL, delivery_ref = NULL, delivery_attempt_ref = NULL, updated_at = NOW() WHERE session_ref = $1 AND state IN ('scheduled', 'leased', 'failed') AND NOT (commitment_ref = ANY($2))",
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
    if session.pending_delivery.is_none()
        && let (Some(context_scope_ref), Some(operator_message)) = (
            session.context_scope_ref.as_deref(),
            completed_operator_message(&session.events, &session.messages),
        )
        && session
            .messages
            .iter()
            .any(|message| message.role == SessionMessageRole::Assistant)
    {
        let actor_ref = operator_message.actor_ref.as_str();
        let latest_user_message = Some(bounded_context_text(&operator_message.text, 4_000));
        let latest_assistant_message = session
            .messages
            .iter()
            .rev()
            .find(|message| message.role == SessionMessageRole::Assistant)
            .map(|message| bounded_context_text(&message.text, 8_000));
        let commitments = session
            .mission
            .commitments
            .iter()
            .take(12)
            .map(|commitment| {
                serde_json::json!({
                    "commitment_ref": commitment.commitment_ref,
                    "summary": bounded_context_text(&commitment.summary, 1_000),
                    "status": commitment.status,
                    "next_action": commitment
                        .next_action
                        .as_deref()
                        .map(|value| bounded_context_text(value, 1_000)),
                })
            })
            .collect::<Vec<_>>();
        let open_loops = session
            .mission
            .open_loops
            .iter()
            .take(12)
            .map(|open_loop| {
                serde_json::json!({
                    "open_loop_ref": open_loop.open_loop_ref,
                    "summary": bounded_context_text(&open_loop.summary, 1_000),
                    "owner": open_loop.owner,
                    "next_action": open_loop
                        .next_action
                        .as_deref()
                        .map(|value| bounded_context_text(value, 1_000)),
                    "blocked_by": open_loop
                        .blocked_by
                        .as_deref()
                        .map(|value| bounded_context_text(value, 1_000)),
                })
            })
            .collect::<Vec<_>>();
        let context_json = serde_json::json!({
            "source_session_ref": session.session_ref,
            "source_thread_ref": session.thread_ref,
            "objective": bounded_context_text(&session.mission.objective, 2_000),
            "desired_outcome": bounded_context_text(&session.mission.desired_outcome, 2_000),
            "status": session.mission.status,
            "open_loops": open_loops,
            "commitments": commitments,
            "latest_user_message": latest_user_message,
            "latest_assistant_message": latest_assistant_message,
        });
        transaction
            .execute(
                "INSERT INTO cerebro_agent_thread_contexts (session_ref, tenant_id, actor_ref, context_scope_ref, thread_ref, context_json) VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (session_ref, actor_ref) DO UPDATE SET context_scope_ref = EXCLUDED.context_scope_ref, context_json = EXCLUDED.context_json, updated_at = NOW()",
                &[&session.session_ref, &session.tenant_id, &actor_ref, &context_scope_ref, &session.thread_ref, &context_json],
            )
            .await
            .map_err(store_unavailable)?;
    }
    Ok(())
}

fn completed_operator_message<'a>(
    events: &[SessionEventRecord],
    messages: &'a [SessionMessage],
) -> Option<&'a SessionMessage> {
    let request_id = match &events.last()?.event {
        SessionEvent::TurnCompleted { request_id, .. } => request_id,
        _ => return None,
    };
    let message_ref = format!("operator:{request_id}");
    messages.iter().rev().find(|message| {
        message.role == SessionMessageRole::User && message.message_ref == message_ref
    })
}

fn bounded_context_text(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut boundary = maximum_bytes.saturating_sub(3);
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}...", &value[..boundary])
}

pub(super) fn thread_transcript_page(
    messages: &[SessionMessage],
    cursor: Option<&str>,
    limit: usize,
) -> Result<AgentThreadTranscriptPage, AgentRuntimeError> {
    if !(1..=20).contains(&limit) {
        return Err(AgentRuntimeError::InvalidRequest(
            "Slack thread transcript limit is invalid".into(),
        ));
    }
    let end = match cursor {
        None => messages.len(),
        Some(cursor) if !cursor.trim().is_empty() && cursor.len() <= 256 => messages
            .iter()
            .position(|message| message.message_ref == cursor)
            .ok_or_else(|| {
                AgentRuntimeError::InvalidRequest(
                    "Slack thread transcript cursor is invalid".into(),
                )
            })?,
        Some(_) => {
            return Err(AgentRuntimeError::InvalidRequest(
                "Slack thread transcript cursor is invalid".into(),
            ));
        }
    };
    let start = end.saturating_sub(limit);
    let page = messages[start..end]
        .iter()
        .map(|message| AgentThreadTranscriptMessage {
            actor_ref: bounded_context_text(&message.actor_ref, 256),
            message_ref: message.message_ref.clone(),
            received_at: message.received_at.clone(),
            role: message.role,
            text: bounded_context_text(&message.text, 2_400),
        })
        .collect();
    Ok(AgentThreadTranscriptPage {
        messages: page,
        next_cursor: (start > 0).then(|| messages[start].message_ref.clone()),
    })
}

pub(super) fn prior_thread_cursor(
    updated_at: &str,
    session_ref: &str,
) -> Result<String, AgentRuntimeError> {
    validate_prior_thread_cursor_parts(updated_at, session_ref)?;
    Ok(format!("{updated_at}|{session_ref}"))
}

pub(super) fn parse_prior_thread_cursor(
    value: &str,
) -> Result<(String, String), AgentRuntimeError> {
    if value.len() > 256 {
        return Err(AgentRuntimeError::InvalidRequest(
            "prior Slack thread cursor is invalid".into(),
        ));
    }
    let (updated_at, session_ref) = value.split_once('|').ok_or_else(|| {
        AgentRuntimeError::InvalidRequest("prior Slack thread cursor is invalid".into())
    })?;
    validate_prior_thread_cursor_parts(updated_at, session_ref)?;
    Ok((updated_at.into(), session_ref.into()))
}

fn validate_prior_thread_cursor_parts(
    updated_at: &str,
    session_ref: &str,
) -> Result<(), AgentRuntimeError> {
    let valid_session_ref = session_ref
        .strip_prefix("agent-session:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        });
    if !valid_session_ref || OffsetDateTime::parse(updated_at, &Rfc3339).is_err() {
        return Err(AgentRuntimeError::InvalidRequest(
            "prior Slack thread cursor is invalid".into(),
        ));
    }
    Ok(())
}

pub(super) fn bound_prior_thread_context(context: &mut Value) {
    let Some(source) = context.as_object() else {
        *context = serde_json::json!({"state": "invalid_stored_context"});
        return;
    };
    let bounded = |name: &str, maximum_bytes: usize| {
        source
            .get(name)
            .and_then(Value::as_str)
            .map(|value| bounded_context_text(value, maximum_bytes))
    };
    *context = serde_json::json!({
        "commitments": bounded_prior_items(source.get("commitments"), false),
        "desired_outcome": bounded("desired_outcome", 600),
        "latest_assistant_message": bounded("latest_assistant_message", 1_000),
        "latest_user_message": bounded("latest_user_message", 800),
        "objective": bounded("objective", 600),
        "open_loops": bounded_prior_items(source.get("open_loops"), true),
        "source_thread_ref": bounded("source_thread_ref", 256),
        "status": source.get("status").cloned(),
    });
}

fn bounded_prior_items(value: Option<&Value>, open_loop: bool) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(2)
        .filter_map(Value::as_object)
        .map(|item| {
            let text = |name: &str, maximum_bytes: usize| {
                item.get(name)
                    .and_then(Value::as_str)
                    .map(|value| bounded_context_text(value, maximum_bytes))
            };
            if open_loop {
                serde_json::json!({
                    "blocked_by": text("blocked_by", 300),
                    "next_action": text("next_action", 300),
                    "open_loop_ref": text("open_loop_ref", 256),
                    "owner": item.get("owner").cloned(),
                    "summary": text("summary", 400),
                })
            } else {
                serde_json::json!({
                    "commitment_ref": text("commitment_ref", 256),
                    "next_action": text("next_action", 300),
                    "status": item.get("status").cloned(),
                    "summary": text("summary", 400),
                })
            }
        })
        .collect()
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

fn encode_session_snapshot(session: &AgentSession) -> Result<Value, AgentRuntimeError> {
    let AgentSession {
        schema_version,
        session_ref,
        tenant_id,
        thread_ref,
        context_scope_ref,
        mission,
        messages,
        events: _,
        effect_authorizations,
        pending_delivery,
        memories,
    } = session;
    let mut snapshot = serde_json::Map::with_capacity(11);
    snapshot.insert(
        "schema_version".into(),
        Value::String(schema_version.clone()),
    );
    snapshot.insert("session_ref".into(), Value::String(session_ref.clone()));
    snapshot.insert("tenant_id".into(), Value::String(tenant_id.clone()));
    snapshot.insert("thread_ref".into(), Value::String(thread_ref.clone()));
    snapshot.insert(
        "context_scope_ref".into(),
        serde_json::to_value(context_scope_ref).map_err(invalid_snapshot)?,
    );
    snapshot.insert(
        "mission".into(),
        serde_json::to_value(mission).map_err(invalid_snapshot)?,
    );
    snapshot.insert(
        "messages".into(),
        serde_json::to_value(messages).map_err(invalid_snapshot)?,
    );
    snapshot.insert("events".into(), Value::Array(Vec::new()));
    snapshot.insert(
        "effect_authorizations".into(),
        serde_json::to_value(effect_authorizations).map_err(invalid_snapshot)?,
    );
    snapshot.insert(
        "pending_delivery".into(),
        serde_json::to_value(pending_delivery).map_err(invalid_snapshot)?,
    );
    snapshot.insert(
        "memories".into(),
        serde_json::to_value(memories).map_err(invalid_snapshot)?,
    );
    Ok(Value::Object(snapshot))
}

async fn hydrate_session_events<C>(
    client: &C,
    expected_session_ref: &str,
    snapshot: Value,
    last_sequence: i64,
) -> Result<(AgentSession, bool), AgentRuntimeError>
where
    C: GenericClient + Sync,
{
    let mut session = decode_session(snapshot)?;
    if session.session_ref != expected_session_ref {
        return Err(invalid_stored_session(
            "snapshot identity does not match its storage key",
        ));
    }
    let stored_last_sequence = last_sequence;
    let last_sequence = u64::try_from(last_sequence)
        .map_err(|_| invalid_stored_session("last sequence is outside the session range"))?;
    let rows = client
        .query(
            "SELECT sequence, event_json FROM cerebro_agent_session_events WHERE session_ref = $1 AND sequence <= $2 ORDER BY sequence",
            &[&expected_session_ref, &stored_last_sequence],
        )
        .await
        .map_err(store_unavailable)?;
    let mut canonical_events = Vec::with_capacity(rows.len());
    for row in rows {
        let stored_sequence: i64 = row.get(0);
        let event: SessionEventRecord =
            serde_json::from_value(row.get(1)).map_err(invalid_snapshot)?;
        if u64::try_from(stored_sequence).ok() != Some(event.sequence) {
            return Err(invalid_stored_session(
                "event row sequence does not match its payload",
            ));
        }
        canonical_events.push(event);
    }

    let legacy_events = std::mem::take(&mut session.events);
    if canonical_events.is_empty() && !legacy_events.is_empty() {
        validate_stored_event_stream(expected_session_ref, last_sequence, &legacy_events)?;
        session.events = legacy_events;
        return Ok((session, true));
    }
    validate_stored_event_stream(expected_session_ref, last_sequence, &canonical_events)?;
    if !legacy_events.is_empty() && legacy_events != canonical_events {
        return Err(invalid_stored_session(
            "legacy snapshot history disagrees with canonical event rows",
        ));
    }
    session.events = canonical_events;
    Ok((session, false))
}

fn validate_stored_event_stream(
    session_ref: &str,
    last_sequence: u64,
    events: &[SessionEventRecord],
) -> Result<(), AgentRuntimeError> {
    if events.last().map_or(0, |event| event.sequence) != last_sequence
        || events.iter().enumerate().any(|(index, event)| {
            event.schema_version != AGENT_SESSION_EVENT_V2
                || event.session_ref != session_ref
                || event.sequence != u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1)
                || OffsetDateTime::parse(&event.occurred_at, &Rfc3339).is_err()
        })
    {
        return Err(invalid_stored_session(
            "canonical event history is not contiguous through last_sequence",
        ));
    }
    Ok(())
}

async fn backfill_legacy_events(
    transaction: &tokio_postgres::Transaction<'_>,
    events: &[SessionEventRecord],
) -> Result<(), AgentRuntimeError> {
    for event in events {
        insert_event(transaction, event).await?;
    }
    Ok(())
}

fn decode_session(value: Value) -> Result<AgentSession, AgentRuntimeError> {
    serde_json::from_value(value).map_err(invalid_snapshot)
}

fn invalid_stored_session(reason: &str) -> AgentRuntimeError {
    AgentRuntimeError::InvalidRequest(format!("stored agent session is invalid: {reason}"))
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
        assert_eq!(
            POSTGRES_AGENT_SESSION_SCHEMA_LOCK_KEY,
            0x4342_524f_5345_5353
        );
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
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("cerebro_agent_thread_contexts"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("PRIMARY KEY (session_ref, actor_ref)"));
        assert!(
            POSTGRES_AGENT_SESSION_SCHEMA
                .contains("tenant_id, actor_ref, context_scope_ref, updated_at DESC")
        );
    }

    #[test]
    fn prior_thread_context_text_is_utf8_safe_and_bounded() {
        let value = "é".repeat(20);
        let bounded = bounded_context_text(&value, 13);

        assert!(bounded.len() <= 13);
        assert!(bounded.ends_with("..."));
    }

    #[test]
    fn completed_context_is_attributed_to_the_exact_turn_actor() {
        let messages = vec![
            SessionMessage {
                role: SessionMessageRole::User,
                message_ref: "operator:first-request".into(),
                actor_ref: "slack-user:first".into(),
                text: "First operator message".into(),
                received_at: "2026-07-31T00:00:00Z".into(),
            },
            SessionMessage {
                role: SessionMessageRole::User,
                message_ref: "operator:second-request".into(),
                actor_ref: "slack-user:second".into(),
                text: "Second operator message".into(),
                received_at: "2026-07-31T00:01:00Z".into(),
            },
        ];
        let events = vec![SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: "agent-session:test".into(),
            sequence: 1,
            occurred_at: "2026-07-31T00:02:00Z".into(),
            event: SessionEvent::TurnCompleted {
                request_id: "second-request".into(),
                state: FinalState::Answered,
            },
        }];

        let completed = completed_operator_message(&events, &messages).unwrap();

        assert_eq!(completed.actor_ref, "slack-user:second");
        assert_eq!(completed.text, "Second operator message");
    }

    #[test]
    fn owned_thread_transcript_pages_newest_messages_without_overlap() {
        let messages = (1..=5)
            .map(|index| SessionMessage {
                role: if index % 2 == 0 {
                    SessionMessageRole::Assistant
                } else {
                    SessionMessageRole::User
                },
                message_ref: format!("message:{index}"),
                actor_ref: format!("actor:{index}"),
                text: format!("message text {index}"),
                received_at: format!("2026-07-31T00:0{index}:00Z"),
            })
            .collect::<Vec<_>>();

        let newest = thread_transcript_page(&messages, None, 2).unwrap();
        assert_eq!(
            newest
                .messages
                .iter()
                .map(|message| message.message_ref.as_str())
                .collect::<Vec<_>>(),
            ["message:4", "message:5"]
        );
        assert_eq!(newest.next_cursor.as_deref(), Some("message:4"));

        let older = thread_transcript_page(&messages, newest.next_cursor.as_deref(), 2).unwrap();
        assert_eq!(
            older
                .messages
                .iter()
                .map(|message| message.message_ref.as_str())
                .collect::<Vec<_>>(),
            ["message:2", "message:3"]
        );
        assert_eq!(older.next_cursor.as_deref(), Some("message:2"));

        let oldest = thread_transcript_page(&messages, older.next_cursor.as_deref(), 2).unwrap();
        assert_eq!(oldest.messages[0].message_ref, "message:1");
        assert!(oldest.next_cursor.is_none());
    }

    #[test]
    fn slack_history_cursors_are_bounded_and_canonical() {
        let session_ref = format!("agent-session:{}", "a".repeat(64));
        let updated_at = "2026-07-31T00:00:00.000001Z";
        let encoded = prior_thread_cursor(updated_at, &session_ref).unwrap();

        assert_eq!(
            parse_prior_thread_cursor(&encoded).unwrap(),
            (updated_at.into(), session_ref)
        );
        assert!(parse_prior_thread_cursor("not-a-cursor").is_err());
        assert!(
            parse_prior_thread_cursor(&format!("{updated_at}|agent-session:{}", "z".repeat(64)))
                .is_err()
        );
    }

    #[test]
    fn prior_thread_context_results_are_structurally_bounded() {
        let oversized = "x".repeat(20_000);
        let mut context = serde_json::json!({
            "commitments": (0..10).map(|index| serde_json::json!({
                "commitment_ref": format!("commitment:{index}"),
                "next_action": &oversized,
                "status": "in_progress",
                "summary": &oversized,
            })).collect::<Vec<_>>(),
            "desired_outcome": &oversized,
            "latest_assistant_message": &oversized,
            "latest_user_message": &oversized,
            "objective": &oversized,
            "open_loops": (0..10).map(|index| serde_json::json!({
                "blocked_by": &oversized,
                "next_action": &oversized,
                "open_loop_ref": format!("loop:{index}"),
                "owner": "cerebro",
                "summary": &oversized,
            })).collect::<Vec<_>>(),
            "source_thread_ref": format!("thread:{}", "a".repeat(1_000)),
            "status": "active",
        });

        bound_prior_thread_context(&mut context);

        assert_eq!(context["commitments"].as_array().unwrap().len(), 2);
        assert_eq!(context["open_loops"].as_array().unwrap().len(), 2);
        assert!(serde_json::to_vec(&context).unwrap().len() < 8_000);
    }

    #[test]
    fn session_snapshot_serializes_projection_without_event_history() {
        let session = context_test_session(ContextTestSessionInput {
            session_ref: "agent-session:projection-unit",
            thread_ref: "slack-thread://projection-unit",
            tenant_id: "tenant:projection-unit",
            actor_ref: "slack-user:projection-unit",
            context_scope_ref: "slack-context-scope://projection-unit",
            request_id: "projection-unit-request",
            user_text: "Keep the projection bounded.",
            assistant_text: "The event table remains canonical.",
            pending_delivery: false,
        });

        let snapshot = encode_session_snapshot(&session).unwrap();
        assert_eq!(snapshot["events"], serde_json::json!([]));
        let mut projection = decode_session(snapshot).unwrap();
        assert!(projection.events.is_empty());
        projection.events = session.events.clone();
        assert_eq!(projection, session);

        let legacy_snapshot = serde_json::to_value(&session).unwrap();
        assert_eq!(decode_session(legacy_snapshot).unwrap(), session);
    }

    #[tokio::test]
    #[ignore = "requires CEREBRO_TEST_POSTGRES_DSN"]
    async fn postgres_completed_thread_context_recall_is_actor_and_scope_isolated() {
        let Ok(dsn) = std::env::var("CEREBRO_TEST_POSTGRES_DSN") else {
            return;
        };
        let source_session_ref = "agent-session:postgres-context-completed";
        let pending_session_ref = "agent-session:postgres-context-pending";
        let tenant_id = "tenant:postgres-context";
        let actor_ref = "slack-user:postgres-context-owner";
        let other_actor_ref = "slack-user:postgres-context-other";
        let context_scope_ref = format!("slack-context-scope://sha256/{}", "a".repeat(64));
        let other_scope_ref = format!("slack-context-scope://sha256/{}", "b".repeat(64));
        let store = PostgresAgentSessionStore::connect(&dsn).await.unwrap();
        for session_ref in [source_session_ref, pending_session_ref] {
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

        let completed = context_test_session(ContextTestSessionInput {
            session_ref: source_session_ref,
            thread_ref: "slack-thread://postgres-context/completed",
            tenant_id,
            actor_ref,
            context_scope_ref: &context_scope_ref,
            request_id: "completed-request",
            user_text: "Remember the completed source-thread decision.",
            assistant_text: "I will retain that completed decision for this channel.",
            pending_delivery: false,
        });
        store.create(&completed).await.unwrap();
        let pending = context_test_session(ContextTestSessionInput {
            session_ref: pending_session_ref,
            thread_ref: "slack-thread://postgres-context/pending",
            tenant_id,
            actor_ref,
            context_scope_ref: &context_scope_ref,
            request_id: "pending-request",
            user_text: "This pending message must not be recalled.",
            assistant_text: "This delivery has not been acknowledged.",
            pending_delivery: true,
        });
        store.create(&pending).await.unwrap();
        drop(store);

        let restarted = PostgresAgentSessionStore::connect(&dsn).await.unwrap();
        let recalled = restarted
            .recall_thread_contexts(
                tenant_id,
                actor_ref,
                &context_scope_ref,
                "agent-session:postgres-context-target",
                12,
            )
            .await
            .unwrap();
        assert_eq!(recalled.len(), 1);
        assert!(
            recalled[0]
                .statement
                .contains("completed source-thread decision")
        );
        assert!(!recalled[0].statement.contains("pending message"));
        assert!(
            restarted
                .recall_thread_contexts(
                    tenant_id,
                    other_actor_ref,
                    &context_scope_ref,
                    "agent-session:postgres-context-target",
                    12,
                )
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            restarted
                .recall_thread_contexts(
                    tenant_id,
                    actor_ref,
                    &other_scope_ref,
                    "agent-session:postgres-context-target",
                    12,
                )
                .await
                .unwrap()
                .is_empty()
        );
        let searched = restarted
            .search_prior_thread_contexts(AgentPriorThreadSearch {
                actor_ref,
                context_scope_ref: &context_scope_ref,
                cursor: None,
                exclude_session_ref: "agent-session:postgres-context-target",
                limit: 2,
                query: "completed source-thread decision",
                tenant_id,
            })
            .await
            .unwrap();
        assert_eq!(searched.threads.len(), 1);
        assert_eq!(
            searched.threads[0].context["latest_user_message"],
            "Remember the completed source-thread decision."
        );
        assert!(searched.next_cursor.is_none());
        assert!(
            restarted
                .search_prior_thread_contexts(AgentPriorThreadSearch {
                    actor_ref: other_actor_ref,
                    context_scope_ref: &context_scope_ref,
                    cursor: None,
                    exclude_session_ref: "agent-session:postgres-context-target",
                    limit: 2,
                    query: "",
                    tenant_id,
                })
                .await
                .unwrap()
                .threads
                .is_empty()
        );
        assert!(
            restarted
                .search_prior_thread_contexts(AgentPriorThreadSearch {
                    actor_ref,
                    context_scope_ref: &other_scope_ref,
                    cursor: None,
                    exclude_session_ref: "agent-session:postgres-context-target",
                    limit: 2,
                    query: "",
                    tenant_id,
                })
                .await
                .unwrap()
                .threads
                .is_empty()
        );

        for session_ref in [source_session_ref, pending_session_ref] {
            restarted
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

    struct ContextTestSessionInput<'a> {
        session_ref: &'a str,
        thread_ref: &'a str,
        tenant_id: &'a str,
        actor_ref: &'a str,
        context_scope_ref: &'a str,
        request_id: &'a str,
        user_text: &'a str,
        assistant_text: &'a str,
        pending_delivery: bool,
    }

    fn context_test_session(input: ContextTestSessionInput<'_>) -> AgentSession {
        let ContextTestSessionInput {
            session_ref,
            thread_ref,
            tenant_id,
            actor_ref,
            context_scope_ref,
            request_id,
            user_text,
            assistant_text,
            pending_delivery,
        } = input;
        let mission = MissionState {
            mission_ref: format!("mission:{request_id}"),
            objective: "Preserve bounded Slack continuity.".into(),
            desired_outcome: "Recall only completed context for the same actor and channel.".into(),
            resolved_scope: Vec::new(),
            scope_assumptions: Vec::new(),
            acceptance_criteria: vec!["Actor and scope boundaries remain exact.".into()],
            commitments: Vec::new(),
            open_loops: Vec::new(),
            status: SessionStatus::Completed,
        };
        let user_message = SessionMessage {
            role: SessionMessageRole::User,
            message_ref: format!("operator:{request_id}"),
            actor_ref: actor_ref.into(),
            text: user_text.into(),
            received_at: "2026-07-31T00:00:00Z".into(),
        };
        let assistant_message = SessionMessage {
            role: SessionMessageRole::Assistant,
            message_ref: format!("assistant:{request_id}"),
            actor_ref: "cerebro".into(),
            text: assistant_text.into(),
            received_at: "2026-07-31T00:00:01Z".into(),
        };
        let draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: assistant_text.into(),
            claims: Vec::new(),
            coverage_notice: None,
            question: None,
            mission: mission.clone(),
            memory_updates: Vec::new(),
            presentation_ready: true,
        };
        AgentSession {
            schema_version: cerebro_agent_runtime::session::AGENT_SESSION_V2.into(),
            session_ref: session_ref.into(),
            tenant_id: tenant_id.into(),
            thread_ref: thread_ref.into(),
            context_scope_ref: Some(context_scope_ref.into()),
            mission,
            messages: vec![user_message, assistant_message],
            events: vec![SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session_ref.into(),
                sequence: 1,
                occurred_at: "2026-07-31T00:00:02Z".into(),
                event: SessionEvent::TurnCompleted {
                    request_id: request_id.into(),
                    state: FinalState::Answered,
                },
            }],
            effect_authorizations: Vec::new(),
            pending_delivery: pending_delivery.then_some(
                cerebro_agent_runtime::session::PendingDelivery {
                    request_id: request_id.into(),
                    draft,
                    produced_at: "2026-07-31T00:00:01Z".into(),
                },
            ),
            memories: Vec::new(),
        }
    }

    #[tokio::test]
    #[ignore = "requires CEREBRO_TEST_POSTGRES_DSN"]
    async fn postgres_snapshot_projection_hydrates_canonical_events_and_fences_sequence() {
        let Ok(dsn) = std::env::var("CEREBRO_TEST_POSTGRES_DSN") else {
            return;
        };
        let session_ref = "agent-session:postgres-projection-events";
        let thread_ref = "slack-thread://postgres-projection-events";
        let tenant_id = "tenant:postgres-projection-events";
        let store = PostgresAgentSessionStore::connect(&dsn).await.unwrap();
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
        let session = context_test_session(ContextTestSessionInput {
            session_ref,
            thread_ref,
            tenant_id,
            actor_ref: "slack-user:postgres-projection-events",
            context_scope_ref: "slack-context-scope://postgres-projection-events",
            request_id: "postgres-projection-request",
            user_text: "Persist this turn once.",
            assistant_text: "The canonical event row is durable.",
            pending_delivery: false,
        });
        store.create(&session).await.unwrap();

        let row = store
            .client
            .lock()
            .await
            .query_one(
                "SELECT jsonb_array_length(snapshot_json->'events'), last_sequence, (SELECT COUNT(*) FROM cerebro_agent_session_events e WHERE e.session_ref = s.session_ref) FROM cerebro_agent_sessions s WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i32>(0), 0);
        assert_eq!(row.get::<_, i64>(1), 1);
        assert_eq!(row.get::<_, i64>(2), 1);
        assert_eq!(
            store.load(session_ref).await.unwrap(),
            Some(session.clone())
        );
        assert_eq!(
            store.load_by_thread(tenant_id, thread_ref).await.unwrap(),
            Some(session.clone())
        );

        let memory = MemoryUpdate {
            memory_ref: "memory:postgres-projection-events".into(),
            kind: MemoryKind::Preference,
            statement: "Keep canonical event history outside the projection snapshot.".into(),
            evidence_atom_refs: Vec::new(),
            promotion_requested: false,
        };
        let appended = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: session_ref.into(),
            sequence: 2,
            occurred_at: "2026-07-31T00:00:03Z".into(),
            event: SessionEvent::MemoryRecorded { update: memory },
        };
        store
            .append(session_ref, 1, std::slice::from_ref(&appended))
            .await
            .unwrap();
        let expected = apply_session_events(&session, std::slice::from_ref(&appended)).unwrap();

        let stale = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: session_ref.into(),
            sequence: 2,
            occurred_at: "2026-07-31T00:00:04Z".into(),
            event: SessionEvent::TurnCompleted {
                request_id: "stale-projection-request".into(),
                state: FinalState::Answered,
            },
        };
        assert!(
            store
                .append(session_ref, 1, std::slice::from_ref(&stale))
                .await
                .is_err()
        );
        let row = store
            .client
            .lock()
            .await
            .query_one(
                "SELECT jsonb_array_length(snapshot_json->'events'), last_sequence, (SELECT COUNT(*) FROM cerebro_agent_session_events e WHERE e.session_ref = s.session_ref) FROM cerebro_agent_sessions s WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i32>(0), 0);
        assert_eq!(row.get::<_, i64>(1), 2);
        assert_eq!(row.get::<_, i64>(2), 2);
        drop(store);

        let restarted = PostgresAgentSessionStore::connect(&dsn).await.unwrap();
        assert_eq!(restarted.load(session_ref).await.unwrap(), Some(expected));
        restarted
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

    #[tokio::test]
    #[ignore = "requires CEREBRO_TEST_POSTGRES_DSN"]
    async fn postgres_legacy_snapshot_history_is_read_and_backfilled_on_append() {
        let Ok(dsn) = std::env::var("CEREBRO_TEST_POSTGRES_DSN") else {
            return;
        };
        let session_ref = "agent-session:postgres-legacy-snapshot-events";
        let store = PostgresAgentSessionStore::connect(&dsn).await.unwrap();
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
        let legacy = context_test_session(ContextTestSessionInput {
            session_ref,
            thread_ref: "slack-thread://postgres-legacy-snapshot-events",
            tenant_id: "tenant:postgres-legacy-snapshot-events",
            actor_ref: "slack-user:postgres-legacy-snapshot-events",
            context_scope_ref: "slack-context-scope://postgres-legacy-snapshot-events",
            request_id: "postgres-legacy-request",
            user_text: "Read my legacy snapshot.",
            assistant_text: "Its event history remains available.",
            pending_delivery: false,
        });
        store.create(&legacy).await.unwrap();
        let legacy_snapshot = serde_json::to_value(&legacy).unwrap();
        let mut client = store.client.lock().await;
        let transaction = client.transaction().await.unwrap();
        transaction
            .execute(
                "DELETE FROM cerebro_agent_session_events WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .unwrap();
        transaction
            .execute(
                "UPDATE cerebro_agent_sessions SET snapshot_json = $2 WHERE session_ref = $1",
                &[&session_ref, &legacy_snapshot],
            )
            .await
            .unwrap();
        transaction.commit().await.unwrap();
        drop(client);

        assert_eq!(store.load(session_ref).await.unwrap(), Some(legacy.clone()));
        let appended = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: session_ref.into(),
            sequence: 2,
            occurred_at: "2026-07-31T00:00:03Z".into(),
            event: SessionEvent::TurnCompleted {
                request_id: "postgres-legacy-follow-up".into(),
                state: FinalState::Answered,
            },
        };
        store
            .append(session_ref, 1, std::slice::from_ref(&appended))
            .await
            .unwrap();
        let expected = apply_session_events(&legacy, std::slice::from_ref(&appended)).unwrap();
        assert_eq!(store.load(session_ref).await.unwrap(), Some(expected));
        let row = store
            .client
            .lock()
            .await
            .query_one(
                "SELECT jsonb_array_length(snapshot_json->'events'), (SELECT COUNT(*) FROM cerebro_agent_session_events e WHERE e.session_ref = s.session_ref) FROM cerebro_agent_sessions s WHERE session_ref = $1",
                &[&session_ref],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i32>(0), 0);
        assert_eq!(row.get::<_, i64>(1), 2);
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
            attention_policy: None,
            wake_at: Some("2020-01-01T00:00:00Z".into()),
            verification: Some("The current observation is recorded.".into()),
        };
        let session = AgentSession {
            schema_version: cerebro_agent_runtime::session::AGENT_SESSION_V2.into(),
            session_ref: session_ref.into(),
            tenant_id: "tenant:postgres-wake".into(),
            thread_ref: "thread:postgres-wake".into(),
            context_scope_ref: None,
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
            delivery: DeliveryDisposition::Visible,
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
        assert!(
            store
                .append_wake_delivery_fenced(&pending_delivery.lease, 2, &delivery_events)
                .await
                .is_err()
        );
        store
            .append_wake_delivery_fenced(&recovered_delivery.lease, 2, &delivery_events)
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

    #[tokio::test]
    #[ignore = "requires CEREBRO_TEST_POSTGRES_DSN"]
    async fn postgres_fifth_wake_failure_blocks_and_queues_one_visible_delivery() {
        let Ok(dsn) = std::env::var("CEREBRO_TEST_POSTGRES_DSN") else {
            return;
        };
        let store = PostgresAgentSessionStore::connect(&dsn).await.unwrap();
        let session_ref = "agent-session:postgres-wake-exhaustion-test";
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
        let session = AgentSession {
            schema_version: cerebro_agent_runtime::session::AGENT_SESSION_V2.into(),
            session_ref: session_ref.into(),
            tenant_id: "tenant:postgres-wake-exhaustion".into(),
            thread_ref: "thread:postgres-wake-exhaustion".into(),
            context_scope_ref: None,
            mission: MissionState {
                mission_ref: "mission:postgres-wake-exhaustion".into(),
                objective: "Verify exhausted wake visibility.".into(),
                desired_outcome: "The operator sees a durable blocked update.".into(),
                resolved_scope: Vec::new(),
                scope_assumptions: Vec::new(),
                acceptance_criteria: vec!["A current state is observed.".into()],
                commitments: vec![Commitment {
                    commitment_ref: "commitment:postgres-wake-exhaustion".into(),
                    summary: "the persisted recovery check".into(),
                    owner: WorkOwner::Cerebro,
                    status: CommitmentStatus::Waiting,
                    next_action: Some("Read the current state.".into()),
                    blocker: None,
                    acceptance_criteria: vec!["A current state is observed.".into()],
                    artifact_refs: Vec::new(),
                    required_tool_ids: Vec::new(),
                    attention_policy: None,
                    wake_at: Some("2020-01-01T00:00:00Z".into()),
                    verification: Some("The current observation is recorded.".into()),
                }],
                open_loops: Vec::new(),
                status: SessionStatus::WaitingForExternal,
            },
            messages: vec![SessionMessage {
                role: SessionMessageRole::User,
                message_ref: "message:postgres-wake-exhaustion".into(),
                actor_ref: "user:postgres-wake-exhaustion".into(),
                text: "Keep owning this recovery check.".into(),
                received_at: "2020-01-01T00:00:00Z".into(),
            }],
            events: Vec::new(),
            effect_authorizations: Vec::new(),
            pending_delivery: None,
            memories: Vec::new(),
        };
        store.create(&session).await.unwrap();
        let claim = store
            .claim_due_wake("worker:postgres-wake-exhaustion", 60)
            .await
            .unwrap()
            .expect("the exhausted wake fixture should be claimable");
        store
            .client
            .lock()
            .await
            .execute(
                "UPDATE cerebro_agent_wakes SET attempt_count = 5 WHERE session_ref = $1 AND commitment_ref = $2",
                &[&session_ref, &claim.commitment_ref],
            )
            .await
            .unwrap();
        let mut stale = claim.clone();
        stale.fence = stale.fence.saturating_sub(1);
        assert!(
            store
                .fail_wake(&stale, "scheduled wake execution failed")
                .await
                .is_err()
        );

        assert_eq!(
            store
                .fail_wake(&claim, "scheduled wake execution failed")
                .await
                .unwrap(),
            AgentWakeFailureDisposition::ExhaustedAwaitingDelivery
        );
        let reloaded = store.load(session_ref).await.unwrap().unwrap();
        assert_eq!(reloaded.mission.status, SessionStatus::Blocked);
        assert_eq!(
            reloaded.mission.commitments[0].status,
            CommitmentStatus::Blocked
        );
        assert!(reloaded.mission.commitments[0].wake_at.is_none());
        let pending = reloaded
            .pending_delivery
            .as_ref()
            .expect("exhaustion must retain one visible pending delivery");
        assert_eq!(pending.draft.delivery, DeliveryDisposition::Visible);
        assert_eq!(pending.draft.state, FinalState::Blocked);
        assert!(
            store
                .claim_due_wake("worker:must-not-run-sixth-attempt", 60)
                .await
                .unwrap()
                .is_none()
        );
        let delivery = store
            .claim_pending_wake_delivery("delivery-worker:exhaustion", 60)
            .await
            .unwrap()
            .expect("the exhausted wake update must survive reload and remain deliverable");
        assert_eq!(delivery.mode, AgentWakeDeliveryMode::Send);
        assert_eq!(delivery.markdown, pending.draft.message);
        let row = store
            .client
            .lock()
            .await
            .query_one(
                "SELECT state, attempt_count FROM cerebro_agent_wakes WHERE session_ref = $1 AND commitment_ref = $2",
                &[&session_ref, &claim.commitment_ref],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "awaiting_delivery");
        assert_eq!(row.get::<_, i32>(1), 5);
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
