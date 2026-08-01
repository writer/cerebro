use async_trait::async_trait;
use cerebro_agent_runtime::{
    AgentRuntimeError,
    session::{
        AgentSession, CommitmentStatus, SessionEventRecord, SessionJournal, SessionStore,
        WorkOwner, apply_session_events,
    },
};
use native_tls::TlsConnector;
use postgres_native_tls::MakeTlsConnector;
use serde_json::Value;
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
  state TEXT NOT NULL DEFAULT 'scheduled'
    CHECK (state IN ('scheduled', 'leased', 'completed', 'cancelled', 'failed')),
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  last_error TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (session_ref, commitment_ref)
);
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
                "UPDATE cerebro_agent_sessions SET active_request_id = $2, lease_owner = $3, lease_expires_at = NOW() + make_interval(secs => $4::double precision), updated_at = NOW() WHERE session_ref = $1 AND (lease_expires_at IS NULL OR lease_expires_at <= NOW() OR (active_request_id = $2 AND lease_owner = $3))",
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
}

pub struct PostgresTurnJournal {
    store: std::sync::Arc<PostgresAgentSessionStore>,
    session_ref: String,
    sequence: Mutex<u64>,
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
        self.store
            .append(&self.session_ref, *sequence, std::slice::from_ref(event))
            .await?;
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
        if events.is_empty() {
            return Ok(());
        }
        let expected_sequence = i64::try_from(expected_sequence).map_err(|_| {
            AgentRuntimeError::InvalidRequest("session sequence exceeds storage range".into())
        })?;
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
            "UPDATE cerebro_agent_wakes SET state = 'cancelled', lease_owner = NULL, lease_expires_at = NULL, updated_at = NOW() WHERE session_ref = $1 AND state IN ('scheduled', 'leased', 'failed') AND NOT (commitment_ref = ANY($2))",
            &[&session.session_ref, &active_refs],
        )
        .await
        .map_err(store_unavailable)?;
    for commitment in active_commitments {
        let wake_at = commitment
            .wake_at
            .as_deref()
            .expect("active scheduled commitments have a wake time");
        transaction
            .execute(
                "INSERT INTO cerebro_agent_wakes (session_ref, commitment_ref, wake_at, state) VALUES ($1, $2, $3::timestamptz, 'scheduled') ON CONFLICT (session_ref, commitment_ref) DO UPDATE SET wake_at = EXCLUDED.wake_at, state = CASE WHEN cerebro_agent_wakes.state = 'leased' AND cerebro_agent_wakes.lease_expires_at > NOW() THEN 'leased' ELSE 'scheduled' END, lease_owner = CASE WHEN cerebro_agent_wakes.state = 'leased' AND cerebro_agent_wakes.lease_expires_at > NOW() THEN cerebro_agent_wakes.lease_owner ELSE NULL END, lease_expires_at = CASE WHEN cerebro_agent_wakes.state = 'leased' AND cerebro_agent_wakes.lease_expires_at > NOW() THEN cerebro_agent_wakes.lease_expires_at ELSE NULL END, updated_at = NOW()",
                &[&session.session_ref, &commitment.commitment_ref, &wake_at],
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
            "INSERT INTO cerebro_agent_session_events (session_ref, sequence, event_json, occurred_at) VALUES ($1, $2, $3, $4::timestamptz)",
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

    #[test]
    fn schema_has_isolated_event_and_wake_records() {
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("UNIQUE (tenant_id, thread_ref)"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("PRIMARY KEY (session_ref, sequence)"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("lease_expires_at TIMESTAMPTZ"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("CHECK (state IN"));
        assert!(POSTGRES_AGENT_SESSION_SCHEMA.contains("cerebro_agent_memories"));
    }
}
