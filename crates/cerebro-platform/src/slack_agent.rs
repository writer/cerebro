use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
    error::Error,
    future::Future,
    sync::Arc,
    time::Duration as StdDuration,
};

use async_trait::async_trait;
use aws_config::{BehaviorVersion, retry::RetryConfig};
use aws_sdk_bedrockruntime::{
    Client as BedrockClient,
    types::{
        AnyToolChoice, ContentBlock, ConversationRole, InferenceConfiguration, Message,
        SpecificToolChoice, SystemContentBlock, Tool, ToolChoice, ToolConfiguration,
        ToolInputSchema, ToolSpecification,
    },
};
use aws_smithy_types::{Document, Number};
use cerebro_agent_context::{AgentGraph, ContextError};
use cerebro_agent_runtime::{
    AGENT_DELIVERY_RECEIPT_V1, AgentDeliveryReceipt, AgentModel, AgentRuntimeError, AgentTools,
    AgentTurnOutcome, AgentTurnRequest, CRITIC_MAX_TOKENS, CritiqueDecision, CritiqueTurn,
    DECISION_MAX_TOKENS, EvidenceRecord, ExecutionLane, FinalState, HARD_MAX_GENERATION_TOKENS,
    ModelDecision, ModelTurn, PRESENTATION_MAX_TOKENS, PROACTIVE_FOLLOWUP_CAPABILITY_V1,
    PresentationDecision, PresentationTurn, ResolvedRequestRoute, RouteDecision, RouteTurn,
    ToolAuthorityClass, ToolDescriptor, ToolEffectClass, ToolResult, ToolResultState,
    session::{
        AGENT_SEMANTIC_EVIDENCE_V1, AGENT_SESSION_EVENT_V2, AGENT_SESSION_V2,
        ALL_STABLE_EXPLANATION_IDS, AgentSession, ClaimContent, DeliveryDisposition,
        EvidenceAssertion, EvidenceAtom, EvidenceAtomization, GroundedDraft, MAX_SESSION_MEMORIES,
        MissionState, ProactiveFollowupOffer, ResearchPlan, SemanticEvidenceAtomization,
        SemanticEvidenceEnvelope, SessionAgentModel, SessionEvent, SessionEventRecord,
        SessionMessage, SessionMessageRole, SessionModelDecision, SessionModelRejection,
        SessionModelRejectionClass, SessionModelTurn, SessionStatus, SessionStore, SessionTools,
        SessionTurnInput, SessionTurnOutcome, SessionTurnTrigger, apply_session_events,
        evidence_atoms_from_json, followup_acceptance_draft, message_digest,
        run_session_turn_recorded, run_session_turn_recorded_with_followup_offers,
        semantic_evidence_atoms, validate_followup_acceptance,
    },
    validate_agent_turn_request,
};

#[cfg(test)]
use cerebro_agent_runtime::session::{
    AttentionReview, BehavioralReview, ClaimReview, ClaimReviewTurn, ClaimReviewVerdict,
    MessageReview, grounded_draft_digest,
};
use cerebro_organizational_model::TenantId;
use cerebro_organizational_store::{Neo4jProjector, PostgresLedger, SourceRuntimeObservation};
use cerebro_source_catalog::{AuthModel, CollectionAuthority, SourceCatalog};
use cerebro_source_runtime_next::{
    RuntimeHealthEvidence, RuntimeReadiness, evaluate_runtime_readiness,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime, format_description::well_known::Rfc3339};

use super::slack_agent_mcp::McpAgentTools;
use super::slack_agent_session::{
    AgentPendingWakeDelivery, AgentPriorThreadSearch, AgentWakeClaim, AgentWakeDeliveryLease,
    AgentWakeFailureDisposition, PostgresAgentSessionStore, PostgresTurnJournal,
};
use super::slack_mrkdwn::render_slack_mrkdwn;

mod prompts;

use prompts::{
    critic_instructions, model_instructions, presentation_instructions, route_instructions,
    session_instructions,
};

const MAX_MODEL_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_MODEL_HISTORY_ITEMS: usize = 24;
const MAX_MODEL_HISTORY_ITEM_BYTES: usize = 8 * 1024;
const MAX_MODEL_HISTORY_TOTAL_BYTES: usize = 96 * 1024;
const MAX_SESSION_MODEL_CURRENT_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_SESSION_MODEL_HISTORY_ITEMS: usize = 32;
const MAX_SESSION_MODEL_HISTORY_ITEM_BYTES: usize = 8 * 1024;
const MAX_SESSION_MODEL_HISTORY_TOTAL_BYTES: usize = 96 * 1024;
const ROUTE_DECISION_TOOL: &str = "submit_route_decision";
const OPERATING_DECISION_TOOL: &str = "submit_operating_decision";
const PRESENTATION_DECISION_TOOL: &str = "submit_slack_presentation";
const CRITIQUE_DECISION_TOOL: &str = "submit_critique_decision";
const SESSION_START_TOOL: &str = "start_agent_work";
const SESSION_CONTINUE_TOOL: &str = "continue_agent_work";
const SESSION_FINISH_TOOL: &str = "finish_agent_turn";
const SESSION_MODEL_ATTEMPTS: usize = 2;
const MAX_GRAPH_LIMIT: usize = 25;
const MAX_GRAPH_DEPTH: usize = 3;
const MAX_RUNTIME_LIMIT: usize = 25;
const MAX_SLACK_HISTORY_LIMIT: usize = 4;
const MAX_SLACK_TRANSCRIPT_LIMIT: usize = 20;
const STARTUP_HEALTH_ATTEMPTS: usize = 12;
const STARTUP_INITIAL_RETRY_DELAY: StdDuration = StdDuration::from_millis(500);
const STARTUP_MAX_RETRY_DELAY: StdDuration = StdDuration::from_secs(5);
const STARTUP_DEPENDENCY_ATTEMPTS: usize = 5;
const STARTUP_DEPENDENCY_RETRY_DELAY: StdDuration = StdDuration::from_millis(250);
const OPERATOR_TURN_LEASE_SECONDS: i64 = 1_000;
const MAX_ACCEPTANCE_CLOCK_DELAY_SECONDS: i64 = 900;
const SLACK_ROUTE_MAX_TOKENS: i32 = 768;
const SLACK_SESSION_DECISION_MAX_TOKENS: i32 = 4_096;

#[derive(Clone)]
struct StructuredToolContract {
    name: &'static str,
    description: &'static str,
    schema: Value,
}

#[derive(Debug)]
struct StructuredToolSelection {
    name: String,
    input: Value,
    contract_digest: String,
}

pub struct SlackAgentService {
    model: Arc<ConfiguredModel>,
    tools: Arc<PlatformAgentTools>,
    sessions: Option<Arc<PostgresAgentSessionStore>>,
    tenant_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SlackAgentModelAttestation {
    pub(super) model_config_sha256: String,
    pub(super) model_id: String,
    pub(super) model_provider: &'static str,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AgentTurnProgress {
    pub schema_version: &'static str,
    pub latest_sequence: u64,
    pub updates: Vec<AgentTurnProgressUpdate>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AgentTurnProgressUpdate {
    pub sequence: u64,
    pub occurred_at: String,
    pub phase: String,
    pub status: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct AgentWakeTurn {
    pub commitment_ref: String,
    pub request_id: String,
    pub schedule_generation: u64,
    pub session_ref: String,
    pub state: &'static str,
}

struct ClaimedWakeTurn {
    delivery: DeliveryDisposition,
    final_state: FinalState,
    payload_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentWakeDeliveryReceipt {
    pub lease: AgentWakeDeliveryLease,
    pub receipt: AgentDeliveryReceipt,
}

impl SlackAgentService {
    pub(super) fn actuation_metrics(&self) -> (u64, u64) {
        self.tools
            .mcp
            .as_deref()
            .map_or((0, 0), McpAgentTools::actuation_metrics)
    }

    pub async fn from_env(tenant_id: String) -> Result<Option<Self>, Box<dyn Error>> {
        if !enabled(&env::var("CEREBRO_SLACK_AGENT_ENABLED").unwrap_or_default()) {
            if enabled(&env::var("CEREBRO_SLACK_PRODUCTION").unwrap_or_default()) {
                return Err("production Slack requires the Rust agent runtime".into());
            }
            return Ok(None);
        }
        let service = Self::initialize(tenant_id).await?;
        Ok(Some(service))
    }

    pub(super) fn model_attestation(&self) -> SlackAgentModelAttestation {
        self.model.attestation()
    }

    pub async fn turn_progress(
        &self,
        thread_ref: &str,
        request_id: &str,
        after_sequence: u64,
    ) -> Result<AgentTurnProgress, AgentRuntimeError> {
        if thread_ref.trim().is_empty()
            || request_id.trim().is_empty()
            || thread_ref.len() > 8 * 1024
            || request_id.len() > 8 * 1024
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "turn progress identity is invalid".into(),
            ));
        }
        let store = self.sessions.as_ref().ok_or_else(|| {
            AgentRuntimeError::ModelUnavailable("durable session store is not configured".into())
        })?;
        let Some(session) = store.load_by_thread(&self.tenant_id, thread_ref).await? else {
            return Ok(AgentTurnProgress {
                schema_version: "agent-turn-progress/v1",
                latest_sequence: after_sequence,
                updates: Vec::new(),
            });
        };
        Ok(project_turn_progress(&session, request_id, after_sequence))
    }

    async fn initialize(tenant_id: String) -> Result<Self, Box<dyn Error>> {
        if !enabled(&env::var("CEREBRO_SLACK_AGENT_SESSION_V2_ENABLED").unwrap_or_default()) {
            return Err("the Rust Slack agent requires durable session V2".into());
        }
        let neo4j_uri = required_env("CEREBRO_NEO4J_URI")?;
        let neo4j_username = required_env("CEREBRO_NEO4J_USERNAME")?;
        let neo4j_password = required_env("CEREBRO_NEO4J_PASSWORD")?;
        let graph = retry_startup(
            STARTUP_DEPENDENCY_ATTEMPTS,
            STARTUP_DEPENDENCY_RETRY_DELAY,
            STARTUP_DEPENDENCY_RETRY_DELAY,
            || Neo4jProjector::connect(&neo4j_uri, &neo4j_username, &neo4j_password),
        )
        .await?;
        retry_startup(
            STARTUP_HEALTH_ATTEMPTS,
            STARTUP_INITIAL_RETRY_DELAY,
            STARTUP_MAX_RETRY_DELAY,
            || graph.health(),
        )
        .await?;
        let postgres_dsn = required_env("CEREBRO_POSTGRES_DSN")?;
        let ledger = retry_startup(
            STARTUP_DEPENDENCY_ATTEMPTS,
            STARTUP_DEPENDENCY_RETRY_DELAY,
            STARTUP_DEPENDENCY_RETRY_DELAY,
            || PostgresLedger::connect_tls(&postgres_dsn),
        )
        .await?;
        let session_store = Arc::new(PostgresAgentSessionStore::connect(&postgres_dsn).await?);
        let sessions = Some(session_store.clone());
        let model = retry_startup(
            STARTUP_DEPENDENCY_ATTEMPTS,
            STARTUP_DEPENDENCY_RETRY_DELAY,
            STARTUP_DEPENDENCY_RETRY_DELAY,
            ConfiguredModel::from_env,
        )
        .await?;
        let catalog = super::load_catalog()?;
        let mcp_configured = McpAgentTools::is_configured();
        let mcp_authority_policy_configured = McpAgentTools::authority_policy_configured();
        let mcp = match retry_mcp_startup(|| McpAgentTools::from_env(&tenant_id)).await {
            Ok(mcp) => mcp.map(Arc::new),
            Err(error) if mcp_authority_policy_configured => {
                return Err(format!(
                    "configured MCP capability authority policy could not be loaded: {error}"
                )
                .into());
            }
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({
                        "component": "rust-slack-agent",
                        "error_kind": "mcp_capability_catalog_unavailable",
                        "message": error,
                        "operation": "load_capabilities",
                        "state": "degraded",
                    })
                );
                None
            }
        };
        Ok(Self {
            model: Arc::new(model),
            tools: Arc::new(PlatformAgentTools {
                catalog: Arc::new(catalog),
                graph: Arc::new(graph),
                ledger: Arc::new(ledger),
                mcp,
                mcp_configured,
                sessions: session_store,
            }),
            sessions,
            tenant_id,
        })
    }

    pub async fn run(
        &self,
        request: AgentTurnRequest,
    ) -> Result<AgentTurnOutcome, AgentRuntimeError> {
        validate_agent_turn_request(&request)?;
        if request.tenant_id != self.tenant_id {
            return Err(AgentRuntimeError::InvalidRequest(
                "tenant does not match the Slack runtime".into(),
            ));
        }
        if self.sessions.is_none() {
            return Err(AgentRuntimeError::ModelUnavailable(
                "durable Slack session storage is required".into(),
            ));
        }
        self.run_session_v2(request).await
    }

    pub async fn run_due_wake(
        &self,
        worker_ref: &str,
    ) -> Result<Option<AgentWakeTurn>, AgentRuntimeError> {
        let store = self.sessions.as_ref().ok_or_else(|| {
            AgentRuntimeError::ModelUnavailable("durable session store is not configured".into())
        })?;
        let Some(claim) = store
            .claim_due_wake(&self.tenant_id, worker_ref, 1_000)
            .await?
        else {
            return Ok(None);
        };
        let result = self.run_claimed_wake(store, &claim).await;
        match result {
            Ok(turn) if turn.delivery == DeliveryDisposition::Visible => {
                store
                    .prepare_wake_delivery(&claim, &turn.payload_digest)
                    .await?;
                Ok(Some(AgentWakeTurn {
                    commitment_ref: claim.commitment_ref,
                    request_id: claim.request_id,
                    schedule_generation: claim.schedule_generation,
                    session_ref: claim.session_ref,
                    state: "awaiting_delivery",
                }))
            }
            Ok(turn) => {
                store
                    .complete_wake_silently(&claim, &turn.payload_digest, turn.final_state)
                    .await?;
                Ok(Some(AgentWakeTurn {
                    commitment_ref: claim.commitment_ref,
                    request_id: claim.request_id,
                    schedule_generation: claim.schedule_generation,
                    session_ref: claim.session_ref,
                    state: "completed_silently",
                }))
            }
            Err(error) => {
                match store
                    .fail_wake(&claim, "scheduled wake execution failed")
                    .await?
                {
                    AgentWakeFailureDisposition::RetryScheduled => Err(error),
                    AgentWakeFailureDisposition::ExhaustedAwaitingDelivery => {
                        Ok(Some(AgentWakeTurn {
                            commitment_ref: claim.commitment_ref,
                            request_id: claim.request_id,
                            schedule_generation: claim.schedule_generation,
                            session_ref: claim.session_ref,
                            state: "awaiting_delivery",
                        }))
                    }
                }
            }
        }
    }

    pub async fn claim_pending_wake_delivery(
        &self,
        worker_ref: &str,
    ) -> Result<Option<AgentPendingWakeDelivery>, AgentRuntimeError> {
        let store = self.sessions.as_ref().ok_or_else(|| {
            AgentRuntimeError::ModelUnavailable("durable session store is not configured".into())
        })?;
        store
            .claim_pending_wake_delivery(&self.tenant_id, worker_ref, 300)
            .await
    }

    async fn run_claimed_wake(
        &self,
        store: &Arc<PostgresAgentSessionStore>,
        claim: &AgentWakeClaim,
    ) -> Result<ClaimedWakeTurn, AgentRuntimeError> {
        let mut session = store.load(&claim.session_ref).await?.ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("wake session does not exist".into())
        })?;
        if session.tenant_id != self.tenant_id {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake session tenant does not match the Slack runtime".into(),
            ));
        }
        if let Some(pending) = &session.pending_delivery {
            if pending.request_id != claim.request_id {
                return Err(AgentRuntimeError::InvalidRequest(
                    "wake session has an unrelated pending delivery".into(),
                ));
            }
            return pending_wake_turn(&session, claim);
        }
        let triggered = session.events.iter().any(|event| {
            matches!(
                &event.event,
                SessionEvent::WakeTriggered {
                    request_id,
                    commitment_ref,
                    occurrence_ref,
                    ..
                } if request_id == &claim.request_id
                    && commitment_ref == &claim.commitment_ref
                    && occurrence_ref == &claim.occurrence_ref
            )
        });
        if !triggered {
            let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
            let occurred_at = OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .map_err(|error| AgentRuntimeError::InvalidRequest(error.to_string()))?;
            let event = SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: expected_sequence + 1,
                occurred_at,
                event: SessionEvent::WakeTriggered {
                    request_id: claim.request_id.clone(),
                    commitment_ref: claim.commitment_ref.clone(),
                    occurrence_ref: claim.occurrence_ref.clone(),
                    scheduled_for: claim.wake_at.clone(),
                },
            };
            store
                .append_wake_fenced(claim, expected_sequence, std::slice::from_ref(&event))
                .await?;
            session = apply_session_events(&session, &[event])?;
        }
        session.effect_authorizations.clear();
        let assessment_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidRequest(error.to_string()))?;
        let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
        let journal =
            PostgresTurnJournal::new_wake(store.clone(), claim.clone(), expected_sequence);
        let outcome = tokio::time::timeout(
            StdDuration::from_secs(900),
            run_session_turn_recorded(
                self.model.as_ref(),
                self.tools.as_ref(),
                &journal,
                session.clone(),
                SessionTurnInput {
                    request_id: claim.request_id.clone(),
                    actor_ref: "cerebro-scheduler".into(),
                    assessment_at,
                    requested_lane: None,
                    trigger: SessionTurnTrigger::Wake {
                        commitment_ref: claim.commitment_ref.clone(),
                        occurrence_ref: claim.occurrence_ref.clone(),
                    },
                },
            ),
        )
        .await
        .map_err(|_| AgentRuntimeError::ModelUnavailable("wake turn deadline exceeded".into()))??;
        let SessionTurnOutcome::PendingDelivery {
            ref markdown,
            delivery,
            final_state,
            ..
        } = outcome
        else {
            return Err(AgentRuntimeError::InvalidRequest(
                "scheduled wakes cannot request effect approval".into(),
            ));
        };
        let delivery_markdown = render_slack_mrkdwn(markdown.trim());
        Ok(ClaimedWakeTurn {
            delivery,
            final_state,
            payload_digest: message_digest(&delivery_markdown),
        })
    }

    async fn run_session_v2(
        &self,
        request: AgentTurnRequest,
    ) -> Result<AgentTurnOutcome, AgentRuntimeError> {
        if let Some(context_scope_ref) = request.context_scope_ref.as_deref() {
            validate_context_scope_ref(context_scope_ref)?;
        }
        let store = self.sessions.as_ref().ok_or_else(|| {
            AgentRuntimeError::ModelUnavailable("durable session store is not configured".into())
        })?;
        let mut session = match store
            .load_by_thread(&request.tenant_id, &request.thread_ref)
            .await?
        {
            Some(session) => session,
            None => {
                let session = new_session(&request)?;
                store.create(&session).await?;
                session
            }
        };
        match (
            session.context_scope_ref.as_deref(),
            request.context_scope_ref.as_deref(),
        ) {
            (Some(stored), Some(requested)) if stored != requested => {
                return Err(AgentRuntimeError::InvalidRequest(
                    "conversation scope does not match the stored Slack session".into(),
                ));
            }
            (None, Some(requested)) => {
                store
                    .bind_context_scope(&session.session_ref, requested)
                    .await?;
                session.context_scope_ref = Some(requested.to_owned());
            }
            _ => {}
        }
        if let Some(context_scope_ref) = request.context_scope_ref.as_deref() {
            let recall_capacity = MAX_SESSION_MEMORIES.saturating_sub(session.memories.len());
            if recall_capacity > 0 {
                let recalled = store
                    .recall_thread_contexts(
                        &request.tenant_id,
                        &request.actor_ref,
                        context_scope_ref,
                        &session.session_ref,
                        i64::try_from(recall_capacity.min(12)).unwrap_or(12),
                    )
                    .await?;
                merge_recalled_memories(&mut session, recalled);
            }
        }
        session.effect_authorizations = request.effect_authorizations.clone();
        let message_ref = format!("operator:{}", request.request_id);
        let original_message = durable_operator_message(&session, &request.request_id);
        if original_message.is_some_and(|message| {
            message.actor_ref != request.actor_ref || message.text != request.message
        }) {
            return Err(AgentRuntimeError::InvalidRequest(
                "request id was reused with a different actor or message".into(),
            ));
        }
        let message_exists = original_message.is_some();
        if message_exists && let Some(replayed) = replay_completed_session_turn(&session, &request)?
        {
            return Ok(replayed);
        }
        if let Some(pending) = &session.pending_delivery {
            if pending.request_id == request.request_id && message_exists {
                return replay_pending_session_turn(&session, &request);
            }
            return Err(AgentRuntimeError::InvalidRequest(
                "the previous response is still awaiting a Slack delivery receipt".into(),
            ));
        }
        if message_exists
            && session
                .messages
                .last()
                .is_none_or(|message| message.message_ref != message_ref)
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "retried request is not the latest queued operator message".into(),
            ));
        }
        let accepted_route = accepted_route_receipt_for_request(&session, &request.request_id);
        let lease_owner = format!(
            "rust-slack-agent:{}:{}",
            request.request_id,
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        if !store
            .acquire_turn(
                &session.session_ref,
                &request.request_id,
                &lease_owner,
                OPERATOR_TURN_LEASE_SECONDS,
            )
            .await?
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "another turn currently owns this Slack session".into(),
            ));
        }
        if request.followup_acceptance.is_some() {
            return self
                .accept_followup_offer(store, session, request, message_exists, &lease_owner)
                .await;
        }
        if !message_exists {
            let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
            let durable_events = vec![SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: expected_sequence + 1,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::UserMessageQueued {
                    message: SessionMessage {
                        role: SessionMessageRole::User,
                        message_ref,
                        actor_ref: request.actor_ref.clone(),
                        text: request.message.clone(),
                        received_at: request.assessment_at.clone(),
                    },
                },
            }];
            if let Err(error) = store
                .append_operator_fenced(
                    &session.session_ref,
                    &request.request_id,
                    &lease_owner,
                    OPERATOR_TURN_LEASE_SECONDS,
                    expected_sequence,
                    &durable_events,
                )
                .await
            {
                return Err(release_turn_after_failure(
                    store,
                    &session.session_ref,
                    &request.request_id,
                    &lease_owner,
                    error,
                )
                .await);
            }
            session = match apply_session_events(&session, &durable_events) {
                Ok(session) => session,
                Err(error) => {
                    return Err(release_turn_after_failure(
                        store,
                        &session.session_ref,
                        &request.request_id,
                        &lease_owner,
                        error,
                    )
                    .await);
                }
            };
        }
        let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
        let journal = PostgresTurnJournal::new(
            store.clone(),
            session.session_ref.clone(),
            request.request_id.clone(),
            lease_owner.clone(),
            OPERATOR_TURN_LEASE_SECONDS,
            expected_sequence,
        );
        let offers_enabled = request
            .capabilities
            .iter()
            .any(|capability| capability == PROACTIVE_FOLLOWUP_CAPABILITY_V1);
        let session_turn = async {
            let input = SessionTurnInput {
                request_id: request.request_id.clone(),
                actor_ref: request.actor_ref.clone(),
                assessment_at: request.assessment_at.clone(),
                requested_lane: accepted_route.map(|route| route.lane),
                trigger: cerebro_agent_runtime::session::SessionTurnTrigger::Operator,
            };
            if offers_enabled {
                run_session_turn_recorded_with_followup_offers(
                    self.model.as_ref(),
                    self.tools.as_ref(),
                    &journal,
                    session.clone(),
                    input,
                )
                .await
            } else {
                run_session_turn_recorded(
                    self.model.as_ref(),
                    self.tools.as_ref(),
                    &journal,
                    session.clone(),
                    input,
                )
                .await
            }
        };
        let outcome = tokio::time::timeout(StdDuration::from_secs(900), session_turn)
            .await
            .map_err(|_| {
                AgentRuntimeError::ModelUnavailable("session turn deadline exceeded".into())
            })
            .and_then(|result| result);
        match outcome {
            Ok(outcome @ SessionTurnOutcome::PendingDelivery { .. }) => {
                Ok(session_outcome_to_turn(outcome))
            }
            Ok(outcome @ SessionTurnOutcome::ApprovalRequired { .. }) => {
                Ok(session_outcome_to_turn(outcome))
            }
            Err(error) => Err(release_turn_after_failure(
                store,
                &session.session_ref,
                &request.request_id,
                &lease_owner,
                error,
            )
            .await),
        }
    }

    async fn accept_followup_offer(
        &self,
        store: &Arc<PostgresAgentSessionStore>,
        session: AgentSession,
        request: AgentTurnRequest,
        message_exists: bool,
        lease_owner: &str,
    ) -> Result<AgentTurnOutcome, AgentRuntimeError> {
        let result = async {
            if message_exists {
                return Err(AgentRuntimeError::InvalidRequest(
                    "proactive follow-up acceptance retry has no committed outcome".into(),
                ));
            }
            let acceptance = request.followup_acceptance.as_ref().ok_or_else(|| {
                AgentRuntimeError::InvalidRequest(
                    "proactive follow-up acceptance payload is missing".into(),
                )
            })?;
            let accepted_at = OffsetDateTime::now_utc();
            let assessment_at =
                OffsetDateTime::parse(&request.assessment_at, &Rfc3339).map_err(|_| {
                    AgentRuntimeError::InvalidRequest("assessment_at is invalid".into())
                })?;
            if accepted_at < assessment_at
                || accepted_at - assessment_at
                    > TimeDuration::seconds(MAX_ACCEPTANCE_CLOCK_DELAY_SECONDS)
            {
                return Err(AgentRuntimeError::InvalidRequest(
                    "follow-up acceptance exceeded the bounded host-entry window".into(),
                ));
            }
            let accepted_at_text = accepted_at
                .format(&Rfc3339)
                .map_err(|error| AgentRuntimeError::InvalidRequest(error.to_string()))?;
            let resolved = validate_followup_acceptance(&session, acceptance, accepted_at)?;
            let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
            let mut events = vec![
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: expected_sequence + 1,
                    occurred_at: accepted_at_text.clone(),
                    event: SessionEvent::UserMessageQueued {
                        message: SessionMessage {
                            role: SessionMessageRole::User,
                            message_ref: format!("operator:{}", request.request_id),
                            actor_ref: request.actor_ref.clone(),
                            text: request.message.clone(),
                            received_at: accepted_at_text.clone(),
                        },
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: expected_sequence + 2,
                    occurred_at: accepted_at_text.clone(),
                    event: SessionEvent::RouteAccepted {
                        request_id: request.request_id.clone(),
                        lane: ExecutionLane::Investigate,
                        future_observation:
                            cerebro_agent_runtime::FutureObservationDisposition::Inherited,
                        future_observation_excerpt: None,
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: expected_sequence + 3,
                    occurred_at: accepted_at_text.clone(),
                    event: SessionEvent::TurnStarted {
                        request_id: request.request_id.clone(),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: expected_sequence + 4,
                    occurred_at: accepted_at_text.clone(),
                    event: SessionEvent::FollowupAccepted {
                        request_id: request.request_id.clone(),
                        offer_ref: resolved.offer.offer_ref.clone(),
                    },
                },
            ];
            let accepted_session = apply_session_events(&session, &events)?;
            let draft = followup_acceptance_draft(
                &accepted_session,
                &resolved.offer.offer_ref,
                accepted_at,
            )?;
            events.push(SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: expected_sequence + 5,
                occurred_at: accepted_at_text,
                event: SessionEvent::DraftProduced {
                    request_id: request.request_id.clone(),
                    draft: draft.clone(),
                },
            });
            store
                .append_operator_finalized(
                    &session.session_ref,
                    &request.request_id,
                    lease_owner,
                    OPERATOR_TURN_LEASE_SECONDS,
                    expected_sequence,
                    &events,
                )
                .await?;
            Ok(session_outcome_to_turn(
                SessionTurnOutcome::PendingDelivery {
                    lane: ExecutionLane::Investigate,
                    delivery: DeliveryDisposition::Visible,
                    markdown: draft.message,
                    final_state: draft.state,
                    evidence_atom_refs: Vec::new(),
                    proactive_followup_offer: None,
                    accepted_followup_ref: Some(resolved.offer.offer_ref),
                    mission: draft.mission,
                    events,
                },
            ))
        }
        .await;
        match result {
            Ok(outcome) => Ok(outcome),
            Err(error) => Err(release_turn_after_failure(
                store,
                &session.session_ref,
                &request.request_id,
                lease_owner,
                error,
            )
            .await),
        }
    }

    pub async fn record_delivery(
        &self,
        receipt: AgentDeliveryReceipt,
    ) -> Result<(), AgentRuntimeError> {
        validate_delivery_receipt(&receipt, &self.tenant_id)?;
        let store = self.sessions.as_ref().ok_or_else(|| {
            AgentRuntimeError::InvalidRequest(
                "delivery receipts require the durable session runtime".into(),
            )
        })?;
        let session = store
            .load_by_thread(&receipt.tenant_id, &receipt.thread_ref)
            .await?
            .ok_or_else(|| AgentRuntimeError::InvalidRequest("session does not exist".into()))?;
        if delivery_replay_matches(&session, &receipt)? {
            return Ok(());
        }
        let pending = session.pending_delivery.as_ref().ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("delivery receipt has no pending response".into())
        })?;
        if pending.request_id != receipt.request_id {
            return Err(AgentRuntimeError::InvalidRequest(
                "delivery receipt belongs to another request".into(),
            ));
        }
        let delivery_markdown = turn_delivery_markdown(&pending.draft.message);
        if receipt.payload_digest != message_digest(&delivery_markdown) {
            return Err(AgentRuntimeError::InvalidRequest(
                "delivery receipt payload does not match the pending response".into(),
            ));
        }
        let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
        let receipt_for_replay = receipt.clone();
        let events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: expected_sequence + 1,
                occurred_at: receipt.delivered_at.clone(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: receipt.request_id.clone(),
                    transport: receipt.transport,
                    delivery_ref: receipt.delivery_ref,
                    payload_digest: receipt.payload_digest,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: expected_sequence + 2,
                occurred_at: receipt.delivered_at,
                event: SessionEvent::TurnCompleted {
                    request_id: receipt.request_id,
                    state: pending.draft.state,
                },
            },
        ];
        match store
            .append_delivery_completion(
                &session.session_ref,
                &receipt_for_replay.request_id,
                expected_sequence,
                &events,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                let replayed = match store.load(&session.session_ref).await? {
                    Some(current) => delivery_replay_matches(&current, &receipt_for_replay)?,
                    None => false,
                };
                if replayed { Ok(()) } else { Err(error) }
            }
        }
    }

    pub async fn record_wake_delivery(
        &self,
        delivery: AgentWakeDeliveryReceipt,
    ) -> Result<(), AgentRuntimeError> {
        let AgentWakeDeliveryReceipt { lease, receipt } = delivery;
        validate_delivery_receipt(&receipt, &self.tenant_id)?;
        if receipt.request_id != lease.request_id || receipt.payload_digest != lease.payload_digest
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake delivery receipt changed after the payload was claimed".into(),
            ));
        }
        let store = self.sessions.as_ref().ok_or_else(|| {
            AgentRuntimeError::InvalidRequest(
                "wake delivery receipts require the durable session runtime".into(),
            )
        })?;
        let session = store
            .load(&lease.session_ref)
            .await?
            .ok_or_else(|| AgentRuntimeError::InvalidRequest("session does not exist".into()))?;
        if session.tenant_id != receipt.tenant_id || session.thread_ref != receipt.thread_ref {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake delivery receipt belongs to another session".into(),
            ));
        }
        if delivery_replay_matches(&session, &receipt)? {
            return Ok(());
        }
        let pending = session.pending_delivery.as_ref().ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("wake delivery has no pending response".into())
        })?;
        if pending.request_id != receipt.request_id
            || message_digest(&turn_delivery_markdown(&pending.draft.message))
                != receipt.payload_digest
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "wake delivery does not match the durable pending response".into(),
            ));
        }
        let expected_sequence = session.events.last().map_or(0, |event| event.sequence);
        let receipt_for_replay = receipt.clone();
        let events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: expected_sequence + 1,
                occurred_at: receipt.delivered_at.clone(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: receipt.request_id.clone(),
                    transport: receipt.transport,
                    delivery_ref: receipt.delivery_ref,
                    payload_digest: receipt.payload_digest,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: expected_sequence + 2,
                occurred_at: receipt.delivered_at,
                event: SessionEvent::TurnCompleted {
                    request_id: receipt.request_id,
                    state: pending.draft.state,
                },
            },
        ];
        match store
            .append_wake_delivery_fenced(&lease, expected_sequence, &events)
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => {
                let replayed = match store.load(&session.session_ref).await? {
                    Some(current) => delivery_replay_matches(&current, &receipt_for_replay)?,
                    None => false,
                };
                if replayed { Ok(()) } else { Err(error) }
            }
        }
    }
}

fn delivery_replay_matches(
    session: &AgentSession,
    receipt: &AgentDeliveryReceipt,
) -> Result<bool, AgentRuntimeError> {
    let Some(recorded) = session.events.iter().find_map(|event| match &event.event {
        SessionEvent::DeliveryRecorded {
            request_id,
            transport,
            delivery_ref,
            payload_digest,
        } if request_id == &receipt.request_id => Some((transport, delivery_ref, payload_digest)),
        _ => None,
    }) else {
        return Ok(false);
    };
    if recorded
        == (
            &receipt.transport,
            &receipt.delivery_ref,
            &receipt.payload_digest,
        )
    {
        return Ok(true);
    }
    Err(AgentRuntimeError::InvalidRequest(
        "delivery receipt changed after the request was recorded".into(),
    ))
}

fn validate_delivery_receipt(
    receipt: &AgentDeliveryReceipt,
    tenant_id: &str,
) -> Result<(), AgentRuntimeError> {
    if receipt.schema_version != AGENT_DELIVERY_RECEIPT_V1
        || receipt.tenant_id != tenant_id
        || receipt.thread_ref.trim().is_empty()
        || receipt.request_id.trim().is_empty()
        || receipt.transport.trim().is_empty()
        || receipt.delivery_ref.trim().is_empty()
        || !is_sha256_digest(&receipt.payload_digest)
        || OffsetDateTime::parse(&receipt.delivered_at, &Rfc3339).is_err()
    {
        return Err(AgentRuntimeError::InvalidRequest(
            "delivery receipt identity, transport, or timestamp is invalid".into(),
        ));
    }
    Ok(())
}

fn project_turn_progress(
    session: &AgentSession,
    request_id: &str,
    after_sequence: u64,
) -> AgentTurnProgress {
    let Some(started_index) = session.events.iter().rposition(|record| {
        matches!(
            &record.event,
            SessionEvent::TurnStarted { request_id: started } if started == request_id
        )
    }) else {
        return AgentTurnProgress {
            schema_version: "agent-turn-progress/v1",
            latest_sequence: after_sequence,
            updates: Vec::new(),
        };
    };
    let updates = session.events[started_index..]
        .iter()
        .take_while(|record| {
            !matches!(
                &record.event,
                SessionEvent::TurnStarted { request_id: started } if started != request_id
            )
        })
        .filter(|record| record.sequence > after_sequence)
        .filter_map(|record| match &record.event {
            SessionEvent::Progressed { phase, status } => Some(AgentTurnProgressUpdate {
                sequence: record.sequence,
                occurred_at: record.occurred_at.clone(),
                phase: phase.clone(),
                status: status.clone(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    let latest_sequence = updates
        .last()
        .map_or(after_sequence, |update| update.sequence);
    AgentTurnProgress {
        schema_version: "agent-turn-progress/v1",
        latest_sequence,
        updates,
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_bedrock_opus_model(value: &str) -> bool {
    let model = value.trim();
    model.starts_with("anthropic.claude-opus-") || model.contains(".anthropic.claude-opus-")
}

pub(super) fn validate_context_scope_ref(value: &str) -> Result<(), AgentRuntimeError> {
    const PREFIX: &str = "slack-context-scope://sha256/";
    let digest = value.strip_prefix(PREFIX).ok_or_else(|| {
        AgentRuntimeError::InvalidRequest(
            "conversation scope must be a canonical Slack context reference".into(),
        )
    })?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(AgentRuntimeError::InvalidRequest(
            "conversation scope must be a canonical Slack context reference".into(),
        ));
    }
    Ok(())
}

fn merge_recalled_memories(
    session: &mut AgentSession,
    recalled: Vec<cerebro_agent_runtime::session::MemoryUpdate>,
) {
    for memory in recalled {
        if session.memories.len() >= MAX_SESSION_MEMORIES {
            break;
        }
        if !session
            .memories
            .iter()
            .any(|existing| existing.memory_ref == memory.memory_ref)
        {
            session.memories.push(memory);
        }
    }
}

pub(super) fn new_session(request: &AgentTurnRequest) -> Result<AgentSession, AgentRuntimeError> {
    validate_agent_turn_request(request)?;
    let identity = format!("{}:{}", request.tenant_id, request.thread_ref);
    let digest = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let messages = request
        .history
        .iter()
        .enumerate()
        .map(|(index, message)| {
            let metadata = request.history_metadata.get(index);
            SessionMessage {
                role: match message.role {
                    cerebro_agent_runtime::ConversationRole::Assistant => {
                        SessionMessageRole::Assistant
                    }
                    cerebro_agent_runtime::ConversationRole::User => SessionMessageRole::User,
                },
                message_ref: metadata
                    .and_then(|value| value.message_ref.clone())
                    .unwrap_or_else(|| format!("imported-history:{}", index + 1)),
                actor_ref: metadata
                    .and_then(|value| value.actor_ref.clone())
                    .unwrap_or_else(|| {
                        if metadata.is_some() {
                            "context:unattributed".into()
                        } else {
                            match message.role {
                                cerebro_agent_runtime::ConversationRole::Assistant => {
                                    "cerebro".into()
                                }
                                cerebro_agent_runtime::ConversationRole::User => {
                                    request.actor_ref.clone()
                                }
                            }
                        }
                    }),
                text: message.content.clone(),
                received_at: metadata
                    .and_then(|value| value.received_at.clone())
                    .unwrap_or_else(|| request.assessment_at.clone()),
            }
        })
        .collect();
    let session = AgentSession {
        schema_version: AGENT_SESSION_V2.into(),
        session_ref: format!("agent-session:{digest}"),
        tenant_id: request.tenant_id.clone(),
        thread_ref: request.thread_ref.clone(),
        context_scope_ref: request.context_scope_ref.clone(),
        mission: MissionState {
            mission_ref: format!("mission:{digest}"),
            objective: request.message.clone(),
            desired_outcome: format!("Handle this operator request: {}", request.message),
            resolved_scope: Vec::new(),
            scope_assumptions: Vec::new(),
            acceptance_criteria: Vec::new(),
            commitments: Vec::new(),
            open_loops: Vec::new(),
            status: SessionStatus::Active,
        },
        messages,
        events: Vec::new(),
        effect_authorizations: request.effect_authorizations.clone(),
        pending_delivery: None,
        memories: Vec::new(),
    };
    cerebro_agent_runtime::session::validate_session(&session)?;
    Ok(session)
}

pub(super) fn session_outcome_to_turn(outcome: SessionTurnOutcome) -> AgentTurnOutcome {
    match outcome {
        SessionTurnOutcome::ApprovalRequired { request, events } => {
            let tool_call_count = events
                .iter()
                .filter(|event| matches!(event.event, SessionEvent::ToolInvoked { .. }))
                .count();
            AgentTurnOutcome::ApprovalRequired {
                schema_version: cerebro_agent_runtime::AGENT_TURN_RESULT_V1,
                lane: ExecutionLane::Act,
                request,
                tool_call_count,
            }
        }
        SessionTurnOutcome::PendingDelivery {
            lane,
            delivery: _,
            markdown,
            final_state,
            evidence_atom_refs,
            proactive_followup_offer,
            accepted_followup_ref,
            mission,
            events,
        } => {
            let tool_call_count = events
                .iter()
                .filter(|event| matches!(event.event, SessionEvent::ToolInvoked { .. }))
                .count();
            let open_loops = mission
                .open_loops
                .iter()
                .map(|open_loop| open_loop.summary.clone())
                .chain(
                    mission
                        .commitments
                        .iter()
                        .filter(|commitment| {
                            !matches!(
                                commitment.status,
                                cerebro_agent_runtime::session::CommitmentStatus::Completed
                                    | cerebro_agent_runtime::session::CommitmentStatus::Cancelled
                            )
                        })
                        .map(|commitment| commitment.summary.clone()),
                )
                .collect();
            let last_outcome = match final_state {
                FinalState::Answered => cerebro_agent_runtime::WorkingOutcome::Completed,
                FinalState::Partial => cerebro_agent_runtime::WorkingOutcome::Blocked,
                FinalState::NeedsInput => cerebro_agent_runtime::WorkingOutcome::NeedsUser,
                FinalState::Blocked => cerebro_agent_runtime::WorkingOutcome::Blocked,
            };
            let last_blocker = events.iter().rev().find_map(|event| match &event.event {
                SessionEvent::DraftProduced { draft, .. } => draft.coverage_notice.clone(),
                _ => None,
            });
            AgentTurnOutcome::PendingDelivery {
                schema_version: cerebro_agent_runtime::AGENT_TURN_RESULT_V1,
                lane,
                markdown: turn_delivery_markdown(&markdown),
                final_state,
                evidence_refs: evidence_atom_refs,
                tool_call_count,
                working_state: Some(cerebro_agent_runtime::WorkingState {
                    mission_ref: Some(mission.mission_ref),
                    current_request: mission.objective,
                    last_outcome,
                    last_blocker,
                    active_lane: Some(lane),
                    requires_current_evidence: Some(lane != ExecutionLane::Converse),
                    open_loops,
                }),
                proactive_followup_offer: proactive_followup_offer.map(|offer| *offer),
                accepted_followup_ref,
            }
        }
    }
}

pub(crate) fn replay_completed_session_turn(
    session: &AgentSession,
    request: &AgentTurnRequest,
) -> Result<Option<AgentTurnOutcome>, AgentRuntimeError> {
    let original = durable_operator_message(session, &request.request_id).ok_or_else(|| {
        AgentRuntimeError::InvalidRequest("replayed request has no durable message".into())
    })?;
    if original.actor_ref != request.actor_ref || original.text != request.message {
        return Err(AgentRuntimeError::InvalidRequest(
            "request id was reused with a different actor or message".into(),
        ));
    }
    let completed_index = session.events.iter().rposition(|event| {
        matches!(
            &event.event,
            SessionEvent::TurnCompleted {
                request_id: completed,
                ..
            } if completed == &request.request_id
        )
    });
    let Some(completed_index) = completed_index else {
        return Ok(None);
    };
    let started_index = session.events[..=completed_index]
        .iter()
        .rposition(|event| {
            matches!(
                &event.event,
                SessionEvent::TurnStarted {
                    request_id: started,
                } if started == &request.request_id
            )
        })
        .ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("completed turn has no start event".into())
        })?;
    let route_index = session.events[..=started_index]
        .iter()
        .rposition(|event| {
            matches!(
                &event.event,
                SessionEvent::RouteAccepted { request_id, .. }
                    if request_id == &request.request_id
            )
        })
        .unwrap_or(started_index);
    let events = session.events[route_index..=completed_index].to_vec();
    let draft = events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::DraftProduced { draft, .. } => Some(draft.clone()),
            _ => None,
        })
        .ok_or_else(|| AgentRuntimeError::InvalidRequest("completed turn has no draft".into()))?;
    let evidence_atom_refs = draft_evidence_refs(&draft);
    let lane = event_lane(&events, &request.request_id);
    let outcome = session_outcome_to_turn(SessionTurnOutcome::PendingDelivery {
        lane,
        delivery: draft.delivery,
        markdown: draft.message,
        final_state: draft.state,
        evidence_atom_refs,
        proactive_followup_offer: events.iter().rev().find_map(|event| match &event.event {
            SessionEvent::FollowupOffered {
                offer, request_id, ..
            } if request_id == &request.request_id => Some(Box::new(offer.clone())),
            _ => None,
        }),
        accepted_followup_ref: events.iter().rev().find_map(|event| match &event.event {
            SessionEvent::FollowupAccepted {
                offer_ref,
                request_id,
            } if request_id == &request.request_id => Some(offer_ref.clone()),
            _ => None,
        }),
        mission: draft.mission,
        events,
    });
    let AgentTurnOutcome::PendingDelivery {
        schema_version,
        lane,
        markdown,
        final_state,
        evidence_refs,
        tool_call_count,
        working_state,
        proactive_followup_offer,
        accepted_followup_ref,
    } = outcome
    else {
        return Err(AgentRuntimeError::InvalidRequest(
            "completed session replay did not reconstruct a response".into(),
        ));
    };
    Ok(Some(AgentTurnOutcome::Delivered {
        schema_version,
        lane,
        markdown,
        final_state,
        evidence_refs,
        tool_call_count,
        working_state,
        proactive_followup_offer,
        accepted_followup_ref,
    }))
}

pub(crate) fn replay_pending_session_turn(
    session: &AgentSession,
    request: &AgentTurnRequest,
) -> Result<AgentTurnOutcome, AgentRuntimeError> {
    let original = durable_operator_message(session, &request.request_id).ok_or_else(|| {
        AgentRuntimeError::InvalidRequest("pending request has no durable message".into())
    })?;
    if original.actor_ref != request.actor_ref || original.text != request.message {
        return Err(AgentRuntimeError::InvalidRequest(
            "request id was reused with a different actor or message".into(),
        ));
    }
    let pending = session.pending_delivery.as_ref().ok_or_else(|| {
        AgentRuntimeError::InvalidRequest("session has no response awaiting delivery".into())
    })?;
    if pending.request_id != request.request_id {
        return Err(AgentRuntimeError::InvalidRequest(
            "pending response belongs to another request".into(),
        ));
    }
    let started_index = session
        .events
        .iter()
        .rposition(|event| {
            matches!(
                &event.event,
                SessionEvent::TurnStarted { request_id } if request_id == &request.request_id
            )
        })
        .ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("pending turn has no start event".into())
        })?;
    let route_index = session.events[..=started_index]
        .iter()
        .rposition(|event| {
            matches!(
                &event.event,
                SessionEvent::RouteAccepted { request_id, .. }
                    if request_id == &request.request_id
            )
        })
        .unwrap_or(started_index);
    let events = session.events[route_index..].to_vec();
    let lane = event_lane(&events, &request.request_id);
    let evidence_atom_refs = draft_evidence_refs(&pending.draft);
    Ok(session_outcome_to_turn(
        SessionTurnOutcome::PendingDelivery {
            lane,
            delivery: pending.draft.delivery,
            markdown: pending.draft.message.clone(),
            final_state: pending.draft.state,
            evidence_atom_refs,
            proactive_followup_offer: offered_followup_for_request(session, &request.request_id)
                .map(Box::new),
            accepted_followup_ref: session.events.iter().rev().find_map(|event| {
                match &event.event {
                    SessionEvent::FollowupAccepted {
                        offer_ref,
                        request_id,
                    } if request_id == &request.request_id => Some(offer_ref.clone()),
                    _ => None,
                }
            }),
            mission: pending.draft.mission.clone(),
            events,
        },
    ))
}

fn offered_followup_for_request(
    session: &AgentSession,
    request_id: &str,
) -> Option<ProactiveFollowupOffer> {
    session
        .events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::FollowupOffered {
                request_id: offered_request_id,
                offer,
                ..
            } if offered_request_id == request_id => Some(offer.clone()),
            _ => None,
        })
}

fn turn_delivery_markdown(markdown: &str) -> String {
    render_slack_mrkdwn(markdown.trim())
}

pub(crate) fn durable_operator_message<'a>(
    session: &'a AgentSession,
    request_id: &str,
) -> Option<&'a SessionMessage> {
    let message_ref = format!("operator:{request_id}");
    session.events.iter().find_map(|event| match &event.event {
        SessionEvent::UserMessageQueued { message } if message.message_ref == message_ref => {
            Some(message)
        }
        _ => None,
    })
}

pub(crate) fn accepted_route_receipt_for_request(
    session: &AgentSession,
    request_id: &str,
) -> Option<ResolvedRequestRoute> {
    session
        .events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::RouteAccepted {
                request_id: accepted_request_id,
                lane,
                future_observation,
                future_observation_excerpt,
            } if accepted_request_id == request_id => Some(ResolvedRequestRoute {
                lane: *lane,
                future_observation: *future_observation,
                future_observation_excerpt: future_observation_excerpt.clone(),
            }),
            _ => None,
        })
}

fn combine_turn_release_error(
    primary: AgentRuntimeError,
    release: AgentRuntimeError,
) -> AgentRuntimeError {
    AgentRuntimeError::ModelUnavailable(format!(
        "{primary}; the exact turn lease also failed to release: {release}"
    ))
}

async fn release_turn_after_failure(
    store: &PostgresAgentSessionStore,
    session_ref: &str,
    request_id: &str,
    lease_owner: &str,
    primary: AgentRuntimeError,
) -> AgentRuntimeError {
    match store
        .release_turn(session_ref, request_id, lease_owner)
        .await
    {
        Ok(()) => primary,
        Err(release) => combine_turn_release_error(primary, release),
    }
}

pub(crate) fn route_request_from_session(
    session: &AgentSession,
    request: &AgentTurnRequest,
) -> AgentTurnRequest {
    let current_message_ref = format!("operator:{}", request.request_id);
    let history = session
        .messages
        .iter()
        .filter(|message| message.message_ref != current_message_ref)
        .map(|message| cerebro_agent_runtime::ConversationMessage {
            role: match message.role {
                SessionMessageRole::Assistant => cerebro_agent_runtime::ConversationRole::Assistant,
                SessionMessageRole::User => cerebro_agent_runtime::ConversationRole::User,
            },
            content: message.text.clone(),
        })
        .collect();
    let has_delivered_turn = session
        .events
        .iter()
        .any(|event| matches!(&event.event, SessionEvent::DeliveryRecorded { .. }));
    let delivered_index = session
        .events
        .iter()
        .rposition(|event| matches!(&event.event, SessionEvent::DeliveryRecorded { .. }));
    let delivered_request_id =
        delivered_index.and_then(|index| match &session.events[index].event {
            SessionEvent::DeliveryRecorded { request_id, .. } => Some(request_id.as_str()),
            _ => None,
        });
    let delivered_start = delivered_index.and_then(|end| {
        let request_id = delivered_request_id?;
        session.events[..=end]
            .iter()
            .rposition(|event| {
                matches!(
                    &event.event,
                    SessionEvent::RouteAccepted {
                        request_id: accepted_request_id,
                        ..
                    } if accepted_request_id == request_id
                )
            })
            .or_else(|| {
                session.events[..=end].iter().rposition(|event| {
                    matches!(
                        &event.event,
                        SessionEvent::TurnStarted {
                            request_id: started_request_id,
                        } if started_request_id == request_id
                    )
                })
            })
    });
    let delivered_end = match (delivered_index, delivered_request_id) {
        (Some(delivery), Some(request_id)) => session.events[delivery..]
            .iter()
            .position(|event| {
                matches!(
                    &event.event,
                    SessionEvent::TurnCompleted {
                        request_id: completed_request_id,
                        ..
                    } if completed_request_id == request_id
                )
            })
            .map_or(delivery, |offset| delivery + offset),
        _ => 0,
    };
    let delivered_events = match delivered_start {
        Some(start) => &session.events[start..=delivered_end],
        _ => &session.events[0..0],
    };
    let latest_delivered_lane = delivered_request_id
        .and_then(|request_id| request_bound_lane(delivered_events, request_id))
        .or_else(|| {
            delivered_events
                .iter()
                .rev()
                .find_map(|event| match &event.event {
                    SessionEvent::PlanEstablished { plan } => Some(plan.lane),
                    _ => None,
                })
        });
    let mission_is_unresolved = !session.mission.open_loops.is_empty()
        || session.mission.commitments.iter().any(|commitment| {
            !matches!(
                commitment.status,
                cerebro_agent_runtime::session::CommitmentStatus::Completed
                    | cerebro_agent_runtime::session::CommitmentStatus::Cancelled
            )
        });
    let active_lane = if mission_is_unresolved {
        delivered_mission_revision_lane(session).or(latest_delivered_lane)
    } else {
        latest_delivered_lane
    };
    let last_outcome = delivered_events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::TurnCompleted { state, .. } => Some(match state {
                FinalState::Answered => cerebro_agent_runtime::WorkingOutcome::Completed,
                FinalState::Partial | FinalState::Blocked => {
                    cerebro_agent_runtime::WorkingOutcome::Blocked
                }
                FinalState::NeedsInput => cerebro_agent_runtime::WorkingOutcome::NeedsUser,
            }),
            _ => None,
        });
    let last_blocker = delivered_events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::DraftProduced { draft, .. } => draft.coverage_notice.clone(),
            _ => None,
        });
    let open_loops = session
        .mission
        .open_loops
        .iter()
        .map(|open_loop| open_loop.summary.clone())
        .chain(
            session
                .mission
                .commitments
                .iter()
                .filter(|commitment| {
                    !matches!(
                        commitment.status,
                        cerebro_agent_runtime::session::CommitmentStatus::Completed
                            | cerebro_agent_runtime::session::CommitmentStatus::Cancelled
                    )
                })
                .map(|commitment| commitment.summary.clone()),
        )
        .collect();
    let mut routed = request.clone();
    routed.history = history;
    routed.history_metadata.clear();
    routed.working_state = has_delivered_turn.then(|| cerebro_agent_runtime::WorkingState {
        mission_ref: Some(session.mission.mission_ref.clone()),
        current_request: session.mission.objective.clone(),
        last_outcome: last_outcome.unwrap_or(cerebro_agent_runtime::WorkingOutcome::Unknown),
        last_blocker,
        active_lane,
        requires_current_evidence: active_lane.map(|lane| lane != ExecutionLane::Converse),
        open_loops,
    });
    routed
}

fn delivered_mission_revision_lane(session: &AgentSession) -> Option<ExecutionLane> {
    let delivered_requests = session
        .events
        .iter()
        .filter_map(|event| match &event.event {
            SessionEvent::DeliveryRecorded { request_id, .. } => Some(request_id.as_str()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut lanes = BTreeMap::new();
    let mut delivered_mission: Option<&MissionState> = None;
    let mut revision_lane = None;
    for event in &session.events {
        match &event.event {
            SessionEvent::RouteAccepted {
                request_id, lane, ..
            } => {
                lanes.entry(request_id.as_str()).or_insert(*lane);
            }
            SessionEvent::ResearchLaneAccepted { request_id, lane } => {
                lanes.insert(request_id.as_str(), *lane);
            }
            SessionEvent::DraftProduced { request_id, draft }
                if delivered_requests.contains(request_id.as_str())
                    && delivered_mission != Some(&draft.mission) =>
            {
                delivered_mission = Some(&draft.mission);
                revision_lane = lanes.get(request_id.as_str()).copied();
            }
            _ => {}
        }
    }
    (delivered_mission == Some(&session.mission))
        .then_some(revision_lane)
        .flatten()
}

fn pending_wake_turn(
    session: &AgentSession,
    claim: &AgentWakeClaim,
) -> Result<ClaimedWakeTurn, AgentRuntimeError> {
    let pending = session.pending_delivery.as_ref().ok_or_else(|| {
        AgentRuntimeError::InvalidRequest("wake session has no pending delivery".into())
    })?;
    if pending.request_id != claim.request_id {
        return Err(AgentRuntimeError::InvalidRequest(
            "pending wake delivery belongs to another request".into(),
        ));
    }
    session
        .events
        .iter()
        .rposition(|event| {
            matches!(
                &event.event,
                SessionEvent::TurnStarted { request_id } if request_id == &claim.request_id
            )
        })
        .ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("pending wake has no turn start event".into())
        })?;
    Ok(ClaimedWakeTurn {
        delivery: pending.draft.delivery,
        final_state: pending.draft.state,
        payload_digest: message_digest(&render_slack_mrkdwn(pending.draft.message.trim())),
    })
}

fn request_bound_lane(events: &[SessionEventRecord], request_id: &str) -> Option<ExecutionLane> {
    events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::ResearchLaneAccepted {
                request_id: accepted_request_id,
                lane,
            } if accepted_request_id == request_id => Some(*lane),
            _ => None,
        })
        .or_else(|| {
            events.iter().rev().find_map(|event| match &event.event {
                SessionEvent::RouteAccepted {
                    request_id: accepted_request_id,
                    lane,
                    ..
                } if accepted_request_id == request_id => Some(*lane),
                _ => None,
            })
        })
}

fn event_lane(events: &[SessionEventRecord], request_id: &str) -> ExecutionLane {
    request_bound_lane(events, request_id)
        .or_else(|| {
            events.iter().rev().find_map(|event| match &event.event {
                SessionEvent::PlanEstablished { plan } => Some(plan.lane),
                _ => None,
            })
        })
        .unwrap_or(ExecutionLane::Converse)
}

fn draft_evidence_refs(draft: &cerebro_agent_runtime::session::GroundedDraft) -> Vec<String> {
    draft
        .claims
        .iter()
        .flat_map(|claim| match &claim.content {
            cerebro_agent_runtime::session::ClaimContent::Observation { atom_refs }
            | cerebro_agent_runtime::session::ClaimContent::Derivation { atom_refs, .. } => {
                atom_refs.clone()
            }
            cerebro_agent_runtime::session::ClaimContent::Recommendation {
                rationale_atom_refs,
                ..
            } => rationale_atom_refs.clone(),
            cerebro_agent_runtime::session::ClaimContent::Hypothesis {
                supporting_atom_refs,
                ..
            } => supporting_atom_refs.clone(),
            cerebro_agent_runtime::session::ClaimContent::HistoricalContext {
                atom_ref, ..
            } => {
                vec![atom_ref.clone()]
            }
            cerebro_agent_runtime::session::ClaimContent::ConversationalSynthesis {
                source_atom_refs,
                ..
            } => source_atom_refs.clone(),
            _ => Vec::new(),
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

async fn retry_startup<T, E, F, Fut>(
    attempts: usize,
    initial_retry_delay: StdDuration,
    max_retry_delay: StdDuration,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    assert!(attempts > 0, "startup attempts must be greater than zero");
    assert!(
        initial_retry_delay <= max_retry_delay,
        "initial startup retry delay must not exceed the maximum"
    );
    let mut retry_delay = initial_retry_delay;
    for attempt in 1..=attempts {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) if attempt == attempts => return Err(error),
            Err(_) => {
                tokio::time::sleep(retry_delay).await;
                retry_delay = next_startup_retry_delay(retry_delay, max_retry_delay);
            }
        }
    }
    unreachable!("a positive attempt count must return from the retry loop")
}

async fn retry_mcp_startup<T, E, F, Fut>(operation: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
{
    retry_startup(
        STARTUP_DEPENDENCY_ATTEMPTS,
        STARTUP_DEPENDENCY_RETRY_DELAY,
        STARTUP_DEPENDENCY_RETRY_DELAY,
        operation,
    )
    .await
}

fn next_startup_retry_delay(current: StdDuration, maximum: StdDuration) -> StdDuration {
    current.saturating_mul(2).min(maximum)
}

pub(super) enum ConfiguredModel {
    AmazonBedrock(BedrockModel),
}

impl ConfiguredModel {
    fn attestation(&self) -> SlackAgentModelAttestation {
        match self {
            Self::AmazonBedrock(model) => SlackAgentModelAttestation {
                model_config_sha256: model_config_sha256("amazon-bedrock", &model.model),
                model_id: model.model.clone(),
                model_provider: "amazon-bedrock",
            },
        }
    }

    pub(super) async fn amazon_bedrock(model: String) -> Result<Self, Box<dyn Error>> {
        if !is_bedrock_opus_model(&model) {
            return Err("the Rust Slack agent requires an Amazon Bedrock Claude Opus model".into());
        }
        let config = aws_config::defaults(BehaviorVersion::latest())
            .retry_config(RetryConfig::standard().with_max_attempts(5))
            .load()
            .await;
        Ok(Self::AmazonBedrock(BedrockModel {
            client: BedrockClient::new(&config),
            model,
        }))
    }

    pub(super) async fn from_env() -> Result<Self, Box<dyn Error>> {
        if required_env("CEREBRO_SLACK_AGENT_MODEL_PROVIDER")? != "amazon-bedrock" {
            return Err("the Rust Slack agent requires the amazon-bedrock adapter".into());
        }
        Self::amazon_bedrock(required_env("CEREBRO_SLACK_AGENT_MODEL")?).await
    }

    pub(super) async fn complete_evaluation_judgment(
        &self,
        instructions: &str,
        payload: Value,
        max_tokens: i32,
        decision_tool: &str,
        decision_schema: Value,
    ) -> Result<Value, AgentRuntimeError> {
        match self {
            Self::AmazonBedrock(model) => {
                model
                    .complete_structured(
                        instructions,
                        payload,
                        max_tokens,
                        decision_tool,
                        decision_schema,
                    )
                    .await
            }
        }
    }

    async fn complete_session_choice(
        &self,
        instructions: &str,
        payload: Value,
        max_tokens: i32,
        contracts: Vec<StructuredToolContract>,
    ) -> Result<StructuredToolSelection, AgentRuntimeError> {
        retry_session_model_call(|| async {
            match self {
                Self::AmazonBedrock(model) => {
                    model
                        .complete_structured_choice(
                            instructions,
                            payload.clone(),
                            max_tokens,
                            &contracts,
                        )
                        .await
                }
            }
        })
        .await
    }
}

async fn retry_session_model_call<T, F, Fut>(mut operation: F) -> Result<T, AgentRuntimeError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, AgentRuntimeError>>,
{
    for attempt in 1..=SESSION_MODEL_ATTEMPTS {
        match operation().await {
            Err(AgentRuntimeError::ModelUnavailable(_)) if attempt < SESSION_MODEL_ATTEMPTS => {}
            result => return result,
        }
    }
    unreachable!("the bounded model-attempt loop must return")
}

fn model_config_sha256(provider: &str, model_id: &str) -> String {
    let public_config = json!({
        "config_schema_version": "slack-agent-model-config/v1",
        "model": {
            "id": model_id,
            "provider": provider,
        },
        "runtime_limits": {
            "hard_max_generation_tokens": HARD_MAX_GENERATION_TOKENS,
            "max_history_item_bytes": MAX_MODEL_HISTORY_ITEM_BYTES,
            "max_history_items": MAX_MODEL_HISTORY_ITEMS,
            "max_history_total_bytes": MAX_MODEL_HISTORY_TOTAL_BYTES,
            "max_session_current_message_bytes": MAX_SESSION_MODEL_CURRENT_MESSAGE_BYTES,
            "max_session_history_item_bytes": MAX_SESSION_MODEL_HISTORY_ITEM_BYTES,
            "max_session_history_items": MAX_SESSION_MODEL_HISTORY_ITEMS,
            "max_session_history_total_bytes": MAX_SESSION_MODEL_HISTORY_TOTAL_BYTES,
            "max_response_bytes": MAX_MODEL_RESPONSE_BYTES,
        },
        "schemas": {
            "delivery_receipt": AGENT_DELIVERY_RECEIPT_V1,
            "semantic_evidence": AGENT_SEMANTIC_EVIDENCE_V1,
            "session": AGENT_SESSION_V2,
            "session_event": AGENT_SESSION_EVENT_V2,
            "turn_request": cerebro_agent_runtime::AGENT_TURN_REQUEST_V1,
            "turn_result": cerebro_agent_runtime::AGENT_TURN_RESULT_V1,
        },
        "agent_loop": {
            "decision_contracts": {
                "continue": structured_choice_contract_value(&agent_loop_contracts(false)),
                "initial": structured_choice_contract_value(&agent_loop_contracts(true)),
            },
            "instructions": session_instructions(),
            "max_tokens": SLACK_SESSION_DECISION_MAX_TOKENS,
        },
    });
    sha256_digest(&public_config.to_string())
}

#[async_trait]
impl SessionAgentModel for ConfiguredModel {
    async fn advance(
        &self,
        turn: SessionModelTurn,
    ) -> Result<SessionModelDecision, AgentRuntimeError> {
        let initial = turn.plan.is_none();
        let contracts = agent_loop_contracts(initial);
        let contract_digest = structured_choice_contract_digest(&contracts);
        let selection = self
            .complete_session_choice(
                session_instructions(),
                session_turn_payload(&turn),
                SLACK_SESSION_DECISION_MAX_TOKENS,
                contracts,
            )
            .await
            .map_err(|error| model_stage_adapter_error(error, &contract_digest))?;
        parse_agent_loop_choice(selection, &turn)
    }
}

#[async_trait]
impl AgentModel for ConfiguredModel {
    async fn route(&self, turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        match self {
            Self::AmazonBedrock(model) => model.route(turn).await,
        }
    }

    async fn next(&self, turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        match self {
            Self::AmazonBedrock(model) => model.next(turn).await,
        }
    }

    async fn present(
        &self,
        turn: PresentationTurn,
    ) -> Result<PresentationDecision, AgentRuntimeError> {
        match self {
            Self::AmazonBedrock(model) => model.present(turn).await,
        }
    }

    async fn critique(&self, turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        match self {
            Self::AmazonBedrock(model) => model.critique(turn).await,
        }
    }
}

pub(super) struct BedrockModel {
    client: BedrockClient,
    model: String,
}

impl BedrockModel {
    async fn complete_structured(
        &self,
        instructions: &str,
        payload: Value,
        max_tokens: i32,
        decision_tool: &str,
        decision_schema: Value,
    ) -> Result<Value, AgentRuntimeError> {
        validate_generation_budget(max_tokens)?;
        let message = Message::builder()
            .role(ConversationRole::User)
            .content(ContentBlock::Text(payload.to_string()))
            .build()
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        let tool_specification = ToolSpecification::builder()
            .name(decision_tool)
            .description("Submit the one schema-constrained decision for this layer.")
            .input_schema(ToolInputSchema::Json(json_to_document(&decision_schema)?))
            .build()
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        let tool_choice = SpecificToolChoice::builder()
            .name(decision_tool)
            .build()
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        let tool_configuration = ToolConfiguration::builder()
            .tools(Tool::ToolSpec(tool_specification))
            .tool_choice(ToolChoice::Tool(tool_choice))
            .build()
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        let request = self
            .client
            .converse()
            .model_id(&self.model)
            .messages(message)
            .system(SystemContentBlock::Text(instructions.into()))
            .inference_config(
                InferenceConfiguration::builder()
                    .max_tokens(max_tokens)
                    .build(),
            )
            .tool_config(tool_configuration);
        let response = request.send().await.map_err(|error| {
            let detail = error
                .as_service_error()
                .map_or_else(|| format!("{error:?}"), |service| format!("{service:?}"));
            AgentRuntimeError::ModelUnavailable(format!("Bedrock request failed: {detail}"))
        })?;
        let content = response
            .output()
            .and_then(|output| output.as_message().ok())
            .map(|message| message.content())
            .ok_or_else(|| {
                AgentRuntimeError::ModelUnavailable("Bedrock returned no message content".into())
            })?;
        let value = bedrock_structured_output(content, decision_tool)?;
        let encoded = serde_json::to_vec(&value)
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        if encoded.len() > MAX_MODEL_RESPONSE_BYTES {
            return Err(AgentRuntimeError::ModelUnavailable(
                "Bedrock response exceeded the size limit".into(),
            ));
        }
        Ok(value)
    }

    async fn complete_structured_choice(
        &self,
        instructions: &str,
        payload: Value,
        max_tokens: i32,
        contracts: &[StructuredToolContract],
    ) -> Result<StructuredToolSelection, AgentRuntimeError> {
        validate_generation_budget(max_tokens)?;
        if contracts.is_empty() {
            return Err(AgentRuntimeError::InvalidRequest(
                "a structured model choice requires at least one contract".into(),
            ));
        }
        let contract_digest = structured_choice_contract_digest(contracts);
        let message = Message::builder()
            .role(ConversationRole::User)
            .content(ContentBlock::Text(payload.to_string()))
            .build()
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        let tools = contracts
            .iter()
            .map(|contract| {
                ToolSpecification::builder()
                    .name(contract.name)
                    .description(contract.description)
                    .input_schema(ToolInputSchema::Json(json_to_document(&contract.schema)?))
                    .build()
                    .map(Tool::ToolSpec)
                    .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let tool_configuration = ToolConfiguration::builder()
            .set_tools(Some(tools))
            .tool_choice(ToolChoice::Any(AnyToolChoice::builder().build()))
            .build()
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        let response = self
            .client
            .converse()
            .model_id(&self.model)
            .messages(message)
            .system(SystemContentBlock::Text(instructions.into()))
            .inference_config(
                InferenceConfiguration::builder()
                    .max_tokens(max_tokens)
                    .build(),
            )
            .tool_config(tool_configuration)
            .send()
            .await
            .map_err(|error| {
                let detail = error
                    .as_service_error()
                    .map_or_else(|| format!("{error:?}"), |service| format!("{service:?}"));
                AgentRuntimeError::ModelUnavailable(format!("Bedrock request failed: {detail}"))
            })?;
        let content = response
            .output()
            .and_then(|output| output.as_message().ok())
            .map(|message| message.content())
            .ok_or_else(|| {
                AgentRuntimeError::ModelUnavailable("Bedrock returned no message content".into())
            })?;
        let selection = bedrock_structured_choice_output(content, contracts, &contract_digest)?;
        let encoded = serde_json::to_vec(&selection.input)
            .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
        if encoded.len() > MAX_MODEL_RESPONSE_BYTES {
            return Err(AgentRuntimeError::ModelUnavailable(
                "Bedrock response exceeded the size limit".into(),
            ));
        }
        Ok(selection)
    }
}

#[async_trait]
impl AgentModel for BedrockModel {
    async fn route(&self, turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError> {
        let value = self
            .complete_structured(
                route_instructions(),
                route_turn_payload(&turn),
                SLACK_ROUTE_MAX_TOKENS,
                ROUTE_DECISION_TOOL,
                route_decision_schema(),
            )
            .await?;
        parse_route_value(value)
    }

    async fn next(&self, turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError> {
        let value = self
            .complete_structured(
                model_instructions(),
                model_turn_payload(&turn),
                DECISION_MAX_TOKENS,
                OPERATING_DECISION_TOOL,
                model_decision_schema(),
            )
            .await?;
        parse_model_value(value)
    }

    async fn present(
        &self,
        turn: PresentationTurn,
    ) -> Result<PresentationDecision, AgentRuntimeError> {
        let value = self
            .complete_structured(
                presentation_instructions(),
                presentation_turn_payload(&turn),
                PRESENTATION_MAX_TOKENS,
                PRESENTATION_DECISION_TOOL,
                presentation_decision_schema(),
            )
            .await?;
        parse_presentation_value(value)
    }

    async fn critique(&self, turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError> {
        let value = self
            .complete_structured(
                critic_instructions(),
                critique_turn_payload(&turn),
                CRITIC_MAX_TOKENS,
                CRITIQUE_DECISION_TOOL,
                critique_decision_schema(),
            )
            .await?;
        parse_critique_value(value)
    }
}

#[cfg(test)]
#[derive(Deserialize)]
struct ChatCompletion {
    choices: Vec<ChatChoice>,
}

#[cfg(test)]
#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[cfg(test)]
#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

#[cfg(test)]
fn completion_content(body: &[u8]) -> Result<String, AgentRuntimeError> {
    let completion: ChatCompletion = serde_json::from_slice(body)
        .map_err(|error| AgentRuntimeError::ModelUnavailable(error.to_string()))?;
    completion
        .choices
        .first()
        .map(|choice| choice.message.content.trim())
        .filter(|content| !content.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| AgentRuntimeError::ModelUnavailable("provider returned no content".into()))
}

fn validate_generation_budget(max_tokens: i32) -> Result<(), AgentRuntimeError> {
    if !(1..=HARD_MAX_GENERATION_TOKENS).contains(&max_tokens) {
        return Err(AgentRuntimeError::ModelUnavailable(
            "generation budget exceeds the hard per-completion ceiling".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
fn structured_json(content: &str) -> &str {
    let content = content.trim();
    content
        .strip_prefix("```json")
        .or_else(|| content.strip_prefix("```"))
        .and_then(|inner| inner.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(content)
}

#[cfg(test)]
fn parse_route_content(content: &str) -> Result<RouteDecision, AgentRuntimeError> {
    serde_json::from_str(structured_json(content))
        .map_err(|error| AgentRuntimeError::InvalidRoute(format!("router output: {error}")))
}

fn parse_route_value(value: Value) -> Result<RouteDecision, AgentRuntimeError> {
    serde_json::from_value(value)
        .map_err(|error| AgentRuntimeError::InvalidRoute(format!("router output: {error}")))
}

#[cfg(test)]
fn parse_model_content(content: &str) -> Result<ModelDecision, AgentRuntimeError> {
    let value = serde_json::from_str(structured_json(content))
        .map_err(|error| AgentRuntimeError::InvalidFinal(format!("model output: {error}")))?;
    parse_model_value(value)
}

fn parse_model_value(mut value: Value) -> Result<ModelDecision, AgentRuntimeError> {
    if let Some(object) = value.as_object_mut() {
        if let Some(Value::Object(mut payload)) = object.remove("payload") {
            for field in ["call", "draft"] {
                if let Some(value) = payload.remove(field) {
                    object.insert(field.into(), value);
                }
            }
        }
        if !object.contains_key("decision") {
            let inferred = if object.get("call").is_some_and(|value| !value.is_null())
                || ["call_id", "tool_id", "purpose", "input"]
                    .iter()
                    .any(|field| object.contains_key(*field))
            {
                Some("invoke_tool")
            } else if object.get("draft").is_some_and(|value| !value.is_null())
                || ["state", "headline", "summary"]
                    .iter()
                    .any(|field| object.contains_key(*field))
            {
                Some("finish")
            } else {
                None
            };
            if let Some(decision) = inferred {
                object.insert("decision".into(), Value::String(decision.into()));
            }
        }
        match object.get("decision").and_then(Value::as_str) {
            Some("invoke_tool") => {
                object.remove("draft");
                if object.get("call").is_none_or(Value::is_null) {
                    let mut call = serde_json::Map::new();
                    for field in ["call_id", "tool_id", "purpose", "input"] {
                        if let Some(value) = object.remove(field) {
                            call.insert(field.into(), value);
                        }
                    }
                    if !call.is_empty() {
                        object.insert("call".into(), Value::Object(call));
                    }
                }
            }
            Some("finish") => {
                object.remove("call");
                if object.get("draft").is_none_or(Value::is_null) {
                    let mut draft = serde_json::Map::new();
                    for field in [
                        "state",
                        "headline",
                        "summary",
                        "summary_evidence_refs",
                        "checked",
                        "changed",
                        "verified",
                        "current_state",
                        "next_actions",
                        "coverage_notice",
                        "question",
                    ] {
                        if let Some(value) = object.remove(field) {
                            draft.insert(field.into(), value);
                        }
                    }
                    if !draft.is_empty() {
                        object.insert("draft".into(), Value::Object(draft));
                    }
                }
            }
            _ => {}
        }
    }
    serde_json::from_value(value)
        .map_err(|error| AgentRuntimeError::InvalidFinal(format!("model output: {error}")))
}

#[cfg(test)]
fn parse_presentation_content(content: &str) -> Result<PresentationDecision, AgentRuntimeError> {
    let value = serde_json::from_str(structured_json(content)).map_err(|error| {
        AgentRuntimeError::InvalidFinal(format!("presentation output: {error}"))
    })?;
    parse_presentation_value(value)
}

fn parse_presentation_value(mut value: Value) -> Result<PresentationDecision, AgentRuntimeError> {
    if let Value::String(text) = value {
        if let Ok(decoded) = serde_json::from_str::<Value>(&text) {
            return parse_presentation_value(decoded);
        }
        return Ok(PresentationDecision {
            messages: vec![text],
        });
    }
    if let Value::Array(values) = &value
        && values.iter().all(Value::is_string)
    {
        return Ok(PresentationDecision {
            messages: values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        });
    }
    if let Some(messages) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("messages"))
        && let Value::String(text) = messages
    {
        *messages = decode_presentation_messages(text);
    }
    serde_json::from_value(value)
        .map_err(|error| AgentRuntimeError::InvalidFinal(format!("presentation output: {error}")))
}

fn decode_presentation_messages(text: &str) -> Value {
    for candidate in [Some(text), text.strip_suffix('}')].into_iter().flatten() {
        if let Ok(Value::Array(values)) = serde_json::from_str::<Value>(candidate)
            && values.iter().all(Value::is_string)
        {
            return Value::Array(values);
        }
    }
    Value::Array(vec![Value::String(text.to_owned())])
}

#[cfg(test)]
fn parse_critique_content(content: &str) -> Result<CritiqueDecision, AgentRuntimeError> {
    serde_json::from_str(structured_json(content))
        .map_err(|error| AgentRuntimeError::InvalidFinal(format!("critic output: {error}")))
}

fn parse_critique_value(value: Value) -> Result<CritiqueDecision, AgentRuntimeError> {
    serde_json::from_value(value)
        .map_err(|error| AgentRuntimeError::InvalidFinal(format!("critic output: {error}")))
}

fn bedrock_structured_output(
    content: &[ContentBlock],
    decision_tool: &str,
) -> Result<Value, AgentRuntimeError> {
    let mut tool_uses = content.iter().filter_map(|block| block.as_tool_use().ok());
    let tool_use = tool_uses.next().ok_or_else(|| {
        AgentRuntimeError::ModelUnavailable(
            "Bedrock returned no schema-constrained decision".into(),
        )
    })?;
    if tool_use.name() != decision_tool {
        return Err(AgentRuntimeError::ModelUnavailable(
            "Bedrock returned an ambiguous schema-constrained decision".into(),
        ));
    }
    let mut value = document_to_json(tool_use.input())?;
    for revised_decision in tool_uses {
        if revised_decision.name() != decision_tool {
            return Err(AgentRuntimeError::ModelUnavailable(
                "Bedrock returned an ambiguous schema-constrained decision".into(),
            ));
        }
        value = document_to_json(revised_decision.input())?;
    }
    Ok(value)
}

fn structured_choice_contract_digest(contracts: &[StructuredToolContract]) -> String {
    let contract = Value::Array(
        contracts
            .iter()
            .map(|contract| {
                json!({
                    "description": contract.description,
                    "name": contract.name,
                    "schema": contract.schema,
                })
            })
            .collect(),
    );
    sha256_digest(&contract.to_string())
}

fn model_stage_rejection(
    class: SessionModelRejectionClass,
    contract_digest: &str,
) -> AgentRuntimeError {
    AgentRuntimeError::ModelStageRejected(SessionModelRejection {
        class,
        contract_digest: contract_digest.to_owned(),
    })
}

fn model_stage_adapter_error(error: AgentRuntimeError, contract_digest: &str) -> AgentRuntimeError {
    match error {
        AgentRuntimeError::ModelStageRejected(_) => error,
        _ => model_stage_rejection(
            SessionModelRejectionClass::AdapterUnavailable,
            contract_digest,
        ),
    }
}

fn bedrock_structured_choice_output(
    content: &[ContentBlock],
    contracts: &[StructuredToolContract],
    contract_digest: &str,
) -> Result<StructuredToolSelection, AgentRuntimeError> {
    let tool_uses = content
        .iter()
        .filter_map(|block| block.as_tool_use().ok())
        .collect::<Vec<_>>();
    let [tool_use] = tool_uses.as_slice() else {
        return Err(model_stage_rejection(
            SessionModelRejectionClass::MissingOrAmbiguousTool,
            contract_digest,
        ));
    };
    if !contracts
        .iter()
        .any(|contract| contract.name == tool_use.name())
    {
        return Err(model_stage_rejection(
            SessionModelRejectionClass::MissingOrAmbiguousTool,
            contract_digest,
        ));
    }
    let input = document_to_json(tool_use.input()).map_err(|_| {
        model_stage_rejection(SessionModelRejectionClass::SchemaDecode, contract_digest)
    })?;
    Ok(StructuredToolSelection {
        name: tool_use.name().to_owned(),
        input,
        contract_digest: contract_digest.to_owned(),
    })
}

fn json_to_document(value: &Value) -> Result<Document, AgentRuntimeError> {
    match value {
        Value::Null => Ok(Document::Null),
        Value::Bool(value) => Ok(Document::Bool(*value)),
        Value::Number(value) => {
            let number = if let Some(value) = value.as_u64() {
                Number::PosInt(value)
            } else if let Some(value) = value.as_i64() {
                Number::NegInt(value)
            } else {
                Number::Float(value.as_f64().ok_or_else(|| {
                    AgentRuntimeError::ModelUnavailable(
                        "JSON schema contains an unsupported number".into(),
                    )
                })?)
            };
            Ok(Document::Number(number))
        }
        Value::String(value) => Ok(Document::String(value.clone())),
        Value::Array(values) => values
            .iter()
            .map(json_to_document)
            .collect::<Result<Vec<_>, _>>()
            .map(Document::Array),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), json_to_document(value)?)))
            .collect::<Result<HashMap<_, _>, AgentRuntimeError>>()
            .map(Document::Object),
    }
}

fn document_to_json(document: &Document) -> Result<Value, AgentRuntimeError> {
    match document {
        Document::Null => Ok(Value::Null),
        Document::Bool(value) => Ok(Value::Bool(*value)),
        Document::Number(Number::PosInt(value)) => Ok(Value::Number((*value).into())),
        Document::Number(Number::NegInt(value)) => Ok(Value::Number((*value).into())),
        Document::Number(Number::Float(value)) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .ok_or_else(|| {
                AgentRuntimeError::ModelUnavailable(
                    "Bedrock returned a non-finite decision number".into(),
                )
            }),
        Document::String(value) => Ok(Value::String(value.clone())),
        Document::Array(values) => values
            .iter()
            .map(document_to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Document::Object(values) => values
            .iter()
            .map(|(key, value)| Ok((key.clone(), document_to_json(value)?)))
            .collect::<Result<serde_json::Map<_, _>, AgentRuntimeError>>()
            .map(Value::Object),
    }
}

fn route_decision_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "lane": {"type": "string", "enum": ["converse", "continue", "lookup", "investigate", "act"]},
            "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
            "reason": {"type": "string", "minLength": 1},
            "requires_current_evidence": {"type": "boolean"},
            "future_observation": {"type": "string", "enum": ["delegated", "refused", "none"]},
            "future_observation_excerpt": {"type": ["string", "null"]}
        },
        "required": ["lane", "confidence", "reason", "requires_current_evidence", "future_observation", "future_observation_excerpt"]
    })
}

fn evidence_claim_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "text": {"type": "string", "minLength": 1},
            "evidence_refs": {
                "type": "array",
                "items": {"type": "string", "minLength": 1}
            }
        },
        "required": ["text", "evidence_refs"]
    })
}

fn final_draft_schema() -> Value {
    let claim = evidence_claim_schema();
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "state": {"type": "string", "enum": ["answered", "partial", "needs_input", "blocked"]},
            "headline": {"type": "string", "minLength": 1, "maxLength": 160},
            "summary": {"type": "string", "minLength": 1, "maxLength": 2400},
            "summary_evidence_refs": {
                "type": "array",
                "items": {"type": "string", "minLength": 1}
            },
            "checked": {"type": "array", "maxItems": 8, "items": claim.clone()},
            "changed": {"type": "array", "maxItems": 8, "items": claim.clone()},
            "verified": {"type": "array", "maxItems": 8, "items": claim.clone()},
            "current_state": {"type": "array", "maxItems": 8, "items": claim},
            "next_actions": {
                "type": "array",
                "maxItems": 5,
                "items": {"type": "string", "minLength": 1}
            },
            "coverage_notice": {"type": ["string", "null"], "maxLength": 800},
            "question": {"type": ["string", "null"], "maxLength": 800}
        },
        "required": [
            "state",
            "headline",
            "summary",
            "summary_evidence_refs",
            "checked",
            "changed",
            "verified",
            "current_state",
            "next_actions",
            "coverage_notice",
            "question"
        ]
    })
}

fn model_decision_schema() -> Value {
    let call = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "call_id": {"type": "string", "minLength": 1},
            "tool_id": {"type": "string", "minLength": 1},
            "purpose": {"type": "string", "minLength": 1},
            "input": {"type": "object"}
        },
        "required": ["call_id", "tool_id", "purpose", "input"]
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "decision": {"type": "string", "enum": ["invoke_tool", "finish"]},
            "payload": {
                "oneOf": [
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"call": call},
                        "required": ["call"]
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"draft": final_draft_schema()},
                        "required": ["draft"]
                    }
                ]
            }
        },
        "required": ["decision", "payload"]
    })
}

fn presentation_decision_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "messages": {
                "type": "array",
                "minItems": 1,
                "maxItems": 2,
                "items": {"type": "string", "minLength": 1, "maxLength": 2400}
            }
        },
        "required": ["messages"]
    })
}

fn critique_decision_schema() -> Value {
    let grounding = json!({
        "type": "array",
        "minItems": 1,
        "maxItems": 64,
        "items": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "unit_id": {"type": "string", "minLength": 1},
                "basis": {
                    "type": "string",
                    "enum": [
                        "direct_observation",
                        "bounded_inference",
                        "operator_supplied",
                        "conversational_synthesis",
                        "retained_context",
                        "tool_outcome",
                        "hypothesis",
                        "recommendation",
                        "stable_explanation",
                        "placeholder",
                        "non_factual"
                    ]
                },
                "support": {
                    "type": "array",
                    "maxItems": 8,
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "evidence_ref": {"type": "string", "minLength": 1},
                            "data_pointer": {"type": ["string", "null"]},
                            "supporting_text": {"type": "string", "minLength": 1}
                        },
                        "required": ["evidence_ref", "data_pointer", "supporting_text"]
                    }
                },
                "context_excerpt": {"type": ["string", "null"], "minLength": 1},
                "observation_sequence": {"type": ["integer", "null"], "minimum": 1}
            },
            "required": ["unit_id", "basis", "support", "context_excerpt", "observation_sequence"]
        }
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "decision": {"type": "string", "enum": ["approve", "revise"]},
            "checks": critique_checks_schema(),
            "grounding": grounding,
            "issues": {
                "type": "array",
                "minItems": 1,
                "maxItems": 16,
                "items": {"type": "string", "minLength": 1}
            }
        },
        "required": ["decision"]
    })
}

fn session_decision_schema() -> Value {
    let string_array = || {
        json!({
            "type": "array",
            "maxItems": 32,
            "items": {"type": "string", "minLength": 1}
        })
    };
    let planned_claim = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "claim_ref": {"type": "string", "minLength": 1},
            "question": {"type": "string", "minLength": 1},
            "required": {"type": "boolean"},
            "subject_refs": string_array(),
            "source_candidates": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "minLength": 1}},
        },
        "required": ["claim_ref", "question", "required", "subject_refs", "source_candidates"]
    });
    let observation_condition = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "tool_id": {"type": "string", "minLength": 1},
            "data_pointer": {"type": "string", "minLength": 1},
            "equals": {}
        },
        "required": ["tool_id", "data_pointer", "equals"]
    });
    let alert_condition = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "tool_id": {"type": "string", "minLength": 1},
            "data_pointer": {"type": "string", "minLength": 1},
            "equals": {"type": "boolean"}
        },
        "required": ["tool_id", "data_pointer", "equals"]
    });
    let attention_policy = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "acceptance_all": {"type": "array", "minItems": 1, "maxItems": 16, "items": observation_condition.clone()},
            "alert_any": {"type": "array", "maxItems": 16, "items": alert_condition},
            "notify_on_change": {"type": "array", "maxItems": 16, "items": observation_condition}
        },
        "required": ["acceptance_all", "alert_any", "notify_on_change"]
    });
    let planned_follow_through = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "commitment_ref": {"type": "string", "minLength": 1},
            "required_tool_ids": string_array(),
            "acceptance_criteria": string_array(),
            "next_action": {"type": "string", "minLength": 1},
            "attention_policy": attention_policy.clone(),
            "check_after_seconds": {"type": "integer", "minimum": 30, "maximum": 3600},
            "verification": {"type": "string", "minLength": 1},
            "authorization_excerpt": {
                "type": ["string", "null"],
                "description": "For an operator-authorized durable follow-through, copy one exact bounded excerpt from the newest operator message. Use null inside an unaccepted follow_through_offer."
            }
        },
        "required": ["commitment_ref", "required_tool_ids", "acceptance_criteria", "next_action", "attention_policy", "check_after_seconds", "verification", "authorization_excerpt"]
    });
    let planned_follow_through_offer = json!({
        "type": "object",
        "additionalProperties": false,
        "description": "Propose only when the current evidence supports a useful optional future observation that the operator has not already authorized. The runtime will offer it for explicit acceptance and will not schedule it from this model output alone.",
        "properties": {
            "kind": {"type": "string", "enum": ["watch_answer", "recheck_evidence"], "description": "Use watch_answer for a complete current answer worth monitoring; use recheck_evidence for a partial answer whose named evidence can be retried."},
            "follow_through": planned_follow_through.clone()
        },
        "required": ["kind", "follow_through"]
    });
    let plan = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "decision": {"type": "string", "minLength": 1},
            "lane": {"type": "string", "enum": ["lookup", "investigate", "act"]},
            "resolved_entities": string_array(),
            "claims": {"type": "array", "minItems": 1, "maxItems": 16, "items": planned_claim},
            "selected_tools": {"type": "array", "minItems": 1, "uniqueItems": true, "items": {"type": "string", "minLength": 1}},
            "stop_conditions": string_array(),
            "user_visible_work": string_array(),
            "follow_through": {"oneOf": [planned_follow_through, {"type": "null"}]},
            "follow_through_offer": {"oneOf": [planned_follow_through_offer, {"type": "null"}], "description": "Optional, explicit-acceptance-only follow-up. Never copy an operator-authorized follow_through here."},
        },
        "required": ["decision", "lane", "resolved_entities", "claims", "selected_tools", "stop_conditions", "user_visible_work", "follow_through"]
    });
    let commitment = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "commitment_ref": {"type": "string", "minLength": 1},
            "summary": {"type": "string", "minLength": 1},
            "owner": {"type": "string", "enum": ["cerebro", "user", "external"]},
            "status": {"type": "string", "enum": ["planned", "in_progress", "waiting", "completed", "blocked", "cancelled"]},
            "next_action": {"type": ["string", "null"]},
            "blocker": {"type": ["string", "null"]},
            "acceptance_criteria": string_array(),
            "artifact_refs": string_array(),
            "required_tool_ids": string_array(),
            "attention_policy": {"oneOf": [attention_policy, {"type": "null"}]},
            "wake_at": {"type": ["string", "null"]},
            "verification": {"type": ["string", "null"]},
        },
        "required": ["commitment_ref", "summary", "owner", "status", "next_action", "blocker", "acceptance_criteria", "artifact_refs", "required_tool_ids", "attention_policy", "wake_at", "verification"]
    });
    let open_loop = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "open_loop_ref": {"type": "string", "minLength": 1},
            "summary": {"type": "string", "minLength": 1},
            "owner": {"type": "string", "enum": ["cerebro", "user", "external"]},
            "next_action": {"type": ["string", "null"]},
            "blocked_by": {"type": ["string", "null"]},
        },
        "required": ["open_loop_ref", "summary", "owner", "next_action", "blocked_by"]
    });
    let mission = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "mission_ref": {"type": "string", "minLength": 1},
            "objective": {"type": "string", "minLength": 1},
            "desired_outcome": {"type": "string", "minLength": 1},
            "resolved_scope": string_array(),
            "scope_assumptions": string_array(),
            "acceptance_criteria": string_array(),
            "commitments": {"type": "array", "maxItems": 16, "items": commitment},
            "open_loops": {"type": "array", "maxItems": 16, "items": open_loop},
            "status": {"type": "string", "enum": ["active", "waiting_for_user", "waiting_for_external", "completed", "blocked", "cancelled"]},
        },
        "required": ["mission_ref", "objective", "desired_outcome", "resolved_scope", "scope_assumptions", "acceptance_criteria", "commitments", "open_loops", "status"]
    });
    let action = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "tool_id": {"type": ["string", "null"]},
            "target_ref": {"type": ["string", "null"]},
            "input": {"type": "object"},
        },
        "required": ["tool_id", "target_ref", "input"]
    });
    let content = json!({
        "oneOf": [
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["observation"]}, "atom_refs": string_array()}, "required": ["basis", "atom_refs"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["operator_context"]}, "message_sequence": {"type": "integer", "minimum": 1}, "exact_excerpt": {"type": "string", "minLength": 1}}, "required": ["basis", "message_sequence", "exact_excerpt"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["conversational_synthesis"]}, "source_message_sequences": {"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true, "items": {"type": "integer", "minimum": 1}}, "source_atom_refs": {"type": "array", "maxItems": 0, "items": {"type": "string"}}}, "required": ["basis", "source_message_sequences", "source_atom_refs"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["rhetorical_move"]}, "move_id": {"type": "string", "enum": ["separate_evidence_from_inference", "frame_decision_with_criteria", "compare_alternatives_consistently", "preserve_reversibility", "identify_decision_changing_information", "clarify_scope"]}}, "required": ["basis", "move_id"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["historical_context"]}, "atom_ref": {"type": "string", "minLength": 1}, "exact_excerpt": {"type": "string", "minLength": 1, "maxLength": 1000}}, "required": ["basis", "atom_ref", "exact_excerpt"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["retained_plan"]}, "open_loop_ref": {"type": "string", "minLength": 1}}, "required": ["basis", "open_loop_ref"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["commitment"]}, "commitment_ref": {"type": "string", "minLength": 1}}, "required": ["basis", "commitment_ref"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["recommendation"]}, "action": action, "directive": {"type": "string", "enum": ["leave_unchanged", "perform_bounded_check", "wait_for_fresh_observation", "inspect_target", "verify_target", "reconcile_provider_state", "request_approval", "remediate_target"]}, "rationale_atom_refs": string_array()}, "required": ["basis", "action", "directive", "rationale_atom_refs"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["hypothesis"]}, "supporting_atom_refs": string_array(), "alternatives": string_array()}, "required": ["basis", "supporting_atom_refs", "alternatives"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["stable_explanation"]}, "explanation_id": {"type": "string", "enum": ALL_STABLE_EXPLANATION_IDS}}, "required": ["basis", "explanation_id"]},
            {"type": "object", "additionalProperties": false, "properties": {"basis": {"type": "string", "enum": ["question"]}, "directive": {"type": "string", "enum": ["which_target", "which_source", "what_decision", "what_outcome", "who_can_provide_identifier", "when_due", "where_evidence"]}}, "required": ["basis", "directive"]}
        ]
    });
    let grounded_claim = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "claim_ref": {"type": "string", "minLength": 1},
            "planned_claim_ref": {"type": ["string", "null"]},
            "text": {"type": "string", "minLength": 1},
            "required_for_answer": {"type": "boolean"},
            "content": content,
        },
        "required": ["claim_ref", "planned_claim_ref", "text", "required_for_answer", "content"]
    });
    let memory_update = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "memory_ref": {"type": "string", "minLength": 1},
            "kind": {"type": "string", "enum": ["fact", "decision", "risk", "blocker", "handoff", "source_health", "preference"]},
            "statement": {"type": "string", "minLength": 1},
            "evidence_atom_refs": string_array(),
            "promotion_requested": {"type": "boolean"},
        },
        "required": ["memory_ref", "kind", "statement", "evidence_atom_refs", "promotion_requested"]
    });
    let draft = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "state": {"type": "string", "enum": ["answered", "partial", "needs_input", "blocked"]},
            "delivery": {"type": "string", "enum": ["visible", "silent"]},
            "message": {"type": "string", "minLength": 1, "maxLength": 16384},
            "claims": {"type": "array", "minItems": 1, "maxItems": 32, "items": grounded_claim},
            "coverage_notice": {"type": ["string", "null"]},
            "question": {"type": ["string", "null"]},
            "mission": mission,
            "memory_updates": {"type": "array", "maxItems": 32, "items": memory_update},
            "presentation_ready": {"type": "boolean"},
        },
        "required": ["state", "delivery", "message", "claims", "coverage_notice", "question", "mission", "memory_updates", "presentation_ready"]
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "decision": {
                "type": "string",
                "enum": ["establish_plan", "invoke_tools", "finish"]
            },
            "plan": {"oneOf": [plan, {"type": "null"}]},
            "calls": {
                "type": "array",
                "maxItems": 8,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "call_id": {"type": "string", "minLength": 1},
                        "tool_id": {"type": "string", "minLength": 1},
                        "purpose": {"type": "string", "minLength": 1},
                        "input": {"type": "object"}
                    },
                    "required": ["call_id", "tool_id", "purpose", "input"]
                }
            },
            "draft": {"oneOf": [draft, {"type": "null"}]}
        },
        "required": ["decision", "plan", "calls", "draft"]
    })
}

#[cfg(test)]
fn session_presentation_schema(claim_count: usize) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "claim_texts": {
                "type": "array",
                "minItems": claim_count,
                "maxItems": claim_count,
                "items": {"type": "string", "minLength": 1, "maxLength": 16384}
            }
        },
        "required": ["claim_texts"]
    })
}

fn structured_choice_contract_value(contracts: &[StructuredToolContract]) -> Value {
    Value::Array(
        contracts
            .iter()
            .map(|contract| {
                json!({
                    "description": contract.description,
                    "name": contract.name,
                    "schema": contract.schema,
                })
            })
            .collect(),
    )
}

fn non_null_session_branch(complete: &Value, field: &str) -> Value {
    complete["properties"][field]["oneOf"][0].clone()
}

fn nonempty_session_calls(complete: &Value) -> Value {
    let mut calls = complete["properties"]["calls"].clone();
    calls["minItems"] = Value::from(1);
    calls
}

fn agent_final_draft_schema(complete: &Value) -> Value {
    let mut draft = non_null_session_branch(complete, "draft");
    if let Some(properties) = draft["properties"].as_object_mut() {
        properties.remove("message");
        properties.remove("presentation_ready");
    }
    if let Some(required) = draft["required"].as_array_mut() {
        required.retain(|field| field != "message" && field != "presentation_ready");
    }
    draft
}

fn agent_loop_contracts(initial: bool) -> Vec<StructuredToolContract> {
    let complete = session_decision_schema();
    let draft = agent_final_draft_schema(&complete);
    let finish = StructuredToolContract {
        name: SESSION_FINISH_TOOL,
        description: "Return the complete final Slack answer from the current agent loop.",
        schema: if initial {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "lane": {"type": "string", "enum": ["converse", "lookup", "investigate", "act"]},
                    "draft": draft,
                },
                "required": ["lane", "draft"]
            })
        } else {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"draft": draft},
                "required": ["draft"]
            })
        },
    };
    let calls = nonempty_session_calls(&complete);
    let research = if initial {
        StructuredToolContract {
            name: SESSION_START_TOOL,
            description: "Start one bounded plan and issue its first useful tool calls.",
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "lane": {"type": "string", "enum": ["lookup", "investigate", "act"]},
                    "plan": non_null_session_branch(&complete, "plan"),
                    "calls": calls,
                },
                "required": ["lane", "plan", "calls"]
            }),
        }
    } else {
        StructuredToolContract {
            name: SESSION_CONTINUE_TOOL,
            description: "Continue the active agent loop with the next useful tool calls.",
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"calls": calls},
                "required": ["calls"]
            }),
        }
    };
    vec![research, finish]
}

#[cfg(test)]
fn claim_review_schema(claim_count: usize) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "claim_reviews": {
                "type": "array",
                "minItems": claim_count,
                "maxItems": claim_count,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "verdict": {"type": "string", "enum": ["supported", "unsupported"]},
                        "issue": {"type": ["string", "null"]}
                    },
                    "required": ["verdict", "issue"]
                }
            },
            "undeclared_material": {
                "type": "array",
                "maxItems": 16,
                "items": {"type": "string", "minLength": 1}
            },
            "attention": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "reason": {"type": "string", "minLength": 1}
                },
                "required": ["reason"]
            },
            "behavioral": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "answers_newest_request": {"type": "boolean"},
                    "conversational": {"type": "boolean"},
                    "owns_follow_through": {"type": "boolean"},
                    "right_sized": {"type": "boolean"},
                    "evidence_boundary_correct": {"type": "boolean"}
                },
                "required": [
                    "answers_newest_request",
                    "conversational",
                    "owns_follow_through",
                    "right_sized",
                    "evidence_boundary_correct"
                ]
            }
        },
        "required": ["claim_reviews", "undeclared_material", "attention", "behavioral"]
    })
}

#[cfg(test)]
fn parse_message_review_value(mut value: Value) -> Result<MessageReview, AgentRuntimeError> {
    if let Some(attention) = value
        .as_object_mut()
        .and_then(|object| object.get_mut("attention"))
        && let Value::String(encoded) = attention
    {
        let decoded = serde_json::from_str::<Value>(encoded)
            .ok()
            .filter(Value::is_object)
            .or_else(|| parse_first_embedded_object(encoded));
        if let Some(decoded) = decoded {
            *attention = decoded;
        }
    }
    serde_json::from_value(value)
        .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))
}

#[cfg(test)]
fn parse_first_embedded_object(encoded: &str) -> Option<Value> {
    let start = encoded.find('{')?;
    let mut depth = 0_u32;
    let mut in_string = false;
    let mut escaped = false;
    for (offset, character) in encoded[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        match character {
            '"' => in_string = true,
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    let end = start + offset + character.len_utf8();
                    return serde_json::from_str::<Value>(&encoded[start..end])
                        .ok()
                        .filter(Value::is_object);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
fn parse_session_decision_value(
    mut value: Value,
) -> Result<SessionModelDecision, AgentRuntimeError> {
    normalize_embedded_session_object(&mut value, "plan");
    normalize_embedded_session_object(&mut value, "draft");
    normalize_grounded_claim_aliases(&mut value);
    let decision = value
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| AgentRuntimeError::InvalidFinal("session decision is missing".into()))?;
    let normalized = match decision {
        "establish_plan" => {
            let plan = value.get("plan").cloned().unwrap_or(Value::Null);
            let calls = value
                .get("calls")
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            if calls.as_array().is_some_and(|calls| !calls.is_empty()) {
                let plan = serde_json::from_value(plan)
                    .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))?;
                let calls = serde_json::from_value(calls)
                    .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))?;
                return Ok(SessionModelDecision::EstablishPlanAndInvoke { plan, calls });
            }
            json!({
                "decision": decision,
                "plan": plan,
            })
        }
        "invoke_tools" => json!({
            "decision": decision,
            "calls": value.get("calls").cloned().unwrap_or(Value::Null),
        }),
        "finish" => json!({
            "decision": decision,
            "draft": value.get("draft").cloned().unwrap_or(Value::Null),
        }),
        _ => {
            return Err(AgentRuntimeError::InvalidFinal(
                "session decision is unsupported".into(),
            ));
        }
    };
    serde_json::from_value(normalized)
        .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))
}

#[cfg(test)]
#[derive(Debug)]
enum SessionResearchDecision {
    Continue(Box<SessionModelDecision>),
}

fn parse_agent_loop_choice(
    selection: StructuredToolSelection,
    turn: &SessionModelTurn,
) -> Result<SessionModelDecision, AgentRuntimeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StartResearch {
        lane: ExecutionLane,
        plan: ResearchPlan,
        calls: Vec<cerebro_agent_runtime::ToolCall>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ContinueResearch {
        calls: Vec<cerebro_agent_runtime::ToolCall>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InitialFinish {
        lane: ExecutionLane,
        draft: Value,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ContinueFinish {
        draft: Value,
    }

    let StructuredToolSelection {
        name,
        input,
        contract_digest,
    } = selection;
    let initial = turn.plan.is_none();
    let schema_rejection =
        || model_stage_rejection(SessionModelRejectionClass::SchemaDecode, &contract_digest);
    match (initial, name.as_str()) {
        (true, SESSION_START_TOOL) => {
            let mut selected: StartResearch =
                serde_json::from_value(input).map_err(|_| schema_rejection())?;
            if selected.calls.is_empty() {
                return Err(model_stage_rejection(
                    SessionModelRejectionClass::RuntimeValidation,
                    &contract_digest,
                ));
            }
            // The top-level lane is the model's single typed authority choice. Bind the
            // nested plan to it instead of asking the provider to echo the same enum twice.
            selected.plan.lane = selected.lane;
            normalize_model_plan_cross_references(&mut selected.plan);
            Ok(SessionModelDecision::EstablishPlanAndInvoke {
                plan: selected.plan,
                calls: selected.calls,
            })
        }
        (false, SESSION_CONTINUE_TOOL) => {
            let selected: ContinueResearch =
                serde_json::from_value(input).map_err(|_| schema_rejection())?;
            if selected.calls.is_empty() {
                return Err(model_stage_rejection(
                    SessionModelRejectionClass::RuntimeValidation,
                    &contract_digest,
                ));
            }
            Ok(SessionModelDecision::InvokeTools {
                calls: selected.calls,
            })
        }
        (true, SESSION_FINISH_TOOL) => {
            let selected: InitialFinish =
                serde_json::from_value(input).map_err(|_| schema_rejection())?;
            let draft =
                decode_research_draft(selected.draft, &contract_digest, turn, Some(selected.lane))?;
            Ok(SessionModelDecision::ResearchComplete {
                draft,
                declared_lane: Some(selected.lane),
            })
        }
        (false, SESSION_FINISH_TOOL) => {
            let selected: ContinueFinish =
                serde_json::from_value(input).map_err(|_| schema_rejection())?;
            let draft = decode_research_draft(selected.draft, &contract_digest, turn, None)?;
            Ok(SessionModelDecision::ResearchComplete {
                draft,
                declared_lane: None,
            })
        }
        _ => Err(model_stage_rejection(
            SessionModelRejectionClass::MissingOrAmbiguousTool,
            &contract_digest,
        )),
    }
}

fn normalize_model_plan_cross_references(plan: &mut ResearchPlan) {
    for claim in &mut plan.claims {
        if claim.subject_refs.is_empty() {
            claim.subject_refs.clone_from(&plan.resolved_entities);
        }
        if claim.source_candidates.is_empty() {
            claim.source_candidates.clone_from(&plan.selected_tools);
        }
    }
}

fn decode_research_draft(
    mut value: Value,
    contract_digest: &str,
    turn: &SessionModelTurn,
    declared_lane: Option<ExecutionLane>,
) -> Result<GroundedDraft, AgentRuntimeError> {
    let message = value
        .get("claims")
        .and_then(Value::as_array)
        .and_then(|claims| {
            claims
                .iter()
                .map(|claim| claim.get("text").and_then(Value::as_str))
                .collect::<Option<String>>()
        })
        .ok_or_else(|| {
            model_stage_rejection(SessionModelRejectionClass::SchemaDecode, contract_digest)
        })?;
    let object = value.as_object_mut().ok_or_else(|| {
        model_stage_rejection(SessionModelRejectionClass::SchemaDecode, contract_digest)
    })?;
    object.insert("message".into(), Value::String(message));
    object.insert("presentation_ready".into(), Value::Bool(false));
    let mut draft: GroundedDraft = serde_json::from_value(value).map_err(|_| {
        model_stage_rejection(SessionModelRejectionClass::SchemaDecode, contract_digest)
    })?;
    if turn.plan.is_none() && declared_lane == Some(ExecutionLane::Converse) {
        // Conversation does not revise durable operating work. Rust owns the current
        // mission identity and the exact newest-message sequence used for synthesis.
        draft.mission.clone_from(&turn.session.mission);
        let newest_operator_sequence = turn
            .session
            .messages
            .iter()
            .rposition(|message| message.role == SessionMessageRole::User)
            .map(|index| (index + 1) as u64)
            .ok_or_else(|| {
                model_stage_rejection(
                    SessionModelRejectionClass::RuntimeValidation,
                    contract_digest,
                )
            })?;
        for claim in &mut draft.claims {
            if let ClaimContent::ConversationalSynthesis {
                source_message_sequences,
                source_atom_refs,
            } = &mut claim.content
            {
                source_message_sequences.clear();
                source_message_sequences.push(newest_operator_sequence);
                source_atom_refs.clear();
            }
        }
    }
    Ok(draft)
}

#[cfg(test)]
fn parse_session_research_decision_value(
    mut value: Value,
    initial: bool,
) -> Result<SessionResearchDecision, AgentRuntimeError> {
    normalize_embedded_session_object(&mut value, "plan");
    normalize_embedded_session_object(&mut value, "draft");
    normalize_grounded_claim_aliases(&mut value);
    let decision = value
        .get("decision")
        .and_then(Value::as_str)
        .ok_or_else(|| AgentRuntimeError::InvalidFinal("session decision is missing".into()))?;
    let calls = value
        .get("calls")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let calls_empty = calls.as_array().is_some_and(Vec::is_empty);
    let declared_lane = if initial {
        Some(
            serde_json::from_value::<ExecutionLane>(
                value.get("lane").cloned().unwrap_or(Value::Null),
            )
            .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))?,
        )
    } else {
        None
    };
    match decision {
        "establish_plan" => {
            if calls_empty {
                return Err(AgentRuntimeError::InvalidFinal(
                    "the first research decision must include at least one read".into(),
                ));
            }
            let plan: ResearchPlan =
                serde_json::from_value(value.get("plan").cloned().unwrap_or(Value::Null))
                    .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))?;
            if declared_lane != Some(plan.lane) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "the declared lane must match the initial research plan lane".into(),
                ));
            }
            let calls = serde_json::from_value(calls)
                .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))?;
            Ok(SessionResearchDecision::Continue(Box::new(
                SessionModelDecision::EstablishPlanAndInvoke { plan, calls },
            )))
        }
        "invoke_tools" => {
            if calls_empty {
                return Err(AgentRuntimeError::InvalidFinal(
                    "invoke_tools must include at least one missing read".into(),
                ));
            }
            let calls = serde_json::from_value(calls)
                .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))?;
            Ok(SessionResearchDecision::Continue(Box::new(
                SessionModelDecision::InvokeTools { calls },
            )))
        }
        "finish_research" => {
            if !calls_empty {
                return Err(AgentRuntimeError::InvalidFinal(
                    "finish_research cannot include tool calls".into(),
                ));
            }
            let draft = serde_json::from_value(value.get("draft").cloned().unwrap_or(Value::Null))
                .map_err(|error| AgentRuntimeError::InvalidFinal(error.to_string()))?;
            Ok(SessionResearchDecision::Continue(Box::new(
                SessionModelDecision::ResearchComplete {
                    draft,
                    declared_lane,
                },
            )))
        }
        _ => Err(AgentRuntimeError::InvalidFinal(
            "session research decision is unsupported".into(),
        )),
    }
}

#[cfg(test)]
fn apply_session_presentation_value(
    research_draft: &GroundedDraft,
    value: Value,
    contract_digest: &str,
) -> Result<GroundedDraft, AgentRuntimeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PresentedClaims {
        claim_texts: Vec<String>,
    }

    let presented: PresentedClaims = serde_json::from_value(value).map_err(|_| {
        model_stage_rejection(SessionModelRejectionClass::SchemaDecode, contract_digest)
    })?;
    if presented.claim_texts.len() != research_draft.claims.len() {
        return Err(model_stage_rejection(
            SessionModelRejectionClass::FrozenClaimCardinality,
            contract_digest,
        ));
    }
    let mut draft = research_draft.clone();
    for (claim, text) in draft.claims.iter_mut().zip(presented.claim_texts) {
        claim.text = text;
    }
    draft.message = draft
        .claims
        .iter()
        .map(|claim| claim.text.as_str())
        .collect();
    draft.presentation_ready = true;
    Ok(draft)
}

#[cfg(test)]
fn apply_claim_review_value(
    turn: &ClaimReviewTurn,
    value: Value,
    contract_digest: &str,
) -> Result<MessageReview, AgentRuntimeError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PositionalClaimReview {
        verdict: ClaimReviewVerdict,
        issue: Option<String>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AttentionJudgment {
        reason: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct PositionalMessageReview {
        claim_reviews: Vec<PositionalClaimReview>,
        undeclared_material: Vec<String>,
        attention: AttentionJudgment,
        behavioral: BehavioralReview,
    }

    let positional: PositionalMessageReview = serde_json::from_value(value).map_err(|_| {
        model_stage_rejection(SessionModelRejectionClass::SchemaDecode, contract_digest)
    })?;
    if positional.claim_reviews.len() != turn.draft.claims.len()
        || positional.claim_reviews.iter().any(|review| {
            match (&review.verdict, review.issue.as_deref()) {
                (ClaimReviewVerdict::Supported, None) => false,
                (ClaimReviewVerdict::Unsupported, Some(issue)) => issue.trim().is_empty(),
                _ => true,
            }
        })
    {
        return Err(model_stage_rejection(
            SessionModelRejectionClass::ReviewBinding,
            contract_digest,
        ));
    }
    let claim_reviews = turn
        .draft
        .claims
        .iter()
        .zip(positional.claim_reviews)
        .map(|(claim, review)| ClaimReview {
            claim_ref: claim.claim_ref.clone(),
            verdict: review.verdict,
            issue: review.issue,
        })
        .collect();
    Ok(MessageReview {
        draft_digest: grounded_draft_digest(&turn.draft),
        message_digest: message_digest(&turn.draft.message),
        claim_reviews,
        undeclared_material: positional.undeclared_material,
        attention: AttentionReview {
            delivery: turn.draft.delivery,
            reason: positional.attention.reason,
        },
        behavioral: positional.behavioral,
    })
}

#[cfg(test)]
fn normalize_embedded_session_object(value: &mut Value, field: &str) {
    let Some(encoded) = value
        .as_object_mut()
        .and_then(|object| object.get_mut(field))
    else {
        return;
    };
    let Value::String(text) = encoded else {
        return;
    };
    let decoded = serde_json::from_str::<Value>(text)
        .ok()
        .filter(Value::is_object)
        .or_else(|| parse_first_embedded_object(text));
    if let Some(decoded) = decoded {
        *encoded = decoded;
    }
}

#[cfg(test)]
fn normalize_grounded_claim_aliases(value: &mut Value) {
    let Some(claims) = value
        .get_mut("draft")
        .and_then(|draft| draft.get_mut("claims"))
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    for claim in claims {
        let Some(claim) = claim.as_object_mut() else {
            continue;
        };
        let legacy_required = claim.remove("required");
        if !claim.contains_key("required_for_answer")
            && let Some(required) = legacy_required
        {
            claim.insert("required_for_answer".into(), required);
        }
    }
}

fn critique_checks_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "answers_newest_request": {"type": "boolean"},
            "conversational": {"type": "boolean"},
            "evidence_boundary_correct": {"type": "boolean"},
            "no_raw_record_dump": {"type": "boolean"},
            "operator_facing": {"type": "boolean"},
            "owns_follow_through": {"type": "boolean"},
            "right_sized": {"type": "boolean"}
        },
        "required": [
            "answers_newest_request",
            "conversational",
            "evidence_boundary_correct",
            "no_raw_record_dump",
            "operator_facing",
            "owns_follow_through",
            "right_sized"
        ]
    })
}

fn route_turn_payload(turn: &RouteTurn) -> Value {
    json!({
        "repair_feedback": &turn.repair_feedback,
        "request": {
            "history": bounded_model_history(&turn.request.history),
            "message": &turn.request.message,
            "working_state": &turn.request.working_state,
        },
    })
}

fn model_turn_payload(turn: &ModelTurn) -> Value {
    json!({
        "available_tools": &turn.available_tools,
        "budget": turn.budget,
        "lane": turn.lane,
        "observations": &turn.observations,
        "revision_feedback": &turn.revision_feedback,
        "request": {
            "effect_authorizations": &turn.request.effect_authorizations,
            "history": bounded_model_history(&turn.request.history),
            "message": &turn.request.message,
            "working_state": turn.request.working_state.as_ref().map(|state| json!({
                "current_request": state.current_request,
                "last_blocker": state.last_blocker,
                "last_outcome": state.last_outcome,
            })),
        },
    })
}

fn session_turn_payload(turn: &SessionModelTurn) -> Value {
    let (current_operator_message, historical_messages) =
        split_session_messages(&turn.session.messages, &turn.trigger);
    let current_operator_message = current_operator_message.map(current_operator_message_value);
    let current_operator_message_missing =
        operator_message_missing(&turn.trigger, current_operator_message.as_ref());
    let (historical_messages, omitted_historical_message_count, oldest_included_message_ref) =
        bounded_session_history(&historical_messages);
    let available_tools = tagged_context_values(&turn.available_tools, "capability_metadata");
    let observations = tagged_context_values(&turn.observations, "current_observation");
    let retained_memories = tagged_context_values(&turn.session.memories, "retained_memory");
    json!({
        "assessment_at": &turn.assessment_at,
        "requested_lane": &turn.requested_lane,
        "available_tools": available_tools,
        "observations": observations,
        "plan": &turn.plan,
        "prior_commitment_checkpoint": &turn.prior_commitment_checkpoint,
        "wake_assessment": &turn.wake_assessment,
        "repair_feedback": &turn.repair_feedback,
        "turn_trigger": &turn.trigger,
        "session": {
            "current_operator_message": current_operator_message,
            "current_operator_message_missing": current_operator_message_missing,
            "effect_authorizations": &turn.session.effect_authorizations,
            "historical_messages": historical_messages,
            "oldest_included_message_ref": oldest_included_message_ref,
            "omitted_historical_message_count": omitted_historical_message_count,
            "mission": &turn.session.mission,
            "memories": retained_memories,
            "session_ref": &turn.session.session_ref,
            "thread_ref": &turn.session.thread_ref,
        },
    })
}

fn split_session_messages<'a>(
    messages: &'a [SessionMessage],
    trigger: &SessionTurnTrigger,
) -> (Option<&'a SessionMessage>, Vec<&'a SessionMessage>) {
    let current_index = matches!(trigger, SessionTurnTrigger::Operator)
        .then(|| {
            messages
                .iter()
                .rposition(|message| message.role == SessionMessageRole::User)
        })
        .flatten();
    let current = current_index.map(|index| &messages[index]);
    let historical = messages
        .iter()
        .enumerate()
        .filter_map(|(index, message)| (Some(index) != current_index).then_some(message))
        .collect();
    (current, historical)
}

fn current_operator_message_value(message: &SessionMessage) -> Value {
    json!({
        "actor_ref": &message.actor_ref,
        "context_kind": "current_operator_message",
        "message_ref": &message.message_ref,
        "received_at": &message.received_at,
        "role": message.role,
        "text": truncate_model_context(
            &message.text,
            MAX_SESSION_MODEL_CURRENT_MESSAGE_BYTES,
        ),
    })
}

fn operator_message_missing(trigger: &SessionTurnTrigger, current: Option<&Value>) -> bool {
    matches!(trigger, SessionTurnTrigger::Operator) && current.is_none()
}

fn bounded_session_history(messages: &[&SessionMessage]) -> (Vec<Value>, usize, Option<String>) {
    let mut selected = Vec::new();
    let mut total_bytes = 2usize;
    let mut omitted = 0usize;
    for (index, message) in messages.iter().rev().enumerate() {
        if selected.len() >= MAX_SESSION_MODEL_HISTORY_ITEMS {
            omitted += messages.len().saturating_sub(index);
            break;
        }
        let text = truncate_model_context(&message.text, MAX_SESSION_MODEL_HISTORY_ITEM_BYTES);
        let entry = json!({
            "actor_ref": &message.actor_ref,
            "context_kind": "historical_message",
            "message_ref": &message.message_ref,
            "received_at": &message.received_at,
            "role": message.role,
            "text": text,
        });
        let entry_bytes = entry.to_string().len() + usize::from(!selected.is_empty());
        if total_bytes.saturating_add(entry_bytes) > MAX_SESSION_MODEL_HISTORY_TOTAL_BYTES {
            omitted += 1;
            continue;
        }
        total_bytes += entry_bytes;
        selected.push(entry);
    }
    selected.reverse();
    let oldest_included_message_ref = selected
        .first()
        .and_then(|message| message["message_ref"].as_str())
        .map(str::to_owned);
    (selected, omitted, oldest_included_message_ref)
}
fn tagged_context_values<T: Serialize>(items: &[T], context_kind: &str) -> Vec<Value> {
    items
        .iter()
        .map(|item| tagged_context_value(item, context_kind))
        .collect()
}

fn tagged_context_value<T: Serialize>(item: &T, context_kind: &str) -> Value {
    match serde_json::to_value(item) {
        Ok(Value::Object(mut object)) if !object.contains_key("context_kind") => {
            object.insert("context_kind".into(), Value::String(context_kind.into()));
            Value::Object(object)
        }
        Ok(value) => json!({
            "context_kind": context_kind,
            "value": value,
        }),
        Err(_) => json!({
            "context_kind": context_kind,
            "value_unavailable": true,
        }),
    }
}
fn presentation_turn_payload(turn: &PresentationTurn) -> Value {
    json!({
        "completed_answer": &turn.draft,
        "lane": turn.lane,
        "repair_feedback": &turn.repair_feedback,
        "request": {
            "history": bounded_model_history(&turn.request.history),
            "message": &turn.request.message,
            "working_state": &turn.request.working_state,
        },
    })
}

fn critique_turn_payload(turn: &CritiqueTurn) -> Value {
    json!({
        "draft": &turn.draft,
        "grounding_units": &turn.grounding_units,
        "lane": turn.lane,
        "observations": &turn.observations,
        "repair_feedback": &turn.repair_feedback,
        "request": {
            "history": bounded_model_history(&turn.request.history),
            "message": &turn.request.message,
            "working_state": &turn.request.working_state,
        },
    })
}

fn bounded_model_history(history: &[cerebro_agent_runtime::ConversationMessage]) -> Value {
    let mut selected = Vec::new();
    let mut total_bytes = 0usize;
    for message in history.iter().rev().take(MAX_MODEL_HISTORY_ITEMS) {
        let content = truncate_model_context(&message.content, MAX_MODEL_HISTORY_ITEM_BYTES);
        if total_bytes.saturating_add(content.len()) > MAX_MODEL_HISTORY_TOTAL_BYTES {
            break;
        }
        total_bytes += content.len();
        selected.push(json!({
            "role": message.role,
            "content": content,
        }));
    }
    selected.reverse();
    Value::Array(selected)
}

fn truncate_model_context(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }
    let mut boundary = maximum_bytes.saturating_sub(3);
    while boundary > 0 && !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}...", value[..boundary].trim_end())
}

struct PlatformAgentTools {
    catalog: Arc<SourceCatalog>,
    graph: Arc<dyn AgentGraph>,
    ledger: Arc<PostgresLedger>,
    mcp: Option<Arc<McpAgentTools>>,
    mcp_configured: bool,
    sessions: Arc<PostgresAgentSessionStore>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphSearchInput {
    query: String,
    #[serde(default)]
    kinds: Vec<String>,
    #[serde(default = "default_graph_limit")]
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphExpandInput {
    root_key: String,
    #[serde(default = "default_graph_depth")]
    depth: usize,
    #[serde(default = "default_graph_limit")]
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRuntimeInspectInput {
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    source_ref: Option<String>,
    #[serde(default)]
    runtime_ref: Option<String>,
    #[serde(default = "default_runtime_limit")]
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceCatalogInspectInput {
    query: String,
    #[serde(default = "default_runtime_limit")]
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlackThreadReadInput {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_slack_transcript_limit")]
    limit: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SlackHistorySearchInput {
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_slack_history_limit")]
    limit: usize,
    #[serde(default)]
    query: String,
}

pub(super) fn parse_slack_thread_read_input(
    value: &Value,
) -> Result<(Option<String>, usize), AgentRuntimeError> {
    let input: SlackThreadReadInput = serde_json::from_value(value.clone())
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    if input.limit == 0 || input.limit > MAX_SLACK_TRANSCRIPT_LIMIT {
        return Err(AgentRuntimeError::InvalidToolCall(
            "Slack thread transcript limit is invalid".into(),
        ));
    }
    Ok((input.cursor, input.limit))
}

pub(super) fn parse_slack_history_search_input(
    value: &Value,
) -> Result<(Option<String>, usize, String), AgentRuntimeError> {
    let input: SlackHistorySearchInput = serde_json::from_value(value.clone())
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    if input.query.len() > 256 || input.limit == 0 || input.limit > MAX_SLACK_HISTORY_LIMIT {
        return Err(AgentRuntimeError::InvalidToolCall(
            "prior Slack thread search input is invalid".into(),
        ));
    }
    Ok((input.cursor, input.limit, input.query.trim().into()))
}

const MAX_CAPABILITY_SEARCH_LIMIT: usize = 20;
const MAX_CAPABILITY_DESCRIBE_IDS: usize = 12;
const MAX_CAPABILITY_CATALOG_OFFSET: usize = 512;
const MAX_CAPABILITY_QUERY_BYTES: usize = 512;
const MAX_CAPABILITY_TOOL_ID_BYTES: usize = 256;
pub(super) const CAPABILITY_EXECUTE_READ: &str = "capability.execute_read";
pub(super) const CAPABILITY_EXECUTE_PROPOSAL: &str = "capability.execute_proposal";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilitySearchInput {
    query: String,
    #[serde(default)]
    namespaces: Vec<String>,
    #[serde(default)]
    authority_classes: Vec<ToolAuthorityClass>,
    #[serde(default)]
    effect_classes: Vec<ToolEffectClass>,
    #[serde(default = "default_capability_search_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityDescribeInput {
    tool_ids: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityExecuteInput {
    selection_ref: String,
    input: Value,
}

fn default_capability_search_limit() -> usize {
    8
}

fn search_capability_catalog<'a>(
    catalog: &'a [ToolDescriptor],
    input: &CapabilitySearchInput,
) -> Vec<(usize, &'a ToolDescriptor)> {
    let namespaces = input
        .namespaces
        .iter()
        .map(|namespace| namespace.trim().to_ascii_lowercase())
        .filter(|namespace| !namespace.is_empty())
        .collect::<BTreeSet<_>>();
    let mut matches = catalog
        .iter()
        .filter(|descriptor| capability_search_selectable(&descriptor.tool_id))
        .filter(|descriptor| {
            namespaces.is_empty()
                || namespaces
                    .iter()
                    .any(|namespace| capability_namespace_matches(&descriptor.tool_id, namespace))
        })
        .filter(|descriptor| {
            if input.authority_classes.is_empty() {
                descriptor.authority_class == ToolAuthorityClass::Observe
            } else {
                input
                    .authority_classes
                    .contains(&descriptor.authority_class)
            }
        })
        .filter(|descriptor| {
            if input.effect_classes.is_empty() {
                descriptor.effect_class == ToolEffectClass::Read
            } else {
                input.effect_classes.contains(&descriptor.effect_class)
            }
        })
        .map(|descriptor| (0, descriptor))
        .collect::<Vec<_>>();
    matches.sort_by(|(_, left), (_, right)| left.tool_id.cmp(&right.tool_id));
    matches
}

fn capability_search_selectable(tool_id: &str) -> bool {
    !matches!(
        tool_id,
        "capability.search"
            | "capability.describe"
            | "capability.overview"
            | CAPABILITY_EXECUTE_READ
            | CAPABILITY_EXECUTE_PROPOSAL
    )
}

fn capability_search_summary(summary: &str) -> &str {
    summary
        .split(" Input JSON Schema:")
        .next()
        .unwrap_or(summary)
}

fn capability_input_schema(descriptor: &ToolDescriptor) -> Option<Value> {
    descriptor
        .summary
        .rsplit_once(" Input JSON Schema:")
        .and_then(|(_, schema)| serde_json::from_str(schema.trim()).ok())
}

fn capability_namespace_matches(tool_id: &str, namespace: &str) -> bool {
    let tool_id = tool_id.to_ascii_lowercase();
    let namespace = namespace.trim_start_matches("mcp.");
    let provider_id = tool_id.strip_prefix("mcp.").unwrap_or(&tool_id);
    provider_id == namespace
        || provider_id
            .strip_prefix(namespace)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn capability_namespace(tool_id: &str) -> &str {
    if let Some(provider_id) = tool_id.strip_prefix("mcp.") {
        return provider_id
            .split_once('.')
            .map_or(tool_id, |(provider, _)| {
                &tool_id[.."mcp.".len() + provider.len()]
            });
    }
    tool_id
        .split_once('.')
        .map_or(tool_id, |(namespace, _)| namespace)
}

fn capability_executor_tool(descriptor: &ToolDescriptor) -> Option<&'static str> {
    if !descriptor.tool_id.starts_with("mcp.") {
        return None;
    }
    match (descriptor.authority_class, descriptor.effect_class) {
        (ToolAuthorityClass::Observe, ToolEffectClass::Read) => Some(CAPABILITY_EXECUTE_READ),
        (ToolAuthorityClass::Propose, ToolEffectClass::Read) => Some(CAPABILITY_EXECUTE_PROPOSAL),
        _ => None,
    }
}

fn capability_descriptor_json(descriptor: &ToolDescriptor, score: usize) -> Value {
    let mut descriptor_value = json!({
        "authority_class": descriptor.authority_class,
        "context_kind": "capability_metadata",
        "effect_class": descriptor.effect_class,
        "input_schema_ref": descriptor.input_schema_ref,
        "result_schema_ref": descriptor.result_schema_ref,
        "summary": capability_search_summary(&descriptor.summary),
        "title": descriptor.title,
        "tool_id": descriptor.tool_id,
    });
    if let Some(input_schema) = capability_input_schema(descriptor) {
        descriptor_value["input_schema"] = input_schema;
    }
    json!({
        "descriptor": descriptor_value,
        "descriptor_digest": sha256_digest(&descriptor_value.to_string()),
        "namespace": capability_namespace(&descriptor.tool_id),
        "score": score,
    })
}

pub(super) fn capability_descriptor_binding_digest(descriptor: &ToolDescriptor) -> String {
    capability_descriptor_json(descriptor, 0)["descriptor_digest"]
        .as_str()
        .expect("capability descriptors always have a digest")
        .into()
}

pub(super) fn capability_search_result<F>(
    catalog: &[ToolDescriptor],
    input: &Value,
    mut selection: F,
) -> Result<ToolResult, AgentRuntimeError>
where
    F: FnMut(&ToolDescriptor, &str) -> Result<Option<(String, String)>, AgentRuntimeError>,
{
    let input: CapabilitySearchInput = serde_json::from_value(input.clone())
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    let query = input.query.trim();
    if query.is_empty()
        || query.len() > MAX_CAPABILITY_QUERY_BYTES
        || input.limit == 0
        || input.limit > MAX_CAPABILITY_SEARCH_LIMIT
        || input.offset > MAX_CAPABILITY_CATALOG_OFFSET
        || input.namespaces.len() > MAX_CAPABILITY_DESCRIBE_IDS
        || input.namespaces.iter().any(|namespace| {
            namespace.trim().is_empty() || namespace.len() > MAX_CAPABILITY_TOOL_ID_BYTES
        })
    {
        return Err(AgentRuntimeError::InvalidToolCall(
            "capability search bounds are invalid".into(),
        ));
    }
    let matches = search_capability_catalog(catalog, &input);
    let total_matches = matches.len();
    let query_digest = sha256_digest(query);
    let page = matches
        .into_iter()
        .skip(input.offset)
        .take(input.limit)
        .enumerate()
        .map(|(index, (score, descriptor))| {
            let mut value = capability_descriptor_json(descriptor, score);
            value["rank"] = json!(input.offset + index + 1);
            if let Some((execution_tool_id, selection_ref)) = selection(descriptor, &query_digest)?
            {
                value["execution_tool_id"] = Value::String(execution_tool_id);
                value["selection_ref"] = Value::String(selection_ref);
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, AgentRuntimeError>>()?;
    let next_offset =
        (input.offset + page.len() < total_matches).then_some(input.offset + page.len());
    Ok(ToolResult {
        state: ToolResultState::Succeeded,
        summary: format!(
            "Returned {} bound tools from the requested typed catalog filters.",
            page.len()
        ),
        data: json!({
            "matches": page,
            "next_offset": next_offset,
            "offset": input.offset,
            "query": query,
            "query_digest": query_digest,
            "schema_version": "capability-search-result/v1",
            "selection_status": "catalog_page",
            "top_score_tie_count": 0,
            "total_matches": total_matches,
        }),
        evidence: vec![],
        blocker: None,
    })
}

pub(super) fn capability_describe_result<F>(
    catalog: &[ToolDescriptor],
    input: &Value,
    mut selection: F,
) -> Result<ToolResult, AgentRuntimeError>
where
    F: FnMut(&ToolDescriptor, &str) -> Result<Option<(String, String)>, AgentRuntimeError>,
{
    let input: CapabilityDescribeInput = serde_json::from_value(input.clone())
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    if input.tool_ids.is_empty() || input.tool_ids.len() > MAX_CAPABILITY_DESCRIBE_IDS {
        return Err(AgentRuntimeError::InvalidToolCall(
            "capability describe requires between 1 and 12 tool ids".into(),
        ));
    }
    let requested = input.tool_ids.into_iter().collect::<BTreeSet<_>>();
    if requested.len() > MAX_CAPABILITY_DESCRIBE_IDS
        || requested.iter().any(|tool_id| {
            tool_id.trim().is_empty() || tool_id.len() > MAX_CAPABILITY_TOOL_ID_BYTES
        })
    {
        return Err(AgentRuntimeError::InvalidToolCall(
            "capability describe tool ids are invalid".into(),
        ));
    }
    let by_id = catalog
        .iter()
        .map(|descriptor| (descriptor.tool_id.as_str(), descriptor))
        .collect::<BTreeMap<_, _>>();
    let mut described = Vec::new();
    let mut unavailable = Vec::new();
    for tool_id in &requested {
        if let Some(descriptor) = by_id.get(tool_id.as_str()) {
            let mut value = capability_descriptor_json(descriptor, 0);
            let selection_digest = sha256_digest(&format!("describe:{tool_id}"));
            if let Some((execution_tool_id, selection_ref)) =
                selection(descriptor, &selection_digest)?
            {
                value["execution_tool_id"] = Value::String(execution_tool_id);
                value["selection_ref"] = Value::String(selection_ref);
            }
            described.push(value);
        } else {
            unavailable.push(tool_id);
        }
    }
    let complete = unavailable.is_empty();
    Ok(ToolResult {
        state: if complete {
            ToolResultState::Succeeded
        } else {
            ToolResultState::Partial
        },
        summary: "Read exact bound tool descriptors and authority policy.".into(),
        data: json!({
            "schema_version": "capability-describe-result/v1",
            "tools": described,
            "unavailable_tool_ids": unavailable,
        }),
        evidence: vec![],
        blocker: (!complete).then(|| "One or more requested tools are not bound.".into()),
    })
}

fn sha256_digest(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

#[async_trait]
impl AgentTools for PlatformAgentTools {
    fn catalog(&self) -> Vec<ToolDescriptor> {
        model_capability_catalog(self.mcp.as_deref().map_or(&[], McpAgentTools::descriptors))
    }

    async fn invoke(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let tenant_id = TenantId::parse(request.tenant_id.clone())
            .map_err(|error| AgentRuntimeError::InvalidRequest(error.to_string()))?;
        let result = match call.tool_id.as_str() {
            "capability.search" => self.search_capabilities(request, call),
            "capability.describe" => self.describe_capabilities(request, call),
            "capability.overview" => self.inspect_capability_overview(request, call),
            CAPABILITY_EXECUTE_READ | CAPABILITY_EXECUTE_PROPOSAL => {
                return self.execute_selected_capability(request, call).await;
            }
            "graph.search" => self.search(&tenant_id, request, call).await,
            "graph.expand" => self.expand(&tenant_id, request, call).await,
            "source_runtime.inspect" => {
                self.inspect_source_runtime(&tenant_id, request, call).await
            }
            "source_runtime.overview" => {
                self.inspect_source_runtime_overview(&tenant_id, request, call)
                    .await
            }
            "source_catalog.inspect" => self.inspect_source_catalog(request, call),
            "slack.thread.read" => self.read_slack_thread(request, call).await,
            "slack.history.search" => self.search_slack_history(request, call).await,
            _ => match &self.mcp {
                Some(mcp)
                    if mcp.descriptor(&call.tool_id).is_some_and(|descriptor| {
                        descriptor.authority_class == ToolAuthorityClass::Actuate
                    }) =>
                {
                    mcp.invoke(request, call).await
                }
                _ => Err(AgentRuntimeError::ToolUnavailable(call.tool_id.clone())),
            },
        }?;
        atomize_tool_result(call, result)
    }
}

fn built_in_capability_catalog() -> Vec<ToolDescriptor> {
    vec![
            ToolDescriptor {
                tool_id: "capability.search".into(),
                title: "Find tools for an intent".into(),
                summary: "Search the complete bound capability catalog by intent, namespace, authority class, and effect class before choosing a provider tool. Catalog results describe capability only and are not evidence about an external system. Input fields: query string, optional namespaces string array, optional authority_classes and effect_classes arrays, optional limit from 1 to 20, and optional offset.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/capability-search-input/v1".into(),
                result_schema_ref: "schema://cerebro/capability-search-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "capability.describe".into(),
                title: "Describe exact tools".into(),
                summary: "Read exact bound tool descriptors, authority and effect policy, structured provider input schemas, and executable signed selections for up to 12 tool ids. Catalog results describe capability only and are not evidence about an external system. Input field: tool_ids string array.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/capability-describe-input/v1".into(),
                result_schema_ref: "schema://cerebro/capability-describe-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: CAPABILITY_EXECUTE_READ.into(),
                title: "Execute a selected read capability".into(),
                summary: "Redeem one host-signed capability selection for its exact read-only provider tool. Input fields: selection_ref string returned by capability.search or capability.describe and input object matching the selected provider schema.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/capability-execute-input/v1".into(),
                result_schema_ref: "schema://cerebro/capability-execute-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: CAPABILITY_EXECUTE_PROPOSAL.into(),
                title: "Execute a selected proposal capability".into(),
                summary: "Redeem one host-signed capability selection for its exact proposal-only provider tool. Input fields: selection_ref string returned by capability.search or capability.describe and input object matching the selected provider schema.".into(),
                authority_class: ToolAuthorityClass::Propose,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/capability-execute-input/v1".into(),
                result_schema_ref: "schema://cerebro/capability-execute-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "capability.overview".into(),
                title: "Read current agent capabilities".into(),
                summary: "Read the exact capability families currently bound to this Slack agent, including degraded optional capability gateways. Input is an empty object.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/capability-overview-input/v1".into(),
                result_schema_ref: "schema://cerebro/capability-overview-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "graph.search".into(),
                title: "Search governed security graph".into(),
                summary: "Find bounded graph entities by label, identifier, and entity kind. Input fields: query string, optional kinds string array, optional limit from 1 to 25.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/graph-search-input/v1".into(),
                result_schema_ref: "schema://cerebro/graph-search-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "graph.expand".into(),
                title: "Inspect governed entity context".into(),
                summary: "Read bounded neighboring entities and assertions for one graph entity. Input fields: root_key string, optional depth from 1 to 3, optional limit from 1 to 25.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/graph-expand-input/v1".into(),
                result_schema_ref: "schema://cerebro/graph-expand-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "source_runtime.inspect".into(),
                title: "Inspect source runtime health".into(),
                summary: "Read tenant-scoped runtime status, cursor state, latest sync, latest collection receipt, and evidence gaps without exposing connector configuration. Input must contain exactly one of query, source_ref, or runtime_ref, plus an optional limit from 1 to 25.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/source-runtime-inspect-input/v1".into(),
                result_schema_ref: "schema://cerebro/source-runtime-inspect-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "source_runtime.overview".into(),
                title: "Read source runtime overview".into(),
                summary: "Read a bounded tenant-scoped operational overview across source runtimes, including health, cursor, collection receipt, and evidence-gap counts. Input is an empty object.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/source-runtime-overview-input/v1".into(),
                result_schema_ref: "schema://cerebro/source-runtime-overview-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "source_catalog.inspect".into(),
                title: "Inspect declared source capabilities".into(),
                summary: "Read the non-secret connector definition for a named source, including its authentication model, declared record families, and projection authority. This does not prove credentials, provider-side permissions, runtime enablement, or collected evidence. Input fields: query string, optional limit from 1 to 25.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/source-catalog-inspect-input/v1".into(),
                result_schema_ref: "schema://cerebro/source-catalog-inspect-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "slack.thread.read".into(),
                title: "Read this owned Slack thread".into(),
                summary: "Read one bounded page of the current Cerebro-owned thread transcript. Scope is derived from the active tenant and thread; no channel or thread selector is accepted. Input fields: optional cursor string, optional limit from 1 to 20.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/slack-thread-read-input/v1".into(),
                result_schema_ref: "schema://cerebro/slack-thread-read-result/v1".into(),
            },
            ToolDescriptor {
                tool_id: "slack.history.search".into(),
                title: "Search prior Slack thread context".into(),
                summary: "Read one bounded page of prior completed thread context for the same tenant, operator, and channel as the active request. Input fields: optional query string up to 256 bytes, optional cursor string, optional limit from 1 to 4.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema://cerebro/slack-history-search-input/v1".into(),
                result_schema_ref: "schema://cerebro/slack-history-search-result/v1".into(),
            },
    ]
}

pub(super) fn model_capability_catalog(remote: &[ToolDescriptor]) -> Vec<ToolDescriptor> {
    let mut catalog = built_in_capability_catalog();
    catalog.extend(
        remote
            .iter()
            .filter(|descriptor| descriptor.authority_class == ToolAuthorityClass::Actuate)
            .cloned(),
    );
    catalog
}

fn capability_overview_descriptor_json(descriptor: &ToolDescriptor) -> Value {
    json!({
        "authority_class": descriptor.authority_class,
        "effect_class": descriptor.effect_class,
        "title": &descriptor.title,
        "tool_id": &descriptor.tool_id,
    })
}

fn atomize_tool_result(
    call: &cerebro_agent_runtime::ToolCall,
    mut result: ToolResult,
) -> Result<ToolResult, AgentRuntimeError> {
    if matches!(
        call.tool_id.as_str(),
        "slack.thread.read" | "slack.history.search"
    ) {
        for evidence in &mut result.evidence {
            evidence.fresh_until = None;
            evidence.atoms =
                slack_conversation_event_atoms(&call.tool_id, &evidence.evidence_ref, &result.data);
        }
        return Ok(result);
    }
    let subject_ref = production_input_subject(&call.tool_id, &call.input)?.map(str::to_owned);
    for evidence in &mut result.evidence {
        let semantic_assertions = evidence
            .atoms
            .iter()
            .filter_map(|atom| match &atom.assertion {
                EvidenceAssertion::Semantic { assertion } => Some(assertion.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();
        evidence.atoms = if semantic_assertions.is_empty() {
            Vec::new()
        } else {
            semantic_evidence_atoms(SemanticEvidenceAtomization {
                evidence_ref: &evidence.evidence_ref,
                envelope: SemanticEvidenceEnvelope {
                    schema_version: AGENT_SEMANTIC_EVIDENCE_V1.into(),
                    assertions: semantic_assertions,
                },
                observed_at: &evidence.observed_at,
                fresh_until: evidence.fresh_until.as_deref(),
                complete: evidence.complete,
            })
            .unwrap_or_default()
        };
        evidence
            .atoms
            .extend(evidence_atoms_from_json(EvidenceAtomization {
                evidence_ref: &evidence.evidence_ref,
                subject_ref: subject_ref.as_deref(),
                data: &result.data,
                state: result.state,
                summary: &result.summary,
                observed_at: &evidence.observed_at,
                fresh_until: evidence.fresh_until.as_deref(),
                complete: evidence.complete,
            }));
    }
    Ok(result)
}

fn slack_conversation_event_atoms(
    tool_id: &str,
    evidence_ref: &str,
    data: &Value,
) -> Vec<EvidenceAtom> {
    let mut atoms = Vec::new();
    let mut push_event = |suffix: String,
                          thread_ref: &str,
                          actor_ref: &str,
                          role: &str,
                          occurred_at: &str,
                          text: &str| {
        if text.trim().is_empty() || text.len() > 2_000 || occurred_at.trim().is_empty() {
            return;
        }
        atoms.push(EvidenceAtom {
            atom_ref: format!("{evidence_ref}#conversation:{suffix}"),
            subject_ref: Some(thread_ref.to_owned()),
            assertion: EvidenceAssertion::ConversationEvent {
                thread_ref: thread_ref.to_owned(),
                actor_ref: actor_ref.to_owned(),
                role: role.to_owned(),
                occurred_at: occurred_at.to_owned(),
                text: text.to_owned(),
            },
            observed_at: occurred_at.to_owned(),
            fresh_until: None,
            complete: true,
        });
    };
    match tool_id {
        "slack.thread.read" => {
            for (index, message) in data
                .get("messages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let Some(thread_ref) = message
                    .get("thread_ref")
                    .and_then(Value::as_str)
                    .or_else(|| data.get("thread_ref").and_then(Value::as_str))
                else {
                    continue;
                };
                let Some(actor_ref) = message.get("actor_ref").and_then(Value::as_str) else {
                    continue;
                };
                let Some(role) = message.get("role").and_then(Value::as_str) else {
                    continue;
                };
                let Some(occurred_at) = message.get("received_at").and_then(Value::as_str) else {
                    continue;
                };
                let Some(text) = message.get("text").and_then(Value::as_str) else {
                    continue;
                };
                push_event(
                    index.to_string(),
                    thread_ref,
                    actor_ref,
                    role,
                    occurred_at,
                    text,
                );
            }
        }
        "slack.history.search" => {
            for (index, thread) in data
                .get("threads")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .enumerate()
            {
                let Some(thread_ref) = thread.get("thread_ref").and_then(Value::as_str) else {
                    continue;
                };
                let Some(occurred_at) = thread.get("updated_at").and_then(Value::as_str) else {
                    continue;
                };
                let Some(context) = thread.get("context").and_then(Value::as_object) else {
                    continue;
                };
                for (field, actor_ref, role) in [
                    ("latest_user_message", "historical-operator", "user"),
                    ("latest_assistant_message", "cerebro", "assistant"),
                    ("objective", "retained-mission", "objective"),
                    ("desired_outcome", "retained-mission", "desired_outcome"),
                ] {
                    if let Some(text) = context.get(field).and_then(Value::as_str) {
                        push_event(
                            format!("{index}:{field}"),
                            thread_ref,
                            actor_ref,
                            role,
                            occurred_at,
                            text,
                        );
                    }
                }
                for (collection, actor_ref, role) in [
                    ("open_loops", "retained-open-loop", "open_loop"),
                    ("commitments", "retained-commitment", "commitment"),
                ] {
                    for (item_index, item) in context
                        .get(collection)
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .enumerate()
                    {
                        if let Some(text) = item.as_str() {
                            push_event(
                                format!("{index}:{collection}:{item_index}"),
                                thread_ref,
                                actor_ref,
                                role,
                                occurred_at,
                                text,
                            );
                            continue;
                        }
                        let Some(item) = item.as_object() else {
                            continue;
                        };
                        for field in ["summary", "next_action", "blocked_by", "status", "owner"] {
                            if let Some(text) = item.get(field).and_then(Value::as_str) {
                                push_event(
                                    format!("{index}:{collection}:{item_index}:{field}"),
                                    thread_ref,
                                    actor_ref,
                                    role,
                                    occurred_at,
                                    text,
                                );
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    atoms
}

fn production_input_subject<'a>(
    tool_id: &str,
    input: &'a Value,
) -> Result<Option<&'a str>, AgentRuntimeError> {
    let Some(input) = input.as_object() else {
        return Ok(None);
    };
    let subjects = [
        "subject_ref",
        "finding_ref",
        "asset_ref",
        "investigation_ref",
        "connector_ref",
        "runtime_ref",
        "source_ref",
        "root_key",
    ]
    .iter()
    .filter_map(|field| input.get(*field).and_then(Value::as_str))
    .collect::<BTreeSet<_>>();
    let query_subject = matches!(tool_id, "source_runtime.inspect" | "source_catalog.inspect")
        .then(|| input.get("query").and_then(Value::as_str))
        .flatten();
    let subjects = query_subject
        .into_iter()
        .chain(subjects)
        .collect::<BTreeSet<_>>();
    if subjects.len() > 1 {
        return Err(AgentRuntimeError::InvalidToolCall(
            "tool input has conflicting subject aliases".into(),
        ));
    }
    Ok(subjects.into_iter().next())
}

#[async_trait]
impl SessionTools for PlatformAgentTools {
    fn catalog(&self) -> Vec<ToolDescriptor> {
        <Self as AgentTools>::catalog(self)
    }

    async fn invoke(
        &self,
        session: &cerebro_agent_runtime::session::AgentSession,
        input: &SessionTurnInput,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let request_text =
            cerebro_agent_runtime::session::session_turn_request_text(session, input)?;
        let history = session
            .messages
            .iter()
            .take(session.messages.len().saturating_sub(1))
            .map(|message| {
                let role = match message.role {
                    SessionMessageRole::Assistant => {
                        cerebro_agent_runtime::ConversationRole::Assistant
                    }
                    SessionMessageRole::User => cerebro_agent_runtime::ConversationRole::User,
                };
                cerebro_agent_runtime::ConversationMessage {
                    role,
                    content: message.text.clone(),
                }
            })
            .collect();
        let request = AgentTurnRequest {
            schema_version: cerebro_agent_runtime::AGENT_TURN_REQUEST_V1.into(),
            tenant_id: session.tenant_id.clone(),
            request_id: input.request_id.clone(),
            thread_ref: session.thread_ref.clone(),
            context_scope_ref: session.context_scope_ref.clone(),
            actor_ref: input.actor_ref.clone(),
            assessment_at: input.assessment_at.clone(),
            message: request_text,
            history,
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: session.effect_authorizations.clone(),
            capabilities: Vec::new(),
            followup_acceptance: None,
        };
        <Self as AgentTools>::invoke(self, &request, call).await
    }
}

impl PlatformAgentTools {
    fn complete_capability_catalog(&self) -> Vec<ToolDescriptor> {
        let mut catalog = built_in_capability_catalog();
        if let Some(mcp) = &self.mcp {
            catalog.extend(mcp.descriptors().iter().cloned());
        }
        catalog
    }

    fn search_capabilities(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let catalog = self.complete_capability_catalog();
        capability_search_result(&catalog, &call.input, |descriptor, query_digest| {
            let (Some(mcp), Some(executor_tool_id)) =
                (&self.mcp, capability_executor_tool(descriptor))
            else {
                return Ok(None);
            };
            let selection_ref = mcp
                .issue_selection_ref(request, descriptor, query_digest)
                .map_err(AgentRuntimeError::InvalidToolCall)?;
            Ok(Some((executor_tool_id.into(), selection_ref)))
        })
    }

    fn describe_capabilities(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let catalog = self.complete_capability_catalog();
        capability_describe_result(&catalog, &call.input, |descriptor, query_digest| {
            let (Some(mcp), Some(executor_tool_id)) =
                (&self.mcp, capability_executor_tool(descriptor))
            else {
                return Ok(None);
            };
            let selection_ref = mcp
                .issue_selection_ref(request, descriptor, query_digest)
                .map_err(AgentRuntimeError::InvalidToolCall)?;
            Ok(Some((executor_tool_id.into(), selection_ref)))
        })
    }

    async fn execute_selected_capability(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let input: CapabilityExecuteInput = serde_json::from_value(call.input.clone())
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
        if input.selection_ref.len() > 1_024 || !input.input.is_object() {
            return Err(AgentRuntimeError::InvalidToolCall(
                "capability execution requires a bounded selection_ref and object input".into(),
            ));
        }
        let mcp = self.mcp.as_ref().ok_or_else(|| {
            AgentRuntimeError::ToolUnavailable("MCP capability gateway is not bound".into())
        })?;
        let descriptor = mcp
            .verify_selection_ref(request, &input.selection_ref)
            .map_err(AgentRuntimeError::InvalidToolCall)?;
        if capability_executor_tool(&descriptor) != Some(call.tool_id.as_str()) {
            return Err(AgentRuntimeError::InvalidToolCall(
                "capability selection authority does not match this executor".into(),
            ));
        }
        let provider_call = cerebro_agent_runtime::ToolCall {
            call_id: call.call_id.clone(),
            tool_id: descriptor.tool_id,
            purpose: call.purpose.clone(),
            input: input.input,
        };
        let result = mcp.invoke(request, &provider_call).await?;
        atomize_tool_result(&provider_call, result)
    }

    fn inspect_capability_overview(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let input = call.input.as_object().ok_or_else(|| {
            AgentRuntimeError::InvalidToolCall("capability overview input must be an object".into())
        })?;
        if !input.is_empty() {
            return Err(AgentRuntimeError::InvalidToolCall(
                "capability overview input must be empty".into(),
            ));
        }
        let remote = self
            .mcp
            .as_ref()
            .map(|mcp| mcp.descriptors())
            .unwrap_or_default();
        let built_in = built_in_capability_catalog();
        let observed = remote
            .iter()
            .filter(|tool| tool.authority_class == ToolAuthorityClass::Observe)
            .count();
        let proposed = remote
            .iter()
            .filter(|tool| tool.authority_class == ToolAuthorityClass::Propose)
            .count();
        let actuated = remote
            .iter()
            .filter(|tool| tool.authority_class == ToolAuthorityClass::Actuate)
            .count();
        let gateway_state = if self.mcp.is_some() {
            "connected"
        } else if self.mcp_configured {
            "unavailable"
        } else {
            "not_configured"
        };
        let complete = !self.mcp_configured || self.mcp.is_some();
        let evidence = runtime_evidence(
            request,
            call,
            complete,
            format!(
                "The Slack agent capability registry observed {} built-in tools and {} bound MCP tools; MCP gateway state={gateway_state}.",
                built_in.len(),
                remote.len()
            ),
        )?;
        Ok(ToolResult {
            state: if complete {
                ToolResultState::Succeeded
            } else {
                ToolResultState::Partial
            },
            summary: "Read the current Slack agent capability registry.".into(),
            data: json!({
                "built_in": built_in.iter().map(capability_overview_descriptor_json).collect::<Vec<_>>(),
                "mcp": {
                    "actuate_tools": actuated,
                    "gateway_state": gateway_state,
                    "observe_tools": observed,
                    "propose_tools": proposed,
                    "tool_count": remote.len(),
                    "tools": remote.iter().map(capability_overview_descriptor_json).collect::<Vec<_>>(),
                },
            }),
            evidence: vec![evidence],
            blocker: (!complete).then(|| {
                "The configured MCP capability gateway did not return its tool catalog.".into()
            }),
        })
    }

    async fn read_slack_thread(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let (cursor, limit) = parse_slack_thread_read_input(&call.input)?;
        let page = self
            .sessions
            .read_owned_thread_transcript(
                &request.tenant_id,
                &request.thread_ref,
                cursor.as_deref(),
                limit,
            )
            .await?;
        let complete = page.next_cursor.is_none();
        let evidence = slack_history_evidence(
            request,
            call,
            complete,
            format!(
                "The durable Slack session returned {} transcript messages from the current Cerebro-owned thread; more_pages={}. This retained context is not current external-system evidence.",
                page.messages.len(),
                !complete,
            ),
        )?;
        Ok(ToolResult {
            state: if complete {
                ToolResultState::Succeeded
            } else {
                ToolResultState::Partial
            },
            summary: format!(
                "Read {} messages from this owned Slack thread.",
                page.messages.len()
            ),
            data: json!({
                "thread_ref": request.thread_ref,
                "messages": page.messages,
                "next_cursor": page.next_cursor,
            }),
            evidence: vec![evidence],
            blocker: (!complete).then(|| {
                "Older messages remain available through the returned bounded cursor.".into()
            }),
        })
    }

    async fn search_slack_history(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let (cursor, limit, query) = parse_slack_history_search_input(&call.input)?;
        let context_scope_ref = request.context_scope_ref.as_deref().ok_or_else(|| {
            AgentRuntimeError::InvalidToolCall(
                "prior Slack thread search requires the active channel scope".into(),
            )
        })?;
        validate_context_scope_ref(context_scope_ref)?;
        let session = self
            .sessions
            .load_by_thread(&request.tenant_id, &request.thread_ref)
            .await?
            .ok_or_else(|| {
                AgentRuntimeError::InvalidRequest("Slack thread session does not exist".into())
            })?;
        let page = self
            .sessions
            .search_prior_thread_contexts(AgentPriorThreadSearch {
                actor_ref: &request.actor_ref,
                context_scope_ref,
                cursor: cursor.as_deref(),
                exclude_session_ref: &session.session_ref,
                limit,
                query: &query,
                tenant_id: &request.tenant_id,
            })
            .await?;
        let complete = page.next_cursor.is_none();
        let evidence = slack_history_evidence(
            request,
            call,
            complete,
            format!(
                "The durable Slack context index returned {} prior completed threads scoped to the same tenant, operator, and channel; more_pages={}. Retained context is not current external-system evidence.",
                page.threads.len(),
                !complete,
            ),
        )?;
        Ok(ToolResult {
            state: if complete {
                ToolResultState::Succeeded
            } else {
                ToolResultState::Partial
            },
            summary: format!(
                "Read {} prior thread contexts for this operator and channel.",
                page.threads.len()
            ),
            data: serde_json::to_value(page)
                .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
            evidence: vec![evidence],
            blocker: (!complete).then(|| {
                "More matching prior threads remain available through the returned bounded cursor."
                    .into()
            }),
        })
    }

    fn inspect_source_catalog(
        &self,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let input: SourceCatalogInspectInput = serde_json::from_value(call.input.clone())
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
        let query = input.query.trim();
        if query.is_empty() || input.limit == 0 || input.limit > MAX_RUNTIME_LIMIT {
            return Err(AgentRuntimeError::InvalidToolCall(
                "source catalog query or limit is invalid".into(),
            ));
        }
        let (sources, truncated) = source_catalog_views(&self.catalog, input.limit);
        let evidence = catalog_evidence(
            request,
            call,
            !truncated,
            format!(
                "The checked-in source catalog returned {} connector definitions; truncated={truncated}.",
                sources.len(),
            ),
        )?;
        Ok(ToolResult {
            state: if truncated {
                ToolResultState::Partial
            } else {
                ToolResultState::Succeeded
            },
            summary: format!("Read {} source definitions.", sources.len()),
            data: json!({
                "sources": sources,
                "truncated": truncated,
            }),
            evidence: vec![evidence],
            blocker: truncated
                .then(|| "More source definitions exist than this bounded page returned.".into()),
        })
    }

    async fn search(
        &self,
        tenant_id: &TenantId,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let input: GraphSearchInput = serde_json::from_value(call.input.clone())
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
        let query = input.query.trim();
        if query.is_empty() || input.limit == 0 || input.limit > MAX_GRAPH_LIMIT {
            return Err(AgentRuntimeError::InvalidToolCall(
                "graph search query or limit is invalid".into(),
            ));
        }
        let requested = input.limit.saturating_add(1);
        let entities = match self
            .graph
            .search(tenant_id, query, &input.kinds, requested)
            .await
        {
            Ok(entities) => entities,
            Err(error) => return Ok(graph_failure(error)),
        };
        let truncated = entities.len() > input.limit;
        let entities = entities.into_iter().take(input.limit).collect::<Vec<_>>();
        let revision = self.graph.revision(tenant_id).await.ok();
        let evidence = graph_evidence(
            request,
            call,
            !truncated,
            format!(
                "The governed graph returned {} matching entities; truncated={truncated}; revision={}.",
                entities.len(),
                revision.map_or_else(|| "unavailable".into(), |value| value.to_string())
            ),
        )?;
        Ok(ToolResult {
            state: if truncated {
                ToolResultState::Partial
            } else {
                ToolResultState::Succeeded
            },
            summary: format!("Found {} matching graph entities.", entities.len()),
            data: json!({
                "entities": entities,
                "graph_revision": revision,
                "truncated": truncated,
            }),
            evidence: vec![evidence],
            blocker: truncated.then(|| {
                "More matching graph entities exist than this bounded read returned.".into()
            }),
        })
    }

    async fn expand(
        &self,
        tenant_id: &TenantId,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let input: GraphExpandInput = serde_json::from_value(call.input.clone())
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
        if input.root_key.trim().is_empty()
            || input.depth == 0
            || input.depth > MAX_GRAPH_DEPTH
            || input.limit == 0
            || input.limit > MAX_GRAPH_LIMIT
        {
            return Err(AgentRuntimeError::InvalidToolCall(
                "graph expansion input is invalid".into(),
            ));
        }
        let root = match self.graph.resolve(tenant_id, input.root_key.trim()).await {
            Ok(root) => root,
            Err(error) => return Ok(graph_failure(error)),
        };
        let neighborhood = match self
            .graph
            .expand(tenant_id, &root.entity_id, input.depth, input.limit)
            .await
        {
            Ok(neighborhood) => neighborhood,
            Err(error) => return Ok(graph_failure(error)),
        };
        let evidence = graph_evidence(
            request,
            call,
            !neighborhood.truncated,
            format!(
                "The governed graph returned {} neighboring entities and {} assertions for {}; truncated={}; revision={}.",
                neighborhood.entities.len(),
                neighborhood.edges.len(),
                neighborhood.root.label,
                neighborhood.truncated,
                neighborhood.graph_revision,
            ),
        )?;
        Ok(ToolResult {
            state: if neighborhood.truncated {
                ToolResultState::Partial
            } else {
                ToolResultState::Succeeded
            },
            summary: format!("Read governed context for {}.", neighborhood.root.label),
            data: serde_json::to_value(&neighborhood)
                .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
            evidence: vec![evidence],
            blocker: neighborhood.truncated.then(|| {
                "More neighboring assertions exist than this bounded read returned.".into()
            }),
        })
    }

    async fn inspect_source_runtime(
        &self,
        tenant_id: &TenantId,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let input: SourceRuntimeInspectInput = serde_json::from_value(call.input.clone())
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
        production_input_subject(&call.tool_id, &call.input)?;
        let query = [
            input.query.as_deref(),
            input.source_ref.as_deref(),
            input.runtime_ref.as_deref(),
        ]
        .into_iter()
        .flatten()
        .next()
        .ok_or_else(|| {
            AgentRuntimeError::InvalidToolCall(
                "source runtime inspection requires one exact query, source_ref, or runtime_ref"
                    .into(),
            )
        })?
        .trim();
        if query.is_empty() || input.limit == 0 || input.limit > MAX_RUNTIME_LIMIT {
            return Err(AgentRuntimeError::InvalidToolCall(
                "source runtime query or limit is invalid".into(),
            ));
        }
        let requested = input.limit.saturating_add(1);
        let records = match self
            .ledger
            .source_runtime_observations(tenant_id.as_str(), query, requested)
            .await
        {
            Ok(records) => records,
            Err(_) => return Ok(source_runtime_failure()),
        };
        let records = prefer_exact_runtime_matches(records, query);
        let truncated = records.len() > input.limit;
        let now = OffsetDateTime::now_utc();
        let mut has_gaps = false;
        let runtimes = records
            .into_iter()
            .take(input.limit)
            .map(|record| {
                let (view, gaps) = source_runtime_view(record, now);
                has_gaps |= !gaps.is_empty();
                view
            })
            .collect::<Vec<_>>();
        let evidence = runtime_evidence(
            request,
            call,
            !truncated,
            format!(
                "The Rust source-runtime ledger returned {} matching runtimes with their latest collection receipts; truncated={truncated}.",
                runtimes.len(),
            ),
        )?;
        let partial = truncated || has_gaps;
        Ok(ToolResult {
            state: if partial {
                ToolResultState::Partial
            } else {
                ToolResultState::Succeeded
            },
            summary: format!(
                "Read health and progress for {} source runtimes.",
                runtimes.len()
            ),
            data: json!({
                "runtimes": runtimes,
                "truncated": truncated,
            }),
            evidence: vec![evidence],
            blocker: partial.then(|| {
                "One or more runtime health signals are missing, incomplete, rejected, or truncated."
                    .into()
            }),
        })
    }

    async fn inspect_source_runtime_overview(
        &self,
        tenant_id: &TenantId,
        request: &AgentTurnRequest,
        call: &cerebro_agent_runtime::ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError> {
        let input = call.input.as_object().ok_or_else(|| {
            AgentRuntimeError::InvalidToolCall(
                "source runtime overview input must be an object".into(),
            )
        })?;
        if !input.is_empty() {
            return Err(AgentRuntimeError::InvalidToolCall(
                "source runtime overview input must be empty".into(),
            ));
        }
        let records = match self
            .ledger
            .source_runtime_observations(
                tenant_id.as_str(),
                "",
                MAX_RUNTIME_LIMIT.saturating_add(1),
            )
            .await
        {
            Ok(records) => records,
            Err(_) => return Ok(source_runtime_failure()),
        };
        let truncated = records.len() > MAX_RUNTIME_LIMIT;
        let now = OffsetDateTime::now_utc();
        let mut evidence_gap_count = 0usize;
        let mut health_counts = BTreeMap::<String, usize>::new();
        let mut cursor_pending_count = 0usize;
        let mut incomplete_collection_count = 0usize;
        let runtimes = records
            .into_iter()
            .take(MAX_RUNTIME_LIMIT)
            .map(|record| {
                let (view, gaps) = source_runtime_view(record, now);
                evidence_gap_count = evidence_gap_count.saturating_add(gaps.len());
                if let Some(health) = view.get("health").and_then(Value::as_str) {
                    let count = health_counts.entry(health.to_owned()).or_default();
                    *count = count.saturating_add(1);
                }
                if view["cursor_state"] == "pending" {
                    cursor_pending_count = cursor_pending_count.saturating_add(1);
                }
                if view
                    .get("latest_collection")
                    .and_then(|collection| collection.get("status"))
                    .and_then(Value::as_str)
                    .is_none_or(|status| status != "complete")
                {
                    incomplete_collection_count = incomplete_collection_count.saturating_add(1);
                }
                view
            })
            .collect::<Vec<_>>();
        let observed_runtime_count = runtimes.len();
        let evidence = runtime_evidence(
            request,
            call,
            !truncated,
            format!(
                "The Rust source-runtime ledger returned a bounded operational overview for {observed_runtime_count} runtimes; truncated={truncated}."
            ),
        )?;
        let partial = truncated || evidence_gap_count > 0;
        Ok(ToolResult {
            state: if partial {
                ToolResultState::Partial
            } else {
                ToolResultState::Succeeded
            },
            summary: format!(
                "Read a bounded operational overview for {observed_runtime_count} source runtimes."
            ),
            data: json!({
                "coverage": {
                    "complete": !truncated,
                    "observed_runtime_count": observed_runtime_count,
                    "truncated": truncated,
                },
                "counts": {
                    "cursor_pending": cursor_pending_count,
                    "evidence_gaps": evidence_gap_count,
                    "health": health_counts,
                    "incomplete_collections": incomplete_collection_count,
                },
                "runtimes": runtimes,
            }),
            evidence: vec![evidence],
            blocker: partial.then(|| {
                "The operational overview contains incomplete runtime evidence or exceeded the bounded read."
                    .into()
            }),
        })
    }
}

fn source_catalog_views(catalog: &SourceCatalog, limit: usize) -> (Vec<Value>, bool) {
    let mut matches = catalog.sources().collect::<Vec<_>>();
    matches.sort_by(|left, right| left.id().cmp(right.id()));
    let truncated = matches.len() > limit;
    let sources = matches
        .into_iter()
        .take(limit)
        .map(|source| {
            json!({
                "source_id": source.id(),
                "display_name": source.display_name(),
                "authentication_model": auth_model_name(source.auth()),
                "generic_runtime_supported": source.auth().supports_generic_runtime(),
                "collection_authority": collection_authority_name(source.authority()),
                "declared_families": source.families().iter().map(|family| {
                    json!({
                        "family_id": family.id(),
                        "projection_class": family.projection().class(),
                        "collection_authoritative": family.is_authoritative(),
                        "projection_authoritative": family.is_projection_authoritative(),
                    })
                }).collect::<Vec<_>>(),
                "credential_access_observed": false,
                "provider_permission_scope_observed": false,
                "runtime_enablement_observed": false,
            })
        })
        .collect();
    (sources, truncated)
}

fn prefer_exact_runtime_matches(
    records: Vec<SourceRuntimeObservation>,
    query: &str,
) -> Vec<SourceRuntimeObservation> {
    if records.iter().any(|record| {
        record.runtime_id.eq_ignore_ascii_case(query)
            || record.source_id.eq_ignore_ascii_case(query)
    }) {
        records
            .into_iter()
            .filter(|record| {
                record.runtime_id.eq_ignore_ascii_case(query)
                    || record.source_id.eq_ignore_ascii_case(query)
            })
            .collect()
    } else {
        records
    }
}

fn source_runtime_view(
    record: SourceRuntimeObservation,
    now: OffsetDateTime,
) -> (Value, Vec<String>) {
    let mut evidence_gaps = Vec::new();
    let enabled_state = match record.enabled_state.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "enabled" => "enabled",
        "false" | "0" | "disabled" => "disabled",
        "" => {
            evidence_gaps.push("enabled_state_not_observed".to_owned());
            "unknown"
        }
        _ => {
            evidence_gaps.push("enabled_state_invalid".to_owned());
            "unknown"
        }
    };
    let parsed_sync = record
        .last_synced_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
    if record.last_synced_at.is_none() {
        evidence_gaps.push("last_sync_not_observed".to_owned());
    } else if parsed_sync.is_none() {
        evidence_gaps.push("last_sync_timestamp_invalid".to_owned());
    }
    if record.stale_after_seconds.is_none() {
        evidence_gaps.push("freshness_threshold_not_configured".to_owned());
    }
    let sync_lag_seconds = parsed_sync.map(|synced_at| (now - synced_at).whole_seconds().max(0));
    let sync_stale = record
        .stale_after_seconds
        .zip(sync_lag_seconds)
        .is_some_and(|(threshold, lag)| u64::try_from(lag).is_ok_and(|lag| lag > threshold));
    let source_status = if record.last_failure_category.is_some() {
        "failing"
    } else if parsed_sync.is_none() {
        "unknown"
    } else if sync_stale {
        "stale"
    } else {
        "healthy"
    };
    let finding_evaluation_state = record
        .latest_finding_evaluation_status
        .as_deref()
        .map(source_runtime_finding_state)
        .unwrap_or("not_observed");
    let schedule_context_configured =
        record.stale_after_seconds.is_some() || record.expected_cadence_seconds.is_some();
    let decision = evaluate_runtime_readiness(RuntimeHealthEvidence {
        enabled_state,
        source_status,
        graph_state: "not_observed",
        cursor_pending: record.cursor_pending,
        schedule_context_configured,
        contract_probe_state: &record.contract_probe_state,
        finding_evaluation_state,
    });
    let health = match decision.readiness {
        RuntimeReadiness::Bad => "failing",
        RuntimeReadiness::NeedsRefresh => "stale",
        RuntimeReadiness::Poor => "unknown",
        RuntimeReadiness::Healthy => "healthy",
    };
    let latest_collection = record.latest_collection.map(|collection| {
        if collection.status != "complete" {
            evidence_gaps.push("latest_collection_incomplete".to_owned());
        }
        if collection.records_rejected > 0 {
            evidence_gaps.push("latest_collection_has_rejected_records".to_owned());
        }
        json!({
            "collection_id": collection.collection_id,
            "status": collection.status,
            "completed_at": unix_millis_rfc3339(collection.completed_at_unix_ms),
            "pages_read": collection.pages_read,
            "records_scanned": collection.records_scanned,
            "records_accepted": collection.records_accepted,
            "records_rejected": collection.records_rejected,
        })
    });
    if latest_collection.is_none() {
        evidence_gaps.push("collection_receipt_not_observed".to_owned());
    }
    (
        json!({
            "runtime_id": record.runtime_id,
            "source_id": record.source_id,
            "enabled_state": enabled_state,
            "health": health,
            "readiness": decision.readiness.as_str(),
            "next_action": decision.next_action.as_str(),
            "last_failure_category": record.last_failure_category,
            "last_synced_at": record.last_synced_at,
            "sync_lag_seconds": sync_lag_seconds,
            "stale_after_seconds": record.stale_after_seconds,
            "expected_cadence_seconds": record.expected_cadence_seconds,
            "schedule_context_configured": schedule_context_configured,
            "contract_probe_state": record.contract_probe_state,
            "graph_state": "not_observed",
            "finding_evaluation_state": finding_evaluation_state,
            "cursor_state": if record.cursor_pending { "pending" } else { "clear" },
            "checkpoint_cursor_state": if record.checkpoint_cursor_present { "present" } else { "clear" },
            "latest_collection": latest_collection,
            "evidence_gaps": evidence_gaps,
        }),
        evidence_gaps,
    )
}

fn source_runtime_finding_state(status: &str) -> &'static str {
    match status.trim().to_ascii_lowercase().as_str() {
        "failed" | "error" | "cancelled" | "canceled" => "failed",
        "running" | "pending" => "running",
        "current" | "complete" | "completed" | "success" | "succeeded" => "current",
        _ => "not_observed",
    }
}

fn unix_millis_rfc3339(value: u64) -> Option<String> {
    let nanos = i128::from(value).checked_mul(1_000_000)?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn source_runtime_failure() -> ToolResult {
    ToolResult {
        state: ToolResultState::Failed,
        summary: "The Rust source-runtime ledger read failed.".into(),
        data: json!({
            "error_kind": "backend_unavailable",
            "retryable": true,
            "operator_action": "Retry after the source-runtime ledger recovers."
        }),
        evidence: vec![],
        blocker: Some(
            "The source-runtime ledger could not complete this tenant-scoped read.".into(),
        ),
    }
}

fn graph_failure(error: ContextError) -> ToolResult {
    let state = match error {
        ContextError::EntityNotFound => ToolResultState::Succeeded,
        _ => ToolResultState::Failed,
    };
    ToolResult {
        state,
        summary: match state {
            ToolResultState::Succeeded => "The governed graph did not contain that entity.".into(),
            _ => "The governed graph read failed.".into(),
        },
        data: match state {
            ToolResultState::Succeeded => json!({"result_kind": "not_found"}),
            _ => json!({
                "error_kind": graph_error_kind(&error),
                "retryable": matches!(&error, ContextError::BackendUnavailable(_)),
                "operator_action": match &error {
                    ContextError::BackendUnavailable(_) => {
                        "Retry after the governed graph backend recovers."
                    }
                    _ => "Correct the governed graph read input before retrying.",
                }
            }),
        },
        evidence: vec![],
        blocker: (state == ToolResultState::Failed)
            .then(|| "The governed graph could not complete this bounded read.".into()),
    }
}

fn graph_error_kind(error: &ContextError) -> &'static str {
    match error {
        ContextError::InvalidLimit
        | ContextError::InvalidDepth
        | ContextError::InvalidRootKey
        | ContextError::InvalidRootCount
        | ContextError::InvalidQuery(_) => "invalid_request",
        ContextError::EntityNotFound => "not_found",
        ContextError::BackendUnavailable(_) => "backend_unavailable",
    }
}

fn graph_evidence(
    request: &AgentTurnRequest,
    call: &cerebro_agent_runtime::ToolCall,
    complete: bool,
    statement: String,
) -> Result<EvidenceRecord, AgentRuntimeError> {
    let observed_at = OffsetDateTime::now_utc();
    let fresh_until = observed_at
        .checked_add(TimeDuration::minutes(5))
        .ok_or_else(|| AgentRuntimeError::InvalidToolCall("evidence time overflow".into()))?;
    let identity = format!(
        "{}:{}:{}:{}",
        request.tenant_id,
        request.request_id,
        call.call_id,
        call.input_digest()
    );
    let digest = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(EvidenceRecord {
        evidence_ref: format!("evidence://graph/{digest}"),
        statement,
        observed_at: observed_at
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        fresh_until: Some(
            fresh_until
                .format(&Rfc3339)
                .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        ),
        complete,
        atoms: Vec::new(),
    })
}

fn runtime_evidence(
    request: &AgentTurnRequest,
    call: &cerebro_agent_runtime::ToolCall,
    complete: bool,
    statement: String,
) -> Result<EvidenceRecord, AgentRuntimeError> {
    let observed_at = OffsetDateTime::now_utc();
    let fresh_until = observed_at
        .checked_add(TimeDuration::minutes(1))
        .ok_or_else(|| AgentRuntimeError::InvalidToolCall("evidence time overflow".into()))?;
    let identity = format!(
        "{}:{}:{}:{}",
        request.tenant_id,
        request.request_id,
        call.call_id,
        call.input_digest()
    );
    let digest = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(EvidenceRecord {
        evidence_ref: format!("evidence://source-runtime/{digest}"),
        statement,
        observed_at: observed_at
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        fresh_until: Some(
            fresh_until
                .format(&Rfc3339)
                .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        ),
        complete,
        atoms: Vec::new(),
    })
}

fn catalog_evidence(
    request: &AgentTurnRequest,
    call: &cerebro_agent_runtime::ToolCall,
    complete: bool,
    statement: String,
) -> Result<EvidenceRecord, AgentRuntimeError> {
    let observed_at = OffsetDateTime::now_utc();
    let fresh_until = observed_at
        .checked_add(TimeDuration::minutes(5))
        .ok_or_else(|| AgentRuntimeError::InvalidToolCall("evidence time overflow".into()))?;
    let identity = format!(
        "{}:{}:{}:{}",
        request.tenant_id,
        request.request_id,
        call.call_id,
        call.input_digest()
    );
    let digest = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(EvidenceRecord {
        evidence_ref: format!("evidence://source-catalog/{digest}"),
        statement,
        observed_at: observed_at
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        fresh_until: Some(
            fresh_until
                .format(&Rfc3339)
                .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        ),
        complete,
        atoms: Vec::new(),
    })
}

fn slack_history_evidence(
    request: &AgentTurnRequest,
    call: &cerebro_agent_runtime::ToolCall,
    complete: bool,
    statement: String,
) -> Result<EvidenceRecord, AgentRuntimeError> {
    let observed_at = OffsetDateTime::now_utc();
    let identity = format!(
        "{}:{}:{}:{}:{}:{}",
        request.tenant_id,
        request.actor_ref,
        request
            .context_scope_ref
            .as_deref()
            .unwrap_or("current-thread"),
        request.thread_ref,
        call.call_id,
        call.input_digest(),
    );
    let digest = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(EvidenceRecord {
        evidence_ref: format!("evidence://slack-context/{digest}"),
        statement,
        observed_at: observed_at
            .format(&Rfc3339)
            .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?,
        fresh_until: None,
        complete,
        atoms: Vec::new(),
    })
}

const fn auth_model_name(model: &AuthModel) -> &'static str {
    match model {
        AuthModel::None => "none",
        AuthModel::ApiKey => "api_key",
        AuthModel::BearerToken => "bearer_token",
        AuthModel::Basic => "basic",
        AuthModel::OauthAuthorizationCode => "oauth_authorization_code",
        AuthModel::OauthClientCredentials => "oauth_client_credentials",
        AuthModel::TwoStep => "two_step",
        AuthModel::Jwt => "jwt",
        AuthModel::Signature => "signature",
        AuthModel::AwsSigV4 => "aws_sigv4",
        AuthModel::DuoHmac => "duo_hmac",
        AuthModel::DuoHmacV5 => "duo_hmac_v5",
    }
}

const fn collection_authority_name(authority: CollectionAuthority) -> &'static str {
    match authority {
        CollectionAuthority::Authoritative => "authoritative",
        CollectionAuthority::ShadowOnly => "shadow_only",
    }
}

const fn default_graph_limit() -> usize {
    10
}

const fn default_graph_depth() -> usize {
    1
}

const fn default_runtime_limit() -> usize {
    10
}

const fn default_slack_history_limit() -> usize {
    4
}

const fn default_slack_transcript_limit() -> usize {
    12
}

fn enabled(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true")
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    let value = env::var(name)?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{name} is required").into());
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_agent_runtime::session::{
        AuthorityBindingState, AuthorityDuty, SemanticEvidenceAssertion,
    };
    use cerebro_organizational_store::SourceRuntimeCollectionObservation;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn discovered_tool(
        tool_id: &str,
        title: &str,
        summary: &str,
        authority_class: ToolAuthorityClass,
        effect_class: ToolEffectClass,
    ) -> ToolDescriptor {
        ToolDescriptor {
            tool_id: tool_id.into(),
            title: title.into(),
            summary: summary.into(),
            authority_class,
            effect_class,
            input_schema_ref: format!("schema://{tool_id}/input"),
            result_schema_ref: format!("schema://{tool_id}/result"),
        }
    }

    #[test]
    fn direct_model_catalog_exposes_only_bounded_host_tools() {
        let catalog = model_capability_catalog(&[]);

        assert_eq!(catalog.len(), 12);
        assert!(catalog.iter().all(|tool| !tool.tool_id.starts_with("mcp.")));
        assert!(
            catalog
                .iter()
                .any(|tool| tool.tool_id == "capability.search")
        );
        assert!(
            catalog
                .iter()
                .any(|tool| tool.tool_id == "slack.thread.read")
        );
        assert!(
            catalog
                .iter()
                .any(|tool| tool.tool_id == "slack.history.search")
        );
    }

    #[test]
    fn capability_overview_descriptor_shape_preserves_authority_and_effect() {
        for descriptor in built_in_capability_catalog() {
            let encoded = capability_overview_descriptor_json(&descriptor);
            assert_eq!(encoded["tool_id"], descriptor.tool_id);
            assert_eq!(
                encoded["authority_class"],
                serde_json::to_value(descriptor.authority_class).unwrap()
            );
            assert_eq!(
                encoded["effect_class"],
                serde_json::to_value(descriptor.effect_class).unwrap()
            );
        }
        let proposal = built_in_capability_catalog()
            .into_iter()
            .find(|descriptor| descriptor.tool_id == CAPABILITY_EXECUTE_PROPOSAL)
            .expect("the proposal executor is built in");
        assert_eq!(proposal.authority_class, ToolAuthorityClass::Propose);
        assert_eq!(proposal.effect_class, ToolEffectClass::Read);
    }

    #[test]
    fn model_context_carries_machine_readable_evidence_classes() {
        let descriptor = discovered_tool(
            "mcp.github.pull_request.read",
            "Read a GitHub pull request",
            "Read pull request state and checks.",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        );
        let direct = tagged_context_value(&descriptor, "capability_metadata");
        let discovered = capability_descriptor_json(&descriptor, 42);
        let current = tagged_context_value(
            &json!({"tool_id": "mcp.github.pull_request.read", "state": "succeeded"}),
            "current_observation",
        );

        assert_eq!(direct["context_kind"], "capability_metadata");
        assert_eq!(
            discovered["descriptor"]["context_kind"],
            "capability_metadata"
        );
        assert_eq!(current["context_kind"], "current_observation");
        assert_eq!(current["state"], "succeeded");

        for value in [json!(["one"]), json!("one"), json!(1)] {
            let tagged = tagged_context_value(&value, "current_observation");
            assert_eq!(tagged["context_kind"], "current_observation");
            assert_eq!(tagged["value"], value);
        }
        let collision = tagged_context_value(
            &json!({"context_kind": "untrusted", "state": "succeeded"}),
            "current_observation",
        );
        assert_eq!(collision["context_kind"], "current_observation");
        assert_eq!(collision["value"]["context_kind"], "untrusted");

        struct FailingContext;
        impl Serialize for FailingContext {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("synthetic serialization failure"))
            }
        }
        let unavailable = tagged_context_value(&FailingContext, "retained_memory");
        assert_eq!(unavailable["context_kind"], "retained_memory");
        assert_eq!(unavailable["value_unavailable"], true);
    }

    #[test]
    fn production_subject_resolution_rejects_conflicts_and_unscoped_search_prose() {
        assert!(
            production_input_subject(
                "source_runtime.inspect",
                &json!({"query": "source:alpha", "source_ref": "source:beta"})
            )
            .is_err()
        );
        assert_eq!(
            production_input_subject(
                "source_runtime.inspect",
                &json!({"source_ref": "source:alpha"})
            )
            .unwrap(),
            Some("source:alpha")
        );
        assert_eq!(
            production_input_subject("graph.search", &json!({"query": "open findings"})).unwrap(),
            None
        );
    }

    #[test]
    fn direct_model_catalog_hides_remote_reads_but_keeps_exact_effect_identity() {
        let read = discovered_tool(
            "mcp.slack.thread.read",
            "Read a thread",
            "Read messages.",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        );
        let actuation = discovered_tool(
            "mcp.slack.message.send",
            "Send a message",
            "Send one message.",
            ToolAuthorityClass::Actuate,
            ToolEffectClass::ExternalEffect,
        );

        let catalog = model_capability_catalog(&[read, actuation]);

        assert!(
            !catalog
                .iter()
                .any(|tool| tool.tool_id == "mcp.slack.thread.read")
        );
        assert!(catalog.iter().any(|tool| {
            tool.tool_id == "mcp.slack.message.send"
                && tool.authority_class == ToolAuthorityClass::Actuate
        }));
    }

    #[test]
    fn capability_search_returns_a_stable_typed_catalog_page() {
        let catalog = vec![
            discovered_tool(
                "graph.search",
                "Search governed graph",
                "Find graph entities and relations.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            discovered_tool(
                "mcp.slack.thread.read",
                "Read a Slack thread",
                "Read the exact prior messages in an owned Slack conversation.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            discovered_tool(
                "github.pull_request.read",
                "Read a GitHub pull request",
                "Read pull request state and checks.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
        ];
        let input = CapabilitySearchInput {
            query: "prior Slack thread conversation".into(),
            namespaces: Vec::new(),
            authority_classes: vec![ToolAuthorityClass::Observe],
            effect_classes: vec![ToolEffectClass::Read],
            limit: 8,
            offset: 0,
        };

        let matches = search_capability_catalog(&catalog, &input);

        assert_eq!(
            matches
                .iter()
                .map(|(_, descriptor)| descriptor.tool_id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "github.pull_request.read",
                "graph.search",
                "mcp.slack.thread.read"
            ]
        );
        assert_eq!(
            capability_namespace(matches[2].1.tool_id.as_str()),
            "mcp.slack"
        );
        assert!(capability_namespace_matches(
            matches[2].1.tool_id.as_str(),
            "slack"
        ));
    }

    #[test]
    fn capability_search_does_not_claim_a_lexical_winner() {
        let catalog = vec![
            discovered_tool(
                "mcp.chat.alpha.read",
                "Read message",
                "Read one message.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            discovered_tool(
                "mcp.chat.bravo.read",
                "Read message",
                "Read one message.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
        ];

        let result =
            capability_search_result(&catalog, &json!({"query": "message"}), |_, _| Ok(None))
                .unwrap();

        assert_eq!(result.data["selection_status"], "catalog_page");
        assert_eq!(result.data["top_score_tie_count"], 0);
    }

    #[test]
    fn capability_describe_returns_an_executable_provider_selection() {
        let catalog = vec![discovered_tool(
            "mcp.slack.thread.read",
            "Read a Slack thread",
            "Read one conversation.",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        )];

        let result = capability_describe_result(
            &catalog,
            &json!({"tool_ids": ["mcp.slack.thread.read"]}),
            |descriptor, digest| {
                assert_eq!(descriptor.tool_id, "mcp.slack.thread.read");
                assert!(digest.starts_with("sha256:"));
                Ok(Some((
                    CAPABILITY_EXECUTE_READ.into(),
                    "signed-selection".into(),
                )))
            },
        )
        .unwrap();

        assert_eq!(
            result.data["tools"][0]["execution_tool_id"],
            CAPABILITY_EXECUTE_READ
        );
        assert_eq!(result.data["tools"][0]["selection_ref"], "signed-selection");
    }

    #[test]
    fn capability_search_never_returns_its_own_discovery_plumbing() {
        let mut catalog = built_in_capability_catalog();
        catalog.push(discovered_tool(
            "mcp.github.pull_request.read",
            "Read a GitHub pull request",
            "Read pull request state and checks.",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        ));
        let input = CapabilitySearchInput {
            query: "read tools and pull request state".into(),
            namespaces: Vec::new(),
            authority_classes: Vec::new(),
            effect_classes: Vec::new(),
            limit: 8,
            offset: 0,
        };

        let matches = search_capability_catalog(&catalog, &input);

        assert!(
            matches
                .iter()
                .any(|(_, descriptor)| { descriptor.tool_id == "mcp.github.pull_request.read" })
        );
        assert!(
            matches
                .iter()
                .all(|(_, descriptor)| { capability_search_selectable(&descriptor.tool_id) })
        );
        let built_ins = built_in_capability_catalog();
        for tool_id in [
            "capability.search",
            "capability.describe",
            "capability.overview",
            CAPABILITY_EXECUTE_READ,
            CAPABILITY_EXECUTE_PROPOSAL,
        ] {
            let descriptor = built_ins
                .iter()
                .find(|descriptor| descriptor.tool_id == tool_id)
                .unwrap();
            assert!(
                !capability_search_selectable(&descriptor.tool_id),
                "{tool_id}"
            );
        }
        assert!(built_ins.iter().all(|descriptor| {
            matches!(
                descriptor.tool_id.as_str(),
                "capability.search"
                    | "capability.describe"
                    | "capability.overview"
                    | CAPABILITY_EXECUTE_READ
                    | CAPABILITY_EXECUTE_PROPOSAL
            ) || capability_search_selectable(&descriptor.tool_id)
        }));
    }

    #[test]
    fn capability_search_applies_namespace_and_effect_policy_filters() {
        let catalog = vec![
            discovered_tool(
                "mcp.slack.thread.read",
                "Read a Slack thread",
                "Read Slack conversation history.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            discovered_tool(
                "mcp.slack.message.send",
                "Send a Slack message",
                "Send a Slack message to a channel.",
                ToolAuthorityClass::Actuate,
                ToolEffectClass::ExternalEffect,
            ),
            discovered_tool(
                "github.issue.create",
                "Create a GitHub issue",
                "Create an issue.",
                ToolAuthorityClass::Actuate,
                ToolEffectClass::ExternalEffect,
            ),
        ];
        let input = CapabilitySearchInput {
            query: "Slack message".into(),
            namespaces: vec!["slack".into()],
            authority_classes: vec![ToolAuthorityClass::Actuate],
            effect_classes: vec![ToolEffectClass::ExternalEffect],
            limit: 8,
            offset: 0,
        };

        let matches = search_capability_catalog(&catalog, &input);

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.tool_id, "mcp.slack.message.send");
    }

    #[test]
    fn capability_search_defaults_to_observe_read_and_ignores_schema_keyword_stuffing() {
        let catalog = vec![
            discovered_tool(
                "mcp.slack.thread.read",
                "Read a conversation",
                "Read retained conversation messages. Input JSON Schema: {\"description\":\"deploy change issue create send write\"}",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            discovered_tool(
                "mcp.slack.message.send",
                "Send a message",
                "Send a message to a conversation.",
                ToolAuthorityClass::Actuate,
                ToolEffectClass::ExternalEffect,
            ),
            discovered_tool(
                "mcp.code.change.apply",
                "Apply a deployment change",
                "Apply an external deployment change.",
                ToolAuthorityClass::Actuate,
                ToolEffectClass::ExternalEffect,
            ),
        ];
        let input = CapabilitySearchInput {
            query: "deployment change".into(),
            namespaces: Vec::new(),
            authority_classes: Vec::new(),
            effect_classes: Vec::new(),
            limit: 8,
            offset: 0,
        };

        let matches = search_capability_catalog(&catalog, &input);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].1.tool_id, "mcp.slack.thread.read");
    }

    #[test]
    fn capability_discovery_returns_provider_input_schema_as_json() {
        let descriptor = discovered_tool(
            "mcp.slack.thread.read",
            "Read a Slack thread",
            "Read one conversation. Input JSON Schema: {\"type\":\"object\",\"required\":[\"channel_id\",\"thread_ts\"],\"properties\":{\"channel_id\":{\"type\":\"string\"},\"thread_ts\":{\"type\":\"string\"}},\"additionalProperties\":false}",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        );

        let discovered = capability_descriptor_json(&descriptor, 42);

        assert_eq!(
            discovered["descriptor"]["summary"],
            "Read one conversation."
        );
        assert_eq!(
            discovered["descriptor"]["input_schema"]["required"],
            json!(["channel_id", "thread_ts"])
        );
        assert_eq!(
            discovered["descriptor"]["input_schema"]["additionalProperties"],
            false
        );

        let delimiter_in_description = discovered_tool(
            "mcp.slack.search",
            "Search Slack",
            "Search literal Input JSON Schema: documentation. Input JSON Schema: {\"type\":\"object\",\"properties\":{\"query\":{\"type\":\"string\"}}}",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        );
        assert_eq!(
            capability_descriptor_json(&delimiter_in_description, 1)["descriptor"]["input_schema"]
                ["properties"]["query"]["type"],
            "string"
        );
    }

    #[test]
    fn capability_search_results_do_not_depend_on_query_wording() {
        let catalog = vec![
            discovered_tool(
                "mcp.github.deploy.read",
                "Read repository deploy state",
                "Read one deploy and its check state.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
            discovered_tool(
                "mcp.policy.search",
                "Search policies",
                "Find one policy record.",
                ToolAuthorityClass::Observe,
                ToolEffectClass::Read,
            ),
        ];
        let input = |query: &str| CapabilitySearchInput {
            query: query.into(),
            namespaces: Vec::new(),
            authority_classes: Vec::new(),
            effect_classes: Vec::new(),
            limit: 8,
            offset: 0,
        };

        let expected = vec!["mcp.github.deploy.read", "mcp.policy.search"];
        for query in [
            "deployments",
            "deployed repos",
            "repository checks",
            "police",
        ] {
            let matches = search_capability_catalog(&catalog, &input(query));
            assert_eq!(
                matches
                    .iter()
                    .map(|(_, descriptor)| descriptor.tool_id.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "{query}"
            );
        }
    }

    #[test]
    fn session_context_isolates_the_current_operator_message() {
        let message = |role, message_ref: &str, text: &str| SessionMessage {
            role,
            message_ref: message_ref.into(),
            actor_ref: "actor:context-test".into(),
            text: text.into(),
            received_at: "2026-08-12T20:00:00Z".into(),
        };
        let messages = vec![
            message(SessionMessageRole::User, "message:1", "Check Source A."),
            message(
                SessionMessageRole::Assistant,
                "message:2",
                "I checked the source.",
            ),
            message(
                SessionMessageRole::User,
                "message:3",
                "Use the current receipt instead.",
            ),
        ];

        let (current, historical) =
            split_session_messages(&messages, &SessionTurnTrigger::Operator);
        assert_eq!(
            current.map(|message| message.message_ref.as_str()),
            Some("message:3")
        );
        assert_eq!(
            historical
                .iter()
                .map(|message| message.message_ref.as_str())
                .collect::<Vec<_>>(),
            vec!["message:1", "message:2"]
        );

        let (current, historical) = split_session_messages(
            &messages,
            &SessionTurnTrigger::Wake {
                commitment_ref: "commitment:1".into(),
                occurrence_ref: "occurrence:1".into(),
            },
        );
        assert!(current.is_none());
        assert_eq!(historical.len(), messages.len());

        let oversized = SessionMessage {
            role: SessionMessageRole::User,
            message_ref: "message:oversized".into(),
            actor_ref: "actor:context-test".into(),
            text: "x".repeat(MAX_SESSION_MODEL_CURRENT_MESSAGE_BYTES + 20),
            received_at: "2026-08-12T20:00:00Z".into(),
        };
        let current = current_operator_message_value(&oversized);
        assert!(
            current["text"]
                .as_str()
                .is_some_and(|text| text.len() <= MAX_SESSION_MODEL_CURRENT_MESSAGE_BYTES)
        );
        assert!(!operator_message_missing(
            &SessionTurnTrigger::Operator,
            Some(&current)
        ));
        assert!(operator_message_missing(
            &SessionTurnTrigger::Operator,
            None
        ));
    }

    #[test]
    fn session_history_sent_to_the_model_is_recent_and_bounded() {
        let messages = (0..40)
            .map(|index| SessionMessage {
                role: SessionMessageRole::Assistant,
                message_ref: format!("message:{index}"),
                actor_ref: "actor:context-test".into(),
                text: if index == 39 {
                    "x".repeat(MAX_SESSION_MODEL_HISTORY_ITEM_BYTES + 20)
                } else {
                    format!("Historical message {index}")
                },
                received_at: "2026-08-12T20:00:00Z".into(),
            })
            .collect::<Vec<_>>();
        let references = messages.iter().collect::<Vec<_>>();

        let (bounded, omitted, oldest_included) = bounded_session_history(&references);

        assert_eq!(bounded.len(), MAX_SESSION_MODEL_HISTORY_ITEMS);
        assert_eq!(omitted, 8);
        assert_eq!(oldest_included.as_deref(), Some("message:8"));
        assert_eq!(bounded[0]["message_ref"], "message:8");
        assert_eq!(bounded[0]["context_kind"], "historical_message");
        assert_eq!(bounded[31]["message_ref"], "message:39");
        assert!(
            bounded[31]["text"]
                .as_str()
                .is_some_and(|text| text.len() <= MAX_SESSION_MODEL_HISTORY_ITEM_BYTES)
        );
        assert!(
            serde_json::to_string(&bounded).unwrap().len() <= MAX_SESSION_MODEL_HISTORY_TOTAL_BYTES
        );
    }

    #[test]
    fn session_history_skips_an_oversized_entry_without_dropping_fitting_context() {
        let mut messages = vec![SessionMessage {
            role: SessionMessageRole::User,
            message_ref: "message:small-oldest".into(),
            actor_ref: "actor:context-test".into(),
            text: "Keep this bounded constraint.".into(),
            received_at: "2026-08-12T19:00:00Z".into(),
        }];
        messages.extend((0..12).map(|index| SessionMessage {
            role: SessionMessageRole::Assistant,
            message_ref: format!("message:large-{index}"),
            actor_ref: "actor:context-test".into(),
            text: "x".repeat(MAX_SESSION_MODEL_HISTORY_ITEM_BYTES),
            received_at: "2026-08-12T20:00:00Z".into(),
        }));
        let references = messages.iter().collect::<Vec<_>>();

        let (bounded, omitted, oldest_included) = bounded_session_history(&references);

        assert!(omitted > 0);
        assert!(
            bounded
                .iter()
                .any(|message| message["message_ref"] == "message:small-oldest")
        );
        assert_eq!(oldest_included.as_deref(), Some("message:small-oldest"));
        assert!(
            serde_json::to_string(&bounded).unwrap().len() <= MAX_SESSION_MODEL_HISTORY_TOTAL_BYTES
        );
    }

    #[test]
    fn capability_executor_preserves_the_selected_authority_boundary() {
        let read = discovered_tool(
            "mcp.slack.thread.read",
            "Read a thread",
            "Read retained conversation messages.",
            ToolAuthorityClass::Observe,
            ToolEffectClass::Read,
        );
        let proposal = discovered_tool(
            "mcp.change.propose",
            "Propose a change",
            "Prepare a proposal.",
            ToolAuthorityClass::Propose,
            ToolEffectClass::Read,
        );
        let actuation = discovered_tool(
            "mcp.change.apply",
            "Apply a change",
            "Apply an approved effect.",
            ToolAuthorityClass::Actuate,
            ToolEffectClass::ExternalEffect,
        );

        assert_eq!(
            capability_executor_tool(&read),
            Some(CAPABILITY_EXECUTE_READ)
        );
        assert_eq!(
            capability_executor_tool(&proposal),
            Some(CAPABILITY_EXECUTE_PROPOSAL)
        );
        assert_eq!(capability_executor_tool(&actuation), None);
    }

    #[test]
    fn turn_progress_projects_only_new_model_authored_updates_for_the_request() {
        let request = replay_request();
        let mut session = new_session(&request).unwrap();
        session.events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-08-11T07:00:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: request.request_id.clone(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-08-11T07:00:01Z".into(),
                event: SessionEvent::Progressed {
                    phase: "scoping".into(),
                    status: "I’m narrowing to the current identity-risk slice because it is decision-relevant."
                        .into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 3,
                occurred_at: "2026-08-11T07:00:02Z".into(),
                event: SessionEvent::Progressed {
                    phase: "working".into(),
                    status: "I’m checking current access evidence before expanding the scope."
                        .into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 4,
                occurred_at: "2026-08-11T07:01:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "request:later".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 5,
                occurred_at: "2026-08-11T07:01:01Z".into(),
                event: SessionEvent::Progressed {
                    phase: "scoping".into(),
                    status: "This belongs to another request.".into(),
                },
            },
        ];

        let progress = project_turn_progress(&session, &request.request_id, 2);

        assert_eq!(progress.latest_sequence, 3);
        assert_eq!(progress.updates.len(), 1);
        assert_eq!(
            progress.updates[0].status,
            "I’m checking current access evidence before expanding the scope."
        );
    }

    #[test]
    fn generic_atomization_preserves_validated_semantic_atoms() {
        let evidence_ref = "evidence://semantic/preserved";
        let semantic_atoms = semantic_evidence_atoms(SemanticEvidenceAtomization {
            evidence_ref,
            envelope: SemanticEvidenceEnvelope {
                schema_version: AGENT_SEMANTIC_EVIDENCE_V1.into(),
                assertions: vec![SemanticEvidenceAssertion::AuthorityBinding {
                    subject_ref: "finding:one".into(),
                    duty: AuthorityDuty::Remediation,
                    state: AuthorityBindingState::PresentIdentityNotReturned,
                }],
            },
            observed_at: "2026-08-01T00:00:00Z",
            fresh_until: Some("2026-08-01T00:05:00Z"),
            complete: true,
        })
        .unwrap();
        let mut producer_atoms = semantic_atoms.clone();
        producer_atoms.push(cerebro_agent_runtime::session::EvidenceAtom {
            atom_ref: "producer://unvalidated".into(),
            subject_ref: Some("finding:one".into()),
            assertion: EvidenceAssertion::LegacyStatement {
                statement: "Unvalidated producer atom.".into(),
            },
            observed_at: "2026-08-01T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:05:00Z".into()),
            complete: true,
        });
        let call = cerebro_agent_runtime::ToolCall {
            call_id: "call:semantic".into(),
            tool_id: "finding.read".into(),
            purpose: "Read the finding.".into(),
            input: json!({"subject_ref": "finding:one"}),
        };
        let result = atomize_tool_result(
            &call,
            ToolResult {
                state: ToolResultState::Succeeded,
                summary: "Read the finding.".into(),
                data: json!({"owner_present": true}),
                evidence: vec![EvidenceRecord {
                    evidence_ref: evidence_ref.into(),
                    statement: "The finding was observed.".into(),
                    observed_at: "2026-08-01T00:00:00Z".into(),
                    fresh_until: Some("2026-08-01T00:05:00Z".into()),
                    complete: true,
                    atoms: producer_atoms,
                }],
                blocker: None,
            },
        )
        .unwrap();

        let atoms = &result.evidence[0].atoms;
        assert_eq!(&atoms[..semantic_atoms.len()], semantic_atoms.as_slice());
        assert!(
            atoms
                .iter()
                .any(|atom| atom.atom_ref.ends_with("#tool-outcome"))
        );
        assert!(
            atoms
                .iter()
                .any(|atom| atom.atom_ref.ends_with("#value:/owner_present"))
        );
        assert!(
            !atoms
                .iter()
                .any(|atom| matches!(&atom.assertion, EvidenceAssertion::LegacyStatement { .. }))
        );
    }

    #[test]
    fn retained_slack_context_stays_non_evidentiary_after_atomization() {
        for tool_id in ["slack.thread.read", "slack.history.search"] {
            let call = cerebro_agent_runtime::ToolCall {
                call_id: format!("call:{tool_id}"),
                tool_id: tool_id.into(),
                purpose: "Read retained Slack context.".into(),
                input: json!({}),
            };
            let preexisting_atoms = evidence_atoms_from_json(EvidenceAtomization {
                evidence_ref: "evidence://slack-context/pre-atomized",
                subject_ref: None,
                data: &json!({"messages": []}),
                state: ToolResultState::Succeeded,
                summary: "Pre-atomized retained Slack context.",
                observed_at: "2026-08-01T00:00:00Z",
                fresh_until: Some("2026-08-01T00:05:00Z"),
                complete: true,
            });
            let data = if tool_id == "slack.thread.read" {
                json!({
                    "thread_ref": "thread:synthetic",
                    "messages": [{
                        "actor_ref": "operator:synthetic",
                        "message_ref": "message:synthetic",
                        "received_at": "2026-08-01T00:00:00Z",
                        "role": "user",
                        "text": "Keep the decision reversible."
                    }],
                    "next_cursor": null
                })
            } else {
                json!({
                    "threads": [{
                        "thread_ref": "thread:prior-synthetic",
                        "updated_at": "2026-08-01T00:00:00Z",
                        "context": {
                            "objective": "Reach a synthetic decision.",
                            "desired_outcome": "Keep the synthetic decision reversible.",
                            "open_loops": [{"summary": "Read one fictional source."}],
                            "commitments": [{"summary": "Recheck one fictional boundary."}],
                            "latest_user_message": "Keep the decision reversible.",
                            "latest_assistant_message": null
                        }
                    }],
                    "next_cursor": null
                })
            };
            let result =
                atomize_tool_result(
                    &call,
                    ToolResult {
                        state: ToolResultState::Succeeded,
                        summary: "Read retained Slack context.".into(),
                        data,
                        evidence: vec![EvidenceRecord {
                            evidence_ref: format!("evidence://slack-context/{tool_id}"),
                            statement:
                                "Retained Slack context is not current external-system evidence."
                                    .into(),
                            observed_at: "2026-08-01T00:00:00Z".into(),
                            fresh_until: Some("2026-08-01T00:05:00Z".into()),
                            complete: true,
                            atoms: preexisting_atoms,
                        }],
                        blocker: None,
                    },
                )
                .unwrap();

            assert!(result.evidence[0].fresh_until.is_none(), "{tool_id}");
            let expected_atoms = if tool_id == "slack.history.search" {
                5
            } else {
                1
            };
            assert_eq!(result.evidence[0].atoms.len(), expected_atoms, "{tool_id}");
            assert!(matches!(
                &result.evidence[0].atoms[0].assertion,
                EvidenceAssertion::ConversationEvent { text, .. }
                    if text == "Keep the decision reversible."
            ));
            assert!(result.evidence[0].atoms[0].fresh_until.is_none());
            if tool_id == "slack.history.search" {
                let roles = result.evidence[0]
                    .atoms
                    .iter()
                    .filter_map(|atom| match &atom.assertion {
                        EvidenceAssertion::ConversationEvent { role, .. } => Some(role.as_str()),
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>();
                assert!(roles.contains("objective"));
                assert!(roles.contains("desired_outcome"));
                assert!(roles.contains("open_loop"));
                assert!(roles.contains("commitment"));
            }
        }
    }

    #[test]
    fn new_session_preserves_attributed_history_and_rejects_oversized_imports() {
        let request = AgentTurnRequest {
            schema_version: "agent-turn-request/v1".into(),
            tenant_id: "tenant:history-import".into(),
            request_id: "request:history-import".into(),
            thread_ref: "thread:history-import".into(),
            context_scope_ref: None,
            actor_ref: "actor:current".into(),
            assessment_at: "2026-08-02T18:00:00Z".into(),
            message: "Continue from the earlier distinction.".into(),
            history: vec![cerebro_agent_runtime::ConversationMessage {
                role: cerebro_agent_runtime::ConversationRole::User,
                content: "The earlier distinction matters.".into(),
            }],
            history_metadata: vec![cerebro_agent_runtime::ConversationMessageMetadata {
                actor_ref: Some("slack-actor://sha256/actor".into()),
                message_ref: Some("slack-message://sha256/message".into()),
                received_at: Some("2026-08-02T17:59:00Z".into()),
            }],
            working_state: None,
            effect_authorizations: Vec::new(),
            capabilities: Vec::new(),
            followup_acceptance: None,
        };

        let session = new_session(&request).unwrap();
        assert_eq!(session.messages.len(), 1);
        assert_eq!(session.messages[0].actor_ref, "slack-actor://sha256/actor");
        assert_eq!(
            session.messages[0].message_ref,
            "slack-message://sha256/message"
        );
        assert_eq!(session.messages[0].received_at, "2026-08-02T17:59:00Z");

        let mut reserved = request.clone();
        reserved.history_metadata[0].message_ref =
            Some(format!("operator:{}", reserved.request_id));
        assert!(matches!(
            new_session(&reserved),
            Err(AgentRuntimeError::HistoryInvalid)
        ));

        let mut oversized = request;
        oversized.history[0].content = "x".repeat(16 * 1024 + 1);
        assert!(matches!(
            new_session(&oversized),
            Err(AgentRuntimeError::HistoryInvalid)
        ));
    }

    fn replay_request() -> AgentTurnRequest {
        AgentTurnRequest {
            schema_version: "agent-turn-request/v1".into(),
            tenant_id: "tenant:request-replay".into(),
            request_id: "request:replay-after-compaction".into(),
            thread_ref: "thread:request-replay".into(),
            context_scope_ref: None,
            actor_ref: "actor:request-replay".into(),
            assessment_at: "2026-08-02T18:00:00Z".into(),
            message: "Explain the durable replay boundary.".into(),
            history: Vec::new(),
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: Vec::new(),
            capabilities: Vec::new(),
            followup_acceptance: None,
        }
    }

    fn initial_session_model_turn(message: &str) -> SessionModelTurn {
        let mut request = replay_request();
        request.message = message.into();
        let mut session = new_session(&request).unwrap();
        session.messages.push(SessionMessage {
            role: SessionMessageRole::User,
            message_ref: format!("operator:{}", request.request_id),
            actor_ref: request.actor_ref.clone(),
            text: request.message.clone(),
            received_at: request.assessment_at.clone(),
        });
        SessionModelTurn {
            session,
            trigger: SessionTurnTrigger::Operator,
            assessment_at: request.assessment_at,
            requested_lane: None,
            prior_commitment_checkpoint: None,
            wake_assessment: None,
            plan: None,
            available_tools: Vec::new(),
            observations: Vec::new(),
            repair_feedback: Vec::new(),
        }
    }

    fn replay_draft(session: &AgentSession) -> cerebro_agent_runtime::session::GroundedDraft {
        cerebro_agent_runtime::session::GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: "The durable event retains the original request identity.".into(),
            claims: Vec::new(),
            coverage_notice: None,
            question: None,
            mission: session.mission.clone(),
            memory_updates: Vec::new(),
            presentation_ready: true,
        }
    }

    fn replay_events(
        session: &AgentSession,
        request: &AgentTurnRequest,
        completed: bool,
    ) -> Vec<SessionEventRecord> {
        let mut events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 1,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::UserMessageQueued {
                    message: SessionMessage {
                        role: SessionMessageRole::User,
                        message_ref: format!("operator:{}", request.request_id),
                        actor_ref: request.actor_ref.clone(),
                        text: request.message.clone(),
                        received_at: request.assessment_at.clone(),
                    },
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 2,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::RouteAccepted {
                    request_id: request.request_id.clone(),
                    lane: ExecutionLane::Investigate,
                    future_observation: cerebro_agent_runtime::FutureObservationDisposition::None,
                    future_observation_excerpt: None,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 3,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::TurnStarted {
                    request_id: request.request_id.clone(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 4,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::DraftProduced {
                    request_id: request.request_id.clone(),
                    draft: replay_draft(session),
                },
            },
        ];
        if completed {
            events.push(SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 5,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::TurnCompleted {
                    request_id: request.request_id.clone(),
                    state: FinalState::Answered,
                },
            });
        }
        events
    }

    fn unrouted_replay_events(
        session: &AgentSession,
        request: &AgentTurnRequest,
        completed: bool,
    ) -> Vec<SessionEventRecord> {
        let mut events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 1,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::UserMessageQueued {
                    message: SessionMessage {
                        role: SessionMessageRole::User,
                        message_ref: format!("operator:{}", request.request_id),
                        actor_ref: request.actor_ref.clone(),
                        text: request.message.clone(),
                        received_at: request.assessment_at.clone(),
                    },
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 2,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::TurnStarted {
                    request_id: request.request_id.clone(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 3,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::ResearchLaneAccepted {
                    request_id: request.request_id.clone(),
                    lane: ExecutionLane::Investigate,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 4,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::DraftProduced {
                    request_id: request.request_id.clone(),
                    draft: replay_draft(session),
                },
            },
        ];
        if completed {
            events.push(SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 5,
                occurred_at: request.assessment_at.clone(),
                event: SessionEvent::TurnCompleted {
                    request_id: request.request_id.clone(),
                    state: FinalState::Answered,
                },
            });
        }
        events
    }

    #[test]
    fn completed_request_replays_from_immutable_events_after_message_compaction() {
        let request = replay_request();
        let base = new_session(&request).unwrap();
        let mut session =
            apply_session_events(&base, &unrouted_replay_events(&base, &request, true)).unwrap();
        session.messages.clear();

        assert!(matches!(
            replay_completed_session_turn(&session, &request).unwrap(),
            Some(AgentTurnOutcome::Delivered {
                lane: ExecutionLane::Investigate,
                ..
            })
        ));

        let mut changed = request;
        changed.message.push_str(" Changed.");
        assert!(matches!(
            replay_completed_session_turn(&session, &changed),
            Err(AgentRuntimeError::InvalidRequest(_))
        ));
    }

    #[test]
    fn pending_request_replays_from_immutable_events_after_message_compaction() {
        let request = replay_request();
        let base = new_session(&request).unwrap();
        let mut session =
            apply_session_events(&base, &unrouted_replay_events(&base, &request, false)).unwrap();
        session.messages.clear();

        assert!(matches!(
            replay_pending_session_turn(&session, &request).unwrap(),
            AgentTurnOutcome::PendingDelivery {
                lane: ExecutionLane::Investigate,
                ..
            }
        ));

        let mut changed = request;
        changed.actor_ref.push_str(":changed");
        assert!(matches!(
            replay_pending_session_turn(&session, &changed),
            Err(AgentRuntimeError::InvalidRequest(_))
        ));
    }

    #[test]
    fn routing_context_comes_from_the_last_delivered_session_not_the_caller() {
        let prior = replay_request();
        let base = new_session(&prior).unwrap();
        let mut session =
            apply_session_events(&base, &unrouted_replay_events(&base, &prior, false)).unwrap();
        session = apply_session_events(
            &session,
            &[
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 5,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::DeliveryRecorded {
                        request_id: prior.request_id.clone(),
                        transport: "slack".into(),
                        delivery_ref: "slack-message:prior".into(),
                        payload_digest: message_digest(&replay_draft(&base).message),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 6,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::TurnCompleted {
                        request_id: prior.request_id.clone(),
                        state: FinalState::Answered,
                    },
                },
            ],
        )
        .unwrap();

        let mut next = prior.clone();
        next.request_id = "request:next".into();
        next.message = "Keep going.".into();
        next.history = vec![cerebro_agent_runtime::ConversationMessage {
            role: cerebro_agent_runtime::ConversationRole::User,
            content: "caller supplied fiction".into(),
        }];
        next.history_metadata = vec![cerebro_agent_runtime::ConversationMessageMetadata {
            actor_ref: Some("caller".into()),
            message_ref: Some("caller:message".into()),
            received_at: Some(next.assessment_at.clone()),
        }];
        next.working_state = Some(cerebro_agent_runtime::WorkingState {
            mission_ref: Some("caller:mission".into()),
            current_request: "caller supplied fiction".into(),
            last_outcome: cerebro_agent_runtime::WorkingOutcome::NeedsUser,
            last_blocker: Some("caller blocker".into()),
            active_lane: Some(ExecutionLane::Converse),
            requires_current_evidence: Some(false),
            open_loops: vec!["caller loop".into()],
        });

        let routed = route_request_from_session(&session, &next);
        assert!(routed.history_metadata.is_empty());
        assert_eq!(routed.history.len(), 2);
        assert!(
            routed
                .history
                .iter()
                .all(|message| message.content != "caller supplied fiction")
        );
        let working = routed
            .working_state
            .expect("a delivered durable turn should create continuation state");
        assert_eq!(
            working.mission_ref.as_deref(),
            Some(session.mission.mission_ref.as_str())
        );
        assert_eq!(
            working.last_outcome,
            cerebro_agent_runtime::WorkingOutcome::Completed
        );
        assert_eq!(working.active_lane, Some(ExecutionLane::Investigate));
        assert_eq!(working.requires_current_evidence, Some(true));
        assert!(!working.open_loops.iter().any(|item| item == "caller loop"));
    }

    #[test]
    fn delivered_mission_revision_uses_the_research_lane_without_a_legacy_route() {
        let request = replay_request();
        let base = new_session(&request).unwrap();
        let mut events = unrouted_replay_events(&base, &request, false);
        let revised_mission = events
            .iter_mut()
            .find_map(|event| match &mut event.event {
                SessionEvent::DraftProduced { draft, .. } => {
                    draft.mission.objective = "Finish the durable investigation.".into();
                    draft
                        .mission
                        .open_loops
                        .push(cerebro_agent_runtime::session::OpenLoop {
                            open_loop_ref: "open-loop:research-lane".into(),
                            summary: "Finish the durable investigation.".into(),
                            owner: cerebro_agent_runtime::session::WorkOwner::Cerebro,
                            next_action: Some("Read the remaining current evidence.".into()),
                            blocked_by: None,
                        });
                    Some(draft.mission.clone())
                }
                _ => None,
            })
            .expect("the replay fixture should contain a draft");
        let draft_message = events
            .iter()
            .find_map(|event| match &event.event {
                SessionEvent::DraftProduced { draft, .. } => Some(draft.message.clone()),
                _ => None,
            })
            .expect("the replay fixture should contain a draft message");
        let mut session = apply_session_events(&base, &events).unwrap();
        session = apply_session_events(
            &session,
            &[
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 5,
                    occurred_at: request.assessment_at.clone(),
                    event: SessionEvent::DeliveryRecorded {
                        request_id: request.request_id.clone(),
                        transport: "slack".into(),
                        delivery_ref: "slack-message:research-lane".into(),
                        payload_digest: message_digest(&draft_message),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 6,
                    occurred_at: request.assessment_at.clone(),
                    event: SessionEvent::TurnCompleted {
                        request_id: request.request_id.clone(),
                        state: FinalState::Answered,
                    },
                },
            ],
        )
        .unwrap();

        assert_eq!(session.mission, revised_mission);
        assert_eq!(
            delivered_mission_revision_lane(&session),
            Some(ExecutionLane::Investigate)
        );
    }

    #[test]
    fn side_conversation_does_not_replace_an_unresolved_operating_lane() {
        let prior = replay_request();
        let mut base = new_session(&prior).unwrap();
        base.mission
            .open_loops
            .push(cerebro_agent_runtime::session::OpenLoop {
                open_loop_ref: "open-loop:investigation".into(),
                summary: "Finish the durable investigation.".into(),
                owner: cerebro_agent_runtime::session::WorkOwner::Cerebro,
                next_action: Some("Inspect the remaining evidence.".into()),
                blocked_by: None,
            });
        let mut session =
            apply_session_events(&base, &replay_events(&base, &prior, false)).unwrap();
        let first_draft = replay_draft(&session);
        session = apply_session_events(
            &session,
            &[
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 5,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::DeliveryRecorded {
                        request_id: prior.request_id.clone(),
                        transport: "slack".into(),
                        delivery_ref: "slack-message:prior".into(),
                        payload_digest: message_digest(&first_draft.message),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 6,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::TurnCompleted {
                        request_id: prior.request_id.clone(),
                        state: FinalState::Answered,
                    },
                },
            ],
        )
        .unwrap();

        let side_request_id = "request:side-conversation";
        let side_message = "Do you have a favorite map?";
        let side_draft = cerebro_agent_runtime::session::GroundedDraft {
            message: "I like maps that make the next decision clearer.".into(),
            mission: session.mission.clone(),
            ..replay_draft(&session)
        };
        session = apply_session_events(
            &session,
            &[
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 7,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::UserMessageQueued {
                        message: SessionMessage {
                            role: SessionMessageRole::User,
                            message_ref: format!("operator:{side_request_id}"),
                            actor_ref: prior.actor_ref.clone(),
                            text: side_message.into(),
                            received_at: prior.assessment_at.clone(),
                        },
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 8,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::RouteAccepted {
                        request_id: side_request_id.into(),
                        lane: ExecutionLane::Converse,
                        future_observation:
                            cerebro_agent_runtime::FutureObservationDisposition::None,
                        future_observation_excerpt: None,
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 9,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::TurnStarted {
                        request_id: side_request_id.into(),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 10,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::DraftProduced {
                        request_id: side_request_id.into(),
                        draft: side_draft.clone(),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 11,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::DeliveryRecorded {
                        request_id: side_request_id.into(),
                        transport: "slack".into(),
                        delivery_ref: "slack-message:side".into(),
                        payload_digest: message_digest(&side_draft.message),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: session.session_ref.clone(),
                    sequence: 12,
                    occurred_at: prior.assessment_at.clone(),
                    event: SessionEvent::TurnCompleted {
                        request_id: side_request_id.into(),
                        state: FinalState::Answered,
                    },
                },
            ],
        )
        .unwrap();

        let mut continuation = prior;
        continuation.request_id = "request:continue-after-side-conversation".into();
        continuation.message = "Keep going.".into();
        let routed = route_request_from_session(&session, &continuation);
        assert_eq!(
            routed
                .working_state
                .expect("delivered turns should create continuation state")
                .active_lane,
            Some(ExecutionLane::Investigate)
        );
    }

    #[test]
    fn a_new_conversational_mission_does_not_resurrect_an_old_operating_lane() {
        let prior = replay_request();
        let mut session = new_session(&prior).unwrap();
        let old_mission = session.mission.clone();
        let mut conversational_mission = old_mission.clone();
        conversational_mission.mission_ref = "mission:concise-handoff".into();
        conversational_mission.objective = "Create a concise handoff.".into();
        conversational_mission
            .open_loops
            .push(cerebro_agent_runtime::session::OpenLoop {
                open_loop_ref: "open-loop:concise-handoff".into(),
                summary: "Finish the concise handoff.".into(),
                owner: cerebro_agent_runtime::session::WorkOwner::Cerebro,
                next_action: Some("Draft the handoff.".into()),
                blocked_by: None,
            });
        let old_draft = cerebro_agent_runtime::session::GroundedDraft {
            mission: old_mission,
            ..replay_draft(&session)
        };
        let conversational_draft = cerebro_agent_runtime::session::GroundedDraft {
            message: "I can make that handoff concise.".into(),
            mission: conversational_mission.clone(),
            ..replay_draft(&session)
        };
        let record = |sequence, event| SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: session.session_ref.clone(),
            sequence,
            occurred_at: prior.assessment_at.clone(),
            event,
        };
        session.events = vec![
            record(
                1,
                SessionEvent::RouteAccepted {
                    request_id: "request:old-act".into(),
                    lane: ExecutionLane::Act,
                    future_observation: cerebro_agent_runtime::FutureObservationDisposition::None,
                    future_observation_excerpt: None,
                },
            ),
            record(
                2,
                SessionEvent::DraftProduced {
                    request_id: "request:old-act".into(),
                    draft: old_draft,
                },
            ),
            record(
                3,
                SessionEvent::DeliveryRecorded {
                    request_id: "request:old-act".into(),
                    transport: "slack".into(),
                    delivery_ref: "slack-message:old-act".into(),
                    payload_digest: format!("sha256:{}", "a".repeat(64)),
                },
            ),
            record(
                4,
                SessionEvent::TurnCompleted {
                    request_id: "request:old-act".into(),
                    state: FinalState::Answered,
                },
            ),
            record(
                5,
                SessionEvent::RouteAccepted {
                    request_id: "request:new-conversation".into(),
                    lane: ExecutionLane::Converse,
                    future_observation: cerebro_agent_runtime::FutureObservationDisposition::None,
                    future_observation_excerpt: None,
                },
            ),
            record(
                6,
                SessionEvent::DraftProduced {
                    request_id: "request:new-conversation".into(),
                    draft: conversational_draft,
                },
            ),
            record(
                7,
                SessionEvent::DeliveryRecorded {
                    request_id: "request:new-conversation".into(),
                    transport: "slack".into(),
                    delivery_ref: "slack-message:new-conversation".into(),
                    payload_digest: format!("sha256:{}", "b".repeat(64)),
                },
            ),
            record(
                8,
                SessionEvent::TurnCompleted {
                    request_id: "request:new-conversation".into(),
                    state: FinalState::Answered,
                },
            ),
        ];
        session.mission = conversational_mission;

        assert_eq!(
            delivered_mission_revision_lane(&session),
            Some(ExecutionLane::Converse)
        );
        let mut continuation = prior;
        continuation.request_id = "request:continue-conversation".into();
        continuation.message = "Keep going.".into();
        assert_eq!(
            route_request_from_session(&session, &continuation)
                .working_state
                .expect("the conversational mission is delivered")
                .active_lane,
            Some(ExecutionLane::Converse)
        );
    }

    #[test]
    fn exact_delivery_receipt_replays_but_a_changed_receipt_conflicts() {
        let request = AgentTurnRequest {
            schema_version: "agent-turn-request/v1".into(),
            tenant_id: "tenant:delivery-replay".into(),
            request_id: "request:delivery-replay".into(),
            thread_ref: "thread:delivery-replay".into(),
            context_scope_ref: None,
            actor_ref: "actor:delivery-replay".into(),
            assessment_at: "2026-07-31T20:00:00Z".into(),
            message: "Test delivery replay.".into(),
            history: Vec::new(),
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: Vec::new(),
            capabilities: Vec::new(),
            followup_acceptance: None,
        };
        let mut session = new_session(&request).unwrap();
        let receipt = AgentDeliveryReceipt {
            schema_version: AGENT_DELIVERY_RECEIPT_V1.into(),
            tenant_id: request.tenant_id,
            thread_ref: request.thread_ref,
            request_id: request.request_id,
            transport: "slack".into(),
            delivery_ref: "slack-message:delivery-replay".into(),
            payload_digest: format!("sha256:{}", "a".repeat(64)),
            delivered_at: "2026-07-31T20:01:00Z".into(),
        };
        session.events.push(SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: session.session_ref.clone(),
            sequence: 1,
            occurred_at: receipt.delivered_at.clone(),
            event: SessionEvent::DeliveryRecorded {
                request_id: receipt.request_id.clone(),
                transport: receipt.transport.clone(),
                delivery_ref: receipt.delivery_ref.clone(),
                payload_digest: receipt.payload_digest.clone(),
            },
        });

        assert!(delivery_replay_matches(&session, &receipt).unwrap());
        let mut changed = receipt;
        changed.delivery_ref.push_str(":changed");
        assert!(delivery_replay_matches(&session, &changed).is_err());
    }

    #[tokio::test]
    async fn startup_recovers_from_transient_dependency_timeouts() {
        let attempts = AtomicUsize::new(0);
        let result = retry_startup(
            STARTUP_HEALTH_ATTEMPTS,
            StdDuration::ZERO,
            StdDuration::ZERO,
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                async move {
                    if attempt < STARTUP_HEALTH_ATTEMPTS {
                        Err(ContextError::BackendUnavailable(format!(
                            "transient failure {attempt}"
                        )))
                    } else {
                        Ok("ready")
                    }
                }
            },
        )
        .await;

        assert_eq!(result.unwrap(), "ready");
        assert_eq!(attempts.load(Ordering::Relaxed), STARTUP_HEALTH_ATTEMPTS);
    }

    #[tokio::test]
    async fn startup_stops_after_the_bounded_retry_budget() {
        let attempts = AtomicUsize::new(0);
        let result: Result<(), ContextError> = retry_startup(
            STARTUP_HEALTH_ATTEMPTS,
            StdDuration::ZERO,
            StdDuration::ZERO,
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                async move {
                    Err(ContextError::BackendUnavailable(format!(
                        "persistent failure {attempt}"
                    )))
                }
            },
        )
        .await;

        assert_eq!(
            result,
            Err(ContextError::BackendUnavailable(
                "persistent failure 12".to_owned()
            ))
        );
        assert_eq!(attempts.load(Ordering::Relaxed), STARTUP_HEALTH_ATTEMPTS);
    }

    #[tokio::test]
    async fn non_graph_startup_dependencies_keep_their_retry_budget() {
        let attempts = AtomicUsize::new(0);
        let result: Result<(), ContextError> = retry_startup(
            STARTUP_DEPENDENCY_ATTEMPTS,
            StdDuration::ZERO,
            StdDuration::ZERO,
            || {
                let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                async move {
                    Err(ContextError::BackendUnavailable(format!(
                        "dependency failure {attempt}"
                    )))
                }
            },
        )
        .await;

        assert_eq!(
            result,
            Err(ContextError::BackendUnavailable(
                "dependency failure 5".to_owned()
            ))
        );
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            STARTUP_DEPENDENCY_ATTEMPTS
        );
    }

    #[tokio::test]
    async fn mcp_startup_recovers_within_the_dependency_retry_budget() {
        let attempts = AtomicUsize::new(0);
        let result = retry_mcp_startup(|| {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
            async move {
                if attempt < STARTUP_DEPENDENCY_ATTEMPTS {
                    Err(ContextError::BackendUnavailable(format!(
                        "transient MCP failure {attempt}"
                    )))
                } else {
                    Ok("catalog ready")
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), "catalog ready");
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            STARTUP_DEPENDENCY_ATTEMPTS
        );
    }

    #[tokio::test]
    async fn mcp_startup_fails_closed_after_the_dependency_retry_budget() {
        let attempts = AtomicUsize::new(0);
        let result: Result<(), ContextError> = retry_mcp_startup(|| {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
            async move {
                Err(ContextError::BackendUnavailable(format!(
                    "persistent MCP failure {attempt}"
                )))
            }
        })
        .await;

        assert_eq!(
            result,
            Err(ContextError::BackendUnavailable(
                "persistent MCP failure 5".to_owned()
            ))
        );
        assert_eq!(
            attempts.load(Ordering::Relaxed),
            STARTUP_DEPENDENCY_ATTEMPTS
        );
    }

    #[tokio::test]
    async fn session_model_retry_repeats_only_one_unavailable_adapter_call() {
        let attempts = AtomicUsize::new(0);
        let value = retry_session_model_call(|| {
            let attempt = attempts.fetch_add(1, Ordering::Relaxed) + 1;
            async move {
                if attempt == 1 {
                    Err(AgentRuntimeError::ModelUnavailable(
                        "transient adapter failure".into(),
                    ))
                } else {
                    Ok(json!({"decision": "finish_research", "calls": []}))
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(value["decision"], "finish_research");
        assert_eq!(attempts.load(Ordering::Relaxed), SESSION_MODEL_ATTEMPTS);

        let attempts = AtomicUsize::new(0);
        let error = retry_session_model_call(|| {
            attempts.fetch_add(1, Ordering::Relaxed);
            async {
                Err::<Value, _>(AgentRuntimeError::ModelUnavailable(
                    "persistent adapter failure".into(),
                ))
            }
        })
        .await
        .unwrap_err();
        assert!(matches!(error, AgentRuntimeError::ModelUnavailable(_)));
        assert_eq!(attempts.load(Ordering::Relaxed), SESSION_MODEL_ATTEMPTS);

        let attempts = AtomicUsize::new(0);
        let error = retry_session_model_call(|| {
            attempts.fetch_add(1, Ordering::Relaxed);
            async { Err::<Value, _>(AgentRuntimeError::InvalidFinal("schema mismatch".into())) }
        })
        .await
        .unwrap_err();
        assert!(matches!(error, AgentRuntimeError::InvalidFinal(_)));
        assert_eq!(attempts.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn startup_backoff_is_exponential_and_capped() {
        let mut delay = STARTUP_INITIAL_RETRY_DELAY;
        let delays = (1..STARTUP_HEALTH_ATTEMPTS)
            .map(|_| {
                let current = delay;
                delay = next_startup_retry_delay(delay, STARTUP_MAX_RETRY_DELAY);
                current
            })
            .collect::<Vec<_>>();

        assert_eq!(
            delays,
            vec![
                StdDuration::from_millis(500),
                StdDuration::from_secs(1),
                StdDuration::from_secs(2),
                StdDuration::from_secs(4),
                StdDuration::from_secs(5),
                StdDuration::from_secs(5),
                StdDuration::from_secs(5),
                StdDuration::from_secs(5),
                StdDuration::from_secs(5),
                StdDuration::from_secs(5),
                StdDuration::from_secs(5),
            ]
        );
    }

    #[test]
    fn model_attestation_binds_public_behavior_config_without_secrets() {
        let digest = model_config_sha256("amazon-bedrock", "global.anthropic.claude-opus-4-1-v1:0");

        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
        assert_eq!(
            digest,
            model_config_sha256("amazon-bedrock", "global.anthropic.claude-opus-4-1-v1:0")
        );
        assert_ne!(
            digest,
            model_config_sha256("amazon-bedrock", "global.anthropic.claude-opus-4-5-v1:0")
        );
        assert_ne!(
            digest,
            model_config_sha256("another-provider", "global.anthropic.claude-opus-4-1-v1:0")
        );
    }

    #[test]
    fn live_model_contract_is_compact_and_rust_keeps_structural_authority() {
        assert_eq!(SLACK_ROUTE_MAX_TOKENS, 768);
        assert_eq!(SLACK_SESSION_DECISION_MAX_TOKENS, 4_096);
        let complete_schema = session_decision_schema();
        let decision_schema = complete_schema.to_string();
        for explanation_id in ALL_STABLE_EXPLANATION_IDS {
            assert!(decision_schema.contains(explanation_id));
        }
        assert!(decision_schema.contains("conversational_synthesis"));
        assert!(decision_schema.contains("source_message_sequences"));
        assert!(!decision_schema.contains("coverage_boundary"));

        let initial_contracts = agent_loop_contracts(true);
        let continue_contracts = agent_loop_contracts(false);
        assert_eq!(
            initial_contracts
                .iter()
                .map(|contract| contract.name)
                .collect::<Vec<_>>(),
            vec![SESSION_START_TOOL, SESSION_FINISH_TOOL]
        );
        assert_eq!(
            continue_contracts
                .iter()
                .map(|contract| contract.name)
                .collect::<Vec<_>>(),
            vec![SESSION_CONTINUE_TOOL, SESSION_FINISH_TOOL]
        );
        let initial_read = &initial_contracts[0].schema;
        let initial_finish = &initial_contracts[1].schema;
        let continue_read = &continue_contracts[0].schema;
        let continue_finish = &continue_contracts[1].schema;
        let property_names = |schema: &Value| {
            let mut names = schema["properties"]
                .as_object()
                .expect("the stage contract has object properties")
                .keys()
                .cloned()
                .collect::<Vec<_>>();
            names.sort();
            names
        };
        assert_eq!(property_names(initial_read), vec!["calls", "lane", "plan"]);
        assert_eq!(initial_read["properties"]["calls"]["minItems"], 1);
        assert_eq!(property_names(initial_finish), vec!["draft", "lane"]);
        assert!(
            initial_finish["properties"]["draft"]["properties"]
                .get("message")
                .is_none()
        );
        assert!(
            initial_finish["properties"]["draft"]["properties"]
                .get("presentation_ready")
                .is_none()
        );
        assert_eq!(property_names(continue_read), vec!["calls"]);
        assert_eq!(property_names(continue_finish), vec!["draft"]);
        assert!(continue_read.to_string().len() < decision_schema.len());
        assert!(
            !built_in_capability_catalog()
                .iter()
                .any(|tool| tool.tool_id.contains("graph.reason"))
        );
    }

    #[test]
    fn claim_review_recovers_a_schema_object_encoded_as_text() {
        let review = parse_message_review_value(json!({
            "draft_digest": format!("sha256:{}", "0".repeat(64)),
            "message_digest": format!("sha256:{}", "0".repeat(64)),
            "claim_reviews": [],
            "undeclared_material": [],
            "attention": "{\"delivery\":\"silent\",\"reason\":\"Routine nonterminal progress.\"}}",
            "behavioral": {
                "answers_newest_request": true,
                "conversational": true,
                "owns_follow_through": true,
                "right_sized": true,
                "evidence_boundary_correct": true
            }
        }))
        .unwrap();

        assert_eq!(review.attention.delivery, DeliveryDisposition::Silent);
        assert_eq!(review.attention.reason, "Routine nonterminal progress.");
    }

    #[test]
    fn session_presentation_rewrites_only_visible_claim_copy() {
        let research_draft: GroundedDraft = serde_json::from_value(json!({
            "state": "answered",
            "delivery": "visible",
            "message": "The current read is complete.",
            "claims": [{
                "claim_ref": "claim:one",
                "planned_claim_ref": "planned:one",
                "text": "The current read is complete.",
                "required_for_answer": true,
                "content": {"basis": "observation", "atom_refs": ["atom:one"]}
            }],
            "coverage_notice": null,
            "question": null,
            "mission": {
                "mission_ref": "mission:one",
                "objective": "Answer the bounded question.",
                "desired_outcome": "The operator has the supported answer.",
                "resolved_scope": ["source:one"],
                "scope_assumptions": [],
                "acceptance_criteria": ["Current read returned."],
                "commitments": [],
                "open_loops": [],
                "status": "completed"
            },
            "memory_updates": [],
            "presentation_ready": true
        }))
        .unwrap();

        let presented = apply_session_presentation_value(
            &research_draft,
            json!({
                "claim_texts": ["The current read is complete, so the bounded check passed."]
            }),
            &sha256_digest(&session_presentation_schema(1).to_string()),
        )
        .unwrap();

        assert!(presented.claims[0].required_for_answer);
        assert_eq!(
            presented.claims[0].content,
            research_draft.claims[0].content
        );
        assert_eq!(presented.mission, research_draft.mission);
        assert_eq!(presented.memory_updates, research_draft.memory_updates);
        assert_eq!(
            presented.message,
            "The current read is complete, so the bounded check passed."
        );
        assert!(
            apply_session_presentation_value(
                &research_draft,
                json!({"claim_texts": ["First.", "Invented."]}),
                &sha256_digest(&session_presentation_schema(1).to_string()),
            )
            .is_err()
        );
    }

    #[test]
    fn positional_review_injects_exact_rust_owned_bindings() {
        let request = replay_request();
        let session = new_session(&request).unwrap();
        let mut draft = replay_draft(&session);
        draft.claims = vec![cerebro_agent_runtime::session::GroundedClaim {
            claim_ref: "claim:one".into(),
            planned_claim_ref: None,
            text: "The durable event retains the request identity.".into(),
            required_for_answer: true,
            content: cerebro_agent_runtime::session::ClaimContent::StableExplanation {
                explanation_id:
                    cerebro_agent_runtime::session::StableExplanationId::EvidenceAuthorityBoundary,
            },
        }];
        draft.message = draft.claims[0].text.clone();
        let turn = ClaimReviewTurn {
            session,
            trigger: SessionTurnTrigger::Operator,
            prior_commitment_checkpoint: None,
            wake_assessment: None,
            draft: draft.clone(),
            observations: Vec::new(),
        };
        let schema = claim_review_schema(1);
        let review = apply_claim_review_value(
            &turn,
            json!({
                "claim_reviews": [{"verdict": "supported", "issue": null}],
                "undeclared_material": [],
                "attention": {"reason": "Deliver the direct answer."},
                "behavioral": {
                    "answers_newest_request": true,
                    "conversational": true,
                    "owns_follow_through": true,
                    "right_sized": true,
                    "evidence_boundary_correct": true
                }
            }),
            &sha256_digest(&schema.to_string()),
        )
        .unwrap();

        assert_eq!(review.draft_digest, grounded_draft_digest(&draft));
        assert_eq!(review.message_digest, message_digest(&draft.message));
        assert_eq!(review.claim_reviews[0].claim_ref, "claim:one");
        assert_eq!(review.attention.delivery, draft.delivery);
        assert!(matches!(
            apply_claim_review_value(
                &turn,
                json!({
                    "claim_reviews": [],
                    "undeclared_material": [],
                    "attention": {"reason": "Deliver."},
                    "behavioral": {
                        "answers_newest_request": true,
                        "conversational": true,
                        "owns_follow_through": true,
                        "right_sized": true,
                        "evidence_boundary_correct": true
                    }
                }),
                &sha256_digest(&schema.to_string()),
            ),
            Err(AgentRuntimeError::ModelStageRejected(
                SessionModelRejection {
                    class: SessionModelRejectionClass::ReviewBinding,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn session_research_hands_completed_evidence_to_the_presenter() {
        let research_draft = json!({
            "state": "answered",
            "delivery": "visible",
            "message": "The current read is complete.",
            "claims": [{
                "claim_ref": "claim:one",
                "planned_claim_ref": null,
                "text": "The current read is complete.",
                "required_for_answer": true,
                "content": {"basis": "stable_explanation", "explanation_id": "evidence_authority_boundary"}
            }],
            "coverage_notice": null,
            "question": null,
            "mission": {
                "mission_ref": "mission:one",
                "objective": "Answer the bounded question.",
                "desired_outcome": "The operator has the supported answer.",
                "resolved_scope": [],
                "scope_assumptions": [],
                "acceptance_criteria": ["The answer is delivered."],
                "commitments": [],
                "open_loops": [],
                "status": "completed"
            },
            "memory_updates": [],
            "presentation_ready": false
        });
        let decision = parse_session_research_decision_value(
            json!({
                "decision": "finish_research",
                "lane": "converse",
                "plan": null,
                "calls": [],
                "draft": research_draft
            }),
            true,
        )
        .unwrap();

        assert!(matches!(
            decision,
            SessionResearchDecision::Continue(decision)
                if matches!(
                    *decision,
                    SessionModelDecision::ResearchComplete {
                        declared_lane: Some(ExecutionLane::Converse),
                        ..
                    }
                )
        ));
        assert!(
            parse_session_research_decision_value(
                json!({
                    "decision": "finish_research",
                    "lane": "investigate",
                    "plan": null,
                    "calls": [{
                        "call_id": "call:late",
                        "tool_id": "source_runtime.inspect",
                        "purpose": "This call must be made before presenting.",
                        "input": {}
                    }],
                    "draft": null
                }),
                true
            )
            .is_err()
        );
        assert!(
            parse_session_research_decision_value(
                json!({
                    "decision": "finish_research",
                    "plan": null,
                    "calls": [],
                    "draft": null
                }),
                true
            )
            .is_err(),
            "the initial research decision must declare its typed lane"
        );
    }

    #[test]
    fn initial_research_lane_must_match_the_coissued_plan() {
        let plan = json!({
            "decision": "Read the named source once.",
            "lane": "investigate",
            "resolved_entities": ["source:one"],
            "claims": [{
                "claim_ref": "planned:one",
                "question": "What is the current source state?",
                "required": true,
                "subject_refs": ["source:one"],
                "source_candidates": ["source_runtime.inspect"]
            }],
            "selected_tools": ["source_runtime.inspect"],
            "stop_conditions": ["The bounded current state is returned."],
            "user_visible_work": ["Inspect the named source runtime."],
            "follow_through": null
        });
        let calls = json!([{
            "call_id": "call:one",
            "tool_id": "source_runtime.inspect",
            "purpose": "Read the current state of source:one.",
            "input": {"source_ref": "source:one"}
        }]);
        assert!(
            parse_session_research_decision_value(
                json!({
                    "decision": "establish_plan",
                    "lane": "lookup",
                    "plan": plan.clone(),
                    "calls": calls.clone(),
                    "draft": null
                }),
                true
            )
            .is_err()
        );

        let matching = parse_session_research_decision_value(
            json!({
                "decision": "establish_plan",
                "lane": "investigate",
                "plan": plan,
                "calls": calls,
                "draft": null
            }),
            true,
        )
        .unwrap();
        assert!(matches!(
            matching,
            SessionResearchDecision::Continue(decision)
                if matches!(
                    *decision,
                    SessionModelDecision::EstablishPlanAndInvoke {
                        plan: ResearchPlan {
                            lane: ExecutionLane::Investigate,
                            ..
                        },
                        ..
                    }
                )
        ));
    }

    #[test]
    fn session_decision_coissues_first_reads_with_the_plan() {
        let decision = parse_session_decision_value(json!({
            "decision": "establish_plan",
            "plan": {
                "decision": "Read the named source once.",
                "lane": "investigate",
                "resolved_entities": ["source:one"],
                "claims": [{
                    "claim_ref": "planned:one",
                    "question": "What is the current source state?",
                    "required": true,
                    "subject_refs": ["source:one"],
                    "source_candidates": ["source_runtime.inspect"]
                }],
                "selected_tools": ["source_runtime.inspect"],
                "stop_conditions": ["The bounded current state is returned."],
                "user_visible_work": ["Inspect the named source runtime."],
                "follow_through": null
            },
            "calls": [{
                "call_id": "call:one",
                "tool_id": "source_runtime.inspect",
                "purpose": "Read the current state of source:one.",
                "input": {"source_ref": "source:one"}
            }],
            "draft": null
        }))
        .unwrap();

        let SessionModelDecision::EstablishPlanAndInvoke { plan, calls } = decision else {
            panic!("expected a plan with coissued reads");
        };
        assert_eq!(plan.lane, ExecutionLane::Investigate);
        assert_eq!(calls[0].tool_id, "source_runtime.inspect");
    }

    #[test]
    fn claim_review_recovers_an_attention_object_with_trailing_wrapper_text() {
        let review = parse_message_review_value(json!({
            "draft_digest": format!("sha256:{}", "0".repeat(64)),
            "message_digest": format!("sha256:{}", "0".repeat(64)),
            "claim_reviews": [],
            "undeclared_material": [],
            "attention": "[{\"delivery\":\"silent\",\"reason\":\"Routine progress.\"}]",
            "behavioral": {
                "answers_newest_request": true,
                "conversational": true,
                "owns_follow_through": true,
                "right_sized": true,
                "evidence_boundary_correct": true
            }
        }))
        .unwrap();

        assert_eq!(review.attention.delivery, DeliveryDisposition::Silent);
        assert_eq!(review.attention.reason, "Routine progress.");
    }

    #[test]
    fn parses_a_structured_model_tool_decision() {
        let body = br#"{"choices":[{"message":{"content":"{\"decision\":\"invoke_tool\",\"call\":{\"call_id\":\"search-1\",\"tool_id\":\"graph.search\",\"purpose\":\"Find the source runtime.\",\"input\":{\"query\":\"Okta\"}}}"}}]}"#;
        let decision = parse_model_content(&completion_content(body).unwrap()).unwrap();
        assert!(matches!(decision, ModelDecision::InvokeTool { .. }));
    }

    #[test]
    fn critic_tool_schema_is_bedrock_compatible_and_rust_stays_variant_strict() {
        let schema = critique_decision_schema();
        assert_eq!(schema.get("type"), Some(&json!("object")));
        assert!(schema.get("oneOf").is_none());
        assert_eq!(
            schema.pointer("/properties/decision/enum"),
            Some(&json!(["approve", "revise"]))
        );
        assert!(schema.to_string().contains("conversational_synthesis"));
        assert!(parse_critique_value(json!({"decision": "approve"})).is_err());
        assert!(parse_critique_value(json!({"decision": "revise"})).is_err());
    }

    #[test]
    fn rejects_model_prose_instead_of_a_decision() {
        let body = br#"{"choices":[{"message":{"content":"I checked the graph."}}]}"#;
        assert!(matches!(
            completion_content(body).and_then(|content| parse_model_content(&content)),
            Err(AgentRuntimeError::InvalidFinal(_))
        ));
    }

    #[test]
    fn parses_route_and_critic_contracts_and_rejects_malformed_routes() {
        let route = parse_route_content(
            r#"{"lane":"investigate","confidence":"high","reason":"Current work claims require evidence.","requires_current_evidence":true,"future_observation":"none","future_observation_excerpt":null}"#,
        )
        .unwrap();
        assert_eq!(
            route.lane,
            cerebro_agent_runtime::ExecutionLane::Investigate
        );
        assert!(matches!(
            parse_route_content(r#"{"lane":"investigate"}"#),
            Err(AgentRuntimeError::InvalidRoute(_))
        ));
        assert_eq!(
            parse_critique_content(r#"{"decision":"revise","issues":["Cite current evidence."]}"#)
                .unwrap(),
            CritiqueDecision::Revise {
                issues: vec!["Cite current evidence.".into()]
            }
        );
        assert!(matches!(
            parse_critique_content(
                r#"{"decision":"approve","checks":{"answers_newest_request":true,"conversational":true,"evidence_boundary_correct":true,"no_raw_record_dump":true,"operator_facing":true,"owns_follow_through":true,"right_sized":true},"grounding":[{"unit_id":"visible-01","basis":"direct_observation","support":[{"evidence_ref":"evidence://current","data_pointer":"/status","supporting_text":"ready"}],"context_excerpt":null,"observation_sequence":null}]}"#
            )
            .unwrap(),
            CritiqueDecision::Approve { .. }
        ));
        assert!(parse_critique_content(r#"{"decision":"approve"}"#).is_err());
    }

    #[test]
    fn parses_the_conversational_presentation_contract() {
        assert_eq!(
            parse_presentation_content(
                r#"{"messages":["The current evidence supports the recommendation."]}"#
            )
            .unwrap()
            .messages,
            vec!["The current evidence supports the recommendation."]
        );
        assert!(parse_presentation_content(r#"{"message":"report"}"#).is_err());
        assert_eq!(
            parse_presentation_value(Value::String("A direct conversational reply.".into()))
                .unwrap()
                .messages,
            vec!["A direct conversational reply."]
        );
        assert_eq!(
            parse_presentation_value(json!({
                "messages": "[\"First message.\",\"Second message.\"]}"
            }))
            .unwrap()
            .messages,
            vec!["First message.", "Second message."]
        );
    }

    #[test]
    fn uses_the_final_forced_bedrock_decision_and_ignores_hidden_reasoning() {
        let decision = json!({
            "lane": "investigate",
            "confidence": "high",
            "reason": "Current work claims require evidence.",
            "requires_current_evidence": true,
            "future_observation": "none",
            "future_observation_excerpt": null
        });
        let tool_use = aws_sdk_bedrockruntime::types::ToolUseBlock::builder()
            .tool_use_id("tool-use-1")
            .name(ROUTE_DECISION_TOOL)
            .input(json_to_document(&decision).unwrap())
            .build()
            .unwrap();
        let content = vec![ContentBlock::ToolUse(tool_use.clone())];
        assert_eq!(
            bedrock_structured_output(&content, ROUTE_DECISION_TOOL).unwrap(),
            decision
        );
        assert!(parse_route_value(decision.clone()).is_ok());

        let with_hidden_reasoning = vec![
            ContentBlock::Text("unstructured answer".into()),
            ContentBlock::ToolUse(tool_use.clone()),
        ];
        assert_eq!(
            bedrock_structured_output(&with_hidden_reasoning, ROUTE_DECISION_TOOL).unwrap(),
            decision
        );
        let duplicate = vec![
            ContentBlock::ToolUse(tool_use.clone()),
            ContentBlock::ToolUse(tool_use.clone()),
        ];
        assert_eq!(
            bedrock_structured_output(&duplicate, ROUTE_DECISION_TOOL).unwrap(),
            decision
        );
        let disagreeing_decision = json!({
            "lane": "lookup",
            "confidence": "high",
            "reason": "A bounded current fact needs one read.",
            "requires_current_evidence": true,
            "future_observation": "none",
            "future_observation_excerpt": null
        });
        let disagreeing = aws_sdk_bedrockruntime::types::ToolUseBlock::builder()
            .tool_use_id("tool-use-2")
            .name(ROUTE_DECISION_TOOL)
            .input(json_to_document(&disagreeing_decision).unwrap())
            .build()
            .unwrap();
        assert_eq!(
            bedrock_structured_output(
                &[
                    ContentBlock::ToolUse(tool_use),
                    ContentBlock::ToolUse(disagreeing),
                ],
                ROUTE_DECISION_TOOL,
            )
            .unwrap(),
            disagreeing_decision
        );
    }

    #[test]
    fn bedrock_research_choice_requires_one_recognized_active_contract() {
        let contracts = agent_loop_contracts(true);
        let contract_digest = structured_choice_contract_digest(&contracts);
        let turn = initial_session_model_turn("Check the current source state.");
        let input = json!({
            "lane": "investigate",
            "plan": {
                "decision": "Read one current source state.",
                "lane": "investigate",
                "resolved_entities": ["source:one"],
                "claims": [{
                    "claim_ref": "planned:one",
                    "question": "What is the current source state?",
                    "required": true,
                    "subject_refs": ["source:one"],
                    "source_candidates": ["source_runtime.inspect"]
                }],
                "selected_tools": ["source_runtime.inspect"],
                "stop_conditions": ["The current state is returned."],
                "user_visible_work": ["Read the current source state."],
                "follow_through": null
            },
            "calls": [{
                "call_id": "call:one",
                "tool_id": "source_runtime.inspect",
                "purpose": "Read source:one.",
                "input": {"source_ref": "source:one"}
            }]
        });
        let tool_use = aws_sdk_bedrockruntime::types::ToolUseBlock::builder()
            .tool_use_id("tool-use-research")
            .name(SESSION_START_TOOL)
            .input(json_to_document(&input).unwrap())
            .build()
            .unwrap();
        let selection = bedrock_structured_choice_output(
            &[ContentBlock::ToolUse(tool_use.clone())],
            &contracts,
            &contract_digest,
        )
        .unwrap();
        assert!(matches!(
            parse_agent_loop_choice(selection, &turn).unwrap(),
            SessionModelDecision::EstablishPlanAndInvoke { plan, calls }
                if plan.lane == ExecutionLane::Investigate && calls.len() == 1
        ));

        let missing =
            bedrock_structured_choice_output(&[], &contracts, &contract_digest).unwrap_err();
        assert!(matches!(
            missing,
            AgentRuntimeError::ModelStageRejected(SessionModelRejection {
                class: SessionModelRejectionClass::MissingOrAmbiguousTool,
                ..
            })
        ));
        let duplicate = bedrock_structured_choice_output(
            &[
                ContentBlock::ToolUse(tool_use.clone()),
                ContentBlock::ToolUse(tool_use),
            ],
            &contracts,
            &contract_digest,
        )
        .unwrap_err();
        assert!(matches!(
            duplicate,
            AgentRuntimeError::ModelStageRejected(SessionModelRejection {
                class: SessionModelRejectionClass::MissingOrAmbiguousTool,
                ..
            })
        ));
    }

    #[test]
    fn initial_research_binds_redundant_plan_fields_before_runtime_admission() {
        let contracts = agent_loop_contracts(true);
        let turn = initial_session_model_turn("Check the current source state.");
        let selection = StructuredToolSelection {
            name: SESSION_START_TOOL.into(),
            input: json!({
                "lane": "investigate",
                "plan": {
                    "decision": "Read one current source state.",
                    "lane": "lookup",
                    "resolved_entities": ["source:one"],
                    "claims": [{
                        "claim_ref": "planned:one",
                        "question": "What is the current source state?",
                        "required": true,
                        "subject_refs": [],
                        "source_candidates": []
                    }],
                    "selected_tools": ["source_runtime.inspect"],
                    "stop_conditions": ["The current state is returned."],
                    "user_visible_work": ["Read the current source state."],
                    "follow_through": null,
                    "follow_through_offer": null
                },
                "calls": [{
                    "call_id": "call:one",
                    "tool_id": "source_runtime.inspect",
                    "purpose": "Read source:one.",
                    "input": {"source_ref": "source:one"}
                }]
            }),
            contract_digest: structured_choice_contract_digest(&contracts),
        };

        let SessionModelDecision::EstablishPlanAndInvoke { plan, calls } =
            parse_agent_loop_choice(selection, &turn).unwrap()
        else {
            panic!("expected the initial operating decision");
        };
        assert_eq!(plan.lane, ExecutionLane::Investigate);
        assert_eq!(plan.claims[0].subject_refs, vec!["source:one"]);
        assert_eq!(
            plan.claims[0].source_candidates,
            vec!["source_runtime.inspect"]
        );
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn converse_finish_binds_mission_and_newest_message_identity_in_rust() {
        let contracts = agent_loop_contracts(true);
        let turn = initial_session_model_turn("How are you feeling about the new setup?");
        let selection = StructuredToolSelection {
            name: SESSION_FINISH_TOOL.into(),
            input: json!({
                "lane": "converse",
                "draft": {
                    "state": "answered",
                    "delivery": "visible",
                    "claims": [{
                        "claim_ref": "claim:conversation",
                        "planned_claim_ref": null,
                        "text": "It feels much better; the next useful proof is a real operating turn.",
                        "required_for_answer": true,
                        "content": {
                            "basis": "conversational_synthesis",
                            "source_message_sequences": [999],
                            "source_atom_refs": ["untrusted:model-echo"]
                        }
                    }],
                    "coverage_notice": null,
                    "question": null,
                    "mission": {
                        "mission_ref": "model:must-not-replace-mission",
                        "objective": "Replace the durable mission.",
                        "desired_outcome": "Wrong mission",
                        "resolved_scope": [],
                        "scope_assumptions": [],
                        "acceptance_criteria": [],
                        "commitments": [],
                        "open_loops": [],
                        "status": "completed"
                    },
                    "memory_updates": []
                }
            }),
            contract_digest: structured_choice_contract_digest(&contracts),
        };

        let SessionModelDecision::ResearchComplete {
            draft,
            declared_lane,
        } = parse_agent_loop_choice(selection, &turn).unwrap()
        else {
            panic!("expected the direct conversation artifact");
        };
        assert_eq!(declared_lane, Some(ExecutionLane::Converse));
        assert_eq!(draft.mission, turn.session.mission);
        let ClaimContent::ConversationalSynthesis {
            source_message_sequences,
            source_atom_refs,
        } = &draft.claims[0].content
        else {
            panic!("expected conversational synthesis grounding");
        };
        assert_eq!(source_message_sequences, &[1]);
        assert!(source_atom_refs.is_empty());
    }

    #[test]
    fn accepts_one_fenced_structured_bedrock_decision() {
        let decision = parse_model_content(
            "```json\n{\"decision\":\"invoke_tool\",\"call\":{\"call_id\":\"runtime-1\",\"tool_id\":\"source_runtime.inspect\",\"purpose\":\"Read connector health.\",\"input\":{\"query\":\"identity provider\"}}}\n```",
        )
        .unwrap();
        assert!(matches!(decision, ModelDecision::InvokeTool { .. }));
    }

    #[test]
    fn recovers_unambiguous_flattened_bedrock_decisions() {
        let decision = parse_model_value(json!({
            "call_id": "runtime-1",
            "tool_id": "source_runtime.inspect",
            "purpose": "Read connector health.",
            "input": {"query": "identity provider"}
        }))
        .unwrap();
        assert!(matches!(decision, ModelDecision::InvokeTool { .. }));
    }

    #[test]
    fn source_runtime_view_marks_stale_and_incomplete_signals() {
        let now = OffsetDateTime::parse("2026-07-29T12:00:00Z", &Rfc3339).unwrap();
        let (view, gaps) = source_runtime_view(
            SourceRuntimeObservation {
                runtime_id: "identity-provider-primary".into(),
                source_id: "identity-provider".into(),
                enabled_state: "true".into(),
                last_failure_category: None,
                last_synced_at: Some("2026-07-29T10:00:00Z".into()),
                cursor_pending: true,
                checkpoint_cursor_present: true,
                stale_after_seconds: Some(3_600),
                expected_cadence_seconds: Some(3_600),
                contract_probe_state: "passing".into(),
                latest_finding_evaluation_status: Some("current".into()),
                latest_collection: Some(SourceRuntimeCollectionObservation {
                    collection_id: "collection-1".into(),
                    status: "incomplete".into(),
                    completed_at_unix_ms: 1_753_786_800_000,
                    pages_read: 2,
                    records_scanned: 12,
                    records_accepted: 11,
                    records_rejected: 1,
                }),
            },
            now,
        );
        assert_eq!(view["health"], "stale");
        assert_eq!(view["readiness"], "needs_refresh");
        assert_eq!(view["next_action"], "run_graph_ingest");
        assert_eq!(view["cursor_state"], "pending");
        assert!(gaps.iter().any(|gap| gap == "latest_collection_incomplete"));
        assert!(
            gaps.iter()
                .any(|gap| gap == "latest_collection_has_rejected_records")
        );
    }

    #[test]
    fn production_model_gate_accepts_opus_and_rejects_nova_or_smaller_claude_models() {
        assert!(is_bedrock_opus_model("us.anthropic.claude-opus-4-8"));
        assert!(is_bedrock_opus_model("anthropic.claude-opus-4-1-v1:0"));
        assert!(!is_bedrock_opus_model("amazon.nova-pro-v1:0"));
        assert!(!is_bedrock_opus_model(
            "us.anthropic.claude-sonnet-4-5-v1:0"
        ));
    }

    #[test]
    fn source_runtime_view_never_serializes_connector_config() {
        let now = OffsetDateTime::parse("2026-07-29T12:00:00Z", &Rfc3339).unwrap();
        let (view, _) = source_runtime_view(
            SourceRuntimeObservation {
                runtime_id: "runtime-1".into(),
                source_id: "source-1".into(),
                enabled_state: "true".into(),
                last_failure_category: None,
                last_synced_at: None,
                cursor_pending: false,
                checkpoint_cursor_present: false,
                stale_after_seconds: None,
                expected_cadence_seconds: None,
                contract_probe_state: "unknown".into(),
                latest_finding_evaluation_status: None,
                latest_collection: None,
            },
            now,
        );
        assert!(view.get("config").is_none());
        assert!(view.get("credentials").is_none());
        assert!(view.get("secret_references").is_none());
    }

    #[test]
    fn source_catalog_view_reports_declared_vanta_access_without_credentials() {
        let catalog = super::super::load_catalog().unwrap();
        let source_count = catalog.sources().count();
        let (sources, truncated) = source_catalog_views(&catalog, source_count);

        assert!(!truncated);
        let vanta = sources
            .iter()
            .find(|source| source["source_id"] == "vanta")
            .expect("the bounded catalog page includes Vanta");
        assert_eq!(vanta["authentication_model"], "oauth_client_credentials");
        assert_eq!(vanta["credential_access_observed"], false);
        assert_eq!(vanta["provider_permission_scope_observed"], false);
        assert_eq!(vanta["runtime_enablement_observed"], false);
        assert_eq!(
            vanta["declared_families"]
                .as_array()
                .unwrap()
                .iter()
                .map(|family| family["family_id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["users", "controls", "findings"]
        );
        let encoded = serde_json::to_string(&sources).unwrap();
        assert!(!encoded.contains("client_secret"));
        assert!(!encoded.contains("token_url"));
        assert!(!encoded.contains("api.vanta.com"));
    }

    #[test]
    fn catalog_evidence_remains_fresh_for_the_turn() {
        let request = AgentTurnRequest {
            schema_version: cerebro_agent_runtime::AGENT_TURN_REQUEST_V1.into(),
            tenant_id: "tenant-1".into(),
            request_id: "request-1".into(),
            thread_ref: "thread-1".into(),
            context_scope_ref: None,
            actor_ref: "actor-1".into(),
            assessment_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            message: "What access do you have to Vanta?".into(),
            history: Vec::new(),
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: Vec::new(),
            capabilities: Vec::new(),
            followup_acceptance: None,
        };
        let call = cerebro_agent_runtime::ToolCall {
            call_id: "catalog-1".into(),
            tool_id: "source_catalog.inspect".into(),
            purpose: "Describe declared Vanta access.".into(),
            input: json!({"source": "vanta"}),
        };

        let evidence =
            catalog_evidence(&request, &call, true, "Declared Vanta access.".into()).unwrap();
        let observed_at = OffsetDateTime::parse(&evidence.observed_at, &Rfc3339).unwrap();
        let fresh_until =
            OffsetDateTime::parse(evidence.fresh_until.as_deref().unwrap(), &Rfc3339).unwrap();

        assert_eq!(fresh_until - observed_at, TimeDuration::minutes(5));
    }

    #[test]
    fn exact_vanta_runtime_wins_over_mandiant_advantage_substring() {
        let record = |runtime_id: &str, source_id: &str| SourceRuntimeObservation {
            runtime_id: runtime_id.into(),
            source_id: source_id.into(),
            enabled_state: "true".into(),
            last_failure_category: None,
            last_synced_at: None,
            cursor_pending: false,
            checkpoint_cursor_present: false,
            stale_after_seconds: None,
            expected_cadence_seconds: None,
            contract_probe_state: "unknown".into(),
            latest_finding_evaluation_status: None,
            latest_collection: None,
        };
        let records = prefer_exact_runtime_matches(
            vec![
                record("mandiant-advantage-prod", "mandiant_advantage"),
                record("vanta-prod", "vanta"),
            ],
            "Vanta",
        );

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source_id, "vanta");
    }

    #[test]
    fn source_runtime_view_never_promotes_unknown_enabled_state() {
        let now = OffsetDateTime::parse("2026-07-29T12:00:00Z", &Rfc3339).unwrap();
        for (enabled_state, expected_gap) in [
            ("", "enabled_state_not_observed"),
            ("sometimes", "enabled_state_invalid"),
        ] {
            let (view, gaps) = source_runtime_view(
                SourceRuntimeObservation {
                    runtime_id: "runtime-1".into(),
                    source_id: "source-1".into(),
                    enabled_state: enabled_state.into(),
                    last_failure_category: None,
                    last_synced_at: Some("2026-07-29T11:59:00Z".into()),
                    cursor_pending: false,
                    checkpoint_cursor_present: false,
                    stale_after_seconds: Some(300),
                    expected_cadence_seconds: Some(300),
                    contract_probe_state: "passing".into(),
                    latest_finding_evaluation_status: Some("current".into()),
                    latest_collection: Some(SourceRuntimeCollectionObservation {
                        collection_id: "collection-1".into(),
                        status: "complete".into(),
                        completed_at_unix_ms: 1_753_790_340_000,
                        pages_read: 1,
                        records_scanned: 12,
                        records_accepted: 12,
                        records_rejected: 0,
                    }),
                },
                now,
            );
            assert_eq!(view["enabled_state"], "unknown");
            assert_eq!(view["health"], "unknown");
            assert_eq!(view["readiness"], "poor");
            assert_eq!(view["next_action"], "inspect_connection");
            assert!(gaps.iter().any(|gap| gap == expected_gap));
        }
    }

    #[test]
    fn session_transport_renders_validated_markdown_for_slack_delivery() {
        let request = AgentTurnRequest {
            schema_version: "agent-turn-request/v1".into(),
            tenant_id: "tenant:slack-render".into(),
            request_id: "request:slack-render".into(),
            thread_ref: "thread:slack-render".into(),
            context_scope_ref: None,
            actor_ref: "actor:slack-render".into(),
            assessment_at: "2026-08-01T23:30:00Z".into(),
            message: "Show the current state.".into(),
            history: Vec::new(),
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: Vec::new(),
            capabilities: Vec::new(),
            followup_acceptance: None,
        };
        let mission = new_session(&request).unwrap().mission;
        let outcome = session_outcome_to_turn(SessionTurnOutcome::PendingDelivery {
            lane: ExecutionLane::Converse,
            delivery: DeliveryDisposition::Visible,
            markdown: "## Current state\n\n**Healthy**".into(),
            final_state: FinalState::Answered,
            evidence_atom_refs: Vec::new(),
            proactive_followup_offer: None,
            accepted_followup_ref: None,
            mission,
            events: Vec::new(),
        });

        let AgentTurnOutcome::PendingDelivery { markdown, .. } = outcome else {
            panic!("validated Slack answer should remain pending delivery");
        };
        assert_eq!(markdown, "*Current state*\n\n*Healthy*");
    }

    #[test]
    fn delivery_markdown_contains_only_the_model_message() {
        assert_eq!(
            turn_delivery_markdown("## Current state\n\n**Healthy**"),
            "*Current state*\n\n*Healthy*"
        );
    }

    #[test]
    fn slack_context_scope_requires_the_canonical_channel_digest() {
        let valid = format!("slack-context-scope://sha256/{}", "a".repeat(64));
        assert!(validate_context_scope_ref(&valid).is_ok());
        for invalid in [
            "",
            "slack-context-scope://sha256/",
            "slack-context-scope://sha256/ABCDEF",
            "slack-context-scope://sha256/not-a-digest",
        ] {
            assert!(validate_context_scope_ref(invalid).is_err());
        }
    }

    #[test]
    fn recalled_threads_never_overflow_the_durable_memory_bound() {
        let request = AgentTurnRequest {
            schema_version: cerebro_agent_runtime::AGENT_TURN_REQUEST_V1.into(),
            tenant_id: "tenant:memory-bound".into(),
            request_id: "request:memory-bound".into(),
            thread_ref: "thread:memory-bound".into(),
            context_scope_ref: None,
            actor_ref: "actor:memory-bound".into(),
            assessment_at: "2026-07-31T20:00:00Z".into(),
            message: "Keep the prior context bounded.".into(),
            history: Vec::new(),
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: Vec::new(),
            capabilities: Vec::new(),
            followup_acceptance: None,
        };
        let mut session = new_session(&request).unwrap();
        session.memories = (0..MAX_SESSION_MEMORIES)
            .map(|index| cerebro_agent_runtime::session::MemoryUpdate {
                memory_ref: format!("memory:{index}"),
                kind: cerebro_agent_runtime::session::MemoryKind::Fact,
                statement: format!("Memory {index}"),
                evidence_atom_refs: Vec::new(),
                promotion_requested: false,
            })
            .collect();

        merge_recalled_memories(
            &mut session,
            vec![cerebro_agent_runtime::session::MemoryUpdate {
                memory_ref: "recalled-thread:extra".into(),
                kind: cerebro_agent_runtime::session::MemoryKind::Handoff,
                statement: "Extra prior thread".into(),
                evidence_atom_refs: Vec::new(),
                promotion_requested: false,
            }],
        );

        assert_eq!(session.memories.len(), MAX_SESSION_MEMORIES);
        assert!(
            session
                .memories
                .iter()
                .all(|memory| memory.memory_ref != "recalled-thread:extra")
        );
    }
}
