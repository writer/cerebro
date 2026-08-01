//! Durable conversation and provenance contracts for the Cerebro agent.
//!
//! A session is the unit of work. Slack and other clients append operator input
//! and render session events; they do not own the model loop or its continuity.

use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    AgentRuntimeError, ApprovalRequest, EffectAuthorization, ExecutionLane, FinalState,
    ToolAuthorityClass, ToolCall, ToolDescriptor, ToolEffectClass, ToolObservation, ToolResult,
    ToolResultState,
};

pub const AGENT_SESSION_V2: &str = "agent-session/v2";
pub const AGENT_SESSION_EVENT_V2: &str = "agent-session-event/v2";

const MAX_PLAN_CLAIMS: usize = 16;
const MAX_PLAN_TOOLS: usize = 16;
const MAX_SCOPE_ITEMS: usize = 32;
const MAX_COMMITMENTS: usize = 16;
const MAX_OPEN_LOOPS: usize = 16;
const MAX_VISIBLE_CLAIMS: usize = 32;
const MAX_SESSION_STEPS: usize = 48;
const MAX_MODEL_REPAIRS: usize = 10;
const MAX_CRITIC_REPAIRS: usize = 5;
const MAX_DELIVERY_MESSAGE_BYTES: usize = 3_500;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_SESSION_MESSAGES: usize = 400;
const MAX_SESSION_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_MEMORIES: usize = 128;
const MAX_RECALLED_OBSERVATIONS: usize = 96;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    WaitingForUser,
    WaitingForExternal,
    Completed,
    Blocked,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentStatus {
    Planned,
    InProgress,
    Waiting,
    Completed,
    Blocked,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkOwner {
    Cerebro,
    User,
    External,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MissionState {
    pub mission_ref: String,
    pub objective: String,
    pub desired_outcome: String,
    pub resolved_scope: Vec<String>,
    pub scope_assumptions: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub commitments: Vec<Commitment>,
    pub open_loops: Vec<OpenLoop>,
    pub status: SessionStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub commitment_ref: String,
    pub summary: String,
    pub owner: WorkOwner,
    pub status: CommitmentStatus,
    pub next_action: Option<String>,
    pub blocker: Option<String>,
    pub acceptance_criteria: Vec<String>,
    pub artifact_refs: Vec<String>,
    #[serde(default)]
    pub required_tool_ids: Vec<String>,
    #[serde(default)]
    pub attention_policy: Option<CommitmentAttentionPolicy>,
    pub wake_at: Option<String>,
    pub verification: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentAttentionPolicy {
    pub acceptance_all: Vec<ObservationCondition>,
    pub alert_any: Vec<ObservationCondition>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationCondition {
    pub tool_id: String,
    pub data_pointer: String,
    pub equals: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpenLoop {
    pub open_loop_ref: String,
    pub summary: String,
    pub owner: WorkOwner,
    pub next_action: Option<String>,
    pub blocked_by: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedClaim {
    pub claim_ref: String,
    pub question: String,
    pub required: bool,
    pub source_candidates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResearchPlan {
    pub decision: String,
    pub lane: ExecutionLane,
    pub resolved_entities: Vec<String>,
    pub claims: Vec<PlannedClaim>,
    pub selected_tools: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub user_visible_work: Vec<String>,
    #[serde(default)]
    pub follow_through: Option<PlannedFollowThrough>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedFollowThrough {
    pub commitment_ref: String,
    pub required_tool_ids: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub next_action: String,
    pub attention_policy: CommitmentAttentionPolicy,
    pub check_after_seconds: u32,
    pub verification: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageState {
    Observed,
    ExplicitlyNotReturned,
    NotApplicable,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceAssertion {
    Value {
        predicate: String,
        value: Value,
    },
    Relation {
        predicate: String,
        object_ref: String,
    },
    FieldCoverage {
        field: String,
        state: CoverageState,
    },
    ToolOutcome {
        state: ToolResultState,
        summary: String,
    },
    LegacyStatement {
        statement: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceAtom {
    pub atom_ref: String,
    pub subject_ref: Option<String>,
    pub assertion: EvidenceAssertion,
    pub observed_at: String,
    pub fresh_until: Option<String>,
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationRule {
    Count,
    SetDifference,
    DeadlineOffsetSeconds,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpec {
    pub tool_id: Option<String>,
    pub target_ref: Option<String>,
    pub input: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum ClaimContent {
    Observation {
        atom_refs: Vec<String>,
    },
    Derivation {
        rule: DerivationRule,
        atom_refs: Vec<String>,
        result: Value,
    },
    OperatorContext {
        message_sequence: u64,
        exact_excerpt: String,
    },
    RetainedPlan {
        open_loop_ref: String,
    },
    Commitment {
        commitment_ref: String,
    },
    Recommendation {
        action: ActionSpec,
        rationale_atom_refs: Vec<String>,
    },
    Hypothesis {
        supporting_atom_refs: Vec<String>,
        alternatives: Vec<String>,
    },
    StableExplanation,
    Question,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedClaim {
    pub claim_ref: String,
    #[serde(default)]
    pub planned_claim_ref: Option<String>,
    pub text: String,
    pub required_for_answer: bool,
    pub content: ClaimContent,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroundedDraft {
    pub state: FinalState,
    #[serde(default)]
    pub delivery: DeliveryDisposition,
    pub message: String,
    pub claims: Vec<GroundedClaim>,
    pub coverage_notice: Option<String>,
    pub question: Option<String>,
    pub mission: MissionState,
    pub memory_updates: Vec<MemoryUpdate>,
    pub presentation_ready: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryDisposition {
    #[default]
    Visible,
    Silent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    Fact,
    Decision,
    Risk,
    Blocker,
    Handoff,
    SourceHealth,
    Preference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryUpdate {
    pub memory_ref: String,
    pub kind: MemoryKind,
    pub statement: String,
    pub evidence_atom_refs: Vec<String>,
    pub promotion_requested: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum SessionModelDecision {
    EstablishPlan { plan: ResearchPlan },
    InvokeTools { calls: Vec<ToolCall> },
    Finish { draft: GroundedDraft },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMessageRole {
    Assistant,
    User,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionMessage {
    pub role: SessionMessageRole,
    pub message_ref: String,
    pub actor_ref: String,
    pub text: String,
    pub received_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SessionEvent {
    UserMessageQueued {
        message: SessionMessage,
    },
    WakeTriggered {
        request_id: String,
        commitment_ref: String,
        occurrence_ref: String,
        scheduled_for: String,
    },
    WakeExhausted {
        request_id: String,
        commitment_ref: String,
        occurrence_ref: String,
        schedule_generation: u64,
        failure_class: String,
        draft: GroundedDraft,
    },
    TurnStarted {
        request_id: String,
    },
    PlanEstablished {
        plan: ResearchPlan,
    },
    Progressed {
        phase: String,
        status: String,
    },
    ToolInvoked {
        observation: ToolObservation,
    },
    EffectStarted {
        call: ToolCall,
        descriptor: ToolDescriptor,
    },
    DraftProduced {
        request_id: String,
        draft: GroundedDraft,
    },
    ApprovalRequested {
        tool_id: String,
        input_digest: String,
    },
    TurnCompleted {
        request_id: String,
        state: FinalState,
    },
    TurnFailed {
        request_id: String,
        reason: String,
    },
    Interrupted {
        request_id: String,
        reason: String,
    },
    DeliveryRecorded {
        request_id: String,
        transport: String,
        delivery_ref: String,
        payload_digest: String,
    },
    MemoryRecorded {
        update: MemoryUpdate,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEventRecord {
    pub schema_version: String,
    pub session_ref: String,
    pub sequence: u64,
    pub occurred_at: String,
    pub event: SessionEvent,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSession {
    pub schema_version: String,
    pub session_ref: String,
    pub tenant_id: String,
    pub thread_ref: String,
    pub mission: MissionState,
    pub messages: Vec<SessionMessage>,
    pub events: Vec<SessionEventRecord>,
    pub effect_authorizations: Vec<EffectAuthorization>,
    #[serde(default)]
    pub pending_delivery: Option<PendingDelivery>,
    #[serde(default)]
    pub memories: Vec<MemoryUpdate>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDelivery {
    pub request_id: String,
    pub draft: GroundedDraft,
    pub produced_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SessionModelTurn {
    pub session: AgentSession,
    pub trigger: SessionTurnTrigger,
    pub assessment_at: String,
    pub prior_commitment_checkpoint: Option<CommitmentCheckpoint>,
    pub wake_assessment: Option<WakeAssessment>,
    pub plan: Option<ResearchPlan>,
    pub available_tools: Vec<ToolDescriptor>,
    pub observations: Vec<ToolObservation>,
    pub repair_feedback: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentCheckpoint {
    pub commitment_ref: String,
    pub source_request_id: String,
    pub recorded_at: String,
    pub delivery_ref: String,
    pub payload_digest: String,
    pub trigger_occurrence_ref: Option<String>,
    pub delivery: DeliveryDisposition,
    pub state: FinalState,
    pub summary: String,
    pub observations: Vec<CommitmentCheckpointObservation>,
    pub commitment_status: CommitmentStatus,
    pub next_wake_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentCheckpointObservation {
    pub tool_id: String,
    pub input: Value,
    pub input_digest: String,
    pub observed_at: Option<String>,
    pub state: ToolResultState,
    pub complete: bool,
    pub summary: String,
    pub data: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WakeAssessment {
    pub commitment_ref: String,
    pub required_observations_present: bool,
    pub required_observations_healthy: bool,
    pub acceptance_met: bool,
    pub matched_attention_signals: Vec<ObservationCondition>,
    pub scalar_comparisons: Vec<WakeScalarComparison>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WakeScalarComparison {
    pub tool_id: String,
    pub input_digest: String,
    pub data_pointer: String,
    pub previous: Option<Value>,
    pub current: Option<Value>,
    pub relation: WakeScalarRelation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WakeScalarRelation {
    AddedToCurrentRead,
    Changed,
    Unchanged,
    NotReturnedByCurrentRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimReviewVerdict {
    Supported,
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimReview {
    pub claim_ref: String,
    pub verdict: ClaimReviewVerdict,
    pub issue: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BehavioralReview {
    pub answers_newest_request: bool,
    pub conversational: bool,
    pub owns_follow_through: bool,
    pub right_sized: bool,
    pub evidence_boundary_correct: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttentionReview {
    pub delivery: DeliveryDisposition,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MessageReview {
    pub message_digest: String,
    pub claim_reviews: Vec<ClaimReview>,
    pub undeclared_material: Vec<String>,
    pub attention: AttentionReview,
    pub behavioral: BehavioralReview,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClaimReviewTurn {
    pub session: AgentSession,
    pub trigger: SessionTurnTrigger,
    pub prior_commitment_checkpoint: Option<CommitmentCheckpoint>,
    pub wake_assessment: Option<WakeAssessment>,
    pub draft: GroundedDraft,
    pub observations: Vec<ToolObservation>,
}

#[async_trait]
pub trait SessionAgentModel: Send + Sync {
    async fn advance(
        &self,
        turn: SessionModelTurn,
    ) -> Result<SessionModelDecision, AgentRuntimeError>;

    async fn review_message(
        &self,
        turn: ClaimReviewTurn,
    ) -> Result<MessageReview, AgentRuntimeError>;
}

#[async_trait]
pub trait SessionTools: Send + Sync {
    fn catalog(&self) -> Vec<ToolDescriptor>;

    async fn invoke(
        &self,
        session: &AgentSession,
        input: &SessionTurnInput,
        call: &ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create(&self, session: &AgentSession) -> Result<(), AgentRuntimeError>;

    async fn load(&self, session_ref: &str) -> Result<Option<AgentSession>, AgentRuntimeError>;

    async fn append(
        &self,
        session_ref: &str,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError>;
}

#[async_trait]
pub trait SessionJournal: Send + Sync {
    async fn record(&self, event: &SessionEventRecord) -> Result<(), AgentRuntimeError>;
}

struct NoopSessionJournal;

#[async_trait]
impl SessionJournal for NoopSessionJournal {
    async fn record(&self, _event: &SessionEventRecord) -> Result<(), AgentRuntimeError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTurnInput {
    pub request_id: String,
    pub actor_ref: String,
    pub assessment_at: String,
    pub trigger: SessionTurnTrigger,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionTurnTrigger {
    Operator,
    Wake {
        commitment_ref: String,
        occurrence_ref: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SessionTurnOutcome {
    PendingDelivery {
        lane: ExecutionLane,
        delivery: DeliveryDisposition,
        markdown: String,
        final_state: FinalState,
        evidence_atom_refs: Vec<String>,
        mission: MissionState,
        events: Vec<SessionEventRecord>,
    },
    ApprovalRequired {
        request: ApprovalRequest,
        events: Vec<SessionEventRecord>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDraft {
    pub markdown: String,
    pub evidence_atom_refs: Vec<String>,
}

pub struct EvidenceAtomization<'a> {
    pub evidence_ref: &'a str,
    pub subject_ref: Option<&'a str>,
    pub data: &'a Value,
    pub state: ToolResultState,
    pub summary: &'a str,
    pub observed_at: &'a str,
    pub fresh_until: Option<&'a str>,
    pub complete: bool,
}

pub fn evidence_atoms_from_json(input: EvidenceAtomization<'_>) -> Vec<EvidenceAtom> {
    let EvidenceAtomization {
        evidence_ref,
        subject_ref,
        data,
        state,
        summary,
        observed_at,
        fresh_until,
        complete,
    } = input;
    let mut atoms = vec![EvidenceAtom {
        atom_ref: format!("{evidence_ref}#tool-outcome"),
        subject_ref: subject_ref.map(str::to_owned),
        assertion: EvidenceAssertion::ToolOutcome {
            state,
            summary: summary.to_owned(),
        },
        observed_at: observed_at.to_owned(),
        fresh_until: fresh_until.map(str::to_owned),
        complete: true,
    }];
    let context = AtomizationContext {
        evidence_ref,
        subject_ref,
        observed_at,
        fresh_until,
        complete,
    };
    let truncated = append_value_atoms(&context, "", data, &mut atoms);
    if !complete || truncated {
        atoms.push(EvidenceAtom {
            atom_ref: format!(
                "{evidence_ref}#coverage:{}",
                if truncated { "atomization" } else { "result" }
            ),
            subject_ref: subject_ref.map(str::to_owned),
            assertion: EvidenceAssertion::FieldCoverage {
                field: if truncated {
                    "bounded_atomization".into()
                } else {
                    "bounded_result".into()
                },
                state: CoverageState::Unknown,
            },
            observed_at: observed_at.to_owned(),
            fresh_until: fresh_until.map(str::to_owned),
            complete: true,
        });
    }
    atoms
}

struct AtomizationContext<'a> {
    evidence_ref: &'a str,
    subject_ref: Option<&'a str>,
    observed_at: &'a str,
    fresh_until: Option<&'a str>,
    complete: bool,
}

fn append_value_atoms(
    context: &AtomizationContext<'_>,
    pointer: &str,
    value: &Value,
    atoms: &mut Vec<EvidenceAtom>,
) -> bool {
    const MAX_ATOMS: usize = 128;
    const MAX_ATOM_STRING_BYTES: usize = 2 * 1024;
    if atoms.len() >= MAX_ATOMS {
        return true;
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                if append_value_atoms(context, &format!("{pointer}/{escaped}"), value, atoms) {
                    return true;
                }
            }
            false
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                if append_value_atoms(context, &format!("{pointer}/{index}"), value, atoms) {
                    return true;
                }
            }
            false
        }
        Value::String(value) if value.len() > MAX_ATOM_STRING_BYTES => true,
        Value::Null => false,
        scalar => {
            atoms.push(EvidenceAtom {
                atom_ref: format!("{}#value:{pointer}", context.evidence_ref),
                subject_ref: context.subject_ref.map(str::to_owned),
                assertion: EvidenceAssertion::Value {
                    predicate: pointer.to_owned(),
                    value: scalar.clone(),
                },
                observed_at: context.observed_at.to_owned(),
                fresh_until: context.fresh_until.map(str::to_owned),
                complete: context.complete,
            });
            false
        }
    }
}

pub fn apply_session_events(
    session: &AgentSession,
    new_events: &[SessionEventRecord],
) -> Result<AgentSession, AgentRuntimeError> {
    validate_session(session)?;
    let mut next = session.clone();
    let mut expected = next.events.last().map_or(1, |event| event.sequence + 1);
    for record in new_events {
        if record.schema_version != AGENT_SESSION_EVENT_V2
            || record.session_ref != next.session_ref
            || record.sequence != expected
            || OffsetDateTime::parse(&record.occurred_at, &Rfc3339).is_err()
        {
            return Err(AgentRuntimeError::InvalidRequest(
                "session event stream is not contiguous or belongs to another session".into(),
            ));
        }
        match &record.event {
            SessionEvent::UserMessageQueued { message } => {
                if message.role != SessionMessageRole::User {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "queued user input must have the user role".into(),
                    ));
                }
                next.messages.push(message.clone());
            }
            SessionEvent::WakeTriggered {
                request_id,
                commitment_ref,
                occurrence_ref,
                scheduled_for,
            } => {
                if !bounded(request_id, MAX_TEXT_BYTES)
                    || !bounded(commitment_ref, MAX_TEXT_BYTES)
                    || !bounded(occurrence_ref, MAX_TEXT_BYTES)
                    || OffsetDateTime::parse(scheduled_for, &Rfc3339).is_err()
                {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "wake control identity or scheduled time is invalid".into(),
                    ));
                }
            }
            SessionEvent::DraftProduced { request_id, draft } => {
                if next.pending_delivery.is_some() {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "session already has a response awaiting delivery".into(),
                    ));
                }
                next.pending_delivery = Some(PendingDelivery {
                    request_id: request_id.clone(),
                    draft: draft.clone(),
                    produced_at: record.occurred_at.clone(),
                });
            }
            SessionEvent::WakeExhausted {
                request_id, draft, ..
            } => {
                if next.pending_delivery.is_some() {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "session already has a response awaiting delivery".into(),
                    ));
                }
                next.mission = draft.mission.clone();
                next.pending_delivery = Some(PendingDelivery {
                    request_id: request_id.clone(),
                    draft: draft.clone(),
                    produced_at: record.occurred_at.clone(),
                });
            }
            SessionEvent::DeliveryRecorded {
                request_id,
                transport,
                ..
            } => {
                let pending = next.pending_delivery.take().ok_or_else(|| {
                    AgentRuntimeError::InvalidRequest(
                        "delivery receipt has no pending response".into(),
                    )
                })?;
                if pending.request_id != *request_id {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "delivery receipt belongs to another request".into(),
                    ));
                }
                next.mission = pending.draft.mission;
                for update in pending.draft.memory_updates {
                    next.memories
                        .retain(|memory| memory.memory_ref != update.memory_ref);
                    next.memories.push(update);
                }
                if transport != "internal_scheduler" {
                    next.messages.push(SessionMessage {
                        role: SessionMessageRole::Assistant,
                        message_ref: format!("assistant:{request_id}"),
                        actor_ref: "cerebro".into(),
                        text: pending.draft.message,
                        received_at: record.occurred_at.clone(),
                    });
                }
            }
            SessionEvent::MemoryRecorded { update } => {
                next.memories
                    .retain(|memory| memory.memory_ref != update.memory_ref);
                next.memories.push(update.clone());
            }
            _ => {}
        }
        next.events.push(record.clone());
        expected += 1;
    }
    validate_session(&next)?;
    Ok(next)
}

pub async fn run_session_turn(
    model: &dyn SessionAgentModel,
    tools: &dyn SessionTools,
    session: AgentSession,
    input: SessionTurnInput,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    run_session_turn_recorded(model, tools, &NoopSessionJournal, session, input).await
}

pub async fn run_session_turn_recorded(
    model: &dyn SessionAgentModel,
    tools: &dyn SessionTools,
    journal: &dyn SessionJournal,
    session: AgentSession,
    input: SessionTurnInput,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    validate_session(&session)?;
    validate_turn_input(&session, &input)?;
    let trigger = input.trigger.clone();
    let assessment_at = OffsetDateTime::parse(&input.assessment_at, &Rfc3339)
        .map_err(|_| AgentRuntimeError::InvalidRequest("assessment_at is invalid".into()))?;
    let available_tools = tools.catalog();
    let available_tool_ids = available_tools
        .iter()
        .map(|descriptor| descriptor.tool_id.clone())
        .collect::<Vec<_>>();
    let descriptors = available_tools
        .iter()
        .map(|descriptor| (descriptor.tool_id.clone(), descriptor.clone()))
        .collect::<BTreeMap<_, _>>();
    let prior_commitment_checkpoint = prior_commitment_checkpoint(&session, &trigger);
    let (resumed, mut plan, turn_observations) = resume_turn_state(&session, &input.request_id);
    let mut observations = if resumed {
        turn_observations.clone()
    } else {
        recalled_observations_for_trigger(&session, &trigger, assessment_at)
    };
    let mut events = Vec::new();
    if !resumed {
        emit_event(
            &session,
            &input.assessment_at,
            &mut events,
            SessionEvent::TurnStarted {
                request_id: input.request_id.clone(),
            },
            journal,
        )
        .await?;
    }
    if plan.is_none()
        && let Some(executor_plan) = wake_research_plan(&session, &trigger)
    {
        validate_plan(&executor_plan, &available_tool_ids)?;
        emit_event(
            &session,
            &input.assessment_at,
            &mut events,
            SessionEvent::PlanEstablished {
                plan: executor_plan.clone(),
            },
            journal,
        )
        .await?;
        plan = Some(executor_plan);
    }
    let mut call_ids = turn_observations
        .iter()
        .map(|observation| observation.call.call_id.clone())
        .collect::<BTreeSet<_>>();
    let mut call_fingerprints = turn_observations
        .iter()
        .map(|observation| {
            (
                observation.call.tool_id.clone(),
                observation.call.input_digest(),
            )
        })
        .collect::<BTreeSet<_>>();
    let mut consumed_approvals = BTreeSet::new();
    let mut repair_feedback = Vec::new();
    let mut repairs = 0;
    let mut critic_repairs = 0;
    let mut rejected_reviews = BTreeSet::new();
    let mut rejected_operating_drafts = BTreeSet::new();

    for _ in 0..MAX_SESSION_STEPS {
        if repairs > MAX_MODEL_REPAIRS {
            return repair_fallback_outcome(
                &session,
                &input,
                &trigger,
                plan.as_ref(),
                &observations,
                events,
                journal,
            )
            .await;
        }
        if critic_repairs > MAX_CRITIC_REPAIRS {
            return repair_fallback_outcome(
                &session,
                &input,
                &trigger,
                plan.as_ref(),
                &observations,
                events,
                journal,
            )
            .await;
        }
        let decision = match model
            .advance(SessionModelTurn {
                session: session.clone(),
                trigger: trigger.clone(),
                assessment_at: input.assessment_at.clone(),
                prior_commitment_checkpoint: prior_commitment_checkpoint.clone(),
                wake_assessment: build_wake_assessment(
                    &session,
                    &trigger,
                    prior_commitment_checkpoint.as_ref(),
                    &observations,
                    assessment_at,
                ),
                plan: plan.clone(),
                available_tools: available_tools.clone(),
                observations: observations.clone(),
                repair_feedback: repair_feedback.clone(),
            })
            .await
        {
            Ok(decision) => decision,
            Err(AgentRuntimeError::InvalidFinal(reason)) => {
                repairs += 1;
                repair_feedback = vec![format!(
                    "The prior decision did not match the session contract: {reason}"
                )];
                continue;
            }
            Err(_) => {
                return repair_fallback_outcome(
                    &session,
                    &input,
                    &trigger,
                    plan.as_ref(),
                    &observations,
                    events,
                    journal,
                )
                .await;
            }
        };

        match decision {
            SessionModelDecision::EstablishPlan { plan: proposed } => {
                if critic_repairs > 0 {
                    record_operating_repair(
                        &mut repairs,
                        &mut repair_feedback,
                        "Claim review has started. The reviewed plan and evidence are frozen; revise only the final draft from that same evidence envelope.".into(),
                    );
                    continue;
                }
                if let Err(error) = validate_plan(&proposed, &available_tool_ids) {
                    record_operating_repair(&mut repairs, &mut repair_feedback, error.to_string());
                    continue;
                }
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && let Err(error) = validate_explicit_follow_through(&session, &proposed)
                {
                    record_operating_repair(&mut repairs, &mut repair_feedback, error.to_string());
                    continue;
                }
                if plan.as_ref() == Some(&proposed) {
                    record_operating_repair(
                        &mut repairs,
                        &mut repair_feedback,
                        "The research plan is already active. Invoke a selected tool or finish from the available evidence; establish another plan only when the evidence requires a material revision.".into(),
                    );
                    continue;
                }
                emit_event(
                    &session,
                    &input.assessment_at,
                    &mut events,
                    SessionEvent::PlanEstablished {
                        plan: proposed.clone(),
                    },
                    journal,
                )
                .await?;
                plan = Some(proposed);
                repairs = 0;
                repair_feedback.clear();
            }
            SessionModelDecision::InvokeTools { calls } => {
                if critic_repairs > 0 {
                    record_operating_repair(
                        &mut repairs,
                        &mut repair_feedback,
                        "Claim review has started. Tool use is frozen; revise only the final draft from the already observed evidence.".into(),
                    );
                    continue;
                }
                let Some(mut established) = plan.clone() else {
                    record_operating_repair(
                        &mut repairs,
                        &mut repair_feedback,
                        "Establish a typed research plan before invoking evidence tools.".into(),
                    );
                    continue;
                };
                if let Some(expanded) = expand_plan_for_read_calls(
                    &established,
                    &calls,
                    &descriptors,
                    &available_tool_ids,
                )? {
                    emit_event(
                        &session,
                        &input.assessment_at,
                        &mut events,
                        SessionEvent::PlanEstablished {
                            plan: expanded.clone(),
                        },
                        journal,
                    )
                    .await?;
                    plan = Some(expanded.clone());
                    established = expanded;
                }
                if matches!(trigger, SessionTurnTrigger::Wake { .. })
                    && calls.iter().any(|call| {
                        descriptors.get(&call.tool_id).is_some_and(|descriptor| {
                            descriptor.authority_class == ToolAuthorityClass::Actuate
                        })
                    })
                {
                    record_operating_repair(
                        &mut repairs,
                        &mut repair_feedback,
                        "Scheduled wakes cannot authorize external effects. Finish with the observed state and an exact prospective action that still requires fresh operator authorization.".into(),
                    );
                    continue;
                }
                let mut proposed_call_ids = call_ids.clone();
                let mut proposed_call_fingerprints = call_fingerprints.clone();
                if let Err(error) = validate_calls(
                    &calls,
                    &established,
                    &descriptors,
                    observations.len(),
                    &mut proposed_call_ids,
                    &mut proposed_call_fingerprints,
                ) {
                    record_operating_repair(&mut repairs, &mut repair_feedback, error.to_string());
                    continue;
                }
                call_ids = proposed_call_ids;
                call_fingerprints = proposed_call_fingerprints;
                if let Some(call) = calls.iter().find(|call| {
                    descriptors.get(&call.tool_id).is_some_and(|descriptor| {
                        descriptor.authority_class == ToolAuthorityClass::Actuate
                            && !has_effect_authorization(
                                &session,
                                &input,
                                call,
                                &consumed_approvals,
                            )
                    })
                }) {
                    let input_digest = call.input_digest();
                    emit_event(
                        &session,
                        &input.assessment_at,
                        &mut events,
                        SessionEvent::ApprovalRequested {
                            tool_id: call.tool_id.clone(),
                            input_digest: input_digest.clone(),
                        },
                        journal,
                    )
                    .await?;
                    return Ok(SessionTurnOutcome::ApprovalRequired {
                        request: ApprovalRequest {
                            approval_ref: format!(
                                "approval://agent-effect/{}",
                                input_digest.trim_start_matches("sha256:")
                            ),
                            tool_id: call.tool_id.clone(),
                            input_digest,
                            purpose: call.purpose.clone(),
                        },
                        events,
                    });
                }
                for call in &calls {
                    if descriptors.get(&call.tool_id).is_some_and(|descriptor| {
                        descriptor.authority_class == ToolAuthorityClass::Actuate
                    }) {
                        let approval = matching_effect_authorization(&session, &input, call)
                            .expect("authorization presence was checked before invocation");
                        if !consumed_approvals.insert(approval.approval_ref.clone()) {
                            return Err(AgentRuntimeError::InvalidToolCall(
                                "effect authorization was already consumed".into(),
                            ));
                        }
                    }
                }
                for call in &calls {
                    if let Some(descriptor) = descriptors.get(&call.tool_id)
                        && descriptor.authority_class == ToolAuthorityClass::Actuate
                    {
                        emit_event(
                            &session,
                            &input.assessment_at,
                            &mut events,
                            SessionEvent::EffectStarted {
                                call: call.clone(),
                                descriptor: descriptor.clone(),
                            },
                            journal,
                        )
                        .await?;
                    }
                }
                let results = join_all(
                    calls
                        .iter()
                        .map(|call| tools.invoke(&session, &input, call)),
                )
                .await;
                for (call, result) in calls.into_iter().zip(results) {
                    let descriptor = descriptors
                        .get(&call.tool_id)
                        .expect("tool descriptor was validated")
                        .clone();
                    let result = match result {
                        Ok(result) => result,
                        Err(_) if descriptor.authority_class == ToolAuthorityClass::Actuate => {
                            uncertain_effect_result(
                                &session.session_ref,
                                &input.request_id,
                                &call,
                                &input.assessment_at,
                            )
                        }
                        Err(_) => failed_tool_result(&session, &input, &call, assessment_at)?,
                    };
                    let observation = ToolObservation {
                        sequence: observations.len() + 1,
                        call,
                        descriptor,
                        result,
                    };
                    emit_event(
                        &session,
                        &input.assessment_at,
                        &mut events,
                        SessionEvent::ToolInvoked {
                            observation: observation.clone(),
                        },
                        journal,
                    )
                    .await?;
                    observations.push(observation);
                }
                repairs = 0;
                repair_feedback.clear();
            }
            SessionModelDecision::Finish { mut draft } => {
                materialize_planned_follow_through(
                    &session,
                    &trigger,
                    plan.as_ref(),
                    assessment_at,
                    &mut draft,
                )?;
                if !matches!(trigger, SessionTurnTrigger::Operator)
                    || plan
                        .as_ref()
                        .is_none_or(|plan| plan.follow_through.is_none())
                {
                    normalize_redundant_baseline_alerts(&session, &mut draft, &observations);
                }
                normalize_passive_wake_handback(&trigger, &mut draft);
                normalize_coverage_notice(&mut draft, &observations);
                if let Err(error) = validate_planned_follow_through_viability(
                    plan.as_ref(),
                    &observations,
                    assessment_at,
                ) {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                if let Err(error) = validate_commitment_baselines(
                    &session,
                    &draft,
                    plan.as_ref(),
                    &observations,
                    assessment_at,
                ) {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                if let Err(error) = validate_wake_completion(
                    &session,
                    &draft,
                    &trigger,
                    assessment_at,
                    &observations,
                ) {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                if let Err(error) = validate_plan_completion(plan.as_ref(), &draft) {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                if let Err(error) = validate_cross_turn_consistency(&session, &draft) {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                let validated =
                    match validate_grounded_draft(&session, &draft, &observations, assessment_at) {
                        Ok(validated) => validated,
                        Err(error) => {
                            record_draft_repair(
                                &mut rejected_operating_drafts,
                                &draft,
                                &mut repairs,
                                &mut repair_feedback,
                                error.to_string(),
                            );
                            continue;
                        }
                    };
                if let Err(error) = validate_effect_closure(&observations, &draft, assessment_at) {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                let review = match model
                    .review_message(ClaimReviewTurn {
                        session: session.clone(),
                        trigger: trigger.clone(),
                        prior_commitment_checkpoint: prior_commitment_checkpoint.clone(),
                        wake_assessment: build_wake_assessment(
                            &session,
                            &trigger,
                            prior_commitment_checkpoint.as_ref(),
                            &observations,
                            assessment_at,
                        ),
                        draft: draft.clone(),
                        observations: observations.clone(),
                    })
                    .await
                {
                    Ok(review) => review,
                    Err(_) => {
                        return repair_fallback_outcome(
                            &session,
                            &input,
                            &trigger,
                            plan.as_ref(),
                            &observations,
                            events,
                            journal,
                        )
                        .await;
                    }
                };
                let issues = match validate_message_review(&draft, &review) {
                    Ok(issues) => issues,
                    Err(_) => {
                        return repair_fallback_outcome(
                            &session,
                            &input,
                            &trigger,
                            plan.as_ref(),
                            &observations,
                            events,
                            journal,
                        )
                        .await;
                    }
                };
                if !issues.is_empty() {
                    let mut issue_signature = issues.clone();
                    issue_signature.sort();
                    issue_signature.dedup();
                    if !rejected_reviews.insert((message_digest(&draft.message), issue_signature)) {
                        critic_repairs = MAX_CRITIC_REPAIRS + 1;
                        repair_feedback = issues;
                        continue;
                    }
                    critic_repairs += 1;
                    repair_feedback = issues;
                    continue;
                }
                emit_event(
                    &session,
                    &input.assessment_at,
                    &mut events,
                    SessionEvent::DraftProduced {
                        request_id: input.request_id.clone(),
                        draft: draft.clone(),
                    },
                    journal,
                )
                .await?;
                for update in &draft.memory_updates {
                    emit_event(
                        &session,
                        &input.assessment_at,
                        &mut events,
                        SessionEvent::MemoryRecorded {
                            update: update.clone(),
                        },
                        journal,
                    )
                    .await?;
                }
                return Ok(SessionTurnOutcome::PendingDelivery {
                    lane: plan
                        .as_ref()
                        .map_or(ExecutionLane::Converse, |plan| plan.lane),
                    delivery: draft.delivery,
                    markdown: validated.markdown,
                    final_state: draft.state,
                    evidence_atom_refs: validated.evidence_atom_refs,
                    mission: draft.mission,
                    events,
                });
            }
        }
    }
    repair_fallback_outcome(
        &session,
        &input,
        &trigger,
        plan.as_ref(),
        &observations,
        events,
        journal,
    )
    .await
}

async fn repair_fallback_outcome(
    session: &AgentSession,
    input: &SessionTurnInput,
    trigger: &SessionTurnTrigger,
    plan: Option<&ResearchPlan>,
    observations: &[ToolObservation],
    mut events: Vec<SessionEventRecord>,
    journal: &dyn SessionJournal,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    let assessment_at = OffsetDateTime::parse(&input.assessment_at, &Rfc3339)
        .map_err(|_| AgentRuntimeError::InvalidRequest("assessment_at is invalid".into()))?;
    let mut mission = session.mission.clone();
    let uncertain_effect = observations.iter().find_map(|observation| {
        if observation.descriptor.authority_class != ToolAuthorityClass::Actuate
            || observation.result.state != ToolResultState::OutcomeUnknown
            || observation.result.summary.len() > 1_500
            || observation.result.summary.trim().is_empty()
        {
            return None;
        }
        let atom_ref = observation
            .result
            .evidence
            .iter()
            .flat_map(|evidence| &evidence.atoms)
            .find(|atom| atom.atom_ref.ends_with("#tool-outcome"))?
            .atom_ref
            .clone();
        Some((observation.result.summary.trim().to_owned(), atom_ref))
    });
    let supported = observations.iter().find_map(|observation| {
        if !matches!(
            observation.result.state,
            ToolResultState::Succeeded | ToolResultState::Partial
        ) || observation.result.summary.len() > 1_500
            || observation.result.summary.trim().is_empty()
            || observation
                .result
                .summary
                .chars()
                .any(|character| character.is_control() && character != '\n')
        {
            return None;
        }
        let atom_ref = observation
            .result
            .evidence
            .iter()
            .flat_map(|evidence| &evidence.atoms)
            .find(|atom| atom.atom_ref.ends_with("#tool-outcome"))?
            .atom_ref
            .clone();
        Some((observation.result.summary.trim().to_owned(), atom_ref))
    });
    let failed = observations.iter().rev().find_map(|observation| {
        if observation.result.state != ToolResultState::Failed
            || observation.result.summary.len() > 1_500
            || observation.result.summary.trim().is_empty()
            || observation
                .result
                .summary
                .chars()
                .any(|character| character.is_control() && character != '\n')
        {
            return None;
        }
        let atom_ref = observation
            .result
            .evidence
            .iter()
            .flat_map(|evidence| &evidence.atoms)
            .find(|atom| atom.atom_ref.ends_with("#tool-outcome"))?
            .atom_ref
            .clone();
        Some((observation.result.summary.trim().to_owned(), atom_ref))
    });
    let rescheduled_wake = match trigger {
        SessionTurnTrigger::Wake { commitment_ref, .. } if uncertain_effect.is_none() => {
            let next_wake_at = assessment_at
                .checked_add(Duration::minutes(5))
                .ok_or_else(|| {
                    AgentRuntimeError::InvalidFinal(
                        "the repair fallback wake time overflowed".into(),
                    )
                })?
                .format(&Rfc3339)
                .map_err(|_| {
                    AgentRuntimeError::InvalidFinal(
                        "the repair fallback wake time could not be formatted".into(),
                    )
                })?;
            let commitment = mission
                .commitments
                .iter_mut()
                .find(|commitment| commitment.commitment_ref == *commitment_ref)
                .ok_or_else(|| {
                    AgentRuntimeError::InvalidFinal(
                        "the repair fallback wake has no exact durable commitment".into(),
                    )
                })?;
            commitment.status = CommitmentStatus::Waiting;
            commitment.blocker = Some(
                "This check could not produce a fully grounded response; a bounded retry is scheduled."
                    .into(),
            );
            commitment.wake_at = Some(next_wake_at.clone());
            mission.status = SessionStatus::WaitingForExternal;
            Some((commitment_ref.clone(), next_wake_at))
        }
        SessionTurnTrigger::Wake { commitment_ref, .. } => {
            if let Some(commitment) = mission
                .commitments
                .iter_mut()
                .find(|commitment| commitment.commitment_ref == *commitment_ref)
            {
                commitment.status = CommitmentStatus::Blocked;
                commitment.blocker = Some(
                    "The scheduled check encountered an external effect with an unknown outcome."
                        .into(),
                );
                commitment.wake_at = None;
                mission.status = SessionStatus::Blocked;
            }
            None
        }
        SessionTurnTrigger::Operator if uncertain_effect.is_none() => plan
            .and_then(|plan| plan.follow_through.as_ref())
            .map(|follow_through| {
                let commitment = planned_commitment(follow_through, assessment_at)?;
                let wake_at = commitment
                    .wake_at
                    .clone()
                    .expect("a planned commitment always has a wake time");
                mission
                    .commitments
                    .retain(|candidate| candidate.commitment_ref != follow_through.commitment_ref);
                mission.commitments.push(commitment);
                mission.status = SessionStatus::WaitingForExternal;
                Ok((follow_through.commitment_ref.clone(), wake_at))
            })
            .transpose()?,
        SessionTurnTrigger::Operator => None,
    };
    let coverage_notice = if uncertain_effect.is_some() {
        mission.status = SessionStatus::Blocked;
        "Coverage gap: The external action outcome is unknown. Reconcile the provider state with a fresh observation before another effect. I did not retry the action or record a new follow-up."
    } else if rescheduled_wake.is_some() && supported.is_some() {
        "Coverage gap: This check is partial, so the acceptance condition remains unverified."
    } else if rescheduled_wake.is_some() && failed.is_some() {
        "Coverage gap: The source read failed, so the acceptance condition remains unverified."
    } else if rescheduled_wake.is_some() {
        "Coverage gap: This check returned no authoritative observation, so the acceptance condition remains unverified."
    } else if supported.is_some() {
        "Coverage gap: The available evidence does not support the full requested conclusion. No action or future follow-up was recorded."
    } else if failed.is_some() {
        "Coverage gap: The source read failed. I did not evaluate the requested condition, execute an action, or record a new follow-up."
    } else {
        "Coverage gap: No current authoritative observation was obtained. I did not evaluate the requested condition, execute an action, or record a new follow-up."
    }
    .to_owned();
    let (state, mut message, mut claims) = if let Some((summary, atom_ref)) = uncertain_effect {
        let notice = format!("\n\n{coverage_notice}");
        (
            FinalState::Blocked,
            format!("{summary}{notice}"),
            vec![
                GroundedClaim {
                    claim_ref: format!("fallback-observation:{}", input.request_id),
                    planned_claim_ref: None,
                    text: summary,
                    required_for_answer: true,
                    content: ClaimContent::Observation {
                        atom_refs: vec![atom_ref],
                    },
                },
                GroundedClaim {
                    claim_ref: format!("fallback-boundary:{}", input.request_id),
                    planned_claim_ref: None,
                    text: notice,
                    required_for_answer: true,
                    content: ClaimContent::StableExplanation,
                },
            ],
        )
    } else if let Some((summary, atom_ref)) = supported {
        let notice = format!("\n\n{coverage_notice}");
        (
            FinalState::Partial,
            format!("{summary}{notice}"),
            vec![
                GroundedClaim {
                    claim_ref: format!("fallback-observation:{}", input.request_id),
                    planned_claim_ref: None,
                    text: summary,
                    required_for_answer: true,
                    content: ClaimContent::Observation {
                        atom_refs: vec![atom_ref],
                    },
                },
                GroundedClaim {
                    claim_ref: format!("fallback-boundary:{}", input.request_id),
                    planned_claim_ref: None,
                    text: notice,
                    required_for_answer: true,
                    content: ClaimContent::StableExplanation,
                },
            ],
        )
    } else if let Some((summary, atom_ref)) = failed {
        let notice = format!("\n\n{coverage_notice}");
        (
            FinalState::Blocked,
            format!("{summary}{notice}"),
            vec![
                GroundedClaim {
                    claim_ref: format!("fallback-observation:{}", input.request_id),
                    planned_claim_ref: None,
                    text: summary,
                    required_for_answer: true,
                    content: ClaimContent::Observation {
                        atom_refs: vec![atom_ref],
                    },
                },
                GroundedClaim {
                    claim_ref: format!("fallback-boundary:{}", input.request_id),
                    planned_claim_ref: None,
                    text: notice,
                    required_for_answer: true,
                    content: ClaimContent::StableExplanation,
                },
            ],
        )
    } else {
        (
            FinalState::Blocked,
            coverage_notice.clone(),
            vec![GroundedClaim {
                claim_ref: format!("fallback-boundary:{}", input.request_id),
                planned_claim_ref: None,
                text: coverage_notice.clone(),
                required_for_answer: true,
                content: ClaimContent::StableExplanation,
            }],
        )
    };
    if let Some((commitment_ref, wake_at)) = rescheduled_wake {
        let follow_up = format!("\n\nI’ll check again at {wake_at}.");
        message.push_str(&follow_up);
        claims.push(GroundedClaim {
            claim_ref: format!("fallback-commitment:{}", input.request_id),
            planned_claim_ref: None,
            text: follow_up,
            required_for_answer: true,
            content: ClaimContent::Commitment { commitment_ref },
        });
    }
    let draft = GroundedDraft {
        state,
        delivery: DeliveryDisposition::Visible,
        message,
        claims,
        coverage_notice: Some(coverage_notice),
        question: None,
        mission,
        memory_updates: Vec::new(),
        presentation_ready: true,
    };
    let validated = validate_grounded_draft(session, &draft, observations, assessment_at)?;
    emit_event(
        session,
        &input.assessment_at,
        &mut events,
        SessionEvent::DraftProduced {
            request_id: input.request_id.clone(),
            draft: draft.clone(),
        },
        journal,
    )
    .await?;
    Ok(SessionTurnOutcome::PendingDelivery {
        lane: plan.map_or(ExecutionLane::Converse, |plan| plan.lane),
        delivery: DeliveryDisposition::Visible,
        markdown: validated.markdown,
        final_state: state,
        evidence_atom_refs: validated.evidence_atom_refs,
        mission: draft.mission,
        events,
    })
}

fn expand_plan_for_read_calls(
    plan: &ResearchPlan,
    calls: &[ToolCall],
    descriptors: &BTreeMap<String, ToolDescriptor>,
    available_tool_ids: &[String],
) -> Result<Option<ResearchPlan>, AgentRuntimeError> {
    let missing = calls
        .iter()
        .filter(|call| !plan.selected_tools.contains(&call.tool_id))
        .map(|call| call.tool_id.clone())
        .collect::<BTreeSet<_>>();
    if missing.is_empty()
        || missing.iter().any(|tool_id| {
            descriptors.get(tool_id).is_none_or(|descriptor| {
                descriptor.authority_class == ToolAuthorityClass::Actuate
                    || descriptor.effect_class != ToolEffectClass::Read
            })
        })
    {
        return Ok(None);
    }
    let mut expanded = plan.clone();
    if expanded.lane == ExecutionLane::Lookup {
        expanded.lane = ExecutionLane::Investigate;
    }
    for tool_id in missing {
        expanded.selected_tools.push(tool_id.clone());
        for claim in &mut expanded.claims {
            if !claim.source_candidates.contains(&tool_id) {
                claim.source_candidates.push(tool_id.clone());
            }
        }
    }
    validate_plan(&expanded, available_tool_ids)?;
    Ok(Some(expanded))
}

fn wake_research_plan(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
) -> Option<ResearchPlan> {
    let SessionTurnTrigger::Wake { commitment_ref, .. } = trigger else {
        return None;
    };
    let commitment = session
        .mission
        .commitments
        .iter()
        .find(|commitment| commitment.commitment_ref == *commitment_ref)?;
    if commitment.required_tool_ids.is_empty() {
        return None;
    }
    let claims = vec![PlannedClaim {
        claim_ref: format!("wake-claim:{commitment_ref}:verification"),
        question: commitment
            .verification
            .clone()
            .or_else(|| commitment.acceptance_criteria.first().cloned())
            .unwrap_or_else(|| "Determine the current commitment state.".into()),
        required: true,
        source_candidates: commitment.required_tool_ids.clone(),
    }];
    let mut stop_conditions = commitment.acceptance_criteria.clone();
    if let Some(verification) = &commitment.verification {
        stop_conditions.push(verification.clone());
    }
    Some(ResearchPlan {
        decision: format!("Execute scheduled commitment {commitment_ref}."),
        lane: ExecutionLane::Investigate,
        resolved_entities: vec![commitment_ref.clone()],
        claims,
        selected_tools: commitment.required_tool_ids.clone(),
        stop_conditions,
        user_visible_work: Vec::new(),
        follow_through: None,
    })
}

fn validate_turn_input(
    session: &AgentSession,
    input: &SessionTurnInput,
) -> Result<(), AgentRuntimeError> {
    if !bounded(&input.request_id, MAX_TEXT_BYTES)
        || !bounded(&input.actor_ref, MAX_TEXT_BYTES)
        || OffsetDateTime::parse(&input.assessment_at, &Rfc3339).is_err()
    {
        return Err(AgentRuntimeError::InvalidRequest(
            "session turn identity or assessment time is invalid".into(),
        ));
    }
    match &input.trigger {
        SessionTurnTrigger::Operator => {
            let latest = session.messages.last().ok_or_else(|| {
                AgentRuntimeError::InvalidRequest(
                    "operator turn requires a queued user message".into(),
                )
            })?;
            if latest.role != SessionMessageRole::User || latest.actor_ref != input.actor_ref {
                return Err(AgentRuntimeError::InvalidRequest(
                    "turn actor does not match the latest queued user message".into(),
                ));
            }
        }
        SessionTurnTrigger::Wake {
            commitment_ref,
            occurrence_ref,
        } => {
            if input.actor_ref != "cerebro-scheduler"
                || !bounded(commitment_ref, MAX_TEXT_BYTES)
                || !bounded(occurrence_ref, MAX_TEXT_BYTES)
                || !session.events.iter().any(|event| {
                    matches!(
                        &event.event,
                        SessionEvent::WakeTriggered {
                            request_id,
                            commitment_ref: recorded_commitment,
                            occurrence_ref: recorded_occurrence,
                            ..
                        } if request_id == &input.request_id
                            && recorded_commitment == commitment_ref
                            && recorded_occurrence == occurrence_ref
                    )
                })
            {
                return Err(AgentRuntimeError::InvalidRequest(
                    "wake trigger is not bound to its durable scheduler event".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn session_turn_request_text(
    session: &AgentSession,
    input: &SessionTurnInput,
) -> Result<String, AgentRuntimeError> {
    match &input.trigger {
        SessionTurnTrigger::Operator => session
            .messages
            .last()
            .filter(|message| message.role == SessionMessageRole::User)
            .map(|message| message.text.clone())
            .ok_or_else(|| {
                AgentRuntimeError::InvalidRequest("operator turn has no queued user request".into())
            }),
        SessionTurnTrigger::Wake { commitment_ref, .. } => {
            let commitment = session
                .mission
                .commitments
                .iter()
                .find(|commitment| commitment.commitment_ref == *commitment_ref)
                .ok_or_else(|| {
                    AgentRuntimeError::InvalidRequest(
                        "wake turn has no matching durable commitment".into(),
                    )
                })?;
            Ok(format!(
                "Resume the scheduled commitment {}. Next action: {} Acceptance criteria: {} Verification: {}",
                commitment.commitment_ref,
                commitment.next_action.as_deref().unwrap_or("not recorded"),
                commitment.acceptance_criteria.join("; "),
                commitment.verification.as_deref().unwrap_or("not recorded"),
            ))
        }
    }
}

fn validate_wake_completion(
    session: &AgentSession,
    draft: &GroundedDraft,
    trigger: &SessionTurnTrigger,
    assessment_at: OffsetDateTime,
    observations: &[ToolObservation],
) -> Result<(), AgentRuntimeError> {
    let SessionTurnTrigger::Wake { commitment_ref, .. } = trigger else {
        if draft.delivery != DeliveryDisposition::Visible {
            return Err(AgentRuntimeError::InvalidFinal(
                "operator turns must produce a visible response".into(),
            ));
        }
        return Ok(());
    };
    if draft.delivery == DeliveryDisposition::Silent
        && (draft.state != FinalState::Answered
            || draft.coverage_notice.is_some()
            || draft.question.is_some())
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "routine nonterminal wake progress must use delivery=silent, state=answered, coverage_notice=null, question=null, preserve the exact commitment, and set a later wake_at"
                .into(),
        ));
    }
    let current = session
        .mission
        .commitments
        .iter()
        .find(|commitment| commitment.commitment_ref == *commitment_ref)
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "the wake does not match a current durable commitment".into(),
            )
        })?;
    if current.owner != WorkOwner::Cerebro
        || matches!(
            current.status,
            CommitmentStatus::Blocked | CommitmentStatus::Completed | CommitmentStatus::Cancelled
        )
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "the wake commitment is not active Cerebro-owned work".into(),
        ));
    }
    let due_at = current
        .wake_at
        .as_deref()
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal("the wake commitment has no due time".into())
        })
        .and_then(|value| {
            OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                AgentRuntimeError::InvalidFinal("the wake commitment due time is invalid".into())
            })
        })?;
    if due_at > assessment_at {
        return Err(AgentRuntimeError::InvalidFinal(
            "the wake commitment is not due yet".into(),
        ));
    }
    let checkpoint = prior_commitment_checkpoint(session, trigger);
    let missing_required_tools = current
        .required_tool_ids
        .iter()
        .filter(|tool_id| {
            let expected_input_digest = checkpoint.as_ref().and_then(|checkpoint| {
                checkpoint
                    .observations
                    .iter()
                    .rev()
                    .find(|observation| observation.tool_id.as_str() == tool_id.as_str())
                    .map(|observation| observation.input_digest.as_str())
            });
            !observations.iter().any(|observation| {
                observation.call.tool_id.as_str() == tool_id.as_str()
                    && expected_input_digest
                        .is_none_or(|expected| observation.call.input_digest() == expected)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    if !missing_required_tools.is_empty() {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "scheduled wake must invoke its required tools with the exact prior completed-check input before finishing: {}. Copy the matching tool input from prior_commitment_checkpoint.observations.",
            missing_required_tools.join(", ")
        )));
    }
    let unhealthy_required_tools = current
        .required_tool_ids
        .iter()
        .filter(|tool_id| {
            !observations.iter().any(|observation| {
                observation.call.tool_id.as_str() == tool_id.as_str()
                    && observation_is_complete_and_fresh(observation, assessment_at)
            })
        })
        .cloned()
        .collect::<Vec<_>>();
    if !unhealthy_required_tools.is_empty()
        && (draft.delivery != DeliveryDisposition::Visible || draft.state == FinalState::Answered)
    {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "failed, incomplete, or stale required observations must produce a visible partial or blocked update: {}",
            unhealthy_required_tools.join(", ")
        )));
    }
    let next = draft
        .mission
        .commitments
        .iter()
        .find(|commitment| commitment.commitment_ref == *commitment_ref)
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "a wake must close or explicitly reschedule its exact commitment".into(),
            )
        })?;
    if next.required_tool_ids != current.required_tool_ids
        || next.attention_policy != current.attention_policy
        || next.acceptance_criteria != current.acceptance_criteria
        || next.verification != current.verification
    {
        let expected = serde_json::to_string(current)
            .unwrap_or_else(|_| "the current durable commitment".into());
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "a scheduled wake cannot rewrite its executor contract. Copy required_tool_ids, attention_policy, acceptance_criteria, and verification exactly from this durable commitment, including when closing it: {expected}"
        )));
    }
    let accepted = unhealthy_required_tools.is_empty()
        && current.attention_policy.as_ref().is_some_and(|policy| {
            !policy.acceptance_all.is_empty()
                && policy
                    .acceptance_all
                    .iter()
                    .all(|condition| observation_condition_matches(condition, observations))
        });
    let alert = !accepted
        && current.attention_policy.as_ref().is_some_and(|policy| {
            policy
                .alert_any
                .iter()
                .any(|condition| observation_condition_matches(condition, observations))
        });
    let closed = matches!(
        next.status,
        CommitmentStatus::Completed | CommitmentStatus::Cancelled
    );
    if closed {
        if !accepted {
            return Err(AgentRuntimeError::InvalidFinal(
                "the commitment cannot close before its typed acceptance condition is satisfied"
                    .into(),
            ));
        }
        if draft.delivery != DeliveryDisposition::Visible {
            return Err(AgentRuntimeError::InvalidFinal(
                "a closed wake commitment must notify the operator".into(),
            ));
        }
        if next.wake_at.is_some() {
            return Err(AgentRuntimeError::InvalidFinal(
                "a closed wake commitment cannot retain a due time".into(),
            ));
        }
        return Ok(());
    }
    if unhealthy_required_tools.is_empty() {
        let required_delivery = if accepted || alert {
            DeliveryDisposition::Visible
        } else {
            DeliveryDisposition::Silent
        };
        if draft.delivery != required_delivery {
            let exact_state = match required_delivery {
                DeliveryDisposition::Silent => {
                    "Set delivery=silent, state=answered, coverage_notice=null, question=null, preserve the exact commitment, and set a later wake_at."
                }
                DeliveryDisposition::Visible => {
                    "Set delivery=visible and report the current alert state while preserving and rescheduling the exact commitment."
                }
            };
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "the runtime attention policy requires {:?} delivery for this nonterminal wake. {exact_state}",
                required_delivery
            )));
        }
    }
    let next_wake = next
        .wake_at
        .as_deref()
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "an unfinished wake commitment requires a replacement due time".into(),
            )
        })?;
    if next_wake <= assessment_at {
        return Err(AgentRuntimeError::InvalidFinal(
            "a rescheduled wake commitment must move to a future due time".into(),
        ));
    }
    Ok(())
}

fn observation_condition_matches(
    condition: &ObservationCondition,
    observations: &[ToolObservation],
) -> bool {
    observations.iter().any(|observation| {
        observation.call.tool_id == condition.tool_id
            && observation.result.state == ToolResultState::Succeeded
            && observation.result.data.pointer(&condition.data_pointer) == Some(&condition.equals)
    })
}

fn build_wake_assessment(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
    checkpoint: Option<&CommitmentCheckpoint>,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
) -> Option<WakeAssessment> {
    let SessionTurnTrigger::Wake { commitment_ref, .. } = trigger else {
        return None;
    };
    let commitment = session
        .mission
        .commitments
        .iter()
        .find(|commitment| commitment.commitment_ref == *commitment_ref)?;
    let current_required = commitment
        .required_tool_ids
        .iter()
        .filter_map(|tool_id| {
            observations
                .iter()
                .rev()
                .find(|observation| observation.call.tool_id == *tool_id)
        })
        .collect::<Vec<_>>();
    let required_observations_present =
        current_required.len() == commitment.required_tool_ids.len();
    let required_observations_healthy = required_observations_present
        && current_required
            .iter()
            .all(|observation| observation_is_complete_and_fresh(observation, assessment_at));
    let acceptance_met = required_observations_healthy
        && commitment.attention_policy.as_ref().is_some_and(|policy| {
            !policy.acceptance_all.is_empty()
                && policy
                    .acceptance_all
                    .iter()
                    .all(|condition| observation_condition_matches(condition, observations))
        });
    let matched_attention_signals = commitment
        .attention_policy
        .as_ref()
        .map(|policy| {
            policy
                .alert_any
                .iter()
                .filter(|condition| {
                    observations.iter().any(|observation| {
                        observation.call.tool_id == condition.tool_id
                            && observation.result.data.pointer(&condition.data_pointer)
                                == Some(&condition.equals)
                    })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    let mut scalar_comparisons = Vec::new();
    for current_observation in current_required {
        let input_digest = current_observation.call.input_digest();
        let prior = checkpoint.and_then(|checkpoint| {
            checkpoint.observations.iter().rev().find(|prior| {
                prior.tool_id == current_observation.call.tool_id
                    && prior.input_digest == input_digest
            })
        });
        let mut previous = BTreeMap::new();
        if let Some(prior) = prior {
            collect_scalar_json_pointers(&prior.data, "", &mut previous);
        }
        let mut current = BTreeMap::new();
        collect_scalar_json_pointers(&current_observation.result.data, "", &mut current);
        let pointers = previous
            .keys()
            .chain(current.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        for data_pointer in pointers.into_iter().take(64) {
            let previous_value = previous.get(&data_pointer).cloned();
            let current_value = current.get(&data_pointer).cloned();
            let relation = match (&previous_value, &current_value) {
                (None, Some(_)) => WakeScalarRelation::AddedToCurrentRead,
                (Some(previous), Some(current)) if previous == current => {
                    WakeScalarRelation::Unchanged
                }
                (Some(_), Some(_)) => WakeScalarRelation::Changed,
                (Some(_), None) => WakeScalarRelation::NotReturnedByCurrentRead,
                (None, None) => continue,
            };
            scalar_comparisons.push(WakeScalarComparison {
                tool_id: current_observation.call.tool_id.clone(),
                input_digest: input_digest.clone(),
                data_pointer,
                previous: previous_value,
                current: current_value,
                relation,
            });
        }
    }

    Some(WakeAssessment {
        commitment_ref: commitment_ref.clone(),
        required_observations_present,
        required_observations_healthy,
        acceptance_met,
        matched_attention_signals,
        scalar_comparisons,
    })
}

fn collect_scalar_json_pointers(value: &Value, prefix: &str, output: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(entries) => {
            for (key, value) in entries {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                collect_scalar_json_pointers(value, &format!("{prefix}/{escaped}"), output);
            }
        }
        Value::Array(_) | Value::Null => {}
        _ if !prefix.is_empty() => {
            output.insert(prefix.to_owned(), value.clone());
        }
        _ => {}
    }
}

fn validate_commitment_baselines(
    session: &AgentSession,
    draft: &GroundedDraft,
    plan: Option<&ResearchPlan>,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
) -> Result<(), AgentRuntimeError> {
    for commitment in draft.mission.commitments.iter().filter(|commitment| {
        commitment.owner == WorkOwner::Cerebro
            && !matches!(
                commitment.status,
                CommitmentStatus::Blocked
                    | CommitmentStatus::Completed
                    | CommitmentStatus::Cancelled
            )
            && session
                .mission
                .commitments
                .iter()
                .find(|current| current.commitment_ref == commitment.commitment_ref)
                .is_none_or(|current| {
                    current.required_tool_ids != commitment.required_tool_ids
                        || current.acceptance_criteria != commitment.acceptance_criteria
                        || current.attention_policy != commitment.attention_policy
                        || current.verification != commitment.verification
                })
    }) {
        for tool_id in &commitment.required_tool_ids {
            if plan.is_none_or(|plan| !plan.selected_tools.contains(tool_id)) {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "the new or changed commitment requires {tool_id}, but the active plan does not select that tool"
                )));
            }
            if !observations.iter().any(|observation| {
                observation.call.tool_id == *tool_id
                    && observation_is_complete_and_fresh(observation, assessment_at)
            }) {
                let last_state = observations
                    .iter()
                    .rev()
                    .find(|observation| observation.call.tool_id == *tool_id)
                    .map(|observation| {
                        format!("; its last result was {:?}", observation.result.state)
                    })
                    .unwrap_or_default();
                let successful_alternatives = observations
                    .iter()
                    .filter(|observation| {
                        observation.call.tool_id != *tool_id
                            && observation_is_complete_and_fresh(observation, assessment_at)
                    })
                    .map(|observation| observation.call.tool_id.clone())
                    .collect::<BTreeSet<_>>();
                let revision = if successful_alternatives.is_empty() {
                    "Establish a materially revised plan selecting another available read, invoke it for a fresh baseline, and bind follow-through to that successful authority."
                        .into()
                } else {
                    format!(
                        "Fresh successful alternatives are already observed: {}. Return establish_plan now, preserve the commitment identity and acceptance criteria, and bind required_tool_ids to the exact successful authority that supports the follow-through.",
                        successful_alternatives
                            .into_iter()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "the new or changed commitment requires {tool_id}, but this turn has no successful, complete, fresh baseline observation from that tool{last_state}. Do not finish with this executor contract. {revision}"
                )));
            }
        }
        if let Some(policy) = &commitment.attention_policy {
            if policy
                .acceptance_all
                .iter()
                .all(|condition| observation_condition_matches(condition, observations))
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "the new commitment's typed acceptance condition is already satisfied by its baseline; finish the work instead of scheduling it"
                        .into(),
                ));
            }
            let matching_baseline_alerts = policy
                .alert_any
                .iter()
                .filter(|condition| observation_condition_matches(condition, observations))
                .collect::<Vec<_>>();
            if !matching_baseline_alerts.is_empty() {
                let matching = serde_json::to_string(&matching_baseline_alerts)
                    .unwrap_or_else(|_| "the matching alert conditions".into());
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "the new commitment has alert_any conditions already true at baseline: {matching}. Remove those baseline-matching alerts. Put a desired future success value in acceptance_all; keep alert_any only for a regression, conflict, stale, or mismatch value that is not true now."
                )));
            }
            let covered = policy
                .acceptance_all
                .iter()
                .chain(&policy.alert_any)
                .map(|condition| (condition.tool_id.as_str(), condition.data_pointer.as_str()))
                .collect::<BTreeSet<_>>();
            for observation in observations.iter().filter(|observation| {
                commitment
                    .required_tool_ids
                    .contains(&observation.call.tool_id)
            }) {
                let mut false_signals = Vec::new();
                collect_false_boolean_pointers(&observation.result.data, "", &mut false_signals);
                if let Some(pointer) = false_signals.into_iter().find(|pointer| {
                    !covered.contains(&(observation.call.tool_id.as_str(), pointer.as_str()))
                }) {
                    return Err(AgentRuntimeError::InvalidFinal(format!(
                        "the new commitment's typed attention policy does not classify false baseline boolean signal {}{}. Cover this pointer with equals=true in acceptance_all when true is the desired completion state, or equals=true in alert_any when true is a future regression, conflict, stale, or mismatch signal. Do not use equals=false because the baseline already matches it.",
                        observation.call.tool_id, pointer
                    )));
                }
            }
        }
    }
    Ok(())
}

fn normalize_redundant_baseline_alerts(
    session: &AgentSession,
    draft: &mut GroundedDraft,
    observations: &[ToolObservation],
) {
    for commitment in draft.mission.commitments.iter_mut().filter(|commitment| {
        commitment.owner == WorkOwner::Cerebro
            && !matches!(
                commitment.status,
                CommitmentStatus::Blocked
                    | CommitmentStatus::Completed
                    | CommitmentStatus::Cancelled
            )
            && session
                .mission
                .commitments
                .iter()
                .all(|current| current.commitment_ref != commitment.commitment_ref)
    }) {
        let Some(policy) = commitment.attention_policy.as_mut() else {
            continue;
        };
        let acceptance_targets = policy
            .acceptance_all
            .iter()
            .map(|condition| {
                (
                    condition.tool_id.clone(),
                    condition.data_pointer.clone(),
                    condition.equals.clone(),
                )
            })
            .collect::<Vec<_>>();
        policy.alert_any.retain(|alert| {
            let baseline_matches = observation_condition_matches(alert, observations);
            let acceptance_replaces_baseline =
                acceptance_targets
                    .iter()
                    .any(|(tool_id, data_pointer, equals)| {
                        tool_id == &alert.tool_id
                            && data_pointer == &alert.data_pointer
                            && equals != &alert.equals
                    });
            !(baseline_matches && acceptance_replaces_baseline)
        });
    }
}

fn normalize_coverage_notice(draft: &mut GroundedDraft, _observations: &[ToolObservation]) {
    if !matches!(draft.state, FinalState::Partial | FinalState::Blocked) {
        return;
    }
    let existing = draft
        .coverage_notice
        .as_deref()
        .map(str::trim)
        .filter(|notice| !notice.is_empty())
        .map(str::to_owned);
    if let Some(existing) = existing.filter(|notice| draft.message.contains(notice)) {
        draft.coverage_notice = Some(existing);
        return;
    }
    if let Some(visible_boundary) = visible_coverage_boundary(&draft.message, draft.state) {
        draft.coverage_notice = Some(visible_boundary);
        return;
    }
    let notice: String = match draft.state {
        FinalState::Partial => {
            "Coverage gap: The requested conclusion remains only partially supported.".into()
        }
        FinalState::Blocked => {
            "Coverage gap: The requested conclusion is blocked by missing authoritative evidence."
                .into()
        }
        _ => unreachable!("coverage normalization is restricted to partial and blocked drafts"),
    };
    draft.coverage_notice = Some(notice.clone());
    if !draft.message.contains(&notice) {
        let visible_notice = format!("\n\n{notice}");
        draft.message.push_str(&visible_notice);
        draft.claims.push(GroundedClaim {
            claim_ref: format!("claim:normalized-coverage:{}", draft.claims.len() + 1),
            planned_claim_ref: None,
            text: visible_notice,
            required_for_answer: true,
            content: ClaimContent::StableExplanation,
        });
    }
}

fn visible_coverage_boundary(message: &str, state: FinalState) -> Option<String> {
    let preferred_markers: &[&str] = match state {
        FinalState::Partial => &[
            "not yet decision-grade",
            "not decision-grade",
            "cannot yet",
            "remains unverified",
            "remains incomplete",
            "is stale",
            "does not count",
            "missing",
        ],
        FinalState::Blocked => &[
            "could not",
            "cannot",
            "blocked",
            "unavailable",
            "missing",
            "failed",
            "unknown",
        ],
        _ => return None,
    };
    let sentences = message
        .split_inclusive(['.', '!', '?'])
        .map(str::trim)
        .filter(|sentence| !sentence.is_empty() && sentence.len() <= 800)
        .collect::<Vec<_>>();
    preferred_markers.iter().find_map(|marker| {
        sentences
            .iter()
            .find(|sentence| sentence.to_ascii_lowercase().contains(marker))
            .map(|sentence| (*sentence).to_owned())
    })
}

fn normalize_passive_wake_handback(trigger: &SessionTurnTrigger, draft: &mut GroundedDraft) {
    if !matches!(trigger, SessionTurnTrigger::Wake { .. }) {
        return;
    }
    const PASSIVE_HANDBACKS: [&str; 3] = [
        "\n\nLet me know if you want to adjust the approach.",
        " Let me know if you want to adjust the approach.",
        "Let me know if you want to adjust the approach.",
    ];
    for claim in &mut draft.claims {
        for handback in PASSIVE_HANDBACKS {
            claim.text = claim.text.replace(handback, "");
        }
    }
    draft.claims.retain(|claim| !claim.text.is_empty());
    draft.message = draft
        .claims
        .iter()
        .map(|claim| claim.text.as_str())
        .collect();
}

fn collect_false_boolean_pointers(value: &Value, prefix: &str, output: &mut Vec<String>) {
    match value {
        Value::Bool(false) if !prefix.is_empty() => output.push(prefix.to_owned()),
        Value::Object(object) => {
            for (key, value) in object {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                collect_false_boolean_pointers(value, &format!("{prefix}/{escaped}"), output);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_false_boolean_pointers(value, &format!("{prefix}/{index}"), output);
            }
        }
        _ => {}
    }
}

fn observation_is_complete_and_fresh(
    observation: &ToolObservation,
    assessment_at: OffsetDateTime,
) -> bool {
    observation.result.state == ToolResultState::Succeeded
        && observation.result.evidence.iter().any(|evidence| {
            evidence.complete
                && evidence.fresh_until.as_deref().is_some_and(|fresh_until| {
                    OffsetDateTime::parse(fresh_until, &Rfc3339)
                        .is_ok_and(|fresh_until| fresh_until >= assessment_at)
                })
        })
}

fn resume_turn_state(
    session: &AgentSession,
    request_id: &str,
) -> (bool, Option<ResearchPlan>, Vec<ToolObservation>) {
    let Some(started_index) = session.events.iter().rposition(|event| {
        matches!(
            &event.event,
            SessionEvent::TurnStarted {
                request_id: started,
            } if started == request_id
        )
    }) else {
        return (false, None, Vec::new());
    };
    if session.events[started_index..].iter().any(|event| {
        matches!(
            &event.event,
            SessionEvent::TurnCompleted {
                request_id: completed,
                ..
            } if completed == request_id
        )
    }) {
        return (false, None, Vec::new());
    }
    let mut plan = None;
    let mut observations = Vec::new();
    let mut pending_effects = BTreeMap::new();
    for event in &session.events[started_index..] {
        match &event.event {
            SessionEvent::PlanEstablished { plan: established } => {
                plan = Some(established.clone());
            }
            SessionEvent::ToolInvoked { observation } => {
                pending_effects.remove(&observation.call.call_id);
                observations.push(observation.clone());
            }
            SessionEvent::EffectStarted { call, descriptor } => {
                pending_effects.insert(
                    call.call_id.clone(),
                    (call.clone(), descriptor.clone(), event.occurred_at.clone()),
                );
            }
            _ => {}
        }
    }
    for (_, (call, descriptor, occurred_at)) in pending_effects {
        observations.push(ToolObservation {
            sequence: observations.len() + 1,
            result: uncertain_effect_result(&session.session_ref, request_id, &call, &occurred_at),
            call,
            descriptor,
        });
    }
    (true, plan, observations)
}

fn prior_read_observations(
    session: &AgentSession,
    assessment_at: OffsetDateTime,
) -> Vec<ToolObservation> {
    let mut observations = session
        .events
        .iter()
        .rev()
        .filter_map(|event| match &event.event {
            SessionEvent::ToolInvoked { observation }
                if observation.descriptor.authority_class != ToolAuthorityClass::Actuate =>
            {
                observation
                    .result
                    .evidence
                    .iter()
                    .flat_map(|evidence| &evidence.atoms)
                    .any(|atom| {
                        atom.complete
                            && atom.fresh_until.as_deref().is_some_and(|fresh_until| {
                                OffsetDateTime::parse(fresh_until, &Rfc3339)
                                    .is_ok_and(|fresh_until| fresh_until >= assessment_at)
                            })
                    })
                    .then(|| observation.clone())
            }
            _ => None,
        })
        .take(MAX_RECALLED_OBSERVATIONS)
        .collect::<Vec<_>>();
    observations.reverse();
    observations
}

fn recalled_observations_for_trigger(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
    assessment_at: OffsetDateTime,
) -> Vec<ToolObservation> {
    if matches!(trigger, SessionTurnTrigger::Wake { .. }) {
        Vec::new()
    } else {
        prior_read_observations(session, assessment_at)
    }
}

fn prior_commitment_checkpoint(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
) -> Option<CommitmentCheckpoint> {
    let SessionTurnTrigger::Wake { commitment_ref, .. } = trigger else {
        return None;
    };
    session
        .events
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, record)| {
            let SessionEvent::DraftProduced { request_id, draft } = &record.event else {
                return None;
            };
            let commitment = draft
                .mission
                .commitments
                .iter()
                .find(|candidate| candidate.commitment_ref == *commitment_ref)?;
            let later_events = &session.events[index + 1..];
            let delivery = later_events
                .iter()
                .find_map(|candidate| match &candidate.event {
                    SessionEvent::DeliveryRecorded {
                        request_id: delivered_request,
                        delivery_ref,
                        payload_digest,
                        ..
                    } if delivered_request == request_id => {
                        Some((delivery_ref.clone(), payload_digest.clone()))
                    }
                    _ => None,
                })?;
            let completion = later_events.iter().find(|candidate| {
                matches!(
                    &candidate.event,
                    SessionEvent::TurnCompleted {
                        request_id: completed_request,
                        ..
                    } if completed_request == request_id
                )
            })?;
            let turn_start = session.events[..index].iter().rposition(|candidate| {
                matches!(
                    &candidate.event,
                    SessionEvent::TurnStarted {
                        request_id: started_request,
                    } if started_request == request_id
                )
            })?;
            let observations = session.events[turn_start + 1..index]
                .iter()
                .filter_map(|candidate| match &candidate.event {
                    SessionEvent::ToolInvoked { observation } => {
                        Some(CommitmentCheckpointObservation {
                            tool_id: observation.call.tool_id.clone(),
                            input: observation.call.input.clone(),
                            input_digest: observation.call.input_digest(),
                            observed_at: observation
                                .result
                                .evidence
                                .iter()
                                .map(|evidence| evidence.observed_at.clone())
                                .max(),
                            state: observation.result.state,
                            complete: observation
                                .result
                                .evidence
                                .iter()
                                .any(|evidence| evidence.complete),
                            summary: observation.result.summary.clone(),
                            data: observation.result.data.clone(),
                        })
                    }
                    _ => None,
                })
                .collect();
            let trigger_occurrence_ref =
                session.events[..index]
                    .iter()
                    .rev()
                    .find_map(|candidate| match &candidate.event {
                        SessionEvent::WakeTriggered {
                            request_id: triggered_request,
                            occurrence_ref,
                            ..
                        } if triggered_request == request_id => Some(occurrence_ref.clone()),
                        _ => None,
                    });
            Some(CommitmentCheckpoint {
                commitment_ref: commitment_ref.clone(),
                source_request_id: request_id.clone(),
                recorded_at: completion.occurred_at.clone(),
                delivery_ref: delivery.0,
                payload_digest: delivery.1,
                trigger_occurrence_ref,
                delivery: draft.delivery,
                state: draft.state,
                summary: draft.message.clone(),
                observations,
                commitment_status: commitment.status,
                next_wake_at: commitment.wake_at.clone(),
            })
        })
}

fn record_operating_repair(
    repairs: &mut usize,
    repair_feedback: &mut Vec<String>,
    feedback: String,
) {
    *repairs += 1;
    *repair_feedback = vec![feedback];
}

fn record_draft_repair(
    rejected: &mut BTreeSet<(String, String)>,
    draft: &GroundedDraft,
    repairs: &mut usize,
    repair_feedback: &mut Vec<String>,
    feedback: String,
) {
    let repeated = !rejected.insert((message_digest(&draft.message), feedback.clone()));
    record_operating_repair(repairs, repair_feedback, feedback);
    if repeated {
        *repairs = MAX_MODEL_REPAIRS + 1;
    }
}

fn push_event(
    session: &AgentSession,
    occurred_at: &str,
    events: &mut Vec<SessionEventRecord>,
    event: SessionEvent,
) {
    let base_sequence = session.events.last().map_or(0, |record| record.sequence);
    events.push(SessionEventRecord {
        schema_version: AGENT_SESSION_EVENT_V2.into(),
        session_ref: session.session_ref.clone(),
        sequence: base_sequence + events.len() as u64 + 1,
        occurred_at: occurred_at.into(),
        event,
    });
}

async fn emit_event(
    session: &AgentSession,
    occurred_at: &str,
    events: &mut Vec<SessionEventRecord>,
    event: SessionEvent,
    journal: &dyn SessionJournal,
) -> Result<(), AgentRuntimeError> {
    push_event(session, occurred_at, events, event);
    journal
        .record(events.last().expect("an emitted event was appended"))
        .await
}

fn validate_calls(
    calls: &[ToolCall],
    plan: &ResearchPlan,
    descriptors: &BTreeMap<String, ToolDescriptor>,
    observed_count: usize,
    call_ids: &mut BTreeSet<String>,
    call_fingerprints: &mut BTreeSet<(String, String)>,
) -> Result<(), AgentRuntimeError> {
    if calls.is_empty()
        || observed_count.saturating_add(calls.len()) > plan.lane.budget().max_tool_calls
    {
        return Err(AgentRuntimeError::ToolBudgetExceeded);
    }
    let planned = plan.selected_tools.iter().collect::<BTreeSet<_>>();
    let mut actuations = 0;
    for call in calls {
        if !bounded(&call.call_id, MAX_TEXT_BYTES)
            || !bounded(&call.tool_id, MAX_TEXT_BYTES)
            || !bounded(&call.purpose, MAX_TEXT_BYTES)
            || !call_ids.insert(call.call_id.clone())
        {
            return Err(AgentRuntimeError::InvalidToolCall(
                "tool calls require unique bounded identities and purposes".into(),
            ));
        }
        let descriptor = descriptors
            .get(&call.tool_id)
            .ok_or_else(|| AgentRuntimeError::ToolUnavailable(call.tool_id.clone()))?;
        if !planned.contains(&call.tool_id) {
            return Err(AgentRuntimeError::InvalidToolCall(
                "tool call is outside the established research plan".into(),
            ));
        }
        if !call_fingerprints.insert((call.tool_id.clone(), call.input_digest())) {
            return Err(AgentRuntimeError::DuplicateCallId);
        }
        if descriptor.authority_class == ToolAuthorityClass::Actuate {
            actuations += 1;
            if plan.lane != ExecutionLane::Act {
                return Err(AgentRuntimeError::InvalidToolCall(
                    "actuation requires an act plan".into(),
                ));
            }
        }
    }
    if actuations > 0 && calls.len() != 1 {
        return Err(AgentRuntimeError::InvalidToolCall(
            "an effect must execute alone so its authorization and receipt are unambiguous".into(),
        ));
    }
    Ok(())
}

fn matching_effect_authorization<'a>(
    session: &'a AgentSession,
    input: &SessionTurnInput,
    call: &ToolCall,
) -> Option<&'a EffectAuthorization> {
    let digest = call.input_digest();
    let expected_approval_ref = format!(
        "approval://agent-effect/{}",
        digest.trim_start_matches("sha256:")
    );
    session.effect_authorizations.iter().find(|authorization| {
        authorization.approval_ref == expected_approval_ref
            && authorization.tenant_id == session.tenant_id
            && authorization.request_id == input.request_id
            && authorization.thread_ref == session.thread_ref
            && authorization.actor_ref == input.actor_ref
            && authorization.tool_id == call.tool_id
            && authorization.input_digest == digest
    })
}

fn has_effect_authorization(
    session: &AgentSession,
    input: &SessionTurnInput,
    call: &ToolCall,
    consumed: &BTreeSet<String>,
) -> bool {
    matching_effect_authorization(session, input, call)
        .is_some_and(|authorization| !consumed.contains(&authorization.approval_ref))
}

fn validate_effect_closure(
    observations: &[ToolObservation],
    draft: &GroundedDraft,
    assessment_at: OffsetDateTime,
) -> Result<(), AgentRuntimeError> {
    for (effect_index, effect) in observations.iter().enumerate().filter(|(_, observation)| {
        observation.descriptor.authority_class == ToolAuthorityClass::Actuate
    }) {
        if effect.result.state == ToolResultState::Failed {
            continue;
        }
        if effect.result.state == ToolResultState::OutcomeUnknown {
            if matches!(draft.state, FinalState::Partial | FinalState::Blocked)
                && draft
                    .coverage_notice
                    .as_deref()
                    .is_some_and(|notice| draft.message.contains(notice))
            {
                continue;
            }
            return Err(AgentRuntimeError::UnverifiedEffect);
        }
        let targets = target_refs_from_input(&effect.call.input);
        if targets.is_empty() {
            return Err(AgentRuntimeError::UnverifiedEffect);
        }
        let verification_expectation = effect
            .result
            .data
            .get("verification_expectation")
            .and_then(Value::as_object)
            .and_then(|expectation| {
                let target_ref = expectation.get("target_ref")?.as_str()?;
                let input_digest = expectation.get("input_digest")?.as_str()?;
                let assertions = expectation.get("assertions")?.as_object()?;
                (!assertions.is_empty()
                    && targets.contains(target_ref)
                    && input_digest == effect.call.input_digest())
                .then_some((
                    target_ref.to_owned(),
                    assertions
                        .iter()
                        .map(|(predicate, value)| (predicate.clone(), value.clone()))
                        .collect::<BTreeMap<_, _>>(),
                ))
            });
        let effect_at = effect
            .result
            .evidence
            .iter()
            .flat_map(|evidence| evidence.atoms.iter())
            .filter_map(|atom| OffsetDateTime::parse(&atom.observed_at, &Rfc3339).ok())
            .max();
        let verified = effect_at
            .zip(verification_expectation.as_ref())
            .is_some_and(|(effect_at, (expected_target, expected_assertions))| {
                observations
                    .iter()
                    .skip(effect_index + 1)
                    .any(|observation| {
                        if observation.descriptor.authority_class != ToolAuthorityClass::Observe
                            || observation.result.state != ToolResultState::Succeeded
                            || target_refs_from_input(&observation.call.input).is_disjoint(&targets)
                        {
                            return false;
                        }
                        expected_assertions
                            .iter()
                            .all(|(predicate, expected_value)| {
                                observation.result.evidence.iter().any(|evidence| {
                                    evidence.atoms.iter().any(|atom| {
                                atom.complete
                                    && atom.subject_ref.as_ref() == Some(expected_target)
                                    && OffsetDateTime::parse(&atom.observed_at, &Rfc3339)
                                        .is_ok_and(|observed_at| observed_at >= effect_at)
                                    && atom
                                        .fresh_until
                                        .as_deref()
                                        .and_then(|value| {
                                            OffsetDateTime::parse(value, &Rfc3339).ok()
                                        })
                                        .is_some_and(|fresh_until| fresh_until >= assessment_at)
                                    && matches!(
                                        &atom.assertion,
                                        EvidenceAssertion::Value { predicate: actual, value }
                                            if actual == predicate && value == expected_value
                                    )
                            })
                                })
                            })
                    })
            });
        if !verified {
            return Err(AgentRuntimeError::UnverifiedEffect);
        }
    }
    Ok(())
}

fn target_refs_from_input(input: &Value) -> BTreeSet<String> {
    fn collect(value: &Value, key: Option<&str>, refs: &mut BTreeSet<String>) {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    collect(value, Some(key), refs);
                }
            }
            Value::Array(items) => {
                for item in items {
                    collect(item, key, refs);
                }
            }
            Value::String(value)
                if key.is_some_and(|key| {
                    let key = key.to_ascii_lowercase();
                    key.ends_with("_ref")
                        || key.ends_with("_id")
                        || key == "target"
                        || key == "subject"
                }) && !value.trim().is_empty() =>
            {
                refs.insert(value.clone());
            }
            _ => {}
        }
    }
    let mut refs = BTreeSet::new();
    collect(input, None, &mut refs);
    refs
}

fn failed_tool_result(
    session: &AgentSession,
    input: &SessionTurnInput,
    call: &ToolCall,
    observed_at: OffsetDateTime,
) -> Result<ToolResult, AgentRuntimeError> {
    let observed_at_text = observed_at
        .format(&Rfc3339)
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    let fresh_until = observed_at
        .checked_add(Duration::minutes(5))
        .ok_or_else(|| AgentRuntimeError::InvalidToolCall("evidence time overflow".into()))?
        .format(&Rfc3339)
        .map_err(|error| AgentRuntimeError::InvalidToolCall(error.to_string()))?;
    let evidence_ref = format!(
        "evidence://agent-tool-outcome/{}/{}/{}",
        session.session_ref, input.request_id, call.call_id
    );
    let summary = format!(
        "The bounded {} invocation failed before it returned domain evidence.",
        call.tool_id
    );
    Ok(ToolResult {
        state: ToolResultState::Failed,
        summary: summary.clone(),
        data: Value::Null,
        evidence: vec![crate::EvidenceRecord {
            evidence_ref: evidence_ref.clone(),
            statement: summary.clone(),
            observed_at: observed_at_text.clone(),
            fresh_until: Some(fresh_until.clone()),
            complete: false,
            atoms: vec![EvidenceAtom {
                atom_ref: format!("{evidence_ref}#tool-outcome"),
                subject_ref: None,
                assertion: EvidenceAssertion::ToolOutcome {
                    state: ToolResultState::Failed,
                    summary,
                },
                observed_at: observed_at_text,
                fresh_until: Some(fresh_until),
                complete: true,
            }],
        }],
        blocker: Some(
            "The capability invocation failed; other bounded tools remain available.".into(),
        ),
    })
}

fn uncertain_effect_result(
    session_ref: &str,
    request_id: &str,
    call: &ToolCall,
    observed_at: &str,
) -> ToolResult {
    let evidence_ref = format!(
        "evidence://agent-effect-outcome/{session_ref}/{request_id}/{}",
        call.call_id
    );
    let summary = format!(
        "The {} effect was durably started, but its provider outcome was not recorded; it will not be invoked again automatically.",
        call.tool_id
    );
    ToolResult {
        state: ToolResultState::OutcomeUnknown,
        summary: summary.clone(),
        data: Value::Null,
        evidence: vec![crate::EvidenceRecord {
            evidence_ref: evidence_ref.clone(),
            statement: summary.clone(),
            observed_at: observed_at.to_owned(),
            fresh_until: None,
            complete: false,
            atoms: vec![EvidenceAtom {
                atom_ref: format!("{evidence_ref}#tool-outcome"),
                subject_ref: None,
                assertion: EvidenceAssertion::ToolOutcome {
                    state: ToolResultState::OutcomeUnknown,
                    summary,
                },
                observed_at: observed_at.to_owned(),
                fresh_until: None,
                complete: true,
            }],
        }],
        blocker: Some(
            "Reconcile the provider state with a fresh observation before any further effect."
                .into(),
        ),
    }
}

fn validate_message_review(
    draft: &GroundedDraft,
    review: &MessageReview,
) -> Result<Vec<String>, AgentRuntimeError> {
    if review.message_digest != message_digest(&draft.message) {
        return Err(AgentRuntimeError::InvalidFinal(
            "message review digest does not match the visible response".into(),
        ));
    }
    let expected = draft
        .claims
        .iter()
        .map(|claim| claim.claim_ref.as_str())
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    let mut issues = Vec::new();
    for claim_review in &review.claim_reviews {
        if !expected.contains(claim_review.claim_ref.as_str())
            || !actual.insert(claim_review.claim_ref.as_str())
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "claim review contains an unknown or duplicate claim reference".into(),
            ));
        }
        match claim_review.verdict {
            ClaimReviewVerdict::Supported if claim_review.issue.is_some() => {
                return Err(AgentRuntimeError::InvalidFinal(
                    "a supported claim review cannot contain an issue".into(),
                ));
            }
            ClaimReviewVerdict::Supported => {}
            ClaimReviewVerdict::Unsupported => {
                let issue = claim_review
                    .issue
                    .as_deref()
                    .filter(|value| bounded(value, MAX_TEXT_BYTES));
                let issue = issue.ok_or_else(|| {
                    AgentRuntimeError::InvalidFinal(
                        "an unsupported claim review requires one bounded issue".into(),
                    )
                })?;
                issues.push(format!("{}: {issue}", claim_review.claim_ref));
            }
        }
    }
    if actual != expected {
        return Err(AgentRuntimeError::InvalidFinal(
            "every visible claim requires exactly one review".into(),
        ));
    }
    for material in &review.undeclared_material {
        if !bounded(material, MAX_TEXT_BYTES) {
            return Err(AgentRuntimeError::InvalidFinal(
                "message review contains an invalid undeclared-material issue".into(),
            ));
        }
        issues.push(format!("undeclared material: {material}"));
    }
    if !bounded(&review.attention.reason, MAX_TEXT_BYTES) {
        return Err(AgentRuntimeError::InvalidFinal(
            "message review contains an invalid attention rationale".into(),
        ));
    }
    let behavioral = &review.behavioral;
    if !behavioral.answers_newest_request {
        issues.push("the response does not answer the newest operator request".into());
    }
    if !behavioral.conversational {
        issues.push("the response is not conversationally usable".into());
    }
    if !behavioral.owns_follow_through {
        issues.push("the response pushes avoidable follow-through back to the operator".into());
    }
    if !behavioral.right_sized {
        issues.push("the response is not right-sized for the request".into());
    }
    if !behavioral.evidence_boundary_correct {
        issues.push("the response overstates its evidence or action boundary".into());
    }
    Ok(issues)
}

pub fn message_digest(message: &str) -> String {
    let digest = Sha256::digest(message.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

pub fn validate_plan(
    plan: &ResearchPlan,
    available_tools: &[String],
) -> Result<(), AgentRuntimeError> {
    let budget = plan.lane.budget();
    if matches!(
        plan.lane,
        ExecutionLane::Ignore | ExecutionLane::Converse | ExecutionLane::Continue
    ) || !bounded(&plan.decision, MAX_TEXT_BYTES)
        || plan.claims.is_empty()
        || plan.claims.len() > MAX_PLAN_CLAIMS
        || plan.selected_tools.len() > MAX_PLAN_TOOLS
        || plan.selected_tools.len() > budget.max_selected_capabilities
        || plan.resolved_entities.len() > MAX_SCOPE_ITEMS
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "research plan is empty or exceeds its bounded contract".into(),
        ));
    }
    let available = available_tools.iter().collect::<BTreeSet<_>>();
    let mut claim_refs = BTreeSet::new();
    for claim in &plan.claims {
        if !bounded(&claim.claim_ref, MAX_TEXT_BYTES)
            || !bounded(&claim.question, MAX_TEXT_BYTES)
            || !claim_refs.insert(&claim.claim_ref)
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "research plan claims require unique bounded references and questions".into(),
            ));
        }
    }
    let unique_tools = plan.selected_tools.iter().collect::<BTreeSet<_>>();
    if unique_tools.len() != plan.selected_tools.len()
        || plan
            .selected_tools
            .iter()
            .any(|tool| !available.contains(tool))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "research plan selected an unavailable tool".into(),
        ));
    }
    if let Some(follow_through) = &plan.follow_through {
        if !bounded(&follow_through.commitment_ref, MAX_TEXT_BYTES) {
            return Err(AgentRuntimeError::InvalidFinal(
                "planned follow-through requires one stable bounded commitment_ref".into(),
            ));
        }
        if follow_through.required_tool_ids.is_empty() {
            return Err(AgentRuntimeError::InvalidFinal(
                "planned follow-through requires at least one exact read tool".into(),
            ));
        }
        if follow_through.required_tool_ids.len()
            != follow_through
                .required_tool_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "planned follow-through required_tool_ids must be unique".into(),
            ));
        }
        let unselected = follow_through
            .required_tool_ids
            .iter()
            .filter(|tool_id| !plan.selected_tools.contains(tool_id))
            .cloned()
            .collect::<Vec<_>>();
        if !unselected.is_empty() {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "planned follow-through tools must also appear in selected_tools: {}",
                unselected.join(", ")
            )));
        }
        if follow_through.acceptance_criteria.is_empty()
            || follow_through.acceptance_criteria.len() > MAX_SCOPE_ITEMS
            || follow_through
                .acceptance_criteria
                .iter()
                .any(|criterion| !bounded(criterion, MAX_TEXT_BYTES))
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "planned follow-through acceptance_criteria require one or more bounded criteria"
                    .into(),
            ));
        }
        if !bounded(&follow_through.next_action, MAX_TEXT_BYTES)
            || !bounded(&follow_through.verification, MAX_TEXT_BYTES)
            || !(30..=3_600).contains(&follow_through.check_after_seconds)
            || follow_through.attention_policy.acceptance_all.is_empty()
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "planned follow-through requires a bounded next action and verification, a 30-3600 second check delay, and at least one typed acceptance condition"
                    .into(),
            ));
        }
        if follow_through
            .attention_policy
            .acceptance_all
            .iter()
            .chain(&follow_through.attention_policy.alert_any)
            .any(|condition| {
                !follow_through
                    .required_tool_ids
                    .contains(&condition.tool_id)
                    || !bounded(&condition.tool_id, MAX_TEXT_BYTES)
                    || !condition.data_pointer.starts_with('/')
                    || !bounded(&condition.data_pointer, MAX_TEXT_BYTES)
                    || !matches!(
                        &condition.equals,
                        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                    )
                    || condition
                        .equals
                        .as_str()
                        .is_some_and(|value| !bounded(value, MAX_TEXT_BYTES))
            })
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "planned attention conditions must reference required tools and bounded JSON pointers"
                    .into(),
            ));
        }
        if follow_through
            .attention_policy
            .alert_any
            .iter()
            .any(|condition| !condition.equals.is_boolean())
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "planned alert conditions must target explicit boolean authority signals; numeric and string progress values belong in acceptance conditions"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn validate_explicit_follow_through(
    session: &AgentSession,
    plan: &ResearchPlan,
) -> Result<(), AgentRuntimeError> {
    let request = session
        .messages
        .iter()
        .rev()
        .find(|message| message.role == SessionMessageRole::User)
        .map(|message| message.text.as_str())
        .unwrap_or_default();
    if explicitly_delegates_future_observation(request) && plan.follow_through.is_none() {
        return Err(AgentRuntimeError::InvalidFinal(
            "the operator explicitly delegated future observation. Record one bounded follow_through with a stable commitment_ref, exact read tools, acceptance criteria, and a final scheduled commitment; do not finish this as one-turn advice"
                .into(),
        ));
    }
    Ok(())
}

fn explicitly_delegates_future_observation(request: &str) -> bool {
    let normalized = request.to_ascii_lowercase();
    [
        "keep an eye",
        "keep checking",
        "keep monitoring",
        "keep watching",
        "check again",
        "keep going",
        "keep owning",
        "own the recovery",
        "notify me when",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase))
        || (normalized.contains("watch ")
            && (normalized.contains("recovery")
                || normalized.contains("until")
                || normalized.contains("tell me when")
                || normalized.contains("progress")))
        || (normalized.contains("only interrupt me")
            && (normalized.contains("final") || normalized.contains("gap")))
}

fn validate_plan_completion(
    plan: Option<&ResearchPlan>,
    draft: &GroundedDraft,
) -> Result<(), AgentRuntimeError> {
    let Some(plan) = plan else {
        return Ok(());
    };
    let planned = plan
        .claims
        .iter()
        .map(|claim| claim.claim_ref.as_str())
        .collect::<BTreeSet<_>>();
    for claim in &draft.claims {
        if let Some(planned_claim_ref) = claim.planned_claim_ref.as_deref()
            && !planned.contains(planned_claim_ref)
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "visible claim references an unknown planned claim".into(),
            ));
        }
    }
    if let Some(follow_through) = &plan.follow_through {
        let persisted = draft
            .mission
            .commitments
            .iter()
            .find(|commitment| commitment.commitment_ref == follow_through.commitment_ref);
        let exact = persisted.is_some_and(|commitment| {
            commitment.owner == WorkOwner::Cerebro
                && !matches!(
                    commitment.status,
                    CommitmentStatus::Completed | CommitmentStatus::Cancelled
                )
                && commitment.required_tool_ids == follow_through.required_tool_ids
                && commitment.acceptance_criteria == follow_through.acceptance_criteria
                && commitment.next_action.as_deref() == Some(&follow_through.next_action)
                && commitment.attention_policy.as_ref() == Some(&follow_through.attention_policy)
                && commitment.verification.as_deref() == Some(&follow_through.verification)
                && commitment.wake_at.is_some()
        });
        if !exact {
            let expected = serde_json::to_string(follow_through)
                .unwrap_or_else(|_| "the established follow-through".into());
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "the final mission must persist this exact active, scheduled executor contract without rewriting another commitment: {expected}"
            )));
        }
    }
    Ok(())
}

fn validate_cross_turn_consistency(
    session: &AgentSession,
    draft: &GroundedDraft,
) -> Result<(), AgentRuntimeError> {
    let current = draft.message.to_ascii_lowercase();
    if current.contains("no regressions occurred")
        && session.messages.iter().any(|message| {
            message.role == SessionMessageRole::Assistant && {
                let prior = message.text.to_ascii_lowercase();
                prior.contains("regressed")
                    || prior.contains("regression detected")
                    || prior.contains("streak reset")
            }
        })
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "the response contradicts the delivered trajectory: an earlier update reported a regression, so do not claim that no regressions occurred; describe only the current check or say that no further regression was observed"
                .into(),
        ));
    }
    Ok(())
}

fn planned_commitment(
    follow_through: &PlannedFollowThrough,
    assessment_at: OffsetDateTime,
) -> Result<Commitment, AgentRuntimeError> {
    let wake_at = assessment_at
        .checked_add(Duration::seconds(i64::from(
            follow_through.check_after_seconds,
        )))
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "the planned follow-through wake time overflowed".into(),
            )
        })?
        .format(&Rfc3339)
        .map_err(|_| {
            AgentRuntimeError::InvalidFinal(
                "the planned follow-through wake time could not be formatted".into(),
            )
        })?;
    Ok(Commitment {
        commitment_ref: follow_through.commitment_ref.clone(),
        summary: follow_through.next_action.clone(),
        owner: WorkOwner::Cerebro,
        status: CommitmentStatus::Waiting,
        next_action: Some(follow_through.next_action.clone()),
        blocker: None,
        acceptance_criteria: follow_through.acceptance_criteria.clone(),
        artifact_refs: Vec::new(),
        required_tool_ids: follow_through.required_tool_ids.clone(),
        attention_policy: Some(follow_through.attention_policy.clone()),
        wake_at: Some(wake_at),
        verification: Some(follow_through.verification.clone()),
    })
}

fn materialize_planned_follow_through(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
    plan: Option<&ResearchPlan>,
    assessment_at: OffsetDateTime,
    draft: &mut GroundedDraft,
) -> Result<(), AgentRuntimeError> {
    if !matches!(trigger, SessionTurnTrigger::Operator) {
        return Ok(());
    }
    let Some(follow_through) = plan.and_then(|plan| plan.follow_through.as_ref()) else {
        return Ok(());
    };
    let persisted_refs = session
        .mission
        .commitments
        .iter()
        .map(|commitment| commitment.commitment_ref.as_str())
        .collect::<BTreeSet<_>>();
    draft.mission.commitments.retain(|commitment| {
        persisted_refs.contains(commitment.commitment_ref.as_str())
            || commitment.commitment_ref == follow_through.commitment_ref
            || commitment.owner != WorkOwner::Cerebro
    });
    let canonical = planned_commitment(follow_through, assessment_at)?;
    if let Some(commitment) = draft
        .mission
        .commitments
        .iter_mut()
        .find(|commitment| commitment.commitment_ref == follow_through.commitment_ref)
    {
        *commitment = canonical;
    } else {
        draft.mission.commitments.push(canonical);
    }
    draft.mission.status = SessionStatus::WaitingForExternal;
    Ok(())
}

fn validate_planned_follow_through_viability(
    plan: Option<&ResearchPlan>,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
) -> Result<(), AgentRuntimeError> {
    let Some(follow_through) = plan.and_then(|plan| plan.follow_through.as_ref()) else {
        return Ok(());
    };
    for tool_id in &follow_through.required_tool_ids {
        if observations.iter().any(|observation| {
            observation.call.tool_id == *tool_id
                && observation_is_complete_and_fresh(observation, assessment_at)
        }) {
            continue;
        }
        let last_state = observations
            .iter()
            .rev()
            .find(|observation| observation.call.tool_id == *tool_id)
            .map(|observation| format!("; its last result was {:?}", observation.result.state));
        let Some(last_state) = last_state else {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "the planned follow-through requires {tool_id}. Invoke that selected read for a successful, complete, fresh baseline before finishing."
            )));
        };
        let successful_alternatives = observations
            .iter()
            .filter(|observation| {
                !follow_through
                    .required_tool_ids
                    .contains(&observation.call.tool_id)
                    && observation_is_complete_and_fresh(observation, assessment_at)
            })
            .map(|observation| observation.call.tool_id.clone())
            .collect::<BTreeSet<_>>();
        let next_step = if successful_alternatives.is_empty() {
            "Establish a materially revised plan selecting another available read, invoke it, and bind follow-through only after a fresh baseline succeeds."
                .into()
        } else {
            format!(
                "Successful fresh alternatives are already observed: {}. Return establish_plan now and replace the failed required_tool_ids with the exact successful authorities needed by the acceptance criteria.",
                successful_alternatives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "the planned follow-through requires {tool_id}, but it has no valid baseline{last_state}. Do not finish or copy the stale executor contract. {next_step}"
        )));
    }
    Ok(())
}

pub fn validate_grounded_draft(
    session: &AgentSession,
    draft: &GroundedDraft,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
) -> Result<ValidatedDraft, AgentRuntimeError> {
    validate_session(session)?;
    validate_mission(&draft.mission)?;
    validate_explicit_streak_reset_language(draft, observations)?;
    if !bounded(&draft.message, MAX_DELIVERY_MESSAGE_BYTES)
        || draft.claims.len() > MAX_VISIBLE_CLAIMS
        || !draft.presentation_ready
        || draft
            .message
            .chars()
            .any(|character| character.is_control() && character != '\n')
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "visible response is empty, too large, or contains invalid control characters".into(),
        ));
    }

    let atoms = evidence_atoms(observations)?;
    let open_loops = draft
        .mission
        .open_loops
        .iter()
        .map(|item| item.open_loop_ref.as_str())
        .collect::<BTreeSet<_>>();
    let commitments = draft
        .mission
        .commitments
        .iter()
        .map(|commitment| (commitment.commitment_ref.as_str(), commitment))
        .collect::<BTreeMap<_, _>>();
    let mut claim_refs = BTreeSet::new();
    let mut cited_atoms = BTreeSet::new();
    let message_sequence = session
        .messages
        .iter()
        .enumerate()
        .map(|(index, message)| ((index + 1) as u64, message))
        .collect::<BTreeMap<_, _>>();
    let claim_context = ClaimValidationContext {
        atoms: &atoms,
        open_loops: &open_loops,
        commitments: &commitments,
        messages: &message_sequence,
        assessment_at,
        final_state: draft.state,
    };

    if draft.claims.is_empty()
        || draft
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect::<String>()
            != draft.message
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "ordered grounded claims must reconstruct every byte of the visible response".into(),
        ));
    }

    for claim in &draft.claims {
        if !bounded(&claim.claim_ref, MAX_TEXT_BYTES)
            || !bounded(&claim.text, MAX_TEXT_BYTES)
            || !claim_refs.insert(&claim.claim_ref)
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "every visible claim requires a unique reference and exact text in the message"
                    .into(),
            ));
        }
        validate_claim(claim, &claim_context, &mut cited_atoms)?;
    }

    for update in &draft.memory_updates {
        if !bounded(&update.memory_ref, MAX_TEXT_BYTES)
            || !bounded(&update.statement, MAX_TEXT_BYTES)
            || update
                .evidence_atom_refs
                .iter()
                .any(|atom_ref| !atoms.contains_key(atom_ref))
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "memory updates require bounded text and observed provenance".into(),
            ));
        }
        if update.promotion_requested
            && update.evidence_atom_refs.iter().any(|atom_ref| {
                atoms.get(atom_ref).is_none_or(|atom| {
                    !atom.complete
                        || atom
                            .fresh_until
                            .is_none_or(|fresh_until| fresh_until < assessment_at)
                })
            })
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "promoted memory requires complete fresh evidence".into(),
            ));
        }
        cited_atoms.extend(update.evidence_atom_refs.iter().cloned());
    }

    if matches!(draft.state, FinalState::Partial | FinalState::Blocked)
        && draft
            .coverage_notice
            .as_deref()
            .is_none_or(|notice| notice.is_empty() || !draft.message.contains(notice))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "partial and blocked responses require a coverage notice".into(),
        ));
    }
    if draft.state == FinalState::NeedsInput
        && draft
            .question
            .as_deref()
            .is_none_or(|question| question.is_empty() || !draft.message.contains(question))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "needs_input requires one precise question".into(),
        ));
    }

    Ok(ValidatedDraft {
        markdown: draft.message.trim().to_owned(),
        evidence_atom_refs: cited_atoms.into_iter().collect(),
    })
}

fn validate_explicit_streak_reset_language(
    draft: &GroundedDraft,
    observations: &[ToolObservation],
) -> Result<(), AgentRuntimeError> {
    let claims_reset = draft.claims.iter().any(|claim| {
        let text = claim.text.to_ascii_lowercase();
        text.contains("streak reset")
            || text.contains("streak has reset")
            || text.contains("streak was reset")
            || text.contains("reset the streak")
    });
    if !claims_reset {
        return Ok(());
    }
    let observed_reset = observations
        .iter()
        .any(|observation| json_has_true_named_field(&observation.result.data, "streak_reset"));
    if observed_reset {
        return Ok(());
    }
    Err(AgentRuntimeError::InvalidFinal(
        "the response says the receipt streak reset, but no current observation reports streak_reset=true. If a stale receipt merely failed to advance an unchanged fresh count, say the count remains at its current value"
            .into(),
    ))
}

fn json_has_true_named_field(value: &Value, field: &str) -> bool {
    match value {
        Value::Object(entries) => entries.iter().any(|(key, value)| {
            (key == field && value.as_bool() == Some(true))
                || json_has_true_named_field(value, field)
        }),
        Value::Array(items) => items
            .iter()
            .any(|item| json_has_true_named_field(item, field)),
        _ => false,
    }
}

struct ClaimValidationContext<'a, 'b> {
    atoms: &'a BTreeMap<String, AtomContext<'b>>,
    open_loops: &'a BTreeSet<&'a str>,
    commitments: &'a BTreeMap<&'a str, &'a Commitment>,
    messages: &'a BTreeMap<u64, &'a SessionMessage>,
    assessment_at: OffsetDateTime,
    final_state: FinalState,
}

fn validate_claim(
    claim: &GroundedClaim,
    context: &ClaimValidationContext<'_, '_>,
    cited_atoms: &mut BTreeSet<String>,
) -> Result<(), AgentRuntimeError> {
    let atom_refs = match &claim.content {
        ClaimContent::Observation { atom_refs } => atom_refs.as_slice(),
        ClaimContent::Derivation { .. } => {
            return Err(AgentRuntimeError::InvalidFinal(
                "derivations require a deterministic runtime evaluator before delivery".into(),
            ));
        }
        ClaimContent::Recommendation {
            rationale_atom_refs,
            ..
        } => rationale_atom_refs.as_slice(),
        ClaimContent::Hypothesis {
            supporting_atom_refs,
            alternatives,
        } => {
            if alternatives.is_empty() {
                return Err(AgentRuntimeError::InvalidFinal(
                    "a hypothesis must preserve at least one alternative".into(),
                ));
            }
            supporting_atom_refs.as_slice()
        }
        ClaimContent::OperatorContext {
            message_sequence,
            exact_excerpt,
        } => {
            let message = context.messages.get(message_sequence).ok_or_else(|| {
                AgentRuntimeError::InvalidFinal("operator context cites an unknown message".into())
            })?;
            if exact_excerpt.is_empty() || !message.text.contains(exact_excerpt) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "operator context must quote an exact supplied excerpt".into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::RetainedPlan { open_loop_ref } => {
            if !context.open_loops.contains(open_loop_ref.as_str()) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "retained plan cites an unknown open loop".into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::Commitment { commitment_ref } => {
            let commitment = context
                .commitments
                .get(commitment_ref.as_str())
                .ok_or_else(|| {
                    AgentRuntimeError::InvalidFinal(
                        "commitment claim cites an unknown durable commitment".into(),
                    )
                })?;
            if commitment.owner != WorkOwner::Cerebro
                || !matches!(
                    commitment.status,
                    CommitmentStatus::Planned
                        | CommitmentStatus::InProgress
                        | CommitmentStatus::Waiting
                )
                || commitment.wake_at.is_none()
                || commitment.next_action.is_none()
                || commitment.acceptance_criteria.is_empty()
                || commitment.verification.is_none()
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "commitment claims require an active executor-bound Cerebro commitment".into(),
                ));
            }
            let normalized = claim.text.to_ascii_lowercase();
            if normalized.contains("immediately")
                || normalized.contains("the moment")
                || normalized.contains("as soon as it changes")
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "a scheduled check supports notification after that check, not immediate or continuous detection"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::StableExplanation => {
            if contains_unbound_future_promise(&claim.text) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "future Cerebro work must cite the exact active commitment that records it"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::Question => return Ok(()),
    };

    if atom_refs.is_empty() {
        return Err(AgentRuntimeError::InvalidFinal(
            "observations, derivations, recommendations, and hypotheses require evidence atoms"
                .into(),
        ));
    }
    for atom_ref in atom_refs {
        let atom = context
            .atoms
            .get(atom_ref)
            .ok_or_else(|| AgentRuntimeError::EvidenceNotObserved(atom_ref.clone()))?;
        if matches!(claim.content, ClaimContent::Observation { .. })
            && (!atom.complete
                || atom
                    .fresh_until
                    .is_none_or(|until| until < context.assessment_at))
            && !matches!(
                context.final_state,
                FinalState::Partial | FinalState::Blocked
            )
        {
            return Err(AgentRuntimeError::EvidenceNotAuthoritative(
                atom_ref.clone(),
            ));
        }
        cited_atoms.insert(atom_ref.clone());
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct AtomContext<'a> {
    _atom: &'a EvidenceAtom,
    complete: bool,
    fresh_until: Option<OffsetDateTime>,
}

fn evidence_atoms(
    observations: &[ToolObservation],
) -> Result<BTreeMap<String, AtomContext<'_>>, AgentRuntimeError> {
    let mut atoms = BTreeMap::new();
    for observation in observations {
        for evidence in &observation.result.evidence {
            for atom in &evidence.atoms {
                OffsetDateTime::parse(&atom.observed_at, &Rfc3339).map_err(|_| {
                    AgentRuntimeError::InvalidFinal("invalid evidence observation time".into())
                })?;
                let fresh_until = atom
                    .fresh_until
                    .as_deref()
                    .map(|value| OffsetDateTime::parse(value, &Rfc3339))
                    .transpose()
                    .map_err(|_| {
                        AgentRuntimeError::InvalidFinal("invalid evidence freshness".into())
                    })?;
                if !bounded(&atom.atom_ref, MAX_TEXT_BYTES)
                    || atoms
                        .insert(
                            atom.atom_ref.clone(),
                            AtomContext {
                                _atom: atom,
                                complete: atom.complete,
                                fresh_until,
                            },
                        )
                        .is_some()
                {
                    return Err(AgentRuntimeError::InvalidFinal(
                        "evidence atoms require unique bounded references".into(),
                    ));
                }
            }
        }
    }
    Ok(atoms)
}

fn validate_session(session: &AgentSession) -> Result<(), AgentRuntimeError> {
    if session.schema_version != AGENT_SESSION_V2
        || !bounded(&session.session_ref, MAX_TEXT_BYTES)
        || !bounded(&session.tenant_id, MAX_TEXT_BYTES)
        || !bounded(&session.thread_ref, MAX_TEXT_BYTES)
        || session.messages.len() > MAX_SESSION_MESSAGES
        || session
            .messages
            .iter()
            .map(|message| message.text.len())
            .sum::<usize>()
            > MAX_SESSION_MESSAGE_BYTES
        || session.messages.iter().any(|message| {
            !bounded(&message.message_ref, MAX_TEXT_BYTES)
                || !bounded(&message.actor_ref, MAX_TEXT_BYTES)
                || !bounded(&message.text, MAX_MESSAGE_BYTES)
                || OffsetDateTime::parse(&message.received_at, &Rfc3339).is_err()
        })
    {
        return Err(AgentRuntimeError::InvalidRequest(
            "session identity or schema is invalid".into(),
        ));
    }
    let mut memory_refs = BTreeSet::new();
    if session.memories.len() > MAX_MEMORIES
        || session.memories.iter().any(|memory| {
            !bounded(&memory.memory_ref, MAX_TEXT_BYTES)
                || !bounded(&memory.statement, MAX_TEXT_BYTES)
                || !memory_refs.insert(&memory.memory_ref)
                || memory
                    .evidence_atom_refs
                    .iter()
                    .any(|reference| !bounded(reference, MAX_TEXT_BYTES))
        })
    {
        return Err(AgentRuntimeError::InvalidRequest(
            "session memory is invalid or exceeds its bounded contract".into(),
        ));
    }
    validate_mission(&session.mission)
}

fn validate_mission(mission: &MissionState) -> Result<(), AgentRuntimeError> {
    if !bounded(&mission.mission_ref, MAX_TEXT_BYTES)
        || !bounded(&mission.objective, MAX_TEXT_BYTES)
        || !bounded(&mission.desired_outcome, MAX_TEXT_BYTES)
        || mission.resolved_scope.len() > MAX_SCOPE_ITEMS
        || mission.commitments.len() > MAX_COMMITMENTS
        || mission.open_loops.len() > MAX_OPEN_LOOPS
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "mission state is empty or exceeds its bounded contract".into(),
        ));
    }
    let mut refs = BTreeSet::new();
    for commitment in &mission.commitments {
        let required_tool_ids = commitment.required_tool_ids.iter().collect::<BTreeSet<_>>();
        if !bounded(&commitment.commitment_ref, MAX_TEXT_BYTES)
            || !bounded(&commitment.summary, MAX_TEXT_BYTES)
            || !refs.insert(&commitment.commitment_ref)
            || required_tool_ids.len() != commitment.required_tool_ids.len()
            || commitment
                .required_tool_ids
                .iter()
                .any(|tool_id| !bounded(tool_id, MAX_TEXT_BYTES))
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "commitments require unique bounded references and summaries".into(),
            ));
        }
        if commitment.owner == WorkOwner::Cerebro
            && !matches!(
                commitment.status,
                CommitmentStatus::Blocked
                    | CommitmentStatus::Completed
                    | CommitmentStatus::Cancelled
            )
            && (commitment.wake_at.is_none()
                || commitment
                    .next_action
                    .as_deref()
                    .is_none_or(|value| !bounded(value, MAX_TEXT_BYTES))
                || commitment.acceptance_criteria.is_empty()
                || commitment
                    .verification
                    .as_deref()
                    .is_none_or(|value| !bounded(value, MAX_TEXT_BYTES)))
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "unfinished Cerebro commitments require an exact wake time, next action, acceptance criteria, and verification condition".into(),
            ));
        }
        if commitment.owner == WorkOwner::Cerebro
            && !matches!(
                commitment.status,
                CommitmentStatus::Blocked
                    | CommitmentStatus::Completed
                    | CommitmentStatus::Cancelled
            )
            && !commitment.required_tool_ids.is_empty()
        {
            let policy = commitment.attention_policy.as_ref().ok_or_else(|| {
                AgentRuntimeError::InvalidFinal(
                    "unfinished observed commitments require a typed attention policy".into(),
                )
            })?;
            if policy.acceptance_all.is_empty()
                || policy
                    .alert_any
                    .iter()
                    .any(|condition| !condition.equals.is_boolean())
                || policy
                    .acceptance_all
                    .iter()
                    .chain(&policy.alert_any)
                    .any(|condition| {
                        !commitment.required_tool_ids.contains(&condition.tool_id)
                            || !bounded(&condition.tool_id, MAX_TEXT_BYTES)
                            || !condition.data_pointer.starts_with('/')
                            || !bounded(&condition.data_pointer, MAX_TEXT_BYTES)
                            || !matches!(
                                &condition.equals,
                                Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_)
                            )
                            || condition
                                .equals
                                .as_str()
                                .is_some_and(|value| !bounded(value, MAX_TEXT_BYTES))
                    })
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "typed attention conditions must reference required tools and bounded JSON pointers, and alerts must target explicit boolean authority signals"
                        .into(),
                ));
            }
        }
        if commitment
            .wake_at
            .as_deref()
            .is_some_and(|wake_at| OffsetDateTime::parse(wake_at, &Rfc3339).is_err())
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "commitment wake_at must be an RFC3339 timestamp".into(),
            ));
        }
    }
    for open_loop in &mission.open_loops {
        if !bounded(&open_loop.open_loop_ref, MAX_TEXT_BYTES)
            || !bounded(&open_loop.summary, MAX_TEXT_BYTES)
            || !refs.insert(&open_loop.open_loop_ref)
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "open loops require unique bounded references and summaries".into(),
            ));
        }
    }
    Ok(())
}

fn bounded(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes
}

fn contains_unbound_future_promise(value: &str) -> bool {
    let normalized = value.to_lowercase().replace('’', "'");
    [
        "i'll check",
        "i will check",
        "i'll re-check",
        "i will re-check",
        "i'll monitor",
        "i will monitor",
        "i'll follow up",
        "i will follow up",
        "i'll update you",
        "i will update you",
        "check scheduled",
    ]
    .iter()
    .any(|promise| normalized.contains(promise))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;
    use crate::{ToolAuthorityClass, ToolDescriptor, ToolEffectClass, ToolResult};
    use serde_json::json;

    fn mission() -> MissionState {
        MissionState {
            mission_ref: "mission:1".into(),
            objective: "Explain the current connector state.".into(),
            desired_outcome: "A grounded operator decision.".into(),
            resolved_scope: vec!["connector:alpha".into()],
            scope_assumptions: Vec::new(),
            acceptance_criteria: vec!["Current state is supported.".into()],
            commitments: Vec::new(),
            open_loops: Vec::new(),
            status: SessionStatus::Active,
        }
    }

    fn session() -> AgentSession {
        AgentSession {
            schema_version: AGENT_SESSION_V2.into(),
            session_ref: "session:1".into(),
            tenant_id: "tenant:1".into(),
            thread_ref: "thread:1".into(),
            mission: mission(),
            messages: vec![SessionMessage {
                role: SessionMessageRole::User,
                message_ref: "message:1".into(),
                actor_ref: "user:1".into(),
                text: "Check connector alpha.".into(),
                received_at: "2026-07-31T00:00:00Z".into(),
            }],
            events: Vec::new(),
            effect_authorizations: Vec::new(),
            pending_delivery: None,
            memories: Vec::new(),
        }
    }

    fn observation(complete: bool, fresh_until: Option<&str>) -> ToolObservation {
        ToolObservation {
            sequence: 1,
            call: ToolCall {
                call_id: "call:1".into(),
                tool_id: "connector.read".into(),
                purpose: "Read connector alpha.".into(),
                input: json!({"connector_ref": "connector:alpha"}),
            },
            descriptor: ToolDescriptor {
                tool_id: "connector.read".into(),
                title: "Connector read".into(),
                summary: "Reads one connector.".into(),
                authority_class: ToolAuthorityClass::Observe,
                effect_class: ToolEffectClass::Read,
                input_schema_ref: "schema:input".into(),
                result_schema_ref: "schema:result".into(),
            },
            result: ToolResult {
                state: ToolResultState::Succeeded,
                summary: "Connector alpha is healthy.".into(),
                data: json!({"status": "healthy"}),
                evidence: vec![crate::EvidenceRecord {
                    evidence_ref: "evidence:1".into(),
                    statement: "Connector alpha status was returned.".into(),
                    observed_at: "2026-07-31T00:00:00Z".into(),
                    fresh_until: fresh_until.map(str::to_owned),
                    complete,
                    atoms: vec![EvidenceAtom {
                        atom_ref: "atom:status".into(),
                        subject_ref: Some("connector:alpha".into()),
                        assertion: EvidenceAssertion::Value {
                            predicate: "status".into(),
                            value: json!("healthy"),
                        },
                        observed_at: "2026-07-31T00:00:00Z".into(),
                        fresh_until: fresh_until.map(str::to_owned),
                        complete,
                    }],
                }],
                blocker: None,
            },
        }
    }

    fn draft() -> GroundedDraft {
        GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: "Connector alpha is healthy. I would leave it unchanged.".into(),
            claims: vec![
                GroundedClaim {
                    claim_ref: "claim:state".into(),
                    planned_claim_ref: Some("claim:state".into()),
                    text: "Connector alpha is healthy.".into(),
                    required_for_answer: true,
                    content: ClaimContent::Observation {
                        atom_refs: vec!["atom:status".into()],
                    },
                },
                GroundedClaim {
                    claim_ref: "claim:recommendation".into(),
                    planned_claim_ref: None,
                    text: " I would leave it unchanged.".into(),
                    required_for_answer: false,
                    content: ClaimContent::Recommendation {
                        action: ActionSpec {
                            tool_id: None,
                            target_ref: Some("connector:alpha".into()),
                            input: json!({}),
                        },
                        rationale_atom_refs: vec!["atom:status".into()],
                    },
                },
            ],
            coverage_notice: None,
            question: None,
            mission: MissionState {
                status: SessionStatus::Completed,
                ..mission()
            },
            memory_updates: Vec::new(),
            presentation_ready: true,
        }
    }

    fn scheduled_commitment() -> Commitment {
        Commitment {
            commitment_ref: "commitment:scheduled-check".into(),
            summary: "Re-observe connector alpha at the scheduled boundary.".into(),
            owner: WorkOwner::Cerebro,
            status: CommitmentStatus::Waiting,
            next_action: Some("Read connector alpha and compare the current state.".into()),
            blocker: None,
            acceptance_criteria: vec!["A fresh connector state is recorded.".into()],
            artifact_refs: Vec::new(),
            required_tool_ids: vec!["connector.read".into()],
            attention_policy: Some(CommitmentAttentionPolicy {
                acceptance_all: vec![ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/status".into(),
                    equals: json!("healthy"),
                }],
                alert_any: Vec::new(),
            }),
            wake_at: Some("2026-07-31T00:00:30Z".into()),
            verification: Some("A current connector observation closes the check.".into()),
        }
    }

    fn plan() -> ResearchPlan {
        ResearchPlan {
            decision: "Establish the current connector state.".into(),
            lane: ExecutionLane::Investigate,
            resolved_entities: vec!["connector:alpha".into()],
            claims: vec![PlannedClaim {
                claim_ref: "claim:state".into(),
                question: "What is the current state?".into(),
                required: true,
                source_candidates: vec!["connector.read".into()],
            }],
            selected_tools: vec!["connector.read".into()],
            stop_conditions: vec!["Current state is observed.".into()],
            user_visible_work: vec!["Checking connector alpha.".into()],
            follow_through: None,
        }
    }

    fn planned_follow_through() -> PlannedFollowThrough {
        PlannedFollowThrough {
            commitment_ref: "commitment:scheduled-check".into(),
            required_tool_ids: vec!["connector.read".into()],
            acceptance_criteria: vec!["A fresh connector state is recorded.".into()],
            next_action: "Read connector alpha and compare the current state.".into(),
            attention_policy: CommitmentAttentionPolicy {
                acceptance_all: vec![ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/status".into(),
                    equals: json!("healthy"),
                }],
                alert_any: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "A current connector observation closes the check.".into(),
        }
    }

    struct ScriptedSessionModel {
        decisions: Mutex<VecDeque<SessionModelDecision>>,
    }

    #[async_trait]
    impl SessionAgentModel for ScriptedSessionModel {
        async fn advance(
            &self,
            _turn: SessionModelTurn,
        ) -> Result<SessionModelDecision, AgentRuntimeError> {
            self.decisions
                .lock()
                .expect("decision script poisoned")
                .pop_front()
                .ok_or(AgentRuntimeError::ModelStepLimit)
        }

        async fn review_message(
            &self,
            turn: ClaimReviewTurn,
        ) -> Result<MessageReview, AgentRuntimeError> {
            let message_digest = message_digest(&turn.draft.message);
            let claim_reviews = turn
                .draft
                .claims
                .into_iter()
                .map(|claim| ClaimReview {
                    claim_ref: claim.claim_ref,
                    verdict: ClaimReviewVerdict::Supported,
                    issue: None,
                })
                .collect();
            Ok(MessageReview {
                message_digest,
                claim_reviews,
                undeclared_material: Vec::new(),
                attention: AttentionReview {
                    delivery: turn.draft.delivery,
                    reason: "The scripted review accepts the requested delivery boundary.".into(),
                },
                behavioral: BehavioralReview {
                    answers_newest_request: true,
                    conversational: true,
                    owns_follow_through: true,
                    right_sized: true,
                    evidence_boundary_correct: true,
                },
            })
        }
    }

    struct RefiningSessionModel {
        decisions: Mutex<VecDeque<SessionModelDecision>>,
        reviews: AtomicUsize,
    }

    #[async_trait]
    impl SessionAgentModel for RefiningSessionModel {
        async fn advance(
            &self,
            _turn: SessionModelTurn,
        ) -> Result<SessionModelDecision, AgentRuntimeError> {
            self.decisions
                .lock()
                .expect("decision script poisoned")
                .pop_front()
                .ok_or(AgentRuntimeError::ModelStepLimit)
        }

        async fn review_message(
            &self,
            turn: ClaimReviewTurn,
        ) -> Result<MessageReview, AgentRuntimeError> {
            let review_number = self.reviews.fetch_add(1, Ordering::SeqCst);
            let mut claim_reviews = turn
                .draft
                .claims
                .iter()
                .map(|claim| ClaimReview {
                    claim_ref: claim.claim_ref.clone(),
                    verdict: ClaimReviewVerdict::Supported,
                    issue: None,
                })
                .collect::<Vec<_>>();
            let mut behavioral = BehavioralReview {
                answers_newest_request: true,
                conversational: true,
                owns_follow_through: true,
                right_sized: true,
                evidence_boundary_correct: true,
            };
            if review_number == 0 {
                claim_reviews[0].verdict = ClaimReviewVerdict::Unsupported;
                claim_reviews[0].issue = Some("State the observed scope precisely.".into());
            } else if review_number == 1 {
                behavioral.conversational = false;
            }
            Ok(MessageReview {
                message_digest: message_digest(&turn.draft.message),
                claim_reviews,
                undeclared_material: Vec::new(),
                attention: AttentionReview {
                    delivery: turn.draft.delivery,
                    reason: "The scripted review accepts the requested delivery boundary.".into(),
                },
                behavioral,
            })
        }
    }

    struct ConnectorTools;

    #[async_trait]
    impl SessionTools for ConnectorTools {
        fn catalog(&self) -> Vec<ToolDescriptor> {
            vec![observation(true, Some("2026-08-01T00:00:00Z")).descriptor]
        }

        async fn invoke(
            &self,
            _session: &AgentSession,
            _input: &SessionTurnInput,
            _call: &ToolCall,
        ) -> Result<ToolResult, AgentRuntimeError> {
            Ok(observation(true, Some("2026-08-01T00:00:00Z")).result)
        }
    }

    struct CountingEffectTools {
        invocations: AtomicUsize,
        descriptor: ToolDescriptor,
    }

    struct WakeTools {
        effects: AtomicUsize,
    }

    #[async_trait]
    impl SessionTools for WakeTools {
        fn catalog(&self) -> Vec<ToolDescriptor> {
            let read = observation(true, Some("2026-08-01T00:00:00Z")).descriptor;
            let mut update = read.clone();
            update.tool_id = "connector.update".into();
            update.authority_class = ToolAuthorityClass::Actuate;
            update.effect_class = ToolEffectClass::Write;
            vec![read, update]
        }

        async fn invoke(
            &self,
            _session: &AgentSession,
            _input: &SessionTurnInput,
            call: &ToolCall,
        ) -> Result<ToolResult, AgentRuntimeError> {
            if call.tool_id == "connector.update" {
                self.effects.fetch_add(1, Ordering::SeqCst);
                return Err(AgentRuntimeError::InvalidToolCall(
                    "a wake effect reached the tool adapter".into(),
                ));
            }
            Ok(observation(true, Some("2026-08-01T00:00:00Z")).result)
        }
    }

    #[async_trait]
    impl SessionTools for CountingEffectTools {
        fn catalog(&self) -> Vec<ToolDescriptor> {
            vec![self.descriptor.clone()]
        }

        async fn invoke(
            &self,
            _session: &AgentSession,
            _input: &SessionTurnInput,
            _call: &ToolCall,
        ) -> Result<ToolResult, AgentRuntimeError> {
            self.invocations.fetch_add(1, Ordering::SeqCst);
            Err(AgentRuntimeError::ToolUnavailable(
                "the resumed effect must not run again".into(),
            ))
        }
    }

    #[test]
    fn validates_a_conversational_provenance_bound_answer() {
        let validated = validate_grounded_draft(
            &session(),
            &draft(),
            &[observation(true, Some("2026-08-01T00:00:00Z"))],
            OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
        )
        .unwrap();
        assert_eq!(validated.markdown, draft().message);
        assert_eq!(validated.evidence_atom_refs, vec!["atom:status"]);
    }

    #[test]
    fn rejects_current_claims_from_stale_or_partial_atoms() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        assert!(
            validate_grounded_draft(
                &session(),
                &draft(),
                &[observation(false, Some("2026-08-01T00:00:00Z"))],
                assessment,
            )
            .is_err()
        );
        assert!(
            validate_grounded_draft(
                &session(),
                &draft(),
                &[observation(true, Some("2026-07-30T00:00:00Z"))],
                assessment,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unscheduled_cerebro_promises() {
        let mut promise = draft();
        promise.mission.commitments.push(Commitment {
            commitment_ref: "commitment:1".into(),
            summary: "Keep investigating.".into(),
            owner: WorkOwner::Cerebro,
            status: CommitmentStatus::InProgress,
            next_action: Some("Read the next source.".into()),
            blocker: None,
            acceptance_criteria: vec!["Cause established.".into()],
            artifact_refs: Vec::new(),
            required_tool_ids: Vec::new(),
            attention_policy: None,
            wake_at: None,
            verification: None,
        });
        assert!(
            validate_grounded_draft(
                &session(),
                &promise,
                &[observation(true, Some("2026-08-01T00:00:00Z"))],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_future_work_disguised_as_a_stable_explanation() {
        let mut promise = draft();
        promise.message = "I’ll check back at 14:27 UTC.".into();
        promise.claims = vec![GroundedClaim {
            claim_ref: "claim:unbound-future-work".into(),
            planned_claim_ref: None,
            text: promise.message.clone(),
            required_for_answer: true,
            content: ClaimContent::StableExplanation,
        }];

        let error = validate_grounded_draft(
            &session(),
            &promise,
            &[observation(true, Some("2026-08-01T00:00:00Z"))],
            OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
        )
        .expect_err("future work requires a real commitment claim");
        assert!(error.to_string().contains("exact active commitment"));
    }

    #[test]
    fn accepts_only_executor_bound_cerebro_commitments() {
        let mut scheduled = draft();
        scheduled.mission.commitments.push(scheduled_commitment());
        scheduled.mission.status = SessionStatus::WaitingForExternal;
        assert!(validate_mission(&scheduled.mission).is_ok());

        scheduled.mission.commitments[0].verification = None;
        assert!(validate_mission(&scheduled.mission).is_err());
    }

    #[test]
    fn commitment_claims_are_bound_to_the_exact_draft_scheduler_record() {
        let mut scheduled = draft();
        scheduled.message = "I’ll re-check connector alpha at the recorded wake time.".into();
        scheduled.claims = vec![GroundedClaim {
            claim_ref: "claim:scheduled-follow-through".into(),
            planned_claim_ref: None,
            text: scheduled.message.clone(),
            required_for_answer: false,
            content: ClaimContent::Commitment {
                commitment_ref: "commitment:scheduled-check".into(),
            },
        }];
        scheduled.mission.commitments.push(scheduled_commitment());
        scheduled.mission.status = SessionStatus::WaitingForExternal;
        assert!(
            validate_grounded_draft(
                &session(),
                &scheduled,
                &[],
                OffsetDateTime::parse("2026-07-31T00:00:00Z", &Rfc3339).unwrap(),
            )
            .is_ok()
        );

        let ClaimContent::Commitment { commitment_ref } = &mut scheduled.claims[0].content else {
            unreachable!()
        };
        *commitment_ref = "commitment:unknown".into();
        assert!(
            validate_grounded_draft(
                &session(),
                &scheduled,
                &[],
                OffsetDateTime::parse("2026-07-31T00:00:00Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_visible_material_outside_ordered_grounded_units() {
        let mut unclaimed = draft();
        unclaimed.message = format!("Unreviewed prefix. {}", unclaimed.message);
        assert!(matches!(
            validate_grounded_draft(
                &session(),
                &unclaimed,
                &[observation(true, Some("2026-08-01T00:00:00Z"))],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            ),
            Err(AgentRuntimeError::InvalidFinal(_))
        ));
    }

    #[test]
    fn full_message_review_is_digest_bound_and_behavioral() {
        let draft = draft();
        let review = MessageReview {
            message_digest: message_digest(&draft.message),
            claim_reviews: draft
                .claims
                .iter()
                .map(|claim| ClaimReview {
                    claim_ref: claim.claim_ref.clone(),
                    verdict: ClaimReviewVerdict::Supported,
                    issue: None,
                })
                .collect(),
            undeclared_material: vec!["The prefix claims a current fact.".into()],
            attention: AttentionReview {
                delivery: draft.delivery,
                reason: "This response requires normal visible delivery.".into(),
            },
            behavioral: BehavioralReview {
                answers_newest_request: true,
                conversational: false,
                owns_follow_through: true,
                right_sized: true,
                evidence_boundary_correct: true,
            },
        };
        let issues = validate_message_review(&draft, &review).unwrap();
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("undeclared material"))
        );
        assert!(
            issues
                .iter()
                .any(|issue| issue.contains("conversationally"))
        );
        let mut attention_mismatch = review.clone();
        attention_mismatch.attention.delivery = DeliveryDisposition::Silent;
        let issues = validate_message_review(&draft, &attention_mismatch).unwrap();
        assert!(
            !issues
                .iter()
                .any(|issue| issue.contains("attention review"))
        );
        let mut wrong_digest = review;
        wrong_digest.message_digest = format!("sha256:{}", "0".repeat(64));
        assert!(validate_message_review(&draft, &wrong_digest).is_err());
    }

    #[test]
    fn internal_plan_claims_do_not_force_user_visible_prose() {
        let mut unfinished = draft();
        unfinished.claims[0].planned_claim_ref = None;
        assert!(validate_plan_completion(Some(&plan()), &unfinished).is_ok());

        let mut over_budget = plan();
        over_budget.lane = ExecutionLane::Lookup;
        over_budget.selected_tools = vec![
            "one".into(),
            "two".into(),
            "three".into(),
            "four".into(),
            "five".into(),
        ];
        assert!(validate_plan(&over_budget, &over_budget.selected_tools.clone()).is_err());
    }

    #[test]
    fn effect_verification_requires_the_expected_target_and_assertion() {
        let mut effect = observation(true, Some("2026-08-01T00:00:00Z"));
        effect.descriptor.authority_class = ToolAuthorityClass::Actuate;
        effect.call.tool_id = "connector.update".into();
        effect.call.input = json!({"connector_ref": "connector:alpha"});
        effect.result.data = json!({
            "verification_expectation": {
                "target_ref": "connector:alpha",
                "input_digest": effect.call.input_digest(),
                "assertions": {"/collection_receipt": "complete"}
            }
        });
        let mut verification = observation(true, Some("2026-08-01T00:00:00Z"));
        verification.sequence = 2;
        verification.call.call_id = "call:2".into();
        verification.call.input = json!({"connector_ref": "connector:alpha"});
        verification.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/collection_receipt".into(),
            value: json!("complete"),
        };
        assert!(
            validate_effect_closure(
                &[effect.clone(), verification.clone()],
                &draft(),
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_ok()
        );
        verification.result.evidence[0].atoms[0].subject_ref = Some("connector:other".into());
        assert!(
            validate_effect_closure(
                &[effect, verification],
                &draft(),
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn effect_authorization_requires_the_runtime_issued_approval_identity() {
        let call = ToolCall {
            call_id: "call:effect-approval".into(),
            tool_id: "connector.update".into(),
            purpose: "Update connector alpha.".into(),
            input: json!({"connector_ref": "connector:alpha", "enabled": false}),
        };
        let input = SessionTurnInput {
            request_id: "request:1".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            trigger: SessionTurnTrigger::Operator,
        };
        let mut authorized = session();
        authorized.effect_authorizations.push(EffectAuthorization {
            approval_ref: "approval://agent-effect/not-the-issued-identity".into(),
            tenant_id: authorized.tenant_id.clone(),
            request_id: input.request_id.clone(),
            thread_ref: authorized.thread_ref.clone(),
            actor_ref: input.actor_ref.clone(),
            tool_id: call.tool_id.clone(),
            input_digest: call.input_digest(),
        });
        assert!(matching_effect_authorization(&authorized, &input, &call).is_none());

        authorized.effect_authorizations[0].approval_ref = format!(
            "approval://agent-effect/{}",
            call.input_digest().trim_start_matches("sha256:")
        );
        assert!(matching_effect_authorization(&authorized, &input, &call).is_some());
    }

    #[test]
    fn mission_and_assistant_message_commit_only_after_delivery() {
        let initial = session();
        let pending = apply_session_events(
            &initial,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: initial.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::DraftProduced {
                    request_id: "request:1".into(),
                    draft: draft(),
                },
            }],
        )
        .unwrap();
        assert!(pending.pending_delivery.is_some());
        assert_eq!(pending.messages.len(), 1);
        assert_eq!(pending.mission.status, SessionStatus::Active);

        let delivered = apply_session_events(
            &pending,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: pending.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:02:00Z".into(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: "request:1".into(),
                    transport: "slack".into(),
                    delivery_ref: "slack-message:1".into(),
                    payload_digest: message_digest(&draft().message),
                },
            }],
        )
        .unwrap();
        assert!(delivered.pending_delivery.is_none());
        assert_eq!(delivered.messages.len(), 2);
        assert_eq!(delivered.mission.status, SessionStatus::Completed);
    }

    #[test]
    fn silent_scheduler_completion_commits_state_without_faking_a_slack_message() {
        let initial = session();
        let mut internal = draft();
        internal.delivery = DeliveryDisposition::Silent;
        let pending = apply_session_events(
            &initial,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: initial.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::DraftProduced {
                    request_id: "wake-request:quiet".into(),
                    draft: internal.clone(),
                },
            }],
        )
        .unwrap();
        let completed = apply_session_events(
            &pending,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: pending.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:02:00Z".into(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: "wake-request:quiet".into(),
                    transport: "internal_scheduler".into(),
                    delivery_ref: "occurrence:quiet".into(),
                    payload_digest: message_digest(&internal.message),
                },
            }],
        )
        .unwrap();
        assert!(completed.pending_delivery.is_none());
        assert_eq!(completed.messages.len(), initial.messages.len());
        assert_eq!(completed.mission, internal.mission);
    }

    #[test]
    fn durable_memory_events_are_recalled_in_the_session_snapshot() {
        let initial = session();
        let updated = apply_session_events(
            &initial,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: initial.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::MemoryRecorded {
                    update: MemoryUpdate {
                        memory_ref: "memory:connector-alpha".into(),
                        kind: MemoryKind::Blocker,
                        statement: "Connector alpha needs a fresh receipt.".into(),
                        evidence_atom_refs: vec!["atom:status".into()],
                        promotion_requested: false,
                    },
                },
            }],
        )
        .unwrap();
        assert_eq!(updated.memories.len(), 1);
        assert_eq!(
            updated.memories[0].statement,
            "Connector alpha needs a fresh receipt."
        );
        let serialized = serde_json::to_value(&updated).unwrap();
        let reloaded: AgentSession = serde_json::from_value(serialized).unwrap();
        assert_eq!(reloaded.memories, updated.memories);
    }

    #[test]
    fn validates_selected_tools_against_the_host_catalog() {
        let plan = plan();
        assert!(validate_plan(&plan, &["connector.read".into()]).is_ok());
        assert!(validate_plan(&plan, &["graph.read".into()]).is_err());
    }

    #[test]
    fn invalid_follow_through_plan_reports_the_exact_field() {
        let mut invalid = plan();
        invalid.follow_through = Some(PlannedFollowThrough {
            commitment_ref: "commitment:later-check".into(),
            required_tool_ids: vec!["graph.read".into()],
            acceptance_criteria: vec!["A fresh state is recorded.".into()],
            next_action: "Read the graph again.".into(),
            attention_policy: CommitmentAttentionPolicy {
                acceptance_all: vec![ObservationCondition {
                    tool_id: "graph.read".into(),
                    data_pointer: "/decision_grade".into(),
                    equals: json!(true),
                }],
                alert_any: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "graph.read reports decision_grade=true".into(),
        });
        let error =
            validate_plan(&invalid, &["connector.read".into(), "graph.read".into()]).unwrap_err();
        assert!(error.to_string().contains("selected_tools: graph.read"));

        invalid.selected_tools.push("graph.read".into());
        invalid.follow_through.as_mut().unwrap().required_tool_ids =
            vec!["graph.read".into(), "graph.read".into()];
        let error =
            validate_plan(&invalid, &["connector.read".into(), "graph.read".into()]).unwrap_err();
        assert!(error.to_string().contains("must be unique"));
    }

    #[test]
    fn planned_alerts_reject_ordinary_progress_values() {
        let mut proposed = plan();
        let mut follow_through = planned_follow_through();
        follow_through
            .attention_policy
            .alert_any
            .push(ObservationCondition {
                tool_id: "connector.read".into(),
                data_pointer: "/receipt_count".into(),
                equals: json!(2),
            });
        proposed.follow_through = Some(follow_through);
        let error = validate_plan(&proposed, &["connector.read".into()]).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("explicit boolean authority signals")
        );
    }

    #[test]
    fn rust_materializes_the_planned_executor_contract() {
        let current = session();
        let mut proposed = plan();
        proposed.follow_through = Some(planned_follow_through());
        let mut answer = draft();
        let mut invented = scheduled_commitment();
        invented.commitment_ref = "commitment:invented".into();
        invented.required_tool_ids = vec!["graph.read".into()];
        answer.mission.commitments.push(invented);

        materialize_planned_follow_through(
            &current,
            &SessionTurnTrigger::Operator,
            Some(&proposed),
            OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            &mut answer,
        )
        .unwrap();

        assert_eq!(answer.mission.status, SessionStatus::WaitingForExternal);
        assert_eq!(answer.mission.commitments.len(), 1);
        let commitment = &answer.mission.commitments[0];
        assert_eq!(commitment.commitment_ref, "commitment:scheduled-check");
        assert_eq!(commitment.required_tool_ids, vec!["connector.read"]);
        assert_eq!(
            commitment.attention_policy.as_ref(),
            Some(&planned_follow_through().attention_policy)
        );
        assert_eq!(commitment.wake_at.as_deref(), Some("2026-07-31T00:06:00Z"));
    }

    #[test]
    fn planned_follow_through_cannot_disappear_from_the_final_mission() {
        let mut plan = plan();
        plan.follow_through = Some(PlannedFollowThrough {
            commitment_ref: "commitment:scheduled-check".into(),
            required_tool_ids: vec!["connector.read".into()],
            acceptance_criteria: vec!["A fresh connector state is recorded.".into()],
            next_action: "Read connector alpha and compare the current state.".into(),
            attention_policy: CommitmentAttentionPolicy {
                acceptance_all: vec![ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/status".into(),
                    equals: json!("healthy"),
                }],
                alert_any: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "A current connector observation closes the check.".into(),
        });
        let mut answer = draft();
        assert!(validate_plan_completion(Some(&plan), &answer).is_err());
        answer.mission.commitments.push(scheduled_commitment());
        assert!(validate_plan_completion(Some(&plan), &answer).is_ok());
    }

    #[test]
    fn planned_follow_through_requires_the_named_exact_executor() {
        let mut plan = plan();
        plan.follow_through = Some(PlannedFollowThrough {
            commitment_ref: "commitment:scheduled-check".into(),
            required_tool_ids: vec!["connector.read".into()],
            acceptance_criteria: vec!["A fresh connector state is recorded.".into()],
            next_action: "Read connector alpha and compare the current state.".into(),
            attention_policy: CommitmentAttentionPolicy {
                acceptance_all: vec![ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/status".into(),
                    equals: json!("healthy"),
                }],
                alert_any: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "A current connector observation closes the check.".into(),
        });
        let mut answer = draft();
        let mut commitment = scheduled_commitment();
        commitment.required_tool_ids = vec!["graph.read".into()];
        answer.mission.commitments.push(commitment);
        assert_eq!(
            answer.mission.commitments[0].required_tool_ids,
            vec!["graph.read"]
        );
        assert!(validate_plan_completion(Some(&plan), &answer).is_err());

        answer.mission.commitments[0] = scheduled_commitment();
        assert!(validate_plan_completion(Some(&plan), &answer).is_ok());

        answer.mission.commitments[0].acceptance_criteria = vec!["Different criterion.".into()];
        assert!(validate_plan_completion(Some(&plan), &answer).is_err());

        answer.mission.commitments[0] = scheduled_commitment();
        answer.mission.commitments[0].commitment_ref = "commitment:other".into();
        assert!(validate_plan_completion(Some(&plan), &answer).is_err());
    }

    #[test]
    fn planned_follow_through_replans_before_copying_a_failed_executor() {
        let mut plan = plan();
        plan.selected_tools.push("graph.read".into());
        plan.follow_through = Some(PlannedFollowThrough {
            commitment_ref: "commitment:scheduled-check".into(),
            required_tool_ids: vec!["connector.read".into()],
            acceptance_criteria: vec!["A fresh connector state is recorded.".into()],
            next_action: "Read connector alpha and compare the current state.".into(),
            attention_policy: CommitmentAttentionPolicy {
                acceptance_all: vec![ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/status".into(),
                    equals: json!("healthy"),
                }],
                alert_any: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "A current connector observation closes the check.".into(),
        });
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();

        let missing =
            validate_planned_follow_through_viability(Some(&plan), &[], assessment_at).unwrap_err();
        assert!(missing.to_string().contains("Invoke that selected read"));

        let mut failed = observation(true, Some("2026-07-31T00:06:00Z"));
        failed.result.state = ToolResultState::Failed;
        let mut alternative = observation(true, Some("2026-07-31T00:06:00Z"));
        alternative.call.tool_id = "graph.read".into();
        let stale = validate_planned_follow_through_viability(
            Some(&plan),
            &[failed, alternative],
            assessment_at,
        )
        .unwrap_err();
        assert!(stale.to_string().contains("graph.read"));
        assert!(stale.to_string().contains("Return establish_plan now"));

        let current = observation(true, Some("2026-07-31T00:06:00Z"));
        assert!(
            validate_planned_follow_through_viability(Some(&plan), &[current], assessment_at)
                .is_ok()
        );
    }

    #[test]
    fn read_calls_can_adapt_a_plan_but_effects_cannot() {
        let catalog = SessionTools::catalog(&WakeTools {
            effects: AtomicUsize::new(0),
        });
        let connector_read = catalog
            .iter()
            .find(|descriptor| descriptor.tool_id == "connector.read")
            .unwrap()
            .clone();
        let connector_update = catalog
            .iter()
            .find(|descriptor| descriptor.tool_id == "connector.update")
            .unwrap()
            .clone();
        let mut graph_read = connector_read.clone();
        graph_read.tool_id = "graph.read".into();
        let descriptors = BTreeMap::from([
            ("connector.read".into(), connector_read),
            ("graph.read".into(), graph_read),
            ("connector.update".into(), connector_update),
        ]);
        let read_call = ToolCall {
            call_id: "call:adaptive-read".into(),
            tool_id: "graph.read".into(),
            purpose: "Read one additional bounded view.".into(),
            input: json!({}),
        };
        let expanded = expand_plan_for_read_calls(
            &plan(),
            &[read_call],
            &descriptors,
            &["connector.read".into(), "graph.read".into()],
        )
        .unwrap()
        .expect("an available read should widen the plan");
        assert!(expanded.selected_tools.contains(&"graph.read".into()));
        assert!(
            expanded.claims[0]
                .source_candidates
                .contains(&"graph.read".into())
        );

        let effect_call = ToolCall {
            call_id: "call:unplanned-effect".into(),
            tool_id: "connector.update".into(),
            purpose: "Attempt an unplanned effect.".into(),
            input: json!({}),
        };
        assert!(
            expand_plan_for_read_calls(
                &plan(),
                &[effect_call],
                &descriptors,
                &["connector.read".into(), "connector.update".into()],
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn commitment_checkpoint_recovers_the_latest_summary_for_the_exact_commitment() {
        let mut awakened = session();
        let mut prior_draft = draft();
        prior_draft.delivery = DeliveryDisposition::Silent;
        prior_draft.message = "Two of three receipts are current; checking again.".into();
        prior_draft.mission.commitments.push(scheduled_commitment());
        awakened.events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:00:59Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "request:initiating-operator-turn".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::ToolInvoked {
                    observation: observation(true, Some("2026-07-31T00:06:00Z")),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 3,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::DraftProduced {
                    request_id: "request:initiating-operator-turn".into(),
                    draft: prior_draft,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 4,
                occurred_at: "2026-07-31T00:01:01Z".into(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: "request:initiating-operator-turn".into(),
                    transport: "internal_scheduler".into(),
                    delivery_ref: "occurrence:initiating-turn".into(),
                    payload_digest: format!("sha256:{}", "a".repeat(64)),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 5,
                occurred_at: "2026-07-31T00:01:02Z".into(),
                event: SessionEvent::TurnCompleted {
                    request_id: "request:initiating-operator-turn".into(),
                    state: FinalState::Answered,
                },
            },
        ];
        let checkpoint = prior_commitment_checkpoint(
            &awakened,
            &SessionTurnTrigger::Wake {
                commitment_ref: "commitment:scheduled-check".into(),
                occurrence_ref: "occurrence:next-wake".into(),
            },
        )
        .expect("the initiating commitment summary should remain available as continuity");
        assert_eq!(checkpoint.delivery, DeliveryDisposition::Silent);
        assert_eq!(
            checkpoint.summary,
            "Two of three receipts are current; checking again."
        );
        assert_eq!(checkpoint.recorded_at, "2026-07-31T00:01:02Z");
        assert_eq!(
            checkpoint.source_request_id,
            "request:initiating-operator-turn"
        );
        assert_eq!(checkpoint.delivery_ref, "occurrence:initiating-turn");
        assert_eq!(checkpoint.observations.len(), 1);
        assert_eq!(checkpoint.observations[0].tool_id, "connector.read");
        assert!(prior_commitment_checkpoint(&awakened, &SessionTurnTrigger::Operator).is_none());
    }

    #[test]
    fn commitment_checkpoint_ignores_unfinished_or_undelivered_drafts() {
        let mut awakened = session();
        let mut prior_draft = draft();
        prior_draft.mission.commitments.push(scheduled_commitment());
        awakened.events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:00:59Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "request:unfinished".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::DraftProduced {
                    request_id: "request:unfinished".into(),
                    draft: prior_draft,
                },
            },
        ];

        assert!(
            prior_commitment_checkpoint(
                &awakened,
                &SessionTurnTrigger::Wake {
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:next-wake".into(),
                },
            )
            .is_none()
        );
    }

    #[test]
    fn exhausted_wake_blocks_the_exact_commitment_and_creates_visible_delivery() {
        let mut current = session();
        current.mission.commitments.push(scheduled_commitment());
        current.mission.status = SessionStatus::WaitingForExternal;
        let mut blocked = draft();
        blocked.state = FinalState::Blocked;
        blocked.delivery = DeliveryDisposition::Visible;
        blocked.message = "The scheduled check exhausted five attempts.".into();
        blocked.coverage_notice = Some("The scheduled check could not complete.".into());
        blocked.mission = current.mission.clone();
        blocked.mission.status = SessionStatus::Blocked;
        blocked.mission.commitments[0].status = CommitmentStatus::Blocked;
        blocked.mission.commitments[0].blocker = Some("Five attempts exhausted.".into());
        blocked.mission.commitments[0].next_action = None;
        blocked.mission.commitments[0].wake_at = None;
        let event = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: current.session_ref.clone(),
            sequence: 1,
            occurred_at: "2026-07-31T00:01:00Z".into(),
            event: SessionEvent::WakeExhausted {
                request_id: "wake-request:exhausted".into(),
                commitment_ref: "commitment:scheduled-check".into(),
                occurrence_ref: "occurrence:exhausted".into(),
                schedule_generation: 5,
                failure_class: "scheduled wake execution failed".into(),
                draft: blocked,
            },
        };

        let updated = apply_session_events(&current, &[event]).unwrap();

        assert_eq!(updated.mission.status, SessionStatus::Blocked);
        assert_eq!(
            updated.mission.commitments[0].status,
            CommitmentStatus::Blocked
        );
        assert!(updated.mission.commitments[0].wake_at.is_none());
        let pending = updated
            .pending_delivery
            .expect("exhaustion must produce a durable operator update");
        assert_eq!(pending.request_id, "wake-request:exhausted");
        assert_eq!(pending.draft.delivery, DeliveryDisposition::Visible);
        assert_eq!(pending.draft.state, FinalState::Blocked);
    }

    #[tokio::test]
    async fn one_loop_plans_reads_reviews_and_prepares_delivery() {
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan { plan: plan() },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:1".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Read connector alpha.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::Finish { draft: draft() },
            ])),
        };
        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            session(),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .unwrap();
        let SessionTurnOutcome::PendingDelivery {
            markdown,
            evidence_atom_refs,
            events,
            ..
        } = outcome
        else {
            panic!("expected a pending-delivery session turn")
        };
        assert_eq!(markdown, draft().message);
        assert_eq!(evidence_atom_refs, vec!["atom:status"]);
        assert_eq!(events.first().map(|event| event.sequence), Some(1));
        assert!(
            events
                .windows(2)
                .all(|pair| pair[1].sequence == pair[0].sequence + 1)
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.event, SessionEvent::PlanEstablished { .. }))
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.event, SessionEvent::TurnCompleted { .. }))
        );
        assert!(
            events
                .iter()
                .any(|event| matches!(event.event, SessionEvent::DraftProduced { .. }))
        );
    }

    #[tokio::test]
    async fn due_wake_runs_as_scheduler_control_without_faking_a_user_message() {
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        let original_message_count = awakened.messages.len();
        awakened = apply_session_events(
            &awakened,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::WakeTriggered {
                    request_id: "wake-request:1".into(),
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:1".into(),
                    scheduled_for: "2026-07-31T00:00:30Z".into(),
                },
            }],
        )
        .unwrap();
        assert_eq!(awakened.messages.len(), original_message_count);
        let mut completed = draft();
        completed.mission = awakened.mission.clone();
        let commitment = completed
            .mission
            .commitments
            .iter_mut()
            .find(|commitment| commitment.commitment_ref == "commitment:scheduled-check")
            .unwrap();
        commitment.status = CommitmentStatus::Completed;
        commitment.next_action = None;
        commitment.wake_at = None;
        completed.mission.status = SessionStatus::Completed;
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan { plan: plan() },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:wake:1".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Complete the scheduled connector observation.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::Finish { draft: completed },
            ])),
        };

        let outcome = run_session_turn_recorded(
            &model,
            &ConnectorTools,
            &NoopSessionJournal,
            awakened,
            SessionTurnInput {
                request_id: "wake-request:1".into(),
                actor_ref: "cerebro-scheduler".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Wake {
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:1".into(),
                },
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SessionTurnOutcome::PendingDelivery { .. }
        ));
    }

    #[test]
    fn wake_completion_requires_the_commitments_fresh_tools_in_that_wake() {
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        let mut completed = draft();
        completed.mission = awakened.mission.clone();
        completed.mission.commitments[0].status = CommitmentStatus::Completed;
        completed.mission.commitments[0].next_action = None;
        completed.mission.commitments[0].wake_at = None;
        completed.mission.status = SessionStatus::Completed;
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:required-tools".into(),
        };
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();

        let error = validate_wake_completion(&awakened, &completed, &trigger, assessment_at, &[])
            .unwrap_err();
        assert!(error.to_string().contains("connector.read"));

        let current = observation(true, Some("2026-07-31T00:06:00Z"));
        assert!(
            validate_wake_completion(&awakened, &completed, &trigger, assessment_at, &[current],)
                .is_ok()
        );

        let mut prior_draft = draft();
        prior_draft.mission = awakened.mission.clone();
        awakened.events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:00:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "request:prior".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:00:00Z".into(),
                event: SessionEvent::ToolInvoked {
                    observation: observation(true, Some("2026-07-31T00:06:00Z")),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 3,
                occurred_at: "2026-07-31T00:00:00Z".into(),
                event: SessionEvent::DraftProduced {
                    request_id: "request:prior".into(),
                    draft: prior_draft,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 4,
                occurred_at: "2026-07-31T00:00:01Z".into(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: "request:prior".into(),
                    transport: "slack".into(),
                    delivery_ref: "delivery:prior".into(),
                    payload_digest: format!("sha256:{}", "b".repeat(64)),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 5,
                occurred_at: "2026-07-31T00:00:02Z".into(),
                event: SessionEvent::TurnCompleted {
                    request_id: "request:prior".into(),
                    state: FinalState::Answered,
                },
            },
        ];
        let mut wrong_subject = observation(true, Some("2026-07-31T00:06:00Z"));
        wrong_subject.call.input = json!({"connector_ref": "connector:beta"});
        let error = validate_wake_completion(
            &awakened,
            &completed,
            &trigger,
            assessment_at,
            &[wrong_subject],
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("exact prior completed-check input")
        );
    }

    #[test]
    fn new_commitments_require_a_same_turn_complete_fresh_baseline() {
        let session = session();
        let mut scheduled = draft();
        scheduled.mission.commitments.push(scheduled_commitment());
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();

        let error =
            validate_commitment_baselines(&session, &scheduled, Some(&plan()), &[], assessment_at)
                .unwrap_err();
        assert!(error.to_string().contains("baseline observation"));

        let mut current = observation(true, Some("2026-07-31T00:06:00Z"));
        current.result.data = json!({"status": "recovering"});
        assert!(
            validate_commitment_baselines(
                &session,
                &scheduled,
                Some(&plan()),
                std::slice::from_ref(&current),
                assessment_at,
            )
            .is_ok()
        );

        let incomplete = observation(false, Some("2026-07-31T00:06:00Z"));
        assert!(
            validate_commitment_baselines(
                &session,
                &scheduled,
                Some(&plan()),
                &[incomplete],
                assessment_at,
            )
            .is_err()
        );

        let mut failed = observation(true, Some("2026-07-31T00:06:00Z"));
        failed.result.state = ToolResultState::Failed;
        let error = validate_commitment_baselines(
            &session,
            &scheduled,
            Some(&plan()),
            std::slice::from_ref(&failed),
            assessment_at,
        )
        .unwrap_err();
        assert!(error.to_string().contains("last result was Failed"));
        assert!(error.to_string().contains("materially revised plan"));

        let mut alternative = observation(true, Some("2026-07-31T00:06:00Z"));
        alternative.call.tool_id = "graph.read".into();
        let error = validate_commitment_baselines(
            &session,
            &scheduled,
            Some(&plan()),
            &[failed.clone(), alternative],
            assessment_at,
        )
        .unwrap_err();
        assert!(error.to_string().contains("graph.read"));
        assert!(error.to_string().contains("Return establish_plan now"));

        let already_accepted = observation(true, Some("2026-07-31T00:06:00Z"));
        let error = validate_commitment_baselines(
            &session,
            &scheduled,
            Some(&plan()),
            &[already_accepted],
            assessment_at,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already satisfied"));
    }

    #[test]
    fn new_commitments_must_classify_false_baseline_signals() {
        let session = session();
        let mut scheduled = draft();
        let mut commitment = scheduled_commitment();
        commitment.attention_policy = Some(CommitmentAttentionPolicy {
            acceptance_all: vec![ObservationCondition {
                tool_id: "connector.read".into(),
                data_pointer: "/decision_grade".into(),
                equals: json!(true),
            }],
            alert_any: Vec::new(),
        });
        scheduled.mission.commitments.push(commitment);
        let mut baseline = observation(true, Some("2026-07-31T00:06:00Z"));
        baseline.result.data = json!({"decision_grade": false, "streak_reset": false});
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let error = validate_commitment_baselines(
            &session,
            &scheduled,
            Some(&plan()),
            std::slice::from_ref(&baseline),
            assessment_at,
        )
        .unwrap_err();
        assert!(error.to_string().contains("/streak_reset"));
        assert!(error.to_string().contains("acceptance_all"));
        assert!(error.to_string().contains("Do not use equals=false"));

        scheduled.mission.commitments[0]
            .attention_policy
            .as_mut()
            .unwrap()
            .alert_any
            .push(ObservationCondition {
                tool_id: "connector.read".into(),
                data_pointer: "/streak_reset".into(),
                equals: json!(true),
            });
        assert!(
            validate_commitment_baselines(
                &session,
                &scheduled,
                Some(&plan()),
                std::slice::from_ref(&baseline),
                assessment_at,
            )
            .is_ok()
        );

        scheduled.mission.commitments[0]
            .attention_policy
            .as_mut()
            .unwrap()
            .alert_any[0]
            .equals = json!(false);
        let error = validate_commitment_baselines(
            &session,
            &scheduled,
            Some(&plan()),
            std::slice::from_ref(&baseline),
            assessment_at,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already true at baseline"));
        assert!(error.to_string().contains("/streak_reset"));
        assert!(error.to_string().contains("desired future success"));
    }

    #[test]
    fn redundant_current_state_alerts_are_removed_when_acceptance_owns_the_transition() {
        let session = session();
        let mut scheduled = draft();
        let mut commitment = scheduled_commitment();
        commitment.attention_policy = Some(CommitmentAttentionPolicy {
            acceptance_all: vec![ObservationCondition {
                tool_id: "connector.read".into(),
                data_pointer: "/decision_grade".into(),
                equals: json!(true),
            }],
            alert_any: vec![
                ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/decision_grade".into(),
                    equals: json!(false),
                },
                ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/streak_reset".into(),
                    equals: json!(true),
                },
            ],
        });
        scheduled.mission.commitments.push(commitment);
        let mut baseline = observation(true, Some("2026-07-31T00:06:00Z"));
        baseline.result.data = json!({"decision_grade": false, "streak_reset": false});

        normalize_redundant_baseline_alerts(
            &session,
            &mut scheduled,
            std::slice::from_ref(&baseline),
        );

        let alerts = &scheduled.mission.commitments[0]
            .attention_policy
            .as_ref()
            .unwrap()
            .alert_any;
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].data_pointer, "/streak_reset");
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        assert!(
            validate_commitment_baselines(
                &session,
                &scheduled,
                Some(&plan()),
                &[baseline],
                assessment_at,
            )
            .is_ok()
        );
    }

    #[test]
    fn failed_observation_supplies_a_missing_partial_coverage_notice() {
        let mut partial = draft();
        partial.state = FinalState::Partial;
        partial.coverage_notice = Some("   ".into());
        let mut failed = observation(false, Some("2026-07-31T00:06:00Z"));
        failed.result.state = ToolResultState::Failed;
        failed.result.blocker = Some("The source runtime returned a bounded read failure.".into());

        normalize_coverage_notice(&mut partial, &[failed]);

        assert_eq!(
            partial.coverage_notice.as_deref(),
            Some("Coverage gap: The requested conclusion remains only partially supported.")
        );
        assert!(partial.message.ends_with(
            "\n\nCoverage gap: The requested conclusion remains only partially supported."
        ));
        assert_eq!(
            partial
                .claims
                .iter()
                .map(|claim| claim.text.as_str())
                .collect::<String>(),
            partial.message
        );
    }

    #[test]
    fn partial_draft_with_successful_reads_gets_a_visible_generic_coverage_boundary() {
        let mut partial = draft();
        partial.state = FinalState::Partial;
        partial.coverage_notice = None;

        normalize_coverage_notice(
            &mut partial,
            &[observation(true, Some("2026-07-31T00:06:00Z"))],
        );

        let notice = partial
            .coverage_notice
            .as_deref()
            .expect("partial drafts require a normalized notice");
        assert!(notice.contains("remains only partially supported"));
        assert!(partial.message.contains(notice));
        assert_eq!(
            partial
                .claims
                .iter()
                .map(|claim| claim.text.as_str())
                .collect::<String>(),
            partial.message
        );
    }

    #[test]
    fn partial_draft_reuses_a_natural_visible_coverage_boundary() {
        let mut partial = draft();
        partial.state = FinalState::Partial;
        partial.coverage_notice = None;
        partial.message = "The feed remains at one of three fresh receipts. The evidence is not yet decision-grade.".into();
        partial.claims = vec![GroundedClaim {
            claim_ref: "claim:visible-boundary".into(),
            planned_claim_ref: None,
            text: partial.message.clone(),
            required_for_answer: true,
            content: ClaimContent::StableExplanation,
        }];

        normalize_coverage_notice(
            &mut partial,
            &[observation(false, Some("2026-07-31T00:06:00Z"))],
        );

        assert_eq!(
            partial.coverage_notice.as_deref(),
            Some("The evidence is not yet decision-grade.")
        );
        assert_eq!(partial.message.matches("not yet decision-grade").count(), 1);
    }

    #[test]
    fn scheduled_wake_removes_a_passive_operator_handback() {
        let mut progress = draft();
        let handback = " Let me know if you want to adjust the approach.";
        progress.message.push_str(handback);
        progress.claims.push(GroundedClaim {
            claim_ref: "claim:passive-handback".into(),
            planned_claim_ref: None,
            text: handback.into(),
            required_for_answer: false,
            content: ClaimContent::StableExplanation,
        });

        normalize_passive_wake_handback(
            &SessionTurnTrigger::Wake {
                commitment_ref: "commitment:scheduled-check".into(),
                occurrence_ref: "occurrence:passive-handback".into(),
            },
            &mut progress,
        );

        assert!(!progress.message.contains("Let me know"));
        assert!(
            progress
                .claims
                .iter()
                .all(|claim| !claim.text.contains("Let me know"))
        );
        assert_eq!(
            progress
                .claims
                .iter()
                .map(|claim| claim.text.as_str())
                .collect::<String>(),
            progress.message
        );
    }

    #[test]
    fn receipt_streak_reset_language_requires_an_explicit_current_signal() {
        let mut candidate = draft();
        candidate.claims[0].text = "The fresh receipt streak reset to one.".into();
        candidate.message = candidate
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect();
        let mut current = observation(true, Some("2026-07-31T00:06:00Z"));
        current.result.data = json!({
            "fresh_complete_receipts": 1,
            "streak_reset": false
        });

        assert!(
            validate_explicit_streak_reset_language(&candidate, &[current.clone()])
                .unwrap_err()
                .to_string()
                .contains("streak_reset=true")
        );

        current.result.data["streak_reset"] = json!(true);
        assert!(validate_explicit_streak_reset_language(&candidate, &[current]).is_ok());
    }

    #[test]
    fn final_update_cannot_erase_an_earlier_reported_regression() {
        let mut current = session();
        current.messages.push(SessionMessage {
            role: SessionMessageRole::Assistant,
            message_ref: "message:regression".into(),
            actor_ref: "cerebro".into(),
            text: "Regression detected: the streak regressed from 2 to 0.".into(),
            received_at: "2026-07-31T00:01:00Z".into(),
        });
        let mut final_update = draft();
        final_update.message =
            "The feed is decision-grade at this check. No regressions occurred.".into();
        let error = validate_cross_turn_consistency(&current, &final_update).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("contradicts the delivered trajectory")
        );

        final_update.message =
            "The feed is decision-grade at this check. No further regression was observed.".into();
        assert!(validate_cross_turn_consistency(&current, &final_update).is_ok());
    }

    #[test]
    fn wake_assessment_computes_typed_scalar_deltas_before_model_review() {
        let mut awakened = session();
        let mut commitment = scheduled_commitment();
        commitment.attention_policy = Some(CommitmentAttentionPolicy {
            acceptance_all: vec![ObservationCondition {
                tool_id: "connector.read".into(),
                data_pointer: "/decision_grade".into(),
                equals: json!(true),
            }],
            alert_any: vec![ObservationCondition {
                tool_id: "connector.read".into(),
                data_pointer: "/receipt_fresh".into(),
                equals: json!(false),
            }],
        });
        awakened.mission.commitments.push(commitment);
        let mut current = observation(false, Some("2026-07-31T00:06:00Z"));
        current.result.state = ToolResultState::Partial;
        current.result.data = json!({
            "decision_grade": false,
            "fresh_complete_receipts": 1,
            "receipt_fresh": false,
            "reported_receipts": 2
        });
        let checkpoint = CommitmentCheckpoint {
            commitment_ref: "commitment:scheduled-check".into(),
            source_request_id: "request:prior".into(),
            recorded_at: "2026-07-31T00:00:00Z".into(),
            delivery_ref: "delivery:prior".into(),
            payload_digest: "sha256:prior".into(),
            trigger_occurrence_ref: None,
            delivery: DeliveryDisposition::Visible,
            state: FinalState::Answered,
            summary: "The feed has one fresh receipt.".into(),
            observations: vec![CommitmentCheckpointObservation {
                tool_id: current.call.tool_id.clone(),
                input: current.call.input.clone(),
                input_digest: current.call.input_digest(),
                observed_at: Some("2026-07-31T00:00:00Z".into()),
                state: ToolResultState::Succeeded,
                complete: true,
                summary: "The feed has one fresh receipt.".into(),
                data: json!({
                    "decision_grade": false,
                    "fresh_complete_receipts": 1,
                    "receipt_fresh": true
                }),
            }],
            commitment_status: CommitmentStatus::Waiting,
            next_wake_at: Some("2026-07-31T00:01:00Z".into()),
        };
        let assessment = build_wake_assessment(
            &awakened,
            &SessionTurnTrigger::Wake {
                commitment_ref: "commitment:scheduled-check".into(),
                occurrence_ref: "occurrence:typed-delta".into(),
            },
            Some(&checkpoint),
            &[current],
            OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
        )
        .expect("a scheduled commitment produces a typed wake assessment");

        assert!(assessment.required_observations_present);
        assert!(!assessment.required_observations_healthy);
        assert!(!assessment.acceptance_met);
        assert_eq!(assessment.matched_attention_signals.len(), 1);
        assert_eq!(
            assessment
                .scalar_comparisons
                .iter()
                .find(|comparison| comparison.data_pointer == "/fresh_complete_receipts")
                .map(|comparison| comparison.relation),
            Some(WakeScalarRelation::Unchanged)
        );
        assert_eq!(
            assessment
                .scalar_comparisons
                .iter()
                .find(|comparison| comparison.data_pointer == "/receipt_fresh")
                .map(|comparison| comparison.relation),
            Some(WakeScalarRelation::Changed)
        );
        assert_eq!(
            assessment
                .scalar_comparisons
                .iter()
                .find(|comparison| comparison.data_pointer == "/reported_receipts")
                .map(|comparison| comparison.relation),
            Some(WakeScalarRelation::AddedToCurrentRead)
        );
    }

    #[test]
    fn resumed_wake_counts_its_persisted_fresh_observation() {
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        awakened.events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "wake-request:resumed".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::ToolInvoked {
                    observation: observation(true, Some("2026-07-31T00:06:00Z")),
                },
            },
        ];
        let (resumed, _, observations) = resume_turn_state(&awakened, "wake-request:resumed");
        assert!(resumed);

        let mut completed = draft();
        completed.mission = awakened.mission.clone();
        completed.mission.commitments[0].status = CommitmentStatus::Completed;
        completed.mission.commitments[0].next_action = None;
        completed.mission.commitments[0].wake_at = None;
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:resumed".into(),
        };
        assert!(
            validate_wake_completion(
                &awakened,
                &completed,
                &trigger,
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
                &observations,
            )
            .is_ok()
        );
    }

    #[test]
    fn wake_executor_repair_names_the_exact_durable_contract() {
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        let mut completed = draft();
        completed.mission = awakened.mission.clone();
        completed.mission.commitments[0].status = CommitmentStatus::Completed;
        completed.mission.commitments[0].next_action = None;
        completed.mission.commitments[0].wake_at = None;
        completed.mission.commitments[0].attention_policy = None;
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:executor-repair".into(),
        };
        let error = validate_wake_completion(
            &awakened,
            &completed,
            &trigger,
            OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            &[observation(true, Some("2026-07-31T00:06:00Z"))],
        )
        .unwrap_err();
        assert!(error.to_string().contains("connector.read"));
        assert!(error.to_string().contains("acceptance_all"));
        assert!(error.to_string().contains("including when closing it"));
    }

    #[test]
    fn scheduled_wake_plan_is_derived_from_the_persisted_commitment() {
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        let plan = wake_research_plan(
            &awakened,
            &SessionTurnTrigger::Wake {
                commitment_ref: "commitment:scheduled-check".into(),
                occurrence_ref: "occurrence:auto-plan".into(),
            },
        )
        .expect("a required-read wake should have an executor plan");
        assert_eq!(plan.lane, ExecutionLane::Investigate);
        assert_eq!(plan.selected_tools, vec!["connector.read"]);
        assert_eq!(plan.claims.len(), 1);
        assert_eq!(
            plan.claims[0].question,
            "A current connector observation closes the check."
        );
        assert!(
            validate_plan(&plan, &["connector.read".into()]).is_ok(),
            "the derived plan must satisfy the same host contract as a model plan"
        );
    }

    #[test]
    fn explicit_future_delegation_requires_a_planned_executor() {
        let mut delegated = session();
        delegated.messages.push(SessionMessage {
            role: SessionMessageRole::User,
            message_ref: "message:delegation".into(),
            actor_ref: "user:one".into(),
            text: "Own the recovery check. Only interrupt me for a gap or the final result.".into(),
            received_at: "2026-07-31T00:00:00Z".into(),
        });
        let mut proposed = plan();
        proposed.follow_through = None;
        assert!(
            validate_explicit_follow_through(&delegated, &proposed)
                .unwrap_err()
                .to_string()
                .contains("explicitly delegated future observation")
        );

        proposed.follow_through = Some(PlannedFollowThrough {
            commitment_ref: "commitment:delegated-check".into(),
            required_tool_ids: vec!["connector.read".into()],
            acceptance_criteria: vec!["The connector is healthy.".into()],
            next_action: "Read connector alpha and compare the current state.".into(),
            attention_policy: CommitmentAttentionPolicy {
                acceptance_all: vec![ObservationCondition {
                    tool_id: "connector.read".into(),
                    data_pointer: "/status".into(),
                    equals: json!("healthy"),
                }],
                alert_any: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "A current connector observation closes the check.".into(),
        });
        assert!(validate_explicit_follow_through(&delegated, &proposed).is_ok());

        delegated
            .messages
            .last_mut()
            .expect("the delegated request was added")
            .text = "Summarize the current source state.".into();
        proposed.follow_through = None;
        assert!(validate_explicit_follow_through(&delegated, &proposed).is_ok());
    }

    #[test]
    fn delivery_disposition_enforces_human_attention_boundaries() {
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut operator_draft = draft();
        operator_draft.delivery = DeliveryDisposition::Silent;
        let error = validate_wake_completion(
            &session(),
            &operator_draft,
            &SessionTurnTrigger::Operator,
            assessment_at,
            &[],
        )
        .unwrap_err();
        assert!(error.to_string().contains("operator turns must produce"));

        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:delivery-boundary".into(),
        };
        let mut current = observation(true, Some("2026-07-31T00:06:00Z"));
        current.result.data = json!({"status": "recovering"});

        let mut rescheduled = draft();
        rescheduled.delivery = DeliveryDisposition::Silent;
        rescheduled.mission = awakened.mission.clone();
        rescheduled.mission.commitments[0].status = CommitmentStatus::Waiting;
        rescheduled.mission.commitments[0].wake_at = Some("2026-07-31T00:06:00Z".into());
        assert!(
            validate_wake_completion(
                &awakened,
                &rescheduled,
                &trigger,
                assessment_at,
                std::slice::from_ref(&current),
            )
            .is_ok()
        );

        rescheduled.delivery = DeliveryDisposition::Visible;
        let error = validate_wake_completion(
            &awakened,
            &rescheduled,
            &trigger,
            assessment_at,
            std::slice::from_ref(&current),
        )
        .unwrap_err();
        assert!(error.to_string().contains("coverage_notice=null"));
        rescheduled.delivery = DeliveryDisposition::Silent;

        rescheduled.mission.commitments[0].status = CommitmentStatus::Completed;
        rescheduled.mission.commitments[0].wake_at = None;
        let error =
            validate_wake_completion(&awakened, &rescheduled, &trigger, assessment_at, &[current])
                .unwrap_err();
        assert!(error.to_string().contains("cannot close before"));
    }

    #[test]
    fn runtime_policy_forces_visible_regression_and_acceptance() {
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut awakened = session();
        let mut commitment = scheduled_commitment();
        commitment
            .attention_policy
            .as_mut()
            .unwrap()
            .alert_any
            .push(ObservationCondition {
                tool_id: "connector.read".into(),
                data_pointer: "/regressed".into(),
                equals: json!(true),
            });
        awakened.mission.commitments.push(commitment);
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:typed-attention".into(),
        };

        let mut regression = observation(true, Some("2026-07-31T00:06:00Z"));
        regression.result.data = json!({"status": "recovering", "regressed": true});
        let mut rescheduled = draft();
        rescheduled.mission = awakened.mission.clone();
        rescheduled.mission.commitments[0].wake_at = Some("2026-07-31T00:06:00Z".into());
        rescheduled.delivery = DeliveryDisposition::Silent;
        let error = validate_wake_completion(
            &awakened,
            &rescheduled,
            &trigger,
            assessment_at,
            std::slice::from_ref(&regression),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Visible"));
        rescheduled.delivery = DeliveryDisposition::Visible;
        assert!(
            validate_wake_completion(
                &awakened,
                &rescheduled,
                &trigger,
                assessment_at,
                &[regression],
            )
            .is_ok()
        );

        let accepted = observation(true, Some("2026-07-31T00:06:00Z"));
        let mut accepted_but_still_open = draft();
        accepted_but_still_open.mission = awakened.mission.clone();
        accepted_but_still_open.mission.commitments[0].wake_at =
            Some("2026-07-31T00:06:00Z".into());
        accepted_but_still_open.delivery = DeliveryDisposition::Silent;
        let error = validate_wake_completion(
            &awakened,
            &accepted_but_still_open,
            &trigger,
            assessment_at,
            std::slice::from_ref(&accepted),
        )
        .unwrap_err();
        assert!(error.to_string().contains("Visible"));
        accepted_but_still_open.delivery = DeliveryDisposition::Visible;
        assert!(
            validate_wake_completion(
                &awakened,
                &accepted_but_still_open,
                &trigger,
                assessment_at,
                std::slice::from_ref(&accepted),
            )
            .is_ok(),
            "typed attention owns visibility; semantic review owns whether every stated criterion is complete"
        );

        let mut completed = draft();
        completed.mission = awakened.mission.clone();
        completed.mission.commitments[0].status = CommitmentStatus::Completed;
        completed.mission.commitments[0].wake_at = None;
        completed.delivery = DeliveryDisposition::Visible;
        assert!(
            validate_wake_completion(&awakened, &completed, &trigger, assessment_at, &[accepted],)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn scheduled_wake_cannot_consume_effect_authority() {
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        awakened = apply_session_events(
            &awakened,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::WakeTriggered {
                    request_id: "wake-request:effect".into(),
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:effect".into(),
                    scheduled_for: "2026-07-31T00:00:30Z".into(),
                },
            }],
        )
        .unwrap();
        let mut wake_plan = plan();
        wake_plan.selected_tools.push("connector.update".into());
        let mut completed = draft();
        completed.mission = awakened.mission.clone();
        let commitment = &mut completed.mission.commitments[0];
        commitment.status = CommitmentStatus::Completed;
        commitment.next_action = None;
        commitment.wake_at = None;
        completed.mission.status = SessionStatus::Completed;
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan { plan: wake_plan },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:wake:read".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Read connector alpha.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:wake:effect".into(),
                        tool_id: "connector.update".into(),
                        purpose: "Attempt an unauthorized scheduled effect.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::Finish { draft: completed },
            ])),
        };
        let tools = WakeTools {
            effects: AtomicUsize::new(0),
        };

        let outcome = run_session_turn_recorded(
            &model,
            &tools,
            &NoopSessionJournal,
            awakened,
            SessionTurnInput {
                request_id: "wake-request:effect".into(),
                actor_ref: "cerebro-scheduler".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Wake {
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:effect".into(),
                },
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SessionTurnOutcome::PendingDelivery { .. }
        ));
        assert_eq!(tools.effects.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn critic_can_raise_distinct_issues_across_bounded_revisions() {
        let model = RefiningSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan { plan: plan() },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:1".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Read connector alpha.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::Finish { draft: draft() },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:review-escape".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Try to gather different evidence after review.".into(),
                        input: json!({"connector_ref": "connector:other"}),
                    }],
                },
                SessionModelDecision::EstablishPlan { plan: plan() },
                SessionModelDecision::Finish { draft: draft() },
                SessionModelDecision::Finish { draft: draft() },
            ])),
            reviews: AtomicUsize::new(0),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            session(),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SessionTurnOutcome::PendingDelivery { .. }
        ));
        assert_eq!(model.reviews.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn an_identical_plan_retry_is_repaired_without_dropping_the_turn() {
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan { plan: plan() },
                SessionModelDecision::EstablishPlan { plan: plan() },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:1".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Read connector alpha.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::Finish { draft: draft() },
            ])),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            session(),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            SessionTurnOutcome::PendingDelivery { .. }
        ));
    }

    #[tokio::test]
    async fn a_new_turn_can_ground_itself_in_fresh_prior_session_evidence() {
        let mut continued = session();
        continued.events.push(SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: continued.session_ref.clone(),
            sequence: 1,
            occurred_at: "2026-07-31T00:00:30Z".into(),
            event: SessionEvent::ToolInvoked {
                observation: observation(true, Some("2026-08-01T00:00:00Z")),
            },
        });
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan { plan: plan() },
                SessionModelDecision::Finish { draft: draft() },
            ])),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            continued,
            SessionTurnInput {
                request_id: "request:2".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .unwrap();

        let SessionTurnOutcome::PendingDelivery {
            evidence_atom_refs,
            events,
            ..
        } = outcome
        else {
            panic!("expected a pending-delivery session turn")
        };
        assert_eq!(evidence_atom_refs, vec!["atom:status"]);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event.event, SessionEvent::ToolInvoked { .. }))
        );
    }

    #[test]
    fn stale_prior_turn_atoms_are_not_reintroduced_as_current_model_evidence() {
        let mut continued = session();
        continued.events.push(SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: continued.session_ref.clone(),
            sequence: 1,
            occurred_at: "2026-07-31T00:00:30Z".into(),
            event: SessionEvent::ToolInvoked {
                observation: observation(true, Some("2026-07-31T00:00:45Z")),
            },
        });

        assert_eq!(
            prior_read_observations(
                &continued,
                OffsetDateTime::parse("2026-07-31T00:00:40Z", &Rfc3339).unwrap(),
            )
            .len(),
            1
        );
        assert!(
            prior_read_observations(
                &continued,
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_empty()
        );
        let fresh_assessment = OffsetDateTime::parse("2026-07-31T00:00:40Z", &Rfc3339).unwrap();
        assert_eq!(
            recalled_observations_for_trigger(
                &continued,
                &SessionTurnTrigger::Operator,
                fresh_assessment,
            )
            .len(),
            1
        );
        assert!(
            recalled_observations_for_trigger(
                &continued,
                &SessionTurnTrigger::Wake {
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:fresh-envelope".into(),
                },
                fresh_assessment,
            )
            .is_empty()
        );
    }

    #[tokio::test]
    async fn tool_use_without_a_typed_plan_degrades_to_a_visible_blocked_answer() {
        let invalid = SessionModelDecision::InvokeTools {
            calls: vec![ToolCall {
                call_id: "call:1".into(),
                tool_id: "connector.read".into(),
                purpose: "Read connector alpha.".into(),
                input: json!({"connector_ref": "connector:alpha"}),
            }],
        };
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from(vec![invalid; MAX_MODEL_REPAIRS + 1])),
        };
        let result = run_session_turn(
            &model,
            &ConnectorTools,
            session(),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await;
        let SessionTurnOutcome::PendingDelivery {
            delivery,
            final_state,
            markdown,
            ..
        } = result.expect("repair exhaustion should produce a visible fallback")
        else {
            panic!("repair exhaustion should not request approval");
        };
        assert_eq!(delivery, DeliveryDisposition::Visible);
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("No current authoritative observation was obtained"));
    }

    #[tokio::test]
    async fn repair_fallback_reports_the_concrete_failed_read() {
        let mut failed = observation(true, Some("2026-08-01T00:00:00Z"));
        failed.result.state = ToolResultState::Failed;
        failed.result.summary =
            "The source read failed because the upstream request timed out.".into();
        failed.result.blocker = Some("The upstream request timed out.".into());
        failed.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:1#tool-outcome".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: ToolResultState::Failed,
                summary: failed.result.summary.clone(),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let input = SessionTurnInput {
            request_id: "request:failed-read".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            trigger: SessionTurnTrigger::Operator,
        };

        let outcome = repair_fallback_outcome(
            &session(),
            &input,
            &input.trigger,
            None,
            &[failed],
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("a failed read should produce a grounded visible fallback");
        let SessionTurnOutcome::PendingDelivery {
            delivery,
            final_state,
            markdown,
            ..
        } = outcome
        else {
            panic!("a failed read should not request approval");
        };
        assert_eq!(delivery, DeliveryDisposition::Visible);
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("upstream request timed out"));
        assert!(markdown.contains("The source read failed"));
        assert!(!markdown.contains("No current authoritative observation was obtained"));
    }

    #[tokio::test]
    async fn scheduled_repair_fallback_reschedules_the_exact_commitment() {
        let invalid = SessionModelDecision::InvokeTools {
            calls: vec![ToolCall {
                call_id: "call:scheduled-effect".into(),
                tool_id: "connector.update".into(),
                purpose: "Attempt an effect from a scheduled wake.".into(),
                input: json!({"connector_ref": "connector:alpha", "enabled": true}),
            }],
        };
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from(vec![invalid; MAX_MODEL_REPAIRS + 1])),
        };
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        awakened = apply_session_events(
            &awakened,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::WakeTriggered {
                    request_id: "wake-request:repair-fallback".into(),
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:repair-fallback".into(),
                    scheduled_for: "2026-07-31T00:00:30Z".into(),
                },
            }],
        )
        .unwrap();
        let tools = WakeTools {
            effects: AtomicUsize::new(0),
        };

        let outcome = run_session_turn(
            &model,
            &tools,
            awakened,
            SessionTurnInput {
                request_id: "wake-request:repair-fallback".into(),
                actor_ref: "cerebro-scheduler".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Wake {
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:repair-fallback".into(),
                },
            },
        )
        .await
        .expect("a failed scheduled repair should remain durable");

        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            mission,
            ..
        } = outcome
        else {
            panic!("scheduled repair fallback should not request approval");
        };
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("I’ll check again at 2026-07-31T00:06:00Z"));
        let commitment = mission
            .commitments
            .iter()
            .find(|commitment| commitment.commitment_ref == "commitment:scheduled-check")
            .expect("the exact commitment must survive repair fallback");
        assert_eq!(commitment.status, CommitmentStatus::Waiting);
        assert_eq!(commitment.wake_at.as_deref(), Some("2026-07-31T00:06:00Z"));
        assert_eq!(tools.effects.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn operator_repair_fallback_preserves_delegated_follow_through() {
        let current = session();
        let mut proposed = plan();
        proposed.follow_through = Some(planned_follow_through());
        let mut baseline = observation(true, Some("2026-07-31T00:06:00Z"));
        baseline.result.summary =
            "Connector alpha is recovering and is not ready at this check.".into();
        baseline.result.data = json!({"status": "recovering"});
        let outcome = repair_fallback_outcome(
            &current,
            &SessionTurnInput {
                request_id: "request:operator-fallback".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                trigger: SessionTurnTrigger::Operator,
            },
            &SessionTurnTrigger::Operator,
            Some(&proposed),
            &[baseline],
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("delegated work should survive model repair exhaustion");

        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            mission,
            ..
        } = outcome
        else {
            panic!("operator fallback should produce a durable visible update")
        };
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("I’ll check again at 2026-07-31T00:06:00Z"));
        let commitment = mission
            .commitments
            .iter()
            .find(|commitment| commitment.commitment_ref == "commitment:scheduled-check")
            .expect("the planned commitment must survive fallback");
        assert_eq!(commitment.status, CommitmentStatus::Waiting);
        assert_eq!(commitment.wake_at.as_deref(), Some("2026-07-31T00:06:00Z"));
    }

    #[tokio::test]
    async fn a_started_effect_with_no_result_resumes_unknown_without_reinvocation() {
        let call = ToolCall {
            call_id: "call:effect-1".into(),
            tool_id: "connector.update".into(),
            purpose: "Update connector alpha.".into(),
            input: json!({"connector_ref": "connector:alpha", "enabled": true}),
        };
        let descriptor = ToolDescriptor {
            tool_id: call.tool_id.clone(),
            title: "Connector update".into(),
            summary: "Updates one connector.".into(),
            authority_class: ToolAuthorityClass::Actuate,
            effect_class: ToolEffectClass::Write,
            input_schema_ref: "schema:input".into(),
            result_schema_ref: "schema:result".into(),
        };
        let mut resumed_session = session();
        resumed_session.events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: resumed_session.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "request:1".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: resumed_session.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:01:01Z".into(),
                event: SessionEvent::PlanEstablished { plan: plan() },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: resumed_session.session_ref.clone(),
                sequence: 3,
                occurred_at: "2026-07-31T00:01:02Z".into(),
                event: SessionEvent::EffectStarted {
                    call: call.clone(),
                    descriptor: descriptor.clone(),
                },
            },
        ];
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([SessionModelDecision::InvokeTools {
                calls: vec![call],
            }])),
        };
        let tools = CountingEffectTools {
            invocations: AtomicUsize::new(0),
            descriptor,
        };

        let result = run_session_turn(
            &model,
            &tools,
            resumed_session,
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:02:00Z".into(),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await;

        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            ..
        } = result.expect("an unknown effect should produce a visible reconciliation boundary")
        else {
            panic!("an unknown effect should not request another approval");
        };
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("effect was durably started"));
        assert!(markdown.contains("external action outcome is unknown"));
        assert_eq!(tools.invocations.load(Ordering::SeqCst), 0);
    }
}
