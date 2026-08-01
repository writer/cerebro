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
    ToolAuthorityClass, ToolCall, ToolDescriptor, ToolObservation, ToolResult, ToolResultState,
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
const MAX_MODEL_REPAIRS: usize = 3;
const MAX_DELIVERY_MESSAGE_BYTES: usize = 3_500;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_SESSION_MESSAGES: usize = 400;
const MAX_SESSION_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_MEMORIES: usize = 128;

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
    pub wake_at: Option<String>,
    pub verification: Option<String>,
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
    pub message: String,
    pub claims: Vec<GroundedClaim>,
    pub coverage_notice: Option<String>,
    pub question: Option<String>,
    pub mission: MissionState,
    pub memory_updates: Vec<MemoryUpdate>,
    pub presentation_ready: bool,
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
    pub plan: Option<ResearchPlan>,
    pub available_tools: Vec<ToolDescriptor>,
    pub observations: Vec<ToolObservation>,
    pub repair_feedback: Vec<String>,
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
pub struct MessageReview {
    pub message_digest: String,
    pub claim_reviews: Vec<ClaimReview>,
    pub undeclared_material: Vec<String>,
    pub behavioral: BehavioralReview,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClaimReviewTurn {
    pub session: AgentSession,
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
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SessionTurnOutcome {
    PendingDelivery {
        lane: ExecutionLane,
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
            SessionEvent::DeliveryRecorded { request_id, .. } => {
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
                next.messages.push(SessionMessage {
                    role: SessionMessageRole::Assistant,
                    message_ref: format!("assistant:{request_id}"),
                    actor_ref: "cerebro".into(),
                    text: pending.draft.message,
                    received_at: record.occurred_at.clone(),
                });
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
    let (resumed, mut plan, mut observations) = resume_turn_state(&session, &input.request_id);
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
    let mut call_ids = observations
        .iter()
        .map(|observation| observation.call.call_id.clone())
        .collect::<BTreeSet<_>>();
    let mut call_fingerprints = observations
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
    let mut draft_repaired_after_review = false;

    for _ in 0..MAX_SESSION_STEPS {
        let decision = match model
            .advance(SessionModelTurn {
                session: session.clone(),
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
                if repairs > MAX_MODEL_REPAIRS {
                    return Err(AgentRuntimeError::OperatingRepairLimit);
                }
                repair_feedback = vec![format!(
                    "The prior decision did not match the session contract: {reason}"
                )];
                continue;
            }
            Err(error) => return Err(error),
        };

        match decision {
            SessionModelDecision::EstablishPlan { plan: proposed } => {
                if plan.is_some() {
                    return Err(AgentRuntimeError::InvalidFinal(
                        "the turn already has an established research plan".into(),
                    ));
                }
                validate_plan(&proposed, &available_tool_ids)?;
                if !observations.is_empty() {
                    return Err(AgentRuntimeError::InvalidFinal(
                        "the research plan cannot be replaced after tool execution begins".into(),
                    ));
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
                if draft_repaired_after_review {
                    return Err(AgentRuntimeError::InvalidToolCall(
                        "claim-review repair is tool-frozen and must finish from existing evidence"
                            .into(),
                    ));
                }
                let established = plan.as_ref().ok_or_else(|| {
                    AgentRuntimeError::InvalidToolCall(
                        "establish a typed research plan before invoking evidence tools".into(),
                    )
                })?;
                validate_calls(
                    &calls,
                    established,
                    &descriptors,
                    observations.len(),
                    &mut call_ids,
                    &mut call_fingerprints,
                )?;
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
            SessionModelDecision::Finish { draft } => {
                validate_plan_completion(plan.as_ref(), &draft)?;
                let validated =
                    match validate_grounded_draft(&session, &draft, &observations, assessment_at) {
                        Ok(validated) => validated,
                        Err(error) => {
                            repairs += 1;
                            if repairs > MAX_MODEL_REPAIRS {
                                return Err(AgentRuntimeError::OperatingRepairLimit);
                            }
                            repair_feedback = vec![error.to_string()];
                            continue;
                        }
                    };
                validate_effect_closure(&observations, &draft, assessment_at)?;
                let review = model
                    .review_message(ClaimReviewTurn {
                        session: session.clone(),
                        draft: draft.clone(),
                        observations: observations.clone(),
                    })
                    .await?;
                let issues = validate_message_review(&draft, &review)?;
                if !issues.is_empty() {
                    if draft_repaired_after_review {
                        return Err(AgentRuntimeError::CriticRepairLimit);
                    }
                    draft_repaired_after_review = true;
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
                    markdown: validated.markdown,
                    final_state: draft.state,
                    evidence_atom_refs: validated.evidence_atom_refs,
                    mission: draft.mission,
                    events,
                });
            }
        }
    }
    Err(AgentRuntimeError::ModelStepLimit)
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
    let latest = session.messages.last().ok_or_else(|| {
        AgentRuntimeError::InvalidRequest("session turn requires a queued user message".into())
    })?;
    if latest.role != SessionMessageRole::User || latest.actor_ref != input.actor_ref {
        return Err(AgentRuntimeError::InvalidRequest(
            "turn actor does not match the latest queued message".into(),
        ));
    }
    Ok(())
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
    Ok(())
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
        .map(|claim| (claim.claim_ref.as_str(), claim.required))
        .collect::<BTreeMap<_, _>>();
    let mut closed = BTreeSet::new();
    for claim in &draft.claims {
        if let Some(planned_claim_ref) = claim.planned_claim_ref.as_deref() {
            let required = planned.get(planned_claim_ref).ok_or_else(|| {
                AgentRuntimeError::InvalidFinal(
                    "visible claim references an unknown planned claim".into(),
                )
            })?;
            if *required && !claim.required_for_answer {
                return Err(AgentRuntimeError::InvalidFinal(
                    "required planned claims require a required visible disposition".into(),
                ));
            }
            closed.insert(planned_claim_ref);
        }
    }
    if plan
        .claims
        .iter()
        .any(|claim| claim.required && !closed.contains(claim.claim_ref.as_str()))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "every required planned claim needs a visible disposition".into(),
        ));
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
    let mut claim_refs = BTreeSet::new();
    let mut cited_atoms = BTreeSet::new();
    let message_sequence = session
        .messages
        .iter()
        .enumerate()
        .map(|(index, message)| ((index + 1) as u64, message))
        .collect::<BTreeMap<_, _>>();

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
        validate_claim(
            claim,
            &atoms,
            &open_loops,
            &message_sequence,
            assessment_at,
            draft.state,
            &mut cited_atoms,
        )?;
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

fn validate_claim(
    claim: &GroundedClaim,
    atoms: &BTreeMap<String, AtomContext<'_>>,
    open_loops: &BTreeSet<&str>,
    messages: &BTreeMap<u64, &SessionMessage>,
    assessment_at: OffsetDateTime,
    final_state: FinalState,
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
            let message = messages.get(message_sequence).ok_or_else(|| {
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
            if !open_loops.contains(open_loop_ref.as_str()) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "retained plan cites an unknown open loop".into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::StableExplanation | ClaimContent::Question => return Ok(()),
    };

    if atom_refs.is_empty() {
        return Err(AgentRuntimeError::InvalidFinal(
            "observations, derivations, recommendations, and hypotheses require evidence atoms"
                .into(),
        ));
    }
    for atom_ref in atom_refs {
        let context = atoms
            .get(atom_ref)
            .ok_or_else(|| AgentRuntimeError::EvidenceNotObserved(atom_ref.clone()))?;
        if matches!(claim.content, ClaimContent::Observation { .. })
            && (!context.complete
                || context
                    .fresh_until
                    .is_none_or(|until| until < assessment_at))
            && !matches!(final_state, FinalState::Partial | FinalState::Blocked)
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
        if !bounded(&commitment.commitment_ref, MAX_TEXT_BYTES)
            || !bounded(&commitment.summary, MAX_TEXT_BYTES)
            || !refs.insert(&commitment.commitment_ref)
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "commitments require unique bounded references and summaries".into(),
            ));
        }
        if commitment.owner == WorkOwner::Cerebro
            && !matches!(
                commitment.status,
                CommitmentStatus::Completed | CommitmentStatus::Cancelled
            )
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "unfinished Cerebro commitments require an active background executor".into(),
            ));
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
        let mut wrong_digest = review;
        wrong_digest.message_digest = format!("sha256:{}", "0".repeat(64));
        assert!(validate_message_review(&draft, &wrong_digest).is_err());
    }

    #[test]
    fn required_planned_claims_and_lane_budgets_are_enforced() {
        let mut unfinished = draft();
        unfinished.claims[0].planned_claim_ref = None;
        assert!(validate_plan_completion(Some(&plan()), &unfinished).is_err());

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
    async fn tool_use_without_a_typed_plan_fails_closed() {
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([SessionModelDecision::InvokeTools {
                calls: vec![ToolCall {
                    call_id: "call:1".into(),
                    tool_id: "connector.read".into(),
                    purpose: "Read connector alpha.".into(),
                    input: json!({"connector_ref": "connector:alpha"}),
                }],
            }])),
        };
        let result = run_session_turn(
            &model,
            &ConnectorTools,
            session(),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
            },
        )
        .await;
        assert!(matches!(result, Err(AgentRuntimeError::InvalidToolCall(_))));
    }

    #[tokio::test]
    async fn a_started_effect_with_no_result_resumes_unknown_and_is_not_reinvoked() {
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
            },
        )
        .await;

        assert!(matches!(result, Err(AgentRuntimeError::InvalidToolCall(_))));
        assert_eq!(tools.invocations.load(Ordering::SeqCst), 0);
    }
}
