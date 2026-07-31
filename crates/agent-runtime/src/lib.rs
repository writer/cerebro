#![deny(unsafe_code)]

//! Portable operating loop for a tool-using Cerebro agent.
//!
//! The runtime owns lane selection, bounded tool execution, exact effect
//! authorization, evidence-bound reporting, and post-effect verification.
//! Model providers, durable stores, transports, and concrete tool adapters are
//! injected ports.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const AGENT_TURN_REQUEST_V1: &str = "agent-turn-request/v1";
pub const AGENT_TURN_RESULT_V1: &str = "agent-turn-result/v1";
pub const MAX_HISTORY_ITEMS: usize = 200;
pub const MAX_HISTORY_ITEM_BYTES: usize = 1024 * 1024;
pub const MAX_HISTORY_TOTAL_BYTES: usize = 1024 * 1024;
pub const MAX_MODEL_STEPS: usize = 24;
pub const MAX_ROUTER_ATTEMPTS: usize = 4;
pub const MAX_OPERATING_REPAIRS: usize = 8;
pub const MAX_PRESENTATION_REPAIRS: usize = 4;
pub const MAX_CRITIC_REPAIRS: usize = 4;
pub const MAX_CRITIC_REVISIONS: usize = 4;
pub const ROUTER_MAX_TOKENS: i32 = 32_768;
pub const DECISION_MAX_TOKENS: i32 = 65_536;
pub const PRESENTATION_MAX_TOKENS: i32 = 16_384;
pub const CRITIC_MAX_TOKENS: i32 = 65_536;
pub const HARD_MAX_GENERATION_TOKENS: i32 = 131_072;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_TOOL_DATA_BYTES: usize = 64 * 1024;
const MAX_HEADLINE_BYTES: usize = 160;
const MAX_SUMMARY_BYTES: usize = 2_400;
const MAX_SUPPLEMENT_BYTES: usize = 800;
const MAX_CLAIMS_PER_SECTION: usize = 8;
const MAX_TOTAL_CLAIMS: usize = 16;
const MAX_NEXT_ACTIONS: usize = 5;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLane {
    Ignore,
    Converse,
    Continue,
    Lookup,
    Investigate,
    Act,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteConfidence {
    High,
    Medium,
    Low,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteDecision {
    pub lane: ExecutionLane,
    pub confidence: RouteConfidence,
    pub reason: String,
    pub requires_current_evidence: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RouteTurn {
    pub request: AgentTurnRequest,
    pub repair_feedback: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct TurnBudget {
    pub max_selected_capabilities: usize,
    pub max_tool_calls: usize,
}

impl ExecutionLane {
    #[must_use]
    pub const fn budget(self) -> TurnBudget {
        match self {
            Self::Ignore | Self::Converse | Self::Continue => TurnBudget {
                max_selected_capabilities: 0,
                max_tool_calls: 0,
            },
            Self::Lookup => TurnBudget {
                max_selected_capabilities: 4,
                max_tool_calls: 3,
            },
            Self::Investigate => TurnBudget {
                max_selected_capabilities: 10,
                max_tool_calls: 8,
            },
            Self::Act => TurnBudget {
                max_selected_capabilities: 12,
                max_tool_calls: 12,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessage {
    pub role: ConversationRole,
    pub content: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRole {
    Assistant,
    User,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkingState {
    pub mission_ref: Option<String>,
    pub current_request: String,
    pub last_outcome: WorkingOutcome,
    pub last_blocker: Option<String>,
    #[serde(default)]
    pub active_lane: Option<ExecutionLane>,
    #[serde(default)]
    pub requires_current_evidence: Option<bool>,
    #[serde(default)]
    pub open_loops: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkingOutcome {
    Blocked,
    Completed,
    NeedsUser,
    Owned,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentTurnRequest {
    pub schema_version: String,
    pub tenant_id: String,
    pub request_id: String,
    pub thread_ref: String,
    pub actor_ref: String,
    pub assessment_at: String,
    pub message: String,
    pub history: Vec<ConversationMessage>,
    pub working_state: Option<WorkingState>,
    pub effect_authorizations: Vec<EffectAuthorization>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EffectAuthorization {
    pub approval_ref: String,
    pub tenant_id: String,
    pub request_id: String,
    pub thread_ref: String,
    pub actor_ref: String,
    pub tool_id: String,
    pub input_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAuthorityClass {
    Observe,
    Propose,
    Actuate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolEffectClass {
    Read,
    Write,
    ExternalEffect,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDescriptor {
    pub tool_id: String,
    pub title: String,
    pub summary: String,
    pub authority_class: ToolAuthorityClass,
    pub effect_class: ToolEffectClass,
    pub input_schema_ref: String,
    pub result_schema_ref: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub call_id: String,
    pub tool_id: String,
    pub purpose: String,
    pub input: Value,
}

impl ToolCall {
    #[must_use]
    pub fn input_digest(&self) -> String {
        digest_json(&self.input)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolResultState {
    Succeeded,
    Partial,
    Failed,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub evidence_ref: String,
    pub statement: String,
    pub observed_at: String,
    pub fresh_until: Option<String>,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResult {
    pub state: ToolResultState,
    pub summary: String,
    pub data: Value,
    pub evidence: Vec<EvidenceRecord>,
    pub blocker: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ToolObservation {
    pub sequence: usize,
    pub call: ToolCall,
    pub descriptor: ToolDescriptor,
    pub result: ToolResult,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceClaim {
    pub text: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalState {
    Answered,
    Partial,
    NeedsInput,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalDraft {
    pub state: FinalState,
    pub headline: String,
    pub summary: String,
    pub summary_evidence_refs: Vec<String>,
    pub checked: Vec<EvidenceClaim>,
    pub changed: Vec<EvidenceClaim>,
    pub verified: Vec<EvidenceClaim>,
    pub current_state: Vec<EvidenceClaim>,
    pub next_actions: Vec<String>,
    pub coverage_notice: Option<String>,
    pub question: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum ModelDecision {
    InvokeTool { call: ToolCall },
    Finish { draft: FinalDraft },
}

#[derive(Clone, Debug, Serialize)]
pub struct ModelTurn {
    pub request: AgentTurnRequest,
    pub lane: ExecutionLane,
    pub budget: TurnBudget,
    pub available_tools: Vec<ToolDescriptor>,
    pub observations: Vec<ToolObservation>,
    pub revision_feedback: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CritiqueTurn {
    pub request: AgentTurnRequest,
    pub lane: ExecutionLane,
    pub draft: FinalDraft,
    pub observations: Vec<ToolObservation>,
    pub repair_feedback: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PresentationTurn {
    pub request: AgentTurnRequest,
    pub lane: ExecutionLane,
    pub draft: FinalDraft,
    pub observations: Vec<ToolObservation>,
    pub repair_feedback: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationDecision {
    pub messages: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum CritiqueDecision {
    Approve { checks: CritiqueChecks },
    Revise { issues: Vec<String> },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CritiqueChecks {
    pub answers_newest_request: bool,
    pub conversational: bool,
    pub evidence_boundary_correct: bool,
    pub no_raw_record_dump: bool,
    pub operator_facing: bool,
    pub owns_follow_through: bool,
    pub right_sized: bool,
}

#[async_trait]
/// Model authority for routing, operating, and independent critique.
///
/// Every implementation must provide a critic. Omitting it is a compile error:
///
/// ```compile_fail
/// use async_trait::async_trait;
/// use cerebro_agent_runtime::{
///     AgentModel, AgentRuntimeError, ModelDecision, ModelTurn, RouteDecision, RouteTurn,
/// };
///
/// struct MissingCritic;
///
/// #[async_trait]
/// impl AgentModel for MissingCritic {
///     async fn route(
///         &self,
///         _turn: RouteTurn,
///     ) -> Result<RouteDecision, AgentRuntimeError> {
///         unimplemented!()
///     }
///
///     async fn next(
///         &self,
///         _turn: ModelTurn,
///     ) -> Result<ModelDecision, AgentRuntimeError> {
///         unimplemented!()
///     }
/// }
/// ```
pub trait AgentModel: Send + Sync {
    async fn route(&self, turn: RouteTurn) -> Result<RouteDecision, AgentRuntimeError>;

    async fn next(&self, turn: ModelTurn) -> Result<ModelDecision, AgentRuntimeError>;

    async fn present(
        &self,
        turn: PresentationTurn,
    ) -> Result<PresentationDecision, AgentRuntimeError> {
        Ok(PresentationDecision {
            messages: vec![turn.draft.summary],
        })
    }

    async fn critique(&self, turn: CritiqueTurn) -> Result<CritiqueDecision, AgentRuntimeError>;
}

#[async_trait]
pub trait AgentTools: Send + Sync {
    fn catalog(&self) -> Vec<ToolDescriptor>;

    async fn invoke(
        &self,
        request: &AgentTurnRequest,
        call: &ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalRequest {
    pub approval_ref: String,
    pub tool_id: String,
    pub input_digest: String,
    pub purpose: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AgentTurnOutcome {
    Delivered {
        schema_version: &'static str,
        lane: ExecutionLane,
        markdown: String,
        final_state: FinalState,
        evidence_refs: Vec<String>,
        tool_call_count: usize,
        working_state: Option<WorkingState>,
    },
    ApprovalRequired {
        schema_version: &'static str,
        lane: ExecutionLane,
        request: ApprovalRequest,
        tool_call_count: usize,
    },
    Ignored {
        schema_version: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentRuntimeError {
    DuplicateCallId,
    EvidenceNotObserved(String),
    EvidenceNotAuthoritative(String),
    HistoryInvalid,
    InvalidFinal(String),
    InvalidRequest(String),
    InvalidRoute(String),
    InvalidToolCall(String),
    ModelUnavailable(String),
    ModelStepLimit,
    OperatingRepairLimit,
    PresentationRepairLimit,
    CriticRepairLimit,
    ToolBudgetExceeded,
    ToolUnavailable(String),
    UnverifiedEffect,
}

impl fmt::Display for AgentRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCallId => formatter.write_str("the model repeated a tool call identity"),
            Self::EvidenceNotObserved(reference) => {
                write!(
                    formatter,
                    "the final answer cited unobserved evidence {reference}"
                )
            }
            Self::EvidenceNotAuthoritative(reference) => {
                write!(
                    formatter,
                    "the final answer treated stale or incomplete evidence as authoritative: {reference}"
                )
            }
            Self::HistoryInvalid => formatter.write_str("conversation history is invalid"),
            Self::InvalidFinal(reason) => {
                write!(formatter, "the final answer is invalid: {reason}")
            }
            Self::InvalidRequest(reason) => {
                write!(formatter, "the turn request is invalid: {reason}")
            }
            Self::InvalidRoute(reason) => {
                write!(formatter, "the semantic route is invalid: {reason}")
            }
            Self::InvalidToolCall(reason) => {
                write!(formatter, "the tool call is invalid: {reason}")
            }
            Self::ModelUnavailable(reason) => {
                write!(formatter, "the agent model is unavailable: {reason}")
            }
            Self::ModelStepLimit => formatter.write_str("the model exceeded the turn step limit"),
            Self::OperatingRepairLimit => {
                formatter.write_str("the operating decision repair loop exceeded its bounded limit")
            }
            Self::PresentationRepairLimit => formatter.write_str(
                "the conversational presentation repair loop exceeded its bounded limit",
            ),
            Self::CriticRepairLimit => {
                formatter.write_str("the critic repair loop exceeded its bounded limit")
            }
            Self::ToolBudgetExceeded => formatter.write_str("the turn exceeded its tool budget"),
            Self::ToolUnavailable(tool_id) => write!(formatter, "tool {tool_id} is unavailable"),
            Self::UnverifiedEffect => {
                formatter.write_str("a completed effect requires a later independent verification")
            }
        }
    }
}

impl Error for AgentRuntimeError {}

pub async fn run_turn(
    model: &dyn AgentModel,
    tools: &dyn AgentTools,
    request: AgentTurnRequest,
) -> Result<AgentTurnOutcome, AgentRuntimeError> {
    validate_request(&request)?;
    let routed_lane = route_with_repair(model, request.clone()).await?;
    let resumed_mission = routed_lane == ExecutionLane::Continue;
    let lane = if resumed_mission {
        let state = request.working_state.as_ref().ok_or_else(|| {
            AgentRuntimeError::InvalidRequest("continuation requires working state".into())
        })?;
        if state.mission_ref.is_none() {
            return Err(AgentRuntimeError::InvalidRequest(
                "continuation requires a durable mission".into(),
            ));
        }
        if let Some(active_lane) = state.active_lane {
            if matches!(active_lane, ExecutionLane::Ignore | ExecutionLane::Continue) {
                return Err(AgentRuntimeError::InvalidRequest(
                    "durable mission contains an invalid active lane".into(),
                ));
            }
            active_lane
        } else {
            let mut resumed = request.clone();
            resumed.message.clone_from(&state.current_request);
            resumed.working_state = None;
            match route_with_repair(model, resumed).await? {
                ExecutionLane::Ignore | ExecutionLane::Converse | ExecutionLane::Continue => {
                    ExecutionLane::Investigate
                }
                lane => lane,
            }
        }
    } else {
        routed_lane
    };
    if lane == ExecutionLane::Ignore {
        return Ok(AgentTurnOutcome::Ignored {
            schema_version: AGENT_TURN_RESULT_V1,
        });
    }
    let budget = lane.budget();
    let available_tools = tools
        .catalog()
        .into_iter()
        .filter(|tool| tool_allowed_in_lane(lane, tool))
        .collect::<Vec<_>>();
    validate_catalog(&available_tools)?;
    let mut observations = Vec::new();
    let mut call_ids = BTreeSet::new();
    let mut consumed_effect_authorizations = BTreeSet::new();
    let mut selected_tools = BTreeSet::new();
    let mut revision_feedback = Vec::new();
    let mut operating_repairs = 0;
    let mut critic_revisions = 0;
    for _ in 0..MAX_MODEL_STEPS {
        let decision = match model
            .next(ModelTurn {
                request: request.clone(),
                lane,
                budget,
                available_tools: available_tools.clone(),
                observations: observations.clone(),
                revision_feedback: revision_feedback.clone(),
            })
            .await
        {
            Ok(decision) => decision,
            Err(AgentRuntimeError::InvalidFinal(reason)) => {
                operating_repairs += 1;
                if operating_repairs > MAX_OPERATING_REPAIRS {
                    return Err(AgentRuntimeError::OperatingRepairLimit);
                }
                revision_feedback = vec![format!(
                    "The prior operating decision did not match the required JSON schema: {reason}. Return exactly one corrected JSON object."
                )];
                continue;
            }
            Err(error) => return Err(error),
        };
        match decision {
            ModelDecision::InvokeTool { call } => {
                operating_repairs = 0;
                revision_feedback.clear();
                validate_call(&call)?;
                if observations.len() >= budget.max_tool_calls {
                    return Err(AgentRuntimeError::ToolBudgetExceeded);
                }
                if !call_ids.insert(call.call_id.clone()) {
                    return Err(AgentRuntimeError::DuplicateCallId);
                }
                let descriptor = available_tools
                    .iter()
                    .find(|candidate| candidate.tool_id == call.tool_id)
                    .cloned()
                    .ok_or_else(|| AgentRuntimeError::ToolUnavailable(call.tool_id.clone()))?;
                selected_tools.insert(call.tool_id.clone());
                if selected_tools.len() > budget.max_selected_capabilities {
                    return Err(AgentRuntimeError::ToolBudgetExceeded);
                }
                if descriptor.authority_class == ToolAuthorityClass::Actuate {
                    if lane != ExecutionLane::Act {
                        return Err(AgentRuntimeError::InvalidToolCall(
                            "actuation requires the act lane".into(),
                        ));
                    }
                    let input_digest = call.input_digest();
                    let Some(approval_ref) = effect_authorization(&request, &call)
                        .map(|authorization| authorization.approval_ref.clone())
                    else {
                        return Ok(AgentTurnOutcome::ApprovalRequired {
                            schema_version: AGENT_TURN_RESULT_V1,
                            lane,
                            request: ApprovalRequest {
                                approval_ref: format!(
                                    "approval://agent-effect/{}",
                                    input_digest.trim_start_matches("sha256:")
                                ),
                                tool_id: call.tool_id,
                                input_digest,
                                purpose: call.purpose,
                            },
                            tool_call_count: observations.len(),
                        });
                    };
                    if !consumed_effect_authorizations.insert(approval_ref) {
                        return Err(AgentRuntimeError::InvalidToolCall(
                            "effect authorization was already consumed".into(),
                        ));
                    }
                }
                let result = tools.invoke(&request, &call).await?;
                validate_tool_result(&result)?;
                observations.push(ToolObservation {
                    sequence: observations.len() + 1,
                    call,
                    descriptor,
                    result,
                });
                if observations.last().is_some_and(|observation| {
                    observation.result.state == ToolResultState::OutcomeUnknown
                }) {
                    return finalize_unknown_effect(lane, &observations);
                }
            }
            ModelDecision::Finish { draft } => {
                let draft = normalize_converse_draft(lane, draft, &observations);
                if let Err(error) = validate_final(&request, lane, &draft, &observations) {
                    operating_repairs += 1;
                    if operating_repairs > MAX_OPERATING_REPAIRS {
                        return Err(AgentRuntimeError::OperatingRepairLimit);
                    }
                    revision_feedback = vec![error.to_string()];
                    continue;
                }
                let draft = present_with_repair(
                    model,
                    PresentationTurn {
                        request: request.clone(),
                        lane,
                        draft,
                        observations: observations.clone(),
                        repair_feedback: Vec::new(),
                    },
                )
                .await?;
                if let Err(error) = validate_final(&request, lane, &draft, &observations) {
                    operating_repairs += 1;
                    if operating_repairs > MAX_OPERATING_REPAIRS {
                        return Err(AgentRuntimeError::OperatingRepairLimit);
                    }
                    revision_feedback = vec![error.to_string()];
                    continue;
                }
                operating_repairs = 0;
                let critique = match critique_with_repair(
                    model,
                    CritiqueTurn {
                        request: request.clone(),
                        lane,
                        draft: draft.clone(),
                        observations: observations.clone(),
                        repair_feedback: Vec::new(),
                    },
                )
                .await
                {
                    Ok(decision) => Some(decision),
                    Err(AgentRuntimeError::ModelUnavailable(_)) => None,
                    Err(error) => return Err(error),
                };
                match critique {
                    None | Some(CritiqueDecision::Approve { .. }) => {}
                    Some(CritiqueDecision::Revise { issues }) => {
                        critic_revisions += 1;
                        if critic_revisions > MAX_CRITIC_REVISIONS {
                            return Err(AgentRuntimeError::CriticRepairLimit);
                        }
                        revision_feedback = issues;
                        continue;
                    }
                }
                let evidence_refs = final_evidence_refs(&draft);
                return Ok(AgentTurnOutcome::Delivered {
                    schema_version: AGENT_TURN_RESULT_V1,
                    lane,
                    markdown: render_final(&draft),
                    final_state: draft.state,
                    evidence_refs,
                    tool_call_count: observations.len(),
                    working_state: Some(next_working_state(
                        &request,
                        lane,
                        resumed_mission,
                        &draft,
                    )),
                });
            }
        }
    }
    Err(AgentRuntimeError::ModelStepLimit)
}

fn normalize_converse_draft(
    lane: ExecutionLane,
    mut draft: FinalDraft,
    observations: &[ToolObservation],
) -> FinalDraft {
    if lane != ExecutionLane::Converse || !observations.is_empty() {
        return draft;
    }
    draft.summary_evidence_refs.clear();
    draft.checked.clear();
    draft.changed.clear();
    draft.verified.clear();
    draft.current_state.clear();
    if !bounded_display_text(&draft.headline, MAX_HEADLINE_BYTES)
        || draft.headline.contains('\n')
        || draft.headline.contains('\r')
    {
        // The headline is planning metadata and is not rendered into Slack. Do not
        // spend another model round trip repairing it on an evidence-free turn.
        draft.headline = "Conversation response".into();
    }
    if draft.state == FinalState::Answered {
        draft.coverage_notice = None;
    }
    draft
}

fn next_working_state(
    request: &AgentTurnRequest,
    lane: ExecutionLane,
    resumed_mission: bool,
    draft: &FinalDraft,
) -> WorkingState {
    let prior = request.working_state.as_ref();
    let current_request = if resumed_mission {
        prior
            .map(|state| state.current_request.clone())
            .unwrap_or_else(|| request.message.clone())
    } else {
        request.message.clone()
    };
    let last_outcome = match draft.state {
        FinalState::Answered => WorkingOutcome::Completed,
        FinalState::Partial => WorkingOutcome::Owned,
        FinalState::NeedsInput => WorkingOutcome::NeedsUser,
        FinalState::Blocked => WorkingOutcome::Blocked,
    };
    let mut open_loops = draft.next_actions.clone();
    if let Some(question) = &draft.question
        && !open_loops.contains(question)
    {
        open_loops.push(question.clone());
    }
    WorkingState {
        mission_ref: prior
            .and_then(|state| state.mission_ref.clone())
            .or_else(|| Some(request.thread_ref.clone())),
        current_request,
        last_outcome,
        last_blocker: matches!(draft.state, FinalState::Blocked)
            .then(|| draft.coverage_notice.clone())
            .flatten(),
        active_lane: Some(lane),
        requires_current_evidence: Some(lane != ExecutionLane::Converse),
        open_loops,
    }
}

async fn present_with_repair(
    model: &dyn AgentModel,
    mut turn: PresentationTurn,
) -> Result<FinalDraft, AgentRuntimeError> {
    let validated_fallback = turn.draft.clone();
    for _ in 0..MAX_PRESENTATION_REPAIRS {
        let presentation = match model.present(turn.clone()).await {
            Ok(presentation) => presentation,
            Err(AgentRuntimeError::InvalidFinal(reason)) => {
                turn.repair_feedback = vec![format!(
                    "The prior Slack presentation did not match the required JSON schema: {reason}. Return exactly one corrected presentation JSON object."
                )];
                continue;
            }
            Err(AgentRuntimeError::ModelUnavailable(_)) => return Ok(validated_fallback),
            Err(error) => return Err(error),
        };
        match validate_presentation(&presentation) {
            Ok(summary) => {
                let mut draft = turn.draft;
                draft.summary = summary;
                return Ok(draft);
            }
            Err(error) => {
                turn.repair_feedback = vec![format!(
                    "The prior Slack presentation did not satisfy the conversational contract: {error}. Rewrite only the visible reply."
                )];
            }
        }
    }
    Ok(validated_fallback)
}

async fn critique_with_repair(
    model: &dyn AgentModel,
    mut turn: CritiqueTurn,
) -> Result<CritiqueDecision, AgentRuntimeError> {
    for _ in 0..MAX_CRITIC_REPAIRS {
        match model.critique(turn.clone()).await {
            Ok(decision) => {
                if let Err(error) = validate_critique_decision(&decision) {
                    turn.repair_feedback = vec![format!(
                        "The prior critic decision did not satisfy the bounded critic contract: {error}. Return exactly one corrected critic JSON object."
                    )];
                    continue;
                }
                return Ok(decision);
            }
            Err(AgentRuntimeError::InvalidFinal(reason)) => {
                turn.repair_feedback = vec![format!(
                    "The prior critic decision did not match the required JSON schema: {reason}. Return exactly one corrected critic JSON object."
                )];
            }
            Err(error) => return Err(error),
        }
    }
    Err(AgentRuntimeError::ModelUnavailable(
        "critic decision unavailable after bounded repairs".into(),
    ))
}

async fn route_with_repair(
    model: &dyn AgentModel,
    request: AgentTurnRequest,
) -> Result<ExecutionLane, AgentRuntimeError> {
    let mut repair_feedback = Vec::new();
    for _ in 0..MAX_ROUTER_ATTEMPTS {
        let decision = match model
            .route(RouteTurn {
                request: request.clone(),
                repair_feedback: repair_feedback.clone(),
            })
            .await
        {
            Ok(decision) => decision,
            Err(AgentRuntimeError::InvalidRoute(reason)) => {
                repair_feedback = vec![reason];
                continue;
            }
            Err(error) => return Err(error),
        };
        match validate_route(&request, &decision) {
            Ok(()) => return Ok(decision.lane),
            Err(error) => repair_feedback = vec![error.to_string()],
        }
    }
    Err(AgentRuntimeError::InvalidRoute(
        "router repair attempts were exhausted".into(),
    ))
}

fn validate_route(
    request: &AgentTurnRequest,
    decision: &RouteDecision,
) -> Result<(), AgentRuntimeError> {
    if !bounded_text(&decision.reason) {
        return Err(AgentRuntimeError::InvalidRoute(
            "route reason is empty or too large".into(),
        ));
    }
    if decision.confidence == RouteConfidence::Low {
        return Err(AgentRuntimeError::InvalidRoute(
            "low-confidence routing cannot authorize a lane".into(),
        ));
    }
    match decision.lane {
        ExecutionLane::Ignore => Err(AgentRuntimeError::InvalidRoute(
            "transport events are ignored before semantic routing".into(),
        )),
        ExecutionLane::Converse if decision.requires_current_evidence => Err(
            AgentRuntimeError::InvalidRoute("conversation cannot require current evidence".into()),
        ),
        ExecutionLane::Converse => Ok(()),
        ExecutionLane::Continue
            if request
                .working_state
                .as_ref()
                .and_then(|state| state.mission_ref.as_ref())
                .is_none() =>
        {
            Err(AgentRuntimeError::InvalidRoute(
                "continuation requires a durable mission".into(),
            ))
        }
        ExecutionLane::Continue
            if request
                .working_state
                .as_ref()
                .and_then(|state| state.requires_current_evidence)
                .is_some_and(|required| required != decision.requires_current_evidence) =>
        {
            Err(AgentRuntimeError::InvalidRoute(
                "continuation evidence requirement does not match the durable mission".into(),
            ))
        }
        ExecutionLane::Continue => Ok(()),
        ExecutionLane::Lookup | ExecutionLane::Investigate | ExecutionLane::Act
            if !decision.requires_current_evidence =>
        {
            Err(AgentRuntimeError::InvalidRoute(
                "the selected operating lane requires current evidence".into(),
            ))
        }
        ExecutionLane::Lookup | ExecutionLane::Investigate | ExecutionLane::Act => Ok(()),
    }
}

fn validate_critique_issues(issues: &[String]) -> Result<(), AgentRuntimeError> {
    if issues.is_empty() || issues.len() > 16 || issues.iter().any(|issue| !bounded_text(issue)) {
        return Err(AgentRuntimeError::InvalidFinal(
            "critic revision issues are empty or exceed the bound".into(),
        ));
    }
    Ok(())
}

fn validate_presentation(presentation: &PresentationDecision) -> Result<String, AgentRuntimeError> {
    if presentation.messages.is_empty()
        || presentation.messages.len() > 2
        || presentation
            .messages
            .iter()
            .any(|message| !bounded_display_text(message, MAX_SUMMARY_BYTES))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "Slack presentation requires one or two bounded messages".into(),
        ));
    }
    let summary = presentation
        .messages
        .iter()
        .map(|message| message.trim())
        .collect::<Vec<_>>()
        .join("\n\n");
    if summary.len() > MAX_SUMMARY_BYTES {
        return Err(AgentRuntimeError::InvalidFinal(
            "Slack presentation exceeds the visible reply limit".into(),
        ));
    }
    if looks_like_report_copy(&summary) || looks_like_user_handback(&summary) {
        return Err(AgentRuntimeError::InvalidFinal(
            "Slack presentation reads like an internal report or hands assistant-owned work back to the user"
                .into(),
        ));
    }
    Ok(summary)
}

fn validate_critique_decision(decision: &CritiqueDecision) -> Result<(), AgentRuntimeError> {
    match decision {
        CritiqueDecision::Approve { checks }
            if checks.answers_newest_request
                && checks.conversational
                && checks.evidence_boundary_correct
                && checks.no_raw_record_dump
                && checks.operator_facing
                && checks.owns_follow_through
                && checks.right_sized =>
        {
            Ok(())
        }
        CritiqueDecision::Approve { checks } => {
            let failed = [
                ("answers_newest_request", checks.answers_newest_request),
                ("conversational", checks.conversational),
                (
                    "evidence_boundary_correct",
                    checks.evidence_boundary_correct,
                ),
                ("no_raw_record_dump", checks.no_raw_record_dump),
                ("operator_facing", checks.operator_facing),
                ("owns_follow_through", checks.owns_follow_through),
                ("right_sized", checks.right_sized),
            ]
            .into_iter()
            .filter_map(|(name, passed)| (!passed).then_some(name))
            .collect::<Vec<_>>()
            .join(", ");
            Err(AgentRuntimeError::InvalidFinal(format!(
                "critic approval has failed checks: {failed}"
            )))
        }
        CritiqueDecision::Revise { issues } => validate_critique_issues(issues),
    }
}

fn validate_request(request: &AgentTurnRequest) -> Result<(), AgentRuntimeError> {
    if request.schema_version != AGENT_TURN_REQUEST_V1 {
        return Err(AgentRuntimeError::InvalidRequest(
            "schema version is unsupported".into(),
        ));
    }
    for (label, value) in [
        ("tenant_id", request.tenant_id.as_str()),
        ("request_id", request.request_id.as_str()),
        ("thread_ref", request.thread_ref.as_str()),
        ("actor_ref", request.actor_ref.as_str()),
        ("assessment_at", request.assessment_at.as_str()),
        ("message", request.message.as_str()),
    ] {
        if !bounded_text(value) {
            return Err(AgentRuntimeError::InvalidRequest(format!(
                "{label} is empty or too large"
            )));
        }
    }
    parse_timestamp(&request.assessment_at)
        .map_err(|_| AgentRuntimeError::InvalidRequest("assessment_at is invalid".into()))?;
    let history_bytes = request
        .history
        .iter()
        .map(|message| message.content.len())
        .sum::<usize>();
    if request.history.len() > MAX_HISTORY_ITEMS
        || history_bytes > MAX_HISTORY_TOTAL_BYTES
        || request.history.iter().any(|message| {
            message.content.trim().is_empty()
                || message.content.len() > MAX_HISTORY_ITEM_BYTES
                || message.content.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
        })
    {
        return Err(AgentRuntimeError::HistoryInvalid);
    }
    if request.working_state.as_ref().is_some_and(|state| {
        !bounded_text(&state.current_request)
            || state
                .mission_ref
                .as_ref()
                .is_some_and(|value| !bounded_text(value))
            || state
                .last_blocker
                .as_ref()
                .is_some_and(|value| !bounded_text(value))
            || state.open_loops.len() > MAX_NEXT_ACTIONS + 1
            || state.open_loops.iter().any(|value| !bounded_text(value))
    }) {
        return Err(AgentRuntimeError::InvalidRequest(
            "working state contains an invalid field".into(),
        ));
    }
    Ok(())
}

fn validate_catalog(catalog: &[ToolDescriptor]) -> Result<(), AgentRuntimeError> {
    let mut ids = BTreeSet::new();
    for tool in catalog {
        if !bounded_text(&tool.tool_id)
            || !bounded_text(&tool.title)
            || !bounded_text(&tool.summary)
            || !bounded_text(&tool.input_schema_ref)
            || !bounded_text(&tool.result_schema_ref)
        {
            return Err(AgentRuntimeError::InvalidToolCall(
                "tool catalog contains an invalid field".into(),
            ));
        }
        if !ids.insert(tool.tool_id.as_str()) {
            return Err(AgentRuntimeError::InvalidToolCall(
                "tool catalog repeats an id".into(),
            ));
        }
    }
    Ok(())
}

fn validate_call(call: &ToolCall) -> Result<(), AgentRuntimeError> {
    if !bounded_text(&call.call_id)
        || !bounded_text(&call.tool_id)
        || !bounded_text(&call.purpose)
        || !call.input.is_object()
    {
        return Err(AgentRuntimeError::InvalidToolCall(
            "tool call fields are invalid".into(),
        ));
    }
    Ok(())
}

fn validate_tool_result(result: &ToolResult) -> Result<(), AgentRuntimeError> {
    if !bounded_text(&result.summary)
        || result
            .blocker
            .as_ref()
            .is_some_and(|value| !bounded_text(value))
        || result.evidence.iter().any(|evidence| {
            !bounded_text(&evidence.evidence_ref)
                || !bounded_text(&evidence.statement)
                || !bounded_text(&evidence.observed_at)
        })
        || serde_json::to_vec(&result.data).is_ok_and(|encoded| encoded.len() > MAX_TOOL_DATA_BYTES)
    {
        return Err(AgentRuntimeError::InvalidToolCall(
            "tool result fields are invalid".into(),
        ));
    }
    let mut evidence_refs = BTreeSet::new();
    for evidence in &result.evidence {
        parse_timestamp(&evidence.observed_at).map_err(|_| {
            AgentRuntimeError::InvalidToolCall("evidence observed_at is invalid".into())
        })?;
        if let Some(fresh_until) = &evidence.fresh_until {
            parse_timestamp(fresh_until).map_err(|_| {
                AgentRuntimeError::InvalidToolCall("evidence fresh_until is invalid".into())
            })?;
        }
        if !evidence_refs.insert(evidence.evidence_ref.as_str()) {
            return Err(AgentRuntimeError::InvalidToolCall(
                "tool result repeats an evidence reference".into(),
            ));
        }
    }
    Ok(())
}

fn validate_final(
    request: &AgentTurnRequest,
    lane: ExecutionLane,
    draft: &FinalDraft,
    observations: &[ToolObservation],
) -> Result<(), AgentRuntimeError> {
    if !bounded_display_text(&draft.headline, MAX_HEADLINE_BYTES)
        || draft.headline.contains('\n')
        || draft.headline.contains('\r')
        || !bounded_display_text(&draft.summary, MAX_SUMMARY_BYTES)
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "headline or summary is empty, oversized, or structurally invalid".into(),
        ));
    }
    let claim_count = all_claims(draft).count();
    if draft.checked.len() > MAX_CLAIMS_PER_SECTION
        || draft.changed.len() > MAX_CLAIMS_PER_SECTION
        || draft.verified.len() > MAX_CLAIMS_PER_SECTION
        || draft.current_state.len() > MAX_CLAIMS_PER_SECTION
        || claim_count > MAX_TOTAL_CLAIMS
        || draft.next_actions.len() > MAX_NEXT_ACTIONS
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "operator output contains too many report items".into(),
        ));
    }
    if looks_like_raw_record_dump(&draft.summary)
        || looks_like_internal_query_failure(&draft.summary)
        || draft.coverage_notice.as_ref().is_some_and(|value| {
            looks_like_raw_record_dump(value) || looks_like_internal_query_failure(value)
        })
        || draft.question.as_ref().is_some_and(|value| {
            looks_like_raw_record_dump(value) || looks_like_internal_query_failure(value)
        })
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "operator output exposes raw records or internal query mechanics instead of a bounded answer"
                .into(),
        ));
    }
    if draft
        .coverage_notice
        .as_ref()
        .is_some_and(|value| !bounded_display_text(value, MAX_SUPPLEMENT_BYTES))
        || draft
            .question
            .as_ref()
            .is_some_and(|value| !bounded_display_text(value, MAX_SUPPLEMENT_BYTES))
        || draft.next_actions.iter().any(|value| !bounded_text(value))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "display fields are invalid".into(),
        ));
    }
    match draft.state {
        FinalState::Answered if draft.question.is_some() => {
            return Err(AgentRuntimeError::InvalidFinal(
                "answered output cannot ask for input".into(),
            ));
        }
        FinalState::Partial if draft.coverage_notice.is_none() => {
            return Err(AgentRuntimeError::InvalidFinal(
                "partial output requires a coverage notice".into(),
            ));
        }
        FinalState::NeedsInput if draft.question.is_none() => {
            return Err(AgentRuntimeError::InvalidFinal(
                "needs-input output requires one question".into(),
            ));
        }
        FinalState::Blocked if draft.coverage_notice.is_none() => {
            return Err(AgentRuntimeError::InvalidFinal(
                "blocked output requires a coverage notice".into(),
            ));
        }
        _ => {}
    }

    let observed_evidence = observations
        .iter()
        .flat_map(|observation| &observation.result.evidence)
        .map(|evidence| (evidence.evidence_ref.as_str(), evidence))
        .collect::<BTreeMap<_, _>>();
    let requested_assessment_at = parse_timestamp(&request.assessment_at)
        .map_err(|_| AgentRuntimeError::InvalidFinal("assessment time is invalid".into()))?;
    let assessment_at = observations
        .iter()
        .flat_map(|observation| &observation.result.evidence)
        .filter_map(|evidence| parse_timestamp(&evidence.observed_at).ok())
        .fold(requested_assessment_at, OffsetDateTime::max);
    if matches!(draft.state, FinalState::Answered | FinalState::Partial)
        && !matches!(lane, ExecutionLane::Converse)
        && draft.summary_evidence_refs.is_empty()
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "operator summary requires evidence".into(),
        ));
    }
    let mut referenced_non_authoritative = false;
    for reference in &draft.summary_evidence_refs {
        let evidence = observed_evidence
            .get(reference.as_str())
            .ok_or_else(|| AgentRuntimeError::EvidenceNotObserved(reference.clone()))?;
        if !evidence_is_authoritative(evidence, assessment_at)? {
            referenced_non_authoritative = true;
        }
    }
    for claim in all_claims(draft) {
        if !bounded_text(&claim.text) || claim.evidence_refs.is_empty() {
            return Err(AgentRuntimeError::InvalidFinal(
                "operator claims require evidence".into(),
            ));
        }
        for reference in &claim.evidence_refs {
            let evidence = observed_evidence
                .get(reference.as_str())
                .ok_or_else(|| AgentRuntimeError::EvidenceNotObserved(reference.clone()))?;
            if !evidence_is_authoritative(evidence, assessment_at)? {
                referenced_non_authoritative = true;
            }
        }
    }
    if referenced_non_authoritative
        && !matches!(draft.state, FinalState::Partial | FinalState::Blocked)
    {
        let reference = draft
            .summary_evidence_refs
            .iter()
            .chain(all_claims(draft).flat_map(|claim| &claim.evidence_refs))
            .find(|reference| {
                observed_evidence
                    .get(reference.as_str())
                    .is_some_and(|evidence| {
                        !evidence
                            .fresh_until
                            .as_deref()
                            .and_then(|value| parse_timestamp(value).ok())
                            .is_some_and(|fresh_until| {
                                evidence.complete && fresh_until >= assessment_at
                            })
                    })
            })
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        return Err(AgentRuntimeError::EvidenceNotAuthoritative(reference));
    }

    let last_effect_sequence = observations
        .iter()
        .filter(|observation| observation.descriptor.authority_class == ToolAuthorityClass::Actuate)
        .map(|observation| observation.sequence)
        .max();
    if lane == ExecutionLane::Act && last_effect_sequence.is_some() {
        let verification_refs = observations
            .iter()
            .filter(|observation| {
                observation.sequence > last_effect_sequence.unwrap_or(0)
                    && observation.descriptor.authority_class == ToolAuthorityClass::Observe
                    && observation.result.state == ToolResultState::Succeeded
            })
            .flat_map(|observation| &observation.result.evidence)
            .filter(|evidence| evidence_is_authoritative(evidence, assessment_at).unwrap_or(false))
            .map(|evidence| evidence.evidence_ref.as_str())
            .collect::<BTreeSet<_>>();
        if draft.verified.is_empty()
            || draft
                .verified
                .iter()
                .flat_map(|claim| &claim.evidence_refs)
                .any(|reference| !verification_refs.contains(reference.as_str()))
        {
            return Err(AgentRuntimeError::UnverifiedEffect);
        }
    }
    Ok(())
}

fn finalize_unknown_effect(
    lane: ExecutionLane,
    observations: &[ToolObservation],
) -> Result<AgentTurnOutcome, AgentRuntimeError> {
    let observation = observations.last().ok_or_else(|| {
        AgentRuntimeError::InvalidFinal("unknown effect has no observation".into())
    })?;
    let blocker = observation
        .result
        .blocker
        .as_deref()
        .unwrap_or("The effect outcome could not be confirmed.");
    Ok(AgentTurnOutcome::Delivered {
        schema_version: AGENT_TURN_RESULT_V1,
        lane,
        markdown: format!(
            "**Outcome not confirmed**\n\n{blocker}\n\n**Next**\n- Reconcile the existing effect receipt before retrying."
        ),
        final_state: FinalState::Blocked,
        evidence_refs: observation
            .result
            .evidence
            .iter()
            .map(|evidence| evidence.evidence_ref.clone())
            .collect(),
        tool_call_count: observations.len(),
        working_state: None,
    })
}

fn effect_authorization<'a>(
    request: &'a AgentTurnRequest,
    call: &ToolCall,
) -> Option<&'a EffectAuthorization> {
    let input_digest = call.input_digest();
    request.effect_authorizations.iter().find(|authorization| {
        authorization.tenant_id == request.tenant_id
            && authorization.request_id == request.request_id
            && authorization.thread_ref == request.thread_ref
            && authorization.actor_ref == request.actor_ref
            && authorization.tool_id == call.tool_id
            && authorization.input_digest == input_digest
            && bounded_text(&authorization.approval_ref)
    })
}

fn all_claims(draft: &FinalDraft) -> impl Iterator<Item = &EvidenceClaim> {
    draft
        .checked
        .iter()
        .chain(&draft.changed)
        .chain(&draft.verified)
        .chain(&draft.current_state)
}

fn final_evidence_refs(draft: &FinalDraft) -> Vec<String> {
    draft
        .summary_evidence_refs
        .iter()
        .cloned()
        .chain(all_claims(draft).flat_map(|claim| claim.evidence_refs.iter().cloned()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn tool_allowed_in_lane(lane: ExecutionLane, tool: &ToolDescriptor) -> bool {
    match lane {
        ExecutionLane::Ignore | ExecutionLane::Converse | ExecutionLane::Continue => false,
        ExecutionLane::Lookup => tool.authority_class == ToolAuthorityClass::Observe,
        ExecutionLane::Investigate => tool.authority_class != ToolAuthorityClass::Actuate,
        ExecutionLane::Act => true,
    }
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

fn evidence_is_authoritative(
    evidence: &EvidenceRecord,
    assessment_at: OffsetDateTime,
) -> Result<bool, AgentRuntimeError> {
    let observed_at = parse_timestamp(&evidence.observed_at)
        .map_err(|_| AgentRuntimeError::InvalidFinal("evidence timestamp is invalid".into()))?;
    if observed_at > assessment_at {
        return Err(AgentRuntimeError::InvalidFinal(
            "evidence observation is in the future".into(),
        ));
    }
    let fresh = evidence
        .fresh_until
        .as_deref()
        .and_then(|value| parse_timestamp(value).ok())
        .is_some_and(|fresh_until| fresh_until >= assessment_at);
    Ok(evidence.complete && fresh)
}

fn render_final(draft: &FinalDraft) -> String {
    let mut sections = vec![draft.summary.trim().to_owned()];
    if let Some(notice) = &draft.coverage_notice
        && !draft.summary.contains(notice.trim())
    {
        sections.push(notice.trim().to_owned());
    }
    if let Some(question) = &draft.question
        && !draft.summary.contains(question.trim())
    {
        sections.push(question.trim().to_owned());
    }
    sections.join("\n\n")
}

fn digest_json(value: &Value) -> String {
    let encoded = serde_json::to_vec(value).expect("JSON values always serialize");
    let digest = Sha256::digest(encoded);
    let encoded = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{encoded}")
}

fn bounded_text(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= MAX_TEXT_BYTES
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn bounded_display_text(value: &str, max_bytes: usize) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= max_bytes
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn looks_like_raw_record_dump(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let internal_marker_count = [
        "urn:cerebro:",
        "evidence://",
        "schema://",
        "\"graph_revision\"",
        "\"runtime_id\"",
        "\"source_ref\"",
        "\"tenant_id\"",
        "\"trace_id\"",
    ]
    .into_iter()
    .map(|marker| normalized.matches(marker).count())
    .sum::<usize>();
    let has_markdown_table = normalized
        .lines()
        .any(|line| line.contains("|---") || line.contains("---|"));
    let has_nested_heading = normalized
        .lines()
        .any(|line| line.trim_start().starts_with('#'));
    internal_marker_count >= 2
        || (internal_marker_count > 0 && (has_markdown_table || has_nested_heading))
}

fn looks_like_internal_query_failure(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "deterministic ask query",
        "row-expanding cypher",
        "read-only cypher validator",
        "query matched more graph rows than can be safely post-processed",
        "unwind, range(), and collect()",
    ]
    .into_iter()
    .any(|marker| normalized.contains(marker))
}

fn looks_like_report_copy(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    normalized.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with('#')
            || [
                "checked:",
                "evidence:",
                "current state:",
                "next actions:",
                "research:",
                "tool trail:",
                "observations:",
            ]
            .into_iter()
            .any(|prefix| line.starts_with(prefix))
    })
}

fn looks_like_user_handback(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "let me know if",
        "would you like me to",
        "do you want me to",
        "if you'd like, i can",
        "say the word",
        "tell me if you want",
    ]
    .into_iter()
    .any(|marker| normalized.contains(marker))
}
