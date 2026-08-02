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

pub mod session;

pub const AGENT_TURN_REQUEST_V1: &str = "agent-turn-request/v1";
pub const AGENT_TURN_RESULT_V1: &str = "agent-turn-result/v1";
pub const AGENT_DELIVERY_RECEIPT_V1: &str = "agent-delivery-receipt/v1";
pub const MAX_HISTORY_ITEMS: usize = 200;
pub const MAX_HISTORY_ITEM_BYTES: usize = 16 * 1024;
pub const MAX_HISTORY_TOTAL_BYTES: usize = 1024 * 1024;
pub const MAX_MODEL_STEPS: usize = 24;
pub const MAX_ROUTER_ATTEMPTS: usize = 4;
pub const MAX_OPERATING_REPAIRS: usize = 8;
pub const MAX_PRESENTATION_REPAIRS: usize = 4;
pub const MAX_CRITIC_REPAIRS: usize = 4;
pub const MAX_CRITIC_REVISIONS: usize = 4;
pub const ROUTER_MAX_TOKENS: i32 = 32_768;
pub const DECISION_MAX_TOKENS: i32 = 63_999;
pub const PRESENTATION_MAX_TOKENS: i32 = 16_384;
pub const CRITIC_MAX_TOKENS: i32 = 16_384;
pub const HARD_MAX_GENERATION_TOKENS: i32 = 131_072;
const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_TOOL_DATA_BYTES: usize = 64 * 1024;
const MAX_HEADLINE_BYTES: usize = 160;
const MAX_SUMMARY_BYTES: usize = 2_400;
const MAX_SUPPLEMENT_BYTES: usize = 800;
const MAX_CLAIMS_PER_SECTION: usize = 8;
const MAX_TOTAL_CLAIMS: usize = 16;
const MAX_NEXT_ACTIONS: usize = 5;
const MAX_GROUNDING_UNITS: usize = 64;

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
                max_selected_capabilities: 14,
                max_tool_calls: 14,
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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConversationMessageMetadata {
    #[serde(default)]
    pub actor_ref: Option<String>,
    #[serde(default)]
    pub message_ref: Option<String>,
    #[serde(default)]
    pub received_at: Option<String>,
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
    #[serde(default)]
    pub context_scope_ref: Option<String>,
    pub actor_ref: String,
    pub assessment_at: String,
    pub message: String,
    pub history: Vec<ConversationMessage>,
    #[serde(default)]
    pub history_metadata: Vec<ConversationMessageMetadata>,
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
    #[serde(default)]
    pub atoms: Vec<session::EvidenceAtom>,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
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
    pub grounding_units: Vec<CritiqueGroundingUnit>,
    pub repair_feedback: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CritiqueGroundingUnit {
    pub unit_id: String,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CritiqueGroundingBasis {
    DirectObservation,
    BoundedInference,
    OperatorSupplied,
    RetainedContext,
    ToolOutcome,
    Hypothesis,
    Recommendation,
    StableExplanation,
    Placeholder,
    NonFactual,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CritiqueGroundingSupport {
    pub evidence_ref: String,
    pub data_pointer: Option<String>,
    pub supporting_text: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CritiqueGroundingCheck {
    pub unit_id: String,
    pub basis: CritiqueGroundingBasis,
    pub support: Vec<CritiqueGroundingSupport>,
    pub context_excerpt: Option<String>,
    pub observation_sequence: Option<usize>,
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
    Approve {
        checks: CritiqueChecks,
        grounding: Vec<CritiqueGroundingCheck>,
    },
    Revise {
        issues: Vec<String>,
    },
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
    pub input_preview: String,
    pub purpose: String,
}

fn approval_input_preview(input: &Value) -> String {
    const MAX_APPROVAL_PREVIEW_BYTES: usize = 12 * 1024;

    fn sensitive_key(key: &str) -> bool {
        let key = key
            .chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .flat_map(char::to_lowercase)
            .collect::<String>();
        key == "auth"
            || [
                "accesskey",
                "apikey",
                "authorization",
                "bearer",
                "cookie",
                "credential",
                "encryptionkey",
                "passphrase",
                "password",
                "privatekey",
                "secret",
                "sessionid",
                "sessiontoken",
                "signingkey",
                "token",
            ]
            .iter()
            .any(|sensitive| key.contains(sensitive))
    }

    fn redacted(value: &Value, key: Option<&str>) -> Value {
        if key.is_some_and(sensitive_key) {
            return Value::String("<redacted>".into());
        }
        match value {
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(key, value)| (key.clone(), redacted(value, Some(key))))
                    .collect(),
            ),
            Value::Array(items) => {
                Value::Array(items.iter().map(|item| redacted(item, key)).collect())
            }
            _ => value.clone(),
        }
    }

    let preview = serde_json::to_string_pretty(&redacted(input, None))
        .unwrap_or_else(|_| "<input preview unavailable>".into());
    if preview.len() <= MAX_APPROVAL_PREVIEW_BYTES {
        return preview;
    }
    let mut boundary = MAX_APPROVAL_PREVIEW_BYTES;
    while boundary > 0 && !preview.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!(
        "{}\n<truncated; exact input remains bound by digest>",
        &preview[..boundary]
    )
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDeliveryReceipt {
    pub schema_version: String,
    pub tenant_id: String,
    pub thread_ref: String,
    pub request_id: String,
    pub transport: String,
    pub delivery_ref: String,
    pub payload_digest: String,
    pub delivered_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AgentTurnOutcome {
    PendingDelivery {
        schema_version: &'static str,
        lane: ExecutionLane,
        markdown: String,
        final_state: FinalState,
        evidence_refs: Vec<String>,
        tool_call_count: usize,
        working_state: Option<WorkingState>,
    },
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
    validate_agent_turn_request(&request)?;
    let routed_lane = route_request(model, request.clone()).await?;
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
            match route_request(model, resumed).await? {
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
    let mut call_fingerprints = BTreeSet::new();
    let mut consumed_effect_authorizations = BTreeSet::new();
    let mut selected_tools = BTreeSet::new();
    let mut revision_feedback = Vec::new();
    let mut operating_repairs = 0;
    let mut critic_revisions = 0;
    for _ in 0..MAX_MODEL_STEPS {
        let presentation_feedback = revision_feedback.clone();
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
                    return Ok(repair_limit_outcome(
                        &request,
                        lane,
                        resumed_mission,
                        &observations,
                    ));
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
                    operating_repairs += 1;
                    if operating_repairs > MAX_OPERATING_REPAIRS {
                        return Err(AgentRuntimeError::ToolBudgetExceeded);
                    }
                    revision_feedback = vec![format!(
                        "The {lane:?} lane has used all {} bounded tool calls. Do not invoke another capability. Finish now from the collected observations, preserving the exact unsupported fields as a coverage gap.",
                        budget.max_tool_calls
                    )];
                    continue;
                }
                if !call_ids.insert(call.call_id.clone()) {
                    operating_repairs += 1;
                    if operating_repairs > MAX_OPERATING_REPAIRS {
                        return Ok(repair_limit_outcome(
                            &request,
                            lane,
                            resumed_mission,
                            &observations,
                        ));
                    }
                    revision_feedback = vec![format!(
                        "Tool call_id {:?} was already used in this turn. Do not repeat the call. Finish from existing observations, or use a new unique call_id only for a materially different read.",
                        call.call_id
                    )];
                    continue;
                }
                let descriptor = available_tools
                    .iter()
                    .find(|candidate| candidate.tool_id == call.tool_id)
                    .cloned()
                    .ok_or_else(|| AgentRuntimeError::ToolUnavailable(call.tool_id.clone()))?;
                if descriptor.authority_class != ToolAuthorityClass::Actuate {
                    let call_fingerprint = (call.tool_id.clone(), call.input_digest());
                    if !call_fingerprints.insert(call_fingerprint) {
                        operating_repairs += 1;
                        if operating_repairs > MAX_OPERATING_REPAIRS {
                            return Ok(repair_limit_outcome(
                                &request,
                                lane,
                                resumed_mission,
                                &observations,
                            ));
                        }
                        revision_feedback = vec![
                            "The identical capability and input were already observed in this turn. Use the existing observation, choose a materially different read, or finish the answer."
                                .into(),
                        ];
                        continue;
                    }
                }
                selected_tools.insert(call.tool_id.clone());
                if selected_tools.len() > budget.max_selected_capabilities {
                    selected_tools.remove(&call.tool_id);
                    operating_repairs += 1;
                    if operating_repairs > MAX_OPERATING_REPAIRS {
                        return Err(AgentRuntimeError::ToolBudgetExceeded);
                    }
                    revision_feedback = vec![format!(
                        "The {lane:?} lane has reached its bounded capability-selection limit. Do not select another capability. Finish now from the collected observations and name any remaining field as a coverage gap."
                    )];
                    continue;
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
                                tool_id: call.tool_id.clone(),
                                input_digest,
                                input_preview: approval_input_preview(&call.input),
                                purpose: call.purpose.clone(),
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
                if descriptor.authority_class == ToolAuthorityClass::Actuate {
                    call_fingerprints.clear();
                }
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
                if let Err(error) =
                    validate_final(&request, lane, resumed_mission, &draft, &observations)
                {
                    operating_repairs += 1;
                    if operating_repairs > MAX_OPERATING_REPAIRS {
                        return Ok(repair_limit_outcome(
                            &request,
                            lane,
                            resumed_mission,
                            &observations,
                        ));
                    }
                    revision_feedback = if resumed_mission
                        && lane != ExecutionLane::Converse
                        && observations.is_empty()
                    {
                        vec![format!(
                            "The durable mission resumed in the {lane:?} lane, so thread history cannot support the current answer: {error}. Invoke one available bounded observation capability now. If no capability can observe the required field, finish blocked with no evidence claims and one exact coverage notice. Never cite history or working state as evidence."
                        )]
                    } else {
                        vec![error.to_string()]
                    };
                    continue;
                }
                let draft = present_with_repair(
                    model,
                    PresentationTurn {
                        request: request.clone(),
                        lane,
                        draft,
                        observations: observations.clone(),
                        repair_feedback: presentation_feedback,
                    },
                )
                .await?;
                if let Err(error) =
                    validate_final(&request, lane, resumed_mission, &draft, &observations)
                {
                    operating_repairs += 1;
                    if operating_repairs > MAX_OPERATING_REPAIRS {
                        return Ok(repair_limit_outcome(
                            &request,
                            lane,
                            resumed_mission,
                            &observations,
                        ));
                    }
                    revision_feedback = vec![error.to_string()];
                    continue;
                }
                operating_repairs = 0;
                let grounding_units = critique_grounding_units(&draft);
                let critique = critique_with_repair(
                    model,
                    CritiqueTurn {
                        request: request.clone(),
                        lane,
                        draft: draft.clone(),
                        observations: observations.clone(),
                        grounding_units,
                        repair_feedback: Vec::new(),
                    },
                )
                .await?;
                match critique {
                    CritiqueDecision::Approve { .. } => {}
                    CritiqueDecision::Revise { issues } => {
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

fn repair_limit_outcome(
    request: &AgentTurnRequest,
    lane: ExecutionLane,
    resumed_mission: bool,
    observations: &[ToolObservation],
) -> AgentTurnOutcome {
    let effect_observed = observations
        .iter()
        .any(|observation| observation.descriptor.authority_class == ToolAuthorityClass::Actuate);
    let (summary, next_action) = if effect_observed {
        (
            "I couldn't produce a reliable final synthesis after the bounded repair attempts. The effect observation remains recorded, but I am not claiming completion without a clean independent verification.",
            "Reconcile the recorded effect outcome and obtain a fresh independent verification before closure.",
        )
    } else {
        (
            "I couldn't produce a reliable answer after the bounded repair attempts. I preserved the thread, and no external change was applied.",
            "Retry the bounded read or final synthesis without repeating the prior failed decision.",
        )
    };
    let draft = FinalDraft {
        state: FinalState::Blocked,
        headline: "Reliable answer blocked".into(),
        summary: summary.into(),
        summary_evidence_refs: Vec::new(),
        checked: Vec::new(),
        changed: Vec::new(),
        verified: Vec::new(),
        current_state: Vec::new(),
        next_actions: vec![next_action.into()],
        coverage_notice: Some(
            "The operating model could not satisfy the final-answer contract within its bounded repair limit."
                .into(),
        ),
        question: None,
    };
    AgentTurnOutcome::Delivered {
        schema_version: AGENT_TURN_RESULT_V1,
        lane,
        markdown: render_final(&draft),
        final_state: draft.state,
        evidence_refs: Vec::new(),
        tool_call_count: observations.len(),
        working_state: Some(next_working_state(request, lane, resumed_mission, &draft)),
    }
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
                if let Err(error) = validate_critique_decision(&turn, &decision) {
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
    Err(AgentRuntimeError::CriticRepairLimit)
}

pub async fn route_request(
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

pub async fn resolve_request_lane(
    model: &dyn AgentModel,
    request: AgentTurnRequest,
) -> Result<ExecutionLane, AgentRuntimeError> {
    validate_agent_turn_request(&request)?;
    let routed_lane = route_request(model, request.clone()).await?;
    if routed_lane != ExecutionLane::Continue {
        return Ok(routed_lane);
    }
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
        return Ok(active_lane);
    }
    let current_request = state.current_request.clone();
    let mut resumed = request;
    resumed.message = current_request;
    resumed.working_state = None;
    Ok(match route_request(model, resumed).await? {
        ExecutionLane::Ignore | ExecutionLane::Converse | ExecutionLane::Continue => {
            ExecutionLane::Investigate
        }
        lane => lane,
    })
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
    if request_explicitly_requires_investigation(&request.message)
        && matches!(
            decision.lane,
            ExecutionLane::Converse | ExecutionLane::Lookup
        )
    {
        return Err(AgentRuntimeError::InvalidRoute(
            "the newest request requires current multi-claim synthesis and cannot use a conversation or single-record lookup lane"
                .into(),
        ));
    }
    match decision.lane {
        ExecutionLane::Ignore => Err(AgentRuntimeError::InvalidRoute(
            "transport events are ignored before semantic routing".into(),
        )),
        ExecutionLane::Converse
            if decision.requires_current_evidence
                || request_explicitly_requires_current_evidence(&request.message) =>
        {
            Err(AgentRuntimeError::InvalidRoute(
                "the newest request explicitly requires current evidence and cannot use conversation"
                    .into(),
            ))
        }
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
        ExecutionLane::Act
            if request.effect_authorizations.is_empty()
                && request
                    .working_state
                    .as_ref()
                    .and_then(|state| state.mission_ref.as_ref())
                    .is_some()
                && request.message.split_whitespace().count() <= 3 =>
        {
            Err(AgentRuntimeError::InvalidRoute(
                "a short directive with no exact effect authorization is ambiguous in an active mission. Route continue to advance the retained request; use act only when the newest request identifies the external effect"
                    .into(),
            ))
        }
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

fn request_explicitly_requires_current_evidence(message: &str) -> bool {
    clause_explicitly_requires_current_evidence(message)
}

pub(crate) fn request_is_artifact_transformation(message: &str) -> bool {
    let normalized = normalized_phrase_text(message);
    let transformation = [
        " rewrite ",
        " draft ",
        " summarize ",
        " tighten ",
        " make that ",
        " turn this into ",
        " less technical ",
        " more concise ",
    ]
    .iter()
    .any(|marker| normalized.contains(marker));
    let requests_live_check = [
        " check ",
        " inspect ",
        " verify ",
        " reconcile ",
        " look up ",
        " search ",
    ]
    .iter()
    .any(|marker| normalized.contains(marker));
    transformation && !requests_live_check
}

fn clause_explicitly_requires_current_evidence(clause: &str) -> bool {
    let normalized = normalized_phrase_text(clause);
    let words = normalized.split_whitespace().collect::<Vec<_>>();
    let named_operational_subject = words.iter().enumerate().any(|(index, word)| {
        if !matches!(
            *word,
            "source"
                | "sources"
                | "connector"
                | "connectors"
                | "provider"
                | "providers"
                | "runtime"
                | "runtimes"
        ) {
            return false;
        }
        let next = words.get(index + 1).copied();
        !matches!(
            next,
            None | Some(
                "neutral" | "architecture" | "design" | "model" | "pattern" | "concept" | "theory"
            )
        )
    });
    let explicit_named_operational_read = named_operational_subject
        && [
            "inspect",
            "inspected",
            "read",
            "reads",
            "search",
            "searched",
            "reconcile",
            "reconciled",
            "reconciling",
            "recheck",
            "rechecked",
            "verify",
            "verification",
            "working",
            "missing",
            "enabled",
            "healthy",
            "connected",
            "available",
        ]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} ")));
    let explicit_named_current_state = named_operational_subject
        && [
            "current",
            "currently",
            "right now",
            "today",
            "actually have",
            "actually available",
        ]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} ")))
        && [
            "status",
            "statuses",
            "state",
            "states",
            "evidence",
            "receipt",
            "receipts",
            "access",
            "visibility",
            "field",
            "fields",
            "source",
            "sources",
            "connector",
            "connectors",
            "provider",
            "providers",
            "runtime",
            "runtimes",
        ]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} ")));
    let conceptual_explanation = normalized.contains(" state of the art ")
        || (normalized.contains(" provider neutral ")
            && ["architecture", "design", "model", "pattern", "concept"]
                .iter()
                .any(|marker| normalized.contains(&format!(" {marker} "))))
        || normalized.contains(" what does current evidence state mean ")
        || normalized.contains(" what does evidence state mean ");
    let explicit_time_boundary = [
        "current",
        "currently",
        "right now",
        "today",
        "actually have",
        "actually available",
    ]
    .iter()
    .any(|marker| normalized.contains(&format!(" {marker} ")));
    let named_operational_state = [
        "status",
        "statuses",
        "state",
        "states",
        "evidence",
        "receipt",
        "receipts",
        "access",
        "visibility",
        "field",
        "fields",
        "source",
        "sources",
        "connector",
        "connectors",
        "provider",
        "providers",
        "runtime",
        "runtimes",
        "tool",
        "tools",
        "capability",
        "capabilities",
    ]
    .iter()
    .any(|marker| normalized.contains(&format!(" {marker} ")));
    let explicit_reconciliation = [
        "reconcile",
        "reconciled",
        "reconciling",
        "correct",
        "corrected",
        "correction",
        "re read",
        "reread",
        "recheck",
        "rechecked",
        "verify",
        "verification",
    ]
    .iter()
    .any(|marker| normalized.contains(&format!(" {marker} ")))
        && [
            "field",
            "fields",
            "receipt",
            "receipts",
            "source",
            "sources",
            "connector",
            "connectors",
            "provider",
            "providers",
            "runtime",
            "runtimes",
        ]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} ")));
    let named_access_boundary = (normalized.contains(" visibility ")
        || normalized.contains(" access "))
        && [
            "source",
            "sources",
            "connector",
            "connectors",
            "provider",
            "providers",
            "runtime",
            "runtimes",
        ]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} ")));
    let present_operational_question = ((["what", "which", "whether", "can you", "do we have"]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} "))))
        && [
            "evidence",
            "collection",
            "collections",
            "receipt",
            "receipts",
            "access",
            "visibility",
            "runtime",
            "runtimes",
            "connector",
            "connectors",
            "source",
            "sources",
            "tool",
            "tools",
            "capability",
            "capabilities",
        ]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} ")))
        && [
            "inspect",
            "inspected",
            "read",
            "reads",
            "search",
            "searched",
            "working",
            "missing",
            "enabled",
            "healthy",
            "connected",
            "available",
            "have access",
            "can access",
        ]
        .iter()
        .any(|marker| normalized.contains(&format!(" {marker} "))))
        || (normalized.contains(" collection ")
            && (normalized.contains(" is working ")
                || normalized.contains(" whether collection ")));
    let conceptual_naming = normalized.contains(" codename ")
        || normalized.contains(" as a name ")
        || normalized.contains(" name choice ")
        || normalized.contains(" title ")
        || normalized.contains(" story ")
        || normalized.contains(" novel ")
        || normalized.contains(" analogy ")
        || normalized.contains(" metaphor ");
    let generic_state_request = clause.trim_end().ends_with('?')
        || words.first().is_some_and(|word| {
            matches!(
                *word,
                "are"
                    | "check"
                    | "did"
                    | "explain"
                    | "find"
                    | "give"
                    | "has"
                    | "have"
                    | "is"
                    | "tell"
                    | "what"
                    | "when"
                    | "where"
                    | "which"
                    | "who"
                    | "how"
                    | "why"
            )
        });
    let generic_live_predicate = !conceptual_naming
        && generic_state_request
        && words.iter().enumerate().any(|(predicate_index, word)| {
            if !matches!(
                *word,
                "broken"
                    | "crash"
                    | "crashed"
                    | "degraded"
                    | "down"
                    | "fixed"
                    | "green"
                    | "healthy"
                    | "offline"
                    | "online"
                    | "operational"
                    | "ready"
                    | "reachable"
                    | "resolved"
                    | "responsive"
                    | "restored"
                    | "running"
                    | "stable"
                    | "up"
                    | "unavailable"
                    | "working"
                    | "available"
                    | "landed"
                    | "passed"
                    | "failed"
                    | "completed"
                    | "shipped"
            ) {
                return false;
            }
            let has_subject_bound_verb =
                words[..predicate_index]
                    .iter()
                    .enumerate()
                    .any(|(verb_index, verb)| {
                        if !matches!(*verb, "is" | "are" | "has" | "have" | "did") {
                            return false;
                        }
                        let verb_has_subject_before = verb_index > 0
                            && !matches!(
                                words[verb_index - 1],
                                "why" | "what" | "when" | "where" | "how" | "which"
                            );
                        let verb_has_subject_after = predicate_index > verb_index + 1;
                        verb_has_subject_before || verb_has_subject_after
                    });
            let has_time_boundary = [
                "now",
                "today",
                "yesterday",
                "currently",
                "recently",
                "already",
                "latest",
            ]
            .iter()
            .any(|time| words.contains(time));
            let question_explains_generic_subject = words[..predicate_index]
                .iter()
                .position(|word| matches!(*word, "how" | "when" | "why"))
                .is_some_and(|question_index| {
                    !has_time_boundary
                        && (predicate_index + 1 < words.len()
                            || words[question_index + 1..predicate_index]
                                .iter()
                                .any(|word| matches!(*word, "a" | "an")))
                });
            (has_subject_bound_verb && !question_explains_generic_subject) || has_time_boundary
        });
    let named_current_follow_up = !conceptual_naming
        && generic_state_request
        && (normalized.starts_with(" what about ") || normalized.starts_with(" how about "))
        && ["now", "today", "currently", "recently", "already", "latest"]
            .iter()
            .any(|time| words.contains(time))
        && words
            .iter()
            .position(|word| *word == "about")
            .is_some_and(|about_index| {
                words[about_index + 1..].iter().any(|word| {
                    !matches!(
                        *word,
                        "already" | "currently" | "latest" | "now" | "recently" | "today"
                    )
                })
            });
    let generic_live_ownership = normalized.contains(" who handles ")
        || normalized.contains(" who owns ")
        || normalized.contains(" owns remediation ")
        || normalized.contains(" handles remediation ")
        || normalized.contains(" is owned by ");
    let generic_live_capability = normalized.contains(" are we able to ")
        || normalized.contains(" can we ship ")
        || normalized.contains(" can you execute ");
    let generic_live_read = [
        " after you check ",
        " and check ",
        " then check ",
        " can you check ",
        " please check ",
        " can you inspect ",
        " please inspect ",
        " look up ",
    ]
    .iter()
    .any(|marker| normalized.contains(marker));
    let requires_current = (explicit_time_boundary && named_operational_state)
        || explicit_reconciliation
        || named_access_boundary
        || present_operational_question
        || generic_live_predicate
        || named_current_follow_up
        || generic_live_ownership
        || generic_live_capability
        || generic_live_read;
    if request_is_artifact_transformation(clause) {
        return false;
    }
    if conceptual_explanation
        && !explicit_named_operational_read
        && !explicit_named_current_state
        && !generic_live_predicate
        && !generic_live_ownership
        && !generic_live_capability
        && !generic_live_read
    {
        return false;
    }
    requires_current
}

fn normalized_phrase_text(value: &str) -> String {
    let words = value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    format!(" {} ", words.join(" "))
}

fn request_explicitly_requires_investigation(message: &str) -> bool {
    let normalized = message.to_ascii_lowercase();
    let asks_reconciliation = normalized.contains("reconcile");
    let asks_ownership = normalized.contains("owner") || normalized.contains("who owns");
    let asks_trigger = normalized.contains("trigger") || normalized.contains("next check");
    let asks_closure = normalized.contains("closure") || normalized.contains("closes it");
    asks_reconciliation && asks_ownership && asks_trigger && asks_closure
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
    if !presentation_markup_is_balanced(&summary) {
        return Err(AgentRuntimeError::InvalidFinal(
            "Slack presentation contains an unclosed code fence or emphasis span".into(),
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

fn presentation_markup_is_balanced(value: &str) -> bool {
    let mut in_fence = false;
    for line in value.lines() {
        if line.trim().starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let mut cursor = 0;
        let mut strong_asterisks = 0;
        let mut strong_underscores = 0;
        let mut single_asterisk_open = false;
        let mut single_underscore_open = false;
        while cursor < line.len() {
            let remaining = &line[cursor..];
            let image = remaining.starts_with("![");
            if (image || remaining.starts_with('['))
                && let Some(end) = presentation_markdown_link_end(line, cursor, image)
            {
                cursor = end;
                continue;
            }
            if (image || remaining.starts_with('[')) && remaining.contains("](") {
                return false;
            }
            if remaining.starts_with('[') || remaining.starts_with(']') {
                return false;
            }
            if let Some(end) = presentation_raw_url_end(line, cursor) {
                cursor = end;
                continue;
            }
            if remaining.starts_with('<')
                && remaining[1..]
                    .chars()
                    .next()
                    .is_some_and(|next| matches!(next, '@' | '#' | '!' | 'h' | 'm'))
            {
                let Some(close_offset) = remaining.find('>') else {
                    return false;
                };
                cursor += close_offset + 1;
                continue;
            }
            if remaining.starts_with('`') {
                let delimiter_len = remaining.bytes().take_while(|byte| *byte == b'`').count();
                let delimiter = &remaining[..delimiter_len];
                let content_start = cursor + delimiter_len;
                let Some(close_offset) = line[content_start..].find(delimiter) else {
                    return false;
                };
                cursor = content_start + close_offset + delimiter_len;
                continue;
            }
            if remaining.starts_with("**") {
                strong_asterisks += 1;
                cursor += 2;
                continue;
            }
            if remaining.starts_with("__") {
                strong_underscores += 1;
                cursor += 2;
                continue;
            }
            if remaining.starts_with('*') || remaining.starts_with('_') {
                let delimiter = remaining
                    .chars()
                    .next()
                    .expect("markup cursor remains on a character boundary");
                let open = if delimiter == '*' {
                    &mut single_asterisk_open
                } else {
                    &mut single_underscore_open
                };
                let previous = line[..cursor].chars().next_back();
                let previous_is_word = previous.is_some_and(char::is_alphanumeric);
                let previous_can_close = previous.is_some_and(|value| !value.is_whitespace());
                let next_is_word = remaining[delimiter.len_utf8()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric);
                let clear_intraword_asterisk_close =
                    delimiter == '*' && previous_is_word && next_is_word;
                let next = remaining[delimiter.len_utf8()..].chars().next();
                let previous_nonspace = line[..cursor]
                    .chars()
                    .rev()
                    .find(|value| !value.is_whitespace());
                let next_nonspace = remaining[delimiter.len_utf8()..]
                    .chars()
                    .find(|value| !value.is_whitespace());
                let numeric_infix = delimiter == '*'
                    && previous_nonspace.is_some_and(|value| value.is_ascii_digit())
                    && next_nonspace.is_some_and(|value| value.is_ascii_digit());
                let underscore_infix = delimiter == '_' && previous_is_word && next_is_word;
                if !*open && !previous_is_word && next_is_word {
                    *open = true;
                } else if *open
                    && previous_can_close
                    && (!next_is_word || clear_intraword_asterisk_close)
                {
                    *open = false;
                } else if !*open && !numeric_infix && !underscore_infix {
                    return false;
                }
                cursor += delimiter.len_utf8();
                continue;
            }
            cursor += remaining
                .chars()
                .next()
                .expect("markup cursor remains on a character boundary")
                .len_utf8();
        }
        if strong_asterisks % 2 != 0
            || strong_underscores % 2 != 0
            || single_asterisk_open
            || single_underscore_open
        {
            return false;
        }
    }
    !in_fence
}

fn presentation_raw_url_end(value: &str, start: usize) -> Option<usize> {
    if !value[start..].starts_with("https://") && !value[start..].starts_with("http://") {
        return None;
    }
    Some(
        value[start..]
            .char_indices()
            .find_map(|(offset, character)| {
                (offset > 0 && (character.is_whitespace() || matches!(character, '<' | '>')))
                    .then_some(start + offset)
            })
            .unwrap_or(value.len()),
    )
}

fn presentation_markdown_link_end(value: &str, start: usize, image: bool) -> Option<usize> {
    let open = start + usize::from(image);
    let label_start = open + 1;
    let close = label_start + value[label_start..].find("](")?;
    let url_start = close + 2;
    let mut depth = 0;
    for (offset, character) in value[url_start..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' if depth == 0 => return Some(url_start + offset + 1),
            ')' => depth -= 1,
            _ => {}
        }
    }
    None
}

fn validate_critique_decision(
    turn: &CritiqueTurn,
    decision: &CritiqueDecision,
) -> Result<(), AgentRuntimeError> {
    match decision {
        CritiqueDecision::Approve { checks, grounding }
            if checks.answers_newest_request
                && checks.conversational
                && checks.evidence_boundary_correct
                && checks.no_raw_record_dump
                && checks.operator_facing
                && checks.owns_follow_through
                && checks.right_sized =>
        {
            validate_critique_grounding(turn, grounding)
        }
        CritiqueDecision::Approve { checks, .. } => {
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

fn validate_critique_grounding(
    turn: &CritiqueTurn,
    grounding: &[CritiqueGroundingCheck],
) -> Result<(), AgentRuntimeError> {
    let expected = turn
        .grounding_units
        .iter()
        .map(|unit| unit.unit_id.as_str())
        .collect::<Vec<_>>();
    let supplied = grounding
        .iter()
        .map(|check| check.unit_id.as_str())
        .collect::<Vec<_>>();
    if supplied != expected {
        return Err(AgentRuntimeError::InvalidFinal(
            "critic approval must review every grounding unit exactly once and in order".into(),
        ));
    }
    let units = turn
        .grounding_units
        .iter()
        .map(|unit| (unit.unit_id.as_str(), unit.text.as_str()))
        .collect::<BTreeMap<_, _>>();

    let observed = turn
        .observations
        .iter()
        .flat_map(|observation| {
            observation.result.evidence.iter().map(move |evidence| {
                (
                    evidence.evidence_ref.as_str(),
                    (evidence, &observation.result.data),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    let draft_evidence = final_evidence_refs(&turn.draft)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let requested_assessment_at = parse_timestamp(&turn.request.assessment_at)
        .map_err(|_| AgentRuntimeError::InvalidFinal("assessment time is invalid".into()))?;
    let assessment_at = turn
        .observations
        .iter()
        .flat_map(|observation| &observation.result.evidence)
        .filter_map(|evidence| parse_timestamp(&evidence.observed_at).ok())
        .fold(requested_assessment_at, OffsetDateTime::max);
    let operator_context = turn
        .request
        .history
        .iter()
        .filter(|message| message.role == ConversationRole::User)
        .map(|message| message.content.as_str())
        .chain(std::iter::once(turn.request.message.as_str()))
        .collect::<Vec<_>>()
        .join("\n");
    let retained_context = turn
        .request
        .working_state
        .as_ref()
        .map(|state| {
            let mut parts = vec![state.current_request.as_str()];
            parts.extend(state.last_blocker.as_deref());
            parts.extend(state.open_loops.iter().map(String::as_str));
            parts.join("\n")
        })
        .unwrap_or_default();
    let continuity_context = format!("{operator_context}\n{retained_context}");
    let observation_context = turn
        .observations
        .iter()
        .map(|observation| {
            format!(
                "{} {} {}",
                observation.result.summary,
                observation
                    .result
                    .evidence
                    .iter()
                    .map(|evidence| evidence.statement.as_str())
                    .collect::<Vec<_>>()
                    .join(" "),
                observation.result.data
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    for check in grounding {
        let unit_text = units[check.unit_id.as_str()];
        if matches!(
            check.basis,
            CritiqueGroundingBasis::DirectObservation
                | CritiqueGroundingBasis::BoundedInference
                | CritiqueGroundingBasis::Hypothesis
        ) && check.support.is_empty()
        {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {} requires observed support",
                check.unit_id
            )));
        }
        if check.basis == CritiqueGroundingBasis::OperatorSupplied {
            validate_operator_supplied_unit(unit_text, check, &operator_context)?;
        } else if check.basis == CritiqueGroundingBasis::RetainedContext {
            validate_retained_context_unit(unit_text, check, &retained_context)?;
        } else if check.context_excerpt.is_some() {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {} has a context excerpt on a different basis",
                check.unit_id
            )));
        }
        if check.basis == CritiqueGroundingBasis::ToolOutcome {
            validate_tool_outcome_unit(turn, unit_text, check)?;
        } else if check.observation_sequence.is_some() {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {} has an observation sequence on a different basis",
                check.unit_id
            )));
        }
        if matches!(
            check.basis,
            CritiqueGroundingBasis::OperatorSupplied
                | CritiqueGroundingBasis::RetainedContext
                | CritiqueGroundingBasis::ToolOutcome
                | CritiqueGroundingBasis::StableExplanation
                | CritiqueGroundingBasis::Placeholder
                | CritiqueGroundingBasis::NonFactual
        ) && !check.support.is_empty()
        {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {} uses a basis that cannot cite observations",
                check.unit_id
            )));
        }
        match check.basis {
            CritiqueGroundingBasis::Placeholder if !looks_like_placeholder(unit_text) => {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} is not visibly unresolved",
                    check.unit_id
                )));
            }
            CritiqueGroundingBasis::Recommendation
                if !looks_like_prospective_recommendation(unit_text) =>
            {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} is not visibly prospective advice",
                    check.unit_id
                )));
            }
            CritiqueGroundingBasis::Hypothesis if !looks_like_hypothesis(unit_text) => {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} is not visibly qualified as a hypothesis",
                    check.unit_id
                )));
            }
            CritiqueGroundingBasis::NonFactual if !unit_text.trim_end().ends_with('?') => {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} is not a non-factual question",
                    check.unit_id
                )));
            }
            CritiqueGroundingBasis::StableExplanation
                if turn.lane != ExecutionLane::Converse
                    || !looks_like_stable_explanation(unit_text) =>
            {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} is not a stable non-operational explanation",
                    check.unit_id
                )));
            }
            _ => {}
        }
        validate_material_literals(
            unit_text,
            check.basis,
            &continuity_context,
            &observation_context,
            &check.unit_id,
        )?;

        let mut unique_support = BTreeSet::new();
        for support in &check.support {
            let key = (
                support.evidence_ref.as_str(),
                support.data_pointer.as_deref(),
                support.supporting_text.as_str(),
            );
            if !unique_support.insert(key) || !bounded_text(&support.supporting_text) {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} has invalid or duplicate support",
                    check.unit_id
                )));
            }
            if !draft_evidence.contains(&support.evidence_ref) {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} cites evidence omitted from the final draft",
                    check.unit_id
                )));
            }
            let (evidence, data) =
                observed.get(support.evidence_ref.as_str()).ok_or_else(|| {
                    AgentRuntimeError::EvidenceNotObserved(support.evidence_ref.clone())
                })?;
            if matches!(
                check.basis,
                CritiqueGroundingBasis::DirectObservation
                    | CritiqueGroundingBasis::BoundedInference
            ) && !evidence_is_authoritative(evidence, assessment_at)?
                && !acknowledges_non_authoritative_evidence(unit_text)
            {
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "critic grounding unit {} uses stale or incomplete support without saying so",
                    check.unit_id
                )));
            }
            match support.data_pointer.as_deref() {
                Some(pointer) => {
                    let value = data.pointer(pointer).ok_or_else(|| {
                        AgentRuntimeError::InvalidFinal(format!(
                            "critic grounding pointer {pointer} does not exist for {}",
                            support.evidence_ref
                        ))
                    })?;
                    let scalar = grounding_scalar(value).ok_or_else(|| {
                        AgentRuntimeError::InvalidFinal(format!(
                            "critic grounding pointer {pointer} must select one scalar value"
                        ))
                    })?;
                    if scalar != support.supporting_text {
                        return Err(AgentRuntimeError::InvalidFinal(format!(
                            "critic grounding text does not match the scalar at {pointer}"
                        )));
                    }
                }
                None if !evidence.statement.contains(support.supporting_text.trim()) => {
                    return Err(AgentRuntimeError::InvalidFinal(format!(
                        "critic grounding text is not an exact excerpt of {}",
                        support.evidence_ref
                    )));
                }
                None => {}
            }
        }
    }
    Ok(())
}

fn validate_operator_supplied_unit(
    unit_text: &str,
    check: &CritiqueGroundingCheck,
    operator_context: &str,
) -> Result<(), AgentRuntimeError> {
    check
        .context_excerpt
        .as_deref()
        .filter(|excerpt| bounded_text(excerpt) && operator_context.contains(excerpt))
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {} lacks an exact operator-authored excerpt",
                check.unit_id
            ))
        })?;
    let unit_words = grounding_words(unit_text);
    let excerpt_words = grounding_words(
        check
            .context_excerpt
            .as_deref()
            .expect("validated operator excerpt"),
    );
    let matched = unit_words.intersection(&excerpt_words).count();
    if unit_words.is_empty() || matched == 0 {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "critic grounding unit {} lacks material vocabulary overlap with operator-authored text",
            check.unit_id
        )));
    }
    validate_material_literals(
        unit_text,
        CritiqueGroundingBasis::OperatorSupplied,
        operator_context,
        "",
        &check.unit_id,
    )?;
    Ok(())
}

fn validate_retained_context_unit(
    unit_text: &str,
    check: &CritiqueGroundingCheck,
    retained_context: &str,
) -> Result<(), AgentRuntimeError> {
    let excerpt = check
        .context_excerpt
        .as_deref()
        .filter(|excerpt| bounded_text(excerpt) && retained_context.contains(excerpt))
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {} lacks an exact retained-context excerpt",
                check.unit_id
            ))
        })?;
    require_grounding_vocabulary_overlap(unit_text, excerpt, &check.unit_id)
}

fn validate_tool_outcome_unit(
    turn: &CritiqueTurn,
    unit_text: &str,
    check: &CritiqueGroundingCheck,
) -> Result<(), AgentRuntimeError> {
    let sequence = check.observation_sequence.ok_or_else(|| {
        AgentRuntimeError::InvalidFinal(format!(
            "critic grounding unit {} lacks an exact failed observation sequence",
            check.unit_id
        ))
    })?;
    let observation = turn
        .observations
        .iter()
        .find(|observation| observation.sequence == sequence)
        .filter(|observation| observation.result.state != ToolResultState::Succeeded)
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {} does not reference a failed or incomplete observation",
                check.unit_id
            ))
        })?;
    let outcome_context = format!(
        "{} {} {}",
        observation.result.summary,
        observation.result.blocker.as_deref().unwrap_or_default(),
        observation.result.data
    );
    require_grounding_vocabulary_overlap(unit_text, &outcome_context, &check.unit_id)
}

fn require_grounding_vocabulary_overlap(
    unit_text: &str,
    source_text: &str,
    unit_id: &str,
) -> Result<(), AgentRuntimeError> {
    let unit_words = grounding_words(unit_text);
    let source_words = grounding_words(source_text);
    if unit_words.is_empty() || unit_words.intersection(&source_words).next().is_none() {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "critic grounding unit {unit_id} lacks material vocabulary overlap with its source"
        )));
    }
    Ok(())
}

fn looks_like_placeholder(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    let bracketed_label = [('<', '>'), ('[', ']')].into_iter().any(|(open, close)| {
        value.find(open).is_some_and(|start| {
            value[start + 1..].find(close).is_some_and(|relative_end| {
                let end = start + 1 + relative_end;
                let prefix = value[..start].trim();
                let suffix = value[end + 1..].trim();
                (prefix.is_empty() || prefix.ends_with(':'))
                    && suffix.chars().all(|character| {
                        character.is_ascii_punctuation() || character.is_whitespace()
                    })
            })
        })
    });
    bracketed_label
        || [
            "tbd",
            "unknown",
            "unresolved",
            "not returned",
            "not supplied",
            "placeholder",
        ]
        .into_iter()
        .any(|marker| normalized.contains(marker))
}

fn looks_like_prospective_recommendation(value: &str) -> bool {
    let normalized = value
        .trim_start_matches(|character: char| !character.is_alphanumeric())
        .to_ascii_lowercase();
    [
        "i recommend",
        "we should",
        "you should",
        "the next step",
        "next,",
        "needs to",
        "need to",
        "must ",
        "do not ",
        "don't ",
        "ask ",
        "attach ",
        "capture ",
        "check ",
        "compare ",
        "confirm ",
        "escalate ",
        "hold ",
        "keep ",
        "provide ",
        "request ",
        "reset ",
        "resume ",
        "retry ",
        "route ",
        "run ",
        "use ",
        "wait ",
    ]
    .into_iter()
    .any(|marker| normalized.starts_with(marker) || normalized.contains(marker))
}

fn looks_like_hypothesis(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        " may ",
        " might ",
        " could ",
        "possibly",
        "consistent with",
        "one possibility",
        "cannot distinguish",
        "can't distinguish",
    ]
    .into_iter()
    .any(|marker| format!(" {normalized} ").contains(marker))
}

fn looks_like_stable_explanation(value: &str) -> bool {
    let normalized = format!(" {} ", value.to_ascii_lowercase());
    ![
        " currently ",
        " today ",
        " now ",
        " latest ",
        " observed ",
        " returned ",
        " enabled ",
        " connected ",
        " healthy ",
        " degraded ",
        " failed ",
        " missing ",
        " attempted ",
        " completed ",
        " succeeded ",
        " changed ",
        " restored ",
        " ready ",
        " blocked ",
        " closed ",
        " owner ",
        " team ",
        " admin ",
        " administrator ",
        " role ",
        " executor ",
        " trigger ",
    ]
    .into_iter()
    .any(|marker| normalized.contains(marker))
        && !value.chars().any(|character| character.is_ascii_digit())
}

fn grounding_words(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .map(str::to_ascii_lowercase)
        .filter(|word| word.chars().count() >= 3)
        .filter(|word| {
            ![
                "and", "are", "but", "for", "from", "has", "have", "that", "the", "this", "was",
                "were", "with", "you", "your", "after", "before", "into",
            ]
            .contains(&word.as_str())
        })
        .map(|word| match word.as_str() {
            "our" | "ours" | "we" | "cerebro" => "cerebro".into(),
            "owner" | "owns" | "owned" | "ownership" | "responsibility" => "own".into(),
            "checked" | "checks" | "recheck" => "check".into(),
            _ => word,
        })
        .collect()
}

fn acknowledges_non_authoritative_evidence(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "stale",
        "incomplete",
        "partial",
        "missing",
        "not observed",
        "not returned",
        "unavailable",
        "unknown",
        "gap",
    ]
    .into_iter()
    .any(|marker| normalized.contains(marker))
}

fn validate_material_literals(
    unit_text: &str,
    basis: CritiqueGroundingBasis,
    operator_context: &str,
    observation_context: &str,
    unit_id: &str,
) -> Result<(), AgentRuntimeError> {
    let authority_context =
        format!("{operator_context}\n{observation_context}").to_ascii_lowercase();
    let material_text = if basis == CritiqueGroundingBasis::Placeholder {
        remove_bracketed_placeholders(unit_text)
    } else {
        unit_text.to_owned()
    };
    let normalized_unit = material_text.to_ascii_lowercase();
    for marker in [
        "all safe reads",
        "everything else is normal",
        "exact parameters",
        "guarantees that",
        "no fallback",
        "only cause",
        "proves that",
        "rule out",
        "rules out",
        "staged parameters",
        "will restore",
        "will return",
    ] {
        if normalized_unit.contains(marker) && !authority_context.contains(marker) {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {unit_id} introduces unsupported operational claim {marker}"
            )));
        }
    }
    if basis == CritiqueGroundingBasis::Recommendation
        && normalized_unit.contains(" will ")
        && !authority_context.contains(" will ")
    {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "critic grounding unit {unit_id} turns a recommendation into an unsupported future guarantee"
        )));
    }
    let sensitive = [
        "admin",
        "administrator",
        "escalation",
        "executor",
        "fallback",
        "grant",
        "oncall",
        "owner",
        "registry",
        "role",
        "scope",
        "team",
        "timestamp",
        "trigger",
    ];
    for word in material_text
        .split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
    {
        let normalized = word.to_ascii_lowercase();
        let exact_literal = word.chars().any(|character| character.is_ascii_digit());
        let sensitive_literal = sensitive.contains(&normalized.as_str());
        let placeholder_label = basis == CritiqueGroundingBasis::Placeholder
            && normalized_unit
                .trim_start()
                .starts_with(&format!("{normalized}:"));
        if (sensitive_literal || exact_literal)
            && !placeholder_label
            && !authority_context
                .split(|character: char| !character.is_alphanumeric())
                .any(|candidate| candidate == normalized)
        {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "critic grounding unit {unit_id} introduces unsupported operational literal {word}"
            )));
        }
    }
    Ok(())
}

fn remove_bracketed_placeholders(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    let mut closing = None;
    for character in value.chars() {
        match (closing, character) {
            (None, '<') => closing = Some('>'),
            (None, '[') => closing = Some(']'),
            (Some(expected), actual) if expected == actual => closing = None,
            (None, _) => result.push(character),
            (Some(_), _) => result.push(' '),
        }
    }
    result
}

fn grounding_scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Null => Some("null".into()),
        Value::Array(_) | Value::Object(_) => None,
    }
}

pub fn validate_agent_turn_request(request: &AgentTurnRequest) -> Result<(), AgentRuntimeError> {
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
    if (!request.history_metadata.is_empty()
        && request.history_metadata.len() != request.history.len())
        || request.history_metadata.iter().any(|metadata| {
            metadata
                .actor_ref
                .as_ref()
                .is_some_and(|value| !bounded_text(value))
                || metadata.message_ref.as_ref().is_some_and(|value| {
                    !bounded_text(value)
                        || value.starts_with("operator:")
                        || value.starts_with("assistant:")
                })
                || metadata
                    .received_at
                    .as_ref()
                    .is_some_and(|value| !bounded_text(value) || parse_timestamp(value).is_err())
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
    resumed_mission: bool,
    draft: &FinalDraft,
    observations: &[ToolObservation],
) -> Result<(), AgentRuntimeError> {
    if !bounded_display_text(&draft.headline, MAX_HEADLINE_BYTES)
        || draft.headline.contains('\n')
        || draft.headline.contains('\r')
    {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "headline must be one non-empty line no longer than {MAX_HEADLINE_BYTES} bytes; the prior headline was {} bytes",
            draft.headline.len()
        )));
    }
    if draft.summary.trim().is_empty()
        || draft.summary.len() > MAX_SUMMARY_BYTES
        || draft
            .summary
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "summary must be non-empty, conversational text no longer than {MAX_SUMMARY_BYTES} bytes; the prior summary was {} bytes. Rewrite it materially shorter instead of repeating the same draft",
            draft.summary.len()
        )));
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
    if critique_grounding_units(draft).len() > MAX_GROUNDING_UNITS {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "visible reply exceeds the {MAX_GROUNDING_UNITS}-unit grounding limit; combine fragments into complete sentences"
        )));
    }
    if resumed_mission && repeats_recent_assistant_reply(&render_final(draft), &request.history) {
        return Err(AgentRuntimeError::InvalidFinal(
            "the continuation substantially repeats a recent assistant reply. Advance the work: produce the next useful artifact, consolidate the blocker into a handoff, answer a newly resolved point, or state the exact new fact that changed. Do not echo the prior refusal or question"
                .into(),
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

fn repeats_recent_assistant_reply(candidate: &str, history: &[ConversationMessage]) -> bool {
    let candidate_words = significant_words(candidate);
    if candidate_words.len() < 6 {
        return false;
    }
    history
        .iter()
        .rev()
        .filter(|message| message.role == ConversationRole::Assistant)
        .take(3)
        .any(|message| {
            let prior_words = significant_words(&message.content);
            if prior_words.len() < 6 {
                return false;
            }
            let shared = candidate_words.intersection(&prior_words).count();
            let smaller = candidate_words.len().min(prior_words.len());
            let larger = candidate_words.len().max(prior_words.len());
            shared * 100 >= smaller * 82 && shared * 100 >= larger * 65
        })
}

fn significant_words(text: &str) -> BTreeSet<String> {
    const STOP_WORDS: [&str; 14] = [
        "and", "are", "but", "for", "from", "has", "have", "that", "the", "this", "was", "were",
        "with", "you",
    ];
    text.split(|character: char| !character.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|word| word.chars().count() >= 3 && !STOP_WORDS.contains(&word.as_str()))
        .collect()
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

fn critique_grounding_units(draft: &FinalDraft) -> Vec<CritiqueGroundingUnit> {
    let rendered = render_final(draft);
    let mut texts = Vec::new();
    for line in rendered
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let mut start = 0;
        for (index, character) in line.char_indices() {
            let end = index + character.len_utf8();
            let boundary = character == ';'
                || (matches!(character, '.' | '!' | '?')
                    && line[end..].chars().next().is_none_or(char::is_whitespace));
            if boundary {
                let unit = line[start..end].trim();
                if !unit.is_empty() {
                    texts.push(unit.to_owned());
                }
                start = end;
            }
        }
        let remainder = line[start..].trim();
        if !remainder.is_empty() {
            texts.push(remainder.to_owned());
        }
    }
    let mut units = texts
        .into_iter()
        .enumerate()
        .map(|(index, text)| CritiqueGroundingUnit {
            unit_id: format!("visible-{:02}", index + 1),
            text,
        })
        .collect::<Vec<_>>();
    units.extend(draft.next_actions.iter().enumerate().map(|(index, text)| {
        CritiqueGroundingUnit {
            unit_id: format!("open-loop-{:02}", index + 1),
            text: text.clone(),
        }
    }));
    units
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

#[cfg(test)]
mod grounding_tests {
    use super::*;
    use serde_json::json;

    fn route_request(message: &str) -> AgentTurnRequest {
        AgentTurnRequest {
            schema_version: "agent-turn/v1".into(),
            tenant_id: "tenant:synthetic".into(),
            request_id: "request:route".into(),
            thread_ref: "thread:synthetic".into(),
            context_scope_ref: None,
            actor_ref: "operator:synthetic".into(),
            assessment_at: "2026-07-31T00:00:00Z".into(),
            message: message.into(),
            history: Vec::new(),
            history_metadata: Vec::new(),
            working_state: None,
            effect_authorizations: Vec::new(),
        }
    }

    #[test]
    fn explicit_current_field_reconciliation_cannot_route_to_conversation() {
        for message in [
            "Reconcile that provider field with a current Source A receipt.",
            "What visibility or access do we actually have for Source A?",
        ] {
            let decision = RouteDecision {
                lane: ExecutionLane::Converse,
                confidence: RouteConfidence::High,
                reason: "This is only explanatory.".into(),
                requires_current_evidence: false,
            };
            assert!(validate_route(&route_request(message), &decision).is_err());
        }

        assert!(!request_explicitly_requires_current_evidence(
            "What does evidence freshness mean in a control program?"
        ));
        assert!(!request_explicitly_requires_current_evidence(
            "What is a provider?"
        ));
        assert!(request_explicitly_requires_current_evidence(
            "What Lantern Vale evidence can you actually inspect, whether collection is working, and what is missing?"
        ));
        for conversational_message in [
            "I don't have access to that resource.",
            "That's incorrect, the provider is fine.",
            "What tools have we already covered in this thread?",
            "Please read the statement correctly before replying.",
            "What is the current state of provider-neutral architecture?",
            "Explain the current provider-neutral capability model.",
            "What does current evidence state mean in a provider-neutral system?",
            "What is the current state of the art for evidence theory?",
            "What is the current state of provider-neutral source architecture?",
            "Explain why healthy evidence is not necessarily verified evidence.",
            "Rewrite ‘Atlas has landed’ more concisely.",
            "Draft a response saying the rollout is ready.",
            "Why is Atlas Green a good codename?",
            "Why is green a calming color?",
            "Why is healthy conflict a useful concept?",
            "Why is a healthy debate useful?",
            "Why is the color green calming?",
            "Explain why a debate is healthy.",
            "Explain how a debate is healthy.",
            "Tell me when a debate is healthy.",
            "Why did Atlas fail in this story?",
            "Why is Atlas operational in the novel?",
            "Why is the system healthy in this analogy?",
            "Why is “Atlas Now” a good title?",
            "Break down this idea for me.",
            "Why is feeling down hard?",
            "What should I think about now?",
        ] {
            assert!(
                !request_explicitly_requires_current_evidence(conversational_message),
                "ordinary conversation was misclassified: {conversational_message}"
            );
        }
        for current_evidence_request in [
            "What is the current state of Source A?",
            "Which provider receipts are currently missing?",
            "Can you inspect the current provider runtime?",
            "What does the current Source A state mean for today's decision?",
            "Using the provider-neutral architecture, inspect Source A's current receipt.",
            "What is the state of the art, and is Provider B currently healthy?",
            "Within the provider-neutral architecture inspect Source A's current receipt.",
            "Explain provider-neutral architecture but inspect Source A's current receipt.",
            "In the state of the art model, what is Source A's current receipt?",
            "Is Atlas green?",
            "Is Atlas online?",
            "Is Atlas operational?",
            "Is Atlas down?",
            "Is Atlas offline?",
            "Is Atlas degraded?",
            "Is Atlas broken?",
            "Is Atlas up?",
            "What about Atlas now?",
            "what about atlas now?",
            "Is Atlas fixed?",
            "Is Atlas restored?",
            "Is Atlas resolved?",
            "Is Atlas running?",
            "Is Atlas reachable?",
            "Is Atlas responsive?",
            "Is Atlas stable?",
            "Is Atlas unavailable?",
            "Did Atlas crash? Give me your take.",
            "Is Story Service operational?",
            "Has the rollout landed?",
            "Who handles remediation for Atlas?",
            "Are we able to ship this?",
            "Explain provider-neutral architecture, and is Atlas green?",
            "Draft a status after you check Atlas.",
        ] {
            assert!(
                request_explicitly_requires_current_evidence(current_evidence_request),
                "current evidence request was misclassified: {current_evidence_request}"
            );
        }

        let synthesis = route_request(
            "Reconcile Source A's current receipt, identify who owns the gap, state the next check trigger, and tell me what closes it.",
        );
        let lookup = RouteDecision {
            lane: ExecutionLane::Lookup,
            confidence: RouteConfidence::High,
            reason: "One current source record should answer this.".into(),
            requires_current_evidence: true,
        };
        assert!(validate_route(&synthesis, &lookup).is_err());

        let mut continuation = synthesis.clone();
        continuation.working_state = Some(WorkingState {
            mission_ref: Some("mission:synthetic".into()),
            current_request: synthesis.message.clone(),
            last_outcome: WorkingOutcome::Owned,
            last_blocker: None,
            active_lane: Some(ExecutionLane::Investigate),
            requires_current_evidence: Some(true),
            open_loops: vec!["Reconcile the current state.".into()],
        });
        let continue_route = RouteDecision {
            lane: ExecutionLane::Continue,
            confidence: RouteConfidence::High,
            reason: "Resume the exact durable investigation.".into(),
            requires_current_evidence: true,
        };
        assert!(validate_route(&continuation, &continue_route).is_ok());

        let ignored = RouteDecision {
            lane: ExecutionLane::Ignore,
            confidence: RouteConfidence::High,
            reason: "Ignore transport metadata.".into(),
            requires_current_evidence: false,
        };
        assert!(matches!(
            validate_route(&synthesis, &ignored),
            Err(AgentRuntimeError::InvalidRoute(reason))
                if reason.contains("transport events")
        ));
    }

    #[test]
    fn slack_presentation_rejects_unbalanced_fences_and_emphasis() {
        for message in [
            "The result is:\n```\nhealthy",
            "The source is **healthy.",
            "The source is __healthy.",
            "The source is *healthy.",
            "The source is _healthy.",
            "The source is healthy*.",
            "The source is healthy_.",
            "Read [the source](unfinished before answering.",
            "Ask <@U123 for the source.",
            "The source] is healthy.",
            "The source is `healthy.",
        ] {
            assert!(
                validate_presentation(&PresentationDecision {
                    messages: vec![message.into()],
                })
                .is_err(),
                "unbalanced Slack markup was accepted: {message}"
            );
        }
        for message in [
            "snake_case remains readable.",
            "The ratio is 2*3.",
            "To explain multiplication: 2 * 3 = 6.",
        ] {
            assert!(
                validate_presentation(&PresentationDecision {
                    messages: vec![message.into()],
                })
                .is_ok(),
                "literal infix punctuation was misclassified: {message}"
            );
        }
        assert!(
            validate_presentation(&PresentationDecision {
                messages: vec![
                    "The source is **healthy**.\n\n```text\nreceipt complete\n```".into(),
                ],
            })
            .is_ok()
        );
        for message in [
            "See https://example.com/run__alpha__latest for the receipt.",
            "See https://example.com/run__alpha for the receipt.",
            "See [the run](https://example.com/run__alpha__(latest)) for the receipt.",
        ] {
            assert!(
                validate_presentation(&PresentationDecision {
                    messages: vec![message.into()],
                })
                .is_ok(),
                "URL text was misclassified as emphasis: {message}"
            );
        }
    }

    #[test]
    fn approval_preview_shows_targets_and_redacts_credentials() {
        let preview = approval_input_preview(&json!({
            "channel_id": "channel-one",
            "text": "send this",
            "apiKey": "must-not-leak",
            "access_key": "also-secret",
            "nested": {"bearer": "third-secret"},
            "target_key": "target-one"
        }));

        assert!(preview.contains("channel-one"));
        assert!(preview.contains("send this"));
        assert!(!preview.contains("must-not-leak"));
        assert!(!preview.contains("also-secret"));
        assert!(!preview.contains("third-secret"));
        assert!(preview.contains("target-one"));
        assert_eq!(preview.matches("<redacted>").count(), 3);
    }

    #[test]
    fn investigate_budget_allows_bounded_recovery_after_bad_reads() {
        assert_eq!(ExecutionLane::Investigate.budget().max_tool_calls, 14);
        assert_eq!(
            ExecutionLane::Investigate
                .budget()
                .max_selected_capabilities,
            14
        );
        assert_eq!(ExecutionLane::Investigate.budget().max_tool_calls, 14);
    }

    #[test]
    fn runtime_errors_keep_specific_operator_diagnostics() {
        let cases = vec![
            (
                AgentRuntimeError::DuplicateCallId,
                "repeated a tool call identity",
            ),
            (
                AgentRuntimeError::EvidenceNotObserved("evidence:missing".into()),
                "unobserved evidence evidence:missing",
            ),
            (
                AgentRuntimeError::EvidenceNotAuthoritative("evidence:stale".into()),
                "stale or incomplete evidence as authoritative: evidence:stale",
            ),
            (AgentRuntimeError::HistoryInvalid, "history is invalid"),
            (
                AgentRuntimeError::InvalidFinal("missing claim".into()),
                "final answer is invalid: missing claim",
            ),
            (
                AgentRuntimeError::InvalidRequest("missing actor".into()),
                "turn request is invalid: missing actor",
            ),
            (
                AgentRuntimeError::InvalidRoute("unknown lane".into()),
                "semantic route is invalid: unknown lane",
            ),
            (
                AgentRuntimeError::InvalidToolCall("unknown input".into()),
                "tool call is invalid: unknown input",
            ),
            (
                AgentRuntimeError::ModelUnavailable("dispatch failed".into()),
                "agent model is unavailable: dispatch failed",
            ),
            (AgentRuntimeError::ModelStepLimit, "turn step limit"),
            (
                AgentRuntimeError::OperatingRepairLimit,
                "operating decision repair loop",
            ),
            (
                AgentRuntimeError::PresentationRepairLimit,
                "presentation repair loop",
            ),
            (AgentRuntimeError::CriticRepairLimit, "critic repair loop"),
            (AgentRuntimeError::ToolBudgetExceeded, "tool budget"),
            (
                AgentRuntimeError::ToolUnavailable("connector.read".into()),
                "tool connector.read is unavailable",
            ),
            (
                AgentRuntimeError::UnverifiedEffect,
                "later independent verification",
            ),
        ];
        for (error, expected) in cases {
            assert!(error.to_string().contains(expected), "{error:?}");
        }
    }

    fn passing_checks() -> CritiqueChecks {
        CritiqueChecks {
            answers_newest_request: true,
            conversational: true,
            evidence_boundary_correct: true,
            no_raw_record_dump: true,
            operator_facing: true,
            owns_follow_through: true,
            right_sized: true,
        }
    }

    fn sample_turn() -> CritiqueTurn {
        let draft = FinalDraft {
            state: FinalState::Answered,
            headline: "Current owner mapping".into(),
            summary: "An owner mapping exists.".into(),
            summary_evidence_refs: vec!["evidence://owner".into()],
            checked: vec![],
            changed: vec![],
            verified: vec![],
            current_state: vec![],
            next_actions: vec![],
            coverage_notice: None,
            question: None,
        };
        CritiqueTurn {
            request: AgentTurnRequest {
                schema_version: AGENT_TURN_REQUEST_V1.into(),
                tenant_id: "tenant".into(),
                request_id: "request".into(),
                thread_ref: "thread".into(),
                context_scope_ref: None,
                actor_ref: "actor".into(),
                assessment_at: "2026-07-31T12:00:00Z".into(),
                message: "Who owns it?".into(),
                history: vec![],
                history_metadata: vec![],
                working_state: None,
                effect_authorizations: vec![],
            },
            lane: ExecutionLane::Lookup,
            grounding_units: critique_grounding_units(&draft),
            draft,
            observations: vec![ToolObservation {
                sequence: 1,
                call: ToolCall {
                    call_id: "owner-read".into(),
                    tool_id: "owner_status".into(),
                    purpose: "Read the owner mapping status.".into(),
                    input: json!({}),
                },
                descriptor: ToolDescriptor {
                    tool_id: "owner_status".into(),
                    title: "Owner status".into(),
                    summary: "Reads the owner mapping status.".into(),
                    authority_class: ToolAuthorityClass::Observe,
                    effect_class: ToolEffectClass::Read,
                    input_schema_ref: "schema://owner-input".into(),
                    result_schema_ref: "schema://owner-result".into(),
                },
                result: ToolResult {
                    state: ToolResultState::Succeeded,
                    summary: "Owner mapping status returned.".into(),
                    data: json!({"owner_present": true}),
                    evidence: vec![EvidenceRecord {
                        evidence_ref: "evidence://owner".into(),
                        statement: "An owner mapping exists.".into(),
                        observed_at: "2026-07-31T11:59:00Z".into(),
                        fresh_until: Some("2026-07-31T12:05:00Z".into()),
                        complete: true,
                        atoms: Vec::new(),
                    }],
                    blocker: None,
                },
            }],
            repair_feedback: vec![],
        }
    }

    fn valid_grounding(turn: &CritiqueTurn) -> Vec<CritiqueGroundingCheck> {
        vec![CritiqueGroundingCheck {
            unit_id: turn.grounding_units[0].unit_id.clone(),
            basis: CritiqueGroundingBasis::DirectObservation,
            support: vec![CritiqueGroundingSupport {
                evidence_ref: "evidence://owner".into(),
                data_pointer: Some("/owner_present".into()),
                supporting_text: "true".into(),
            }],
            context_excerpt: None,
            observation_sequence: None,
        }]
    }

    #[test]
    fn accepts_complete_exact_scalar_grounding() {
        let turn = sample_turn();
        let decision = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding: valid_grounding(&turn),
        };
        assert_eq!(validate_critique_decision(&turn, &decision), Ok(()));
    }

    #[test]
    fn rejects_missing_duplicate_and_unknown_grounding_units() {
        let turn = sample_turn();
        for grounding in [
            vec![],
            vec![
                valid_grounding(&turn)[0].clone(),
                valid_grounding(&turn)[0].clone(),
            ],
            vec![CritiqueGroundingCheck {
                unit_id: "unit-99".into(),
                ..valid_grounding(&turn)[0].clone()
            }],
        ] {
            let decision = CritiqueDecision::Approve {
                checks: passing_checks(),
                grounding,
            };
            assert!(matches!(
                validate_critique_decision(&turn, &decision),
                Err(AgentRuntimeError::InvalidFinal(_))
            ));
        }
    }

    #[test]
    fn rejects_unobserved_refs_and_nonexistent_or_mismatched_pointers() {
        let turn = sample_turn();
        let variants = [
            CritiqueGroundingSupport {
                evidence_ref: "evidence://invented".into(),
                data_pointer: Some("/owner_present".into()),
                supporting_text: "true".into(),
            },
            CritiqueGroundingSupport {
                evidence_ref: "evidence://owner".into(),
                data_pointer: Some("/owner_identity".into()),
                supporting_text: "admin".into(),
            },
            CritiqueGroundingSupport {
                evidence_ref: "evidence://owner".into(),
                data_pointer: Some("/owner_present".into()),
                supporting_text: "admin".into(),
            },
        ];
        for support in variants {
            let decision = CritiqueDecision::Approve {
                checks: passing_checks(),
                grounding: vec![CritiqueGroundingCheck {
                    unit_id: turn.grounding_units[0].unit_id.clone(),
                    basis: CritiqueGroundingBasis::DirectObservation,
                    support: vec![support],
                    context_excerpt: None,
                    observation_sequence: None,
                }],
            };
            assert!(validate_critique_decision(&turn, &decision).is_err());
        }
    }

    #[test]
    fn rejects_support_omitted_from_the_final_draft_evidence_set() {
        let mut turn = sample_turn();
        turn.draft.summary_evidence_refs.clear();
        let decision = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding: valid_grounding(&turn),
        };
        assert!(validate_critique_decision(&turn, &decision).is_err());
    }

    #[test]
    fn rejects_observation_support_on_non_evidentiary_bases() {
        let turn = sample_turn();
        for basis in [
            CritiqueGroundingBasis::OperatorSupplied,
            CritiqueGroundingBasis::RetainedContext,
            CritiqueGroundingBasis::ToolOutcome,
            CritiqueGroundingBasis::Placeholder,
            CritiqueGroundingBasis::NonFactual,
        ] {
            let mut grounding = valid_grounding(&turn);
            grounding[0].basis = basis;
            let decision = CritiqueDecision::Approve {
                checks: passing_checks(),
                grounding,
            };
            assert!(validate_critique_decision(&turn, &decision).is_err());
        }
    }

    #[test]
    fn rejects_unchecked_non_evidentiary_basis_labels() {
        let cases = [
            CritiqueGroundingBasis::OperatorSupplied,
            CritiqueGroundingBasis::Recommendation,
            CritiqueGroundingBasis::StableExplanation,
            CritiqueGroundingBasis::Placeholder,
            CritiqueGroundingBasis::Hypothesis,
            CritiqueGroundingBasis::NonFactual,
        ];
        for basis in cases {
            let mut turn = sample_turn();
            turn.observations.clear();
            turn.draft.summary_evidence_refs.clear();
            let decision = CritiqueDecision::Approve {
                checks: passing_checks(),
                grounding: vec![CritiqueGroundingCheck {
                    unit_id: turn.grounding_units[0].unit_id.clone(),
                    basis,
                    support: vec![],
                    context_excerpt: None,
                    observation_sequence: None,
                }],
            };
            assert!(validate_critique_decision(&turn, &decision).is_err());
        }
    }

    #[test]
    fn rejects_unqualified_use_of_stale_or_incomplete_claim_support() {
        let mut turn = sample_turn();
        turn.observations[0].result.evidence[0].complete = false;
        let decision = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding: valid_grounding(&turn),
        };
        assert!(validate_critique_decision(&turn, &decision).is_err());

        turn.draft.summary = "The owner mapping evidence is incomplete.".into();
        turn.grounding_units = critique_grounding_units(&turn.draft);
        let qualified = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding: valid_grounding(&turn),
        };
        assert!(validate_critique_decision(&turn, &qualified).is_ok());
    }

    #[test]
    fn rejects_reordered_grounding_and_too_many_units_before_critique() {
        let mut turn = sample_turn();
        turn.draft.summary = "An owner mapping exists. Its status was returned.".into();
        turn.grounding_units = critique_grounding_units(&turn.draft);
        let first = CritiqueGroundingCheck {
            unit_id: turn.grounding_units[0].unit_id.clone(),
            ..valid_grounding(&turn)[0].clone()
        };
        let second = CritiqueGroundingCheck {
            unit_id: turn.grounding_units[1].unit_id.clone(),
            ..valid_grounding(&turn)[0].clone()
        };
        let decision = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding: vec![second, first],
        };
        assert!(validate_critique_decision(&turn, &decision).is_err());

        let mut oversized = sample_turn();
        oversized.draft.summary = (0..=MAX_GROUNDING_UNITS)
            .map(|index| format!("Sentence {index}."))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(matches!(
            validate_final(
                &oversized.request,
                ExecutionLane::Lookup,
                false,
                &oversized.draft,
                &oversized.observations,
            ),
            Err(AgentRuntimeError::InvalidFinal(reason)) if reason.contains("grounding limit")
        ));
    }

    #[test]
    fn stable_explanations_are_converse_only_and_cannot_hide_dynamic_claims() {
        let mut turn = sample_turn();
        turn.lane = ExecutionLane::Converse;
        turn.observations.clear();
        turn.draft.summary_evidence_refs.clear();
        turn.draft.summary = "Evidence freshness is the observation reuse window.".into();
        turn.grounding_units = critique_grounding_units(&turn.draft);
        let valid = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding: vec![CritiqueGroundingCheck {
                unit_id: turn.grounding_units[0].unit_id.clone(),
                basis: CritiqueGroundingBasis::StableExplanation,
                support: vec![],
                context_excerpt: None,
                observation_sequence: None,
            }],
        };
        assert!(validate_critique_decision(&turn, &valid).is_ok());

        turn.grounding_units[0].text = "The connector is currently healthy.".into();
        assert!(validate_critique_decision(&turn, &valid).is_err());
    }

    #[test]
    fn rejects_mixed_placeholder_bypasses_and_invented_inference_numbers() {
        let mut turn = sample_turn();
        turn.grounding_units[0].text =
            "READY: yes | platform team owns dispatch | executor: <unknown>".into();
        let placeholder = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding: vec![CritiqueGroundingCheck {
                unit_id: turn.grounding_units[0].unit_id.clone(),
                basis: CritiqueGroundingBasis::Placeholder,
                support: vec![],
                context_excerpt: None,
                observation_sequence: None,
            }],
        };
        assert!(validate_critique_decision(&turn, &placeholder).is_err());

        turn.grounding_units[0].text = "There are 999 owner mappings.".into();
        let mut grounding = valid_grounding(&turn);
        grounding[0].basis = CritiqueGroundingBasis::BoundedInference;
        let numeric = CritiqueDecision::Approve {
            checks: passing_checks(),
            grounding,
        };
        assert!(validate_critique_decision(&turn, &numeric).is_err());
    }
}
