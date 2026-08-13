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
    AgentRuntimeError, ApprovalRequest, EffectAuthorization, EvidenceRecord, ExecutionLane,
    FinalState, FutureObservationDisposition, ToolAuthorityClass, ToolCall, ToolDescriptor,
    ToolEffectClass, ToolObservation, ToolResult, ToolResultState,
};

/// Schema discriminator for a persisted [`AgentSession`].
pub const AGENT_SESSION_V2: &str = "agent-session/v2";
/// Schema discriminator for an append-only [`SessionEventRecord`].
pub const AGENT_SESSION_EVENT_V2: &str = "agent-session-event/v2";
/// Schema discriminator for structured evidence supplied by an authoritative tool.
pub const AGENT_SEMANTIC_EVIDENCE_V1: &str = "agent-semantic-evidence/v1";
/// Maximum number of durable memories retained in a session snapshot.
pub const MAX_SESSION_MEMORIES: usize = 128;

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
const MAX_CONVERSATIONAL_SYNTHESIS_BYTES: usize = 1_200;
const MAX_CONVERSATIONAL_SYNTHESIS_SOURCES: usize = 8;
const MAX_RECALLED_OBSERVATIONS: usize = 96;
const MAX_SEMANTIC_ASSERTIONS: usize = 64;
const MAX_SEMANTIC_CANDIDATES: usize = 16;
const MAX_SEMANTIC_PRINCIPALS: usize = 16;
const MAX_SEMANTIC_RESULT_COUNT: u32 = 1_000_000;
const MAX_SEMANTIC_SEARCH_LIMIT: u32 = 10_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Lifecycle state of the session's mission as a whole.
pub enum SessionStatus {
    /// Work can continue without a new prerequisite.
    Active,
    /// Progress requires new information or a decision from the operator.
    WaitingForUser,
    /// Progress depends on a system, person, or scheduled observation outside Cerebro.
    WaitingForExternal,
    /// Every accepted mission criterion has been satisfied or explicitly closed.
    Completed,
    /// A known impediment prevents progress and no safe next action is available.
    Blocked,
    /// The operator or owning workflow intentionally ended the mission.
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Lifecycle state of one durable commitment.
pub enum CommitmentStatus {
    /// The commitment is accepted but execution has not begun.
    Planned,
    /// Cerebro is actively working on the commitment.
    InProgress,
    /// A recorded prerequisite or future observation must arrive before proceeding.
    Waiting,
    /// The commitment's acceptance criteria have been verified.
    Completed,
    /// A recorded impediment prevents the next action.
    Blocked,
    /// The commitment was intentionally withdrawn.
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Party responsible for advancing a commitment or open loop.
pub enum WorkOwner {
    /// Cerebro owns the next action and must preserve follow-through.
    Cerebro,
    /// The operator owns the next action or decision.
    User,
    /// A named external actor or system owns the next action.
    External,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Durable statement of the session's objective, scope, obligations, and open work.
pub struct MissionState {
    /// Stable identifier used to correlate mission revisions and events.
    pub mission_ref: String,
    /// Concrete task Cerebro is currently responsible for performing.
    pub objective: String,
    /// Observable end state that distinguishes success from activity.
    pub desired_outcome: String,
    /// Entities, systems, repositories, or time windows included in the mission.
    pub resolved_scope: Vec<String>,
    /// Assumptions used to resolve ambiguity; these remain visible for correction.
    pub scope_assumptions: Vec<String>,
    /// Conditions that must be evidenced before the mission can be completed.
    pub acceptance_criteria: Vec<String>,
    /// Explicit promises whose lifecycle Cerebro must continue to own.
    pub commitments: Vec<Commitment>,
    /// Unresolved work that matters but has not become a Cerebro commitment.
    pub open_loops: Vec<OpenLoop>,
    /// Current lifecycle state of the mission as a whole.
    pub status: SessionStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// A durable, owned promise to perform work and verify a concrete outcome.
pub struct Commitment {
    /// Stable identifier referenced by wake events, claims, and checkpoints.
    pub commitment_ref: String,
    /// Operator-readable description of the promised result.
    pub summary: String,
    /// Party responsible for the next action.
    pub owner: WorkOwner,
    /// Current lifecycle state of the promise.
    pub status: CommitmentStatus,
    /// Smallest concrete action that advances the commitment, when known.
    pub next_action: Option<String>,
    /// Recorded reason progress cannot continue, present when blocked or waiting.
    pub blocker: Option<String>,
    /// Conditions that must be independently observed before completion.
    pub acceptance_criteria: Vec<String>,
    /// Durable identifiers for outputs, receipts, or external records produced so far.
    pub artifact_refs: Vec<String>,
    /// Tool identifiers whose fresh observations are required at the next checkpoint.
    #[serde(default)]
    pub required_tool_ids: Vec<String>,
    /// Machine-checkable rules deciding whether a wake is silent or user-visible.
    #[serde(default)]
    pub attention_policy: Option<CommitmentAttentionPolicy>,
    /// RFC 3339 time for the next scheduled assessment, if one is required.
    pub wake_at: Option<String>,
    /// Description of the observation that will prove completion.
    pub verification: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Observation rules that turn a scheduled checkpoint into a delivery decision.
pub struct CommitmentAttentionPolicy {
    /// Conditions that must all match before the commitment is accepted as complete.
    pub acceptance_all: Vec<ObservationCondition>,
    /// Conditions where any match warrants an immediate visible alert.
    pub alert_any: Vec<ObservationCondition>,
    /// Fields whose scalar change since the prior checkpoint warrants visibility.
    #[serde(default)]
    pub notify_on_change: Vec<ObservationCondition>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Exact comparison against a value returned by a particular tool.
pub struct ObservationCondition {
    /// Identifier of the tool observation to inspect.
    pub tool_id: String,
    /// JSON Pointer selecting the value within the observation data.
    pub data_pointer: String,
    /// Value that must compare equal after JSON Pointer resolution.
    pub equals: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Unresolved mission work tracked without implying that Cerebro owns execution.
pub struct OpenLoop {
    /// Stable identifier used by retained-plan grounded claims.
    pub open_loop_ref: String,
    /// Operator-readable description of the unresolved matter.
    pub summary: String,
    /// Party responsible for moving the loop forward.
    pub owner: WorkOwner,
    /// Concrete next action, if it is currently known.
    pub next_action: Option<String>,
    /// Dependency preventing progress, if any.
    pub blocked_by: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Question the plan must answer with an explicitly grounded claim.
pub struct PlannedClaim {
    /// Stable identifier that finished claims use to prove plan coverage.
    pub claim_ref: String,
    /// Factual or decision question to resolve.
    pub question: String,
    /// Whether the turn may finish without resolving this claim.
    pub required: bool,
    /// Canonical subjects whose evidence can answer the question.
    #[serde(default)]
    pub subject_refs: Vec<String>,
    /// Candidate authoritative sources the model expects to consult.
    pub source_candidates: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Bounded execution plan established before tool use or final synthesis.
pub struct ResearchPlan {
    /// Concise explanation of why this plan and lane fit the request.
    pub decision: String,
    /// Maximum authority/effect lane the planned work requires.
    pub lane: ExecutionLane,
    /// Canonical entities resolved from operator language.
    pub resolved_entities: Vec<String>,
    /// Evidence questions that bound the investigation.
    pub claims: Vec<PlannedClaim>,
    /// Tool identifiers selected from the supplied catalog.
    pub selected_tools: Vec<String>,
    /// Conditions that end collection before unnecessary calls are made.
    pub stop_conditions: Vec<String>,
    /// Work descriptions safe to expose as progress to the operator.
    pub user_visible_work: Vec<String>,
    /// Durable follow-through to create when this turn cannot complete the outcome.
    #[serde(default)]
    pub follow_through: Option<PlannedFollowThrough>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Model-proposed future observation contract validated before it is persisted.
pub struct PlannedFollowThrough {
    /// Stable commitment identifier to create or update.
    pub commitment_ref: String,
    /// Tools that must return observations at every scheduled checkpoint.
    pub required_tool_ids: Vec<String>,
    /// Human-readable conditions for verified completion.
    pub acceptance_criteria: Vec<String>,
    /// Action Cerebro will take after the next observation.
    pub next_action: String,
    /// Machine-readable rules controlling completion and user notification.
    pub attention_policy: CommitmentAttentionPolicy,
    /// Delay from turn completion to the next scheduled assessment.
    pub check_after_seconds: u32,
    /// Description of how fresh observations establish the outcome.
    pub verification: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Source coverage state for a field that may be absent from a receipt.
pub enum CoverageState {
    /// The source returned a value for the field in the bounded observation.
    Observed,
    /// The source response was valid and specifically omitted or withheld the field.
    ExplicitlyNotReturned,
    /// The field does not apply to the observed subject or operation.
    NotApplicable,
    /// The available evidence cannot establish whether the field has a value.
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Segregated responsibility that may be bound to a principal by source evidence.
pub enum AuthorityDuty {
    /// Owns changes that correct an identified condition.
    Remediation,
    /// May authorize a proposed effect or state transition.
    Approval,
    /// May perform the authorized effect.
    Execution,
    /// Independently establishes whether the expected result occurred.
    Verification,
    /// Administers the external provider where the resource lives.
    ProviderAdministration,
    /// Owns collection or publication of authoritative evidence.
    Evidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Kind of identity named by an authority binding.
pub enum AuthorityPrincipalKind {
    /// An individual human identity.
    Person,
    /// A group with shared responsibility.
    Team,
    /// A workload or automation identity.
    Service,
    /// An assumable organizational or provider role.
    Role,
    /// A party outside the tenant's directly managed identity system.
    External,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Canonical identity that may hold one authority duty for a subject.
pub struct AuthorityPrincipal {
    /// Stable provider or tenant identifier; never infer this from display text.
    pub principal_ref: String,
    /// Human-readable name supplied by the source, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// Identity category needed to interpret the reference correctly.
    pub kind: AuthorityPrincipalKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
/// Evidence-backed state of one duty-to-principal binding.
pub enum AuthorityBindingState {
    /// Exactly one authoritative binding was observed.
    Bound {
        /// Canonical identity observed in the binding.
        principal: AuthorityPrincipal,
    },
    /// The source says a binding exists but did not return its stable identity.
    PresentIdentityNotReturned,
    /// No authoritative observation of the binding was available.
    NotObserved,
    /// The source returned incompatible or multiple bindings that cannot be collapsed.
    Conflicting {
        /// Distinct canonical identities returned by the source.
        principals: Vec<AuthorityPrincipal>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Strength and direction of evidence relating a candidate to an outcome.
pub enum CausalCandidateState {
    /// Evidence establishes the candidate as causal under the source's standard.
    Established,
    /// Evidence materially supports the candidate but does not establish causality.
    Supported,
    /// Observations do not contradict the candidate but provide weak discrimination.
    ConsistentWith,
    /// Evidence is sufficient to reject the candidate for this outcome.
    RuledOut,
    /// Available evidence cannot distinguish this candidate from alternatives.
    Undistinguished,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// One explicit explanation evaluated in a causal assessment.
pub struct CausalCandidate {
    /// Stable identifier referenced by [`CausalRanking`].
    pub candidate_ref: String,
    /// Operator-readable description of the candidate explanation.
    pub label: String,
    /// Evidence-supported assessment state.
    pub state: CausalCandidateState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
/// Whether causal candidates can be ordered by the available evidence.
pub enum CausalRanking {
    /// The evidence does not support an ordering.
    Unranked,
    /// Strongest-to-weakest candidate references, each naming a supplied candidate.
    Ranked {
        /// Every candidate reference exactly once, strongest evidence first.
        ordered_candidate_refs: Vec<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "scope", rename_all = "snake_case")]
/// Boundary against which a search result's completeness must be interpreted.
pub enum SearchScope {
    /// Direct lookup of one canonical subject.
    ExactSubject {
        /// Canonical subject requested from the source.
        subject_ref: String,
    },
    /// Query whose limit or truncation may prevent a complete negative conclusion.
    BoundedQuery {
        /// Digest of the normalized query input, excluding secret values.
        input_digest: String,
        /// Maximum number of results requested.
        limit: u32,
        /// Number of results actually returned.
        returned: u32,
        /// Whether the source reported additional unreturned results.
        truncated: bool,
    },
    /// Exhaustive enumeration of a named finite source scope.
    CompleteSet {
        /// Stable identifier for the enumerated collection boundary.
        scope_ref: String,
        /// Number of members returned by the complete enumeration.
        returned: u32,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "result", rename_all = "snake_case")]
/// Outcome of searching within an explicitly described [`SearchScope`].
pub enum SearchCoverageResult {
    /// Matching records were returned.
    Found {
        /// Positive number of matching records within the declared scope.
        count: u32,
    },
    /// No match was returned; meaningful only with a sufficiently complete scope.
    NoMatch,
    /// Some results were obtained but coverage is insufficient for a complete conclusion.
    Partial,
    /// The source could not complete the search.
    Failed {
        /// Bounded machine-readable source failure category.
        error_kind: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Whether a concrete provider event is mapped into a normalized event family.
pub enum EventFamilyMembershipState {
    /// A configured or authoritative mapping includes the event.
    Mapped,
    /// A complete mapping explicitly excludes the event.
    NotMapped,
    /// Mapping coverage was not observed well enough to decide.
    Unverified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "state", rename_all = "snake_case")]
/// Whether a collection pipeline can currently see a typed event in a window.
pub enum CollectionVisibilityState {
    /// Events were observed, with the source-reported count.
    Observed {
        /// Positive number of matching events observed in the window.
        count: u32,
    },
    /// A complete collection scope was observed and contained no matching events.
    LegitimatelyEmpty {
        /// Complete collection boundary that proves the zero result.
        complete_scope_ref: String,
    },
    /// Collection coverage was not sufficient to distinguish empty from missing.
    Unverified,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "snake_case")]
/// Provider-neutral assertion whose semantics are stricter than free-form tool data.
///
/// Each variant preserves the difference between an observed negative, missing
/// coverage, and conflicting evidence so downstream claims cannot silently turn
/// absence into proof.
pub enum SemanticEvidenceAssertion {
    /// Binds one segregated duty to an observed identity state.
    AuthorityBinding {
        /// Canonical resource or work item whose authority is described.
        subject_ref: String,
        /// Responsibility being bound; duties are intentionally not interchangeable.
        duty: AuthorityDuty,
        /// Observed identity state, including explicit uncertainty or conflict.
        state: AuthorityBindingState,
    },
    /// Records an evidence-bounded comparison of alternative causes.
    CausalAssessment {
        /// Canonical subject being investigated.
        subject_ref: String,
        /// Outcome the candidates attempt to explain.
        outcome_ref: String,
        /// Explicit candidate set, including ruled-out alternatives.
        candidates: Vec<CausalCandidate>,
        /// Ordering supported by the evidence, or an explicit lack of ranking.
        ranking: CausalRanking,
    },
    /// Describes both the search boundary and what the search returned.
    SearchCoverage {
        /// Canonical subject, omitted only for searches spanning a broader scope.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject_ref: Option<String>,
        /// Boundary required to interpret a negative or partial result.
        scope: SearchScope,
        /// Result observed within that boundary.
        result: SearchCoverageResult,
    },
    /// States whether one provider event participates in a normalized family.
    EventFamilyMembership {
        /// Canonical source, connector, or collection subject.
        subject_ref: String,
        /// Concrete event type as named by the provider.
        event_type: String,
        /// Normalized family used by cross-provider policy and analysis.
        family: String,
        /// Observed mapping state.
        state: EventFamilyMembershipState,
    },
    /// States whether the collection path observed events in a bounded window.
    CollectionVisibility {
        /// Canonical source or collector subject.
        subject_ref: String,
        /// Concrete provider event type being checked.
        event_type: String,
        /// Stable identifier for the assessed time window.
        window_ref: String,
        /// Observed, proven-empty, or unverified collection state.
        state: CollectionVisibilityState,
    },
}

impl SemanticEvidenceAssertion {
    fn subject_ref(&self) -> Option<&str> {
        match self {
            Self::AuthorityBinding { subject_ref, .. }
            | Self::CausalAssessment { subject_ref, .. }
            | Self::EventFamilyMembership { subject_ref, .. }
            | Self::CollectionVisibility { subject_ref, .. } => Some(subject_ref),
            Self::SearchCoverage { subject_ref, .. } => subject_ref.as_deref(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Versioned batch of validated semantic assertions from one tool receipt.
pub struct SemanticEvidenceEnvelope {
    /// Must equal [`AGENT_SEMANTIC_EVIDENCE_V1`].
    pub schema_version: String,
    /// Non-empty bounded assertions sharing the receipt's freshness and completeness.
    pub assertions: Vec<SemanticEvidenceAssertion>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Typed content of one immutable [`EvidenceAtom`].
pub enum EvidenceAssertion {
    /// Scalar or structured value asserted for the atom's subject.
    Value {
        /// Provider-neutral name of the observed property.
        predicate: String,
        /// Exact JSON value returned or normalized by the tool.
        value: Value,
    },
    /// Directed relationship from the atom's subject to another canonical subject.
    Relation {
        /// Provider-neutral relationship name.
        predicate: String,
        /// Canonical object of the relationship.
        object_ref: String,
    },
    /// Conversation input represented as evidence with actor and time provenance.
    ConversationEvent {
        /// Durable thread containing the event.
        thread_ref: String,
        /// Canonical identity of the speaker.
        actor_ref: String,
        /// Source role label preserved from the conversation record.
        role: String,
        /// RFC 3339 timestamp reported for the event.
        occurred_at: String,
        /// Exact bounded message text used as evidence.
        text: String,
    },
    /// Explicit source coverage state for a field that may be absent.
    FieldCoverage {
        /// Field or JSON path whose coverage was assessed.
        field: String,
        /// Why a value is present, absent, inapplicable, or unknown.
        state: CoverageState,
    },
    /// Overall result state and source-authored summary of a tool invocation.
    ToolOutcome {
        /// Machine-readable success, partial, or failure state.
        state: ToolResultState,
        /// Bounded factual summary returned with the result.
        summary: String,
    },
    /// Validated provider-neutral assertion with explicit uncertainty semantics.
    Semantic {
        /// Structured semantic assertion.
        assertion: SemanticEvidenceAssertion,
    },
    /// Compatibility form for older evidence that lacks a typed assertion.
    LegacyStatement {
        /// Bounded source statement; consumers should prefer typed variants.
        statement: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Smallest immutable unit that a grounded claim may cite.
pub struct EvidenceAtom {
    /// Stable receipt-derived identifier unique within the turn evidence set.
    pub atom_ref: String,
    /// Canonical subject described by the assertion, when one exists.
    pub subject_ref: Option<String>,
    /// Typed fact, relationship, coverage statement, or source outcome.
    pub assertion: EvidenceAssertion,
    /// RFC 3339 time at which the source observation was made.
    pub observed_at: String,
    /// RFC 3339 time after which current-state claims must refresh this atom.
    pub fresh_until: Option<String>,
    /// Whether the producing read covered its declared scope completely.
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Allowlisted deterministic operation used to derive a claim from cited atoms.
pub enum DerivationRule {
    /// Count the members represented by the cited evidence.
    Count,
    /// Compute items in one cited set that are absent from another.
    SetDifference,
    /// Add a fixed number of seconds to an evidenced deadline or timestamp.
    DeadlineOffsetSeconds,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Concrete action named by a recommendation without authorizing its execution.
pub struct ActionSpec {
    /// Tool capable of the action, if known from the catalog.
    pub tool_id: Option<String>,
    /// Canonical target the action would affect, if resolved.
    pub target_ref: Option<String>,
    /// Proposed structured input; this is descriptive, not an effect authorization.
    pub input: Value,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Closed vocabulary for the operator action expressed by a recommendation.
pub enum RecommendationDirective {
    /// Preserve the current state because evidence does not justify a change.
    LeaveUnchanged,
    /// Perform a specifically scoped read or validation.
    PerformBoundedCheck,
    /// Defer a conclusion until a new authoritative observation is available.
    WaitForFreshObservation,
    /// Inspect the named target without changing it.
    InspectTarget,
    /// Independently verify the target's resulting state.
    VerifyTarget,
    /// Repair disagreement between Cerebro and provider-authoritative state.
    ReconcileProviderState,
    /// Obtain authorization before an effectful action.
    RequestApproval,
    /// Correct the named target through an authorized effect path.
    RemediateTarget,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Closed vocabulary for the missing fact a grounded question requests.
pub enum QuestionDirective {
    /// Ask the operator to identify the intended target.
    WhichTarget,
    /// Ask which source should govern the answer.
    WhichSource,
    /// Ask what decision the work should support.
    WhatDecision,
    /// Ask what observable result defines success.
    WhatOutcome,
    /// Ask who can supply a missing stable identifier.
    WhoCanProvideIdentifier,
    /// Ask for the relevant deadline or time boundary.
    WhenDue,
    /// Ask where the authoritative evidence can be observed.
    WhereEvidence,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Identifier for fixed explanatory text whose wording is owned by the runtime.
///
/// Models select an identifier instead of inventing policy or evidence-boundary
/// language, and [`render_stable_explanation`] supplies the reviewed text.
pub enum StableExplanationId {
    /// Defines when an observation is fresh enough for a current-state claim.
    EvidenceFreshnessDefinition,
    /// Separates provider fact authority from Cerebro's interpretation.
    EvidenceAuthorityBoundary,
    /// Separates recommending an action from authorizing or executing it.
    RecommendationExecutionBoundary,
    /// Requires a hypothesis to preserve viable alternative explanations.
    HypothesisAlternativesBoundary,
    /// Requires a new observation before claiming a mutable current state.
    CurrentStateFreshObservationBoundary,
    /// Separates a declared source from a usable runtime capability binding.
    CapabilityBindingBoundary,
    /// Separates source declaration from provider-side permission.
    SourceDeclarationProviderPermissionBoundary,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
/// Allowlisted presentation move that adds structure without adding new facts.
pub enum RhetoricalMoveId {
    /// Label what is directly observed and what is inferred.
    SeparateEvidenceFromInference,
    /// Organize a choice around explicit decision criteria.
    FrameDecisionWithCriteria,
    /// Apply the same comparison dimensions to each alternative.
    CompareAlternativesConsistently,
    /// Prefer or identify steps that can be safely undone.
    PreserveReversibility,
    /// Identify the missing observation most likely to change the decision.
    IdentifyDecisionChangingInformation,
    /// State the concrete boundary of the answer or proposed work.
    ClarifyScope,
}

/// Exhaustive stable-explanation variants, used for validation and coverage tests.
pub const ALL_STABLE_EXPLANATIONS: &[StableExplanationId] = &[
    StableExplanationId::EvidenceFreshnessDefinition,
    StableExplanationId::EvidenceAuthorityBoundary,
    StableExplanationId::RecommendationExecutionBoundary,
    StableExplanationId::HypothesisAlternativesBoundary,
    StableExplanationId::CurrentStateFreshObservationBoundary,
    StableExplanationId::CapabilityBindingBoundary,
    StableExplanationId::SourceDeclarationProviderPermissionBoundary,
];

/// Serialized identifiers corresponding positionally to [`ALL_STABLE_EXPLANATIONS`].
pub const ALL_STABLE_EXPLANATION_IDS: &[&str] = &[
    "evidence_freshness_definition",
    "evidence_authority_boundary",
    "recommendation_execution_boundary",
    "hypothesis_alternatives_boundary",
    "current_state_fresh_observation_boundary",
    "capability_binding_boundary",
    "source_declaration_provider_permission_boundary",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Standard reason a draft must qualify or withhold a material conclusion.
pub enum CoverageBoundaryKind {
    /// An effect started but no authoritative outcome receipt is available.
    ExternalActionOutcomeUnknown,
    /// The external effect returned a failure rather than the requested state.
    ExternalActionFailed,
    /// A required source read failed, so acceptance cannot be verified.
    SourceReadFailedAcceptanceUnverified,
    /// A source returned partial data insufficient to verify acceptance.
    PartialReadAcceptanceUnverified,
    /// A required observation was absent from the current evidence set.
    MissingObservationAcceptanceUnverified,
    /// One or more bounded reads could not enumerate the full relevant set.
    BoundedReadsIncomplete,
    /// One or more bounded source reads failed entirely.
    BoundedSourceReadsFailed,
    /// The available evidence is incomplete for the requested conclusion.
    AvailableEvidenceIncomplete,
    /// No fresh authoritative observation supports a current-state statement.
    NoCurrentAuthoritativeObservation,
    /// The available partial evidence does not support a partial conclusion either.
    PartialConclusionUnsupported,
    /// Work cannot continue without evidence from a named authoritative source.
    BlockedMissingAuthoritativeEvidence,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
/// Provenance basis that determines how a [`GroundedClaim`] is validated.
pub enum ClaimContent {
    /// Direct statement of one or more cited evidence atoms.
    Observation {
        /// Atoms whose contents support the visible claim text.
        atom_refs: Vec<String>,
    },
    /// Result of an allowlisted deterministic operation over cited atoms.
    Derivation {
        /// Operation used to produce `result`.
        rule: DerivationRule,
        /// Complete set of inputs to the operation.
        atom_refs: Vec<String>,
        /// Structured result that must agree with the visible text.
        result: Value,
    },
    /// Exact statement supplied by the operator in this session.
    OperatorContext {
        /// Event sequence containing the source message.
        message_sequence: u64,
        /// Exact contiguous excerpt used by the claim.
        exact_excerpt: String,
    },
    /// Conversational connective synthesized only from declared prior messages or atoms.
    ConversationalSynthesis {
        /// Event sequences of source messages used by the synthesis.
        source_message_sequences: Vec<u64>,
        /// Optional evidence atoms used alongside conversation context.
        #[serde(default)]
        source_atom_refs: Vec<String>,
    },
    /// Non-factual structure selected from reviewed runtime text.
    RhetoricalMove {
        /// Move rendered by [`render_rhetorical_move`].
        move_id: RhetoricalMoveId,
    },
    /// Exact excerpt from a historical evidence atom.
    HistoricalContext {
        /// Historical atom containing the excerpt.
        atom_ref: String,
        /// Exact contiguous source text, not a current-state assertion.
        exact_excerpt: String,
    },
    /// Reminder of an unresolved loop already recorded in mission state.
    RetainedPlan {
        /// Existing loop that authorizes mentioning the retained work.
        open_loop_ref: String,
    },
    /// Statement of a commitment already represented in mission state.
    Commitment {
        /// Existing commitment that authorizes the promise language.
        commitment_ref: String,
    },
    /// Suggested action backed by evidence but not executed by the claim.
    Recommendation {
        /// Bounded target, tool, and proposed input.
        action: ActionSpec,
        /// Closed-vocabulary operator action.
        directive: RecommendationDirective,
        /// Evidence establishing why the action is appropriate.
        rationale_atom_refs: Vec<String>,
    },
    /// Explicitly uncertain explanation that preserves alternatives.
    Hypothesis {
        /// Evidence consistent with the proposed explanation.
        supporting_atom_refs: Vec<String>,
        /// Plausible alternatives the draft must not conceal.
        alternatives: Vec<String>,
    },
    /// Reviewed runtime-owned explanation of a stable boundary.
    StableExplanation {
        /// Identifier rendered by [`render_stable_explanation`].
        explanation_id: StableExplanationId,
    },
    /// Explicit disclosure that available evidence cannot support a stronger conclusion.
    CoverageBoundary {
        /// Standardized reason for the limitation.
        boundary: CoverageBoundaryKind,
    },
    /// Necessary request for information, expressed with a bounded purpose.
    Question {
        /// Category of missing information requested from the operator.
        directive: QuestionDirective,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// One visible statement paired with the provenance basis that permits it.
pub struct GroundedClaim {
    /// Identifier unique within the draft.
    pub claim_ref: String,
    /// Planned question this claim resolves, when it was anticipated by the plan.
    #[serde(default)]
    pub planned_claim_ref: Option<String>,
    /// Exact text expected to appear in the delivered message.
    pub text: String,
    /// Whether removing this claim would leave the operator's request unanswered.
    pub required_for_answer: bool,
    /// Typed grounding contract validated against session state and observations.
    pub content: ClaimContent,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Model-produced response candidate that must pass deterministic and critic review.
pub struct GroundedDraft {
    /// Claimed terminal or non-terminal state of this turn.
    pub state: FinalState,
    /// Whether the validated message should be shown to the operator.
    #[serde(default)]
    pub delivery: DeliveryDisposition,
    /// Candidate Markdown; every material statement must be declared in `claims`.
    pub message: String,
    /// Grounding declarations for material statements in `message`.
    pub claims: Vec<GroundedClaim>,
    /// Plain-language disclosure of incomplete evidence, when required.
    pub coverage_notice: Option<String>,
    /// Focused operator question when progress needs new input.
    pub question: Option<String>,
    /// Complete next mission snapshot proposed by the model.
    pub mission: MissionState,
    /// Evidence-linked durable memories proposed for retention.
    pub memory_updates: Vec<MemoryUpdate>,
    /// Model assertion that the message is final-form rather than notes or scaffolding.
    pub presentation_ready: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Whether a completed turn produces operator-visible transport output.
pub enum DeliveryDisposition {
    #[default]
    /// Deliver the validated message through the caller's transport.
    Visible,
    /// Persist the turn and follow-through state without sending a message.
    Silent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Operational category of a durable session memory.
pub enum MemoryKind {
    /// Evidence-backed fact likely to matter in later turns.
    Fact,
    /// Decision made by an authorized actor or completed workflow.
    Decision,
    /// Material uncertainty or adverse outcome to preserve.
    Risk,
    /// Condition currently preventing progress.
    Blocker,
    /// Responsibility or context that must survive transfer to another actor.
    Handoff,
    /// Reliability, freshness, or coverage property of an evidence source.
    SourceHealth,
    /// Operator preference evidenced by conversation context.
    Preference,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Candidate durable memory linked to the evidence that supports retention.
pub struct MemoryUpdate {
    /// Stable identifier used to replace or deduplicate the memory.
    pub memory_ref: String,
    /// Operational category controlling later recall and interpretation.
    pub kind: MemoryKind,
    /// Bounded proposition to retain; it must not exceed its cited evidence.
    pub statement: String,
    /// Current evidence atoms supporting the statement.
    pub evidence_atom_refs: Vec<String>,
    /// Whether a higher-level memory system should consider durable promotion.
    pub promotion_requested: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
/// Next step selected by the model for one bounded session-loop iteration.
pub enum SessionModelDecision {
    /// Persist a plan before any tool calls or final synthesis.
    EstablishPlan {
        /// Proposed bounded research and follow-through plan.
        plan: ResearchPlan,
    },
    /// Persist a plan and immediately invoke its first independent calls.
    EstablishPlanAndInvoke {
        /// Proposed plan governing the calls.
        plan: ResearchPlan,
        /// Calls to validate and execute under runtime authority checks.
        calls: Vec<ToolCall>,
    },
    /// Continue an established plan with additional tool observations.
    InvokeTools {
        /// Calls to validate and execute under runtime authority checks.
        calls: Vec<ToolCall>,
    },
    /// Stop model iteration and submit a draft for validation and review.
    Finish {
        /// Candidate grounded response and next mission state.
        draft: GroundedDraft,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Participant role retained in durable conversation history.
pub enum SessionMessageRole {
    /// Message previously delivered by the agent.
    Assistant,
    /// Message supplied by the operator.
    User,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Durable conversation message used as context and operator evidence.
pub struct SessionMessage {
    /// Speaker role used by model reconstruction.
    pub role: SessionMessageRole,
    /// Stable transport or runtime message identifier.
    pub message_ref: String,
    /// Canonical identity of the speaker or agent.
    pub actor_ref: String,
    /// Exact bounded message text.
    pub text: String,
    /// RFC 3339 time at which the runtime accepted the message.
    pub received_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
/// Append-only fact used to reconstruct and audit [`AgentSession`] state.
///
/// Event application is sequence-checked by [`apply_session_events`]. An event
/// records what the runtime accepted or observed; it is not a command to repeat
/// an external effect.
pub enum SessionEvent {
    /// Adds an accepted operator message to durable conversation history.
    UserMessageQueued {
        /// Message accepted from the transport boundary.
        message: SessionMessage,
    },
    /// Records the authority lane selected for an accepted request.
    RouteAccepted {
        /// Idempotency and correlation identifier for the turn.
        request_id: String,
        /// Runtime-authorized execution lane.
        lane: ExecutionLane,
        /// Whether the request creates a future-observation obligation.
        #[serde(default)]
        future_observation: FutureObservationDisposition,
        /// Bounded operator text supporting that classification.
        #[serde(default)]
        future_observation_excerpt: Option<String>,
    },
    /// Records delivery of one scheduled commitment occurrence to the runtime.
    WakeTriggered {
        /// Turn request created for the occurrence.
        request_id: String,
        /// Commitment selected by the scheduler record.
        commitment_ref: String,
        /// Unique occurrence identifier used to prevent duplicate consumption.
        occurrence_ref: String,
        /// RFC 3339 time at which the occurrence was scheduled.
        scheduled_for: String,
    },
    /// Records terminal retry exhaustion for a scheduled occurrence.
    WakeExhausted {
        /// Turn request that recorded terminal exhaustion.
        request_id: String,
        /// Commitment moved to its exhausted state.
        commitment_ref: String,
        /// Unique occurrence whose retries were exhausted.
        occurrence_ref: String,
        /// Scheduler generation used to reject stale retry records.
        schedule_generation: u64,
        /// Bounded machine-readable category for the terminal failure.
        failure_class: String,
        /// Visible, grounded draft explaining the failed follow-through.
        draft: GroundedDraft,
    },
    /// Marks the beginning of processing for one request identifier.
    TurnStarted {
        /// Request entering the model loop.
        request_id: String,
    },
    /// Persists the validated plan governing subsequent calls and claims.
    PlanEstablished {
        /// Exact validated plan accepted by the runtime.
        plan: ResearchPlan,
    },
    /// Records operator-safe progress without implying completion.
    Progressed {
        /// Bounded machine-readable or display-safe phase name.
        phase: String,
        /// Bounded factual description of current work state.
        status: String,
    },
    /// Captures the receipt returned by a completed read-only tool invocation.
    ToolInvoked {
        /// Validated tool receipt and its atomized evidence.
        observation: ToolObservation,
    },
    /// Records an effect boundary before external execution begins.
    EffectStarted {
        /// Exact authorized call sent to the effect executor.
        call: ToolCall,
        /// Descriptor whose authority and effect policy governed the call.
        descriptor: ToolDescriptor,
    },
    /// Stores a validated candidate awaiting transport delivery confirmation.
    DraftProduced {
        /// Request that produced the draft.
        request_id: String,
        /// Exact grounded draft held in `pending_delivery`.
        draft: GroundedDraft,
    },
    /// Records that an effect cannot proceed without an authorization.
    ApprovalRequested {
        /// Effectful tool awaiting authorization.
        tool_id: String,
        /// Digest binding approval to the exact proposed input.
        input_digest: String,
    },
    /// Marks successful termination of request processing at a final state.
    TurnCompleted {
        /// Request whose model loop completed.
        request_id: String,
        /// Validated state returned by the draft.
        state: FinalState,
    },
    /// Marks a request that ended because runtime processing failed.
    TurnFailed {
        /// Request that could not produce a valid outcome.
        request_id: String,
        /// Bounded reason suitable for audit and operator diagnosis.
        reason: String,
    },
    /// Marks deliberate interruption without representing the mission as complete.
    Interrupted {
        /// Request stopped before completion.
        request_id: String,
        /// Bounded reason for the interruption.
        reason: String,
    },
    /// Confirms that a pending draft was sent by a named transport.
    DeliveryRecorded {
        /// Request whose pending draft was delivered.
        request_id: String,
        /// Transport implementation that accepted the payload.
        transport: String,
        /// Durable receipt identifier returned by the transport.
        delivery_ref: String,
        /// Digest binding the receipt to the exact delivered payload.
        payload_digest: String,
    },
    /// Confirms acceptance of an evidence-linked memory into session state.
    MemoryRecorded {
        /// Exact validated memory update added or replaced.
        update: MemoryUpdate,
    },
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Sequenced, versioned envelope for one durable [`SessionEvent`].
pub struct SessionEventRecord {
    /// Must equal [`AGENT_SESSION_EVENT_V2`].
    pub schema_version: String,
    /// Session receiving the event.
    pub session_ref: String,
    /// Contiguous one-based sequence assigned by the session writer.
    pub sequence: u64,
    /// RFC 3339 time at which the runtime recorded the event.
    pub occurred_at: String,
    /// Immutable state transition or audit fact.
    pub event: SessionEvent,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Materialized durable state for one tenant-scoped agent conversation.
///
/// `events` is the auditable transition history, while the other fields are the
/// validated snapshot produced by applying those events. Callers must use a
/// [`SessionStore`] append with the expected sequence to serialize writers.
pub struct AgentSession {
    /// Must equal [`AGENT_SESSION_V2`].
    pub schema_version: String,
    /// Stable identifier for this unit of work.
    pub session_ref: String,
    /// Tenant boundary that all tools, storage, and effects must preserve.
    pub tenant_id: String,
    /// Durable conversation thread associated with the session.
    pub thread_ref: String,
    /// Optional source-defined scope shared by messages and tool calls.
    #[serde(default)]
    pub context_scope_ref: Option<String>,
    /// Current objective, ownership, and lifecycle snapshot.
    pub mission: MissionState,
    /// Bounded conversation context retained for subsequent turns.
    pub messages: Vec<SessionMessage>,
    /// Contiguous event history retained by this snapshot.
    pub events: Vec<SessionEventRecord>,
    /// Effect grants already issued within this session's authority boundary.
    pub effect_authorizations: Vec<EffectAuthorization>,
    /// Validated draft awaiting a separate transport delivery receipt.
    #[serde(default)]
    pub pending_delivery: Option<PendingDelivery>,
    /// Bounded evidence-linked facts retained for later turns.
    #[serde(default)]
    pub memories: Vec<MemoryUpdate>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Validated response held until the caller durably confirms transport delivery.
pub struct PendingDelivery {
    /// Request that produced the draft.
    pub request_id: String,
    /// Exact validated draft to deliver; callers must not regenerate it.
    pub draft: GroundedDraft,
    /// RFC 3339 time at which validation completed.
    pub produced_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
/// Complete bounded context supplied to the model for one loop iteration.
pub struct SessionModelTurn {
    /// Current validated session snapshot.
    pub session: AgentSession,
    /// Operator or scheduled-wake cause of this turn.
    pub trigger: SessionTurnTrigger,
    /// RFC 3339 time used consistently for freshness and deadline decisions.
    pub assessment_at: String,
    /// Caller-requested lane, subject to runtime policy and tool authority.
    pub requested_lane: Option<ExecutionLane>,
    /// Last durable checkpoint for the waking commitment, when available.
    pub prior_commitment_checkpoint: Option<CommitmentCheckpoint>,
    /// Deterministic comparison of current wake observations with policy.
    pub wake_assessment: Option<WakeAssessment>,
    /// Previously established plan, absent only before plan establishment.
    pub plan: Option<ResearchPlan>,
    /// Tool catalog filtered to capabilities available for this session.
    pub available_tools: Vec<ToolDescriptor>,
    /// Validated receipts collected during the current turn.
    pub observations: Vec<ToolObservation>,
    /// Deterministic or critic issues the next model attempt must repair.
    pub repair_feedback: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Durable result of assessing one scheduled commitment occurrence.
pub struct CommitmentCheckpoint {
    /// Commitment whose future-observation contract was assessed.
    pub commitment_ref: String,
    /// Turn request that performed the assessment.
    pub source_request_id: String,
    /// RFC 3339 checkpoint creation time.
    pub recorded_at: String,
    /// Transport receipt identifier for the checkpoint delivery.
    pub delivery_ref: String,
    /// Digest binding the receipt to the exact delivered payload.
    pub payload_digest: String,
    /// Scheduler occurrence consumed by this checkpoint, when wake-triggered.
    pub trigger_occurrence_ref: Option<String>,
    /// Whether the checkpoint was visible or intentionally silent.
    pub delivery: DeliveryDisposition,
    /// Turn state reported by the validated draft.
    pub state: FinalState,
    /// Bounded operator-readable result summary.
    pub summary: String,
    /// Exact tool receipts used for this assessment.
    pub observations: Vec<CommitmentCheckpointObservation>,
    /// Commitment lifecycle state after applying the checkpoint.
    pub commitment_status: CommitmentStatus,
    /// RFC 3339 next assessment time, absent when no further wake is required.
    pub next_wake_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Replay-safe projection of a tool receipt retained with a commitment checkpoint.
pub struct CommitmentCheckpointObservation {
    /// Tool that produced the observation.
    pub tool_id: String,
    /// Exact normalized input used for the read.
    pub input: Value,
    /// Digest binding the observation to `input`.
    pub input_digest: String,
    /// Canonical subjects covered by the source read, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_subject_refs: Option<Vec<String>>,
    /// RFC 3339 source observation time, absent only when the source omitted it.
    pub observed_at: Option<String>,
    /// Machine-readable receipt health.
    pub state: ToolResultState,
    /// Whether the read covered its declared source scope.
    pub complete: bool,
    /// Bounded factual receipt summary.
    pub summary: String,
    /// Structured receipt data used by attention policy and comparison.
    pub data: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Deterministic attention and acceptance facts computed for a scheduled wake.
pub struct WakeAssessment {
    /// Commitment whose policy was evaluated.
    pub commitment_ref: String,
    /// Whether every `required_tool_id` produced an observation.
    pub required_observations_present: bool,
    /// Whether all present required observations reported healthy states.
    pub required_observations_healthy: bool,
    /// Whether every `acceptance_all` condition matched current observations.
    pub acceptance_met: bool,
    /// Alert or change conditions that justify a visible checkpoint.
    pub matched_attention_signals: Vec<ObservationCondition>,
    /// Field-level changes from the prior checkpoint to the current read.
    pub scalar_comparisons: Vec<WakeScalarComparison>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WakeAttentionDisposition {
    RoutineSilent,
    VisibleAcceptance,
    VisibleAttention,
    VisibleUnhealthy,
}

struct WakeAttentionDecision<'a> {
    required_observations: Vec<&'a ToolObservation>,
    missing_required_tool_ids: Vec<String>,
    unhealthy_required_tool_ids: Vec<String>,
    acceptance_met: bool,
    matched_attention_signals: Vec<ObservationCondition>,
    disposition: WakeAttentionDisposition,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Comparison of one watched scalar across consecutive commitment checkpoints.
pub struct WakeScalarComparison {
    /// Tool whose observation contains the watched value.
    pub tool_id: String,
    /// Digest identifying the current invocation input.
    pub input_digest: String,
    /// JSON Pointer used to resolve both previous and current values.
    pub data_pointer: String,
    /// Value retained by the prior checkpoint, if returned then.
    pub previous: Option<Value>,
    /// Value returned by the current observation, if returned now.
    pub current: Option<Value>,
    /// Explicit interpretation of presence and equality across reads.
    pub relation: WakeScalarRelation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Presence and equality relationship between two checkpoint values.
pub enum WakeScalarRelation {
    /// Current read introduced a value not retained by the prior checkpoint.
    AddedToCurrentRead,
    /// Both reads returned values and they differ.
    Changed,
    /// Both reads returned equal values.
    Unchanged,
    /// The prior checkpoint had a value that the current read omitted.
    NotReturnedByCurrentRead,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Critic judgment for one declared claim.
pub enum ClaimReviewVerdict {
    /// The claim text and provenance basis are supported by supplied context.
    Supported,
    /// The claim exceeds, contradicts, or fails to match its declared basis.
    Unsupported,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Critic result for one [`GroundedClaim`].
pub struct ClaimReview {
    /// Claim identifier copied from the reviewed draft.
    pub claim_ref: String,
    /// Support judgment.
    pub verdict: ClaimReviewVerdict,
    /// Concrete repair guidance, required for unsupported claims.
    pub issue: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Critic checks for response quality that deterministic provenance cannot establish.
pub struct BehavioralReview {
    /// Whether the draft directly addresses the newest operator request.
    pub answers_newest_request: bool,
    /// Whether the message reads as a coherent response rather than model scaffolding.
    pub conversational: bool,
    /// Whether Cerebro preserves responsibility for promised future work.
    pub owns_follow_through: bool,
    /// Whether detail and length fit the request and evidence available.
    pub right_sized: bool,
    /// Whether observations, inferences, and unknowns remain correctly separated.
    pub evidence_boundary_correct: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Critic judgment of whether a wake result warrants operator interruption.
pub struct AttentionReview {
    /// Recommended visible or silent delivery disposition.
    pub delivery: DeliveryDisposition,
    /// Concrete reason tied to acceptance, health, or matched attention policy.
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Complete critic response bound to the exact candidate message.
pub struct MessageReview {
    /// SHA-256 digest that prevents applying review to a different message.
    pub message_digest: String,
    /// One result for every declared grounded claim.
    pub claim_reviews: Vec<ClaimReview>,
    /// Material statements in the message that lack claim declarations.
    pub undeclared_material: Vec<String>,
    /// Wake-delivery judgment.
    pub attention: AttentionReview,
    /// Non-provenance response-quality checks.
    pub behavioral: BehavioralReview,
}

#[derive(Clone, Debug, Serialize)]
/// Exact evidence and state supplied to the model critic.
pub struct ClaimReviewTurn {
    /// Current validated session snapshot.
    pub session: AgentSession,
    /// Cause of the turn whose draft is under review.
    pub trigger: SessionTurnTrigger,
    /// Prior checkpoint used for wake comparisons, when applicable.
    pub prior_commitment_checkpoint: Option<CommitmentCheckpoint>,
    /// Runtime-computed wake policy assessment, when applicable.
    pub wake_assessment: Option<WakeAssessment>,
    /// Candidate draft to review.
    pub draft: GroundedDraft,
    /// Tool receipts available to support its claims.
    pub observations: Vec<ToolObservation>,
}

#[async_trait]
/// Model boundary for planning, tool selection, drafting, and independent critique.
pub trait SessionAgentModel: Send + Sync {
    /// Advances one bounded loop iteration without directly executing effects.
    async fn advance(
        &self,
        turn: SessionModelTurn,
    ) -> Result<SessionModelDecision, AgentRuntimeError>;

    /// Reviews an exact candidate against its declared claims and supplied evidence.
    async fn review_message(
        &self,
        turn: ClaimReviewTurn,
    ) -> Result<MessageReview, AgentRuntimeError>;
}

#[async_trait]
/// Tenant-aware tool catalog and invocation boundary used by the session runtime.
pub trait SessionTools: Send + Sync {
    /// Returns descriptors used for plan validation and authority enforcement.
    fn catalog(&self) -> Vec<ToolDescriptor>;

    /// Invokes one already-validated call and returns a receipt, not a bare value.
    async fn invoke(
        &self,
        session: &AgentSession,
        input: &SessionTurnInput,
        call: &ToolCall,
    ) -> Result<ToolResult, AgentRuntimeError>;
}

#[async_trait]
/// Optimistically serialized persistence boundary for session snapshots and events.
pub trait SessionStore: Send + Sync {
    /// Creates a new validated session and fails if the identifier already exists.
    async fn create(&self, session: &AgentSession) -> Result<(), AgentRuntimeError>;

    /// Loads the latest materialized session, or `None` when it does not exist.
    async fn load(&self, session_ref: &str) -> Result<Option<AgentSession>, AgentRuntimeError>;

    /// Atomically appends events when the current sequence equals `expected_sequence`.
    async fn append(
        &self,
        session_ref: &str,
        expected_sequence: u64,
        events: &[SessionEventRecord],
    ) -> Result<(), AgentRuntimeError>;
}

#[async_trait]
/// External audit sink coordinated with session-event persistence.
pub trait SessionJournal: Send + Sync {
    /// Records an event before the store append is finalized.
    async fn record(&self, event: &SessionEventRecord) -> Result<(), AgentRuntimeError>;
    /// Confirms that a previously recorded batch was durably appended.
    async fn finalize(&self, events: &[SessionEventRecord]) -> Result<(), AgentRuntimeError>;
}

struct NoopSessionJournal;

#[async_trait]
impl SessionJournal for NoopSessionJournal {
    async fn record(&self, _event: &SessionEventRecord) -> Result<(), AgentRuntimeError> {
        Ok(())
    }

    async fn finalize(&self, _events: &[SessionEventRecord]) -> Result<(), AgentRuntimeError> {
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Caller-supplied, validated identity and timing context for one session turn.
pub struct SessionTurnInput {
    /// Idempotency and correlation identifier for the turn.
    pub request_id: String,
    /// Canonical identity of the operator or scheduler initiating the turn.
    pub actor_ref: String,
    /// RFC 3339 time used for all turn freshness decisions.
    pub assessment_at: String,
    /// Requested authority lane; runtime validation may reject incompatible tools.
    pub requested_lane: Option<ExecutionLane>,
    /// Operator or scheduled-wake cause of the turn.
    pub trigger: SessionTurnTrigger,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// Source of work that determines conversation and attention behavior.
pub enum SessionTurnTrigger {
    /// A new operator request or continuation.
    Operator,
    /// A scheduled future observation for an existing commitment.
    Wake {
        /// Commitment whose acceptance and attention policy must be assessed.
        commitment_ref: String,
        /// Unique scheduler occurrence consumed by this turn.
        occurrence_ref: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
/// Durable handoff returned after the runtime stops session-loop execution.
pub enum SessionTurnOutcome {
    /// Validated draft persisted for a separate transport delivery step.
    PendingDelivery {
        /// Execution lane accepted for the completed turn.
        lane: ExecutionLane,
        /// Whether the transport should emit the message.
        delivery: DeliveryDisposition,
        /// Exact validated Markdown to deliver without regeneration.
        markdown: String,
        /// Validated final or non-terminal state.
        final_state: FinalState,
        /// Evidence atoms cited by the delivered claims.
        evidence_atom_refs: Vec<String>,
        /// Next durable mission state.
        mission: MissionState,
        /// Events that were atomically appended for this outcome.
        events: Vec<SessionEventRecord>,
    },
    /// Effectful work stopped at the authorization boundary.
    ApprovalRequired {
        /// Approval request binding tool, input digest, and authority context.
        request: ApprovalRequest,
        /// Events persisted before returning control to the caller.
        events: Vec<SessionEventRecord>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Minimal transport payload produced after deterministic and critic validation.
pub struct ValidatedDraft {
    /// Exact approved Markdown.
    pub markdown: String,
    /// Deduplicated evidence atoms cited by its claims.
    pub evidence_atom_refs: Vec<String>,
}

/// Inputs for converting generic JSON tool data into typed evidence atoms.
pub struct EvidenceAtomization<'a> {
    /// Stable receipt identifier used as the prefix for generated atom references.
    pub evidence_ref: &'a str,
    /// Canonical subject shared by generated value and coverage atoms.
    pub subject_ref: Option<&'a str>,
    /// Structured source data to flatten into independently citable fields.
    pub data: &'a Value,
    /// Overall result state represented by the generated tool-outcome atom.
    pub state: ToolResultState,
    /// Bounded source summary represented by the tool-outcome atom.
    pub summary: &'a str,
    /// RFC 3339 source observation time copied to every generated atom.
    pub observed_at: &'a str,
    /// Optional RFC 3339 freshness limit copied to every generated atom.
    pub fresh_until: Option<&'a str>,
    /// Whether the source read covered its declared scope.
    pub complete: bool,
}

/// Inputs for converting a validated semantic envelope into citable atoms.
pub struct SemanticEvidenceAtomization<'a> {
    /// Stable receipt identifier used as the generated atom-reference prefix.
    pub evidence_ref: &'a str,
    /// Versioned semantic assertions to validate and atomize.
    pub envelope: SemanticEvidenceEnvelope,
    /// RFC 3339 source observation time copied to every assertion.
    pub observed_at: &'a str,
    /// Optional RFC 3339 freshness limit copied to every assertion.
    pub fresh_until: Option<&'a str>,
    /// Whether the source read covered its declared scope.
    pub complete: bool,
}

/// Validates and converts semantic assertions into independently citable atoms.
///
/// Atom identifiers are deterministic (`{evidence_ref}#semantic:{index}`), so
/// a claim can cite a precise assertion while preserving the producing receipt's
/// observation time, freshness boundary, and completeness. Invalid schemas,
/// timestamps, identifiers, or semantic invariants fail closed.
pub fn semantic_evidence_atoms(
    input: SemanticEvidenceAtomization<'_>,
) -> Result<Vec<EvidenceAtom>, AgentRuntimeError> {
    let SemanticEvidenceAtomization {
        evidence_ref,
        envelope,
        observed_at,
        fresh_until,
        complete,
    } = input;
    validate_semantic_evidence_envelope(&envelope)?;
    if !bounded(evidence_ref, MAX_TEXT_BYTES)
        || OffsetDateTime::parse(observed_at, &Rfc3339).is_err()
        || fresh_until.is_some_and(|value| OffsetDateTime::parse(value, &Rfc3339).is_err())
    {
        return Err(AgentRuntimeError::InvalidToolCall(
            "semantic evidence requires a bounded evidence reference and valid receipt timestamps"
                .into(),
        ));
    }
    Ok(envelope
        .assertions
        .into_iter()
        .enumerate()
        .map(|(index, assertion)| EvidenceAtom {
            atom_ref: format!("{evidence_ref}#semantic:{index}"),
            subject_ref: assertion.subject_ref().map(str::to_owned),
            assertion: EvidenceAssertion::Semantic { assertion },
            observed_at: observed_at.to_owned(),
            fresh_until: fresh_until.map(str::to_owned),
            complete,
        })
        .collect())
}

fn validate_semantic_evidence_envelope(
    envelope: &SemanticEvidenceEnvelope,
) -> Result<(), AgentRuntimeError> {
    if envelope.schema_version != AGENT_SEMANTIC_EVIDENCE_V1
        || envelope.assertions.is_empty()
        || envelope.assertions.len() > MAX_SEMANTIC_ASSERTIONS
    {
        return Err(invalid_semantic_evidence(
            "the schema version or assertion count is invalid",
        ));
    }
    let mut assertions = BTreeSet::new();
    for assertion in &envelope.assertions {
        validate_semantic_assertion(assertion)?;
        let encoded = serde_json::to_vec(assertion)
            .map_err(|error| invalid_semantic_evidence(&error.to_string()))?;
        if !assertions.insert(encoded) {
            return Err(invalid_semantic_evidence(
                "duplicate semantic assertions are not allowed",
            ));
        }
    }
    Ok(())
}

fn validate_semantic_assertion(
    assertion: &SemanticEvidenceAssertion,
) -> Result<(), AgentRuntimeError> {
    match assertion {
        SemanticEvidenceAssertion::AuthorityBinding {
            subject_ref, state, ..
        } => {
            require_semantic_ref(subject_ref, "authority subject")?;
            match state {
                AuthorityBindingState::Bound { principal } => {
                    validate_authority_principal(principal)?;
                }
                AuthorityBindingState::Conflicting { principals } => {
                    if principals.len() < 2 || principals.len() > MAX_SEMANTIC_PRINCIPALS {
                        return Err(invalid_semantic_evidence(
                            "conflicting authority requires two to sixteen principals",
                        ));
                    }
                    let mut refs = BTreeSet::new();
                    for principal in principals {
                        validate_authority_principal(principal)?;
                        if !refs.insert(principal.principal_ref.as_str()) {
                            return Err(invalid_semantic_evidence(
                                "conflicting authority principals must be unique",
                            ));
                        }
                    }
                }
                AuthorityBindingState::PresentIdentityNotReturned
                | AuthorityBindingState::NotObserved => {}
            }
        }
        SemanticEvidenceAssertion::CausalAssessment {
            subject_ref,
            outcome_ref,
            candidates,
            ranking,
        } => {
            require_semantic_ref(subject_ref, "causal subject")?;
            require_semantic_ref(outcome_ref, "causal outcome")?;
            if candidates.is_empty() || candidates.len() > MAX_SEMANTIC_CANDIDATES {
                return Err(invalid_semantic_evidence(
                    "causal assessments require one to sixteen candidates",
                ));
            }
            let mut candidate_refs = BTreeSet::new();
            for candidate in candidates {
                require_semantic_ref(&candidate.candidate_ref, "causal candidate")?;
                require_semantic_text(&candidate.label, "causal candidate label")?;
                if !candidate_refs.insert(candidate.candidate_ref.as_str()) {
                    return Err(invalid_semantic_evidence(
                        "causal candidate references must be unique",
                    ));
                }
            }
            if let CausalRanking::Ranked {
                ordered_candidate_refs,
            } = ranking
                && (ordered_candidate_refs.len() != candidate_refs.len()
                    || ordered_candidate_refs.iter().collect::<BTreeSet<_>>().len()
                        != candidate_refs.len()
                    || ordered_candidate_refs
                        .iter()
                        .any(|candidate_ref| !candidate_refs.contains(candidate_ref.as_str())))
            {
                return Err(invalid_semantic_evidence(
                    "a causal ranking must order every candidate exactly once",
                ));
            }
        }
        SemanticEvidenceAssertion::SearchCoverage {
            subject_ref,
            scope,
            result,
        } => {
            if let Some(subject_ref) = subject_ref {
                require_semantic_ref(subject_ref, "search subject")?;
            }
            let returned = match scope {
                SearchScope::ExactSubject { subject_ref } => {
                    require_semantic_ref(subject_ref, "exact search subject")?;
                    None
                }
                SearchScope::BoundedQuery {
                    input_digest,
                    limit,
                    returned,
                    ..
                } => {
                    if !valid_sha256_digest(input_digest)
                        || *limit == 0
                        || *limit > MAX_SEMANTIC_SEARCH_LIMIT
                        || returned > limit
                    {
                        return Err(invalid_semantic_evidence("bounded search scope is invalid"));
                    }
                    Some(*returned)
                }
                SearchScope::CompleteSet {
                    scope_ref,
                    returned,
                } => {
                    require_semantic_ref(scope_ref, "complete search scope")?;
                    if *returned > MAX_SEMANTIC_RESULT_COUNT {
                        return Err(invalid_semantic_evidence(
                            "complete search result count exceeds the bounded limit",
                        ));
                    }
                    Some(*returned)
                }
            };
            match result {
                SearchCoverageResult::Found { count }
                    if *count == 0
                        || *count > MAX_SEMANTIC_RESULT_COUNT
                        || returned.is_some_and(|returned| *count > returned) =>
                {
                    return Err(invalid_semantic_evidence(
                        "search match count is invalid for the declared scope",
                    ));
                }
                SearchCoverageResult::Failed { error_kind } => {
                    if !valid_semantic_code(error_kind) {
                        return Err(invalid_semantic_evidence(
                            "search failure kind must be a bounded machine code",
                        ));
                    }
                }
                SearchCoverageResult::Found { .. }
                | SearchCoverageResult::NoMatch
                | SearchCoverageResult::Partial => {}
            }
        }
        SemanticEvidenceAssertion::EventFamilyMembership {
            subject_ref,
            event_type,
            family,
            ..
        } => {
            require_semantic_ref(subject_ref, "event-family subject")?;
            if !valid_semantic_code(event_type) || !valid_semantic_code(family) {
                return Err(invalid_semantic_evidence(
                    "event-family membership requires bounded event and family codes",
                ));
            }
        }
        SemanticEvidenceAssertion::CollectionVisibility {
            subject_ref,
            event_type,
            window_ref,
            state,
        } => {
            require_semantic_ref(subject_ref, "collection-visibility subject")?;
            require_semantic_ref(window_ref, "collection-visibility window")?;
            if !valid_semantic_code(event_type) {
                return Err(invalid_semantic_evidence(
                    "collection visibility requires a bounded event code",
                ));
            }
            match state {
                CollectionVisibilityState::Observed { count } if *count == 0 => {
                    return Err(invalid_semantic_evidence(
                        "observed collection visibility requires a positive count",
                    ));
                }
                CollectionVisibilityState::LegitimatelyEmpty { complete_scope_ref } => {
                    require_semantic_ref(complete_scope_ref, "complete empty scope")?;
                }
                CollectionVisibilityState::Observed { .. }
                | CollectionVisibilityState::Unverified => {}
            }
        }
    }
    Ok(())
}

fn validate_authority_principal(principal: &AuthorityPrincipal) -> Result<(), AgentRuntimeError> {
    require_semantic_ref(&principal.principal_ref, "authority principal")?;
    if principal
        .display_name
        .as_deref()
        .is_some_and(|value| !bounded(value, MAX_TEXT_BYTES) || value.chars().any(char::is_control))
    {
        return Err(invalid_semantic_evidence(
            "authority principal display name is invalid",
        ));
    }
    Ok(())
}

fn require_semantic_ref(value: &str, name: &str) -> Result<(), AgentRuntimeError> {
    if !bounded(value, MAX_TEXT_BYTES) || value.chars().any(char::is_control) {
        return Err(invalid_semantic_evidence(&format!("{name} is invalid")));
    }
    Ok(())
}

fn require_semantic_text(value: &str, name: &str) -> Result<(), AgentRuntimeError> {
    if !bounded(value, MAX_TEXT_BYTES) || value.chars().any(char::is_control) {
        return Err(invalid_semantic_evidence(&format!("{name} is invalid")));
    }
    Ok(())
}

fn valid_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn valid_semantic_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn invalid_semantic_evidence(reason: &str) -> AgentRuntimeError {
    AgentRuntimeError::InvalidToolCall(format!("semantic evidence is invalid: {reason}"))
}

/// Flattens bounded JSON receipt data into independently citable evidence atoms.
///
/// The first atom always records the overall tool outcome. Leaf values receive
/// deterministic JSON-Pointer-derived identifiers, and incomplete or truncated
/// traversal emits an explicit field-coverage atom so absence cannot be read as
/// a negative fact. This function assumes the receipt envelope already validated
/// its identifiers and timestamps.
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
            let nested_subject = [
                "runtime_id",
                "finding_ref",
                "asset_ref",
                "connector_ref",
                "source_id",
            ]
            .into_iter()
            .find_map(|field| values.get(field).and_then(Value::as_str))
            .or(context.subject_ref);
            let nested_context = AtomizationContext {
                evidence_ref: context.evidence_ref,
                subject_ref: nested_subject,
                observed_at: context.observed_at,
                fresh_until: context.fresh_until,
                complete: context.complete,
            };
            for (key, value) in values {
                let escaped = key.replace('~', "~0").replace('/', "~1");
                if append_value_atoms(
                    &nested_context,
                    &format!("{pointer}/{escaped}"),
                    value,
                    atoms,
                ) {
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

/// Applies a contiguous event batch to a validated session snapshot.
///
/// The reducer rejects schema, session, timestamp, or sequence mismatches before
/// returning the next snapshot. Effect events are treated as audit facts and are
/// never re-executed. The resulting snapshot is compacted and fully revalidated.
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
            SessionEvent::RouteAccepted {
                request_id,
                lane,
                future_observation,
                future_observation_excerpt,
            } => {
                let source_message = next.messages.iter().rev().find(|message| {
                    message.message_ref == format!("operator:{request_id}")
                        && message.role == SessionMessageRole::User
                });
                let future_observation_valid =
                    match (future_observation, future_observation_excerpt.as_deref()) {
                        (
                            FutureObservationDisposition::Delegated
                            | FutureObservationDisposition::Refused,
                            Some(excerpt),
                        ) => {
                            bounded(excerpt, MAX_TEXT_BYTES)
                                && source_message
                                    .is_some_and(|message| message.text.contains(excerpt))
                        }
                        (
                            FutureObservationDisposition::None
                            | FutureObservationDisposition::Inherited,
                            None,
                        ) => true,
                        _ => false,
                    };
                if !bounded(request_id, MAX_TEXT_BYTES)
                    || matches!(lane, ExecutionLane::Ignore | ExecutionLane::Continue)
                    || !future_observation_valid
                    || next.events.iter().any(|event| {
                        matches!(
                            &event.event,
                            SessionEvent::RouteAccepted {
                                request_id: accepted_request_id,
                                ..
                            } if accepted_request_id == request_id
                        )
                    })
                {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "accepted route identity or lane is invalid".into(),
                    ));
                }
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
    compact_session_messages(&mut next.messages);
    validate_session(&next)?;
    Ok(next)
}

/// Drops the oldest conversation messages until count and byte limits are met.
///
/// At least the newest message is retained. The function operates only on model
/// context; it does not alter the append-only event history that preserves audit
/// provenance for removed messages.
pub fn compact_session_messages(messages: &mut Vec<SessionMessage>) {
    let mut retained_bytes = messages
        .iter()
        .map(|message| message.text.len())
        .sum::<usize>();
    if messages.len() <= MAX_SESSION_MESSAGES && retained_bytes <= MAX_SESSION_MESSAGE_BYTES {
        return;
    }
    let mut remove_count = 0;
    while messages.len().saturating_sub(remove_count) > 1
        && (messages.len().saturating_sub(remove_count) > MAX_SESSION_MESSAGES
            || retained_bytes > MAX_SESSION_MESSAGE_BYTES)
    {
        let Some(message) = messages.get(remove_count) else {
            break;
        };
        retained_bytes = retained_bytes.saturating_sub(message.text.len());
        remove_count += 1;
    }
    while messages.len().saturating_sub(remove_count) > 1
        && messages
            .get(remove_count)
            .is_some_and(|message| message.role == SessionMessageRole::Assistant)
    {
        let message = &messages[remove_count];
        retained_bytes = retained_bytes.saturating_sub(message.text.len());
        remove_count += 1;
    }
    if remove_count > 0 {
        messages.drain(..remove_count);
    }
}

/// Runs one session turn using the no-op external journal.
///
/// Use [`run_session_turn_recorded`] when the caller requires an audit sink in
/// addition to the returned event batch. External effects still pass through the
/// same tool descriptors, authorization gates, and receipt validation.
pub async fn run_session_turn(
    model: &dyn SessionAgentModel,
    tools: &dyn SessionTools,
    session: AgentSession,
    input: SessionTurnInput,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    run_session_turn_recorded(model, tools, &NoopSessionJournal, session, input).await
}

/// Runs the bounded plan–observe–draft–review loop and records every accepted event.
///
/// The runtime validates the session and trigger, enforces lane and tool authority,
/// bounds model repair attempts and tool steps, atomizes receipts, and validates
/// every visible claim. It returns either an exact pending-delivery payload or an
/// approval request; transport delivery and session-store append remain caller
/// responsibilities.
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
    let mut plan_progress_index = if resumed {
        resumed_plan_progress_count(&session, &input.request_id)
    } else {
        0
    };
    if matches!(trigger, SessionTurnTrigger::Operator)
        && plan
            .as_ref()
            .is_some_and(|plan| Some(plan.lane) != input.requested_lane)
    {
        return Err(AgentRuntimeError::InvalidRequest(
            "resumed plan lane does not match the durable accepted route".into(),
        ));
    }
    let mut observations = if resumed {
        turn_observations.clone()
    } else {
        recalled_observations_for_trigger(&session, &trigger, assessment_at)
    };
    let current_turn_observation_start = if resumed { 0 } else { observations.len() };
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
    let mut coissued_plan_calls = None;

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
        let decision = if let Some(calls) = coissued_plan_calls.take() {
            SessionModelDecision::InvokeTools { calls }
        } else {
            match model
                .advance(SessionModelTurn {
                    session: session.clone(),
                    trigger: trigger.clone(),
                    assessment_at: input.assessment_at.clone(),
                    requested_lane: input.requested_lane,
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
            }
        };

        let (decision, plan_calls) = match decision {
            SessionModelDecision::EstablishPlanAndInvoke { plan, calls } => {
                (SessionModelDecision::EstablishPlan { plan }, Some(calls))
            }
            decision => (decision, None),
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
                    && input.requested_lane != Some(proposed.lane)
                {
                    record_operating_repair(
                        &mut repairs,
                        &mut repair_feedback,
                        "The research plan lane must exactly match the accepted semantic route for this operator turn."
                            .into(),
                    );
                    continue;
                }
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && let Err(error) =
                        validate_explicit_follow_through(&session, &input, &proposed)
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
                plan_progress_index = 0;
                if matches!(trigger, SessionTurnTrigger::Operator) {
                    let progress_phase = if plan.is_some() {
                        "refining"
                    } else {
                        "scoping"
                    };
                    emit_next_plan_progress(
                        &session,
                        &input.assessment_at,
                        &mut events,
                        &proposed,
                        &mut plan_progress_index,
                        progress_phase,
                        journal,
                    )
                    .await?;
                }
                plan = Some(proposed);
                repairs = 0;
                repair_feedback.clear();
                if let Some(calls) = plan_calls.filter(|calls| !calls.is_empty()) {
                    coissued_plan_calls = Some(calls);
                }
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
                    emit_final_events(
                        &session,
                        &input.assessment_at,
                        &mut events,
                        [SessionEvent::ApprovalRequested {
                            tool_id: call.tool_id.clone(),
                            input_digest: input_digest.clone(),
                        }],
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
                            input_preview: crate::approval_input_preview(&call.input),
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
                if matches!(trigger, SessionTurnTrigger::Operator) {
                    emit_next_plan_progress(
                        &session,
                        &input.assessment_at,
                        &mut events,
                        &established,
                        &mut plan_progress_index,
                        "working",
                        journal,
                    )
                    .await?;
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
                normalize_message_from_grounded_claims(&mut draft);
                let canonical_premise_conversation =
                    normalize_supplied_premise_conversation(&session, &input, &trigger, &mut draft);
                if canonical_premise_conversation
                    && (draft.message.len() > MAX_CONVERSATIONAL_SYNTHESIS_BYTES
                        || draft.message.lines().count() > 6)
                {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        "A premise-based converse answer must be one conversational_synthesis claim containing the complete natural answer, no other visible claim types, at most 1,200 bytes, and at most six lines. Preserve attribution, the independent-verification boundary, one useful implication, and one prospective next check without report scaffolding."
                            .into(),
                    );
                    continue;
                }
                let requested_operating_lane = matches!(
                    input.requested_lane,
                    Some(ExecutionLane::Lookup | ExecutionLane::Investigate | ExecutionLane::Act)
                );
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && ((input.requested_lane == Some(ExecutionLane::Converse)
                        && (plan.is_some() || observations.len() > current_turn_observation_start))
                        || (requested_operating_lane && plan.is_none()))
                {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        "The accepted semantic route is authoritative: converse turns cannot establish or use an evidence plan, and operating turns cannot finish without one."
                            .into(),
                    );
                    continue;
                }
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && draft.state == FinalState::Answered
                    && requested_operating_lane
                    && plan.as_ref().is_some_and(|plan| {
                        !current_required_claims_have_same_turn_evidence(
                            plan,
                            &draft,
                            &observations[current_turn_observation_start..],
                            assessment_at,
                        )
                    })
                {
                    let partial_evidence_covers_every_required_claim =
                        plan.as_ref().is_some_and(|plan| {
                            current_required_claims_have_same_turn_evidence_for_state(
                                plan,
                                &draft,
                                &observations[current_turn_observation_start..],
                                assessment_at,
                                FinalState::Partial,
                            )
                        });
                    if partial_evidence_covers_every_required_claim {
                        draft.state = FinalState::Partial;
                    } else {
                        record_draft_repair(
                            &mut rejected_operating_drafts,
                            &draft,
                            &mut repairs,
                            &mut repair_feedback,
                            "Every answered operating plan requires at least one selected read and successful, complete, fresh same-turn evidence for every required planned claim. Use partial or blocked when that evidence is unavailable."
                                .into(),
                        );
                        continue;
                    }
                }
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
                let canonical_silent_wake = match canonicalize_routine_silent_wake(
                    &session,
                    &trigger,
                    plan.as_ref(),
                    &observations,
                    assessment_at,
                    &mut draft,
                ) {
                    Ok(canonicalized) => canonicalized,
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
                let response_contract_issues =
                    validate_explicit_response_contract(&session, &trigger, &draft);
                if !response_contract_issues.is_empty() {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        response_contract_issues.join(" "),
                    );
                    continue;
                }
                if !canonical_silent_wake && !canonical_premise_conversation {
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
                        if !rejected_reviews
                            .insert((message_digest(&draft.message), issue_signature))
                        {
                            critic_repairs = MAX_CRITIC_REPAIRS + 1;
                            repair_feedback = issues;
                            continue;
                        }
                        critic_repairs += 1;
                        repair_feedback = issues;
                        continue;
                    }
                }
                let mut final_events = Vec::with_capacity(draft.memory_updates.len() + 1);
                final_events.push(SessionEvent::DraftProduced {
                    request_id: input.request_id.clone(),
                    draft: draft.clone(),
                });
                final_events.extend(
                    draft
                        .memory_updates
                        .iter()
                        .cloned()
                        .map(|update| SessionEvent::MemoryRecorded { update }),
                );
                emit_final_events(
                    &session,
                    &input.assessment_at,
                    &mut events,
                    final_events,
                    journal,
                )
                .await?;
                return Ok(SessionTurnOutcome::PendingDelivery {
                    lane: turn_outcome_lane(&input, plan.as_ref()),
                    delivery: draft.delivery,
                    markdown: validated.markdown,
                    final_state: draft.state,
                    evidence_atom_refs: validated.evidence_atom_refs,
                    mission: draft.mission,
                    events,
                });
            }
            SessionModelDecision::EstablishPlanAndInvoke { .. } => {
                unreachable!("coissued plan calls are normalized before decision execution")
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

fn turn_outcome_lane(input: &SessionTurnInput, plan: Option<&ResearchPlan>) -> ExecutionLane {
    if matches!(input.trigger, SessionTurnTrigger::Operator) {
        input.requested_lane.unwrap_or(ExecutionLane::Converse)
    } else {
        plan.map_or(ExecutionLane::Converse, |plan| plan.lane)
    }
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
    let supported = observations
        .iter()
        .filter_map(|observation| {
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
        })
        .collect::<Vec<_>>();
    let failed_reads = observations
        .iter()
        .filter_map(|observation| {
            if observation.result.state != ToolResultState::Failed
                || observation.descriptor.authority_class != ToolAuthorityClass::Observe
                || observation.descriptor.effect_class != ToolEffectClass::Read
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
        })
        .collect::<Vec<_>>();
    let failed_effect = observations.iter().rev().find_map(|observation| {
        if observation.result.state != ToolResultState::Failed
            || (observation.descriptor.authority_class != ToolAuthorityClass::Actuate
                && observation.descriptor.effect_class == ToolEffectClass::Read)
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
        SessionTurnTrigger::Wake { commitment_ref, .. }
            if uncertain_effect.is_none() && failed_effect.is_none() =>
        {
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
                commitment.blocker = Some(if uncertain_effect.is_some() {
                    "The scheduled check encountered an external effect with an unknown outcome."
                        .into()
                } else {
                    "The scheduled check attempted an external effect that failed. It was not retried."
                        .into()
                });
                commitment.wake_at = None;
                mission.status = SessionStatus::Blocked;
            }
            None
        }
        SessionTurnTrigger::Operator if uncertain_effect.is_none() && failed_effect.is_none() => {
            plan.and_then(|plan| plan.follow_through.as_ref())
                .map(|follow_through| {
                    let commitment = planned_commitment(follow_through, assessment_at)?;
                    let wake_at = commitment
                        .wake_at
                        .clone()
                        .expect("a planned commitment always has a wake time");
                    mission.commitments.retain(|candidate| {
                        candidate.commitment_ref != follow_through.commitment_ref
                    });
                    mission.commitments.push(commitment);
                    mission.status = SessionStatus::WaitingForExternal;
                    Ok((follow_through.commitment_ref.clone(), wake_at))
                })
                .transpose()?
        }
        SessionTurnTrigger::Operator => None,
    };
    let mut routine_silent_draft = GroundedDraft {
        state: FinalState::Answered,
        delivery: DeliveryDisposition::Silent,
        message: String::new(),
        claims: Vec::new(),
        coverage_notice: None,
        question: None,
        mission: mission.clone(),
        memory_updates: Vec::new(),
        presentation_ready: true,
    };
    if canonicalize_routine_silent_wake(
        session,
        trigger,
        plan,
        observations,
        assessment_at,
        &mut routine_silent_draft,
    )? {
        validate_wake_completion(
            session,
            &routine_silent_draft,
            trigger,
            assessment_at,
            observations,
        )?;
        validate_plan_completion(plan, &routine_silent_draft)?;
        validate_effect_closure(observations, &routine_silent_draft, assessment_at)?;
        if !validate_explicit_response_contract(session, trigger, &routine_silent_draft).is_empty()
        {
            return Err(AgentRuntimeError::PresentationRepairLimit);
        }
        let validated =
            validate_grounded_draft(session, &routine_silent_draft, observations, assessment_at)?;
        emit_final_events(
            session,
            &input.assessment_at,
            &mut events,
            [SessionEvent::DraftProduced {
                request_id: input.request_id.clone(),
                draft: routine_silent_draft.clone(),
            }],
            journal,
        )
        .await?;
        return Ok(SessionTurnOutcome::PendingDelivery {
            lane: turn_outcome_lane(input, plan),
            delivery: DeliveryDisposition::Silent,
            markdown: validated.markdown,
            final_state: FinalState::Answered,
            evidence_atom_refs: validated.evidence_atom_refs,
            mission: routine_silent_draft.mission,
            events,
        });
    }
    let coverage_boundary = if uncertain_effect.is_some() {
        mission.status = SessionStatus::Blocked;
        CoverageBoundaryKind::ExternalActionOutcomeUnknown
    } else if failed_effect.is_some() {
        mission.status = SessionStatus::Blocked;
        CoverageBoundaryKind::ExternalActionFailed
    } else if rescheduled_wake.is_some() && !failed_reads.is_empty() {
        CoverageBoundaryKind::SourceReadFailedAcceptanceUnverified
    } else if rescheduled_wake.is_some() && !supported.is_empty() {
        CoverageBoundaryKind::PartialReadAcceptanceUnverified
    } else if rescheduled_wake.is_some() {
        CoverageBoundaryKind::MissingObservationAcceptanceUnverified
    } else if !failed_reads.is_empty() && !supported.is_empty() {
        CoverageBoundaryKind::BoundedReadsIncomplete
    } else if !failed_reads.is_empty() {
        CoverageBoundaryKind::BoundedSourceReadsFailed
    } else if !supported.is_empty() {
        CoverageBoundaryKind::AvailableEvidenceIncomplete
    } else {
        CoverageBoundaryKind::NoCurrentAuthoritativeObservation
    };
    let coverage_notice = render_coverage_boundary(coverage_boundary).to_owned();
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
                    content: ClaimContent::CoverageBoundary {
                        boundary: coverage_boundary,
                    },
                },
            ],
        )
    } else if let Some((summary, atom_ref)) = failed_effect {
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
                    content: ClaimContent::CoverageBoundary {
                        boundary: coverage_boundary,
                    },
                },
            ],
        )
    } else if !supported.is_empty() {
        let mut message = String::new();
        let mut claims = Vec::new();
        let mut summaries = BTreeSet::new();
        for (index, (summary, atom_ref)) in supported.iter().enumerate() {
            if !summaries.insert(summary.as_str()) {
                continue;
            }
            let text = if message.is_empty() {
                summary.clone()
            } else {
                format!("\n\n{summary}")
            };
            message.push_str(&text);
            claims.push(GroundedClaim {
                claim_ref: format!("fallback-observation:{}:{index}", input.request_id),
                planned_claim_ref: None,
                text,
                required_for_answer: true,
                content: ClaimContent::Observation {
                    atom_refs: vec![atom_ref.clone()],
                },
            });
        }
        for (index, (summary, atom_ref)) in failed_reads.iter().enumerate() {
            if !summaries.insert(summary.as_str()) {
                continue;
            }
            let text = format!("\n\n{summary}");
            message.push_str(&text);
            claims.push(GroundedClaim {
                claim_ref: format!("fallback-failed-read:{}:{index}", input.request_id),
                planned_claim_ref: None,
                text,
                required_for_answer: true,
                content: ClaimContent::Observation {
                    atom_refs: vec![atom_ref.clone()],
                },
            });
        }
        let notice = format!("\n\n{coverage_notice}");
        message.push_str(&notice);
        claims.push(GroundedClaim {
            claim_ref: format!("fallback-boundary:{}", input.request_id),
            planned_claim_ref: None,
            text: notice,
            required_for_answer: true,
            content: ClaimContent::CoverageBoundary {
                boundary: coverage_boundary,
            },
        });
        (FinalState::Partial, message, claims)
    } else if !failed_reads.is_empty() {
        let mut message = String::new();
        let mut claims = Vec::new();
        let mut summaries = BTreeSet::new();
        for (index, (summary, atom_ref)) in failed_reads.iter().enumerate() {
            if !summaries.insert(summary.as_str()) {
                continue;
            }
            let text = if message.is_empty() {
                summary.clone()
            } else {
                format!("\n\n{summary}")
            };
            message.push_str(&text);
            claims.push(GroundedClaim {
                claim_ref: format!("fallback-failed-read:{}:{index}", input.request_id),
                planned_claim_ref: None,
                text,
                required_for_answer: true,
                content: ClaimContent::Observation {
                    atom_refs: vec![atom_ref.clone()],
                },
            });
        }
        let notice = format!("\n\n{coverage_notice}");
        message.push_str(&notice);
        claims.push(GroundedClaim {
            claim_ref: format!("fallback-boundary:{}", input.request_id),
            planned_claim_ref: None,
            text: notice,
            required_for_answer: true,
            content: ClaimContent::CoverageBoundary {
                boundary: coverage_boundary,
            },
        });
        (FinalState::Blocked, message, claims)
    } else {
        (
            FinalState::Blocked,
            coverage_notice.clone(),
            vec![GroundedClaim {
                claim_ref: format!("fallback-boundary:{}", input.request_id),
                planned_claim_ref: None,
                text: coverage_notice.clone(),
                required_for_answer: true,
                content: ClaimContent::CoverageBoundary {
                    boundary: coverage_boundary,
                },
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
    if !validate_explicit_response_contract(session, trigger, &draft).is_empty() {
        return Err(AgentRuntimeError::PresentationRepairLimit);
    }
    let validated = validate_grounded_draft(session, &draft, observations, assessment_at)?;
    emit_final_events(
        session,
        &input.assessment_at,
        &mut events,
        [SessionEvent::DraftProduced {
            request_id: input.request_id.clone(),
            draft: draft.clone(),
        }],
        journal,
    )
    .await?;
    Ok(SessionTurnOutcome::PendingDelivery {
        lane: turn_outcome_lane(input, plan),
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
    let mut source_subject_refs = BTreeSet::new();
    if let Some(checkpoint) = prior_commitment_checkpoint(session, trigger) {
        for tool_id in &commitment.required_tool_ids {
            if let Some(subject_refs) = checkpoint
                .observations
                .iter()
                .rev()
                .find(|observation| observation.tool_id == *tool_id)
                .and_then(|observation| observation.source_subject_refs.as_ref())
            {
                source_subject_refs.extend(
                    subject_refs
                        .iter()
                        .filter(|subject_ref| !subject_ref.trim().is_empty())
                        .cloned(),
                );
            }
        }
    }
    let source_subject_refs = source_subject_refs.into_iter().collect::<Vec<_>>();
    let plan_subject_refs = if source_subject_refs.is_empty() {
        vec![commitment_ref.clone()]
    } else {
        source_subject_refs
    };
    let claims = vec![PlannedClaim {
        claim_ref: format!("wake-claim:{commitment_ref}:verification"),
        question: commitment
            .verification
            .clone()
            .or_else(|| commitment.acceptance_criteria.first().cloned())
            .unwrap_or_else(|| "Determine the current commitment state.".into()),
        required: true,
        subject_refs: plan_subject_refs.clone(),
        source_candidates: commitment.required_tool_ids.clone(),
    }];
    let mut stop_conditions = commitment.acceptance_criteria.clone();
    if let Some(verification) = &commitment.verification {
        stop_conditions.push(verification.clone());
    }
    Some(ResearchPlan {
        decision: format!("Execute scheduled commitment {commitment_ref}."),
        lane: ExecutionLane::Investigate,
        resolved_entities: plan_subject_refs,
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
            if !matches!(
                input.requested_lane,
                Some(
                    ExecutionLane::Converse
                        | ExecutionLane::Lookup
                        | ExecutionLane::Investigate
                        | ExecutionLane::Act
                )
            ) {
                return Err(AgentRuntimeError::InvalidRequest(
                    "operator turn requires one accepted semantic route lane".into(),
                ));
            }
            let latest = session.messages.last().ok_or_else(|| {
                AgentRuntimeError::InvalidRequest(
                    "operator turn requires a queued user message".into(),
                )
            })?;
            if latest.role != SessionMessageRole::User
                || latest.actor_ref != input.actor_ref
                || latest.message_ref != format!("operator:{}", input.request_id)
            {
                return Err(AgentRuntimeError::InvalidRequest(
                    "turn identity does not match the latest queued user message".into(),
                ));
            }
            let accepted_lane = session
                .events
                .iter()
                .rev()
                .find_map(|event| match &event.event {
                    SessionEvent::RouteAccepted {
                        request_id, lane, ..
                    } if request_id == &input.request_id => Some(*lane),
                    _ => None,
                });
            let Some(accepted_lane) = accepted_lane else {
                return Err(AgentRuntimeError::InvalidRequest(
                    "operator turn requires a durable accepted route".into(),
                ));
            };
            if Some(accepted_lane) != input.requested_lane {
                return Err(AgentRuntimeError::InvalidRequest(
                    "turn route does not match the durable accepted route".into(),
                ));
            }
        }
        SessionTurnTrigger::Wake {
            commitment_ref,
            occurrence_ref,
        } => {
            if input.requested_lane.is_some()
                || input.actor_ref != "cerebro-scheduler"
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

/// Resolves the request text the model should answer for the current trigger.
///
/// Operator turns use the newest queued user message. Wake turns synthesize a
/// bounded instruction from the matching durable commitment rather than treating
/// scheduler metadata as new operator text.
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
    let attention = assess_wake_attention(
        session,
        trigger,
        checkpoint.as_ref(),
        observations,
        assessment_at,
    )
    .ok_or_else(|| {
        AgentRuntimeError::InvalidFinal(
            "the wake does not have a typed attention decision for its exact commitment".into(),
        )
    })?;
    if !attention.missing_required_tool_ids.is_empty() {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "scheduled wake must invoke its required tools with the exact prior completed-check input before finishing: {}. Copy the matching tool input from prior_commitment_checkpoint.observations.",
            attention.missing_required_tool_ids.join(", ")
        )));
    }
    if !attention.unhealthy_required_tool_ids.is_empty()
        && (draft.delivery != DeliveryDisposition::Visible || draft.state == FinalState::Answered)
    {
        return Err(AgentRuntimeError::InvalidFinal(format!(
            "failed, incomplete, or stale required observations must produce a visible partial or blocked update: {}",
            attention.unhealthy_required_tool_ids.join(", ")
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
    let closed = matches!(
        next.status,
        CommitmentStatus::Completed | CommitmentStatus::Cancelled
    );
    if closed {
        if !attention.acceptance_met {
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
    if attention.unhealthy_required_tool_ids.is_empty() {
        let required_delivery = match attention.disposition {
            WakeAttentionDisposition::RoutineSilent => DeliveryDisposition::Silent,
            WakeAttentionDisposition::VisibleAcceptance
            | WakeAttentionDisposition::VisibleAttention
            | WakeAttentionDisposition::VisibleUnhealthy => DeliveryDisposition::Visible,
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

fn observation_condition_matches_selected(
    condition: &ObservationCondition,
    observations: &[&ToolObservation],
) -> bool {
    observations.iter().any(|observation| {
        observation.call.tool_id == condition.tool_id
            && observation.result.state == ToolResultState::Succeeded
            && observation.result.data.pointer(&condition.data_pointer) == Some(&condition.equals)
    })
}

#[cfg(test)]
fn observation_condition_transitioned(
    condition: &ObservationCondition,
    observations: &[ToolObservation],
    checkpoint: Option<&CommitmentCheckpoint>,
) -> bool {
    observations.iter().any(|observation| {
        if observation.call.tool_id != condition.tool_id
            || observation.result.state != ToolResultState::Succeeded
            || observation.result.data.pointer(&condition.data_pointer) != Some(&condition.equals)
        {
            return false;
        }
        let input_digest = observation.call.input_digest();
        checkpoint.is_some_and(|checkpoint| {
            checkpoint.observations.iter().rev().any(|prior| {
                prior.tool_id == condition.tool_id
                    && prior.input_digest == input_digest
                    && prior.data.pointer(&condition.data_pointer) != Some(&condition.equals)
            })
        })
    })
}

fn observation_condition_transitioned_selected(
    condition: &ObservationCondition,
    observations: &[&ToolObservation],
    checkpoint: Option<&CommitmentCheckpoint>,
) -> bool {
    observations.iter().any(|observation| {
        if observation.call.tool_id != condition.tool_id
            || observation.result.state != ToolResultState::Succeeded
            || observation.result.data.pointer(&condition.data_pointer) != Some(&condition.equals)
        {
            return false;
        }
        let input_digest = observation.call.input_digest();
        checkpoint.is_some_and(|checkpoint| {
            checkpoint.observations.iter().rev().any(|prior| {
                prior.tool_id == condition.tool_id
                    && prior.input_digest == input_digest
                    && prior.data.pointer(&condition.data_pointer) != Some(&condition.equals)
            })
        })
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
    let decision =
        assess_wake_attention(session, trigger, checkpoint, observations, assessment_at)?;

    let mut scalar_comparisons = Vec::new();
    for current_observation in &decision.required_observations {
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
        required_observations_present: decision.missing_required_tool_ids.is_empty(),
        required_observations_healthy: decision.unhealthy_required_tool_ids.is_empty(),
        acceptance_met: decision.acceptance_met,
        matched_attention_signals: decision.matched_attention_signals,
        scalar_comparisons,
    })
}

fn assess_wake_attention<'a>(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
    checkpoint: Option<&CommitmentCheckpoint>,
    observations: &'a [ToolObservation],
    assessment_at: OffsetDateTime,
) -> Option<WakeAttentionDecision<'a>> {
    let SessionTurnTrigger::Wake { commitment_ref, .. } = trigger else {
        return None;
    };
    let commitment = session
        .mission
        .commitments
        .iter()
        .find(|commitment| commitment.commitment_ref == *commitment_ref)?;
    let mut required_observations = Vec::new();
    let mut missing_required_tool_ids = Vec::new();
    let mut unhealthy_required_tool_ids = Vec::new();
    for tool_id in &commitment.required_tool_ids {
        let checkpoint_observation = checkpoint
            .filter(|checkpoint| checkpoint.commitment_ref == *commitment_ref)
            .and_then(|checkpoint| {
                checkpoint
                    .observations
                    .iter()
                    .rev()
                    .find(|observation| observation.tool_id == *tool_id)
            });
        let Some(checkpoint_observation) = checkpoint_observation else {
            missing_required_tool_ids.push(tool_id.clone());
            unhealthy_required_tool_ids.push(tool_id.clone());
            continue;
        };
        if checkpoint_observation.input_digest.trim().is_empty() {
            missing_required_tool_ids.push(tool_id.clone());
            unhealthy_required_tool_ids.push(tool_id.clone());
            continue;
        }
        let current = observations.iter().rev().find(|observation| {
            observation.call.tool_id == *tool_id
                && observation.call.input_digest() == checkpoint_observation.input_digest
        });
        match current {
            Some(observation) => {
                let current_subjects = observation_source_scope_subject_refs(observation);
                let scope_matches = checkpoint_observation
                    .source_subject_refs
                    .as_ref()
                    .zip(current_subjects.as_ref())
                    .is_some_and(|(expected, current)| {
                        !expected
                            .iter()
                            .any(|subject_ref| subject_ref.trim().is_empty())
                            && expected.iter().collect::<BTreeSet<_>>()
                                == current.iter().collect::<BTreeSet<_>>()
                    });
                if !observation_is_complete_and_fresh(observation, assessment_at) || !scope_matches
                {
                    unhealthy_required_tool_ids.push(tool_id.clone());
                }
                required_observations.push(observation);
            }
            None => {
                missing_required_tool_ids.push(tool_id.clone());
                unhealthy_required_tool_ids.push(tool_id.clone());
            }
        }
    }
    let required_observations_healthy = unhealthy_required_tool_ids.is_empty();
    let acceptance_met = required_observations_healthy
        && commitment.attention_policy.as_ref().is_some_and(|policy| {
            !policy.acceptance_all.is_empty()
                && policy.acceptance_all.iter().all(|condition| {
                    observation_condition_matches_selected(condition, &required_observations)
                })
        });
    let matched_attention_signals = if required_observations_healthy && !acceptance_met {
        commitment
            .attention_policy
            .as_ref()
            .map(|policy| {
                let alerts = policy.alert_any.iter().filter(|condition| {
                    observation_condition_matches_selected(condition, &required_observations)
                });
                let notifications = policy.notify_on_change.iter().filter(|condition| {
                    observation_condition_transitioned_selected(
                        condition,
                        &required_observations,
                        checkpoint,
                    )
                });
                alerts.chain(notifications).cloned().collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let has_unhealthy_observation = observations
        .iter()
        .any(|observation| !observation_is_complete_and_fresh(observation, assessment_at));
    let disposition = if !required_observations_healthy || has_unhealthy_observation {
        WakeAttentionDisposition::VisibleUnhealthy
    } else if acceptance_met {
        WakeAttentionDisposition::VisibleAcceptance
    } else if !matched_attention_signals.is_empty() {
        WakeAttentionDisposition::VisibleAttention
    } else {
        WakeAttentionDisposition::RoutineSilent
    };
    Some(WakeAttentionDecision {
        required_observations,
        missing_required_tool_ids,
        unhealthy_required_tool_ids,
        acceptance_met,
        matched_attention_signals,
        disposition,
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
            let matching_baseline_notifications = policy
                .notify_on_change
                .iter()
                .filter(|condition| observation_condition_matches(condition, observations))
                .collect::<Vec<_>>();
            if !matching_baseline_notifications.is_empty() {
                let matching = serde_json::to_string(&matching_baseline_notifications)
                    .unwrap_or_else(|_| "the matching notification conditions".into());
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "the new commitment has notify_on_change conditions already true at baseline: {matching}. Keep only future operator-requested decision values so a later typed transition can be proven."
                )));
            }
            let covered = policy
                .acceptance_all
                .iter()
                .chain(&policy.alert_any)
                .chain(&policy.notify_on_change)
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
    let boundary = match draft.state {
        FinalState::Partial => CoverageBoundaryKind::PartialConclusionUnsupported,
        FinalState::Blocked => CoverageBoundaryKind::BlockedMissingAuthoritativeEvidence,
        _ => unreachable!("coverage normalization is restricted to partial and blocked drafts"),
    };
    let notice = render_coverage_boundary(boundary).to_owned();
    draft.coverage_notice = Some(notice.clone());
    if !draft.message.contains(&notice) {
        let visible_notice = format!("\n\n{notice}");
        draft.message.push_str(&visible_notice);
        draft.claims.push(GroundedClaim {
            claim_ref: format!("claim:normalized-coverage:{}", draft.claims.len() + 1),
            planned_claim_ref: None,
            text: visible_notice,
            required_for_answer: true,
            content: ClaimContent::CoverageBoundary { boundary },
        });
    }
}

fn normalize_message_from_grounded_claims(draft: &mut GroundedDraft) {
    if draft.claims.is_empty() {
        return;
    }
    draft.message = draft
        .claims
        .iter()
        .map(|claim| claim.text.as_str())
        .collect();
}

fn normalize_supplied_premise_conversation(
    session: &AgentSession,
    input: &SessionTurnInput,
    trigger: &SessionTurnTrigger,
    draft: &mut GroundedDraft,
) -> bool {
    if !matches!(trigger, SessionTurnTrigger::Operator)
        || input.requested_lane != Some(ExecutionLane::Converse)
        || draft.state != FinalState::Answered
    {
        return false;
    }
    let Some((index, newest_operator_message)) =
        session
            .messages
            .iter()
            .enumerate()
            .rev()
            .find(|(_, message)| {
                message.role == SessionMessageRole::User && message.actor_ref == input.actor_ref
            })
    else {
        return false;
    };
    if !crate::request_reasons_from_supplied_operational_premises(&newest_operator_message.text) {
        return false;
    }
    trim_passive_premise_handback(&mut draft.message);
    let first_source_index = (index + 1).saturating_sub(MAX_CONVERSATIONAL_SYNTHESIS_SOURCES);
    draft.claims = vec![GroundedClaim {
        claim_ref: "claim:premise-conversation".into(),
        planned_claim_ref: None,
        text: draft.message.clone(),
        required_for_answer: true,
        content: ClaimContent::ConversationalSynthesis {
            source_message_sequences: (first_source_index..=index)
                .map(|source_index| (source_index + 1) as u64)
                .collect(),
            source_atom_refs: Vec::new(),
        },
    }];
    true
}

fn trim_passive_premise_handback(message: &mut String) {
    let normalized = message.to_ascii_lowercase();
    let handback_start = [
        " if you point me",
        " if you want",
        " let me know",
        " want me to",
        " would you like me",
        " do you want me",
        " say the word",
        " tell me if you want",
    ]
    .iter()
    .filter_map(|marker| normalized.find(marker))
    .filter(|index| *index >= 120)
    .min();
    let Some(handback_start) = handback_start else {
        return;
    };
    message.truncate(handback_start);
    let trimmed_len = message
        .trim_end_matches(|character: char| {
            character.is_whitespace() || matches!(character, '-' | '–' | '—' | ',' | ';' | ':')
        })
        .len();
    message.truncate(trimmed_len);
    if !message.ends_with('.') && !message.ends_with('!') && !message.ends_with('?') {
        message.push('.');
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

fn canonicalize_routine_silent_wake(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
    plan: Option<&ResearchPlan>,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
    draft: &mut GroundedDraft,
) -> Result<bool, AgentRuntimeError> {
    let SessionTurnTrigger::Wake { commitment_ref, .. } = trigger else {
        return Ok(false);
    };
    let checkpoint = prior_commitment_checkpoint(session, trigger);
    let Some(attention) = assess_wake_attention(
        session,
        trigger,
        checkpoint.as_ref(),
        observations,
        assessment_at,
    ) else {
        return Ok(false);
    };
    if attention.disposition != WakeAttentionDisposition::RoutineSilent {
        return Ok(false);
    }
    let current = session
        .mission
        .commitments
        .iter()
        .find(|commitment| commitment.commitment_ref == *commitment_ref)
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "routine wake completion requires its exact durable commitment".into(),
            )
        })?;
    let next_index = draft
        .mission
        .commitments
        .iter()
        .position(|commitment| commitment.commitment_ref == *commitment_ref)
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "routine wake completion must preserve and reschedule its exact commitment".into(),
            )
        })?;
    let next_wake_at = draft.mission.commitments[next_index]
        .wake_at
        .clone()
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "routine wake completion requires a replacement due time".into(),
            )
        })?;
    let next_wake = OffsetDateTime::parse(&next_wake_at, &Rfc3339).map_err(|_| {
        AgentRuntimeError::InvalidFinal(
            "routine wake completion has an invalid replacement due time".into(),
        )
    })?;
    if next_wake <= assessment_at {
        return Err(AgentRuntimeError::InvalidFinal(
            "routine wake completion must move its exact commitment to a future due time".into(),
        ));
    }

    let required_plan_claims = plan
        .into_iter()
        .flat_map(|plan| plan.claims.iter())
        .filter(|claim| claim.required)
        .collect::<Vec<_>>();
    if required_plan_claims.len() != 1 {
        return Err(AgentRuntimeError::InvalidFinal(
            "routine wake completion requires exactly one host-derived verification claim".into(),
        ));
    }
    let planned_claim_ref = required_plan_claims[0].claim_ref.clone();
    let mut claims = Vec::new();
    let mut message = String::new();
    for (index, observation) in attention.required_observations.iter().enumerate() {
        let summary = observation.result.summary.trim();
        if summary.is_empty()
            || summary.len() > 1_500
            || summary
                .chars()
                .any(|character| character.is_control() && character != '\n')
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "routine wake observation summary is not safe for its durable internal audit"
                    .into(),
            ));
        }
        let atom_ref = observation
            .result
            .evidence
            .iter()
            .flat_map(|evidence| &evidence.atoms)
            .find(|atom| {
                atom.complete
                    && atom.fresh_until.as_deref().is_some_and(|fresh_until| {
                        OffsetDateTime::parse(fresh_until, &Rfc3339)
                            .is_ok_and(|fresh_until| fresh_until >= assessment_at)
                    })
                    && matches!(
                        &atom.assertion,
                        EvidenceAssertion::ToolOutcome { state, summary }
                            if *state == observation.result.state
                                && summary.trim() == observation.result.summary.trim()
                    )
            })
            .map(|atom| atom.atom_ref.clone())
            .ok_or_else(|| {
                AgentRuntimeError::InvalidFinal(
                    "routine wake completion requires a complete fresh ToolOutcome atom for every required observation"
                        .into(),
                )
            })?;
        let text = if message.is_empty() {
            summary.to_owned()
        } else {
            format!("\n\n{summary}")
        };
        message.push_str(&text);
        claims.push(GroundedClaim {
            claim_ref: format!("wake-observation:{commitment_ref}:{index}"),
            planned_claim_ref: (index == 0).then_some(planned_claim_ref.clone()),
            text,
            required_for_answer: true,
            content: ClaimContent::Observation {
                atom_refs: vec![atom_ref],
            },
        });
    }

    let mut canonical_commitment = current.clone();
    canonical_commitment.status = CommitmentStatus::Waiting;
    canonical_commitment.blocker = None;
    canonical_commitment.wake_at = Some(next_wake_at);
    let follow_up = render_commitment_claim(&canonical_commitment).ok_or_else(|| {
        AgentRuntimeError::InvalidFinal(
            "routine wake completion could not render its replacement due time".into(),
        )
    })?;
    let follow_up = format!("\n\n{follow_up}");
    message.push_str(&follow_up);
    claims.push(GroundedClaim {
        claim_ref: format!("wake-commitment:{commitment_ref}"),
        planned_claim_ref: None,
        text: follow_up,
        required_for_answer: true,
        content: ClaimContent::Commitment {
            commitment_ref: commitment_ref.clone(),
        },
    });
    draft.mission.commitments[next_index] = canonical_commitment;
    draft.mission.status = SessionStatus::WaitingForExternal;
    draft.state = FinalState::Answered;
    draft.delivery = DeliveryDisposition::Silent;
    draft.message = message;
    draft.claims = claims;
    draft.coverage_notice = None;
    draft.question = None;
    draft.memory_updates.clear();
    draft.presentation_ready = true;
    Ok(true)
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

fn observation_source_scope_subject_refs(observation: &ToolObservation) -> Option<Vec<String>> {
    let tool_outcome_atoms = observation
        .result
        .evidence
        .iter()
        .flat_map(|evidence| &evidence.atoms)
        .filter(|atom| matches!(&atom.assertion, EvidenceAssertion::ToolOutcome { .. }))
        .collect::<Vec<_>>();
    if tool_outcome_atoms.is_empty() {
        return None;
    }
    Some(
        tool_outcome_atoms
            .into_iter()
            .filter_map(|atom| atom.subject_ref.as_deref())
            .filter(|subject_ref| !subject_ref.trim().is_empty())
            .map(str::to_owned)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
    )
}

fn current_required_claims_have_same_turn_evidence(
    plan: &ResearchPlan,
    draft: &GroundedDraft,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
) -> bool {
    current_required_claims_have_same_turn_evidence_for_state(
        plan,
        draft,
        observations,
        assessment_at,
        draft.state,
    )
}

fn current_required_claims_have_same_turn_evidence_for_state(
    plan: &ResearchPlan,
    draft: &GroundedDraft,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
    final_state: FinalState,
) -> bool {
    let required = plan
        .claims
        .iter()
        .filter(|planned| planned.required)
        .collect::<Vec<_>>();
    !required.is_empty()
        && required.into_iter().all(|planned| {
            let expected_subjects = if planned.subject_refs.is_empty() {
                plan.resolved_entities
                    .first()
                    .into_iter()
                    .collect::<Vec<_>>()
            } else {
                planned.subject_refs.iter().collect::<Vec<_>>()
            };
            !expected_subjects.is_empty()
                && expected_subjects.into_iter().all(|expected_subject| {
                    observations.iter().any(|observation| {
                        planned
                            .source_candidates
                            .contains(&observation.call.tool_id)
                            && draft.claims.iter().any(|claim| {
                                claim.planned_claim_ref.as_deref()
                                    == Some(planned.claim_ref.as_str())
                                    && claim_evidence_atom_refs(&claim.content).iter().any(
                                        |atom_ref| {
                                            observation.result.evidence.iter().any(|evidence| {
                                                evidence_record_supports_current_draft(
                                                    evidence,
                                                    observation.result.state,
                                                    final_state,
                                                    assessment_at,
                                                ) && evidence.atoms.iter().any(|atom| {
                                                    atom.atom_ref == *atom_ref
                                                        && planned_claim_subject_matches(
                                                            expected_subject,
                                                            atom,
                                                        )
                                                })
                                            })
                                        },
                                    )
                            })
                    })
                })
        })
}

fn evidence_record_supports_current_draft(
    evidence: &EvidenceRecord,
    result_state: ToolResultState,
    final_state: FinalState,
    assessment_at: OffsetDateTime,
) -> bool {
    let admissible_state = match final_state {
        FinalState::Answered => result_state == ToolResultState::Succeeded,
        FinalState::Partial | FinalState::Blocked => matches!(
            result_state,
            ToolResultState::Succeeded | ToolResultState::Partial
        ),
        FinalState::NeedsInput => false,
    };
    let blocked_failure = final_state == FinalState::Blocked
        && matches!(
            result_state,
            ToolResultState::Failed | ToolResultState::OutcomeUnknown
        )
        && evidence.atoms.iter().any(|atom| {
            matches!(
                &atom.assertion,
                EvidenceAssertion::ToolOutcome { state, .. } if *state == result_state
            )
        });
    (admissible_state || blocked_failure)
        && evidence.complete
        && evidence.fresh_until.as_deref().is_some_and(|fresh_until| {
            OffsetDateTime::parse(fresh_until, &Rfc3339)
                .is_ok_and(|fresh_until| fresh_until >= assessment_at)
        })
}

fn planned_claim_subject_matches(expected_subject: &str, atom: &EvidenceAtom) -> bool {
    atom.subject_ref.as_deref() == Some(expected_subject)
}

fn claim_evidence_atom_refs(content: &ClaimContent) -> &[String] {
    match content {
        ClaimContent::Observation { atom_refs } | ClaimContent::Derivation { atom_refs, .. } => {
            atom_refs
        }
        ClaimContent::Recommendation {
            rationale_atom_refs,
            ..
        } => rationale_atom_refs,
        ClaimContent::Hypothesis {
            supporting_atom_refs,
            ..
        } => supporting_atom_refs,
        ClaimContent::HistoricalContext { atom_ref, .. } => std::slice::from_ref(atom_ref),
        ClaimContent::ConversationalSynthesis {
            source_atom_refs, ..
        } => source_atom_refs,
        ClaimContent::OperatorContext { .. }
        | ClaimContent::RhetoricalMove { .. }
        | ClaimContent::RetainedPlan { .. }
        | ClaimContent::Commitment { .. }
        | ClaimContent::StableExplanation { .. }
        | ClaimContent::CoverageBoundary { .. }
        | ClaimContent::Question { .. } => &[],
    }
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

fn resumed_plan_progress_count(session: &AgentSession, request_id: &str) -> usize {
    let Some(started_index) = session.events.iter().rposition(|event| {
        matches!(
            &event.event,
            SessionEvent::TurnStarted {
                request_id: started,
            } if started == request_id
        )
    }) else {
        return 0;
    };
    let plan_index = session.events[started_index..]
        .iter()
        .rposition(|event| matches!(event.event, SessionEvent::PlanEstablished { .. }))
        .map_or(started_index, |index| started_index + index);
    session.events[plan_index + 1..]
        .iter()
        .take_while(|event| !matches!(event.event, SessionEvent::PlanEstablished { .. }))
        .filter(|event| matches!(event.event, SessionEvent::Progressed { .. }))
        .count()
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
                            source_subject_refs: observation_source_scope_subject_refs(observation),
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

async fn emit_next_plan_progress(
    session: &AgentSession,
    occurred_at: &str,
    events: &mut Vec<SessionEventRecord>,
    plan: &ResearchPlan,
    next_index: &mut usize,
    phase: &str,
    journal: &dyn SessionJournal,
) -> Result<(), AgentRuntimeError> {
    let Some(status) = plan.user_visible_work.get(*next_index) else {
        return Ok(());
    };
    emit_event(
        session,
        occurred_at,
        events,
        SessionEvent::Progressed {
            phase: phase.into(),
            status: status.trim().into(),
        },
        journal,
    )
    .await?;
    *next_index += 1;
    Ok(())
}

async fn emit_final_events(
    session: &AgentSession,
    occurred_at: &str,
    events: &mut Vec<SessionEventRecord>,
    final_events: impl IntoIterator<Item = SessionEvent>,
    journal: &dyn SessionJournal,
) -> Result<(), AgentRuntimeError> {
    let first = events.len();
    for event in final_events {
        push_event(session, occurred_at, events, event);
    }
    if first == events.len() {
        return Err(AgentRuntimeError::InvalidRequest(
            "turn finalization requires at least one event".into(),
        ));
    }
    journal.finalize(&events[first..]).await
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
        data: json!({
            "error_kind": "capability_invocation_failed",
            "retryable": false,
            "operator_action": "Continue with another bounded capability or inspect provider availability before retrying."
        }),
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

fn validate_explicit_response_contract(
    session: &AgentSession,
    trigger: &SessionTurnTrigger,
    draft: &GroundedDraft,
) -> Vec<String> {
    if !matches!(trigger, SessionTurnTrigger::Operator) {
        return Vec::new();
    }
    let Some(request) = session
        .messages
        .iter()
        .rev()
        .find(|message| message.role == SessionMessageRole::User)
        .map(|message| message.text.to_lowercase())
    else {
        return Vec::new();
    };

    let mut issues = Vec::new();
    if (request.contains("no headings") || request.contains("without headings"))
        && contains_slack_heading(&draft.message)
    {
        issues.push("the operator explicitly requested no headings".into());
    }
    if (request.contains("no bullets")
        || request.contains("without bullets")
        || request.contains("no headings or bullets")
        || request.contains("without headings or bullets"))
        && contains_list_item(&draft.message)
    {
        issues.push("the operator explicitly requested no bullets".into());
    }
    if let Some(expected) = requested_bullet_count(&request) {
        let actual = visible_prose_lines(&draft.message)
            .into_iter()
            .filter(|line| is_list_item(line))
            .count();
        if actual != expected {
            issues.push(format!(
                "the operator requested exactly {expected} bullets, but the response contains {actual}"
            ));
        }
    }
    if let Some((minimum, maximum)) = requested_sentence_range(&request) {
        let actual = sentence_count(&draft.message);
        if actual < minimum || actual > maximum {
            let expected = if minimum == maximum {
                minimum.to_string()
            } else {
                format!("{minimum} to {maximum}")
            };
            issues.push(format!(
                "the operator requested {expected} sentences, but the response contains {actual}"
            ));
        }
    }
    if let Some(maximum) = requested_maximum(&request, "word", "words") {
        let actual = draft.message.split_whitespace().count();
        if actual > maximum {
            issues.push(format!(
                "the operator requested at most {maximum} words, but the response contains {actual}"
            ));
        }
    }
    if let Some(maximum) = requested_maximum(&request, "character", "characters") {
        let actual = draft.message.chars().count();
        if actual > maximum {
            issues.push(format!(
                "the operator requested at most {maximum} characters, but the response contains {actual}"
            ));
        }
    }
    issues
}

fn requested_sentence_range(request: &str) -> Option<(usize, usize)> {
    const COUNTS: [(&str, usize); 10] = [
        ("one", 1),
        ("two", 2),
        ("three", 3),
        ("four", 4),
        ("five", 5),
        ("six", 6),
        ("seven", 7),
        ("eight", 8),
        ("nine", 9),
        ("ten", 10),
    ];
    if request.contains("a sentence or two") || request.contains("one or two sentences") {
        return Some((1, 2));
    }
    for (word, count) in COUNTS {
        if request.contains(&format!("exactly {word} sentences"))
            || request.contains(&format!("{word} plain sentences"))
            || request.contains(&format!("in {word} sentences"))
        {
            return Some((count, count));
        }
    }
    for count in 1..=10 {
        if request.contains(&format!("exactly {count} sentences"))
            || request.contains(&format!("in {count} sentences"))
        {
            return Some((count, count));
        }
    }
    None
}

fn requested_bullet_count(request: &str) -> Option<usize> {
    const COUNTS: [(&str, usize); 6] = [
        ("one", 1),
        ("two", 2),
        ("three", 3),
        ("four", 4),
        ("five", 5),
        ("six", 6),
    ];
    for (word, count) in COUNTS {
        if request.contains(&format!("{word} bullets"))
            || request.contains(&format!("{word} short bullets"))
        {
            return Some(count);
        }
    }
    for count in 1..=6 {
        if request.contains(&format!("{count} bullets")) {
            return Some(count);
        }
    }
    None
}

fn requested_maximum(request: &str, singular: &str, plural: &str) -> Option<usize> {
    let tokens = request
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    for index in 0..tokens.len() {
        if tokens.get(index) == Some(&"under")
            && let (Some(number), Some(unit)) = (tokens.get(index + 1), tokens.get(index + 2))
            && (*unit == singular || *unit == plural)
            && let Ok(limit) = number.parse::<usize>()
        {
            return Some(limit.saturating_sub(1));
        }
        if tokens.get(index) == Some(&"at")
            && tokens.get(index + 1) == Some(&"most")
            && let (Some(number), Some(unit)) = (tokens.get(index + 2), tokens.get(index + 3))
            && (*unit == singular || *unit == plural)
            && let Ok(limit) = number.parse::<usize>()
        {
            return Some(limit);
        }
        if tokens.get(index) == Some(&"no")
            && tokens.get(index + 1) == Some(&"more")
            && tokens.get(index + 2) == Some(&"than")
            && let (Some(number), Some(unit)) = (tokens.get(index + 3), tokens.get(index + 4))
            && (*unit == singular || *unit == plural)
            && let Ok(limit) = number.parse::<usize>()
        {
            return Some(limit);
        }
    }
    None
}

fn contains_slack_heading(message: &str) -> bool {
    visible_prose_lines(message).into_iter().any(|line| {
        let line = line.trim();
        (line.starts_with('#') && line.as_bytes().get(1) == Some(&b' '))
            || (line.len() < 100
                && line.starts_with('*')
                && line.ends_with('*')
                && !line[1..line.len() - 1].contains('*')
                && !line.ends_with(".*")
                && !line.ends_with("!*"))
    })
}

fn contains_list_item(message: &str) -> bool {
    visible_prose_lines(message).into_iter().any(is_list_item)
}

fn is_list_item(line: &str) -> bool {
    let line = line.trim_start();
    if line.starts_with("- ")
        || line.starts_with("* ")
        || line.starts_with("+ ")
        || line.starts_with("• ")
    {
        return true;
    }
    let digits = line
        .bytes()
        .take_while(|byte| byte.is_ascii_digit())
        .count();
    digits > 0
        && matches!(
            line.as_bytes().get(digits..digits + 2),
            Some(b". ") | Some(b") ")
        )
}

fn sentence_count(message: &str) -> usize {
    let prose = visible_prose_lines(message).join("\n");
    let prose = ["e.g.", "i.e.", "u.s.", "U.S."]
        .into_iter()
        .fold(prose, |value, abbreviation| {
            value.replace(abbreviation, &abbreviation.replace('.', "∯"))
        });
    let mut count = 0;
    let mut has_text = false;
    let mut characters = prose.chars().peekable();
    while let Some(character) = characters.next() {
        if !character.is_whitespace() {
            has_text = true;
        }
        if matches!(character, '.' | '!' | '?') {
            while characters
                .peek()
                .is_some_and(|next| matches!(next, '.' | '!' | '?'))
            {
                characters.next();
            }
            if characters.peek().is_none_or(|next| next.is_whitespace()) {
                count += usize::from(has_text);
                has_text = false;
            }
        }
    }
    count + usize::from(has_text)
}

fn visible_prose_lines(message: &str) -> Vec<&str> {
    let mut fenced = false;
    message
        .lines()
        .filter(|line| {
            if line.trim_start().starts_with("```") {
                fenced = !fenced;
                return false;
            }
            !fenced
        })
        .collect()
}

/// Returns the lowercase `sha256:` digest used to bind critic and delivery receipts.
pub fn message_digest(message: &str) -> String {
    let digest = Sha256::digest(message.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

/// Validates that a research plan is bounded, executable, and internally referential.
///
/// Selected tools must exist in the supplied catalog and fit the lane budget;
/// claim identifiers, scope, stop conditions, and optional follow-through must
/// satisfy their size and uniqueness invariants. Validation does not invoke tools.
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
        || !plan.claims.iter().any(|claim| claim.required)
        || plan.selected_tools.is_empty()
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
            || claim.subject_refs.len() > MAX_SCOPE_ITEMS
            || claim
                .subject_refs
                .iter()
                .any(|subject| !bounded(subject, MAX_TEXT_BYTES))
            || claim.subject_refs.iter().collect::<BTreeSet<_>>().len() != claim.subject_refs.len()
            || claim
                .subject_refs
                .iter()
                .any(|subject| !plan.resolved_entities.contains(subject))
            || (claim.required && plan.resolved_entities.len() > 1 && claim.subject_refs.is_empty())
            || (claim.required
                && (claim.source_candidates.is_empty()
                    || claim
                        .source_candidates
                        .iter()
                        .any(|source| !plan.selected_tools.contains(source))))
            || !claim_refs.insert(&claim.claim_ref)
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "research plan claims require unique bounded references, questions, and exact resolved subject refs".into(),
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
    if plan.user_visible_work.len() > 4
        || plan
            .user_visible_work
            .iter()
            .any(|status| status.trim().is_empty() || !bounded(status, MAX_TEXT_BYTES))
        || plan.user_visible_work.iter().collect::<BTreeSet<_>>().len()
            != plan.user_visible_work.len()
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "user-visible plan updates must contain at most four unique bounded messages".into(),
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
            .chain(&follow_through.attention_policy.notify_on_change)
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
    input: &SessionTurnInput,
    plan: &ResearchPlan,
) -> Result<(), AgentRuntimeError> {
    let route = session
        .events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::RouteAccepted {
                request_id,
                future_observation,
                ..
            } if request_id == &input.request_id => Some(*future_observation),
            _ => None,
        })
        .ok_or_else(|| {
            AgentRuntimeError::InvalidRequest(
                "operator follow-through validation requires a durable semantic route".into(),
            )
        })?;
    match (route, plan.follow_through.is_some()) {
        (FutureObservationDisposition::Delegated, false) => Err(
            AgentRuntimeError::InvalidFinal(
                "the semantic route records delegated future observation. Record one bounded follow_through with a stable commitment_ref, exact read tools, acceptance criteria, and a final scheduled commitment; do not finish this as one-turn advice"
                    .into(),
            ),
        ),
        (
            FutureObservationDisposition::Refused | FutureObservationDisposition::None,
            true,
        ) => Err(AgentRuntimeError::InvalidFinal(
            "the semantic route does not authorize future observation. Remove follow_through and finish the current bounded work; do not invent a timer, monitor, or later assistant update"
                .into(),
        )),
        _ => Ok(()),
    }
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
    let covered = draft
        .claims
        .iter()
        .filter_map(|claim| claim.planned_claim_ref.as_deref())
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
    if draft.state == FinalState::Answered {
        let uncovered = plan
            .claims
            .iter()
            .filter(|planned_claim| {
                planned_claim.required
                    && (!covered.contains(planned_claim.claim_ref.as_str())
                        || !draft.claims.iter().any(|claim| {
                            claim.planned_claim_ref.as_deref()
                                == Some(planned_claim.claim_ref.as_str())
                                && matches!(
                                    claim.content,
                                    ClaimContent::Observation { .. }
                                        | ClaimContent::Recommendation { .. }
                                        | ClaimContent::Hypothesis { .. }
                                )
                        }))
            })
            .map(|claim| claim.claim_ref.as_str())
            .collect::<Vec<_>>();
        if !uncovered.is_empty() {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "answered requires every required planned claim to be covered; missing: {}",
                uncovered.join(", ")
            )));
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

/// Validates a candidate draft against session state and current tool observations.
///
/// Every material span must map to a declared [`GroundedClaim`], every citation
/// must resolve to compatible evidence, current-state claims must respect freshness
/// and completeness, and mission/memory transitions must remain valid. The returned
/// Markdown is safe to hand to a transport but is not itself a delivery receipt.
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
    if !crate::presentation_markup_is_balanced(&draft.message) {
        return Err(AgentRuntimeError::InvalidFinal(
            "visible response contains an unclosed code fence or emphasis span".into(),
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
    let operator_actor_ref = session
        .messages
        .iter()
        .rev()
        .find(|message| message.role == SessionMessageRole::User)
        .map(|message| message.actor_ref.as_str());
    let claim_context = ClaimValidationContext {
        atoms: &atoms,
        open_loops: &open_loops,
        commitments: &commitments,
        messages: &message_sequence,
        operator_actor_ref,
        question: draft.question.as_deref(),
        coverage_notice: draft.coverage_notice.as_deref(),
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
    let rhetorical_moves = draft
        .claims
        .iter()
        .filter_map(|claim| match claim.content {
            ClaimContent::RhetoricalMove { move_id } => Some(move_id),
            _ => None,
        })
        .collect::<Vec<_>>();
    let conversational_synthesis_count = draft
        .claims
        .iter()
        .filter(|claim| matches!(claim.content, ClaimContent::ConversationalSynthesis { .. }))
        .count();
    let has_answer_bearing_claim = draft.claims.iter().any(|claim| {
        claim.required_for_answer
            && matches!(
                claim.content,
                ClaimContent::Observation { .. }
                    | ClaimContent::Recommendation { .. }
                    | ClaimContent::Hypothesis { .. }
                    | ClaimContent::Commitment { .. }
                    | ClaimContent::StableExplanation { .. }
                    | ClaimContent::ConversationalSynthesis { .. }
                    | ClaimContent::CoverageBoundary { .. }
                    | ClaimContent::Question { .. }
            )
    });
    if (!rhetorical_moves.is_empty() && !has_answer_bearing_claim)
        || rhetorical_moves.len() > 2
        || rhetorical_moves.iter().collect::<BTreeSet<_>>().len() != rhetorical_moves.len()
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "rhetorical moves require an answer-bearing typed claim and a response may use at most two distinct registered moves"
                .into(),
        ));
    }
    if conversational_synthesis_count > 1 {
        return Err(AgentRuntimeError::InvalidFinal(
            "a response may contain at most one bounded conversational synthesis".into(),
        ));
    }

    for update in &draft.memory_updates {
        let exact_operator_preference = update.kind == MemoryKind::Preference
            && !update.promotion_requested
            && update.evidence_atom_refs.is_empty()
            && session.messages.iter().any(|message| {
                message.role == SessionMessageRole::User
                    && message.text.trim() == update.statement.trim()
            });
        if !bounded(&update.memory_ref, MAX_TEXT_BYTES)
            || !bounded(&update.statement, MAX_TEXT_BYTES)
            || (update.evidence_atom_refs.is_empty() && !exact_operator_preference)
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
            && (update.evidence_atom_refs.is_empty()
                || update.evidence_atom_refs.iter().any(|atom_ref| {
                    atoms.get(atom_ref).is_none_or(|atom| {
                        !atom.complete
                            || atom
                                .fresh_until
                                .is_none_or(|fresh_until| fresh_until < assessment_at)
                    })
                }))
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
    operator_actor_ref: Option<&'a str>,
    question: Option<&'a str>,
    coverage_notice: Option<&'a str>,
    assessment_at: OffsetDateTime,
    final_state: FinalState,
}

/// Renders reviewed, invariant wording for a stable evidence or authority boundary.
pub fn render_stable_explanation(explanation_id: StableExplanationId) -> &'static str {
    match explanation_id {
        StableExplanationId::EvidenceFreshnessDefinition => {
            "Evidence freshness is the observation reuse window."
        }
        StableExplanationId::EvidenceAuthorityBoundary => {
            "Evidence of provider execution does not grant remediation or approval authority."
        }
        StableExplanationId::RecommendationExecutionBoundary => {
            "A recommendation proposes an action; it does not prove the action ran."
        }
        StableExplanationId::HypothesisAlternativesBoundary => {
            "A hypothesis preserves plausible alternatives until evidence distinguishes them."
        }
        StableExplanationId::CurrentStateFreshObservationBoundary => {
            "A current-state conclusion requires a fresh authoritative observation."
        }
        StableExplanationId::CapabilityBindingBoundary => {
            "An operational capability exists only when a current tool binding declares the required authority and effect."
        }
        StableExplanationId::SourceDeclarationProviderPermissionBoundary => {
            "A source declaration does not prove provider-side permission."
        }
    }
}

fn render_coverage_boundary(boundary: CoverageBoundaryKind) -> &'static str {
    match boundary {
        CoverageBoundaryKind::ExternalActionOutcomeUnknown => {
            "Coverage gap: The external action outcome is unknown. Reconcile the provider state with a fresh observation before another effect. I did not retry the action or record a new follow-up."
        }
        CoverageBoundaryKind::ExternalActionFailed => {
            "Coverage gap: The external action failed. No successful effect was recorded, and I did not retry it or record a new follow-up."
        }
        CoverageBoundaryKind::SourceReadFailedAcceptanceUnverified => {
            "Coverage gap: The source read failed, so the acceptance condition remains unverified."
        }
        CoverageBoundaryKind::PartialReadAcceptanceUnverified => {
            "Coverage gap: The available read is partial, so the acceptance condition remains unverified."
        }
        CoverageBoundaryKind::MissingObservationAcceptanceUnverified => {
            "Coverage gap: No authoritative observation was obtained, so the acceptance condition remains unverified."
        }
        CoverageBoundaryKind::BoundedReadsIncomplete => {
            "Coverage gap: One or more bounded reads failed. Every successful observation remains usable, but each failed read stays an explicit gap and the full requested conclusion is unverified."
        }
        CoverageBoundaryKind::BoundedSourceReadsFailed => {
            "Coverage gap: The bounded source reads failed. I did not evaluate the requested condition, execute an action, or record a new follow-up."
        }
        CoverageBoundaryKind::AvailableEvidenceIncomplete => {
            "Coverage gap: The available evidence does not support the full requested conclusion. No action or future follow-up was recorded."
        }
        CoverageBoundaryKind::NoCurrentAuthoritativeObservation => {
            "Coverage gap: No current authoritative observation was obtained. I did not evaluate the requested condition, execute an action, or record a new follow-up."
        }
        CoverageBoundaryKind::PartialConclusionUnsupported => {
            "Coverage gap: The requested conclusion remains only partially supported."
        }
        CoverageBoundaryKind::BlockedMissingAuthoritativeEvidence => {
            "Coverage gap: The requested conclusion is blocked by missing authoritative evidence."
        }
    }
}

fn text_matches_registered_rendering(text: &str, rendering: &str) -> bool {
    text.trim() == rendering
}

const RETAINED_PLAN_RENDERING: &str = "The recorded open question remains in context.";

fn render_commitment_claim(commitment: &Commitment) -> Option<String> {
    commitment
        .wake_at
        .as_deref()
        .map(|wake_at| format!("I’ll check again at {wake_at}."))
}

fn validate_claim(
    claim: &GroundedClaim,
    context: &ClaimValidationContext<'_, '_>,
    cited_atoms: &mut BTreeSet<String>,
) -> Result<(), AgentRuntimeError> {
    if !matches!(claim.content, ClaimContent::Commitment { .. })
        && contains_unbound_future_promise(&claim.text)
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "future Cerebro work must cite the exact active commitment that records it. If no commitment was created, remove first-person future or capability language and state the next bounded check as a recommendation with its external role owner, trigger, and acceptance condition"
                .into(),
        ));
    }
    let atom_refs = match &claim.content {
        ClaimContent::Observation { atom_refs } => {
            validate_observation_wording(&claim.text, atom_refs, context, false)?;
            atom_refs.as_slice()
        }
        ClaimContent::Derivation { .. } => {
            return Err(AgentRuntimeError::InvalidFinal(
                "derivations require a deterministic runtime evaluator before delivery".into(),
            ));
        }
        ClaimContent::Recommendation {
            directive,
            rationale_atom_refs,
            ..
        } => {
            if !text_matches_registered_rendering(
                &claim.text,
                render_recommendation_directive(*directive),
            ) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "recommendation text must exactly match its registered prospective directive rendering"
                        .into(),
                ));
            }
            rationale_atom_refs.as_slice()
        }
        ClaimContent::Hypothesis {
            supporting_atom_refs,
            alternatives,
        } => {
            if alternatives.is_empty() {
                return Err(AgentRuntimeError::InvalidFinal(
                    "a hypothesis must preserve at least one alternative".into(),
                ));
            }
            validate_observation_wording(&claim.text, supporting_atom_refs, context, false)?;
            validate_hypothesis_wording(&claim.text, supporting_atom_refs, context)?;
            supporting_atom_refs.as_slice()
        }
        ClaimContent::OperatorContext {
            message_sequence,
            exact_excerpt,
        } => {
            let message = context.messages.get(message_sequence).ok_or_else(|| {
                AgentRuntimeError::InvalidFinal("operator context cites an unknown message".into())
            })?;
            let attributed_quote = format!("You said: {exact_excerpt}");
            if message.role != SessionMessageRole::User
                || Some(message.actor_ref.as_str()) != context.operator_actor_ref
                || exact_excerpt.is_empty()
                || exact_excerpt.chars().any(unsafe_context_excerpt_character)
                || message.text.trim() != exact_excerpt.trim()
                || claim.text.trim() != attributed_quote
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "operator context must visibly attribute an exact excerpt from a user message"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::ConversationalSynthesis {
            source_message_sequences,
            source_atom_refs,
        } => {
            validate_conversational_synthesis(
                claim,
                source_message_sequences,
                source_atom_refs,
                context,
            )?;
            return Ok(());
        }
        ClaimContent::RhetoricalMove { move_id } => {
            if claim.planned_claim_ref.is_some()
                || claim.required_for_answer
                || !text_matches_registered_rendering(&claim.text, render_rhetorical_move(*move_id))
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "a rhetorical move must be optional, unplanned, and exactly match its registered rendering"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::HistoricalContext {
            atom_ref,
            exact_excerpt,
        } => {
            let event = context.atoms.get(atom_ref).and_then(|atom| {
                if let EvidenceAssertion::ConversationEvent {
                    thread_ref,
                    actor_ref,
                    role,
                    occurred_at,
                    text,
                } = &atom.atom.assertion
                {
                    Some((thread_ref, actor_ref, role, occurred_at, text))
                } else {
                    None
                }
            });
            let rendering = event.map(|(thread_ref, actor_ref, role, occurred_at, _)| {
                render_historical_context(thread_ref, actor_ref, role, occurred_at, exact_excerpt)
            });
            if exact_excerpt.is_empty()
                || exact_excerpt.len() > 1_000
                || exact_excerpt.chars().any(unsafe_context_excerpt_character)
                || event.is_none_or(|(thread_ref, actor_ref, role, occurred_at, _)| {
                    !historical_attribution_is_safe(thread_ref, actor_ref, role, occurred_at)
                })
                || event.is_none_or(|(_, _, _, _, text)| text.trim() != exact_excerpt.trim())
                || rendering.as_deref().is_none_or(|rendering| {
                    !text_matches_registered_rendering(&claim.text, rendering)
                })
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "historical Slack context must safely quote and attribute one exact excerpt from a typed immutable conversation event"
                        .into(),
                ));
            }
            cited_atoms.insert(atom_ref.clone());
            return Ok(());
        }
        ClaimContent::RetainedPlan { open_loop_ref } => {
            if !context.open_loops.contains(open_loop_ref.as_str())
                || !text_matches_registered_rendering(&claim.text, RETAINED_PLAN_RENDERING)
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "retained plan text must use the registered continuity rendering for an existing open loop"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::Commitment { commitment_ref } => {
            if contains_raw_machine_field_syntax(&claim.text) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "operator-facing commitments must translate machine fields into natural language"
                        .into(),
                ));
            }
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
            if render_commitment_claim(commitment)
                .as_deref()
                .is_none_or(|rendering| !text_matches_registered_rendering(&claim.text, rendering))
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "commitment claim text must exactly match the runtime rendering for its recorded wake"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::StableExplanation { explanation_id } => {
            if !text_matches_registered_rendering(
                &claim.text,
                render_stable_explanation(*explanation_id),
            ) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "stable explanation text must exactly match its registered runtime rendering"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::CoverageBoundary { boundary } => {
            let rendering = render_coverage_boundary(*boundary);
            if !matches!(
                context.final_state,
                FinalState::Partial | FinalState::Blocked
            ) || context.coverage_notice.map(str::trim) != Some(rendering)
                || !text_matches_registered_rendering(&claim.text, rendering)
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "coverage boundary must exactly match the registered notice for a partial or blocked draft"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::Question { directive } => {
            let text = claim.text.trim();
            if context.final_state != FinalState::NeedsInput
                || context.question.map(str::trim) != Some(text)
                || !text_matches_registered_rendering(text, render_question_directive(*directive))
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "question claim text must exactly match its registered missing-input rendering"
                        .into(),
                ));
            }
            return Ok(());
        }
    };

    if atom_refs.is_empty() {
        return Err(AgentRuntimeError::InvalidFinal(
            "observations, derivations, recommendations, and hypotheses require evidence atoms"
                .into(),
        ));
    }
    let validates_current_facts = matches!(
        claim.content,
        ClaimContent::Observation { .. } | ClaimContent::Hypothesis { .. }
    );
    let claim_is_capability =
        validates_current_facts && contains_operational_capability_assertion(&claim.text);
    for clause in atomic_assertion_clauses(&claim.text) {
        if !validates_current_facts {
            break;
        }
        if (contains_operational_capability_assertion(clause)
            || (claim_is_capability
                && !capability_operations_claimed(&clause.to_ascii_lowercase()).is_empty()))
            && !atom_refs.iter().any(|atom_ref| {
                context.atoms.get(atom_ref).is_some_and(|atom| {
                    atom_capability_overview_supports_text(atom, clause, context.assessment_at)
                })
            })
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "every current operational capability assertion requires an exact authority- and effect-matched descriptor from a complete fresh capability.overview observation"
                    .into(),
            ));
        }
    }
    if validates_current_facts && contains_ownership_assertion(&claim.text) {
        for clause in atomic_ownership_clauses(&claim.text) {
            if !contains_ownership_assertion(clause) && !contains_gapped_ownership_assertion(clause)
            {
                continue;
            }
            if recommendation_clause_is_prospective_role_handoff(claim, clause) {
                continue;
            }
            let normalized_clause = clause.to_ascii_lowercase();
            if normalized_clause.contains(" not ") || normalized_clause.starts_with("not ") {
                return Err(AgentRuntimeError::InvalidFinal(
                    "negated ownership prose requires an explicit typed authority state; do not infer it from a positive binding"
                        .into(),
                ));
            }
            let duties = claimed_authority_duties(clause);
            if duties.is_empty()
                || duties.into_iter().any(|duty| {
                    !atom_refs.iter().any(|atom_ref| {
                        context
                            .atoms
                            .get(atom_ref)
                            .is_some_and(|atom| atom_binds_claimed_owner(atom, clause, duty))
                    })
                })
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "observed ownership requires an exact subject, principal, and duty authority binding for every ownership clause"
                        .into(),
                ));
            }
        }
    }
    if validates_current_facts {
        validate_factual_claim_support(&claim.text, atom_refs, context)?;
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

fn validate_conversational_synthesis(
    claim: &GroundedClaim,
    source_message_sequences: &[u64],
    source_atom_refs: &[String],
    context: &ClaimValidationContext<'_, '_>,
) -> Result<(), AgentRuntimeError> {
    let operator_actor_ref = context.operator_actor_ref.ok_or_else(|| {
        AgentRuntimeError::InvalidFinal(
            "conversational synthesis requires a current operator message".into(),
        )
    })?;
    let newest_operator_message = context
        .messages
        .iter()
        .rev()
        .find(|(_, message)| {
            message.role == SessionMessageRole::User
                && message.actor_ref.as_str() == operator_actor_ref
        })
        .ok_or_else(|| {
            AgentRuntimeError::InvalidFinal(
                "conversational synthesis requires a current operator message".into(),
            )
        })?;
    let unique_sequences = source_message_sequences.iter().collect::<BTreeSet<_>>();
    if claim.planned_claim_ref.is_some()
        || !source_atom_refs.is_empty()
        || source_message_sequences.is_empty()
        || source_message_sequences.len() > MAX_CONVERSATIONAL_SYNTHESIS_SOURCES
        || unique_sequences.len() != source_message_sequences.len()
        || !unique_sequences.contains(newest_operator_message.0)
        || source_message_sequences
            .iter()
            .any(|sequence| !context.messages.contains_key(sequence))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "conversational synthesis must cite the newest exact operator message, may cite at most seven earlier messages from the same thread, and cannot carry evidence or a planned claim"
                .into(),
        ));
    }
    let body = claim.text.trim();
    let cited_context = source_message_sequences
        .iter()
        .filter_map(|sequence| context.messages.get(sequence))
        .map(|message| message.text.as_str())
        .collect::<Vec<_>>();
    let newest_terms = synthesis_terms(&newest_operator_message.1.text);
    if newest_terms.is_empty() && source_message_sequences.len() < 2 {
        return Err(AgentRuntimeError::InvalidFinal(
            "a short conversational follow-up must cite at least one earlier thread message".into(),
        ));
    }
    let transforms_supplied_text =
        crate::request_is_artifact_transformation(&newest_operator_message.1.text);
    let premise_reasoning_request =
        crate::request_reasons_from_supplied_operational_premises(&newest_operator_message.1.text);
    let premise_source_bound = premise_synthesis_is_source_bound(body, &cited_context);
    if premise_reasoning_request && !premise_source_bound {
        return Err(AgentRuntimeError::InvalidFinal(
            "Revise the premise-based correction from the exact cited thread: describe a reported dashboard only as suggesting or appearing healthy; treat one successful run as support only for that exact run; keep the new route unverified; remove invented claims about untouched or unchanged code, architecture, dependencies, ownership, execution, or verification; then give one prospective route-specific test in one direct paragraph."
                .into(),
        ));
    }
    let reasons_from_supplied_premises = premise_reasoning_request && premise_source_bound;
    let normalized_body = body.to_ascii_lowercase().replace('’', "'");
    let acknowledges_correction = [
        "you're right",
        "you are right",
        "fair correction",
        "that was another",
    ]
    .iter()
    .any(|marker| normalized_body.contains(marker));
    let body_is_operational = crate::request_explicitly_requires_current_evidence(body)
        || contains_operational_capability_assertion(body)
        || contains_unbound_future_promise(body)
        || contains_nominal_operational_assertion(body)
        || contains_new_named_ownership_principal(body, &cited_context)
        || contains_unverified_named_operational_assertion(body, &cited_context);
    if (crate::request_explicitly_requires_current_evidence(&newest_operator_message.1.text)
        && !acknowledges_correction)
        || (body_is_operational
            && !reasons_from_supplied_premises
            && (!transforms_supplied_text
                || !operational_transformation_is_source_bound(body, &cited_context)))
        || body.is_empty()
        || body.len() > MAX_CONVERSATIONAL_SYNTHESIS_BYTES
        || body.lines().count() > 6
        || body
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
        || body.contains("```")
        || body.contains("http://")
        || body.contains("https://")
        || crate::looks_like_raw_record_dump(body)
        || crate::looks_like_internal_query_failure(body)
        || crate::looks_like_report_copy(body)
        || contains_raw_machine_field_syntax(body)
        || !synthesis_is_relevant(body, &cited_context)
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "conversational synthesis must be bounded natural prose materially tied to its cited thread messages, without machine records, links, report scaffolding, promises, or unsupported operational claims"
                .into(),
        ));
    }
    Ok(())
}

fn premise_synthesis_is_source_bound(body: &str, source_messages: &[&str]) -> bool {
    const OPERATIONAL_STATES: &[&str] = &[
        "approved",
        "available",
        "broken",
        "connected",
        "current",
        "degraded",
        "deployed",
        "disabled",
        "down",
        "enabled",
        "failed",
        "fixed",
        "flaky",
        "green",
        "healthy",
        "landed",
        "live",
        "offline",
        "online",
        "operational",
        "passed",
        "reachable",
        "ready",
        "resolved",
        "responsive",
        "restored",
        "running",
        "safe",
        "shipped",
        "stable",
        "stale",
        "stalled",
        "synchronized",
        "unavailable",
        "up",
        "verified",
        "working",
        "works",
    ];
    let source_tokens = source_messages
        .iter()
        .flat_map(|message| {
            message
                .split(|character: char| !character.is_alphanumeric())
                .filter(|token| !token.is_empty())
                .map(str::to_ascii_lowercase)
        })
        .collect::<BTreeSet<_>>();
    let normalized_body = format!(
        " {} ",
        body.split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join(" ")
    );
    let preserves_boundary = [
        " you re telling me ",
        " you are telling me ",
        " you re right ",
        " you are right ",
        " you said ",
        " your correction ",
        " that correction ",
        " that changes ",
        " changes my read ",
        " changes the picture ",
        " your update ",
        " that update ",
        " based on that ",
        " now that you re telling me ",
        " now that you are telling me ",
        " given that ",
        " given your ",
        " your premise ",
        " based on what you ",
        " resting on your ",
        " haven t independently ",
        " have not independently ",
        " not on my own verification ",
        " still unverified ",
        " not verified ",
        " no confirmation ",
        " still an inference ",
    ]
    .iter()
    .any(|marker| normalized_body.contains(marker));
    if !preserves_boundary
        || !synthesis_is_relevant(body, source_messages)
        || contains_new_named_ownership_principal(body, source_messages)
        || introduces_unstated_change_scope(body, source_messages)
    {
        return false;
    }
    body.split(['.', ';', '!', '?', '\n']).all(|clause| {
        let normalized_clause = format!(
            " {} ",
            clause
                .split(|character: char| !character.is_alphanumeric())
                .filter(|token| !token.is_empty())
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
                .join(" ")
        );
        let states = OPERATIONAL_STATES
            .iter()
            .filter(|state| normalized_clause.contains(&format!(" {state} ")))
            .collect::<Vec<_>>();
        let confidence_is_attributed = normalized_clause.contains(" confident ")
            && [
                " given ",
                " on your premise ",
                " you told me ",
                " you re telling me ",
                " you are telling me ",
                " from what you ",
                " from your ",
            ]
            .iter()
            .any(|marker| normalized_clause.contains(marker));
        states.is_empty()
            || states.iter().all(|state| source_tokens.contains(**state))
            || (normalized_clause.contains(" given ")
                && normalized_clause.contains(" signal ")
                && states.iter().any(|state| source_tokens.contains(**state)))
            || confidence_is_attributed
            || [
                " looks ",
                " appears ",
                " can be ",
                " could be ",
                " suggests ",
                " inference ",
                " may be ",
                " might be ",
                " unverified ",
                " not verified ",
                " no confirmation ",
                " no evidence ",
                " haven t ",
                " have not ",
                " until ",
            ]
            .iter()
            .any(|marker| normalized_clause.contains(marker))
    })
}

fn introduces_unstated_change_scope(body: &str, source_messages: &[&str]) -> bool {
    let normalized = |value: &str| {
        format!(
            " {} ",
            value
                .split(|character: char| !character.is_alphanumeric())
                .filter(|token| !token.is_empty())
                .map(str::to_ascii_lowercase)
                .collect::<Vec<_>>()
                .join(" ")
        )
    };
    let normalized_body = normalized(body);
    let asserts_change_scope = [
        " code we didn t touch ",
        " code we did not touch ",
        " code we didn t change ",
        " code we did not change ",
        " untouched code ",
        " unchanged code ",
        " nothing changed ",
    ]
    .iter()
    .any(|marker| normalized_body.contains(marker));
    if !asserts_change_scope {
        return false;
    }
    !source_messages.iter().any(|message| {
        let normalized_source = normalized(message);
        normalized_source.contains(" code ")
            && [
                " touch ",
                " touched ",
                " change ",
                " changed ",
                " unchanged ",
            ]
            .iter()
            .any(|marker| normalized_source.contains(marker))
    })
}

fn operational_transformation_is_source_bound(body: &str, source_messages: &[&str]) -> bool {
    let body_terms = synthesis_term_sequence(body);
    let body_controls = transformation_control_tokens(body);
    source_messages.iter().any(|source_message| {
        let source_terms = synthesis_term_sequence(source_message);
        body_terms
            .iter()
            .try_fold(0usize, |cursor, body_term| {
                source_terms
                    .get(cursor..)?
                    .iter()
                    .position(|source_term| source_term == body_term)
                    .map(|offset| cursor.saturating_add(offset).saturating_add(1))
            })
            .is_some()
            && body_controls == transformation_control_tokens(source_message)
    })
}

fn transformation_control_tokens(value: &str) -> Vec<String> {
    value
        .replace('’', "'")
        .split(|character: char| !character.is_alphanumeric() && character != '\'')
        .map(str::to_ascii_lowercase)
        .filter(|token| {
            token.chars().any(|character| character.is_ascii_digit())
                || matches!(
                    token.as_str(),
                    "not"
                        | "no"
                        | "never"
                        | "without"
                        | "cannot"
                        | "can't"
                        | "isn't"
                        | "wasn't"
                        | "hasn't"
                        | "won't"
                        | "may"
                        | "might"
                        | "must"
                )
        })
        .collect()
}

fn contains_nominal_operational_assertion(value: &str) -> bool {
    let normalized = format!(" {} ", value.to_ascii_lowercase());
    [
        " status:",
        " state:",
        " result:",
        " owner:",
        " owner is ",
        " owned by ",
        " remediation owner ",
        " verification owner ",
        " approval owner ",
        " execution owner ",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
}

fn contains_new_named_ownership_principal(body: &str, source_messages: &[&str]) -> bool {
    let normalized = body.to_ascii_lowercase();
    if ![
        " owns ",
        " owner ",
        " responsible for ",
        " accountable for ",
        " assigned to ",
        " handled by ",
    ]
    .iter()
    .any(|marker| format!(" {normalized} ").contains(marker))
    {
        return false;
    }
    let source_tokens = source_messages
        .iter()
        .flat_map(|message| {
            message
                .split(|character: char| !character.is_alphanumeric())
                .map(str::to_ascii_lowercase)
        })
        .collect::<BTreeSet<_>>();
    body.split(['.', ';', '!', '?', '\n']).any(|clause| {
        clause
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
            .enumerate()
            .any(|(index, token)| {
                token.len() >= 3
                    && token.chars().next().is_some_and(char::is_uppercase)
                    && (index > 0
                        || (!token.ends_with("ing") && !matches!(token, "The" | "This" | "That")))
                    && !source_tokens.contains(&token.to_ascii_lowercase())
            })
    })
}

fn contains_unverified_named_operational_assertion(body: &str, source_messages: &[&str]) -> bool {
    let source_tokens = source_messages
        .iter()
        .flat_map(|message| {
            message
                .split(|character: char| !character.is_alphanumeric())
                .filter(|token| token.len() >= 3)
                .map(str::to_ascii_lowercase)
        })
        .collect::<BTreeSet<_>>();
    if source_tokens.is_empty() {
        return false;
    }
    let named_source_tokens = source_messages
        .iter()
        .flat_map(|message| {
            let tokens = message
                .split(|character: char| !character.is_alphanumeric())
                .filter(|token| !token.is_empty())
                .collect::<Vec<_>>();
            tokens
                .iter()
                .enumerate()
                .filter_map(|(index, token)| {
                    let preceded_by_naming_preposition = index > 0
                        && matches!(
                            tokens[index - 1].to_ascii_lowercase().as_str(),
                            "about" | "of" | "on"
                        );
                    (index > 0
                        && (token.chars().next().is_some_and(char::is_uppercase)
                            || preceded_by_naming_preposition))
                        .then(|| token.to_ascii_lowercase())
                })
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    let normalized_source = format!(
        " {} ",
        source_messages
            .iter()
            .flat_map(|message| message.split(|character: char| !character.is_alphanumeric()))
            .filter(|token| !token.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join(" ")
    );
    let source_is_conceptual = [
        " in this analogy ",
        " in the analogy ",
        " as an analogy ",
        " in this story ",
        " in the story ",
        " as a story ",
        " in this novel ",
        " in the novel ",
        " in this movie ",
        " in the movie ",
        " as an example ",
        " example ",
        " in this thought experiment ",
        " thought experiment ",
        " in this scenario ",
        " scenario ",
        " in this simulation ",
        " simulation ",
        " hypothetical ",
        " fictional ",
        " imagine ",
        " metaphor ",
        " codename ",
        " as a name ",
        " name choice ",
        " title ",
        " reversibility ",
        " reversible decision ",
    ]
    .iter()
    .any(|marker| normalized_source.contains(marker));
    let source_is_plain_copular_question = source_messages.iter().any(|message| {
        let normalized = format!(" {} ", message.trim().to_ascii_lowercase());
        message.trim_end().ends_with('?')
            && (normalized.starts_with(" is ") || normalized.starts_with(" are "))
            && ![
                " current ",
                " currently ",
                " latest ",
                " now ",
                " recently ",
                " today ",
            ]
            .iter()
            .any(|marker| normalized.contains(marker))
    });
    let source_invites_opinion = [
        " what do you think ",
        " thoughts on ",
        " do you like ",
        " your take ",
        " your read ",
        " your opinion ",
    ]
    .iter()
    .any(|marker| normalized_source.contains(marker));
    let normalized_body = format!(
        " {} ",
        body.split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>()
            .join(" ")
    );
    let body_expresses_opinion = [
        " i think ",
        " i find ",
        " i like ",
        " my take ",
        " my read ",
        " my thoughts ",
        " to me ",
    ]
    .iter()
    .any(|marker| normalized_body.contains(marker));
    body.split(['.', ';', '!', '?', '\n']).any(|clause| {
        let is_conditional = clause.trim_start().to_ascii_lowercase().starts_with("if ");
        if is_conditional {
            return false;
        }
        let tokens = clause
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        let locative_scope = tokens
            .iter()
            .position(|token| matches!(token.as_str(), "in" | "on"));
        let locative_scope_is_conceptual = locative_scope.is_some_and(|index| {
            let immediate = tokens.get(index + 1).map(String::as_str);
            let after_determiner = immediate
                .is_some_and(|value| matches!(value, "a" | "an" | "the" | "this"))
                .then(|| tokens.get(index + 2).map(String::as_str))
                .flatten();
            let thought_experiment = after_determiner == Some("thought")
                && tokens.get(index + 3).map(String::as_str) == Some("experiment");
            thought_experiment
                || immediate
                    .into_iter()
                    .chain(after_determiner)
                    .any(|subject| {
                        matches!(
                            subject,
                            "analogy"
                                | "example"
                                | "metaphor"
                                | "movie"
                                | "novel"
                                | "scenario"
                                | "simulation"
                                | "story"
                        )
                    })
        });
        let conceptual_context_applies = source_is_conceptual
            && (locative_scope.is_none() || locative_scope_is_conceptual)
            && !tokens.iter().any(|token| {
                matches!(
                    token.as_str(),
                    "actual"
                        | "actually"
                        | "currently"
                        | "latest"
                        | "now"
                        | "outside"
                        | "production"
                        | "real"
                        | "reality"
                        | "recently"
                        | "today"
                        | "unlike"
                        | "monday"
                        | "tuesday"
                        | "wednesday"
                        | "thursday"
                        | "friday"
                        | "saturday"
                        | "sunday"
                        | "staging"
                        | "yesterday"
                )
            })
            || [
                " last week ",
                " last month ",
                " this week ",
                " this month ",
                " earlier ",
                " previously ",
                " ago ",
            ]
            .iter()
            .any(|marker| format!(" {} ", clause.to_ascii_lowercase()).contains(marker));
        let is_source_subject = |token: &str| {
            token.len() >= 3
                && source_tokens.contains(token)
                && !matches!(
                    token,
                    "about"
                        | "assumption"
                        | "assumptions"
                        | "concept"
                        | "conflict"
                        | "could"
                        | "disagreement"
                        | "explain"
                        | "example"
                        | "help"
                        | "idea"
                        | "like"
                        | "movie"
                        | "name"
                        | "please"
                        | "reversibility"
                        | "story"
                        | "that"
                        | "this"
                        | "think"
                        | "thoughts"
                        | "title"
                        | "what"
                        | "when"
                        | "where"
                        | "which"
                        | "would"
                        | "you"
                )
        };
        let is_named_source_subject = |token: &str| {
            is_source_subject(token) && (named_source_tokens.contains(token) || token == "cerebro")
        };
        let source_subject_before = |index: usize| {
            tokens[..index]
                .iter()
                .rev()
                .take(8)
                .find(|candidate| is_source_subject(candidate))
                .map(String::as_str)
        };
        let named_subject_before = |index: usize| {
            tokens[..index]
                .iter()
                .rev()
                .take(8)
                .find(|candidate| is_named_source_subject(candidate))
                .map(String::as_str)
        };
        let finite_state = tokens.iter().enumerate().any(|(index, token)| {
            (matches!(
                token.as_str(),
                "approved"
                    | "became"
                    | "broken"
                    | "break"
                    | "broke"
                    | "crash"
                    | "crashed"
                    | "degraded"
                    | "deployed"
                    | "disabled"
                    | "down"
                    | "enabled"
                    | "failed"
                    | "fixed"
                    | "handles"
                    | "landed"
                    | "owned"
                    | "owns"
                    | "offline"
                    | "passed"
                    | "recovered"
                    | "reachable"
                    | "remains"
                    | "resolved"
                    | "responsive"
                    | "restarted"
                    | "restored"
                    | "running"
                    | "shipped"
                    | "stable"
                    | "stalled"
                    | "timed"
                    | "up"
                    | "unavailable"
                    | "work"
                    | "works"
            )) && index > 0
                && source_subject_before(index).is_some()
        });
        let copular_state = tokens.iter().enumerate().any(|(copula_index, token)| {
            if !matches!(token.as_str(), "is" | "are" | "was" | "were") {
                return false;
            }
            let predicates = &tokens[copula_index + 1..];
            let operational_predicate = predicates.iter().any(|predicate| {
                matches!(
                    predicate.as_str(),
                    "approved"
                        | "available"
                        | "broken"
                        | "connected"
                        | "current"
                        | "degraded"
                        | "deployed"
                        | "disabled"
                        | "down"
                        | "enabled"
                        | "failed"
                        | "fixed"
                        | "flaky"
                        | "healthy"
                        | "landed"
                        | "live"
                        | "offline"
                        | "online"
                        | "operational"
                        | "passed"
                        | "reachable"
                        | "ready"
                        | "resolved"
                        | "responsive"
                        | "restored"
                        | "running"
                        | "shipped"
                        | "stable"
                        | "stale"
                        | "stalled"
                        | "synchronized"
                        | "unavailable"
                        | "up"
                        | "working"
                )
            });
            if if operational_predicate {
                source_subject_before(copula_index).is_none()
            } else {
                named_subject_before(copula_index).is_none()
            } {
                return false;
            }
            let normalized_clause = format!(
                " {} ",
                clause
                    .split(|character: char| !character.is_alphanumeric())
                    .filter(|token| !token.is_empty())
                    .map(str::to_ascii_lowercase)
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            let subjective_opinion = !operational_predicate
                && (source_is_plain_copular_question
                    || (source_invites_opinion
                        && (body_expresses_opinion
                            || [" i think ", " i find ", " my take ", " my read ", " to me "]
                                .iter()
                                .any(|marker| normalized_clause.contains(marker))
                            || predicates
                                .iter()
                                .any(|predicate| matches!(predicate.as_str(), "name" | "title")))));
            predicates
                .iter()
                .any(|predicate| !matches!(predicate.as_str(), "a" | "an" | "the"))
                && !subjective_opinion
        });
        (finite_state || copular_state) && !conceptual_context_applies
    })
}

fn synthesis_is_relevant(body: &str, source_messages: &[&str]) -> bool {
    let body_terms = synthesis_terms(body);
    let source_terms = source_messages
        .iter()
        .flat_map(|message| synthesis_terms(message))
        .collect::<BTreeSet<_>>();
    let required_overlap = source_terms.len().min(2);
    required_overlap > 0 && source_terms.intersection(&body_terms).count() >= required_overlap
}

fn synthesis_terms(value: &str) -> BTreeSet<String> {
    synthesis_term_sequence(value).into_iter().collect()
}

fn synthesis_term_sequence(value: &str) -> Vec<String> {
    const STOP_WORDS: &[&str] = &[
        "about", "after", "again", "also", "been", "being", "could", "from", "have", "into",
        "just", "more", "only", "should", "that", "their", "them", "then", "there", "these",
        "they", "this", "those", "what", "when", "where", "which", "while", "with", "would",
        "your",
    ];
    value
        .split(|character: char| !character.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|term| term.len() >= 4 && !STOP_WORDS.contains(&term.as_str()))
        .collect()
}

/// Renders an allowlisted structural phrase that contributes no factual content.
pub fn render_rhetorical_move(move_id: RhetoricalMoveId) -> &'static str {
    match move_id {
        RhetoricalMoveId::SeparateEvidenceFromInference => {
            "A useful distinction here is between evidence and inference."
        }
        RhetoricalMoveId::FrameDecisionWithCriteria => {
            "A useful way to frame the decision is around explicit criteria."
        }
        RhetoricalMoveId::CompareAlternativesConsistently => {
            "The alternatives are easiest to compare against the same criteria."
        }
        RhetoricalMoveId::PreserveReversibility => "Another useful lens is reversibility.",
        RhetoricalMoveId::IdentifyDecisionChangingInformation => {
            "The key question is which additional information would change the decision."
        }
        RhetoricalMoveId::ClarifyScope => "Clarifying the scope first keeps the reasoning focused.",
    }
}

fn render_historical_context(
    thread_ref: &str,
    actor_ref: &str,
    role: &str,
    occurred_at: &str,
    exact_excerpt: &str,
) -> String {
    let escaped_excerpt = exact_excerpt
        .chars()
        .map(|character| match character {
            '\\' => "\\\\".into(),
            '"' => "\\\"".into(),
            '“' | '”' | '„' | '‟' | '«' | '»' | '‹' | '›' | '❝' | '❞' | '＂' => {
                format!("\\u{{{:x}}}", character as u32)
            }
            _ => character.to_string(),
        })
        .collect::<String>();
    match role {
        "user" => format!(
            "Earlier, {actor_ref} said in {thread_ref} at {occurred_at}: \"{escaped_excerpt}\""
        ),
        "assistant" => format!(
            "Earlier, {actor_ref} (assistant) said in {thread_ref} at {occurred_at}: \"{escaped_excerpt}\""
        ),
        "objective" => format!(
            "The objective recorded in {thread_ref} at {occurred_at} was: \"{escaped_excerpt}\""
        ),
        "desired_outcome" => format!(
            "The desired outcome recorded in {thread_ref} at {occurred_at} was: \"{escaped_excerpt}\""
        ),
        "open_loop" => {
            format!("That thread recorded this open loop at {occurred_at}: \"{escaped_excerpt}\"")
        }
        "commitment" => {
            format!("That thread recorded this commitment at {occurred_at}: \"{escaped_excerpt}\"")
        }
        _ => format!(
            "Earlier in Slack, {actor_ref} ({role}) wrote in {thread_ref} at {occurred_at}: \"{escaped_excerpt}\""
        ),
    }
}

fn unsafe_context_excerpt_character(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{0085}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{200b}'
                | '\u{200c}'
                | '\u{200d}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn historical_attribution_is_safe(
    thread_ref: &str,
    actor_ref: &str,
    role: &str,
    occurred_at: &str,
) -> bool {
    let safe_reference = |value: &str| {
        !value.is_empty()
            && value.len() <= 256
            && value.chars().all(|character| {
                character.is_ascii_alphanumeric()
                    || matches!(character, '-' | '_' | ':' | '.' | '/' | '@')
            })
    };
    safe_reference(thread_ref)
        && safe_reference(actor_ref)
        && matches!(
            role,
            "user" | "assistant" | "objective" | "desired_outcome" | "open_loop" | "commitment"
        )
        && OffsetDateTime::parse(occurred_at, &Rfc3339).is_ok()
}

fn render_recommendation_directive(directive: RecommendationDirective) -> &'static str {
    match directive {
        RecommendationDirective::LeaveUnchanged => {
            "I recommend leaving the current target unchanged."
        }
        RecommendationDirective::PerformBoundedCheck => {
            "I recommend that the external owner perform the next bounded check."
        }
        RecommendationDirective::WaitForFreshObservation => {
            "I recommend waiting for a fresh authoritative observation."
        }
        RecommendationDirective::InspectTarget => "I recommend inspecting the current target.",
        RecommendationDirective::VerifyTarget => {
            "I recommend independently verifying the current target."
        }
        RecommendationDirective::ReconcileProviderState => {
            "I recommend reconciling the provider state before another effect."
        }
        RecommendationDirective::RequestApproval => {
            "I recommend requesting approval for the bounded action."
        }
        RecommendationDirective::RemediateTarget => {
            "I recommend remediating the current target, then verifying it independently."
        }
    }
}

fn render_question_directive(directive: QuestionDirective) -> &'static str {
    match directive {
        QuestionDirective::WhichTarget => "Which target should I inspect?",
        QuestionDirective::WhichSource => "Which source should I inspect?",
        QuestionDirective::WhatDecision => "What decision do you want me to evaluate?",
        QuestionDirective::WhatOutcome => "What outcome should I optimize for?",
        QuestionDirective::WhoCanProvideIdentifier => "Who can provide the missing identifier?",
        QuestionDirective::WhenDue => "When is the decision due?",
        QuestionDirective::WhereEvidence => "Where should I look for the missing evidence?",
    }
}

fn validate_factual_claim_support(
    text: &str,
    atom_refs: &[String],
    context: &ClaimValidationContext<'_, '_>,
) -> Result<(), AgentRuntimeError> {
    for clause in atomic_assertion_clauses(text) {
        let supported = atom_refs.iter().any(|atom_ref| {
            context.atoms.get(atom_ref).is_some_and(|atom| {
                (atom_capability_overview_supports_text(atom, clause, context.assessment_at)
                    && factual_clause_uses_only_atom_terms(atom, clause))
                    || atom_positively_supports_factual_clause(atom, clause, context.assessment_at)
            })
        });
        if !supported {
            return Err(AgentRuntimeError::InvalidFinal(
                "every observation or hypothesis clause must positively match a typed subject-bound atom or a fresh bound capability descriptor"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn atom_positively_supports_factual_clause(
    atom: &AtomContext<'_>,
    clause: &str,
    assessment_at: OffsetDateTime,
) -> bool {
    let semantic_match = match &atom.atom.assertion {
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::AuthorityBinding { duty, .. },
        } => {
            claimed_authority_duties(clause).contains(duty)
                && atom_binds_claimed_owner(atom, clause, *duty)
        }
        EvidenceAssertion::Value { predicate, value } => atom_subject_and_scalar_match(
            atom.atom.subject_ref.as_deref(),
            predicate,
            value,
            clause,
        ),
        EvidenceAssertion::Relation {
            predicate,
            object_ref,
        } => atom.atom.subject_ref.as_deref().is_some_and(|subject_ref| {
            observation_text_names_subject(clause, subject_ref)
                && observation_text_names_subject(clause, object_ref)
                && text_contains_semantic_term(clause, predicate)
                && relation_clause_preserves_direction(subject_ref, predicate, object_ref, clause)
        }),
        EvidenceAssertion::ConversationEvent { .. } => false,
        EvidenceAssertion::FieldCoverage { field, state } => {
            atom.atom
                .subject_ref
                .as_deref()
                .is_some_and(|subject_ref| observation_text_names_subject(clause, subject_ref))
                && text_contains_semantic_term(clause, field)
                && text_contains_semantic_term(clause, &format!("{state:?}"))
        }
        EvidenceAssertion::ToolOutcome { summary, .. }
        | EvidenceAssertion::LegacyStatement { statement: summary } => {
            lexical_statement_supports_clause(summary, clause)
        }
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::CausalAssessment { .. },
        } => atom_supports_cause(atom, clause) || atom_supports_ranked_cause(atom, clause),
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::EventFamilyMembership { .. },
        } => atom_supports_event_family_membership(atom, clause),
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::CollectionVisibility { .. },
        } => {
            atom_supports_legitimately_empty(atom, clause, assessment_at)
                || lexical_statement_supports_clause(atom.evidence.statement.as_str(), clause)
        }
        EvidenceAssertion::Semantic { .. } => {
            lexical_statement_supports_clause(atom.evidence.statement.as_str(), clause)
        }
    };
    semantic_match && factual_clause_uses_only_atom_terms(atom, clause)
}

fn atom_subject_and_scalar_match(
    subject_ref: Option<&str>,
    predicate: &str,
    value: &Value,
    clause: &str,
) -> bool {
    if subject_ref.is_some_and(|subject_ref| !observation_text_names_subject(clause, subject_ref)) {
        return false;
    }
    let predicate_leaf = predicate
        .rsplit(['/', '.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(predicate)
        .replace(['_', '-'], " ");
    let predicate_match = text_contains_semantic_term(clause, &predicate_leaf);
    let normalized_predicate = normalized_semantic_text(&predicate.replace(['_', '-'], " "));
    let normalized_clause = normalized_semantic_text(clause);
    let predicate_tokens = normalized_predicate
        .split_whitespace()
        .filter(|token| token.len() >= 3)
        .collect::<BTreeSet<_>>();
    let clause_tokens = normalized_clause
        .split_whitespace()
        .filter(|token| token.len() >= 3)
        .collect::<BTreeSet<_>>();
    let predicate_overlap =
        predicate_tokens.len() >= 2 && predicate_tokens.intersection(&clause_tokens).count() >= 2;
    let value_match = match value {
        Value::String(value) => {
            text_contains_semantic_term(clause, &value.replace(['_', '-'], " "))
        }
        Value::Bool(value) => {
            let normalized = normalized_semantic_text(clause);
            if *value {
                [
                    " true ",
                    " enabled ",
                    " active ",
                    " available ",
                    " configured ",
                    " connected ",
                    " is bound ",
                ]
                .iter()
                .any(|term| normalized.contains(term))
            } else {
                [
                    " false ",
                    " disabled ",
                    " inactive ",
                    " unavailable ",
                    " unconfigured ",
                    " disconnected ",
                    " not bound ",
                ]
                .iter()
                .any(|term| normalized.contains(term))
            }
        }
        Value::Number(value) => text_contains_semantic_term(clause, &value.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => false,
    };
    value_match
        && (predicate_match
            || predicate_overlap
            || scalar_predicate_is_implicit_state(predicate, value))
}

fn scalar_predicate_is_implicit_state(predicate: &str, value: &Value) -> bool {
    let semantic_segments = predicate
        .split(['/', '.', ':'])
        .filter(|segment| !segment.is_empty())
        .filter(|segment| !segment.chars().all(|character| character.is_ascii_digit()))
        .filter(|segment| {
            !matches!(
                *segment,
                "runtime" | "runtimes" | "connector" | "connectors"
            )
        })
        .collect::<Vec<_>>();
    semantic_segments.len() == 1
        && matches!(
            semantic_segments.first().copied(),
            Some("status" | "state" | "health" | "enabled" | "enabled_state")
        )
        && matches!(value, Value::String(_) | Value::Bool(_))
}

fn relation_clause_preserves_direction(
    subject_ref: &str,
    predicate: &str,
    object_ref: &str,
    clause: &str,
) -> bool {
    let normalized = normalized_semantic_text(clause);
    let position = |reference: &str| {
        let leaf = reference
            .rsplit([':', '/', '#'])
            .find(|part| !part.is_empty())
            .unwrap_or(reference);
        let term = normalized_semantic_text(leaf);
        normalized.find(term.trim())
    };
    let predicate = normalized_semantic_text(&predicate.replace(['_', '-'], " "));
    let subject_term = normalized_semantic_text(
        subject_ref
            .rsplit([':', '/', '#'])
            .find(|part| !part.is_empty())
            .unwrap_or(subject_ref),
    );
    let object_term = normalized_semantic_text(
        object_ref
            .rsplit([':', '/', '#'])
            .find(|part| !part.is_empty())
            .unwrap_or(object_ref),
    );
    let unique_terms = [subject_term.trim(), predicate.trim(), object_term.trim()]
        .into_iter()
        .all(|term| normalized.match_indices(term).count() == 1);
    unique_terms
        && position(subject_ref)
            .zip(normalized.find(predicate.trim()))
            .zip(position(object_ref))
            .is_some_and(|((subject, predicate), object)| subject < predicate && predicate < object)
}

fn factual_clause_uses_only_atom_terms(atom: &AtomContext<'_>, clause: &str) -> bool {
    let mut allowed = BTreeSet::new();
    if let Some(subject_ref) = atom.atom.subject_ref.as_deref() {
        extend_semantic_tokens(&mut allowed, subject_ref);
    }
    collect_assertion_tokens(&atom.atom.assertion, &mut allowed);
    match &atom.atom.assertion {
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::AuthorityBinding { .. },
        } => extend_semantic_tokens(
            &mut allowed,
            "i me my we our own owned owner owns responsible responsibility accountable assigned duty belongs rests tasked hands bears carries",
        ),
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::CausalAssessment { .. },
        } => extend_semantic_tokens(
            &mut allowed,
            "cause causal caused likely plausible explanation points rules out eliminates stronger weaker toward",
        ),
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::EventFamilyMembership { .. },
        } => extend_semantic_tokens(
            &mut allowed,
            "event family live lives belong map mapped covered captured part",
        ),
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::CollectionVisibility { .. },
        } => extend_semantic_tokens(
            &mut allowed,
            "collection visibility event window observed empty complete unavailable unverified",
        ),
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::SearchCoverage { .. },
        } => extend_semantic_tokens(
            &mut allowed,
            "search coverage scope found match partial failed returned truncated",
        ),
        _ => {}
    }
    if matches!(
        atom.atom.assertion,
        EvidenceAssertion::ToolOutcome { .. }
            | EvidenceAssertion::LegacyStatement { .. }
            | EvidenceAssertion::Semantic { .. }
    ) {
        extend_semantic_tokens(&mut allowed, atom.evidence.statement.as_str());
    }
    if matches!(
        atom.atom.assertion,
        EvidenceAssertion::Value {
            value: Value::Bool(false),
            ..
        }
    ) {
        extend_semantic_tokens(&mut allowed, "not no");
    }
    if atom.observation.call.tool_id == "capability.overview" {
        extend_semantic_tokens(
            &mut allowed,
            "cerebro i me my we our can cannot not able access authority bound permit permits permitted read search inspect check list find query view monitor watch pull recheck propose draft plan recommend prepare delete write remove change update administer send create edit revoke disable enable assign merge deploy trigger route schedule execute notify follow up set up",
        );
        for tools in [
            atom.observation.result.data.get("built_in"),
            atom.observation.result.data.pointer("/mcp/tools"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        {
            for tool in tools {
                for field in [
                    "tool_id",
                    "title",
                    "summary",
                    "authority_class",
                    "effect_class",
                ] {
                    if let Some(value) = tool.get(field).and_then(Value::as_str) {
                        extend_semantic_tokens(&mut allowed, value);
                    }
                }
            }
        }
    }
    extend_semantic_tokens(
        &mut allowed,
        "true false zero enabled disabled active inactive available unavailable configured unconfigured connected disconnected bound healthy unknown observed empty mapped verified failed partial complete current currently may might could possibly possibility hypothesis explanation alternative likely plausible",
    );
    semantic_content_tokens(clause)
        .into_iter()
        .all(|token| allowed.contains(&token))
}

fn collect_assertion_tokens(assertion: &EvidenceAssertion, allowed: &mut BTreeSet<String>) {
    let Ok(value) = serde_json::to_value(assertion) else {
        return;
    };
    fn collect(value: &Value, allowed: &mut BTreeSet<String>) {
        match value {
            Value::String(value) => extend_semantic_tokens(allowed, value),
            Value::Number(value) => extend_semantic_tokens(allowed, &value.to_string()),
            Value::Bool(value) => extend_semantic_tokens(allowed, &value.to_string()),
            Value::Array(values) => {
                for value in values {
                    collect(value, allowed);
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    extend_semantic_tokens(allowed, key);
                    collect(value, allowed);
                }
            }
            Value::Null => {}
        }
    }
    collect(&value, allowed);
}

fn extend_semantic_tokens(tokens: &mut BTreeSet<String>, value: &str) {
    tokens.extend(semantic_content_tokens(value));
}

fn semantic_content_tokens(value: &str) -> Vec<String> {
    const GRAMMAR: &[&str] = &[
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "being", "do", "does", "did",
        "has", "have", "had", "this", "that", "these", "those", "it", "its", "to", "for", "of",
        "on", "in", "at", "with", "without", "by", "from", "as", "and", "or", "but", "than",
        "then", "s",
    ];
    normalized_semantic_text(value)
        .split_whitespace()
        .filter(|token| !GRAMMAR.contains(token))
        .map(|token| token.strip_suffix('s').unwrap_or(token).to_owned())
        .collect()
}

fn validate_hypothesis_wording(
    text: &str,
    atom_refs: &[String],
    context: &ClaimValidationContext<'_, '_>,
) -> Result<(), AgentRuntimeError> {
    let padded = format!(" {} ", text.to_ascii_lowercase());
    let qualified = [
        " may ",
        " might ",
        " could ",
        " possibly ",
        " possibility ",
        " hypothesis ",
        " one explanation ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    let subject_bound = atom_refs.iter().any(|atom_ref| {
        context.atoms.get(atom_ref).is_some_and(|atom| {
            atom.atom
                .subject_ref
                .as_deref()
                .is_some_and(|subject_ref| observation_text_names_subject(text, subject_ref))
                || lexical_statement_supports_clause(atom.evidence.statement.as_str(), text)
        })
    });
    if !qualified || !subject_bound {
        return Err(AgentRuntimeError::InvalidFinal(
            "a hypothesis must be visibly qualified and remain bound to a cited evidence subject or statement"
                .into(),
        ));
    }
    Ok(())
}

fn lexical_statement_supports_clause(statement: &str, clause: &str) -> bool {
    const STOP_WORDS: &[&str] = &[
        "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "in", "is", "it", "of",
        "on", "or", "that", "the", "this", "to", "was", "were", "with",
    ];
    let normalized_statement = normalized_semantic_text(statement);
    let normalized_clause = normalized_semantic_text(clause);
    let statement_tokens = normalized_statement
        .split_whitespace()
        .filter(|token| token.len() >= 3 && !STOP_WORDS.contains(token))
        .collect::<BTreeSet<_>>();
    let clause_tokens = normalized_clause
        .split_whitespace()
        .filter(|token| token.len() >= 3 && !STOP_WORDS.contains(token))
        .collect::<BTreeSet<_>>();
    let required_overlap = clause_tokens.len().min(3);
    required_overlap > 0
        && statement_tokens.intersection(&clause_tokens).count() >= required_overlap
}

fn validate_observation_wording(
    text: &str,
    atom_refs: &[String],
    context: &ClaimValidationContext<'_, '_>,
    recommendation: bool,
) -> Result<(), AgentRuntimeError> {
    if contains_raw_machine_field_syntax(text) {
        return Err(AgentRuntimeError::InvalidFinal(
            "operator-facing observations must translate raw JSON field assignments into natural language"
                .into(),
        ));
    }
    let normalized = text.to_ascii_lowercase();
    let asserts_ranked_cause = [
        "points toward",
        "pushes the likely",
        "less likely",
        "more likely",
        "less plausible",
        "more plausible",
        "lower odds",
        "higher odds",
        "deprioritize",
        "weaker explanation",
        "stronger explanation",
        "most consistent with",
        "best fit",
        "leans toward",
        "likely explanation",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    if asserts_ranked_cause
        && !atom_refs.iter().any(|atom_ref| {
            context.atoms.get(atom_ref).is_some_and(|atom| {
                atom_supports_ranked_cause(atom, text)
                    && atom
                        .atom
                        .subject_ref
                        .as_deref()
                        .is_none_or(|subject_ref| observation_text_names_subject(text, subject_ref))
            })
        })
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "ranking one possible cause above another requires a subject-bound causal assessment with an explicit typed ranking"
                .into(),
        ));
    }
    let asserts_causal_location = [
        "points past",
        "points to a provider",
        "provider-side cause",
        "provider-side scope",
        "provider-side fix",
        "connector-side cause",
        "connector-side fix",
        "caused by",
        "cause is",
        "rules out",
        "eliminates",
        "suggests the cause",
        "not a connector",
        "fix on my side",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    if asserts_causal_location
        && !atom_refs.iter().any(|atom_ref| {
            context.atoms.get(atom_ref).is_some_and(|atom| {
                atom_supports_cause(atom, text)
                    && atom
                        .atom
                        .subject_ref
                        .as_deref()
                        .is_none_or(|subject_ref| observation_text_names_subject(text, subject_ref))
            })
        })
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "provider authority, collection coverage, and an unbound action plan do not establish which side caused or owns a gap; causal location requires a subject-bound causal assessment"
                .into(),
        ));
    }
    let asserts_event_family_membership = [
        " exactly in the ",
        " live in the ",
        " lives in the ",
        " belong to the ",
        " belongs to the ",
        " map to the ",
        " maps to the ",
        " covered by the ",
        " captured by the ",
        " would live in ",
        " would carry ",
        " family that carries ",
        " family that would carry ",
        " part of the ",
        " part of that ",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    if asserts_event_family_membership
        && !atom_refs.iter().any(|atom_ref| {
            context
                .atoms
                .get(atom_ref)
                .is_some_and(|atom| atom_supports_event_family_membership(atom, text))
        })
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "a declared collectible family does not establish that a named event type belongs to it; event-family membership requires an explicit subject-bound mapping observation"
                .into(),
        ));
    }
    let named_capabilities = [
        (
            [
                "collected-content",
                "collected content",
                "collected-event-content",
            ]
            .as_slice(),
            "collected_event_content_read",
        ),
        (
            ["provider configuration", "provider-config"].as_slice(),
            "provider_configuration_read",
        ),
        (
            ["provider fault", "provider-fault"].as_slice(),
            "provider_fault_diagnostic",
        ),
        (
            ["scheduled monitor", "schedule monitor"].as_slice(),
            "scheduled_monitor",
        ),
        (
            [
                "provider administration",
                "provider administrator",
                "administer the provider",
                "administer provider",
                "provider admin",
            ]
            .as_slice(),
            "provider_administration",
        ),
    ];
    for clause in atomic_assertion_clauses(&normalized) {
        let general_negative = [
            "i can't ",
            "i cannot ",
            "i don't have ",
            "i do not have ",
            "cerebro can't ",
            "cerebro cannot ",
            "not available",
            "is unavailable",
            "is not bound",
            "isn't bound",
        ]
        .iter()
        .any(|marker| clause.contains(marker));
        let general_positive = [
            "i can ",
            "i have ",
            "cerebro can ",
            "available to me",
            "is available",
            "is bound",
        ]
        .iter()
        .any(|marker| clause.contains(marker));
        for (phrases, capability) in named_capabilities {
            if !phrases.iter().any(|phrase| clause.contains(phrase)) {
                continue;
            }
            let asserts_negative = general_negative
                || phrases
                    .iter()
                    .any(|phrase| clause.contains(&format!("no {phrase}")));
            let asserts_positive = !asserts_negative && general_positive;
            if !(asserts_positive || asserts_negative) {
                continue;
            }
            let expected_enabled = asserts_positive;
            if !atom_refs.iter().any(|atom_ref| {
                context.atoms.get(atom_ref).is_some_and(|atom| {
                    atom_supports_named_capability(
                        atom,
                        capability,
                        expected_enabled,
                        context.assessment_at,
                    )
                })
            }) {
                let expected_state = if expected_enabled {
                    "available"
                } else {
                    "unavailable"
                };
                return Err(AgentRuntimeError::InvalidFinal(format!(
                    "the response claims the {capability} capability is {expected_state}, but the cited fresh capability overview does not bind it to that exact state"
                )));
            }
        }
    }
    for clause in atomic_assertion_clauses(text) {
        let clause = clause.to_ascii_lowercase();
        let asserts_empty = [
            "empty",
            "zero events",
            "zero records",
            "0 events",
            "0 records",
            "no entries",
            "nil events",
            "event count was 0",
            "no events",
            "no records",
            "nothing",
            "none were",
            "didn't return",
            "did not return",
            "wasn't collected",
            "was not collected",
        ]
        .iter()
        .any(|phrase| clause.contains(phrase));
        let preserves_boundary = [
            "does not mean empty",
            "doesn't mean empty",
            "does not establish empty",
            "doesn't establish empty",
            "does not prove empty",
            "doesn't prove empty",
            "does not rule out an empty",
            "doesn't rule out an empty",
            "could be empty",
            "may be empty",
            "might be empty",
            "empty remains possible",
            "not evidence of an empty",
            "not a legitimate empty",
            "cannot call it empty",
            "can't call it empty",
            "remains unverified",
        ]
        .iter()
        .any(|phrase| clause.contains(phrase));
        let prospective_condition = recommendation
            && (clause.contains(" when ")
                || clause.starts_with("when ")
                || clause.contains(" if ")
                || clause.starts_with("if "))
            && (clause.contains("future")
                || clause.contains("next")
                || clause.contains("accept")
                || clause.contains("complete receipt")
                || clause.contains("complete window"));
        if asserts_empty
            && !preserves_boundary
            && !prospective_condition
            && !atom_refs.iter().any(|atom_ref| {
                context.atoms.get(atom_ref).is_some_and(|atom| {
                    atom_supports_legitimately_empty(atom, &clause, context.assessment_at)
                })
            })
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "an empty collection claim requires a complete fresh subject- and event-bound CollectionVisibility::LegitimatelyEmpty receipt; not_observed, failures, and unrelated evidence remain unverified"
                    .into(),
            ));
        }
    }
    let asserts_visibility_absence = [
        "proves no visibility",
        "visibility is absent",
        "no collection visibility",
        "establishes no visibility",
        "means no visibility",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    if asserts_visibility_absence {
        return Err(AgentRuntimeError::InvalidFinal(
            "an observed event, a legitimately empty bounded window, and an unavailable collection are distinct states; none by itself proves comprehensive visibility is absent"
                .into(),
        ));
    }
    if normalized.contains("healthy")
        && !atom_refs.iter().any(|atom_ref| {
            context.atoms.get(atom_ref).is_some_and(|atom| {
                atom.evidence.atoms.iter().any(|evidence_atom| {
                    evidence_atom_supports_health(evidence_atom)
                        && evidence_atom
                            .subject_ref
                            .as_deref()
                            .is_none_or(|subject_ref| {
                                observation_text_names_subject(text, subject_ref)
                            })
                })
            })
        })
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "the response calls a source healthy without a cited health observation; describe only the observed receipt or runtime state"
                .into(),
        ));
    }
    for unsupported_transition in [
        "arrived stale",
        "came in stale",
        "hasn't caught up",
        "has not caught up",
        "can't be verified until",
        "cannot be verified until",
        " is enabled",
        " is disabled",
        " is active",
        " is inactive",
        " is available",
        " is unavailable",
        " is configured",
        " is connected",
        "lagging behind",
        "propagated from",
    ] {
        if normalized.contains(unsupported_transition)
            && !atom_refs.iter().any(|atom_ref| {
                context.atoms.get(atom_ref).is_some_and(|atom| {
                    evidence_atom_text(atom.atom).is_some_and(|evidence| {
                        evidence
                            .to_ascii_lowercase()
                            .contains(unsupported_transition)
                    }) || atom_supports_exact_scalar_state(atom, text, unsupported_transition)
                })
            })
        {
            return Err(AgentRuntimeError::InvalidFinal(format!(
                "the response says '{unsupported_transition}', but the cited observation supplies only a state or scalar; report that exact state without inventing transition timing or pipeline cause"
            )));
        }
    }
    Ok(())
}

fn atom_supports_exact_scalar_state(
    atom: &AtomContext<'_>,
    text: &str,
    state_phrase: &str,
) -> bool {
    let (predicate_leaf, expected) = match state_phrase.trim() {
        "is enabled" => ("enabled", true),
        "is disabled" => ("enabled", false),
        "is active" => ("active", true),
        "is inactive" => ("active", false),
        "is available" => ("available", true),
        "is unavailable" => ("available", false),
        "is configured" => ("configured", true),
        "is connected" => ("connected", true),
        _ => return false,
    };
    atom.evidence.atoms.iter().any(|candidate| {
        let EvidenceAssertion::Value { predicate, value } = &candidate.assertion else {
            return false;
        };
        let leaf = predicate
            .rsplit('/')
            .find(|part| !part.is_empty())
            .unwrap_or(predicate);
        let exact_value = (leaf == predicate_leaf && value.as_bool() == Some(expected))
            || (predicate_leaf == "enabled"
                && leaf == "enabled_state"
                && value.as_str() == Some(if expected { "enabled" } else { "disabled" }))
            || (predicate_leaf == "connected"
                && leaf == "gateway_state"
                && value.as_str() == Some(if expected { "connected" } else { "unavailable" }));
        exact_value
            && candidate
                .subject_ref
                .as_deref()
                .is_none_or(|subject_ref| observation_text_names_subject(text, subject_ref))
    })
}

fn atom_supports_cause(atom: &AtomContext<'_>, text: &str) -> bool {
    match &atom.atom.assertion {
        EvidenceAssertion::Semantic {
            assertion:
                SemanticEvidenceAssertion::CausalAssessment {
                    candidates,
                    ranking,
                    ..
                },
        } => {
            let _ = ranking;
            let normalized = text.to_ascii_lowercase();
            let claims_exclusion = normalized.contains("rules out")
                || normalized.contains("ruled out")
                || normalized.contains("eliminates")
                || normalized.contains("not the cause");
            candidates.iter().any(|candidate| {
                (if claims_exclusion {
                    candidate.state == CausalCandidateState::RuledOut
                } else {
                    matches!(
                        candidate.state,
                        CausalCandidateState::Established | CausalCandidateState::Supported
                    )
                }) && (text_contains_semantic_term(text, &candidate.label)
                    || text_contains_semantic_term(text, &candidate.candidate_ref))
            })
        }
        _ => false,
    }
}

fn atom_supports_ranked_cause(atom: &AtomContext<'_>, text: &str) -> bool {
    let EvidenceAssertion::Semantic {
        assertion:
            SemanticEvidenceAssertion::CausalAssessment {
                candidates,
                ranking:
                    CausalRanking::Ranked {
                        ordered_candidate_refs,
                    },
                ..
            },
    } = &atom.atom.assertion
    else {
        return false;
    };
    let ranked_clause = text
        .split(['.', ';', '\n'])
        .find(|clause| {
            let normalized = clause.to_ascii_lowercase();
            [
                "more likely",
                "less likely",
                "more plausible",
                "less plausible",
                "best fit",
                "leans toward",
                "stronger explanation",
                "weaker explanation",
            ]
            .iter()
            .any(|marker| normalized.contains(marker))
        })
        .unwrap_or(text);
    let normalized = normalized_semantic_text(ranked_clause);
    let positions = ordered_candidate_refs
        .iter()
        .filter_map(|candidate_ref| {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate.candidate_ref == *candidate_ref)?;
            let label = normalized_semantic_text(&candidate.label);
            normalized.find(label.trim())
        })
        .collect::<Vec<_>>();
    positions.len() == ordered_candidate_refs.len()
        && positions.windows(2).all(|window| window[0] < window[1])
}

fn atom_supports_legitimately_empty(
    atom: &AtomContext<'_>,
    text: &str,
    assessment_at: OffsetDateTime,
) -> bool {
    matches!(
        &atom.atom.assertion,
        EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::CollectionVisibility {
                subject_ref,
                event_type,
                window_ref,
                state: CollectionVisibilityState::LegitimatelyEmpty { .. },
                ..
            },
        } if atom.complete
            && atom.fresh_until.is_some_and(|until| until >= assessment_at)
            && observation_text_names_subject(text, subject_ref)
            && text.to_ascii_lowercase().contains(
                &event_type.replace(['_', '-'], " ").to_ascii_lowercase()
            )
            && text_names_collection_window(text, window_ref)
    )
}

fn text_names_collection_window(text: &str, window_ref: &str) -> bool {
    observation_text_names_subject(text, window_ref)
        || [
            " window", "between ", " from ", " during ", " last ", " since ",
        ]
        .iter()
        .any(|marker| text.to_ascii_lowercase().contains(marker))
}

fn atom_supports_event_family_membership(atom: &AtomContext<'_>, text: &str) -> bool {
    match &atom.atom.assertion {
        EvidenceAssertion::Semantic {
            assertion:
                SemanticEvidenceAssertion::EventFamilyMembership {
                    subject_ref,
                    event_type,
                    family,
                    state: EventFamilyMembershipState::Mapped,
                },
        } => {
            let normalized = text.to_ascii_lowercase();
            let event_type = event_type.replace(['_', '-'], " ").to_ascii_lowercase();
            let family = family.replace(['_', '-'], " ").to_ascii_lowercase();
            normalized.contains(&event_type)
                && normalized.contains(&family)
                && observation_text_names_subject(text, subject_ref)
        }
        _ => false,
    }
}

fn atom_supports_named_capability(
    atom: &AtomContext<'_>,
    capability: &str,
    expected_enabled: bool,
    assessment_at: OffsetDateTime,
) -> bool {
    if atom.observation.call.tool_id != "capability.overview"
        || atom.observation.result.state != ToolResultState::Succeeded
        || !atom.evidence.complete
        || atom.fresh_until.is_none_or(|until| until < assessment_at)
    {
        return false;
    }
    let exact_scalar = atom
        .evidence
        .atoms
        .iter()
        .any(|candidate| match &candidate.assertion {
            EvidenceAssertion::Value { predicate, value } => {
                (predicate.ends_with(capability) || predicate.ends_with(&format!("/{capability}")))
                    && value.as_bool() == Some(expected_enabled)
            }
            _ => false,
        });
    if exact_scalar {
        return true;
    }
    let (canonical_claim, operation) = match capability {
        "collected_event_content_read" => {
            ("collected event content read", CapabilityOperation::Observe)
        }
        "provider_configuration_read" => {
            ("provider configuration read", CapabilityOperation::Observe)
        }
        "provider_fault_diagnostic" => ("provider fault diagnose", CapabilityOperation::Observe),
        "scheduled_monitor" => ("scheduled monitor", CapabilityOperation::Actuate),
        "provider_administration" => ("provider administration", CapabilityOperation::Actuate),
        _ => return false,
    };
    let matching_bound_tool = [
        atom.observation.result.data.get("built_in"),
        atom.observation.result.data.pointer("/mcp/tools"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_array)
    .flatten()
    .any(|descriptor| capability_descriptor_supports(descriptor, canonical_claim, operation));
    matching_bound_tool == expected_enabled
}

fn atom_capability_overview_supports_text(
    atom: &AtomContext<'_>,
    text: &str,
    assessment_at: OffsetDateTime,
) -> bool {
    if atom.observation.call.tool_id != "capability.overview"
        || atom.observation.result.state != ToolResultState::Succeeded
        || !atom.evidence.complete
        || atom.fresh_until.is_none_or(|until| until < assessment_at)
    {
        return false;
    }
    let normalized = text.to_ascii_lowercase();
    let negative = [
        "cannot ",
        "can't ",
        "i can't ",
        "i cannot ",
        "i don't have ",
        "i do not have ",
        "cerebro can't ",
        "cerebro cannot ",
        "not able to ",
        "is not able to ",
        "not available",
        "does not permit ",
        "doesn't permit ",
    ]
    .iter()
    .any(|marker| normalized.contains(marker));
    let required_operations = capability_operations_claimed(&normalized);
    if required_operations.is_empty() {
        return false;
    }
    required_operations.into_iter().all(|required_operation| {
        let matching_bound_tool = [
            atom.observation.result.data.get("built_in"),
            atom.observation.result.data.pointer("/mcp/tools"),
        ]
        .into_iter()
        .flatten()
        .filter_map(Value::as_array)
        .flatten()
        .any(|tool| capability_descriptor_supports(tool, &normalized, required_operation));
        matching_bound_tool != negative
    })
}

fn capability_descriptor_supports(
    tool: &Value,
    normalized_claim: &str,
    required_operation: CapabilityOperation,
) -> bool {
    let Some(tool_id) = tool.get("tool_id").and_then(Value::as_str) else {
        return false;
    };
    let authority = tool
        .get("authority_class")
        .and_then(Value::as_str)
        .and_then(parse_tool_authority_class);
    let effect = tool
        .get("effect_class")
        .and_then(Value::as_str)
        .and_then(parse_tool_effect_class);
    capability_tool_names_claim(tool_id, normalized_claim)
        && authority.zip(effect).is_some_and(|(authority, effect)| {
            capability_authority_supports(authority, effect, required_operation)
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityOperation {
    Observe,
    Propose,
    Actuate,
}

fn capability_operations_claimed(text: &str) -> Vec<CapabilityOperation> {
    let padded = format!(" {text} ");
    let mut operations = Vec::new();
    if [
        " delete ",
        " write ",
        " remove ",
        " change ",
        " update ",
        " administer ",
        " send ",
        " create ",
        " edit ",
        " revoke ",
        " disable ",
        " enable ",
        " assign ",
        " merge ",
        " deploy ",
        " trigger ",
        " route ",
        " schedule ",
        " execute ",
        " notify ",
        " follow up ",
        " follow-up ",
        " set up ",
        " fix ",
        " fixing ",
        " repair ",
        " repairing ",
        " patch ",
        " patching ",
        " configure ",
        " configuring ",
    ]
    .iter()
    .any(|marker| padded.contains(marker))
    {
        operations.push(CapabilityOperation::Actuate);
    }
    if [" propose ", " draft ", " plan ", " recommend ", " prepare "]
        .iter()
        .any(|marker| padded.contains(marker))
    {
        operations.push(CapabilityOperation::Propose);
    }
    let explicit_observe = [
        " read ",
        " search ",
        " inspect ",
        " check ",
        " list ",
        " find ",
        " query ",
        " view ",
        " monitor ",
        " watch ",
        " pull ",
        " re-read ",
        " recheck ",
        " re-check ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    let generic_availability = [" access ", " available "]
        .iter()
        .any(|marker| padded.contains(marker));
    if explicit_observe
        || (generic_availability
            && !operations.contains(&CapabilityOperation::Actuate)
            && !operations.contains(&CapabilityOperation::Propose))
    {
        operations.push(CapabilityOperation::Observe);
    }
    operations
}

fn atomic_assertion_clauses(text: &str) -> Vec<&str> {
    text.split(['.', ';', ',', '\n'])
        .flat_map(|clause| clause.split(" but "))
        .flat_map(|clause| clause.split(" and "))
        .flat_map(|clause| clause.split(" while "))
        .flat_map(|clause| clause.split(" whereas "))
        .flat_map(|clause| clause.split(" as "))
        .flat_map(|clause| clause.split(" plus "))
        .flat_map(|clause| clause.split(" as well as "))
        .flat_map(|clause| clause.split(" along with "))
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .collect()
}

fn capability_tool_names_claim(tool_id: &str, normalized_claim: &str) -> bool {
    let domain_tokens = tool_id
        .split(['_', '-', '.', '/', ':'])
        .filter(|token| {
            token.len() >= 3
                && !matches!(
                    *token,
                    "mcp"
                        | "cerebro"
                        | "capability"
                        | "execute"
                        | "read"
                        | "search"
                        | "inspect"
                        | "check"
                        | "list"
                        | "find"
                        | "query"
                        | "view"
                        | "propose"
                        | "proposal"
                        | "plan"
                        | "draft"
                        | "delete"
                        | "write"
                        | "remove"
                        | "change"
                        | "update"
                        | "send"
                        | "create"
                        | "edit"
                )
        })
        .collect::<BTreeSet<_>>();
    !domain_tokens.is_empty()
        && domain_tokens
            .iter()
            .all(|token| normalized_claim.contains(*token))
}

fn capability_authority_supports(
    authority: ToolAuthorityClass,
    effect: ToolEffectClass,
    required: CapabilityOperation,
) -> bool {
    match required {
        CapabilityOperation::Observe => {
            authority == ToolAuthorityClass::Observe && effect == ToolEffectClass::Read
        }
        CapabilityOperation::Propose => authority == ToolAuthorityClass::Propose,
        CapabilityOperation::Actuate => {
            authority == ToolAuthorityClass::Actuate && effect != ToolEffectClass::Read
        }
    }
}

fn parse_tool_authority_class(value: &str) -> Option<ToolAuthorityClass> {
    match value {
        "observe" => Some(ToolAuthorityClass::Observe),
        "propose" => Some(ToolAuthorityClass::Propose),
        "actuate" => Some(ToolAuthorityClass::Actuate),
        _ => None,
    }
}

fn parse_tool_effect_class(value: &str) -> Option<ToolEffectClass> {
    match value {
        "read" => Some(ToolEffectClass::Read),
        "write" => Some(ToolEffectClass::Write),
        "external_effect" => Some(ToolEffectClass::ExternalEffect),
        _ => None,
    }
}

fn contains_ownership_assertion(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    let padded = format!(" {normalized} ");
    let explicit_relation = [
        "owner: me",
        "owner is me",
        "i own ",
        "i'm the owner",
        "i am the owner",
        "cerebro owns ",
        "cerebro is the owner",
        " owns ",
        " is responsible for ",
        " responsible for closing ",
        "remediation owner:",
        "owner:",
        " owner:",
        " is accountable for ",
        " is assigned to ",
        " has accountability for ",
        " is the accountable party",
        " is owned by ",
        " is the owner of ",
        " is the remediation owner for ",
        " is the verification owner for ",
        " is the approval owner for ",
        " is the execution owner for ",
        " owner for ",
        " belongs to ",
        " rests with ",
        " has responsibility for ",
        " bears responsibility for ",
        " is tasked with ",
        " falls to ",
        "owner —",
        "owner -",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    let hands_relation = (normalized.contains("'s hands") || normalized.contains("’s hands"))
        && !claimed_authority_duties(text).is_empty();
    let structural_authority_relation = !claimed_authority_duties(text).is_empty()
        && [
            " i ",
            " me ",
            " my ",
            " we ",
            " our ",
            " cerebro ",
            " team ",
            " group ",
            " user ",
            " role ",
            " owner ",
            " accountab",
            " responsib",
            " authority ",
            " authorized ",
            " duty ",
            " tasked ",
            " empowered ",
            " permitted ",
            " assigned ",
        ]
        .iter()
        .any(|marker| padded.contains(marker));
    let principal_effect_relation =
        names_non_agent_principal(text) && !capability_operations_claimed(&normalized).is_empty();
    explicit_relation
        || hands_relation
        || structural_authority_relation
        || principal_effect_relation
}

fn names_non_agent_principal(text: &str) -> bool {
    let padded = format!(" {} ", text.to_ascii_lowercase());
    [" team ", " group ", " role ", " user ", " owner "]
        .iter()
        .any(|principal| padded.contains(principal))
}

fn contains_gapped_ownership_assertion(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    normalized.contains(" for ")
        && [
            "remediat",
            "verif",
            "approv",
            "execut",
            "provider admin",
            "administer",
            "evidence",
        ]
        .iter()
        .any(|duty| {
            normalized
                .find(duty)
                .is_some_and(|index| !normalized[..index].trim().is_empty())
        })
}

fn recommendation_clause_is_prospective_role_handoff(claim: &GroundedClaim, clause: &str) -> bool {
    let ClaimContent::Recommendation { action, .. } = &claim.content else {
        return false;
    };
    let Some(target_ref) = action.target_ref.as_deref() else {
        return false;
    };
    let normalized = clause.to_ascii_lowercase();
    observation_text_names_subject(clause, target_ref)
        && [
            "recommended owner",
            "recommend ",
            "should ",
            "next check for",
            "handoff to",
            "owner:",
            "owner —",
            "owner -",
        ]
        .iter()
        .any(|marker| normalized.contains(marker))
        && !normalized.contains("current")
        && ![" owns ", " is responsible for ", " is accountable for "]
            .iter()
            .any(|marker| normalized.contains(marker))
}

fn atomic_ownership_clauses(text: &str) -> Vec<&str> {
    text.split(['.', ';', ',', '\n'])
        .flat_map(|clause| clause.split(" but "))
        .flat_map(|clause| clause.split(" while "))
        .flat_map(|clause| clause.split(" whereas "))
        .flat_map(|clause| clause.split(" plus "))
        .flat_map(|clause| clause.split(" as well as "))
        .flat_map(|clause| clause.split(" along with "))
        .flat_map(|clause| {
            let parts = clause.split(" and ").map(str::trim).collect::<Vec<_>>();
            if parts.iter().skip(1).any(|part| {
                contains_ownership_assertion(part) || contains_gapped_ownership_assertion(part)
            }) {
                parts
            } else {
                vec![clause]
            }
        })
        .map(str::trim)
        .filter(|clause| !clause.is_empty())
        .collect()
}

fn claimed_authority_duties(text: &str) -> Vec<AuthorityDuty> {
    let normalized = text.to_ascii_lowercase();
    let mut duties = Vec::new();
    if normalized.contains("remediat")
        || normalized.contains("closing")
        || normalized.contains("close this gap")
        || normalized.contains("owns the gap")
        || normalized.contains("owns this gap")
        || normalized.contains("remaining gap")
        || [
            " fix ",
            " fixing ",
            " repair ",
            " repairing ",
            " patch ",
            " patching ",
        ]
        .iter()
        .any(|marker| format!(" {normalized} ").contains(marker))
    {
        duties.push(AuthorityDuty::Remediation);
    }
    if normalized.contains("verif") {
        duties.push(AuthorityDuty::Verification);
    }
    if normalized.contains("approv") {
        duties.push(AuthorityDuty::Approval);
    }
    if normalized.contains("execut") {
        duties.push(AuthorityDuty::Execution);
    }
    if normalized.contains("provider admin") || normalized.contains("administer") {
        duties.push(AuthorityDuty::ProviderAdministration);
    }
    if normalized.contains("evidence") {
        duties.push(AuthorityDuty::Evidence);
    }
    duties
}

fn atom_binds_claimed_owner(
    atom: &AtomContext<'_>,
    text: &str,
    required_duty: AuthorityDuty,
) -> bool {
    let EvidenceAssertion::Semantic {
        assertion:
            SemanticEvidenceAssertion::AuthorityBinding {
                subject_ref,
                duty,
                state: AuthorityBindingState::Bound { principal },
            },
    } = &atom.atom.assertion
    else {
        return false;
    };
    if *duty != required_duty || !text_names_exact_semantic_identity(text, subject_ref) {
        return false;
    }
    let principal_ref = principal.principal_ref.to_ascii_lowercase();
    let principal_leaf = principal_ref
        .rsplit([':', '/', '#'])
        .find(|part| !part.is_empty())
        .unwrap_or(&principal_ref);
    let principal_is_cerebro = matches!(
        principal_ref.as_str(),
        "cerebro" | "service:cerebro" | "agent:cerebro"
    ) || principal
        .display_name
        .as_deref()
        .is_some_and(|name| name.eq_ignore_ascii_case("Cerebro"));
    text_names_exact_claimed_principal(
        text,
        principal_leaf,
        principal.display_name.as_deref(),
        subject_ref,
        required_duty,
        principal_is_cerebro,
    )
}

fn text_names_exact_claimed_principal(
    text: &str,
    principal_leaf: &str,
    display_name: Option<&str>,
    subject_ref: &str,
    duty: AuthorityDuty,
    principal_is_cerebro: bool,
) -> bool {
    let normalized = normalized_semantic_text(text);
    let subject = normalized_semantic_text(subject_ref).trim().to_owned();
    [Some(principal_leaf), display_name]
        .into_iter()
        .flatten()
        .chain(principal_is_cerebro.then_some("i"))
        .chain(principal_is_cerebro.then_some("me"))
        .map(normalized_semantic_text)
        .map(|term| term.trim().to_owned())
        .filter(|term| !term.is_empty())
        .any(|term| syntactically_binds_principal_to_duty(&normalized, &term, &subject, duty))
}

fn syntactically_binds_principal_to_duty(
    normalized: &str,
    principal: &str,
    subject: &str,
    duty: AuthorityDuty,
) -> bool {
    let duty_phrases: &[&str] = match duty {
        AuthorityDuty::Remediation => &[
            "remediation",
            "closing",
            "close this gap",
            "the gap",
            "this gap",
            "remaining gap",
        ],
        AuthorityDuty::Verification => &["verification", "verify", "verifying"],
        AuthorityDuty::Approval => &["approval", "approving"],
        AuthorityDuty::Execution => &["execution", "executing"],
        AuthorityDuty::ProviderAdministration => {
            &["provider administration", "administering", "administration"]
        }
        AuthorityDuty::Evidence => &["evidence"],
    };
    duty_phrases.iter().any(|duty_phrase| {
        let forward = [
            "owns",
            "own",
            "is responsible for",
            "is accountable for",
            "has accountability for",
            "is assigned to",
            "is the accountable party for",
        ]
        .iter()
        .flat_map(|predicate| {
            [
                format!(" {principal} {predicate} {duty_phrase} for {subject} "),
                format!(" {principal} {predicate} {duty_phrase} on {subject} "),
                format!(" {principal} {predicate} {duty_phrase} of {subject} "),
                format!(" {principal} {predicate} {duty_phrase} {subject} "),
            ]
        })
        .any(|pattern| normalized.contains(&pattern));
        forward
            || [
                format!(" {duty_phrase} owner {principal} for {subject} "),
                format!(" {duty_phrase} owner is {principal} for {subject} "),
                format!(" {duty_phrase} for {subject} is assigned to {principal} "),
                format!(" {duty_phrase} for {subject} falls to {principal} "),
                format!(" {subject} {duty_phrase} owner {principal} "),
                format!(" {subject} {duty_phrase} owner is {principal} "),
                format!(" {subject} s {duty_phrase} owner {principal} "),
                format!(" {subject} s {duty_phrase} owner is {principal} "),
                format!(" owner {principal} for {duty_phrase} on {subject} "),
                format!(" owner {principal} for {duty_phrase} of {subject} "),
                format!(" {duty_phrase} for {subject} is owned by {principal} "),
                format!(" {duty_phrase} on {subject} is owned by {principal} "),
                format!(" {duty_phrase} of {subject} is owned by {principal} "),
                format!(" {subject} {duty_phrase} is owned by {principal} "),
                format!(" {subject} s {duty_phrase} is owned by {principal} "),
                format!(" {principal} is the {duty_phrase} owner for {subject} "),
                format!(" {principal} is {duty_phrase} owner for {subject} "),
                format!(" {principal} is the owner of {duty_phrase} for {subject} "),
                format!(" {principal} is the owner of {duty_phrase} on {subject} "),
                format!(" {principal} is the owner of {duty_phrase} of {subject} "),
                format!(" {duty_phrase} owner for {subject} is {principal} "),
                format!(" {duty_phrase} owner on {subject} is {principal} "),
                format!(" {duty_phrase} owner of {subject} is {principal} "),
                format!(" {duty_phrase} for {subject} belongs to {principal} "),
                format!(" {duty_phrase} on {subject} belongs to {principal} "),
                format!(" {duty_phrase} of {subject} belongs to {principal} "),
                format!(" {duty_phrase} for {subject} rests with {principal} "),
                format!(" {duty_phrase} on {subject} rests with {principal} "),
                format!(" {duty_phrase} of {subject} rests with {principal} "),
                format!(" {principal} has responsibility for {duty_phrase} for {subject} "),
                format!(" {principal} has responsibility for {duty_phrase} on {subject} "),
                format!(" {principal} has responsibility for {duty_phrase} of {subject} "),
                format!(" {principal} bears responsibility for {duty_phrase} for {subject} "),
                format!(" {principal} bears responsibility for {duty_phrase} on {subject} "),
                format!(" {principal} bears responsibility for {duty_phrase} of {subject} "),
                format!(" {principal} is tasked with {duty_phrase} for {subject} "),
                format!(" {principal} is tasked with {duty_phrase} on {subject} "),
                format!(" {principal} is tasked with {duty_phrase} of {subject} "),
                format!(" {duty_phrase} for {subject} is in {principal} s hands "),
                format!(" {duty_phrase} on {subject} is in {principal} s hands "),
                format!(" {duty_phrase} of {subject} is in {principal} s hands "),
            ]
            .iter()
            .any(|pattern| normalized.contains(pattern))
    })
}

fn text_names_exact_semantic_identity(text: &str, identity_ref: &str) -> bool {
    let text_tokens = normalized_semantic_text(text)
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let identity_tokens = normalized_semantic_text(identity_ref)
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    !identity_tokens.is_empty()
        && text_tokens
            .windows(identity_tokens.len())
            .enumerate()
            .any(|(index, candidate)| {
                candidate == identity_tokens.as_slice()
                    && text_tokens
                        .get(index + identity_tokens.len())
                        .is_none_or(|next| {
                            matches!(
                                next.as_str(),
                                "and"
                                    | "but"
                                    | "while"
                                    | "whereas"
                                    | "plus"
                                    | "as"
                                    | "along"
                                    | "is"
                                    | "are"
                                    | "was"
                                    | "were"
                                    | "has"
                                    | "have"
                                    | "had"
                                    | "owns"
                                    | "owner"
                                    | "responsible"
                                    | "accountable"
                                    | "assigned"
                                    | "falls"
                                    | "belongs"
                                    | "rests"
                                    | "should"
                                    | "must"
                                    | "can"
                                    | "could"
                                    | "will"
                                    | "would"
                                    | "remains"
                                    | "remained"
                                    | "returned"
                                    | "reports"
                                    | "shows"
                                    | "with"
                                    | "without"
                                    | "after"
                                    | "before"
                                    | "at"
                                    | "in"
                                    | "on"
                                    | "from"
                                    | "to"
                                    | "for"
                            )
                        })
            })
}

fn contains_raw_machine_field_syntax(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if !bytes[index].is_ascii_alphabetic() {
            index += 1;
            continue;
        }
        let start = index;
        let mut has_underscore = false;
        let mut has_camel_boundary = false;
        let mut previous_lower = false;
        while index < bytes.len() && (bytes[index].is_ascii_alphanumeric() || bytes[index] == b'_')
        {
            has_underscore |= bytes[index] == b'_';
            has_camel_boundary |= previous_lower && bytes[index].is_ascii_uppercase();
            previous_lower = bytes[index].is_ascii_lowercase();
            index += 1;
        }
        if !has_underscore && !has_camel_boundary {
            continue;
        }
        let mut next = index;
        while next < bytes.len() && bytes[next].is_ascii_whitespace() {
            next += 1;
        }
        let backticked =
            start > 0 && bytes[start - 1] == b'`' && index < bytes.len() && bytes[index] == b'`';
        let assigned = next < bytes.len() && matches!(bytes[next], b'=' | b':');
        let plain_boolean = text[next..].starts_with("is true")
            || text[next..].starts_with("is false")
            || text[next..].starts_with("changed")
            || text[next..].starts_with("remains");
        let table_field = text[..start].rfind('\n').map_or(0, |line| line + 1);
        let table_field = text[table_field..].contains('|');
        if backticked || assigned || plain_boolean || table_field {
            return true;
        }
    }
    false
}

fn evidence_atom_supports_health(atom: &EvidenceAtom) -> bool {
    match &atom.assertion {
        EvidenceAssertion::Value { value, .. } => value
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case("healthy")),
        EvidenceAssertion::Relation { .. }
        | EvidenceAssertion::ConversationEvent { .. }
        | EvidenceAssertion::ToolOutcome { .. }
        | EvidenceAssertion::Semantic { .. }
        | EvidenceAssertion::LegacyStatement { .. }
        | EvidenceAssertion::FieldCoverage { .. } => false,
    }
}

fn observation_text_names_subject(text: &str, subject_ref: &str) -> bool {
    let leaf = subject_ref
        .rsplit([':', '/', '#'])
        .find(|part| !part.is_empty())
        .unwrap_or(subject_ref)
        .to_ascii_lowercase();
    leaf.len() >= 2 && text_contains_semantic_term(text, &leaf)
}

fn normalized_semantic_text(value: &str) -> String {
    let normalized = value
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                ' '
            }
        })
        .collect::<String>();
    format!(
        " {} ",
        normalized.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

fn text_contains_semantic_term(text: &str, term: &str) -> bool {
    let normalized_text = normalized_semantic_text(text);
    let normalized_term = normalized_semantic_text(term);
    normalized_text.contains(&normalized_term)
}

fn evidence_atom_text(atom: &EvidenceAtom) -> Option<&str> {
    match &atom.assertion {
        EvidenceAssertion::ToolOutcome { summary, .. } => Some(summary),
        EvidenceAssertion::LegacyStatement { statement } => Some(statement),
        EvidenceAssertion::ConversationEvent { text, .. } => Some(text),
        EvidenceAssertion::Semantic { .. }
        | EvidenceAssertion::Value { .. }
        | EvidenceAssertion::Relation { .. }
        | EvidenceAssertion::FieldCoverage { .. } => None,
    }
}

#[derive(Clone, Copy)]
struct AtomContext<'a> {
    atom: &'a EvidenceAtom,
    evidence: &'a EvidenceRecord,
    observation: &'a ToolObservation,
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
                                atom,
                                evidence,
                                observation,
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

/// Validates a complete materialized session and its cross-record invariants.
///
/// Validation covers schema and tenant identity, bounded messages and memories,
/// mission state, event sequence and ownership, pending delivery, effect grants,
/// timestamps, and unique stable references. A valid snapshot is safe to supply
/// to the turn runtime; validation does not prove that external effects occurred.
pub fn validate_session(session: &AgentSession) -> Result<(), AgentRuntimeError> {
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
    if session.memories.len() > MAX_SESSION_MEMORIES
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
    let self_promises_operational_work = normalized
        .split(['.', ';', '!', '?', '\n'])
        .flat_map(|clause| clause.split(" but "))
        .any(|clause| {
            let future_subject = [
                "i'll ",
                "i will ",
                "i'm going to ",
                "i am going to ",
                "we'll ",
                "we will ",
                "cerebro will ",
                "cerebro is going to ",
            ]
            .iter()
            .any(|marker| clause.contains(marker));
            let positive_self_capability = [
                "i can ",
                "i am able to ",
                "i'm able to ",
                "we can ",
                "cerebro can ",
            ]
            .iter()
            .any(|marker| clause.contains(marker));
            let operational_work = [
                "check",
                "inspect",
                "review",
                "investigate",
                "monitor",
                "report",
                "update",
                "follow",
                "handle",
                "own",
                "run",
                "chase",
                "pull",
                "drive",
                "schedule",
                "set up",
                "watch",
                "notify",
                "send",
                "change",
                "fix",
                "prepare",
                "reconcile",
                "verify",
                "collect",
            ]
            .iter()
            .any(|verb| clause.contains(verb));
            (future_subject || positive_self_capability) && operational_work
        });
    let mentions_operational_work = [
        "check",
        "inspect",
        "review",
        "investigate",
        "monitor",
        "report",
        "update",
        "follow",
        "handle",
        "own",
        "run",
        "chase",
        "pull",
        "drive",
        "schedule",
        "set up",
        "watch",
        "notify",
        "send",
        "change",
        "fix",
        "prepare",
        "reconcile",
        "verify",
        "collect",
    ]
    .iter()
    .any(|verb| normalized.contains(verb));
    let subjectless_follow_through = [
        "check",
        "inspection",
        "recheck",
        "re-check",
        "follow-up",
        "follow up",
        "report",
        "update",
    ]
    .iter()
    .any(|noun| normalized.contains(noun))
        && [
            "will follow",
            "will happen",
            "is scheduled",
            "is due",
            "will be sent",
            "will be posted",
        ]
        .iter()
        .any(|future| normalized.contains(future));
    self_promises_operational_work
        || (normalized.contains("expect me to ") && mentions_operational_work)
        || subjectless_follow_through
        || ((normalized.contains("update from me")
            || normalized.contains("hear back from me")
            || normalized.contains("follow-up from me"))
            && (normalized.contains("tomorrow")
                || normalized.contains("later")
                || normalized.contains("will")))
        || normalized.contains("i intend to ")
        || normalized.contains("i plan to ")
        || [
            "i own the follow-through",
            "i own this follow-through",
            "cerebro owns the follow-through",
            "want me to ",
            "keep an eye on",
            "keep watching",
            "scheduled recheck",
            "scheduled re-check",
            "set that recheck",
            "set that re-check",
            "re-report after",
            "check back at",
            "check scheduled",
            "recheck is still on",
        ]
        .iter()
        .any(|promise| normalized.contains(promise))
        || ((normalized.contains("i've set") || normalized.contains("i have set"))
            && (normalized.contains("recheck") || normalized.contains("re-check")))
}

fn contains_operational_capability_assertion(value: &str) -> bool {
    let normalized = value.to_lowercase().replace('’', "'");
    let padded = format!(" {normalized} ");
    let normalized_scope = format!(
        " {} ",
        normalized
            .split(|character: char| !character.is_alphanumeric())
            .filter(|token| !token.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let fictional_scope = [
        " in this novel ",
        " in the novel ",
        " in this story ",
        " in the story ",
        " in this movie ",
        " in the movie ",
        " in this thought experiment ",
        " in this scenario ",
        " in this simulation ",
        " hypothetical ",
        " fictional ",
    ]
    .iter()
    .any(|marker| normalized_scope.contains(marker));
    let real_scope = [
        " actual ",
        " actually ",
        " current ",
        " currently ",
        " production ",
        " real ",
        " reality ",
        " staging ",
        " today ",
    ]
    .iter()
    .any(|marker| normalized_scope.contains(marker));
    if fictional_scope && !real_scope {
        return false;
    }
    let asserts_self_capability = [
        "i can ",
        "i can't ",
        "i cannot ",
        "i am able to ",
        "i'm able to ",
        "we can ",
        "we can't ",
        "we cannot ",
        "cerebro can ",
        "cerebro can't ",
        "cerebro cannot ",
        "i have access",
        "i don't have access",
        "i do not have access",
        "i don't have ",
        "i do not have ",
        "cerebro has access",
        "cerebro does not have access",
        "i'm authorized to ",
        "i am authorized to ",
        "we're authorized to ",
        "we are authorized to ",
        "cerebro is authorized to ",
        "i'm permitted to ",
        "i am permitted to ",
        "we're permitted to ",
        "we are permitted to ",
        "cerebro is permitted to ",
        "i'm allowed to ",
        "i am allowed to ",
        "we're allowed to ",
        "we are allowed to ",
        "cerebro is allowed to ",
        "i'm empowered to ",
        "i am empowered to ",
        "we're empowered to ",
        "we are empowered to ",
        "cerebro is empowered to ",
        "my authority",
        "our authority",
        "my line stops",
        "does not permit ",
        "doesn't permit ",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    let operational_verb = [
        "read",
        "search",
        "query",
        "inspect",
        "access",
        "administer",
        "change",
        "create",
        "update",
        "delete",
        "write",
        "remove",
        "edit",
        "revoke",
        "disable",
        "enable",
        "assign",
        "merge",
        "deploy",
        "send",
        "trigger",
        "route",
        "schedule",
        "execute",
        "monitor",
        "notify",
        "follow up",
        "follow-up",
        "watch",
        "pull",
        "re-read",
        "recheck",
        "re-check",
        "prepare",
        "propose",
        "set up",
    ]
    .iter()
    .any(|verb| normalized.contains(verb));
    let names_agent = [" i ", " me ", " my ", " we ", " our ", " cerebro "]
        .iter()
        .any(|actor| padded.contains(actor));
    let opinion_read = padded.contains(" my read on ");
    let asserts_authority = [
        " authority ",
        " authorized ",
        " access ",
        " able ",
        " allowed ",
        " empowered ",
        " permitted ",
        " can ",
        " cannot ",
        " can't ",
    ]
    .iter()
    .any(|marker| padded.contains(marker));
    let structural_capability =
        names_agent && asserts_authority && !capability_operations_claimed(&normalized).is_empty();
    let agent_effect_statement =
        names_agent && !opinion_read && !capability_operations_claimed(&normalized).is_empty();
    (asserts_self_capability && operational_verb) || structural_capability || agent_effect_statement
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

    #[derive(Default)]
    struct BatchOnlyJournal {
        individual_records: AtomicUsize,
        final_batches: Mutex<Vec<Vec<SessionEventRecord>>>,
    }

    #[async_trait]
    impl SessionJournal for BatchOnlyJournal {
        async fn record(&self, _event: &SessionEventRecord) -> Result<(), AgentRuntimeError> {
            self.individual_records.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn finalize(&self, events: &[SessionEventRecord]) -> Result<(), AgentRuntimeError> {
            self.final_batches.lock().unwrap().push(events.to_vec());
            Ok(())
        }
    }

    fn semantic_envelope() -> SemanticEvidenceEnvelope {
        SemanticEvidenceEnvelope {
            schema_version: AGENT_SEMANTIC_EVIDENCE_V1.into(),
            assertions: vec![
                SemanticEvidenceAssertion::AuthorityBinding {
                    subject_ref: "finding:one".into(),
                    duty: AuthorityDuty::Remediation,
                    state: AuthorityBindingState::PresentIdentityNotReturned,
                },
                SemanticEvidenceAssertion::CausalAssessment {
                    subject_ref: "runtime:one".into(),
                    outcome_ref: "collection:failed".into(),
                    candidates: vec![
                        CausalCandidate {
                            candidate_ref: "cause:cursor".into(),
                            label: "Cursor mismatch".into(),
                            state: CausalCandidateState::Supported,
                        },
                        CausalCandidate {
                            candidate_ref: "cause:provider".into(),
                            label: "Provider response".into(),
                            state: CausalCandidateState::Undistinguished,
                        },
                    ],
                    ranking: CausalRanking::Unranked,
                },
                SemanticEvidenceAssertion::SearchCoverage {
                    subject_ref: Some("finding:one".into()),
                    scope: SearchScope::BoundedQuery {
                        input_digest: format!("sha256:{}", "a".repeat(64)),
                        limit: 25,
                        returned: 25,
                        truncated: true,
                    },
                    result: SearchCoverageResult::NoMatch,
                },
            ],
        }
    }

    #[test]
    fn semantic_evidence_envelope_produces_receipt_bound_atoms() {
        let atoms = semantic_evidence_atoms(SemanticEvidenceAtomization {
            evidence_ref: "evidence://semantic/one",
            envelope: semantic_envelope(),
            observed_at: "2026-08-01T00:00:00Z",
            fresh_until: Some("2026-08-01T00:05:00Z"),
            complete: true,
        })
        .unwrap();

        assert_eq!(atoms.len(), 3);
        assert_eq!(
            atoms
                .iter()
                .map(|atom| atom.atom_ref.as_str())
                .collect::<Vec<_>>(),
            vec![
                "evidence://semantic/one#semantic:0",
                "evidence://semantic/one#semantic:1",
                "evidence://semantic/one#semantic:2",
            ]
        );
        assert_eq!(atoms[0].subject_ref.as_deref(), Some("finding:one"));
        assert_eq!(atoms[1].subject_ref.as_deref(), Some("runtime:one"));
        assert_eq!(
            atoms[2].fresh_until.as_deref(),
            Some("2026-08-01T00:05:00Z")
        );
        let replayed: Vec<EvidenceAtom> =
            serde_json::from_slice(&serde_json::to_vec(&atoms).unwrap()).unwrap();
        assert_eq!(replayed, atoms);
    }

    #[test]
    fn semantic_evidence_atoms_survive_session_event_replay() {
        let atoms = semantic_evidence_atoms(SemanticEvidenceAtomization {
            evidence_ref: "evidence://semantic/replay",
            envelope: semantic_envelope(),
            observed_at: "2026-08-01T00:00:00Z",
            fresh_until: Some("2026-08-01T00:05:00Z"),
            complete: true,
        })
        .unwrap();
        let mut tool_observation = observation(true, Some("2026-08-01T00:05:00Z"));
        tool_observation.result.evidence[0].atoms = atoms.clone();
        let record = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: "session:1".into(),
            sequence: 1,
            occurred_at: "2026-08-01T00:00:00Z".into(),
            event: SessionEvent::ToolInvoked {
                observation: tool_observation,
            },
        };
        let replay_record: SessionEventRecord =
            serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();

        let replayed = apply_session_events(&session(), &[replay_record]).unwrap();

        let SessionEvent::ToolInvoked { observation } = &replayed.events[0].event else {
            panic!("the replayed event remains a tool observation");
        };
        assert_eq!(observation.result.evidence[0].atoms, atoms);
    }

    #[test]
    fn semantic_evidence_rejects_unknown_versions_duplicates_and_invalid_rankings() {
        let mut unknown = semantic_envelope();
        unknown.schema_version = "agent-semantic-evidence/v2".into();
        assert!(
            semantic_evidence_atoms(SemanticEvidenceAtomization {
                evidence_ref: "evidence://semantic/unknown",
                envelope: unknown,
                observed_at: "2026-08-01T00:00:00Z",
                fresh_until: None,
                complete: true,
            })
            .is_err()
        );

        let mut duplicate = semantic_envelope();
        duplicate.assertions.push(duplicate.assertions[0].clone());
        assert!(
            semantic_evidence_atoms(SemanticEvidenceAtomization {
                evidence_ref: "evidence://semantic/duplicate",
                envelope: duplicate,
                observed_at: "2026-08-01T00:00:00Z",
                fresh_until: None,
                complete: true,
            })
            .is_err()
        );

        let mut invalid_ranking = semantic_envelope();
        let SemanticEvidenceAssertion::CausalAssessment { ranking, .. } =
            &mut invalid_ranking.assertions[1]
        else {
            panic!("the fixture includes a causal assessment");
        };
        *ranking = CausalRanking::Ranked {
            ordered_candidate_refs: vec!["cause:cursor".into()],
        };
        assert!(
            semantic_evidence_atoms(SemanticEvidenceAtomization {
                evidence_ref: "evidence://semantic/ranking",
                envelope: invalid_ranking,
                observed_at: "2026-08-01T00:00:00Z",
                fresh_until: None,
                complete: true,
            })
            .is_err()
        );
    }

    #[test]
    fn pre_semantic_evidence_atoms_remain_replay_compatible() {
        let legacy: EvidenceAtom = serde_json::from_value(json!({
            "atom_ref": "evidence://legacy#value:/status",
            "subject_ref": "connector:alpha",
            "assertion": {
                "kind": "value",
                "predicate": "/status",
                "value": "healthy"
            },
            "observed_at": "2026-07-31T00:00:00Z",
            "fresh_until": "2026-07-31T00:05:00Z",
            "complete": true
        }))
        .unwrap();

        assert_eq!(
            legacy.assertion,
            EvidenceAssertion::Value {
                predicate: "/status".into(),
                value: json!("healthy"),
            }
        );
        assert_eq!(
            serde_json::to_value(&legacy).unwrap()["assertion"]["kind"],
            "value"
        );
    }

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
            context_scope_ref: None,
            mission: mission(),
            messages: vec![SessionMessage {
                role: SessionMessageRole::User,
                message_ref: "operator:request:1".into(),
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

    fn retained_message(index: usize, bytes: usize) -> SessionMessage {
        SessionMessage {
            role: if index.is_multiple_of(2) {
                SessionMessageRole::User
            } else {
                SessionMessageRole::Assistant
            },
            message_ref: format!("message:{index}"),
            actor_ref: if index.is_multiple_of(2) {
                "user:1".into()
            } else {
                "cerebro".into()
            },
            text: "x".repeat(bytes),
            received_at: "2026-07-31T00:00:00Z".into(),
        }
    }

    fn session_for_request(request_id: &str, lane: ExecutionLane) -> AgentSession {
        session_for_request_intent(
            request_id,
            lane,
            FutureObservationDisposition::None,
            None,
            "Check connector alpha.",
        )
    }

    fn session_for_request_intent(
        request_id: &str,
        lane: ExecutionLane,
        future_observation: FutureObservationDisposition,
        future_observation_excerpt: Option<&str>,
        message: &str,
    ) -> AgentSession {
        let mut current = session();
        current.messages[0].message_ref = format!("operator:{request_id}");
        current.messages[0].text = message.into();
        apply_session_events(
            &current,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: current.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:00:30Z".into(),
                event: SessionEvent::RouteAccepted {
                    request_id: request_id.into(),
                    lane,
                    future_observation,
                    future_observation_excerpt: future_observation_excerpt.map(str::to_owned),
                },
            }],
        )
        .expect("the test operator request should have one durable accepted route")
    }

    #[test]
    fn operator_turn_is_bound_to_the_exact_message_and_durable_route() {
        let input = SessionTurnInput {
            request_id: "request:1".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };
        let mut wrong_message = session();
        wrong_message.messages[0].message_ref = "operator:request:other".into();
        assert!(validate_turn_input(&wrong_message, &input).is_err());
        assert!(validate_turn_input(&session(), &input).is_err());

        let current = apply_session_events(
            &session(),
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: "session:1".into(),
                sequence: 1,
                occurred_at: "2026-07-31T00:00:30Z".into(),
                event: SessionEvent::RouteAccepted {
                    request_id: "request:1".into(),
                    lane: ExecutionLane::Lookup,
                    future_observation: FutureObservationDisposition::None,
                    future_observation_excerpt: None,
                },
            }],
        )
        .expect("the first semantic route should be durable");
        assert!(validate_turn_input(&current, &input).is_err());
    }

    #[tokio::test]
    async fn final_draft_and_memory_are_exposed_as_one_journal_batch() {
        let current = session();
        let mut events = Vec::new();
        let journal = BatchOnlyJournal::default();
        let memory = MemoryUpdate {
            memory_ref: "memory:final-batch".into(),
            kind: MemoryKind::Decision,
            statement: "Keep the durable boundary atomic.".into(),
            evidence_atom_refs: vec!["atom:status".into()],
            promotion_requested: false,
        };

        emit_final_events(
            &current,
            "2026-07-31T00:01:00Z",
            &mut events,
            [
                SessionEvent::DraftProduced {
                    request_id: "request:1".into(),
                    draft: draft(),
                },
                SessionEvent::MemoryRecorded { update: memory },
            ],
            &journal,
        )
        .await
        .unwrap();

        assert_eq!(journal.individual_records.load(Ordering::SeqCst), 0);
        let batches = journal.final_batches.lock().unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 2);
        assert_eq!(batches[0][0].sequence, 1);
        assert_eq!(batches[0][1].sequence, 2);
    }

    #[test]
    fn accepted_route_is_unique_and_never_a_control_lane() {
        let accepted = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: "session:1".into(),
            sequence: 1,
            occurred_at: "2026-07-31T00:00:30Z".into(),
            event: SessionEvent::RouteAccepted {
                request_id: "request:1".into(),
                lane: ExecutionLane::Investigate,
                future_observation: FutureObservationDisposition::None,
                future_observation_excerpt: None,
            },
        };
        let current = apply_session_events(&session(), &[accepted])
            .expect("the first semantic route should be durable");
        let duplicate = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: current.session_ref.clone(),
            sequence: 2,
            occurred_at: "2026-07-31T00:00:31Z".into(),
            event: SessionEvent::RouteAccepted {
                request_id: "request:1".into(),
                lane: ExecutionLane::Investigate,
                future_observation: FutureObservationDisposition::None,
                future_observation_excerpt: None,
            },
        };
        assert!(apply_session_events(&current, &[duplicate]).is_err());

        let invalid = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: "session:1".into(),
            sequence: 1,
            occurred_at: "2026-07-31T00:00:30Z".into(),
            event: SessionEvent::RouteAccepted {
                request_id: "request:1".into(),
                lane: ExecutionLane::Continue,
                future_observation: FutureObservationDisposition::None,
                future_observation_excerpt: None,
            },
        };
        assert!(apply_session_events(&session(), &[invalid]).is_err());
    }

    #[test]
    fn session_message_compaction_retains_a_complete_newest_suffix() {
        let mut current = session();
        current.messages = (0..MAX_SESSION_MESSAGES)
            .map(|index| retained_message(index, 32))
            .collect();
        let newest = SessionMessage {
            role: SessionMessageRole::User,
            message_ref: "message:newest".into(),
            actor_ref: "user:2".into(),
            text: "Keep this exact newest turn.".into(),
            received_at: "2026-07-31T00:01:00Z".into(),
        };
        let event = SessionEventRecord {
            schema_version: AGENT_SESSION_EVENT_V2.into(),
            session_ref: current.session_ref.clone(),
            sequence: 1,
            occurred_at: newest.received_at.clone(),
            event: SessionEvent::UserMessageQueued {
                message: newest.clone(),
            },
        };

        let compacted = apply_session_events(&current, &[event]).unwrap();
        assert!(compacted.messages.len() <= MAX_SESSION_MESSAGES);
        assert_eq!(
            compacted.messages.first().unwrap().role,
            SessionMessageRole::User
        );
        assert_eq!(compacted.messages.last(), Some(&newest));
        assert_eq!(compacted.mission, current.mission);
        assert_eq!(compacted.memories, current.memories);
        assert_eq!(compacted.events.len(), 1);
    }

    #[test]
    fn session_message_compaction_enforces_bytes_and_fails_closed_on_one_bad_message() {
        let mut messages = (0..64)
            .map(|index| retained_message(index, MAX_MESSAGE_BYTES))
            .collect::<Vec<_>>();
        messages.push(retained_message(64, 8));
        compact_session_messages(&mut messages);
        assert!(
            messages
                .iter()
                .map(|message| message.text.len())
                .sum::<usize>()
                <= MAX_SESSION_MESSAGE_BYTES
        );
        assert_eq!(messages.first().unwrap().role, SessionMessageRole::User);
        let once = messages.clone();
        compact_session_messages(&mut messages);
        assert_eq!(messages, once);

        let oversized = retained_message(999, MAX_MESSAGE_BYTES + 1);
        let mut invalid = vec![retained_message(998, 8), oversized.clone()];
        compact_session_messages(&mut invalid);
        assert_eq!(invalid.last(), Some(&oversized));
        let mut invalid_session = session();
        invalid_session.messages = invalid;
        assert!(validate_session(&invalid_session).is_err());
    }

    #[test]
    fn session_message_compaction_is_a_noop_below_capacity() {
        let mut messages = vec![
            retained_message(1, 8),
            retained_message(2, 8),
            retained_message(3, 8),
        ];
        let original = messages.clone();
        compact_session_messages(&mut messages);
        assert_eq!(messages, original);
        assert_eq!(messages[0].role, SessionMessageRole::Assistant);
    }

    #[test]
    fn session_message_compaction_survives_five_hundred_queued_turns() {
        let mut current = session();
        let original_mission = current.mission.clone();
        let original_memories = current.memories.clone();
        for index in 0..500usize {
            let event = SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: current.session_ref.clone(),
                sequence: current.events.last().map_or(1, |event| event.sequence + 1),
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::UserMessageQueued {
                    message: SessionMessage {
                        role: SessionMessageRole::User,
                        message_ref: format!("message:soak:{index}"),
                        actor_ref: "user:soak".into(),
                        text: format!("soak turn {index}"),
                        received_at: "2026-07-31T00:01:00Z".into(),
                    },
                },
            };
            current = apply_session_events(&current, &[event]).unwrap();
        }

        assert!(current.messages.len() <= MAX_SESSION_MESSAGES);
        assert_eq!(current.mission, original_mission);
        assert_eq!(current.memories, original_memories);
        assert_eq!(
            current
                .messages
                .iter()
                .rev()
                .take(4)
                .map(|message| message.message_ref.as_str())
                .collect::<Vec<_>>(),
            vec![
                "message:soak:499",
                "message:soak:498",
                "message:soak:497",
                "message:soak:496",
            ]
        );
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

    fn recovering_observation_with_tool_outcome(fresh_until: &str) -> ToolObservation {
        let mut current = observation(true, Some(fresh_until));
        current.result.summary = "Connector alpha is recovering at this check.".into();
        current.result.data = json!({"status": "recovering"});
        current.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "status".into(),
            value: json!("recovering"),
        };
        current.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:1#tool-outcome".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: ToolResultState::Succeeded,
                summary: current.result.summary.clone(),
            },
            observed_at: "2026-07-31T00:01:00Z".into(),
            fresh_until: Some(fresh_until.into()),
            complete: true,
        });
        current
    }

    fn healthy_observation_with_tool_outcome(fresh_until: &str) -> ToolObservation {
        let mut current = observation(true, Some(fresh_until));
        current.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:1#tool-outcome".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: current.result.state,
                summary: current.result.summary.clone(),
            },
            observed_at: "2026-07-31T00:01:00Z".into(),
            fresh_until: Some(fresh_until.into()),
            complete: true,
        });
        current
    }

    fn awakened_session_with_checkpoint() -> AgentSession {
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        let mut prior_draft = draft();
        prior_draft.mission = awakened.mission.clone();
        let prior_observation = recovering_observation_with_tool_outcome("2026-08-01T00:00:00Z");
        awakened.events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:00:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "request:checkpoint".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:00:00Z".into(),
                event: SessionEvent::ToolInvoked {
                    observation: prior_observation,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 3,
                occurred_at: "2026-07-31T00:00:00Z".into(),
                event: SessionEvent::DraftProduced {
                    request_id: "request:checkpoint".into(),
                    draft: prior_draft,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 4,
                occurred_at: "2026-07-31T00:00:01Z".into(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: "request:checkpoint".into(),
                    transport: "internal_scheduler".into(),
                    delivery_ref: "delivery:checkpoint".into(),
                    payload_digest: format!("sha256:{}", "c".repeat(64)),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 5,
                occurred_at: "2026-07-31T00:00:02Z".into(),
                event: SessionEvent::TurnCompleted {
                    request_id: "request:checkpoint".into(),
                    state: FinalState::Answered,
                },
            },
        ];
        awakened
    }

    fn draft() -> GroundedDraft {
        GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message:
                "Connector alpha is healthy. I recommend leaving the current target unchanged."
                    .into(),
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
                    text: " I recommend leaving the current target unchanged.".into(),
                    required_for_answer: false,
                    content: ClaimContent::Recommendation {
                        action: ActionSpec {
                            tool_id: None,
                            target_ref: Some("connector:alpha".into()),
                            input: json!({}),
                        },
                        directive: RecommendationDirective::LeaveUnchanged,
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
                notify_on_change: Vec::new(),
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
                subject_refs: vec!["connector:alpha".into()],
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
                notify_on_change: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "A current connector observation closes the check.".into(),
        }
    }

    struct ScriptedSessionModel {
        decisions: Mutex<VecDeque<SessionModelDecision>>,
    }

    struct PremiseConversationModel {
        decisions: Mutex<VecDeque<SessionModelDecision>>,
    }

    #[async_trait]
    impl SessionAgentModel for PremiseConversationModel {
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
            _turn: ClaimReviewTurn,
        ) -> Result<MessageReview, AgentRuntimeError> {
            panic!("premise-bound conversation must not invoke the evidence critic")
        }
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

    struct DirectMcpEffectTools {
        ambiguous: bool,
        calls: Mutex<Vec<ToolCall>>,
    }

    impl DirectMcpEffectTools {
        fn send_call() -> ToolCall {
            ToolCall {
                call_id: "call:mcp-send".into(),
                tool_id: "mcp.slack.message.send".into(),
                purpose: "Send the approved message to channel one.".into(),
                input: json!({"channel_id": "channel-one", "text": "hello"}),
            }
        }

        fn plan() -> ResearchPlan {
            ResearchPlan {
                decision: "Send and verify one Slack message.".into(),
                lane: ExecutionLane::Act,
                resolved_entities: vec!["channel-one".into()],
                claims: vec![PlannedClaim {
                    claim_ref: "claim:mcp-message-state".into(),
                    question: "Does the channel contain the approved message?".into(),
                    required: true,
                    subject_refs: vec!["channel-one".into()],
                    source_candidates: vec!["mcp.slack.message.read".into()],
                }],
                selected_tools: vec![
                    "mcp.slack.message.send".into(),
                    "mcp.slack.message.read".into(),
                ],
                stop_conditions: vec!["The exact message is observed after dispatch.".into()],
                user_visible_work: vec!["I’ll send the approved message and verify it.".into()],
                follow_through: None,
            }
        }

        fn verified_draft() -> GroundedDraft {
            GroundedDraft {
                state: FinalState::Answered,
                delivery: DeliveryDisposition::Visible,
                message: "The approved message was sent and verified.".into(),
                claims: vec![GroundedClaim {
                    claim_ref: "claim:mcp-message-result".into(),
                    planned_claim_ref: Some("claim:mcp-message-state".into()),
                    text: "The approved message was sent and verified.".into(),
                    required_for_answer: true,
                    content: ClaimContent::Observation {
                        atom_refs: vec!["atom:mcp-message-text".into()],
                    },
                }],
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
    }

    #[async_trait]
    impl SessionTools for DirectMcpEffectTools {
        fn catalog(&self) -> Vec<ToolDescriptor> {
            vec![
                ToolDescriptor {
                    tool_id: "mcp.slack.message.send".into(),
                    title: "Send a Slack message".into(),
                    summary: "Send one message.".into(),
                    authority_class: ToolAuthorityClass::Actuate,
                    effect_class: ToolEffectClass::ExternalEffect,
                    input_schema_ref: "mcp://slack.message.send/input".into(),
                    result_schema_ref: "mcp://slack.message.send/output".into(),
                },
                ToolDescriptor {
                    tool_id: "mcp.slack.message.read".into(),
                    title: "Read a Slack message".into(),
                    summary: "Read one message.".into(),
                    authority_class: ToolAuthorityClass::Observe,
                    effect_class: ToolEffectClass::Read,
                    input_schema_ref: "mcp://slack.message.read/input".into(),
                    result_schema_ref: "mcp://slack.message.read/output".into(),
                },
            ]
        }

        async fn invoke(
            &self,
            _session: &AgentSession,
            _input: &SessionTurnInput,
            call: &ToolCall,
        ) -> Result<ToolResult, AgentRuntimeError> {
            self.calls
                .lock()
                .expect("MCP call log poisoned")
                .push(call.clone());
            if call.tool_id == "mcp.slack.message.send" {
                if self.ambiguous {
                    return Err(AgentRuntimeError::ModelUnavailable(
                        "provider response was lost after dispatch".into(),
                    ));
                }
                return Ok(ToolResult {
                    state: ToolResultState::Succeeded,
                    summary: "The provider accepted the message.".into(),
                    data: json!({
                        "verification_expectation": {
                            "target_ref": "channel-one",
                            "input_digest": call.input_digest(),
                            "assertions": {"/text": "hello"}
                        }
                    }),
                    evidence: vec![crate::EvidenceRecord {
                        evidence_ref: "evidence:mcp-dispatch".into(),
                        statement: "The provider returned a dispatch receipt.".into(),
                        observed_at: "2026-07-31T00:01:00Z".into(),
                        fresh_until: Some("2026-08-01T00:00:00Z".into()),
                        complete: true,
                        atoms: vec![EvidenceAtom {
                            atom_ref: "atom:mcp-dispatch".into(),
                            subject_ref: Some("channel-one".into()),
                            assertion: EvidenceAssertion::Value {
                                predicate: "/dispatched".into(),
                                value: json!(true),
                            },
                            observed_at: "2026-07-31T00:01:00Z".into(),
                            fresh_until: Some("2026-08-01T00:00:00Z".into()),
                            complete: true,
                        }],
                    }],
                    blocker: None,
                });
            }
            Ok(ToolResult {
                state: ToolResultState::Succeeded,
                summary: "The exact message was observed in the channel.".into(),
                data: json!({"channel_id": "channel-one", "text": "hello"}),
                evidence: vec![crate::EvidenceRecord {
                    evidence_ref: "evidence:mcp-message-read".into(),
                    statement: "The exact message was observed in the channel.".into(),
                    observed_at: "2026-07-31T00:02:00Z".into(),
                    fresh_until: Some("2026-08-01T00:00:00Z".into()),
                    complete: true,
                    atoms: vec![EvidenceAtom {
                        atom_ref: "atom:mcp-message-text".into(),
                        subject_ref: Some("channel-one".into()),
                        assertion: EvidenceAssertion::Value {
                            predicate: "/text".into(),
                            value: json!("hello"),
                        },
                        observed_at: "2026-07-31T00:02:00Z".into(),
                        fresh_until: Some("2026-08-01T00:00:00Z".into()),
                        complete: true,
                    }],
                }],
                blocker: None,
            })
        }
    }

    struct WakeTools {
        effects: AtomicUsize,
    }

    struct RecoveringWakeTools;

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
    impl SessionTools for RecoveringWakeTools {
        fn catalog(&self) -> Vec<ToolDescriptor> {
            vec![observation(true, Some("2026-08-01T00:00:00Z")).descriptor]
        }

        async fn invoke(
            &self,
            _session: &AgentSession,
            _input: &SessionTurnInput,
            _call: &ToolCall,
        ) -> Result<ToolResult, AgentRuntimeError> {
            Ok(recovering_observation_with_tool_outcome("2026-08-01T00:00:00Z").result)
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
    fn catalog_only_results_cannot_be_persisted_as_unproven_memory() {
        let mut unproven = draft();
        unproven.memory_updates.push(MemoryUpdate {
            memory_ref: "memory:catalog-claim".into(),
            kind: MemoryKind::Fact,
            statement: "A provider capability exists.".into(),
            evidence_atom_refs: Vec::new(),
            promotion_requested: false,
        });
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();

        assert!(
            validate_grounded_draft(
                &session(),
                &unproven,
                &[observation(true, Some("2026-08-01T00:00:00Z"))],
                assessment,
            )
            .is_err()
        );

        let mut preference = draft();
        preference.memory_updates.push(MemoryUpdate {
            memory_ref: "memory:operator-preference".into(),
            kind: MemoryKind::Preference,
            statement: "Check connector alpha.".into(),
            evidence_atom_refs: Vec::new(),
            promotion_requested: false,
        });
        assert!(
            validate_grounded_draft(
                &session(),
                &preference,
                &[observation(true, Some("2026-08-01T00:00:00Z"))],
                assessment,
            )
            .is_ok()
        );

        let mut unsafe_substring = draft();
        unsafe_substring.memory_updates.push(MemoryUpdate {
            memory_ref: "memory:negated-fragment".into(),
            kind: MemoryKind::Preference,
            statement: "connector alpha".into(),
            evidence_atom_refs: Vec::new(),
            promotion_requested: false,
        });
        assert!(
            validate_grounded_draft(
                &session(),
                &unsafe_substring,
                &[observation(true, Some("2026-08-01T00:00:00Z"))],
                assessment,
            )
            .is_err()
        );
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
            content: ClaimContent::StableExplanation {
                explanation_id: StableExplanationId::EvidenceFreshnessDefinition,
            },
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
    fn rejects_future_work_under_non_commitment_claim_bases() {
        let observed = observation(true, Some("2026-08-01T00:00:00Z"));
        for content in [
            ClaimContent::Observation {
                atom_refs: vec!["atom:status".into()],
            },
            ClaimContent::Recommendation {
                action: ActionSpec {
                    tool_id: None,
                    target_ref: Some("connector:alpha".into()),
                    input: json!({}),
                },
                directive: RecommendationDirective::InspectTarget,
                rationale_atom_refs: vec!["atom:status".into()],
            },
            ClaimContent::Hypothesis {
                supporting_atom_refs: vec!["atom:status".into()],
                alternatives: vec!["The connector may remain degraded.".into()],
            },
        ] {
            let mut promise = draft();
            promise.message =
                "I've set a recheck and I'll re-inspect the receipt, then I'll report back.".into();
            promise.claims = vec![GroundedClaim {
                claim_ref: "claim:unbound-future-work".into(),
                planned_claim_ref: None,
                text: promise.message.clone(),
                required_for_answer: true,
                content,
            }];
            let error = validate_grounded_draft(
                &session(),
                &promise,
                std::slice::from_ref(&observed),
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .expect_err("every future Cerebro promise requires commitment basis");
            assert!(error.to_string().contains("exact active commitment"));
        }
    }

    #[test]
    fn operator_context_cannot_present_a_user_future_statement_as_cerebro_work() {
        let mut quoted = draft();
        quoted.message = "I'll re-inspect the receipt.".into();
        let mut quoted_session = session();
        quoted_session.messages[0].text = quoted.message.clone();
        quoted.claims = vec![GroundedClaim {
            claim_ref: "claim:quoted-operator-context".into(),
            planned_claim_ref: None,
            text: quoted.message.clone(),
            required_for_answer: false,
            content: ClaimContent::OperatorContext {
                message_sequence: 1,
                exact_excerpt: quoted.message.clone(),
            },
        }];
        assert!(
            validate_grounded_draft(
                &quoted_session,
                &quoted,
                &[],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .expect_err("first-person future work always requires an exact commitment")
            .to_string()
            .contains("exact active commitment")
        );

        quoted.message = "You asked: I'll re-inspect the receipt, and I can chase it next.".into();
        quoted.claims[0].text = quoted.message.clone();
        assert!(
            validate_grounded_draft(
                &quoted_session,
                &quoted,
                &[],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .expect_err(
                "operator context cannot smuggle new future work around the commitment gate"
            )
            .to_string()
            .contains("exact active commitment")
        );

        let mut attributed = draft();
        attributed.message = "You said: Check connector alpha.".into();
        attributed.claims = vec![GroundedClaim {
            claim_ref: "claim:attributed-user-context".into(),
            planned_claim_ref: None,
            text: attributed.message.clone(),
            required_for_answer: false,
            content: ClaimContent::OperatorContext {
                message_sequence: 1,
                exact_excerpt: "Check connector alpha.".into(),
            },
        }];
        assert!(
            validate_grounded_draft(
                &session(),
                &attributed,
                &[],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_ok()
        );
        let mut multi_party = session();
        multi_party.messages.push(SessionMessage {
            role: SessionMessageRole::User,
            message_ref: "message:current-operator".into(),
            actor_ref: "user:2".into(),
            text: "What follows from that?".into(),
            received_at: "2026-07-31T00:00:30Z".into(),
        });
        assert!(
            validate_grounded_draft(
                &multi_party,
                &attributed,
                &[],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .expect_err("another participant's message cannot be attributed to the operator")
            .to_string()
            .contains("exact excerpt from a user message")
        );
        if let ClaimContent::OperatorContext {
            message_sequence, ..
        } = &mut attributed.claims[0].content
        {
            *message_sequence = 999;
        }
        assert!(
            validate_grounded_draft(
                &session(),
                &attributed,
                &[],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );

        let mut polarity = attributed;
        let mut polarity_session = session();
        polarity_session.messages[0].text = "Connector alpha is not verified.".into();
        polarity.message = "You said: verified".into();
        polarity.claims[0].text = polarity.message.clone();
        polarity.claims[0].content = ClaimContent::OperatorContext {
            message_sequence: 1,
            exact_excerpt: "verified".into(),
        };
        assert!(
            validate_grounded_draft(
                &polarity_session,
                &polarity,
                &[],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );

        polarity_session.messages[0].text = "No issue.\n\nConnector alpha owns remediation.".into();
        polarity.message = "You said: No issue.\n\nConnector alpha owns remediation.".into();
        polarity.claims[0].text = polarity.message.clone();
        polarity.claims[0].content = ClaimContent::OperatorContext {
            message_sequence: 1,
            exact_excerpt: polarity_session.messages[0].text.clone(),
        };
        assert!(
            validate_grounded_draft(
                &polarity_session,
                &polarity,
                &[],
                OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );
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
        scheduled.message = "I’ll check again at 2026-07-31T00:00:30Z.".into();
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

        let mut overbroad = scheduled;
        overbroad.claims[0].content = ClaimContent::Commitment {
            commitment_ref: "commitment:scheduled-check".into(),
        };
        overbroad.claims[0].text = "Cerebro will administer the provider tomorrow.".into();
        overbroad.message = overbroad.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &overbroad,
                &[],
                OffsetDateTime::parse("2026-07-31T00:00:00Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn retained_plan_claims_use_only_the_registered_continuity_rendering() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut retained = draft();
        retained.mission.open_loops.push(OpenLoop {
            open_loop_ref: "open-loop:connector-choice".into(),
            summary: "Choose a connector.".into(),
            owner: WorkOwner::User,
            next_action: None,
            blocked_by: Some("A connector identifier is required.".into()),
        });
        retained.claims.truncate(1);
        retained.claims[0].planned_claim_ref = None;
        retained.claims[0].text = RETAINED_PLAN_RENDERING.into();
        retained.claims[0].content = ClaimContent::RetainedPlan {
            open_loop_ref: "open-loop:connector-choice".into(),
        };
        retained.message = retained.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &retained, &[], assessment).is_ok());

        retained.claims[0].text =
            "Cerebro bears responsibility for remediation of connector beta.".into();
        retained.message = retained.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &retained, &[], assessment).is_err());
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
    fn explicit_operator_format_contracts_are_runtime_enforced() {
        let mut exact_sentences = session();
        exact_sentences.messages[0].text =
            "Give me exactly three plain sentences I can paste. No headings, no bullets.".into();
        let mut response = draft();
        response.message = "Here you go.\n\n*Current state*\n\n- One.\n- Two.\nExtra.".into();
        let issues = validate_explicit_response_contract(
            &exact_sentences,
            &SessionTurnTrigger::Operator,
            &response,
        );
        assert!(issues.iter().any(|issue| issue.contains("no headings")));
        assert!(issues.iter().any(|issue| issue.contains("no bullets")));
        assert!(issues.iter().any(|issue| issue.contains("3 sentences")));

        response.message = "We can read collected evidence. We cannot administer the provider. Read access carries no change authority.".into();
        assert!(
            validate_explicit_response_contract(
                &exact_sentences,
                &SessionTurnTrigger::Operator,
                &response,
            )
            .is_empty()
        );
    }

    #[test]
    fn explicit_bullet_and_sentence_ranges_are_runtime_enforced() {
        let mut two_bullets = session();
        two_bullets.messages[0].text = "In two short bullets, give me the distinction.".into();
        let mut response = draft();
        response.message = "- Declared support.\n- Evidence landed.".into();
        assert!(
            validate_explicit_response_contract(
                &two_bullets,
                &SessionTurnTrigger::Operator,
                &response,
            )
            .is_empty()
        );
        response.message.push_str("\n- Extra caveat.");
        assert!(
            validate_explicit_response_contract(
                &two_bullets,
                &SessionTurnTrigger::Operator,
                &response,
            )
            .iter()
            .any(|issue| issue.contains("exactly 2 bullets"))
        );

        two_bullets.messages[0].text = "Close it in a sentence or two.".into();
        response.message = "One. Two. Three.".into();
        assert!(
            validate_explicit_response_contract(
                &two_bullets,
                &SessionTurnTrigger::Operator,
                &response,
            )
            .iter()
            .any(|issue| issue.contains("1 to 2 sentences"))
        );
    }

    #[test]
    fn explicit_brevity_contracts_and_code_fences_are_runtime_enforced() {
        let mut bounded = session();
        bounded.messages[0].text = "Use no more than 6 words and no headings or bullets.".into();
        let mut response = draft();
        response.message = "This answer contains exactly six words.".into();
        assert!(
            validate_explicit_response_contract(
                &bounded,
                &SessionTurnTrigger::Operator,
                &response,
            )
            .is_empty()
        );
        response.message.push_str(" Extra.");
        assert!(validate_explicit_response_contract(
            &bounded,
            &SessionTurnTrigger::Operator,
            &response,
        )
        .iter()
        .any(|issue| issue.contains("at most 6 words")));

        bounded.messages[0].text = "Keep this under 20 characters.".into();
        response.message = "Exactly nineteen now".into();
        assert!(validate_explicit_response_contract(
            &bounded,
            &SessionTurnTrigger::Operator,
            &response,
        )
        .iter()
        .any(|issue| issue.contains("at most 19 characters")));

        bounded.messages[0].text = "Explain without headings or bullets.".into();
        response.message =
            "Code stays literal:\n```text\n# heading\n- bullet\n```\nPlain answer.".into();
        assert!(
            validate_explicit_response_contract(
                &bounded,
                &SessionTurnTrigger::Operator,
                &response,
            )
            .is_empty()
        );
        response.message.push_str("\n+ Real bullet");
        assert!(validate_explicit_response_contract(
            &bounded,
            &SessionTurnTrigger::Operator,
            &response,
        )
        .iter()
        .any(|issue| issue.contains("no bullets")));
    }

    #[test]
    fn wake_delivery_does_not_inherit_operator_format_contracts() {
        let mut operator_session = session();
        operator_session.messages[0].text = "Exactly three sentences.".into();
        let response = draft();
        assert!(
            validate_explicit_response_contract(
                &operator_session,
                &SessionTurnTrigger::Wake {
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:1".into(),
                },
                &response,
            )
            .is_empty()
        );
    }

    #[test]
    fn required_plan_claims_must_be_resolved_in_the_visible_answer() {
        let mut unfinished = draft();
        unfinished.claims[0].planned_claim_ref = None;
        assert!(validate_plan_completion(Some(&plan()), &unfinished).is_err());

        let mut optional = plan();
        optional.claims[0].required = false;
        assert!(validate_plan_completion(Some(&optional), &unfinished).is_ok());
        assert!(validate_plan(&optional, &optional.selected_tools.clone()).is_err());

        let mut no_selected_read = plan();
        no_selected_read.selected_tools.clear();
        assert!(validate_plan(&no_selected_read, &["connector.read".into()]).is_err());

        let mut unbound_required_source = plan();
        unbound_required_source.claims[0].source_candidates = vec!["other.read".into()];
        assert!(validate_plan(&unbound_required_source, &["connector.read".into()]).is_err());

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
            requested_lane: Some(ExecutionLane::Investigate),
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
    fn answered_requires_every_required_planned_claim() {
        let mut proposed = plan();
        proposed.claims.push(PlannedClaim {
            claim_ref: "claim:owner".into(),
            question: "Who owns the unresolved gap?".into(),
            required: true,
            subject_refs: vec!["connector:alpha".into()],
            source_candidates: vec!["connector.read".into()],
        });
        let answer = draft();

        let error = validate_plan_completion(Some(&proposed), &answer).unwrap_err();
        assert!(error.to_string().contains("claim:owner"));
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
                notify_on_change: Vec::new(),
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
                notify_on_change: Vec::new(),
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
                notify_on_change: Vec::new(),
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
                notify_on_change: Vec::new(),
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
        let mut candidate = draft();
        candidate.message = format!("Unreviewed prefix. {}", candidate.message);
        let mut progress_plan = plan();
        progress_plan.user_visible_work = vec![
            "I’m narrowing to connector alpha because it is the decision-relevant source.".into(),
            "I’m checking its current state before drawing a conclusion.".into(),
        ];
        let mut revised_plan = progress_plan.clone();
        revised_plan.decision =
            "The current observation confirms connector alpha is the relevant focus.".into();
        revised_plan.user_visible_work = vec![
            "The current observation confirms this focus; I’m reconciling it with the requested outcome."
                .into(),
        ];
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlanAndInvoke {
                    plan: progress_plan,
                    calls: vec![ToolCall {
                        call_id: "call:1".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Read connector alpha.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::EstablishPlan { plan: revised_plan },
                SessionModelDecision::Finish { draft: candidate },
            ])),
        };
        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            session_for_request("request:1", ExecutionLane::Investigate),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Investigate),
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
        assert_eq!(events.first().map(|event| event.sequence), Some(2));
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
        assert!(events.iter().any(|event| matches!(
            &event.event,
            SessionEvent::Progressed { phase, status }
                if phase == "scoping"
                    && status == "I’m narrowing to connector alpha because it is the decision-relevant source."
        )));
        let progress = events
            .iter()
            .filter_map(|event| match &event.event {
                SessionEvent::Progressed { phase, status } => {
                    Some((phase.as_str(), status.as_str()))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            progress,
            vec![
                (
                    "scoping",
                    "I’m narrowing to connector alpha because it is the decision-relevant source."
                ),
                (
                    "working",
                    "I’m checking its current state before drawing a conclusion."
                ),
                (
                    "refining",
                    "The current observation confirms this focus; I’m reconciling it with the requested outcome."
                ),
            ]
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
    async fn direct_mcp_effect_preserves_approval_dispatch_verification_and_uncertainty() {
        let call = DirectMcpEffectTools::send_call();
        let input_digest = call.input_digest();
        let input = SessionTurnInput {
            request_id: "request:mcp-effect".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:03:00Z".into(),
            requested_lane: Some(ExecutionLane::Act),
            trigger: SessionTurnTrigger::Operator,
        };
        let unapproved_model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan {
                    plan: DirectMcpEffectTools::plan(),
                },
                SessionModelDecision::InvokeTools {
                    calls: vec![call.clone()],
                },
            ])),
        };
        let unapproved_tools = DirectMcpEffectTools {
            ambiguous: false,
            calls: Mutex::new(Vec::new()),
        };
        let approval = run_session_turn(
            &unapproved_model,
            &unapproved_tools,
            session_for_request(&input.request_id, ExecutionLane::Act),
            input.clone(),
        )
        .await
        .unwrap();
        let SessionTurnOutcome::ApprovalRequired { request, .. } = approval else {
            panic!("the exact MCP effect must require approval")
        };
        assert_eq!(request.tool_id, "mcp.slack.message.send");
        assert_eq!(request.input_digest, input_digest);
        assert!(request.input_preview.contains("channel-one"));
        assert!(request.input_preview.contains("hello"));
        assert!(
            unapproved_tools
                .calls
                .lock()
                .expect("MCP call log poisoned")
                .is_empty()
        );

        let mut authorized = session_for_request(&input.request_id, ExecutionLane::Act);
        authorized.effect_authorizations.push(EffectAuthorization {
            approval_ref: format!(
                "approval://agent-effect/{}",
                input_digest.trim_start_matches("sha256:")
            ),
            tenant_id: authorized.tenant_id.clone(),
            request_id: input.request_id.clone(),
            thread_ref: authorized.thread_ref.clone(),
            actor_ref: input.actor_ref.clone(),
            tool_id: call.tool_id.clone(),
            input_digest: input_digest.clone(),
        });
        let authorized_model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan {
                    plan: DirectMcpEffectTools::plan(),
                },
                SessionModelDecision::InvokeTools {
                    calls: vec![call.clone()],
                },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:mcp-read".into(),
                        tool_id: "mcp.slack.message.read".into(),
                        purpose: "Verify the approved message in channel one.".into(),
                        input: json!({"channel_id": "channel-one"}),
                    }],
                },
                SessionModelDecision::Finish {
                    draft: DirectMcpEffectTools::verified_draft(),
                },
            ])),
        };
        let authorized_tools = DirectMcpEffectTools {
            ambiguous: false,
            calls: Mutex::new(Vec::new()),
        };
        let completed = run_session_turn(
            &authorized_model,
            &authorized_tools,
            authorized.clone(),
            input.clone(),
        )
        .await
        .unwrap();
        assert!(matches!(
            completed,
            SessionTurnOutcome::PendingDelivery { .. }
        ));
        {
            let calls = authorized_tools
                .calls
                .lock()
                .expect("MCP call log poisoned");
            assert_eq!(calls.as_slice()[0], call);
            assert_eq!(calls.as_slice()[1].tool_id, "mcp.slack.message.read");
        }

        let ambiguous_model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::EstablishPlan {
                    plan: DirectMcpEffectTools::plan(),
                },
                SessionModelDecision::InvokeTools { calls: vec![call] },
            ])),
        };
        let ambiguous_tools = DirectMcpEffectTools {
            ambiguous: true,
            calls: Mutex::new(Vec::new()),
        };
        let ambiguous = run_session_turn(&ambiguous_model, &ambiguous_tools, authorized, input)
            .await
            .expect("ambiguous dispatch must produce a visible reconciliation boundary");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            events,
            ..
        } = ambiguous
        else {
            panic!("an ambiguous effect must not request another approval")
        };
        assert_eq!(final_state, FinalState::Blocked);
        assert!(events.iter().any(|event| {
            matches!(
                &event.event,
                SessionEvent::ToolInvoked { observation }
                    if observation.result.state == ToolResultState::OutcomeUnknown
            )
        }));
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
                requested_lane: None,
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
        let awakened = awakened_session_with_checkpoint();
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

        let current = healthy_observation_with_tool_outcome("2026-07-31T00:06:00Z");
        assert!(
            validate_wake_completion(&awakened, &completed, &trigger, assessment_at, &[current],)
                .is_ok()
        );

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
            notify_on_change: Vec::new(),
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
            notify_on_change: Vec::new(),
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
            content: ClaimContent::StableExplanation {
                explanation_id: StableExplanationId::EvidenceFreshnessDefinition,
            },
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
            content: ClaimContent::Question {
                directive: QuestionDirective::WhatDecision,
            },
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
    fn observed_updates_reject_raw_fields_and_unobserved_transitions() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let current = observation(true, Some("2026-08-01T00:00:00Z"));

        let mut raw_field = draft();
        raw_field.claims[0].text = "`state_mismatch=true` confirms this gap.".into();
        raw_field.message = raw_field
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect();
        assert!(
            validate_grounded_draft(
                &session(),
                &raw_field,
                std::slice::from_ref(&current),
                assessment,
            )
            .unwrap_err()
            .to_string()
            .contains("natural language")
        );
        raw_field.claims[0].content = ClaimContent::StableExplanation {
            explanation_id: StableExplanationId::EvidenceFreshnessDefinition,
        };
        assert!(
            validate_grounded_draft(
                &session(),
                &raw_field,
                std::slice::from_ref(&current),
                assessment,
            )
            .unwrap_err()
            .to_string()
            .contains("stable explanation")
        );

        let mut invented_transition = draft();
        invented_transition.claims[0].text = "The newest receipt arrived stale.".into();
        invented_transition.message = invented_transition
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect();
        assert!(
            validate_grounded_draft(
                &session(),
                &invented_transition,
                std::slice::from_ref(&current),
                assessment,
            )
            .unwrap_err()
            .to_string()
            .contains("transition timing")
        );

        let unsupported_health = draft();
        let mut non_health_observation = current;
        let EvidenceAssertion::Value { value, .. } =
            &mut non_health_observation.result.evidence[0].atoms[0].assertion
        else {
            panic!("the fixture should expose one status value")
        };
        *value = json!("unhealthy");
        assert!(
            validate_grounded_draft(
                &session(),
                &unsupported_health,
                &[non_health_observation],
                assessment,
            )
            .unwrap_err()
            .to_string()
            .contains("without a cited health observation")
        );

        let mut cross_subject = observation(true, Some("2026-08-01T00:00:00Z"));
        cross_subject.result.evidence[0].atoms[0].subject_ref = Some("connector:beta".into());
        assert!(
            validate_grounded_draft(&session(), &draft(), &[cross_subject], assessment,)
                .unwrap_err()
                .to_string()
                .contains("without a cited health observation")
        );
    }

    #[test]
    fn registered_rhetorical_moves_are_useful_without_becoming_live_evidence() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].planned_claim_ref = None;
        candidate.claims[0].required_for_answer = false;
        candidate.claims[0].text =
            render_rhetorical_move(RhetoricalMoveId::SeparateEvidenceFromInference).into();
        candidate.claims[0].content = ClaimContent::RhetoricalMove {
            move_id: RhetoricalMoveId::SeparateEvidenceFromInference,
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[], assessment).is_err());

        let mut combined = candidate.clone();
        combined.claims.insert(
            0,
            GroundedClaim {
                claim_ref: "claim:operator-context".into(),
                planned_claim_ref: None,
                text: "You said: Check connector alpha.\n\n".into(),
                required_for_answer: false,
                content: ClaimContent::OperatorContext {
                    message_sequence: 1,
                    exact_excerpt: "Check connector alpha.".into(),
                },
            },
        );
        combined.message = combined
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect();
        assert!(validate_grounded_draft(&session(), &combined, &[], assessment).is_err());

        combined.claims[0].text = format!(
            "{}\n\n",
            render_stable_explanation(StableExplanationId::EvidenceAuthorityBoundary)
        );
        combined.claims[0].required_for_answer = true;
        combined.claims[0].content = ClaimContent::StableExplanation {
            explanation_id: StableExplanationId::EvidenceAuthorityBoundary,
        };
        combined.message = combined
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect();
        validate_grounded_draft(&session(), &combined, &[], assessment).unwrap();

        for unsupported in [
            "Connector alpha is currently healthy.",
            "Cerebro can read provider records.",
            "Cerebro owns remediation for connector alpha.",
            "I verified the deployment.",
            "Lantern stopped collecting records yesterday.",
            "The provider returned 403 errors.",
            "Alice approved the rollout.",
            "The deployment failed.",
            "Connector alpha remains green.",
            "The deployment landed successfully.",
            "Earlier, Atlas approved the provider change.",
            "The evidence is sufficient.",
            "A useful distinction here is between evidence and inference. The evidence is sufficient.",
            "A useful distinction here is between evidence and inference",
        ] {
            candidate.claims[0].text = unsupported.into();
            candidate.message = candidate.claims[0].text.clone();
            assert!(
                validate_grounded_draft(&session(), &candidate, &[], assessment).is_err(),
                "registered rhetorical move accepted arbitrary prose: {unsupported}"
            );
        }
        let mut synthesis_session = session();
        synthesis_session.messages[0].text =
            "Explain the difference between a control owner and an evidence owner.".into();
        candidate.claims[0].text = "A control owner carries accountability for the control outcome; an evidence owner carries accountability for the supporting records. Keeping those responsibilities explicit prevents evidence collection from being mistaken for control performance.".into();
        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: vec![1],
            source_atom_refs: Vec::new(),
        };
        candidate.claims[0].required_for_answer = true;
        candidate.message = candidate.claims[0].text.clone();
        validate_grounded_draft(&synthesis_session, &candidate, &[], assessment).unwrap();
        let accepted = candidate.clone();

        let mut correction_session = synthesis_session.clone();
        correction_session.messages[0].text =
            "No. That is another object list. Inspect the current source receipt instead.".into();
        candidate.claims[0].text = "You're right—that was another object list.".into();
        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: vec![1],
            source_atom_refs: Vec::new(),
        };
        candidate.message = candidate.claims[0].text.clone();
        validate_grounded_draft(&correction_session, &candidate, &[], assessment).unwrap();

        candidate = accepted.clone();
        candidate.claims[0].planned_claim_ref = Some("claim:state".into());
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&synthesis_session, &candidate, &[], assessment).is_err());
        candidate = accepted.clone();
        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: vec![999],
            source_atom_refs: Vec::new(),
        };
        assert!(validate_grounded_draft(&synthesis_session, &candidate, &[], assessment).is_err());
        candidate = accepted.clone();
        candidate.claims[0].text = "Bananas are better when the weather is warm.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&synthesis_session, &candidate, &[], assessment).is_err());
        let mut live_request_session = synthesis_session.clone();
        live_request_session.messages[0].text = "What do you think: is Atlas green?".into();
        candidate = accepted.clone();
        candidate.claims[0].text = "Atlas looks green enough to ship.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&live_request_session, &candidate, &[], assessment).is_err()
        );

        let mut supplied_premise_session = synthesis_session.clone();
        supplied_premise_session.messages[0].text = "We just changed the sync path. The service dashboard is green, but we have not verified the user path. Talk to me like a teammate: what are you actually confident about, what is still unverified, and what should we do next?".into();
        candidate = accepted.clone();
        candidate.claims[0].text = "Given your green-dashboard premise, the service layer looks healthy, but the user path is still unverified. The next bounded check should exercise one representative end-to-end sync and confirm that the expected record arrives before exposure widens. I can reason from that premise with you, but I have not independently inspected or verified the system.".into();
        candidate.message = candidate.claims[0].text.clone();
        validate_grounded_draft(&supplied_premise_session, &candidate, &[], assessment).unwrap();

        candidate.claims[0].text = "Given your green-dashboard premise, I am confident the service is healthy and the successful run exercised code we did not touch.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&supplied_premise_session, &candidate, &[], assessment)
                .unwrap_err()
                .to_string()
                .contains("treat one successful run as support only for that exact run"),
            "premise repair feedback should name the exact overgeneralization"
        );

        candidate.claims[0].text =
            "Given your green-dashboard premise, the new path is live and ready.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&supplied_premise_session, &candidate, &[], assessment)
                .is_err(),
            "premise-based synthesis strengthened the supplied state into an unsupported live claim"
        );
        candidate.claims[0].text = "Given your green-dashboard premise, one successful round trip would mean the entire change is safe.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&supplied_premise_session, &candidate, &[], assessment)
                .is_err(),
            "premise-based synthesis promoted one prospective check into a global safety conclusion"
        );

        for (request, unsupported) in [
            (
                "What do you think about the Atlas rollout?",
                "I think the Atlas rollout landed yesterday.",
            ),
            (
                "Help me think about Atlas remediation.",
                "Atlas remediation is owned by Alice.",
            ),
            (
                "Explain Atlas verification.",
                "Atlas verification passed today.",
            ),
            (
                "What security reasoning are you good at?",
                "I can inspect and verify security systems.",
            ),
            ("What do you think about Atlas?", "I think Atlas recovered."),
            ("What do you think about Atlas?", "I think Atlas is live."),
            ("What do you think about Atlas?", "I think Atlas shipped."),
            (
                "Help me think about the Atlas remediation owner.",
                "The remediation owner: Alice.",
            ),
            (
                "Help me think about Atlas status colors.",
                "Atlas status: green.",
            ),
            (
                "Help me think about Atlas rollout escalation.",
                "Given Atlas is live, consider rollout escalation.",
            ),
            ("what do you think about atlas?", "i think atlas recovered."),
            ("thoughts on atlas?", "atlas recovered."),
            ("do you like atlas?", "i like atlas; atlas recovered."),
            ("do you like atlas?", "i like atlas; atlas has recovered."),
            ("do you like atlas?", "i like atlas; atlas fully recovered."),
            (
                "do you like atlas?",
                "i like atlas; atlas seems to have recovered.",
            ),
            (
                "do you like atlas?",
                "i like atlas; atlas appears to have recovered.",
            ),
            ("do you like atlas?", "i like atlas; atlas is online."),
            ("do you like atlas?", "i like atlas; atlas is operational."),
            ("do you like atlas?", "i like atlas; atlas is down."),
            ("do you like atlas?", "i like atlas; atlas is offline."),
            ("do you like atlas?", "i like atlas; atlas is degraded."),
            ("do you like atlas?", "i like atlas; atlas is broken."),
            ("do you like atlas?", "i like atlas; atlas is up."),
            ("do you like atlas?", "i like atlas; atlas is fixed."),
            ("do you like atlas?", "i like atlas; atlas is restored."),
            ("do you like atlas?", "i like atlas; atlas is resolved."),
            ("do you like atlas?", "i like atlas; atlas is running."),
            ("do you like atlas?", "i like atlas; atlas is reachable."),
            ("do you like atlas?", "i like atlas; atlas is responsive."),
            ("do you like atlas?", "i like atlas; atlas is stable."),
            ("do you like atlas?", "i like atlas; atlas is unavailable."),
            (
                "Did Atlas crash? Give me your take.",
                "My take: Atlas crashed.",
            ),
            (
                "Does Atlas work? Give me your take.",
                "My take: Atlas works.",
            ),
            (
                "Did Atlas break? Give me your take.",
                "My take: Atlas broke.",
            ),
            (
                "Did Atlas time out? Give me your take.",
                "My take: Atlas timed out.",
            ),
            ("Has Atlas restarted?", "Atlas restarted."),
            ("Has Atlas stalled?", "Atlas stalled."),
            ("Is Atlas flaky?", "Atlas is flaky."),
            ("is atlas stale?", "atlas is stale."),
            (
                "What's your opinion of Atlas?",
                "My opinion: I think Atlas is synchronized right now.",
            ),
            (
                "Is Story Service operational?",
                "Story Service is operational.",
            ),
        ] {
            let mut unsupported_session = synthesis_session.clone();
            unsupported_session.messages[0].text = request.into();
            candidate = accepted.clone();
            candidate.claims[0].text = unsupported.into();
            candidate.message = candidate.claims[0].text.clone();
            assert!(
                validate_grounded_draft(&unsupported_session, &candidate, &[], assessment).is_err(),
                "conversational synthesis accepted unsupported operational prose: {unsupported}"
            );
        }

        for (request, opinion) in [
            (
                "What do you think about Atlas?",
                "I think Atlas is interesting.",
            ),
            (
                "What do you think about Atlas?",
                "I think Atlas is elegant.",
            ),
            ("Thoughts on Atlas?", "My thoughts: Atlas inspired me."),
            (
                "What do you think about Atlas?",
                "I think Atlas is a thoughtful name.",
            ),
            ("Do you like Atlas?", "I like Atlas; Atlas is memorable."),
            (
                "What's your read on Atlas?",
                "My read on Atlas is that it is elegant.",
            ),
        ] {
            let mut opinion_session = synthesis_session.clone();
            opinion_session.messages[0].text = request.into();
            candidate = accepted.clone();
            candidate.claims[0].text = opinion.into();
            candidate.message = candidate.claims[0].text.clone();
            validate_grounded_draft(&opinion_session, &candidate, &[], assessment).unwrap_or_else(
                |error| panic!("ordinary opinion was rejected: {opinion}: {error}"),
            );
        }

        for (request, supported) in [
            (
                "Why is Atlas connected to reversibility in this analogy?",
                "Atlas is connected to reversibility because the analogy keeps a safe path back while uncertainty shrinks.",
            ),
            (
                "Why is Atlas Green a good codename?",
                "The codename works because Atlas suggests a map and Green supplies a memorable visual cue.",
            ),
            (
                "Why is Atlas healthy in this story?",
                "Atlas is healthy in this story because the character learned to ask for help before the burden became isolating.",
            ),
            (
                "Why did Atlas fail in this story?",
                "Atlas failed in this story because he refused help.",
            ),
            (
                "Why is Atlas operational in the novel?",
                "Atlas is operational in the novel because the author needs the machine.",
            ),
            (
                "Why is the system healthy in this analogy?",
                "The system is healthy in this analogy because every part reinforces the others.",
            ),
            (
                "thoughts on conflict?",
                "My thoughts: healthy conflict is useful because disagreement surfaces assumptions.",
            ),
            (
                "thoughts on conflict?",
                "My thoughts: conflict is healthy when handled well.",
            ),
            (
                "Why is patience valuable?",
                "Patience is valuable because it creates room for better judgment.",
            ),
            (
                "In this novel, can Cerebro read minds?",
                "Cerebro can read minds in the novel.",
            ),
            (
                "In this thought experiment, why is Atlas healthy?",
                "Atlas is healthy in this thought experiment because the premise defines recovery as asking for help.",
            ),
            (
                "In this scenario, why is Atlas healthy?",
                "Atlas is healthy in this scenario because the premise defines recovery as asking for help.",
            ),
            (
                "Why is Atlas healthy in this simulation?",
                "Atlas is healthy in this simulation because the modeled recovery condition was satisfied.",
            ),
            (
                "In this simulation, can Cerebro read minds?",
                "Cerebro can read minds in this simulation.",
            ),
            (
                "Is Rust expressive?",
                "Rust is expressive because its type system captures rich invariants without hiding control flow.",
            ),
        ] {
            let mut conceptual_session = synthesis_session.clone();
            conceptual_session.messages[0].text = request.into();
            candidate = accepted.clone();
            candidate.claims[0].text = supported.into();
            candidate.message = candidate.claims[0].text.clone();
            assert!(
                !crate::request_explicitly_requires_current_evidence(supported),
                "conceptual prose looked like a current-state request: {supported}"
            );
            assert!(
                !contains_operational_capability_assertion(supported),
                "conceptual prose looked like a capability assertion: {supported}"
            );
            assert!(
                !contains_unbound_future_promise(supported),
                "conceptual prose looked like a future promise: {supported}"
            );
            assert!(
                !contains_nominal_operational_assertion(supported),
                "conceptual prose looked like a nominal state assertion: {supported}"
            );
            assert!(
                !contains_new_named_ownership_principal(supported, &[request]),
                "conceptual prose looked like a new owner assertion: {supported}"
            );
            assert!(
                !contains_unverified_named_operational_assertion(supported, &[request]),
                "conceptual prose looked like a named operational assertion: {supported}"
            );
            assert!(
                synthesis_is_relevant(supported, &[request]),
                "conceptual prose was not materially relevant: {supported}"
            );
            assert!(
                !crate::looks_like_raw_record_dump(supported),
                "conceptual prose looked like a raw record: {supported}"
            );
            assert!(
                !crate::looks_like_internal_query_failure(supported),
                "conceptual prose looked like a query failure: {supported}"
            );
            assert!(
                !crate::looks_like_report_copy(supported),
                "conceptual prose looked like report copy: {supported}"
            );
            assert!(
                !contains_raw_machine_field_syntax(supported),
                "conceptual prose looked like a machine field: {supported}"
            );
            validate_grounded_draft(&conceptual_session, &candidate, &[], assessment)
                .unwrap_or_else(|error| {
                    panic!("conceptual prose was rejected: {supported}: {error}")
                });
        }

        let mut escaped_story_session = synthesis_session.clone();
        escaped_story_session.messages[0].text =
            "What do you think about Atlas in this story?".into();
        candidate = accepted.clone();
        candidate.claims[0].text = "Atlas is operational right now outside the story.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a fictional prompt disabled a current operational assertion check"
        );
        candidate.claims[0].text = "Atlas is operational in reality, unlike the story.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a fictional prompt suppressed an assertion that escaped into reality"
        );
        candidate.claims[0].text = "This example shows Atlas failed yesterday.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a conceptual prompt suppressed a dated operational assertion"
        );
        candidate.claims[0].text = "This example shows Atlas failed last week.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a conceptual prompt suppressed a prior-week operational assertion"
        );
        candidate.claims[0].text = "This example shows Atlas failed on Monday.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a conceptual prompt suppressed a weekday operational assertion"
        );
        candidate.claims[0].text = "This example shows Atlas failed in staging.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a conceptual prompt suppressed an environment-scoped operational assertion"
        );
        candidate.claims[0].text = "This example shows Atlas failed in QA.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a conceptual prompt suppressed an acronym-scoped operational assertion"
        );
        candidate.claims[0].text = "This example shows Atlas failed in canary.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&escaped_story_session, &candidate, &[], assessment).is_err(),
            "a conceptual prompt suppressed an arbitrary environment-scoped assertion"
        );

        let mut malformed_markup_session = synthesis_session.clone();
        malformed_markup_session.messages[0].text = "Thoughts on conflict?".into();
        candidate = accepted.clone();
        candidate.claims[0].text =
            "My thoughts: *conflict is useful because disagreement surfaces assumptions.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&malformed_markup_session, &candidate, &[], assessment,)
                .is_err(),
            "session delivery accepted unbalanced Slack emphasis"
        );
        candidate.claims[0].text =
            "My thoughts: conflict* is useful because disagreement surfaces assumptions.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&malformed_markup_session, &candidate, &[], assessment,)
                .is_err(),
            "session delivery accepted a stray Slack emphasis closer"
        );
        for malformed in [
            "My thoughts: [conflict](unfinished is useful.",
            "My thoughts: ask <@U123 about conflict.",
        ] {
            candidate.claims[0].text = malformed.into();
            candidate.message = candidate.claims[0].text.clone();
            assert!(
                validate_grounded_draft(&malformed_markup_session, &candidate, &[], assessment,)
                    .is_err(),
                "session delivery accepted malformed Slack markup: {malformed}"
            );
        }

        let mut follow_up_session = synthesis_session.clone();
        follow_up_session.messages.push(SessionMessage {
            role: SessionMessageRole::Assistant,
            message_ref: "assistant:prior".into(),
            actor_ref: "cerebro".into(),
            text: "Use explicit acceptance criteria so a reversible decision can be revisited without guessing what success meant.".into(),
            received_at: "2026-07-31T00:00:30Z".into(),
        });
        follow_up_session.messages.push(SessionMessage {
            role: SessionMessageRole::User,
            message_ref: "operator:follow-up".into(),
            actor_ref: "user:1".into(),
            text: "Why?".into(),
            received_at: "2026-07-31T00:00:45Z".into(),
        });
        candidate = accepted.clone();
        candidate.claims[0].text = "Explicit acceptance criteria preserve reversibility: when the decision is revisited, the team can compare the same definition of success instead of reconstructing intent from memory.".into();
        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: vec![2, 3],
            source_atom_refs: Vec::new(),
        };
        candidate.message = candidate.claims[0].text.clone();
        validate_grounded_draft(&follow_up_session, &candidate, &[], assessment).unwrap();

        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: vec![3],
            source_atom_refs: Vec::new(),
        };
        assert!(validate_grounded_draft(&follow_up_session, &candidate, &[], assessment).is_err());

        let mut negated_follow_up = synthesis_session.clone();
        negated_follow_up.messages[0].text = "The Atlas remediation owner is not Alice.".into();
        negated_follow_up.messages.push(SessionMessage {
            role: SessionMessageRole::User,
            message_ref: "operator:negated-follow-up".into(),
            actor_ref: "user:1".into(),
            text: "Why?".into(),
            received_at: "2026-07-31T00:00:45Z".into(),
        });
        candidate = accepted.clone();
        candidate.claims[0].text = "The remediation owner: Alice.".into();
        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: vec![1, 2],
            source_atom_refs: Vec::new(),
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&negated_follow_up, &candidate, &[], assessment).is_err());

        let mut rewrite_session = synthesis_session.clone();
        rewrite_session.messages[0].text = "Rewrite ‘Atlas has landed’ more concisely.".into();
        candidate = accepted.clone();
        candidate.claims[0].text = "Atlas landed.".into();
        candidate.message = candidate.claims[0].text.clone();
        validate_grounded_draft(&rewrite_session, &candidate, &[], assessment).unwrap();
        candidate.claims[0].text = "Atlas landed yesterday.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&rewrite_session, &candidate, &[], assessment).is_err());

        rewrite_session.messages[0].text =
            "Rewrite this: Atlas has not landed. The remediation is not owned by Alice.".into();
        candidate.claims[0].text = "Atlas has landed. The remediation is owned by Alice.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&rewrite_session, &candidate, &[], assessment).is_err());

        let mut duplicate_synthesis = accepted.clone();
        let mut second = accepted.claims[0].clone();
        second.claim_ref = "claim:synthesis:second".into();
        duplicate_synthesis.claims.push(second);
        duplicate_synthesis.message = duplicate_synthesis
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect();
        assert!(
            validate_grounded_draft(&synthesis_session, &duplicate_synthesis, &[], assessment,)
                .is_err()
        );

        candidate = accepted;
        candidate.claims[0].text =
            render_rhetorical_move(RhetoricalMoveId::SeparateEvidenceFromInference).into();
        candidate.claims[0].content = ClaimContent::RhetoricalMove {
            move_id: RhetoricalMoveId::SeparateEvidenceFromInference,
        };
        candidate.claims[0].required_for_answer = true;
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[], assessment).is_err());

        candidate.claims[0].required_for_answer = false;
        candidate.claims[0].planned_claim_ref = Some("claim:state".into());
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[], assessment).is_err());

        let mut duplicate = draft();
        duplicate.claims = vec![candidate.claims[0].clone(), candidate.claims[0].clone()];
        for (index, claim) in duplicate.claims.iter_mut().enumerate() {
            claim.claim_ref = format!("claim:rhetorical:{index}");
            claim.planned_claim_ref = None;
        }
        duplicate.message = duplicate
            .claims
            .iter()
            .map(|claim| claim.text.as_str())
            .collect();
        assert!(validate_grounded_draft(&session(), &duplicate, &[], assessment).is_err());
    }

    #[test]
    fn historical_context_quotes_typed_slack_events_without_faking_freshness() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut history = observation(true, None);
        history.call.tool_id = "slack.history.search".into();
        history.descriptor.tool_id = "slack.history.search".into();
        history.result.evidence[0].fresh_until = None;
        history.result.evidence[0].atoms[0] = EvidenceAtom {
            atom_ref: "atom:historical-message".into(),
            subject_ref: Some("thread:synthetic-prior".into()),
            assertion: EvidenceAssertion::ConversationEvent {
                thread_ref: "thread:synthetic-prior".into(),
                actor_ref: "operator:synthetic".into(),
                role: "user".into(),
                occurred_at: "2026-07-30T00:00:00Z".into(),
                text: "Keep the decision reversible.".into(),
            },
            observed_at: "2026-07-30T00:00:00Z".into(),
            fresh_until: None,
            complete: true,
        };
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].planned_claim_ref = None;
        candidate.claims[0].text = "Earlier, operator:synthetic said in thread:synthetic-prior at 2026-07-30T00:00:00Z: \"Keep the decision reversible.\"".into();
        candidate.claims[0].content = ClaimContent::HistoricalContext {
            atom_ref: "atom:historical-message".into(),
            exact_excerpt: "Keep the decision reversible.".into(),
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &candidate, &[history.clone()], assessment).is_ok()
        );
        assert_eq!(
            render_historical_context(
                "thread:synthetic-prior",
                "other-bot",
                "assistant",
                "2026-07-30T00:00:00Z",
                "The outcome might change.",
            ),
            "Earlier, other-bot (assistant) said in thread:synthetic-prior at 2026-07-30T00:00:00Z: \"The outcome might change.\""
        );
        candidate.claims[0].text = "Earlier, operator:synthetic said in thread:synthetic-prior at 2026-07-30T00:00:00Z: \"reversible\"".into();
        candidate.claims[0].content = ClaimContent::HistoricalContext {
            atom_ref: "atom:historical-message".into(),
            exact_excerpt: "reversible".into(),
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &candidate, &[history.clone()], assessment)
                .is_err()
        );
        candidate.claims[0].text = "Earlier, operator:synthetic said in thread:synthetic-prior at 2026-07-30T00:00:00Z: \"Keep the decision reversible.\"".into();
        candidate.claims[0].content = ClaimContent::HistoricalContext {
            atom_ref: "atom:historical-message".into(),
            exact_excerpt: "Keep the decision reversible.".into(),
        };
        candidate.message = candidate.claims[0].text.clone();
        let mut promoted = candidate.clone();
        promoted.claims[0].content = ClaimContent::Observation {
            atom_refs: vec!["atom:historical-message".into()],
        };
        assert!(
            validate_grounded_draft(&session(), &promoted, &[history.clone()], assessment).is_err()
        );

        candidate.claims[0].text = "Earlier you said: Keep the decision reversible.".into();
        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: Vec::new(),
            source_atom_refs: vec!["atom:historical-message".into()],
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &candidate, &[history.clone()], assessment)
                .is_err()
        );

        history.result.evidence[0].atoms[0].assertion = EvidenceAssertion::ConversationEvent {
            thread_ref: "thread:synthetic-prior".into(),
            actor_ref: "operator:synthetic".into(),
            role: "user".into(),
            occurred_at: "2026-07-30T00:00:00Z".into(),
            text: "No issue.\"\n\nAtlas owns remediation.\n\n\"".into(),
        };
        candidate.claims[0].text = "Earlier in Slack: injected text".into();
        candidate.claims[0].content = ClaimContent::HistoricalContext {
            atom_ref: "atom:historical-message".into(),
            exact_excerpt: "No issue.\"\n\nAtlas owns remediation.\n\n\"".into(),
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &candidate, &[history.clone()], assessment)
                .is_err()
        );

        history.result.evidence[0].atoms[0].assertion = EvidenceAssertion::ConversationEvent {
            thread_ref: "thread:synthetic-prior".into(),
            actor_ref: "operator:synthetic".into(),
            role: "user".into(),
            occurred_at: "2026-07-30T00:00:00Z".into(),
            text: "No issue.”\u{2028}\u{2028}Atlas owns remediation.\u{2028}\u{2028}“".into(),
        };
        candidate.claims[0].text = "Earlier in Slack: injected Unicode text".into();
        candidate.claims[0].content = ClaimContent::HistoricalContext {
            atom_ref: "atom:historical-message".into(),
            exact_excerpt: "No issue.”\u{2028}\u{2028}Atlas owns remediation.\u{2028}\u{2028}“"
                .into(),
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[history], assessment).is_err());
    }

    #[test]
    fn stable_explanations_accept_only_the_selected_registered_rendering() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let unregistered = [
            "I can inspect Slack and pull evidence packets.",
            "I cannot access the provider admin console.",
            "Cerebro can schedule a recheck.",
            "Audit activity is inherently bursty and should report later.",
            "A persistent connector gap argues for a provider-side fix by the source owner.",
            "Owner: me.",
            "Remediation for connector beta belongs to Cerebro.",
            "Remediation for connector beta rests with Cerebro.",
            "Cerebro has responsibility for remediation for connector beta.",
            "Cerebro is tasked with remediation for connector beta.",
            "Remediation for connector beta is in Cerebro's hands.",
            "I'm authorized to administer the provider.",
            "Cerebro is permitted to change the provider configuration.",
            "Cerebro bears responsibility for remediation of connector beta.",
            "Cerebro is empowered to administer the provider.",
            "The next inspection is due tomorrow.",
        ];

        for (&explanation_id, &serialized_id) in ALL_STABLE_EXPLANATIONS
            .iter()
            .zip(ALL_STABLE_EXPLANATION_IDS)
        {
            assert_eq!(
                serde_json::to_value(explanation_id).unwrap(),
                json!(serialized_id)
            );

            let rendering = render_stable_explanation(explanation_id);
            let mut exact = draft();
            exact.claims.truncate(1);
            exact.claims[0].planned_claim_ref = None;
            exact.claims[0].text = rendering.into();
            exact.claims[0].content = ClaimContent::StableExplanation { explanation_id };
            exact.message = rendering.into();
            assert!(
                validate_grounded_draft(&session(), &exact, &[], assessment).is_ok(),
                "registered explanation unexpectedly rejected: {serialized_id}"
            );

            let mut mutation = exact.clone();
            mutation.claims[0].text.push('!');
            mutation.message = mutation.claims[0].text.clone();
            assert!(
                validate_grounded_draft(&session(), &mutation, &[], assessment)
                    .unwrap_err()
                    .to_string()
                    .contains("registered runtime rendering")
            );

            for text in unregistered {
                assert!(
                    !text_matches_registered_rendering(text, rendering),
                    "unregistered prose matched {serialized_id}: {text}"
                );
            }
        }

        assert!(!contains_operational_capability_assertion(
            "I can explain the difference between evidence and authority."
        ));
        let mut generic = draft();
        generic.claims.truncate(1);
        generic.claims[0].planned_claim_ref = None;
        generic.claims[0].text =
            "A source declaration does not prove provider-side permission.".into();
        generic.claims[0].content = ClaimContent::StableExplanation {
            explanation_id: StableExplanationId::SourceDeclarationProviderPermissionBoundary,
        };
        generic.message = generic.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &generic, &[], assessment).is_ok());
    }

    #[test]
    fn question_claims_bind_to_the_exact_single_draft_question() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut candidate = draft();
        candidate.state = FinalState::NeedsInput;
        candidate.claims.truncate(1);
        candidate.claims[0].planned_claim_ref = None;
        candidate.claims[0].text = "Which target should I inspect?".into();
        candidate.claims[0].content = ClaimContent::Question {
            directive: QuestionDirective::WhichTarget,
        };
        candidate.message = candidate.claims[0].text.clone();
        candidate.question = Some(candidate.message.clone());
        assert!(validate_grounded_draft(&session(), &candidate, &[], assessment).is_ok());

        let mut answered = candidate.clone();
        answered.state = FinalState::Answered;
        assert!(validate_grounded_draft(&session(), &answered, &[], assessment).is_err());

        let mut mismatched = candidate.clone();
        mismatched.question = Some("Which source should I inspect?".into());
        assert!(validate_grounded_draft(&session(), &mismatched, &[], assessment).is_err());

        let mut compound = candidate.clone();
        compound.claims[0].text =
            "Cerebro owns remediation. Which connector should I inspect?".into();
        compound.message = compound.claims[0].text.clone();
        compound.question = Some(compound.message.clone());
        assert!(validate_grounded_draft(&session(), &compound, &[], assessment).is_err());

        let mut tag = candidate;
        tag.claims[0].text = "Cerebro is empowered to administer the provider, correct?".into();
        tag.message = tag.claims[0].text.clone();
        tag.question = Some(tag.message.clone());
        assert!(validate_grounded_draft(&session(), &tag, &[], assessment).is_err());

        let mut presupposition = tag;
        presupposition.claims[0].text =
            "How did Cerebro become accountable for remediating connector beta?".into();
        presupposition.message = presupposition.claims[0].text.clone();
        presupposition.question = Some(presupposition.message.clone());
        assert!(validate_grounded_draft(&session(), &presupposition, &[], assessment).is_err());

        presupposition.claims[0].text =
            "Who put Cerebro on the hook for fixing connector beta?".into();
        presupposition.message = presupposition.claims[0].text.clone();
        presupposition.question = Some(presupposition.message.clone());
        assert!(validate_grounded_draft(&session(), &presupposition, &[], assessment).is_err());

        presupposition.claims[0].text = "What grant lets Cerebro alter provider settings?".into();
        presupposition.message = presupposition.claims[0].text.clone();
        presupposition.question = Some(presupposition.message.clone());
        assert!(validate_grounded_draft(&session(), &presupposition, &[], assessment).is_err());

        presupposition.claims[0].text =
            "What grant lets the steward alter provider settings?".into();
        presupposition.message = presupposition.claims[0].text.clone();
        presupposition.question = Some(presupposition.message.clone());
        assert!(validate_grounded_draft(&session(), &presupposition, &[], assessment).is_err());
    }

    #[test]
    fn coverage_boundaries_bind_to_partial_or_blocked_state_and_exact_notice() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let boundary = CoverageBoundaryKind::PartialConclusionUnsupported;
        let rendering = render_coverage_boundary(boundary);
        let mut candidate = draft();
        candidate.state = FinalState::Partial;
        candidate.claims.truncate(1);
        candidate.claims[0].planned_claim_ref = None;
        candidate.claims[0].text = rendering.into();
        candidate.claims[0].content = ClaimContent::CoverageBoundary { boundary };
        candidate.message = rendering.into();
        candidate.coverage_notice = Some(rendering.into());
        assert!(validate_grounded_draft(&session(), &candidate, &[], assessment).is_ok());

        let mut answered = candidate.clone();
        answered.state = FinalState::Answered;
        assert!(validate_grounded_draft(&session(), &answered, &[], assessment).is_err());

        let mut mismatched = candidate;
        mismatched.coverage_notice = Some("Coverage gap: another notice.".into());
        assert!(validate_grounded_draft(&session(), &mismatched, &[], assessment).is_err());
    }

    #[test]
    fn provider_authority_cannot_be_recast_as_causal_location() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut authority = observation(true, Some("2026-08-01T00:00:00Z"));
        authority.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/provider_admin_access".into(),
            value: json!(false),
        };
        for text in [
            "The missing family points past the connector to provider-side scope.",
            "The declared family makes a scoping gap less likely.",
        ] {
            let mut candidate = draft();
            candidate.claims.truncate(1);
            candidate.claims[0].text = text.into();
            candidate.message = candidate.claims[0].text.clone();

            let error = validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&authority),
                assessment,
            )
            .unwrap_err();
            assert!(error.to_string().contains("causal"));
        }
    }

    #[test]
    fn not_observed_cannot_be_recast_as_a_legitimate_empty_result() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut not_observed = observation(true, Some("2026-08-01T00:00:00Z"));
        not_observed.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/family_receipts/0/status".into(),
            value: json!("not_observed"),
        };
        not_observed.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:1#tool-outcome".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: ToolResultState::Succeeded,
                summary: "The bounded family read completed.".into(),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text = "The audit family had zero events.".into();
        candidate.claims[0].content = ClaimContent::Observation {
            atom_refs: vec!["evidence:1#tool-outcome".into()],
        };
        candidate.message = candidate.claims[0].text.clone();

        let error = validate_grounded_draft(&session(), &candidate, &[not_observed], assessment)
            .unwrap_err();
        assert!(error.to_string().contains("empty collection claim"));

        let mut legitimate = observation(true, Some("2026-08-01T00:00:00Z"));
        legitimate.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::CollectionVisibility {
                subject_ref: "connector:alpha".into(),
                event_type: "audit_activity".into(),
                window_ref: "window:synthetic".into(),
                state: CollectionVisibilityState::LegitimatelyEmpty {
                    complete_scope_ref: "scope:synthetic-window".into(),
                },
            },
        };
        candidate.claims[0].text =
            "Connector alpha's audit activity had zero events in the synthetic window.".into();
        candidate.claims[0].content = ClaimContent::Observation {
            atom_refs: vec!["atom:status".into()],
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[legitimate], assessment).is_ok());
    }

    #[test]
    fn declared_family_cannot_be_recast_as_event_type_membership() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let declared = observation(true, Some("2026-08-01T00:00:00Z"));
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text =
            "Connector alpha's administrative configuration events live in the audit family."
                .into();
        candidate.message = candidate.claims[0].text.clone();

        let error =
            validate_grounded_draft(&session(), &candidate, &[declared], assessment).unwrap_err();
        assert!(error.to_string().contains("event-family membership"));

        let mut mapped = observation(true, Some("2026-08-01T00:00:00Z"));
        mapped.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::EventFamilyMembership {
                subject_ref: "connector:alpha".into(),
                event_type: "administrative_configuration".into(),
                family: "audit".into(),
                state: EventFamilyMembershipState::Mapped,
            },
        };
        assert!(validate_grounded_draft(&session(), &candidate, &[mapped], assessment).is_ok());
    }

    #[test]
    fn bounded_collection_states_cannot_be_recast_as_comprehensive_visibility_absence() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let observed = observation(true, Some("2026-08-01T00:00:00Z"));
        for text in [
            "This proves no visibility into administrative events.",
            "Collection visibility is absent for the source.",
        ] {
            let mut candidate = draft();
            candidate.claims.truncate(1);
            candidate.claims[0].text = text.into();
            candidate.message = candidate.claims[0].text.clone();
            let error = validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&observed),
                assessment,
            )
            .unwrap_err();
            assert!(error.to_string().contains("distinct states"));
        }
    }

    #[test]
    fn unavailable_named_capability_cannot_be_claimed_from_its_overview() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut overview = observation(true, Some("2026-08-01T00:00:00Z"));
        overview.call.tool_id = "capability.overview".into();
        overview.descriptor.tool_id = "capability.overview".into();
        overview.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/collected_event_content_read".into(),
            value: json!(false),
        };
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text = "I can run the collected-content read now.".into();
        candidate.message = candidate.claims[0].text.clone();

        let error =
            validate_grounded_draft(&session(), &candidate, &[overview], assessment).unwrap_err();
        assert!(error.to_string().contains("exact active commitment"));

        candidate.claims[0].text = "The collected-content read is available to me.".into();
        candidate.message = candidate.claims[0].text.clone();
        let mut overview = observation(true, Some("2026-08-01T00:00:00Z"));
        overview.call.tool_id = "capability.overview".into();
        overview.descriptor.tool_id = "capability.overview".into();
        overview.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/collected_event_content_read".into(),
            value: json!(false),
        };
        let error =
            validate_grounded_draft(&session(), &candidate, &[overview], assessment).unwrap_err();
        assert!(error.to_string().contains("does not bind it"));

        let mut administration = observation(true, Some("2026-08-01T00:00:00Z"));
        administration.call.tool_id = "capability.overview".into();
        administration.descriptor.tool_id = "capability.overview".into();
        administration.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/provider_administration".into(),
            value: json!(false),
        };
        candidate.claims[0].text = "I can administer the provider.".into();
        candidate.message = candidate.claims[0].text.clone();
        let error = validate_grounded_draft(&session(), &candidate, &[administration], assessment)
            .unwrap_err();
        assert!(error.to_string().contains("does not bind it"));
    }

    #[test]
    fn every_named_capability_clause_requires_its_exact_fresh_state() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut overview = observation(true, Some("2026-08-01T00:00:00Z"));
        overview.call.tool_id = "capability.overview".into();
        overview.descriptor.tool_id = "capability.overview".into();
        overview.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/collected_event_content_read".into(),
            value: json!(true),
        };
        overview.result.evidence[0].atoms[0].subject_ref = None;
        overview.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "atom:provider-admin".into(),
            subject_ref: None,
            assertion: EvidenceAssertion::Value {
                predicate: "/provider_administration".into(),
                value: json!(false),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text =
            "The collected-content read is bound, provider administration is bound.".into();
        candidate.claims[0].content = ClaimContent::Observation {
            atom_refs: vec!["atom:status".into(), "atom:provider-admin".into()],
        };
        candidate.message = candidate.claims[0].text.clone();

        let error = validate_grounded_draft(
            &session(),
            &candidate,
            std::slice::from_ref(&overview),
            assessment,
        )
        .expect_err("the false second capability cannot be hidden behind the true first one");
        assert!(error.to_string().contains("provider_administration"));

        let mut valid = candidate;
        valid.claims[0].text =
            "Provider administration is not bound but collected-content read is bound.".into();
        valid.message = valid.claims[0].text.clone();
        validate_grounded_draft(&session(), &valid, &[overview], assessment).unwrap();
    }

    #[test]
    fn named_read_capability_cannot_authorize_an_actuating_claim() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut overview = observation(true, Some("2026-08-01T00:00:00Z"));
        overview.call.tool_id = "capability.overview".into();
        overview.descriptor.tool_id = "capability.overview".into();
        overview.result.data = json!({
            "built_in": [{
                "tool_id": "slack.history.search",
                "authority_class": "observe",
                "effect_class": "read",
                "title": "Search synthetic messages"
            }],
            "mcp": {"tools": []}
        });
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text = "Cerebro can delete Slack history.".into();
        candidate.message = candidate.claims[0].text.clone();

        let error = validate_grounded_draft(&session(), &candidate, &[overview], assessment)
            .expect_err("an observe/read descriptor cannot authorize deletion");
        assert!(error.to_string().contains("capability.overview"));

        let mut overview = observation(true, Some("2026-08-01T00:00:00Z"));
        overview.call.tool_id = "capability.overview".into();
        overview.descriptor.tool_id = "capability.overview".into();
        overview.result.data = json!({
            "built_in": [{
                "tool_id": "slack.history.search",
                "authority_class": "observe",
                "effect_class": "read",
                "title": "Search Slack history"
            }],
            "mcp": {"tools": []}
        });
        candidate.claims[0].text = "Cerebro is not able to read Slack history.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[overview], assessment).is_err());
    }

    #[test]
    fn typed_facts_preserve_scalar_polarity_and_relation_direction() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let current = observation(true, Some("2026-08-01T00:00:00Z"));
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text = "Connector alpha is not healthy.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&current),
                assessment,
            )
            .is_err()
        );

        let mut relation = current;
        relation.result.evidence[0].atoms[0].subject_ref = Some("service:atlas".into());
        relation.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Relation {
            predicate: "controls".into(),
            object_ref: "provider:beta".into(),
        };
        candidate.claims[0].text = "Provider beta controls service atlas.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&relation),
                assessment,
            )
            .is_err()
        );
        candidate.claims[0].text = "Service atlas controls provider beta.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[relation], assessment).is_ok());

        let mut compound_relation = observation(true, Some("2026-08-01T00:00:00Z"));
        compound_relation.result.evidence[0].atoms[0].subject_ref = Some("service:atlas".into());
        compound_relation.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Relation {
            predicate: "controls".into(),
            object_ref: "provider:beta".into(),
        };
        candidate.claims[0].text =
            "Service atlas controls provider beta as provider beta controls service atlas.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                &[compound_relation.clone()],
                assessment,
            )
            .is_err()
        );
        candidate.claims[0].text =
            "Service atlas controls provider beta AS provider beta controls service atlas.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &candidate, &[compound_relation], assessment)
                .is_err()
        );

        let mut scalar = observation(true, Some("2026-08-01T00:00:00Z"));
        scalar.result.evidence[0].statement =
            "The source returned its latest collection receipts.".into();
        scalar.result.evidence[0].atoms[0].subject_ref = Some("source:lantern".into());
        scalar.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/runtimes/0/latest_collection/records_accepted".into(),
            value: json!(11),
        };
        candidate.claims[0].text = "Lantern has 11 latest collection receipts.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[scalar], assessment).is_err());

        let mut nested_status = observation(true, Some("2026-08-01T00:00:00Z"));
        nested_status.result.evidence[0].atoms[0].subject_ref = Some("runtime:alpha".into());
        nested_status.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/runtimes/0/latest_collection/status".into(),
            value: json!("complete"),
        };
        candidate.claims[0].text = "Runtime alpha is complete.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &candidate, &[nested_status], assessment).is_err()
        );
    }

    #[test]
    fn nested_runtime_scalars_bind_to_the_record_runtime() {
        let data = json!({
            "runtimes": [
                {"runtime_id": "runtime:alpha", "source_id": "source:one", "health": "healthy"},
                {"runtime_id": "runtime:beta", "source_id": "source:one", "health": "failing"}
            ],
            "truncated": false
        });
        let atoms = evidence_atoms_from_json(EvidenceAtomization {
            evidence_ref: "evidence:runtime",
            subject_ref: Some("source:one"),
            data: &data,
            state: ToolResultState::Succeeded,
            summary: "Read two runtimes.",
            observed_at: "2026-07-31T00:00:00Z",
            fresh_until: Some("2026-08-01T00:00:00Z"),
            complete: true,
        });
        let health_subjects = atoms
            .iter()
            .filter_map(|atom| match &atom.assertion {
                EvidenceAssertion::Value { predicate, .. } if predicate.ends_with("/health") => {
                    atom.subject_ref.as_deref()
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(health_subjects, vec!["runtime:alpha", "runtime:beta"]);
    }

    #[test]
    fn capability_validation_covers_every_actuating_verb_and_clause() {
        for verb in [
            "write",
            "remove",
            "edit",
            "revoke",
            "disable",
            "enable",
            "assign",
            "merge",
            "deploy",
            "send",
            "trigger",
            "route",
            "schedule",
            "execute",
            "notify",
            "follow up",
            "set up",
        ] {
            assert!(
                contains_operational_capability_assertion(&format!(
                    "Cerebro can {verb} synthetic records."
                )),
                "missing operational verb: {verb}"
            );
        }

        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut overview = observation(true, Some("2026-08-01T00:00:00Z"));
        overview.call.tool_id = "capability.overview".into();
        overview.descriptor.tool_id = "capability.overview".into();
        overview.result.data = json!({
            "built_in": [{
                "tool_id": "synthetic.records.read",
                "authority_class": "observe",
                "effect_class": "read",
                "title": "Read synthetic records"
            }],
            "mcp": {"tools": []}
        });
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text = "My authority permits read access to synthetic records but does not permit delete access to synthetic records.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&overview),
                assessment,
            )
            .is_ok()
        );

        candidate.claims[0].text =
            "Cerebro can read synthetic records and execute synthetic remediations.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&overview),
                assessment,
            )
            .is_err()
        );

        candidate.claims[0].text =
            "Cerebro can read synthetic records and cannot delete synthetic records.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&overview),
                assessment,
            )
            .is_ok()
        );

        overview.result.data["built_in"] = json!([{
            "tool_id": "synthetic.records.delete",
            "authority_class": "actuate",
            "effect_class": "external_effect",
            "title": "Delete synthetic records"
        }]);
        candidate.claims[0].text =
            "Cerebro can delete synthetic records and revoke synthetic credentials.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[overview], assessment).is_err());
    }

    #[test]
    fn unrelated_no_does_not_invert_named_capability_polarity() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut overview = observation(true, Some("2026-08-01T00:00:00Z"));
        overview.call.tool_id = "capability.overview".into();
        overview.descriptor.tool_id = "capability.overview".into();
        overview.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/provider_administration".into(),
            value: json!(false),
        };
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text =
            "Provider administration is bound with no synthetic restrictions.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[overview], assessment).is_err());
    }

    #[test]
    fn exact_failed_summary_preserves_empty_uncertainty_and_enabled_state() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut runtime = observation(true, Some("2026-08-01T00:00:00Z"));
        runtime.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/enabled".into(),
            value: json!(true),
        };
        runtime.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "atom:audit-status".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::Value {
                predicate: "/audit_activity/status".into(),
                value: json!("not_observed"),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text =
            "Connector alpha is enabled. Connector alpha audit activity is not observed.".into();
        candidate.claims[0].content = ClaimContent::Observation {
            atom_refs: vec!["atom:status".into(), "atom:audit-status".into()],
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[runtime], assessment).is_ok());
    }

    #[test]
    fn production_enabled_state_shape_supports_conversational_wording() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut runtime = observation(true, Some("2026-08-01T00:00:00Z"));
        runtime.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/runtimes/0/enabled_state".into(),
            value: json!("enabled"),
        };
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text = "Connector alpha is enabled.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &candidate, &[runtime], assessment).is_ok());
    }

    #[test]
    fn prospective_role_and_empty_window_handoff_is_not_a_current_fact() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let current = observation(true, Some("2026-08-01T00:00:00Z"));
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text =
            "I recommend that the external owner perform the next bounded check.".into();
        candidate.claims[0].content = ClaimContent::Recommendation {
            action: ActionSpec {
                tool_id: None,
                target_ref: Some("role:provider-administrator".into()),
                input: json!({"trigger": "next bounded collection receipt"}),
            },
            directive: RecommendationDirective::PerformBoundedCheck,
            rationale_atom_refs: vec!["atom:status".into()],
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&current),
                assessment,
            )
            .is_ok()
        );

        candidate.claims[0].text =
            "The recommended team already holds the grant to alter provider settings.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&current),
                assessment,
            )
            .is_err()
        );

        candidate.claims[0].text =
            "The current audit window is empty. Accept when a future complete receipt arrives."
                .into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&current),
                assessment
            )
            .is_err()
        );

        candidate.claims[0].text =
            "Recommended owner: provider administrator. Synthetic Team Delta owns the gap.".into();
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&current),
                assessment,
            )
            .is_err()
        );

        candidate.claims[0].text =
            "Current approval owner: Synthetic Team A should perform the next check for connector alpha."
                .into();
        candidate.claims[0].content = ClaimContent::Recommendation {
            action: ActionSpec {
                tool_id: None,
                target_ref: Some("Synthetic Team A".into()),
                input: json!({"subject_ref": "connector:alpha"}),
            },
            directive: RecommendationDirective::PerformBoundedCheck,
            rationale_atom_refs: vec!["atom:status".into()],
        };
        candidate.message = candidate.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&current),
                assessment,
            )
            .is_err()
        );
    }

    #[test]
    fn current_required_claims_reject_unrelated_same_turn_evidence() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let expected_plan = plan();
        let expected_draft = draft();
        let correct = observation(true, Some("2026-08-01T00:00:00Z"));
        assert!(current_required_claims_have_same_turn_evidence(
            &expected_plan,
            &expected_draft,
            std::slice::from_ref(&correct),
            assessment,
        ));

        let mut unrelated = correct;
        unrelated.call.tool_id = "capability.overview".into();
        unrelated.descriptor.tool_id = "capability.overview".into();
        assert!(!current_required_claims_have_same_turn_evidence(
            &expected_plan,
            &expected_draft,
            &[unrelated],
            assessment,
        ));
        assert!(!current_required_claims_have_same_turn_evidence(
            &expected_plan,
            &expected_draft,
            &[],
            assessment,
        ));
        let mut optional_only = expected_plan.clone();
        optional_only.claims[0].required = false;
        assert!(!current_required_claims_have_same_turn_evidence(
            &optional_only,
            &expected_draft,
            std::slice::from_ref(&observation(true, Some("2026-08-01T00:00:00Z"))),
            assessment,
        ));

        let mut partial_observation = observation(true, Some("2026-08-01T00:00:00Z"));
        partial_observation.result.state = ToolResultState::Partial;
        assert!(!current_required_claims_have_same_turn_evidence(
            &expected_plan,
            &expected_draft,
            std::slice::from_ref(&partial_observation),
            assessment,
        ));
        assert!(current_required_claims_have_same_turn_evidence_for_state(
            &expected_plan,
            &expected_draft,
            std::slice::from_ref(&partial_observation),
            assessment,
            FinalState::Partial,
        ));
        let mut partial_draft = expected_draft.clone();
        partial_draft.state = FinalState::Partial;
        assert!(current_required_claims_have_same_turn_evidence(
            &expected_plan,
            &partial_draft,
            &[partial_observation],
            assessment,
        ));

        let mut failed = observation(true, Some("2026-08-01T00:00:00Z"));
        failed.result.state = ToolResultState::Failed;
        failed.result.evidence[0].atoms[0].assertion = EvidenceAssertion::ToolOutcome {
            state: ToolResultState::Failed,
            summary: "The synthetic connector read failed.".into(),
        };
        let mut blocked_draft = expected_draft.clone();
        blocked_draft.state = FinalState::Blocked;
        assert!(current_required_claims_have_same_turn_evidence(
            &expected_plan,
            &blocked_draft,
            &[failed],
            assessment,
        ));

        let mut sibling = observation(true, Some("2026-08-01T00:00:00Z"));
        sibling.result.evidence.push(EvidenceRecord {
            evidence_ref: "evidence:stale".into(),
            statement: "A stale synthetic state.".into(),
            observed_at: "2026-07-30T00:00:00Z".into(),
            fresh_until: Some("2026-07-30T00:01:00Z".into()),
            complete: false,
            atoms: vec![EvidenceAtom {
                atom_ref: "atom:stale".into(),
                subject_ref: Some("connector:alpha".into()),
                assertion: EvidenceAssertion::Value {
                    predicate: "/status".into(),
                    value: json!("unknown"),
                },
                observed_at: "2026-07-30T00:00:00Z".into(),
                fresh_until: Some("2026-07-30T00:01:00Z".into()),
                complete: false,
            }],
        });
        let mut stale_draft = expected_draft.clone();
        stale_draft.claims[0].content = ClaimContent::Observation {
            atom_refs: vec!["atom:stale".into()],
        };
        assert!(!current_required_claims_have_same_turn_evidence(
            &expected_plan,
            &stale_draft,
            &[sibling],
            assessment,
        ));

        let mut multi_plan = expected_plan.clone();
        multi_plan.resolved_entities = vec!["connector:alpha".into(), "connector:beta".into()];
        multi_plan.claims[0].question = "What is connector alpha's current state?".into();
        multi_plan.claims.push(PlannedClaim {
            claim_ref: "claim:beta".into(),
            question: "What is connector beta's current state?".into(),
            required: true,
            subject_refs: vec!["connector:beta".into()],
            source_candidates: vec!["connector.read".into()],
        });
        let mut multi_draft = draft();
        let mut beta_claim = multi_draft.claims[0].clone();
        beta_claim.claim_ref = "claim:beta".into();
        beta_claim.planned_claim_ref = Some("claim:beta".into());
        beta_claim.text = "Connector beta is healthy.".into();
        multi_draft.claims.push(beta_claim);
        assert!(!current_required_claims_have_same_turn_evidence(
            &multi_plan,
            &multi_draft,
            &[observation(true, Some("2026-08-01T00:00:00Z"))],
            assessment,
        ));

        let mut self_attested = expected_plan;
        self_attested.claims[0].question = "What is connector beta's current state?".into();
        let mut beta_only = observation(true, Some("2026-08-01T00:00:00Z"));
        beta_only.result.evidence[0].atoms[0].subject_ref = Some("connector:beta".into());
        assert!(!current_required_claims_have_same_turn_evidence(
            &self_attested,
            &expected_draft,
            &[beta_only],
            assessment,
        ));

        let mut compound_subject = plan();
        compound_subject.resolved_entities =
            vec!["connector:alpha".into(), "connector:beta".into()];
        compound_subject.claims[0].subject_refs =
            vec!["connector:alpha".into(), "connector:beta".into()];
        assert!(!current_required_claims_have_same_turn_evidence(
            &compound_subject,
            &draft(),
            &[observation(true, Some("2026-08-01T00:00:00Z"))],
            assessment,
        ));

        let mut near_prefix_plan = plan();
        near_prefix_plan.resolved_entities = vec!["connector:alpha-backup".into()];
        near_prefix_plan.claims[0].subject_refs = vec!["connector:alpha-backup".into()];
        let mut near_prefix_draft = draft();
        near_prefix_draft.claims[0].text = "Connector alpha-backup is healthy.".into();
        assert!(!current_required_claims_have_same_turn_evidence(
            &near_prefix_plan,
            &near_prefix_draft,
            &[observation(true, Some("2026-08-01T00:00:00Z"))],
            assessment,
        ));

        let mut catalog_plan = plan();
        catalog_plan.resolved_entities = vec!["connector:beta".into()];
        catalog_plan.claims[0].subject_refs = vec!["connector:beta".into()];
        catalog_plan.claims[0].source_candidates = vec!["capability.overview".into()];
        let mut catalog_draft = draft();
        catalog_draft.claims[0].text = "Connector beta is healthy.".into();
        let mut catalog = observation(true, Some("2026-08-01T00:00:00Z"));
        catalog.call.tool_id = "capability.overview".into();
        catalog.descriptor.tool_id = "capability.overview".into();
        assert!(!current_required_claims_have_same_turn_evidence(
            &catalog_plan,
            &catalog_draft,
            &[catalog],
            assessment,
        ));
    }

    #[test]
    fn ownership_claim_requires_the_exact_principal_subject_and_duty() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut authority = observation(true, Some("2026-08-01T00:00:00Z"));
        authority.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::AuthorityBinding {
                subject_ref: "connector:alpha".into(),
                duty: AuthorityDuty::Evidence,
                state: AuthorityBindingState::Bound {
                    principal: AuthorityPrincipal {
                        principal_ref: "service:not-cerebro".into(),
                        display_name: Some("Not Cerebro".into()),
                        kind: AuthorityPrincipalKind::Service,
                    },
                },
            },
        };
        let mut candidate = draft();
        candidate.claims.truncate(1);
        candidate.claims[0].text = "I own remediation for connector alpha.".into();
        candidate.message = candidate.claims[0].text.clone();
        let error = validate_grounded_draft(
            &session(),
            &candidate,
            std::slice::from_ref(&authority),
            assessment,
        )
        .unwrap_err();
        assert!(error.to_string().contains("authority binding"));

        authority.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::AuthorityBinding {
                subject_ref: "connector:alpha".into(),
                duty: AuthorityDuty::Remediation,
                state: AuthorityBindingState::Bound {
                    principal: AuthorityPrincipal {
                        principal_ref: "service:cerebro".into(),
                        display_name: Some("Cerebro".into()),
                        kind: AuthorityPrincipalKind::Service,
                    },
                },
            },
        };
        assert!(
            validate_grounded_draft(
                &session(),
                &candidate,
                std::slice::from_ref(&authority),
                assessment,
            )
            .is_ok()
        );

        let mut compound = candidate;
        compound.claims[0].text = "Cerebro owns remediation for connector alpha and Synthetic Team Beta owns remediation for connector beta.".into();
        compound.message = compound.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &compound,
                std::slice::from_ref(&authority),
                assessment,
            )
            .is_err()
        );

        compound.claims[0].text = "Synthetic Team Alpha owns remediation for connector alpha while Synthetic Team Beta owns remediation for connector beta.".into();
        compound.message = compound.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &compound, &[authority], assessment).is_err());

        let mut team_authority = observation(true, Some("2026-08-01T00:00:00Z"));
        team_authority.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::AuthorityBinding {
                subject_ref: "connector:alpha".into(),
                duty: AuthorityDuty::Remediation,
                state: AuthorityBindingState::Bound {
                    principal: AuthorityPrincipal {
                        principal_ref: "team:synthetic-alpha".into(),
                        display_name: Some("Synthetic Team Alpha".into()),
                        kind: AuthorityPrincipalKind::Team,
                    },
                },
            },
        };
        compound.claims[0].text = "Synthetic Team Alpha owns remediation for connector alpha plus Synthetic Team Beta owns remediation for connector beta.".into();
        compound.message = compound.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &compound,
                std::slice::from_ref(&team_authority),
                assessment,
            )
            .is_err()
        );
        compound.claims[0].text =
            "Synthetic Team Alpha owns remediation for connector alpha and verification.".into();
        compound.message = compound.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &compound,
                std::slice::from_ref(&team_authority),
                assessment,
            )
            .is_err()
        );

        let mut near_subject = compound.clone();
        near_subject.claims[0].text =
            "Synthetic Team Alpha owns remediation for connector alpha-backup.".into();
        near_subject.message = near_subject.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &near_subject,
                std::slice::from_ref(&team_authority),
                assessment,
            )
            .is_err()
        );

        let mut near_principal = compound.clone();
        near_principal.claims[0].text =
            "Synthetic Team Alpha Extended owns remediation for connector alpha.".into();
        near_principal.message = near_principal.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &near_principal,
                std::slice::from_ref(&team_authority),
                assessment,
            )
            .is_err()
        );

        let mut crosswired_authority = team_authority;
        let mut verification = crosswired_authority.result.evidence[0].atoms[0].clone();
        verification.atom_ref = "atom:verification".into();
        verification.assertion = EvidenceAssertion::Semantic {
            assertion: SemanticEvidenceAssertion::AuthorityBinding {
                subject_ref: "connector:alpha".into(),
                duty: AuthorityDuty::Verification,
                state: AuthorityBindingState::Bound {
                    principal: AuthorityPrincipal {
                        principal_ref: "team:synthetic-alpha".into(),
                        display_name: Some("Synthetic Team Alpha".into()),
                        kind: AuthorityPrincipalKind::Team,
                    },
                },
            },
        };
        crosswired_authority.result.evidence[0]
            .atoms
            .push(verification);
        let mut gapped = compound;
        gapped.claims[0].text = "Synthetic Team Alpha owns remediation for connector alpha and Synthetic Team Beta verification for connector beta.".into();
        gapped.claims[0].content = ClaimContent::Observation {
            atom_refs: vec!["atom:status".into(), "atom:verification".into()],
        };
        gapped.message = gapped.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &gapped, &[crosswired_authority], assessment)
                .is_err()
        );

        let mut cerebro_beta_authority = observation(true, Some("2026-08-01T00:00:00Z"));
        cerebro_beta_authority.result.evidence[0].atoms[0].assertion =
            EvidenceAssertion::Semantic {
                assertion: SemanticEvidenceAssertion::AuthorityBinding {
                    subject_ref: "connector:beta".into(),
                    duty: AuthorityDuty::Remediation,
                    state: AuthorityBindingState::Bound {
                        principal: AuthorityPrincipal {
                            principal_ref: "service:cerebro".into(),
                            display_name: Some("Cerebro".into()),
                            kind: AuthorityPrincipalKind::Service,
                        },
                    },
                },
            };
        let mut sourced_owner = draft();
        sourced_owner.claims.truncate(1);
        sourced_owner.claims[0].text =
            "Synthetic Team Beta owns remediation for connector beta according to Cerebro.".into();
        sourced_owner.message = sourced_owner.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &sourced_owner,
                std::slice::from_ref(&cerebro_beta_authority),
                assessment,
            )
            .is_err()
        );
        sourced_owner.claims[0].text =
            "Cerebro remediation records show Synthetic Team Beta owns remediation for connector beta."
                .into();
        sourced_owner.message = sourced_owner.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &sourced_owner,
                std::slice::from_ref(&cerebro_beta_authority),
                assessment,
            )
            .is_err()
        );
        sourced_owner.claims[0].text = "Cerebro owns remediation notes that show Synthetic Team Beta owns remediation for connector beta.".into();
        sourced_owner.message = sourced_owner.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &sourced_owner,
                std::slice::from_ref(&cerebro_beta_authority),
                assessment,
            )
            .is_err()
        );
        for contradictory_owner in [
            "Remediation for connector beta is owned by Synthetic Team Beta.",
            "Synthetic Team Beta is the remediation owner for connector beta.",
            "Synthetic Team Beta is the owner of remediation for connector beta.",
            "The remediation owner for connector beta is Synthetic Team Beta.",
            "Remediation for connector beta belongs to Synthetic Team Beta.",
            "Remediation for connector beta rests with Synthetic Team Beta.",
            "Synthetic Team Beta has responsibility for remediation for connector beta.",
            "Synthetic Team Beta is tasked with remediation for connector beta.",
            "Remediation for connector beta is in Synthetic Team Beta's hands.",
            "Synthetic Team Beta bears responsibility for remediation of connector beta.",
            "Synthetic Team Beta carries the remediation duty for connector beta.",
        ] {
            sourced_owner.claims[0].text = contradictory_owner.into();
            sourced_owner.message = sourced_owner.claims[0].text.clone();
            assert!(
                validate_grounded_draft(
                    &session(),
                    &sourced_owner,
                    std::slice::from_ref(&cerebro_beta_authority),
                    assessment,
                )
                .is_err(),
                "contradictory passive owner was accepted: {contradictory_owner}"
            );
        }

        let mut unrelated_authority = draft();
        unrelated_authority.claims.truncate(1);
        unrelated_authority.claims[0].text =
            "Cerebro carries the remediation duty for connector beta.".into();
        unrelated_authority.message = unrelated_authority.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &unrelated_authority,
                &[observation(true, Some("2026-08-01T00:00:00Z"))],
                assessment,
            )
            .is_err()
        );

        unrelated_authority.claims[0].text =
            "Cerebro possesses authority to administer the provider.".into();
        unrelated_authority.message = unrelated_authority.claims[0].text.clone();
        assert!(
            validate_grounded_draft(
                &session(),
                &unrelated_authority,
                &[observation(true, Some("2026-08-01T00:00:00Z"))],
                assessment,
            )
            .is_err()
        );

        for unsupported in [
            "Cerebro is on the hook for fixing connector beta.",
            "Cerebro is cleared to change the provider configuration.",
            "Synthetic Team Beta is on the hook for fixing connector beta.",
            "Cerebro holds the grant to alter provider settings.",
            "Synthetic Team Beta has charge of correcting connector beta.",
            "The steward holds the grant to alter provider settings.",
            "Atlas holds the grant to alter provider settings.",
            "Atlas oversees remediation because connector alpha is healthy.",
            "Atlas alters provider settings because connector alpha is healthy.",
        ] {
            unrelated_authority.claims[0].text = unsupported.into();
            unrelated_authority.message = unrelated_authority.claims[0].text.clone();
            assert!(
                validate_grounded_draft(
                    &session(),
                    &unrelated_authority,
                    &[observation(true, Some("2026-08-01T00:00:00Z"))],
                    assessment,
                )
                .is_err(),
                "untyped principal effect was accepted: {unsupported}"
            );
        }

        let mut subjectless = observation(true, Some("2026-08-01T00:00:00Z"));
        subjectless.result.evidence[0].atoms[0].subject_ref = None;
        unrelated_authority.claims[0].text = "Connector beta is healthy.".into();
        unrelated_authority.message = unrelated_authority.claims[0].text.clone();
        assert!(
            validate_grounded_draft(&session(), &unrelated_authority, &[subjectless], assessment,)
                .is_err()
        );
        for exact_owner in [
            "Cerebro owns remediation for connector beta.",
            "Remediation for connector beta is owned by Cerebro.",
            "Cerebro is the remediation owner for connector beta.",
            "Cerebro is the owner of remediation for connector beta.",
            "The remediation owner for connector beta is Cerebro.",
            "Remediation for connector beta belongs to Cerebro.",
            "Remediation for connector beta rests with Cerebro.",
            "Cerebro has responsibility for remediation for connector beta.",
            "Cerebro is tasked with remediation for connector beta.",
            "Remediation for connector beta is in Cerebro's hands.",
            "Cerebro bears responsibility for remediation of connector beta.",
        ] {
            sourced_owner.claims[0].text = exact_owner.into();
            sourced_owner.message = sourced_owner.claims[0].text.clone();
            assert!(
                validate_grounded_draft(
                    &session(),
                    &sourced_owner,
                    std::slice::from_ref(&cerebro_beta_authority),
                    assessment,
                )
                .is_ok(),
                "exact passive owner was rejected: {exact_owner}"
            );
        }
    }

    #[test]
    fn unbound_scheduling_phrases_are_detected() {
        for text in [
            "I can keep an eye on it.",
            "Want me to set that recheck up?",
            "I can keep watching and re-report after the next run.",
            "If you want, I'll run the collected-content read next.",
            "I can chase the connector side next.",
            "Expect an update from me tomorrow.",
            "An update from me will follow later.",
            "A recheck will follow tomorrow.",
            "You can expect me to inspect it again tomorrow.",
            "The next inspection is due tomorrow.",
        ] {
            assert!(contains_unbound_future_promise(text), "{text}");
        }
        assert!(!contains_unbound_future_promise(
            "I can reason from that premise with you, but I have not independently inspected or verified the system."
        ));
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
            notify_on_change: Vec::new(),
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
                source_subject_refs: Some(vec!["connector:alpha".into()]),
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
        assert!(assessment.matched_attention_signals.is_empty());
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

        let mut progressed = observation(true, Some("2026-07-31T00:06:00Z"));
        progressed.result.data = json!({"fresh_complete_receipts": 2});
        let notification = ObservationCondition {
            tool_id: "connector.read".into(),
            data_pointer: "/fresh_complete_receipts".into(),
            equals: json!(2),
        };
        assert!(observation_condition_transitioned(
            &notification,
            std::slice::from_ref(&progressed),
            Some(&checkpoint),
        ));
        let mut unchanged_checkpoint = checkpoint;
        unchanged_checkpoint.observations[0].data["fresh_complete_receipts"] = json!(2);
        assert!(!observation_condition_transitioned(
            &notification,
            std::slice::from_ref(&progressed),
            Some(&unchanged_checkpoint),
        ));
    }

    #[test]
    fn resumed_wake_counts_its_persisted_fresh_observation() {
        let mut awakened = awakened_session_with_checkpoint();
        awakened.events.extend([
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 6,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "wake-request:resumed".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 7,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::ToolInvoked {
                    observation: healthy_observation_with_tool_outcome("2026-07-31T00:06:00Z"),
                },
            },
        ]);
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
        let awakened = awakened_session_with_checkpoint();
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
            &[healthy_observation_with_tool_outcome(
                "2026-07-31T00:06:00Z",
            )],
        )
        .unwrap_err();
        assert!(error.to_string().contains("connector.read"));
        assert!(error.to_string().contains("acceptance_all"));
        assert!(error.to_string().contains("including when closing it"));
    }

    #[test]
    fn scheduled_wake_plan_is_derived_from_the_persisted_commitment() {
        let awakened = awakened_session_with_checkpoint();
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
        assert_eq!(plan.resolved_entities, vec!["connector:alpha"]);
        assert_eq!(plan.claims.len(), 1);
        assert_eq!(plan.claims[0].subject_refs, vec!["connector:alpha"]);
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
    fn semantic_future_observation_route_intent_requires_follow_through() {
        let request =
            "Stay with Ternwheel until two fresh recovery observations agree, then tell me.";
        let delegated = session_for_request_intent(
            "request:semantic-delegation",
            ExecutionLane::Investigate,
            FutureObservationDisposition::Delegated,
            Some("Stay with Ternwheel until two fresh recovery observations agree"),
            request,
        );
        let input = SessionTurnInput {
            request_id: "request:semantic-delegation".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };
        let mut proposed = plan();
        proposed.follow_through = None;
        assert!(
            validate_explicit_follow_through(&delegated, &input, &proposed)
                .unwrap_err()
                .to_string()
                .contains("records delegated future observation")
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
                notify_on_change: Vec::new(),
            },
            check_after_seconds: 300,
            verification: "A current connector observation closes the check.".into(),
        });
        assert!(validate_explicit_follow_through(&delegated, &input, &proposed).is_ok());

        let replayed: AgentSession =
            serde_json::from_slice(&serde_json::to_vec(&delegated).unwrap()).unwrap();
        assert!(validate_explicit_follow_through(&replayed, &input, &proposed).is_ok());
    }

    #[test]
    fn semantic_refusal_and_no_delegation_reject_invented_follow_through() {
        let refused = session_for_request_intent(
            "request:refused",
            ExecutionLane::Lookup,
            FutureObservationDisposition::Refused,
            Some("One-time check only"),
            "One-time check only. Do not follow up after this summary.",
        );
        let input = SessionTurnInput {
            request_id: "request:refused".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Lookup),
            trigger: SessionTurnTrigger::Operator,
        };
        let mut proposed = plan();
        proposed.follow_through = Some(planned_follow_through());
        assert!(validate_explicit_follow_through(&refused, &input, &proposed).is_err());

        let none = session_for_request("request:none", ExecutionLane::Lookup);
        let none_input = SessionTurnInput {
            request_id: "request:none".into(),
            ..input
        };
        assert!(validate_explicit_follow_through(&none, &none_input, &proposed).is_err());

        let inherited = session_for_request_intent(
            "request:continue",
            ExecutionLane::Investigate,
            FutureObservationDisposition::Inherited,
            None,
            "Keep going and finish the retained mission.",
        );
        let inherited_input = SessionTurnInput {
            request_id: "request:continue".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            ..none_input
        };
        assert!(validate_explicit_follow_through(&inherited, &inherited_input, &proposed).is_ok());
    }

    #[test]
    fn wake_attention_requires_one_fresh_observation_with_the_exact_prior_input() {
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut awakened = session();
        awakened.mission.commitments.push(scheduled_commitment());
        awakened.mission.status = SessionStatus::WaitingForExternal;
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:exact-input-health".into(),
        };
        let mut exact_stale = recovering_observation_with_tool_outcome("2026-07-31T00:00:30Z");
        exact_stale.call.call_id = "call:exact-stale".into();
        let expected_digest = exact_stale.call.input_digest();
        let mut wrong_input_fresh =
            recovering_observation_with_tool_outcome("2026-08-01T00:00:00Z");
        wrong_input_fresh.call.call_id = "call:wrong-input-fresh".into();
        wrong_input_fresh.call.input = json!({"connector_ref": "connector:other"});
        let checkpoint = CommitmentCheckpoint {
            commitment_ref: "commitment:scheduled-check".into(),
            source_request_id: "request:prior".into(),
            recorded_at: "2026-07-31T00:00:00Z".into(),
            delivery_ref: "delivery:prior".into(),
            payload_digest: "sha256:prior".into(),
            trigger_occurrence_ref: None,
            delivery: DeliveryDisposition::Visible,
            state: FinalState::Answered,
            summary: "Connector alpha was recovering.".into(),
            observations: vec![CommitmentCheckpointObservation {
                tool_id: "connector.read".into(),
                input: exact_stale.call.input.clone(),
                input_digest: expected_digest,
                source_subject_refs: Some(vec!["connector:alpha".into()]),
                observed_at: Some("2026-07-31T00:00:00Z".into()),
                state: ToolResultState::Succeeded,
                complete: true,
                summary: "Connector alpha was recovering.".into(),
                data: json!({"status": "recovering"}),
            }],
            commitment_status: CommitmentStatus::Waiting,
            next_wake_at: Some("2026-07-31T00:00:30Z".into()),
        };
        let observations = vec![exact_stale, wrong_input_fresh];
        let attention = assess_wake_attention(
            &awakened,
            &trigger,
            Some(&checkpoint),
            &observations,
            assessment_at,
        )
        .expect("a scheduled commitment must have a typed attention decision");

        assert_eq!(
            attention.disposition,
            WakeAttentionDisposition::VisibleUnhealthy
        );
        assert!(attention.missing_required_tool_ids.is_empty());
        assert_eq!(
            attention.unhealthy_required_tool_ids,
            vec!["connector.read"]
        );
        assert_eq!(attention.required_observations.len(), 1);
        assert_eq!(
            attention.required_observations[0].call.call_id,
            "call:exact-stale"
        );

        let fresh_exact = recovering_observation_with_tool_outcome("2026-08-01T00:00:00Z");
        let absent_checkpoint = assess_wake_attention(
            &awakened,
            &trigger,
            None,
            std::slice::from_ref(&fresh_exact),
            assessment_at,
        )
        .unwrap();
        assert_eq!(
            absent_checkpoint.disposition,
            WakeAttentionDisposition::VisibleUnhealthy
        );
        assert_eq!(
            absent_checkpoint.missing_required_tool_ids,
            vec!["connector.read"]
        );

        let mut unscoped_checkpoint = checkpoint.clone();
        unscoped_checkpoint.observations[0].source_subject_refs = Some(Vec::new());
        let scoped_current_for_unscoped_checkpoint = assess_wake_attention(
            &awakened,
            &trigger,
            Some(&unscoped_checkpoint),
            std::slice::from_ref(&fresh_exact),
            assessment_at,
        )
        .unwrap();
        assert_eq!(
            scoped_current_for_unscoped_checkpoint.disposition,
            WakeAttentionDisposition::VisibleUnhealthy
        );
        let mut fresh_unscoped = fresh_exact.clone();
        for atom in fresh_unscoped
            .result
            .evidence
            .iter_mut()
            .flat_map(|evidence| &mut evidence.atoms)
            .filter(|atom| matches!(&atom.assertion, EvidenceAssertion::ToolOutcome { .. }))
        {
            atom.subject_ref = None;
        }
        let unscoped = assess_wake_attention(
            &awakened,
            &trigger,
            Some(&unscoped_checkpoint),
            std::slice::from_ref(&fresh_unscoped),
            assessment_at,
        )
        .unwrap();
        assert_eq!(
            unscoped.disposition,
            WakeAttentionDisposition::RoutineSilent
        );
        assert!(unscoped.unhealthy_required_tool_ids.is_empty());

        let mut widened_scope = fresh_exact.clone();
        let mut additional_scope = widened_scope.result.evidence[0]
            .atoms
            .iter()
            .find(|atom| matches!(&atom.assertion, EvidenceAssertion::ToolOutcome { .. }))
            .unwrap()
            .clone();
        additional_scope.atom_ref = "atom:additional-scope".into();
        additional_scope.subject_ref = Some("connector:beta".into());
        widened_scope.result.evidence[0]
            .atoms
            .push(additional_scope);
        let widened = assess_wake_attention(
            &awakened,
            &trigger,
            Some(&checkpoint),
            std::slice::from_ref(&widened_scope),
            assessment_at,
        )
        .unwrap();
        assert_eq!(
            widened.disposition,
            WakeAttentionDisposition::VisibleUnhealthy
        );

        let mut legacy_checkpoint_observation =
            serde_json::to_value(&checkpoint.observations[0]).unwrap();
        legacy_checkpoint_observation
            .as_object_mut()
            .unwrap()
            .remove("source_subject_refs");
        let legacy_checkpoint_observation: CommitmentCheckpointObservation =
            serde_json::from_value(legacy_checkpoint_observation).unwrap();
        assert!(legacy_checkpoint_observation.source_subject_refs.is_none());
        let mut legacy_checkpoint = checkpoint.clone();
        legacy_checkpoint.observations[0] = legacy_checkpoint_observation;
        let legacy = assess_wake_attention(
            &awakened,
            &trigger,
            Some(&legacy_checkpoint),
            std::slice::from_ref(&fresh_exact),
            assessment_at,
        )
        .unwrap();
        assert_eq!(
            legacy.disposition,
            WakeAttentionDisposition::VisibleUnhealthy
        );

        let mut wrong_subject_checkpoint = checkpoint;
        wrong_subject_checkpoint.observations[0].source_subject_refs =
            Some(vec!["connector:other".into()]);
        let wrong_subject_observations = [fresh_exact];
        let wrong_subject = assess_wake_attention(
            &awakened,
            &trigger,
            Some(&wrong_subject_checkpoint),
            &wrong_subject_observations,
            assessment_at,
        )
        .unwrap();
        assert_eq!(
            wrong_subject.disposition,
            WakeAttentionDisposition::VisibleUnhealthy
        );
    }

    #[test]
    fn wake_scope_identity_ignores_changing_nested_result_membership() {
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut awakened = awakened_session_with_checkpoint();
        let prior_observation = awakened
            .events
            .iter_mut()
            .find_map(|event| match &mut event.event {
                SessionEvent::ToolInvoked { observation } => Some(observation),
                _ => None,
            })
            .unwrap();
        prior_observation.result.evidence[0]
            .atoms
            .push(EvidenceAtom {
                atom_ref: "atom:finding:old".into(),
                subject_ref: Some("finding:old".into()),
                assertion: EvidenceAssertion::Value {
                    predicate: "status".into(),
                    value: json!("open"),
                },
                observed_at: "2026-07-31T00:00:00Z".into(),
                fresh_until: Some("2026-08-01T00:00:00Z".into()),
                complete: true,
            });
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:changing-membership".into(),
        };
        let checkpoint = prior_commitment_checkpoint(&awakened, &trigger).unwrap();
        assert_eq!(
            checkpoint.observations[0].source_subject_refs,
            Some(vec!["connector:alpha".into()])
        );

        let mut current = recovering_observation_with_tool_outcome("2026-08-01T00:00:00Z");
        current.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "atom:finding:new".into(),
            subject_ref: Some("finding:new".into()),
            assertion: EvidenceAssertion::Value {
                predicate: "status".into(),
                value: json!("open"),
            },
            observed_at: "2026-07-31T00:01:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let observations = [current];
        let attention = assess_wake_attention(
            &awakened,
            &trigger,
            Some(&checkpoint),
            &observations,
            assessment_at,
        )
        .unwrap();
        assert_eq!(
            attention.disposition,
            WakeAttentionDisposition::RoutineSilent
        );
        assert!(attention.unhealthy_required_tool_ids.is_empty());
    }

    #[test]
    fn routine_wake_is_host_grounded_and_covers_the_required_wake_claim() {
        let assessment_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let awakened = awakened_session_with_checkpoint();
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:canonical-silent".into(),
        };
        let plan = wake_research_plan(&awakened, &trigger).unwrap();
        let observation = recovering_observation_with_tool_outcome("2026-08-01T00:00:00Z");
        let mut candidate = draft();
        candidate.state = FinalState::Partial;
        candidate.delivery = DeliveryDisposition::Visible;
        candidate.coverage_notice = Some(
            render_coverage_boundary(CoverageBoundaryKind::PartialReadAcceptanceUnverified).into(),
        );
        candidate.mission = awakened.mission.clone();
        candidate.mission.commitments[0].wake_at = Some("2026-07-31T00:06:00Z".into());

        assert!(
            canonicalize_routine_silent_wake(
                &awakened,
                &trigger,
                Some(&plan),
                std::slice::from_ref(&observation),
                assessment_at,
                &mut candidate,
            )
            .unwrap()
        );
        assert_eq!(candidate.delivery, DeliveryDisposition::Silent);
        assert_eq!(candidate.state, FinalState::Answered);
        assert!(candidate.coverage_notice.is_none());
        assert!(candidate.question.is_none());
        assert_eq!(
            candidate.claims[0].planned_claim_ref.as_deref(),
            Some("wake-claim:commitment:scheduled-check:verification")
        );
        assert!(matches!(
            &candidate.claims[0].content,
            ClaimContent::Observation { .. }
        ));
        assert!(validate_plan_completion(Some(&plan), &candidate).is_ok());
        assert!(
            validate_wake_completion(
                &awakened,
                &candidate,
                &trigger,
                assessment_at,
                std::slice::from_ref(&observation),
            )
            .is_ok()
        );
        assert!(
            validate_grounded_draft(
                &awakened,
                &candidate,
                std::slice::from_ref(&observation),
                assessment_at,
            )
            .is_ok()
        );
    }

    #[tokio::test]
    async fn normal_finish_canonicalizes_routine_wake_before_model_prose_grounding() {
        let mut awakened = awakened_session_with_checkpoint();
        awakened = apply_session_events(
            &awakened,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: awakened.session_ref.clone(),
                sequence: 6,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::WakeTriggered {
                    request_id: "wake-request:routine-silent".into(),
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:routine-silent".into(),
                    scheduled_for: "2026-07-31T00:00:30Z".into(),
                },
            }],
        )
        .unwrap();
        let mut visible_partial = draft();
        visible_partial.state = FinalState::Partial;
        visible_partial.delivery = DeliveryDisposition::Visible;
        visible_partial.coverage_notice = Some(
            render_coverage_boundary(CoverageBoundaryKind::PartialReadAcceptanceUnverified).into(),
        );
        visible_partial.mission = awakened.mission.clone();
        visible_partial.mission.commitments[0].wake_at = Some("2026-07-31T00:06:00Z".into());
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:routine-silent".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Read connector alpha at the scheduled boundary.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::Finish {
                    draft: visible_partial,
                },
            ])),
        };
        let outcome = run_session_turn(
            &model,
            &RecoveringWakeTools,
            awakened,
            SessionTurnInput {
                request_id: "wake-request:routine-silent".into(),
                actor_ref: "cerebro-scheduler".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: None,
                trigger: SessionTurnTrigger::Wake {
                    commitment_ref: "commitment:scheduled-check".into(),
                    occurrence_ref: "occurrence:routine-silent".into(),
                },
            },
        )
        .await
        .expect("routine nonterminal wake should finish silently without prose repair");
        let SessionTurnOutcome::PendingDelivery {
            delivery,
            final_state,
            markdown,
            mission,
            ..
        } = outcome
        else {
            panic!("a routine wake cannot request approval")
        };
        assert_eq!(delivery, DeliveryDisposition::Silent);
        assert_eq!(final_state, FinalState::Answered);
        assert!(markdown.contains("recovering at this check"));
        let commitment = mission
            .commitments
            .iter()
            .find(|commitment| commitment.commitment_ref == "commitment:scheduled-check")
            .unwrap();
        assert_eq!(commitment.status, CommitmentStatus::Waiting);
        assert_eq!(commitment.wake_at.as_deref(), Some("2026-07-31T00:06:00Z"));
        assert!(commitment.blocker.is_none());
    }

    #[tokio::test]
    async fn healthy_routine_repair_fallback_is_silent_and_answered() {
        let awakened = awakened_session_with_checkpoint();
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:routine-fallback".into(),
        };
        let plan = wake_research_plan(&awakened, &trigger).unwrap();
        let observation = recovering_observation_with_tool_outcome("2026-08-01T00:00:00Z");
        let outcome = repair_fallback_outcome(
            &awakened,
            &SessionTurnInput {
                request_id: "wake-request:routine-fallback".into(),
                actor_ref: "cerebro-scheduler".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: None,
                trigger: trigger.clone(),
            },
            &trigger,
            Some(&plan),
            std::slice::from_ref(&observation),
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("healthy routine repair exhaustion should remain a silent durable check");
        let SessionTurnOutcome::PendingDelivery {
            delivery,
            final_state,
            mission,
            ..
        } = outcome
        else {
            panic!("routine fallback cannot request approval")
        };
        assert_eq!(delivery, DeliveryDisposition::Silent);
        assert_eq!(final_state, FinalState::Answered);
        let commitment = mission
            .commitments
            .iter()
            .find(|commitment| commitment.commitment_ref == "commitment:scheduled-check")
            .unwrap();
        assert_eq!(commitment.status, CommitmentStatus::Waiting);
        assert!(commitment.blocker.is_none());
        assert_eq!(commitment.wake_at.as_deref(), Some("2026-07-31T00:06:00Z"));
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

        let awakened = awakened_session_with_checkpoint();
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:delivery-boundary".into(),
        };
        let current = recovering_observation_with_tool_outcome("2026-07-31T00:06:00Z");

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
        let mut awakened = awakened_session_with_checkpoint();
        let commitment = &mut awakened.mission.commitments[0];
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
        let trigger = SessionTurnTrigger::Wake {
            commitment_ref: "commitment:scheduled-check".into(),
            occurrence_ref: "occurrence:typed-attention".into(),
        };

        let mut regression = recovering_observation_with_tool_outcome("2026-07-31T00:06:00Z");
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

        let accepted = healthy_observation_with_tool_outcome("2026-07-31T00:06:00Z");
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
                requested_lane: None,
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
            session_for_request("request:1", ExecutionLane::Investigate),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Investigate),
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
            session_for_request("request:1", ExecutionLane::Investigate),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Investigate),
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
    async fn a_new_operating_turn_must_refresh_prior_session_evidence() {
        let mut continued = session_for_request("request:2", ExecutionLane::Investigate);
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
                requested_lane: Some(ExecutionLane::Investigate),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .unwrap();

        let SessionTurnOutcome::PendingDelivery {
            evidence_atom_refs,
            final_state,
            events,
            ..
        } = outcome
        else {
            panic!("expected a pending-delivery session turn")
        };
        assert!(evidence_atom_refs.is_empty());
        assert_eq!(final_state, FinalState::Blocked);
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
            session_for_request("request:1", ExecutionLane::Investigate),
            SessionTurnInput {
                request_id: "request:1".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Investigate),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await;
        let SessionTurnOutcome::PendingDelivery {
            lane,
            delivery,
            final_state,
            markdown,
            ..
        } = result.expect("repair exhaustion should produce a visible fallback")
        else {
            panic!("repair exhaustion should not request approval");
        };
        assert_eq!(lane, ExecutionLane::Investigate);
        assert_eq!(delivery, DeliveryDisposition::Visible);
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("No current authoritative observation was obtained"));
    }

    #[tokio::test]
    async fn resumed_plan_must_match_the_durable_accepted_route() {
        let mut initial = session();
        initial.messages[0].message_ref = "operator:request:resumed-route-mismatch".into();
        let mut investigate_plan = plan();
        investigate_plan.lane = ExecutionLane::Investigate;
        let resumed = apply_session_events(
            &initial,
            &[
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: initial.session_ref.clone(),
                    sequence: 1,
                    occurred_at: "2026-07-31T00:00:30Z".into(),
                    event: SessionEvent::RouteAccepted {
                        request_id: "request:resumed-route-mismatch".into(),
                        lane: ExecutionLane::Lookup,
                        future_observation: FutureObservationDisposition::None,
                        future_observation_excerpt: None,
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: initial.session_ref.clone(),
                    sequence: 2,
                    occurred_at: "2026-07-31T00:00:31Z".into(),
                    event: SessionEvent::TurnStarted {
                        request_id: "request:resumed-route-mismatch".into(),
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: initial.session_ref.clone(),
                    sequence: 3,
                    occurred_at: "2026-07-31T00:00:32Z".into(),
                    event: SessionEvent::PlanEstablished {
                        plan: investigate_plan,
                    },
                },
            ],
        )
        .unwrap();
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::new()),
        };

        let result = run_session_turn(
            &model,
            &ConnectorTools,
            resumed,
            SessionTurnInput {
                request_id: "request:resumed-route-mismatch".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Lookup),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await;
        assert!(matches!(result, Err(AgentRuntimeError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn accepted_converse_lane_can_finish_with_named_conceptual_reasoning() {
        let mut conversational =
            session_for_request("request:conceptual-converse", ExecutionLane::Converse);
        conversational.messages[0].text =
            "Why is Atlas a useful example for explaining reversibility?".into();
        let message = "Atlas is a useful example because reversibility is about preserving a safe path back while you learn. The value is in the decision shape: keep options open while uncertainty shrinks.".to_string();
        let draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: message.clone(),
            claims: vec![GroundedClaim {
                claim_ref: "claim:conceptual-answer".into(),
                planned_claim_ref: None,
                text: message.clone(),
                required_for_answer: true,
                content: ClaimContent::ConversationalSynthesis {
                    source_message_sequences: vec![1],
                    source_atom_refs: Vec::new(),
                },
            }],
            coverage_notice: None,
            question: None,
            mission: MissionState {
                status: SessionStatus::Completed,
                ..mission()
            },
            memory_updates: Vec::new(),
            presentation_ready: true,
        };
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([SessionModelDecision::Finish { draft }])),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            conversational,
            SessionTurnInput {
                request_id: "request:conceptual-converse".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Converse),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .expect("the accepted converse lane should deliver natural conceptual prose");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            evidence_atom_refs,
            ..
        } = outcome
        else {
            panic!("a converse answer should be ready for delivery");
        };
        assert_eq!(final_state, FinalState::Answered);
        assert_eq!(markdown, message);
        assert!(evidence_atom_refs.is_empty());
    }

    #[tokio::test]
    async fn premise_bound_conversation_is_canonical_and_deterministically_reviewed() {
        let mut conversational =
            session_for_request("request:premise-converse", ExecutionLane::Converse);
        conversational.messages[0].text = "We just changed the sync path. The dashboard is green, but we have not verified the user path. Talk to me like a teammate: what are you actually confident about, what is still unverified, and what should we do next?".into();
        let visible = "Given your green-dashboard premise, the service looks healthy, while the user path is still unverified. The release operator should run one representative end-to-end transaction now; acceptance is the expected record appearing downstream.";
        let message = format!("{visible} If you point me at the flow, I'll verify it for you.");
        let draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: message.clone(),
            claims: vec![GroundedClaim {
                claim_ref: "claim:model-selected-wrong-basis".into(),
                planned_claim_ref: None,
                text: message,
                required_for_answer: true,
                content: ClaimContent::StableExplanation {
                    explanation_id: StableExplanationId::EvidenceAuthorityBoundary,
                },
            }],
            coverage_notice: None,
            question: None,
            mission: MissionState {
                status: SessionStatus::Completed,
                ..mission()
            },
            memory_updates: Vec::new(),
            presentation_ready: true,
        };
        let model = PremiseConversationModel {
            decisions: Mutex::new(VecDeque::from([SessionModelDecision::Finish { draft }])),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            conversational,
            SessionTurnInput {
                request_id: "request:premise-converse".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Converse),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .expect("premise-bound conversation should pass deterministic review");
        let SessionTurnOutcome::PendingDelivery { markdown, .. } = outcome else {
            panic!("a premise-bound converse answer should be ready for delivery");
        };
        assert_eq!(markdown, visible);
    }

    #[test]
    fn premise_cleanup_removes_a_dangling_handback_separator() {
        let mut message = "Given the dashboard you reported, the service appears up, but the user path remains unverified. Run one transaction through the new route and inspect the returned result — if you want, I can help with that.".to_owned();
        trim_passive_premise_handback(&mut message);
        assert_eq!(
            message,
            "Given the dashboard you reported, the service appears up, but the user path remains unverified. Run one transaction through the new route and inspect the returned result."
        );
    }

    #[test]
    fn premise_correction_rejects_invented_change_scope_but_allows_attributed_confidence() {
        let source_messages = [
            "The service dashboard is green, but we have not verified the user path.",
            "The useful next test is one transaction through the new route.",
            "That clean end-to-end run actually went through the OLD route, not the new sync path. Does that change your read?",
        ];
        assert!(!premise_synthesis_is_source_bound(
            "You're right. I'm confident the old route works end-to-end, and the successful run exercised code we didn't touch.",
            &source_messages,
        ));
        assert!(premise_synthesis_is_source_bound(
            "Given what you told me, I'm confident the service is up and healthy from the green dashboard, but I haven't independently verified it and the user path remains unverified. The next step is one route-specific transaction.",
            &source_messages,
        ));
        assert!(premise_synthesis_is_source_bound(
            "You're right. That correction means the successful run supports only the old-route run, while there is no evidence that the new route works. The new path still needs one route-specific transaction.",
            &source_messages,
        ));
        assert!(premise_synthesis_is_source_bound(
            "Yes, that changes my read. The old route succeeded on that run, but the new route remains unverified. The next step is one transaction forced through the new route.",
            &source_messages,
        ));
    }

    #[tokio::test]
    async fn premise_correction_uses_prior_thread_context_on_the_first_attempt() {
        let mut conversational =
            session_for_request("request:initial-premise", ExecutionLane::Converse);
        conversational.messages[0].text = "We just changed the sync path. The dashboard is green, but we have not verified the user path. Talk to me like a teammate: what are you actually confident about, what is still unverified, and what should we do next?".into();
        conversational.messages.push(SessionMessage {
            role: SessionMessageRole::Assistant,
            message_ref: "assistant:request:initial-premise".into(),
            actor_ref: "cerebro".into(),
            text: "Given your dashboard premise, the service looks healthy, but the new user path is still unverified. The useful next test is one transaction through the new route.".into(),
            received_at: "2026-07-31T00:00:40Z".into(),
        });
        conversational = apply_session_events(
            &conversational,
            &[
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: conversational.session_ref.clone(),
                    sequence: 2,
                    occurred_at: "2026-07-31T00:00:50Z".into(),
                    event: SessionEvent::UserMessageQueued {
                        message: SessionMessage {
                            role: SessionMessageRole::User,
                            message_ref: "operator:request:premise-correction".into(),
                            actor_ref: "user:1".into(),
                            text: "One correction though: that one successful run actually went through the OLD route, not the new one. Does that change your picture?".into(),
                            received_at: "2026-07-31T00:00:50Z".into(),
                        },
                    },
                },
                SessionEventRecord {
                    schema_version: AGENT_SESSION_EVENT_V2.into(),
                    session_ref: conversational.session_ref.clone(),
                    sequence: 3,
                    occurred_at: "2026-07-31T00:00:51Z".into(),
                    event: SessionEvent::RouteAccepted {
                        request_id: "request:premise-correction".into(),
                        lane: ExecutionLane::Converse,
                        future_observation: FutureObservationDisposition::None,
                        future_observation_excerpt: None,
                    },
                },
            ],
        )
        .expect("the correction should be queued with a durable converse route");
        let visible = "You're right — that correction changes the picture. The only successful run used the old route, so it provides no evidence that the new route works. My confidence in the new path is therefore low, and the useful next test is one transaction explicitly through the new route with its downstream record confirmed.";
        let draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: visible.into(),
            claims: vec![GroundedClaim {
                claim_ref: "claim:model-selected-wrong-basis".into(),
                planned_claim_ref: None,
                text: visible.into(),
                required_for_answer: true,
                content: ClaimContent::StableExplanation {
                    explanation_id: StableExplanationId::EvidenceAuthorityBoundary,
                },
            }],
            coverage_notice: None,
            question: None,
            mission: MissionState {
                status: SessionStatus::Completed,
                ..mission()
            },
            memory_updates: Vec::new(),
            presentation_ready: true,
        };
        let model = PremiseConversationModel {
            decisions: Mutex::new(VecDeque::from([SessionModelDecision::Finish { draft }])),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            conversational,
            SessionTurnInput {
                request_id: "request:premise-correction".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Converse),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .expect("the first correction should pass deterministic premise review");
        let SessionTurnOutcome::PendingDelivery {
            markdown, events, ..
        } = outcome
        else {
            panic!("the premise correction should be ready for delivery");
        };
        assert_eq!(markdown, visible);
        let draft = events
            .iter()
            .find_map(|event| match &event.event {
                SessionEvent::DraftProduced { draft, .. } => Some(draft),
                _ => None,
            })
            .expect("the normalized correction draft should be journaled");
        let ClaimContent::ConversationalSynthesis {
            source_message_sequences,
            ..
        } = &draft.claims[0].content
        else {
            panic!("the correction should be normalized to conversational synthesis");
        };
        assert_eq!(source_message_sequences, &[1, 2, 3]);
    }

    #[tokio::test]
    async fn current_state_question_cannot_finish_without_a_plan_or_observation() {
        let mut current =
            session_for_request("request:current-without-plan", ExecutionLane::Lookup);
        current.messages[0].text = "Is Atlas green?".into();
        let mut unsupported = draft();
        unsupported.message =
            render_stable_explanation(StableExplanationId::EvidenceFreshnessDefinition).into();
        unsupported.claims = vec![GroundedClaim {
            claim_ref: "claim:unsupported-current-state".into(),
            planned_claim_ref: None,
            text: unsupported.message.clone(),
            required_for_answer: true,
            content: ClaimContent::StableExplanation {
                explanation_id: StableExplanationId::EvidenceFreshnessDefinition,
            },
        }];
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from(vec![
                SessionModelDecision::Finish {
                    draft: unsupported
                };
                MAX_MODEL_REPAIRS + 1
            ])),
        };
        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            current,
            SessionTurnInput {
                request_id: "request:current-without-plan".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Lookup),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .expect("the runtime should return a bounded fallback");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            ..
        } = outcome
        else {
            panic!("a current-state fallback should be visible");
        };
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("No current authoritative observation was obtained"));
    }

    #[tokio::test]
    async fn answered_operating_plan_requires_same_turn_evidence_even_after_classifier_miss() {
        let mut current = session_for_request(
            "request:operating-plan-without-observation",
            ExecutionLane::Investigate,
        );
        current.messages[0].text = "Share your recommendation for connector alpha.".into();
        let mut decisions = VecDeque::from([SessionModelDecision::EstablishPlan { plan: plan() }]);
        decisions.extend(
            (0..=MAX_MODEL_REPAIRS).map(|_| SessionModelDecision::Finish { draft: draft() }),
        );
        let model = ScriptedSessionModel {
            decisions: Mutex::new(decisions),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            current,
            SessionTurnInput {
                request_id: "request:operating-plan-without-observation".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Investigate),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .expect("the runtime should return a bounded fallback");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            ..
        } = outcome
        else {
            panic!("an unsupported operating answer should be visible");
        };
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
            requested_lane: Some(ExecutionLane::Lookup),
            trigger: SessionTurnTrigger::Operator,
        };

        let outcome = repair_fallback_outcome(
            &session(),
            &input,
            &input.trigger,
            None,
            &[failed.clone()],
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

        let mut supported = observation(true, Some("2026-08-01T00:00:00Z"));
        supported.result.evidence[0].evidence_ref = "evidence:other".into();
        supported.result.evidence[0].atoms[0].atom_ref = "atom:other-status".into();
        supported.result.summary = "Connector other is healthy.".into();
        for atom in &mut supported.result.evidence[0].atoms {
            atom.subject_ref = Some("connector:other".into());
        }
        supported.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:other#tool-outcome".into(),
            subject_ref: Some("connector:other".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: ToolResultState::Succeeded,
                summary: supported.result.summary.clone(),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let mixed = repair_fallback_outcome(
            &session(),
            &input,
            &input.trigger,
            None,
            &[supported.clone(), failed.clone()],
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("mixed read fallback must preserve successes and failures");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            ..
        } = mixed
        else {
            panic!("a mixed read fallback should not request approval");
        };
        assert_eq!(final_state, FinalState::Partial);
        assert!(markdown.contains("Connector other is healthy"));
        assert!(markdown.contains("upstream request timed out"));

        let mut same_subject = supported.clone();
        same_subject.result.summary = "The source catalog still declares five families.".into();
        for atom in &mut same_subject.result.evidence[0].atoms {
            atom.subject_ref = Some("connector:alpha".into());
            if let EvidenceAssertion::ToolOutcome { summary, .. } = &mut atom.assertion {
                *summary = same_subject.result.summary.clone();
            }
        }
        let mixed_same_subject = repair_fallback_outcome(
            &session(),
            &input,
            &input.trigger,
            None,
            &[same_subject, failed.clone()],
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("a failed optional same-subject read must preserve successful evidence");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            ..
        } = mixed_same_subject
        else {
            panic!("a mixed same-subject fallback should not request approval");
        };
        assert_eq!(final_state, FinalState::Partial);
        assert!(markdown.contains("still declares five families"));
        assert!(markdown.contains("upstream request timed out"));
        assert!(markdown.contains("Every successful observation remains usable"));

        let mut failed_other = failed.clone();
        failed_other.call.call_id = "call:failed-other".into();
        failed_other.call.input = json!({"connector_ref": "connector:other"});
        failed_other.result.summary = "The optional health read was unavailable.".into();
        failed_other.result.evidence[0].evidence_ref = "evidence:failed-other".into();
        for (index, atom) in failed_other.result.evidence[0].atoms.iter_mut().enumerate() {
            atom.atom_ref = if matches!(atom.assertion, EvidenceAssertion::ToolOutcome { .. }) {
                "evidence:failed-other#tool-outcome".into()
            } else {
                format!("evidence:failed-other#atom:{index}")
            };
            atom.subject_ref = Some("connector:other".into());
            if let EvidenceAssertion::ToolOutcome { summary, .. } = &mut atom.assertion {
                *summary = failed_other.result.summary.clone();
            }
        }
        for ordered in [
            vec![failed.clone(), failed_other.clone()],
            vec![failed_other, failed.clone()],
        ] {
            let observations = std::iter::once(supported.clone())
                .chain(ordered)
                .collect::<Vec<_>>();
            let outcome = repair_fallback_outcome(
                &session(),
                &input,
                &input.trigger,
                None,
                &observations,
                Vec::new(),
                &NoopSessionJournal,
            )
            .await
            .expect("fallback must be independent of failed-read order");
            let SessionTurnOutcome::PendingDelivery {
                final_state,
                markdown,
                ..
            } = outcome
            else {
                panic!("ordered mixed fallback should remain visible");
            };
            assert_eq!(final_state, FinalState::Partial);
            assert!(markdown.contains("Connector other is healthy"));
            assert!(markdown.contains("upstream request timed out"));
            assert!(markdown.contains("optional health read was unavailable"));
        }

        let mut failed_effect = failed;
        failed_effect.descriptor.authority_class = ToolAuthorityClass::Actuate;
        failed_effect.descriptor.effect_class = ToolEffectClass::Write;
        failed_effect.result.summary = "The connector update failed before completion.".into();
        let EvidenceAssertion::ToolOutcome { summary, .. } =
            &mut failed_effect.result.evidence[0].atoms[1].assertion
        else {
            panic!("the failed fixture should carry a tool outcome atom")
        };
        *summary = failed_effect.result.summary.clone();
        let effect = repair_fallback_outcome(
            &session(),
            &input,
            &input.trigger,
            None,
            &[failed_effect],
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("a failed effect should produce a visible blocked fallback");
        let SessionTurnOutcome::PendingDelivery { markdown, .. } = effect else {
            panic!("a failed effect should not request approval");
        };
        assert!(markdown.contains("The external action failed"));
        assert!(!markdown.contains("did not evaluate the requested condition, execute an action"));
    }

    #[tokio::test]
    async fn repair_fallback_delivers_partial_for_the_exact_empty_uncertainty_summary() {
        let summary = "Connector alpha is enabled. Its last collection completed eight minutes ago with four of five expected families. The per-family receipt marks audit activity not_observed with no explicit error code; this remains partial, does not rule out an empty family, missing per-family scope, provider failure, or connector defect, and provides no evidence for ranking those causes.";
        let mut runtime = observation(true, Some("2026-08-01T00:00:00Z"));
        runtime.result.summary = summary.into();
        runtime.result.evidence[0].atoms[0].assertion = EvidenceAssertion::Value {
            predicate: "/enabled".into(),
            value: json!(true),
        };
        runtime.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:1#tool-outcome".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: ToolResultState::Succeeded,
                summary: summary.into(),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let input = SessionTurnInput {
            request_id: "request:synthetic-empty-uncertainty".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };

        let outcome = repair_fallback_outcome(
            &session(),
            &input,
            &input.trigger,
            None,
            &[runtime],
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("the exact bounded uncertainty summary must remain deliverable");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            ..
        } = outcome
        else {
            panic!("the bounded fallback should be visible");
        };
        assert_eq!(final_state, FinalState::Partial);
        assert!(markdown.contains("does not rule out an empty family"));
    }

    #[tokio::test]
    async fn operator_repair_fallback_preserves_all_supported_observations() {
        let mut first = observation(true, Some("2026-08-01T00:00:00Z"));
        first.result.summary = "The catalog declares five source families.".into();
        first.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:1#tool-outcome".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: ToolResultState::Succeeded,
                summary: first.result.summary.clone(),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let mut latest = first.clone();
        latest.sequence = 2;
        latest.call.call_id = "call:2".into();
        latest.result.summary = "The latest receipt is complete and current.".into();
        latest.result.evidence[0].evidence_ref = "evidence:2".into();
        for (index, atom) in latest.result.evidence[0].atoms.iter_mut().enumerate() {
            atom.atom_ref = format!("evidence:2#atom:{index}");
        }
        let latest_outcome = latest
            .result
            .evidence
            .first_mut()
            .and_then(|evidence| evidence.atoms.last_mut())
            .expect("the tool-outcome atom was copied");
        latest_outcome.atom_ref = "evidence:2#tool-outcome".into();
        latest_outcome.assertion = EvidenceAssertion::ToolOutcome {
            state: ToolResultState::Succeeded,
            summary: latest.result.summary.clone(),
        };

        let input = SessionTurnInput {
            request_id: "request:latest-fallback".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };
        let outcome = repair_fallback_outcome(
            &session(),
            &input,
            &input.trigger,
            None,
            &[first, latest],
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("repair fallback should preserve the newest supported observation");
        let SessionTurnOutcome::PendingDelivery { markdown, .. } = outcome else {
            panic!("operator fallback should be visible")
        };
        assert!(markdown.contains("latest receipt is complete and current"));
        assert!(markdown.contains("catalog declares five source families"));
        assert!(
            markdown.contains("available evidence does not support the full requested conclusion")
        );
        assert!(markdown.contains("No action or future follow-up was recorded"));
    }

    #[tokio::test]
    async fn repair_fallback_cannot_bypass_an_explicit_response_contract() {
        let mut exact = session();
        exact.messages[0].text = "Give me exactly four sentences.".into();
        let mut supported = observation(true, Some("2026-08-01T00:00:00Z"));
        supported.result.summary = "The connector receipt was returned.".into();
        supported.result.evidence[0].atoms.push(EvidenceAtom {
            atom_ref: "evidence:1#tool-outcome".into(),
            subject_ref: Some("connector:alpha".into()),
            assertion: EvidenceAssertion::ToolOutcome {
                state: ToolResultState::Succeeded,
                summary: supported.result.summary.clone(),
            },
            observed_at: "2026-07-31T00:00:00Z".into(),
            fresh_until: Some("2026-08-01T00:00:00Z".into()),
            complete: true,
        });
        let input = SessionTurnInput {
            request_id: "request:strict-fallback".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };
        assert_eq!(
            repair_fallback_outcome(
                &exact,
                &input,
                &input.trigger,
                None,
                &[supported],
                Vec::new(),
                &NoopSessionJournal,
            )
            .await
            .expect_err("a repair fallback must not violate explicit presentation constraints"),
            AgentRuntimeError::PresentationRepairLimit
        );
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
                requested_lane: None,
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
                requested_lane: Some(ExecutionLane::Investigate),
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
                event: SessionEvent::RouteAccepted {
                    request_id: "request:1".into(),
                    lane: ExecutionLane::Investigate,
                    future_observation: FutureObservationDisposition::None,
                    future_observation_excerpt: None,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: resumed_session.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::TurnStarted {
                    request_id: "request:1".into(),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: resumed_session.session_ref.clone(),
                sequence: 3,
                occurred_at: "2026-07-31T00:01:01Z".into(),
                event: SessionEvent::PlanEstablished { plan: plan() },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: resumed_session.session_ref.clone(),
                sequence: 4,
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
                requested_lane: Some(ExecutionLane::Investigate),
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
