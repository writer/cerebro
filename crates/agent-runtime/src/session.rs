//! Durable conversation and provenance contracts for the Cerebro agent.
//!
//! A session is the unit of work. Slack and other clients append operator input
//! and render session events; they do not own the model loop or its continuity.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
    time::Instant,
};

use async_trait::async_trait;
use futures_util::future::join_all;
use regex::RegexSet;
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
/// Schema discriminator for one Rust-authored proactive follow-up offer.
pub const PROACTIVE_FOLLOWUP_OFFER_V1: &str = "proactive-followup-offer/v1";
/// Schema discriminator for exact acceptance of a proactive follow-up offer.
pub const PROACTIVE_FOLLOWUP_ACCEPTANCE_V1: &str = "proactive-followup-acceptance/v1";
/// Maximum number of durable memories retained in a session snapshot.
pub const MAX_SESSION_MEMORIES: usize = 128;

const MAX_PLAN_CLAIMS: usize = 16;
const MAX_PLAN_TOOLS: usize = 16;
const MAX_SCOPE_ITEMS: usize = 32;
const MAX_COMMITMENTS: usize = 16;
const MAX_OPEN_LOOPS: usize = 16;
const MAX_VISIBLE_CLAIMS: usize = 32;
const MAX_SESSION_STEPS: usize = 48;
const MAX_MODEL_REPAIRS: usize = 3;
const MAX_IN_TURN_EVIDENCE_DELAY_SECONDS: i64 = 15 * 60;
const MAX_EVIDENCE_CLOCK_SKEW_SECONDS: i64 = 60;
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
const PROACTIVE_FOLLOWUP_TTL_SECONDS: i64 = 60 * 60;
const MAX_PROACTIVE_FOLLOWUP_GROUNDING_REFS: usize = 16;

fn contains_credential_shaped_text(value: &str) -> bool {
    static PATTERNS: OnceLock<RegexSet> = OnceLock::new();
    PATTERNS
        .get_or_init(|| {
            RegexSet::new([
                r"xox[baprs]-[a-z0-9-]+",
                r"(?:akia|asia)[a-z0-9]{16}",
                r"-----begin [a-z0-9 ]{1,32} private key-----",
                r#"(?:bearer|api[_-]?key|token|secret|password)[\"']?[ \t]*[:=][ \t]*(?:\"[^\"\r\n]+\"|'[^'\r\n]+'|[^ \t\r\n,;]{8,})"#,
            ])
            .expect("credential egress patterns are static")
        })
        .is_match(&value.to_ascii_lowercase())
}

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
    /// Optional future observation that may be offered but is not authorized yet.
    #[serde(default)]
    pub follow_through_offer: Option<PlannedFollowThroughOffer>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Closed set of proactive follow-up actions the runtime may render.
pub enum ProactiveFollowupKind {
    /// Re-observe the evidence supporting an answered turn for material changes.
    WatchAnswer,
    /// Retry a bounded observation that left a partial evidence gap.
    RecheckEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Model-authored candidate whose executable payload remains uncommitted until accepted.
pub struct PlannedFollowThroughOffer {
    /// Closed action kind used for deterministic operator copy.
    pub kind: ProactiveFollowupKind,
    /// Exact future-observation contract to materialize after acceptance.
    pub follow_through: PlannedFollowThrough,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Public, evidence-bound offer returned to a capable transport host.
pub struct ProactiveFollowupOffer {
    /// Must equal [`PROACTIVE_FOLLOWUP_OFFER_V1`].
    pub schema_version: String,
    /// Stable digest identity for this exact offer.
    pub offer_ref: String,
    /// Stable action identity checked again on acceptance.
    pub action_key: String,
    /// Exact ordinary operator message that accepts the offer.
    pub action: String,
    /// Short operator-facing label.
    pub title: String,
    /// Tenant boundary copied from the authoritative session.
    pub tenant_id: String,
    /// Thread boundary copied from the authoritative session.
    pub thread_ref: String,
    /// Turn that produced and grounded the offer.
    pub turn_ref: String,
    /// Current evidence atoms that justified offering the follow-through.
    pub grounding_refs: Vec<String>,
    /// RFC 3339 time at which the runtime authored the offer.
    pub created_at: String,
    /// RFC 3339 deadline after which acceptance fails closed.
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
/// Exact full-offer echo submitted with an ordinary turn acceptance.
pub struct ProactiveFollowupAcceptance {
    /// Must equal [`PROACTIVE_FOLLOWUP_ACCEPTANCE_V1`].
    pub schema_version: String,
    /// Full Rust-authored offer; every field must match durable session history.
    pub offer: ProactiveFollowupOffer,
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
    /// Non-factual structure selected by the independent presentation model.
    RhetoricalMove {
        /// Typed rhetorical purpose carried through review.
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
    /// Persists a Rust-authored offer before any transport sends its invitation.
    FollowupOffered {
        /// Request whose validated evidence produced the offer.
        request_id: String,
        /// Public exact offer returned to the transport.
        offer: ProactiveFollowupOffer,
        /// Private future-observation contract materialized only after acceptance.
        planned_follow_through: PlannedFollowThrough,
    },
    /// Records exact acceptance and materializes its offered follow-through.
    FollowupAccepted {
        /// Ordinary operator request carrying the acceptance.
        request_id: String,
        /// Exact durable offer being accepted.
        offer_ref: String,
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
    /// SHA-256 digest of the complete typed draft, including every claim and provenance field.
    pub draft_digest: String,
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
        /// Rust-authored proactive offer, when the capable host may present one.
        proactive_followup_offer: Option<Box<ProactiveFollowupOffer>>,
        /// Offer accepted by this turn, when acceptance committed successfully.
        accepted_followup_ref: Option<String>,
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
            SessionEvent::FollowupOffered {
                request_id,
                offer,
                planned_follow_through,
            } => {
                validate_proactive_followup_offer(&next, request_id, offer)?;
                if next.events.iter().any(|event| {
                    matches!(
                        &event.event,
                        SessionEvent::FollowupOffered { offer: prior, .. }
                            if prior.offer_ref == offer.offer_ref
                    )
                }) {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "proactive follow-up offer identity was reused".into(),
                    ));
                }
                let available = next
                    .events
                    .iter()
                    .filter_map(|event| match &event.event {
                        SessionEvent::ToolInvoked { observation } => {
                            Some(observation.descriptor.tool_id.as_str())
                        }
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>();
                if planned_follow_through
                    .required_tool_ids
                    .iter()
                    .any(|tool_id| !available.contains(tool_id.as_str()))
                {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "proactive follow-up offer references an unavailable observed tool".into(),
                    ));
                }
            }
            SessionEvent::FollowupAccepted {
                request_id,
                offer_ref,
            } => {
                let accepted_at =
                    OffsetDateTime::parse(&record.occurred_at, &Rfc3339).map_err(|_| {
                        AgentRuntimeError::InvalidRequest(
                            "proactive follow-up acceptance time is invalid".into(),
                        )
                    })?;
                let accepted = resolve_followup_offer(&next, offer_ref, accepted_at)?;
                if !bounded(request_id, MAX_TEXT_BYTES)
                    || next.events.iter().any(|event| {
                        matches!(
                            &event.event,
                            SessionEvent::FollowupAccepted { offer_ref: prior, .. }
                                if prior == offer_ref
                        )
                    })
                {
                    return Err(AgentRuntimeError::InvalidRequest(
                        "proactive follow-up offer was already accepted".into(),
                    ));
                }
                let commitment = planned_commitment(&accepted.planned_follow_through, accepted_at)?;
                next.mission
                    .commitments
                    .retain(|candidate| candidate.commitment_ref != commitment.commitment_ref);
                next.mission.commitments.push(commitment);
                next.mission.status = SessionStatus::Active;
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

/// Runs one deterministic session turn from an explicit host-entry time.
///
/// This entry point is intended for replay and evaluation harnesses that use a
/// recorded request clock. Live transports must use [`run_session_turn`] or
/// [`run_session_turn_recorded`] so host time remains authoritative.
pub async fn run_session_turn_at(
    model: &dyn SessionAgentModel,
    tools: &dyn SessionTools,
    session: AgentSession,
    input: SessionTurnInput,
    host_entry_at: OffsetDateTime,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    run_session_turn_recorded_at(
        model,
        tools,
        &NoopSessionJournal,
        session,
        input,
        SessionTurnHostContext {
            host_entry_at,
            host_turn_started_at: Instant::now(),
            proactive_followup_offers_enabled: false,
        },
    )
    .await
}

/// Runs the bounded plan–observe–draft loop and records every accepted event.
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
    let host_entry_at = OffsetDateTime::now_utc();
    let host_turn_started_at = Instant::now();
    run_session_turn_recorded_at(
        model,
        tools,
        journal,
        session,
        input,
        SessionTurnHostContext {
            host_entry_at,
            host_turn_started_at,
            proactive_followup_offers_enabled: false,
        },
    )
    .await
}

/// Runs a recorded session turn with proactive follow-up offer output enabled.
pub async fn run_session_turn_recorded_with_followup_offers(
    model: &dyn SessionAgentModel,
    tools: &dyn SessionTools,
    journal: &dyn SessionJournal,
    session: AgentSession,
    input: SessionTurnInput,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    let host_entry_at = OffsetDateTime::now_utc();
    let host_turn_started_at = Instant::now();
    run_session_turn_recorded_at(
        model,
        tools,
        journal,
        session,
        input,
        SessionTurnHostContext {
            host_entry_at,
            host_turn_started_at,
            proactive_followup_offers_enabled: true,
        },
    )
    .await
}

struct SessionTurnHostContext {
    host_entry_at: OffsetDateTime,
    host_turn_started_at: Instant,
    proactive_followup_offers_enabled: bool,
}

async fn run_session_turn_recorded_at(
    model: &dyn SessionAgentModel,
    tools: &dyn SessionTools,
    journal: &dyn SessionJournal,
    session: AgentSession,
    input: SessionTurnInput,
    host: SessionTurnHostContext,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    let SessionTurnHostContext {
        host_entry_at,
        host_turn_started_at,
        proactive_followup_offers_enabled,
    } = host;
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
    let mut observations = if resumed {
        turn_observations.clone()
    } else {
        recalled_observations_for_trigger(&session, &trigger, assessment_at)
    };
    let resumed_turn_clock = authoritative_turn_clock(&turn_observations, assessment_at)?;
    let host_turn_clock_base =
        validate_host_entry_time(assessment_at, host_entry_at, resumed_turn_clock)?;
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
    let mut rejected_operating_drafts = BTreeSet::new();
    let mut coissued_plan_calls = None;

    for _ in 0..MAX_SESSION_STEPS {
        if repairs > MAX_MODEL_REPAIRS {
            let accepted_at = elapsed_host_turn_time(host_turn_clock_base, host_turn_started_at)?;
            return repair_fallback_outcome(
                &session,
                &input,
                plan.as_ref(),
                &observations,
                accepted_at,
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
                    let accepted_at =
                        elapsed_host_turn_time(host_turn_clock_base, host_turn_started_at)?;
                    return repair_fallback_outcome(
                        &session,
                        &input,
                        plan.as_ref(),
                        &observations,
                        accepted_at,
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
                if let Err(error) = validate_plan(&proposed, &available_tool_ids) {
                    record_operating_repair(&mut repairs, &mut repair_feedback, error.to_string());
                    continue;
                }
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && let Err(error) =
                        validate_explicit_follow_through(&session, &input, Some(&proposed))
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
                let results = join_all(calls.iter().map(|call| async {
                    let result = tools.invoke(&session, &input, call).await;
                    (
                        result,
                        elapsed_host_turn_time(host_turn_clock_base, host_turn_started_at),
                    )
                }))
                .await;
                for (call, (result, recorded_at)) in calls.into_iter().zip(results) {
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
                    let recorded_at = recorded_at?.format(&Rfc3339).map_err(|_| {
                        AgentRuntimeError::InvalidToolCall(
                            "tool observation time could not be formatted".into(),
                        )
                    })?;
                    let observation = ToolObservation {
                        sequence: observations.len() + 1,
                        recorded_at: Some(recorded_at.clone()),
                        call,
                        descriptor,
                        result,
                    };
                    emit_event(
                        &session,
                        &recorded_at,
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
                let accepted_at =
                    elapsed_host_turn_time(host_turn_clock_base, host_turn_started_at)?;
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && let Err(error) =
                        validate_explicit_follow_through(&session, &input, plan.as_ref())
                {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                normalize_message_from_grounded_claims(&mut draft);
                let effective_lane = turn_outcome_lane(&input, plan.as_ref());
                let planned_operating_lane = plan.is_some()
                    && matches!(
                        effective_lane,
                        ExecutionLane::Lookup | ExecutionLane::Investigate | ExecutionLane::Act
                    );
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && plan.is_none()
                    && observations.len() > current_turn_observation_start
                {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        "A tool observation cannot be presented without the typed plan that authorized it. Establish the plan before using tools."
                            .into(),
                    );
                    continue;
                }
                if matches!(trigger, SessionTurnTrigger::Operator)
                    && draft.state == FinalState::Answered
                    && planned_operating_lane
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
                if let Err(error) = canonicalize_routine_silent_wake(
                    &session,
                    &trigger,
                    plan.as_ref(),
                    &observations,
                    assessment_at,
                    &mut draft,
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
                let validated = match validate_grounded_draft_at(
                    &session,
                    &draft,
                    &observations,
                    assessment_at,
                    accepted_at,
                ) {
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
                if let Err(error) =
                    validate_effect_closure_at(&observations, &draft, assessment_at, accepted_at)
                {
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
                    Err(AgentRuntimeError::InvalidFinal(reason)) => {
                        record_draft_repair(
                            &mut rejected_operating_drafts,
                            &draft,
                            &mut repairs,
                            &mut repair_feedback,
                            format!("The presentation review was malformed: {reason}"),
                        );
                        continue;
                    }
                    Err(_) => {
                        return repair_fallback_outcome(
                            &session,
                            &input,
                            plan.as_ref(),
                            &observations,
                            accepted_at,
                            events,
                            journal,
                        )
                        .await;
                    }
                };
                if let Err(error) = validate_message_review(&draft, &review) {
                    record_draft_repair(
                        &mut rejected_operating_drafts,
                        &draft,
                        &mut repairs,
                        &mut repair_feedback,
                        error.to_string(),
                    );
                    continue;
                }
                let proactive_followup = if proactive_followup_offers_enabled {
                    materialize_proactive_followup_offer(
                        &session,
                        &input,
                        plan.as_ref(),
                        &draft,
                        &observations,
                        &validated.evidence_atom_refs,
                        accepted_at,
                    )?
                } else {
                    None
                };
                let mut final_events = Vec::with_capacity(draft.memory_updates.len() + 2);
                final_events.push(SessionEvent::DraftProduced {
                    request_id: input.request_id.clone(),
                    draft: draft.clone(),
                });
                if let Some((offer, planned_follow_through)) = &proactive_followup {
                    final_events.push(SessionEvent::FollowupOffered {
                        request_id: input.request_id.clone(),
                        offer: offer.clone(),
                        planned_follow_through: planned_follow_through.clone(),
                    });
                }
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
                let proactive_followup_offer = proactive_followup.map(|(offer, _)| Box::new(offer));
                return Ok(SessionTurnOutcome::PendingDelivery {
                    lane: turn_outcome_lane(&input, plan.as_ref()),
                    delivery: draft.delivery,
                    markdown: validated.markdown,
                    final_state: draft.state,
                    evidence_atom_refs: validated.evidence_atom_refs,
                    proactive_followup_offer,
                    accepted_followup_ref: None,
                    mission: draft.mission,
                    events,
                });
            }
            SessionModelDecision::EstablishPlanAndInvoke { .. } => {
                unreachable!("coissued plan calls are normalized before decision execution")
            }
        }
    }
    let accepted_at = elapsed_host_turn_time(host_turn_clock_base, host_turn_started_at)?;
    repair_fallback_outcome(
        &session,
        &input,
        plan.as_ref(),
        &observations,
        accepted_at,
        events,
        journal,
    )
    .await
}

fn turn_outcome_lane(_input: &SessionTurnInput, plan: Option<&ResearchPlan>) -> ExecutionLane {
    plan.map_or(ExecutionLane::Converse, |plan| plan.lane)
}

async fn repair_fallback_outcome(
    session: &AgentSession,
    input: &SessionTurnInput,
    plan: Option<&ResearchPlan>,
    observations: &[ToolObservation],
    accepted_at: OffsetDateTime,
    mut events: Vec<SessionEventRecord>,
    journal: &dyn SessionJournal,
) -> Result<SessionTurnOutcome, AgentRuntimeError> {
    let assessment_at = OffsetDateTime::parse(&input.assessment_at, &Rfc3339)
        .map_err(|_| AgentRuntimeError::InvalidRequest("assessment_at is invalid".into()))?;
    let trigger = &input.trigger;
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
            let atom_ref = observation.result.evidence.iter().find_map(|evidence| {
                if !evidence_record_supports_current_draft(
                    evidence,
                    observation.result.state,
                    FinalState::Partial,
                    accepted_at,
                ) {
                    return None;
                }
                evidence
                    .atoms
                    .iter()
                    .find(|atom| atom.atom_ref.ends_with("#tool-outcome"))
                    .map(|atom| atom.atom_ref.clone())
            })?;
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
        validate_effect_closure_at(
            observations,
            &routine_silent_draft,
            assessment_at,
            accepted_at,
        )?;
        let validated = validate_grounded_draft_at(
            session,
            &routine_silent_draft,
            observations,
            assessment_at,
            accepted_at,
        )?;
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
            proactive_followup_offer: None,
            accepted_followup_ref: None,
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
    let validated =
        validate_grounded_draft_at(session, &draft, observations, assessment_at, accepted_at)?;
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
        proactive_followup_offer: None,
        accepted_followup_ref: None,
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
        follow_through_offer: None,
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
    let Ok(turn_clock) = authoritative_turn_clock(std::slice::from_ref(observation), assessment_at)
    else {
        return false;
    };
    observation.result.state == ToolResultState::Succeeded
        && observation.result.evidence.iter().any(|evidence| {
            let observed_at = OffsetDateTime::parse(&evidence.observed_at, &Rfc3339).ok();
            let fresh_until = evidence
                .fresh_until
                .as_deref()
                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok());
            evidence.complete
                && observed_at.is_some_and(|observed_at| observed_at <= turn_clock)
                && fresh_until.is_some_and(|fresh_until| {
                    fresh_until >= turn_clock
                        && observed_at.is_some_and(|observed_at| fresh_until >= observed_at)
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
    let Ok(assessment_at) = authoritative_turn_clock(observations, assessment_at) else {
        return false;
    };
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
            recorded_at: Some(occurred_at.clone()),
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

#[cfg(test)]
fn validate_effect_closure(
    observations: &[ToolObservation],
    draft: &GroundedDraft,
    assessment_at: OffsetDateTime,
) -> Result<(), AgentRuntimeError> {
    let accepted_at = authoritative_turn_clock(observations, assessment_at)?;
    validate_effect_closure_at(observations, draft, assessment_at, accepted_at)
}

fn validate_effect_closure_at(
    observations: &[ToolObservation],
    draft: &GroundedDraft,
    assessment_at: OffsetDateTime,
    accepted_at: OffsetDateTime,
) -> Result<(), AgentRuntimeError> {
    let assessment_at = authoritative_turn_clock_at(observations, assessment_at, accepted_at)?;
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
        data: serde_json::json!({
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
        data: serde_json::json!({
            "error_kind": "effect_outcome_unknown",
            "retryable": false,
            "operator_action": "Reconcile the provider state with a fresh observation before any further effect."
        }),
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

/// Returns the canonical digest for an exact candidate message.
pub fn message_digest(message: &str) -> String {
    let digest = Sha256::digest(message.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

/// Returns the canonical digest for an exact typed candidate draft.
pub fn grounded_draft_digest(draft: &GroundedDraft) -> String {
    let encoded = serde_json::to_vec(draft).expect("grounded drafts are serializable");
    let digest = Sha256::digest(encoded)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{digest}")
}

fn validate_message_review(
    draft: &GroundedDraft,
    review: &MessageReview,
) -> Result<(), AgentRuntimeError> {
    if review.draft_digest != grounded_draft_digest(draft)
        || review.message_digest != message_digest(&draft.message)
        || review.claim_reviews.len() != draft.claims.len()
        || review.attention.delivery != draft.delivery
        || !bounded(&review.attention.reason, MAX_TEXT_BYTES)
        || review
            .undeclared_material
            .iter()
            .any(|item| !bounded(item, MAX_TEXT_BYTES))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "The presentation review must bind the exact message, every declared claim, and the selected delivery disposition."
                .into(),
        ));
    }
    let declared = draft
        .claims
        .iter()
        .map(|claim| claim.claim_ref.as_str())
        .collect::<BTreeSet<_>>();
    let mut reviewed = BTreeSet::new();
    let mut issues = Vec::new();
    for claim in &review.claim_reviews {
        if !bounded(&claim.claim_ref, MAX_TEXT_BYTES)
            || !declared.contains(claim.claim_ref.as_str())
            || !reviewed.insert(claim.claim_ref.as_str())
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "The presentation review must contain one result for each exact claim reference."
                    .into(),
            ));
        }
        match (&claim.verdict, claim.issue.as_deref()) {
            (ClaimReviewVerdict::Supported, None) => {}
            (ClaimReviewVerdict::Unsupported, Some(issue)) if bounded(issue, MAX_TEXT_BYTES) => {
                issues.push(issue);
            }
            _ => {
                return Err(AgentRuntimeError::InvalidFinal(
                    "Supported claim reviews cannot carry an issue, and unsupported reviews require one bounded repair issue."
                        .into(),
                ));
            }
        }
    }
    if reviewed.len() != declared.len() {
        return Err(AgentRuntimeError::InvalidFinal(
            "The presentation review omitted a declared claim.".into(),
        ));
    }
    if !review.undeclared_material.is_empty() {
        issues.push("Remove or declare material that appears outside the reviewed claims.");
    }
    if !review.behavioral.answers_newest_request {
        issues.push("Answer the newest operator request directly.");
    }
    if !review.behavioral.conversational {
        issues.push("Rewrite the response as coherent conversational prose.");
    }
    if !review.behavioral.owns_follow_through {
        issues.push("Bind future Cerebro work to the typed follow-through contract.");
    }
    if !review.behavioral.right_sized {
        issues.push("Match the response detail and length to the request.");
    }
    if !review.behavioral.evidence_boundary_correct {
        issues.push("Separate observations, inferences, and unknowns correctly.");
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(AgentRuntimeError::InvalidFinal(issues.join(" ")))
    }
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
    if plan
        .user_visible_work
        .iter()
        .any(|status| contains_credential_shaped_text(status))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "user-visible plan updates contain credential-shaped text".into(),
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
    if plan.follow_through.is_some() && plan.follow_through_offer.is_some() {
        return Err(AgentRuntimeError::InvalidFinal(
            "a plan cannot both commit and merely offer the same future observation".into(),
        ));
    }
    if let Some(offer) = &plan.follow_through_offer {
        let mut offered_plan = plan.clone();
        offered_plan.follow_through = Some(offer.follow_through.clone());
        offered_plan.follow_through_offer = None;
        validate_plan(&offered_plan, available_tools)?;
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
    plan: Option<&ResearchPlan>,
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
    match (
        route,
        plan.is_some_and(|plan| plan.follow_through.is_some()),
        plan.is_some_and(|plan| plan.follow_through_offer.is_some()),
    ) {
        (FutureObservationDisposition::Delegated, false, _) => Err(
            AgentRuntimeError::InvalidFinal(
                "the semantic route records delegated future observation. Record one bounded follow_through with a stable commitment_ref, exact read tools, acceptance criteria, and a final scheduled commitment; do not finish this as one-turn advice"
                    .into(),
            ),
        ),
        (
            FutureObservationDisposition::Refused | FutureObservationDisposition::None,
            true,
            _,
        ) => Err(AgentRuntimeError::InvalidFinal(
            "the semantic route does not authorize future observation. Remove follow_through and finish the current bounded work; do not invent a timer, monitor, or later assistant update"
                .into(),
        )),
        (FutureObservationDisposition::Delegated, _, true)
        | (FutureObservationDisposition::Refused, _, true) => Err(
            AgentRuntimeError::InvalidFinal(
                "a proactive follow-through offer is allowed only when the operator did not already delegate or explicitly request refusal of future observation"
                    .into(),
            ),
        ),
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

#[derive(Clone, Debug)]
/// Private durable payload resolved after validating an exact public offer.
pub struct ResolvedFollowupOffer {
    /// Exact public offer retained in the event log.
    pub offer: ProactiveFollowupOffer,
    /// Private executor contract retained with the offer event.
    pub planned_follow_through: PlannedFollowThrough,
}

/// Returns the exact durable offer when it is delivered, unaccepted, and current.
pub fn resolve_followup_offer(
    session: &AgentSession,
    offer_ref: &str,
    accepted_at: OffsetDateTime,
) -> Result<ResolvedFollowupOffer, AgentRuntimeError> {
    let (offer_index, offer, planned_follow_through) = session
        .events
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, event)| match &event.event {
            SessionEvent::FollowupOffered {
                offer,
                planned_follow_through,
                ..
            } if offer.offer_ref == offer_ref => {
                Some((index, offer.clone(), planned_follow_through.clone()))
            }
            _ => None,
        })
        .ok_or_else(|| {
            AgentRuntimeError::InvalidRequest(
                "proactive follow-up acceptance has no matching durable offer".into(),
            )
        })?;
    let expires_at = OffsetDateTime::parse(&offer.expires_at, &Rfc3339).map_err(|_| {
        AgentRuntimeError::InvalidRequest("proactive follow-up expiry is invalid".into())
    })?;
    if accepted_at > expires_at {
        return Err(AgentRuntimeError::InvalidRequest(
            "proactive follow-up offer expired before acceptance".into(),
        ));
    }
    let source_request_id = offer
        .turn_ref
        .strip_prefix("agent-turn://")
        .ok_or_else(|| {
            AgentRuntimeError::InvalidRequest(
                "proactive follow-up turn reference is invalid".into(),
            )
        })?;
    let delivered = session.events[offer_index + 1..].iter().any(|event| {
        matches!(
            &event.event,
            SessionEvent::DeliveryRecorded { request_id, .. }
                if request_id == source_request_id
        )
    });
    if !delivered {
        return Err(AgentRuntimeError::InvalidRequest(
            "proactive follow-up offer was not delivered".into(),
        ));
    }
    if session.events[offer_index + 1..].iter().any(|event| {
        matches!(
            &event.event,
            SessionEvent::FollowupAccepted { offer_ref: accepted, .. }
                if accepted == offer_ref
        )
    }) {
        return Err(AgentRuntimeError::InvalidRequest(
            "proactive follow-up offer was already accepted".into(),
        ));
    }
    for grounding_ref in &offer.grounding_refs {
        let current = session.events[..offer_index].iter().any(|event| {
            let SessionEvent::ToolInvoked { observation } = &event.event else {
                return false;
            };
            matches!(
                observation.result.state,
                ToolResultState::Succeeded | ToolResultState::Partial
            ) && observation.result.evidence.iter().any(|evidence| {
                evidence.complete
                    && evidence
                        .fresh_until
                        .as_deref()
                        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                        .is_some_and(|fresh_until| fresh_until >= accepted_at)
                    && evidence.atoms.iter().any(|atom| {
                        atom.atom_ref == *grounding_ref
                            && atom
                                .fresh_until
                                .as_deref()
                                .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                                .is_some_and(|fresh_until| fresh_until >= accepted_at)
                    })
            })
        });
        if !current {
            return Err(AgentRuntimeError::InvalidRequest(
                "proactive follow-up grounding evidence is no longer authoritative".into(),
            ));
        }
    }
    Ok(ResolvedFollowupOffer {
        offer,
        planned_follow_through,
    })
}

/// Validates a full acceptance echo against the durable Rust-authored offer.
pub fn validate_followup_acceptance(
    session: &AgentSession,
    acceptance: &ProactiveFollowupAcceptance,
    accepted_at: OffsetDateTime,
) -> Result<ResolvedFollowupOffer, AgentRuntimeError> {
    if acceptance.schema_version != PROACTIVE_FOLLOWUP_ACCEPTANCE_V1 {
        return Err(AgentRuntimeError::InvalidRequest(
            "proactive follow-up acceptance schema is unsupported".into(),
        ));
    }
    let resolved = resolve_followup_offer(session, &acceptance.offer.offer_ref, accepted_at)?;
    if acceptance.offer != resolved.offer {
        return Err(AgentRuntimeError::InvalidRequest(
            "proactive follow-up acceptance does not exactly match the durable offer".into(),
        ));
    }
    Ok(resolved)
}

/// Builds the deterministic grounded confirmation after a follow-up acceptance event.
pub fn followup_acceptance_draft(
    session: &AgentSession,
    offer_ref: &str,
    assessment_at: OffsetDateTime,
) -> Result<GroundedDraft, AgentRuntimeError> {
    let accepted = session.events.iter().rev().any(|event| {
        matches!(
            &event.event,
            SessionEvent::FollowupAccepted { offer_ref: accepted, .. }
                if accepted == offer_ref
        )
    });
    let resolved = session
        .events
        .iter()
        .rev()
        .find_map(|event| match &event.event {
            SessionEvent::FollowupOffered {
                offer,
                planned_follow_through,
                ..
            } if offer.offer_ref == offer_ref => Some((offer, planned_follow_through)),
            _ => None,
        });
    let Some((_, planned)) = resolved.filter(|_| accepted) else {
        return Err(AgentRuntimeError::InvalidRequest(
            "proactive follow-up confirmation has no accepted durable offer".into(),
        ));
    };
    let commitment = session
        .mission
        .commitments
        .iter()
        .find(|commitment| commitment.commitment_ref == planned.commitment_ref)
        .ok_or_else(|| {
            AgentRuntimeError::InvalidRequest(
                "proactive follow-up acceptance did not materialize its commitment".into(),
            )
        })?;
    let claim_text = render_commitment_claim(commitment).ok_or_else(|| {
        AgentRuntimeError::InvalidRequest(
            "proactive follow-up commitment has no scheduled assessment".into(),
        )
    })?;
    let message = claim_text.clone();
    let draft = GroundedDraft {
        state: FinalState::Answered,
        delivery: DeliveryDisposition::Visible,
        message: message.clone(),
        claims: vec![GroundedClaim {
            claim_ref: format!("followup-accepted:{}", planned.commitment_ref),
            planned_claim_ref: None,
            text: claim_text,
            required_for_answer: true,
            content: ClaimContent::Commitment {
                commitment_ref: planned.commitment_ref.clone(),
            },
        }],
        coverage_notice: None,
        question: None,
        mission: session.mission.clone(),
        memory_updates: Vec::new(),
        presentation_ready: true,
    };
    validate_grounded_draft_at(session, &draft, &[], assessment_at, assessment_at)?;
    Ok(draft)
}

fn validate_proactive_followup_offer(
    session: &AgentSession,
    request_id: &str,
    offer: &ProactiveFollowupOffer,
) -> Result<(), AgentRuntimeError> {
    let created_at = OffsetDateTime::parse(&offer.created_at, &Rfc3339);
    let expires_at = OffsetDateTime::parse(&offer.expires_at, &Rfc3339);
    if offer.schema_version != PROACTIVE_FOLLOWUP_OFFER_V1
        || !bounded(request_id, MAX_TEXT_BYTES)
        || !bounded(&offer.offer_ref, MAX_TEXT_BYTES)
        || !bounded(&offer.action_key, MAX_TEXT_BYTES)
        || !bounded(&offer.action, MAX_TEXT_BYTES)
        || !bounded(&offer.title, MAX_TEXT_BYTES)
        || offer.tenant_id != session.tenant_id
        || offer.thread_ref != session.thread_ref
        || offer.turn_ref != format!("agent-turn://{request_id}")
        || offer.grounding_refs.is_empty()
        || offer.grounding_refs.len() > MAX_PROACTIVE_FOLLOWUP_GROUNDING_REFS
        || offer.grounding_refs.iter().collect::<BTreeSet<_>>().len() != offer.grounding_refs.len()
        || offer
            .grounding_refs
            .iter()
            .any(|reference| !bounded(reference, MAX_TEXT_BYTES))
        || created_at.is_err()
        || expires_at.is_err()
        || created_at
            .ok()
            .zip(expires_at.ok())
            .is_none_or(|(created, expires)| {
                expires <= created
                    || expires - created > Duration::seconds(PROACTIVE_FOLLOWUP_TTL_SECONDS)
            })
    {
        return Err(AgentRuntimeError::InvalidRequest(
            "proactive follow-up offer is invalid or crosses its authority boundary".into(),
        ));
    }
    Ok(())
}

fn materialize_proactive_followup_offer(
    session: &AgentSession,
    input: &SessionTurnInput,
    plan: Option<&ResearchPlan>,
    draft: &GroundedDraft,
    observations: &[ToolObservation],
    cited_atom_refs: &[String],
    accepted_at: OffsetDateTime,
) -> Result<Option<(ProactiveFollowupOffer, PlannedFollowThrough)>, AgentRuntimeError> {
    if !matches!(input.trigger, SessionTurnTrigger::Operator)
        || !matches!(draft.state, FinalState::Answered | FinalState::Partial)
    {
        return Ok(None);
    }
    let Some(candidate) = plan.and_then(|plan| plan.follow_through_offer.as_ref()) else {
        return Ok(None);
    };
    if !matches!(
        (candidate.kind, draft.state),
        (ProactiveFollowupKind::WatchAnswer, FinalState::Answered)
            | (ProactiveFollowupKind::RecheckEvidence, FinalState::Partial)
    ) {
        return Ok(None);
    }
    if session.events.iter().rev().any(|event| match &event.event {
        SessionEvent::FollowupOffered { offer, .. } => {
            OffsetDateTime::parse(&offer.expires_at, &Rfc3339)
                .is_ok_and(|expires_at| expires_at >= accepted_at)
        }
        _ => false,
    }) {
        return Ok(None);
    }
    let cited = cited_atom_refs.iter().collect::<BTreeSet<_>>();
    let required_tools = candidate
        .follow_through
        .required_tool_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut grounding_refs = BTreeSet::new();
    let mut grounded_tools = BTreeSet::new();
    let mut expires_at = accepted_at
        .checked_add(Duration::seconds(PROACTIVE_FOLLOWUP_TTL_SECONDS))
        .ok_or_else(|| AgentRuntimeError::InvalidFinal("follow-up expiry overflowed".into()))?;
    for observation in observations {
        if !required_tools.contains(observation.descriptor.tool_id.as_str()) {
            continue;
        }
        for evidence in &observation.result.evidence {
            if !evidence_record_supports_current_draft(
                evidence,
                observation.result.state,
                draft.state,
                accepted_at,
            ) {
                continue;
            }
            for atom in &evidence.atoms {
                if cited.contains(&atom.atom_ref) {
                    let Some(fresh_until) = atom
                        .fresh_until
                        .as_deref()
                        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                    else {
                        continue;
                    };
                    expires_at = expires_at.min(fresh_until);
                    grounding_refs.insert(atom.atom_ref.clone());
                    grounded_tools.insert(observation.descriptor.tool_id.as_str());
                }
            }
        }
    }
    if grounding_refs.is_empty() || grounded_tools != required_tools || expires_at <= accepted_at {
        return Ok(None);
    }
    let grounding_refs = grounding_refs
        .into_iter()
        .take(MAX_PROACTIVE_FOLLOWUP_GROUNDING_REFS)
        .collect::<Vec<_>>();
    let (action, title) = match candidate.kind {
        ProactiveFollowupKind::WatchAnswer => (
            "watch this answer for changes",
            "Watch this answer for changes",
        ),
        ProactiveFollowupKind::RecheckEvidence => (
            "recheck the missing evidence",
            "Recheck the missing evidence",
        ),
    };
    let created_at = accepted_at.format(&Rfc3339).map_err(|_| {
        AgentRuntimeError::InvalidFinal("follow-up creation time is invalid".into())
    })?;
    let expires_at = expires_at
        .format(&Rfc3339)
        .map_err(|_| AgentRuntimeError::InvalidFinal("follow-up expiry is invalid".into()))?;
    let identity = serde_json::to_vec(&serde_json::json!({
        "tenant_id": session.tenant_id,
        "thread_ref": session.thread_ref,
        "request_id": input.request_id,
        "kind": candidate.kind,
        "grounding_refs": grounding_refs,
        "created_at": created_at,
        "expires_at": expires_at,
        "planned_follow_through": candidate.follow_through,
    }))
    .map_err(|_| AgentRuntimeError::InvalidFinal("follow-up identity is invalid".into()))?;
    let digest = Sha256::digest(identity)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let offer = ProactiveFollowupOffer {
        schema_version: PROACTIVE_FOLLOWUP_OFFER_V1.into(),
        offer_ref: format!("proactive-followup://sha256/{digest}"),
        action_key: format!("followup:{}", &digest[..32]),
        action: action.into(),
        title: title.into(),
        tenant_id: session.tenant_id.clone(),
        thread_ref: session.thread_ref.clone(),
        turn_ref: format!("agent-turn://{}", input.request_id),
        grounding_refs,
        created_at,
        expires_at,
    };
    validate_proactive_followup_offer(session, &input.request_id, &offer)?;
    Ok(Some((offer, candidate.follow_through.clone())))
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
    let Some(follow_through) = plan.and_then(|plan| {
        plan.follow_through.as_ref().or_else(|| {
            plan.follow_through_offer
                .as_ref()
                .map(|offer| &offer.follow_through)
        })
    }) else {
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
    let accepted_at = authoritative_turn_clock(observations, assessment_at)?;
    validate_grounded_draft_at(session, draft, observations, assessment_at, accepted_at)
}

fn validate_grounded_draft_at(
    session: &AgentSession,
    draft: &GroundedDraft,
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
    accepted_at: OffsetDateTime,
) -> Result<ValidatedDraft, AgentRuntimeError> {
    validate_session(session)?;
    validate_mission(&draft.mission)?;
    let assessment_at = authoritative_turn_clock_at(observations, assessment_at, accepted_at)?;
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
    if contains_credential_shaped_text(&draft.message) {
        return Err(AgentRuntimeError::InvalidFinal(
            "visible response contains credential-shaped text".into(),
        ));
    }

    let atoms = evidence_atoms(observations, assessment_at)?;
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
            "Coverage gap: I couldn't obtain current evidence, so I can't evaluate the requested condition honestly. I did not take action or schedule a follow-up. Retry once; if this persists, inspect the agent's model and capability health."
        }
        CoverageBoundaryKind::PartialConclusionUnsupported => {
            "Coverage gap: The requested conclusion remains only partially supported."
        }
        CoverageBoundaryKind::BlockedMissingAuthoritativeEvidence => {
            "Coverage gap: The requested conclusion is blocked by missing authoritative evidence."
        }
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
            if message.role != SessionMessageRole::User
                || Some(message.actor_ref.as_str()) != context.operator_actor_ref
                || exact_excerpt.is_empty()
                || exact_excerpt.chars().any(unsafe_context_excerpt_character)
                || message.text.trim() != exact_excerpt.trim()
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
        ClaimContent::RhetoricalMove { .. } => {
            if claim.planned_claim_ref.is_some() || claim.required_for_answer {
                return Err(AgentRuntimeError::InvalidFinal(
                    "a rhetorical move must be optional and unplanned".into(),
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
            if exact_excerpt.is_empty()
                || exact_excerpt.len() > 1_000
                || exact_excerpt.chars().any(unsafe_context_excerpt_character)
                || event.is_none_or(|(thread_ref, actor_ref, role, occurred_at, _)| {
                    !historical_attribution_is_safe(thread_ref, actor_ref, role, occurred_at)
                })
                || event.is_none_or(|(_, _, _, _, text)| text.trim() != exact_excerpt.trim())
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
            if !context.open_loops.contains(open_loop_ref.as_str()) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "retained plan must reference an existing open loop".into(),
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
            return Ok(());
        }
        ClaimContent::StableExplanation { .. } => return Ok(()),
        ClaimContent::CoverageBoundary { .. } => {
            if !matches!(
                context.final_state,
                FinalState::Partial | FinalState::Blocked
            ) || context.coverage_notice.map(str::trim) != Some(claim.text.trim())
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "coverage boundary must match the declared notice for a partial or blocked draft"
                        .into(),
                ));
            }
            return Ok(());
        }
        ClaimContent::Question { .. } => {
            let text = claim.text.trim();
            if context.final_state != FinalState::NeedsInput
                || context.question.map(str::trim) != Some(text)
            {
                return Err(AgentRuntimeError::InvalidFinal(
                    "question claim must match the declared missing-input question".into(),
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
    if body.is_empty()
        || body.len() > MAX_CONVERSATIONAL_SYNTHESIS_BYTES
        || body.lines().count() > 6
        || body
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
    {
        return Err(AgentRuntimeError::InvalidFinal(
            "conversational synthesis must be non-empty, bounded text tied to the exact cited thread messages"
                .into(),
        ));
    }
    Ok(())
}

/// Renders an allowlisted structural phrase that contributes no factual content.
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

#[derive(Clone, Copy)]
struct AtomContext<'a> {
    atom: &'a EvidenceAtom,
    complete: bool,
    fresh_until: Option<OffsetDateTime>,
}

fn evidence_atoms(
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
) -> Result<BTreeMap<String, AtomContext<'_>>, AgentRuntimeError> {
    authoritative_turn_clock(observations, assessment_at)?;
    let mut atoms = BTreeMap::new();
    for observation in observations {
        for evidence in &observation.result.evidence {
            let evidence_observed_at = OffsetDateTime::parse(&evidence.observed_at, &Rfc3339)
                .map_err(|_| {
                    AgentRuntimeError::InvalidFinal("invalid evidence observation time".into())
                })?;
            let evidence_fresh_until = evidence
                .fresh_until
                .as_deref()
                .map(|value| OffsetDateTime::parse(value, &Rfc3339))
                .transpose()
                .map_err(|_| {
                    AgentRuntimeError::InvalidFinal("invalid evidence freshness".into())
                })?;
            if evidence_fresh_until.is_some_and(|fresh_until| fresh_until < evidence_observed_at) {
                return Err(AgentRuntimeError::InvalidFinal(
                    "evidence timestamps exceed the authoritative turn clock".into(),
                ));
            }
            for atom in &evidence.atoms {
                let atom_observed_at =
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
                if fresh_until.is_some_and(|fresh_until| fresh_until < atom_observed_at) {
                    return Err(AgentRuntimeError::InvalidFinal(
                        "evidence timestamps exceed the authoritative turn clock".into(),
                    ));
                }
                if !bounded(&atom.atom_ref, MAX_TEXT_BYTES)
                    || atoms
                        .insert(
                            atom.atom_ref.clone(),
                            AtomContext {
                                atom,
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

fn authoritative_turn_clock(
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
) -> Result<OffsetDateTime, AgentRuntimeError> {
    let accepted_at = observations.iter().try_fold(
        assessment_at,
        |accepted_at, observation| -> Result<_, AgentRuntimeError> {
            let Some(value) = observation.recorded_at.as_deref() else {
                return Ok(accepted_at);
            };
            let recorded_at = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                AgentRuntimeError::InvalidFinal("invalid host tool observation time".into())
            })?;
            Ok(accepted_at.max(recorded_at))
        },
    )?;
    authoritative_turn_clock_at(observations, assessment_at, accepted_at)
}

fn elapsed_host_turn_time(
    clock_base: OffsetDateTime,
    started_at: Instant,
) -> Result<OffsetDateTime, AgentRuntimeError> {
    let elapsed_seconds = i64::try_from(started_at.elapsed().as_secs())
        .map_err(|_| AgentRuntimeError::InvalidFinal("host turn duration overflowed".into()))?;
    clock_base
        .checked_add(Duration::seconds(elapsed_seconds))
        .ok_or_else(|| AgentRuntimeError::InvalidFinal("host turn clock overflowed".into()))
}

fn validate_host_entry_time(
    assessment_at: OffsetDateTime,
    host_entry_at: OffsetDateTime,
    resumed_turn_clock: OffsetDateTime,
) -> Result<OffsetDateTime, AgentRuntimeError> {
    let deadline = assessment_at
        .checked_add(Duration::seconds(MAX_IN_TURN_EVIDENCE_DELAY_SECONDS))
        .ok_or_else(|| AgentRuntimeError::InvalidFinal("turn clock overflowed".into()))?;
    if host_entry_at < assessment_at || host_entry_at > deadline {
        return Err(AgentRuntimeError::InvalidRequest(
            "host session entry time exceeds the bounded turn window".into(),
        ));
    }
    if resumed_turn_clock < assessment_at || resumed_turn_clock > deadline {
        return Err(AgentRuntimeError::InvalidFinal(
            "resumed host turn clock exceeds the bounded turn window".into(),
        ));
    }
    Ok(host_entry_at.max(resumed_turn_clock))
}

fn authoritative_turn_clock_at(
    observations: &[ToolObservation],
    assessment_at: OffsetDateTime,
    accepted_at: OffsetDateTime,
) -> Result<OffsetDateTime, AgentRuntimeError> {
    let deadline = assessment_at
        .checked_add(Duration::seconds(MAX_IN_TURN_EVIDENCE_DELAY_SECONDS))
        .ok_or_else(|| AgentRuntimeError::InvalidFinal("turn clock overflowed".into()))?;
    if accepted_at < assessment_at || accepted_at > deadline {
        return Err(AgentRuntimeError::InvalidFinal(
            "host acceptance time exceeds the bounded turn window".into(),
        ));
    }
    for observation in observations {
        let evidence_times = observation
            .result
            .evidence
            .iter()
            .flat_map(|evidence| {
                std::iter::once(evidence.observed_at.as_str())
                    .chain(evidence.atoms.iter().map(|atom| atom.observed_at.as_str()))
            })
            .map(|value| {
                OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                    AgentRuntimeError::InvalidFinal("invalid evidence observation time".into())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let recorded_at = match observation.recorded_at.as_deref() {
            Some(value) => OffsetDateTime::parse(value, &Rfc3339).map_err(|_| {
                AgentRuntimeError::InvalidFinal("invalid host tool observation time".into())
            })?,
            None => accepted_at,
        };
        if recorded_at > deadline {
            return Err(AgentRuntimeError::InvalidFinal(
                "host tool observation time exceeds the bounded turn window".into(),
            ));
        }
        if recorded_at > accepted_at {
            return Err(AgentRuntimeError::InvalidFinal(
                "host tool observation time exceeds the host acceptance time".into(),
            ));
        }
        let evidence_deadline = recorded_at
            .checked_add(Duration::seconds(MAX_EVIDENCE_CLOCK_SKEW_SECONDS))
            .ok_or_else(|| AgentRuntimeError::InvalidFinal("evidence clock overflowed".into()))?;
        if evidence_times
            .iter()
            .any(|observed_at| *observed_at > evidence_deadline)
        {
            return Err(AgentRuntimeError::InvalidFinal(
                "evidence timestamps exceed the host-recorded tool clock".into(),
            ));
        }
    }
    Ok(accepted_at)
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

    async fn run_session_turn(
        model: &dyn SessionAgentModel,
        tools: &dyn SessionTools,
        session: AgentSession,
        input: SessionTurnInput,
    ) -> Result<SessionTurnOutcome, AgentRuntimeError> {
        run_session_turn_recorded(model, tools, &NoopSessionJournal, session, input).await
    }

    async fn run_session_turn_recorded(
        model: &dyn SessionAgentModel,
        tools: &dyn SessionTools,
        journal: &dyn SessionJournal,
        session: AgentSession,
        input: SessionTurnInput,
    ) -> Result<SessionTurnOutcome, AgentRuntimeError> {
        let host_entry_at = OffsetDateTime::parse(&input.assessment_at, &Rfc3339)
            .map_err(|_| AgentRuntimeError::InvalidRequest("assessment_at is invalid".into()))?;
        super::run_session_turn_recorded_at(
            model,
            tools,
            journal,
            session,
            input,
            SessionTurnHostContext {
                host_entry_at,
                host_turn_started_at: Instant::now(),
                proactive_followup_offers_enabled: false,
            },
        )
        .await
    }

    fn test_turn_time() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap()
    }

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
            recorded_at: Some("2026-07-31T00:00:01Z".into()),
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

    #[test]
    fn future_dated_evidence_cannot_become_authoritative() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut future_record = observation(true, Some("2026-08-01T00:05:00Z"));
        future_record.result.evidence[0].observed_at = "2026-08-01T00:00:00Z".into();

        assert!(!observation_is_complete_and_fresh(
            &future_record,
            assessment
        ));
        let error = evidence_atoms(&[future_record], assessment).err().unwrap();
        assert!(matches!(
            error,
            AgentRuntimeError::InvalidFinal(message)
                if message == "evidence timestamps exceed the host-recorded tool clock"
        ));

        let mut future_atom = observation(true, Some("2026-08-01T00:05:00Z"));
        future_atom.result.evidence[0].atoms[0].observed_at = "2026-08-01T00:00:00Z".into();
        let error = evidence_atoms(&[future_atom], assessment).err().unwrap();
        assert!(matches!(
            error,
            AgentRuntimeError::InvalidFinal(message)
                if message == "evidence timestamps exceed the host-recorded tool clock"
        ));
    }

    #[test]
    fn live_in_turn_evidence_after_message_arrival_is_authoritative() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut live = observation(true, Some("2026-07-31T00:02:45Z"));
        live.recorded_at = Some("2026-07-31T00:01:45Z".into());
        live.result.evidence[0].observed_at = "2026-07-31T00:01:45Z".into();
        live.result.evidence[0].atoms[0].observed_at = "2026-07-31T00:01:45Z".into();

        assert!(observation_is_complete_and_fresh(&live, assessment));
        assert!(evidence_atoms(std::slice::from_ref(&live), assessment).is_ok());
        assert!(validate_grounded_draft(&session(), &draft(), &[live], assessment).is_ok());
    }

    #[test]
    fn evidence_expired_before_host_acceptance_is_rejected() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut live = observation(true, Some("2026-07-31T00:02:00Z"));
        live.recorded_at = Some("2026-07-31T00:01:45Z".into());
        live.result.evidence[0].observed_at = "2026-07-31T00:01:45Z".into();
        live.result.evidence[0].atoms[0].observed_at = "2026-07-31T00:01:45Z".into();

        let before_expiry = OffsetDateTime::parse("2026-07-31T00:01:59Z", &Rfc3339).unwrap();
        assert!(
            validate_grounded_draft_at(
                &session(),
                &draft(),
                std::slice::from_ref(&live),
                assessment,
                before_expiry,
            )
            .is_ok()
        );

        let after_expiry = OffsetDateTime::parse("2026-07-31T00:02:01Z", &Rfc3339).unwrap();
        assert!(
            validate_grounded_draft_at(
                &session(),
                &draft(),
                std::slice::from_ref(&live),
                assessment,
                after_expiry,
            )
            .is_err()
        );
    }

    #[test]
    fn host_acceptance_time_obeys_the_exact_turn_window() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let boundary = OffsetDateTime::parse("2026-07-31T00:16:00Z", &Rfc3339).unwrap();
        assert_eq!(
            authoritative_turn_clock_at(&[], assessment, boundary).unwrap(),
            boundary
        );

        let beyond = OffsetDateTime::parse("2026-07-31T00:16:01Z", &Rfc3339).unwrap();
        assert!(matches!(
            authoritative_turn_clock_at(&[], assessment, beyond),
            Err(AgentRuntimeError::InvalidFinal(message))
                if message == "host acceptance time exceeds the bounded turn window"
        ));
    }

    #[test]
    fn host_entry_after_route_delay_advances_the_freshness_clock() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let host_entry = OffsetDateTime::parse("2026-07-31T00:02:20Z", &Rfc3339).unwrap();
        let clock_base = validate_host_entry_time(assessment, host_entry, assessment).unwrap();
        assert_eq!(clock_base, host_entry);

        let mut live = observation(true, Some("2026-07-31T00:02:30Z"));
        live.recorded_at = Some("2026-07-31T00:02:25Z".into());
        live.result.evidence[0].observed_at = "2026-07-31T00:02:25Z".into();
        live.result.evidence[0].atoms[0].observed_at = "2026-07-31T00:02:25Z".into();
        let accepted_at = OffsetDateTime::parse("2026-07-31T00:02:26Z", &Rfc3339).unwrap();
        assert!(
            validate_grounded_draft_at(&session(), &draft(), &[live], assessment, accepted_at,)
                .is_ok()
        );
    }

    #[test]
    fn host_entry_beyond_the_turn_window_is_rejected() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let stale_entry = OffsetDateTime::parse("2026-07-31T00:16:01Z", &Rfc3339).unwrap();
        assert!(matches!(
            validate_host_entry_time(assessment, stale_entry, assessment),
            Err(AgentRuntimeError::InvalidRequest(message))
                if message == "host session entry time exceeds the bounded turn window"
        ));
    }

    #[test]
    fn provider_timestamp_cannot_advance_the_host_owned_turn_clock() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut honest = observation(true, Some("2026-07-31T00:02:40Z"));
        honest.recorded_at = Some("2026-07-31T00:01:40Z".into());
        honest.result.evidence[0].observed_at = "2026-07-31T00:01:40Z".into();
        honest.result.evidence[0].atoms[0].observed_at = "2026-07-31T00:01:40Z".into();
        assert_eq!(
            authoritative_turn_clock(std::slice::from_ref(&honest), assessment).unwrap(),
            OffsetDateTime::parse("2026-07-31T00:01:40Z", &Rfc3339).unwrap()
        );

        let mut adversarial = honest;
        adversarial.recorded_at = Some("2026-07-31T00:01:50Z".into());
        adversarial.result.evidence[0].observed_at = "2026-07-31T00:11:00Z".into();
        adversarial.result.evidence[0].atoms[0].observed_at = "2026-07-31T00:11:00Z".into();
        assert!(matches!(
            authoritative_turn_clock(std::slice::from_ref(&adversarial), assessment),
            Err(AgentRuntimeError::InvalidFinal(message))
                if message == "evidence timestamps exceed the host-recorded tool clock"
        ));
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
            follow_through_offer: None,
        }
    }

    #[test]
    fn credential_shaped_text_is_rejected_from_visible_progress_and_answers() {
        let synthetic_token = format!("xoxb-{}", "a".repeat(32));
        assert!(contains_credential_shaped_text(&synthetic_token));
        assert!(contains_credential_shaped_text(&format!(
            "api_key={}",
            "b".repeat(32)
        )));
        assert!(!contains_credential_shaped_text(
            "The provider token is missing and no request was sent."
        ));

        let mut progress = plan();
        progress.user_visible_work = vec![format!("Using {synthetic_token} for the request.")];
        let error = validate_plan(&progress, &["connector.read".into()])
            .err()
            .unwrap();
        assert!(matches!(
            error,
            AgentRuntimeError::InvalidFinal(message)
                if message == "user-visible plan updates contain credential-shaped text"
        ));

        let mut answer = draft();
        answer.message = format!("The provider returned token={synthetic_token}.");
        answer.claims[0].text.clone_from(&answer.message);
        answer.claims.truncate(1);
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let error = validate_grounded_draft(
            &session(),
            &answer,
            &[observation(true, Some("2026-08-01T00:00:00Z"))],
            assessment,
        )
        .err()
        .unwrap();
        assert!(matches!(
            error,
            AgentRuntimeError::InvalidFinal(message)
                if message == "visible response contains credential-shaped text"
        ));
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

    fn delivered_proactive_followup() -> (AgentSession, ProactiveFollowupOffer) {
        let current = session();
        let observed = observation(true, Some("2026-07-31T00:10:00Z"));
        let mut offered_plan = plan();
        offered_plan.follow_through_offer = Some(PlannedFollowThroughOffer {
            kind: ProactiveFollowupKind::WatchAnswer,
            follow_through: planned_follow_through(),
        });
        let answer = draft();
        let input = SessionTurnInput {
            request_id: "request:1".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };
        let (offer, private_plan) = materialize_proactive_followup_offer(
            &current,
            &input,
            Some(&offered_plan),
            &answer,
            std::slice::from_ref(&observed),
            &["atom:status".into()],
            OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap(),
        )
        .unwrap()
        .expect("a capable host should receive a current grounded offer");
        let events = vec![
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: current.session_ref.clone(),
                sequence: 1,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::ToolInvoked {
                    observation: observed,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: current.session_ref.clone(),
                sequence: 2,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::DraftProduced {
                    request_id: "request:1".into(),
                    draft: answer,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: current.session_ref.clone(),
                sequence: 3,
                occurred_at: "2026-07-31T00:01:00Z".into(),
                event: SessionEvent::FollowupOffered {
                    request_id: "request:1".into(),
                    offer: offer.clone(),
                    planned_follow_through: private_plan,
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: current.session_ref.clone(),
                sequence: 4,
                occurred_at: "2026-07-31T00:01:01Z".into(),
                event: SessionEvent::DeliveryRecorded {
                    request_id: "request:1".into(),
                    transport: "slack".into(),
                    delivery_ref: "slack-message:1".into(),
                    payload_digest: message_digest("delivered answer and offer"),
                },
            },
            SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: current.session_ref.clone(),
                sequence: 5,
                occurred_at: "2026-07-31T00:01:01Z".into(),
                event: SessionEvent::TurnCompleted {
                    request_id: "request:1".into(),
                    state: FinalState::Answered,
                },
            },
        ];
        (apply_session_events(&current, &events).unwrap(), offer)
    }

    #[test]
    fn proactive_followup_acceptance_is_exact_current_and_materializes_without_a_model() {
        let (session, offer) = delivered_proactive_followup();
        let accepted_at = OffsetDateTime::parse("2026-07-31T00:02:00Z", &Rfc3339).unwrap();
        let acceptance = ProactiveFollowupAcceptance {
            schema_version: PROACTIVE_FOLLOWUP_ACCEPTANCE_V1.into(),
            offer: offer.clone(),
        };
        validate_followup_acceptance(&session, &acceptance, accepted_at).unwrap();

        let mut tampered_action = acceptance.clone();
        tampered_action.offer.action_key.push_str(":tampered");
        assert!(validate_followup_acceptance(&session, &tampered_action, accepted_at).is_err());
        let mut wrong_tenant = acceptance.clone();
        wrong_tenant.offer.tenant_id = "tenant:other".into();
        assert!(validate_followup_acceptance(&session, &wrong_tenant, accepted_at).is_err());
        let mut wrong_thread = acceptance.clone();
        wrong_thread.offer.thread_ref = "thread:other".into();
        assert!(validate_followup_acceptance(&session, &wrong_thread, accepted_at).is_err());
        assert!(
            validate_followup_acceptance(
                &session,
                &acceptance,
                OffsetDateTime::parse("2026-07-31T00:10:01Z", &Rfc3339).unwrap(),
            )
            .is_err()
        );

        let accepted = apply_session_events(
            &session,
            &[SessionEventRecord {
                schema_version: AGENT_SESSION_EVENT_V2.into(),
                session_ref: session.session_ref.clone(),
                sequence: 6,
                occurred_at: "2026-07-31T00:02:00Z".into(),
                event: SessionEvent::FollowupAccepted {
                    request_id: "request:accept".into(),
                    offer_ref: offer.offer_ref.clone(),
                },
            }],
        )
        .unwrap();
        let commitment = accepted
            .mission
            .commitments
            .iter()
            .find(|commitment| commitment.commitment_ref == "commitment:scheduled-check")
            .expect("acceptance must materialize the private executor contract atomically");
        assert_eq!(commitment.required_tool_ids, vec!["connector.read"]);
        assert_eq!(commitment.wake_at.as_deref(), Some("2026-07-31T00:07:00Z"));
        let confirmation =
            followup_acceptance_draft(&accepted, &offer.offer_ref, accepted_at).unwrap();
        assert_eq!(
            confirmation.message,
            "I’ll check again at 2026-07-31T00:07:00Z."
        );
    }

    #[test]
    fn proactive_followup_offer_requires_capability_and_all_executor_evidence() {
        let current = session();
        let observed = observation(true, Some("2026-07-31T00:10:00Z"));
        let mut offered_plan = plan();
        let mut follow_through = planned_follow_through();
        follow_through.required_tool_ids.push("graph.read".into());
        offered_plan.selected_tools.push("graph.read".into());
        offered_plan.follow_through_offer = Some(PlannedFollowThroughOffer {
            kind: ProactiveFollowupKind::WatchAnswer,
            follow_through,
        });
        let input = SessionTurnInput {
            request_id: "request:1".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };
        let accepted_at = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        assert!(
            materialize_proactive_followup_offer(
                &current,
                &input,
                Some(&offered_plan),
                &draft(),
                &[observed],
                &["atom:status".into()],
                accepted_at,
            )
            .unwrap()
            .is_none()
        );
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
            turn: ClaimReviewTurn,
        ) -> Result<MessageReview, AgentRuntimeError> {
            Ok(supported_message_review(turn))
        }
    }

    fn supported_message_review(turn: ClaimReviewTurn) -> MessageReview {
        MessageReview {
            draft_digest: grounded_draft_digest(&turn.draft),
            message_digest: message_digest(&turn.draft.message),
            claim_reviews: turn
                .draft
                .claims
                .into_iter()
                .map(|claim| ClaimReview {
                    claim_ref: claim.claim_ref,
                    verdict: ClaimReviewVerdict::Supported,
                    issue: None,
                })
                .collect(),
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
            Ok(supported_message_review(turn))
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
                draft_digest: grounded_draft_digest(&turn.draft),
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
                follow_through_offer: None,
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
    fn operator_context_requires_exact_thread_attribution() {
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
    fn commitment_claims_are_bound_to_the_typed_scheduler_record() {
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
            .is_ok()
        );
    }

    #[test]
    fn retained_plan_claims_bind_the_open_loop_without_parsing_prose() {
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
        retained.claims[0].text = "That question is still open.".into();
        retained.claims[0].content = ClaimContent::RetainedPlan {
            open_loop_ref: "open-loop:connector-choice".into(),
        };
        retained.message = retained.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &retained, &[], assessment).is_ok());

        retained.claims[0].text = "Any paraphrase remains presentation content.".into();
        retained.message = retained.claims[0].text.clone();
        assert!(validate_grounded_draft(&session(), &retained, &[], assessment).is_ok());

        retained.claims[0].content = ClaimContent::RetainedPlan {
            open_loop_ref: "open-loop:unknown".into(),
        };
        assert!(validate_grounded_draft(&session(), &retained, &[], assessment).is_err());
    }

    #[test]
    fn model_review_is_bound_to_the_complete_typed_draft() {
        let candidate = draft();
        let review = MessageReview {
            draft_digest: grounded_draft_digest(&candidate),
            message_digest: message_digest(&candidate.message),
            claim_reviews: candidate
                .claims
                .iter()
                .map(|claim| ClaimReview {
                    claim_ref: claim.claim_ref.clone(),
                    verdict: ClaimReviewVerdict::Supported,
                    issue: None,
                })
                .collect(),
            undeclared_material: Vec::new(),
            attention: AttentionReview {
                delivery: candidate.delivery,
                reason: "The response is useful and evidence-honest.".into(),
            },
            behavioral: BehavioralReview {
                answers_newest_request: true,
                conversational: true,
                owns_follow_through: true,
                right_sized: true,
                evidence_boundary_correct: true,
            },
        };
        assert!(validate_message_review(&candidate, &review).is_ok());

        let mut changed_provenance = candidate;
        changed_provenance.claims[0].required_for_answer =
            !changed_provenance.claims[0].required_for_answer;
        assert!(validate_message_review(&changed_provenance, &review).is_err());
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
    fn conversational_synthesis_is_structurally_bound_without_phrase_classification() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
        let mut current = session();
        current.messages[0].text = "@Cerebro how ya feeling about your new digs".into();
        let response = "Honestly? Pretty good — I have more room to think, use the right tools when they help, and still just talk with you when they do not.";
        let mut candidate = draft();
        candidate.message = response.into();
        candidate.claims = vec![GroundedClaim {
            claim_ref: "claim:conversation".into(),
            planned_claim_ref: None,
            text: response.into(),
            required_for_answer: true,
            content: ClaimContent::ConversationalSynthesis {
                source_message_sequences: vec![1],
                source_atom_refs: Vec::new(),
            },
        }];
        validate_grounded_draft(&current, &candidate, &[], assessment).unwrap();

        candidate.claims[0].planned_claim_ref = Some("claim:state".into());
        assert!(validate_grounded_draft(&current, &candidate, &[], assessment).is_err());

        candidate.claims[0].planned_claim_ref = None;
        candidate.claims[0].content = ClaimContent::ConversationalSynthesis {
            source_message_sequences: vec![999],
            source_atom_refs: Vec::new(),
        };
        assert!(validate_grounded_draft(&current, &candidate, &[], assessment).is_err());
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
    fn stable_explanations_bind_typed_ids_without_parsing_prose() {
        let assessment = OffsetDateTime::parse("2026-07-31T00:01:00Z", &Rfc3339).unwrap();
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
            mutation.claims[0].text = "The same typed idea, expressed naturally.".into();
            mutation.message = mutation.claims[0].text.clone();
            assert!(
                validate_grounded_draft(&session(), &mutation, &[], assessment).is_ok(),
                "presentation wording should not be classified in Rust"
            );
        }
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
        assert!(matches!(
            validate_explicit_follow_through(&delegated, &input, None),
            Err(AgentRuntimeError::InvalidFinal(_))
        ));
        assert!(
            validate_explicit_follow_through(&delegated, &input, Some(&proposed))
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
        assert!(validate_explicit_follow_through(&delegated, &input, Some(&proposed)).is_ok());

        let replayed: AgentSession =
            serde_json::from_slice(&serde_json::to_vec(&delegated).unwrap()).unwrap();
        assert!(validate_explicit_follow_through(&replayed, &input, Some(&proposed)).is_ok());
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
        assert!(validate_explicit_follow_through(&refused, &input, None).is_ok());
        proposed.follow_through = Some(planned_follow_through());
        assert!(validate_explicit_follow_through(&refused, &input, Some(&proposed)).is_err());

        let none = session_for_request("request:none", ExecutionLane::Lookup);
        let none_input = SessionTurnInput {
            request_id: "request:none".into(),
            ..input
        };
        assert!(validate_explicit_follow_through(&none, &none_input, None).is_ok());
        assert!(validate_explicit_follow_through(&none, &none_input, Some(&proposed)).is_err());

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
        assert!(
            validate_explicit_follow_through(&inherited, &inherited_input, Some(&proposed)).is_ok()
        );
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
            Some(&plan),
            std::slice::from_ref(&observation),
            test_turn_time(),
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
    async fn presentation_review_repairs_unsupported_and_unhelpful_drafts() {
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
        assert_eq!(lane, ExecutionLane::Converse);
        assert_eq!(delivery, DeliveryDisposition::Visible);
        assert_eq!(final_state, FinalState::Blocked);
        assert!(markdown.contains("couldn't obtain current evidence"));
    }

    #[tokio::test]
    async fn resumed_typed_plan_remains_authoritative_after_an_advisory_route() {
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
        let SessionTurnOutcome::PendingDelivery { lane, .. } =
            result.expect("the durable typed plan should resume independently of route advice")
        else {
            panic!("a resumed typed plan should produce a bounded delivery");
        };
        assert_eq!(lane, ExecutionLane::Investigate);
    }

    #[tokio::test]
    async fn research_loop_can_finish_social_conversation_after_an_overeager_route() {
        let mut conversational =
            session_for_request("request:social-route-recovery", ExecutionLane::Investigate);
        conversational.messages[0].text = "@Cerebro how ya feeling about your new digs".into();
        let message = "Honestly? Pretty good — I have more room to think, use the right tools when they help, and still just talk with you when they don't.".to_string();
        let draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: message.clone(),
            claims: vec![GroundedClaim {
                claim_ref: "claim:social-answer".into(),
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
                request_id: "request:social-route-recovery".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Investigate),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .expect("the research loop should hand a social answer to presentation without tools");
        let SessionTurnOutcome::PendingDelivery {
            lane,
            final_state,
            markdown,
            evidence_atom_refs,
            ..
        } = outcome
        else {
            panic!("the social answer should be ready for delivery");
        };
        assert_eq!(lane, ExecutionLane::Converse);
        assert_eq!(final_state, FinalState::Answered);
        assert_eq!(markdown, message);
        assert!(evidence_atom_refs.is_empty());
    }

    #[tokio::test]
    async fn presentation_review_rejects_a_current_claim_disguised_as_conversation() {
        let mut current = session_for_request(
            "request:misclassified-current-state",
            ExecutionLane::Converse,
        );
        current.messages[0].text = "Is Atlas currently green?".into();
        let make_draft = |claim_ref: &str, message: &str| GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: message.into(),
            claims: vec![GroundedClaim {
                claim_ref: claim_ref.into(),
                planned_claim_ref: None,
                text: message.into(),
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
        let unsupported = make_draft(
            "claim:unsupported",
            "Atlas is currently green and the deployment passed.",
        );
        let safe = make_draft(
            "claim:safe-boundary",
            "I need a current observation before I can answer that honestly.",
        );
        let model = RefiningSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::Finish { draft: unsupported },
                SessionModelDecision::Finish {
                    draft: safe.clone(),
                },
                SessionModelDecision::Finish { draft: safe },
            ])),
            reviews: AtomicUsize::new(0),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            current,
            SessionTurnInput {
                request_id: "request:misclassified-current-state".into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Converse),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .unwrap();
        let SessionTurnOutcome::PendingDelivery { markdown, .. } = outcome else {
            panic!("the reviewed boundary should be ready for delivery");
        };
        assert_eq!(
            markdown,
            "I need a current observation before I can answer that honestly."
        );
        assert_eq!(model.reviews.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn delegated_future_observation_must_enter_the_typed_plan_before_finish() {
        let request_id = "request:delegated-direct-finish";
        let request =
            "Stay with Ternwheel until two fresh recovery observations agree, then tell me.";
        let delegated = session_for_request_intent(
            request_id,
            ExecutionLane::Investigate,
            FutureObservationDisposition::Delegated,
            Some("Stay with Ternwheel until two fresh recovery observations agree"),
            request,
        );
        let direct_message = "I can keep an eye on that and let you know.".to_string();
        let direct_draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: direct_message.clone(),
            claims: vec![GroundedClaim {
                claim_ref: "claim:direct-answer".into(),
                planned_claim_ref: None,
                text: direct_message,
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
        let mut delegated_plan = plan();
        delegated_plan.follow_through = Some(planned_follow_through());
        let model = ScriptedSessionModel {
            decisions: Mutex::new(VecDeque::from([
                SessionModelDecision::Finish {
                    draft: direct_draft,
                },
                SessionModelDecision::EstablishPlan {
                    plan: delegated_plan,
                },
                SessionModelDecision::InvokeTools {
                    calls: vec![ToolCall {
                        call_id: "call:delegated-baseline".into(),
                        tool_id: "connector.read".into(),
                        purpose: "Establish the current connector baseline.".into(),
                        input: json!({"connector_ref": "connector:alpha"}),
                    }],
                },
                SessionModelDecision::Finish { draft: draft() },
            ])),
        };

        let outcome = run_session_turn(
            &model,
            &ConnectorTools,
            delegated,
            SessionTurnInput {
                request_id: request_id.into(),
                actor_ref: "user:1".into(),
                assessment_at: "2026-07-31T00:01:00Z".into(),
                requested_lane: Some(ExecutionLane::Investigate),
                trigger: SessionTurnTrigger::Operator,
            },
        )
        .await
        .expect("delegated future work should recover through a typed plan");
        let SessionTurnOutcome::PendingDelivery {
            lane,
            mission,
            events,
            ..
        } = outcome
        else {
            panic!("delegated future work should be ready for delivery");
        };
        assert_eq!(lane, ExecutionLane::Investigate);
        assert!(
            events
                .iter()
                .any(|event| matches!(event.event, SessionEvent::PlanEstablished { .. }))
        );
        assert!(mission.commitments.iter().any(|commitment| {
            commitment.commitment_ref == "commitment:scheduled-check"
                && commitment.status == CommitmentStatus::Waiting
        }));
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
    async fn presentation_model_answers_from_thread_premises_without_phrase_rewriting() {
        let mut conversational =
            session_for_request("request:premise-converse", ExecutionLane::Converse);
        conversational.messages[0].text = "We just changed the sync path. The dashboard is green, but we have not verified the user path. Talk to me like a teammate: what are you actually confident about, what is still unverified, and what should we do next?".into();
        let visible = "Given what you reported, the dashboard is green and the user path is still unverified. The useful next step is one representative end-to-end transaction.";
        let draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: visible.into(),
            claims: vec![GroundedClaim {
                claim_ref: "claim:premise-conversation".into(),
                planned_claim_ref: None,
                text: visible.into(),
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
        .expect("the presentation model should return its typed conversational answer");
        let SessionTurnOutcome::PendingDelivery { markdown, .. } = outcome else {
            panic!("the conversational answer should be ready for delivery");
        };
        assert_eq!(markdown, visible);
    }

    #[tokio::test]
    async fn presentation_model_can_bind_a_correction_to_prior_thread_messages() {
        let mut conversational =
            session_for_request("request:initial-premise", ExecutionLane::Converse);
        conversational.messages[0].text =
            "The dashboard is green, but we have not verified the user path.".into();
        conversational.messages.push(SessionMessage {
            role: SessionMessageRole::Assistant,
            message_ref: "assistant:request:initial-premise".into(),
            actor_ref: "cerebro".into(),
            text: "The useful next test is one transaction through the new route.".into(),
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
                            text: "That successful run used the old route. Does that change your picture?".into(),
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
        .unwrap();
        let visible = "That changes the picture: the successful run supports the old route, while the new route remains unverified.";
        let draft = GroundedDraft {
            state: FinalState::Answered,
            delivery: DeliveryDisposition::Visible,
            message: visible.into(),
            claims: vec![GroundedClaim {
                claim_ref: "claim:premise-correction".into(),
                planned_claim_ref: None,
                text: visible.into(),
                required_for_answer: true,
                content: ClaimContent::ConversationalSynthesis {
                    source_message_sequences: vec![1, 2, 3],
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
        .unwrap();
        let SessionTurnOutcome::PendingDelivery {
            markdown, events, ..
        } = outcome
        else {
            panic!("the correction should be ready for delivery");
        };
        assert_eq!(markdown, visible);
        let source_sequences = events.iter().find_map(|event| match &event.event {
            SessionEvent::DraftProduced { draft, .. } => match &draft.claims[0].content {
                ClaimContent::ConversationalSynthesis {
                    source_message_sequences,
                    ..
                } => Some(source_message_sequences.as_slice()),
                _ => None,
            },
            _ => None,
        });
        assert_eq!(source_sequences, Some(&[1, 2, 3][..]));
    }

    #[tokio::test]
    async fn a_current_claim_cannot_finish_without_a_structural_evidence_reference() {
        let mut current =
            session_for_request("request:current-without-plan", ExecutionLane::Lookup);
        current.messages[0].text = "Is Atlas green?".into();
        let mut unsupported = draft();
        unsupported.message = "Atlas is currently green.".into();
        unsupported.claims = vec![GroundedClaim {
            claim_ref: "claim:unsupported-current-state".into(),
            planned_claim_ref: None,
            text: unsupported.message.clone(),
            required_for_answer: true,
            content: ClaimContent::Observation {
                atom_refs: vec!["evidence://missing#current-state".into()],
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
        assert!(markdown.contains("couldn't obtain current evidence"));
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
        assert!(markdown.contains("couldn't obtain current evidence"));
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
            None,
            &[failed.clone()],
            test_turn_time(),
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
        assert!(!markdown.contains("couldn't obtain current evidence"));

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
            None,
            &[supported.clone(), failed.clone()],
            test_turn_time(),
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
            None,
            &[same_subject, failed.clone()],
            test_turn_time(),
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
                None,
                &observations,
                test_turn_time(),
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
            None,
            &[failed_effect],
            test_turn_time(),
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
    async fn repair_fallback_excludes_evidence_expired_before_host_acceptance() {
        let mut supported = recovering_observation_with_tool_outcome("2026-07-31T00:02:00Z");
        supported.recorded_at = Some("2026-07-31T00:01:45Z".into());
        for evidence in &mut supported.result.evidence {
            evidence.observed_at = "2026-07-31T00:01:45Z".into();
            evidence.fresh_until = Some("2026-07-31T00:02:00Z".into());
            for atom in &mut evidence.atoms {
                atom.observed_at = "2026-07-31T00:01:45Z".into();
                atom.fresh_until = Some("2026-07-31T00:02:00Z".into());
            }
        }
        let input = SessionTurnInput {
            request_id: "request:expired-fallback".into(),
            actor_ref: "user:1".into(),
            assessment_at: "2026-07-31T00:01:00Z".into(),
            requested_lane: Some(ExecutionLane::Investigate),
            trigger: SessionTurnTrigger::Operator,
        };
        let accepted_at = OffsetDateTime::parse("2026-07-31T00:02:01Z", &Rfc3339).unwrap();

        let outcome = repair_fallback_outcome(
            &session(),
            &input,
            None,
            &[supported],
            accepted_at,
            Vec::new(),
            &NoopSessionJournal,
        )
        .await
        .expect("expired support should produce a safe coverage-only fallback");
        let SessionTurnOutcome::PendingDelivery {
            final_state,
            markdown,
            evidence_atom_refs,
            ..
        } = outcome
        else {
            panic!("a coverage-only fallback must remain visible")
        };
        assert_eq!(final_state, FinalState::Blocked);
        assert!(!markdown.contains("recovering"));
        assert!(markdown.contains("couldn't obtain current evidence"));
        assert!(evidence_atom_refs.is_empty());
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
            None,
            &[runtime],
            test_turn_time(),
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
            None,
            &[first, latest],
            test_turn_time(),
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
                None,
                &[supported],
                test_turn_time(),
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
            Some(&proposed),
            &[baseline],
            test_turn_time(),
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
