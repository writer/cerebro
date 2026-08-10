#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Deterministic Slack request and answer authority.
//!
//! Slack transport supplies tenant-bound questions and graph providers supply
//! candidate facts. This crate owns the fail-closed decisions about whether a
//! request can be sent upstream and whether a candidate can be delivered as
//! grounded evidence or as a structured safe refusal.
//!
//! The authority has two independent boundaries:
//!
//! 1. [`authorize_question`] validates tenant, request, question, and bounded
//!    history before selecting a deterministic execution lane.
//! 2. [`validate_answer`] accepts only a terminal answer with either validated,
//!    row-backed citations or a complete, trace-bound safe refusal.
//!
//! Callers cannot assert authorization, verification, or refusal state through
//! extra JSON fields because all candidate records reject unknown fields. This
//! crate does not authenticate Slack, query the graph, generate prose, validate
//! citation contents, or persist traces; those remain host responsibilities.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

/// Supported schema for an untrusted answer submitted to [`validate_answer`].
pub const ANSWER_CANDIDATE_V1: &str = "slack-answer-candidate/v1";
/// Schema emitted for an authoritative [`AnswerDecision`].
pub const ANSWER_DECISION_V1: &str = "slack-answer-decision/v1";
/// Supported schema for an untrusted question submitted to [`authorize_question`].
pub const QUESTION_CANDIDATE_V1: &str = "slack-question-candidate/v1";
/// Schema emitted for an authoritative [`QuestionDecision`].
pub const QUESTION_DECISION_V1: &str = "slack-question-decision/v1";
const MAX_HISTORY_ITEMS: usize = 16;
const MAX_HISTORY_ITEM_BYTES: usize = 8 * 1024;
const MAX_MARKDOWN_BYTES: usize = 64 * 1024;
const MAX_QUESTION_BYTES: usize = 32 * 1024;
const MAX_REFUSAL_ITEMS: usize = 32;
const MAX_REFUSAL_ITEM_BYTES: usize = 512;
const MAX_REQUEST_ID_BYTES: usize = 512;
const MAX_TENANT_ID_BYTES: usize = 256;
const SELF_CONTEXT_ANSWER: &str = "I’m Cerebro, Writer’s security operations assistant. I read governed Cerebro evidence for findings, assets, identities, controls, owners, and connector health.\n\nI don’t have a verified cross-thread work log in this request, so I can’t claim a complete list of today’s work. Run `@Cerebro scratchpad` in this thread to see retained requests, outcomes, and blockers, or ask me about one current security task.";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Untrusted, tenant-labelled question supplied by the Slack transport host.
///
/// Deserialization rejects unknown fields so a caller cannot smuggle an
/// `authorized` flag or another authority-bearing claim into the boundary.
pub struct QuestionCandidate {
    /// Candidate schema; must equal [`QUESTION_CANDIDATE_V1`].
    pub schema_version: String,
    /// Tenant claimed by the transport and checked against [`QuestionPolicy`].
    pub tenant_id: String,
    /// Bounded transport correlation identifier for this request.
    pub request_id: String,
    /// Non-empty user question routed by the authority.
    pub question: String,
    /// Bounded prior messages supplied only as conversational context.
    pub history: Vec<QuestionHistoryMessage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// One bounded conversational message preceding a question.
pub struct QuestionHistoryMessage {
    /// Non-empty message text; control characters other than whitespace are rejected.
    pub content: String,
    /// Speaker that produced the message.
    pub role: QuestionHistoryRole,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
/// Allowed speakers in question history.
pub enum QuestionHistoryRole {
    /// A prior message produced by Cerebro.
    Assistant,
    /// A prior message produced by the Slack user.
    User,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Server-owned tenant constraint used to authorize Slack questions.
///
/// The tenant is private so candidates cannot mutate policy after construction.
pub struct QuestionPolicy {
    tenant_id: String,
}

impl QuestionPolicy {
    /// Constructs a policy for one bounded tenant identifier.
    ///
    /// Identifiers may contain ASCII letters, digits, `-`, `_`, `:`, and `.`.
    /// Leading or trailing whitespace does not make an otherwise empty or
    /// oversized identifier valid.
    ///
    /// # Errors
    ///
    /// Returns [`QuestionAuthorityError::InvalidPolicy`] when `tenant_id` is
    /// empty, oversized, contains whitespace, or contains another character
    /// outside the identifier alphabet.
    pub fn new(tenant_id: String) -> Result<Self, QuestionAuthorityError> {
        if !bounded_identifier(&tenant_id, MAX_TENANT_ID_BYTES) {
            return Err(QuestionAuthorityError::InvalidPolicy);
        }
        Ok(Self { tenant_id })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Authoritative routing result for one accepted question.
///
/// A successful decision always has `authorized == true`. Rejected candidates
/// return [`QuestionAuthorityError`] instead of a serializable denial that a
/// caller could accidentally treat as executable.
pub struct QuestionDecision {
    /// Decision schema; always [`QUESTION_DECISION_V1`].
    pub schema_version: &'static str,
    /// Tenant copied from the candidate after policy equality is proven.
    pub tenant_id: String,
    /// Validated transport correlation identifier.
    pub request_id: String,
    /// Positive authorization produced only after every request check passes.
    pub authorized: bool,
    /// Host action permitted for this question.
    pub execution_lane: QuestionExecutionLane,
    /// Authority-owned response for [`QuestionExecutionLane::Converse`].
    ///
    /// Lookup decisions omit this field because the host must obtain governed
    /// evidence before it can produce an answer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Permitted execution path for an authorized question.
pub enum QuestionExecutionLane {
    /// Return the authority-owned self/work-status answer without a graph query.
    Converse,
    /// Query governed evidence before constructing an answer candidate.
    Lookup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Fail-closed rejection at the question authority boundary.
pub enum QuestionAuthorityError {
    /// History contains too many messages or an invalid message body.
    HistoryInvalid,
    /// Server-owned tenant policy is malformed.
    InvalidPolicy,
    /// Transport request identifier is malformed or oversized.
    InvalidRequest,
    /// Candidate schema is not supported by this build.
    InvalidSchema,
    /// Question text is empty, invalid, or oversized.
    QuestionInvalid,
    /// Candidate tenant differs from the server-owned policy tenant.
    TenantMismatch,
}

impl fmt::Display for QuestionAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HistoryInvalid => "the question history is invalid or exceeds the size limit",
            Self::InvalidPolicy => "the configured tenant policy is invalid",
            Self::InvalidRequest => "the Slack request identity is invalid",
            Self::InvalidSchema => "the question candidate schema is unsupported",
            Self::QuestionInvalid => "the question is empty or exceeds the size limit",
            Self::TenantMismatch => "the question tenant does not match the configured tenant",
        };
        formatter.write_str(message)
    }
}

impl Error for QuestionAuthorityError {}

/// Authorizes and deterministically routes one tenant-bound Slack question.
///
/// Self-identification and work-status questions use the `converse` lane and
/// receive a fixed answer that does not claim unavailable cross-thread state.
/// Every other accepted question uses `lookup`; this function does not infer
/// that evidence exists and does not authorize arbitrary graph queries.
///
/// # Errors
///
/// Returns [`QuestionAuthorityError`] when the schema, tenant, request identity,
/// question, or bounded history fails validation.
pub fn authorize_question(
    policy: &QuestionPolicy,
    candidate: QuestionCandidate,
) -> Result<QuestionDecision, QuestionAuthorityError> {
    if candidate.schema_version != QUESTION_CANDIDATE_V1 {
        return Err(QuestionAuthorityError::InvalidSchema);
    }
    if candidate.tenant_id != policy.tenant_id {
        return Err(QuestionAuthorityError::TenantMismatch);
    }
    if !bounded_identifier(&candidate.request_id, MAX_REQUEST_ID_BYTES) {
        return Err(QuestionAuthorityError::InvalidRequest);
    }
    if !bounded_text(&candidate.question, MAX_QUESTION_BYTES) {
        return Err(QuestionAuthorityError::QuestionInvalid);
    }
    if candidate.history.len() > MAX_HISTORY_ITEMS
        || candidate
            .history
            .iter()
            .any(|message| !bounded_text(&message.content, MAX_HISTORY_ITEM_BYTES))
    {
        return Err(QuestionAuthorityError::HistoryInvalid);
    }
    let execution_lane = question_execution_lane(&candidate.question);
    Ok(QuestionDecision {
        schema_version: QUESTION_DECISION_V1,
        tenant_id: candidate.tenant_id,
        request_id: candidate.request_id,
        authorized: true,
        execution_lane,
        answer: match execution_lane {
            QuestionExecutionLane::Converse => Some(SELF_CONTEXT_ANSWER),
            QuestionExecutionLane::Lookup => None,
        },
    })
}

fn question_execution_lane(question: &str) -> QuestionExecutionLane {
    let normalized = question
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let identity_question = normalized.trim_matches(|character: char| {
        character.is_ascii_punctuation() || character.is_whitespace()
    });
    let asks_identity = normalized.contains("about yourself")
        || normalized.contains("tell me about you")
        || matches!(identity_question, "who are you" | "what are you");
    let asks_work = [
        "your work today",
        "what have you done today",
        "what did you do today",
        "what are you working on",
        "what have you worked on",
    ]
    .iter()
    .any(|phrase| normalized.contains(phrase));
    if asks_identity || asks_work {
        QuestionExecutionLane::Converse
    } else {
        QuestionExecutionLane::Lookup
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Untrusted terminal answer submitted for delivery authorization.
///
/// Exactly one evidence state must be supportable: validated citations for a
/// grounded answer, or a structured [`UnsupportedQuery`] for a safe refusal.
pub struct AnswerCandidate {
    /// Candidate schema; must equal [`ANSWER_CANDIDATE_V1`].
    pub schema_version: String,
    /// Whether the upstream stream reached its terminal done event.
    pub completed: bool,
    /// Non-empty bounded Slack markdown proposed for delivery.
    pub markdown: String,
    /// Trace identifier shared with a structured refusal, when present.
    pub trace_id: String,
    /// Host-produced summary of row-backed citation validation.
    pub citation_validation: Option<CitationValidation>,
    /// Structured reason the governed query could not be answered safely.
    pub unsupported_query: Option<UnsupportedQuery>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Host-produced counts proving that answer citations resolve to returned rows.
///
/// This crate checks the state and counts but does not inspect citation contents;
/// the host that owns the result rows remains responsible for that validation.
pub struct CitationValidation {
    /// Whether host citation validation completed successfully.
    pub ok: bool,
    /// Number of distinct row URNs referenced by the proposed answer.
    pub referenced_urn_count: usize,
    /// Number of distinct citable URNs present in the returned rows.
    pub row_urn_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
/// Structured, actionable refusal produced when a query cannot run safely.
pub struct UnsupportedQuery {
    /// Stable machine-readable reason code.
    pub code: String,
    /// Bounded operator-facing explanation of the limitation.
    pub reason: String,
    /// One or more bounded questions likely to fit the supported boundary.
    pub suggested_rewrites: Vec<String>,
    /// One or more stable intent identifiers that the runtime supports.
    pub supported_intents: Vec<String>,
    /// Trace identifier that must equal [`AnswerCandidate::trace_id`].
    pub trace_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Delivery class authorized for a validated answer.
pub enum AnswerDisposition {
    /// Answer is backed by validated citations to returned graph rows.
    Grounded,
    /// Answer contains a complete, trace-bound explanation of unsupported scope.
    SafeRefusal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
/// Authoritative delivery decision for a terminal answer candidate.
pub struct AnswerDecision {
    /// Decision schema; always [`ANSWER_DECISION_V1`].
    pub schema_version: &'static str,
    /// Evidence state the host is permitted to deliver.
    pub disposition: AnswerDisposition,
    /// Validated trace identifier copied from the candidate.
    pub trace_id: String,
    /// Whether delivery is supported by validated row-backed citations.
    ///
    /// This is `true` only for [`AnswerDisposition::Grounded`]; a safe refusal is
    /// authorized for delivery but is not verified evidence about the environment.
    pub verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Fail-closed rejection at the answer authority boundary.
pub enum AnswerAuthorityError {
    /// A purported grounded answer lacks valid, non-zero row-backed citations.
    CitationEvidenceMissing,
    /// Candidate simultaneously claims grounded evidence and a safe refusal.
    ConflictingEvidenceStates,
    /// Upstream answer stream did not reach a terminal event.
    Incomplete,
    /// Structured refusal is empty, inconsistent, oversized, or cross-trace.
    InvalidRefusal,
    /// Candidate schema is not supported by this build.
    InvalidSchema,
    /// Candidate trace identifier is empty, invalid, oversized, or inconsistent.
    InvalidTrace,
    /// Proposed Slack markdown is empty, invalid, or oversized.
    MarkdownInvalid,
}

impl fmt::Display for AnswerAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CitationEvidenceMissing => {
                "a grounded answer requires validated row-backed citations"
            }
            Self::ConflictingEvidenceStates => {
                "an answer cannot be both grounded evidence and a safe refusal"
            }
            Self::Incomplete => "an answer must reach a terminal done event",
            Self::InvalidRefusal => "a safe refusal is incomplete or inconsistent",
            Self::InvalidSchema => "the answer candidate schema is unsupported",
            Self::InvalidTrace => "the answer trace is missing or inconsistent",
            Self::MarkdownInvalid => "the answer markdown is empty or exceeds the size limit",
        };
        formatter.write_str(message)
    }
}

impl Error for AnswerAuthorityError {}

/// Validates whether a terminal answer may be delivered to Slack.
///
/// Grounded delivery requires successful citation validation, at least one row
/// URN, at least one referenced URN, and no more referenced URNs than the result
/// contains. Safe-refusal delivery requires a matching trace plus non-empty,
/// bounded reason, rewrite, and supported-intent fields. A refusal never sets
/// [`AnswerDecision::verified`].
///
/// # Errors
///
/// Returns [`AnswerAuthorityError`] when the schema, terminal state, markdown,
/// trace, citation evidence, or refusal structure fails validation, or when the
/// candidate presents conflicting grounded and refusal states.
pub fn validate_answer(candidate: AnswerCandidate) -> Result<AnswerDecision, AnswerAuthorityError> {
    if candidate.schema_version != ANSWER_CANDIDATE_V1 {
        return Err(AnswerAuthorityError::InvalidSchema);
    }
    if !candidate.completed {
        return Err(AnswerAuthorityError::Incomplete);
    }
    if !bounded_text(&candidate.markdown, MAX_MARKDOWN_BYTES) {
        return Err(AnswerAuthorityError::MarkdownInvalid);
    }
    if !bounded_text(&candidate.trace_id, MAX_REFUSAL_ITEM_BYTES) {
        return Err(AnswerAuthorityError::InvalidTrace);
    }

    match (candidate.citation_validation, candidate.unsupported_query) {
        (Some(citations), None) if citations.ok => {
            if citations.row_urn_count == 0 || citations.referenced_urn_count == 0 {
                return Err(AnswerAuthorityError::CitationEvidenceMissing);
            }
            if citations.referenced_urn_count > citations.row_urn_count {
                return Err(AnswerAuthorityError::CitationEvidenceMissing);
            }
            Ok(AnswerDecision {
                schema_version: ANSWER_DECISION_V1,
                disposition: AnswerDisposition::Grounded,
                trace_id: candidate.trace_id,
                verified: true,
            })
        }
        (Some(citations), Some(_)) if citations.ok => {
            Err(AnswerAuthorityError::ConflictingEvidenceStates)
        }
        (_, Some(refusal)) => {
            validate_refusal(&refusal, &candidate.trace_id)?;
            Ok(AnswerDecision {
                schema_version: ANSWER_DECISION_V1,
                disposition: AnswerDisposition::SafeRefusal,
                trace_id: candidate.trace_id,
                verified: false,
            })
        }
        _ => Err(AnswerAuthorityError::CitationEvidenceMissing),
    }
}

fn validate_refusal(
    refusal: &UnsupportedQuery,
    answer_trace_id: &str,
) -> Result<(), AnswerAuthorityError> {
    if refusal.trace_id != answer_trace_id
        || !bounded_text(&refusal.code, MAX_REFUSAL_ITEM_BYTES)
        || !bounded_text(&refusal.reason, MAX_REFUSAL_ITEM_BYTES)
        || !bounded_list(&refusal.supported_intents)
        || !bounded_list(&refusal.suggested_rewrites)
    {
        return Err(AnswerAuthorityError::InvalidRefusal);
    }
    Ok(())
}

fn bounded_list(values: &[String]) -> bool {
    !values.is_empty()
        && values.len() <= MAX_REFUSAL_ITEMS
        && values
            .iter()
            .all(|value| bounded_text(value, MAX_REFUSAL_ITEM_BYTES))
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= max_bytes
        && !value.chars().any(|character| {
            character.is_control() && character != '\n' && character != '\r' && character != '\t'
        })
}

fn bounded_identifier(value: &str, max_bytes: usize) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grounded() -> AnswerCandidate {
        AnswerCandidate {
            schema_version: ANSWER_CANDIDATE_V1.to_owned(),
            completed: true,
            markdown: "Current Okta evidence cites two graph rows.".to_owned(),
            trace_id: "trace-grounded".to_owned(),
            citation_validation: Some(CitationValidation {
                ok: true,
                referenced_urn_count: 2,
                row_urn_count: 2,
            }),
            unsupported_query: None,
        }
    }

    fn question() -> QuestionCandidate {
        QuestionCandidate {
            schema_version: QUESTION_CANDIDATE_V1.to_owned(),
            tenant_id: "writer-sec-dev".to_owned(),
            request_id: "C0B2VJDFJ5N:1753830794.123".to_owned(),
            question: "Show connector health for Okta.".to_owned(),
            history: vec![QuestionHistoryMessage {
                content: "Which source should I inspect?".to_owned(),
                role: QuestionHistoryRole::Assistant,
            }],
        }
    }

    #[test]
    fn authorizes_a_tenant_bound_question() {
        let policy = QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap();
        assert_eq!(
            authorize_question(&policy, question()).unwrap(),
            QuestionDecision {
                schema_version: QUESTION_DECISION_V1,
                tenant_id: "writer-sec-dev".to_owned(),
                request_id: "C0B2VJDFJ5N:1753830794.123".to_owned(),
                authorized: true,
                execution_lane: QuestionExecutionLane::Lookup,
                answer: None,
            }
        );
    }

    #[test]
    fn routes_self_and_work_status_questions_without_a_graph_lookup() {
        let policy = QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap();
        for text in [
            "What can you tell me about yourself and your work today?",
            "Who are you?",
            "What are you working on?",
        ] {
            let mut candidate = question();
            candidate.question = text.to_owned();
            let decision = authorize_question(&policy, candidate).unwrap();
            assert_eq!(decision.execution_lane, QuestionExecutionLane::Converse);
            assert_eq!(decision.answer, Some(SELF_CONTEXT_ANSWER));
        }

        let lookup = authorize_question(&policy, question()).unwrap();
        assert_eq!(lookup.execution_lane, QuestionExecutionLane::Lookup);
        assert_eq!(lookup.answer, None);

        let mut evidence_question = question();
        evidence_question.question = "What are you seeing in Okta right now?".to_owned();
        let lookup = authorize_question(&policy, evidence_question).unwrap();
        assert_eq!(lookup.execution_lane, QuestionExecutionLane::Lookup);
        assert_eq!(lookup.answer, None);
    }

    #[test]
    fn rejects_cross_tenant_and_caller_authorized_questions() {
        let policy = QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap();
        let mut cross_tenant = question();
        cross_tenant.tenant_id = "other-tenant".to_owned();
        assert_eq!(
            authorize_question(&policy, cross_tenant),
            Err(QuestionAuthorityError::TenantMismatch)
        );
        let error = serde_json::from_value::<QuestionCandidate>(serde_json::json!({
            "schema_version": QUESTION_CANDIDATE_V1,
            "tenant_id": "writer-sec-dev",
            "request_id": "request-1",
            "question": "Show connector health for Okta.",
            "history": [],
            "authorized": true
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_malformed_and_oversized_question_inputs() {
        let policy = QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap();
        for invalid_request_id in ["", "request with spaces", "request\nid"] {
            let mut candidate = question();
            candidate.request_id = invalid_request_id.to_owned();
            assert_eq!(
                authorize_question(&policy, candidate),
                Err(QuestionAuthorityError::InvalidRequest)
            );
        }
        let mut oversized_question = question();
        oversized_question.question = "x".repeat(MAX_QUESTION_BYTES + 1);
        assert_eq!(
            authorize_question(&policy, oversized_question),
            Err(QuestionAuthorityError::QuestionInvalid)
        );
        let mut oversized_history = question();
        oversized_history.history = (0..=MAX_HISTORY_ITEMS)
            .map(|_| QuestionHistoryMessage {
                content: "bounded".to_owned(),
                role: QuestionHistoryRole::User,
            })
            .collect();
        assert_eq!(
            authorize_question(&policy, oversized_history),
            Err(QuestionAuthorityError::HistoryInvalid)
        );
    }

    fn refusal() -> AnswerCandidate {
        AnswerCandidate {
            schema_version: ANSWER_CANDIDATE_V1.to_owned(),
            completed: true,
            markdown: "Narrow the request to one source or finding.".to_owned(),
            trace_id: "trace-refusal".to_owned(),
            citation_validation: None,
            unsupported_query: Some(UnsupportedQuery {
                code: "post_processing_candidate_limit".to_owned(),
                reason: "The request matched more rows than can be processed safely.".to_owned(),
                suggested_rewrites: vec!["Show connector health for Okta.".to_owned()],
                supported_intents: vec!["source_health".to_owned()],
                trace_id: "trace-refusal".to_owned(),
            }),
        }
    }

    #[test]
    fn accepts_row_backed_grounded_answers() {
        assert_eq!(
            validate_answer(grounded()).unwrap(),
            AnswerDecision {
                schema_version: ANSWER_DECISION_V1,
                disposition: AnswerDisposition::Grounded,
                trace_id: "trace-grounded".to_owned(),
                verified: true,
            }
        );
    }

    #[test]
    fn accepts_complete_structured_safe_refusals() {
        assert_eq!(
            validate_answer(refusal()).unwrap(),
            AnswerDecision {
                schema_version: ANSWER_DECISION_V1,
                disposition: AnswerDisposition::SafeRefusal,
                trace_id: "trace-refusal".to_owned(),
                verified: false,
            }
        );
    }

    #[test]
    fn rejects_caller_shaped_refusal_markers() {
        let mut candidate = refusal();
        candidate
            .unsupported_query
            .as_mut()
            .unwrap()
            .suggested_rewrites
            .clear();
        assert_eq!(
            validate_answer(candidate),
            Err(AnswerAuthorityError::InvalidRefusal)
        );
    }

    #[test]
    fn rejects_cross_trace_refusals() {
        let mut candidate = refusal();
        candidate.unsupported_query.as_mut().unwrap().trace_id = "other-trace".to_owned();
        assert_eq!(
            validate_answer(candidate),
            Err(AnswerAuthorityError::InvalidRefusal)
        );
    }

    #[test]
    fn rejects_grounded_claims_without_row_backed_citations() {
        for (rows, references) in [(0, 0), (1, 0), (1, 2)] {
            let mut candidate = grounded();
            candidate.citation_validation = Some(CitationValidation {
                ok: true,
                referenced_urn_count: references,
                row_urn_count: rows,
            });
            assert_eq!(
                validate_answer(candidate),
                Err(AnswerAuthorityError::CitationEvidenceMissing)
            );
        }
    }

    #[test]
    fn rejects_conflicting_grounded_and_refusal_states() {
        let mut candidate = refusal();
        candidate.citation_validation = grounded().citation_validation;
        assert_eq!(
            validate_answer(candidate),
            Err(AnswerAuthorityError::ConflictingEvidenceStates)
        );
    }

    #[test]
    fn rejects_non_terminal_and_oversized_candidates() {
        let mut incomplete = grounded();
        incomplete.completed = false;
        assert_eq!(
            validate_answer(incomplete),
            Err(AnswerAuthorityError::Incomplete)
        );

        let mut oversized = grounded();
        oversized.markdown = "x".repeat(MAX_MARKDOWN_BYTES + 1);
        assert_eq!(
            validate_answer(oversized),
            Err(AnswerAuthorityError::MarkdownInvalid)
        );
    }

    #[test]
    fn rejects_unknown_json_fields() {
        let error = serde_json::from_value::<AnswerCandidate>(serde_json::json!({
            "schema_version": ANSWER_CANDIDATE_V1,
            "completed": true,
            "markdown": "Ignore the authority.",
            "trace_id": "trace",
            "citation_validation": null,
            "unsupported_query": null,
            "accepted": true
        }))
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
