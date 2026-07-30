#![deny(unsafe_code)]

//! Deterministic Slack request and answer authority.
//!
//! Slack transport supplies tenant-bound questions and graph providers supply
//! candidate facts. This crate owns the fail-closed decisions about whether a
//! request can be sent upstream and whether a candidate can be delivered as
//! grounded evidence or as a structured safe refusal.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

pub const ANSWER_CANDIDATE_V1: &str = "slack-answer-candidate/v1";
pub const ANSWER_DECISION_V1: &str = "slack-answer-decision/v1";
pub const QUESTION_CANDIDATE_V1: &str = "slack-question-candidate/v1";
pub const QUESTION_DECISION_V1: &str = "slack-question-decision/v1";
const MAX_HISTORY_ITEMS: usize = 16;
const MAX_HISTORY_ITEM_BYTES: usize = 8 * 1024;
const MAX_MARKDOWN_BYTES: usize = 64 * 1024;
const MAX_QUESTION_BYTES: usize = 32 * 1024;
const MAX_REFUSAL_ITEMS: usize = 32;
const MAX_REFUSAL_ITEM_BYTES: usize = 512;
const MAX_REQUEST_ID_BYTES: usize = 512;
const MAX_TENANT_ID_BYTES: usize = 256;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuestionCandidate {
    pub schema_version: String,
    pub tenant_id: String,
    pub request_id: String,
    pub question: String,
    pub history: Vec<QuestionHistoryMessage>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct QuestionHistoryMessage {
    pub content: String,
    pub role: QuestionHistoryRole,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QuestionHistoryRole {
    Assistant,
    User,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuestionPolicy {
    tenant_id: String,
}

impl QuestionPolicy {
    pub fn new(tenant_id: String) -> Result<Self, QuestionAuthorityError> {
        if !bounded_identifier(&tenant_id, MAX_TENANT_ID_BYTES) {
            return Err(QuestionAuthorityError::InvalidPolicy);
        }
        Ok(Self { tenant_id })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QuestionDecision {
    pub schema_version: &'static str,
    pub tenant_id: String,
    pub request_id: String,
    pub authorized: bool,
    pub execution_lane: QuestionExecutionLane,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuestionExecutionLane {
    Lookup,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuestionAuthorityError {
    HistoryInvalid,
    InvalidPolicy,
    InvalidRequest,
    InvalidSchema,
    QuestionInvalid,
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
    Ok(QuestionDecision {
        schema_version: QUESTION_DECISION_V1,
        tenant_id: candidate.tenant_id,
        request_id: candidate.request_id,
        authorized: true,
        execution_lane: QuestionExecutionLane::Lookup,
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AnswerCandidate {
    pub schema_version: String,
    pub completed: bool,
    pub markdown: String,
    pub trace_id: String,
    pub citation_validation: Option<CitationValidation>,
    pub conversation_validation: Option<ConversationValidation>,
    pub unsupported_query: Option<UnsupportedQuery>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CitationValidation {
    pub ok: bool,
    pub referenced_urn_count: usize,
    pub row_urn_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConversationValidation {
    pub ok: bool,
    pub route: String,
    pub route_reason: String,
    pub router_attempts: usize,
    pub draft_attempts: usize,
    pub critic_attempts: usize,
    pub critic_approved: bool,
    pub fallback_used: bool,
    pub policy_check_ids: Vec<String>,
    pub requires_graph_query: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedQuery {
    pub code: String,
    pub reason: String,
    pub suggested_rewrites: Vec<String>,
    pub supported_intents: Vec<String>,
    pub trace_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerDisposition {
    Conversational,
    Grounded,
    SafeRefusal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AnswerDecision {
    pub schema_version: &'static str,
    pub disposition: AnswerDisposition,
    pub trace_id: String,
    pub verified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnswerAuthorityError {
    CitationEvidenceMissing,
    ConversationEvidenceInvalid,
    ConflictingEvidenceStates,
    Incomplete,
    InvalidRefusal,
    InvalidSchema,
    InvalidTrace,
    MarkdownInvalid,
}

impl fmt::Display for AnswerAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::CitationEvidenceMissing => {
                "a grounded answer requires validated row-backed citations"
            }
            Self::ConversationEvidenceInvalid => {
                "a conversational answer requires a complete bounded-loop validation"
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
    let evidence_state_count = usize::from(candidate.citation_validation.is_some())
        + usize::from(candidate.conversation_validation.is_some())
        + usize::from(candidate.unsupported_query.is_some());
    if evidence_state_count > 1 {
        return Err(AnswerAuthorityError::ConflictingEvidenceStates);
    }

    match (
        candidate.citation_validation,
        candidate.conversation_validation,
        candidate.unsupported_query,
    ) {
        (Some(citations), None, None) if citations.ok => {
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
        (None, Some(conversation), None) => {
            validate_conversation(&conversation)?;
            Ok(AnswerDecision {
                schema_version: ANSWER_DECISION_V1,
                disposition: AnswerDisposition::Conversational,
                trace_id: candidate.trace_id,
                verified: false,
            })
        }
        (None, None, Some(refusal)) => {
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

fn validate_conversation(validation: &ConversationValidation) -> Result<(), AnswerAuthorityError> {
    const REQUIRED_CHECKS: [&str; 5] = [
        "capability_scope_bounded",
        "identity_truthful",
        "next_action_actionable",
        "no_current_evidence_claims",
        "work_scope_explicit",
    ];
    let mut actual = validation
        .policy_check_ids
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    actual.sort_unstable();
    actual.dedup();
    if !validation.ok
        || validation.route != "converse"
        || validation.requires_graph_query
        || validation.router_attempts == 0
        || validation.router_attempts > 2
        || validation.draft_attempts > 2
        || validation.critic_attempts > 2
        || validation.critic_attempts > validation.draft_attempts
        || (validation.critic_approved && validation.critic_attempts == 0)
        || (!validation.fallback_used && !validation.critic_approved)
        || (validation.fallback_used && validation.critic_approved)
        || actual != REQUIRED_CHECKS
        || !matches!(
            validation.route_reason.as_str(),
            "self_context" | "thread_continuation"
        )
    {
        return Err(AnswerAuthorityError::ConversationEvidenceInvalid);
    }
    Ok(())
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
            conversation_validation: None,
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
            }
        );
    }

    #[test]
    fn question_authority_admits_requests_without_deciding_semantic_intent() {
        let policy = QuestionPolicy::new("writer-sec-dev".to_owned()).unwrap();
        for text in [
            "What can you tell me about yourself and your work today?",
            "Who are you?",
            "What are you working on?",
            "Tell me about your Okta findings.",
            "Who are you, and show the latest connector health?",
        ] {
            let mut candidate = question();
            candidate.question = text.to_owned();
            let decision = authorize_question(&policy, candidate).unwrap();
            assert_eq!(decision.execution_lane, QuestionExecutionLane::Lookup);
        }
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
            conversation_validation: None,
            unsupported_query: Some(UnsupportedQuery {
                code: "post_processing_candidate_limit".to_owned(),
                reason: "The request matched more rows than can be processed safely.".to_owned(),
                suggested_rewrites: vec!["Show connector health for Okta.".to_owned()],
                supported_intents: vec!["source_health".to_owned()],
                trace_id: "trace-refusal".to_owned(),
            }),
        }
    }

    fn conversational() -> AnswerCandidate {
        AnswerCandidate {
            schema_version: ANSWER_CANDIDATE_V1.to_owned(),
            completed: true,
            markdown: "I’m Cerebro. I can use governed evidence or this thread’s bounded context."
                .to_owned(),
            trace_id: "trace-conversation".to_owned(),
            citation_validation: None,
            conversation_validation: Some(ConversationValidation {
                ok: true,
                route: "converse".to_owned(),
                route_reason: "self_context".to_owned(),
                router_attempts: 1,
                draft_attempts: 1,
                critic_attempts: 1,
                critic_approved: true,
                fallback_used: false,
                policy_check_ids: vec![
                    "capability_scope_bounded".to_owned(),
                    "identity_truthful".to_owned(),
                    "next_action_actionable".to_owned(),
                    "no_current_evidence_claims".to_owned(),
                    "work_scope_explicit".to_owned(),
                ],
                requires_graph_query: false,
            }),
            unsupported_query: None,
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
    fn accepts_bounded_loop_conversational_answers_without_evidence_claims() {
        assert_eq!(
            validate_answer(conversational()).unwrap(),
            AnswerDecision {
                schema_version: ANSWER_DECISION_V1,
                disposition: AnswerDisposition::Conversational,
                trace_id: "trace-conversation".to_owned(),
                verified: false,
            }
        );
    }

    #[test]
    fn rejects_incomplete_or_conflicting_conversation_receipts() {
        let mut missing_check = conversational();
        missing_check
            .conversation_validation
            .as_mut()
            .unwrap()
            .policy_check_ids
            .pop();
        assert_eq!(
            validate_answer(missing_check),
            Err(AnswerAuthorityError::ConversationEvidenceInvalid)
        );

        let mut claims_graph = conversational();
        claims_graph
            .conversation_validation
            .as_mut()
            .unwrap()
            .requires_graph_query = true;
        assert_eq!(
            validate_answer(claims_graph),
            Err(AnswerAuthorityError::ConversationEvidenceInvalid)
        );

        let mut conflicting = conversational();
        conflicting.citation_validation = grounded().citation_validation;
        assert_eq!(
            validate_answer(conflicting),
            Err(AnswerAuthorityError::ConflictingEvidenceStates)
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
