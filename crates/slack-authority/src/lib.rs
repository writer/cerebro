#![deny(unsafe_code)]

//! Deterministic Slack answer acceptance authority.
//!
//! Slack transport and graph providers supply candidate facts. This crate owns the
//! fail-closed decision about whether a candidate can be delivered as grounded
//! evidence or as a structured safe refusal.

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

pub const ANSWER_CANDIDATE_V1: &str = "slack-answer-candidate/v1";
pub const ANSWER_DECISION_V1: &str = "slack-answer-decision/v1";
const MAX_MARKDOWN_BYTES: usize = 64 * 1024;
const MAX_REFUSAL_ITEMS: usize = 32;
const MAX_REFUSAL_ITEM_BYTES: usize = 512;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AnswerCandidate {
    pub schema_version: String,
    pub completed: bool,
    pub markdown: String,
    pub trace_id: String,
    pub citation_validation: Option<CitationValidation>,
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
    !value.is_empty() && value.len() <= max_bytes
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
