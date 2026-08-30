//! Transport-neutral contracts for declaring and recording graph assertions.
//!
//! An assertion definition binds a tenant-scoped fact query to a count
//! condition and a content digest. Execution engines validate that digest
//! before evaluation so callers cannot silently change the query, condition,
//! triggers, or evidence-age policy while retaining the same definition.

use serde::Serialize;

use crate::{AssertionDefinitionId, ContentDigest, FactQuery, GraphRevision, SdkError, TenantId};

/// Event that may cause an assertion definition to be evaluated again.
///
/// Triggers describe scheduling intent only. They do not authorize a graph
/// read, identify a scheduler, or prove that an evaluation ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationTrigger {
    /// Re-evaluate after the tenant graph advances.
    GraphChange,
    /// Re-evaluate when supporting evidence crosses a freshness boundary.
    EvidenceFreshness,
    /// Re-evaluate during a periodic reconciliation pass.
    ScheduledReconciliation,
    /// Re-evaluate in response to an explicit operator or API request.
    Manual,
}

/// Three-valued outcome of evaluating an assertion against graph evidence.
///
/// [`Self::Indeterminate`] is distinct from a violation: it means the engine
/// could not make the positive or negative claim responsibly. Consumers should
/// inspect [`AssertionEvaluation::reason_codes`] before choosing a next action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionState {
    /// Complete, usable evidence met the declared condition.
    Satisfied,
    /// Complete, usable evidence did not meet the declared condition.
    Violated,
    /// Disabled evaluation or unusable evidence prevented a conclusion.
    Indeterminate,
}

/// Predicate applied to the number of complete fact-query matches.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "count")]
pub enum AssertionCondition {
    /// Satisfied only when the query returns no matches.
    NoMatches,
    /// Satisfied when the query returns one or more matches.
    AtLeastOneMatch,
    /// Satisfied when the match count is at most the inclusive maximum.
    MatchCountAtMost(u32),
    /// Satisfied when the match count reaches the non-zero inclusive minimum.
    MatchCountAtLeast(u32),
}

impl AssertionCondition {
    /// Applies this predicate to a complete, bounded match count.
    ///
    /// This method does not decide whether the query result is truncated or
    /// whether its evidence is usable. The assertion engine performs those
    /// fail-closed checks before calling the predicate.
    pub fn evaluate(self, matching_paths: u32) -> bool {
        match self {
            Self::NoMatches => matching_paths == 0,
            Self::AtLeastOneMatch => matching_paths > 0,
            Self::MatchCountAtMost(maximum) => matching_paths <= maximum,
            Self::MatchCountAtLeast(minimum) => matching_paths >= minimum,
        }
    }

    fn validate(self) -> Result<(), SdkError> {
        // A zero lower bound is a tautology and usually signals a malformed
        // policy; callers must use a semantically explicit condition instead.
        if matches!(self, Self::MatchCountAtLeast(0)) {
            return Err(SdkError::OutOfRange("assertion minimum match count"));
        }
        Ok(())
    }
}

/// Content-addressed declaration of a tenant-scoped graph assertion.
///
/// The definition contains no execution state. Its digest covers every field
/// except the digest itself and must be recomputed when any semantic input
/// changes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssertionDefinition {
    /// Stable identity of this definition across evaluations.
    pub assertion_id: AssertionDefinitionId,
    /// Tenant whose graph the query is permitted to read.
    pub tenant_id: TenantId,
    /// Normalized operator-facing name for the assertion.
    pub name: String,
    /// Validated, bounded fact query that supplies match bindings.
    pub query: FactQuery,
    /// Predicate applied after evidence and completeness checks succeed.
    pub condition: AssertionCondition,
    /// Non-empty set of scheduling intents for re-evaluation.
    pub triggers: Vec<EvaluationTrigger>,
    /// Maximum acceptable age of supporting evidence, in seconds.
    pub evidence_max_age_seconds: u64,
    /// Whether the engine may produce a satisfied or violated outcome.
    pub enabled: bool,
    /// Canonical digest of all preceding semantic fields.
    pub definition_digest: ContentDigest,
}

impl AssertionDefinition {
    /// Validates the definition fields that are independent of its digest.
    ///
    /// Digest verification is deliberately performed by the execution engine,
    /// which owns canonical serialization of the full definition material.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::Invalid`] or [`SdkError::TooLong`] for an invalid
    /// name, [`SdkError::Empty`] when no trigger is declared, or
    /// [`SdkError::OutOfRange`] for a zero evidence-age bound or invalid
    /// condition threshold.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.name.trim() != self.name || self.name.is_empty() {
            return Err(SdkError::Invalid("assertion name"));
        }
        if self.name.len() > 256 {
            return Err(SdkError::TooLong("assertion name"));
        }
        if self.triggers.is_empty() {
            return Err(SdkError::Empty("assertion triggers"));
        }
        if self.evidence_max_age_seconds == 0 {
            return Err(SdkError::OutOfRange("assertion evidence max age"));
        }
        self.condition.validate()
    }
}

/// Immutable receipt for one assertion evaluation at one graph revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssertionEvaluation {
    /// Definition that was evaluated.
    pub assertion_id: AssertionDefinitionId,
    /// Non-zero graph revision from which the query result was read.
    pub graph_revision: GraphRevision,
    /// Conclusive or indeterminate evaluation outcome.
    pub state: AssertionState,
    /// Caller-supplied Unix-millisecond time assigned to this evaluation.
    pub evaluated_at_unix_millis: i64,
    /// Number of distinct query bindings considered by the condition.
    pub matching_paths: u32,
    /// Stable machine-readable explanations; empty for a satisfied result.
    pub reason_codes: Vec<String>,
    /// Canonical digest of the exact query result and evidence-quality input.
    pub evidence_digest: ContentDigest,
}
