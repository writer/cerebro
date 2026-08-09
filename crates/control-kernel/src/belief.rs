use std::{collections::BTreeSet, error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ActorId, BeliefId};

const MAX_TEXT_BYTES: usize = 4_096;
const MAX_REFERENCES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Provenance class describing how a belief statement was produced.
pub enum BeliefBasis {
    /// Statement directly reflects an authoritative observation.
    Observed,
    /// Statement is the reproducible output of a deterministic rule over evidence.
    DeterministicallyDerived,
    /// Statement was supplied by an actor and has not been independently established.
    Asserted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
/// Evidence judgment for a belief at one source and aggregate revision.
pub enum BeliefVerdict {
    /// Proposition is under consideration but has not met a support threshold.
    Candidate,
    /// Complete supporting evidence exists with no counterevidence or known gaps.
    Supported,
    /// Some evidence supports the proposition, but material limits remain.
    WeaklySupported,
    /// At least one recorded counterevidence item contradicts the proposition.
    Contradicted,
    /// Available evidence cannot currently establish direction or support.
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Inputs for recording revision one of an evidence-bounded belief.
pub struct BeliefInput {
    /// Stable identity preserved across belief revisions.
    pub belief_id: BeliefId,
    /// Exact bounded proposition being evaluated.
    pub statement: String,
    /// Method by which the proposition was produced.
    pub basis: BeliefBasis,
    /// Evidence judgment that must agree with the supplied references.
    pub verdict: BeliefVerdict,
    /// Non-empty canonical subjects described by the proposition.
    pub subject_urns: Vec<String>,
    /// Evidence records supporting the proposition.
    pub supporting_evidence_urns: Vec<String>,
    /// Evidence records contradicting the proposition.
    pub counterevidence_urns: Vec<String>,
    /// Named observations still required for a complete conclusion.
    pub missing_evidence: Vec<String>,
    /// Non-empty conditions that require reevaluation of the belief.
    pub invalidation_conditions: Vec<String>,
    /// Confidence from zero through 10,000 basis points.
    pub confidence_basis_points: u16,
    /// Authoritative source revision to which current-state evidence is bound.
    pub source_revision: Option<String>,
    /// Actor creating the initial belief record.
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Versioned proposition with explicit support, conflict, gaps, and invalidation.
///
/// A belief never turns confidence into evidence. [`BeliefVerdict::Supported`]
/// requires positive supporting references and forbids both counterevidence and
/// declared gaps, regardless of `confidence_basis_points`.
pub struct Belief {
    /// Stable identity preserved across every revision.
    pub belief_id: BeliefId,
    /// Optimistic-concurrency revision, starting at one.
    pub revision: u64,
    /// Immutable proposition evaluated by this belief history.
    pub statement: String,
    /// Immutable provenance class of the proposition.
    pub basis: BeliefBasis,
    /// Current evidence judgment.
    pub verdict: BeliefVerdict,
    /// Sorted, deduplicated canonical subjects.
    pub subject_urns: Vec<String>,
    /// Sorted, deduplicated evidence supporting the proposition.
    pub supporting_evidence_urns: Vec<String>,
    /// Sorted, deduplicated evidence contradicting the proposition.
    pub counterevidence_urns: Vec<String>,
    /// Sorted, deduplicated known evidence gaps.
    pub missing_evidence: Vec<String>,
    /// Conditions requiring a new revision rather than silent reuse.
    pub invalidation_conditions: Vec<String>,
    /// Current confidence from zero through 10,000 basis points.
    pub confidence_basis_points: u16,
    /// Source revision governing the current evidence snapshot, when supplied.
    pub source_revision: Option<String>,
    /// Actor responsible for the latest revision.
    pub changed_by: ActorId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Optimistic evidence update for an existing [`Belief`].
pub struct BeliefRevision {
    /// Revision observed by the caller; stale updates fail closed.
    pub expected_revision: u64,
    /// New evidence judgment.
    pub verdict: BeliefVerdict,
    /// Complete supporting evidence set for the new revision.
    pub supporting_evidence_urns: Vec<String>,
    /// Complete counterevidence set for the new revision.
    pub counterevidence_urns: Vec<String>,
    /// Complete known-gap set for the new revision.
    pub missing_evidence: Vec<String>,
    /// Non-empty invalidation conditions for future reuse.
    pub invalidation_conditions: Vec<String>,
    /// New confidence from zero through 10,000 basis points.
    pub confidence_basis_points: u16,
    /// Source revision governing the new evidence set.
    pub source_revision: Option<String>,
    /// Actor responsible for the evidence judgment.
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Reason a belief record or revision was rejected.
pub enum BeliefError {
    /// Proposition violated the bounded text contract.
    InvalidStatement,
    /// A required collection was empty or a reference was invalid or excessive.
    InvalidReferences,
    /// Confidence exceeded 10,000 basis points.
    InvalidConfidence,
    /// Verdict conflicts with supporting, contrary, or missing evidence.
    InvalidVerdict,
    /// Caller attempted to revise a stale aggregate.
    RevisionConflict {
        /// Revision supplied by the caller.
        expected: u64,
        /// Current belief revision.
        actual: u64,
    },
}

impl fmt::Display for BeliefError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidStatement => formatter.write_str("belief statement is invalid"),
            Self::InvalidReferences => formatter.write_str("belief references are invalid"),
            Self::InvalidConfidence => formatter.write_str("belief confidence is invalid"),
            Self::InvalidVerdict => {
                formatter.write_str("belief verdict conflicts with its evidence")
            }
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "belief revision conflict: expected {expected}, actual {actual}"
            ),
        }
    }
}

impl Error for BeliefError {}

impl Belief {
    /// Records revision one after normalizing references and checking the verdict.
    ///
    /// Reference collections are sorted and deduplicated. The statement, basis,
    /// and subjects become immutable; changing the proposition requires a new
    /// belief identity rather than rewriting its evidence history.
    pub fn record(input: BeliefInput) -> Result<Self, BeliefError> {
        validate_text(&input.statement).map_err(|_| BeliefError::InvalidStatement)?;
        validate_confidence(input.confidence_basis_points)?;
        let belief = Self {
            belief_id: input.belief_id,
            revision: 1,
            statement: input.statement,
            basis: input.basis,
            verdict: input.verdict,
            subject_urns: normalize_required(input.subject_urns)?,
            supporting_evidence_urns: normalize_optional(input.supporting_evidence_urns)?,
            counterevidence_urns: normalize_optional(input.counterevidence_urns)?,
            missing_evidence: normalize_optional(input.missing_evidence)?,
            invalidation_conditions: normalize_required(input.invalidation_conditions)?,
            confidence_basis_points: input.confidence_basis_points,
            source_revision: normalize_optional_text(input.source_revision)?,
            changed_by: input.actor_id,
        };
        belief.validate_verdict()?;
        Ok(belief)
    }

    /// Replaces the complete evidence judgment and returns a new belief revision.
    ///
    /// Updates are optimistic. Evidence collections are replacement snapshots,
    /// not deltas, preventing removed counterevidence or gaps from surviving by
    /// accident. The result is revalidated before it is returned.
    pub fn revise(&self, revision: BeliefRevision) -> Result<Self, BeliefError> {
        if revision.expected_revision != self.revision {
            return Err(BeliefError::RevisionConflict {
                expected: revision.expected_revision,
                actual: self.revision,
            });
        }
        validate_confidence(revision.confidence_basis_points)?;
        let mut next = self.clone();
        next.revision += 1;
        next.verdict = revision.verdict;
        next.supporting_evidence_urns = normalize_optional(revision.supporting_evidence_urns)?;
        next.counterevidence_urns = normalize_optional(revision.counterevidence_urns)?;
        next.missing_evidence = normalize_optional(revision.missing_evidence)?;
        next.invalidation_conditions = normalize_required(revision.invalidation_conditions)?;
        next.confidence_basis_points = revision.confidence_basis_points;
        next.source_revision = normalize_optional_text(revision.source_revision)?;
        next.changed_by = revision.actor_id;
        next.validate_verdict()?;
        Ok(next)
    }

    fn validate_verdict(&self) -> Result<(), BeliefError> {
        if self.verdict == BeliefVerdict::Supported
            && (self.supporting_evidence_urns.is_empty()
                || !self.counterevidence_urns.is_empty()
                || !self.missing_evidence.is_empty())
        {
            return Err(BeliefError::InvalidVerdict);
        }
        if self.verdict == BeliefVerdict::Contradicted && self.counterevidence_urns.is_empty() {
            return Err(BeliefError::InvalidVerdict);
        }
        Ok(())
    }
}

fn validate_confidence(value: u16) -> Result<(), BeliefError> {
    if value > 10_000 {
        return Err(BeliefError::InvalidConfidence);
    }
    Ok(())
}

fn normalize_required(values: Vec<String>) -> Result<Vec<String>, BeliefError> {
    let values = normalize_optional(values)?;
    if values.is_empty() {
        return Err(BeliefError::InvalidReferences);
    }
    Ok(values)
}

fn normalize_optional(values: Vec<String>) -> Result<Vec<String>, BeliefError> {
    if values.len() > MAX_REFERENCES {
        return Err(BeliefError::InvalidReferences);
    }
    let mut normalized = BTreeSet::new();
    for value in values {
        validate_text(&value).map_err(|_| BeliefError::InvalidReferences)?;
        normalized.insert(value);
    }
    Ok(normalized.into_iter().collect())
}

fn normalize_optional_text(value: Option<String>) -> Result<Option<String>, BeliefError> {
    value
        .map(|value| {
            validate_text(&value).map_err(|_| BeliefError::InvalidReferences)?;
            Ok(value)
        })
        .transpose()
}

fn validate_text(value: &str) -> Result<(), ()> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> BeliefInput {
        BeliefInput {
            belief_id: BeliefId::parse("belief-1").unwrap(),
            statement: "A terminated identity retains production access".into(),
            basis: BeliefBasis::DeterministicallyDerived,
            verdict: BeliefVerdict::Candidate,
            subject_urns: vec!["urn:identity:1".into()],
            supporting_evidence_urns: vec![],
            counterevidence_urns: vec![],
            missing_evidence: vec!["fresh access snapshot".into()],
            invalidation_conditions: vec!["access source revision changes".into()],
            confidence_basis_points: 5_000,
            source_revision: Some("rev-1".into()),
            actor_id: ActorId::parse("resolver").unwrap(),
        }
    }

    #[test]
    fn supported_beliefs_require_uncontested_complete_evidence() {
        let belief = Belief::record(input()).unwrap();
        let supported = belief
            .revise(BeliefRevision {
                expected_revision: 1,
                verdict: BeliefVerdict::Supported,
                supporting_evidence_urns: vec!["urn:evidence:access:1".into()],
                counterevidence_urns: vec![],
                missing_evidence: vec![],
                invalidation_conditions: vec!["access source revision changes".into()],
                confidence_basis_points: 9_500,
                source_revision: Some("rev-2".into()),
                actor_id: ActorId::parse("verifier").unwrap(),
            })
            .unwrap();
        assert_eq!(supported.revision, 2);
        assert_eq!(supported.verdict, BeliefVerdict::Supported);

        let mut invalid = input();
        invalid.verdict = BeliefVerdict::Supported;
        assert_eq!(Belief::record(invalid), Err(BeliefError::InvalidVerdict));
    }
}
