use std::{collections::BTreeSet, error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ActorId, BeliefId};

const MAX_TEXT_BYTES: usize = 4_096;
const MAX_REFERENCES: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BeliefBasis {
    Observed,
    DeterministicallyDerived,
    Asserted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BeliefVerdict {
    Candidate,
    Supported,
    WeaklySupported,
    Contradicted,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BeliefInput {
    pub belief_id: BeliefId,
    pub statement: String,
    pub basis: BeliefBasis,
    pub verdict: BeliefVerdict,
    pub subject_urns: Vec<String>,
    pub supporting_evidence_urns: Vec<String>,
    pub counterevidence_urns: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub invalidation_conditions: Vec<String>,
    pub confidence_basis_points: u16,
    pub source_revision: Option<String>,
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Belief {
    pub belief_id: BeliefId,
    pub revision: u64,
    pub statement: String,
    pub basis: BeliefBasis,
    pub verdict: BeliefVerdict,
    pub subject_urns: Vec<String>,
    pub supporting_evidence_urns: Vec<String>,
    pub counterevidence_urns: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub invalidation_conditions: Vec<String>,
    pub confidence_basis_points: u16,
    pub source_revision: Option<String>,
    pub changed_by: ActorId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BeliefRevision {
    pub expected_revision: u64,
    pub verdict: BeliefVerdict,
    pub supporting_evidence_urns: Vec<String>,
    pub counterevidence_urns: Vec<String>,
    pub missing_evidence: Vec<String>,
    pub invalidation_conditions: Vec<String>,
    pub confidence_basis_points: u16,
    pub source_revision: Option<String>,
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BeliefError {
    InvalidStatement,
    InvalidReferences,
    InvalidConfidence,
    InvalidVerdict,
    RevisionConflict { expected: u64, actual: u64 },
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
