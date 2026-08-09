use std::{collections::BTreeSet, error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ActorId, BeliefId, PlanId};

const MAX_TEXT_BYTES: usize = 4_096;
const MAX_STEPS: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// One capability-bound effect or observation in a plan dependency graph.
pub struct PlanStep {
    /// Stable identifier unique within the plan revision.
    pub step_id: String,
    /// Exact capability an executor must possess for this step.
    pub capability: String,
    /// Canonical subject the step reads or changes.
    pub subject_urn: String,
    /// Observable result later receipts and verification should establish.
    pub expected_effect: String,
    /// Step identifiers in this same revision that must complete first.
    pub depends_on: Vec<String>,
    /// Whether execution requires a separate approval decision.
    pub requires_decision: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
/// Immutable, validated revision of an evidence-backed execution plan.
///
/// Steps form a directed acyclic graph. A new revision may replace the graph but
/// must point to the immediately previous revision and explicitly name removed
/// prior steps in `superseded_step_ids`.
pub struct PlanRevision {
    /// Stable identity shared by all revisions of the plan.
    pub plan_id: PlanId,
    /// Positive, contiguous revision number.
    pub revision: u64,
    /// Immediately preceding revision, absent only for revision one.
    pub previous_revision: Option<u64>,
    /// Bounded explanation connecting current beliefs to the proposed steps.
    pub rationale: String,
    /// Non-empty, unique beliefs or hypotheses motivating this revision.
    pub hypothesis_ids: Vec<BeliefId>,
    /// Non-empty bounded dependency graph for the current revision.
    pub steps: Vec<PlanStep>,
    /// Unique step identifiers removed from the immediately previous revision.
    pub superseded_step_ids: Vec<String>,
    /// Actor that produced this immutable revision.
    pub created_by: ActorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
/// Reason a plan revision failed structural validation.
pub enum PlanError {
    /// Revision numbering or previous-plan identity was not contiguous.
    InvalidRevision,
    /// Rationale violated the bounded text contract.
    InvalidRationale,
    /// Hypothesis set was empty or contained duplicates.
    InvalidHypotheses,
    /// Step collection or supersession record was malformed.
    InvalidSteps,
    /// Two current steps used the same identifier.
    DuplicateStep,
    /// Dependency referenced itself, a missing step, or participated in a cycle.
    InvalidDependency,
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRevision => formatter.write_str("plan revision is invalid"),
            Self::InvalidRationale => formatter.write_str("plan rationale is invalid"),
            Self::InvalidHypotheses => formatter.write_str("plan hypotheses are invalid"),
            Self::InvalidSteps => formatter.write_str("plan steps are invalid"),
            Self::DuplicateStep => formatter.write_str("plan step id is duplicated"),
            Self::InvalidDependency => formatter.write_str("plan dependency is invalid"),
        }
    }
}

impl Error for PlanError {}

impl PlanRevision {
    /// Validates revision lineage, evidence references, and the complete step graph.
    ///
    /// Revision one must not name a predecessor. Later revisions must follow the
    /// supplied plan exactly, including plan identity and contiguous numbering.
    /// Every dependency must name a current step, and iterative graph completion
    /// rejects cycles. Superseded identifiers must exist in the supplied previous
    /// revision. Validation does not authorize or execute any step.
    pub fn validate(&self, previous: Option<&Self>) -> Result<(), PlanError> {
        if self.revision == 0
            || (self.revision == 1 && self.previous_revision.is_some())
            || (self.revision > 1 && self.previous_revision != Some(self.revision - 1))
        {
            return Err(PlanError::InvalidRevision);
        }
        if let Some(previous) = previous
            && (previous.plan_id != self.plan_id || self.revision != previous.revision + 1)
        {
            return Err(PlanError::InvalidRevision);
        }
        validate_text(&self.rationale).map_err(|_| PlanError::InvalidRationale)?;
        if self.hypothesis_ids.is_empty() {
            return Err(PlanError::InvalidHypotheses);
        }
        let hypothesis_ids = self.hypothesis_ids.iter().collect::<BTreeSet<_>>();
        if hypothesis_ids.len() != self.hypothesis_ids.len() {
            return Err(PlanError::InvalidHypotheses);
        }
        if self.steps.is_empty() || self.steps.len() > MAX_STEPS {
            return Err(PlanError::InvalidSteps);
        }
        let mut step_ids = BTreeSet::new();
        for step in &self.steps {
            validate_text(&step.step_id).map_err(|_| PlanError::InvalidSteps)?;
            validate_text(&step.capability).map_err(|_| PlanError::InvalidSteps)?;
            validate_text(&step.subject_urn).map_err(|_| PlanError::InvalidSteps)?;
            validate_text(&step.expected_effect).map_err(|_| PlanError::InvalidSteps)?;
            if !step_ids.insert(step.step_id.as_str()) {
                return Err(PlanError::DuplicateStep);
            }
        }
        for step in &self.steps {
            for dependency in &step.depends_on {
                if dependency == &step.step_id || !step_ids.contains(dependency.as_str()) {
                    return Err(PlanError::InvalidDependency);
                }
            }
        }
        let mut completed = BTreeSet::new();
        loop {
            let before = completed.len();
            for step in &self.steps {
                if step
                    .depends_on
                    .iter()
                    .all(|dependency| completed.contains(dependency.as_str()))
                {
                    completed.insert(step.step_id.as_str());
                }
            }
            if completed.len() == self.steps.len() {
                break;
            }
            if completed.len() == before {
                return Err(PlanError::InvalidDependency);
            }
        }
        let mut superseded_ids = BTreeSet::new();
        for superseded in &self.superseded_step_ids {
            validate_text(superseded).map_err(|_| PlanError::InvalidSteps)?;
            if !superseded_ids.insert(superseded.as_str()) {
                return Err(PlanError::InvalidSteps);
            }
            let Some(previous) = previous else {
                return Err(PlanError::InvalidSteps);
            };
            if !previous
                .steps
                .iter()
                .any(|step| step.step_id == *superseded)
            {
                return Err(PlanError::InvalidSteps);
            }
        }
        Ok(())
    }
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

    fn plan(revision: u64) -> PlanRevision {
        PlanRevision {
            plan_id: PlanId::parse("plan-1").unwrap(),
            revision,
            previous_revision: (revision > 1).then_some(revision - 1),
            rationale: "Remove direct access, then verify a newer source revision".into(),
            hypothesis_ids: vec![BeliefId::parse("belief-1").unwrap()],
            steps: vec![
                PlanStep {
                    step_id: "remove-access".into(),
                    capability: "identity.access.revoke".into(),
                    subject_urn: "urn:identity:1".into(),
                    expected_effect: "Production access is removed".into(),
                    depends_on: vec![],
                    requires_decision: true,
                },
                PlanStep {
                    step_id: "verify-access".into(),
                    capability: "identity.access.observe".into(),
                    subject_urn: "urn:identity:1".into(),
                    expected_effect: "A newer source revision shows no access path".into(),
                    depends_on: vec!["remove-access".into()],
                    requires_decision: false,
                },
            ],
            superseded_step_ids: vec![],
            created_by: ActorId::parse("planner").unwrap(),
        }
    }

    #[test]
    fn revisions_are_ordered_and_dependencies_reference_current_steps() {
        let first = plan(1);
        first.validate(None).unwrap();
        plan(2).validate(Some(&first)).unwrap();

        let mut invalid = plan(1);
        invalid.steps[1].depends_on = vec!["missing".into()];
        assert_eq!(invalid.validate(None), Err(PlanError::InvalidDependency));

        let mut cycle = plan(1);
        cycle.steps[0].depends_on = vec!["verify-access".into()];
        assert_eq!(cycle.validate(None), Err(PlanError::InvalidDependency));
    }
}
