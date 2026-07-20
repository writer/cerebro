use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::{ActorId, MandateId, TenantId};

const MAX_CONDITION_BYTES: usize = 4_096;
const MAX_SCOPE_URNS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateStatus {
    Active,
    Suspended,
    Retired,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MandateInput {
    pub tenant_id: TenantId,
    pub mandate_id: MandateId,
    pub desired_condition: String,
    pub scope_urns: Vec<String>,
    pub maximum_violation_age_seconds: u64,
    pub actor_id: ActorId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Mandate {
    pub tenant_id: TenantId,
    pub mandate_id: MandateId,
    pub revision: u64,
    pub status: MandateStatus,
    pub desired_condition: String,
    pub scope_urns: Vec<String>,
    pub maximum_violation_age_seconds: u64,
    pub changed_by: ActorId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MandateError {
    InvalidCondition,
    InvalidScope,
    InvalidMaximumViolationAge,
    RevisionConflict {
        expected: u64,
        actual: u64,
    },
    InvalidTransition {
        from: MandateStatus,
        to: MandateStatus,
    },
}

impl fmt::Display for MandateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCondition => formatter.write_str("mandate desired condition is invalid"),
            Self::InvalidScope => formatter.write_str("mandate scope is invalid"),
            Self::InvalidMaximumViolationAge => {
                formatter.write_str("mandate maximum violation age must be positive")
            }
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "mandate revision conflict: expected {expected}, actual {actual}"
            ),
            Self::InvalidTransition { from, to } => {
                write!(formatter, "invalid mandate transition: {from:?} -> {to:?}")
            }
        }
    }
}

impl Error for MandateError {}

impl Mandate {
    pub fn create(input: MandateInput) -> Result<Self, MandateError> {
        validate_condition(&input.desired_condition)?;
        let scope_urns = normalize_scope(input.scope_urns)?;
        if input.maximum_violation_age_seconds == 0 {
            return Err(MandateError::InvalidMaximumViolationAge);
        }
        Ok(Self {
            tenant_id: input.tenant_id,
            mandate_id: input.mandate_id,
            revision: 1,
            status: MandateStatus::Active,
            desired_condition: input.desired_condition,
            scope_urns,
            maximum_violation_age_seconds: input.maximum_violation_age_seconds,
            changed_by: input.actor_id,
        })
    }

    pub fn revise(
        &self,
        expected_revision: u64,
        desired_condition: String,
        scope_urns: Vec<String>,
        maximum_violation_age_seconds: u64,
        actor_id: ActorId,
    ) -> Result<Self, MandateError> {
        self.require_revision(expected_revision)?;
        if self.status == MandateStatus::Retired {
            return Err(MandateError::InvalidTransition {
                from: self.status,
                to: self.status,
            });
        }
        validate_condition(&desired_condition)?;
        let scope_urns = normalize_scope(scope_urns)?;
        if maximum_violation_age_seconds == 0 {
            return Err(MandateError::InvalidMaximumViolationAge);
        }
        Ok(Self {
            tenant_id: self.tenant_id.clone(),
            mandate_id: self.mandate_id.clone(),
            revision: self.revision + 1,
            status: self.status,
            desired_condition,
            scope_urns,
            maximum_violation_age_seconds,
            changed_by: actor_id,
        })
    }

    pub fn transition(
        &self,
        expected_revision: u64,
        status: MandateStatus,
        actor_id: ActorId,
    ) -> Result<Self, MandateError> {
        self.require_revision(expected_revision)?;
        let allowed = matches!(
            (self.status, status),
            (MandateStatus::Active, MandateStatus::Suspended)
                | (MandateStatus::Suspended, MandateStatus::Active)
                | (MandateStatus::Active, MandateStatus::Retired)
                | (MandateStatus::Suspended, MandateStatus::Retired)
        );
        if !allowed {
            return Err(MandateError::InvalidTransition {
                from: self.status,
                to: status,
            });
        }
        let mut next = self.clone();
        next.revision += 1;
        next.status = status;
        next.changed_by = actor_id;
        Ok(next)
    }

    fn require_revision(&self, expected_revision: u64) -> Result<(), MandateError> {
        if expected_revision != self.revision {
            return Err(MandateError::RevisionConflict {
                expected: expected_revision,
                actual: self.revision,
            });
        }
        Ok(())
    }
}

fn validate_condition(condition: &str) -> Result<(), MandateError> {
    if condition.trim().is_empty()
        || condition.trim() != condition
        || condition.len() > MAX_CONDITION_BYTES
        || condition.chars().any(char::is_control)
    {
        return Err(MandateError::InvalidCondition);
    }
    Ok(())
}

fn normalize_scope(mut scope_urns: Vec<String>) -> Result<Vec<String>, MandateError> {
    if scope_urns.is_empty() || scope_urns.len() > MAX_SCOPE_URNS {
        return Err(MandateError::InvalidScope);
    }
    for urn in &scope_urns {
        if urn.trim().is_empty()
            || urn.trim() != urn
            || urn.len() > 1_024
            || urn.chars().any(char::is_control)
        {
            return Err(MandateError::InvalidScope);
        }
    }
    scope_urns.sort();
    scope_urns.dedup();
    Ok(scope_urns)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mandate() -> Mandate {
        Mandate::create(MandateInput {
            tenant_id: TenantId::parse("tenant-1").unwrap(),
            mandate_id: MandateId::parse("mandate-1").unwrap(),
            desired_condition: "Terminated identities have no production access".into(),
            scope_urns: vec!["urn:scope:prod".into(), "urn:scope:prod".into()],
            maximum_violation_age_seconds: 86_400,
            actor_id: ActorId::parse("operator-1").unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn mandate_revisions_are_optimistic_and_immutable() {
        let original = mandate();
        let revised = original
            .revise(
                1,
                "Terminated identities have no effective production access".into(),
                vec!["urn:scope:prod".into()],
                43_200,
                ActorId::parse("operator-2").unwrap(),
            )
            .unwrap();

        assert_eq!(original.revision, 1);
        assert_eq!(revised.revision, 2);
        assert!(matches!(
            revised.revise(
                1,
                revised.desired_condition.clone(),
                revised.scope_urns.clone(),
                revised.maximum_violation_age_seconds,
                ActorId::parse("operator-3").unwrap(),
            ),
            Err(MandateError::RevisionConflict { .. })
        ));
    }

    #[test]
    fn retired_mandates_cannot_reactivate_or_change() {
        let actor = ActorId::parse("operator-2").unwrap();
        let retired = mandate()
            .transition(1, MandateStatus::Retired, actor.clone())
            .unwrap();

        assert!(matches!(
            retired.transition(2, MandateStatus::Active, actor.clone()),
            Err(MandateError::InvalidTransition { .. })
        ));
        assert!(matches!(
            retired.revise(
                2,
                retired.desired_condition.clone(),
                retired.scope_urns.clone(),
                retired.maximum_violation_age_seconds,
                actor,
            ),
            Err(MandateError::InvalidTransition { .. })
        ));
    }
}
