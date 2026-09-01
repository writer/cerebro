//! Deterministic evaluation of immutable context bindings.
//!
//! The engine consumes the existing temporal graph diff contract. It does not
//! load revisions, persist bindings, or construct another graph snapshot.

use std::collections::{BTreeMap, BTreeSet};

use cerebro_platform_sdk::{
    ContentDigest, ContextAuthorityState, ContextBinding, ContextBindingEvaluation,
    ContextBindingState, ContextDependencyTarget, ContextObservation, GraphChange, GraphDiff,
    SdkError, WakeCondition, WakeConditionId, WakeConditionKind, WakeSignal,
};

use crate::canonical;

const REASON_DIFF_TRUNCATED: &str = "context_diff_truncated";
const REASON_DEPENDENCY_MISMATCH: &str = "context_dependency_digest_mismatch";
const CONTEXT_INVALIDATED_EVENT_TYPE: &str = "cerebro.context-binding.invalidated";

/// Arms the existing mission wake contract for one exact context binding.
///
/// The binding digest becomes the event subject, so another task's context
/// invalidation cannot satisfy this condition. The control kernel remains the
/// lifecycle authority; this function only adapts a validated binding into its
/// closed event predicate.
///
/// # Errors
///
/// Returns a binding validation error or [`SdkError::Invalid`] when the wake
/// identity, timestamp, or reason violates the control-kernel contract.
pub fn arm_context_invalidation_wake(
    binding: &ContextBinding,
    wake_condition_id: WakeConditionId,
    armed_at_unix_ms: u64,
    reason: String,
) -> Result<WakeCondition, SdkError> {
    binding.validate()?;
    WakeCondition::arm(
        wake_condition_id,
        WakeConditionKind::EventObserved {
            event_type: CONTEXT_INVALIDATED_EVENT_TYPE.to_owned(),
            subject_urn: context_binding_subject(&binding.binding_digest),
        },
        armed_at_unix_ms,
        reason,
    )
    .map_err(|_| SdkError::Invalid("context invalidation wake condition"))
}

/// Converts a verified invalidation outcome into a mission wake signal.
///
/// Unchanged, unrelated changed, and unknown outcomes deliberately return
/// `None`: none proves that the exact bound dependency set was invalidated.
///
/// # Errors
///
/// Returns the evaluation validation error when its digest or evidence shape
/// is not self-consistent.
pub fn context_invalidation_wake_signal(
    evaluation: &ContextBindingEvaluation,
) -> Result<Option<WakeSignal>, SdkError> {
    evaluation.validate()?;
    Ok(
        (evaluation.state == ContextBindingState::Invalidated).then(|| WakeSignal::Event {
            event_type: CONTEXT_INVALIDATED_EVENT_TYPE.to_owned(),
            subject_urn: context_binding_subject(&evaluation.binding_digest),
        }),
    )
}

fn context_binding_subject(binding_digest: &ContentDigest) -> String {
    format!("urn:cerebro:context-binding:{binding_digest}")
}

/// Evaluates one immutable context binding against a later graph observation.
///
/// Complete authoritative diffs yield `unchanged`, `changed`, or `invalidated`.
/// Non-authoritative or paginated observations yield `unknown`. Cross-tenant,
/// wrong-base-revision, malformed, reordered, duplicate, or digest-tampered
/// diffs are invalid inputs rather than uncertain observations.
///
/// A dependency update or retraction invalidates the binding only when its
/// before digest equals the exact digest recorded in the binding. A mismatch
/// yields `unknown`, because the supplied diff cannot prove it began from the
/// bound dependency state.
///
/// # Errors
///
/// Returns the binding or observation validation error, [`SdkError::Invalid`]
/// for an inconsistent or tampered diff, or [`SdkError::Backend`] if canonical
/// digest serialization fails.
pub fn evaluate_context_binding(
    binding: &ContextBinding,
    observation: &ContextObservation,
) -> Result<ContextBindingEvaluation, SdkError> {
    binding.validate()?;
    observation.validate()?;

    let mut observed_revision = None;
    let mut delta_digest = None;
    let mut dependency_changes = Vec::new();
    let mut reason_codes = observation.reason_codes.clone();

    if let Some(diff) = &observation.diff {
        validate_diff_binding(binding, diff)?;
        observed_revision = Some(diff.to_revision);
        delta_digest = Some(diff.digest.clone());
    }

    let state = match observation.authority {
        ContextAuthorityState::Incomplete | ContextAuthorityState::Unavailable => {
            ContextBindingState::Unknown
        }
        ContextAuthorityState::Authoritative => {
            let diff = observation
                .diff
                .as_ref()
                .expect("validated authoritative observation has a diff");
            if diff.truncated {
                reason_codes.push(REASON_DIFF_TRUNCATED.to_owned());
                ContextBindingState::Unknown
            } else {
                validate_complete_diff_digest(diff)?;
                let dependencies = binding
                    .dependencies
                    .iter()
                    .map(|dependency| (&dependency.target, &dependency.content_digest))
                    .collect::<BTreeMap<_, _>>();
                let mut dependency_mismatch = false;
                for change in &diff.changes {
                    let target = change_target(change)
                        .expect("validated diff change has exactly one target");
                    if let Some(expected_digest) = dependencies.get(&target) {
                        dependency_changes.push(change.clone());
                        if change.before_digest.as_ref() != Some(*expected_digest) {
                            dependency_mismatch = true;
                        }
                    }
                }
                if dependency_mismatch {
                    reason_codes.push(REASON_DEPENDENCY_MISMATCH.to_owned());
                    ContextBindingState::Unknown
                } else if !dependency_changes.is_empty() {
                    ContextBindingState::Invalidated
                } else if diff.changes.is_empty() {
                    ContextBindingState::Unchanged
                } else {
                    ContextBindingState::Changed
                }
            }
        }
    };

    reason_codes.sort();
    reason_codes.dedup();
    let mut evaluation = ContextBindingEvaluation {
        tenant_id: binding.tenant_id.clone(),
        binding_digest: binding.binding_digest.clone(),
        bound_revision: binding.graph_revision,
        observed_revision,
        state,
        delta_digest,
        dependency_changes,
        reason_codes,
        evaluation_digest: ContentDigest::of_bytes([]),
    };
    evaluation.bind_computed_digest()?;
    evaluation.validate()?;
    Ok(evaluation)
}

fn validate_diff_binding(binding: &ContextBinding, diff: &GraphDiff) -> Result<(), SdkError> {
    if diff.tenant_id != binding.tenant_id {
        return Err(SdkError::Invalid("context diff tenant"));
    }
    if diff.from_revision != binding.graph_revision {
        return Err(SdkError::Invalid("context diff starting revision"));
    }
    if diff.to_revision <= diff.from_revision {
        return Err(SdkError::Invalid("context diff revision window"));
    }
    if diff.truncated != diff.next_cursor.is_some() {
        return Err(SdkError::Invalid("context diff pagination"));
    }

    let mut targets = BTreeSet::new();
    let mut previous = None;
    for change in &diff.changes {
        change.validate()?;
        let target = change_target(change).ok_or(SdkError::Invalid("context diff target"))?;
        if !targets.insert(target.clone()) {
            return Err(SdkError::Conflict(
                "duplicate context diff target".to_owned(),
            ));
        }
        if previous.as_ref().is_some_and(|prior| prior > &target) {
            return Err(SdkError::Invalid("context diff order"));
        }
        previous = Some(target);
    }
    Ok(())
}

fn validate_complete_diff_digest(diff: &GraphDiff) -> Result<(), SdkError> {
    let expected = canonical::digest(&(
        &diff.tenant_id,
        diff.from_revision,
        diff.to_revision,
        &diff.changes,
    ))?;
    if expected != diff.digest {
        return Err(SdkError::Invalid("context diff digest"));
    }
    Ok(())
}

fn change_target(change: &GraphChange) -> Option<ContextDependencyTarget> {
    match (&change.entity_id, &change.assertion_id) {
        (Some(entity_id), None) => Some(ContextDependencyTarget::Entity(entity_id.clone())),
        (None, Some(assertion_id)) => {
            Some(ContextDependencyTarget::Assertion(assertion_id.clone()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use cerebro_platform_sdk::{
        ContextDependency, GraphDiffRequest, GraphRevision, RevisionSelector, TenantId,
        WakeConditionState,
    };

    use super::*;
    use crate::{RevisionSnapshot, SnapshotKey, SnapshotValue, diff_snapshots};

    fn tenant() -> TenantId {
        TenantId::parse("tenant-1").unwrap()
    }

    fn entity(id: &str) -> cerebro_platform_sdk::EntityId {
        cerebro_platform_sdk::EntityId::parse(id).unwrap()
    }

    fn digest(value: &str) -> ContentDigest {
        ContentDigest::of_bytes(value)
    }

    fn binding(expected: ContentDigest) -> ContextBinding {
        ContextBinding::bind(
            tenant(),
            GraphRevision::new(1).unwrap(),
            digest("rendered-context"),
            vec![ContextDependency {
                target: ContextDependencyTarget::Entity(entity("entity-1")),
                content_digest: expected,
            }],
        )
        .unwrap()
    }

    fn snapshot(revision: u64, values: &[(&str, &str)]) -> RevisionSnapshot {
        RevisionSnapshot {
            tenant_id: tenant(),
            revision: GraphRevision::new(revision).unwrap(),
            values: values
                .iter()
                .map(|(id, value)| {
                    (
                        SnapshotKey::Entity(entity(id)),
                        SnapshotValue {
                            digest: digest(value),
                            observed_at_unix_millis: i64::try_from(revision).unwrap(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn observation(
        before: &RevisionSnapshot,
        after: &RevisionSnapshot,
        limit: u32,
    ) -> ContextObservation {
        let diff = diff_snapshots(
            &GraphDiffRequest {
                tenant_id: tenant(),
                from_revision: before.revision,
                to_revision: RevisionSelector::Exact(after.revision),
                limit,
                cursor: None,
            },
            before,
            after,
        )
        .unwrap();
        ContextObservation {
            authority: ContextAuthorityState::Authoritative,
            diff: Some(diff),
            reason_codes: Vec::new(),
        }
    }

    #[test]
    fn relevant_authoritative_change_invalidates_the_exact_binding() {
        let before = snapshot(1, &[("entity-1", "before")]);
        let after = snapshot(2, &[("entity-1", "after")]);
        let result = evaluate_context_binding(
            &binding(digest("before")),
            &observation(&before, &after, 500),
        )
        .unwrap();

        assert_eq!(result.state, ContextBindingState::Invalidated);
        assert_eq!(result.dependency_changes.len(), 1);
        assert!(result.reason_codes.is_empty());
    }

    #[test]
    fn unrelated_authoritative_change_is_explicitly_changed() {
        let before = snapshot(1, &[("entity-1", "bound"), ("entity-2", "before")]);
        let after = snapshot(2, &[("entity-1", "bound"), ("entity-2", "after")]);
        let result = evaluate_context_binding(
            &binding(digest("bound")),
            &observation(&before, &after, 500),
        )
        .unwrap();

        assert_eq!(result.state, ContextBindingState::Changed);
        assert!(result.dependency_changes.is_empty());
    }

    #[test]
    fn complete_empty_diff_is_unchanged() {
        let before = snapshot(1, &[("entity-1", "bound")]);
        let after = snapshot(2, &[("entity-1", "bound")]);
        let result = evaluate_context_binding(
            &binding(digest("bound")),
            &observation(&before, &after, 500),
        )
        .unwrap();

        assert_eq!(result.state, ContextBindingState::Unchanged);
    }

    #[test]
    fn truncated_or_unavailable_authority_is_unknown() {
        let before = snapshot(1, &[("entity-1", "bound"), ("entity-2", "before")]);
        let after = snapshot(2, &[("entity-1", "after"), ("entity-2", "after")]);
        let truncated =
            evaluate_context_binding(&binding(digest("bound")), &observation(&before, &after, 1))
                .unwrap();
        assert_eq!(truncated.state, ContextBindingState::Unknown);
        assert_eq!(truncated.reason_codes, vec![REASON_DIFF_TRUNCATED]);

        let unavailable = evaluate_context_binding(
            &binding(digest("bound")),
            &ContextObservation {
                authority: ContextAuthorityState::Unavailable,
                diff: None,
                reason_codes: vec!["graph_authority_unavailable".to_owned()],
            },
        )
        .unwrap();
        assert_eq!(unavailable.state, ContextBindingState::Unknown);
        assert_eq!(
            unavailable.reason_codes,
            vec!["graph_authority_unavailable"]
        );
    }

    #[test]
    fn dependency_digest_mismatch_is_unknown_and_evaluation_is_deterministic() {
        let before = snapshot(1, &[("entity-1", "actual-before")]);
        let after = snapshot(2, &[("entity-1", "after")]);
        let observation = observation(&before, &after, 500);
        let first = evaluate_context_binding(&binding(digest("different")), &observation).unwrap();
        let second = evaluate_context_binding(&binding(digest("different")), &observation).unwrap();

        assert_eq!(first.state, ContextBindingState::Unknown);
        assert_eq!(first.reason_codes, vec![REASON_DEPENDENCY_MISMATCH]);
        assert_eq!(first.evaluation_digest, second.evaluation_digest);
    }

    #[test]
    fn tenant_revision_and_complete_diff_digest_are_fail_closed() {
        let before = snapshot(1, &[("entity-1", "before")]);
        let after = snapshot(2, &[("entity-1", "after")]);
        let binding = binding(digest("before"));
        let observation = observation(&before, &after, 500);

        let mut cross_tenant = observation.clone();
        cross_tenant.diff.as_mut().unwrap().tenant_id = TenantId::parse("tenant-2").unwrap();
        assert_eq!(
            evaluate_context_binding(&binding, &cross_tenant),
            Err(SdkError::Invalid("context diff tenant"))
        );

        let mut wrong_revision = observation.clone();
        wrong_revision.diff.as_mut().unwrap().from_revision = GraphRevision::new(9).unwrap();
        assert_eq!(
            evaluate_context_binding(&binding, &wrong_revision),
            Err(SdkError::Invalid("context diff starting revision"))
        );

        let mut tampered = observation;
        tampered.diff.as_mut().unwrap().digest = digest("forged");
        assert_eq!(
            evaluate_context_binding(&binding, &tampered),
            Err(SdkError::Invalid("context diff digest"))
        );
    }

    #[test]
    fn exact_dependency_invalidation_satisfies_the_bound_mission_wake() {
        let binding = binding(digest("before"));
        let condition = arm_context_invalidation_wake(
            &binding,
            WakeConditionId::parse("wake-context-1").unwrap(),
            10,
            "replan when the bound context becomes invalid".to_owned(),
        )
        .unwrap();
        let evaluation = evaluate_context_binding(
            &binding,
            &observation(
                &snapshot(1, &[("entity-1", "before")]),
                &snapshot(2, &[("entity-1", "after")]),
                500,
            ),
        )
        .unwrap();
        let signal = context_invalidation_wake_signal(&evaluation)
            .unwrap()
            .expect("invalidation emits a wake signal");

        assert_eq!(
            condition.satisfy(&signal, 11).unwrap().state,
            WakeConditionState::Satisfied
        );
    }

    #[test]
    fn unrelated_changed_and_unknown_outcomes_do_not_wake_a_mission() {
        let binding = binding(digest("bound"));
        let changed = evaluate_context_binding(
            &binding,
            &observation(
                &snapshot(1, &[("entity-1", "bound"), ("entity-2", "before")]),
                &snapshot(2, &[("entity-1", "bound"), ("entity-2", "after")]),
                500,
            ),
        )
        .unwrap();
        let unknown = evaluate_context_binding(
            &binding,
            &ContextObservation {
                authority: ContextAuthorityState::Unavailable,
                diff: None,
                reason_codes: vec!["graph_authority_unavailable".to_owned()],
            },
        )
        .unwrap();

        assert_eq!(context_invalidation_wake_signal(&changed).unwrap(), None);
        assert_eq!(context_invalidation_wake_signal(&unknown).unwrap(), None);

        let mut tampered = changed;
        tampered.state = ContextBindingState::Invalidated;
        assert!(context_invalidation_wake_signal(&tampered).is_err());
    }
}
