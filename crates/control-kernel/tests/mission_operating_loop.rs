use cerebro_control_kernel::{
    ActorId, BeliefBasis, BeliefId, BeliefInput, BeliefRevision, BeliefVerdict, CommitmentId,
    CommitmentInput, CommitmentState, CommitmentTransition, DecisionId, GrantId, MandateId,
    MissionAggregate, MissionEvent, MissionEventEnvelope, MissionId, MissionInput, MissionState,
    PlanId, PlanRevision, PlanStep, TenantId, VerificationId, VerificationReceipt, WakeConditionId,
    WakeConditionKind, WakeConditionState, WakeSignal,
};

fn envelope(sequence: u64, actor: &str, event: MissionEvent) -> MissionEventEnvelope {
    MissionEventEnvelope {
        schema_version: cerebro_control_kernel::SCHEMA_VERSION.into(),
        tenant_id: TenantId::parse("tenant-1").unwrap(),
        mission_id: MissionId::parse("mission-offboarding-1").unwrap(),
        sequence,
        observed_at_unix_ms: 1_000 + sequence,
        actor_id: ActorId::parse(actor).unwrap(),
        idempotency_key: format!("mission-offboarding-1:{sequence}"),
        event,
    }
}

fn transition(from: MissionState, to: MissionState, reason: &str) -> MissionEvent {
    MissionEvent::Transitioned {
        from,
        to,
        reason: reason.into(),
    }
}

#[test]
fn offboarding_mission_survives_approval_execution_verification_and_reopen() {
    let belief_id = BeliefId::parse("belief-access-remains").unwrap();
    let plan_id = PlanId::parse("plan-remove-access").unwrap();
    let commitment_id = CommitmentId::parse("commitment-remove-access").unwrap();
    let wake_condition_id = WakeConditionId::parse("wake-access-revision").unwrap();
    let events = vec![
        envelope(
            1,
            "kernel",
            MissionEvent::Opened {
                input: MissionInput {
                    tenant_id: TenantId::parse("tenant-1").unwrap(),
                    mission_id: MissionId::parse("mission-offboarding-1").unwrap(),
                    mandate_id: MandateId::parse("mandate-offboarding").unwrap(),
                    mandate_revision: 1,
                    objective: "Remove production access for a terminated identity".into(),
                    subject_urns: vec!["urn:identity:former-worker".into()],
                    actor_id: ActorId::parse("kernel").unwrap(),
                },
            },
        ),
        envelope(
            2,
            "resolver",
            transition(
                MissionState::Open,
                MissionState::ResolvingScope,
                "resolve the identity and effective access path",
            ),
        ),
        envelope(
            3,
            "resolver",
            MissionEvent::BeliefRecorded {
                input: BeliefInput {
                    belief_id: belief_id.clone(),
                    statement: "The terminated identity retains production access".into(),
                    basis: BeliefBasis::DeterministicallyDerived,
                    verdict: BeliefVerdict::Candidate,
                    subject_urns: vec!["urn:identity:former-worker".into()],
                    supporting_evidence_urns: vec!["urn:evidence:access:rev-1".into()],
                    counterevidence_urns: vec![],
                    missing_evidence: vec!["post-change access snapshot".into()],
                    invalidation_conditions: vec!["access source revision changes".into()],
                    confidence_basis_points: 8_000,
                    source_revision: Some("rev-1".into()),
                    actor_id: ActorId::parse("resolver").unwrap(),
                },
            },
        ),
        envelope(
            4,
            "planner",
            transition(
                MissionState::ResolvingScope,
                MissionState::Planning,
                "the subject and effective path are known",
            ),
        ),
        envelope(
            5,
            "planner",
            MissionEvent::PlanRevised {
                revision: PlanRevision {
                    plan_id: plan_id.clone(),
                    revision: 1,
                    previous_revision: None,
                    rationale:
                        "Remove the effective access path and verify a newer source revision".into(),
                    hypothesis_ids: vec![belief_id.clone()],
                    steps: vec![PlanStep {
                        step_id: "remove-access".into(),
                        capability: "identity.access.revoke".into(),
                        subject_urn: "urn:identity:former-worker".into(),
                        expected_effect: "No production access path remains".into(),
                        depends_on: vec![],
                        requires_decision: true,
                    }],
                    superseded_step_ids: vec![],
                    created_by: ActorId::parse("planner").unwrap(),
                },
            },
        ),
        envelope(
            6,
            "planner",
            MissionEvent::CommitmentProposed {
                input: CommitmentInput {
                    commitment_id: commitment_id.clone(),
                    plan_id: plan_id.clone(),
                    plan_revision: 1,
                    step_id: "remove-access".into(),
                    actor_id: ActorId::parse("executor").unwrap(),
                    capability: "identity.access.revoke".into(),
                    resource_urn: "urn:identity:former-worker".into(),
                    expected_effect: "No production access path remains".into(),
                    rollback_reference: Some("runbook:restore-access".into()),
                    requires_decision: true,
                },
            },
        ),
        envelope(
            7,
            "planner",
            transition(
                MissionState::Planning,
                MissionState::WaitingOnApproval,
                "the production mutation needs an exact decision",
            ),
        ),
        envelope(
            8,
            "operator",
            MissionEvent::CommitmentTransitioned {
                commitment_id: commitment_id.clone(),
                transition: CommitmentTransition {
                    expected_revision: 1,
                    to: CommitmentState::Ready,
                    grant_id: None,
                    decision_id: Some(DecisionId::parse("decision-remove-access").unwrap()),
                    receipt_urns: vec![],
                    reason: "operator approved the exact removal".into(),
                },
            },
        ),
        envelope(
            9,
            "kernel",
            transition(
                MissionState::WaitingOnApproval,
                MissionState::ReadyToAct,
                "the exact commitment is approved",
            ),
        ),
        envelope(
            10,
            "executor",
            MissionEvent::CommitmentTransitioned {
                commitment_id: commitment_id.clone(),
                transition: CommitmentTransition {
                    expected_revision: 2,
                    to: CommitmentState::Executing,
                    grant_id: Some(GrantId::parse("grant-remove-access").unwrap()),
                    decision_id: None,
                    receipt_urns: vec![],
                    reason: "execute through the approved identity adapter".into(),
                },
            },
        ),
        envelope(
            11,
            "executor",
            transition(
                MissionState::ReadyToAct,
                MissionState::Acting,
                "the approved commitment is executing",
            ),
        ),
        envelope(
            12,
            "executor",
            MissionEvent::CommitmentTransitioned {
                commitment_id: commitment_id.clone(),
                transition: CommitmentTransition {
                    expected_revision: 3,
                    to: CommitmentState::WaitingOnVerification,
                    grant_id: None,
                    decision_id: None,
                    receipt_urns: vec!["urn:receipt:execution:remove-access".into()],
                    reason: "the provider accepted the removal".into(),
                },
            },
        ),
        envelope(
            13,
            "kernel",
            MissionEvent::WakeConditionArmed {
                wake_condition_id: wake_condition_id.clone(),
                kind: WakeConditionKind::SourceRevisionChanged {
                    source_urn: "urn:source:identity-access".into(),
                    baseline_revision: "rev-1".into(),
                },
                reason: "wait for an authoritative post-change snapshot".into(),
            },
        ),
        envelope(
            14,
            "kernel",
            transition(
                MissionState::Acting,
                MissionState::Verifying,
                "provider success is not closure",
            ),
        ),
        envelope(
            15,
            "source-runtime",
            MissionEvent::WakeConditionSatisfied {
                wake_condition_id: wake_condition_id.clone(),
                signal: WakeSignal::SourceRevision {
                    source_urn: "urn:source:identity-access".into(),
                    revision: "rev-2".into(),
                },
            },
        ),
        envelope(
            16,
            "verifier",
            MissionEvent::BeliefRevised {
                belief_id: belief_id.clone(),
                revision: BeliefRevision {
                    expected_revision: 1,
                    verdict: BeliefVerdict::Contradicted,
                    supporting_evidence_urns: vec![],
                    counterevidence_urns: vec!["urn:evidence:access:rev-2".into()],
                    missing_evidence: vec![],
                    invalidation_conditions: vec!["access source revision changes".into()],
                    confidence_basis_points: 9_900,
                    source_revision: Some("rev-2".into()),
                    actor_id: ActorId::parse("verifier").unwrap(),
                },
            },
        ),
        envelope(
            17,
            "verifier",
            MissionEvent::CommitmentTransitioned {
                commitment_id: commitment_id.clone(),
                transition: CommitmentTransition {
                    expected_revision: 4,
                    to: CommitmentState::Fulfilled,
                    grant_id: None,
                    decision_id: None,
                    receipt_urns: vec!["urn:receipt:verification:access-rev-2".into()],
                    reason: "a newer authoritative snapshot shows no access path".into(),
                },
            },
        ),
        envelope(
            18,
            "verifier",
            MissionEvent::Verified {
                from: MissionState::Verifying,
                reason: "production access is independently absent".into(),
                receipt: VerificationReceipt {
                    verification_id: VerificationId::parse("verification-access-rev-2").unwrap(),
                    executor_actor_id: ActorId::parse("executor").unwrap(),
                    verifier_actor_id: ActorId::parse("verifier").unwrap(),
                    previous_source_revision: "rev-1".into(),
                    observed_source_revision: "rev-2".into(),
                    effective: true,
                    evidence_urns: vec!["urn:evidence:access:rev-2".into()],
                    verified_at_unix_ms: 1_018,
                },
            },
        ),
        envelope(
            19,
            "kernel",
            transition(
                MissionState::Verified,
                MissionState::Closed,
                "the desired condition is verified",
            ),
        ),
        envelope(
            20,
            "source-runtime",
            transition(
                MissionState::Closed,
                MissionState::ResolvingScope,
                "a later source event requires the condition to be checked again",
            ),
        ),
    ];

    let first = MissionAggregate::replay(&events).unwrap();
    let second = MissionAggregate::replay(&events).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.mission.state, MissionState::ResolvingScope);
    assert_eq!(
        first.beliefs[&belief_id].verdict,
        BeliefVerdict::Contradicted
    );
    assert_eq!(
        first.commitments[&commitment_id].state,
        CommitmentState::Fulfilled
    );
    assert_eq!(
        first.wake_conditions[&wake_condition_id].state,
        WakeConditionState::Satisfied
    );
}
