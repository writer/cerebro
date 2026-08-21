use std::collections::BTreeMap;

use serde_json::Value;

use super::*;

use super::*;

fn digest(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn evidence() -> WireEvidenceState {
    WireEvidenceState {
        completeness: EvidenceCompleteness::Complete,
        freshness: EvidenceFreshness::Fresh,
    }
}

fn envelope(family: WireContractFamily, payload: Value) -> ExternalEventEnvelope {
    ExternalEventEnvelope {
        schema_version: EXTERNAL_EVENT_SCHEMA_V1.to_owned(),
        contract_family: family,
        payload_schema_ref: family.schema_ref().to_owned(),
        event_id: "event-1".to_owned(),
        tenant_id: "tenant-1".to_owned(),
        producer_id: "producer-1".to_owned(),
        producer_instance_id: "instance-1".to_owned(),
        subject_id: "subject-1".to_owned(),
        sequence: 1,
        occurred_at_unix_ms: 1_000,
        observed_at_unix_ms: 1_001,
        evidence: evidence(),
        payload,
        attributes: BTreeMap::new(),
        previous_event_digest: None,
        signature: None,
    }
}

fn sample_payloads() -> Vec<(WireContractFamily, Value)> {
    vec![
        (
            WireContractFamily::AgentActivity,
            serde_json::to_value(AgentActivity {
                session_id: "session-1".into(),
                agent_id: "agent-1".into(),
                device_id: Some("device-1".into()),
                action: "repository.read".into(),
                resource_ref: "repository:example".into(),
                policy_revision: "policy-1".into(),
                input_digest: digest('a'),
                outcome_digest: Some(digest('b')),
            })
            .unwrap(),
        ),
        (
            WireContractFamily::EndpointTelemetry,
            serde_json::to_value(EndpointTelemetry {
                endpoint_id: "endpoint-1".into(),
                agent_id: "agent-1".into(),
                observation_kind: "posture".into(),
                collector: "collector-1".into(),
                privacy_class: "operational_metadata".into(),
                truncated: false,
                content_digest: digest('c'),
                evidence_refs: vec!["evidence:1".into()],
            })
            .unwrap(),
        ),
        (
            WireContractFamily::EndpointSessionLease,
            serde_json::to_value(EndpointSessionLease {
                lease_id: "lease-1".into(),
                agent_id: "agent-1".into(),
                user_subject: "user:1".into(),
                session_id: "session-1".into(),
                operation: "repository.read".into(),
                repository_ref: "repository:example".into(),
                repository_revision: Some("abc123".into()),
                endpoint_ownership: EndpointOwnership::OrganizationOwned,
                network_profile: EndpointNetworkProfile::ProviderOnly,
                capabilities: vec!["repository.read".into()],
                policy_id: "policy-1".into(),
                policy_revision: "revision-1".into(),
                issued_at_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
                revocation_epoch: 3,
                audience: vec!["repository-broker".into()],
                posture_source_refs: vec!["source:endpoint".into()],
            })
            .unwrap(),
        ),
        (
            WireContractFamily::ThreatIntelligence,
            serde_json::to_value(ThreatIntelligenceObservation {
                indicator_id: "indicator-1".into(),
                indicator_kind: ThreatIndicatorKind::Domain,
                normalized_value: "malicious.example".into(),
                verdict: ThreatVerdict::Malicious,
                score_basis_points: 8_000,
                confidence_basis_points: 9_000,
                source_count: 2,
                internal_observation_count: 0,
                first_seen_unix_ms: 1_000,
                last_seen_unix_ms: 2_000,
                valid_until_unix_ms: 3_000,
                source_event_refs: vec!["event:1".into(), "event:2".into()],
                evidence_refs: vec!["evidence:1".into()],
                promotion_reason: ThreatPromotionReason::MultiSourceCorroboration,
            })
            .unwrap(),
        ),
        (
            WireContractFamily::RemediationOutcome,
            serde_json::to_value(RemediationOutcome {
                operation_id: "operation-1".into(),
                finding_id: "finding-1".into(),
                action_kind: "package.update".into(),
                target_id: "endpoint-1".into(),
                state: ActionState::Verified,
                idempotency_key: ["idempotency", "1"].join("-"),
                proposal_digest: digest('d'),
                provider_receipt_digest: Some(digest('e')),
                verification_receipt_digest: Some(digest('f')),
            })
            .unwrap(),
        ),
        (
            WireContractFamily::MetricSnapshot,
            serde_json::to_value(MetricSnapshot {
                metric_id: "metric-1".into(),
                definition_version: 1,
                observed_at_unix_ms: 2_000,
                value_microunits: 500_000,
                unit: "ratio".into(),
                truncated: false,
                evidence_refs: vec!["evidence:1".into()],
                snapshot_digest: digest('1'),
            })
            .unwrap(),
        ),
        (
            WireContractFamily::ScannerFinding,
            serde_json::to_value(ScannerFinding {
                finding_id: "finding-1".into(),
                scanner_id: "scanner-1".into(),
                rule_id: "rule-1".into(),
                rule_version: "1".into(),
                severity: ScannerSeverity::High,
                validation_state: ScannerValidationState::Validated,
                subject_ref: "repository:example".into(),
                source_revision: "abc123".into(),
                location_ref: Some("src/lib.rs:10".into()),
                evidence_digest: digest('2'),
                evidence_ref: Some("evidence:1".into()),
                fixed_version: None,
            })
            .unwrap(),
        ),
        (
            WireContractFamily::ConnectorManifest,
            serde_json::to_value(ConnectorManifest {
                connector_id: "connector-1".into(),
                manifest_version: 1,
                auth_kind: "oauth2".into(),
                object_kinds: vec!["user".into()],
                capabilities: vec!["users.read".into()],
                input_digest: digest('3'),
                compiled_digest: digest('4'),
                compiled_at_unix_ms: 2_000,
            })
            .unwrap(),
        ),
        (
            WireContractFamily::AgentCapability,
            serde_json::to_value(AgentCapability {
                agent_id: "agent-1".into(),
                capability_id: "capability-1".into(),
                tool_ids: vec!["graph.read".into()],
                maximum_action_stage: AgentActionStage::Recommend,
                evidence_source_refs: vec!["source:graph".into()],
                definition_digest: digest('5'),
            })
            .unwrap(),
        ),
    ]
}

#[test]
fn all_contract_families_round_trip_and_validate() {
    for (family, payload) in sample_payloads() {
        let original = envelope(family, payload);
        original.validate().unwrap();
        let encoded = serde_json::to_vec(&original).unwrap();
        let decoded: ExternalEventEnvelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, original);
        decoded.validate().unwrap();
    }
}

#[test]
fn remediation_fixture_preserves_its_serialized_idempotency_key() {
    let (_, payload) = sample_payloads()
        .into_iter()
        .find(|(family, _)| *family == WireContractFamily::RemediationOutcome)
        .unwrap();
    assert_eq!(
        payload["idempotency_key"],
        Value::String(["idempotency", "1"].join("-"))
    );
}

#[test]
fn family_schema_and_payload_must_match() {
    let (_, payload) = sample_payloads().remove(0);
    let mut event = envelope(WireContractFamily::AgentActivity, payload);
    event.payload_schema_ref = THREAT_INTELLIGENCE_SCHEMA_V1.into();
    assert!(event.validate().is_err());

    event.payload_schema_ref = AGENT_ACTIVITY_SCHEMA_V1.into();
    event.contract_family = WireContractFamily::MetricSnapshot;
    assert!(event.validate().is_err());
}

#[test]
fn omitted_evidence_fails_closed() {
    let state = WireEvidenceState::default();
    assert!(!state.supports_authoritative_decision());
    assert_eq!(state.completeness, EvidenceCompleteness::Partial);
    assert_eq!(state.freshness, EvidenceFreshness::Unknown);
}

#[test]
fn signing_material_is_stable_and_excludes_signature_value() {
    let (family, payload) = sample_payloads().remove(0);
    let mut event = envelope(family, payload);
    let before = event.signing_bytes("ed25519", "key-1").unwrap();
    event.signature = Some(WireSignature {
        algorithm: "ed25519".into(),
        key_id: "key-1".into(),
        value: "signature-a".into(),
    });
    let after = event.signing_bytes("ed25519", "key-1").unwrap();
    assert_eq!(before, after);
    assert_ne!(event.digest().unwrap(), ContentDigest::of_bytes(before));
}

#[test]
fn threat_promotion_requires_fresh_complete_evidence_and_a_gate_reason() {
    let observation = ThreatIntelligenceObservation {
        indicator_id: "indicator-1".into(),
        indicator_kind: ThreatIndicatorKind::IpAddress,
        normalized_value: "192.0.2.1".into(),
        verdict: ThreatVerdict::Malicious,
        score_basis_points: 9_000,
        confidence_basis_points: 8_000,
        source_count: 2,
        internal_observation_count: 0,
        first_seen_unix_ms: 1_000,
        last_seen_unix_ms: 2_000,
        valid_until_unix_ms: 4_000,
        source_event_refs: vec!["event:1".into(), "event:2".into()],
        evidence_refs: vec!["evidence:1".into()],
        promotion_reason: ThreatPromotionReason::MultiSourceCorroboration,
    };
    assert!(observation.supports_promotion(evidence(), 3_000));
    assert!(!observation.supports_promotion(WireEvidenceState::default(), 3_000));
    assert!(!observation.supports_promotion(evidence(), 4_000));
}

#[test]
fn metric_verification_rejects_truncated_or_incomplete_evidence() {
    let metric = MetricSnapshot {
        metric_id: "metric-1".into(),
        definition_version: 1,
        observed_at_unix_ms: 2_000,
        value_microunits: 1,
        unit: "count".into(),
        truncated: false,
        evidence_refs: vec!["evidence:1".into()],
        snapshot_digest: digest('6'),
    };
    assert!(metric.is_verified(evidence()));
    assert!(!metric.is_verified(WireEvidenceState::default()));

    let mut truncated = metric;
    truncated.truncated = true;
    assert!(!truncated.is_verified(evidence()));
}

#[test]
fn endpoint_lease_is_bounded_and_revocation_epoch_bound() {
    let lease = EndpointSessionLease {
        lease_id: "lease-1".into(),
        agent_id: "agent-1".into(),
        user_subject: "user:1".into(),
        session_id: "session-1".into(),
        operation: "repository.read".into(),
        repository_ref: "repository:example".into(),
        repository_revision: None,
        endpoint_ownership: EndpointOwnership::OrganizationOwned,
        network_profile: EndpointNetworkProfile::Isolated,
        capabilities: vec!["repository.read".into()],
        policy_id: "policy-1".into(),
        policy_revision: "revision-1".into(),
        issued_at_unix_ms: 1_000,
        expires_at_unix_ms: 2_000,
        revocation_epoch: 4,
        audience: vec!["repository-broker".into()],
        posture_source_refs: vec!["source:endpoint".into()],
    };
    assert!(lease.is_active_at(1_500, 4));
    assert!(!lease.is_active_at(1_500, 5));
    assert!(!lease.is_active_at(2_000, 4));
}

#[test]
fn receipt_outcome_reason_and_digest_matrix_is_exhaustive() {
    let outcomes = [
        WireIngestOutcome::Accepted,
        WireIngestOutcome::Duplicate,
        WireIngestOutcome::Rejected,
    ];
    let reasons = [
        WireIngestReason::Accepted,
        WireIngestReason::EventAlreadyAccepted,
        WireIngestReason::EventIdCollision,
        WireIngestReason::UnsupportedSchema,
        WireIngestReason::InvalidEnvelope,
        WireIngestReason::InvalidPayload,
        WireIngestReason::SignatureVerificationFailed,
        WireIngestReason::UnsafePayload,
        WireIngestReason::SequenceGapOrReordering,
        WireIngestReason::EventChainMismatch,
        WireIngestReason::PersistenceUnavailable,
    ];
    let valid_cases = [
        (
            WireIngestOutcome::Accepted,
            WireIngestReason::Accepted,
            true,
        ),
        (
            WireIngestOutcome::Duplicate,
            WireIngestReason::EventAlreadyAccepted,
            true,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::EventIdCollision,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::UnsupportedSchema,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::InvalidEnvelope,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::InvalidPayload,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::SignatureVerificationFailed,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::UnsafePayload,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::SequenceGapOrReordering,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::EventChainMismatch,
            false,
        ),
        (
            WireIngestOutcome::Rejected,
            WireIngestReason::PersistenceUnavailable,
            false,
        ),
    ];

    for outcome in outcomes {
        for reason in reasons {
            for has_digest in [false, true] {
                let receipt = WireIngestReceipt {
                    event_id: "event-1".into(),
                    event_digest: has_digest.then(|| digest('7')),
                    outcome,
                    reason,
                    received_at_unix_ms: 2_000,
                };
                assert_eq!(
                    receipt.validate().is_ok(),
                    valid_cases.contains(&(outcome, reason, has_digest)),
                    "unexpected receipt result for {outcome:?}, {reason:?}, digest={has_digest}"
                );
            }
        }
    }
}
