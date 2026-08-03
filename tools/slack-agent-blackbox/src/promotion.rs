use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use cerebro_slack_agent_eval_wire::{
    BlindPacketKindV2, ExactHeadBindingV2, ExecutionPrincipalsV2, HoldoutAssignmentCommitmentV2,
    IndependentGradeReceiptV2, MaterializedBlindPacketV2, PromotionAggregationReceiptV2,
    PromotionPolicyV2, SealedHoldoutAssignmentsV2, SealedSuiteManifestV2, SignatureAlgorithmV2,
    SignedReceiptEnvelopeV2, SignerAttestationV2, SlackCanaryReceiptV2,
    SupervisorExecutionReceiptV2, sha256_json,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Debug)]
pub enum PromotionValidationError {
    Contract(String),
    Io(std::io::Error),
    Json(serde_json::Error),
    Signature(String),
}

impl fmt::Display for PromotionValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(message) => write!(formatter, "promotion contract rejected: {message}"),
            Self::Io(error) => write!(formatter, "promotion receipt I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "promotion receipt JSON failed: {error}"),
            Self::Signature(message) => {
                write!(formatter, "promotion receipt signature rejected: {message}")
            }
        }
    }
}

impl Error for PromotionValidationError {}

impl From<std::io::Error> for PromotionValidationError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for PromotionValidationError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

pub trait ReceiptSignatureVerifier {
    fn verify(
        &self,
        signer: &SignerAttestationV2,
        payload_digest: &str,
        signature_base64: &str,
    ) -> Result<(), String>;
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ed25519PublicKeyBinding {
    pub key_ref: String,
    pub principal_ref: String,
    pub public_key_base64: String,
}

pub struct Ed25519KeyringVerifier {
    keys: BTreeMap<String, (String, VerifyingKey)>,
}

impl Ed25519KeyringVerifier {
    pub fn new(bindings: Vec<Ed25519PublicKeyBinding>) -> Result<Self, PromotionValidationError> {
        if bindings.is_empty() {
            return Err(PromotionValidationError::Signature(
                "the promotion bundle has no trusted public keys".into(),
            ));
        }
        let mut keys = BTreeMap::new();
        for binding in bindings {
            if binding.key_ref.trim().is_empty() || binding.principal_ref.trim().is_empty() {
                return Err(PromotionValidationError::Signature(
                    "a trusted public-key binding is incomplete".into(),
                ));
            }
            let decoded = STANDARD.decode(&binding.public_key_base64).map_err(|_| {
                PromotionValidationError::Signature(
                    "a trusted Ed25519 public key is not valid base64".into(),
                )
            })?;
            let bytes: [u8; 32] = decoded.try_into().map_err(|_| {
                PromotionValidationError::Signature(
                    "a trusted Ed25519 public key is not 32 bytes".into(),
                )
            })?;
            let key = VerifyingKey::from_bytes(&bytes).map_err(|_| {
                PromotionValidationError::Signature(
                    "a trusted Ed25519 public key is invalid".into(),
                )
            })?;
            if keys
                .insert(binding.key_ref, (binding.principal_ref, key))
                .is_some()
            {
                return Err(PromotionValidationError::Signature(
                    "trusted public-key references must be unique".into(),
                ));
            }
        }
        Ok(Self { keys })
    }
}

impl ReceiptSignatureVerifier for Ed25519KeyringVerifier {
    fn verify(
        &self,
        signer: &SignerAttestationV2,
        payload_digest: &str,
        signature_base64: &str,
    ) -> Result<(), String> {
        if signer.algorithm != SignatureAlgorithmV2::Ed25519 {
            return Err("the local promotion verifier accepts Ed25519 receipts only".into());
        }
        let (principal_ref, key) = self
            .keys
            .get(&signer.key_ref)
            .ok_or_else(|| "the receipt key is not in the trusted keyring".to_owned())?;
        if principal_ref != &signer.principal_ref {
            return Err("the receipt signer does not own the trusted key".into());
        }
        let decoded = STANDARD
            .decode(signature_base64)
            .map_err(|_| "the Ed25519 signature is not valid base64".to_owned())?;
        let signature = Signature::from_slice(&decoded)
            .map_err(|_| "the Ed25519 signature is not 64 bytes".to_owned())?;
        key.verify(payload_digest.as_bytes(), &signature)
            .map_err(|_| "the Ed25519 signature does not verify".to_owned())
    }
}

pub struct RequiredPromotionArtifacts<'a> {
    pub assignment_commitment: &'a HoldoutAssignmentCommitmentV2,
    pub exact_head: &'a SignedReceiptEnvelopeV2<ExactHeadBindingV2>,
    pub slack_canary: &'a SignedReceiptEnvelopeV2<SlackCanaryReceiptV2>,
    pub execution_receipts: &'a [SignedReceiptEnvelopeV2<SupervisorExecutionReceiptV2>],
    pub independent_grades: &'a [SignedReceiptEnvelopeV2<IndependentGradeReceiptV2>],
    pub materialized_packets: &'a [MaterializedBlindPacketV2],
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionVerificationBundle {
    aggregate: SignedReceiptEnvelopeV2<PromotionAggregationReceiptV2>,
    assignment_commitment: HoldoutAssignmentCommitmentV2,
    exact_head: SignedReceiptEnvelopeV2<ExactHeadBindingV2>,
    execution_receipts: Vec<SignedReceiptEnvelopeV2<SupervisorExecutionReceiptV2>>,
    independent_grades: Vec<SignedReceiptEnvelopeV2<IndependentGradeReceiptV2>>,
    materialized_packets: Vec<MaterializedBlindPacketV2>,
    policy: PromotionPolicyV2,
    principals: ExecutionPrincipalsV2,
    public_keys: Vec<Ed25519PublicKeyBinding>,
    slack_canary: SignedReceiptEnvelopeV2<SlackCanaryReceiptV2>,
    suite: SealedSuiteManifestV2,
}

pub fn verify_promotion_file(
    bundle_path: impl AsRef<Path>,
) -> Result<(), PromotionValidationError> {
    let bundle: PromotionVerificationBundle = read_json(bundle_path)?;
    let verifier = Ed25519KeyringVerifier::new(bundle.public_keys)?;
    validate_promotion_aggregate(
        &bundle.aggregate,
        &bundle.suite,
        &bundle.policy,
        &bundle.principals,
        RequiredPromotionArtifacts {
            assignment_commitment: &bundle.assignment_commitment,
            exact_head: &bundle.exact_head,
            slack_canary: &bundle.slack_canary,
            execution_receipts: &bundle.execution_receipts,
            independent_grades: &bundle.independent_grades,
            materialized_packets: &bundle.materialized_packets,
        },
        &verifier,
    )
}

pub fn validate_sealed_suite_and_assignments(
    suite: &SealedSuiteManifestV2,
    assignments: &SealedHoldoutAssignmentsV2,
) -> Result<HoldoutAssignmentCommitmentV2, PromotionValidationError> {
    suite
        .validate_coverage()
        .map_err(PromotionValidationError::Contract)?;
    let suite_digest = suite.digest()?;
    if assignments.suite_manifest_digest != suite_digest {
        return Err(PromotionValidationError::Contract(
            "private assignments belong to another sealed suite".into(),
        ));
    }
    let commitment = assignments
        .validate_and_commit()
        .map_err(PromotionValidationError::Contract)?;
    let suite_episodes = suite
        .episode_bindings
        .iter()
        .map(|binding| binding.episode_manifest_digest.as_str())
        .collect::<BTreeSet<_>>();
    let mut candidates_by_episode = BTreeMap::<&str, BTreeSet<&str>>::new();
    for assignment in &assignments.assignments {
        if !suite_episodes.contains(assignment.episode_manifest_digest.as_str()) {
            return Err(PromotionValidationError::Contract(format!(
                "assignment {} references an episode outside the sealed suite",
                assignment.assignment_ref
            )));
        }
        candidates_by_episode
            .entry(assignment.episode_manifest_digest.as_str())
            .or_default()
            .insert(assignment.candidate_attestation_digest.as_str());
    }
    for episode_digest in suite_episodes {
        let candidates = candidates_by_episode.get(episode_digest).ok_or_else(|| {
            PromotionValidationError::Contract(format!(
                "sealed episode {episode_digest} has no private assignment"
            ))
        })?;
        if candidates.len() < 2 {
            return Err(PromotionValidationError::Contract(format!(
                "sealed episode {episode_digest} lacks a randomized candidate/baseline pair"
            )));
        }
    }
    Ok(commitment)
}

pub fn validate_suite_files_and_write_commitment(
    suite_path: impl AsRef<Path>,
    assignments_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> Result<HoldoutAssignmentCommitmentV2, PromotionValidationError> {
    let suite: SealedSuiteManifestV2 = read_json(suite_path)?;
    let assignments: SealedHoldoutAssignmentsV2 = read_json(assignments_path)?;
    let commitment = validate_sealed_suite_and_assignments(&suite, &assignments)?;
    write_new_json(output_path, &commitment)?;
    Ok(commitment)
}

pub fn validate_promotion_aggregate<V: ReceiptSignatureVerifier>(
    aggregate: &SignedReceiptEnvelopeV2<PromotionAggregationReceiptV2>,
    suite: &SealedSuiteManifestV2,
    policy: &PromotionPolicyV2,
    principals: &ExecutionPrincipalsV2,
    artifacts: RequiredPromotionArtifacts<'_>,
    verifier: &V,
) -> Result<(), PromotionValidationError> {
    verify_signed(aggregate, verifier)?;
    if aggregate.signer.principal_ref != principals.supervisor.principal_ref {
        return Err(PromotionValidationError::Contract(
            "promotion aggregate was not signed by the sealed supervisor principal".into(),
        ));
    }
    if suite.promotion_policy_digest != policy.digest()? {
        return Err(PromotionValidationError::Contract(
            "sealed suite does not bind the supplied promotion policy".into(),
        ));
    }
    let suite_digest = suite.digest()?;
    if artifacts.assignment_commitment.suite_manifest_digest != suite_digest
        || aggregate
            .payload
            .randomized_baseline
            .holdout_assignment_commitment_digest
            != sha256_json(artifacts.assignment_commitment)?
        || aggregate.payload.assignment_results.len()
            != artifacts.assignment_commitment.assignment_count
        || artifacts.execution_receipts.len() != artifacts.assignment_commitment.assignment_count
    {
        return Err(PromotionValidationError::Contract(
            "promotion artifacts do not cover the committed holdout assignments exactly once"
                .into(),
        ));
    }
    verify_signed(artifacts.exact_head, verifier)?;
    verify_control_signer(principals, &artifacts.exact_head.signer)?;
    if artifacts.exact_head.payload != aggregate.payload.exact_head {
        return Err(PromotionValidationError::Contract(
            "promotion aggregate substituted the exact-head artifact".into(),
        ));
    }
    verify_signed(artifacts.slack_canary, verifier)?;
    verify_control_signer(principals, &artifacts.slack_canary.signer)?;
    if artifacts.slack_canary.payload != aggregate.payload.slack_canary {
        return Err(PromotionValidationError::Contract(
            "promotion aggregate substituted the Slack canary artifact".into(),
        ));
    }

    let suite_episode_digests = suite
        .episode_bindings
        .iter()
        .map(|binding| binding.episode_manifest_digest.as_str())
        .collect::<BTreeSet<_>>();
    let mut execution_digests = BTreeSet::new();
    let mut terminal_defect_count = 0_usize;
    for receipt in artifacts.execution_receipts {
        verify_signed(receipt, verifier)?;
        if receipt.signer.principal_ref != principals.supervisor.principal_ref {
            return Err(PromotionValidationError::Contract(
                "execution receipt was not signed by the sealed supervisor principal".into(),
            ));
        }
        if !suite_episode_digests.contains(receipt.payload.episode_manifest_digest.as_str()) {
            return Err(PromotionValidationError::Contract(
                "execution receipt belongs to an episode outside the sealed suite".into(),
            ));
        }
        for decision in &receipt.payload.operator_decisions {
            decision
                .validate_semantics()
                .map_err(PromotionValidationError::Contract)?;
        }
        terminal_defect_count = terminal_defect_count
            .checked_add(
                receipt
                    .payload
                    .deterministic_defects
                    .iter()
                    .filter(|defect| defect.terminal)
                    .count(),
            )
            .ok_or_else(|| {
                PromotionValidationError::Contract("terminal defect count overflowed".into())
            })?;
        if !execution_digests.insert(receipt.payload_digest.clone()) {
            return Err(PromotionValidationError::Contract(
                "duplicate execution receipt cannot satisfy holdout coverage".into(),
            ));
        }
    }
    if execution_digests
        != aggregate
            .payload
            .execution_receipt_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
        || terminal_defect_count != aggregate.payload.execution_terminal_defect_count
    {
        return Err(PromotionValidationError::Contract(
            "promotion aggregate omitted, substituted, or miscounted execution receipts".into(),
        ));
    }

    let mut grades = Vec::with_capacity(artifacts.independent_grades.len());
    for grade in artifacts.independent_grades {
        verify_signed(grade, verifier)?;
        if grade.signer.principal_ref != grade.payload.grader.principal_ref {
            return Err(PromotionValidationError::Contract(
                "grade signer does not match the attested grader principal".into(),
            ));
        }
        principals
            .validate_grader_separation(&grade.signer.principal_ref)
            .map_err(PromotionValidationError::Contract)?;
        grades.push(grade.payload.clone());
    }
    validate_independent_grade_packet_bindings(&grades, artifacts.materialized_packets)?;
    aggregate
        .payload
        .validate_against(suite, policy, principals, &grades)
        .map_err(PromotionValidationError::Contract)
}

fn validate_independent_grade_packet_bindings(
    grades: &[IndependentGradeReceiptV2],
    packets: &[MaterializedBlindPacketV2],
) -> Result<(), PromotionValidationError> {
    let mut packets_by_assignment_and_kind =
        BTreeMap::<(&str, BlindPacketKindV2), &MaterializedBlindPacketV2>::new();
    let mut candidate_by_assignment = BTreeMap::<&str, &str>::new();
    for packet in packets {
        let key = (packet.assignment_alias(), packet.packet_kind());
        if packets_by_assignment_and_kind.insert(key, packet).is_some() {
            return Err(PromotionValidationError::Contract(
                "materialized blind packets must be unique by assignment and packet kind".into(),
            ));
        }
        if candidate_by_assignment
            .insert(packet.assignment_alias(), packet.candidate_alias())
            .is_some_and(|candidate| candidate != packet.candidate_alias())
        {
            return Err(PromotionValidationError::Contract(
                "materialized blind packets for an assignment substitute different candidates"
                    .into(),
            ));
        }
    }
    let grade_keys = grades
        .iter()
        .map(|grade| (grade.assignment_alias.as_str(), grade.packet_kind))
        .collect::<BTreeSet<_>>();
    if grade_keys
        != packets_by_assignment_and_kind
            .keys()
            .copied()
            .collect::<BTreeSet<_>>()
    {
        return Err(PromotionValidationError::Contract(
            "promotion bundle omits a graded materialized packet or includes an ungraded packet"
                .into(),
        ));
    }
    for grade in grades {
        let packet = packets_by_assignment_and_kind
            .get(&(grade.assignment_alias.as_str(), grade.packet_kind))
            .ok_or_else(|| {
                PromotionValidationError::Contract(
                    "promotion bundle is missing the materialized packet for an independent grade"
                        .into(),
                )
            })?;
        packet
            .validate_grade_binding(grade)
            .map_err(PromotionValidationError::Contract)?;
    }
    Ok(())
}

fn verify_signed<T: Serialize, V: ReceiptSignatureVerifier>(
    envelope: &SignedReceiptEnvelopeV2<T>,
    verifier: &V,
) -> Result<(), PromotionValidationError> {
    envelope
        .validate_digest_and_signature_shape()
        .map_err(PromotionValidationError::Contract)?;
    verifier
        .verify(
            &envelope.signer,
            &envelope.payload_digest,
            &envelope.signature_base64,
        )
        .map_err(PromotionValidationError::Signature)
}

fn verify_control_signer(
    principals: &ExecutionPrincipalsV2,
    signer: &SignerAttestationV2,
) -> Result<(), PromotionValidationError> {
    if signer.principal_ref == principals.candidate.principal_ref
        || signer.principal_ref == principals.operator.principal_ref
    {
        return Err(PromotionValidationError::Contract(
            "candidate or operator principal cannot attest a promotion control artifact".into(),
        ));
    }
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, PromotionValidationError> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_new_json(
    path: impl AsRef<Path>,
    value: &impl Serialize,
) -> Result<(), PromotionValidationError> {
    let path = path.as_ref();
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(PromotionValidationError::Io(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebro_slack_agent_eval_wire::{
        CONTENT_BLIND_PACKET_V2, ContentBlindPacketV2, DimensionScoreV2, EPISODE_EVENT_PROGRAM_V2,
        EpisodeEventProgramV2, EpisodeLimitsV2, GradeCitationV2, GradeDimensionV2,
        GraderAttestationV2, INDEPENDENT_GRADE_RECEIPT_V2, OperatorControllerAttestationV2,
        SEALED_EPISODE_MANIFEST_V2, SEALED_SUITE_MANIFEST_V2, SealedEpisodeManifestV2,
        SuiteEpisodeBindingV2, SuiteFamilyRequirementV2, SurfaceGeneratorAttestationV2,
    };

    fn episode_digest(label: &str) -> String {
        SealedEpisodeManifestV2 {
            schema_version: SEALED_EPISODE_MANIFEST_V2.into(),
            manifest_ref: format!("manifest:{label}"),
            scenario_digest: format!("sha256:scenario-{label}"),
            generator: SurfaceGeneratorAttestationV2 {
                generator_ref: "generator:v2".into(),
                artifact_digest: "sha256:generator".into(),
                semantic_template_digest: "sha256:template".into(),
                surface_seed_commitment: format!("sha256:seed-{label}"),
            },
            program: EpisodeEventProgramV2 {
                schema_version: EPISODE_EVENT_PROGRAM_V2.into(),
                program_ref: format!("program:{label}"),
                events: Vec::new(),
            },
            limits: EpisodeLimitsV2 {
                max_events: 4,
                max_candidate_turns: 4,
                candidate_turn_timeout_ms: 60_000,
                operator_turn_timeout_ms: 10_000,
                episode_timeout_ms: 300_000,
                phase_latency_limits_ms: BTreeMap::from([("route".into(), 10_000)]),
            },
            world_digest: format!("sha256:world-{label}"),
            operator_controller: OperatorControllerAttestationV2 {
                controller_ref: "controller:v2".into(),
                artifact_digest: "sha256:controller".into(),
                policy_digest: "sha256:operator-policy".into(),
                principal_ref: "principal:operator".into(),
            },
            candidate_surface_contract_digest: "sha256:surface-contract".into(),
        }
        .digest()
        .unwrap()
    }

    #[test]
    fn suite_validation_requires_candidate_and_baseline_for_every_episode() {
        let episode = episode_digest("one");
        let suite = SealedSuiteManifestV2 {
            schema_version: SEALED_SUITE_MANIFEST_V2.into(),
            suite_ref: "suite:one".into(),
            corpus_digest: "sha256:corpus".into(),
            suite_generator_digest: "sha256:generator".into(),
            episode_bindings: vec![SuiteEpisodeBindingV2 {
                episode_manifest_digest: episode.clone(),
                family_ref: "family:correction".into(),
                semantic_template_ref: "template:one".into(),
                surface_variant_ref: "surface:one".into(),
                sample_index: 1,
                comparison_pair_ref: "pair:one".into(),
            }],
            family_requirements: vec![SuiteFamilyRequirementV2 {
                family_ref: "family:correction".into(),
                minimum_episode_count: 1,
                minimum_surface_variant_count: 1,
                minimum_sample_count_per_variant: 1,
            }],
            assignment_policy_digest: "sha256:assignment-policy".into(),
            promotion_policy_digest: "sha256:promotion-policy".into(),
        };
        let assignment = |suffix: &str| cerebro_slack_agent_eval_wire::PrivateHoldoutAssignmentV2 {
            assignment_ref: format!("private:{suffix}"),
            assignment_alias: format!("assignment:{suffix}"),
            episode_manifest_digest: episode.clone(),
            candidate_attestation_digest: format!("sha256:artifact-{suffix}"),
            candidate_alias: format!("participant:{suffix}"),
            presentation_order: usize::from(suffix == "baseline"),
        };
        let mut assignments = SealedHoldoutAssignmentsV2 {
            schema_version: cerebro_slack_agent_eval_wire::SEALED_HOLDOUT_ASSIGNMENTS_V2.into(),
            suite_manifest_digest: suite.digest().unwrap(),
            blinding_nonce: "a-private-nonce-with-more-than-thirty-two-bytes".into(),
            assignments: vec![assignment("candidate")],
        };
        assert!(validate_sealed_suite_and_assignments(&suite, &assignments).is_err());
        assignments.assignments.push(assignment("baseline"));
        assert!(validate_sealed_suite_and_assignments(&suite, &assignments).is_ok());
    }

    #[test]
    fn public_commitment_does_not_serialize_private_mapping() {
        let commitment = HoldoutAssignmentCommitmentV2 {
            schema_version: cerebro_slack_agent_eval_wire::HOLDOUT_ASSIGNMENT_COMMITMENT_V2.into(),
            suite_manifest_digest: "sha256:suite".into(),
            assignment_count: 2,
            sealed_assignment_manifest_digest: "sha256:sealed".into(),
        };
        let encoded = serde_json::to_string(&commitment).unwrap();
        assert!(!encoded.contains("candidate_attestation_digest"));
        assert!(!encoded.contains("blinding_nonce"));
        assert!(!encoded.contains("presentation_order"));
    }

    fn packet_and_grade() -> (MaterializedBlindPacketV2, IndependentGradeReceiptV2) {
        let packet = MaterializedBlindPacketV2::Content(ContentBlindPacketV2 {
            schema_version: CONTENT_BLIND_PACKET_V2.into(),
            assignment_alias: "assignment:red".into(),
            candidate_alias: "participant:blue".into(),
            task: cerebro_slack_agent_eval_wire::BlindTaskBriefV2 {
                operator_request: "Explain the decision.".into(),
                success_definition: "The operator can act.".into(),
            },
            transcript: vec![cerebro_slack_agent_eval_wire::BlindTranscriptTurn {
                role: "assistant".into(),
                message: "Here is the decision and its basis.".into(),
            }],
        });
        let grade = IndependentGradeReceiptV2 {
            schema_version: INDEPENDENT_GRADE_RECEIPT_V2.into(),
            grade_ref: "grade:one".into(),
            suite_manifest_digest: "sha256:suite".into(),
            assignment_alias: "assignment:red".into(),
            packet_kind: BlindPacketKindV2::Content,
            packet_digest: packet.payload_digest().unwrap(),
            grader: GraderAttestationV2 {
                principal_ref: "principal:grader".into(),
                artifact_digest: "sha256:grader".into(),
                rubric_digest: "sha256:rubric".into(),
                calibration_receipt_digest: "sha256:calibration".into(),
                calibration_passed: true,
            },
            scores: vec![DimensionScoreV2 {
                dimension: GradeDimensionV2::HumanUsefulness,
                score: 90,
            }],
            hard_defect_codes: Vec::new(),
            citations: vec![GradeCitationV2 {
                dimension: GradeDimensionV2::HumanUsefulness,
                packet_item_ref: "/transcript/0/message".into(),
                rationale: "The cited response states the decision.".into(),
            }],
            graded_at: "2026-08-03T00:01:00Z".into(),
        };
        (packet, grade)
    }

    #[test]
    fn promotion_requires_exactly_the_graded_materialized_packets() {
        let (packet, grade) = packet_and_grade();
        assert!(
            validate_independent_grade_packet_bindings(
                std::slice::from_ref(&grade),
                std::slice::from_ref(&packet),
            )
            .is_ok()
        );
        assert!(
            validate_independent_grade_packet_bindings(&[grade], &[])
                .unwrap_err()
                .to_string()
                .contains("omits a graded materialized packet")
        );
        assert!(
            validate_independent_grade_packet_bindings(&[], &[packet])
                .unwrap_err()
                .to_string()
                .contains("includes an ungraded packet")
        );
    }

    #[test]
    fn promotion_rejects_substituted_and_unresolvable_grade_packets() {
        let (packet, mut grade) = packet_and_grade();
        grade.packet_digest = "sha256:substituted".into();
        assert!(
            validate_independent_grade_packet_bindings(
                std::slice::from_ref(&grade),
                std::slice::from_ref(&packet),
            )
            .unwrap_err()
            .to_string()
            .contains("does not bind the exact materialized packet")
        );

        grade.packet_digest = packet.payload_digest().unwrap();
        grade.citations[0].packet_item_ref = "/transcript/99/message".into();
        assert!(
            validate_independent_grade_packet_bindings(&[grade], &[packet])
                .unwrap_err()
                .to_string()
                .contains("citation does not resolve")
        );
    }

    #[test]
    fn promotion_rejects_cross_candidate_packet_substitution() {
        let (content, _) = packet_and_grade();
        let evidence = MaterializedBlindPacketV2::Evidence(
            cerebro_slack_agent_eval_wire::EvidenceBlindPacketV2 {
                schema_version: cerebro_slack_agent_eval_wire::EVIDENCE_BLIND_PACKET_V2.into(),
                assignment_alias: "assignment:red".into(),
                candidate_alias: "participant:substituted".into(),
                task: cerebro_slack_agent_eval_wire::BlindTaskBriefV2 {
                    operator_request: "Explain the decision.".into(),
                    success_definition: "The operator can act.".into(),
                },
                claims: Vec::new(),
                authoritative_facts: Vec::new(),
                authoritative_actions: Vec::new(),
            },
        );
        assert!(
            validate_independent_grade_packet_bindings(&[], &[content, evidence])
                .unwrap_err()
                .to_string()
                .contains("substitute different candidates")
        );
    }
}
