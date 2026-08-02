use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SYNTHETIC_EVIDENCE_GOLD: &str = include_str!("../evals/synthetic_evidence_gold_v1.json");
const SYNTHETIC_EVIDENCE_GOLD_SHA256: &str =
    "17fde96a308f1de6b4cbe773abb42ed47a348e9ca783bb0073c9dd7a6da60967";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticEvidenceGoldPack {
    schema_version: String,
    pack_ref: String,
    privacy_profile: SyntheticPrivacyProfile,
    rubric: SyntheticEvidenceRubric,
    cases: Vec<SyntheticEvidenceGoldCase>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyntheticPrivacyProfile {
    CodeOwnedExactCorpusV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SyntheticEvidenceRubric {
    required_dimensions: Vec<RequiredDimension>,
    hard_failures: Vec<HardFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum RequiredDimension {
    LeadWithTheSupportedDecision,
    BindEachMaterialClaimToAnObservation,
    SeparateDirectObservationFromInference,
    NameScopeFreshnessAndCompleteness,
    PreserveUnknownsAndCompetingExplanations,
    DistinguishExecutionReceiptsFromIndependentVerification,
    CorrectPriorOverstatementExplicitly,
    StateTheOwnedNextActionAndTerminalCondition,
    RemainConversationalAndProportional,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum HardFailure {
    CatalogMetadataPresentedAsProviderState,
    BoundedResultsPresentedAsGlobalTotals,
    TemporalCorrelationPresentedAsCause,
    SuccessfulExecutionReceiptPresentedAsVerifiedOutcome,
    OmissionPresentedAsAbsence,
    CredentialOrSecretDisclosure,
    InventedOwnerPermissionRouteOrRemediation,
    GenericOfferInsteadOfAvailableFollowThrough,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticEvidenceGoldCase {
    case_ref: SyntheticCaseRef,
    operator_message: String,
    observations: Vec<SyntheticObservation>,
    required_conclusions: Vec<String>,
    forbidden_conclusions: Vec<String>,
    gold_response: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
enum SyntheticCaseRef {
    #[serde(rename = "synthetic-evidence://upstream-isolation")]
    UpstreamIsolation,
    #[serde(rename = "synthetic-evidence://causal-correction")]
    CausalCorrection,
    #[serde(rename = "synthetic-evidence://partial-coverage")]
    PartialCoverage,
    #[serde(rename = "synthetic-evidence://effect-versus-closure")]
    EffectVersusClosure,
    #[serde(rename = "synthetic-evidence://declared-versus-effective-access")]
    DeclaredVersusEffectiveAccess,
    #[serde(rename = "synthetic-evidence://continuity-correction")]
    ContinuityCorrection,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticObservation {
    observation_ref: SyntheticObservationRef,
    source_role: SyntheticSourceRole,
    state: SyntheticObservationState,
    observed_at: SyntheticObservedAt,
    facts: SyntheticFacts,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyntheticObservationState {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
enum SyntheticObservedAt {
    #[serde(rename = "T-12m")]
    Minus12Minutes,
    #[serde(rename = "T+00m")]
    Plus0Minutes,
    #[serde(rename = "T+01m")]
    Plus1Minute,
    #[serde(rename = "T+02m")]
    Plus2Minutes,
    #[serde(rename = "T+03m")]
    Plus3Minutes,
    #[serde(rename = "T+04m")]
    Plus4Minutes,
    #[serde(rename = "T+06m")]
    Plus6Minutes,
    #[serde(rename = "T+38m")]
    Plus38Minutes,
    #[serde(rename = "T+41m")]
    Plus41Minutes,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
enum SyntheticObservationRef {
    #[serde(rename = "observation://synthetic/relay-request")]
    RelayRequest,
    #[serde(rename = "observation://synthetic/direct-upstream-probe")]
    DirectUpstreamProbe,
    #[serde(rename = "observation://synthetic/control-probe")]
    ControlProbe,
    #[serde(rename = "observation://synthetic/first-failure")]
    FirstFailure,
    #[serde(rename = "observation://synthetic/rollout")]
    Rollout,
    #[serde(rename = "observation://synthetic/pre-rollout-sample")]
    PreRolloutSample,
    #[serde(rename = "observation://synthetic/collection-receipt")]
    CollectionReceipt,
    #[serde(rename = "observation://synthetic/bounded-search")]
    BoundedSearch,
    #[serde(rename = "observation://synthetic/change-receipt")]
    ChangeReceipt,
    #[serde(rename = "observation://synthetic/independent-read")]
    IndependentRead,
    #[serde(rename = "observation://synthetic/source-contract")]
    SourceContract,
    #[serde(rename = "observation://synthetic/permission-probe")]
    PermissionProbe,
    #[serde(rename = "observation://synthetic/prior-thread")]
    PriorThread,
    #[serde(rename = "observation://synthetic/current-samples")]
    CurrentSamples,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum SyntheticSourceRole {
    SystemUnderTest,
    IndependentPath,
    Control,
    EventLog,
    DeploymentReceipt,
    IndependentLogSlice,
    CollectionReceipt,
    BoundedQuery,
    ExecutorReceipt,
    IndependentStateRead,
    DeclaredContract,
    LiveProviderProbe,
    RetainedConversation,
    FreshRuntimeRead,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(untagged)]
enum SyntheticFacts {
    RelayRequest(RelayRequestFacts),
    DirectUpstreamProbe(DirectUpstreamProbeFacts),
    ControlProbe(ControlProbeFacts),
    FirstFailure(FirstFailureFacts),
    Rollout(RolloutFacts),
    PreRolloutSample(PreRolloutSampleFacts),
    CollectionReceipt(CollectionReceiptFacts),
    BoundedSearch(BoundedSearchFacts),
    ChangeReceipt(ChangeReceiptFacts),
    IndependentRead(IndependentReadFacts),
    SourceContract(SourceContractFacts),
    PermissionProbe(PermissionProbeFacts),
    PriorThread(PriorThreadFacts),
    CurrentSamples(CurrentSamplesFacts),
}

macro_rules! synthetic_facts {
    ($name:ident { $($field:ident : $type:ty),+ $(,)? }) => {
        #[allow(dead_code)]
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name {
            $(
                $field: $type,
            )+
        }
    };
}

synthetic_facts!(RelayRequestFacts {
    request_completed: bool,
    client_deadline_seconds: u8,
    http_response_observed: bool,
});
synthetic_facts!(DirectUpstreamProbeFacts {
    same_operation_completed: bool,
    client_deadline_seconds: u8,
    http_response_observed: bool,
    credentials_logged: bool,
});
synthetic_facts!(ControlProbeFacts {
    peer_operation_completed: bool,
    latency_milliseconds: u16,
});
synthetic_facts!(FirstFailureFacts {
    first_failure_offset_minutes: u8,
    failure_signature: FailureSignature,
});
synthetic_facts!(RolloutFacts {
    rollout_offset_minutes: u8,
    artifact_digest_changed: bool,
});
synthetic_facts!(PreRolloutSampleFacts {
    same_failure_signature_before_rollout: bool,
    sample_is_bounded: bool,
});
synthetic_facts!(CollectionReceiptFacts {
    expected_families: u8,
    observed_families: u8,
    unobserved_family: SyntheticFamily,
    unobserved_reason_code: Option<SyntheticReasonCode>,
});
synthetic_facts!(BoundedSearchFacts {
    records_found_in_observed_families: bool,
    unobserved_family_records_found: bool,
    proves_global_absence: bool,
});
synthetic_facts!(ChangeReceiptFacts {
    request_accepted: bool,
    executor_reported_success: bool,
    target_revision: SyntheticRevision,
});
synthetic_facts!(IndependentReadFacts {
    observed_revision: SyntheticRevision,
    desired_condition_observed: bool,
    read_fresh: bool,
});
synthetic_facts!(SourceContractFacts {
    declared_operation: SyntheticOperation,
    credential_configured: bool,
});
synthetic_facts!(PermissionProbeFacts {
    operation_authorized: bool,
    provider_reason: SyntheticReasonCode,
    secret_value_observed: bool,
});
synthetic_facts!(PriorThreadFacts {
    assistant_prior_claim: SyntheticPriorClaim,
    operator_correction: SyntheticOperatorCorrection,
    assistant_acknowledged_correction: bool,
});
synthetic_facts!(CurrentSamplesFacts {
    required_consecutive_samples: u8,
    current_consecutive_successes: u8,
    recovery_condition_met: bool,
});

#[derive(Deserialize)]
enum FailureSignature {
    #[serde(rename = "signature-amber")]
    Amber,
}

#[derive(Deserialize)]
enum SyntheticFamily {
    #[serde(rename = "family-violet")]
    Violet,
}

#[derive(Deserialize)]
enum SyntheticRevision {
    #[serde(rename = "revision-cobalt")]
    Cobalt,
    #[serde(rename = "revision-umber")]
    Umber,
}

#[derive(Deserialize)]
enum SyntheticOperation {
    #[serde(rename = "read-family-silver")]
    ReadFamilySilver,
}

#[derive(Deserialize)]
enum SyntheticReasonCode {
    #[serde(rename = "operation-not-allowed")]
    OperationNotAllowed,
}

#[derive(Deserialize)]
enum SyntheticPriorClaim {
    #[serde(rename = "queue-recovered")]
    QueueRecovered,
}

#[derive(Deserialize)]
enum SyntheticOperatorCorrection {
    #[serde(rename = "one successful sample did not satisfy the three-sample recovery rule")]
    ThreeSampleRecoveryRule,
}

pub(super) fn judge_rubric() -> Result<Value, String> {
    let pack = validated_pack()?;
    serde_json::to_value(pack.rubric)
        .map_err(|error| format!("synthetic evidence rubric is not serializable: {error}"))
}

pub(super) fn validate() -> Result<(), String> {
    validated_pack().map(|_| ())
}

fn validated_pack() -> Result<SyntheticEvidenceGoldPack, String> {
    validated_pack_from_str(SYNTHETIC_EVIDENCE_GOLD)
}

fn validated_pack_from_str(content: &str) -> Result<SyntheticEvidenceGoldPack, String> {
    let digest = Sha256::digest(content.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if digest != SYNTHETIC_EVIDENCE_GOLD_SHA256 {
        return Err(
            "synthetic evidence gold pack is not the exact code-owned approved corpus".into(),
        );
    }
    let pack: SyntheticEvidenceGoldPack = serde_json::from_str(content)
        .map_err(|error| format!("synthetic evidence gold pack is invalid: {error}"))?;
    if pack.schema_version != "synthetic-evidence-gold/v2"
        || pack.pack_ref != "synthetic-evidence-gold://development/v2"
        || pack.privacy_profile != SyntheticPrivacyProfile::CodeOwnedExactCorpusV1
    {
        return Err("synthetic evidence gold pack identity is invalid".into());
    }
    if pack.cases.len() < 6 {
        return Err("synthetic evidence gold pack requires at least six cases".into());
    }
    let required_dimensions = pack
        .rubric
        .required_dimensions
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let hard_failures = pack
        .rubric
        .hard_failures
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if required_dimensions.len() != 9
        || required_dimensions.len() != pack.rubric.required_dimensions.len()
        || hard_failures.len() != 8
        || hard_failures.len() != pack.rubric.hard_failures.len()
    {
        return Err("synthetic evidence gold rubric is incomplete or duplicated".into());
    }
    let refs = pack
        .cases
        .iter()
        .map(|case| case.case_ref)
        .collect::<BTreeSet<_>>();
    let mut observation_refs = BTreeSet::new();
    if refs.len() != pack.cases.len()
        || refs.len() != 6
        || pack.cases.iter().any(|case| {
            case.operator_message.trim().is_empty()
                || case.observations.len() < 2
                || case.required_conclusions.is_empty()
                || case.forbidden_conclusions.is_empty()
                || case.gold_response.trim().is_empty()
                || case.observations.iter().any(|observation| {
                    !observation.valid_binding()
                        || !observation_refs.insert(observation.observation_ref)
                })
        })
    {
        return Err("synthetic evidence gold cases are incomplete or duplicated".into());
    }
    if observation_refs.len() != 14 {
        return Err("synthetic evidence gold observation inventory is incomplete".into());
    }
    Ok(pack)
}

impl SyntheticObservation {
    fn valid_binding(&self) -> bool {
        let state_valid = match self.observation_ref {
            SyntheticObservationRef::CollectionReceipt => {
                self.state == SyntheticObservationState::Partial
            }
            _ => self.state == SyntheticObservationState::Complete,
        };
        let role_and_facts_valid = matches!(
            (self.observation_ref, self.source_role, &self.facts),
            (
                SyntheticObservationRef::RelayRequest,
                SyntheticSourceRole::SystemUnderTest,
                SyntheticFacts::RelayRequest(_)
            ) | (
                SyntheticObservationRef::DirectUpstreamProbe,
                SyntheticSourceRole::IndependentPath,
                SyntheticFacts::DirectUpstreamProbe(_)
            ) | (
                SyntheticObservationRef::ControlProbe,
                SyntheticSourceRole::Control,
                SyntheticFacts::ControlProbe(_)
            ) | (
                SyntheticObservationRef::FirstFailure,
                SyntheticSourceRole::EventLog,
                SyntheticFacts::FirstFailure(_)
            ) | (
                SyntheticObservationRef::Rollout,
                SyntheticSourceRole::DeploymentReceipt,
                SyntheticFacts::Rollout(_)
            ) | (
                SyntheticObservationRef::PreRolloutSample,
                SyntheticSourceRole::IndependentLogSlice,
                SyntheticFacts::PreRolloutSample(_)
            ) | (
                SyntheticObservationRef::CollectionReceipt,
                SyntheticSourceRole::CollectionReceipt,
                SyntheticFacts::CollectionReceipt(_)
            ) | (
                SyntheticObservationRef::BoundedSearch,
                SyntheticSourceRole::BoundedQuery,
                SyntheticFacts::BoundedSearch(_)
            ) | (
                SyntheticObservationRef::ChangeReceipt,
                SyntheticSourceRole::ExecutorReceipt,
                SyntheticFacts::ChangeReceipt(_)
            ) | (
                SyntheticObservationRef::IndependentRead,
                SyntheticSourceRole::IndependentStateRead,
                SyntheticFacts::IndependentRead(_)
            ) | (
                SyntheticObservationRef::SourceContract,
                SyntheticSourceRole::DeclaredContract,
                SyntheticFacts::SourceContract(_)
            ) | (
                SyntheticObservationRef::PermissionProbe,
                SyntheticSourceRole::LiveProviderProbe,
                SyntheticFacts::PermissionProbe(_)
            ) | (
                SyntheticObservationRef::PriorThread,
                SyntheticSourceRole::RetainedConversation,
                SyntheticFacts::PriorThread(_)
            ) | (
                SyntheticObservationRef::CurrentSamples,
                SyntheticSourceRole::FreshRuntimeRead,
                SyntheticFacts::CurrentSamples(_)
            )
        );
        state_valid
            && role_and_facts_valid
            && matches!(
                self.observed_at,
                SyntheticObservedAt::Minus12Minutes
                    | SyntheticObservedAt::Plus0Minutes
                    | SyntheticObservedAt::Plus1Minute
                    | SyntheticObservedAt::Plus2Minutes
                    | SyntheticObservedAt::Plus3Minutes
                    | SyntheticObservedAt::Plus4Minutes
                    | SyntheticObservedAt::Plus6Minutes
                    | SyntheticObservedAt::Plus38Minutes
                    | SyntheticObservedAt::Plus41Minutes
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_gold_pack_is_complete_and_source_anonymous() {
        validate().unwrap();
    }

    #[test]
    fn judge_rubric_contains_the_decision_grade_boundaries() {
        let rubric = judge_rubric().unwrap().to_string();
        for required in [
            "bind_each_material_claim_to_an_observation",
            "preserve_unknowns_and_competing_explanations",
            "distinguish_execution_receipts_from_independent_verification",
            "successful_execution_receipt_presented_as_verified_outcome",
        ] {
            assert!(rubric.contains(required));
        }
    }

    #[test]
    fn code_owned_corpus_rejects_undeclared_names_hosts_and_identifiers() {
        for injected in [
            "lowercase acme breach",
            "lowercase jane owner",
            "ticket-1234",
            "secret.example.io",
        ] {
            let mutated = SYNTHETIC_EVIDENCE_GOLD.replacen(
                "Is the relay broken",
                &format!("{injected}. Is the relay broken"),
                1,
            );
            let error = validated_pack_from_str(&mutated)
                .err()
                .expect("mutated corpus must be rejected");
            assert_eq!(
                error,
                "synthetic evidence gold pack is not the exact code-owned approved corpus"
            );
        }
    }

    #[test]
    fn typed_observations_reject_undeclared_fact_values() {
        let mutated = SYNTHETIC_EVIDENCE_GOLD.replace("signature-amber", "signature-acme");
        assert!(validated_pack_from_str(&mutated).is_err());

        let observation = r#"{
            "observation_ref":"observation://synthetic/first-failure",
            "source_role":"event_log",
            "state":"complete",
            "observed_at":"T+00m",
            "facts":{"first_failure_offset_minutes":0,"failure_signature":"signature-acme"}
        }"#;
        assert!(serde_json::from_str::<SyntheticObservation>(observation).is_err());
    }
}
