use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::Value;

const SYNTHETIC_EVIDENCE_GOLD: &str = include_str!("../evals/synthetic_evidence_gold_v1.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticEvidenceGoldPack {
    schema_version: String,
    pack_ref: String,
    content_origin: String,
    privacy_contract: PrivacyContract,
    rubric: Value,
    cases: Vec<SyntheticEvidenceGoldCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivacyContract {
    copied_messages: bool,
    derived_incidents: bool,
    real_people: bool,
    real_channels: bool,
    real_organizations: bool,
    real_provider_names: bool,
    real_identifiers: bool,
    real_urls: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticEvidenceGoldCase {
    case_ref: String,
    operator_message: String,
    observations: Vec<Value>,
    required_conclusions: Vec<String>,
    forbidden_conclusions: Vec<String>,
    gold_response: String,
}

pub(super) fn judge_rubric() -> Result<Value, String> {
    let pack = validated_pack()?;
    Ok(pack.rubric)
}

pub(super) fn validate() -> Result<(), String> {
    validated_pack().map(|_| ())
}

fn validated_pack() -> Result<SyntheticEvidenceGoldPack, String> {
    let pack: SyntheticEvidenceGoldPack = serde_json::from_str(SYNTHETIC_EVIDENCE_GOLD)
        .map_err(|error| format!("synthetic evidence gold pack is invalid: {error}"))?;
    if pack.schema_version != "synthetic-evidence-gold/v1"
        || pack.pack_ref != "synthetic-evidence-gold://development/v1"
        || pack.content_origin != "wholly_synthetic"
    {
        return Err("synthetic evidence gold pack identity is invalid".into());
    }
    if pack.privacy_contract.copied_messages
        || pack.privacy_contract.derived_incidents
        || pack.privacy_contract.real_people
        || pack.privacy_contract.real_channels
        || pack.privacy_contract.real_organizations
        || pack.privacy_contract.real_provider_names
        || pack.privacy_contract.real_identifiers
        || pack.privacy_contract.real_urls
    {
        return Err("synthetic evidence gold pack violates its privacy contract".into());
    }
    if pack.cases.len() < 6 {
        return Err("synthetic evidence gold pack requires at least six cases".into());
    }
    let refs = pack
        .cases
        .iter()
        .map(|case| case.case_ref.as_str())
        .collect::<BTreeSet<_>>();
    if refs.len() != pack.cases.len()
        || pack.cases.iter().any(|case| {
            case.case_ref.trim().is_empty()
                || case.operator_message.trim().is_empty()
                || case.observations.len() < 2
                || case.required_conclusions.is_empty()
                || case.forbidden_conclusions.is_empty()
                || case.gold_response.trim().is_empty()
        })
    {
        return Err("synthetic evidence gold cases are incomplete or duplicated".into());
    }
    reject_recognizable_source_material(SYNTHETIC_EVIDENCE_GOLD)?;
    Ok(pack)
}

fn reject_recognizable_source_material(content: &str) -> Result<(), String> {
    let normalized = content.to_ascii_lowercase();
    for forbidden in [
        "slack",
        "writer",
        "github",
        "jira",
        "vanta",
        "okta",
        "amazon",
        "anthropic",
        "bedrock",
        "http://",
        "https://",
        "@",
    ] {
        if normalized.contains(forbidden) {
            return Err(format!(
                "synthetic evidence gold pack contains forbidden source token {forbidden}"
            ));
        }
    }
    if content
        .split_whitespace()
        .any(looks_like_external_identifier)
    {
        return Err(
            "synthetic evidence gold pack contains a recognizable external identifier".into(),
        );
    }
    Ok(())
}

fn looks_like_external_identifier(value: &str) -> bool {
    let value = value.trim_matches(|character: char| !character.is_ascii_alphanumeric());
    value.len() >= 9
        && matches!(value.as_bytes().first(), Some(b'C' | b'G' | b'D' | b'U'))
        && value
            .bytes()
            .skip(1)
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
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
}
