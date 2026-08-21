use std::collections::BTreeMap;

use prost::Message;
use sha2::{Digest, Sha256};

use super::{error::WorkerError, wire::SourceExecutionPlanV1};

pub(super) const AZURE_SOURCE_ID: &str = "azure";
pub(super) const AUTHORIZATION_POLICY_FAMILY: &str = "authorization_policy";
pub(super) const AUTHORIZATION_POLICY_KERNEL: &str = "azure.authorization_policy";
pub(super) const AUTHORIZATION_POLICY_PATH: &str = "/v1.0/policies/authorizationPolicy";
pub(super) const AUTHORIZATION_POLICY_FALLBACK_ID: &str = "authorizationPolicy";
pub(super) const AUTHORIZATION_POLICY_KIND: &str = "azure.authorization_policy";
pub(super) const AUTHORIZATION_POLICY_SCHEMA: &str = "azure/authorization_policy/v1";
pub(super) const MAX_RESPONSE_BYTES: u64 = 8 << 20;

pub(super) fn validate_plan(plan: &SourceExecutionPlanV1) -> Result<(), WorkerError> {
    let expected_attributes = [
        "resource_id",
        "resource_name",
        "resource_provider",
        "resource_type",
    ];
    let exact_contract = plan.plan_id == "source-plan-v1:azure:authorization_policy"
        && plan.source_id == AZURE_SOURCE_ID
        && plan.family_id == AUTHORIZATION_POLICY_FAMILY
        && plan.provider_kernel == AUTHORIZATION_POLICY_KERNEL
        && plan.method == "GET"
        && plan.path == AUTHORIZATION_POLICY_PATH
        && plan.record_selector == "$"
        && plan.id_field == "id"
        && plan.singleton_fallback_id == AUTHORIZATION_POLICY_FALLBACK_ID
        && plan.max_response_bytes == MAX_RESPONSE_BYTES
        && plan.event_kind == AUTHORIZATION_POLICY_KIND
        && plan.schema_ref == AUTHORIZATION_POLICY_SCHEMA
        && plan.required_payload_fields.is_empty()
        && expected_attributes.iter().all(|required| {
            plan.required_attributes
                .iter()
                .any(|value| value == required)
        });
    if !exact_contract || plan_digest(plan) != plan.plan_digest_sha256 {
        return Err(WorkerError::InvalidPlan);
    }
    Ok(())
}

pub(super) fn plan_digest(plan: &SourceExecutionPlanV1) -> String {
    let mut plan = plan.clone();
    plan.plan_digest_sha256.clear();
    sha256_hex(&plan.encode_to_vec())
}

pub(super) fn result_digest(
    plan_id: &str,
    plan_digest_sha256: &str,
    logical_page_id: &str,
    request_intent_digest: &str,
    provider_id: &str,
    attributes: &BTreeMap<String, String>,
    payload_json: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    for value in [
        plan_id.as_bytes(),
        plan_digest_sha256.as_bytes(),
        logical_page_id.as_bytes(),
        request_intent_digest.as_bytes(),
        provider_id.as_bytes(),
    ] {
        update_length_prefixed(&mut hasher, value);
    }
    for (key, value) in attributes {
        update_length_prefixed(&mut hasher, key.as_bytes());
        update_length_prefixed(&mut hasher, value.as_bytes());
    }
    update_length_prefixed(&mut hasher, payload_json);
    hex_bytes(&hasher.finalize())
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn sha256_hex(value: &[u8]) -> String {
    hex_bytes(&Sha256::digest(value))
}

fn hex_bytes(value: &[u8]) -> String {
    use std::fmt::Write as _;

    value.iter().fold(
        String::with_capacity(value.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}
