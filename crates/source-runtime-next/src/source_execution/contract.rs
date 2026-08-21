use std::collections::BTreeMap;

use prost::Message;
use sha2::{Digest, Sha256};

use super::{
    error::WorkerError,
    wire::{SourceExecutionPlanV1, SourceWorkerSafeReceiptV1},
};

pub(super) const AZURE_SOURCE_ID: &str = "azure";
pub(super) const AUTHORIZATION_POLICY_FAMILY: &str = "authorization_policy";
pub(super) const AUTHORIZATION_POLICY_KERNEL: &str = "azure.authorization_policy";
pub(super) const AUTHORIZATION_POLICY_PATH: &str = "/v1.0/policies/authorizationPolicy";
pub(super) const AUTHORIZATION_POLICY_FALLBACK_ID: &str = "authorizationPolicy";
pub(super) const AUTHORIZATION_POLICY_KIND: &str = "azure.authorization_policy";
pub(super) const AUTHORIZATION_POLICY_SCHEMA: &str = "azure/authorization_policy/v1";
pub(super) const MAX_RESPONSE_BYTES: u64 = 8 << 20;
pub(super) const GRAPH_ORIGIN: &str = "https://graph.microsoft.com";

pub(super) fn validate_plan(plan: &SourceExecutionPlanV1) -> Result<(), WorkerError> {
    let expected_attributes = [
        "family",
        "resource_id",
        "resource_name",
        "resource_provider",
        "resource_type",
    ];
    let expected_payload_fields = ["id"];
    let exact_contract = plan.plan_id == "source-plan-v1:azure:authorization_policy"
        && plan.source_id == AZURE_SOURCE_ID
        && plan.family_id == AUTHORIZATION_POLICY_FAMILY
        && plan.provider_kernel == AUTHORIZATION_POLICY_KERNEL
        && plan.origin == GRAPH_ORIGIN
        && plan.method == "GET"
        && plan.path == AUTHORIZATION_POLICY_PATH
        && plan.record_selector == "$"
        && plan.id_field == "id"
        && plan.singleton_fallback_id == AUTHORIZATION_POLICY_FALLBACK_ID
        && plan.max_response_bytes == MAX_RESPONSE_BYTES
        && plan.event_kind == AUTHORIZATION_POLICY_KIND
        && plan.schema_ref == AUTHORIZATION_POLICY_SCHEMA
        && plan.required_attributes == expected_attributes
        && plan.required_payload_fields == expected_payload_fields;
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
    receipt: &SourceWorkerSafeReceiptV1,
    next_cursor: &str,
    provider_id: &str,
    attributes: &BTreeMap<String, String>,
    payload_json: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    let runtime_generation = receipt.runtime_generation.to_be_bytes();
    let lease_generation = receipt.lease_generation.to_be_bytes();
    let status_code = (receipt.status_code as u64).to_be_bytes();
    let response_bytes = receipt.response_bytes.to_be_bytes();
    let record_count = 1_u64.to_be_bytes();
    let attribute_count = (attributes.len() as u64).to_be_bytes();
    for value in [
        receipt.plan_digest_sha256.as_bytes(),
        receipt.logical_page_id.as_bytes(),
        receipt.request_intent_digest.as_bytes(),
        runtime_generation.as_slice(),
        lease_generation.as_slice(),
        receipt.credential_operation.as_bytes(),
        status_code.as_slice(),
        response_bytes.as_slice(),
        receipt.response_sha256.as_bytes(),
        next_cursor.as_bytes(),
        record_count.as_slice(),
        provider_id.as_bytes(),
        attribute_count.as_slice(),
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

pub(super) fn response_digest(value: &[u8]) -> String {
    sha256_hex(value)
}

pub(super) fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
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
