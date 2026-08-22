use std::collections::{BTreeMap, HashMap};

use prost::Message;
use sha2::{Digest, Sha256};

use super::{
    error::SourceExecutionError,
    wire::{
        SourceExecutionPlanV1, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
        SourceWorkerExecutionContextV1, SourceWorkerHttpRequestV1, SourceWorkerRecordV1,
        SourceWorkerSafeReceiptV1,
    },
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

/// Maximum bytes accepted for tenant, runtime, and page identifiers.
pub const MAX_CONTEXT_IDENTIFIER_BYTES: usize = 256;
/// Maximum bytes accepted for one opaque continuation cursor.
pub const MAX_CURSOR_BYTES: usize = 4096;
/// Maximum normalized records accepted from one bounded page.
pub const MAX_RECORDS_PER_RESULT: usize = 1000;
/// Maximum canonical JSON bytes accepted across one normalized page.
pub const MAX_RECORD_PAYLOAD_BYTES: usize = 8 << 20;

pub(super) fn validate_plan(plan: &SourceExecutionPlanV1) -> Result<(), SourceExecutionError> {
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
    if !exact_contract || canonical_plan_digest(plan) != plan.plan_digest_sha256 {
        return Err(SourceExecutionError::InvalidPlan);
    }
    Ok(())
}

/// Returns the lowercase SHA-256 of a plan with its digest field cleared.
pub fn canonical_plan_digest(plan: &SourceExecutionPlanV1) -> String {
    let mut canonical = plan.clone();
    canonical.plan_digest_sha256.clear();
    sha256_hex(&canonical.encode_to_vec())
}

/// Validates trusted host identity, cursor, fencing generations, and timestamp.
pub fn validate_execution_context(
    context: &SourceWorkerExecutionContextV1,
) -> Result<(), SourceExecutionError> {
    if !bounded_text(&context.tenant_id, MAX_CONTEXT_IDENTIFIER_BYTES)
        || !safe_identifier(&context.runtime_id, MAX_CONTEXT_IDENTIFIER_BYTES)
        || !safe_identifier(&context.logical_page_id, MAX_CONTEXT_IDENTIFIER_BYTES)
        || context.runtime_generation == 0
        || context.lease_generation == 0
        || context.observed_at_unix_millis <= 0
    {
        return Err(SourceExecutionError::InvalidExecutionContext);
    }
    validate_cursor(&context.prior_cursor)
}

/// Returns the request-intent digest over the exact plan, context, and request.
pub fn canonical_request_intent_digest(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    request: &SourceWorkerHttpRequestV1,
) -> String {
    let mut canonical_request = request.clone();
    canonical_request.request_intent_digest.clear();
    let mut hasher = Sha256::new();
    for value in [
        plan.encode_to_vec(),
        context.encode_to_vec(),
        canonical_request.encode_to_vec(),
    ] {
        update_length_prefixed(&mut hasher, &value);
    }
    hex_bytes(&hasher.finalize())
}

/// Validates an adapter request against the compiled plan, context, and origin.
pub fn validate_http_request(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    request: &SourceWorkerHttpRequestV1,
) -> Result<(), SourceExecutionError> {
    validate_execution_context(context)?;
    if request.plan_id != plan.plan_id
        || request.method != plan.method
        || request.max_response_bytes != plan.max_response_bytes
        || request.plan_digest_sha256 != plan.plan_digest_sha256
        || canonical_plan_digest(plan) != plan.plan_digest_sha256
    {
        return Err(SourceExecutionError::InvalidPlan);
    }
    let allowed_origin =
        reqwest::Url::parse(&plan.origin).map_err(|_| SourceExecutionError::InvalidPlan)?;
    let request_url =
        reqwest::Url::parse(&request.url).map_err(|_| SourceExecutionError::EgressDenied)?;
    if allowed_origin.scheme() != "https"
        || allowed_origin.username() != ""
        || allowed_origin.password().is_some()
        || allowed_origin.query().is_some()
        || allowed_origin.fragment().is_some()
        || allowed_origin.path() != "/"
        || request_url.scheme() != allowed_origin.scheme()
        || request_url.host_str() != allowed_origin.host_str()
        || request_url.port_or_known_default() != allowed_origin.port_or_known_default()
        || request_url.username() != ""
        || request_url.password().is_some()
    {
        return Err(SourceExecutionError::EgressDenied);
    }
    if !lower_sha256(&request.request_intent_digest)
        || request.request_intent_digest != canonical_request_intent_digest(plan, context, request)
    {
        return Err(SourceExecutionError::InvalidDigest);
    }
    Ok(())
}

/// Validates an opaque continuation cursor without interpreting provider data.
pub fn validate_cursor(cursor: &str) -> Result<(), SourceExecutionError> {
    if cursor.len() > MAX_CURSOR_BYTES
        || cursor
            .chars()
            .any(|character| character.is_control() || character == '\u{7f}')
    {
        return Err(SourceExecutionError::InvalidCursor);
    }
    Ok(())
}

/// Validates a provider-safe receipt against trusted context and response bytes.
pub fn validate_safe_receipt(
    receipt: &SourceWorkerSafeReceiptV1,
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    response_body: &[u8],
    status_code: u32,
    request_intent_digest: &str,
) -> Result<(), SourceExecutionError> {
    validate_execution_context(context)?;
    if receipt.tenant_id != context.tenant_id || receipt.runtime_id != context.runtime_id {
        return Err(SourceExecutionError::TenantMismatch);
    }
    if receipt.runtime_generation != context.runtime_generation
        || receipt.lease_generation != context.lease_generation
    {
        return Err(SourceExecutionError::StaleGeneration);
    }
    if receipt.logical_page_id != context.logical_page_id
        || receipt.observed_at_unix_millis != context.observed_at_unix_millis
        || !safe_identifier(&receipt.credential_operation, MAX_CONTEXT_IDENTIFIER_BYTES)
    {
        return Err(SourceExecutionError::MissingExecutionIdentity);
    }
    if !lower_sha256(&plan.plan_digest_sha256)
        || !lower_sha256(request_intent_digest)
        || !lower_sha256(&receipt.response_sha256)
        || receipt.plan_digest_sha256 != plan.plan_digest_sha256
        || receipt.request_intent_digest != request_intent_digest
        || receipt.status_code != status_code
        || receipt.response_bytes != response_body.len() as u64
        || receipt.response_sha256 != response_digest(response_body)
    {
        return Err(SourceExecutionError::InvalidDigest);
    }
    Ok(())
}

/// Returns the lowercase SHA-256 of provider response bytes.
pub fn response_digest(value: &[u8]) -> String {
    sha256_hex(value)
}

/// Builds a deterministic event identity scoped to source, family, and tenant.
pub fn tenant_scoped_event_id(
    source_id: &str,
    family_id: &str,
    tenant_id: &str,
    provider_id: &str,
) -> Result<String, SourceExecutionError> {
    if !safe_identifier(source_id, 128)
        || !safe_identifier(family_id, 128)
        || !bounded_text(tenant_id, MAX_CONTEXT_IDENTIFIER_BYTES)
        || !bounded_text(provider_id, MAX_CONTEXT_IDENTIFIER_BYTES)
    {
        return Err(SourceExecutionError::MissingStableIdentity);
    }
    let mut hasher = Sha256::new();
    for value in [source_id, family_id, tenant_id, provider_id] {
        update_length_prefixed(&mut hasher, value.as_bytes());
    }
    Ok(format!(
        "{source_id}.{family_id}.{}",
        hex_bytes(&hasher.finalize())
    ))
}

/// Collapses exact duplicate events and rejects conflicting duplicate identities.
pub fn validate_and_deduplicate_records(
    records: Vec<SourceWorkerRecordV1>,
) -> Result<Vec<SourceWorkerRecordV1>, SourceExecutionError> {
    if records.len() > MAX_RECORDS_PER_RESULT {
        return Err(SourceExecutionError::ResultTooLarge);
    }
    let mut total_payload_bytes = 0_usize;
    let mut first_by_event = HashMap::<String, usize>::new();
    let mut deduplicated = Vec::with_capacity(records.len());
    for record in records {
        validate_record(&record)?;
        total_payload_bytes = total_payload_bytes
            .checked_add(record.payload_json.len())
            .ok_or(SourceExecutionError::ResultTooLarge)?;
        if total_payload_bytes > MAX_RECORD_PAYLOAD_BYTES {
            return Err(SourceExecutionError::ResultTooLarge);
        }
        if let Some(index) = first_by_event.get(&record.event_id).copied() {
            if deduplicated[index] != record {
                return Err(SourceExecutionError::DuplicateConflict);
            }
            continue;
        }
        first_by_event.insert(record.event_id.clone(), deduplicated.len());
        deduplicated.push(record);
    }
    Ok(deduplicated)
}

/// Returns the result digest over safe receipt, cursor, and canonical records.
pub fn canonical_result_digest(
    receipt: &SourceWorkerSafeReceiptV1,
    next_cursor: &str,
    records: &[SourceWorkerRecordV1],
) -> Result<String, SourceExecutionError> {
    validate_cursor(next_cursor)?;
    if records.len() > MAX_RECORDS_PER_RESULT {
        return Err(SourceExecutionError::ResultTooLarge);
    }
    let mut hasher = Sha256::new();
    for value in [
        receipt.plan_digest_sha256.as_bytes(),
        receipt.tenant_id.as_bytes(),
        receipt.runtime_id.as_bytes(),
        receipt.logical_page_id.as_bytes(),
        receipt.request_intent_digest.as_bytes(),
    ] {
        update_length_prefixed(&mut hasher, value);
    }
    update_length_prefixed(&mut hasher, &receipt.runtime_generation.to_be_bytes());
    update_length_prefixed(&mut hasher, &receipt.lease_generation.to_be_bytes());
    update_length_prefixed(&mut hasher, receipt.credential_operation.as_bytes());
    update_length_prefixed(&mut hasher, &(receipt.status_code as u64).to_be_bytes());
    update_length_prefixed(&mut hasher, &receipt.response_bytes.to_be_bytes());
    update_length_prefixed(&mut hasher, receipt.response_sha256.as_bytes());
    update_length_prefixed(&mut hasher, &receipt.observed_at_unix_millis.to_be_bytes());
    update_length_prefixed(&mut hasher, next_cursor.as_bytes());
    update_length_prefixed(&mut hasher, &(records.len() as u64).to_be_bytes());
    let mut total_payload_bytes = 0_usize;
    for record in records {
        validate_record(record)?;
        total_payload_bytes = total_payload_bytes
            .checked_add(record.payload_json.len())
            .ok_or(SourceExecutionError::ResultTooLarge)?;
        if total_payload_bytes > MAX_RECORD_PAYLOAD_BYTES {
            return Err(SourceExecutionError::ResultTooLarge);
        }
        update_record_digest(&mut hasher, record);
    }
    Ok(hex_bytes(&hasher.finalize()))
}

/// Validates a decoded page before the trusted host attempts append admission.
pub fn validate_decode_result(
    request: &SourceWorkerDecodeRequestV1,
    result: &SourceWorkerDecodeResultV1,
) -> Result<(), SourceExecutionError> {
    let plan = request
        .plan
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    let receipt = request
        .receipt
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    validate_safe_receipt(
        receipt,
        plan,
        context,
        &request.response_body,
        request.status_code,
        &request.request_intent_digest,
    )?;
    validate_cursor(&result.next_cursor)?;
    if result.plan_id != plan.plan_id
        || result.plan_digest_sha256 != plan.plan_digest_sha256
        || result.logical_page_id != context.logical_page_id
        || result.request_intent_digest != request.request_intent_digest
        || result.tenant_id != context.tenant_id
        || result.runtime_id != context.runtime_id
    {
        return Err(SourceExecutionError::TenantMismatch);
    }
    if result.runtime_generation != context.runtime_generation
        || result.lease_generation != context.lease_generation
    {
        return Err(SourceExecutionError::StaleGeneration);
    }
    if result.observed_at_unix_millis != context.observed_at_unix_millis {
        return Err(SourceExecutionError::MissingExecutionIdentity);
    }
    let deduplicated = validate_and_deduplicate_records(result.records.clone())?;
    if deduplicated != result.records {
        return Err(SourceExecutionError::DuplicateConflict);
    }
    for record in &result.records {
        if record
            .attributes
            .get("tenant_id")
            .is_some_and(|tenant_id| tenant_id != &context.tenant_id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        if plan.required_attributes.iter().any(|required| {
            record
                .attributes
                .get(required)
                .is_none_or(|value| value.trim().is_empty())
        }) {
            return Err(SourceExecutionError::EventContractRejected);
        }
        let payload = serde_json::from_slice::<serde_json::Value>(&record.payload_json)
            .map_err(|_| SourceExecutionError::MalformedResponse)?;
        if plan
            .required_payload_fields
            .iter()
            .any(|required| payload.get(required).is_none_or(serde_json::Value::is_null))
        {
            return Err(SourceExecutionError::EventContractRejected);
        }
    }
    if !lower_sha256(&result.result_digest_sha256)
        || result.result_digest_sha256
            != canonical_result_digest(receipt, &result.next_cursor, &result.records)?
    {
        return Err(SourceExecutionError::InvalidDigest);
    }
    Ok(())
}

fn validate_record(record: &SourceWorkerRecordV1) -> Result<(), SourceExecutionError> {
    if !bounded_text(&record.provider_id, MAX_CONTEXT_IDENTIFIER_BYTES)
        || !safe_identifier(&record.event_id, 512)
        || record.occurred_at_unix_millis <= 0
    {
        return Err(SourceExecutionError::MissingStableIdentity);
    }
    if record.payload_json.len() > MAX_RECORD_PAYLOAD_BYTES {
        return Err(SourceExecutionError::ResultTooLarge);
    }
    serde_json::from_slice::<serde_json::Value>(&record.payload_json)
        .map_err(|_| SourceExecutionError::MalformedResponse)?;
    Ok(())
}

fn update_record_digest(hasher: &mut Sha256, record: &SourceWorkerRecordV1) {
    let attributes = record.attributes.iter().collect::<BTreeMap<_, _>>();
    for value in [record.provider_id.as_bytes(), record.event_id.as_bytes()] {
        update_length_prefixed(hasher, value);
    }
    update_length_prefixed(hasher, &record.occurred_at_unix_millis.to_be_bytes());
    update_length_prefixed(hasher, &(attributes.len() as u64).to_be_bytes());
    for (key, value) in attributes {
        update_length_prefixed(hasher, key.as_bytes());
        update_length_prefixed(hasher, value.as_bytes());
    }
    update_length_prefixed(hasher, &record.payload_json);
}

pub(super) fn lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn bounded_text(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
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
