use std::collections::{BTreeMap, HashMap};

use prost::Message;
use sha2::{Digest, Sha256};

use super::{
    error::SourceExecutionError,
    wire::{
        SourceExecutionPlanV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1,
        SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
        SourceWorkerHttpRequestV1, SourceWorkerRecordV1, SourceWorkerRuntimeMetadataV2,
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
/// Maximum public configuration entries carried into one execution context.
pub const MAX_PUBLIC_CONFIG_ENTRIES: usize = 32;
/// Maximum bytes across public configuration keys and values.
pub const MAX_PUBLIC_CONFIG_BYTES: usize = 16 << 10;
/// Maximum credential-free request body emitted by an adapter.
pub const MAX_REQUEST_BODY_BYTES: usize = 1 << 20;
/// Maximum safe request or response header entries.
pub const MAX_SAFE_HEADER_ENTRIES: usize = 32;
/// Maximum bytes across safe header names and values.
pub const MAX_SAFE_HEADER_BYTES: usize = 16 << 10;

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

/// Validates public configuration before it crosses the credential-free wire.
pub fn validate_public_config(
    config: &HashMap<String, String>,
) -> Result<(), SourceExecutionError> {
    if config.len() > MAX_PUBLIC_CONFIG_ENTRIES {
        return Err(SourceExecutionError::InvalidExecutionContext);
    }
    let mut total = 0_usize;
    for (key, value) in config {
        let lower = key.to_ascii_lowercase();
        if key != &lower
            || !safe_identifier(key, 64)
            || sensitive_config_key(&lower)
            || value.len() > MAX_CURSOR_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(SourceExecutionError::InvalidExecutionContext);
        }
        total = total
            .checked_add(key.len() + value.len())
            .ok_or(SourceExecutionError::InvalidExecutionContext)?;
    }
    if total > MAX_PUBLIC_CONFIG_BYTES {
        return Err(SourceExecutionError::InvalidExecutionContext);
    }
    Ok(())
}

/// Validates additive durable-resume metadata without interpreting a provider checkpoint.
pub fn validate_runtime_metadata(
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<(), SourceExecutionError> {
    if metadata.prior_terminal_watermark_unix_millis < 0 {
        return Err(SourceExecutionError::InvalidExecutionContext);
    }
    validate_cursor(&metadata.prior_checkpoint)?;
    validate_public_config(&metadata.public_config)
}

/// Validates a metadata-aware HTTP operation while preserving the stable v1 request contract.
pub fn validate_http_execution(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    execution: &SourceWorkerHttpExecutionV2,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<(), SourceExecutionError> {
    let request = execution
        .request
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    validate_runtime_metadata(metadata)?;
    validate_http_request_for_origin(plan, context, request, &execution.allowed_origin)?;
    validate_declared_headers(&execution.declared_headers)?;
    if execution.body.len() > MAX_REQUEST_BODY_BYTES
        || (request.method == "GET" && !execution.body.is_empty())
        || !matches!(request.method.as_str(), "GET" | "POST")
        || !matches!(
            execution.credential_operation.as_str(),
            "source.bearer" | "jumpcloud.x_api_key" | "sentinelone.api_token" | "twilio.basic"
        )
    {
        return Err(SourceExecutionError::InvalidPlan);
    }
    if !lower_sha256(&execution.execution_intent_digest_sha256)
        || execution.execution_intent_digest_sha256
            != canonical_http_execution_digest(plan, context, metadata, execution)
    {
        return Err(SourceExecutionError::InvalidDigest);
    }
    Ok(())
}

/// Binds public runtime metadata, request body, and declared headers to one operation.
pub fn canonical_http_execution_digest(
    _plan: &SourceExecutionPlanV1,
    _context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    execution: &SourceWorkerHttpExecutionV2,
) -> String {
    let mut hasher = Sha256::new();
    update_length_prefixed(&mut hasher, b"source-worker-http-execution-v2");
    if let Some(request) = &execution.request {
        update_length_prefixed(&mut hasher, request.request_intent_digest.as_bytes());
    } else {
        update_length_prefixed(&mut hasher, b"");
    }
    update_length_prefixed(
        &mut hasher,
        &metadata.prior_terminal_watermark_unix_millis.to_be_bytes(),
    );
    update_length_prefixed(&mut hasher, metadata.prior_checkpoint.as_bytes());
    update_canonical_map(&mut hasher, &metadata.public_config);
    update_length_prefixed(&mut hasher, &execution.body);
    update_canonical_map(&mut hasher, &execution.declared_headers);
    update_length_prefixed(&mut hasher, execution.credential_operation.as_bytes());
    update_length_prefixed(&mut hasher, execution.allowed_origin.as_bytes());
    hex_bytes(&hasher.finalize())
}

/// Validates the host-only response metadata before a provider adapter sees it.
pub fn validate_decode_envelope(
    envelope: &SourceWorkerDecodeEnvelopeV2,
) -> Result<(), SourceExecutionError> {
    let request = envelope
        .request
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let metadata = envelope
        .metadata
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    validate_runtime_metadata(metadata)?;
    validate_response_headers(&envelope.response_headers)?;
    if !envelope.response_headers_sha256.is_empty()
        && (!lower_sha256(&envelope.response_headers_sha256)
            || envelope.response_headers_sha256
                != canonical_response_headers_digest(&envelope.response_headers)?)
    {
        return Err(SourceExecutionError::InvalidDigest);
    }
    if !lower_sha256(&envelope.execution_intent_digest_sha256) {
        return Err(SourceExecutionError::InvalidDigest);
    }
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    validate_execution_context(context)
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
    validate_http_request_for_origin(plan, context, request, &plan.origin)
}

fn validate_http_request_for_origin(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    request: &SourceWorkerHttpRequestV1,
    allowed_origin: &str,
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
        reqwest::Url::parse(allowed_origin).map_err(|_| SourceExecutionError::InvalidPlan)?;
    let request_url =
        reqwest::Url::parse(&request.url).map_err(|_| SourceExecutionError::EgressDenied)?;
    if allowed_origin.scheme() != "https"
        || allowed_origin.username() != ""
        || allowed_origin.password().is_some()
        || allowed_origin.query().is_some()
        || allowed_origin.fragment().is_some()
        || request_url.scheme() != allowed_origin.scheme()
        || request_url.host_str() != allowed_origin.host_str()
        || request_url.port_or_known_default() != allowed_origin.port_or_known_default()
        || request_url.username() != ""
        || request_url.password().is_some()
        || !origin_path_contains(&allowed_origin, &request_url)
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

fn origin_path_contains(origin: &reqwest::Url, request: &reqwest::Url) -> bool {
    let prefix = origin.path().trim_end_matches('/');
    prefix.is_empty()
        || request.path() == prefix
        || request
            .path()
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
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

/// Returns the digest of a canonical, bounded response-header map.
pub fn canonical_response_headers_digest(
    headers: &HashMap<String, String>,
) -> Result<String, SourceExecutionError> {
    validate_response_headers(headers)?;
    let mut hasher = Sha256::new();
    let ordered = headers.iter().collect::<BTreeMap<_, _>>();
    update_length_prefixed(&mut hasher, &(ordered.len() as u64).to_be_bytes());
    for (key, value) in ordered {
        update_length_prefixed(&mut hasher, key.as_bytes());
        update_length_prefixed(&mut hasher, value.as_bytes());
    }
    Ok(hex_bytes(&hasher.finalize()))
}

/// Validates public request headers without allowing credential-bearing names.
pub fn validate_declared_headers(
    headers: &HashMap<String, String>,
) -> Result<(), SourceExecutionError> {
    validate_header_map(headers, false)
}

/// Validates the closed provider-safe response metadata surface.
pub fn validate_response_headers(
    headers: &HashMap<String, String>,
) -> Result<(), SourceExecutionError> {
    validate_header_map(headers, true)
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
        if plan.required_payload_fields.iter().any(|required| {
            required_payload_value(&payload, required).is_none_or(serde_json::Value::is_null)
        }) {
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

fn required_payload_value<'a>(
    payload: &'a serde_json::Value,
    required: &str,
) -> Option<&'a serde_json::Value> {
    required
        .split('.')
        .try_fold(payload, |value, segment| value.get(segment))
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

fn validate_header_map(
    headers: &HashMap<String, String>,
    response: bool,
) -> Result<(), SourceExecutionError> {
    if headers.len() > MAX_SAFE_HEADER_ENTRIES {
        return Err(SourceExecutionError::ResultTooLarge);
    }
    let mut total = 0_usize;
    for (name, value) in headers {
        let lower = name.to_ascii_lowercase();
        if name != &lower
            || reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
            || value.len() > MAX_CURSOR_BYTES
            || value
                .chars()
                .any(|character| character == '\r' || character == '\n')
            || sensitive_header_name(&lower)
            || (!response && !safe_declared_header_name(&lower))
            || (response && !safe_response_header_name(&lower))
        {
            return Err(SourceExecutionError::InvalidExecutionContext);
        }
        total = total
            .checked_add(name.len() + value.len())
            .ok_or(SourceExecutionError::ResultTooLarge)?;
    }
    if total > MAX_SAFE_HEADER_BYTES {
        return Err(SourceExecutionError::ResultTooLarge);
    }
    Ok(())
}

fn safe_declared_header_name(name: &str) -> bool {
    matches!(name, "content-type" | "x-org-id")
}

fn sensitive_config_key(key: &str) -> bool {
    [
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "cookie",
        "credential",
        "password",
        "private_key",
        "secret",
        "token",
    ]
    .iter()
    .any(|fragment| key.contains(fragment))
}

fn sensitive_header_name(name: &str) -> bool {
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "www-authenticate"
            | "proxy-authenticate"
            | "x-api-key"
            | "api-key"
            | "x-auth-token"
            | "x-access-token"
            | "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
    )
}

fn safe_response_header_name(name: &str) -> bool {
    matches!(
        name,
        "content-type"
            | "date"
            | "etag"
            | "last-modified"
            | "link"
            | "retry-after"
            | "x-limit"
            | "x-result-count"
            | "x-search-after"
            | "x-search_after"
    ) || name.starts_with("ratelimit-")
        || name.starts_with("x-ratelimit-")
        || name.starts_with("x-next-")
        || name.starts_with("x-page-")
        || name.starts_with("x-pagination-")
        || name.starts_with("x-total-")
}

fn update_length_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn update_canonical_map(hasher: &mut Sha256, values: &HashMap<String, String>) {
    let ordered = values.iter().collect::<BTreeMap<_, _>>();
    update_length_prefixed(hasher, &(ordered.len() as u64).to_be_bytes());
    for (key, value) in ordered {
        update_length_prefixed(hasher, key.as_bytes());
        update_length_prefixed(hasher, value.as_bytes());
    }
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

#[cfg(test)]
mod tests {
    use super::required_payload_value;

    #[test]
    fn required_payload_paths_traverse_nested_objects_and_fail_closed() {
        let payload = serde_json::json!({"to": {"id": "member-1", "missing": null}});
        assert_eq!(
            required_payload_value(&payload, "to.id").and_then(serde_json::Value::as_str),
            Some("member-1")
        );
        assert!(required_payload_value(&payload, "to.absent").is_none());
        assert!(
            required_payload_value(&payload, "to.missing").is_some_and(serde_json::Value::is_null)
        );
        assert!(required_payload_value(&payload, "to.id.value").is_none());
    }
}
