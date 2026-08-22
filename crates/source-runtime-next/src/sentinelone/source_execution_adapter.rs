//! SentinelOne `agent` adapter for the canonical source-execution protocol.
//!
//! This module intentionally remains outside the provider facade until the
//! shared `source_execution` module publishes its settled public prost types,
//! closed error type, and digest helpers. It does not define a second wire
//! schema. Adding the module declaration is owned by the shared-runtime change.

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionPlanV1,
    SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1,
    SourceWorkerHttpRequestV1, SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
    canonical_plan_digest, canonical_request_intent_digest, canonical_result_digest,
    validate_and_deduplicate_records, validate_decode_result, validate_execution_context,
    validate_http_request, validate_safe_receipt,
};

use super::{
    SentinelOneError, SentinelOneFamily, SentinelOneFilters, SentinelOneKernel, SentinelOneOutcome,
};

#[path = "source_execution_adapter/error.rs"]
mod error;
#[path = "source_execution_adapter/normalization.rs"]
mod normalization;

use error::SentinelOneAgentAdapterError;
use normalization::normalize_agent_record;

const SOURCE_ID: &str = "sentinelone";
const FAMILY_ID: &str = "agent";
const PROVIDER_KERNEL: &str = "sentinelone.agent";
const PLAN_ID: &str = "source-plan-v1:sentinelone:agent";
const METHOD: &str = "GET";
const PATH: &str = "/web/api/v2.1/agents";
const RECORD_SELECTOR: &str = "$.data[*]";
const ID_FIELD: &str = "id";
const EVENT_KIND: &str = "sentinelone.agent";
const SCHEMA_REF: &str = "sentinelone/agent/v1";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
const PAGE_SIZE: usize = 200;

/// Credential-free adapter for the representative SentinelOne agent family.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SentinelOneAgentSourceExecutionAdapter;

impl SourceExecutionAdapter for SentinelOneAgentSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        FAMILY_ID
    }

    fn provider_kernel(&self) -> &'static str {
        PROVIDER_KERNEL
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let expected = agent_event_id(&context.tenant_id, &record.provider_id)
            .map_err(SourceExecutionError::from)?;
        if record.event_id != expected {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }

    fn plan(
        &self,
        request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
        plan_agent_request(request)
    }

    fn decode(
        &self,
        request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        decode_agent_response(request)
    }
}

fn plan_agent_request(
    request: &SourceWorkerPlanRequestV1,
) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
    let plan = request
        .plan
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    validate_plan(plan).map_err(SourceExecutionError::from)?;
    validate_execution_context(context)?;
    validate_agent_tenant(&context.tenant_id).map_err(SourceExecutionError::from)?;

    let kernel = agent_kernel(plan)?;
    let provider_request = kernel
        .plan(optional_cursor(&context.prior_cursor))
        .map_err(map_kernel_error)
        .map_err(SourceExecutionError::from)?;
    validate_provider_request(plan, &provider_request).map_err(SourceExecutionError::from)?;

    let mut result = SourceWorkerHttpRequestV1 {
        plan_id: plan.plan_id.clone(),
        method: METHOD.to_owned(),
        url: provider_request.url().to_string(),
        accept: provider_request.accept().to_owned(),
        max_response_bytes: plan.max_response_bytes,
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        request_intent_digest: String::new(),
    };
    result.request_intent_digest = canonical_request_intent_digest(plan, context, &result);
    validate_http_request(plan, context, &result)?;
    Ok(result)
}

fn decode_agent_response(
    request: &SourceWorkerDecodeRequestV1,
) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
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

    validate_plan(plan).map_err(SourceExecutionError::from)?;
    validate_execution_context(context)?;
    validate_agent_tenant(&context.tenant_id).map_err(SourceExecutionError::from)?;
    classify_status(request.status_code).map_err(SourceExecutionError::from)?;
    if request.response_body.len() as u64 > plan.max_response_bytes {
        return Err(SourceExecutionError::ResponseTooLarge);
    }
    if request.logical_page_id != context.logical_page_id {
        return Err(SourceExecutionError::MissingExecutionIdentity);
    }
    validate_safe_receipt(
        receipt,
        plan,
        context,
        &request.response_body,
        request.status_code,
        &request.request_intent_digest,
    )?;
    let expected_intent = plan_agent_request(&SourceWorkerPlanRequestV1 {
        plan: Some(plan.clone()),
        context: Some(context.clone()),
    })?
    .request_intent_digest;
    if request.request_intent_digest != expected_intent {
        return Err(SourceExecutionError::InvalidDigest);
    }

    let kernel = agent_kernel(plan)?;
    let provider_request = kernel
        .plan(optional_cursor(&context.prior_cursor))
        .map_err(map_kernel_error)
        .map_err(SourceExecutionError::from)?;
    validate_provider_request(plan, &provider_request).map_err(SourceExecutionError::from)?;
    let SentinelOneOutcome::Page(page) = kernel
        .decode(&provider_request, &request.response_body)
        .map_err(map_kernel_error)
        .map_err(SourceExecutionError::from)?
    else {
        return Err(SourceExecutionError::MalformedResponse);
    };

    let records = page
        .records
        .into_iter()
        .map(|record| normalize_agent_record(record, context))
        .collect::<Result<Vec<_>, _>>()
        .map_err(SourceExecutionError::from)?;
    let records = validate_and_deduplicate_records(records)?;
    let next_cursor = page.next_cursor.unwrap_or_default();
    let result_digest_sha256 = canonical_result_digest(receipt, &next_cursor, &records)?;
    let result = SourceWorkerDecodeResultV1 {
        plan_id: plan.plan_id.clone(),
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: request.request_intent_digest.clone(),
        records,
        next_cursor,
        result_digest_sha256,
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    validate_decode_result(request, &result)?;
    for record in &result.records {
        SentinelOneAgentSourceExecutionAdapter.validate_record_identity(context, record)?;
    }
    Ok(result)
}

fn validate_plan(plan: &SourceExecutionPlanV1) -> Result<(), SentinelOneAgentAdapterError> {
    let expected_attributes = ["family"];
    let expected_payload_fields = ["id"];
    let exact = plan.plan_id == PLAN_ID
        && plan.source_id == SOURCE_ID
        && plan.family_id == FAMILY_ID
        && plan.provider_kernel == PROVIDER_KERNEL
        && plan.method == METHOD
        && plan.path == PATH
        && plan.record_selector == RECORD_SELECTOR
        && plan.id_field == ID_FIELD
        && plan.singleton_fallback_id.is_empty()
        && plan.max_response_bytes == MAX_RESPONSE_BYTES
        && plan.event_kind == EVENT_KIND
        && plan.schema_ref == SCHEMA_REF
        && plan.required_attributes == expected_attributes
        && plan.required_payload_fields == expected_payload_fields
        && canonical_plan_digest(plan) == plan.plan_digest_sha256;
    if !exact {
        return Err(SentinelOneAgentAdapterError::InvalidPlan);
    }
    Ok(())
}

fn validate_provider_request(
    plan: &SourceExecutionPlanV1,
    request: &super::SentinelOneRequest,
) -> Result<(), SentinelOneAgentAdapterError> {
    if request.url().origin().ascii_serialization() != plan.origin
        || request.url().path() != plan.path
        || request.authorization_scheme() != "ApiToken"
        || request.accept() != "application/json"
    {
        return Err(SentinelOneAgentAdapterError::InvalidPlan);
    }
    Ok(())
}

fn agent_kernel(
    plan: &SourceExecutionPlanV1,
) -> Result<SentinelOneKernel, SentinelOneAgentAdapterError> {
    SentinelOneKernel::new(
        &plan.origin,
        SentinelOneFamily::Agent,
        SentinelOneFilters::default(),
        Some(PAGE_SIZE),
    )
    .map_err(map_kernel_error)
}

fn classify_status(status: u32) -> Result<(), SentinelOneAgentAdapterError> {
    match status {
        200 => Ok(()),
        401 => Err(SentinelOneAgentAdapterError::AuthenticationRejected),
        403 => Err(SentinelOneAgentAdapterError::PermissionDenied),
        429 => Err(SentinelOneAgentAdapterError::RateLimited),
        500..=599 => Err(SentinelOneAgentAdapterError::ProviderUnavailable),
        _ => Err(SentinelOneAgentAdapterError::UnexpectedProviderStatus),
    }
}

fn map_kernel_error(error: SentinelOneError) -> SentinelOneAgentAdapterError {
    match error {
        SentinelOneError::InvalidCursor
        | SentinelOneError::ConfiguredAgentCursor
        | SentinelOneError::CursorParentMismatch
        | SentinelOneError::CursorParentRequired => SentinelOneAgentAdapterError::InvalidCursor,
        SentinelOneError::MissingRecordIdentity | SentinelOneError::MissingAgentIdentity => {
            SentinelOneAgentAdapterError::MissingProviderIdentity
        }
        SentinelOneError::DuplicateApplicationIdentity => {
            SentinelOneAgentAdapterError::ConflictingProviderIdentity
        }
        SentinelOneError::InvalidResponse | SentinelOneError::MissingApplicationState => {
            SentinelOneAgentAdapterError::InvalidProviderResponse
        }
        SentinelOneError::InvalidFamily
        | SentinelOneError::InvalidBaseUrl
        | SentinelOneError::InvalidPageSize
        | SentinelOneError::UnsupportedTimeFilter
        | SentinelOneError::UnsupportedActivityFilter
        | SentinelOneError::RequestScopeMismatch => SentinelOneAgentAdapterError::InvalidPlan,
    }
}

fn optional_cursor(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn validate_agent_tenant(tenant_id: &str) -> Result<(), SentinelOneAgentAdapterError> {
    if !safe_event_component(tenant_id) {
        return Err(SentinelOneAgentAdapterError::InvalidExecutionContext);
    }
    Ok(())
}

fn agent_event_id(
    tenant_id: &str,
    provider_id: &str,
) -> Result<String, SentinelOneAgentAdapterError> {
    let event_id = format!(
        "sentinelone-agent-{}-{}",
        tenant_id.trim(),
        provider_id.trim()
    );
    if !safe_event_component(tenant_id)
        || !safe_event_component(provider_id)
        || event_id.len() > 512
    {
        return Err(SentinelOneAgentAdapterError::InvalidEventIdentity);
    }
    Ok(event_id)
}

fn safe_event_component(value: &str) -> bool {
    !value.is_empty()
        && value == value.trim()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

#[cfg(test)]
#[path = "source_execution_adapter_tests.rs"]
mod tests;
