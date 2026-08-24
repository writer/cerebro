//! Closed source-execution adapter for SentinelOne application fanout.

use crate::sentinelone::{
    SentinelOneFamily, SentinelOneFilters, SentinelOneKernel, SentinelOneOutcome,
};
use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionPlanV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
    canonical_plan_digest, canonical_result_digest, validate_and_deduplicate_records,
    validate_decode_result, validate_execution_context, validate_http_request,
    validate_safe_receipt,
};

use super::error::SentinelOneAgentAdapterError;
use super::{
    COMPILED_ORIGIN, MAX_RESPONSE_BYTES, METHOD, PAGE_SIZE, RECORD_SELECTOR, SOURCE_ID,
    classify_status, map_kernel_error,
    normalization::{application_event_id, normalize_application_record},
    optional_cursor, plan_with_kernel, runtime, validate_agent_tenant, validate_provider_request,
};

const FAMILY: SentinelOneFamily = SentinelOneFamily::Application;
const PLAN_ID: &str = "source-plan-v1:sentinelone:application";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SentinelOneApplicationSourceExecutionAdapter;

pub(crate) static SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER:
    SentinelOneApplicationSourceExecutionAdapter = SentinelOneApplicationSourceExecutionAdapter;

impl SentinelOneApplicationSourceExecutionAdapter {
    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let mut plan = SourceExecutionPlanV1 {
            plan_id: PLAN_ID.to_owned(),
            source_id: SOURCE_ID.to_owned(),
            family_id: FAMILY.as_str().to_owned(),
            provider_kernel: FAMILY.provider_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: COMPILED_ORIGIN.to_owned(),
            path: SentinelOneFamily::Agent.path().to_owned(),
            record_selector: RECORD_SELECTOR.to_owned(),
            id_field: String::new(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: FAMILY.provider_kind().to_owned(),
            schema_ref: FAMILY.schema_ref().to_owned(),
            required_attributes: vec!["family".to_owned(), "agent_id".to_owned()],
            required_payload_fields: vec!["agent_id".to_owned()],
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        plan
    }
}

impl SourceExecutionAdapter for SentinelOneApplicationSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        FAMILY.as_str()
    }

    fn provider_kernel(&self) -> &'static str {
        FAMILY.provider_kind()
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let payload: serde_json::Value = serde_json::from_slice(&record.payload_json)
            .map_err(|_| SourceExecutionError::MalformedResponse)?;
        let agent_id = payload
            .get("agent_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let application_id = application_identity(&payload);
        let expected = application_event_id(&context.tenant_id, agent_id, &application_id)
            .map_err(SourceExecutionError::from)?;
        if record.event_id != expected
            || record.attributes.get("agent_id").map(String::as_str) != Some(agent_id)
            || record.provider_id != format!("{agent_id}::{application_id}")
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }

    fn plan(
        &self,
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
        validate_application_plan(plan).map_err(SourceExecutionError::from)?;
        validate_execution_context(context)?;
        validate_agent_tenant(&context.tenant_id).map_err(SourceExecutionError::from)?;
        let kernel = application_kernel(plan, None)?;
        let result = plan_with_kernel(plan, context, &kernel, &plan.origin)?;
        validate_http_request(plan, context, &result)?;
        Ok(result)
    }

    fn plan_v2(
        &self,
        envelope: &SourceWorkerPlanEnvelopeV2,
    ) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
        runtime::plan_application_v2(envelope)
    }

    fn decode(
        &self,
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
        let kernel = application_kernel(plan, None)?;
        let expected = plan_with_kernel(plan, context, &kernel, &plan.origin)?;
        decode_application_response_with_kernel(request, self, &kernel, &plan.origin, &expected)
    }

    fn decode_v2(
        &self,
        envelope: &SourceWorkerDecodeEnvelopeV2,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        runtime::decode_application_v2(envelope, self)
    }
}

pub(super) fn decode_application_response_with_kernel(
    request: &SourceWorkerDecodeRequestV1,
    adapter: &SentinelOneApplicationSourceExecutionAdapter,
    kernel: &SentinelOneKernel,
    allowed_origin: &str,
    expected: &SourceWorkerHttpRequestV1,
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
    validate_application_plan(plan).map_err(SourceExecutionError::from)?;
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
    if request.request_intent_digest != expected.request_intent_digest {
        return Err(SourceExecutionError::InvalidDigest);
    }
    let provider_request = kernel
        .plan(optional_cursor(&context.prior_cursor))
        .map_err(map_kernel_error)
        .map_err(SourceExecutionError::from)?;
    validate_provider_request(plan, allowed_origin, &provider_request)
        .map_err(SourceExecutionError::from)?;

    let outcome = kernel
        .decode(&provider_request, &request.response_body)
        .map_err(map_kernel_error)
        .map_err(SourceExecutionError::from)?;
    let (records, next_cursor) = match outcome {
        SentinelOneOutcome::Request(followup) => {
            validate_provider_request(plan, allowed_origin, &followup)
                .map_err(SourceExecutionError::from)?;
            let cursor = followup
                .continuation_cursor()
                .map_err(map_kernel_error)
                .map_err(SourceExecutionError::from)?
                .ok_or(SourceExecutionError::InvalidCursor)?;
            (Vec::new(), cursor)
        }
        SentinelOneOutcome::Page(page) => {
            let records = page
                .records
                .into_iter()
                .map(|record| normalize_application_record(record, context))
                .collect::<Result<Vec<_>, _>>()
                .map_err(SourceExecutionError::from)?;
            (
                validate_and_deduplicate_records(records)?,
                page.next_cursor.unwrap_or_default(),
            )
        }
    };
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
        adapter.validate_record_identity(context, record)?;
    }
    Ok(result)
}

pub(super) fn validate_application_plan(
    plan: &SourceExecutionPlanV1,
) -> Result<(), SentinelOneAgentAdapterError> {
    if plan != &SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER.compiled_plan() {
        return Err(SentinelOneAgentAdapterError::InvalidPlan);
    }
    Ok(())
}

fn application_kernel(
    plan: &SourceExecutionPlanV1,
    agent_id: Option<String>,
) -> Result<SentinelOneKernel, SourceExecutionError> {
    SentinelOneKernel::new(
        &plan.origin,
        FAMILY,
        SentinelOneFilters {
            agent_id,
            ..SentinelOneFilters::default()
        },
        Some(PAGE_SIZE),
    )
    .map_err(map_kernel_error)
    .map_err(SourceExecutionError::from)
}

fn application_identity(payload: &serde_json::Value) -> String {
    let parts = ["publisher", "name", "version"]
        .into_iter()
        .filter_map(|name| payload.get(name).and_then(serde_json::Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.replace(' ', "_"))
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "unknown".to_owned()
    } else {
        parts.join("::")
    }
}
