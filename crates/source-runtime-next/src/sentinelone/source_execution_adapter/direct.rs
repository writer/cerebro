//! Closed source-execution adapters for directly paginated SentinelOne families.

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

use super::{
    COMPILED_ORIGIN, ID_FIELD, MAX_RESPONSE_BYTES, METHOD, PAGE_SIZE, RECORD_SELECTOR, SOURCE_ID,
    classify_status, error::SentinelOneAgentAdapterError, map_kernel_error,
    normalization::normalize_direct_record, optional_cursor, plan_with_kernel, runtime,
    validate_agent_tenant, validate_provider_request,
};

/// One directly paginated SentinelOne family promoted into the closed runtime.
#[derive(Clone, Copy, Debug)]
pub(crate) struct SentinelOneDirectSourceExecutionAdapter {
    family: SentinelOneFamily,
}

impl SentinelOneDirectSourceExecutionAdapter {
    const fn new(family: SentinelOneFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:sentinelone:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: self.family.provider_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: COMPILED_ORIGIN.to_owned(),
            path: self.family.path().to_owned(),
            record_selector: RECORD_SELECTOR.to_owned(),
            id_field: ID_FIELD.to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: self.family.provider_kind().to_owned(),
            schema_ref: self.family.schema_ref().to_owned(),
            required_attributes: vec!["family".to_owned()],
            required_payload_fields: vec!["id".to_owned()],
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        plan
    }
}

pub(crate) static SENTINELONE_DIRECT_SOURCE_EXECUTION_ADAPTERS:
    [SentinelOneDirectSourceExecutionAdapter; 5] = [
    SentinelOneDirectSourceExecutionAdapter::new(SentinelOneFamily::Activity),
    SentinelOneDirectSourceExecutionAdapter::new(SentinelOneFamily::Exclusion),
    SentinelOneDirectSourceExecutionAdapter::new(SentinelOneFamily::Group),
    SentinelOneDirectSourceExecutionAdapter::new(SentinelOneFamily::Site),
    SentinelOneDirectSourceExecutionAdapter::new(SentinelOneFamily::Threat),
];

impl SourceExecutionAdapter for SentinelOneDirectSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        self.family.as_str()
    }

    fn provider_kernel(&self) -> &'static str {
        self.family.provider_kind()
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let expected = direct_event_id(self.family, &context.tenant_id, &record.provider_id)
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
        plan_direct_request(request, self.family)
    }

    fn plan_v2(
        &self,
        envelope: &SourceWorkerPlanEnvelopeV2,
    ) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
        runtime::plan_direct_v2(envelope, self.family)
    }

    fn decode(
        &self,
        request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        decode_direct_response(request, self.family, self)
    }

    fn decode_v2(
        &self,
        envelope: &SourceWorkerDecodeEnvelopeV2,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        runtime::decode_direct_v2(envelope, self.family, self)
    }
}

fn plan_direct_request(
    request: &SourceWorkerPlanRequestV1,
    family: SentinelOneFamily,
) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
    let plan = request
        .plan
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    validate_direct_plan(plan, family).map_err(SourceExecutionError::from)?;
    validate_execution_context(context)?;
    validate_agent_tenant(&context.tenant_id).map_err(SourceExecutionError::from)?;
    let kernel = direct_kernel(plan, family)?;
    let result = plan_with_kernel(plan, context, &kernel, &plan.origin)?;
    validate_http_request(plan, context, &result)?;
    Ok(result)
}

fn decode_direct_response(
    request: &SourceWorkerDecodeRequestV1,
    family: SentinelOneFamily,
    adapter: &SentinelOneDirectSourceExecutionAdapter,
) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
    let plan = request
        .plan
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    let kernel = direct_kernel(plan, family)?;
    let expected = plan_with_kernel(plan, context, &kernel, &plan.origin)?;
    decode_direct_response_with_kernel(request, family, adapter, &kernel, &plan.origin, &expected)
}

pub(super) fn decode_direct_response_with_kernel(
    request: &SourceWorkerDecodeRequestV1,
    family: SentinelOneFamily,
    adapter: &SentinelOneDirectSourceExecutionAdapter,
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
    validate_direct_plan(plan, family).map_err(SourceExecutionError::from)?;
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
        .map(|record| normalize_direct_record(record, context, family))
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
        adapter.validate_record_identity(context, record)?;
    }
    Ok(result)
}

pub(super) fn validate_direct_plan(
    plan: &SourceExecutionPlanV1,
    family: SentinelOneFamily,
) -> Result<(), SentinelOneAgentAdapterError> {
    if plan != &SentinelOneDirectSourceExecutionAdapter::new(family).compiled_plan() {
        return Err(SentinelOneAgentAdapterError::InvalidPlan);
    }
    Ok(())
}

fn direct_kernel(
    plan: &SourceExecutionPlanV1,
    family: SentinelOneFamily,
) -> Result<SentinelOneKernel, SourceExecutionError> {
    SentinelOneKernel::new(
        &plan.origin,
        family,
        SentinelOneFilters::default(),
        Some(PAGE_SIZE),
    )
    .map_err(map_kernel_error)
    .map_err(SourceExecutionError::from)
}

pub(super) fn direct_event_id(
    family: SentinelOneFamily,
    tenant_id: &str,
    provider_id: &str,
) -> Result<String, SentinelOneAgentAdapterError> {
    let event_id = format!(
        "sentinelone-{}-{}-{}",
        family.event_id_family(),
        tenant_id.trim(),
        provider_id.trim()
    );
    if !super::safe_event_component(tenant_id)
        || !super::safe_event_component(provider_id)
        || event_id.len() > 512
    {
        return Err(SentinelOneAgentAdapterError::InvalidEventIdentity);
    }
    Ok(event_id)
}
