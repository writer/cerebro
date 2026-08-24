//! Metadata-aware SentinelOne agent execution bridge.

use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionError, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeResultV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerPlanEnvelopeV2,
    SourceWorkerRuntimeMetadataV2, canonical_http_execution_digest, validate_execution_context,
    validate_runtime_metadata,
};

use super::{
    CREDENTIAL_OPERATION, decode_agent_response_with_kernel, map_kernel_error, plan_with_kernel,
    validate_agent_tenant, validate_plan,
};
use crate::sentinelone::{SentinelOneFamily, SentinelOneFilters, SentinelOneKernel};

pub(super) fn plan_v2(
    envelope: &SourceWorkerPlanEnvelopeV2,
) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
    let request = envelope
        .request
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let plan = request
        .plan
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    let metadata = envelope
        .metadata
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    validate_plan(plan).map_err(SourceExecutionError::from)?;
    let (kernel, allowed_origin) = kernel(context, metadata)?;
    let planned = plan_with_kernel(plan, context, &kernel, &allowed_origin)?;
    let mut execution = SourceWorkerHttpExecutionV2 {
        request: Some(planned),
        body: Vec::new(),
        declared_headers: HashMap::new(),
        execution_intent_digest_sha256: String::new(),
        credential_operation: CREDENTIAL_OPERATION.to_owned(),
        allowed_origin,
    };
    execution.execution_intent_digest_sha256 =
        canonical_http_execution_digest(plan, context, metadata, &execution);
    Ok(execution)
}

pub(super) fn decode_v2(
    envelope: &SourceWorkerDecodeEnvelopeV2,
) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
    let request = envelope
        .request
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let plan = request
        .plan
        .as_ref()
        .ok_or(SourceExecutionError::InvalidPlan)?;
    let context = request
        .context
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    let metadata = envelope
        .metadata
        .as_ref()
        .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
    validate_plan(plan).map_err(SourceExecutionError::from)?;
    let (kernel, allowed_origin) = kernel(context, metadata)?;
    let expected = plan_with_kernel(plan, context, &kernel, &allowed_origin)?;
    decode_agent_response_with_kernel(request, &kernel, &allowed_origin, &expected)
}

fn kernel(
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<(SentinelOneKernel, String), SourceExecutionError> {
    validate_execution_context(context)?;
    validate_runtime_metadata(metadata)?;
    validate_agent_tenant(&context.tenant_id).map_err(SourceExecutionError::from)?;
    let base_url = public_value(&metadata.public_config, "base_url")
        .ok_or(SourceExecutionError::MissingConfiguration)?;
    let page_size = public_value(&metadata.public_config, "per_page")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| SourceExecutionError::InvalidPlan)
        })
        .transpose()?;
    let filters = SentinelOneFilters {
        site_id: public_owned(&metadata.public_config, "site_id"),
        group_id: public_owned(&metadata.public_config, "group_id"),
        ..SentinelOneFilters::default()
    };
    let kernel = SentinelOneKernel::new(base_url, SentinelOneFamily::Agent, filters, page_size)
        .map_err(map_kernel_error)
        .map_err(SourceExecutionError::from)?;
    let allowed_origin = reqwest::Url::parse(base_url)
        .map_err(|_| SourceExecutionError::InvalidPlan)?
        .origin()
        .ascii_serialization();
    Ok((kernel, allowed_origin))
}

fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn public_owned(config: &HashMap<String, String>, key: &str) -> Option<String> {
    public_value(config, key).map(str::to_owned)
}
