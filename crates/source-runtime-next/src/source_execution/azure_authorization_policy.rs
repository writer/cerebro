use prost::Message;

use cerebro_source_runtime_next::AzureAuthenticationMethodsPolicyKernel;

use super::{
    contract::{lower_sha256, response_digest, result_digest, safe_identifier, validate_plan},
    error::WorkerError,
    wire::{
        SourceExecutionPlanV1, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
        SourceWorkerHttpRequestV1, SourceWorkerRecordV1,
    },
};

pub(crate) fn plan(input: &[u8]) -> Result<Vec<u8>, WorkerError> {
    let plan = SourceExecutionPlanV1::decode(input).map_err(|_| WorkerError::Protobuf)?;
    validate_plan(&plan)?;
    let kernel = AzureAuthenticationMethodsPolicyKernel::new(&plan.origin)
        .map_err(|_| WorkerError::InvalidPlan)?;
    let request = kernel
        .plan_authorization_policy()
        .map_err(|_| WorkerError::InvalidPlan)?;
    if request.url().path() != plan.path || request.url().query().is_some() {
        return Err(WorkerError::InvalidPlan);
    }
    Ok(SourceWorkerHttpRequestV1 {
        plan_id: plan.plan_id,
        method: plan.method,
        url: request.url().to_string(),
        accept: request.accept().to_owned(),
        max_response_bytes: plan.max_response_bytes,
        plan_digest_sha256: plan.plan_digest_sha256,
    }
    .encode_to_vec())
}

pub(crate) fn decode(input: &[u8]) -> Result<Vec<u8>, WorkerError> {
    let request = SourceWorkerDecodeRequestV1::decode(input).map_err(|_| WorkerError::Protobuf)?;
    let plan = request.plan.as_ref().ok_or(WorkerError::InvalidPlan)?;
    validate_plan(plan)?;
    if request.status_code != 200 {
        return Err(WorkerError::UnsupportedStatus);
    }
    if request.response_body.len() as u64 > plan.max_response_bytes {
        return Err(WorkerError::ResponseTooLarge);
    }
    if request.logical_page_id.trim().is_empty() || request.request_intent_digest.trim().is_empty()
    {
        return Err(WorkerError::MissingExecutionIdentity);
    }
    let receipt = request
        .receipt
        .as_ref()
        .ok_or(WorkerError::MissingExecutionIdentity)?;
    if receipt.plan_digest_sha256 != plan.plan_digest_sha256
        || receipt.logical_page_id != request.logical_page_id
        || receipt.request_intent_digest != request.request_intent_digest
        || receipt.runtime_generation == 0
        || receipt.lease_generation == 0
        || !safe_identifier(&receipt.credential_operation)
        || receipt.status_code != request.status_code
        || receipt.response_bytes != request.response_body.len() as u64
        || receipt.response_sha256 != response_digest(&request.response_body)
        || !lower_sha256(&receipt.plan_digest_sha256)
        || !lower_sha256(&receipt.request_intent_digest)
        || !lower_sha256(&receipt.response_sha256)
    {
        return Err(WorkerError::MissingExecutionIdentity);
    }

    let kernel = AzureAuthenticationMethodsPolicyKernel::new(&plan.origin)
        .map_err(|_| WorkerError::InvalidPlan)?;
    let provider_request = kernel
        .plan_authorization_policy()
        .map_err(|_| WorkerError::InvalidPlan)?;
    let page = kernel
        .decode_authorization_policy(&provider_request, &request.response_body)
        .map_err(|_| WorkerError::InvalidProviderResponse)?;
    if page.next_cursor.is_some() || page.records.len() != 1 {
        return Err(WorkerError::InvalidProviderResponse);
    }

    let provider_record = page
        .records
        .into_iter()
        .next()
        .ok_or(WorkerError::InvalidProviderResponse)?;
    let mut attributes = provider_record.fields;
    attributes.insert("family".to_owned(), provider_record.family);
    attributes.insert(
        "resource_id".to_owned(),
        provider_record.provider_id.clone(),
    );
    let payload_json = serde_json::to_vec(&provider_record.payload)
        .map_err(|_| WorkerError::InvalidProviderResponse)?;
    if plan
        .required_attributes
        .iter()
        .any(|required| !attributes.get(required).is_some_and(|value| !value.trim().is_empty()))
        || plan.required_payload_fields.iter().any(|required| {
            provider_record
                .payload
                .get(required)
                .is_none_or(serde_json::Value::is_null)
        })
    {
        return Err(WorkerError::InvalidProviderResponse);
    }
    let result_digest_sha256 = result_digest(
        receipt,
        "",
        &provider_record.provider_id,
        &attributes,
        &payload_json,
    );

    Ok(SourceWorkerDecodeResultV1 {
        plan_id: plan.plan_id.clone(),
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: request.logical_page_id,
        request_intent_digest: request.request_intent_digest,
        records: vec![SourceWorkerRecordV1 {
            provider_id: provider_record.provider_id,
            attributes: attributes.into_iter().collect(),
            payload_json,
        }],
        next_cursor: String::new(),
        result_digest_sha256,
    }
    .encode_to_vec())
}
