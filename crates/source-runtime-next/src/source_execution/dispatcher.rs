use prost::Message;

use crate::sentinelone::SentinelOneAgentSourceExecutionAdapter;
use crate::twilio::adapter::TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER;

use super::{
    azure_authorization_policy::AzureAuthorizationPolicyAdapter,
    contract::{validate_decode_result, validate_http_request, validate_safe_receipt},
    error::SourceExecutionError,
    wire::{
        SourceExecutionPlanV1, SourceExecutionSelectionRequestV1, SourceWorkerDecodeRequestV1,
        SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1, SourceWorkerHttpRequestV1,
        SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
    },
};

/// Credential-free provider adapter consumed by the shared source dispatcher.
pub trait SourceExecutionAdapter: Send + Sync {
    /// Catalog source identifier handled by the adapter.
    fn source_id(&self) -> &'static str;
    /// Catalog family identifier handled by the adapter.
    fn family_id(&self) -> &'static str;
    /// Exact provider-kernel identifier handled by the adapter.
    fn provider_kernel(&self) -> &'static str;
    /// Validates the adapter's exact tenant-scoped, Go-compatible event identity.
    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError>;
    /// Builds a bounded, credential-free request description.
    fn plan(
        &self,
        request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError>;
    /// Decodes a bounded provider response into canonical records.
    fn decode(
        &self,
        request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError>;
}

/// Closed shared registry for credential-free provider adapters.
#[derive(Clone, Copy, Debug, Default)]
pub struct SourceExecutionDispatcher;

static AZURE_AUTHORIZATION_POLICY: AzureAuthorizationPolicyAdapter =
    AzureAuthorizationPolicyAdapter;
static SENTINELONE_AGENT: SentinelOneAgentSourceExecutionAdapter =
    SentinelOneAgentSourceExecutionAdapter;

impl SourceExecutionDispatcher {
    /// Compiles a plan only for a Rust-authoritative source-family selection.
    pub fn compile_plan(
        &self,
        request: &SourceExecutionSelectionRequestV1,
    ) -> Result<SourceExecutionPlanV1, SourceExecutionError> {
        if request.source_id == AZURE_AUTHORIZATION_POLICY.source_id()
            && request.family_id == AZURE_AUTHORIZATION_POLICY.family_id()
        {
            return Ok(AZURE_AUTHORIZATION_POLICY.compiled_plan());
        }
        Err(SourceExecutionError::UnknownAdapter)
    }

    /// Returns the registered adapter that exactly matches a compiled plan.
    pub fn adapter_for(
        &self,
        plan: &SourceExecutionPlanV1,
    ) -> Result<&'static dyn SourceExecutionAdapter, SourceExecutionError> {
        if plan.source_id == AZURE_AUTHORIZATION_POLICY.source_id()
            && plan.family_id == AZURE_AUTHORIZATION_POLICY.family_id()
            && plan.provider_kernel == AZURE_AUTHORIZATION_POLICY.provider_kernel()
        {
            return Ok(&AZURE_AUTHORIZATION_POLICY);
        }
        if plan.source_id == SENTINELONE_AGENT.source_id()
            && plan.family_id == SENTINELONE_AGENT.family_id()
            && plan.provider_kernel == SENTINELONE_AGENT.provider_kernel()
        {
            return Ok(&SENTINELONE_AGENT);
        }
        if plan.source_id == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER);
        }
        Err(SourceExecutionError::UnknownAdapter)
    }

    /// Dispatches a typed planning request through the closed registry.
    pub fn dispatch_plan(
        &self,
        request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
        let plan = request
            .plan
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let result = self.adapter_for(plan)?.plan(request)?;
        let context = request
            .context
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        validate_http_request(plan, context, &result)?;
        Ok(result)
    }

    /// Dispatches a typed decode request through the closed registry.
    pub fn dispatch_decode(
        &self,
        request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        let plan = request
            .plan
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        if request.response_body.len() as u64 > plan.max_response_bytes {
            return Err(SourceExecutionError::ResponseTooLarge);
        }
        let context = request
            .context
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        if request.logical_page_id != context.logical_page_id {
            return Err(SourceExecutionError::MissingExecutionIdentity);
        }
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
        let adapter = self.adapter_for(plan)?;
        let planned = adapter.plan(&SourceWorkerPlanRequestV1 {
            plan: Some(plan.clone()),
            context: Some(context.clone()),
        })?;
        validate_http_request(plan, context, &planned)?;
        if planned.request_intent_digest != request.request_intent_digest {
            return Err(SourceExecutionError::InvalidDigest);
        }
        let result = adapter.decode(request)?;
        validate_decode_result(request, &result)?;
        for record in &result.records {
            adapter.validate_record_identity(context, record)?;
        }
        Ok(result)
    }
}

/// Decodes a selection and returns its exact registry-compiled plan.
pub fn compile_plan_bytes(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let request = SourceExecutionSelectionRequestV1::decode(input)
        .map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(SourceExecutionDispatcher
        .compile_plan(&request)?
        .encode_to_vec())
}

/// Decodes, dispatches, and encodes one bounded planning request.
pub fn dispatch_plan_bytes(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let request =
        SourceWorkerPlanRequestV1::decode(input).map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(SourceExecutionDispatcher
        .dispatch_plan(&request)?
        .encode_to_vec())
}

/// Decodes, dispatches, and encodes one bounded provider response.
pub fn dispatch_decode_bytes(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let request =
        SourceWorkerDecodeRequestV1::decode(input).map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(SourceExecutionDispatcher
        .dispatch_decode(&request)?
        .encode_to_vec())
}
