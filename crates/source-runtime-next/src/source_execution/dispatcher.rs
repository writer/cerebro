use prost::Message;

use crate::anthropic::ANTHROPIC_SOURCE_EXECUTION_ADAPTERS;
use crate::asana::ASANA_SOURCE_EXECUTION_ADAPTERS;
use crate::deepseek::DEEPSEEK_SOURCE_EXECUTION_ADAPTERS;
use crate::digitalocean::DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS;
use crate::discord::DISCORD_SOURCE_EXECUTION_ADAPTERS;
use crate::google_workspace::{
    GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER, GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER,
};
use crate::linode::LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER;
use crate::openai::OPENAI_SOURCE_EXECUTION_ADAPTERS;
use crate::pagerduty::PAGERDUTY_SOURCE_EXECUTION_ADAPTERS;
use crate::portable_ai::PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS;
use crate::sentinelone::{
    SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER, SENTINELONE_DIRECT_SOURCE_EXECUTION_ADAPTERS,
    SentinelOneAgentSourceExecutionAdapter,
};
use crate::twilio::adapter::{
    TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER, TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER,
    TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER,
};

use super::{
    azure_authorization_policy::AzureAuthorizationPolicyAdapter,
    contract::{
        canonical_http_execution_digest, canonical_response_headers_digest, response_digest,
        validate_decode_envelope, validate_decode_result, validate_http_execution,
        validate_http_request, validate_runtime_metadata, validate_safe_receipt,
    },
    error::SourceExecutionError,
    jumpcloud::JUMPCLOUD_ADAPTERS,
    tailscale::TAILSCALE_ADAPTERS,
    wire::{
        SourceExecutionPlanV1, SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2,
        SourceWorkerDecodeOutputV2, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
        SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1,
        SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
        SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1,
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
    /// Validates identity for adapters whose public v2 scope affects provider identity.
    fn validate_record_identity_v2(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        _metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(), SourceExecutionError> {
        self.validate_record_identity(context, record)
    }
    /// Builds a bounded, credential-free request description.
    fn plan(
        &self,
        request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError>;
    /// Builds an additive metadata-aware operation without changing v1 providers.
    fn plan_v2(
        &self,
        envelope: &SourceWorkerPlanEnvelopeV2,
    ) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
        let request = envelope
            .request
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let metadata = envelope
            .metadata
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        validate_runtime_metadata(metadata)?;
        let planned = self.plan(request)?;
        let plan = request
            .plan
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let context = request
            .context
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: Vec::new(),
            declared_headers: Default::default(),
            execution_intent_digest_sha256: String::new(),
            credential_operation: "source.bearer".to_owned(),
            allowed_origin: plan.origin.clone(),
        };
        execution.execution_intent_digest_sha256 =
            canonical_http_execution_digest(plan, context, metadata, &execution);
        Ok(execution)
    }
    /// Decodes a bounded provider response into canonical records.
    fn decode(
        &self,
        request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError>;
    /// Decodes a metadata-aware response; v1 providers ignore the additive metadata.
    fn decode_v2(
        &self,
        envelope: &SourceWorkerDecodeEnvelopeV2,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        let request = envelope
            .request
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
        self.decode(request)
    }
}

/// Closed shared registry for credential-free provider adapters.
#[derive(Clone, Copy, Debug, Default)]
pub struct SourceExecutionDispatcher;

static AZURE_AUTHORIZATION_POLICY: AzureAuthorizationPolicyAdapter =
    AzureAuthorizationPolicyAdapter;
static SENTINELONE_AGENT: SentinelOneAgentSourceExecutionAdapter =
    SentinelOneAgentSourceExecutionAdapter;

impl SourceExecutionDispatcher {
    /// Compiles a plan only for a registered credential-free source-family selection.
    /// Production authority is decided independently by the trusted runtime host.
    pub fn compile_plan(
        &self,
        request: &SourceExecutionSelectionRequestV1,
    ) -> Result<SourceExecutionPlanV1, SourceExecutionError> {
        if let Some(adapter) = ANTHROPIC_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return Ok(adapter.compiled_plan());
        }
        if let Some(adapter) = ASANA_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return adapter.compiled_plan();
        }
        if let Some(adapter) = DEEPSEEK_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return Ok(adapter.compiled_plan());
        }
        if let Some(adapter) = OPENAI_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return Ok(adapter.compiled_plan());
        }
        if let Some(adapter) = PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS
            .iter()
            .find(|adapter| {
                request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
            })
        {
            return Ok(adapter.compiled_plan());
        }
        if request.source_id == AZURE_AUTHORIZATION_POLICY.source_id()
            && request.family_id == AZURE_AUTHORIZATION_POLICY.family_id()
        {
            return Ok(AZURE_AUTHORIZATION_POLICY.compiled_plan());
        }
        if request.source_id == SENTINELONE_AGENT.source_id()
            && request.family_id == SENTINELONE_AGENT.family_id()
        {
            return Ok(SENTINELONE_AGENT.compiled_plan());
        }
        if let Some(adapter) = SENTINELONE_DIRECT_SOURCE_EXECUTION_ADAPTERS
            .iter()
            .find(|adapter| {
                request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
            })
        {
            return Ok(adapter.compiled_plan());
        }
        if let Some(adapter) = DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS
            .iter()
            .find(|adapter| {
                request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
            })
        {
            return Ok(adapter.compiled_plan());
        }
        if let Some(adapter) = DISCORD_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return Ok(adapter.compiled_plan());
        }
        if request.source_id == GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.source_id()
            && request.family_id == GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.family_id()
        {
            return Ok(GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.compiled_plan());
        }
        if request.source_id == GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER.source_id()
            && request.family_id == GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER.family_id()
        {
            return Ok(GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER.compiled_plan());
        }
        if request.source_id == SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER.source_id()
            && request.family_id == SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER.family_id()
        {
            return Ok(SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER.compiled_plan());
        }
        if let Some(adapter) = PAGERDUTY_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return Ok(adapter.compiled_plan());
        }
        if request.source_id == LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER.source_id()
            && request.family_id == LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER.family_id()
        {
            return Ok(LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER.compiled_plan());
        }
        if request.source_id == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.source_id()
            && request.family_id == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.family_id()
        {
            return Ok(TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.compiled_plan());
        }
        if request.source_id == TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER.source_id()
            && request.family_id == TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER.family_id()
        {
            return Ok(TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER.compiled_plan());
        }
        if request.source_id == TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER.source_id()
            && request.family_id == TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER.family_id()
        {
            return Ok(TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER.compiled_plan());
        }
        if let Some(adapter) = JUMPCLOUD_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return adapter.compiled_plan();
        }
        if let Some(adapter) = TAILSCALE_ADAPTERS.iter().find(|adapter| {
            request.source_id == adapter.source_id() && request.family_id == adapter.family_id()
        }) {
            return adapter.compiled_plan();
        }
        Err(SourceExecutionError::UnknownAdapter)
    }

    /// Returns the registered adapter that exactly matches a compiled plan.
    pub fn adapter_for(
        &self,
        plan: &SourceExecutionPlanV1,
    ) -> Result<&'static dyn SourceExecutionAdapter, SourceExecutionError> {
        if let Some(adapter) = ANTHROPIC_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
        }
        if let Some(adapter) = ASANA_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
        }
        if let Some(adapter) = DEEPSEEK_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
        }
        if let Some(adapter) = OPENAI_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
        }
        if let Some(adapter) = PORTABLE_AI_SOURCE_EXECUTION_ADAPTERS
            .iter()
            .find(|adapter| {
                plan.source_id == adapter.source_id()
                    && plan.family_id == adapter.family_id()
                    && plan.provider_kernel == adapter.provider_kernel()
            })
        {
            return Ok(adapter);
        }
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
        if let Some(adapter) = SENTINELONE_DIRECT_SOURCE_EXECUTION_ADAPTERS
            .iter()
            .find(|adapter| {
                plan.source_id == adapter.source_id()
                    && plan.family_id == adapter.family_id()
                    && plan.provider_kernel == adapter.provider_kernel()
            })
        {
            return Ok(adapter);
        }
        if let Some(adapter) = DIGITALOCEAN_SOURCE_EXECUTION_ADAPTERS
            .iter()
            .find(|adapter| {
                plan.source_id == adapter.source_id()
                    && plan.family_id == adapter.family_id()
                    && plan.provider_kernel == adapter.provider_kernel()
            })
        {
            return Ok(adapter);
        }
        if let Some(adapter) = DISCORD_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
        }
        if plan.source_id == GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel
                == GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER);
        }
        if plan.source_id == GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel
                == GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER);
        }
        if plan.source_id == SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel
                == SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&SENTINELONE_APPLICATION_SOURCE_EXECUTION_ADAPTER);
        }
        if let Some(adapter) = PAGERDUTY_SOURCE_EXECUTION_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
        }
        if plan.source_id == LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel == LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER);
        }
        if plan.source_id == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel == TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&TWILIO_ACCOUNTS_SOURCE_EXECUTION_ADAPTER);
        }
        if plan.source_id == TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel
                == TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&TWILIO_AUDIT_EVENTS_SOURCE_EXECUTION_ADAPTER);
        }
        if plan.source_id == TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER.source_id()
            && plan.family_id == TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER.family_id()
            && plan.provider_kernel == TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER.provider_kernel()
        {
            return Ok(&TWILIO_KEYS_SOURCE_EXECUTION_ADAPTER);
        }
        if let Some(adapter) = JUMPCLOUD_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
        }
        if let Some(adapter) = TAILSCALE_ADAPTERS.iter().find(|adapter| {
            plan.source_id == adapter.source_id()
                && plan.family_id == adapter.family_id()
                && plan.provider_kernel == adapter.provider_kernel()
        }) {
            return Ok(adapter);
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

    /// Dispatches one additive metadata-aware planning envelope.
    pub fn dispatch_plan_v2(
        &self,
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
        let result = self.adapter_for(plan)?.plan_v2(envelope)?;
        validate_http_execution(plan, context, &result, metadata)?;
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

    /// Dispatches one metadata-aware response with bounded safe headers.
    pub fn dispatch_decode_v2(
        &self,
        envelope: &SourceWorkerDecodeEnvelopeV2,
    ) -> Result<SourceWorkerDecodeOutputV2, SourceExecutionError> {
        validate_decode_envelope(envelope)?;
        let request = envelope
            .request
            .as_ref()
            .ok_or(SourceExecutionError::InvalidPlan)?;
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
        let adapter = self.adapter_for(plan)?;
        let planned = adapter.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: envelope.metadata.clone(),
        })?;
        let metadata = envelope
            .metadata
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        validate_http_execution(plan, context, &planned, metadata)?;
        if planned.execution_intent_digest_sha256 != envelope.execution_intent_digest_sha256
            || planned
                .request
                .as_ref()
                .is_none_or(|value| value.request_intent_digest != request.request_intent_digest)
        {
            return Err(SourceExecutionError::InvalidDigest);
        }
        let response_bytes = u64::try_from(request.response_body.len())
            .map_err(|_| SourceExecutionError::ResponseTooLarge)?;
        let receipt = SourceWorkerSafeReceiptV1 {
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: request.request_intent_digest.clone(),
            runtime_generation: context.runtime_generation,
            lease_generation: context.lease_generation,
            credential_operation: planned.credential_operation,
            status_code: request.status_code,
            response_bytes,
            response_sha256: response_digest(&request.response_body),
            tenant_id: context.tenant_id.clone(),
            runtime_id: context.runtime_id.clone(),
            observed_at_unix_millis: context.observed_at_unix_millis,
        };
        validate_safe_receipt(
            &receipt,
            plan,
            context,
            &request.response_body,
            request.status_code,
            &request.request_intent_digest,
        )?;
        let mut bound_request = request.clone();
        bound_request.receipt = Some(receipt.clone());
        let mut bound_envelope = envelope.clone();
        bound_envelope.request = Some(bound_request.clone());
        bound_envelope.response_headers_sha256 =
            canonical_response_headers_digest(&bound_envelope.response_headers)?;
        let result = adapter.decode_v2(&bound_envelope)?;
        validate_decode_result(&bound_request, &result)?;
        for record in &result.records {
            adapter.validate_record_identity_v2(context, record, metadata)?;
        }
        Ok(SourceWorkerDecodeOutputV2 {
            receipt: Some(receipt),
            result: Some(result),
        })
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

/// Decodes, dispatches, and encodes one metadata-aware planning envelope.
pub fn dispatch_plan_v2_bytes(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let envelope =
        SourceWorkerPlanEnvelopeV2::decode(input).map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(SourceExecutionDispatcher
        .dispatch_plan_v2(&envelope)?
        .encode_to_vec())
}

/// Decodes one metadata-aware response and returns Rust-authored receipt evidence.
pub fn dispatch_decode_v2_bytes(input: &[u8]) -> Result<Vec<u8>, SourceExecutionError> {
    let envelope =
        SourceWorkerDecodeEnvelopeV2::decode(input).map_err(|_| SourceExecutionError::Protobuf)?;
    Ok(SourceExecutionDispatcher
        .dispatch_decode_v2(&envelope)?
        .encode_to_vec())
}
