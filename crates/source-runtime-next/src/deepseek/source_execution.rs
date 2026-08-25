//! DeepSeek bridges into the closed credential-free source-execution dispatcher.
//!
//! Rust owns request construction and response normalization. The trusted host
//! owns bearer-token redemption, bounded network I/O, append, projection, and
//! durable checkpoint ordering.

use std::collections::HashMap;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionPlanV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1,
    SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRecordV1,
    SourceWorkerRuntimeMetadataV2, canonical_http_execution_digest, canonical_plan_digest,
    canonical_request_intent_digest, canonical_result_digest, validate_and_deduplicate_records,
    validate_execution_context, validate_runtime_metadata,
};

use super::{
    DeepSeekError, DeepSeekFamily, DeepSeekKernel, DeepSeekRuntimeDefinition, normalize::event_id,
};

const SOURCE_ID: &str = "deepseek";
const ORIGIN: &str = "https://api.deepseek.com";

/// Credential-free adapter for one exact DeepSeek family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DeepSeekSourceExecutionAdapter {
    family: DeepSeekFamily,
}

impl DeepSeekSourceExecutionAdapter {
    const fn new(family: DeepSeekFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let definition = DeepSeekRuntimeDefinition::compile(self.family)
            .expect("DeepSeek closed runtime definition");
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:{SOURCE_ID}:{}", self.family.as_str()),
            source_id: SOURCE_ID.to_owned(),
            family_id: self.family.as_str().to_owned(),
            provider_kernel: format!("{SOURCE_ID}.{}", self.family.as_str()),
            method: "GET".to_owned(),
            origin: ORIGIN.to_owned(),
            path: self.family.path().to_owned(),
            record_selector: self.family.record_selector().to_owned(),
            id_field: self.family.identity_field().to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: (4 * 1024 * 1024) as u64,
            event_kind: definition.event_contract.kind.to_owned(),
            schema_ref: definition.event_contract.schema_ref.to_owned(),
            required_attributes: definition
                .event_contract
                .required_attributes
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_payload_fields: definition
                .event_contract
                .required_payload_fields
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        plan
    }

    fn validate_plan(&self, plan: &SourceExecutionPlanV1) -> Result<(), SourceExecutionError> {
        if plan != &self.compiled_plan() {
            return Err(SourceExecutionError::InvalidPlan);
        }
        Ok(())
    }

    fn kernel(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<DeepSeekKernel, SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|family| family != self.family.as_str())
            || public_value(&metadata.public_config, "base_url")
                .is_some_and(|base_url| base_url.trim_end_matches('/') != ORIGIN)
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        DeepSeekKernel::new(ORIGIN, &context.tenant_id, self.family).map_err(map_error)
    }

    fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        if record.event_id != event_id(&context.tenant_id, self.family, &record.provider_id)
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("external_id") != Some(&record.provider_id)
            || record.attributes.get("family").map(String::as_str) != Some(self.family.as_str())
            || record.attributes.get("provider").map(String::as_str) != Some(SOURCE_ID)
            || record.attributes.get("source_provider").map(String::as_str) != Some(SOURCE_ID)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

impl SourceExecutionAdapter for DeepSeekSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        self.family.as_str()
    }

    fn provider_kernel(&self) -> &'static str {
        match self.family {
            DeepSeekFamily::AccountBalances => "deepseek.account_balances",
            DeepSeekFamily::ModelCatalog => "deepseek.model_catalog",
        }
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        self.validate_identity(context, record)
    }

    fn plan(
        &self,
        _request: &SourceWorkerPlanRequestV1,
    ) -> Result<SourceWorkerHttpRequestV1, SourceExecutionError> {
        Err(SourceExecutionError::InvalidPlan)
    }

    fn plan_v2(
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
        self.validate_plan(plan)?;
        let provider_request = self
            .kernel(context, metadata)?
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        if provider_request.method() != plan.method
            || provider_request.url().as_str() != format!("{ORIGIN}{}", self.family.path())
            || provider_request.authorization_header() != "Authorization"
            || provider_request.authorization_scheme() != "Bearer"
            || provider_request.contains_credentials()
            || provider_request.allows_redirects()
        {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: provider_request.method().to_owned(),
            url: provider_request.url().to_string(),
            accept: provider_request.accept().to_owned(),
            max_response_bytes: provider_request.max_response_bytes() as u64,
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            request_intent_digest: String::new(),
        };
        planned.request_intent_digest = canonical_request_intent_digest(plan, context, &planned);
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: Vec::new(),
            declared_headers: HashMap::new(),
            execution_intent_digest_sha256: String::new(),
            credential_operation: "source.bearer".to_owned(),
            allowed_origin: ORIGIN.to_owned(),
        };
        execution.execution_intent_digest_sha256 =
            canonical_http_execution_digest(plan, context, metadata, &execution);
        Ok(execution)
    }

    fn decode(
        &self,
        _request: &SourceWorkerDecodeRequestV1,
    ) -> Result<SourceWorkerDecodeResultV1, SourceExecutionError> {
        Err(SourceExecutionError::InvalidPlan)
    }

    fn decode_v2(
        &self,
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
        let receipt = request
            .receipt
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        let metadata = envelope
            .metadata
            .as_ref()
            .ok_or(SourceExecutionError::MissingExecutionIdentity)?;
        self.validate_plan(plan)?;
        let kernel = self.kernel(context, metadata)?;
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        let retry_after_seconds = response_header(&envelope.response_headers, "retry-after")
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)
            })
            .transpose()?;
        let observed_at = observed_at(context.observed_at_unix_millis)?;
        let page = kernel
            .decode_http(
                &provider_request,
                u16::try_from(request.status_code)
                    .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)?,
                retry_after_seconds,
                &request.response_body,
                &observed_at,
            )
            .map_err(map_error)?;
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.tenant_id != context.tenant_id
                    || record.family != self.family
                    || record.kind != plan.event_kind
                    || record.schema_ref != plan.schema_ref
                {
                    return Err(SourceExecutionError::TenantMismatch);
                }
                Ok(SourceWorkerRecordV1 {
                    provider_id: record.provider_id,
                    event_id: record.event_id,
                    occurred_at_unix_millis: parse_timestamp(&record.occurred_at)?,
                    attributes: record.attributes.into_iter().collect(),
                    payload_json: serde_json::to_vec(&record.payload)
                        .map_err(|_| SourceExecutionError::InternalRuntime)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let records = validate_and_deduplicate_records(records)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        let result_digest_sha256 = canonical_result_digest(receipt, &next_cursor, &records)?;
        Ok(SourceWorkerDecodeResultV1 {
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
        })
    }
}

pub(crate) static DEEPSEEK_SOURCE_EXECUTION_ADAPTERS: [DeepSeekSourceExecutionAdapter; 2] = [
    DeepSeekSourceExecutionAdapter::new(DeepSeekFamily::AccountBalances),
    DeepSeekSourceExecutionAdapter::new(DeepSeekFamily::ModelCatalog),
];

fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn response_header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .filter(|value| !value.is_empty())
}

fn observed_at(unix_millis: i64) -> Result<String, SourceExecutionError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_millis) * 1_000_000)
        .map_err(|_| SourceExecutionError::InvalidExecutionContext)?
        .format(&Rfc3339)
        .map_err(|_| SourceExecutionError::InternalRuntime)
}

fn parse_timestamp(value: &str) -> Result<i64, SourceExecutionError> {
    let nanos = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| SourceExecutionError::InvalidProviderRecord)?
        .unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).map_err(|_| SourceExecutionError::InvalidProviderRecord)
}

fn map_error(error: DeepSeekError) -> SourceExecutionError {
    match error {
        DeepSeekError::MissingConfiguration(_)
        | DeepSeekError::InvalidConfiguration(_)
        | DeepSeekError::InvalidBaseUrl
        | DeepSeekError::UnsafeOrigin => SourceExecutionError::MissingConfiguration,
        DeepSeekError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        DeepSeekError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        DeepSeekError::InvalidCursor => SourceExecutionError::InvalidCursor,
        DeepSeekError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        DeepSeekError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        DeepSeekError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        DeepSeekError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        DeepSeekError::MalformedResponse => SourceExecutionError::MalformedResponse,
        DeepSeekError::InvalidProviderRecord | DeepSeekError::CredentialMaterial => {
            SourceExecutionError::InvalidProviderRecord
        }
        DeepSeekError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        DeepSeekError::TenantMismatch => SourceExecutionError::TenantMismatch,
        DeepSeekError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
        DeepSeekError::EventContractRejection => SourceExecutionError::EventContractRejected,
        DeepSeekError::ProviderUnavailable { .. }
        | DeepSeekError::UnexpectedStatus { .. }
        | DeepSeekError::InsufficientBalance
        | DeepSeekError::InvalidRetryAfter => SourceExecutionError::UnexpectedProviderStatus,
        DeepSeekError::TooManyRecords => SourceExecutionError::ResponseTooLarge,
        DeepSeekError::InvalidObservedAt => SourceExecutionError::InvalidProviderRecord,
        DeepSeekError::MissingCredentialReference | DeepSeekError::CredentialUnavailable => {
            SourceExecutionError::MissingConfiguration
        }
        DeepSeekError::RequestScopeMismatch | DeepSeekError::InternalRuntimeFailure => {
            SourceExecutionError::InternalRuntime
        }
        DeepSeekError::EgressDenied
        | DeepSeekError::DnsFailure
        | DeepSeekError::ConnectionFailure
        | DeepSeekError::ProviderTimeout
        | DeepSeekError::AppendFailure
        | DeepSeekError::ProjectionFailure
        | DeepSeekError::LeaseLoss
        | DeepSeekError::StaleAuthority => SourceExecutionError::InternalRuntime,
    }
}

#[cfg(test)]
#[path = "source_execution_tests.rs"]
mod tests;
