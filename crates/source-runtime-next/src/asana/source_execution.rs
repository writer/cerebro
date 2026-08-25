//! Asana family bridges into the closed source-execution dispatcher.
//!
//! The adapters consume authenticated tenant context, public configuration,
//! and bounded provider response bytes. The trusted runtime host retains credential
//! redemption, Bearer authentication, network I/O, durable append, projection,
//! and checkpoint ownership.

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
    AsanaError, AsanaFamily, AsanaKernel, AsanaRuntimeDefinition, normalize::event_id,
    origin::validate_origin, request::MAX_RESPONSE_BYTES,
};

const SOURCE_ID: &str = "asana";
const DEFAULT_BASE_URL: &str = "https://app.asana.com/api/1.0";
const METHOD: &str = "GET";
const RECORD_SELECTOR: &str = "$.data[*]";
const ID_FIELD: &str = "gid";

/// Credential-free adapter for one closed Asana family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AsanaSourceExecutionAdapter {
    family: AsanaFamily,
}

impl AsanaSourceExecutionAdapter {
    const fn new(family: AsanaFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> Result<SourceExecutionPlanV1, SourceExecutionError> {
        let definition = AsanaRuntimeDefinition::compile(self.family).map_err(map_error)?;
        let contract = definition.event_contract;
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:asana:{}", self.family.as_str()),
            source_id: SOURCE_ID.to_owned(),
            family_id: self.family.as_str().to_owned(),
            provider_kernel: self.family.event_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: family_path(self.family, "{workspace_gid}"),
            record_selector: RECORD_SELECTOR.to_owned(),
            id_field: ID_FIELD.to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: u64::try_from(MAX_RESPONSE_BYTES)
                .map_err(|_| SourceExecutionError::InvalidPlan)?,
            event_kind: contract.kind.to_owned(),
            schema_ref: contract.schema_ref.to_owned(),
            required_attributes: contract
                .required_attributes
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_payload_fields: contract
                .required_payload_fields
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        Ok(plan)
    }

    fn validate_plan(&self, plan: &SourceExecutionPlanV1) -> Result<(), SourceExecutionError> {
        if plan != &self.compiled_plan()? {
            return Err(SourceExecutionError::InvalidPlan);
        }
        Ok(())
    }

    fn kernel(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(AsanaKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|value| value != self.family.as_str())
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let base_url =
            public_value(&metadata.public_config, "base_url").unwrap_or(DEFAULT_BASE_URL);
        let normalized = validate_origin(base_url).map_err(map_error)?;
        let allowed_origin = normalized.to_string().trim_end_matches('/').to_owned();
        let workspace_gid = public_value(&metadata.public_config, "workspace_gid")
            .ok_or(SourceExecutionError::MissingConfiguration)?;
        let page_size = public_value(&metadata.public_config, "page_size")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?;
        let kernel = AsanaKernel::new(
            base_url,
            &context.tenant_id,
            workspace_gid,
            self.family,
            page_size,
        )
        .map_err(map_error)?;
        Ok((kernel, allowed_origin))
    }

    fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let expected = event_id(&context.tenant_id, self.family, &record.provider_id);
        if record.event_id != expected
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("source_event_id") != Some(&record.provider_id)
            || (self.family == AsanaFamily::Users
                && record.attributes.get("user_id") != Some(&record.provider_id))
            || (self.family == AsanaFamily::Projects
                && record.attributes.get("resource_id") != Some(&record.provider_id))
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

impl SourceExecutionAdapter for AsanaSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        self.family.as_str()
    }

    fn provider_kernel(&self) -> &'static str {
        self.family.event_kind()
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
        let (kernel, allowed_origin) = self.kernel(context, metadata)?;
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        if provider_request.url().path()
            != family_path(
                self.family,
                public_value(&metadata.public_config, "workspace_gid").unwrap_or_default(),
            )
            || provider_request.method() != plan.method
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
            max_response_bytes: u64::try_from(provider_request.max_response_bytes())
                .map_err(|_| SourceExecutionError::InvalidPlan)?,
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
            allowed_origin,
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
        let (kernel, _) = self.kernel(context, metadata)?;
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
        let status = u16::try_from(request.status_code)
            .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let page = kernel
            .decode_http(
                &provider_request,
                status,
                retry_after_seconds,
                &request.response_body,
                &observed_at,
            )
            .map_err(map_error)?;
        let checkpoint = kernel
            .checkpoint_candidate(
                &provider_request,
                &page,
                optional_watermark(metadata)?.as_deref(),
            )
            .map_err(map_error)?;
        let next_cursor = checkpoint.cursor.unwrap_or_default();
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

pub(crate) static ASANA_SOURCE_EXECUTION_ADAPTERS: [AsanaSourceExecutionAdapter; 3] = [
    AsanaSourceExecutionAdapter::new(AsanaFamily::Users),
    AsanaSourceExecutionAdapter::new(AsanaFamily::Projects),
    AsanaSourceExecutionAdapter::new(AsanaFamily::AuditEvents),
];

fn family_path(family: AsanaFamily, workspace_gid: &str) -> String {
    match family {
        AsanaFamily::Users => "/api/1.0/users".to_owned(),
        AsanaFamily::Projects => "/api/1.0/projects".to_owned(),
        AsanaFamily::AuditEvents => {
            format!("/api/1.0/workspaces/{workspace_gid}/audit_log_events")
        }
    }
}

fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn response_header<'a>(headers: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    headers
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn optional_watermark(
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<Option<String>, SourceExecutionError> {
    (metadata.prior_terminal_watermark_unix_millis > 0)
        .then(|| timestamp(metadata.prior_terminal_watermark_unix_millis))
        .transpose()
}

fn timestamp(unix_millis: i64) -> Result<String, SourceExecutionError> {
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

fn map_error(error: AsanaError) -> SourceExecutionError {
    match error {
        AsanaError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        AsanaError::MissingConfiguration(_)
        | AsanaError::InvalidConfiguration(_)
        | AsanaError::InvalidBaseUrl
        | AsanaError::UnsafeOrigin => SourceExecutionError::MissingConfiguration,
        AsanaError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        AsanaError::MissingCredentialReference => SourceExecutionError::MissingCredentialReference,
        AsanaError::CredentialUnavailable => SourceExecutionError::CredentialUnavailable,
        AsanaError::InvalidCursor => SourceExecutionError::InvalidCursor,
        AsanaError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        AsanaError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        AsanaError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        AsanaError::EgressDenied => SourceExecutionError::EgressDenied,
        AsanaError::DnsFailure | AsanaError::ConnectionFailure => {
            SourceExecutionError::ConnectionFailure
        }
        AsanaError::ProviderTimeout => SourceExecutionError::ProviderTimeout,
        AsanaError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        AsanaError::ProviderUnavailable { .. }
        | AsanaError::UnexpectedStatus { .. }
        | AsanaError::InvalidRetryAfter => SourceExecutionError::UnexpectedProviderStatus,
        AsanaError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        AsanaError::TooManyRecords => SourceExecutionError::ResultTooLarge,
        AsanaError::MalformedResponse => SourceExecutionError::MalformedResponse,
        AsanaError::InvalidProviderRecord | AsanaError::CredentialMaterial => {
            SourceExecutionError::InvalidProviderRecord
        }
        AsanaError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        AsanaError::TenantMismatch => SourceExecutionError::TenantMismatch,
        AsanaError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
        AsanaError::EventContractRejection => SourceExecutionError::EventContractRejected,
        AsanaError::AppendFailure => SourceExecutionError::AppendFailed,
        AsanaError::ProjectionFailure => SourceExecutionError::ProjectionFailed,
        AsanaError::LeaseLoss => SourceExecutionError::LeaseLost,
        AsanaError::StaleAuthority => SourceExecutionError::StaleAuthority,
        AsanaError::InternalRuntimeFailure => SourceExecutionError::InternalRuntime,
    }
}

#[cfg(test)]
#[path = "source_execution_tests.rs"]
mod tests;
