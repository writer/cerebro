//! Linode `issue` bridge into the closed source-execution dispatcher.
//!
//! The adapter consumes authenticated tenant context, public configuration, and
//! bounded provider response bytes. The trusted Go host retains credential
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
    LinodeError, LinodeKernel,
    identity::event_id,
    origin::{scope_base, validate_base_url},
};

const SOURCE_ID: &str = "linode";
const FAMILY_ID: &str = "issue";
const PROVIDER_KERNEL: &str = "linode.issue";
const PLAN_ID: &str = "source-plan-v1:linode:issue";
const DEFAULT_BASE_URL: &str = "https://api.linode.com/v4";
const METHOD: &str = "GET";
const PATH: &str = "/v4/managed/issues";
const KERNEL_PATH: &str = "/managed/issues";
const RECORD_SELECTOR: &str = "$.data[*]";
const ID_FIELD: &str = "id";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
const EVENT_KIND: &str = "linode.issue";
const SCHEMA_REF: &str = "linode/issue/v1";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LinodeIssueSourceExecutionAdapter;

pub(crate) static LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER: LinodeIssueSourceExecutionAdapter =
    LinodeIssueSourceExecutionAdapter;

impl LinodeIssueSourceExecutionAdapter {
    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let mut plan = SourceExecutionPlanV1 {
            plan_id: PLAN_ID.to_owned(),
            source_id: SOURCE_ID.to_owned(),
            family_id: FAMILY_ID.to_owned(),
            provider_kernel: PROVIDER_KERNEL.to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: PATH.to_owned(),
            record_selector: RECORD_SELECTOR.to_owned(),
            id_field: ID_FIELD.to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: EVENT_KIND.to_owned(),
            schema_ref: SCHEMA_REF.to_owned(),
            required_attributes: [
                "tenant_id",
                "source_event_id",
                "finding_id",
                "resource_urn",
                "severity",
                "status",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            required_payload_fields: vec!["id".to_owned()],
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
    ) -> Result<(LinodeKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family").is_some_and(|value| value != FAMILY_ID) {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let base_url = public_value(&metadata.public_config, "base_url");
        let normalized =
            validate_base_url(base_url.unwrap_or(DEFAULT_BASE_URL)).map_err(map_error)?;
        let allowed_origin = scope_base(&normalized);
        let page_size = public_value(&metadata.public_config, "page_size")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?;
        let kernel =
            LinodeKernel::new(base_url, &context.tenant_id, page_size).map_err(map_error)?;
        Ok((kernel, allowed_origin))
    }

    fn expected_event_id(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: Option<&SourceWorkerRuntimeMetadataV2>,
        provider_id: &str,
    ) -> Result<String, SourceExecutionError> {
        let base_url = metadata
            .and_then(|value| public_value(&value.public_config, "base_url"))
            .unwrap_or(DEFAULT_BASE_URL);
        let normalized = validate_base_url(base_url).map_err(map_error)?;
        Ok(event_id(
            &context.tenant_id,
            &scope_base(&normalized),
            KERNEL_PATH,
            provider_id,
        ))
    }

    fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: Option<&SourceWorkerRuntimeMetadataV2>,
    ) -> Result<(), SourceExecutionError> {
        let expected = self.expected_event_id(context, metadata, &record.provider_id)?;
        if record.event_id != expected
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("source_event_id") != Some(&record.provider_id)
            || record.attributes.get("finding_id") != Some(&record.provider_id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

impl SourceExecutionAdapter for LinodeIssueSourceExecutionAdapter {
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
        self.validate_identity(context, record, None)
    }

    fn validate_record_identity_v2(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(), SourceExecutionError> {
        self.validate_identity(context, record, Some(metadata))
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
        if provider_request.url().path() != plan.path
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
        validate_status(request.status_code)?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let page = kernel
            .decode(&provider_request, &request.response_body, observed_at)
            .map_err(map_error)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.tenant_id != context.tenant_id
                    || record.family != FAMILY_ID
                    || record.provider_kind != plan.event_kind
                    || record.schema_ref != plan.schema_ref
                {
                    return Err(SourceExecutionError::TenantMismatch);
                }
                Ok(SourceWorkerRecordV1 {
                    provider_id: record.provider_id,
                    event_id: record.event_id,
                    occurred_at_unix_millis: parse_timestamp(&record.occurred_at)?,
                    attributes: record.fields.into_iter().collect(),
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

pub(crate) fn durable_checkpoint_cursor(
    plan: &SourceExecutionPlanV1,
    result: &SourceWorkerDecodeResultV1,
) -> Option<String> {
    if plan.source_id != SOURCE_ID
        || plan.family_id != FAMILY_ID
        || plan.provider_kernel != PROVIDER_KERNEL
    {
        return None;
    }
    if !result.next_cursor.is_empty() {
        return Some(result.next_cursor.clone());
    }
    Some(
        result
            .records
            .last()
            .map(|record| record.provider_id.clone())
            .unwrap_or_default(),
    )
}

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

fn timestamp(unix_millis: i64) -> Result<OffsetDateTime, SourceExecutionError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_millis) * 1_000_000)
        .map_err(|_| SourceExecutionError::InvalidExecutionContext)
}

fn parse_timestamp(value: &str) -> Result<i64, SourceExecutionError> {
    let nanos = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| SourceExecutionError::InvalidProviderRecord)?
        .unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).map_err(|_| SourceExecutionError::InvalidProviderRecord)
}

fn validate_status(status: u32) -> Result<(), SourceExecutionError> {
    match status {
        200 => Ok(()),
        401 => Err(SourceExecutionError::AuthenticationRejected),
        403 => Err(SourceExecutionError::RequiredProviderScopeMissing),
        408 | 504 => Err(SourceExecutionError::ProviderTimeout),
        429 => Err(SourceExecutionError::ProviderRateLimit),
        _ => Err(SourceExecutionError::UnexpectedProviderStatus),
    }
}

fn map_error(error: LinodeError) -> SourceExecutionError {
    match error {
        LinodeError::InvalidBaseUrl | LinodeError::InvalidPageSize => {
            SourceExecutionError::MissingConfiguration
        }
        LinodeError::MissingTenantId => SourceExecutionError::InvalidExecutionContext,
        LinodeError::InvalidCursor => SourceExecutionError::InvalidCursor,
        LinodeError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        LinodeError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        LinodeError::TooManyRecords => SourceExecutionError::ResultTooLarge,
        LinodeError::InvalidResponse | LinodeError::ResponsePageMismatch => {
            SourceExecutionError::MalformedResponse
        }
        LinodeError::MissingProviderIdentity => SourceExecutionError::MissingStableIdentity,
        LinodeError::InvalidEventIdentity
        | LinodeError::MissingRequiredPayloadField(_)
        | LinodeError::MissingRequiredAttribute(_) => SourceExecutionError::InvalidProviderRecord,
        LinodeError::ConflictingProviderIdentity => SourceExecutionError::DuplicateConflict,
    }
}

#[cfg(test)]
#[path = "source_execution_tests.rs"]
mod tests;
