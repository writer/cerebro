//! PagerDuty `user` bridge into the closed source-execution dispatcher.
//!
//! The adapter consumes authenticated tenant context, public configuration, and
//! bounded provider response bytes. The trusted Go host retains credential
//! redemption, PagerDuty authentication, network I/O, durable append,
//! projection, and checkpoint ownership.

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
    PagerDutyError, PagerDutyFamily, PagerDutyFilters, PagerDutyKernel,
    normalize::event_id,
    origin::{DEFAULT_BASE_URL, origin_string, validate_origin},
};

const SOURCE_ID: &str = "pagerduty";
const FAMILY_ID: &str = "user";
const PROVIDER_KERNEL: &str = "pagerduty.user";
const PLAN_ID: &str = "source-plan-v1:pagerduty:user";
const METHOD: &str = "GET";
const PATH: &str = "/users";
const RECORD_SELECTOR: &str = "$.users[*]";
const ID_FIELD: &str = "id";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
const EVENT_KIND: &str = "pagerduty.user";
const SCHEMA_REF: &str = "pagerduty/user/v1";

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PagerDutyUserSourceExecutionAdapter;

pub(crate) static PAGERDUTY_USER_SOURCE_EXECUTION_ADAPTER: PagerDutyUserSourceExecutionAdapter =
    PagerDutyUserSourceExecutionAdapter;

impl PagerDutyUserSourceExecutionAdapter {
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
                "external_id",
                "family",
                "source_provider",
                "source_product",
                "user_id",
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
    ) -> Result<(PagerDutyKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family").is_some_and(|value| value != FAMILY_ID) {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let base_url = public_value(&metadata.public_config, "base_url");
        let allowed_origin = origin_string(&validate_origin(base_url).map_err(map_error)?);
        let page_size = public_value(&metadata.public_config, "per_page")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?;
        let kernel = PagerDutyKernel::new(
            base_url,
            &context.tenant_id,
            PagerDutyFamily::User,
            PagerDutyFilters::default(),
            page_size,
        )
        .map_err(map_error)?;
        Ok((kernel, allowed_origin))
    }
}

impl SourceExecutionAdapter for PagerDutyUserSourceExecutionAdapter {
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
        let expected = event_id(
            &context.tenant_id,
            DEFAULT_BASE_URL,
            PATH,
            PagerDutyFamily::User,
            &record.provider_id,
        );
        if record.event_id != expected
            || record.attributes.get("external_id") != Some(&record.provider_id)
            || record.attributes.get("user_id") != Some(&record.provider_id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }

    fn validate_record_identity_v2(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(), SourceExecutionError> {
        let origin = origin_string(
            &validate_origin(public_value(&metadata.public_config, "base_url"))
                .map_err(map_error)?,
        );
        let expected = event_id(
            &context.tenant_id,
            &origin,
            PATH,
            PagerDutyFamily::User,
            &record.provider_id,
        );
        if record.event_id != expected
            || record.attributes.get("external_id") != Some(&record.provider_id)
            || record.attributes.get("user_id") != Some(&record.provider_id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
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
            || provider_request.authorization_scheme() != "Token token="
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
            credential_operation: "pagerduty.token".to_owned(),
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
        let status = u16::try_from(request.status_code)
            .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let page = kernel
            .decode(
                &provider_request,
                status,
                &request.response_body,
                observed_at,
            )
            .map_err(map_error)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.tenant_id != context.tenant_id
                    || record.family != PagerDutyFamily::User
                    || record.event_kind != plan.event_kind
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

fn map_error(error: PagerDutyError) -> SourceExecutionError {
    match error {
        PagerDutyError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        PagerDutyError::InvalidBaseUrl
        | PagerDutyError::MissingServiceId
        | PagerDutyError::InvalidServiceId
        | PagerDutyError::InvalidPageSize => SourceExecutionError::MissingConfiguration,
        PagerDutyError::MissingTenantId => SourceExecutionError::InvalidExecutionContext,
        PagerDutyError::InvalidCursor => SourceExecutionError::InvalidCursor,
        PagerDutyError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        PagerDutyError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        PagerDutyError::PermissionDenied => SourceExecutionError::RequiredProviderScopeMissing,
        PagerDutyError::RateLimited => SourceExecutionError::ProviderRateLimit,
        PagerDutyError::ProviderUnavailable | PagerDutyError::UnexpectedProviderStatus => {
            SourceExecutionError::UnexpectedProviderStatus
        }
        PagerDutyError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        PagerDutyError::TooManyRecords => SourceExecutionError::ResultTooLarge,
        PagerDutyError::MalformedResponse => SourceExecutionError::MalformedResponse,
        PagerDutyError::MissingProviderIdentity => SourceExecutionError::MissingStableIdentity,
        PagerDutyError::InvalidProviderIdentity => SourceExecutionError::InvalidProviderRecord,
        PagerDutyError::ConflictingProviderIdentity => SourceExecutionError::DuplicateConflict,
        PagerDutyError::EventContractRejected => SourceExecutionError::EventContractRejected,
    }
}

#[cfg(test)]
#[path = "source_execution_tests.rs"]
mod tests;
