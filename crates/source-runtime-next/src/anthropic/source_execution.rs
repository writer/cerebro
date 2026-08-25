//! Anthropic family bridges for the credential-free source-execution protocol.
//!
//! These adapters compile public family contracts and consume bounded provider
//! bytes. The trusted host retains credential redemption, authentication,
//! network I/O, durable append, projection, lease fencing, and checkpoints.

use std::collections::HashMap;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceWorkerDecodeEnvelopeV2,
    SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1,
    SourceWorkerHttpExecutionV2, SourceWorkerHttpRequestV1, SourceWorkerPlanEnvelopeV2,
    SourceWorkerPlanRequestV1, SourceWorkerRecordV1, SourceWorkerRuntimeMetadataV2,
    canonical_http_execution_digest, canonical_request_intent_digest, canonical_result_digest,
    validate_and_deduplicate_records,
};

#[path = "source_execution/catalog.rs"]
mod catalog;

use catalog::{AnthropicSourceExecutionAdapter, map_error, optional, timestamp, validated_kernel};

impl SourceExecutionAdapter for AnthropicSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        "anthropic"
    }

    fn family_id(&self) -> &'static str {
        self.family().as_str()
    }

    fn provider_kernel(&self) -> &'static str {
        self.family().as_str()
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let metadata = SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([
                ("family".to_owned(), self.family().as_str().to_owned()),
                ("base_url".to_owned(), catalog::DEFAULT_BASE_URL.to_owned()),
            ]),
            prior_terminal_watermark_unix_millis: 0,
            prior_checkpoint: String::new(),
        };
        self.validate_identity(context, record, &metadata)
    }

    fn validate_record_identity_v2(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(), SourceExecutionError> {
        self.validate_identity(context, record, metadata)
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
        let (kernel, allowed_origin) = validated_kernel(self.family(), context, metadata)?;
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        let expected_path = format!("/v1{}", provider_request.operation_path);
        if provider_request.url().path() != expected_path
            || provider_request.method() != plan.method
            || provider_request.contains_credentials()
            || provider_request.allows_redirects()
            || provider_request.api_version_header() != ("anthropic-version", "2023-06-01")
        {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: provider_request.method().to_owned(),
            url: provider_request.url().to_string(),
            accept: "application/json".to_owned(),
            max_response_bytes: u64::try_from(provider_request.max_response_bytes())
                .map_err(|_| SourceExecutionError::InvalidPlan)?,
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            request_intent_digest: String::new(),
        };
        planned.request_intent_digest = canonical_request_intent_digest(plan, context, &planned);
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: Vec::new(),
            declared_headers: HashMap::from([(
                "anthropic-version".to_owned(),
                "2023-06-01".to_owned(),
            )]),
            execution_intent_digest_sha256: String::new(),
            credential_operation: catalog::credential_operation(
                provider_request.authentication(),
                &metadata.public_config,
            )?
            .to_owned(),
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
        let (kernel, _) = validated_kernel(self.family(), context, metadata)?;
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        let status = u16::try_from(request.status_code)
            .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let page = kernel
            .decode_http(
                &provider_request,
                status,
                &request.response_body,
                &observed_at
                    .format(&Rfc3339)
                    .map_err(|_| SourceExecutionError::InvalidExecutionContext)?,
            )
            .map_err(map_error)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.tenant_id != context.tenant_id
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

fn parse_timestamp(value: &str) -> Result<i64, SourceExecutionError> {
    let nanos = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| SourceExecutionError::InvalidProviderRecord)?
        .unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).map_err(|_| SourceExecutionError::InvalidProviderRecord)
}

#[cfg(test)]
#[path = "source_execution_tests.rs"]
mod tests;
