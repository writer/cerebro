//! OpenAI family bridges into the closed source-execution dispatcher.
//!
//! The trusted host owns credential redemption, Bearer authentication,
//! origin-constrained network I/O, durable append, projection, and checkpoints.

use std::{collections::HashMap, sync::LazyLock};

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
    OpenAiError, OpenAiFamily, OpenAiKernel, OpenAiRequestInput,
    family::{BASE_PATH, MAX_RESPONSE_BYTES, ORIGIN, Pagination},
    normalize::go_event_id,
};

const SOURCE_ID: &str = "openai";

/// Credential-free adapter for one exact OpenAI family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OpenAiSourceExecutionAdapter {
    family: OpenAiFamily,
}

impl OpenAiSourceExecutionAdapter {
    fn new(family: OpenAiFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let spec = self.family.spec();
        let mut required_attributes = [
            "external_id",
            "family",
            "provider",
            "source_product",
            "source_provider",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        for attribute in spec.required_attributes {
            if !required_attributes.iter().any(|value| value == attribute) {
                required_attributes.push((*attribute).to_owned());
            }
        }
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:openai:{}", self.family.id()),
            source_id: SOURCE_ID.to_owned(),
            family_id: self.family.id().to_owned(),
            provider_kernel: self.family.id().to_owned(),
            method: "GET".to_owned(),
            origin: ORIGIN.to_owned(),
            path: format!("{BASE_PATH}{}", spec.path),
            record_selector: if spec.pagination == Pagination::None {
                "$".to_owned()
            } else {
                "$.data[*]".to_owned()
            },
            id_field: spec.id_paths.join("|"),
            singleton_fallback_id: spec.singleton_identity.unwrap_or_default().to_owned(),
            max_response_bytes: MAX_RESPONSE_BYTES as u64,
            event_kind: self.family.event_kind(),
            schema_ref: self.family.schema_ref(),
            required_attributes,
            required_payload_fields: spec
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

    fn input(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<OpenAiRequestInput, SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|family| family != self.family.id())
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        if public_value(&metadata.public_config, "base_url").is_some_and(|base_url| {
            let base_url = base_url.trim_end_matches('/');
            base_url != ORIGIN && base_url != format!("{ORIGIN}{BASE_PATH}")
        }) {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let spec = self.family.spec();
        let path_parameters = spec
            .path_parameters
            .iter()
            .filter_map(|name| {
                public_value(&metadata.public_config, name)
                    .map(|value| ((*name).to_owned(), value.to_owned()))
            })
            .collect();
        let query_parameters = spec
            .allowed_query
            .iter()
            .filter_map(|(name, _)| {
                let public_name = if *name == "api_key_ids" {
                    "admin_key_ids"
                } else {
                    *name
                };
                public_value(&metadata.public_config, public_name)
                    .map(|value| ((*name).to_owned(), value.to_owned()))
            })
            .collect();
        let page_size = public_value(&metadata.public_config, "per_page")
            .or_else(|| public_value(&metadata.public_config, "page_size"))
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?;
        Ok(OpenAiRequestInput {
            path_parameters,
            query_parameters,
            page_size,
            cursor: (!context.prior_cursor.is_empty()).then(|| context.prior_cursor.clone()),
        })
    }

    fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(), SourceExecutionError> {
        let input = self.input(context, metadata)?;
        let kernel =
            OpenAiKernel::new(self.family, context.tenant_id.clone()).map_err(map_error)?;
        let request = kernel.plan(&input).map_err(map_error)?;
        let path = request
            .url
            .strip_prefix(&format!("{ORIGIN}{BASE_PATH}"))
            .and_then(|value| value.split('?').next())
            .ok_or(SourceExecutionError::InvalidPlan)?;
        let expected = go_event_id(
            &context.tenant_id,
            path,
            self.family.id(),
            &record.provider_id,
        );
        if record.event_id != expected
            || record.attributes.get("external_id") != Some(&record.provider_id)
            || record.attributes.get("family").map(String::as_str) != Some(self.family.id())
            || record.attributes.get("provider").map(String::as_str) != Some(SOURCE_ID)
            || record.attributes.get("source_provider").map(String::as_str) != Some(SOURCE_ID)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

impl SourceExecutionAdapter for OpenAiSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        self.family.id()
    }

    fn provider_kernel(&self) -> &'static str {
        self.family.id()
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        let metadata = SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([("family".to_owned(), self.family.id().to_owned())]),
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
        let input = self.input(context, metadata)?;
        let provider_request = OpenAiKernel::new(self.family, context.tenant_id.clone())
            .map_err(map_error)?
            .plan(&input)
            .map_err(map_error)?;
        if provider_request.method != plan.method
            || provider_request.allow_redirects
            || provider_request.auth.operation != "openai.admin_api_key_bearer"
            || provider_request.auth.header != "Authorization"
            || provider_request.auth.scheme != "Bearer"
        {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: provider_request.method,
            url: provider_request.url,
            accept: provider_request.accept,
            max_response_bytes: provider_request.max_response_bytes as u64,
            plan_digest_sha256: plan.plan_digest_sha256.clone(),
            request_intent_digest: String::new(),
        };
        planned.request_intent_digest = canonical_request_intent_digest(plan, context, &planned);
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: Vec::new(),
            declared_headers: HashMap::new(),
            execution_intent_digest_sha256: String::new(),
            credential_operation: "openai.admin_api_key_bearer".to_owned(),
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
        let input = self.input(context, metadata)?;
        let page = OpenAiKernel::new(self.family, context.tenant_id.clone())
            .map_err(map_error)?
            .decode(
                &input,
                u16::try_from(request.status_code)
                    .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)?,
                &request.response_body,
                context.observed_at_unix_millis,
            )
            .map_err(map_error)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.tenant_id != context.tenant_id
                    || record.family != self.family.id()
                    || record.provider_kind != plan.event_kind
                    || record.schema_ref != plan.schema_ref
                {
                    return Err(SourceExecutionError::TenantMismatch);
                }
                Ok(SourceWorkerRecordV1 {
                    provider_id: record.provider_id,
                    event_id: record.event_id,
                    occurred_at_unix_millis: record.occurred_at_unix_millis,
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

pub(crate) static OPENAI_SOURCE_EXECUTION_ADAPTERS: LazyLock<Vec<OpenAiSourceExecutionAdapter>> =
    LazyLock::new(|| {
        OpenAiFamily::all()
            .map(OpenAiSourceExecutionAdapter::new)
            .collect()
    });

fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn map_error(error: OpenAiError) -> SourceExecutionError {
    match error {
        OpenAiError::MissingConfiguration(_) => SourceExecutionError::MissingConfiguration,
        OpenAiError::InvalidTenant => SourceExecutionError::InvalidExecutionContext,
        OpenAiError::UnknownFamily => SourceExecutionError::UnknownAdapter,
        OpenAiError::CredentialMaterialRejected => SourceExecutionError::InvalidProviderRecord,
        OpenAiError::InvalidCursor => SourceExecutionError::InvalidCursor,
        OpenAiError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        OpenAiError::PermissionDenied => SourceExecutionError::RequiredProviderScopeMissing,
        OpenAiError::RateLimited => SourceExecutionError::ProviderRateLimit,
        OpenAiError::ProviderUnavailable(_) | OpenAiError::UnexpectedStatus(_) => {
            SourceExecutionError::UnexpectedProviderStatus
        }
        OpenAiError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        OpenAiError::MalformedResponse => SourceExecutionError::MalformedResponse,
        OpenAiError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        OpenAiError::TenantMismatch => SourceExecutionError::TenantMismatch,
        OpenAiError::EventContractRejected => SourceExecutionError::EventContractRejected,
        OpenAiError::DuplicateConflict => SourceExecutionError::DuplicateConflict,
    }
}

#[cfg(test)]
#[path = "source_execution_tests.rs"]
mod tests;
