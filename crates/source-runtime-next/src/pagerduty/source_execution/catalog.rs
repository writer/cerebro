//! Closed PagerDuty source-execution adapter catalog and public configuration.

use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionError, SourceExecutionPlanV1, SourceWorkerExecutionContextV1,
    SourceWorkerRecordV1, SourceWorkerRuntimeMetadataV2, canonical_plan_digest,
    validate_execution_context, validate_runtime_metadata,
};

use super::super::{
    PagerDutyError, PagerDutyFamily, PagerDutyFilters, PagerDutyKernel,
    normalize::event_id,
    origin::{origin_string, validate_origin},
};

const SOURCE_ID: &str = "pagerduty";
pub(super) const DEFAULT_BASE_URL: &str = "https://api.pagerduty.com";
const METHOD: &str = "GET";
const ID_FIELD: &str = "id";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;

/// One credential-free adapter for a closed PagerDuty family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PagerDutySourceExecutionAdapter {
    family: PagerDutyFamily,
}

impl PagerDutySourceExecutionAdapter {
    const fn new(family: PagerDutyFamily) -> Self {
        Self { family }
    }

    pub(super) const fn family(&self) -> PagerDutyFamily {
        self.family
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
        let mut required_attributes = vec![
            "external_id".to_owned(),
            "family".to_owned(),
            "source_provider".to_owned(),
            "source_product".to_owned(),
            self.family.identity_attribute().to_owned(),
        ];
        if self.family == PagerDutyFamily::Integration {
            required_attributes.push("service_id".to_owned());
        }
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:pagerduty:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: self.family.event_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: self.family.path_template().to_owned(),
            record_selector: format!("$.{}[*]", self.family.response_key()),
            id_field: ID_FIELD.to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: self.family.event_kind().to_owned(),
            schema_ref: self.family.schema_ref().to_owned(),
            required_attributes,
            required_payload_fields: vec!["id".to_owned()],
            plan_digest_sha256: String::new(),
        };
        plan.plan_digest_sha256 = canonical_plan_digest(&plan);
        plan
    }

    pub(super) fn validate_plan(
        &self,
        plan: &SourceExecutionPlanV1,
    ) -> Result<(), SourceExecutionError> {
        if plan != &self.compiled_plan() {
            return Err(SourceExecutionError::InvalidPlan);
        }
        Ok(())
    }

    pub(super) fn kernel(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(PagerDutyKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|value| value != self.family.as_str())
        {
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
        let filters = PagerDutyFilters {
            service_ids: service_ids(&metadata.public_config),
        };
        let kernel = PagerDutyKernel::new(
            base_url,
            &context.tenant_id,
            self.family,
            filters,
            page_size,
        )
        .map_err(map_error)?;
        Ok((kernel, allowed_origin))
    }

    pub(super) fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(), SourceExecutionError> {
        let (kernel, origin) = self.kernel(context, metadata)?;
        let request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        let expected = event_id(
            &context.tenant_id,
            &origin,
            request.url().path(),
            self.family,
            &record.provider_id,
        );
        if record.event_id != expected
            || record.attributes.get("external_id") != Some(&record.provider_id)
            || record.attributes.get(self.family.identity_attribute()) != Some(&record.provider_id)
            || (self.family == PagerDutyFamily::Integration
                && record
                    .attributes
                    .get("service_id")
                    .is_none_or(String::is_empty))
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

pub(crate) static PAGERDUTY_USER_SOURCE_EXECUTION_ADAPTER: PagerDutySourceExecutionAdapter =
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::User);

pub(crate) static PAGERDUTY_SOURCE_EXECUTION_ADAPTERS: [PagerDutySourceExecutionAdapter; 7] = [
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::User),
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::Team),
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::Service),
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::Schedule),
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::EscalationPolicy),
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::Integration),
    PagerDutySourceExecutionAdapter::new(PagerDutyFamily::Vendor),
];

pub(super) fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

pub(super) fn map_error(error: PagerDutyError) -> SourceExecutionError {
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

fn service_ids(config: &HashMap<String, String>) -> Vec<String> {
    let mut values = public_value(config, "service_ids")
        .into_iter()
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        if let Some(value) = public_value(config, "service_id") {
            values.push(value.to_owned());
        }
    }
    values
}
