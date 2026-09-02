//! Acunetix bridge for the closed source-execution protocol.
//!
//! These adapters receive authenticated tenant context, public provider
//! configuration, and bounded provider response bytes. The trusted host owns
//! credential redemption, `X-Auth` header authentication, origin-constrained
//! network I/O, durable append, projection, and checkpoint persistence.

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
    AcunetixError, AcunetixFamily, AcunetixKernel, AcunetixRuntimeDefinition, normalize::event_id,
};

const SOURCE_ID: &str = "acunetix";
/// Acunetix has no shared default origin: every tenant supplies its own
/// HTTPS `/api/v1` base, so the compiled plan carries a placeholder host.
const PLAN_ORIGIN: &str = "https://{host}/api/v1";
const BASE_PATH: &str = "/api/v1";
const METHOD: &str = "GET";
const ACCEPT: &str = "application/json";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
/// Host-owned credential operation that applies the Acunetix `X-Auth` header.
pub(crate) const CREDENTIAL_OPERATION: &str = "acunetix.x_auth";

/// Credential-free adapter for one cataloged Acunetix family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AcunetixSourceExecutionAdapter {
    family: AcunetixFamily,
}

/// Provider-local adapter set. Shared dispatcher registration and authority
/// promotion remain separate delivery steps.
pub(crate) static ACUNETIX_SOURCE_EXECUTION_ADAPTERS: [AcunetixSourceExecutionAdapter; 5] = [
    AcunetixSourceExecutionAdapter::new(AcunetixFamily::Reports),
    AcunetixSourceExecutionAdapter::new(AcunetixFamily::ScanningProfiles),
    AcunetixSourceExecutionAdapter::new(AcunetixFamily::Scans),
    AcunetixSourceExecutionAdapter::new(AcunetixFamily::Targets),
    AcunetixSourceExecutionAdapter::new(AcunetixFamily::Vulnerabilities),
];

impl AcunetixSourceExecutionAdapter {
    const fn new(family: AcunetixFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
        let definition = AcunetixRuntimeDefinition::compile(self.family)
            .expect("closed Acunetix family must compile");
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:{SOURCE_ID}:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: self.family.event_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: PLAN_ORIGIN.to_owned(),
            path: format!("{BASE_PATH}{}", self.family.path()),
            record_selector: record_selector(self.family).to_owned(),
            id_field: id_field(self.family).to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
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
    ) -> Result<(AcunetixKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|value| value != self.family.as_str())
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let base_url = public_value(&metadata.public_config, "base_url")
            .ok_or(SourceExecutionError::MissingConfiguration)?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let kernel = AcunetixKernel::new(base_url, &context.tenant_id, self.family, &observed_at)
            .map_err(map_error)?;
        let mut allowed_origin = kernel.plan(None).map_err(map_error)?.url().clone();
        allowed_origin.set_path(BASE_PATH);
        allowed_origin.set_query(None);
        Ok((
            kernel,
            allowed_origin.to_string().trim_end_matches('/').to_owned(),
        ))
    }

    fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: Option<&SourceWorkerRuntimeMetadataV2>,
    ) -> Result<(), SourceExecutionError> {
        let metadata = metadata.ok_or(SourceExecutionError::MissingConfiguration)?;
        let (kernel, _) = self.kernel(context, metadata)?;
        if record.event_id != event_id(&kernel, &record.provider_id)
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("source_event_id") != Some(&record.provider_id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

impl SourceExecutionAdapter for AcunetixSourceExecutionAdapter {
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
        if provider_request.method() != plan.method
            || provider_request.url().path() != plan.path
            || provider_request.authentication_header() != "X-Auth"
            || !provider_request.authentication_scheme().is_empty()
            || provider_request.contains_credentials()
            || provider_request.allows_redirects()
        {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: provider_request.method().to_owned(),
            url: provider_request.url().to_string(),
            accept: ACCEPT.to_owned(),
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
            credential_operation: CREDENTIAL_OPERATION.to_owned(),
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
        let page = kernel
            .decode(
                &provider_request,
                status,
                retry_after_seconds,
                &request.response_body,
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
        for record in &records {
            self.validate_record_identity_v2(context, record, metadata)?;
        }
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

const fn record_selector(family: AcunetixFamily) -> &'static str {
    match family {
        AcunetixFamily::Reports => "$.reports[*]",
        AcunetixFamily::ScanningProfiles => "$.scanning_profiles[*]",
        AcunetixFamily::Scans => "$.scans[*]",
        AcunetixFamily::Targets => "$.targets[*]",
        AcunetixFamily::Vulnerabilities => "$.vulnerabilities[*]",
    }
}

const fn id_field(family: AcunetixFamily) -> &'static str {
    match family {
        AcunetixFamily::Reports => "report_id",
        AcunetixFamily::ScanningProfiles => "profile_id",
        AcunetixFamily::Scans => "scan_id",
        AcunetixFamily::Targets => "target_id",
        AcunetixFamily::Vulnerabilities => "vuln_id",
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

fn map_error(error: AcunetixError) -> SourceExecutionError {
    match error {
        AcunetixError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        AcunetixError::InvalidConfiguration(_) | AcunetixError::InvalidOrigin => {
            SourceExecutionError::MissingConfiguration
        }
        AcunetixError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        AcunetixError::MissingCredentialReference => {
            SourceExecutionError::MissingCredentialReference
        }
        AcunetixError::CredentialUnavailable => SourceExecutionError::CredentialUnavailable,
        AcunetixError::InvalidCursor => SourceExecutionError::InvalidCursor,
        AcunetixError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        AcunetixError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        AcunetixError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        AcunetixError::EgressDenied => SourceExecutionError::EgressDenied,
        AcunetixError::DnsFailure | AcunetixError::ConnectionFailure => {
            SourceExecutionError::ConnectionFailure
        }
        AcunetixError::ProviderTimeout => SourceExecutionError::ProviderTimeout,
        AcunetixError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        AcunetixError::ProviderResourceNotFound
        | AcunetixError::ProviderUnavailable { .. }
        | AcunetixError::UnexpectedStatus { .. }
        | AcunetixError::InvalidRetryAfter => SourceExecutionError::UnexpectedProviderStatus,
        AcunetixError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        AcunetixError::TooManyRecords => SourceExecutionError::ResultTooLarge,
        AcunetixError::MalformedResponse => SourceExecutionError::MalformedResponse,
        AcunetixError::InvalidProviderRecord | AcunetixError::CredentialMaterial => {
            SourceExecutionError::InvalidProviderRecord
        }
        AcunetixError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        AcunetixError::TenantMismatch => SourceExecutionError::TenantMismatch,
        AcunetixError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
        AcunetixError::EventContractRejection => SourceExecutionError::EventContractRejected,
        AcunetixError::AppendFailure => SourceExecutionError::AppendFailed,
        AcunetixError::ProjectionFailure => SourceExecutionError::ProjectionFailed,
        AcunetixError::LeaseLoss => SourceExecutionError::LeaseLost,
        AcunetixError::StaleAuthority => SourceExecutionError::StaleAuthority,
        AcunetixError::InternalRuntimeFailure => SourceExecutionError::InternalRuntime,
    }
}
