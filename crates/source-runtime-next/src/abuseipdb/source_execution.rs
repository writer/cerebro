//! AbuseIPDB bridge for the closed source-execution protocol.
//!
//! These adapters receive authenticated tenant context, public provider
//! filters, and bounded provider response bytes. The trusted host owns
//! credential redemption, `Key` header authentication, origin-constrained
//! network I/O, durable append, projection, and checkpoint persistence.

use std::{collections::HashMap, str::FromStr};

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
    AbuseIpDbError, AbuseIpDbFamily, AbuseIpDbFilters, AbuseIpDbKernel, AbuseIpDbRuntimeDefinition,
    normalize::event_id,
};

const SOURCE_ID: &str = "abuseipdb";
const DEFAULT_BASE_URL: &str = "https://api.abuseipdb.com/api/v2";
const BASE_PATH: &str = "/api/v2";
const METHOD: &str = "GET";
const ACCEPT: &str = "application/json";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
/// Host-owned credential operation that applies the AbuseIPDB `Key` header.
pub(crate) const CREDENTIAL_OPERATION: &str = "abuseipdb.key";

/// Credential-free adapter for one cataloged AbuseIPDB family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AbuseIpDbSourceExecutionAdapter {
    family: AbuseIpDbFamily,
}

/// Provider-local adapter set registered in the shared closed dispatcher.
pub(crate) static ABUSEIPDB_SOURCE_EXECUTION_ADAPTERS: [AbuseIpDbSourceExecutionAdapter; 2] = [
    AbuseIpDbSourceExecutionAdapter::new(AbuseIpDbFamily::Reports),
    AbuseIpDbSourceExecutionAdapter::new(AbuseIpDbFamily::IpAddresses),
];

impl AbuseIpDbSourceExecutionAdapter {
    const fn new(family: AbuseIpDbFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
        let definition = AbuseIpDbRuntimeDefinition::compile(self.family)
            .expect("closed AbuseIPDB family must compile");
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:{SOURCE_ID}:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: self.family.event_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
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
    ) -> Result<(AbuseIpDbKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|value| value != self.family.as_str())
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let base_url =
            public_value(&metadata.public_config, "base_url").unwrap_or(DEFAULT_BASE_URL);
        let filters = filters_from_config(self.family, &metadata.public_config)?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let kernel = AbuseIpDbKernel::new(
            base_url,
            &context.tenant_id,
            self.family,
            filters,
            &observed_at,
        )
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
        let default_metadata;
        let metadata = match metadata {
            Some(metadata) => metadata,
            None => {
                default_metadata = SourceWorkerRuntimeMetadataV2 {
                    public_config: HashMap::new(),
                    prior_terminal_watermark_unix_millis: 0,
                    prior_checkpoint: String::new(),
                };
                &default_metadata
            }
        };
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

impl SourceExecutionAdapter for AbuseIpDbSourceExecutionAdapter {
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
            || provider_request.authentication_header() != "Key"
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

const fn record_selector(family: AbuseIpDbFamily) -> &'static str {
    match family {
        AbuseIpDbFamily::Reports => "$.data.results[*]",
        AbuseIpDbFamily::IpAddresses => "$.data[*]",
    }
}

const fn id_field(family: AbuseIpDbFamily) -> &'static str {
    match family {
        AbuseIpDbFamily::Reports => "reportedAt",
        AbuseIpDbFamily::IpAddresses => "ipAddress",
    }
}

/// Reads only the public filters that belong to the selected family. The host
/// forwards every declared AbuseIPDB selector; the kernel rejects a filter that
/// belongs to the other family, so the bridge never reads it.
fn filters_from_config(
    family: AbuseIpDbFamily,
    config: &HashMap<String, String>,
) -> Result<AbuseIpDbFilters, SourceExecutionError> {
    let mut filters = AbuseIpDbFilters::default();
    match family {
        AbuseIpDbFamily::Reports => {
            filters.ip_address = public_value(config, "ip_address").map(str::to_owned);
            filters.max_age_in_days = public_number(config, "max_age_in_days")?;
        }
        AbuseIpDbFamily::IpAddresses => {
            filters.confidence_minimum = public_number(config, "confidence_minimum")?;
            filters.ip_version = public_number(config, "ip_version")?;
        }
    }
    Ok(filters)
}

fn public_number<T: FromStr>(
    config: &HashMap<String, String>,
    key: &str,
) -> Result<Option<T>, SourceExecutionError> {
    public_value(config, key)
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|_| SourceExecutionError::MissingConfiguration)
        })
        .transpose()
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

fn map_error(error: AbuseIpDbError) -> SourceExecutionError {
    match error {
        AbuseIpDbError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        AbuseIpDbError::MissingConfiguration(_)
        | AbuseIpDbError::InvalidConfiguration(_)
        | AbuseIpDbError::InvalidOrigin => SourceExecutionError::MissingConfiguration,
        AbuseIpDbError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        AbuseIpDbError::MissingCredentialReference => {
            SourceExecutionError::MissingCredentialReference
        }
        AbuseIpDbError::CredentialUnavailable => SourceExecutionError::CredentialUnavailable,
        AbuseIpDbError::InvalidCursor => SourceExecutionError::InvalidCursor,
        AbuseIpDbError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        AbuseIpDbError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        AbuseIpDbError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        AbuseIpDbError::EgressDenied => SourceExecutionError::EgressDenied,
        AbuseIpDbError::DnsFailure | AbuseIpDbError::ConnectionFailure => {
            SourceExecutionError::ConnectionFailure
        }
        AbuseIpDbError::ProviderTimeout => SourceExecutionError::ProviderTimeout,
        AbuseIpDbError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        AbuseIpDbError::ProviderResourceNotFound
        | AbuseIpDbError::ProviderUnavailable { .. }
        | AbuseIpDbError::UnexpectedStatus { .. }
        | AbuseIpDbError::InvalidRetryAfter => SourceExecutionError::UnexpectedProviderStatus,
        AbuseIpDbError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        AbuseIpDbError::TooManyRecords => SourceExecutionError::ResultTooLarge,
        AbuseIpDbError::MalformedResponse => SourceExecutionError::MalformedResponse,
        AbuseIpDbError::InvalidProviderRecord
        | AbuseIpDbError::CredentialMaterial
        | AbuseIpDbError::ProviderIdentityMismatch => SourceExecutionError::InvalidProviderRecord,
        AbuseIpDbError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        AbuseIpDbError::TenantMismatch => SourceExecutionError::TenantMismatch,
        AbuseIpDbError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
        AbuseIpDbError::EventContractRejection => SourceExecutionError::EventContractRejected,
        AbuseIpDbError::AppendFailure => SourceExecutionError::AppendFailed,
        AbuseIpDbError::ProjectionFailure => SourceExecutionError::ProjectionFailed,
        AbuseIpDbError::LeaseLoss => SourceExecutionError::LeaseLost,
        AbuseIpDbError::StaleAuthority => SourceExecutionError::StaleAuthority,
        AbuseIpDbError::InternalRuntimeFailure => SourceExecutionError::InternalRuntime,
    }
}
