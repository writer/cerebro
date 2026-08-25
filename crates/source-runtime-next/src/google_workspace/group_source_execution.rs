//! Google Workspace `group` bridge for the closed source-execution protocol.
//!
//! The adapter receives only authenticated execution context, public Directory
//! selectors, and bounded provider response bytes. The trusted host retains
//! OAuth credential redemption, Bearer authentication, origin-constrained
//! network I/O, durable append, projection, and checkpoint ownership.

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
    GoogleWorkspaceError, GoogleWorkspaceFamily, GoogleWorkspaceFilters, GoogleWorkspaceKernel,
    GoogleWorkspaceOutcome,
};

const SOURCE_ID: &str = "google_workspace";
const FAMILY_ID: &str = "group";
const PROVIDER_KERNEL: &str = "google_workspace.group";
const PLAN_ID: &str = "source-plan-v1:google_workspace:group";
const DEFAULT_BASE_URL: &str = "https://admin.googleapis.com";
const METHOD: &str = "GET";
const PATH: &str = "/admin/directory/v1/groups";
const RECORD_SELECTOR: &str = "$.groups[*]";
const ID_FIELD: &str = "id";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
const EVENT_KIND: &str = "google_workspace.group";
const SCHEMA_REF: &str = "google_workspace/group/v1";

/// Credential-free adapter for the Google Workspace groups family.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct GoogleWorkspaceGroupSourceExecutionAdapter;

/// Shared instance ready for closed-dispatcher registration.
pub(crate) static GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER:
    GoogleWorkspaceGroupSourceExecutionAdapter = GoogleWorkspaceGroupSourceExecutionAdapter;

impl GoogleWorkspaceGroupSourceExecutionAdapter {
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
            required_attributes: ["domain", "family", "group_id"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            required_payload_fields: Vec::new(),
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
    ) -> Result<(GoogleWorkspaceKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family").is_some_and(|value| value != FAMILY_ID) {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let domain = public_value(&metadata.public_config, "domain")
            .ok_or(SourceExecutionError::MissingConfiguration)?;
        let base_url =
            public_value(&metadata.public_config, "base_url").unwrap_or(DEFAULT_BASE_URL);
        let customer_id = public_value(&metadata.public_config, "customer_id").map(str::to_owned);
        let page_size = public_value(&metadata.public_config, "per_page")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?;
        let kernel = GoogleWorkspaceKernel::new(
            base_url,
            domain,
            GoogleWorkspaceFamily::Group,
            GoogleWorkspaceFilters {
                customer_id,
                ..GoogleWorkspaceFilters::default()
            },
            page_size,
        )
        .map_err(map_error)?;
        let origin = kernel
            .plan(None)
            .map_err(map_error)?
            .url()
            .origin()
            .ascii_serialization();
        Ok((kernel, origin))
    }
}

impl SourceExecutionAdapter for GoogleWorkspaceGroupSourceExecutionAdapter {
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
        _context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        if record.event_id != format!("google-workspace-group-{}", record.provider_id)
            || record.attributes.get("group_id") != Some(&record.provider_id)
            || record.attributes.get("family").map(String::as_str) != Some(FAMILY_ID)
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
        self.validate_record_identity(context, record)?;
        let domain = public_value(&metadata.public_config, "domain")
            .ok_or(SourceExecutionError::MissingConfiguration)?;
        if record.attributes.get("domain").map(String::as_str) != Some(domain) {
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
            || provider_request.authorization_scheme() != "Bearer"
            || provider_request.url().username() != ""
            || provider_request.url().password().is_some()
        {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: METHOD.to_owned(),
            url: provider_request.url().to_string(),
            accept: provider_request.accept().to_owned(),
            max_response_bytes: MAX_RESPONSE_BYTES,
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
        let observed_at = observed_at(context.observed_at_unix_millis)?;
        let page = match request.status_code {
            200 => match kernel
                .decode(&provider_request, &request.response_body)
                .map_err(map_error)?
            {
                GoogleWorkspaceOutcome::Page(page) => page,
                GoogleWorkspaceOutcome::Request(_) => {
                    return Err(SourceExecutionError::InvalidPlan);
                }
            },
            401 => return Err(SourceExecutionError::AuthenticationRejected),
            403 => return Err(SourceExecutionError::RequiredProviderScopeMissing),
            429 => return Err(SourceExecutionError::ProviderRateLimit),
            500..=599 => return Err(SourceExecutionError::UnexpectedProviderStatus),
            _ => return Err(SourceExecutionError::UnexpectedProviderStatus),
        }
        .materialize(&observed_at)
        .map_err(map_error)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        let records = page
            .events
            .into_iter()
            .map(|event| {
                if event.source_id != SOURCE_ID
                    || event.provider_kind != plan.event_kind
                    || event.schema_ref != plan.schema_ref
                {
                    return Err(SourceExecutionError::TenantMismatch);
                }
                let provider_id = event
                    .attributes
                    .get("group_id")
                    .cloned()
                    .filter(|value| !value.trim().is_empty())
                    .ok_or(SourceExecutionError::MissingStableIdentity)?;
                Ok(SourceWorkerRecordV1 {
                    provider_id,
                    event_id: event.event_id,
                    occurred_at_unix_millis: parse_timestamp(&event.occurred_at)?,
                    attributes: event.attributes.into_iter().collect(),
                    payload_json: serde_json::to_vec(&event.payload)
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

fn observed_at(unix_millis: i64) -> Result<String, SourceExecutionError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_millis) * 1_000_000)
        .map_err(|_| SourceExecutionError::InvalidExecutionContext)?
        .format(&Rfc3339)
        .map_err(|_| SourceExecutionError::InvalidExecutionContext)
}

fn parse_timestamp(value: &str) -> Result<i64, SourceExecutionError> {
    let nanos = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| SourceExecutionError::InvalidProviderRecord)?
        .unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).map_err(|_| SourceExecutionError::InvalidProviderRecord)
}

fn map_error(error: GoogleWorkspaceError) -> SourceExecutionError {
    match error {
        GoogleWorkspaceError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        GoogleWorkspaceError::InvalidBaseUrl
        | GoogleWorkspaceError::MissingDomain
        | GoogleWorkspaceError::MissingGroupKey
        | GoogleWorkspaceError::InvalidPageSize
        | GoogleWorkspaceError::InvalidTenantIdentity
        | GoogleWorkspaceError::InvalidCustomerId => SourceExecutionError::MissingConfiguration,
        GoogleWorkspaceError::InvalidCursor => SourceExecutionError::InvalidCursor,
        GoogleWorkspaceError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        GoogleWorkspaceError::TooManyUserRecords => SourceExecutionError::ResultTooLarge,
        GoogleWorkspaceError::ConflictingUserIdentity => SourceExecutionError::DuplicateConflict,
        GoogleWorkspaceError::AuthenticationRejected => {
            SourceExecutionError::AuthenticationRejected
        }
        GoogleWorkspaceError::RequiredUserScopeMissing | GoogleWorkspaceError::PermissionDenied => {
            SourceExecutionError::RequiredProviderScopeMissing
        }
        GoogleWorkspaceError::RateLimited => SourceExecutionError::ProviderRateLimit,
        GoogleWorkspaceError::ProviderUnavailable(_)
        | GoogleWorkspaceError::UnexpectedProviderStatus(_) => {
            SourceExecutionError::UnexpectedProviderStatus
        }
        GoogleWorkspaceError::InvalidResponse => SourceExecutionError::MalformedResponse,
        GoogleWorkspaceError::InvalidRecord => SourceExecutionError::InvalidProviderRecord,
        GoogleWorkspaceError::MissingRecordIdentity
        | GoogleWorkspaceError::MissingDiscoveryIdentity => {
            SourceExecutionError::MissingStableIdentity
        }
        GoogleWorkspaceError::MissingRoleState
        | GoogleWorkspaceError::RequestScopeMismatch
        | GoogleWorkspaceError::UserFamilyRequired => SourceExecutionError::InvalidPlan,
        GoogleWorkspaceError::InvalidObservedAt => SourceExecutionError::InvalidExecutionContext,
    }
}
