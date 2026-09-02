//! Cloudflare bridge for the closed source-execution protocol.
//!
//! These adapters receive authenticated tenant context, public provider
//! configuration, and bounded provider response bytes. The trusted host owns
//! credential redemption, `Authorization: Bearer` authentication,
//! origin-constrained network I/O, durable append, projection, and checkpoint
//! persistence.

use std::collections::{BTreeMap, HashMap};

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
    CloudflareError, CloudflareFamily, CloudflareKernel, CloudflareRequestKind, CloudflareScope,
    normalize::tenant_event_id,
};

const SOURCE_ID: &str = "cloudflare";
const DEFAULT_BASE_URL: &str = "https://api.cloudflare.com/client/v4";
const BASE_PATH: &str = "/client/v4";
const METHOD: &str = "GET";
const RECORD_SELECTOR: &str = "$.result[*]";
const ID_FIELD: &str = "id";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;
const ACCOUNT_ID_KEY: &str = "account_id";
const ZONE_ID_KEY: &str = "zone_id";
/// Host-owned credential operation that applies the Cloudflare API token as
/// `Authorization: Bearer`.
pub(crate) const CREDENTIAL_OPERATION: &str = "source.bearer";

/// Credential-free adapter for one cataloged Cloudflare family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CloudflareSourceExecutionAdapter {
    family: CloudflareFamily,
}

/// Provider-local adapter set. Shared dispatcher registration and authority
/// promotion remain separate delivery steps.
pub(crate) static CLOUDFLARE_SOURCE_EXECUTION_ADAPTERS: [CloudflareSourceExecutionAdapter; 16] = [
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::AccessApplication),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::AccessGroup),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::Account),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::AccountRuleset),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::AuditLog),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::Member),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::GatewayRule),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::LoadBalancer),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::LoadBalancerPool),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::Role),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::WorkerScript),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::Zone),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::ZoneAccessApplication),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::ZoneAccessGroup),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::ZoneRuleset),
    CloudflareSourceExecutionAdapter::new(CloudflareFamily::DnsRecord),
];

impl CloudflareSourceExecutionAdapter {
    const fn new(family: CloudflareFamily) -> Self {
        Self { family }
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:{SOURCE_ID}:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: provider_kernel(self.family).to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: format!("{BASE_PATH}{}", catalog_path(self.family)),
            record_selector: RECORD_SELECTOR.to_owned(),
            id_field: ID_FIELD.to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: self.family.event_kind(),
            schema_ref: self.family.schema_ref(),
            required_attributes: required_attributes(self.family)
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_payload_fields: vec![ID_FIELD.to_owned()],
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

    /// Builds the origin- and scope-bound kernel from trusted context and the
    /// public selector the selected family declares. Returns the kernel, the
    /// validated account or zone scope, and the allowed egress origin.
    fn kernel(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(CloudflareKernel, Option<String>, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        if public_value(&metadata.public_config, "family")
            .is_some_and(|value| value != self.family.as_str())
        {
            return Err(SourceExecutionError::MissingConfiguration);
        }
        let base_url =
            public_value(&metadata.public_config, "base_url").unwrap_or(DEFAULT_BASE_URL);
        let scope = scope_from_config(self.family, &metadata.public_config)?;
        let kernel = CloudflareKernel::new(
            base_url,
            &context.tenant_id,
            self.family,
            scope.as_deref(),
            None,
        )
        .map_err(map_error)?;
        let mut allowed_origin = kernel.plan(None).map_err(map_error)?.url().clone();
        allowed_origin.set_path(BASE_PATH);
        allowed_origin.set_query(None);
        Ok((
            kernel,
            scope,
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
        let (_, scope, _) = self.kernel(context, metadata)?;
        let scoped_provider_id = scoped_provider_id(scope.as_deref(), &record.provider_id);
        let expected_event_id =
            tenant_event_id(&context.tenant_id, self.family, &scoped_provider_id);
        if record.event_id != expected_event_id
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("source_event_id") != Some(&record.provider_id)
            || scope_key(self.family)
                .is_some_and(|key| record.attributes.get(key) != scope.as_ref())
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

impl SourceExecutionAdapter for CloudflareSourceExecutionAdapter {
    fn source_id(&self) -> &'static str {
        SOURCE_ID
    }

    fn family_id(&self) -> &'static str {
        self.family.as_str()
    }

    fn provider_kernel(&self) -> &'static str {
        provider_kernel(self.family)
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
        let (kernel, scope, allowed_origin) = self.kernel(context, metadata)?;
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        if provider_request.kind() != &CloudflareRequestKind::List
            || provider_request.url().path() != scoped_path(&plan.path, scope.as_deref())
            || provider_request.authorization_header() != "Authorization"
            || provider_request.authorization_scheme() != "Bearer"
            || provider_request.contains_credentials()
            || provider_request.allows_redirects()
        {
            return Err(SourceExecutionError::InvalidPlan);
        }
        let mut planned = SourceWorkerHttpRequestV1 {
            plan_id: plan.plan_id.clone(),
            method: METHOD.to_owned(),
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
        let (kernel, _, _) = self.kernel(context, metadata)?;
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
            .decode_http(
                &provider_request,
                status,
                retry_after_seconds,
                &request.response_body,
            )
            .map_err(map_error)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.attributes.get("tenant_id") != Some(&context.tenant_id)
                    || record.family != self.family.as_str()
                    || record.event_kind != plan.event_kind
                    || record.schema_ref != plan.schema_ref
                {
                    return Err(SourceExecutionError::TenantMismatch);
                }
                Ok(SourceWorkerRecordV1 {
                    provider_id: record.provider_id,
                    event_id: record.event_id,
                    occurred_at_unix_millis: occurred_at(
                        &record.attributes,
                        context.observed_at_unix_millis,
                    )?,
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

/// Static provider kernel identity for one family.
const fn provider_kernel(family: CloudflareFamily) -> &'static str {
    match family {
        CloudflareFamily::Account => "cloudflare.account",
        CloudflareFamily::Member => "cloudflare.member",
        CloudflareFamily::Role => "cloudflare.role",
        CloudflareFamily::AccountRuleset => "cloudflare.account_ruleset",
        CloudflareFamily::WorkerScript => "cloudflare.worker_script",
        CloudflareFamily::AuditLog => "cloudflare.audit_log",
        CloudflareFamily::AccessApplication => "cloudflare.access_application",
        CloudflareFamily::ZoneAccessApplication => "cloudflare.zone_access_application",
        CloudflareFamily::AccessGroup => "cloudflare.access_group",
        CloudflareFamily::ZoneAccessGroup => "cloudflare.zone_access_group",
        CloudflareFamily::GatewayRule => "cloudflare.gateway_rule",
        CloudflareFamily::Zone => "cloudflare.zone",
        CloudflareFamily::DnsRecord => "cloudflare.dns_record",
        CloudflareFamily::ZoneRuleset => "cloudflare.zone_ruleset",
        CloudflareFamily::LoadBalancer => "cloudflare.load_balancer",
        CloudflareFamily::LoadBalancerPool => "cloudflare.load_balancer_pool",
    }
}

/// Exact `event.required_attributes` from the checked-in Cloudflare catalog.
const fn required_attributes(family: CloudflareFamily) -> &'static [&'static str] {
    match family {
        CloudflareFamily::Account => &["account_id"],
        CloudflareFamily::Member => &["account_id", "member_id"],
        CloudflareFamily::Role => &["account_id", "role_id"],
        CloudflareFamily::AccountRuleset => &["account_id", "ruleset_id"],
        CloudflareFamily::WorkerScript => &["account_id", "script_id"],
        CloudflareFamily::AuditLog => &["account_id", "audit_id"],
        CloudflareFamily::AccessApplication => &["account_id", "application_id"],
        CloudflareFamily::ZoneAccessApplication => &["application_id", "zone_id"],
        CloudflareFamily::AccessGroup => &["account_id", "group_id"],
        CloudflareFamily::ZoneAccessGroup => &["group_id", "zone_id"],
        CloudflareFamily::GatewayRule => &["account_id", "rule_id"],
        CloudflareFamily::Zone => &["zone_id"],
        CloudflareFamily::DnsRecord => &["record_id", "zone_id"],
        CloudflareFamily::ZoneRuleset => &["ruleset_id", "zone_id"],
        CloudflareFamily::LoadBalancer => &["load_balancer_id", "zone_id"],
        CloudflareFamily::LoadBalancerPool => &["account_id", "pool_id"],
    }
}

/// Public config key carrying the scope the family's provider path needs.
pub(super) const fn scope_key(family: CloudflareFamily) -> Option<&'static str> {
    match family.scope() {
        CloudflareScope::None => None,
        CloudflareScope::Account => Some(ACCOUNT_ID_KEY),
        CloudflareScope::Zone => Some(ZONE_ID_KEY),
    }
}

/// Catalog list path with the family's declared path parameter placeholder.
pub(super) fn catalog_path(family: CloudflareFamily) -> String {
    let template = family.path_template();
    match scope_key(family) {
        Some(key) => template.replace("{scope}", &format!("{{{key}}}")),
        None => template.to_owned(),
    }
}

/// Compiled plan path with the validated scope substituted.
fn scoped_path(plan_path: &str, scope: Option<&str>) -> String {
    match scope {
        Some(scope) => plan_path
            .replace(&format!("{{{ACCOUNT_ID_KEY}}}"), scope)
            .replace(&format!("{{{ZONE_ID_KEY}}}"), scope),
        None => plan_path.to_owned(),
    }
}

/// Reads only the public selector that belongs to the selected family. The
/// host forwards every declared Cloudflare selector; global families never
/// read one, account families read `account_id`, and zone families read
/// `zone_id`.
fn scope_from_config(
    family: CloudflareFamily,
    config: &HashMap<String, String>,
) -> Result<Option<String>, SourceExecutionError> {
    scope_key(family)
        .map(|key| {
            public_value(config, key)
                .map(str::to_owned)
                .ok_or(SourceExecutionError::MissingConfiguration)
        })
        .transpose()
}

fn scoped_provider_id(scope: Option<&str>, provider_id: &str) -> String {
    match scope {
        Some(scope) => format!("{scope}|{provider_id}"),
        None => provider_id.to_owned(),
    }
}

/// Provider occurrence time from the normalized `observed_at` attribute, or
/// the bound host-observed fallback when the family carries no timestamp.
fn occurred_at(
    attributes: &BTreeMap<String, String>,
    observed_at_unix_millis: i64,
) -> Result<i64, SourceExecutionError> {
    attributes
        .get("observed_at")
        .map(String::as_str)
        .map(parse_timestamp)
        .transpose()
        .map(|value| value.unwrap_or(observed_at_unix_millis))
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

fn parse_timestamp(value: &str) -> Result<i64, SourceExecutionError> {
    let nanos = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| SourceExecutionError::InvalidProviderRecord)?
        .unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).map_err(|_| SourceExecutionError::InvalidProviderRecord)
}

fn map_error(error: CloudflareError) -> SourceExecutionError {
    match error {
        CloudflareError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        CloudflareError::InvalidBaseUrl
        | CloudflareError::InvalidScopeId
        | CloudflareError::InvalidPageSize => SourceExecutionError::MissingConfiguration,
        CloudflareError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        CloudflareError::InvalidCursor => SourceExecutionError::InvalidCursor,
        CloudflareError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        CloudflareError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        CloudflareError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        CloudflareError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        CloudflareError::ProviderUnavailable { .. }
        | CloudflareError::UnexpectedStatus { .. }
        | CloudflareError::InvalidRetryAfter
        | CloudflareError::ProviderRejected => SourceExecutionError::UnexpectedProviderStatus,
        CloudflareError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        CloudflareError::BudgetExceeded => SourceExecutionError::ResultTooLarge,
        CloudflareError::InvalidResponse => SourceExecutionError::MalformedResponse,
        CloudflareError::MissingProviderIdentity => SourceExecutionError::MissingStableIdentity,
        CloudflareError::ProviderScopeMismatch | CloudflareError::CredentialMaterial => {
            SourceExecutionError::InvalidProviderRecord
        }
        CloudflareError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
    }
}
