//! Closed Anthropic adapter catalog and public execution configuration.

use std::collections::{BTreeMap, HashMap};

use time::OffsetDateTime;

use crate::source_execution::{
    SourceExecutionError, SourceExecutionPlanV1, SourceWorkerExecutionContextV1,
    SourceWorkerRecordV1, SourceWorkerRuntimeMetadataV2, canonical_plan_digest,
    validate_execution_context, validate_runtime_metadata,
};

use super::super::{
    AnthropicAuthentication, AnthropicError, AnthropicFamily, AnthropicKernel, AnthropicScope,
    normalize::event_id,
};

const SOURCE_ID: &str = "anthropic";
pub(super) const DEFAULT_BASE_URL: &str = "https://api.anthropic.com/v1";
const ALLOWED_ORIGIN: &str = "https://api.anthropic.com";
const METHOD: &str = "GET";
const MAX_RESPONSE_BYTES: u64 = 8 << 20;

/// One credential-free adapter for a closed Anthropic family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AnthropicSourceExecutionAdapter {
    family: AnthropicFamily,
}

impl AnthropicSourceExecutionAdapter {
    const fn new(family: AnthropicFamily) -> Self {
        Self { family }
    }

    pub(super) const fn family(&self) -> AnthropicFamily {
        self.family
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
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
        for attribute in self.family.required_attributes() {
            if !required_attributes.iter().any(|value| value == attribute) {
                required_attributes.push((*attribute).to_owned());
            }
        }
        let record_selector = match self.family {
            AnthropicFamily::Organization => "$",
            AnthropicFamily::ComplianceOrganizationSetting => "$.settings[*]",
            _ => "$.data[*]",
        };
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:anthropic:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: family_id.to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: format!("/v1{}", self.family.path()),
            record_selector: record_selector.to_owned(),
            id_field: self.family.id_paths().join("|"),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: self.family.provider_kind(),
            schema_ref: self.family.schema_ref(),
            required_attributes,
            required_payload_fields: self
                .family
                .required_payload_fields()
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
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

    pub(super) fn validate_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(), SourceExecutionError> {
        let (kernel, _) = validated_kernel(self.family, context, metadata)?;
        let request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
        let expected = event_id(
            &context.tenant_id,
            DEFAULT_BASE_URL,
            &request.operation_path,
            self.family,
            &record.provider_id,
        );
        if record.event_id != expected
            || record.attributes.get("external_id") != Some(&record.provider_id)
            || record.attributes.get("family").map(String::as_str) != Some(self.family.as_str())
            || record.attributes.get("provider").map(String::as_str) != Some("anthropic")
            || record.attributes.get("source_provider").map(String::as_str) != Some("anthropic")
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

pub(crate) static ANTHROPIC_SOURCE_EXECUTION_ADAPTERS: [AnthropicSourceExecutionAdapter; 28] = [
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::AnalyticsCost),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ApiKey),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceActivity),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceGroup),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceGroupMember),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceOrganization),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceOrganizationSetting),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceOrganizationUser),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceProject),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceProjectCollaborator),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceRole),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ComplianceRolePermission),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::CostReport),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ExternalKey),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::FederationIssuer),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::FederationRule),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::Invite),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::Organization),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::RateLimit),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::ServiceAccount),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::SpendLimit),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::SpendLimitIncreaseRequest),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::UsageReportClaudeCode),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::UsageReportMessage),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::User),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::Workspace),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::WorkspaceMember),
    AnthropicSourceExecutionAdapter::new(AnthropicFamily::WorkspaceRateLimit),
];

pub(super) fn validated_kernel(
    family: AnthropicFamily,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<(AnthropicKernel, String), SourceExecutionError> {
    validate_execution_context(context)?;
    validate_runtime_metadata(metadata)?;
    if public_value(&metadata.public_config, "family").is_some_and(|value| value != family.as_str())
    {
        return Err(SourceExecutionError::MissingConfiguration);
    }
    if public_value(&metadata.public_config, "base_url")
        .is_some_and(|value| value.trim_end_matches('/') != DEFAULT_BASE_URL)
    {
        return Err(SourceExecutionError::MissingConfiguration);
    }
    let page_size = public_value(&metadata.public_config, "per_page")
        .or_else(|| public_value(&metadata.public_config, "page_size"))
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| SourceExecutionError::MissingConfiguration)
        })
        .transpose()?;
    let path_parameters = family
        .path_parameters()
        .iter()
        .filter_map(|name| {
            public_value(&metadata.public_config, name)
                .map(|value| ((*name).to_owned(), value.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    let query_parameters = family
        .query_parameters()
        .iter()
        .filter_map(|(_, name)| {
            public_value(&metadata.public_config, name)
                .map(|value| ((*name).to_owned(), value.to_owned()))
        })
        .collect::<BTreeMap<_, _>>();
    let kernel = AnthropicKernel::new(
        DEFAULT_BASE_URL,
        &context.tenant_id,
        family,
        AnthropicScope {
            path_parameters,
            query_parameters,
        },
        page_size,
    )
    .map_err(map_error)?;
    Ok((kernel, ALLOWED_ORIGIN.to_owned()))
}

pub(super) fn credential_operation(
    authentication: AnthropicAuthentication,
    config: &HashMap<String, String>,
) -> Result<&'static str, SourceExecutionError> {
    let auth_model = public_value(config, "auth_model");
    match authentication {
        AnthropicAuthentication::AdminKeyOrOrgAdminBearer => match auth_model {
            None | Some("api_key" | "legacy_token") => Ok("anthropic.admin_x_api_key"),
            Some("bearer_token") => Ok("anthropic.org_admin_bearer"),
            Some(_) => Err(SourceExecutionError::MissingConfiguration),
        },
        AnthropicAuthentication::OrgAdminBearer => match auth_model {
            None | Some("bearer_token") => Ok("anthropic.org_admin_bearer"),
            Some(_) => Err(SourceExecutionError::MissingConfiguration),
        },
        AnthropicAuthentication::ComplianceAccessKey => match auth_model {
            None | Some("api_key" | "legacy_token") => Ok("anthropic.compliance_x_api_key"),
            Some(_) => Err(SourceExecutionError::MissingConfiguration),
        },
    }
}

pub(super) fn timestamp(unix_millis: i64) -> Result<OffsetDateTime, SourceExecutionError> {
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(unix_millis) * 1_000_000)
        .map_err(|_| SourceExecutionError::InvalidExecutionContext)
}

pub(super) fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn public_value<'a>(config: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    config
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) fn map_error(error: AnthropicError) -> SourceExecutionError {
    match error {
        AnthropicError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        AnthropicError::InvalidBaseUrl
        | AnthropicError::MissingPathParameter
        | AnthropicError::InvalidParameter
        | AnthropicError::InvalidPageSize => SourceExecutionError::MissingConfiguration,
        AnthropicError::MissingTenantId | AnthropicError::InvalidObservedAt => {
            SourceExecutionError::InvalidExecutionContext
        }
        AnthropicError::InvalidCursor => SourceExecutionError::InvalidCursor,
        AnthropicError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        AnthropicError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        AnthropicError::RequiredProviderScopeMissing => {
            SourceExecutionError::RequiredProviderScopeMissing
        }
        AnthropicError::ProviderRateLimit => SourceExecutionError::ProviderRateLimit,
        AnthropicError::ProviderUnavailable | AnthropicError::UnexpectedProviderStatus => {
            SourceExecutionError::UnexpectedProviderStatus
        }
        AnthropicError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        AnthropicError::MalformedResponse => SourceExecutionError::MalformedResponse,
        AnthropicError::InvalidRecord => SourceExecutionError::InvalidProviderRecord,
        AnthropicError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        AnthropicError::EventContractRejected => SourceExecutionError::EventContractRejected,
        AnthropicError::DuplicateConflict => SourceExecutionError::DuplicateConflict,
    }
}
