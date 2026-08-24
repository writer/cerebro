//! Closed Discord adapter catalog and public execution configuration.

use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionError, SourceExecutionPlanV1, SourceWorkerExecutionContextV1,
    SourceWorkerRecordV1, SourceWorkerRuntimeMetadataV2, canonical_plan_digest,
    validate_execution_context, validate_runtime_metadata,
};

use super::super::{DiscordError, DiscordFamily, DiscordKernel, normalize::event_id};

const SOURCE_ID: &str = "discord";
pub(super) const DEFAULT_BASE_URL: &str = "https://discord.com/api/v10";
const METHOD: &str = "GET";
const MAX_RESPONSE_BYTES: u64 = 4 << 20;

/// One credential-free adapter for a closed Discord family.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DiscordSourceExecutionAdapter {
    family: DiscordFamily,
}

impl DiscordSourceExecutionAdapter {
    const fn new(family: DiscordFamily) -> Self {
        Self { family }
    }

    pub(super) const fn family(&self) -> DiscordFamily {
        self.family
    }

    pub(crate) fn compiled_plan(&self) -> SourceExecutionPlanV1 {
        let family_id = self.family.as_str();
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:discord:{family_id}"),
            source_id: SOURCE_ID.to_owned(),
            family_id: family_id.to_owned(),
            provider_kernel: self.family.provider_kind().to_owned(),
            method: METHOD.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: family_path(self.family).to_owned(),
            record_selector: record_selector(self.family).to_owned(),
            id_field: id_field(self.family).to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: self.family.provider_kind().to_owned(),
            schema_ref: format!("discord/{family_id}/v1"),
            required_attributes: required_attributes(self.family)
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_payload_fields: required_payload_fields(self.family)
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
            || record.attributes.get("provider").map(String::as_str) != Some(SOURCE_ID)
            || record.attributes.get("source_provider").map(String::as_str) != Some(SOURCE_ID)
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
        {
            return Err(SourceExecutionError::TenantMismatch);
        }
        Ok(())
    }
}

pub(crate) static DISCORD_SOURCE_EXECUTION_ADAPTERS: [DiscordSourceExecutionAdapter; 4] = [
    DiscordSourceExecutionAdapter::new(DiscordFamily::AuditLog),
    DiscordSourceExecutionAdapter::new(DiscordFamily::Member),
    DiscordSourceExecutionAdapter::new(DiscordFamily::Role),
    DiscordSourceExecutionAdapter::new(DiscordFamily::Permission),
];

pub(super) fn validated_kernel(
    family: DiscordFamily,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<(DiscordKernel, String), SourceExecutionError> {
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
    let guild_id = public_value(&metadata.public_config, "guild_id")
        .ok_or(SourceExecutionError::MissingConfiguration)?;
    let application_id = if family == DiscordFamily::Permission {
        Some(
            public_value(&metadata.public_config, "application_id")
                .ok_or(SourceExecutionError::MissingConfiguration)?,
        )
    } else {
        None
    };
    let page_size = if matches!(family, DiscordFamily::AuditLog | DiscordFamily::Member) {
        public_value(&metadata.public_config, "per_page")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?
    } else {
        None
    };
    let kernel = DiscordKernel::new(
        DEFAULT_BASE_URL,
        &context.tenant_id,
        guild_id,
        application_id,
        family,
        page_size,
    )
    .map_err(map_error)?;
    Ok((kernel, DEFAULT_BASE_URL.to_owned()))
}

pub(super) const fn family_path(family: DiscordFamily) -> &'static str {
    match family {
        DiscordFamily::AuditLog => "/guilds/{guild_id}/audit-logs",
        DiscordFamily::Member => "/guilds/{guild_id}/members",
        DiscordFamily::Role => "/guilds/{guild_id}/roles",
        DiscordFamily::Permission => {
            "/applications/{application_id}/guilds/{guild_id}/commands/permissions"
        }
    }
}

const fn record_selector(family: DiscordFamily) -> &'static str {
    match family {
        DiscordFamily::AuditLog => "$.audit_log_entries[*]",
        DiscordFamily::Member | DiscordFamily::Role | DiscordFamily::Permission => "$[*]",
    }
}

const fn id_field(family: DiscordFamily) -> &'static str {
    match family {
        DiscordFamily::Member => "user.id",
        DiscordFamily::AuditLog | DiscordFamily::Role | DiscordFamily::Permission => "id",
    }
}

const fn required_attributes(family: DiscordFamily) -> &'static [&'static str] {
    match family {
        DiscordFamily::AuditLog => &["tenant_id", "source_event_id", "event_type"],
        DiscordFamily::Member => &["tenant_id", "source_event_id", "user_id"],
        DiscordFamily::Role => &["tenant_id", "source_event_id", "group_id"],
        DiscordFamily::Permission => &[
            "tenant_id",
            "source_event_id",
            "resource_urn",
            "resource_type",
            "resource_id",
        ],
    }
}

const fn required_payload_fields(family: DiscordFamily) -> &'static [&'static str] {
    match family {
        DiscordFamily::Member => &["avatar"],
        DiscordFamily::AuditLog | DiscordFamily::Role | DiscordFamily::Permission => &["id"],
    }
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

pub(super) fn map_error(error: DiscordError) -> SourceExecutionError {
    match error {
        DiscordError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        DiscordError::InvalidBaseUrl
        | DiscordError::UnsafeOrigin
        | DiscordError::InvalidGuildId
        | DiscordError::InvalidApplicationId
        | DiscordError::MissingApplicationId
        | DiscordError::InvalidPageSize
        | DiscordError::UnsupportedPageSize => SourceExecutionError::MissingConfiguration,
        DiscordError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        DiscordError::InvalidCursor | DiscordError::UnsupportedCursor => {
            SourceExecutionError::InvalidCursor
        }
        DiscordError::InvalidResponse => SourceExecutionError::MalformedResponse,
        DiscordError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        DiscordError::TooManyRecords | DiscordError::TooManyNestedRecords => {
            SourceExecutionError::ResultTooLarge
        }
        DiscordError::InvalidRecord | DiscordError::CredentialMaterial => {
            SourceExecutionError::InvalidProviderRecord
        }
        DiscordError::MissingProviderId => SourceExecutionError::MissingStableIdentity,
        DiscordError::InvalidPageOrder => SourceExecutionError::InvalidProviderRecord,
        DiscordError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        DiscordError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
        DiscordError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        DiscordError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        DiscordError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        DiscordError::ProviderUnavailable { .. } | DiscordError::UnexpectedStatus { .. } => {
            SourceExecutionError::UnexpectedProviderStatus
        }
        DiscordError::InvalidRetryAfter => SourceExecutionError::UnexpectedProviderStatus,
    }
}
