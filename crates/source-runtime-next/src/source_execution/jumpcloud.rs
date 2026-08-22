use std::collections::{BTreeMap, HashMap};

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::jumpcloud::{
    JumpCloudError, JumpCloudFamily, JumpCloudFilters, JumpCloudKernel, JumpCloudResponseMetadata,
    JumpCloudRuntimeDefinition,
    adapter::{JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS, JumpCloudSourceExecutionAdapter},
};

use super::{
    contract::{
        canonical_http_execution_digest, canonical_plan_digest, canonical_request_intent_digest,
        canonical_result_digest, validate_and_deduplicate_records, validate_execution_context,
        validate_runtime_metadata,
    },
    dispatcher::SourceExecutionAdapter,
    error::SourceExecutionError,
    wire::{
        SourceExecutionPlanV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1,
        SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
        SourceWorkerHttpRequestV1, SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1,
        SourceWorkerRecordV1,
    },
};

const MAX_RESPONSE_BYTES: u64 = 8 << 20;

pub(super) static JUMPCLOUD_ADAPTERS: [JumpCloudExecutionBridge; 7] = [
    JumpCloudExecutionBridge::new(JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[0]),
    JumpCloudExecutionBridge::new(JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[1]),
    JumpCloudExecutionBridge::new(JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[2]),
    JumpCloudExecutionBridge::new(JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[3]),
    JumpCloudExecutionBridge::new(JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[4]),
    JumpCloudExecutionBridge::new(JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[5]),
    JumpCloudExecutionBridge::new(JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[6]),
];

pub(super) struct JumpCloudExecutionBridge {
    provider: JumpCloudSourceExecutionAdapter,
}

impl JumpCloudExecutionBridge {
    const fn new(provider: JumpCloudSourceExecutionAdapter) -> Self {
        Self { provider }
    }

    pub(super) fn compiled_plan(&self) -> Result<SourceExecutionPlanV1, SourceExecutionError> {
        let contract = self.provider.contract().map_err(map_error)?;
        let definition =
            JumpCloudRuntimeDefinition::compile(self.provider.family()).map_err(map_error)?;
        let mut origin =
            reqwest::Url::parse(contract.origin).map_err(|_| SourceExecutionError::InvalidPlan)?;
        origin.set_path("");
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:jumpcloud:{}", contract.family_id),
            source_id: contract.source_id.to_owned(),
            family_id: contract.family_id.to_owned(),
            provider_kernel: contract.provider_kernel.to_owned(),
            method: contract.method.to_owned(),
            origin: origin.to_string().trim_end_matches('/').to_owned(),
            path: contract.path.to_owned(),
            record_selector: record_selector(self.provider.family()).to_owned(),
            id_field: id_field(self.provider.family()).to_owned(),
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
        Ok(plan)
    }

    fn validate_plan(&self, plan: &SourceExecutionPlanV1) -> Result<(), SourceExecutionError> {
        if plan != &self.compiled_plan()? {
            return Err(SourceExecutionError::InvalidPlan);
        }
        Ok(())
    }

    fn kernel(
        &self,
        context: &SourceWorkerExecutionContextV1,
        metadata: &super::wire::SourceWorkerRuntimeMetadataV2,
    ) -> Result<(JumpCloudKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        let directory_default = JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[0]
            .contract()
            .map_err(map_error)?
            .origin;
        let insights_default = JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS[6]
            .contract()
            .map_err(map_error)?
            .origin;
        let directory =
            public_value(&metadata.public_config, "base_url").unwrap_or(directory_default);
        let insights =
            public_value(&metadata.public_config, "insights_base_url").unwrap_or(insights_default);
        let filters = JumpCloudFilters {
            org_id: public_owned(&metadata.public_config, "org_id"),
            audit_start_time: public_owned(&metadata.public_config, "audit_start_time"),
            audit_end_time: public_owned(&metadata.public_config, "audit_end_time"),
            audit_services: public_value(&metadata.public_config, "audit_services")
                .into_iter()
                .flat_map(|value| value.split(','))
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect(),
            audit_sort: public_owned(&metadata.public_config, "audit_sort"),
            ..JumpCloudFilters::default()
        }
        .with_group_member_config(
            public_value(&metadata.public_config, "group_ids"),
            public_value(&metadata.public_config, "user_group_ids"),
            public_value(&metadata.public_config, "group_id"),
            public_value(&metadata.public_config, "user_group_id"),
        );
        let page_size = public_value(&metadata.public_config, "per_page")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::InvalidPlan)
            })
            .transpose()?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let kernel = JumpCloudKernel::new(
            directory,
            insights,
            &context.tenant_id,
            self.provider.family(),
            filters,
            page_size,
            &observed_at,
        )
        .map_err(map_error)?;
        let allowed_origin = if self.provider.family() == JumpCloudFamily::AuditEvents {
            insights
        } else {
            directory
        };
        Ok((kernel, allowed_origin.to_owned()))
    }

    fn provider_request(
        &self,
        kernel: &JumpCloudKernel,
        prior_cursor: Option<&str>,
        prior_watermark: Option<&str>,
    ) -> Result<crate::jumpcloud::JumpCloudRequest, SourceExecutionError> {
        if self.provider.family() == JumpCloudFamily::GroupMembers {
            return match prior_cursor {
                Some(cursor) => self.provider.plan_discover(kernel, Some(cursor)),
                None => self.provider.plan_check(kernel),
            }
            .map_err(map_error);
        }
        self.provider
            .plan(kernel, prior_cursor, prior_watermark)
            .map_err(map_error)
    }
}

impl SourceExecutionAdapter for JumpCloudExecutionBridge {
    fn source_id(&self) -> &'static str {
        self.provider
            .contract()
            .expect("registered JumpCloud contract")
            .source_id
    }

    fn family_id(&self) -> &'static str {
        self.provider
            .contract()
            .expect("registered JumpCloud contract")
            .family_id
    }

    fn provider_kernel(&self) -> &'static str {
        self.provider
            .contract()
            .expect("registered JumpCloud contract")
            .provider_kernel
    }

    fn validate_record_identity(
        &self,
        context: &SourceWorkerExecutionContextV1,
        record: &SourceWorkerRecordV1,
    ) -> Result<(), SourceExecutionError> {
        if record.event_id.trim().is_empty()
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
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
        let prior_watermark = optional_watermark(metadata)?;
        let provider_request = self.provider_request(
            &kernel,
            optional(&context.prior_cursor),
            prior_watermark.as_deref(),
        )?;
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
        let mut declared_headers = HashMap::new();
        if let Some(content_type) = provider_request.content_type() {
            declared_headers.insert("content-type".to_owned(), content_type.to_owned());
        }
        if let Some(org_id) = provider_request.organization_id() {
            declared_headers.insert("x-org-id".to_owned(), org_id.to_owned());
        }
        let mut execution = SourceWorkerHttpExecutionV2 {
            request: Some(planned),
            body: provider_request.body().unwrap_or_default().to_vec(),
            declared_headers,
            execution_intent_digest_sha256: String::new(),
            credential_operation: self
                .provider
                .contract()
                .map_err(map_error)?
                .credential_operation
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
        let (kernel, _) = self.kernel(context, metadata)?;
        let prior_watermark = optional_watermark(metadata)?;
        let provider_request = self.provider_request(
            &kernel,
            optional(&context.prior_cursor),
            prior_watermark.as_deref(),
        )?;
        let headers = envelope
            .response_headers
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        let response_metadata =
            JumpCloudResponseMetadata::from_headers(&headers).map_err(map_error)?;
        let status = u16::try_from(request.status_code)
            .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)?;
        let page = self
            .provider
            .decode(
                &kernel,
                &provider_request,
                status,
                &response_metadata,
                &request.response_body,
            )
            .map_err(map_error)?;
        let records = page
            .records
            .into_iter()
            .map(|record| {
                if record.tenant_id != context.tenant_id
                    || record.kind != plan.event_kind
                    || record.schema_ref != plan.schema_ref
                {
                    return Err(SourceExecutionError::TenantMismatch);
                }
                Ok(SourceWorkerRecordV1 {
                    provider_id: record.provider_id,
                    attributes: record.attributes.into_iter().collect(),
                    payload_json: serde_json::to_vec(&record.payload)
                        .map_err(|_| SourceExecutionError::InternalRuntime)?,
                    event_id: record.event_id,
                    occurred_at_unix_millis: parse_timestamp(&record.occurred_at)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let records = validate_and_deduplicate_records(records)?;
        let next_cursor = page.next_cursor.unwrap_or_default();
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

fn public_owned(config: &HashMap<String, String>, key: &str) -> Option<String> {
    public_value(config, key).map(str::to_owned)
}

fn optional(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

fn optional_watermark(
    metadata: &super::wire::SourceWorkerRuntimeMetadataV2,
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

const fn record_selector(family: JumpCloudFamily) -> &'static str {
    match family {
        JumpCloudFamily::Users | JumpCloudFamily::Systems | JumpCloudFamily::Applications => {
            "$.results[*]"
        }
        _ => "$[*]",
    }
}

const fn id_field(family: JumpCloudFamily) -> &'static str {
    match family {
        JumpCloudFamily::Users | JumpCloudFamily::Systems | JumpCloudFamily::Applications => "_id",
        JumpCloudFamily::Groups | JumpCloudFamily::SystemGroups => "id",
        JumpCloudFamily::GroupMembers => "to.id",
        JumpCloudFamily::AuditEvents => "id",
    }
}

fn map_error(error: JumpCloudError) -> SourceExecutionError {
    match error {
        JumpCloudError::InvalidFamily => SourceExecutionError::UnknownAdapter,
        JumpCloudError::MissingConfiguration(_) | JumpCloudError::InvalidConfiguration(_) => {
            SourceExecutionError::MissingConfiguration
        }
        JumpCloudError::InvalidOrigin => SourceExecutionError::EgressDenied,
        JumpCloudError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        JumpCloudError::MissingCredentialReference => {
            SourceExecutionError::MissingCredentialReference
        }
        JumpCloudError::CredentialUnavailable => SourceExecutionError::CredentialUnavailable,
        JumpCloudError::InvalidCursor => SourceExecutionError::InvalidCursor,
        JumpCloudError::RequestScopeMismatch => SourceExecutionError::InvalidPlan,
        JumpCloudError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        JumpCloudError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        JumpCloudError::EgressDenied => SourceExecutionError::EgressDenied,
        JumpCloudError::DnsFailure | JumpCloudError::ConnectionFailure => {
            SourceExecutionError::ConnectionFailure
        }
        JumpCloudError::ProviderTimeout => SourceExecutionError::ProviderTimeout,
        JumpCloudError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        JumpCloudError::ProviderUnavailable { .. }
        | JumpCloudError::UnexpectedStatus { .. }
        | JumpCloudError::InvalidRetryAfter => SourceExecutionError::UnexpectedProviderStatus,
        JumpCloudError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        JumpCloudError::TooManyRecords => SourceExecutionError::ResultTooLarge,
        JumpCloudError::MalformedResponse => SourceExecutionError::MalformedResponse,
        JumpCloudError::InvalidProviderRecord | JumpCloudError::CredentialMaterial => {
            SourceExecutionError::InvalidProviderRecord
        }
        JumpCloudError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        JumpCloudError::TenantMismatch => SourceExecutionError::TenantMismatch,
        JumpCloudError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
        JumpCloudError::EventContractRejection => SourceExecutionError::EventContractRejected,
        JumpCloudError::AppendFailure => SourceExecutionError::AppendFailed,
        JumpCloudError::ProjectionFailure => SourceExecutionError::ProjectionFailed,
        JumpCloudError::LeaseLoss => SourceExecutionError::LeaseLost,
        JumpCloudError::StaleAuthority => SourceExecutionError::StaleAuthority,
        JumpCloudError::InternalRuntimeFailure => SourceExecutionError::InternalRuntime,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::Value;

    use super::super::{
        dispatcher::SourceExecutionDispatcher,
        error::SourceExecutionError,
        wire::{
            SourceExecutionPlanV1, SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2,
            SourceWorkerDecodeOutputV2, SourceWorkerDecodeRequestV1,
            SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
            SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
        },
    };

    fn group_member_plan(dispatcher: SourceExecutionDispatcher) -> SourceExecutionPlanV1 {
        dispatcher
            .compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "jumpcloud".to_owned(),
                family_id: "group_members".to_owned(),
            })
            .unwrap()
    }

    fn group_member_context(prior_cursor: String, page: u32) -> SourceWorkerExecutionContextV1 {
        SourceWorkerExecutionContextV1 {
            tenant_id: "tenant".to_owned(),
            runtime_id: "runtime-1".to_owned(),
            logical_page_id: format!("source-page-v2:{page}"),
            prior_cursor,
            runtime_generation: 7,
            lease_generation: 11,
            observed_at_unix_millis: 1_780_444_800_000,
        }
    }

    fn group_member_metadata(group_ids: &str) -> SourceWorkerRuntimeMetadataV2 {
        SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([
                ("group_ids".to_owned(), group_ids.to_owned()),
                ("user_group_ids".to_owned(), "group-2, group-3".to_owned()),
                ("group_id".to_owned(), "group-4".to_owned()),
                ("user_group_id".to_owned(), "group-5".to_owned()),
                ("per_page".to_owned(), "2".to_owned()),
            ]),
            ..SourceWorkerRuntimeMetadataV2::default()
        }
    }

    fn plan_group_member_page(
        dispatcher: SourceExecutionDispatcher,
        plan: &SourceExecutionPlanV1,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> SourceWorkerHttpExecutionV2 {
        dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(context.clone()),
                }),
                metadata: Some(metadata.clone()),
            })
            .unwrap()
    }

    fn decode_group_member_page(
        dispatcher: SourceExecutionDispatcher,
        plan: &SourceExecutionPlanV1,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
        execution: &SourceWorkerHttpExecutionV2,
        body: &[u8],
    ) -> SourceWorkerDecodeOutputV2 {
        let request = execution.request.as_ref().unwrap();
        dispatcher
            .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
                request: Some(SourceWorkerDecodeRequestV1 {
                    plan: Some(plan.clone()),
                    status_code: 200,
                    response_body: body.to_vec(),
                    logical_page_id: context.logical_page_id.clone(),
                    request_intent_digest: request.request_intent_digest.clone(),
                    receipt: None,
                    context: Some(context.clone()),
                }),
                metadata: Some(metadata.clone()),
                response_headers: HashMap::new(),
                response_headers_sha256: String::new(),
                execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
            })
            .unwrap()
    }

    #[test]
    fn shared_dispatcher_runs_jumpcloud_audit_resume_with_rust_receipt_authority() {
        let dispatcher = SourceExecutionDispatcher;
        let plan = dispatcher
            .compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "jumpcloud".to_owned(),
                family_id: "audit_events".to_owned(),
            })
            .unwrap();
        let context = SourceWorkerExecutionContextV1 {
            tenant_id: "tenant".to_owned(),
            runtime_id: "runtime-1".to_owned(),
            logical_page_id: "source-page-v2:test".to_owned(),
            prior_cursor: String::new(),
            runtime_generation: 7,
            lease_generation: 11,
            observed_at_unix_millis: 1_780_444_800_000,
        };
        let metadata = SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([
                ("org_id".to_owned(), "org-1".to_owned()),
                ("per_page".to_owned(), "1".to_owned()),
            ]),
            prior_terminal_watermark_unix_millis: 1_780_369_445_000,
            prior_checkpoint: "terminal-page-1".to_owned(),
        };
        let execution = dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(context.clone()),
                }),
                metadata: Some(metadata.clone()),
            })
            .unwrap();
        assert_eq!(execution.credential_operation, "jumpcloud.x_api_key");
        assert_eq!(
            execution.allowed_origin,
            "https://api.jumpcloud.com/insights/directory/v1"
        );
        assert_eq!(
            execution.declared_headers["content-type"],
            "application/json"
        );
        let body: Value = serde_json::from_slice(&execution.body).unwrap();
        assert_eq!(body["start_time"], "2026-06-02T03:04:05Z");

        let request = execution.request.unwrap();
        let output = dispatcher
            .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
                request: Some(SourceWorkerDecodeRequestV1 {
                    plan: Some(plan),
                    status_code: 200,
                    response_body: br#"[{"id":"event-1","event_type":"login","initiated_by":{"id":"actor-1"},"timestamp":"2026-06-02T04:05:06Z"}]"#.to_vec(),
                    logical_page_id: context.logical_page_id.clone(),
                    request_intent_digest: request.request_intent_digest,
                    receipt: None,
                    context: Some(context.clone()),
                }),
                metadata: Some(metadata),
                response_headers: HashMap::from([
                    ("x-result-count".to_owned(), "1".to_owned()),
                    ("x-limit".to_owned(), "1".to_owned()),
                    (
                        "x-search_after".to_owned(),
                        r#"[1719849600000,"event-2"]"#.to_owned(),
                    ),
                ]),
                response_headers_sha256: String::new(),
                execution_intent_digest_sha256: execution.execution_intent_digest_sha256,
            })
            .unwrap();
        let receipt = output.receipt.unwrap();
        let result = output.result.unwrap();
        assert_eq!(receipt.credential_operation, "jumpcloud.x_api_key");
        assert_eq!(receipt.tenant_id, context.tenant_id);
        assert_eq!(result.records.len(), 1);
        assert_eq!(result.records[0].attributes["tenant_id"], "tenant");
        assert_eq!(result.next_cursor, r#"[1719849600000,"event-2"]"#);
    }

    #[test]
    fn shared_v2_check_and_discover_preserve_ordered_group_fanout_restart() {
        let dispatcher = SourceExecutionDispatcher;
        let plan = group_member_plan(dispatcher);
        let metadata = group_member_metadata(" group-1, group-2, group-1 ");

        let first_context = group_member_context(String::new(), 1);
        let first_execution = plan_group_member_page(dispatcher, &plan, &first_context, &metadata);
        let first_request = first_execution.request.as_ref().unwrap();
        assert_eq!(
            first_request.url,
            "https://console.jumpcloud.com/api/v2/usergroups/group-1/members?limit=2&skip=0"
        );
        let first = decode_group_member_page(
            dispatcher,
            &plan,
            &first_context,
            &metadata,
            &first_execution,
            br#"[{"to":{"id":"user-1","type":"user"}},{"to":{"id":"user-2","type":"user"}}]"#,
        );
        let first_result = first.result.unwrap();
        assert_eq!(first_result.records.len(), 2);
        assert_eq!(first_result.records[0].attributes["group_id"], "group-1");
        assert_eq!(
            first_result.next_cursor,
            r#"{"version":1,"source":"jumpcloud","mode":"fanout_path_param","token":"{\"index\":0,\"cursor\":\"2\"}"}"#
        );

        let second_context = group_member_context(first_result.next_cursor, 2);
        let second_execution =
            plan_group_member_page(dispatcher, &plan, &second_context, &metadata);
        assert_eq!(
            second_execution.request.as_ref().unwrap().url,
            "https://console.jumpcloud.com/api/v2/usergroups/group-1/members?limit=2&skip=2"
        );
        let second = decode_group_member_page(
            dispatcher,
            &plan,
            &second_context,
            &metadata,
            &second_execution,
            br#"[{"to":{"id":"user-3","type":"user"}}]"#,
        );
        let second_result = second.result.unwrap();
        assert_eq!(
            second_result.next_cursor,
            r#"{"version":1,"source":"jumpcloud","mode":"fanout_path_param","token":"{\"index\":1}"}"#
        );

        let third_context = group_member_context(second_result.next_cursor, 3);
        let third_execution = plan_group_member_page(dispatcher, &plan, &third_context, &metadata);
        assert_eq!(
            third_execution.request.as_ref().unwrap().url,
            "https://console.jumpcloud.com/api/v2/usergroups/group-2/members?limit=2&skip=0"
        );
    }

    #[test]
    fn shared_v2_group_fanout_fails_closed_on_scope_and_cursor_bounds() {
        let dispatcher = SourceExecutionDispatcher;
        let plan = group_member_plan(dispatcher);
        let too_many = (0..=1_000)
            .map(|index| format!("g{index}"))
            .collect::<Vec<_>>();
        let bounded_scope_metadata = SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([
                ("group_ids".to_owned(), too_many[..500].join(",")),
                ("user_group_ids".to_owned(), too_many[500..].join(",")),
            ]),
            ..SourceWorkerRuntimeMetadataV2::default()
        };
        let scope_error = dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(group_member_context(String::new(), 1)),
                }),
                metadata: Some(bounded_scope_metadata),
            })
            .unwrap_err();
        assert_eq!(scope_error, SourceExecutionError::MissingConfiguration);

        let malformed_context = group_member_context(
            r#"{"version":1,"source":"other","mode":"fanout_path_param","token":"{\"index\":0}"}"#
                .to_owned(),
            2,
        );
        let cursor_error = dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan),
                    context: Some(malformed_context),
                }),
                metadata: Some(group_member_metadata("group-1,group-2")),
            })
            .unwrap_err();
        assert_eq!(cursor_error, SourceExecutionError::InvalidCursor);
    }
}
