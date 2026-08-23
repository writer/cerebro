use std::collections::HashMap;

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    TailscaleError, TailscaleFamily, TailscaleKernel, TailscaleResponseMetadata,
    TailscaleRuntimeDefinition,
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
        SourceWorkerRecordV1, SourceWorkerRuntimeMetadataV2,
    },
};

const DEFAULT_BASE_URL: &str = "https://api.tailscale.com/api/v2";
const MAX_RESPONSE_BYTES: u64 = 4 << 20;

pub(super) static TAILSCALE_ADAPTERS: [TailscaleExecutionBridge; 7] = [
    TailscaleExecutionBridge::new(TailscaleFamily::Device),
    TailscaleExecutionBridge::new(TailscaleFamily::Grant),
    TailscaleExecutionBridge::new(TailscaleFamily::Group),
    TailscaleExecutionBridge::new(TailscaleFamily::Service),
    TailscaleExecutionBridge::new(TailscaleFamily::Tag),
    TailscaleExecutionBridge::new(TailscaleFamily::Tailnet),
    TailscaleExecutionBridge::new(TailscaleFamily::User),
];

pub(super) struct TailscaleExecutionBridge {
    family: TailscaleFamily,
}

impl TailscaleExecutionBridge {
    const fn new(family: TailscaleFamily) -> Self {
        Self { family }
    }

    pub(super) fn compiled_plan(&self) -> Result<SourceExecutionPlanV1, SourceExecutionError> {
        let definition = TailscaleRuntimeDefinition::compile(self.family).map_err(map_error)?;
        let mut plan = SourceExecutionPlanV1 {
            plan_id: format!("source-plan-v1:tailscale:{}", self.family.as_str()),
            source_id: definition.source_id.to_owned(),
            family_id: self.family.as_str().to_owned(),
            provider_kernel: provider_kernel(self.family).to_owned(),
            method: definition.method.to_owned(),
            origin: DEFAULT_BASE_URL.to_owned(),
            path: format!("/api/v2{}", definition.path),
            record_selector: record_selector(self.family).to_owned(),
            id_field: id_field(self.family).to_owned(),
            singleton_fallback_id: String::new(),
            max_response_bytes: MAX_RESPONSE_BYTES,
            event_kind: definition.contract.kind.to_owned(),
            schema_ref: definition.contract.schema_ref.to_owned(),
            required_attributes: definition
                .contract
                .required_attributes
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            required_payload_fields: definition
                .contract
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
        metadata: &SourceWorkerRuntimeMetadataV2,
    ) -> Result<(TailscaleKernel, String), SourceExecutionError> {
        validate_execution_context(context)?;
        validate_runtime_metadata(metadata)?;
        let base_url =
            public_value(&metadata.public_config, "base_url").unwrap_or(DEFAULT_BASE_URL);
        let tailnet = public_value(&metadata.public_config, "tailnet")
            .ok_or(SourceExecutionError::MissingConfiguration)?;
        let page_size = public_value(&metadata.public_config, "per_page")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|_| SourceExecutionError::MissingConfiguration)
            })
            .transpose()?;
        let observed_at = timestamp(context.observed_at_unix_millis)?;
        let kernel = TailscaleKernel::new(
            base_url,
            &context.tenant_id,
            tailnet,
            self.family,
            page_size,
            &observed_at,
        )
        .map_err(map_error)?;
        Ok((kernel, base_url.to_owned()))
    }
}

impl SourceExecutionAdapter for TailscaleExecutionBridge {
    fn source_id(&self) -> &'static str {
        "tailscale"
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
        if record.event_id.trim().is_empty()
            || record.attributes.get("tenant_id") != Some(&context.tenant_id)
            || record.attributes.get("family").map(String::as_str) != Some(self.family.as_str())
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
        let provider_request = kernel
            .plan(optional(&context.prior_cursor))
            .map_err(map_error)?;
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
        let response_metadata = TailscaleResponseMetadata {
            next_cursor: response_header(&envelope.response_headers, "x-next-cursor"),
            retry_after_seconds: response_header(&envelope.response_headers, "retry-after")
                .map(|value| {
                    value
                        .parse::<u64>()
                        .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)
                })
                .transpose()?,
        };
        let status = u16::try_from(request.status_code)
            .map_err(|_| SourceExecutionError::UnexpectedProviderStatus)?;
        let page = kernel
            .decode_http(
                &provider_request,
                status,
                &response_metadata,
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
                let provider_id = record
                    .attributes
                    .get("external_id")
                    .cloned()
                    .ok_or(SourceExecutionError::MissingStableIdentity)?;
                Ok(SourceWorkerRecordV1 {
                    provider_id,
                    attributes: record.attributes.into_iter().collect(),
                    payload_json: serde_json::to_vec(&record.payload)
                        .map_err(|_| SourceExecutionError::InternalRuntime)?,
                    event_id: record.event_id,
                    occurred_at_unix_millis: parse_timestamp(&record.occurred_at)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let records = validate_and_deduplicate_records(records)?;
        let next_cursor = checkpoint.cursor.unwrap_or_default();
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

fn response_header(headers: &HashMap<String, String>, key: &str) -> Option<String> {
    headers
        .get(key)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
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

const fn provider_kernel(family: TailscaleFamily) -> &'static str {
    match family {
        TailscaleFamily::Device => "tailscale.device",
        TailscaleFamily::Grant => "tailscale.grant",
        TailscaleFamily::Group => "tailscale.group",
        TailscaleFamily::Service => "tailscale.service",
        TailscaleFamily::Tag => "tailscale.tag",
        TailscaleFamily::Tailnet => "tailscale.tailnet",
        TailscaleFamily::User => "tailscale.user",
    }
}

const fn record_selector(family: TailscaleFamily) -> &'static str {
    match family {
        TailscaleFamily::Device => "$.devices[*]",
        TailscaleFamily::Grant => "$.grants[*]",
        TailscaleFamily::Group => "$.groups",
        TailscaleFamily::Service => "$.vipServices[*]",
        TailscaleFamily::Tag => "$.tagOwners",
        TailscaleFamily::Tailnet => "$",
        TailscaleFamily::User => "$.users[*]",
    }
}

const fn id_field(family: TailscaleFamily) -> &'static str {
    match family {
        TailscaleFamily::Service => "name",
        _ => "id",
    }
}

fn map_error(error: TailscaleError) -> SourceExecutionError {
    match error {
        TailscaleError::MissingConfiguration(_)
        | TailscaleError::InvalidConfiguration(_)
        | TailscaleError::InvalidBaseUrl => SourceExecutionError::MissingConfiguration,
        TailscaleError::InvalidOrigin | TailscaleError::EgressDenied => {
            SourceExecutionError::EgressDenied
        }
        TailscaleError::InvalidTenantId => SourceExecutionError::InvalidExecutionContext,
        TailscaleError::MissingCredentialReference => {
            SourceExecutionError::MissingCredentialReference
        }
        TailscaleError::CredentialUnavailable => SourceExecutionError::CredentialUnavailable,
        TailscaleError::AuthenticationRejected => SourceExecutionError::AuthenticationRejected,
        TailscaleError::RequiredScopeMissing => SourceExecutionError::RequiredProviderScopeMissing,
        TailscaleError::DnsFailure | TailscaleError::ConnectionFailure => {
            SourceExecutionError::ConnectionFailure
        }
        TailscaleError::ProviderTimeout => SourceExecutionError::ProviderTimeout,
        TailscaleError::RateLimited { .. } => SourceExecutionError::ProviderRateLimit,
        TailscaleError::ProviderUnavailable { .. }
        | TailscaleError::UnexpectedStatus { .. }
        | TailscaleError::InvalidRetryAfter => SourceExecutionError::UnexpectedProviderStatus,
        TailscaleError::ResponseTooLarge => SourceExecutionError::ResponseTooLarge,
        TailscaleError::TooManyRecords => SourceExecutionError::ResultTooLarge,
        TailscaleError::MalformedResponse => SourceExecutionError::MalformedResponse,
        TailscaleError::InvalidProviderRecord | TailscaleError::CredentialMaterial => {
            SourceExecutionError::InvalidProviderRecord
        }
        TailscaleError::MissingStableIdentity => SourceExecutionError::MissingStableIdentity,
        TailscaleError::InvalidCursor => SourceExecutionError::InvalidCursor,
        TailscaleError::TenantMismatch => SourceExecutionError::TenantMismatch,
        TailscaleError::ConflictingDuplicate => SourceExecutionError::DuplicateConflict,
        TailscaleError::RequestScopeMismatch | TailscaleError::InvalidCatalogContract => {
            SourceExecutionError::InvalidPlan
        }
        TailscaleError::EventContractRejected => SourceExecutionError::EventContractRejected,
        TailscaleError::AppendFailure => SourceExecutionError::AppendFailed,
        TailscaleError::ProjectionFailure => SourceExecutionError::ProjectionFailed,
        TailscaleError::LeaseLoss => SourceExecutionError::LeaseLost,
        TailscaleError::StaleAuthority => SourceExecutionError::StaleAuthority,
        TailscaleError::UnknownFamily => SourceExecutionError::UnknownAdapter,
        TailscaleError::InternalRuntimeFailure => SourceExecutionError::InternalRuntime,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::super::{
        dispatcher::SourceExecutionDispatcher,
        error::SourceExecutionError,
        runtime::seal_page_program_v2,
        wire::{
            SourceExecutionLifecycleEnvelopeV2, SourceExecutionLifecycleRequestV1,
            SourceExecutionPlanV1, SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2,
            SourceWorkerDecodeOutputV2, SourceWorkerDecodeRequestV1,
            SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
            SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
        },
    };
    use super::DEFAULT_BASE_URL;

    const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

    fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
        SourceWorkerExecutionContextV1 {
            tenant_id: "tenant".to_owned(),
            runtime_id: "tailscale-runtime".to_owned(),
            logical_page_id: format!("source-page-v2:tailscale-{page}"),
            prior_cursor: cursor.to_owned(),
            runtime_generation: 7,
            lease_generation: 11,
            observed_at_unix_millis: OBSERVED_AT_MILLIS,
        }
    }

    fn metadata() -> SourceWorkerRuntimeMetadataV2 {
        SourceWorkerRuntimeMetadataV2 {
            public_config: HashMap::from([
                ("tailnet".to_owned(), "example.test".to_owned()),
                ("per_page".to_owned(), "100".to_owned()),
            ]),
            prior_terminal_watermark_unix_millis: 0,
            prior_checkpoint: String::new(),
        }
    }

    fn plan(dispatcher: SourceExecutionDispatcher, family: &str) -> SourceExecutionPlanV1 {
        dispatcher
            .compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "tailscale".to_owned(),
                family_id: family.to_owned(),
            })
            .unwrap()
    }

    fn plan_page(
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

    fn decode_page(
        dispatcher: SourceExecutionDispatcher,
        plan: &SourceExecutionPlanV1,
        context: &SourceWorkerExecutionContextV1,
        metadata: &SourceWorkerRuntimeMetadataV2,
        execution: &SourceWorkerHttpExecutionV2,
        body: &[u8],
    ) -> SourceWorkerDecodeOutputV2 {
        let planned = execution.request.as_ref().unwrap();
        dispatcher
            .dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
                request: Some(SourceWorkerDecodeRequestV1 {
                    plan: Some(plan.clone()),
                    status_code: 200,
                    response_body: body.to_vec(),
                    logical_page_id: context.logical_page_id.clone(),
                    request_intent_digest: planned.request_intent_digest.clone(),
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
    fn closed_dispatcher_compiles_plans_and_decodes_all_seven_legacy_families() {
        let dispatcher = SourceExecutionDispatcher;
        let cases = [
            ("device", br#"{"devices":[{"id":"device-1"}]}"#.as_slice()),
            ("grant", br#"{"grants":[{"id":"grant-1"}]}"#.as_slice()),
            (
                "group",
                br#"{"groups":{"group:eng":["alice@example.test"]}}"#.as_slice(),
            ),
            (
                "service",
                br#"{"vipServices":[{"name":"svc:api"}]}"#.as_slice(),
            ),
            (
                "tag",
                br#"{"tagOwners":{"tag:prod":["group:eng"]}}"#.as_slice(),
            ),
            ("tailnet", br#"{}"#.as_slice()),
            (
                "user",
                br#"{"users":[{"id":"user-1","loginName":"alice@example.test"}]}"#.as_slice(),
            ),
        ];
        for (family, body) in cases {
            let plan = plan(dispatcher, family);
            assert_eq!(plan.provider_kernel, format!("tailscale.{family}"));
            let context = context("", 1);
            let metadata = metadata();
            let execution = plan_page(dispatcher, &plan, &context, &metadata);
            assert_eq!(execution.credential_operation, "source.bearer");
            assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
            assert!(execution.body.is_empty());
            assert!(execution.declared_headers.is_empty());
            let request = execution.request.as_ref().unwrap();
            assert!(request.url.starts_with(DEFAULT_BASE_URL));
            assert!(request.url.contains("limit=100&per_page=100"));
            let output = decode_page(dispatcher, &plan, &context, &metadata, &execution, body);
            let result = output.result.unwrap();
            assert_eq!(result.records.len(), 1, "{family}");
            assert_eq!(result.records[0].attributes["tenant_id"], "tenant");
            assert_eq!(result.records[0].attributes["family"], family);
            assert_eq!(
                result.records[0].event_id.split('-').next(),
                Some("tailscale")
            );
        }
    }

    #[test]
    fn cursor_checkpoint_and_restart_are_rust_sealed_and_fail_closed() {
        let dispatcher = SourceExecutionDispatcher;
        let plan = plan(dispatcher, "user");
        let first_context = context("", 1);
        let metadata = metadata();
        let first_execution = plan_page(dispatcher, &plan, &first_context, &metadata);
        let mut first = decode_page(
            dispatcher,
            &plan,
            &first_context,
            &metadata,
            &first_execution,
            br#"{"users":[{"id":"user-1","loginName":"alice@example.test"}],"nextCursor":"page-2"}"#,
        );
        let receipt = first.receipt.take().unwrap();
        let result = first.result.take().unwrap();
        assert_eq!(result.next_cursor, "page-2");
        let program = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
            request: Some(SourceExecutionLifecycleRequestV1 {
                plan: Some(plan.clone()),
                context: Some(first_context),
                receipt: Some(receipt),
                result: Some(result),
                current_lease_generation: 11,
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
        assert_eq!(program.checkpoint_cursor, "page-2");
        assert_eq!(program.checkpoint_watermark_unix_millis, OBSERVED_AT_MILLIS);

        let resumed_context = context(&program.checkpoint_cursor, 2);
        let resumed = plan_page(dispatcher, &plan, &resumed_context, &metadata);
        assert!(resumed.request.unwrap().url.ends_with("cursor=page-2"));

        let malformed = context("https://other.example/page", 2);
        let error = dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(malformed),
                }),
                metadata: Some(metadata.clone()),
            })
            .unwrap_err();
        assert_eq!(error, SourceExecutionError::InvalidCursor);

        let missing_tailnet = SourceWorkerRuntimeMetadataV2::default();
        let error = dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan),
                    context: Some(context("", 1)),
                }),
                metadata: Some(missing_tailnet),
            })
            .unwrap_err();
        assert_eq!(error, SourceExecutionError::MissingConfiguration);
    }
}
