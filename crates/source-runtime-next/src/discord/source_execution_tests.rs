use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionDispatcher, SourceExecutionError,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1,
    SourceWorkerExecutionContextV1, SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1,
    SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1, response_digest,
};

use super::catalog::{DEFAULT_BASE_URL, DISCORD_SOURCE_EXECUTION_ADAPTERS};
use crate::discord::DiscordFamily;

const GUILD_ID: &str = "100000000000000000";
const APPLICATION_ID: &str = "200000000000000000";
const OBSERVED_AT_MILLIS: i64 = 1_787_865_600_000;

fn families() -> [DiscordFamily; 4] {
    [
        DiscordFamily::AuditLog,
        DiscordFamily::Member,
        DiscordFamily::Role,
        DiscordFamily::Permission,
    ]
}

fn adapter(family: DiscordFamily) -> &'static super::DiscordSourceExecutionAdapter {
    DISCORD_SOURCE_EXECUTION_ADAPTERS
        .iter()
        .find(|adapter| adapter.family() == family)
        .expect("Discord adapter")
}

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "discord-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:discord-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata(family: DiscordFamily) -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), family.as_str().to_owned()),
            ("guild_id".to_owned(), GUILD_ID.to_owned()),
            ("application_id".to_owned(), APPLICATION_ID.to_owned()),
            ("per_page".to_owned(), "2".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

#[test]
fn shared_dispatcher_compiles_all_discord_families() {
    assert_eq!(DISCORD_SOURCE_EXECUTION_ADAPTERS.len(), families().len());
    for family in families() {
        let plan = adapter(family).compiled_plan();
        assert_eq!(plan.source_id, "discord");
        assert_eq!(plan.family_id, family.as_str());
        assert_eq!(plan.provider_kernel, family.provider_kind());
        assert_eq!(plan.origin, DEFAULT_BASE_URL);
        assert_eq!(plan.event_kind, family.provider_kind());
        assert_eq!(plan.schema_ref, format!("discord/{}/v1", family.as_str()));
        assert!(plan.required_attributes.contains(&"tenant_id".to_owned()));
        assert!(
            plan.required_attributes
                .contains(&"source_event_id".to_owned())
        );
        assert_eq!(
            SourceExecutionDispatcher
                .compile_plan(&SourceExecutionSelectionRequestV1 {
                    source_id: "discord".to_owned(),
                    family_id: family.as_str().to_owned(),
                })
                .unwrap(),
            plan
        );
    }
}

#[test]
fn every_family_plans_one_origin_restricted_bot_request() {
    for family in families() {
        let adapter = adapter(family);
        let plan = adapter.compiled_plan();
        let execution = adapter
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan),
                    context: Some(context("", 1)),
                }),
                metadata: Some(metadata(family)),
            })
            .unwrap_or_else(|error| panic!("{} plan: {error}", family.as_str()));
        assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
        assert_eq!(execution.credential_operation, "discord.bot_token");
        assert!(execution.body.is_empty());
        assert!(execution.declared_headers.is_empty());
        let request = execution.request.expect("planned request");
        assert_eq!(request.method, "GET");
        assert!(request.url.starts_with(DEFAULT_BASE_URL));
        assert!(request.url.contains(GUILD_ID));
        assert!(!request.url.contains("api_key"));
        assert!(!request.url.contains("token"));
        if matches!(family, DiscordFamily::AuditLog | DiscordFamily::Member) {
            assert!(request.url.contains("after=0"));
            assert!(request.url.contains("limit=2"));
        } else {
            assert!(!request.url.contains('?'));
        }
        if family == DiscordFamily::Permission {
            assert!(request.url.contains(APPLICATION_ID));
        }
    }
}

#[test]
fn audit_decode_preserves_scope_cursor_identity_and_typed_failures() {
    let adapter = adapter(DiscordFamily::AuditLog);
    let plan = adapter.compiled_plan();
    let context = context("", 1);
    let metadata = metadata(DiscordFamily::AuditLog);
    let execution = adapter
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    let planned = execution.request.as_ref().unwrap();
    let body = br#"{"audit_log_entries":[{"id":"100000000000000001","user_id":"400000000000000001","action_type":10,"target_id":"300000000000000001"},{"id":"100000000000000002","user_id":null,"action_type":20,"target_id":null}]}"#;
    let result = adapter
        .decode_v2(&decode_envelope(
            &plan,
            &context,
            &metadata,
            planned.request_intent_digest.clone(),
            execution.execution_intent_digest_sha256,
            200,
            body,
            HashMap::new(),
        ))
        .unwrap();
    assert_eq!(result.next_cursor, "100000000000000002");
    assert_eq!(result.records.len(), 2);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "100000000000000001");
    assert_eq!(record.attributes["tenant_id"], "tenant");
    assert_eq!(record.attributes["guild_id"], GUILD_ID);
    assert_eq!(record.attributes["event_type"], "10");
    adapter
        .validate_record_identity_v2(&context, record, &metadata)
        .unwrap();

    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (429, SourceExecutionError::ProviderRateLimit),
        (503, SourceExecutionError::UnexpectedProviderStatus),
    ] {
        let headers = if status == 429 {
            HashMap::from([("Retry-After".to_owned(), "2".to_owned())])
        } else {
            HashMap::new()
        };
        assert_eq!(
            adapter.decode_v2(&decode_envelope(
                &plan,
                &context,
                &metadata,
                planned.request_intent_digest.clone(),
                String::new(),
                status,
                b"{}",
                headers,
            )),
            Err(expected)
        );
    }
}

#[test]
fn origin_family_and_required_scope_fail_closed() {
    let member = adapter(DiscordFamily::Member);
    let mut wrong_origin = metadata(DiscordFamily::Member);
    wrong_origin.public_config.insert(
        "base_url".to_owned(),
        "https://example.invalid/api/v10".to_owned(),
    );
    assert_eq!(
        member.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(member.compiled_plan()),
                context: Some(context("", 1)),
            }),
            metadata: Some(wrong_origin),
        }),
        Err(SourceExecutionError::MissingConfiguration)
    );

    let permission = adapter(DiscordFamily::Permission);
    let missing_application = SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), "permission".to_owned()),
            ("guild_id".to_owned(), GUILD_ID.to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    };
    assert_eq!(
        permission.plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(permission.compiled_plan()),
                context: Some(context("", 1)),
            }),
            metadata: Some(missing_application),
        }),
        Err(SourceExecutionError::MissingConfiguration)
    );
}

#[allow(clippy::too_many_arguments)]
fn decode_envelope(
    plan: &crate::source_execution::SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    request_intent_digest: String,
    execution_intent_digest_sha256: String,
    status_code: u32,
    body: &[u8],
    response_headers: HashMap<String, String>,
) -> SourceWorkerDecodeEnvelopeV2 {
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: "discord.bot_token".to_owned(),
        status_code,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    SourceWorkerDecodeEnvelopeV2 {
        request: Some(SourceWorkerDecodeRequestV1 {
            plan: Some(plan.clone()),
            status_code,
            response_body: body.to_vec(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest,
            receipt: Some(receipt),
            context: Some(context.clone()),
        }),
        metadata: Some(metadata.clone()),
        response_headers,
        response_headers_sha256: String::new(),
        execution_intent_digest_sha256,
    }
}
