use std::collections::HashMap;

use serde_json::Value;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionDispatcher, SourceExecutionError,
    SourceExecutionLifecycleEnvelopeV2, SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeOutputV2,
    SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
    seal_page_program_v2,
};

use super::{DEFAULT_BASE_URL, LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const ISSUE_FIXTURE: &[u8] = include_bytes!("../../../../sources/linode/testdata/read_issue.json");

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant".to_owned(),
        runtime_id: "linode-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:linode-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata() -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), "issue".to_owned()),
            ("page_size".to_owned(), "100".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan(dispatcher: SourceExecutionDispatcher) -> SourceExecutionPlanV1 {
    dispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "linode".to_owned(),
            family_id: "issue".to_owned(),
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
    status_code: u32,
    body: &[u8],
) -> Result<SourceWorkerDecodeOutputV2, SourceExecutionError> {
    let planned = execution.request.as_ref().unwrap();
    dispatcher.dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
        request: Some(SourceWorkerDecodeRequestV1 {
            plan: Some(plan.clone()),
            status_code,
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
}

#[test]
fn closed_dispatcher_registers_only_linode_issue() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    assert_eq!(plan.plan_id, "source-plan-v1:linode:issue");
    assert_eq!(plan.provider_kernel, "linode.issue");
    assert_eq!(plan.origin, DEFAULT_BASE_URL);
    assert_eq!(plan.path, "/v4/managed/issues");
    assert_eq!(plan.record_selector, "$.data[*]");
    assert_eq!(plan.event_kind, "linode.issue");
    assert_eq!(plan.schema_ref, "linode/issue/v1");
    assert_eq!(plan.max_response_bytes, 8 << 20);

    for family in ["event", "credential", "user", "", "future"] {
        assert_eq!(
            dispatcher.compile_plan(&SourceExecutionSelectionRequestV1 {
                source_id: "linode".to_owned(),
                family_id: family.to_owned(),
            }),
            Err(SourceExecutionError::UnknownAdapter),
            "{family}"
        );
    }
}

#[test]
fn plan_decode_and_checkpoint_are_credential_free_and_go_compatible() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    let context = context("", 1);
    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &context, &metadata);
    assert_eq!(execution.credential_operation, "source.bearer");
    assert_eq!(execution.allowed_origin, DEFAULT_BASE_URL);
    assert!(execution.body.is_empty());
    assert!(execution.declared_headers.is_empty());
    let request = execution.request.as_ref().unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.url,
        "https://api.linode.com/v4/managed/issues?page=1&page_size=100"
    );
    assert!(!request.url.contains("token"));

    let output = decode_page(
        dispatcher,
        &plan,
        &context,
        &metadata,
        &execution,
        200,
        ISSUE_FIXTURE,
    )
    .unwrap();
    assert_eq!(
        output.receipt.as_ref().unwrap().credential_operation,
        "source.bearer"
    );
    let result = output.result.as_ref().unwrap();
    assert_eq!(result.next_cursor, "2");
    assert_eq!(result.records.len(), 1);
    let record = &result.records[0];
    assert_eq!(record.provider_id, "823");
    assert_eq!(record.attributes["tenant_id"], "tenant");
    assert_eq!(record.attributes["finding_id"], "823");
    assert_eq!(
        record.attributes["resource_urn"],
        "urn:cerebro:tenant:linode_issue:823"
    );
    assert!(record.event_id.starts_with("linode-tenant-"));
    let payload: Value = serde_json::from_slice(&record.payload_json).unwrap();
    assert_eq!(payload["id"], 823);

    let decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan),
            context: Some(context),
            receipt: output.receipt,
            result: output.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata),
    })
    .unwrap();
    assert_eq!(decision.admitted_records.len(), 1);
    assert_eq!(decision.checkpoint_cursor, "2");
}

#[test]
fn terminal_page_uses_last_provider_identity_as_restart_boundary() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    let context = context("2", 2);
    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &context, &metadata);
    assert_eq!(
        execution.request.as_ref().unwrap().url,
        "https://api.linode.com/v4/managed/issues?page=2&page_size=100"
    );
    let output = decode_page(
        dispatcher,
        &plan,
        &context,
        &metadata,
        &execution,
        200,
        br#"{"data":[{"id":824,"resource_urn":"urn:cerebro:tenant:linode_issue:824","severity":"low","status":"open","updated_at":"2026-06-02T00:00:00Z"}],"page":2,"pages":2,"results":101}"#,
    )
    .unwrap();
    assert!(output.result.as_ref().unwrap().next_cursor.is_empty());
    let decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan),
            context: Some(context),
            receipt: output.receipt,
            result: output.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata),
    })
    .unwrap();
    assert_eq!(decision.checkpoint_cursor, "824");
}

#[test]
fn public_config_cursor_status_and_identity_fail_closed() {
    let dispatcher = SourceExecutionDispatcher;
    let plan = plan(dispatcher);
    let execution_context = context("", 1);

    let mut secret_metadata = metadata();
    secret_metadata
        .public_config
        .insert("token".to_owned(), "must-not-cross".to_owned());
    assert_eq!(
        dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(secret_metadata),
            })
            .unwrap_err(),
        SourceExecutionError::InvalidExecutionContext
    );

    let mut wrong_origin = metadata();
    wrong_origin.public_config.insert(
        "base_url".to_owned(),
        "http://linode.example.test/v4".to_owned(),
    );
    assert_eq!(
        dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(wrong_origin),
            })
            .unwrap_err(),
        SourceExecutionError::MissingConfiguration
    );

    let invalid_cursor = context("01", 2);
    assert_eq!(
        dispatcher
            .dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(invalid_cursor),
                }),
                metadata: Some(metadata()),
            })
            .unwrap_err(),
        SourceExecutionError::InvalidCursor
    );

    let metadata = metadata();
    let execution = plan_page(dispatcher, &plan, &execution_context, &metadata);
    for (status, expected) in [
        (401, SourceExecutionError::AuthenticationRejected),
        (403, SourceExecutionError::RequiredProviderScopeMissing),
        (429, SourceExecutionError::ProviderRateLimit),
        (504, SourceExecutionError::ProviderTimeout),
        (500, SourceExecutionError::UnexpectedProviderStatus),
    ] {
        assert_eq!(
            decode_page(
                dispatcher,
                &plan,
                &execution_context,
                &metadata,
                &execution,
                status,
                b"{}",
            )
            .unwrap_err(),
            expected,
            "{status}"
        );
    }

    let output = decode_page(
        dispatcher,
        &plan,
        &execution_context,
        &metadata,
        &execution,
        200,
        ISSUE_FIXTURE,
    )
    .unwrap();
    let mut record = output.result.unwrap().records.remove(0);
    record.event_id = "linode-other-identity".to_owned();
    assert_eq!(
        LINODE_ISSUE_SOURCE_EXECUTION_ADAPTER.validate_record_identity_v2(
            &execution_context,
            &record,
            &metadata,
        ),
        Err(SourceExecutionError::TenantMismatch)
    );
}
