use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionLifecycleEnvelopeV2,
    SourceExecutionLifecycleRequestV1, SourceExecutionPlanV1, SourceWorkerDecodeEnvelopeV2,
    SourceWorkerDecodeRequestV1, SourceWorkerDecodeResultV1, SourceWorkerExecutionContextV1,
    SourceWorkerHttpExecutionV2, SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1,
    SourceWorkerRuntimeMetadataV2, SourceWorkerSafeReceiptV1, response_digest,
    seal_page_program_v2,
};

use super::{GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER, durable_checkpoint_cursor};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const USERS_PAGE_1: &[u8] = include_bytes!("fixtures/users_page_1.json");
const USERS_PAGE_2: &[u8] = include_bytes!("fixtures/users_page_2.json");

fn context(cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant-1".to_owned(),
        runtime_id: "google-workspace-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:google-workspace-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata() -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), "user".to_owned()),
            ("domain".to_owned(), "writer.com".to_owned()),
            ("customer_id".to_owned(), "C01".to_owned()),
            ("per_page".to_owned(), "2".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan() -> SourceExecutionPlanV1 {
    GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.compiled_plan()
}

fn plan_page(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> SourceWorkerHttpExecutionV2 {
    GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap()
}

fn decode_page(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    execution: &SourceWorkerHttpExecutionV2,
    status_code: u32,
    body: &[u8],
) -> Result<(SourceWorkerSafeReceiptV1, SourceWorkerDecodeResultV1), SourceExecutionError> {
    let request = execution.request.as_ref().unwrap();
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: request.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: execution.credential_operation.clone(),
        status_code,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    let result = GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.decode_v2(
        &SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(plan.clone()),
                status_code,
                response_body: body.to_vec(),
                logical_page_id: context.logical_page_id.clone(),
                request_intent_digest: request.request_intent_digest.clone(),
                receipt: Some(receipt.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
        },
    )?;
    Ok((receipt, result))
}

#[test]
fn users_plan_is_exact_and_credential_free() {
    let plan = plan();
    assert_eq!(plan.plan_id, "source-plan-v1:google_workspace:user");
    assert_eq!(plan.source_id, "google_workspace");
    assert_eq!(plan.family_id, "user");
    assert_eq!(plan.provider_kernel, "google_workspace.user");
    assert_eq!(plan.origin, "https://admin.googleapis.com");
    assert_eq!(plan.path, "/admin/directory/v1/users");
    assert_eq!(plan.record_selector, "$.users[*]");
    assert_eq!(plan.event_kind, "google_workspace.user");
    assert_eq!(plan.schema_ref, "google_workspace/user/v1");

    let context = context("page-2", 2);
    let execution = plan_page(&plan, &context, &metadata());
    assert_eq!(execution.credential_operation, "source.bearer");
    assert_eq!(execution.allowed_origin, "https://admin.googleapis.com");
    assert!(execution.body.is_empty());
    assert!(execution.declared_headers.is_empty());
    let request = execution.request.unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.url,
        "https://admin.googleapis.com/admin/directory/v1/users?customer=C01&maxResults=2&pageToken=page-2"
    );
    assert!(!request.url.to_ascii_lowercase().contains("authorization"));
    assert!(!request.url.to_ascii_lowercase().contains("bearer"));
}

#[test]
fn users_run_two_pages_with_go_compatible_identity_and_checkpoint() {
    let plan = plan();
    let metadata = metadata();
    let first_context = context("", 1);
    let first_execution = plan_page(&plan, &first_context, &metadata);
    let (first_receipt, first) = decode_page(
        &plan,
        &first_context,
        &metadata,
        &first_execution,
        200,
        USERS_PAGE_1,
    )
    .unwrap();
    assert_eq!(first.next_cursor, "page-2");
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].provider_id, "1001");
    assert_eq!(first.records[0].event_id, "google-workspace-user-1001");
    assert_eq!(first.records[0].attributes["domain"], "writer.com");
    assert_eq!(
        durable_checkpoint_cursor(&plan, &first).as_deref(),
        Some("page-2")
    );
    let decision = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan.clone()),
            context: Some(first_context),
            receipt: Some(first_receipt),
            result: Some(first),
            current_lease_generation: 11,
        }),
        metadata: Some(metadata.clone()),
    })
    .unwrap();
    assert_eq!(decision.admitted_records.len(), 1);
    assert_eq!(decision.checkpoint_cursor, "page-2");

    let second_context = context("page-2", 2);
    let second_execution = plan_page(&plan, &second_context, &metadata);
    let (_, second) = decode_page(
        &plan,
        &second_context,
        &metadata,
        &second_execution,
        200,
        USERS_PAGE_2,
    )
    .unwrap();
    assert!(second.next_cursor.is_empty());
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].provider_id, "1002");
    assert_eq!(second.records[0].event_id, "google-workspace-user-1002");
    assert_eq!(
        durable_checkpoint_cursor(&plan, &second).as_deref(),
        Some("google-workspace-user-1002")
    );
}

#[test]
fn users_fail_closed_on_config_cursor_provider_and_identity_errors() {
    let plan = plan();
    let execution_context = context("", 1);
    let mut missing_domain = metadata();
    missing_domain.public_config.remove("domain");
    assert_eq!(
        GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(execution_context.clone()),
                }),
                metadata: Some(missing_domain),
            })
            .unwrap_err(),
        SourceExecutionError::MissingConfiguration
    );

    let invalid_cursor = context(&"x".repeat((4 << 10) + 1), 1);
    assert_eq!(
        GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
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
    let execution = plan_page(&plan, &execution_context, &metadata);
    assert_eq!(
        decode_page(&plan, &execution_context, &metadata, &execution, 401, b"{}",).unwrap_err(),
        SourceExecutionError::AuthenticationRejected
    );
    assert_eq!(
        decode_page(
            &plan,
            &execution_context,
            &metadata,
            &execution,
            403,
            br#"{"error":{"status":"PERMISSION_DENIED","message":"Request had insufficient authentication scopes."}}"#,
        )
        .unwrap_err(),
        SourceExecutionError::RequiredProviderScopeMissing
    );

    let (_, mut output) = decode_page(
        &plan,
        &execution_context,
        &metadata,
        &execution,
        200,
        br#"{"users":[{"id":"1001","primaryEmail":"admin@writer.com"}]}"#,
    )
    .unwrap();
    let mut record = output.records.remove(0);
    record
        .attributes
        .insert("domain".to_owned(), "other.example".to_owned());
    assert_eq!(
        GOOGLE_WORKSPACE_USER_SOURCE_EXECUTION_ADAPTER.validate_record_identity_v2(
            &execution_context,
            &record,
            &metadata,
        ),
        Err(SourceExecutionError::TenantMismatch)
    );
}
