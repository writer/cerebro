use std::collections::HashMap;

use serde_json::Value;

use crate::source_execution::{
    SourceExecutionAdapter, SourceExecutionError, SourceExecutionPlanV1,
    SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
    SourceWorkerSafeReceiptV1, response_digest,
};

use super::GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER;

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
const GROUP_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/googleworkspace/testdata/read_group.json"
));

fn context(cursor: &str) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: "tenant-1".to_owned(),
        runtime_id: "google-workspace-runtime".to_owned(),
        logical_page_id: "source-page-v2:google-workspace-group-1".to_owned(),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

fn metadata() -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), "group".to_owned()),
            ("domain".to_owned(), "writer.com".to_owned()),
            ("customer_id".to_owned(), "C01".to_owned()),
            ("per_page".to_owned(), "2".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

fn plan() -> SourceExecutionPlanV1 {
    GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER.compiled_plan()
}

fn wrapped_fixture(next_cursor: Option<&str>) -> Vec<u8> {
    let groups: Value = serde_json::from_slice(GROUP_FIXTURE).unwrap();
    serde_json::to_vec(&serde_json::json!({
        "groups": groups,
        "nextPageToken": next_cursor,
    }))
    .unwrap()
}

#[test]
fn group_plan_is_exact_credential_free_and_cursor_bound() {
    let plan = plan();
    assert_eq!(plan.plan_id, "source-plan-v1:google_workspace:group");
    assert_eq!(plan.source_id, "google_workspace");
    assert_eq!(plan.family_id, "group");
    assert_eq!(plan.provider_kernel, "google_workspace.group");
    assert_eq!(plan.origin, "https://admin.googleapis.com");
    assert_eq!(plan.path, "/admin/directory/v1/groups");
    assert_eq!(plan.record_selector, "$.groups[*]");
    assert_eq!(plan.event_kind, "google_workspace.group");
    assert_eq!(plan.schema_ref, "google_workspace/group/v1");

    let execution = GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan),
                context: Some(context("page-2")),
            }),
            metadata: Some(metadata()),
        })
        .unwrap();
    assert_eq!(execution.credential_operation, "source.bearer");
    assert_eq!(execution.allowed_origin, "https://admin.googleapis.com");
    assert!(execution.body.is_empty());
    assert!(execution.declared_headers.is_empty());
    let request = execution.request.unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.url,
        "https://admin.googleapis.com/admin/directory/v1/groups?customer=C01&maxResults=2&pageToken=page-2"
    );
    assert!(!request.url.to_ascii_lowercase().contains("authorization"));
    assert!(!request.url.to_ascii_lowercase().contains("bearer"));
}

#[test]
fn group_decodes_go_fixture_with_stable_identity_and_cursor() {
    let plan = plan();
    let context = context("");
    let metadata = metadata();
    let execution = GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
        })
        .unwrap();
    let body = wrapped_fixture(Some("page-2"));
    let request = execution.request.as_ref().unwrap();
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: request.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: execution.credential_operation.clone(),
        status_code: 200,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(&body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    let output = GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
        .decode_v2(&SourceWorkerDecodeEnvelopeV2 {
            request: Some(SourceWorkerDecodeRequestV1 {
                plan: Some(plan),
                status_code: 200,
                response_body: body,
                logical_page_id: context.logical_page_id.clone(),
                request_intent_digest: request.request_intent_digest.clone(),
                receipt: Some(receipt),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata.clone()),
            response_headers: HashMap::new(),
            response_headers_sha256: String::new(),
            execution_intent_digest_sha256: execution.execution_intent_digest_sha256,
        })
        .unwrap();
    assert_eq!(output.next_cursor, "page-2");
    assert_eq!(output.records.len(), 1);
    assert_eq!(output.records[0].provider_id, "group-1");
    assert_eq!(output.records[0].event_id, "google-workspace-group-group-1");
    assert_eq!(output.records[0].attributes["domain"], "writer.com");
    assert_eq!(output.records[0].attributes["family"], "group");
    assert_eq!(output.records[0].attributes["group_id"], "group-1");
    GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
        .validate_record_identity_v2(&context, &output.records[0], &metadata)
        .unwrap();
    let mut foreign = output.records[0].clone();
    foreign
        .attributes
        .insert("domain".to_owned(), "other.example".to_owned());
    assert_eq!(
        GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
            .validate_record_identity_v2(&context, &foreign, &metadata),
        Err(SourceExecutionError::TenantMismatch)
    );
}

#[test]
fn group_fails_closed_on_config_status_and_tenant_identity() {
    let plan = plan();
    let context = context("");
    let mut missing_domain = metadata();
    missing_domain.public_config.remove("domain");
    assert_eq!(
        GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
            .plan_v2(&SourceWorkerPlanEnvelopeV2 {
                request: Some(SourceWorkerPlanRequestV1 {
                    plan: Some(plan.clone()),
                    context: Some(context.clone()),
                }),
                metadata: Some(missing_domain),
            })
            .unwrap_err(),
        SourceExecutionError::MissingConfiguration
    );

    let execution = GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
        .plan_v2(&SourceWorkerPlanEnvelopeV2 {
            request: Some(SourceWorkerPlanRequestV1 {
                plan: Some(plan.clone()),
                context: Some(context.clone()),
            }),
            metadata: Some(metadata()),
        })
        .unwrap();
    let request = execution.request.as_ref().unwrap();
    let body = br#"{}"#;
    let receipt = SourceWorkerSafeReceiptV1 {
        plan_digest_sha256: plan.plan_digest_sha256.clone(),
        logical_page_id: context.logical_page_id.clone(),
        request_intent_digest: request.request_intent_digest.clone(),
        runtime_generation: context.runtime_generation,
        lease_generation: context.lease_generation,
        credential_operation: execution.credential_operation.clone(),
        status_code: 401,
        response_bytes: body.len() as u64,
        response_sha256: response_digest(body),
        tenant_id: context.tenant_id.clone(),
        runtime_id: context.runtime_id.clone(),
        observed_at_unix_millis: context.observed_at_unix_millis,
    };
    assert_eq!(
        GOOGLE_WORKSPACE_GROUP_SOURCE_EXECUTION_ADAPTER
            .decode_v2(&SourceWorkerDecodeEnvelopeV2 {
                request: Some(SourceWorkerDecodeRequestV1 {
                    plan: Some(plan),
                    status_code: 401,
                    response_body: body.to_vec(),
                    logical_page_id: context.logical_page_id.clone(),
                    request_intent_digest: request.request_intent_digest.clone(),
                    receipt: Some(receipt),
                    context: Some(context),
                }),
                metadata: Some(metadata()),
                response_headers: HashMap::new(),
                response_headers_sha256: String::new(),
                execution_intent_digest_sha256: execution.execution_intent_digest_sha256,
            })
            .unwrap_err(),
        SourceExecutionError::AuthenticationRejected
    );
}
