use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionDispatcher, SourceExecutionError, SourceExecutionPlanV1,
    SourceExecutionSelectionRequestV1, SourceWorkerDecodeEnvelopeV2, SourceWorkerDecodeOutputV2,
    SourceWorkerDecodeRequestV1, SourceWorkerExecutionContextV1, SourceWorkerHttpExecutionV2,
    SourceWorkerPlanEnvelopeV2, SourceWorkerPlanRequestV1, SourceWorkerRuntimeMetadataV2,
};

pub(super) const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;
pub(super) const USERS_PAGE_1: &[u8] = include_bytes!("fixtures/users_page_1.json");
pub(super) const USERS_PAGE_2: &[u8] = include_bytes!("fixtures/users_page_2.json");

pub(super) fn context(tenant_id: &str, cursor: &str, page: u32) -> SourceWorkerExecutionContextV1 {
    SourceWorkerExecutionContextV1 {
        tenant_id: tenant_id.to_owned(),
        runtime_id: "asana-users-runtime".to_owned(),
        logical_page_id: format!("source-page-v2:asana-users-{page}"),
        prior_cursor: cursor.to_owned(),
        runtime_generation: 7,
        lease_generation: 11,
        observed_at_unix_millis: OBSERVED_AT_MILLIS,
    }
}

pub(super) fn metadata() -> SourceWorkerRuntimeMetadataV2 {
    SourceWorkerRuntimeMetadataV2 {
        public_config: HashMap::from([
            ("family".to_owned(), "users".to_owned()),
            (
                "base_url".to_owned(),
                "https://app.asana.com/api/1.0".to_owned(),
            ),
            ("workspace_gid".to_owned(), "workspace-1".to_owned()),
            ("page_size".to_owned(), "2".to_owned()),
        ]),
        prior_terminal_watermark_unix_millis: 0,
        prior_checkpoint: String::new(),
    }
}

pub(super) fn plan() -> SourceExecutionPlanV1 {
    SourceExecutionDispatcher
        .compile_plan(&SourceExecutionSelectionRequestV1 {
            source_id: "asana".to_owned(),
            family_id: "users".to_owned(),
        })
        .expect("asana.users plan")
}

pub(super) fn plan_page(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
) -> Result<SourceWorkerHttpExecutionV2, SourceExecutionError> {
    SourceExecutionDispatcher.dispatch_plan_v2(&SourceWorkerPlanEnvelopeV2 {
        request: Some(SourceWorkerPlanRequestV1 {
            plan: Some(plan.clone()),
            context: Some(context.clone()),
        }),
        metadata: Some(metadata.clone()),
    })
}

pub(super) fn decode_page(
    plan: &SourceExecutionPlanV1,
    context: &SourceWorkerExecutionContextV1,
    metadata: &SourceWorkerRuntimeMetadataV2,
    execution: &SourceWorkerHttpExecutionV2,
    status_code: u32,
    response_body: &[u8],
    response_headers: HashMap<String, String>,
) -> Result<SourceWorkerDecodeOutputV2, SourceExecutionError> {
    let request = execution.request.as_ref().expect("planned HTTP request");
    SourceExecutionDispatcher.dispatch_decode_v2(&SourceWorkerDecodeEnvelopeV2 {
        request: Some(SourceWorkerDecodeRequestV1 {
            plan: Some(plan.clone()),
            status_code,
            response_body: response_body.to_vec(),
            logical_page_id: context.logical_page_id.clone(),
            request_intent_digest: request.request_intent_digest.clone(),
            receipt: None,
            context: Some(context.clone()),
        }),
        metadata: Some(metadata.clone()),
        response_headers,
        response_headers_sha256: String::new(),
        execution_intent_digest_sha256: execution.execution_intent_digest_sha256.clone(),
    })
}
