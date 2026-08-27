use std::collections::HashMap;

use crate::source_execution::{
    SourceExecutionError, SourceExecutionLifecycleEnvelopeV2, SourceExecutionLifecycleRequestV1,
    seal_page_program_v2,
};

use super::{request::MAX_CURSOR_BYTES, users_test_support as support};

#[test]
fn asana_users_plans_decodes_and_resumes_two_origin_bound_pages() {
    let plan = support::plan();
    let metadata = support::metadata();
    let first_context = support::context("tenant-a", "", 1);
    let first_execution = support::plan_page(&plan, &first_context, &metadata).unwrap();
    assert_eq!(first_execution.credential_operation, "source.bearer");
    assert_eq!(
        first_execution.allowed_origin,
        "https://app.asana.com/api/1.0"
    );
    assert!(first_execution.body.is_empty());
    assert!(first_execution.declared_headers.is_empty());
    assert_eq!(
        first_execution.request.as_ref().unwrap().url,
        "https://app.asana.com/api/1.0/users?limit=2&workspace=workspace-1"
    );

    let first = support::decode_page(
        &plan,
        &first_context,
        &metadata,
        &first_execution,
        200,
        support::USERS_PAGE_1,
        HashMap::new(),
    )
    .unwrap();
    let first_receipt = first.receipt.as_ref().unwrap();
    let first_result = first.result.as_ref().unwrap();
    assert_eq!(first_receipt.credential_operation, "source.bearer");
    assert_eq!(first_receipt.tenant_id, "tenant-a");
    assert_eq!(first_receipt.runtime_id, "asana-users-runtime");
    assert_eq!(first_result.records.len(), 2);
    assert_eq!(first_result.next_cursor, "cursor-page-2");
    assert!(
        first_result
            .records
            .iter()
            .all(|record| record.attributes["tenant_id"] == "tenant-a")
    );

    let stale = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan.clone()),
            context: Some(first_context.clone()),
            receipt: first.receipt.clone(),
            result: first.result.clone(),
            current_lease_generation: 12,
        }),
        metadata: Some(metadata.clone()),
    });
    assert_eq!(stale, Err(SourceExecutionError::LeaseLost));
    let admitted = seal_page_program_v2(&SourceExecutionLifecycleEnvelopeV2 {
        request: Some(SourceExecutionLifecycleRequestV1 {
            plan: Some(plan.clone()),
            context: Some(first_context),
            receipt: first.receipt,
            result: first.result,
            current_lease_generation: 11,
        }),
        metadata: Some(metadata.clone()),
    })
    .unwrap();
    assert_eq!(admitted.checkpoint_cursor, "cursor-page-2");

    let resumed_context = support::context("tenant-a", &admitted.checkpoint_cursor, 2);
    let resumed_execution = support::plan_page(&plan, &resumed_context, &metadata).unwrap();
    assert_eq!(
        resumed_execution.request.as_ref().unwrap().url,
        "https://app.asana.com/api/1.0/users?limit=2&workspace=workspace-1&offset=cursor-page-2"
    );
    let resumed = support::decode_page(
        &plan,
        &resumed_context,
        &metadata,
        &resumed_execution,
        200,
        support::USERS_PAGE_2,
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(resumed.result.as_ref().unwrap().records.len(), 2);
    assert!(resumed.result.as_ref().unwrap().next_cursor.is_empty());
}

#[test]
fn asana_users_round_trips_bounded_opaque_offsets_as_query_data() {
    let opaque_offset = "https://escape.example/page?token=a/b:c&next=1";
    let plan = support::plan();
    let metadata = support::metadata();
    let context = support::context("tenant-a", "", 1);
    let execution = support::plan_page(&plan, &context, &metadata).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "data": [],
        "next_page": { "offset": opaque_offset },
    }))
    .unwrap();
    let output = support::decode_page(
        &plan,
        &context,
        &metadata,
        &execution,
        200,
        &body,
        HashMap::new(),
    )
    .unwrap();
    assert_eq!(output.result.as_ref().unwrap().next_cursor, opaque_offset);

    let resumed_context = support::context("tenant-a", opaque_offset, 2);
    let resumed = support::plan_page(&plan, &resumed_context, &metadata).unwrap();
    let url = reqwest::Url::parse(&resumed.request.as_ref().unwrap().url).unwrap();
    assert_eq!(url.scheme(), "https");
    assert_eq!(url.host_str(), Some("app.asana.com"));
    assert_eq!(url.port_or_known_default(), Some(443));
    assert_eq!(url.path(), "/api/1.0/users");
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "offset")
            .map(|(_, value)| value.into_owned()),
        Some(opaque_offset.to_owned())
    );

    let oversized_offset = "x".repeat(MAX_CURSOR_BYTES + 1);
    let oversized_body = serde_json::to_vec(&serde_json::json!({
        "data": [],
        "next_page": { "offset": oversized_offset },
    }))
    .unwrap();
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            &oversized_body,
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidCursor)
    );
}
