use std::{collections::HashMap, path::Path};

use cerebro_source_catalog::{AuthModel, HttpMethod, Pagination, SourceCatalog};

use crate::source_execution::{
    SourceExecutionError, SourceExecutionLifecycleEnvelopeV2, SourceExecutionLifecycleRequestV1,
    seal_page_program_v2,
};

use super::{AsanaError, AsanaFamily, AsanaKernel, users_test_support as support};

#[test]
fn asana_users_catalog_and_runtime_config_are_exact() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("compiled source catalog");
    let source = catalog.get("asana").expect("compiled Asana source");
    assert_eq!(source.auth(), &AuthModel::BearerToken);
    assert_eq!(source.token_header(), "Authorization");
    assert_eq!(source.token_scheme(), "Bearer");
    let users = source
        .families()
        .iter()
        .find(|family| family.id() == "users")
        .expect("compiled asana.users family");
    assert_eq!(users.method(), HttpMethod::Get);
    assert_eq!(users.path(), "/users");
    assert_eq!(users.record_selector(), "$.data[*]");
    assert_eq!(users.id_field(), "gid");
    assert_eq!(users.projection().template(), "identity_user");
    assert_eq!(
        users.pagination(),
        &Pagination::Cursor {
            parameter: "offset".to_owned(),
            response_path: "$.next_page.offset".to_owned(),
            page_size_parameter: Some("limit".to_owned()),
            page_size: 100,
        }
    );

    assert!(matches!(
        AsanaKernel::new(
            "https://app.asana.com/api/1.0",
            "tenant-a",
            "workspace-1",
            AsanaFamily::Users,
            Some(0),
        ),
        Err(AsanaError::InvalidConfiguration("page_size"))
    ));
    assert!(matches!(
        AsanaKernel::new(
            "https://127.0.0.1",
            "tenant-a",
            "workspace-1",
            AsanaFamily::Users,
            Some(2),
        ),
        Err(AsanaError::UnsafeOrigin)
    ));

    let plan = support::plan();
    let context = support::context("tenant-a", "", 1);
    let mut missing_workspace = support::metadata();
    missing_workspace.public_config.remove("workspace_gid");
    assert_eq!(
        support::plan_page(&plan, &context, &missing_workspace),
        Err(SourceExecutionError::MissingConfiguration)
    );
    let mut invalid_page_size = support::metadata();
    invalid_page_size
        .public_config
        .insert("page_size".to_owned(), "101".to_owned());
    assert_eq!(
        support::plan_page(&plan, &context, &invalid_page_size),
        Err(SourceExecutionError::MissingConfiguration)
    );
}

#[test]
fn asana_users_plans_and_decodes_two_origin_bound_pages() {
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
    assert_eq!(stale, Err(SourceExecutionError::StaleGeneration));
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
fn asana_users_rejects_escape_bounds_and_typed_provider_failures() {
    let plan = support::plan();
    let context = support::context("tenant-a", "", 1);
    let metadata = support::metadata();
    let execution = support::plan_page(&plan, &context, &metadata).unwrap();

    for (status, headers, expected) in [
        (
            401,
            HashMap::new(),
            SourceExecutionError::AuthenticationRejected,
        ),
        (
            403,
            HashMap::new(),
            SourceExecutionError::RequiredProviderScopeMissing,
        ),
        (
            429,
            HashMap::from([("retry-after".to_owned(), "30".to_owned())]),
            SourceExecutionError::ProviderRateLimit,
        ),
    ] {
        assert_eq!(
            support::decode_page(&plan, &context, &metadata, &execution, status, b"", headers,),
            Err(expected)
        );
    }
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            br#"{"data": ["#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::MalformedResponse)
    );
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            br#"{"data":[],"next_page":{"offset":"https://escape.example/page"}}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::InvalidCursor)
    );
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            br#"{"data":[{"gid":"1"},{"gid":"2"},{"gid":"3"}]}"#,
            HashMap::new(),
        ),
        Err(SourceExecutionError::ResultTooLarge)
    );
    let oversized = vec![b' '; usize::try_from(plan.max_response_bytes).unwrap() + 1];
    assert_eq!(
        support::decode_page(
            &plan,
            &context,
            &metadata,
            &execution,
            200,
            &oversized,
            HashMap::new(),
        ),
        Err(SourceExecutionError::ResponseTooLarge)
    );
}
