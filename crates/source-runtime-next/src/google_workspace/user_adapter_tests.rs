//! Users-family adapter fixtures and host-boundary tests.

use std::collections::BTreeMap;

use reqwest::StatusCode;
use serde_json::Value;

use super::*;

const USERS_PAGE_1: &[u8] = include_bytes!("fixtures/users_page_1.json");
const USERS_PAGE_2: &[u8] = include_bytes!("fixtures/users_page_2.json");
const MISSING_SCOPE: &[u8] = include_bytes!("fixtures/missing_scope.json");
const GO_USER_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/googleworkspace/testdata/read_user.json"
));
const OBSERVED_AT: &str = "2026-08-21T03:00:00Z";

fn user_adapter(tenant: &str, page_size: usize) -> GoogleWorkspaceKernel {
    GoogleWorkspaceKernel::new_user_adapter(
        "https://admin.googleapis.com",
        tenant,
        Some("C01".to_owned()),
        Some(page_size),
    )
    .unwrap()
}

struct GoUserAttributeFixture<'a> {
    user_id: &'a str,
    email: &'a str,
    display_name: &'a str,
    created_at: &'a str,
    last_login_at: &'a str,
    org_unit_path: &'a str,
    is_admin: bool,
    is_delegated_admin: bool,
    mfa_enabled: bool,
}

fn go_user_attributes(fixture: GoUserAttributeFixture<'_>) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("archived".to_owned(), "false".to_owned()),
        ("created_at".to_owned(), fixture.created_at.to_owned()),
        ("display_name".to_owned(), fixture.display_name.to_owned()),
        ("domain".to_owned(), "writer.com".to_owned()),
        ("email".to_owned(), fixture.email.to_owned()),
        ("family".to_owned(), "user".to_owned()),
        ("is_admin".to_owned(), fixture.is_admin.to_string()),
        (
            "is_delegated_admin".to_owned(),
            fixture.is_delegated_admin.to_string(),
        ),
        ("last_login_at".to_owned(), fixture.last_login_at.to_owned()),
        ("login".to_owned(), fixture.email.to_owned()),
        ("mfa_enforced".to_owned(), fixture.mfa_enabled.to_string()),
        ("mfa_enrolled".to_owned(), fixture.mfa_enabled.to_string()),
        ("org_unit_path".to_owned(), fixture.org_unit_path.to_owned()),
        ("primary_email".to_owned(), fixture.email.to_owned()),
        ("suspended".to_owned(), "false".to_owned()),
        ("user_id".to_owned(), fixture.user_id.to_owned()),
    ])
}

#[test]
fn users_adapter_plans_exact_credential_free_request() {
    let adapter = user_adapter("writer.com", 2);
    let request = adapter.plan_user_page(Some("page-2")).unwrap();
    assert_eq!(request.method(), "GET");
    assert_eq!(request.authorization_scheme(), "Bearer");
    assert_eq!(request.accept(), "application/json");
    assert_eq!(
        request.url().as_str(),
        "https://admin.googleapis.com/admin/directory/v1/users?customer=C01&maxResults=2&pageToken=page-2"
    );
    assert!(!GoogleWorkspaceKernel::user_adapter_accepts_credential_values());
    assert_eq!(
        GoogleWorkspaceKernel::user_adapter_required_oauth_scope(),
        "https://www.googleapis.com/auth/admin.directory.user.readonly"
    );
}

#[test]
fn users_adapter_keeps_opaque_pagination_on_the_compiled_origin() {
    let adapter = user_adapter("writer.com", 2);
    assert_eq!(
        adapter.plan_user_page(None).unwrap(),
        adapter.plan_user_page(Some("")).unwrap()
    );
    let normalized = adapter.plan_user_page(Some("  page-2  ")).unwrap();
    assert_eq!(
        normalized
            .url()
            .query_pairs()
            .find(|(name, _)| name == "pageToken")
            .map(|(_, value)| value.into_owned()),
        Some("page-2".to_owned())
    );
    let request = adapter
        .plan_user_page(Some("https://attacker.invalid/next?tenant=other"))
        .unwrap();
    assert_eq!(request.url().scheme(), "https");
    assert_eq!(request.url().host_str(), Some("admin.googleapis.com"));
    assert_eq!(request.url().path(), "/admin/directory/v1/users");
    assert_eq!(
        request
            .url()
            .query_pairs()
            .find(|(name, _)| name == "pageToken")
            .map(|(_, value)| value.into_owned()),
        Some("https://attacker.invalid/next?tenant=other".to_owned())
    );

    let oversized = "x".repeat((4 << 10) + 1);
    assert_eq!(
        adapter.plan_user_page(Some(&oversized)),
        Err(GoogleWorkspaceError::InvalidCursor)
    );
    assert_eq!(
        adapter.plan_user_page(Some("page\n2")),
        Err(GoogleWorkspaceError::InvalidCursor)
    );
}

#[test]
fn users_adapter_preserves_empty_page_continuation_and_terminal_semantics() {
    let adapter = user_adapter("writer.com", 2);
    let request = adapter.plan_user_page(None).unwrap();
    let continued = adapter
        .decode_user_response(
            &request,
            StatusCode::OK,
            br#"{"users":[],"nextPageToken":"  page-2  "}"#,
            OBSERVED_AT,
        )
        .unwrap();
    assert!(continued.events.is_empty());
    assert_eq!(continued.next_cursor.as_deref(), Some("page-2"));
    assert_eq!(continued.checkpoint_cursor.as_deref(), Some("page-2"));
    assert!(continued.watermark.is_none());

    let terminal = adapter
        .decode_user_response(
            &request,
            StatusCode::OK,
            br#"{"users":[],"nextPageToken":""}"#,
            OBSERVED_AT,
        )
        .unwrap();
    assert!(terminal.events.is_empty());
    assert!(terminal.next_cursor.is_none());
    assert!(terminal.checkpoint_cursor.is_none());
    assert!(terminal.watermark.is_none());
}

#[test]
fn users_adapter_runs_two_pages_with_dedupe_and_restartable_cursor() {
    let adapter = user_adapter("writer.com", 2);
    let first_request = adapter.plan_user_page(None).unwrap();
    let first = adapter
        .decode_user_response(&first_request, StatusCode::OK, USERS_PAGE_1, OBSERVED_AT)
        .unwrap();
    assert_eq!(first.events.len(), 1);
    assert_eq!(first.next_cursor.as_deref(), Some("page-2"));
    assert_eq!(first.checkpoint_cursor.as_deref(), Some("page-2"));
    assert_eq!(first.events[0].event_id, "google-workspace-user-1001");
    assert_eq!(
        first.events[0].discovery_urn,
        "urn:cerebro:writer.com:google_workspace_user:1001"
    );

    let resumed_request = adapter
        .plan_user_page(first.next_cursor.as_deref())
        .unwrap();
    let resumed = adapter
        .decode_user_response(&resumed_request, StatusCode::OK, USERS_PAGE_2, OBSERVED_AT)
        .unwrap();
    assert_eq!(resumed.events.len(), 1);
    assert_eq!(resumed.events[0].event_id, "google-workspace-user-1002");
    assert!(resumed.next_cursor.is_none());
    assert_eq!(
        resumed.checkpoint_cursor.as_deref(),
        Some("google-workspace-user-1002")
    );

    let replay = adapter
        .decode_user_response(&first_request, StatusCode::OK, USERS_PAGE_1, OBSERVED_AT)
        .unwrap();
    assert_eq!(replay, first);
}

#[test]
fn users_adapter_matches_go_user_fixture_semantics() {
    let adapter = user_adapter("writer.com", 2);
    let request = adapter.plan_user_page(None).unwrap();
    let users: Value = serde_json::from_slice(GO_USER_FIXTURE).unwrap();
    let provider_users = users.as_array().unwrap().clone();
    let body = serde_json::to_vec(&serde_json::json!({"users": users})).unwrap();
    let page = adapter
        .decode_user_response(&request, StatusCode::OK, &body, OBSERVED_AT)
        .unwrap();
    assert_eq!(page.events.len(), 2);
    let expected = [
        (
            "google-workspace-user-1001",
            "2025-01-15T00:00:00Z",
            "urn:cerebro:writer.com:google_workspace_user:1001",
            go_user_attributes(GoUserAttributeFixture {
                user_id: "1001",
                email: "admin@writer.com",
                display_name: "Admin Writer",
                created_at: "2025-01-01T00:00:00.000Z",
                last_login_at: "2025-01-15T00:00:00.000Z",
                org_unit_path: "/",
                is_admin: true,
                is_delegated_admin: true,
                mfa_enabled: false,
            }),
        ),
        (
            "google-workspace-user-1002",
            "2026-04-23T00:00:00Z",
            "urn:cerebro:writer.com:google_workspace_user:1002",
            go_user_attributes(GoUserAttributeFixture {
                user_id: "1002",
                email: "alice@writer.com",
                display_name: "Alice Writer",
                created_at: "2026-04-20T00:00:00.000Z",
                last_login_at: "2026-04-23T00:00:00.000Z",
                org_unit_path: "/Engineering",
                is_admin: false,
                is_delegated_admin: false,
                mfa_enabled: true,
            }),
        ),
    ];
    for ((event, provider), (event_id, occurred_at, discovery_urn, attributes)) in
        page.events.iter().zip(provider_users).zip(expected)
    {
        assert_eq!(event.event_id, event_id);
        assert_eq!(event.tenant_id, "writer.com");
        assert_eq!(event.source_id, "google_workspace");
        assert_eq!(event.provider_kind, "google_workspace.user");
        assert_eq!(event.schema_ref, "google_workspace/user/v1");
        assert_eq!(event.occurred_at, occurred_at);
        assert_eq!(event.discovery_urn, discovery_urn);
        assert_eq!(event.attributes, attributes);
        let mut expected_payload = provider;
        expected_payload
            .as_object_mut()
            .unwrap()
            .insert("domain".to_owned(), Value::String("writer.com".to_owned()));
        assert_eq!(event.payload, expected_payload);
    }
    assert!(page.next_cursor.is_none());
    assert_eq!(
        page.checkpoint_cursor.as_deref(),
        Some("google-workspace-user-1002")
    );
    assert_eq!(page.watermark.as_deref(), Some("2026-04-23T00:00:00Z"));
}

#[test]
fn users_adapter_scopes_canonical_identity_by_tenant() {
    let writer = user_adapter("writer.com", 2);
    let example = user_adapter("example.com", 2);
    let writer_request = writer.plan_user_page(None).unwrap();
    let example_request = example.plan_user_page(None).unwrap();
    let writer_page = writer
        .decode_user_response(&writer_request, StatusCode::OK, USERS_PAGE_1, OBSERVED_AT)
        .unwrap();
    let example_page = example
        .decode_user_response(&example_request, StatusCode::OK, USERS_PAGE_1, OBSERVED_AT)
        .unwrap();
    assert_eq!(
        writer_page.events[0].event_id,
        example_page.events[0].event_id
    );
    assert_ne!(
        (
            &writer_page.events[0].tenant_id,
            &writer_page.events[0].event_id,
        ),
        (
            &example_page.events[0].tenant_id,
            &example_page.events[0].event_id,
        )
    );
    assert_ne!(
        writer_page.events[0].discovery_urn,
        example_page.events[0].discovery_urn
    );
    assert_eq!(writer_page.events[0].tenant_id, "writer.com");
    assert_eq!(example_page.events[0].tenant_id, "example.com");
}

#[test]
fn users_adapter_classifies_auth_scope_permission_and_retry_failures() {
    let adapter = user_adapter("writer.com", 2);
    let request = adapter.plan_user_page(None).unwrap();
    let cases = [
        (
            StatusCode::UNAUTHORIZED,
            br#"{"error":{"message":"secret-bearing provider text"}}"#.as_slice(),
            GoogleWorkspaceError::AuthenticationRejected,
        ),
        (
            StatusCode::FORBIDDEN,
            MISSING_SCOPE,
            GoogleWorkspaceError::RequiredUserScopeMissing,
        ),
        (
            StatusCode::FORBIDDEN,
            br#"{"error":{"errors":[{"reason":"forbidden"}]}}"#.as_slice(),
            GoogleWorkspaceError::PermissionDenied,
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            br#"{"error":{"message":"quota"}}"#.as_slice(),
            GoogleWorkspaceError::RateLimited,
        ),
        (
            StatusCode::FORBIDDEN,
            br#"{"error":{"errors":[{"reason":"rateLimitExceeded"}]}}"#.as_slice(),
            GoogleWorkspaceError::RateLimited,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            br#"{"error":{"message":"unavailable"}}"#.as_slice(),
            GoogleWorkspaceError::ProviderUnavailable(503),
        ),
        (
            StatusCode::FOUND,
            br#"{"error":{"message":"redirect refused"}}"#.as_slice(),
            GoogleWorkspaceError::UnexpectedProviderStatus(302),
        ),
    ];
    for (status, body, expected) in cases {
        let error = adapter
            .decode_user_response(&request, status, body, OBSERVED_AT)
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("secret-bearing provider text"));
    }
    let provider_canary = "provider-user@fixture.invalid";
    let credential_canary = "fixture-only-bearer-canary";
    let body = format!(
        r#"{{"error":{{"message":"{provider_canary}","credential":"{credential_canary}"}}}}"#
    );
    let error = adapter
        .decode_user_response(
            &request,
            StatusCode::FORBIDDEN,
            body.as_bytes(),
            OBSERVED_AT,
        )
        .unwrap_err();
    for rendered in [error.to_string(), format!("{error:?}")] {
        assert!(!rendered.contains(provider_canary));
        assert!(!rendered.contains(credential_canary));
    }
}

#[test]
fn users_adapter_rejects_response_record_cursor_and_identity_overflow() {
    let adapter = user_adapter("writer.com", 1);
    let request = adapter.plan_user_page(None).unwrap();
    let oversized_response = vec![b' '; (8 << 20) + 1];
    assert_eq!(
        adapter.decode_user_response(&request, StatusCode::OK, &oversized_response, OBSERVED_AT,),
        Err(GoogleWorkspaceError::ResponseTooLarge)
    );
    assert_eq!(
        adapter.decode_user_response(&request, StatusCode::OK, USERS_PAGE_1, OBSERVED_AT),
        Err(GoogleWorkspaceError::TooManyUserRecords)
    );

    let adapter = user_adapter("writer.com", 2);
    let request = adapter.plan_user_page(None).unwrap();
    let conflicting = br#"{
        "users": [
            {"id":"1001","primaryEmail":"admin@writer.com"},
            {"id":"1001","primaryEmail":"other@writer.com"}
        ]
    }"#;
    assert_eq!(
        adapter.decode_user_response(&request, StatusCode::OK, conflicting, OBSERVED_AT),
        Err(GoogleWorkspaceError::ConflictingUserIdentity)
    );
    assert_eq!(
        adapter.decode_user_response(
            &request,
            StatusCode::OK,
            br#"{"users":[{"primaryEmail":"fallback@writer.com"}]}"#,
            OBSERVED_AT,
        ),
        Err(GoogleWorkspaceError::MissingRecordIdentity)
    );
    assert_eq!(
        adapter.decode_user_response(
            &request,
            StatusCode::OK,
            br#"{"users":[{"id":"1003","isAdmin":"true"}]}"#,
            OBSERVED_AT,
        ),
        Err(GoogleWorkspaceError::InvalidRecord)
    );
    let defaults = adapter
        .decode_user_response(
            &request,
            StatusCode::OK,
            br#"{"users":[{"id":"1003"}]}"#,
            OBSERVED_AT,
        )
        .unwrap();
    for attribute in [
        "is_admin",
        "is_delegated_admin",
        "mfa_enrolled",
        "mfa_enforced",
        "suspended",
        "archived",
    ] {
        assert_eq!(
            defaults.events[0]
                .attributes
                .get(attribute)
                .map(String::as_str),
            Some("false")
        );
    }
    let oversized_cursor = serde_json::to_vec(&serde_json::json!({
        "users": [],
        "nextPageToken": "x".repeat((4 << 10) + 1)
    }))
    .unwrap();
    assert_eq!(
        adapter.decode_user_response(&request, StatusCode::OK, &oversized_cursor, OBSERVED_AT),
        Err(GoogleWorkspaceError::InvalidCursor)
    );
}

#[test]
fn users_adapter_rejects_invalid_tenant_family_and_request_contracts() {
    assert!(matches!(
        GoogleWorkspaceKernel::new_user_adapter(
            "https://admin.googleapis.com",
            "Writer.COM",
            None,
            None,
        ),
        Err(GoogleWorkspaceError::InvalidTenantIdentity)
    ));
    assert!(matches!(
        GoogleWorkspaceKernel::new_user_adapter(
            "https://admin.googleapis.com",
            "writer.com",
            Some("customer\nother".to_owned()),
            None,
        ),
        Err(GoogleWorkspaceError::InvalidCustomerId)
    ));
    assert!(matches!(
        GoogleWorkspaceKernel::new_user_adapter(
            "https://admin.googleapis.com",
            "writer.com",
            Some(String::new()),
            None,
        ),
        Err(GoogleWorkspaceError::InvalidCustomerId)
    ));
    let group = GoogleWorkspaceKernel::new(
        "https://admin.googleapis.com",
        "writer.com",
        GoogleWorkspaceFamily::Group,
        GoogleWorkspaceFilters::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        group.plan_user_page(None),
        Err(GoogleWorkspaceError::UserFamilyRequired)
    );
    let adapter = user_adapter("writer.com", 2);
    let generic_request = adapter.plan(None).unwrap();
    assert_eq!(
        adapter.decode_user_response(
            &generic_request,
            StatusCode::OK,
            br#"{"users":[]}"#,
            OBSERVED_AT,
        ),
        Err(GoogleWorkspaceError::RequestScopeMismatch)
    );
}
