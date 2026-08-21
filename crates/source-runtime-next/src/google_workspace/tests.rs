//! Google Workspace provider contract tests.

use super::*;

const AUDIT_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/googleworkspace/testdata/read_audit.json"
));
const GROUP_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/googleworkspace/testdata/read_group.json"
));
const GROUP_MEMBER_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/googleworkspace/testdata/read_group_member.json"
));
const ROLE_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/googleworkspace/testdata/read_role_assignment.json"
));
const USER_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/googleworkspace/testdata/read_user.json"
));

fn kernel(family: GoogleWorkspaceFamily) -> GoogleWorkspaceKernel {
    GoogleWorkspaceKernel::new(
        "https://admin.googleapis.com",
        "writer.com",
        family,
        GoogleWorkspaceFilters {
            customer_id: Some("C01".to_owned()),
            group_key: Some("security@writer.com".to_owned()),
            application: Some("admin".to_owned()),
        },
        Some(2),
    )
    .unwrap()
}

fn fixture_page(family: GoogleWorkspaceFamily, fixture: &[u8]) -> Vec<u8> {
    let records: Value = serde_json::from_slice(fixture).unwrap();
    serde_json::to_vec(&serde_json::json!({family.response_field(): records})).unwrap()
}

fn decoded_fixture_page(family: GoogleWorkspaceFamily, fixture: &[u8]) -> GoogleWorkspacePage {
    let kernel = kernel(family);
    let request = kernel.plan(None).unwrap();
    let outcome = kernel
        .decode(&request, &fixture_page(family, fixture))
        .unwrap();
    let outcome = match outcome {
            GoogleWorkspaceOutcome::Request(request) => kernel
                .decode(
                    &request,
                    br#"{"id":"1001","primaryEmail":"admin@writer.com","name":{"fullName":"Admin Writer"}}"#,
                )
                .unwrap(),
            page => page,
        };
    let GoogleWorkspaceOutcome::Page(page) = outcome else {
        panic!("fixture required more than one bounded lookup")
    };
    page
}

#[test]
fn all_five_families_plan_exact_paths_queries_and_auth_contract() {
    let cases = [
        (
            GoogleWorkspaceFamily::Audit,
            "/admin/reports/v1/activity/users/all/applications/admin",
            Some(("customerId", "C01")),
        ),
        (
            GoogleWorkspaceFamily::Group,
            "/admin/directory/v1/groups",
            Some(("customer", "C01")),
        ),
        (
            GoogleWorkspaceFamily::GroupMember,
            "/admin/directory/v1/groups/security@writer.com/members",
            None,
        ),
        (
            GoogleWorkspaceFamily::RoleAssignment,
            "/admin/directory/v1/customer/C01/roleassignments",
            None,
        ),
        (
            GoogleWorkspaceFamily::User,
            "/admin/directory/v1/users",
            Some(("customer", "C01")),
        ),
    ];
    for (family, path, scope) in cases {
        let request = kernel(family).plan(Some("page-2")).unwrap();
        let query = request
            .url()
            .query_pairs()
            .into_owned()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(request.url().path(), path);
        assert_eq!(query.get("maxResults").map(String::as_str), Some("2"));
        assert_eq!(query.get("pageToken").map(String::as_str), Some("page-2"));
        if let Some((key, value)) = scope {
            assert_eq!(query.get(key).map(String::as_str), Some(value));
        }
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert_eq!(request.accept(), "application/json");
    }
}

#[test]
fn go_fixtures_decode_for_all_families_with_source_specific_identities() {
    let cases = [
        (GoogleWorkspaceFamily::Audit, AUDIT_FIXTURE, "audit-1", 2),
        (GoogleWorkspaceFamily::Group, GROUP_FIXTURE, "group-1", 1),
        (
            GoogleWorkspaceFamily::GroupMember,
            GROUP_MEMBER_FIXTURE,
            "security@writer.com::member-1",
            2,
        ),
        (GoogleWorkspaceFamily::User, USER_FIXTURE, "1001", 2),
    ];
    for (family, fixture, provider_id, count) in cases {
        let kernel = kernel(family);
        let request = kernel.plan(None).unwrap();
        let outcome = kernel
            .decode(&request, &fixture_page(family, fixture))
            .unwrap();
        let GoogleWorkspaceOutcome::Page(page) = outcome else {
            panic!("expected direct fixture page")
        };
        assert_eq!(page.records.len(), count);
        assert_eq!(page.records[0].provider_id, provider_id);
        assert_eq!(page.records[0].provider_kind, family.provider_kind());
        assert_eq!(
            page.records[0].fields.get("domain").map(String::as_str),
            Some("writer.com")
        );
    }
}

#[test]
fn provider_cursor_and_user_attributes_preserve_go_contract() {
    let kernel = kernel(GoogleWorkspaceFamily::User);
    let request = kernel.plan(None).unwrap();
    let records: Value = serde_json::from_slice(USER_FIXTURE).unwrap();
    let body = serde_json::to_vec(&serde_json::json!({
        "users": records,
        "nextPageToken": "page-2"
    }))
    .unwrap();
    let GoogleWorkspaceOutcome::Page(page) = kernel.decode(&request, &body).unwrap() else {
        panic!("expected user page")
    };
    assert_eq!(page.next_cursor.as_deref(), Some("page-2"));
    assert_eq!(
        page.records[0].fields.get("email").map(String::as_str),
        Some("admin@writer.com")
    );
    assert_eq!(
        page.records[0]
            .fields
            .get("mfa_enrolled")
            .map(String::as_str),
        Some("false")
    );
    let materialized = page.materialize("2026-08-20T20:00:00-07:00").unwrap();
    assert_eq!(materialized.next_cursor.as_deref(), Some("page-2"));
    assert_eq!(materialized.checkpoint_cursor.as_deref(), Some("page-2"));
    assert_eq!(
        materialized.watermark.as_deref(),
        Some("2026-04-23T00:00:00Z")
    );
}

#[test]
fn all_five_families_materialize_go_event_and_discovery_contracts() {
    let cases = [
        (
            GoogleWorkspaceFamily::Audit,
            AUDIT_FIXTURE,
            "google-workspace-audit-audit-1",
            "google_workspace/audit/v1",
            "2026-04-23T00:00:00Z",
            "urn:cerebro:writer.com:google_workspace_audit:CHANGE_TWO_STEP_VERIFICATION_ENFORCEMENT",
            "google-workspace-audit-audit-2",
        ),
        (
            GoogleWorkspaceFamily::Group,
            GROUP_FIXTURE,
            "google-workspace-group-group-1",
            "google_workspace/group/v1",
            "2026-08-21T03:00:00Z",
            "urn:cerebro:writer.com:google_workspace_group:group-1",
            "google-workspace-group-group-1",
        ),
        (
            GoogleWorkspaceFamily::GroupMember,
            GROUP_MEMBER_FIXTURE,
            "google-workspace-group-member-security@writer.com-member-1",
            "google_workspace/group_member/v1",
            "2026-08-21T03:00:00Z",
            "urn:cerebro:writer.com:google_workspace_group_member:member-1",
            "google-workspace-group-member-security@writer.com-member-2",
        ),
        (
            GoogleWorkspaceFamily::RoleAssignment,
            ROLE_FIXTURE,
            "google-workspace-role-assignment-ra-1",
            "google_workspace/role_assignment/v1",
            "2026-08-21T03:00:00Z",
            "urn:cerebro:writer.com:google_workspace_role_assignment:ra-1",
            "google-workspace-role-assignment-ra-1",
        ),
        (
            GoogleWorkspaceFamily::User,
            USER_FIXTURE,
            "google-workspace-user-1001",
            "google_workspace/user/v1",
            "2025-01-15T00:00:00Z",
            "urn:cerebro:writer.com:google_workspace_user:1001",
            "google-workspace-user-1002",
        ),
    ];
    for (family, fixture, event_id, schema_ref, occurred_at, discovery_urn, checkpoint) in cases {
        let page = decoded_fixture_page(family, fixture)
            .materialize("2026-08-20T20:00:00-07:00")
            .unwrap();
        assert_eq!(page.events[0].event_id, event_id);
        assert_eq!(page.events[0].source_id, "google_workspace");
        assert_eq!(page.events[0].tenant_id, "writer.com");
        assert_eq!(page.events[0].provider_kind, family.provider_kind());
        assert_eq!(page.events[0].schema_ref, schema_ref);
        assert_eq!(page.events[0].occurred_at, occurred_at);
        assert_eq!(page.events[0].discovery_urn, discovery_urn);
        assert_eq!(
            page.events[0].payload.get("domain").and_then(Value::as_str),
            Some("writer.com")
        );
        assert_eq!(page.checkpoint_cursor.as_deref(), Some(checkpoint));
        assert_eq!(
            page.watermark,
            page.events.last().map(|event| event.occurred_at.clone())
        );
    }
    let memberships =
        decoded_fixture_page(GoogleWorkspaceFamily::GroupMember, GROUP_MEMBER_FIXTURE)
            .materialize("2026-08-20T20:00:00-07:00")
            .unwrap();
    assert_eq!(
        memberships.events[0]
            .payload
            .get("group_key")
            .and_then(Value::as_str),
        Some("security@writer.com")
    );
}

#[test]
fn materialization_matches_go_time_fallback_and_empty_page_semantics() {
    let kernel = kernel(GoogleWorkspaceFamily::User);
    let request = kernel.plan(None).unwrap();
    let GoogleWorkspaceOutcome::Page(page) = kernel
            .decode(
                &request,
                br#"{"users":[{"id":"1003","primaryEmail":"fallback@writer.com","lastLoginTime":"invalid","creationTime":"2026-08-20T01:02:03.456Z"}]}"#,
            )
            .unwrap()
        else {
            panic!("expected user page")
        };
    let materialized = page.materialize("2026-08-21T03:00:00Z").unwrap();
    assert_eq!(
        materialized.events[0].occurred_at,
        "2026-08-20T01:02:03.456Z"
    );
    assert!(matches!(
        page.materialize("not-a-time"),
        Err(GoogleWorkspaceError::InvalidObservedAt)
    ));

    let empty = GoogleWorkspacePage {
        records: Vec::new(),
        next_cursor: Some("provider-should-not-advance".to_owned()),
    }
    .materialize("2026-08-21T03:00:00Z")
    .unwrap();
    assert!(empty.events.is_empty());
    assert_eq!(empty.next_cursor, None);
    assert_eq!(empty.checkpoint_cursor, None);
    assert_eq!(empty.watermark, None);
}

#[test]
fn materialization_fail_closes_go_read_only_identity_fallbacks() {
    for (family, body) in [
            (
                GoogleWorkspaceFamily::User,
                br#"{"users":[{"primaryEmail":"fallback@writer.com"}]}"#.as_slice(),
            ),
            (
                GoogleWorkspaceFamily::Group,
                br#"{"groups":[{"email":"fallback-group@writer.com"}]}"#.as_slice(),
            ),
            (
                GoogleWorkspaceFamily::Audit,
                br#"{"items":[{"id":{"time":"2026-08-20T01:02:03Z","uniqueQualifier":"audit-without-event"},"events":[{"name":""}]}]}"#.as_slice(),
            ),
        ] {
            let kernel = kernel(family);
            let request = kernel.plan(None).unwrap();
            let GoogleWorkspaceOutcome::Page(page) = kernel.decode(&request, body).unwrap()
            else {
                panic!("expected direct page")
            };
            assert!(matches!(
                page.materialize("2026-08-21T03:00:00Z"),
                Err(GoogleWorkspaceError::MissingDiscoveryIdentity)
            ));
        }
}

#[test]
fn missing_role_assignment_id_and_malformed_records_fail_before_admission() {
    let role_kernel = kernel(GoogleWorkspaceFamily::RoleAssignment);
    let request = role_kernel.plan(None).unwrap();
    assert!(matches!(
        role_kernel.decode(
            &request,
            br#"{"items":[{"roleId":"super-admin","assigneeType":"GROUP"}]}"#,
        ),
        Err(GoogleWorkspaceError::MissingRecordIdentity)
    ));

    let user_kernel = kernel(GoogleWorkspaceFamily::User);
    let request = user_kernel.plan(None).unwrap();
    assert!(matches!(
        user_kernel.decode(&request, br#"{"users":[42]}"#),
        Err(GoogleWorkspaceError::InvalidRecord)
    ));
}

#[test]
fn role_assignment_fanout_caches_unique_user_once_per_page() {
    let kernel = kernel(GoogleWorkspaceFamily::RoleAssignment);
    let request = kernel.plan(None).unwrap();
    let mut records: Vec<Value> = serde_json::from_slice(ROLE_FIXTURE).unwrap();
    let mut second = records[0].clone();
    second["roleAssignmentId"] = Value::String("ra-2".to_owned());
    records.push(second);
    let body = serde_json::to_vec(&serde_json::json!({
        "items": records,
        "nextPageToken": "roles-2"
    }))
    .unwrap();
    let GoogleWorkspaceOutcome::Request(user_request) = kernel.decode(&request, &body).unwrap()
    else {
        panic!("expected role user lookup")
    };
    assert_eq!(user_request.url().path(), "/admin/directory/v1/users/1001");
    let GoogleWorkspaceOutcome::Page(page) = kernel
            .decode(
                &user_request,
                br#"{"id":"1001","primaryEmail":"admin@writer.com","name":{"fullName":"Admin Writer"}}"#,
            )
            .unwrap()
        else {
            panic!("expected enriched role page")
        };
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.next_cursor.as_deref(), Some("roles-2"));
    assert!(page.records.iter().all(|record| {
        record.fields.get("subject_email").map(String::as_str) == Some("admin@writer.com")
    }));
    assert!(page.records.iter().all(|record| {
        record.fields.get("subject_name").map(String::as_str) == Some("Admin Writer")
    }));
}

#[test]
fn genuine_role_fixture_uses_one_bounded_lookup() {
    let kernel = kernel(GoogleWorkspaceFamily::RoleAssignment);
    let request = kernel.plan(None).unwrap();
    let outcome = kernel
        .decode(
            &request,
            &fixture_page(GoogleWorkspaceFamily::RoleAssignment, ROLE_FIXTURE),
        )
        .unwrap();
    let GoogleWorkspaceOutcome::Request(request) = outcome else {
        panic!("expected fixture lookup request")
    };
    assert_eq!(request.url().path(), "/admin/directory/v1/users/1001");
}

#[test]
fn kernel_fails_closed_on_unsafe_origins_invalid_scope_and_bad_pages() {
    assert!(matches!(
        GoogleWorkspaceKernel::new(
            "http://169.254.169.254",
            "writer.com",
            GoogleWorkspaceFamily::User,
            GoogleWorkspaceFilters::default(),
            None,
        ),
        Err(GoogleWorkspaceError::InvalidBaseUrl)
    ));
    assert!(matches!(
        GoogleWorkspaceKernel::new(
            "https://admin.googleapis.com",
            "writer.com",
            GoogleWorkspaceFamily::GroupMember,
            GoogleWorkspaceFilters::default(),
            None,
        ),
        Err(GoogleWorkspaceError::MissingGroupKey)
    ));
    let user_kernel = kernel(GoogleWorkspaceFamily::User);
    let group_request = kernel(GoogleWorkspaceFamily::Group).plan(None).unwrap();
    assert!(matches!(
        user_kernel.decode(&group_request, br#"{"groups":[]}"#),
        Err(GoogleWorkspaceError::RequestScopeMismatch)
    ));
    let request = user_kernel.plan(None).unwrap();
    assert!(matches!(
        user_kernel.decode(&request, br#"{"users":{}}"#),
        Err(GoogleWorkspaceError::InvalidResponse)
    ));
}
