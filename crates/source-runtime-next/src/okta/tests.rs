use std::str::FromStr;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::*;

const ORIGIN: &str = "https://writer.okta.com";
const TENANT: &str = "writer.okta.com";

#[test]
fn closed_family_catalog_matches_the_go_runtime_catalog() {
    let expected = [
        "audit",
        "admin_role",
        "app_assignment",
        "application",
        "api_token",
        "authorization_server",
        "authenticator",
        "brand",
        "device_assurance",
        "event_hook",
        "group",
        "group_membership",
        "identity_provider",
        "inline_hook",
        "log_stream",
        "network_zone",
        "policy_rule",
        "threat_insight",
        "trusted_origin",
        "user",
    ];
    let actual: Vec<_> = OktaFamily::ALL
        .into_iter()
        .map(OktaFamily::as_str)
        .collect();
    assert_eq!(actual, expected);
    let catalog = include_str!("../../../../sources/okta/catalog.yaml");
    let compiled: Vec<_> = catalog
        .split_once("runtime_families:\n")
        .unwrap()
        .1
        .split_once("event_contracts:\n")
        .unwrap()
        .0
        .lines()
        .filter_map(|line| line.trim().strip_prefix("- "))
        .collect();
    assert_eq!(compiled, expected);
    for family in expected {
        assert_eq!(OktaFamily::from_str(family).unwrap().as_str(), family);
        assert!(catalog.contains(&format!("kind: okta.{family}\n")));
        assert!(catalog.contains(&format!("schema_ref: okta/{family}/v1\n")));
    }
    assert_eq!(
        OktaFamily::from_str("unknown"),
        Err(OktaError::InvalidFamily)
    );
}

#[test]
fn plans_every_family_without_credential_material() {
    for family in OktaFamily::ALL {
        let filters = filters(family);
        let kernel = OktaKernel::new(ORIGIN, TENANT, family, filters, Some(200)).unwrap();
        assert!(!OktaKernel::requires_credentials());
        let request = kernel.plan(None).unwrap();
        assert_eq!(request.url().origin().unicode_serialization(), ORIGIN);
        assert_eq!(request.authorization_scheme(), "SSWS");
        assert_eq!(request.accept(), "application/json");
        assert!(!request.url().as_str().contains("credential-secret"));
        if !family.singleton() {
            assert_eq!(
                request
                    .url()
                    .query_pairs()
                    .find(|(name, _)| name == "limit")
                    .map(|(_, value)| value.into_owned()),
                Some("200".to_owned())
            );
        }
    }
}

#[test]
fn scoped_families_fail_closed_without_their_parent() {
    for (family, field) in [
        (OktaFamily::GroupMembership, "group_id"),
        (OktaFamily::AppAssignment, "app_id"),
        (OktaFamily::AdminRole, "user_id"),
        (OktaFamily::PolicyRule, "policy_id"),
    ] {
        assert!(matches!(
            OktaKernel::new(ORIGIN, TENANT, family, OktaFilters::default(), None),
            Err(OktaError::MissingScope(name)) if name == field
        ));
    }
}

#[test]
fn selector_validation_and_defaults_match_the_go_runtime() {
    for value in [None, Some("asc"), Some("ascending")] {
        let kernel = OktaKernel::new(
            ORIGIN,
            TENANT,
            OktaFamily::User,
            OktaFilters {
                sort_order: value.map(str::to_owned),
                ..OktaFilters::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(
            query(&kernel.plan(None).unwrap(), "sortOrder").as_deref(),
            Some("asc")
        );
    }
    let group = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::Group,
        OktaFilters {
            search: Some("profile.name sw \"sec\"".to_owned()),
            sort_by: Some("profile.name".to_owned()),
            ..OktaFilters::default()
        },
        None,
    )
    .unwrap()
    .plan(None)
    .unwrap();
    assert_eq!(query(&group, "sortBy").as_deref(), Some("profile.name"));
    let application = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::Application,
        OktaFilters {
            q: Some("portal".to_owned()),
            ..OktaFilters::default()
        },
        None,
    )
    .unwrap()
    .plan(None)
    .unwrap();
    assert_eq!(query(&application, "q").as_deref(), Some("portal"));
    assert!(matches!(
        OktaKernel::new(
            ORIGIN,
            TENANT,
            OktaFamily::Audit,
            OktaFilters {
                search: Some("eventType eq x".to_owned()),
                ..OktaFilters::default()
            },
            None,
        ),
        Err(OktaError::InvalidConfiguration("audit selectors"))
    ));
    assert!(matches!(
        OktaKernel::new(
            ORIGIN,
            TENANT,
            OktaFamily::Group,
            OktaFilters {
                since: Some("2026-08-21T00:00:00Z".to_owned()),
                ..OktaFilters::default()
            },
            None,
        ),
        Err(OktaError::InvalidConfiguration("since/until"))
    ));
}

#[test]
fn rejects_unsafe_origins_and_out_of_range_pages() {
    for origin in [
        "http://example.okta.com",
        "http://localhost",
        "https://127.0.0.1",
        "https://10.0.0.1",
        "https://example.okta.com/path",
        "https://user@example.okta.com",
    ] {
        assert!(matches!(
            OktaKernel::new(
                origin,
                TENANT,
                OktaFamily::User,
                OktaFilters::default(),
                None
            ),
            Err(OktaError::InvalidBaseUrl)
        ));
    }
    assert!(matches!(
        OktaKernel::new(
            ORIGIN,
            TENANT,
            OktaFamily::User,
            OktaFilters::default(),
            Some(201)
        ),
        Err(OktaError::InvalidPageSize)
    ));
}

#[test]
fn response_fixtures_preserve_go_identity_and_projection_contracts() {
    struct Case {
        family: OktaFamily,
        body: &'static [u8],
        expected: &'static str,
        required_fields: &'static [&'static str],
    }
    let cases = [
        Case { family: OktaFamily::Audit, body: br#"[{"uuid":"evt-1","published":"2026-04-23T01:00:00Z","eventType":"user.session.start","severity":"INFO","target":[{"id":"00u1","type":"User"}]}]"#, expected: include_str!("../../../../sources/okta/testdata/read_audit.json"), required_fields: &["event_type", "resource_id", "resource_type"] },
        Case { family: OktaFamily::User, body: include_bytes!("../../../../sources/okta/testdata/api/user/list_users/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_user.json"), required_fields: &["user_id", "status", "email", "login"] },
        Case { family: OktaFamily::Group, body: include_bytes!("../../../../sources/okta/testdata/api/group/list_groups/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_group.json"), required_fields: &["group_id", "group_name", "type"] },
        Case { family: OktaFamily::GroupMembership, body: include_bytes!("../../../../sources/okta/testdata/api/group_membership/list_group_members/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_group_membership.json"), required_fields: &["group_id", "member_id", "member_user_id", "member_email"] },
        Case { family: OktaFamily::Application, body: include_bytes!("../../../../sources/okta/testdata/api/application/list_applications/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_application.json"), required_fields: &["app_id", "app_name", "status", "sign_on_mode"] },
        Case { family: OktaFamily::AppAssignment, body: include_bytes!("../../../../sources/okta/testdata/api/app_assignment/list_app_assignments/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_app_assignment.json"), required_fields: &["app_id", "subject_id", "subject_type", "status"] },
        Case { family: OktaFamily::AdminRole, body: include_bytes!("../../../../sources/okta/testdata/api/admin_role/list_admin_roles/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_admin_role.json"), required_fields: &["role_id", "role_name", "subject_id", "is_admin"] },
        Case { family: OktaFamily::PolicyRule, body: include_bytes!("../../../../sources/okta/testdata/api/policy_rule/list_policy_rules/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_policy_rule.json"), required_fields: &["policy_id", "policy_rule_id", "status", "resource_type"] },
        Case { family: OktaFamily::EventHook, body: include_bytes!("../../../../sources/okta/testdata/api/event_hook/list_event_hooks/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_event_hook.json"), required_fields: &["event_hook_id", "name", "status"] },
        Case { family: OktaFamily::InlineHook, body: include_bytes!("../../../../sources/okta/testdata/api/inline_hook/list_inline_hooks/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_inline_hook.json"), required_fields: &["inline_hook_id", "name", "status"] },
        Case { family: OktaFamily::NetworkZone, body: include_bytes!("../../../../sources/okta/testdata/api/network_zone/list_network_zones/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_network_zone.json"), required_fields: &["network_zone_id", "zone_id", "status", "zone_type"] },
        Case { family: OktaFamily::TrustedOrigin, body: include_bytes!("../../../../sources/okta/testdata/api/trusted_origin/list_trusted_origins/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_trusted_origin.json"), required_fields: &["trusted_origin_id", "origin", "scope_types"] },
        Case { family: OktaFamily::Authenticator, body: include_bytes!("../../../../sources/okta/testdata/api/authenticator/list_authenticators/response.json"), expected: include_str!("../../../../sources/okta/testdata/read_authenticator.json"), required_fields: &["authenticator_id", "key", "name", "status"] },
    ];
    for case in cases {
        let kernel =
            OktaKernel::new(ORIGIN, TENANT, case.family, filters(case.family), Some(200)).unwrap();
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                OktaResponse {
                    status: 200,
                    body: case.body,
                    link_header: None,
                },
                observed_at(),
            )
            .unwrap();
        assert!(!page.records.is_empty(), "{}", case.family.as_str());
        let expected: Vec<Value> = serde_json::from_str(case.expected).unwrap();
        let expected = expected.first().unwrap();
        let record = &page.records[0];
        assert_eq!(record.provider_kind, expected["kind"].as_str().unwrap());
        assert_eq!(record.schema_ref, expected["schema_ref"].as_str().unwrap());
        assert_eq!(record.tenant_id, TENANT);
        assert!(!record.event_id.contains(&record.provider_id));
        for field in case.required_fields {
            let actual = record.fields.get(*field).filter(|value| !value.is_empty());
            assert!(
                actual.is_some(),
                "{}/{} missing {field}",
                case.family.as_str(),
                record.provider_id
            );
            if let Some(expected_value) = expected["attributes"].get(*field).and_then(Value::as_str)
            {
                assert_eq!(
                    actual.map(String::as_str),
                    Some(expected_value),
                    "{}/{} {field}",
                    case.family.as_str(),
                    record.provider_id
                );
            }
        }
        assert_eq!(
            record.fields.get("family").map(String::as_str),
            Some(case.family.as_str())
        );
    }
}

#[test]
fn link_cursor_is_origin_locked_and_assignment_phase_round_trips() {
    let kernel = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::User,
        OktaFilters::default(),
        None,
    )
    .unwrap();
    let request = kernel.plan(Some("prior")).unwrap();
    let body = br#"[{"id":"u1","lastUpdated":"2026-08-21T12:00:00Z"}]"#;
    let page = kernel
        .decode(
            &request,
            OktaResponse {
                status: 200,
                body,
                link_header: Some("</api/v1/users?after=next&limit=10>; rel=\"next\""),
            },
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("next"));
    assert_eq!(
        kernel
            .plan(page.next_cursor.as_deref())
            .unwrap()
            .url()
            .query_pairs()
            .find_map(|(name, value)| (name == "after").then(|| value.into_owned()))
            .as_deref(),
        Some("next")
    );

    let error = kernel
        .decode(
            &request,
            OktaResponse {
                status: 200,
                body,
                link_header: Some("<https://evil.example/api/v1/users?after=next>; rel=next"),
            },
            observed_at(),
        )
        .unwrap_err();
    assert_eq!(error, OktaError::InvalidCursor);

    let assignment = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::AppAssignment,
        filters(OktaFamily::AppAssignment),
        None,
    )
    .unwrap();
    let users = assignment.plan(None).unwrap();
    assert!(users.url().path().ends_with("/users"));
    let page = assignment
        .decode(
            &users,
            OktaResponse {
                status: 200,
                body: b"[]",
                link_header: None,
            },
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("groups:"));
    assert!(
        assignment
            .plan(page.next_cursor.as_deref())
            .unwrap()
            .url()
            .path()
            .ends_with("/groups")
    );
}

#[test]
fn typed_provider_failures_remain_distinct() {
    let kernel = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::User,
        OktaFilters::default(),
        None,
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    for (status, expected) in [
        (401, OktaError::AuthenticationRejected),
        (403, OktaError::PermissionDenied),
        (429, OktaError::RateLimited),
        (503, OktaError::ProviderUnavailable),
        (418, OktaError::UnexpectedProviderStatus),
    ] {
        assert_eq!(
            kernel.decode(
                &request,
                OktaResponse {
                    status,
                    body: b"{}",
                    link_header: None
                },
                observed_at()
            ),
            Err(expected)
        );
    }
}

#[test]
fn secret_shaped_provider_fields_do_not_leave_the_kernel() {
    let kernel = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::ApiToken,
        OktaFilters::default(),
        None,
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    let page = kernel.decode(
        &request,
        OktaResponse { status: 200, body: br#"[{"id":"tok1","name":"integration","created":"2026-08-21T12:00:00Z","token":"secret","access_token":"secret","clientSecret":"secret","authorization":"secret","nested":{"password":"secret","cookie":"secret"}}]"#, link_header: None },
        observed_at(),
    ).unwrap();
    let encoded = serde_json::to_string(&page.records[0].payload).unwrap();
    assert!(!encoded.contains("secret"));
    assert!(!encoded.contains("clientSecret"));
    assert!(!encoded.contains("access_token"));
    assert!(!encoded.contains("authorization"));
    assert!(!encoded.contains("password"));
    assert!(!encoded.contains("cookie"));
    assert!(!page.records[0].event_id.contains("secret"));
    assert!(!page.records[0].occurred_at.contains("secret"));
    assert!(
        page.records[0]
            .fields
            .values()
            .all(|value| !value.contains("secret"))
    );
    let response = OktaResponse {
        status: 200,
        body: b"credential-secret",
        link_header: Some("credential-secret"),
    };
    assert!(!format!("{response:?}").contains("credential-secret"));
}

#[test]
fn provider_payload_cannot_supply_tenant_identity() {
    let kernel = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::User,
        OktaFilters::default(),
        None,
    )
    .unwrap();
    assert_eq!(
        kernel.decode(
            &kernel.plan(None).unwrap(),
            OktaResponse {
                status: 200,
                body:
                    br#"[{"id":"u1","tenant_id":"attacker","lastUpdated":"2026-08-21T12:00:00Z"}]"#,
                link_header: None,
            },
            observed_at(),
        ),
        Err(OktaError::InvalidResponse)
    );
}

#[test]
fn tenant_scope_changes_event_identity_and_audit_time_fails_closed() {
    let first = OktaKernel::new(
        ORIGIN,
        "tenant-a",
        OktaFamily::Audit,
        OktaFilters::default(),
        None,
    )
    .unwrap();
    let second = OktaKernel::new(
        ORIGIN,
        "tenant-b",
        OktaFamily::Audit,
        OktaFilters::default(),
        None,
    )
    .unwrap();
    let body =
        br#"[{"uuid":"evt1","published":"2026-08-21T12:00:00Z","eventType":"user.session.start"}]"#;
    let decode = |kernel: &OktaKernel| {
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                OktaResponse {
                    status: 200,
                    body,
                    link_header: None,
                },
                observed_at(),
            )
            .unwrap()
            .records[0]
            .event_id
            .clone()
    };
    assert_ne!(decode(&first), decode(&second));
    for invalid in [
        br#"[{"uuid":"evt1"}]"#.as_slice(),
        br#"[{"uuid":"evt1","published":"1970-01-01T00:00:00Z"}]"#.as_slice(),
        br#"[{"uuid":"evt1","published":"not-a-time"}]"#.as_slice(),
    ] {
        assert_eq!(
            first.decode(
                &first.plan(None).unwrap(),
                OktaResponse {
                    status: 200,
                    body: invalid,
                    link_header: None
                },
                observed_at()
            ),
            Err(OktaError::InvalidResponse)
        );
    }
}

#[test]
fn response_and_record_limits_fail_closed() {
    let kernel = OktaKernel::new(
        ORIGIN,
        TENANT,
        OktaFamily::User,
        OktaFilters::default(),
        Some(1),
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    let oversized = vec![b' '; response::TEST_MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        kernel.decode(
            &request,
            OktaResponse {
                status: 200,
                body: &oversized,
                link_header: None
            },
            OffsetDateTime::UNIX_EPOCH
        ),
        Err(OktaError::ResponseTooLarge)
    );
    assert_eq!(
        kernel.decode(
            &request,
            OktaResponse {
                status: 200,
                body: br#"[{"id":"u1"},{"id":"u2"}]"#,
                link_header: None
            },
            observed_at()
        ),
        Err(OktaError::TooManyRecords)
    );
}

fn observed_at() -> OffsetDateTime {
    OffsetDateTime::parse("2026-08-21T12:00:00Z", &Rfc3339).unwrap()
}

fn filters(family: OktaFamily) -> OktaFilters {
    OktaFilters {
        group_id: (family == OktaFamily::GroupMembership)
            .then(|| "example-cb373fbc662034f4".to_owned()),
        app_id: (family == OktaFamily::AppAssignment)
            .then(|| "example-f0a6c6d9df5c0037".to_owned()),
        user_id: (family == OktaFamily::AdminRole).then(|| "example-c90b95af0c0b6fef".to_owned()),
        policy_id: (family == OktaFamily::PolicyRule).then(|| "00psfar1lATHw2WXj4x6".to_owned()),
        ..OktaFilters::default()
    }
}

fn query(request: &OktaRequest, name: &str) -> Option<String> {
    request
        .url()
        .query_pairs()
        .find_map(|(candidate, value)| (candidate == name).then(|| value.into_owned()))
}
