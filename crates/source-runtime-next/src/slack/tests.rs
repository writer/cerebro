use std::{collections::BTreeMap, str::FromStr};

use cerebro_source_catalog::{CollectionAuthority, HttpMethod, SourceCatalog};
use serde_json::{Value, json};

use super::*;

const WEB_ORIGIN: &str = "https://slack.com/api";
const AUDIT_ORIGIN: &str = "https://api.slack.com/audit/v1";
const OBSERVED_AT: i64 = 1_780_272_000_000;

fn kernel(family: SlackFamily, filters: SlackFilters) -> SlackKernel {
    SlackKernel::new(
        WEB_ORIGIN,
        AUDIT_ORIGIN,
        "tenant",
        family,
        filters,
        Some(2),
        OBSERVED_AT,
    )
    .unwrap()
}

fn envelope(family: SlackFamily, records: Vec<Value>, next: Option<&str>) -> Vec<u8> {
    let key = match family {
        SlackFamily::Team => "teams",
        SlackFamily::User => "members",
        SlackFamily::Channel => "channels",
        SlackFamily::UserGroup => "usergroups",
        SlackFamily::AccessLog => "logins",
        SlackFamily::ChannelMember => "members",
        SlackFamily::UserGroupMember => "users",
        SlackFamily::AuditLog => "entries",
    };
    let mut root = serde_json::Map::from_iter([(key.to_owned(), Value::Array(records))]);
    if family != SlackFamily::AuditLog {
        root.insert("ok".to_owned(), Value::Bool(true));
    }
    if let Some(next) = next {
        root.insert("response_metadata".to_owned(), json!({"next_cursor": next}));
    }
    serde_json::to_vec(&Value::Object(root)).unwrap()
}

#[test]
fn closed_family_catalog_matches_checked_in_source_contract() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let source = catalog.get("slack").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let families = source
        .families()
        .iter()
        .map(|family| (family.id().to_owned(), family))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(families.len(), 8);
    for name in [
        "team",
        "user",
        "channel",
        "user_group",
        "access_log",
        "channel_member",
        "user_group_member",
        "audit_log",
    ] {
        let contract = SlackFamily::from_str(name).unwrap();
        let family = families[name];
        assert!(family.is_authoritative(), "{name} must compile closed");
        assert_eq!(family.path(), contract.path());
        assert_eq!(
            family.method(),
            if contract.method() == "POST" {
                HttpMethod::Post
            } else {
                HttpMethod::Get
            }
        );
    }
    assert_eq!(
        families["audit_log"].base_url(),
        Some("https://api.slack.com/audit/v1")
    );
    let oauth = source.oauth_authorization_code().unwrap();
    for family in [
        SlackFamily::Team,
        SlackFamily::User,
        SlackFamily::Channel,
        SlackFamily::UserGroup,
        SlackFamily::AccessLog,
        SlackFamily::ChannelMember,
        SlackFamily::UserGroupMember,
        SlackFamily::AuditLog,
    ] {
        for scope in family.required_scopes() {
            assert!(oauth.scopes().iter().any(|candidate| candidate == scope));
        }
    }
}

#[test]
fn plans_every_family_without_credentials_and_locks_origins() {
    let cases = [
        (SlackFamily::Team, "/api/auth.teams.list"),
        (SlackFamily::User, "/api/users.list"),
        (SlackFamily::Channel, "/api/conversations.list"),
        (SlackFamily::UserGroup, "/api/usergroups.list"),
        (SlackFamily::AccessLog, "/api/team.accessLogs"),
        (SlackFamily::ChannelMember, "/api/conversations.members"),
        (SlackFamily::UserGroupMember, "/api/usergroups.users.list"),
        (SlackFamily::AuditLog, "/audit/v1/logs"),
    ];
    for (family, path) in cases {
        let filters = SlackFilters {
            channel_id: Some("C1".to_owned()),
            usergroup_id: Some("S1".to_owned()),
            ..SlackFilters::default()
        };
        let request = kernel(family, filters).plan(None).unwrap();
        assert_eq!(request.url().path(), path);
        assert_eq!(request.method(), family.method());
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert!(!request.follow_redirects());
        let wire = request.url().as_str().as_bytes();
        assert!(!wire.windows(6).any(|window| window == b"Bearer"));
        assert!(!request.url().as_str().contains("token"));
    }
}

#[test]
fn deterministic_queries_and_cursor_rules_are_family_specific() {
    let channel = kernel(SlackFamily::Channel, SlackFilters::default())
        .plan(Some("cursor-1"))
        .unwrap();
    assert_eq!(
        channel.url().query(),
        Some(
            "cursor=cursor-1&exclude_archived=false&limit=2&types=public_channel%2Cprivate_channel"
        )
    );
    let membership = kernel(
        SlackFamily::ChannelMember,
        SlackFilters {
            channel_id: Some("C1".to_owned()),
            ..SlackFilters::default()
        },
    )
    .plan(Some("cursor-2"))
    .unwrap();
    assert_eq!(
        membership.url().query(),
        Some("channel=C1&cursor=cursor-2&limit=2")
    );
    let access = kernel(SlackFamily::AccessLog, SlackFilters::default())
        .plan(Some("4"))
        .unwrap();
    assert_eq!(access.url().query(), Some("count=2&page=4"));
    assert_eq!(
        kernel(SlackFamily::AccessLog, SlackFilters::default()).plan(Some("cursor")),
        Err(SlackError::InvalidCursor)
    );
    assert_eq!(
        kernel(SlackFamily::UserGroup, SlackFilters::default()).plan(Some("cursor")),
        Err(SlackError::UnsupportedCursor)
    );
}

#[test]
fn inventory_and_membership_families_normalize_go_oracle_shapes() {
    let cases = [
        (
            SlackFamily::Team,
            SlackFilters::default(),
            json!({"id":"T1","name":"Writer","domain":"writer"}),
            "team_id",
            "T1",
        ),
        (
            SlackFamily::User,
            SlackFilters::default(),
            json!({"id":"U1","team_id":"T1","name":"alice","profile":{"email":"alice@example.test"},"is_admin":true,"has_2fa":false,"updated":1780272000}),
            "user_id",
            "U1",
        ),
        (
            SlackFamily::Channel,
            SlackFilters::default(),
            json!({"id":"C1","name":"general","context_team_id":"T1","creator":"U1","is_private":false,"is_archived":false,"created":1780272000}),
            "channel_id",
            "C1",
        ),
        (
            SlackFamily::UserGroup,
            SlackFilters::default(),
            json!({"id":"S1","team_id":"T1","handle":"eng","name":"Engineering","date_update":1780272000}),
            "group_id",
            "S1",
        ),
        (
            SlackFamily::ChannelMember,
            SlackFilters {
                channel_id: Some("C1".to_owned()),
                ..SlackFilters::default()
            },
            json!("U1"),
            "channel_id",
            "C1",
        ),
        (
            SlackFamily::UserGroupMember,
            SlackFilters {
                usergroup_id: Some("S1".to_owned()),
                ..SlackFilters::default()
            },
            json!("U1"),
            "usergroup_id",
            "S1",
        ),
    ];
    for (family, filters, value, identity_key, identity_value) in cases {
        let kernel = kernel(family, filters);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(&request, 200, None, &envelope(family, vec![value], None))
            .unwrap();
        assert_eq!(page.records.len(), 1);
        let record = &page.records[0];
        assert_eq!(record.kind, family.event_kind());
        assert_eq!(record.schema_ref, family.schema_ref());
        assert_eq!(record.attributes[identity_key], identity_value);
        assert_eq!(record.tenant_id, "tenant");
        assert_eq!(record.occurred_at_unix_millis, OBSERVED_AT);
    }
}

#[test]
fn checked_in_go_oracle_fixtures_have_exact_rust_semantic_parity() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for family in [
        SlackFamily::Team,
        SlackFamily::User,
        SlackFamily::Channel,
        SlackFamily::UserGroup,
        SlackFamily::AccessLog,
        SlackFamily::ChannelMember,
        SlackFamily::UserGroupMember,
        SlackFamily::AuditLog,
    ] {
        let fixture = std::fs::read(
            root.join("sources/slack/testdata")
                .join(format!("read_{}.json", family.as_str())),
        )
        .unwrap();
        let expected: Vec<Value> = serde_json::from_slice(&fixture).unwrap();
        let expected = expected.first().unwrap();
        let expected_attributes = expected["attributes"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_owned()))
            .collect::<BTreeMap<_, _>>();
        let filters = SlackFilters {
            channel_id: expected_attributes.get("channel_id").cloned(),
            usergroup_id: expected_attributes.get("usergroup_id").cloned(),
            oldest: (family == SlackFamily::AuditLog).then(|| "1780270000".to_owned()),
            latest: (family == SlackFamily::AuditLog).then(|| "1780273000".to_owned()),
            ..SlackFilters::default()
        };
        let kernel = kernel(family, filters);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &envelope(family, vec![expected["payload"].clone()], None),
            )
            .unwrap();
        let actual = page.records.first().unwrap();
        assert_eq!(
            actual.kind,
            expected["kind"].as_str().unwrap(),
            "{family:?}"
        );
        assert_eq!(
            actual.schema_ref,
            expected["schema_ref"].as_str().unwrap(),
            "{family:?}"
        );
        assert_eq!(actual.attributes, expected_attributes, "{family:?}");
        assert_eq!(actual.payload, expected["payload"], "{family:?}");
    }
}

#[test]
fn access_and_audit_families_preserve_activity_context() {
    let access = kernel(SlackFamily::AccessLog, SlackFilters::default());
    let request = access.plan(None).unwrap();
    let body = serde_json::to_vec(&json!({
        "ok":true,
        "logins":[{"user_id":"U1","username":"alice","ip":"203.0.113.10","user_agent":"Mozilla/5.0","count":3,"date_first":1780271000,"date_last":1780272000}],
        "paging":{"page":1,"pages":2}
    })).unwrap();
    let page = access.decode(&request, 200, None, &body).unwrap();
    let record = &page.records[0];
    assert_eq!(record.attributes["actor_id"], "U1");
    assert_eq!(record.attributes["event_type"], "team_access");
    assert_eq!(record.attributes["external_id"], "U1");
    assert_eq!(record.attributes["ip_address"], "203.0.113.10");
    assert_eq!(page.next_cursor.as_deref(), Some("2"));

    let audit = kernel(
        SlackFamily::AuditLog,
        SlackFilters {
            oldest: Some("1780270000".to_owned()),
            latest: Some("1780273000".to_owned()),
            ..SlackFilters::default()
        },
    );
    let request = audit.plan(None).unwrap();
    let value = json!({
        "id":"Ev1","date_create":1780272000,"action":"user_login",
        "actor":{"type":"user","user":{"id":"U1","name":"alice","email":"alice@example.test","team":"T1"}},
        "entity":{"type":"user","user":{"id":"U2","name":"bob","team":"T1"}},
        "context":{"ip_address":"203.0.113.10","ua":"Mozilla/5.0"}
    });
    let page = audit
        .decode(
            &request,
            200,
            None,
            &envelope(SlackFamily::AuditLog, vec![value], Some("cursor-2")),
        )
        .unwrap();
    let record = &page.records[0];
    assert_eq!(record.attributes["actor_id"], "U1");
    assert_eq!(record.attributes["resource_id"], "U2");
    assert_eq!(record.attributes["team_id"], "T1");
    let next = page.next_cursor.as_deref().unwrap();
    assert!(next.contains("\"mode\":\"rolling_window\""));
    let resumed = audit.plan(Some(next)).unwrap();
    assert_eq!(
        resumed
            .url()
            .query_pairs()
            .find(|(key, _)| key == "oldest")
            .unwrap()
            .1,
        "1780270000"
    );
}

#[test]
fn identity_is_tenant_scoped_and_duplicate_conflicts_fail_closed() {
    let value = json!({"id":"U1","name":"alice"});
    let body = envelope(SlackFamily::User, vec![value.clone()], None);
    let first = kernel(SlackFamily::User, SlackFilters::default());
    let first_record = first
        .decode(&first.plan(None).unwrap(), 200, None, &body)
        .unwrap()
        .records
        .remove(0);
    let second = SlackKernel::new(
        WEB_ORIGIN,
        AUDIT_ORIGIN,
        "other-tenant",
        SlackFamily::User,
        SlackFilters::default(),
        Some(2),
        OBSERVED_AT,
    )
    .unwrap();
    let second_record = second
        .decode(&second.plan(None).unwrap(), 200, None, &body)
        .unwrap()
        .records
        .remove(0);
    assert_ne!(first_record.event_id, second_record.event_id);

    let conflict = envelope(
        SlackFamily::User,
        vec![value, json!({"id":"U1","name":"mallory"})],
        None,
    );
    assert_eq!(
        first.decode(&first.plan(None).unwrap(), 200, None, &conflict),
        Err(SlackError::ConflictingDuplicate)
    );
}

#[test]
fn provider_failures_and_secret_material_remain_typed() {
    let kernel = kernel(SlackFamily::User, SlackFilters::default());
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode(&request, 401, None, b"{}"),
        Err(SlackError::AuthenticationRejected)
    );
    assert_eq!(
        kernel.decode(&request, 403, None, b"{}"),
        Err(SlackError::RequiredScopeMissing)
    );
    assert_eq!(
        kernel.decode(&request, 429, Some("30"), b"{}"),
        Err(SlackError::RateLimited {
            retry_after_seconds: Some(30)
        })
    );
    assert_eq!(
        kernel.decode(&request, 503, None, b"{}"),
        Err(SlackError::ProviderUnavailable { status: 503 })
    );
    let missing_scope = br#"{"ok":false,"error":"missing_scope","needed":"users:read"}"#;
    assert_eq!(
        kernel.decode(&request, 200, None, missing_scope),
        Err(SlackError::RequiredScopeMissing)
    );
    let secret = envelope(
        SlackFamily::User,
        vec![json!({"id":"U1","profile":{"access_token":"fixture-secret"}})],
        None,
    );
    assert_eq!(
        kernel.decode(&request, 200, None, &secret),
        Err(SlackError::CredentialMaterial)
    );
    let tenant = envelope(
        SlackFamily::User,
        vec![json!({"id":"U1","tenant_id":"untrusted"})],
        None,
    );
    assert_eq!(
        kernel.decode(&request, 200, None, &tenant),
        Err(SlackError::TenantMismatch)
    );
}

#[test]
fn origins_and_bounds_fail_closed() {
    assert!(matches!(
        SlackKernel::new(
            "http://slack.com/api",
            AUDIT_ORIGIN,
            "tenant",
            SlackFamily::User,
            SlackFilters::default(),
            Some(100),
            OBSERVED_AT,
        ),
        Err(SlackError::InvalidOrigin)
    ));
    assert!(matches!(
        SlackKernel::new(
            "https://127.0.0.1/api",
            AUDIT_ORIGIN,
            "tenant",
            SlackFamily::User,
            SlackFilters::default(),
            Some(100),
            OBSERVED_AT,
        ),
        Err(SlackError::InvalidOrigin)
    ));
    assert!(matches!(
        SlackKernel::new(
            WEB_ORIGIN,
            AUDIT_ORIGIN,
            "tenant",
            SlackFamily::User,
            SlackFilters::default(),
            Some(101),
            OBSERVED_AT,
        ),
        Err(SlackError::InvalidPageSize)
    ));
    let kernel = kernel(SlackFamily::User, SlackFilters::default());
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &vec![b' '; request.max_response_bytes() + 1]
        ),
        Err(SlackError::ResponseTooLarge)
    );
}
