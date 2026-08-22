use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;

const CATALOG: &[u8] = include_bytes!("../../../../sources/jumpcloud/catalog.yaml");
const USERS_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/read_users.json");
const GROUPS_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/read_groups.json");
const SYSTEMS_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/read_systems.json");
const APPLICATIONS_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/read_applications.json");
const SYSTEM_GROUPS_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/read_system_groups.json");
const GROUP_MEMBERS_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/read_group_members.json");
const AUDIT_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/read_audit_events.json");
const IDLESS_AUDIT_ORACLE: &[u8] =
    include_bytes!("../../../../sources/jumpcloud/testdata/idless_audit_events.json");

#[derive(serde::Deserialize)]
struct CatalogWire {
    runtime_families: Vec<String>,
    event_contracts: Vec<EventContractWire>,
}

#[derive(serde::Deserialize)]
struct EventContractWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

fn kernel(tenant: &str, family: JumpCloudFamily) -> JumpCloudKernel {
    let mut filters = JumpCloudFilters {
        org_id: Some("org-1".to_owned()),
        ..JumpCloudFilters::default()
    };
    if family == JumpCloudFamily::GroupMembers {
        filters.group_id = Some("group-1".to_owned());
    }
    if family == JumpCloudFamily::AuditEvents {
        filters.audit_start_time = Some("2026-06-01T00:00:00Z".to_owned());
    }
    JumpCloudKernel::new(
        "https://console.jumpcloud.com/api",
        "https://api.jumpcloud.com/insights/directory/v1",
        tenant,
        family,
        filters,
        Some(100),
        "2026-06-01T00:00:00Z",
    )
    .expect("valid JumpCloud kernel")
}

#[test]
fn closed_runtime_definition_matches_catalog_exactly() {
    let catalog: CatalogWire = serde_saphyr::from_slice(CATALOG).expect("JumpCloud catalog YAML");
    assert_eq!(
        catalog.runtime_families,
        [
            "users",
            "groups",
            "systems",
            "applications",
            "system_groups",
            "group_members",
            "audit_events",
        ]
    );
    let definitions = JumpCloudFamily::ALL
        .into_iter()
        .map(|family| JumpCloudRuntimeDefinition::compile(family).expect("compiled family"))
        .collect::<Vec<_>>();
    assert!(definitions.iter().all(|definition| definition.pull));
    assert_eq!(catalog.event_contracts.len(), definitions.len());
    for expected in catalog.event_contracts {
        let actual = definitions
            .iter()
            .map(|definition| definition.event_contract)
            .find(|contract| contract.kind == expected.kind)
            .expect("catalog contract compiled");
        assert_eq!(actual.schema_ref, expected.schema_ref);
        assert!(
            actual
                .required_attributes
                .iter()
                .copied()
                .eq(expected.required_attributes.iter().map(String::as_str))
        );
        assert!(
            actual
                .required_payload_fields
                .iter()
                .copied()
                .eq(expected.required_payload_fields.iter().map(String::as_str))
        );
    }
    assert_eq!(
        "roles".parse::<JumpCloudFamily>(),
        Err(JumpCloudError::InvalidFamily)
    );
}

#[test]
fn plans_all_families_without_credentials_or_redirects() {
    for (family, method, path) in [
        (JumpCloudFamily::Users, "GET", "/api/systemusers"),
        (JumpCloudFamily::Groups, "GET", "/api/v2/usergroups"),
        (JumpCloudFamily::Systems, "GET", "/api/systems"),
        (JumpCloudFamily::Applications, "GET", "/api/applications"),
        (JumpCloudFamily::SystemGroups, "GET", "/api/v2/systemgroups"),
        (
            JumpCloudFamily::GroupMembers,
            "GET",
            "/api/v2/usergroups/group-1/members",
        ),
        (
            JumpCloudFamily::AuditEvents,
            "POST",
            "/insights/directory/v1/events",
        ),
    ] {
        let request = kernel("tenant-a", family).plan(None).expect("request");
        assert_eq!(request.method(), method);
        assert_eq!(request.url().path(), path);
        assert_eq!(request.authentication_header(), "x-api-key");
        assert_eq!(request.authentication_scheme(), "");
        assert_eq!(request.organization_id(), Some("org-1"));
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        if family == JumpCloudFamily::AuditEvents {
            let body: Value = serde_json::from_slice(request.body().expect("audit body")).unwrap();
            assert_eq!(body["service"], json!(["all"]));
            assert_eq!(body["start_time"], "2026-06-01T00:00:00Z");
            assert_eq!(body["sort"], "ASC");
        } else {
            assert_eq!(
                request
                    .url()
                    .query_pairs()
                    .find(|(key, _)| key == "skip")
                    .map(|(_, value)| value.into_owned()),
                Some("0".to_owned())
            );
        }
        let debug = format!("{request:?}").to_ascii_lowercase();
        for forbidden in [
            "test-key",
            "api_key",
            "access_token",
            "private_key",
            "org-1",
        ] {
            assert!(!debug.contains(forbidden));
        }
    }
    assert!(!JumpCloudKernel::requires_credentials());
}

#[test]
fn checked_in_go_oracles_match_all_rust_families() {
    for (family, oracle, event_id) in [
        (
            JumpCloudFamily::Users,
            USERS_ORACLE,
            "jumpcloud-tenant-7b2f83dc868b-users-user-1",
        ),
        (
            JumpCloudFamily::Groups,
            GROUPS_ORACLE,
            "jumpcloud-tenant-101a38d129e6-groups-group-1",
        ),
        (
            JumpCloudFamily::Systems,
            SYSTEMS_ORACLE,
            "jumpcloud-tenant-2922a216fe1a-systems-system-1",
        ),
        (
            JumpCloudFamily::Applications,
            APPLICATIONS_ORACLE,
            "jumpcloud-tenant-52cd854825d7-applications-app-1",
        ),
        (
            JumpCloudFamily::SystemGroups,
            SYSTEM_GROUPS_ORACLE,
            "jumpcloud-tenant-93d3aa9d2bf0-system_groups-system-group-1",
        ),
        (
            JumpCloudFamily::GroupMembers,
            GROUP_MEMBERS_ORACLE,
            "jumpcloud-tenant-3436a8f4ca37-group_members-user-1-0e0c6c2b62ad1daf6ed6f4b9",
        ),
        (
            JumpCloudFamily::AuditEvents,
            AUDIT_ORACLE,
            "id-110a0d85f5ff3756b59221395dcc5752",
        ),
    ] {
        let expected = oracle_event(oracle);
        let raw = expected["payload"].clone();
        let response = match family {
            JumpCloudFamily::Users | JumpCloudFamily::Systems | JumpCloudFamily::Applications => {
                json!({
                    "results": [raw], "skip": 0, "limit": 100, "totalCount": 1
                })
            }
            _ => json!([raw]),
        };
        let kernel = kernel("tenant", family);
        let page = kernel
            .decode(
                &kernel.plan(None).unwrap(),
                200,
                &JumpCloudResponseMetadata::default(),
                &serde_json::to_vec(&response).unwrap(),
            )
            .expect("fixture page");
        assert_eq!(page.records.len(), 1, "family {family:?}");
        assert_oracle(&page.records[0], &expected, event_id);
    }
}

#[test]
fn idless_audit_identity_hashes_exact_provider_row_bytes_like_go() {
    let audit = kernel("tenant", JumpCloudFamily::AuditEvents);
    let page = audit
        .decode(
            &audit.plan(None).unwrap(),
            200,
            &JumpCloudResponseMetadata::default(),
            IDLESS_AUDIT_ORACLE,
        )
        .expect("idless audit row");
    assert_eq!(page.records.len(), 1);
    assert_eq!(
        page.records[0].provider_id,
        "id-5bded99005439a1abf0d1e0fbee3f84b"
    );
    assert_eq!(
        page.records[0].event_id,
        "id-e7af2eebff7e584819c58bd1b5c3970c"
    );
    assert_eq!(
        page.records[0].attributes["source_event_id"],
        "id-5bded99005439a1abf0d1e0fbee3f84b"
    );

    let reordered = br#"[{"timestamp":"2026-06-02T03:04:05Z","initiated_by":{"id":"actor-1"},"event_type":"login"}]"#;
    let other = audit
        .decode(
            &audit.plan(None).unwrap(),
            200,
            &JumpCloudResponseMetadata::default(),
            reordered,
        )
        .unwrap();
    assert_ne!(page.records[0].provider_id, other.records[0].provider_id);
}

#[test]
fn offset_and_search_after_checkpoints_round_trip_after_restart() {
    let users = kernel("tenant", JumpCloudFamily::Users);
    let request = users.plan(None).unwrap();
    let page = users
        .decode(
            &request,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"{"results":[{"_id":"user-1"},{"_id":"user-2"}],"skip":0,"limit":2,"totalCount":3}"#,
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("2"));
    let checkpoint = users
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    let resumed = users.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(
        resumed
            .url()
            .query_pairs()
            .find(|(key, _)| key == "skip")
            .map(|(_, value)| value.into_owned()),
        Some("2".to_owned())
    );

    let audit = kernel("tenant", JumpCloudFamily::AuditEvents);
    let audit_request = audit.plan(None).unwrap();
    let metadata = JumpCloudResponseMetadata {
        result_count: Some(100),
        limit: Some(100),
        search_after: Some(r#"[1719849600000,"event-2"]"#.to_owned()),
        retry_after_seconds: None,
    };
    let audit_page = audit
        .decode(
            &audit_request,
            200,
            &metadata,
            br#"[{"id":"event-1","event_type":"login","resource":{"id":"user-1"},"timestamp":"2026-06-01T00:00:00Z"}]"#,
        )
        .unwrap();
    assert_eq!(
        audit_page.next_cursor.as_deref(),
        Some(r#"[1719849600000,"event-2"]"#)
    );
    let resumed = audit.plan(audit_page.next_cursor.as_deref()).unwrap();
    let body: Value = serde_json::from_slice(resumed.body().unwrap()).unwrap();
    assert_eq!(body["search_after"], json!([1719849600000_u64, "event-2"]));
    assert_eq!(
        audit.plan(Some("not-json")),
        Err(JumpCloudError::InvalidCursor)
    );
}

#[test]
fn terminal_audit_watermark_drives_the_next_request_after_restart() {
    let filters = JumpCloudFilters {
        org_id: Some("org-1".to_owned()),
        ..JumpCloudFilters::default()
    };
    let audit = JumpCloudKernel::new(
        "https://console.jumpcloud.com/api",
        "https://api.jumpcloud.com/insights/directory/v1",
        "tenant",
        JumpCloudFamily::AuditEvents,
        filters.clone(),
        Some(100),
        "2026-06-03T00:00:00Z",
    )
    .unwrap();
    let request = audit.plan(None).unwrap();
    let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
    assert_eq!(body["start_time"], "2026-06-02T00:00:00Z");
    let page = audit
        .decode(
            &request,
            200,
            &JumpCloudResponseMetadata {
                result_count: Some(1),
                limit: Some(100),
                ..JumpCloudResponseMetadata::default()
            },
            br#"[{"id":"event-1","event_type":"login","initiated_by":{"id":"actor-1"},"timestamp":"2026-06-02T03:04:05Z"}]"#,
        )
        .unwrap();
    assert_eq!(page.next_cursor, None);
    let checkpoint = audit
        .checkpoint_candidate(&request, &page, None)
        .expect("terminal checkpoint");
    assert_eq!(
        checkpoint.watermark.as_deref(),
        Some("2026-06-02T03:04:05Z")
    );

    let restarted = JumpCloudKernel::new(
        "https://console.jumpcloud.com/api",
        "https://api.jumpcloud.com/insights/directory/v1",
        "tenant",
        JumpCloudFamily::AuditEvents,
        filters,
        Some(100),
        "2026-06-04T00:00:00Z",
    )
    .unwrap();
    let resumed = restarted
        .plan_with_checkpoint(None, checkpoint.watermark.as_deref())
        .unwrap();
    assert_eq!(resumed.checkpoint_watermark(), Some("2026-06-02T03:04:05Z"));
    let body: Value = serde_json::from_slice(resumed.body().unwrap()).unwrap();
    assert_eq!(body["start_time"], "2026-06-02T03:04:05Z");

    let configured = kernel("tenant", JumpCloudFamily::AuditEvents)
        .plan_with_checkpoint(None, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    let body: Value = serde_json::from_slice(configured.body().unwrap()).unwrap();
    assert_eq!(body["start_time"], "2026-06-01T00:00:00Z");
}

#[test]
fn audit_dynamic_body_safe_headers_and_alternate_origins_are_exact() {
    let filters = JumpCloudFilters {
        org_id: Some("org-1".to_owned()),
        audit_start_time: Some("2026-06-01T00:00:00Z".to_owned()),
        audit_end_time: Some("2026-06-02T00:00:00Z".to_owned()),
        audit_services: vec!["sso".to_owned(), "directory".to_owned()],
        audit_sort: Some("desc".to_owned()),
        ..JumpCloudFilters::default()
    };
    for origin in [
        "https://api.eu.jumpcloud.com/insights/directory/v1",
        "https://api.in.jumpcloud.com/insights/directory/v1",
    ] {
        let audit = JumpCloudKernel::new(
            "https://console.jumpcloud.com/api",
            origin,
            "tenant",
            JumpCloudFamily::AuditEvents,
            filters.clone(),
            Some(250),
            "2026-06-03T00:00:00Z",
        )
        .unwrap();
        let request = audit.plan(Some(r#"[1719849600000,"event-2"]"#)).unwrap();
        assert_eq!(request.url().as_str(), format!("{origin}/events"));
        assert_eq!(request.content_type(), Some("application/json"));
        let body: Value = serde_json::from_slice(request.body().unwrap()).unwrap();
        assert_eq!(body["service"], json!(["sso", "directory"]));
        assert_eq!(body["start_time"], "2026-06-01T00:00:00Z");
        assert_eq!(body["end_time"], "2026-06-02T00:00:00Z");
        assert_eq!(body["limit"], 250);
        assert_eq!(body["sort"], "DESC");
        assert_eq!(body["search_after"], json!([1719849600000_u64, "event-2"]));
    }

    let headers = BTreeMap::from([
        ("X-Result-Count".to_owned(), "250".to_owned()),
        ("X-Limit".to_owned(), "250".to_owned()),
        (
            "X-Search_after".to_owned(),
            r#"[1719849600000,"event-2"]"#.to_owned(),
        ),
        ("Retry-After".to_owned(), "30".to_owned()),
    ]);
    assert_eq!(
        JumpCloudResponseMetadata::from_headers(&headers).unwrap(),
        JumpCloudResponseMetadata {
            result_count: Some(250),
            limit: Some(250),
            search_after: Some(r#"[1719849600000,"event-2"]"#.to_owned()),
            retry_after_seconds: Some(30),
        }
    );
    assert_eq!(
        JumpCloudResponseMetadata::from_headers(&BTreeMap::from([(
            "X-Result-Count".to_owned(),
            "not-an-integer".to_owned(),
        )])),
        Err(JumpCloudError::MalformedResponse)
    );
}

#[test]
fn provider_local_source_execution_contract_covers_all_seven_families() {
    assert_eq!(adapter::JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS.len(), 7);
    for adapter in adapter::JUMPCLOUD_SOURCE_EXECUTION_ADAPTERS {
        let contract = adapter.contract().unwrap();
        assert_eq!(contract.source_id, "jumpcloud");
        assert_eq!(contract.family_id, adapter.family().as_str());
        assert_eq!(contract.method, adapter.family().method());
        assert_eq!(contract.path, adapter.family().path());
        assert_eq!(contract.credential_operation, "jumpcloud.x_api_key");
        assert_eq!(
            contract.provider_kernel,
            format!("jumpcloud.{}", adapter.family().as_str())
        );
        let audit = adapter.family() == JumpCloudFamily::AuditEvents;
        assert_eq!(contract.request_body, audit);
        assert_eq!(
            contract.response_cursor_header,
            audit.then_some("X-Search_after")
        );
        assert_eq!(
            contract.origin,
            if audit {
                "https://api.jumpcloud.com/insights/directory/v1"
            } else {
                "https://console.jumpcloud.com/api"
            }
        );
        let planned = adapter
            .plan(&kernel("tenant", adapter.family()), None, None)
            .unwrap();
        assert_eq!(planned.family(), adapter.family());
        let response = if adapter.family() == JumpCloudFamily::AuditEvents {
            br#"[{"id":"event-1","event_type":"login","initiated_by":{"id":"actor-1"},"timestamp":"2026-06-02T03:04:05Z"}]"#.as_slice()
        } else if matches!(
            adapter.family(),
            JumpCloudFamily::Users | JumpCloudFamily::Systems | JumpCloudFamily::Applications
        ) {
            br#"{"results":[]}"#.as_slice()
        } else {
            br#"[]"#.as_slice()
        };
        assert!(
            adapter
                .decode(
                    &kernel("tenant", adapter.family()),
                    &planned,
                    200,
                    &JumpCloudResponseMetadata::default(),
                    response,
                )
                .is_ok()
        );
    }
}

#[test]
fn failures_tenants_duplicates_and_origins_fail_closed_without_leaks() {
    assert!(matches!(
        JumpCloudKernel::new(
            "https://attacker.example/api",
            "https://api.jumpcloud.com/insights/directory/v1",
            "tenant",
            JumpCloudFamily::Users,
            JumpCloudFilters::default(),
            None,
            "2026-06-01T00:00:00Z",
        ),
        Err(JumpCloudError::InvalidOrigin)
    ));
    let users = kernel("tenant", JumpCloudFamily::Users);
    let request = users.plan(None).unwrap();
    for body in [
        br#"{"results":[{"_id":"user-1","tenant_id":"attacker"}]}"#.as_slice(),
        br#"{"results":[{"_id":"user-1","profile":{"api_key":"secret-sentinel"}}]}"#.as_slice(),
    ] {
        assert!(matches!(
            users.decode(&request, 200, &JumpCloudResponseMetadata::default(), body),
            Err(JumpCloudError::TenantMismatch | JumpCloudError::CredentialMaterial)
        ));
    }
    assert_eq!(
        users.decode(
            &request,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"{"results":[{"_id":"user-1","displayname":"One"},{"_id":"user-1","displayname":"Two"}]}"#,
        ),
        Err(JumpCloudError::ConflictingDuplicate)
    );
    for (status, expected) in [
        (401, JumpCloudError::AuthenticationRejected),
        (403, JumpCloudError::RequiredScopeMissing),
        (503, JumpCloudError::ProviderUnavailable { status: 503 }),
    ] {
        assert_eq!(
            users.decode(&request, status, &JumpCloudResponseMetadata::default(), b""),
            Err(expected)
        );
    }
    assert_eq!(
        users.decode(
            &request,
            429,
            &JumpCloudResponseMetadata {
                retry_after_seconds: Some(30),
                ..JumpCloudResponseMetadata::default()
            },
            b""
        ),
        Err(JumpCloudError::RateLimited {
            retry_after_seconds: Some(30)
        })
    );
    let other = kernel("tenant-b", JumpCloudFamily::Users)
        .decode(
            &kernel("tenant-b", JumpCloudFamily::Users)
                .plan(None)
                .unwrap(),
            200,
            &JumpCloudResponseMetadata::default(),
            br#"{"results":[{"_id":"user-1"}]}"#,
        )
        .unwrap();
    let first = users
        .decode(
            &request,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"{"results":[{"_id":"user-1"}]}"#,
        )
        .unwrap();
    assert_ne!(first.records[0].event_id, other.records[0].event_id);
    let diagnostic = format!(
        "{:?}",
        users.decode(
            &request,
            200,
            &JumpCloudResponseMetadata::default(),
            br#"{"results":[{"_id":"user-1","password":"secret-sentinel"}]}"#,
        )
    );
    assert!(!diagnostic.contains("secret-sentinel"));
}

#[test]
fn projection_preserves_users_systems_and_memberships() {
    let user = decode_payload(
        JumpCloudFamily::Users,
        json!({"_id":"user-1","displayname":"User One"}),
    );
    let system = decode_payload(
        JumpCloudFamily::Systems,
        json!({"_id":"system-1","displayName":"Mac 1"}),
    );
    let member = decode_payload(
        JumpCloudFamily::GroupMembers,
        json!({"to":{"id":"user-1","type":"user"}}),
    );
    let facts = project_jumpcloud_records(&[user, system, member]);
    assert!(facts.entities.iter().any(|entity| entity.urn
        == "urn:cerebro:tenant:jumpcloud_users:user-1"
        && entity.entity_type == "identity_user"));
    assert!(facts.entities.iter().any(|entity| entity.urn
        == "urn:cerebro:tenant:jumpcloud_systems:system-1"
        && entity.entity_type == "system"));
    assert!(facts.relations.iter().any(|relation| relation.from_urn
        == "urn:cerebro:tenant:jumpcloud_users:user-1"
        && relation.relation == "member_of"
        && relation.to_urn == "urn:cerebro:tenant:jumpcloud_groups:group-1"));
}

fn decode_payload(family: JumpCloudFamily, payload: Value) -> JumpCloudRecord {
    let response = match family {
        JumpCloudFamily::Users | JumpCloudFamily::Systems | JumpCloudFamily::Applications => {
            json!({"results":[payload],"totalCount":1})
        }
        _ => json!([payload]),
    };
    let kernel = kernel("tenant", family);
    kernel
        .decode(
            &kernel.plan(None).unwrap(),
            200,
            &JumpCloudResponseMetadata::default(),
            &serde_json::to_vec(&response).unwrap(),
        )
        .unwrap()
        .records
        .remove(0)
}

fn oracle_event(bytes: &[u8]) -> Value {
    serde_json::from_slice::<Vec<Value>>(bytes)
        .expect("Go oracle JSON")
        .remove(0)
}

fn assert_oracle(record: &JumpCloudRecord, expected: &Value, event_id: &str) {
    assert_eq!(record.tenant_id, expected["tenant_id"]);
    assert_eq!(record.kind, expected["kind"]);
    assert_eq!(record.schema_ref, expected["schema_ref"]);
    assert_eq!(record.occurred_at, expected["occurred_at"]);
    assert_eq!(record.attributes, attributes(&expected["attributes"]));
    assert_eq!(record.payload, expected["payload"]);
    assert_eq!(record.event_id, event_id);
}

fn attributes(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .expect("oracle attributes")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value.as_str().expect("string attribute").to_owned(),
            )
        })
        .collect()
}
