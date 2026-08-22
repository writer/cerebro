use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://api.activtrak.com";
const OBSERVED_AT: &str = "2026-06-01T00:00:00Z";

#[derive(Debug, Deserialize)]
struct GoOracleEvent {
    id: String,
    tenant_id: String,
    source_id: String,
    kind: String,
    occurred_at: String,
    schema_ref: String,
    payload: Value,
    attributes: BTreeMap<String, String>,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn kernel(tenant: &str, family: ActivTrakFamily) -> ActivTrakKernel {
    ActivTrakKernel::new(ORIGIN, tenant, family, OBSERVED_AT).unwrap()
}

fn oracle(family: ActivTrakFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/activtrak/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn response(family: ActivTrakFamily, records: Vec<Value>, cursor: Option<&str>) -> Vec<u8> {
    let mut response = json!({family.response_key(): records});
    if let Some(cursor) = cursor {
        response["cursor"] = Value::String(cursor.to_owned());
    }
    serde_json::to_vec(&response).unwrap()
}

#[test]
fn catalog_closes_the_exact_authoritative_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("activtrak").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let mut families = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<Vec<_>>();
    families.sort_unstable();
    assert_eq!(
        families,
        ["activity_log", "clients", "consumers", "groups", "users"]
    );
    assert!(
        source
            .families()
            .iter()
            .all(|family| family.is_authoritative())
    );
    for family in ActivTrakFamily::ALL {
        let definition = ActivTrakRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "activtrak");
        assert_eq!(definition.event_contract.kind, family.event_kind());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in ActivTrakFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().host_str(), Some("api.activtrak.com"));
        assert_eq!(request.url().path(), family.path());
        assert_eq!(request.authentication_header(), "x-api-key");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), family.page_size());
    }
    assert_eq!(
        kernel("tenant", ActivTrakFamily::Users)
            .plan(Some("101"))
            .unwrap()
            .url()
            .query(),
        Some("count=100&startIndex=101")
    );
    assert_eq!(
        kernel("tenant", ActivTrakFamily::ActivityLog)
            .plan(Some("next-token"))
            .unwrap()
            .url()
            .query(),
        Some("pageSize=150&cursor=next-token")
    );
}

#[test]
fn go_event_and_projection_fixtures_match_semantically() {
    for family in ActivTrakFamily::ALL {
        let oracle = oracle(family);
        let request = kernel("tenant", family).plan(None).unwrap();
        let page = kernel("tenant", family)
            .decode(
                &request,
                200,
                None,
                &response(family, vec![oracle.payload.clone()], None),
            )
            .unwrap();
        let record = &page.records[0];
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "activtrak");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert_eq!(
            oracle.id,
            format!("source-activtrak-{}-event-1", family.as_str())
        );
        assert_eq!(project_activtrak_records(&page.records).entities.len(), 1);
    }
}

#[test]
fn cursors_checkpoint_and_restart_round_trip() {
    let family = ActivTrakFamily::Users;
    let scim_kernel = kernel("tenant", family);
    let request = scim_kernel.plan(None).unwrap();
    let records = (1..=100)
        .map(|id| json!({"id": id.to_string(), "displayName": format!("user-{id}")}))
        .collect::<Vec<_>>();
    let page = scim_kernel
        .decode(&request, 200, None, &response(family, records, None))
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("101"));
    let checkpoint = scim_kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("101"));
    assert_eq!(
        scim_kernel
            .plan(checkpoint.cursor.as_deref())
            .unwrap()
            .url()
            .query(),
        Some("count=100&startIndex=101")
    );

    let activity = ActivTrakFamily::ActivityLog;
    let kernel = kernel("tenant", activity);
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(activity, vec![oracle(activity).payload], Some("next-token")),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("next-token"));
}

#[test]
fn duplicate_conflict_tenant_secret_and_statuses_fail_closed() {
    let family = ActivTrakFamily::Clients;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = oracle(family).payload;
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![raw.clone(), raw.clone()], None),
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    let mut conflict = raw.clone();
    conflict["alias"] = Value::String("different".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![raw, conflict], None)
        ),
        Err(ActivTrakError::ConflictingDuplicate)
    );
    for (field, expected) in [
        ("tenant_id", ActivTrakError::TenantMismatch),
        ("api_key", ActivTrakError::CredentialMaterial),
        ("authorization", ActivTrakError::CredentialMaterial),
    ] {
        let mut raw = oracle(family).payload;
        raw[field] = Value::String("sentinel-secret-value".to_owned());
        let error = kernel
            .decode(&request, 200, None, &response(family, vec![raw], None))
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }
    assert_eq!(
        kernel.decode(&request, 401, None, b"{}"),
        Err(ActivTrakError::AuthenticationRejected)
    );
    assert_eq!(
        kernel.decode(&request, 403, None, b"{}"),
        Err(ActivTrakError::RequiredScopeMissing)
    );
    assert_eq!(
        kernel.decode(&request, 429, Some(60), b"{}"),
        Err(ActivTrakError::RateLimited {
            retry_after_seconds: Some(60)
        })
    );
}

#[test]
fn origin_cursor_and_tenant_inputs_fail_closed() {
    for origin in [
        "http://api.activtrak.com",
        "https://other.activtrak.com",
        "https://user@api.activtrak.com",
        "https://api.activtrak.com:8443",
        "https://api.activtrak.com/path",
        "https://api.activtrak.com?api_key=value",
    ] {
        assert!(
            ActivTrakKernel::new(origin, "tenant", ActivTrakFamily::Users, OBSERVED_AT).is_err()
        );
    }
    assert!(
        ActivTrakKernel::new(ORIGIN, "bad:tenant", ActivTrakFamily::Users, OBSERVED_AT).is_err()
    );
    assert_eq!(
        kernel("tenant", ActivTrakFamily::Users).plan(Some("0")),
        Err(ActivTrakError::InvalidCursor)
    );
    assert_eq!(
        kernel("tenant", ActivTrakFamily::Clients).plan(Some("1")),
        Err(ActivTrakError::InvalidCursor)
    );
    assert_eq!(
        kernel("tenant", ActivTrakFamily::ActivityLog).plan(Some("../escape")),
        Err(ActivTrakError::InvalidCursor)
    );
}

#[test]
fn identity_is_deterministic_and_tenant_scoped() {
    let family = ActivTrakFamily::Consumers;
    let body = response(family, vec![oracle(family).payload], None);
    let first_kernel = kernel("tenant-a", family);
    let first_request = first_kernel.plan(None).unwrap();
    let first = first_kernel
        .decode(&first_request, 200, None, &body)
        .unwrap();
    assert_eq!(
        first,
        first_kernel
            .decode(&first_request, 200, None, &body)
            .unwrap()
    );
    let second_kernel = kernel("tenant-b", family);
    let second_request = second_kernel.plan(None).unwrap();
    let second = second_kernel
        .decode(&second_request, 200, None, &body)
        .unwrap();
    assert_ne!(first.records[0].event_id, second.records[0].event_id);
}
