use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://online.acunetix.com/api/v1";
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

fn kernel(tenant: &str, family: AcunetixFamily) -> AcunetixKernel {
    AcunetixKernel::new(ORIGIN, tenant, family, OBSERVED_AT).unwrap()
}

fn oracle(family: AcunetixFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/acunetix/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn response(family: AcunetixFamily, records: Vec<Value>, cursor: Option<&str>) -> Vec<u8> {
    let mut response = json!({family.response_key(): records});
    if let Some(cursor) = cursor {
        response["pagination"] = json!({"next_cursor": cursor});
    }
    serde_json::to_vec(&response).unwrap()
}

#[test]
fn catalog_closes_the_exact_catalog_runtime_only_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("acunetix").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let mut families = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<Vec<_>>();
    families.sort_unstable();
    assert_eq!(
        families,
        [
            "reports",
            "scanning_profiles",
            "scans",
            "targets",
            "vulnerabilities"
        ]
    );
    assert!(!root().join("sources/acunetix/source.go").exists());
    for family in AcunetixFamily::ALL {
        let definition = AcunetixRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "acunetix");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in AcunetixFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().host_str(), Some("online.acunetix.com"));
        assert_eq!(request.url().path(), format!("/api/v1{}", family.path()));
        assert_eq!(request.url().query(), Some("l=100"));
        assert_eq!(request.authentication_header(), "X-Auth");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), 100);
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert!(!AcunetixKernel::requires_credentials());
        assert_eq!(
            kernel("tenant", family)
                .plan(Some("next-token"))
                .unwrap()
                .url()
                .query(),
            Some("l=100&c=next-token")
        );
    }
}

#[test]
fn go_events_and_projection_fixtures_match_semantically() {
    for family in AcunetixFamily::ALL {
        let oracle = oracle(family);
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![oracle.payload.clone()], None),
            )
            .unwrap();
        let record = &page.records[0];
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "acunetix");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(
            oracle
                .id
                .starts_with(&format!("acunetix-{}", family.as_str().replace('_', "-")))
        );
        let projection = project_acunetix_records(&page.records);
        assert_eq!(projection.entities.len(), 1);
        assert_eq!(
            projection.entities[0].urn,
            format!(
                "urn:cerebro:tenant:acunetix_{}:{}",
                family.as_str(),
                record.provider_id
            )
        );
    }
}

#[test]
fn cursor_checkpoint_and_restart_round_trip() {
    let family = AcunetixFamily::Targets;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![oracle(family).payload], Some("next-token")),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("next-token"));
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("next-token"));
    assert_eq!(checkpoint.watermark, OBSERVED_AT);
    assert_eq!(
        kernel
            .plan(checkpoint.cursor.as_deref())
            .unwrap()
            .url()
            .query(),
        Some("l=100&c=next-token")
    );
    let terminal_request = kernel.plan(Some("next-token")).unwrap();
    let terminal = kernel
        .decode(
            &terminal_request,
            200,
            None,
            &response(family, Vec::new(), None),
        )
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
}

#[test]
fn duplicate_conflict_tenant_secret_and_statuses_fail_closed() {
    let family = AcunetixFamily::Targets;
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
    conflict["address"] = Value::String("https://different.example.test".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![raw, conflict], None)
        ),
        Err(AcunetixError::ConflictingDuplicate)
    );
    for (field, expected) in [
        ("tenant_id", AcunetixError::TenantMismatch),
        ("x_auth", AcunetixError::CredentialMaterial),
        ("token", AcunetixError::CredentialMaterial),
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
        Err(AcunetixError::AuthenticationRejected)
    );
    assert_eq!(
        kernel.decode(&request, 403, None, b"{}"),
        Err(AcunetixError::RequiredScopeMissing)
    );
    assert_eq!(
        kernel.decode(&request, 429, Some(60), b"{}"),
        Err(AcunetixError::RateLimited {
            retry_after_seconds: Some(60)
        })
    );
}

#[test]
fn origin_cursor_and_tenant_inputs_fail_closed() {
    for origin in [
        "http://online.acunetix.com/api/v1",
        "https://user@online.acunetix.com/api/v1",
        "https://online.acunetix.com:8443/api/v1",
        "https://online.acunetix.com",
        "https://online.acunetix.com/api/v2",
        "https://online.acunetix.com/api/v1?token=value",
    ] {
        assert!(
            AcunetixKernel::new(origin, "tenant", AcunetixFamily::Targets, OBSERVED_AT).is_err()
        );
    }
    assert!(
        AcunetixKernel::new(ORIGIN, "bad:tenant", AcunetixFamily::Targets, OBSERVED_AT).is_err()
    );
    assert_eq!(
        kernel("tenant", AcunetixFamily::Targets).plan(Some("../escape")),
        Err(AcunetixError::InvalidCursor)
    );
}

#[test]
fn identity_is_deterministic_tenant_and_origin_scoped() {
    let family = AcunetixFamily::Reports;
    let body = response(family, vec![oracle(family).payload], None);
    let first = kernel("tenant-a", family);
    let first_request = first.plan(None).unwrap();
    let first_page = first.decode(&first_request, 200, None, &body).unwrap();
    assert_eq!(
        first_page,
        first.decode(&first_request, 200, None, &body).unwrap()
    );
    let other_tenant = kernel("tenant-b", family);
    let other_request = other_tenant.plan(None).unwrap();
    let other_page = other_tenant
        .decode(&other_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first_page.records[0].event_id,
        other_page.records[0].event_id
    );
    let other_origin = AcunetixKernel::new(
        "https://scanner.example.test/api/v1",
        "tenant-a",
        family,
        OBSERVED_AT,
    )
    .unwrap();
    let other_origin_request = other_origin.plan(None).unwrap();
    let other_origin_page = other_origin
        .decode(&other_origin_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first_page.records[0].event_id,
        other_origin_page.records[0].event_id
    );
}
