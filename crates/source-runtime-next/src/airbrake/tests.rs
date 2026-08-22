use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::*;

const ORIGIN: &str = "https://api.airbrake.io";
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

fn kernel(tenant: &str, family: AirbrakeFamily) -> AirbrakeKernel {
    AirbrakeKernel::new(
        ORIGIN,
        tenant,
        family,
        family.project_scoped().then_some("1"),
        OBSERVED_AT,
    )
    .unwrap()
}

fn oracle(family: AirbrakeFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/airbrake/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn provider_payload(family: AirbrakeFamily) -> Value {
    let mut payload = oracle(family).payload;
    let values = payload.as_object_mut().unwrap();
    values.remove("tenant_id");
    values.remove("source_id");
    values.remove("schema_ref");
    payload
}

fn response(family: AirbrakeFamily, records: Vec<Value>, cursor: Option<&str>) -> Vec<u8> {
    let mut root = Map::new();
    root.insert(family.response_key().to_owned(), Value::Array(records));
    if let Some(cursor) = cursor {
        root.insert("end".to_owned(), Value::String(cursor.to_owned()));
    }
    serde_json::to_vec(&Value::Object(root)).unwrap()
}

#[test]
fn catalog_closes_the_exact_go_compatibility_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("airbrake").unwrap();
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
            "deploys",
            "groups",
            "project_activities",
            "projects",
            "source_maps"
        ]
    );
    assert!(!root().join("sources/airbrake/source.go").exists());
    for family in AirbrakeFamily::ALL {
        let definition = AirbrakeRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "airbrake");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in AirbrakeFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("api.airbrake.io"));
        assert_eq!(
            request.url().path(),
            family.path(family.project_scoped().then_some("1")).unwrap()
        );
        assert_eq!(request.url().query(), Some("limit=100"));
        assert_eq!(request.authentication_query_parameter(), "token");
        assert!(!request.url().as_str().contains("token"));
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), 100);
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert_eq!(request.required_scope(), "Airbrake API read access");
        assert!(!AirbrakeKernel::requires_credentials());
    }
}

#[test]
fn origin_project_tenant_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://api.airbrake.io",
        "https://user@api.airbrake.io",
        "https://api.airbrake.io:8443",
        "https://airbrake.io",
        "https://nested.api.airbrake.io",
        "https://api.airbrake.io/api/v4",
        "https://api.airbrake.io?token=value",
    ] {
        assert!(
            AirbrakeKernel::new(
                origin,
                "tenant",
                AirbrakeFamily::Projects,
                None,
                OBSERVED_AT
            )
            .is_err()
        );
    }
    assert!(matches!(
        AirbrakeKernel::new(ORIGIN, "tenant", AirbrakeFamily::Deploys, None, OBSERVED_AT),
        Err(AirbrakeError::MissingProjectId)
    ));
    assert!(
        AirbrakeKernel::new(
            ORIGIN,
            "tenant",
            AirbrakeFamily::SourceMaps,
            Some("../escape"),
            OBSERVED_AT
        )
        .is_err()
    );
    assert!(
        AirbrakeKernel::new(
            ORIGIN,
            "bad:tenant",
            AirbrakeFamily::Projects,
            None,
            OBSERVED_AT
        )
        .is_err()
    );
    assert_eq!(
        kernel("tenant", AirbrakeFamily::Projects).plan(Some("cursor")),
        Err(AirbrakeError::InvalidCursor)
    );
    for cursor in ["", "bad&next", "bad=next", "bad?next", "bad#next"] {
        assert_eq!(
            kernel("tenant", AirbrakeFamily::Groups).plan(Some(cursor)),
            Err(AirbrakeError::InvalidCursor)
        );
    }
}

#[test]
fn every_family_matches_the_checked_go_event_and_projection_fixture() {
    for family in AirbrakeFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let oracle = oracle(family);
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![provider_payload(family)], None),
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor, None);
        let record = &page.records[0];
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "airbrake");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(oracle.id.starts_with("airbrake-") || oracle.id.starts_with("source-airbrake-"));
        assert!(record.event_id.starts_with("airbrake-tenant-"));
        let projected = project_airbrake_records(&page.records);
        let expected_entities = usize::from(family == AirbrakeFamily::ProjectActivities) + 1;
        assert_eq!(projected.entities.len(), expected_entities);
    }
}

#[test]
fn groups_cursor_checkpoint_and_restart_are_round_trippable() {
    let family = AirbrakeFamily::Groups;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![provider_payload(family)], Some("cursor-2")),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("cursor-2"));
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("cursor-2"));
    assert_eq!(checkpoint.watermark, OBSERVED_AT);
    let resumed = kernel.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(resumed.url().query(), Some("limit=100&start=cursor-2"));
    let terminal = kernel
        .decode(
            &resumed,
            200,
            None,
            &response(family, Vec::new(), Some("cursor-2")),
        )
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, Vec::new(), Some("bad&cursor"))
        ),
        Err(AirbrakeError::InvalidCursor)
    );
}

#[test]
fn duplicates_statuses_bounds_scope_and_protected_material_fail_closed() {
    let family = AirbrakeFamily::Projects;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = provider_payload(family);
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
    conflict["name"] = Value::String("Different".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![raw, conflict], None)
        ),
        Err(AirbrakeError::ConflictingDuplicate)
    );
    for (status, expected) in [
        (401, AirbrakeError::AuthenticationRejected),
        (403, AirbrakeError::RequiredScopeMissing),
        (404, AirbrakeError::ProviderResourceNotFound),
        (
            429,
            AirbrakeError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, AirbrakeError::ProviderUnavailable { status: 503 }),
        (418, AirbrakeError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(AirbrakeError::ResponseTooLarge)
    );
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![json!({"id": "x", "name": "x"}); 101], None)
        ),
        Err(AirbrakeError::TooManyRecords)
    );

    let scoped = AirbrakeKernel::new(
        ORIGIN,
        "tenant",
        AirbrakeFamily::SourceMaps,
        Some("2"),
        OBSERVED_AT,
    )
    .unwrap();
    let scoped_request = scoped.plan(None).unwrap();
    assert_eq!(
        scoped.decode(
            &scoped_request,
            200,
            None,
            &response(
                AirbrakeFamily::SourceMaps,
                vec![provider_payload(AirbrakeFamily::SourceMaps)],
                None
            )
        ),
        Err(AirbrakeError::ProjectMismatch)
    );

    for (field, expected) in [
        ("tenant_id", AirbrakeError::TenantMismatch),
        ("source_id", AirbrakeError::ProtectedContractField),
        ("schema_ref", AirbrakeError::ProtectedContractField),
        ("authorization", AirbrakeError::CredentialMaterial),
        ("token", AirbrakeError::CredentialMaterial),
        ("private_key", AirbrakeError::CredentialMaterial),
    ] {
        let mut raw = provider_payload(family);
        raw[field] = Value::String("sentinel-secret-value".to_owned());
        let error = kernel
            .decode(&request, 200, None, &response(family, vec![raw], None))
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }
    assert!(!format!("{request:?}").contains("cursor-value"));
}

#[test]
fn identity_is_deterministic_and_tenant_and_project_scoped() {
    let family = AirbrakeFamily::Deploys;
    let body = response(family, vec![provider_payload(family)], None);
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

    let other_tenant =
        AirbrakeKernel::new(ORIGIN, "tenant-b", family, Some("1"), OBSERVED_AT).unwrap();
    let other_tenant_request = other_tenant.plan(None).unwrap();
    let other_tenant_page = other_tenant
        .decode(&other_tenant_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first.records[0].event_id,
        other_tenant_page.records[0].event_id
    );

    let other_project =
        AirbrakeKernel::new(ORIGIN, "tenant-a", family, Some("2"), OBSERVED_AT).unwrap();
    let other_project_request = other_project.plan(None).unwrap();
    let other_project_page = other_project
        .decode(&other_project_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first.records[0].event_id,
        other_project_page.records[0].event_id
    );
}
