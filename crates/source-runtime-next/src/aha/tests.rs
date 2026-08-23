use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use super::*;

const ORIGIN: &str = "https://example.aha.io";
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

fn kernel(tenant: &str, family: AhaFamily) -> AhaKernel {
    AhaKernel::new(
        ORIGIN,
        tenant,
        family,
        (family == AhaFamily::Releases).then_some("product-1"),
        OBSERVED_AT,
    )
    .unwrap()
}

fn oracle(family: AhaFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/aha/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn response(family: AhaFamily, records: Vec<Value>) -> Vec<u8> {
    let mut root = Map::new();
    root.insert(family.response_key().to_owned(), Value::Array(records));
    serde_json::to_vec(&Value::Object(root)).unwrap()
}

#[test]
fn catalog_closes_the_exact_compatibility_authoritative_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("aha").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let mut families = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<Vec<_>>();
    families.sort_unstable();
    assert_eq!(
        families,
        ["audit_events", "features", "products", "releases", "users"]
    );
    assert!(!root().join("sources/aha/source.go").exists());
    for family in AhaFamily::ALL {
        let definition = AhaRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "aha");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in AhaFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("example.aha.io"));
        assert_eq!(
            request.url().path(),
            format!(
                "/api/v1{}",
                family
                    .path((family == AhaFamily::Releases).then_some("product-1"))
                    .unwrap()
            )
        );
        assert_eq!(request.url().query(), Some("per_page=100&page=1"));
        assert_eq!(request.authentication_header(), "Authorization");
        assert_eq!(request.authentication_scheme(), "Bearer");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), 100);
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert_eq!(request.required_scope(), "Aha! API read access");
        assert!(!AhaKernel::requires_credentials());
    }
}

#[test]
fn origin_product_tenant_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://example.aha.io",
        "https://user@example.aha.io",
        "https://example.aha.io:8443",
        "https://aha.io",
        "https://nested.example.aha.io",
        "https://example.aha.io/api/v1",
        "https://example.aha.io?token=value",
    ] {
        assert!(AhaKernel::new(origin, "tenant", AhaFamily::Products, None, OBSERVED_AT).is_err());
    }
    assert!(matches!(
        AhaKernel::new(ORIGIN, "tenant", AhaFamily::Releases, None, OBSERVED_AT),
        Err(AhaError::MissingProductId)
    ));
    assert!(
        AhaKernel::new(
            ORIGIN,
            "tenant",
            AhaFamily::Releases,
            Some("../escape"),
            OBSERVED_AT
        )
        .is_err()
    );
    assert!(AhaKernel::new(ORIGIN, "bad:tenant", AhaFamily::Products, None, OBSERVED_AT).is_err());
    for cursor in ["0", "-1", "1000001", "next"] {
        assert_eq!(
            kernel("tenant", AhaFamily::Products).plan(Some(cursor)),
            Err(AhaError::InvalidCursor)
        );
    }
}

#[test]
fn every_family_matches_the_checked_go_event_and_projection_fixture() {
    for family in AhaFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let oracle = oracle(family);
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![oracle.payload.clone()]),
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor, None);
        let record = &page.records[0];
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "aha");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(oracle.id.starts_with("aha-"));
        assert!(record.event_id.starts_with("aha-tenant-"));
        assert_eq!(project_aha_records(&page.records).entities.len(), 1);
    }
}

#[test]
fn page_checkpoint_and_restart_are_round_trippable() {
    let family = AhaFamily::Features;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let records = (1..=100)
        .map(|number| {
            json!({
                "id": format!("feature-{number}"),
                "name": format!("Feature {number}"),
                "updated_at": OBSERVED_AT
            })
        })
        .collect();
    let page = kernel
        .decode(&request, 200, None, &response(family, records))
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("2"));
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("2"));
    assert_eq!(checkpoint.watermark, OBSERVED_AT);
    let resumed = kernel.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(resumed.url().query(), Some("per_page=100&page=2"));
    let terminal = kernel
        .decode(&resumed, 200, None, &response(family, Vec::new()))
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
}

#[test]
fn duplicates_statuses_bounds_scope_and_secret_material_fail_closed() {
    let family = AhaFamily::Products;
    let product_kernel = kernel("tenant", family);
    let request = product_kernel.plan(None).unwrap();
    let raw = oracle(family).payload;
    let page = product_kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![raw.clone(), raw.clone()]),
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    let mut conflict = raw.clone();
    conflict["updated_at"] = Value::String("2026-06-03T00:00:00Z".to_owned());
    assert_eq!(
        product_kernel.decode(&request, 200, None, &response(family, vec![raw, conflict])),
        Err(AhaError::ConflictingDuplicate)
    );
    for (status, expected) in [
        (401, AhaError::AuthenticationRejected),
        (403, AhaError::RequiredScopeMissing),
        (404, AhaError::ProviderResourceNotFound),
        (
            429,
            AhaError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, AhaError::ProviderUnavailable { status: 503 }),
        (418, AhaError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            product_kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        product_kernel.decode(&request, 200, None, &oversized),
        Err(AhaError::ResponseTooLarge)
    );

    let releases = kernel("tenant", AhaFamily::Releases);
    let releases_request = releases.plan(None).unwrap();
    let mut wrong_scope = oracle(AhaFamily::Releases).payload;
    wrong_scope["product"]["id"] = Value::String("other-product".to_owned());
    assert_eq!(
        releases.decode(
            &releases_request,
            200,
            None,
            &response(AhaFamily::Releases, vec![wrong_scope])
        ),
        Err(AhaError::ProductMismatch)
    );
    for (field, expected) in [
        ("tenant_id", AhaError::TenantMismatch),
        ("authorization", AhaError::CredentialMaterial),
        ("token", AhaError::CredentialMaterial),
        ("private_key", AhaError::CredentialMaterial),
    ] {
        let mut raw = oracle(family).payload;
        raw[field] = Value::String("sentinel-secret-value".to_owned());
        let error = product_kernel
            .decode(&request, 200, None, &response(family, vec![raw]))
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }
}

#[test]
fn identity_is_deterministic_and_tenant_and_account_scoped() {
    let family = AhaFamily::Users;
    let body = response(family, vec![oracle(family).payload]);
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
    let other_tenant = kernel("tenant-b", family);
    let other_tenant_request = other_tenant.plan(None).unwrap();
    let other_tenant_page = other_tenant
        .decode(&other_tenant_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first.records[0].event_id,
        other_tenant_page.records[0].event_id
    );
    let other_account = AhaKernel::new(
        "https://other.aha.io",
        "tenant-a",
        family,
        None,
        OBSERVED_AT,
    )
    .unwrap();
    let other_account_request = other_account.plan(None).unwrap();
    let other_account_page = other_account
        .decode(&other_account_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first.records[0].event_id,
        other_account_page.records[0].event_id
    );
}
