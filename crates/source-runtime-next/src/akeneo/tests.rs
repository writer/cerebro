use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://tenant.akeneo.com";
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

fn scope() -> AkeneoScope {
    AkeneoScope::new(
        Some("asset-family-1"),
        Some("code-1"),
        Some("attribute-1"),
        Some("reference-1"),
        Some("123e4567-e89b-12d3-a456-426614174000"),
    )
}

fn kernel(tenant: &str, family: AkeneoFamily) -> AkeneoKernel {
    AkeneoKernel::new(ORIGIN, tenant, family, scope(), OBSERVED_AT).unwrap()
}

fn oracle(family: AkeneoFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/akeneo/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn provider_payload(family: AkeneoFamily) -> Value {
    let mut payload = oracle(family).payload;
    let values = payload.as_object_mut().unwrap();
    values.remove("tenant_id");
    values.remove("source_id");
    values.remove("schema_ref");
    payload
}

fn response(family: AkeneoFamily, records: Vec<Value>) -> Vec<u8> {
    let value = if family.collection() {
        Value::Array(records)
    } else {
        records.into_iter().next().unwrap_or_else(|| json!({}))
    };
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn catalog_closes_the_exact_go_compatibility_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("akeneo").unwrap();
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
            "asset",
            "asset_families_attribute",
            "asset_family",
            "attribute",
            "attribute_group",
            "attributes_option",
            "draft",
            "option",
            "products_draft",
            "products_uuid_draft",
            "reference_entities_attribute",
            "v1_attribute"
        ]
    );
    assert!(!root().join("sources/akeneo/source.go").exists());
    for family in AkeneoFamily::ALL {
        let definition = AkeneoRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "akeneo");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in AkeneoFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("tenant.akeneo.com"));
        assert_eq!(request.url().path(), family.path(&scope()).unwrap());
        assert_eq!(request.url().query(), None);
        assert_eq!(request.authentication_header(), "Authorization");
        assert_eq!(request.authentication_scheme(), "Bearer");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(
            request.record_limit(),
            if family.collection() { 100 } else { 1 }
        );
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert_eq!(request.required_scope(), "Akeneo API read access");
        assert!(!AkeneoKernel::requires_credentials());
    }
}

#[test]
fn origin_scope_tenant_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://tenant.akeneo.com",
        "https://user@tenant.akeneo.com",
        "https://tenant.akeneo.com:8443",
        "https://akeneo.com",
        "https://nested.tenant.akeneo.com",
        "https://tenant.akeneo.com/api/rest/v1",
        "https://tenant.akeneo.com?token=value",
    ] {
        assert!(
            AkeneoKernel::new(origin, "tenant", AkeneoFamily::Asset, scope(), OBSERVED_AT).is_err()
        );
    }
    assert!(matches!(
        AkeneoKernel::new(
            ORIGIN,
            "tenant",
            AkeneoFamily::Asset,
            AkeneoScope::default(),
            OBSERVED_AT
        ),
        Err(AkeneoError::MissingPathParameter("code"))
    ));
    assert!(
        AkeneoKernel::new(
            ORIGIN,
            "tenant",
            AkeneoFamily::Asset,
            AkeneoScope::new(None, Some("../escape"), None, None, None),
            OBSERVED_AT
        )
        .is_err()
    );
    assert!(
        AkeneoKernel::new(
            ORIGIN,
            "bad:tenant",
            AkeneoFamily::Asset,
            scope(),
            OBSERVED_AT
        )
        .is_err()
    );
    assert_eq!(
        kernel("tenant", AkeneoFamily::Asset).plan(Some("cursor")),
        Err(AkeneoError::InvalidCursor)
    );
}

#[test]
fn every_family_matches_the_checked_go_event_and_projection_fixture() {
    for family in AkeneoFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let oracle = oracle(family);
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![provider_payload(family)]),
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor, None);
        let record = &page.records[0];
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "akeneo");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(oracle.id.starts_with("source-akeneo-"));
        assert!(record.event_id.starts_with("akeneo-tenant-"));
        assert_eq!(project_akeneo_records(&page.records).entities.len(), 1);
    }
}

#[test]
fn terminal_checkpoint_and_embedded_collection_are_bounded() {
    let family = AkeneoFamily::Attribute;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = provider_payload(family);
    let body = serde_json::to_vec(&json!({"_embedded": {"items": [raw]}})).unwrap();
    let page = kernel.decode(&request, 200, None, &body).unwrap();
    assert_eq!(page.next_cursor, None);
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor, None);
    assert_eq!(checkpoint.watermark, OBSERVED_AT);
}

#[test]
fn duplicates_statuses_bounds_and_protected_material_fail_closed() {
    let family = AkeneoFamily::Attribute;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = provider_payload(family);
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![raw.clone(), raw.clone()]),
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    let mut conflict = raw.clone();
    conflict["name"] = Value::String("Different".to_owned());
    assert_eq!(
        kernel.decode(&request, 200, None, &response(family, vec![raw, conflict])),
        Err(AkeneoError::ConflictingDuplicate)
    );
    for (status, expected) in [
        (401, AkeneoError::AuthenticationRejected),
        (403, AkeneoError::RequiredScopeMissing),
        (404, AkeneoError::ProviderResourceNotFound),
        (
            429,
            AkeneoError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, AkeneoError::ProviderUnavailable { status: 503 }),
        (418, AkeneoError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(AkeneoError::ResponseTooLarge)
    );
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![json!({"id": "x"}); 101])
        ),
        Err(AkeneoError::TooManyRecords)
    );
    for (field, expected) in [
        ("tenant_id", AkeneoError::TenantMismatch),
        ("source_id", AkeneoError::ProtectedContractField),
        ("schema_ref", AkeneoError::ProtectedContractField),
        ("authorization", AkeneoError::CredentialMaterial),
        ("token", AkeneoError::CredentialMaterial),
        ("private_key", AkeneoError::CredentialMaterial),
    ] {
        let mut raw = provider_payload(family);
        raw[field] = Value::String("sentinel-secret-value".to_owned());
        let error = kernel
            .decode(&request, 200, None, &response(family, vec![raw]))
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }
}

#[test]
fn identity_is_deterministic_and_tenant_account_and_scope_scoped() {
    let family = AkeneoFamily::Asset;
    let body = response(family, vec![provider_payload(family)]);
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

    let other_tenant = AkeneoKernel::new(ORIGIN, "tenant-b", family, scope(), OBSERVED_AT).unwrap();
    let other_tenant_request = other_tenant.plan(None).unwrap();
    let other_tenant_page = other_tenant
        .decode(&other_tenant_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first.records[0].event_id,
        other_tenant_page.records[0].event_id
    );

    let other_account = AkeneoKernel::new(
        "https://other.akeneo.com",
        "tenant-a",
        family,
        scope(),
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

    let other_scope = AkeneoKernel::new(
        ORIGIN,
        "tenant-a",
        family,
        AkeneoScope::new(None, Some("code-2"), None, None, None),
        OBSERVED_AT,
    )
    .unwrap();
    let other_scope_request = other_scope.plan(None).unwrap();
    let other_scope_page = other_scope
        .decode(&other_scope_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first.records[0].event_id,
        other_scope_page.records[0].event_id
    );
}
