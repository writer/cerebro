use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://api.addigy.com/api/v2";
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

fn kernel(tenant: &str, family: AddigyFamily) -> AddigyKernel {
    AddigyKernel::new(ORIGIN, tenant, family, Some("org-1"), OBSERVED_AT).unwrap()
}

fn oracle(family: AddigyFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/addigy/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn response(family: AddigyFamily, records: Vec<Value>, page: u32) -> Vec<u8> {
    let output = if family.root_array() {
        Value::Array(records)
    } else {
        json!({"items": records, "metadata": {"page": page}})
    };
    serde_json::to_vec(&output).unwrap()
}

#[test]
fn catalog_closes_the_exact_catalog_runtime_only_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("addigy").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let mut families = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<Vec<_>>();
    families.sort_unstable();
    assert_eq!(
        families,
        ["audit_events", "devices", "groups", "policies", "users"]
    );
    assert!(!root().join("sources/addigy/source.go").exists());
    for family in AddigyFamily::ALL {
        let definition = AddigyRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "addigy");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in AddigyFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "POST");
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("api.addigy.com"));
        assert_eq!(
            request.url().path(),
            format!(
                "/api/v2{}",
                family.path(Some("org-1")).expect("closed family")
            )
        );
        assert_eq!(
            request.url().query(),
            family.paginated().then_some("per_page=100&page=1")
        );
        assert_eq!(request.body(), &json!({}));
        assert_eq!(request.authentication_header(), "x-api-key");
        assert_eq!(request.authentication_scheme(), "");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), 100);
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert_eq!(request.required_scope(), "Addigy API v2 read access");
        assert!(!AddigyKernel::requires_credentials());
    }
}

#[test]
fn origin_organization_tenant_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://api.addigy.com/api/v2",
        "https://user@api.addigy.com/api/v2",
        "https://api.addigy.com:8443/api/v2",
        "https://api.addigy.com",
        "https://other.addigy.com/api/v2",
        "https://api.addigy.com/api/v2?token=value",
    ] {
        assert!(
            AddigyKernel::new(
                origin,
                "tenant",
                AddigyFamily::Devices,
                Some("org-1"),
                OBSERVED_AT
            )
            .is_err()
        );
    }
    assert!(AddigyKernel::new(ORIGIN, "tenant", AddigyFamily::Users, None, OBSERVED_AT).is_err());
    assert!(
        AddigyKernel::new(
            ORIGIN,
            "bad:tenant",
            AddigyFamily::Devices,
            Some("org-1"),
            OBSERVED_AT
        )
        .is_err()
    );
    for cursor in ["0", "-1", "1000001", "next"] {
        assert_eq!(
            kernel("tenant", AddigyFamily::Devices).plan(Some(cursor)),
            Err(AddigyError::InvalidCursor)
        );
    }
    assert_eq!(
        kernel("tenant", AddigyFamily::Policies).plan(Some("2")),
        Err(AddigyError::InvalidCursor)
    );
}

#[test]
fn every_family_matches_the_checked_go_event_and_projection_fixture() {
    for family in AddigyFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let oracle = oracle(family);
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![oracle.payload.clone()], 1),
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor, None);
        let record = &page.records[0];
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "addigy");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(oracle.id.starts_with("source-addigy-"));
        assert!(record.event_id.starts_with("addigy-tenant-"));
        assert_eq!(project_addigy_records(&page.records).entities.len(), 1);
    }
}

#[test]
fn page_checkpoint_and_restart_are_round_trippable() {
    let family = AddigyFamily::Devices;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let records = (1..=100)
        .map(|number| {
            json!({
                "agentid": format!("device-{number}"),
                "audit_date": OBSERVED_AT,
                "orgid": "org-1",
                "facts": {"device_name": {"value": format!("device-{number}")}}
            })
        })
        .collect();
    let page = kernel
        .decode(&request, 200, None, &response(family, records, 1))
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
        .decode(&resumed, 200, None, &response(family, Vec::new(), 2))
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
}

#[test]
fn duplicates_statuses_bounds_scope_and_secret_material_fail_closed() {
    let family = AddigyFamily::Devices;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = oracle(family).payload;
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![raw.clone(), raw.clone()], 1),
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    let mut conflict = raw.clone();
    conflict["audit_date"] = Value::String("2026-06-02T00:00:00Z".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![raw, conflict], 1)
        ),
        Err(AddigyError::ConflictingDuplicate)
    );
    for (status, expected) in [
        (401, AddigyError::AuthenticationRejected),
        (403, AddigyError::RequiredScopeMissing),
        (404, AddigyError::ProviderResourceNotFound),
        (
            429,
            AddigyError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, AddigyError::ProviderUnavailable { status: 503 }),
        (418, AddigyError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(AddigyError::ResponseTooLarge)
    );
    let mut wrong_scope = oracle(family).payload;
    wrong_scope["orgid"] = Value::String("other-org".to_owned());
    assert_eq!(
        kernel.decode(&request, 200, None, &response(family, vec![wrong_scope], 1)),
        Err(AddigyError::OrganizationMismatch)
    );
    for (field, expected) in [
        ("tenant_id", AddigyError::TenantMismatch),
        ("x-api-key", AddigyError::CredentialMaterial),
        ("token", AddigyError::CredentialMaterial),
        ("private_key", AddigyError::CredentialMaterial),
    ] {
        let mut raw = oracle(family).payload;
        raw[field] = Value::String("sentinel-secret-value".to_owned());
        let error = kernel
            .decode(&request, 200, None, &response(family, vec![raw], 1))
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }
}

#[test]
fn identity_is_deterministic_and_tenant_and_organization_scoped() {
    let family = AddigyFamily::Users;
    let body = response(family, vec![oracle(family).payload], 1);
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
    let other_org =
        AddigyKernel::new(ORIGIN, "tenant-a", family, Some("other-org"), OBSERVED_AT).unwrap();
    assert_ne!(
        first.records[0].event_id,
        super::normalize::normalize(
            &other_org,
            json!({
                "email": "admin@example.test",
                "name": "Admin One",
                "orgid": "other-org"
            })
        )
        .unwrap()
        .event_id
    );
}
