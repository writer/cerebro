use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://api.adp.com";
const OBSERVED_AT: &str = "2026-07-01T12:00:00Z";

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

fn kernel(tenant: &str, family: AdpFamily) -> AdpKernel {
    AdpKernel::new(ORIGIN, tenant, family, OBSERVED_AT).unwrap()
}

fn oracle(family: AdpFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/adp_workforce_now/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn provider_raw(family: AdpFamily) -> Value {
    let mut payload = oracle(family).payload;
    let values = payload.as_object_mut().unwrap();
    for key in ["schema_ref", "source_id", "tenant_id"] {
        values.remove(key);
    }
    if family == AdpFamily::EventNotifications {
        values.remove("actor");
    }
    payload
}

fn response(family: AdpFamily, records: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({family.response_key(): records})).unwrap()
}

#[test]
fn catalog_closes_the_exact_catalog_runtime_only_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("adp_workforce_now").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let mut families = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<Vec<_>>();
    families.sort_unstable();
    assert_eq!(families, ["event_notifications", "users"]);
    assert!(!root().join("sources/adp_workforce_now/source.go").exists());
    for family in AdpFamily::ALL {
        let definition = AdpRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "adp_workforce_now");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn requests_are_origin_locked_bounded_dual_host_authenticated_and_credential_free() {
    for family in AdpFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("api.adp.com"));
        assert_eq!(request.url().path(), family.path());
        assert_eq!(
            request.url().query(),
            (family == AdpFamily::Users).then_some("%24top=100&%24skip=0")
        );
        assert_eq!(request.authentication_header(), "Authorization");
        assert_eq!(request.authentication_scheme(), "Bearer");
        assert!(request.requires_mutual_tls());
        assert!(request.credential_references_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert!(!AdpKernel::requires_credentials());
    }
}

#[test]
fn origin_tenant_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://api.adp.com",
        "https://user@api.adp.com",
        "https://api.adp.com:8443",
        "https://other.adp.com",
        "https://api.adp.com/hr",
        "https://api.adp.com?token=value",
    ] {
        assert!(AdpKernel::new(origin, "tenant", AdpFamily::Users, OBSERVED_AT).is_err());
    }
    assert!(AdpKernel::new(ORIGIN, "bad:tenant", AdpFamily::Users, OBSERVED_AT).is_err());
    for cursor in ["-1", "10000001", "next"] {
        assert_eq!(
            kernel("tenant", AdpFamily::Users).plan(Some(cursor)),
            Err(AdpError::InvalidCursor)
        );
    }
    assert_eq!(
        kernel("tenant", AdpFamily::EventNotifications).plan(Some("100")),
        Err(AdpError::InvalidCursor)
    );
}

#[test]
fn both_families_match_the_checked_go_event_and_projection_fixtures() {
    for family in AdpFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![provider_raw(family)]),
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor, None);
        let record = &page.records[0];
        let oracle = oracle(family);
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "adp_workforce_now");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(oracle.id.starts_with("adp-workforce-now-"));
        assert!(record.event_id.starts_with("adp-workforce-now-tenant-"));
        assert_eq!(project_adp_records(&page.records).entities.len(), 1);
    }
}

#[test]
fn user_offset_checkpoint_and_restart_are_round_trippable() {
    let family = AdpFamily::Users;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let records = (1..=100)
        .map(|number| {
            json!({
                "associateOID": format!("worker-{number}"),
                "person": {"legalName": {"formattedName": format!("Worker {number}")}},
                "workerDates": {"originalHireDate": "2026-07-01"}
            })
        })
        .collect();
    let page = kernel
        .decode(&request, 200, None, &response(family, records))
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("100"));
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-06-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("100"));
    assert_eq!(checkpoint.watermark, "2026-07-01T00:00:00Z");
    let resumed = kernel.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(resumed.url().query(), Some("%24top=100&%24skip=100"));
    let terminal = kernel
        .decode(&resumed, 200, None, &response(family, Vec::new()))
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
}

#[test]
fn duplicates_statuses_bounds_tenant_and_secret_material_fail_closed() {
    let family = AdpFamily::Users;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = provider_raw(family);
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
    conflict["workerID"] = json!({"idValue": "different"});
    assert_eq!(
        kernel.decode(&request, 200, None, &response(family, vec![raw, conflict])),
        Err(AdpError::ConflictingDuplicate)
    );
    for (status, expected) in [
        (401, AdpError::AuthenticationRejected),
        (403, AdpError::RequiredScopeMissing),
        (404, AdpError::ProviderResourceNotFound),
        (
            429,
            AdpError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, AdpError::ProviderUnavailable { status: 503 }),
        (418, AdpError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(AdpError::ResponseTooLarge)
    );
    for (field, expected) in [
        ("tenant_id", AdpError::TenantMismatch),
        ("access_token", AdpError::CredentialMaterial),
        ("client_certificate", AdpError::CredentialMaterial),
        ("private_key", AdpError::CredentialMaterial),
    ] {
        let mut raw = provider_raw(family);
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
fn identity_is_deterministic_and_tenant_scoped() {
    let family = AdpFamily::Users;
    let body = response(family, vec![provider_raw(family)]);
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
    let other_request = other_tenant.plan(None).unwrap();
    let other = other_tenant
        .decode(&other_request, 200, None, &body)
        .unwrap();
    assert_ne!(first.records[0].event_id, other.records[0].event_id);
}

#[test]
fn identity_encoding_does_not_collapse_distinct_provider_ids() {
    let family = AdpFamily::Users;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let mut event_ids = Vec::new();

    for provider_id in ["worker-a", "worker a", "worker/a", "worker:a"] {
        let mut raw = provider_raw(family);
        raw["associateOID"] = Value::String(provider_id.to_owned());
        let page = kernel
            .decode(&request, 200, None, &response(family, vec![raw]))
            .unwrap();
        let record = &page.records[0];
        assert_eq!(record.provider_id, provider_id);
        assert_eq!(record.attributes["source_event_id"], provider_id);
        event_ids.push(record.event_id.clone());
    }

    event_ids.sort_unstable();
    event_ids.dedup();
    assert_eq!(event_ids.len(), 4);
}
