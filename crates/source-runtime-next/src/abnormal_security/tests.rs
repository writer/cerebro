use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://api.abnormalplatform.com/v1";
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

fn kernel(tenant: &str, family: AbnormalSecurityFamily) -> AbnormalSecurityKernel {
    AbnormalSecurityKernel::new(ORIGIN, tenant, family, OBSERVED_AT).unwrap()
}

fn oracle(family: AbnormalSecurityFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/abnormal_security/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn response(family: AbnormalSecurityFamily, records: Vec<Value>, cursor: Option<u64>) -> Vec<u8> {
    let mut response = json!({family.response_key(): records});
    if let Some(cursor) = cursor {
        if family == AbnormalSecurityFamily::PostureCatalog {
            response["metadata"] = json!({"next_page": cursor});
        } else {
            response["nextPageNumber"] = json!(cursor);
        }
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
    let source = catalog.get("abnormal_security").unwrap();
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
            "audit_events",
            "cases",
            "posture_catalog",
            "resources",
            "threats"
        ]
    );
    assert!(!root().join("sources/abnormal_security/source.go").exists());
    for family in AbnormalSecurityFamily::ALL {
        let definition = AbnormalSecurityRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "abnormal_security");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in AbnormalSecurityFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().host_str(), Some("api.abnormalplatform.com"));
        assert_eq!(request.url().path(), format!("/v1{}", family.path()));
        assert_eq!(request.url().query(), Some("pageSize=100"));
        assert_eq!(request.authentication_header(), "Authorization");
        assert_eq!(request.authentication_scheme(), "Bearer");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), 100);
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert!(!AbnormalSecurityKernel::requires_credentials());
        assert_eq!(
            kernel("tenant", family)
                .plan(Some("2"))
                .unwrap()
                .url()
                .query(),
            Some("pageSize=100&pageNumber=2")
        );
    }
}

#[test]
fn go_events_and_projection_fixtures_match_semantically() {
    for family in AbnormalSecurityFamily::ALL {
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
        assert_eq!(oracle.source_id, "abnormal_security");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(oracle.id.starts_with("abnormal-security-"));
        let projection = project_abnormal_security_records(&page.records);
        assert_eq!(projection.entities.len(), 1);
        assert_eq!(
            projection.entities[0].urn,
            format!(
                "urn:cerebro:tenant:abnormal_security_{}:{}",
                family.as_str(),
                record.provider_id
            )
        );
    }
}

#[test]
fn cursor_checkpoint_and_restart_round_trip_for_both_envelopes() {
    for family in [
        AbnormalSecurityFamily::Resources,
        AbnormalSecurityFamily::PostureCatalog,
    ] {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![oracle(family).payload], Some(2)),
            )
            .unwrap();
        assert_eq!(page.next_cursor.as_deref(), Some("2"));
        let checkpoint = kernel
            .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
            .unwrap();
        assert_eq!(checkpoint.cursor.as_deref(), Some("2"));
        assert_eq!(
            kernel
                .plan(checkpoint.cursor.as_deref())
                .unwrap()
                .url()
                .query(),
            Some("pageSize=100&pageNumber=2")
        );
    }
}

#[test]
fn duplicate_conflict_tenant_secret_and_statuses_fail_closed() {
    let family = AbnormalSecurityFamily::Resources;
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
    conflict["name"] = Value::String("different".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![raw, conflict], None)
        ),
        Err(AbnormalSecurityError::ConflictingDuplicate)
    );
    for (field, expected) in [
        ("tenant_id", AbnormalSecurityError::TenantMismatch),
        ("token", AbnormalSecurityError::CredentialMaterial),
        ("authorization", AbnormalSecurityError::CredentialMaterial),
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
        Err(AbnormalSecurityError::AuthenticationRejected)
    );
    assert_eq!(
        kernel.decode(&request, 403, None, b"{}"),
        Err(AbnormalSecurityError::RequiredScopeMissing)
    );
    assert_eq!(
        kernel.decode(&request, 429, Some(60), b"{}"),
        Err(AbnormalSecurityError::RateLimited {
            retry_after_seconds: Some(60)
        })
    );
}

#[test]
fn origin_cursor_and_tenant_inputs_fail_closed() {
    for origin in [
        "http://api.abnormalplatform.com/v1",
        "https://user@api.abnormalplatform.com/v1",
        "https://api.abnormalplatform.com:8443/v1",
        "https://api.abnormalplatform.com",
        "https://api.abnormalplatform.com/v2",
        "https://api.abnormalplatform.com/v1?token=value",
    ] {
        assert!(
            AbnormalSecurityKernel::new(
                origin,
                "tenant",
                AbnormalSecurityFamily::Resources,
                OBSERVED_AT
            )
            .is_err()
        );
    }
    assert!(
        AbnormalSecurityKernel::new(
            ORIGIN,
            "bad:tenant",
            AbnormalSecurityFamily::Resources,
            OBSERVED_AT
        )
        .is_err()
    );
    assert_eq!(
        kernel("tenant", AbnormalSecurityFamily::Resources).plan(Some("0")),
        Err(AbnormalSecurityError::InvalidCursor)
    );
    assert_eq!(
        kernel("tenant", AbnormalSecurityFamily::Resources).plan(Some("10000001")),
        Err(AbnormalSecurityError::InvalidCursor)
    );
}

#[test]
fn identity_is_deterministic_tenant_and_origin_scoped() {
    let family = AbnormalSecurityFamily::Threats;
    let body = response(family, vec![oracle(family).payload], None);
    let first = kernel("tenant-a", family);
    let first_request = first.plan(None).unwrap();
    let first_page = first.decode(&first_request, 200, None, &body).unwrap();
    assert_eq!(
        first_page,
        first.decode(&first_request, 200, None, &body).unwrap()
    );
    let other = kernel("tenant-b", family);
    let other_request = other.plan(None).unwrap();
    let other_page = other.decode(&other_request, 200, None, &body).unwrap();
    assert_ne!(
        first_page.records[0].event_id,
        other_page.records[0].event_id
    );
    let regional = AbnormalSecurityKernel::new(
        "https://api.eu.abnormalplatform.com/v1",
        "tenant-a",
        family,
        OBSERVED_AT,
    )
    .unwrap();
    let regional_request = regional.plan(None).unwrap();
    let regional_page = regional
        .decode(&regional_request, 200, None, &body)
        .unwrap();
    assert_ne!(
        first_page.records[0].event_id,
        regional_page.records[0].event_id
    );
}
