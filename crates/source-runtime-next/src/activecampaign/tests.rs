use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://example-account.api-us1.com";
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

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn kernel(tenant: &str, family: ActiveCampaignFamily) -> ActiveCampaignKernel {
    ActiveCampaignKernel::new(ORIGIN, tenant, family, OBSERVED_AT).unwrap()
}

fn oracle(family: ActiveCampaignFamily) -> GoOracleEvent {
    let bytes = fs::read(repository_root().join(format!(
        "sources/activecampaign/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn provider_raw(family: ActiveCampaignFamily) -> Value {
    let mut payload = oracle(family).payload;
    payload.as_object_mut().unwrap().remove("schema_ref");
    payload
}

fn response(family: ActiveCampaignFamily, records: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({family.response_key(): records})).unwrap()
}

#[test]
fn catalog_and_kernel_close_the_exact_authoritative_family_set() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let source = catalog.get("activecampaign").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let mut families = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<Vec<_>>();
    families.sort_unstable();
    assert_eq!(
        families,
        ["accounts", "automations", "campaigns", "contacts", "users"]
    );
    assert!(
        source
            .families()
            .iter()
            .all(|family| family.is_authoritative())
    );
    for family in ActiveCampaignFamily::ALL {
        let definition = ActiveCampaignRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "activecampaign");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn every_family_plans_a_bounded_origin_locked_credential_free_request() {
    for family in ActiveCampaignFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.family(), family);
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(
            request.url().host_str(),
            Some("example-account.api-us1.com")
        );
        assert_eq!(request.url().path(), family.path());
        assert_eq!(request.url().query(), Some("limit=100&offset=0"));
        assert_eq!(request.authentication_header(), "Api-Token");
        assert_eq!(request.authentication_scheme(), "");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), 100);
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert_eq!(request.required_scope(), "ActiveCampaign API read access");
        assert!(!ActiveCampaignKernel::requires_credentials());
        assert_eq!(
            kernel.plan(Some("100")).unwrap().url().query(),
            Some("limit=100&offset=100")
        );
    }
}

#[test]
fn origin_tenant_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://example-account.api-us1.com",
        "https://api-us1.com",
        "https://other.example-account.api-us1.com",
        "https://user@example-account.api-us1.com",
        "https://example-account.api-us1.com:8443",
        "https://example-account.api-us1.com/api/3",
        "https://example-account.api-us1.com?token=value",
    ] {
        assert!(
            ActiveCampaignKernel::new(origin, "tenant", ActiveCampaignFamily::Users, OBSERVED_AT,)
                .is_err()
        );
    }
    assert!(
        ActiveCampaignKernel::new(
            ORIGIN,
            "bad:tenant",
            ActiveCampaignFamily::Users,
            OBSERVED_AT
        )
        .is_err()
    );
    assert_eq!(
        kernel("tenant", ActiveCampaignFamily::Users).plan(Some("-1")),
        Err(ActiveCampaignError::InvalidCursor)
    );
    assert_eq!(
        kernel("tenant", ActiveCampaignFamily::Users).plan(Some("10000001")),
        Err(ActiveCampaignError::InvalidCursor)
    );
}

#[test]
fn every_family_matches_the_checked_go_event_fixture_semantically() {
    for family in ActiveCampaignFamily::ALL {
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
        assert_eq!(oracle.source_id, "activecampaign");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert_eq!(
            oracle.id,
            format!("activecampaign-{}-{}", family.as_str(), record.provider_id)
        );
        assert!(record.event_id.starts_with("activecampaign-tenant-"));

        let projection = project_activecampaign_records(&page.records);
        assert_eq!(projection.entities.len(), 1);
        if family == ActiveCampaignFamily::Users {
            assert_eq!(projection.entities[0].entity_type, "activecampaign.user");
        } else {
            assert!(
                projection.entities[0]
                    .entity_type
                    .starts_with("runtime.activecampaign.")
            );
        }
    }
}

#[test]
fn offset_pagination_checkpoint_and_restart_are_round_trippable() {
    let family = ActiveCampaignFamily::Accounts;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let records: Vec<_> = (1..=100)
        .map(|id| json!({"id": id.to_string(), "name": format!("account-{id}")}))
        .collect();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &serde_json::to_vec(&json!({"accounts": records, "meta": {"total": "101"}})).unwrap(),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("100"));
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("100"));
    assert_eq!(checkpoint.watermark, OBSERVED_AT);
    let resumed = kernel.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(resumed.url().query(), Some("limit=100&offset=100"));
    let terminal = kernel
        .decode(
            &resumed,
            200,
            None,
            &response(family, vec![json!({"id":"101","name":"last"})]),
        )
        .unwrap();
    assert_eq!(terminal.next_cursor, None);
}

#[test]
fn duplicate_identity_is_idempotent_but_conflicting_content_fails() {
    let family = ActiveCampaignFamily::Accounts;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = provider_raw(family);
    let identical = kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![raw.clone(), raw.clone()]),
        )
        .unwrap();
    assert_eq!(identical.records.len(), 1);
    let mut conflict = raw.clone();
    conflict["name"] = Value::String("different".to_owned());
    assert_eq!(
        kernel.decode(&request, 200, None, &response(family, vec![raw, conflict])),
        Err(ActiveCampaignError::ConflictingDuplicate)
    );
}

#[test]
fn provider_failures_size_tenant_and_secret_material_remain_typed() {
    let family = ActiveCampaignFamily::Users;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    for (status, expected) in [
        (401, ActiveCampaignError::AuthenticationRejected),
        (403, ActiveCampaignError::RequiredScopeMissing),
        (404, ActiveCampaignError::ProviderResourceNotFound),
        (
            429,
            ActiveCampaignError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (
            503,
            ActiveCampaignError::ProviderUnavailable { status: 503 },
        ),
        (418, ActiveCampaignError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    assert_eq!(
        kernel.decode(&request, 429, Some(3_601), b"{}"),
        Err(ActiveCampaignError::InvalidRetryAfter)
    );
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(ActiveCampaignError::ResponseTooLarge)
    );

    for (field, expected) in [
        ("tenant_id", ActiveCampaignError::TenantMismatch),
        ("api_token", ActiveCampaignError::CredentialMaterial),
        ("authorization", ActiveCampaignError::CredentialMaterial),
        ("private_key", ActiveCampaignError::CredentialMaterial),
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
    let family = ActiveCampaignFamily::Contacts;
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
    let other_kernel = kernel("tenant-b", family);
    let other_request = other_kernel.plan(None).unwrap();
    let other = other_kernel
        .decode(&other_request, 200, None, &body)
        .unwrap();
    assert_eq!(first.records[0].provider_id, other.records[0].provider_id);
    assert_ne!(first.records[0].event_id, other.records[0].event_id);
    assert_ne!(
        first.records[0].attributes["resource_urn"],
        other.records[0].attributes["resource_urn"]
    );
}
