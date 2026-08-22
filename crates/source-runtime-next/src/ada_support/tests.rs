use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const ORIGIN: &str = "https://example.ada.support/api";
const OBSERVED_AT: &str = "2026-06-02T00:00:00Z";

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

fn kernel(tenant: &str, family: AdaSupportFamily) -> AdaSupportKernel {
    AdaSupportKernel::new(ORIGIN, tenant, family, OBSERVED_AT).unwrap()
}

fn oracle(family: AdaSupportFamily) -> GoOracleEvent {
    let bytes = fs::read(root().join(format!(
        "sources/ada_support/testdata/read_{}.json",
        family.as_str()
    )))
    .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

fn provider_raw(family: AdaSupportFamily) -> Value {
    let mut payload = oracle(family).payload;
    let values = payload.as_object_mut().unwrap();
    for key in [
        "api_method",
        "api_path",
        "schema_ref",
        "source_id",
        "tenant_id",
        "event_id",
    ] {
        values.remove(key);
    }
    match family {
        AdaSupportFamily::AuditEvents
        | AdaSupportFamily::Conversations
        | AdaSupportFamily::PlatformIntegrations => {
            values.remove("resource_id");
            values.remove("resource_urn");
        }
        AdaSupportFamily::EndUsers => {
            values.remove("user_id");
        }
        AdaSupportFamily::KnowledgeArticles => {
            values.remove("policy_id");
            values.remove("policy_name");
        }
    }
    payload
}

fn response(family: AdaSupportFamily, records: Vec<Value>, cursor: Option<&str>) -> Vec<u8> {
    let mut output = json!({family.response_key(): records});
    if let Some(cursor) = cursor {
        output["meta"] = json!({family.next_page_key(): cursor});
    }
    serde_json::to_vec(&output).unwrap()
}

#[test]
fn catalog_closes_the_exact_catalog_runtime_only_family_set() {
    let catalog = SourceCatalog::load(
        root().join("internal/connectorcatalog/catalog"),
        root().join("sources"),
    )
    .unwrap();
    let source = catalog.get("ada_support").unwrap();
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
            "conversations",
            "end_users",
            "knowledge_articles",
            "platform_integrations"
        ]
    );
    assert!(!root().join("sources/ada_support/source.go").exists());
    for family in AdaSupportFamily::ALL {
        let definition = AdaSupportRuntimeDefinition::compile(family).unwrap();
        assert_eq!(definition.source_id, "ada_support");
        assert!(definition.pull);
        assert_eq!(definition.event_contract.kind, family.event_kind());
        assert_eq!(definition.event_contract.schema_ref, family.schema_ref());
    }
}

#[test]
fn requests_are_origin_locked_bounded_and_credential_free() {
    for family in AdaSupportFamily::ALL {
        let request = kernel("tenant", family).plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("example.ada.support"));
        assert_eq!(request.url().path(), format!("/api{}", family.path()));
        let size_param = if family == AdaSupportFamily::Conversations {
            "page_size"
        } else {
            "limit"
        };
        let initial_query = format!("{size_param}=100");
        assert_eq!(request.url().query(), Some(initial_query.as_str()));
        assert_eq!(request.authentication_header(), "Authorization");
        assert_eq!(request.authentication_scheme(), "Bearer");
        assert!(request.credential_reference_required());
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.record_limit(), 100);
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert_eq!(request.required_scope(), "Ada Support API read access");
        assert!(!AdaSupportKernel::requires_credentials());
        let cursor_query = format!("{size_param}=100&cursor=next-token");
        assert_eq!(
            kernel("tenant", family)
                .plan(Some("next-token"))
                .unwrap()
                .url()
                .query(),
            Some(cursor_query.as_str())
        );
    }
}

#[test]
fn origin_tenant_and_cursor_inputs_fail_closed() {
    for origin in [
        "http://example.ada.support/api",
        "https://ada.support/api",
        "https://user@example.ada.support/api",
        "https://example.ada.support:8443/api",
        "https://example.ada.support",
        "https://example.ada.support/api/v2",
        "https://example.ada.support/api?token=value",
    ] {
        assert!(
            AdaSupportKernel::new(origin, "tenant", AdaSupportFamily::EndUsers, OBSERVED_AT)
                .is_err()
        );
    }
    assert!(
        AdaSupportKernel::new(
            ORIGIN,
            "bad:tenant",
            AdaSupportFamily::EndUsers,
            OBSERVED_AT
        )
        .is_err()
    );
    let kernel = kernel("tenant", AdaSupportFamily::EndUsers);
    for cursor in [
        "../escape",
        "https://attacker.example/api/v2/end-users/",
        "/api/v2/platform-integrations/",
        "bad/path",
    ] {
        assert_eq!(
            kernel.plan(Some(cursor)),
            Err(AdaSupportError::InvalidCursor)
        );
    }
}

#[test]
fn every_family_matches_the_checked_go_event_and_projection_fixture() {
    for family in AdaSupportFamily::ALL {
        let kernel = kernel("tenant", family);
        let request = kernel.plan(None).unwrap();
        let page = kernel
            .decode(
                &request,
                200,
                None,
                &response(family, vec![provider_raw(family)], None),
            )
            .unwrap();
        assert_eq!(page.records.len(), 1);
        assert_eq!(page.next_cursor, None);
        let record = &page.records[0];
        let oracle = oracle(family);
        assert_eq!(record.tenant_id, oracle.tenant_id);
        assert_eq!(oracle.source_id, "ada_support");
        assert_eq!(record.kind, oracle.kind);
        assert_eq!(record.schema_ref, oracle.schema_ref);
        assert_eq!(record.occurred_at, oracle.occurred_at);
        assert_eq!(record.payload, oracle.payload);
        assert_eq!(record.attributes, oracle.attributes);
        assert!(oracle.id.starts_with("source-ada_support-"));
        assert!(record.event_id.starts_with("ada-support-tenant-"));
        let projection = project_ada_support_records(&page.records);
        assert_eq!(projection.entities.len(), 1);
        if family == AdaSupportFamily::EndUsers {
            assert_eq!(projection.entities[0].entity_type, "ada_support.user");
        } else {
            assert_eq!(
                projection.entities[0].urn,
                record.attributes["resource_urn"]
            );
        }
    }
}

#[test]
fn cursor_checkpoint_and_restart_are_round_trippable() {
    let family = AdaSupportFamily::PlatformIntegrations;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            200,
            None,
            &response(family, vec![provider_raw(family)], Some("next-token")),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("next-token"));
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-05-01T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("next-token"));
    assert_eq!(checkpoint.watermark, OBSERVED_AT);
    let resumed = kernel.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(resumed.url().query(), Some("limit=100&cursor=next-token"));
    let terminal = kernel
        .decode(&resumed, 200, None, &response(family, Vec::new(), None))
        .unwrap();
    assert_eq!(terminal.next_cursor, None);

    let full_cursor = "https://example.ada.support/api/v2/platform-integrations/?cursor=page-2";
    assert!(kernel.plan(Some(full_cursor)).is_ok());
}

#[test]
fn duplicates_statuses_bounds_tenant_and_secret_material_fail_closed() {
    let family = AdaSupportFamily::EndUsers;
    let kernel = kernel("tenant", family);
    let request = kernel.plan(None).unwrap();
    let raw = provider_raw(family);
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
    conflict["external_id"] = Value::String("different".to_owned());
    assert_eq!(
        kernel.decode(
            &request,
            200,
            None,
            &response(family, vec![raw, conflict], None)
        ),
        Err(AdaSupportError::ConflictingDuplicate)
    );
    for (status, expected) in [
        (401, AdaSupportError::AuthenticationRejected),
        (403, AdaSupportError::RequiredScopeMissing),
        (404, AdaSupportError::ProviderResourceNotFound),
        (
            429,
            AdaSupportError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, AdaSupportError::ProviderUnavailable { status: 503 }),
        (418, AdaSupportError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode(&request, status, Some(60), b"{}"),
            Err(expected)
        );
    }
    assert_eq!(
        kernel.decode(&request, 429, Some(3_601), b"{}"),
        Err(AdaSupportError::InvalidRetryAfter)
    );
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, 200, None, &oversized),
        Err(AdaSupportError::ResponseTooLarge)
    );
    for (field, expected) in [
        ("tenant_id", AdaSupportError::TenantMismatch),
        ("token", AdaSupportError::CredentialMaterial),
        ("authorization", AdaSupportError::CredentialMaterial),
        ("private_key", AdaSupportError::CredentialMaterial),
    ] {
        let mut raw = provider_raw(family);
        raw[field] = Value::String("sentinel-secret-value".to_owned());
        let error = kernel
            .decode(&request, 200, None, &response(family, vec![raw], None))
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }
}

#[test]
fn identity_is_deterministic_and_tenant_and_origin_scoped() {
    let family = AdaSupportFamily::KnowledgeArticles;
    let body = response(family, vec![provider_raw(family)], None);
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
    let other_origin = AdaSupportKernel::new(
        "https://other.ada.support/api",
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
        first.records[0].event_id,
        other_origin_page.records[0].event_id
    );
}
