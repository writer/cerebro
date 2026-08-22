use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::*;

const CATALOG: &[u8] = include_bytes!("../../../../sources/asana/catalog.yaml");
const USERS_ORACLE: &[u8] = include_bytes!("../../../../sources/asana/testdata/read_users.json");
const PROJECTS_ORACLE: &[u8] =
    include_bytes!("../../../../sources/asana/testdata/read_projects.json");
const AUDIT_ORACLE: &[u8] =
    include_bytes!("../../../../sources/asana/testdata/read_audit_events.json");

#[derive(serde::Deserialize)]
struct CatalogWire {
    runtime_families: Vec<String>,
    event_contracts: Vec<EventContractWire>,
}

#[derive(serde::Deserialize)]
struct EventContractWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

fn kernel(tenant: &str, family: AsanaFamily) -> AsanaKernel {
    AsanaKernel::new(
        "https://app.asana.com/api/1.0",
        tenant,
        "workspace-1",
        family,
        Some(100),
    )
    .expect("valid Asana kernel")
}

#[test]
fn closed_runtime_definition_matches_catalog_exactly() {
    let catalog: CatalogWire = serde_saphyr::from_slice(CATALOG).expect("Asana catalog YAML");
    assert_eq!(
        catalog.runtime_families,
        ["users", "projects", "audit_events"]
    );
    let definitions = AsanaFamily::ALL
        .into_iter()
        .map(|family| AsanaRuntimeDefinition::compile(family).expect("compiled family"))
        .collect::<Vec<_>>();
    assert!(definitions.iter().all(|definition| definition.pull));
    assert_eq!(catalog.event_contracts.len(), definitions.len());
    for expected in catalog.event_contracts {
        let actual = definitions
            .iter()
            .map(|definition| definition.event_contract)
            .find(|contract| contract.kind == expected.kind)
            .expect("catalog contract compiled");
        assert_eq!(actual.schema_ref, expected.schema_ref);
        assert!(
            actual
                .required_attributes
                .iter()
                .copied()
                .eq(expected.required_attributes.iter().map(String::as_str))
        );
        assert!(
            actual
                .required_payload_fields
                .iter()
                .copied()
                .eq(expected.required_payload_fields.iter().map(String::as_str))
        );
    }
    assert_eq!(
        "tasks".parse::<AsanaFamily>(),
        Err(AsanaError::InvalidFamily)
    );
}

#[test]
fn plans_all_families_without_credentials_or_redirects() {
    for (family, path) in [
        (AsanaFamily::Users, "/api/1.0/users"),
        (AsanaFamily::Projects, "/api/1.0/projects"),
        (
            AsanaFamily::AuditEvents,
            "/api/1.0/workspaces/workspace-1/audit_log_events",
        ),
    ] {
        let request = kernel("tenant-a", family).plan(None).expect("request");
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().path(), path);
        assert_eq!(
            request
                .url()
                .query_pairs()
                .find(|(key, _)| key == "limit")
                .map(|(_, value)| value.into_owned()),
            Some("100".to_owned())
        );
        assert_eq!(request.authorization_header(), "Authorization");
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), 4 * 1024 * 1024);
        let debug = format!("{request:?}").to_ascii_lowercase();
        for forbidden in ["test-token", "access_token", "client_secret", "private_key"] {
            assert!(!debug.contains(forbidden));
        }
    }
    assert!(!AsanaKernel::requires_credentials());
}

#[test]
fn provider_fixtures_match_go_oracles_and_projection_facts() {
    let users = kernel("tenant", AsanaFamily::Users)
        .decode(
            &kernel("tenant", AsanaFamily::Users).plan(None).unwrap(),
            &serde_json::to_vec(&json!({"data": [{
                "id": "user-1", "gid": "user-1", "name": "User One",
                "email": "user@example.test",
                "created_at": "2026-05-01T00:00:00Z", "enabled": true
            }]}))
            .unwrap(),
            "2026-06-01T00:00:00Z",
        )
        .expect("users fixture");
    assert_oracle(&users.records, USERS_ORACLE);

    let projects_kernel = kernel("tenant", AsanaFamily::Projects);
    let projects = projects_kernel
        .decode(
            &projects_kernel.plan(None).unwrap(),
            &serde_json::to_vec(&json!({"data": [{
                "id": "project-1", "gid": "project-1", "name": "Security Evidence",
                "archived": false, "created_at": "2026-05-15T00:00:00Z",
                "modified_at": "2026-06-01T00:00:00Z",
                "evidence_cas": {"digest": "sha256:test", "uri": "cas://cases/asana-project-project-1"}
            }]})).unwrap(),
            "2026-06-01T00:00:00Z",
        )
        .expect("projects fixture");
    assert_oracle(&projects.records, PROJECTS_ORACLE);

    let audit_kernel = kernel("tenant", AsanaFamily::AuditEvents);
    let audit = audit_kernel
        .decode(
            &audit_kernel.plan(None).unwrap(),
            &serde_json::to_vec(&json!({"data": [{
                "id": "audit-1", "gid": "audit-1", "created_at": "2026-06-01T00:00:00Z",
                "event_type": "project.created",
                "actor": {"id": "legacy-user-1", "gid": "user-1", "email": "user@example.test", "name": "User One"},
                "resource": {"id": "legacy-project-1", "gid": "project-1", "type": "legacy_project", "resource_type": "project", "name": "Security Evidence"},
                "target_name": "Target Fallback"
            }]})).unwrap(),
            "2026-06-01T00:00:00Z",
        )
        .expect("audit fixture");
    assert_oracle(&audit.records, AUDIT_ORACLE);

    let projection = project_asana_records(&[
        users.records[0].clone(),
        projects.records[0].clone(),
        audit.records[0].clone(),
    ]);
    assert!(projection.entities.iter().any(|entity| entity.urn
        == "urn:cerebro:tenant:runtime_users:user-1"
        && entity.entity_type == "identity_user"));
    assert!(projection.entities.iter().any(|entity| entity.urn
        == "urn:cerebro:tenant:runtime_projects:project-1"
        && entity.entity_type == "project"));
    assert!(
        projection.relations.is_empty(),
        "audit oracle intentionally has no trusted resource_urn"
    );
}

#[test]
fn cursor_checkpoint_and_restart_are_round_trippable() {
    let kernel = kernel("tenant-a", AsanaFamily::Projects);
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            br#"{"data":[{"gid":"project-1","name":"Evidence","modified_at":"2026-08-22T00:00:00Z"}],"next_page":{"offset":"cursor-2"}}"#,
            "2026-08-22T00:00:00Z",
        )
        .unwrap();
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-08-21T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("cursor-2"));
    assert_eq!(
        checkpoint.watermark.as_deref(),
        Some("2026-08-22T00:00:00Z")
    );
    let resumed = kernel.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(
        resumed
            .url()
            .query_pairs()
            .find(|(key, _)| key == "offset")
            .map(|(_, value)| value.into_owned()),
        Some("cursor-2".to_owned())
    );
    assert_eq!(
        kernel.decode(
            &resumed,
            br#"{"data":[],"next_page":{"offset":"cursor-2"}}"#,
            "2026-08-22T00:00:00Z"
        ),
        Err(AsanaError::InvalidCursor)
    );
}

#[test]
fn rejects_secret_tenant_duplicate_origin_and_provider_failures() {
    assert!(matches!(
        AsanaKernel::new(
            "http://app.asana.com",
            "tenant",
            "workspace",
            AsanaFamily::Users,
            None
        ),
        Err(AsanaError::InvalidBaseUrl)
    ));
    assert!(matches!(
        AsanaKernel::new(
            "https://127.0.0.1",
            "tenant",
            "workspace",
            AsanaFamily::Users,
            None
        ),
        Err(AsanaError::UnsafeOrigin)
    ));
    let tenant_kernel = kernel("tenant", AsanaFamily::Users);
    let request = tenant_kernel.plan(None).unwrap();
    for body in [
        br#"{"data":[{"gid":"user-1","tenant_id":"attacker"}]}"#.as_slice(),
        br#"{"data":[{"gid":"user-1","profile":{"access_token":"secret-sentinel"}}]}"#.as_slice(),
    ] {
        assert!(matches!(
            tenant_kernel.decode(&request, body, "2026-08-22T00:00:00Z"),
            Err(AsanaError::TenantMismatch | AsanaError::CredentialMaterial)
        ));
    }
    assert_eq!(
        tenant_kernel.decode(
            &request,
            br#"{"data":[{"gid":"user-1","name":"One"},{"gid":"user-1","name":"Two"}]}"#,
            "2026-08-22T00:00:00Z"
        ),
        Err(AsanaError::ConflictingDuplicate)
    );
    let other = kernel("tenant-b", AsanaFamily::Users)
        .decode(
            &kernel("tenant-b", AsanaFamily::Users).plan(None).unwrap(),
            br#"{"data":[{"gid":"user-1","name":"One"}]}"#,
            "2026-08-22T00:00:00Z",
        )
        .unwrap();
    let first = tenant_kernel
        .decode(
            &request,
            br#"{"data":[{"gid":"user-1","name":"One"}]}"#,
            "2026-08-22T00:00:00Z",
        )
        .unwrap();
    assert_ne!(first.records[0].event_id, other.records[0].event_id);
    assert_eq!(
        first.records[0].attributes["resource_urn"],
        "urn:cerebro:tenant:runtime_users:user-1"
    );
    assert_eq!(
        tenant_kernel.decode_http(&request, 401, None, b"", "2026-08-22T00:00:00Z"),
        Err(AsanaError::AuthenticationRejected)
    );
    assert_eq!(
        tenant_kernel.decode_http(&request, 403, None, b"", "2026-08-22T00:00:00Z"),
        Err(AsanaError::RequiredScopeMissing)
    );
    assert_eq!(
        tenant_kernel.decode_http(&request, 429, Some(30), b"", "2026-08-22T00:00:00Z"),
        Err(AsanaError::RateLimited {
            retry_after_seconds: Some(30)
        })
    );
    assert_eq!(
        tenant_kernel.decode_http(&request, 503, None, b"", "2026-08-22T00:00:00Z"),
        Err(AsanaError::ProviderUnavailable { status: 503 })
    );
    let diagnostics = format!(
        "{:?}",
        tenant_kernel.decode(
            &request,
            br#"{"data":[{"gid":"user-1","password":"secret-sentinel"}]}"#,
            "2026-08-22T00:00:00Z"
        )
    );
    assert!(!diagnostics.contains("secret-sentinel"));
}

fn assert_oracle(records: &[AsanaRecord], oracle: &[u8]) {
    let oracle: Vec<Value> = serde_json::from_slice(oracle).expect("Go oracle JSON");
    assert_eq!(records.len(), oracle.len());
    for (record, expected) in records.iter().zip(oracle) {
        assert_eq!(record.tenant_id, expected["tenant_id"]);
        assert_eq!(record.kind, expected["kind"]);
        assert_eq!(record.schema_ref, expected["schema_ref"]);
        assert_eq!(record.occurred_at, expected["occurred_at"]);
        assert_eq!(record.attributes, attributes(&expected["attributes"]));
        assert_eq!(record.payload, expected["payload"]);
    }
}

fn attributes(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .expect("oracle attributes")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value.as_str().expect("string attribute").to_owned(),
            )
        })
        .collect()
}
