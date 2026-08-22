use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog, UnsupportedReasonCode};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const OBSERVED_AT: &str = "2026-07-18T08:18:36Z";

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

fn kernel(tenant: &str) -> DockerHubKernel {
    DockerHubKernel::new("https://hub.docker.com", tenant, "library", "ubuntu").unwrap()
}

fn provider_fixture() -> Vec<u8> {
    fs::read(
        repository_root()
            .join("sources/docker_hub/testdata/api/repositories/ubuntu_repository/response.json"),
    )
    .unwrap()
}

fn go_event_fixture() -> GoOracleEvent {
    let bytes =
        fs::read(repository_root().join("sources/docker_hub/testdata/read_repositories.json"))
            .unwrap();
    serde_json::from_slice::<Vec<GoOracleEvent>>(&bytes)
        .unwrap()
        .pop()
        .unwrap()
}

#[test]
fn catalog_closes_only_the_provider_verified_repository_family() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .unwrap();
    let source = catalog.get("docker_hub").unwrap();
    assert_eq!(source.authority(), CollectionAuthority::ShadowOnly);
    let repository = source
        .families()
        .iter()
        .find(|family| family.id() == "repositories")
        .unwrap();
    assert!(!repository.is_authoritative());
    assert!(!repository.is_projection_authoritative());
    assert!(
        repository
            .unsupported_reasons()
            .contains(&UnsupportedReasonCode::MissingProviderProof)
    );
    assert!(
        !repository
            .unsupported_reasons()
            .contains(&UnsupportedReasonCode::UnboundPathConfigParameter)
    );
    assert_eq!(
        repository.path_parameters()["namespace"].field(),
        "namespace"
    );
    assert_eq!(
        repository.path_parameters()["repository"].field(),
        "repository"
    );

    for compatibility_family in ["users", "audit_events"] {
        let family = source
            .families()
            .iter()
            .find(|family| family.id() == compatibility_family)
            .unwrap();
        assert!(!family.is_authoritative());
        assert!(
            family
                .unsupported_reasons()
                .contains(&UnsupportedReasonCode::MissingProviderProof)
        );
    }

    let runtime = DockerHubRuntimeDefinition::compile(DockerHubFamily::Repositories).unwrap();
    assert_eq!(runtime.source_id, "docker_hub");
    assert!(runtime.pull);
    assert_eq!(runtime.event_contract.kind, "docker_hub.repositories");
    assert_eq!(runtime.event_contract.required_payload_fields, &["name"]);
}

#[test]
fn request_is_origin_restricted_terminal_and_credential_free() {
    let kernel = kernel("tenant");
    let request = kernel.plan(None).unwrap();
    assert_eq!(request.method(), "GET");
    assert_eq!(
        request.url().as_str(),
        "https://hub.docker.com/v2/namespaces/library/repositories/ubuntu"
    );
    assert_eq!(request.authorization_header(), "Authorization");
    assert_eq!(request.authorization_scheme(), "Bearer");
    assert!(!request.credential_reference_required());
    assert!(!request.contains_credentials());
    assert!(!request.allows_redirects());
    assert_eq!(request.max_response_bytes(), 1024 * 1024);
    assert_eq!(request.required_scope(), "repository read access");
    assert!(!DockerHubKernel::requires_credentials());
    assert_eq!(
        kernel.plan(Some("next")),
        Err(DockerHubError::InvalidCursor)
    );

    let debug = format!("{kernel:?}{request:?}");
    for secret in ["sentinel-token-value", "Bearer sentinel", "credential:"] {
        assert!(!debug.contains(secret));
    }
}

#[test]
fn origin_and_public_scope_fail_closed() {
    for origin in [
        "http://hub.docker.com",
        "https://localhost",
        "https://127.0.0.1",
        "https://user@hub.docker.com",
        "https://hub.docker.com:8443",
        "https://hub.docker.com/other-api",
        "https://hub.docker.com?token=value",
    ] {
        assert!(DockerHubKernel::new(origin, "tenant", "library", "ubuntu").is_err());
    }
    assert_eq!(
        DockerHubKernel::new("https://hub.docker.com", "tenant", "../library", "ubuntu")
            .unwrap_err(),
        DockerHubError::MissingConfiguration("namespace")
    );
    assert_eq!(
        DockerHubKernel::new("https://hub.docker.com", "tenant", "library", "a/b").unwrap_err(),
        DockerHubError::MissingConfiguration("repository")
    );
}

#[test]
fn captured_provider_response_matches_the_existing_go_oracle_semantically() {
    let kernel = kernel("tenant");
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode_http(&request, 200, None, &provider_fixture(), OBSERVED_AT)
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.next_cursor, None);
    let record = &page.records[0];
    let oracle = go_event_fixture();

    assert_eq!(record.tenant_id, oracle.tenant_id);
    assert_eq!(oracle.source_id, "docker_hub");
    assert_eq!(record.kind, oracle.kind);
    assert_eq!(record.schema_ref, oracle.schema_ref);
    assert_eq!(record.occurred_at, oracle.occurred_at);
    assert_eq!(record.payload, oracle.payload);
    assert_eq!(record.attributes, oracle.attributes);
    assert_eq!(record.provider_id, "library/ubuntu");
    assert_eq!(
        record.event_id,
        "docker_hub-tenant-e4f4db18300a-repositories-library-ubuntu"
    );

    // The checked Go fixture intentionally replaces the live event ID with a
    // content address over Go's exact payload bytes so loopback replay is
    // stable. Keep that oracle identity explicit while production identity is
    // provider-object-stable above.
    assert_eq!(oracle.id, "docker_hub-tenant-repositories-37642678684e8b22");

    let checkpoint = kernel.checkpoint_candidate(&page).unwrap();
    assert_eq!(checkpoint.tenant_id, "tenant");
    assert_eq!(checkpoint.family, DockerHubFamily::Repositories);
    assert_eq!(checkpoint.cursor, None);
    assert_eq!(checkpoint.watermark, "2026-07-16T22:04:47Z");

    let projection = project_docker_hub_records(&page.records);
    assert_eq!(projection.entities.len(), 1);
    assert_eq!(
        projection.entities[0],
        DockerHubEntityFact {
            urn: "urn:cerebro:tenant:docker_hub_repositories:library%2Fubuntu".to_owned(),
            entity_type: "runtime.container.repository".to_owned(),
            label: "ubuntu".to_owned(),
        }
    );
}

#[test]
fn go_fixture_parity_corpus_contains_all_repository_operations() {
    let bytes = fs::read(
        repository_root().join("crates/source-runtime-next/testdata/go_fixture_oracle.json"),
    )
    .unwrap();
    let oracle: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(oracle["schema_version"], "cerebro.source-fixture-parity.v2");
    let cases = oracle["cases"].as_array().unwrap();
    let docker_cases = cases
        .iter()
        .filter(|case| {
            case["source_id"] == "docker_hub"
                && case["family_id"] == "repositories"
                && case["case_id"] == "ubuntu_repository"
        })
        .collect::<Vec<_>>();
    assert_eq!(docker_cases.len(), 3);
    assert_eq!(
        docker_cases
            .iter()
            .map(|case| case["operation"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["check", "discover", "read-page"]
    );
    assert!(docker_cases.iter().all(|case| {
        case["payload_sha256"] == "a5300b497f4d172c91d24eb7d5946ca253e92377591cbe164ce69db9c3c7d8c5"
            && case["provider_network_egress"] == false
            && case["offline_proof"] == "fixture_only_no_provider_network"
    }));
}

#[test]
fn typed_provider_statuses_remain_distinct_and_bounded() {
    let kernel = kernel("tenant");
    let request = kernel.plan(None).unwrap();
    let body = b"{}";
    for (status, expected) in [
        (401, DockerHubError::AuthenticationRejected),
        (403, DockerHubError::RequiredScopeMissing),
        (404, DockerHubError::ProviderResourceNotFound),
        (
            429,
            DockerHubError::RateLimited {
                retry_after_seconds: Some(60),
            },
        ),
        (503, DockerHubError::ProviderUnavailable { status: 503 }),
        (418, DockerHubError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode_http(&request, status, Some(60), body, OBSERVED_AT),
            Err(expected)
        );
    }
    assert_eq!(
        kernel.decode_http(&request, 429, Some(3_601), body, OBSERVED_AT),
        Err(DockerHubError::InvalidRetryAfter)
    );
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode_http(&request, 200, None, &oversized, OBSERVED_AT),
        Err(DockerHubError::ResponseTooLarge)
    );
}

#[test]
fn provider_scope_tenant_and_secret_material_cannot_cross_the_kernel() {
    let kernel = kernel("tenant");
    let request = kernel.plan(None).unwrap();
    for (field, expected) in [
        ("tenant_id", DockerHubError::TenantMismatch),
        ("access_token", DockerHubError::CredentialMaterial),
        ("authorization", DockerHubError::CredentialMaterial),
        ("private_key", DockerHubError::CredentialMaterial),
    ] {
        let body = serde_json::to_vec(&json!({
            "namespace": "library",
            "name": "ubuntu",
            (field): "sentinel-secret-value",
            "last_updated": "2026-07-16T22:04:47Z"
        }))
        .unwrap();
        let error = kernel
            .decode_http(&request, 200, None, &body, OBSERVED_AT)
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("sentinel-secret-value"));
        assert!(!format!("{error:?}").contains("sentinel-secret-value"));
    }

    let wrong_scope = serde_json::to_vec(&json!({
        "namespace": "library",
        "name": "debian",
        "last_updated": "2026-07-16T22:04:47Z"
    }))
    .unwrap();
    assert_eq!(
        kernel.decode_http(&request, 200, None, &wrong_scope, OBSERVED_AT),
        Err(DockerHubError::ProviderIdentityMismatch)
    );
}

#[test]
fn identity_is_deterministic_and_tenant_scoped() {
    let fixture = provider_fixture();
    let first_kernel = kernel("tenant-a");
    let first_request = first_kernel.plan(None).unwrap();
    let first = first_kernel
        .decode_http(&first_request, 200, None, &fixture, OBSERVED_AT)
        .unwrap();
    let replay = first_kernel
        .decode_http(&first_request, 200, None, &fixture, OBSERVED_AT)
        .unwrap();
    assert_eq!(first, replay);

    let other_kernel = kernel("tenant-b");
    let other_request = other_kernel.plan(None).unwrap();
    let other = other_kernel
        .decode_http(&other_request, 200, None, &fixture, OBSERVED_AT)
        .unwrap();
    assert_eq!(first.records[0].provider_id, other.records[0].provider_id);
    assert_ne!(first.records[0].event_id, other.records[0].event_id);
    assert_ne!(
        first.records[0].attributes["resource_urn"],
        other.records[0].attributes["resource_urn"]
    );
}

#[test]
fn errors_expose_operator_actions_without_provider_content() {
    assert_eq!(
        DockerHubError::AuthenticationRejected.operator_action(),
        "repair credential binding"
    );
    assert_eq!(
        DockerHubError::RequiredScopeMissing.operator_action(),
        "grant repository read scope"
    );
    assert_eq!(
        DockerHubError::RateLimited {
            retry_after_seconds: Some(30)
        }
        .operator_action(),
        "retry the collection later"
    );
    assert_eq!(
        DockerHubError::InvalidCursor.operator_action(),
        "restart from the last committed checkpoint"
    );
}
