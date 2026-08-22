use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use super::*;

const ORIGIN: &str = "https://api.tailscale.com/api/v2";
const OBSERVED_AT: &str = "2026-06-01T00:00:00Z";
const CATALOG: &[u8] = include_bytes!("../../../../sources/tailscale/catalog.yaml");

#[derive(Deserialize)]
struct CatalogWire {
    runtime_families: Vec<String>,
    provider_api: ProviderApiWire,
    event_contracts: Vec<EventContractWire>,
}

#[derive(Deserialize)]
struct ProviderApiWire {
    auth: String,
    base_url: String,
    families: Vec<ProviderFamilyWire>,
}

#[derive(Deserialize)]
struct ProviderFamilyWire {
    id: String,
    method: String,
    path: String,
}

#[derive(Deserialize)]
struct ConnectorCatalogWire {
    entries: Vec<ConnectorEntryWire>,
}

#[derive(Deserialize)]
struct ConnectorEntryWire {
    definition: ConnectorDefinitionWire,
}

#[derive(Deserialize)]
struct ConnectorDefinitionWire {
    source_id: String,
    resource_families: Vec<ConnectorFamilyWire>,
}

#[derive(Deserialize)]
struct ConnectorFamilyWire {
    id: String,
    method: String,
    path: String,
}

#[derive(Deserialize)]
struct EventContractWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

fn kernel(family: TailscaleFamily, page_size: usize) -> TailscaleKernel {
    TailscaleKernel::new(
        ORIGIN,
        "tenant",
        "writer.com",
        family,
        Some(page_size),
        OBSERVED_AT,
    )
    .expect("valid kernel")
}

#[test]
fn closed_runtime_definition_matches_provider_catalog_exactly() {
    let catalog: CatalogWire = serde_saphyr::from_slice(CATALOG).expect("Tailscale catalog YAML");
    let runtime = TailscaleFamily::ALL
        .into_iter()
        .map(|family| TailscaleRuntimeDefinition::compile(family).expect("compiled family"))
        .collect::<Vec<_>>();
    let expected_families = catalog
        .runtime_families
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        runtime
            .iter()
            .map(|definition| definition.family.as_str().to_owned())
            .collect::<BTreeSet<_>>(),
        expected_families
    );
    assert_eq!(catalog.provider_api.auth, "bearer_token");
    assert_eq!(catalog.provider_api.base_url, ORIGIN);
    for definition in runtime {
        let provider = catalog
            .provider_api
            .families
            .iter()
            .find(|family| family.id == definition.family.as_str())
            .expect("provider family");
        assert_eq!(provider.method, definition.method);
        assert_eq!(provider.path.replace("{tailnet}", "-"), definition.path);
        let contract = catalog
            .event_contracts
            .iter()
            .find(|contract| contract.kind == definition.contract.kind)
            .expect("event contract");
        assert_eq!(contract.schema_ref, definition.contract.schema_ref);
        assert_eq!(
            contract.required_attributes,
            definition.contract.required_attributes
        );
        assert_eq!(
            contract.required_payload_fields,
            definition.contract.required_payload_fields
        );
    }
}

#[test]
fn provider_proof_covers_every_public_connector_family() {
    let catalog: CatalogWire = serde_saphyr::from_slice(CATALOG).expect("Tailscale catalog YAML");
    let connector: ConnectorCatalogWire = serde_saphyr::from_slice(include_bytes!(
        "../../../../internal/connectorcatalog/catalog/identity-access-secrets/tailscale.yaml"
    ))
    .expect("Tailscale connector YAML");
    let definition = connector
        .entries
        .into_iter()
        .find(|entry| entry.definition.source_id == "tailscale")
        .expect("Tailscale connector definition")
        .definition;
    let proved = catalog
        .provider_api
        .families
        .iter()
        .map(|family| {
            (
                family.id.as_str(),
                family.method.as_str(),
                family.path.replace("{tailnet}", "${config.tailnet}"),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        definition
            .resource_families
            .iter()
            .map(|family| family.id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["configuration", "device", "integration", "user"])
    );
    for family in definition.resource_families {
        assert!(
            proved.contains(&(family.id.as_str(), family.method.as_str(), family.path)),
            "missing provider proof for {}",
            family.id
        );
    }
}

#[test]
fn plans_all_families_without_credentials_or_redirects() {
    for family in TailscaleFamily::ALL {
        let request = kernel(family, 100).plan(None).expect("request");
        assert_eq!(request.method(), "GET");
        assert_eq!(request.family(), family);
        assert_eq!(
            request.url().origin().ascii_serialization(),
            "https://api.tailscale.com"
        );
        assert_eq!(request.url().path(), format!("/api/v2{}", family.path()));
        assert_eq!(request.authorization_header(), "Authorization");
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert_eq!(request.required_scope(), "Tailscale tailnet read access");
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), 4 * 1024 * 1024);
        let debug = format!("{request:?}");
        assert!(!debug.contains("test-token-secret"));
        assert!(!debug.contains("credential_reference"));
    }
    assert!(!TailscaleKernel::requires_credentials());
}

#[test]
fn checked_in_provider_fixtures_match_go_oracle_semantics() {
    for family in TailscaleFamily::ALL {
        let fixture = fixture(family);
        let oracle = oracle(family);
        let request = kernel(family, 100).plan(None).unwrap();
        let page = kernel(family, 100)
            .decode_http(
                &request,
                200,
                &TailscaleResponseMetadata::default(),
                fixture.as_bytes(),
            )
            .unwrap();
        assert_eq!(page.records.len(), oracle.len(), "{family}");
        for (record, expected) in page.records.iter().zip(oracle) {
            assert_eq!(record.kind, expected["kind"]);
            assert_eq!(record.schema_ref, expected["schema_ref"]);
            assert_eq!(record.tenant_id, expected["tenant_id"]);
            assert_eq!(record.payload, expected["payload"]);
            assert_eq!(record.occurred_at, expected["occurred_at"]);
            let mut expected_attributes = expected["attributes"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value.as_str().expect("string fixture attribute").to_owned(),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            expected_attributes.insert("provider".to_owned(), "tailscale".to_owned());
            expected_attributes.insert("source_provider".to_owned(), "tailscale".to_owned());
            if matches!(family, TailscaleFamily::Group | TailscaleFamily::Tag) {
                // ACL map keys are the only live provider name available. The
                // checked fixtures retain editorial labels for UI presentation.
                expected_attributes.insert(
                    "resource_name".to_owned(),
                    expected_attributes["external_id"].clone(),
                );
            }
            assert_eq!(record.attributes, expected_attributes, "{family}");
            assert_eq!(record.event_id, go_oracle_event_id(family), "{family}");
        }
    }
}

#[test]
fn cursor_checkpoint_and_restart_are_bounded_and_round_trippable() {
    let kernel = kernel(TailscaleFamily::User, 2);
    let first_request = kernel.plan(None).unwrap();
    let first = kernel
        .decode_http(
            &first_request,
            200,
            &TailscaleResponseMetadata {
                next_cursor: Some("page-2".to_owned()),
                retry_after_seconds: None,
            },
            br#"{"users":[{"id":"user-1","loginName":"a@example.test"}]}"#,
        )
        .unwrap();
    assert_eq!(first.next_cursor.as_deref(), Some("page-2"));
    let checkpoint = kernel
        .checkpoint_candidate(&first_request, &first, None)
        .unwrap();
    assert_eq!(checkpoint.cursor.as_deref(), Some("page-2"));
    assert_eq!(checkpoint.watermark.as_deref(), Some(OBSERVED_AT));
    let resumed = kernel.plan(checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(resumed.cursor(), Some("page-2"));
    assert_eq!(
        resumed
            .url()
            .query_pairs()
            .find(|(key, _)| key == "cursor")
            .map(|(_, value)| value.into_owned()),
        Some("page-2".to_owned())
    );
    assert_eq!(
        kernel.decode_http(
            &resumed,
            200,
            &TailscaleResponseMetadata {
                next_cursor: Some("page-2".to_owned()),
                retry_after_seconds: None,
            },
            br#"{"users":[]}"#,
        ),
        Err(TailscaleError::InvalidCursor)
    );

    let terminal = kernel
        .decode_http(
            &resumed,
            200,
            &TailscaleResponseMetadata::default(),
            br#"{"users":[{"id":"user-2","loginName":"b@example.test","created":"2026-06-02T00:00:00Z"}]}"#,
        )
        .unwrap();
    let terminal_checkpoint = kernel
        .checkpoint_candidate(&resumed, &terminal, Some("2026-06-01T12:00:00Z"))
        .unwrap();
    assert_eq!(terminal_checkpoint.cursor.as_deref(), Some("user-2"));
    assert_eq!(
        terminal_checkpoint.watermark.as_deref(),
        Some("2026-06-02T00:00:00Z")
    );
    let restarted = kernel.plan(terminal_checkpoint.cursor.as_deref()).unwrap();
    assert_eq!(restarted.cursor(), Some("user-2"));
}

#[test]
fn rejects_secret_tenant_duplicate_origin_cursor_and_provider_failures() {
    assert!(matches!(
        TailscaleKernel::new(
            "https://127.0.0.1/api/v2",
            "tenant",
            "writer.com",
            TailscaleFamily::User,
            None,
            OBSERVED_AT,
        ),
        Err(TailscaleError::InvalidBaseUrl)
    ));
    let kernel = kernel(TailscaleFamily::User, 100);
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode_http(
            &request,
            200,
            &TailscaleResponseMetadata::default(),
            br#"{"users":[{"id":"user-1","loginName":"a@example.test","tenant_id":"attacker"}]}"#,
        ),
        Err(TailscaleError::TenantMismatch)
    );
    assert_eq!(
        kernel.decode_http(
            &request,
            200,
            &TailscaleResponseMetadata::default(),
            br#"{"users":[{"id":"user-1","loginName":"a@example.test","access_token":"secret-sentinel"}]}"#,
        ),
        Err(TailscaleError::CredentialMaterial)
    );
    assert_eq!(
        kernel.decode_http(
            &request,
            200,
            &TailscaleResponseMetadata::default(),
            br#"{"users":[{"id":"user-1","loginName":"a@example.test"},{"id":"user-1","loginName":"b@example.test"}]}"#,
        ),
        Err(TailscaleError::ConflictingDuplicate)
    );
    assert_eq!(
        kernel.plan(Some("https://evil.example/page")),
        Err(TailscaleError::InvalidCursor)
    );
    assert_eq!(
        kernel.decode_http(
            &request,
            401,
            &TailscaleResponseMetadata::default(),
            b"secret response body",
        ),
        Err(TailscaleError::AuthenticationRejected)
    );
    assert_eq!(
        kernel.decode_http(
            &request,
            403,
            &TailscaleResponseMetadata::default(),
            b"scope body",
        ),
        Err(TailscaleError::RequiredScopeMissing)
    );
    assert_eq!(
        kernel.decode_http(
            &request,
            429,
            &TailscaleResponseMetadata {
                next_cursor: None,
                retry_after_seconds: Some(30),
            },
            b"rate body",
        ),
        Err(TailscaleError::RateLimited {
            retry_after_seconds: Some(30)
        })
    );
    for error in [
        TailscaleError::CredentialUnavailable,
        TailscaleError::DnsFailure,
        TailscaleError::ConnectionFailure,
        TailscaleError::ProviderTimeout,
        TailscaleError::AppendFailure,
        TailscaleError::ProjectionFailure,
        TailscaleError::LeaseLoss,
        TailscaleError::StaleAuthority,
    ] {
        let diagnostic = format!("{error}: {}", error.operator_action());
        assert!(!diagnostic.contains("secret-sentinel"));
        assert!(!diagnostic.contains("response body"));
    }
}

#[test]
fn projection_preserves_network_identity_and_acl_semantics() {
    let mut records = Vec::new();
    for family in TailscaleFamily::ALL {
        let request = kernel(family, 100).plan(None).unwrap();
        let page = kernel(family, 100)
            .decode_http(
                &request,
                200,
                &TailscaleResponseMetadata::default(),
                fixture(family).as_bytes(),
            )
            .unwrap();
        records.extend(page.records);
    }
    let facts = project_tailscale_records(&records).unwrap();
    let entities = facts
        .entities
        .iter()
        .map(|entity| entity.urn.as_str())
        .collect::<BTreeSet<_>>();
    for expected in [
        "urn:cerebro:tenant:tailscale_user:user-1",
        "urn:cerebro:tenant:tailscale_device:device-1",
        "urn:cerebro:tenant:tailscale_group:group:eng",
        "urn:cerebro:tenant:tailscale_tag:tag:prod",
        "urn:cerebro:tenant:tailscale_service:svc:api",
        "urn:cerebro:tenant:tailscale_grant:grant-1",
    ] {
        assert!(entities.contains(expected), "missing {expected}");
    }
    let relations = facts
        .relations
        .iter()
        .map(|relation| {
            (
                relation.from.as_str(),
                relation.relation.as_str(),
                relation.to.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    for expected in [
        (
            "urn:cerebro:tenant:tailscale_device:device-1",
            "owned_by",
            "urn:cerebro:tenant:tailscale_user:alice@writer.com",
        ),
        (
            "urn:cerebro:tenant:tailscale_group:group:eng",
            "contains",
            "urn:cerebro:tenant:tailscale_user:alice@writer.com",
        ),
        (
            "urn:cerebro:tenant:tailscale_tag:tag:prod",
            "owned_by",
            "urn:cerebro:tenant:tailscale_group:group:eng",
        ),
        (
            "urn:cerebro:tenant:tailscale_grant:grant-1",
            "can_reach",
            "urn:cerebro:tenant:tailscale_destination:tag:prod:443",
        ),
    ] {
        assert!(relations.contains(&expected), "missing {expected:?}");
    }
}

fn fixture(family: TailscaleFamily) -> String {
    let oracle = oracle(family);
    let payloads = oracle
        .iter()
        .map(|event| event["payload"].clone())
        .collect::<Vec<_>>();
    let value = match family {
        TailscaleFamily::Tailnet => payloads[0].clone(),
        TailscaleFamily::User => serde_json::json!({"users": payloads}),
        TailscaleFamily::Device => serde_json::json!({"devices": payloads}),
        TailscaleFamily::Service => serde_json::json!({"vipServices": payloads}),
        TailscaleFamily::Grant => serde_json::json!({"grants": payloads}),
        TailscaleFamily::Group => serde_json::json!({
            "groups": payloads.into_iter().map(|payload| {
                (payload["id"].as_str().unwrap().to_owned(), payload["members"].clone())
            }).collect::<BTreeMap<_, _>>()
        }),
        TailscaleFamily::Tag => serde_json::json!({
            "tagOwners": payloads.into_iter().map(|payload| {
                (payload["id"].as_str().unwrap().to_owned(), payload["owners"].clone())
            }).collect::<BTreeMap<_, _>>()
        }),
    };
    serde_json::to_string(&value).unwrap()
}

fn oracle(family: TailscaleFamily) -> Vec<Value> {
    let bytes: &[u8] = match family {
        TailscaleFamily::Tailnet => {
            include_bytes!("../../../../sources/tailscale/testdata/read_tailnet.json")
        }
        TailscaleFamily::User => {
            include_bytes!("../../../../sources/tailscale/testdata/read_user.json")
        }
        TailscaleFamily::Device => {
            include_bytes!("../../../../sources/tailscale/testdata/read_device.json")
        }
        TailscaleFamily::Group => {
            include_bytes!("../../../../sources/tailscale/testdata/read_group.json")
        }
        TailscaleFamily::Tag => {
            include_bytes!("../../../../sources/tailscale/testdata/read_tag.json")
        }
        TailscaleFamily::Service => {
            include_bytes!("../../../../sources/tailscale/testdata/read_service.json")
        }
        TailscaleFamily::Grant => {
            include_bytes!("../../../../sources/tailscale/testdata/read_grant.json")
        }
    };
    serde_json::from_slice(bytes).expect("Go fixture oracle")
}

fn go_oracle_event_id(family: TailscaleFamily) -> &'static str {
    match family {
        TailscaleFamily::Tailnet => "tailscale-tenant-fb119763df3d-tailnet-writer.com",
        TailscaleFamily::User => "tailscale-tenant-d997fe6a82ab-user-user-1",
        TailscaleFamily::Device => "tailscale-tenant-4ee73982e195-device-device-1",
        TailscaleFamily::Group => "tailscale-tenant-9980b6ff061b-group-group-eng",
        TailscaleFamily::Tag => "tailscale-tenant-9980b6ff061b-tag-tag-prod",
        TailscaleFamily::Service => "tailscale-tenant-aa65280fbb01-service-svc-api",
        TailscaleFamily::Grant => "tailscale-tenant-9980b6ff061b-grant-grant-1",
    }
}
