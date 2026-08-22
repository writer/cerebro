use std::collections::BTreeMap;

use cerebro_source_catalog::{AuthModel, CollectionAuthority, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;

const CATALOG: &[u8] = include_bytes!("../../../../sources/deepseek/catalog.yaml");
const MODEL_ORACLE: &[u8] =
    include_bytes!("../../../../sources/deepseek/testdata/read_model_catalog.json");
const BALANCE_ORACLE: &[u8] =
    include_bytes!("../../../../sources/deepseek/testdata/read_account_balances.json");
const PROJECTION_ORACLE: &[u8] = include_bytes!("fixtures/projection_oracle.json");
const OBSERVED_AT: &str = "2026-06-01T00:00:00Z";

#[derive(Deserialize)]
struct CatalogWire {
    runtime_families: Vec<String>,
    event_contracts: Vec<EventContractWire>,
}

#[derive(Deserialize)]
struct EventContractWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

#[derive(Deserialize)]
struct ProjectionOracle {
    entities: Vec<ProjectionEntity>,
    relations: Vec<ProjectionRelation>,
}

#[derive(Deserialize)]
struct ProjectionEntity {
    urn: String,
    entity_type: String,
    label: String,
}

#[derive(Deserialize)]
struct ProjectionRelation {
    from_urn: String,
    relation: String,
    to_urn: String,
}

fn kernel(tenant: &str, family: DeepSeekFamily) -> DeepSeekKernel {
    DeepSeekKernel::new("https://api.deepseek.com", tenant, family).expect("valid kernel")
}

#[test]
fn closed_runtime_definition_matches_both_catalogs() {
    let catalog: CatalogWire = serde_saphyr::from_slice(CATALOG).expect("DeepSeek catalog YAML");
    assert_eq!(
        catalog.runtime_families,
        ["account_balances", "model_catalog"]
    );
    let definitions = DeepSeekFamily::ALL
        .into_iter()
        .map(|family| DeepSeekRuntimeDefinition::compile(family).expect("compiled family"))
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

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let compiled = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("compile connector catalog");
    let source = compiled.get("deepseek").expect("compiled DeepSeek source");
    assert_eq!(source.auth(), &AuthModel::BearerToken);
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    assert_eq!(
        source
            .families()
            .iter()
            .map(|family| family.id())
            .collect::<Vec<_>>(),
        ["model_catalog", "account_balances"]
    );
    assert!(
        source
            .families()
            .iter()
            .all(|family| family.is_authoritative())
    );
    assert!(
        source
            .families()
            .iter()
            .all(|family| family.is_projection_authoritative())
    );
    assert_eq!(
        "models".parse::<DeepSeekFamily>(),
        Err(DeepSeekError::InvalidFamily)
    );
}

#[test]
fn plans_bounded_origin_restricted_requests_without_credentials() {
    for family in DeepSeekFamily::ALL {
        let request = kernel("tenant", family).plan(None).expect("request");
        assert_eq!(request.method(), "GET");
        assert_eq!(request.url().scheme(), "https");
        assert_eq!(request.url().host_str(), Some("api.deepseek.com"));
        assert_eq!(request.url().path(), family.path());
        assert_eq!(request.url().query(), None);
        assert_eq!(request.authorization_header(), "Authorization");
        assert_eq!(request.authorization_scheme(), "Bearer");
        assert_eq!(request.accept(), "application/json");
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), 4 * 1024 * 1024);
        let protocol = format!("{request:?}").to_ascii_lowercase();
        for forbidden in ["test-token", "access_token", "client_secret", "private_key"] {
            assert!(!protocol.contains(forbidden));
        }
    }
    assert!(!DeepSeekKernel::requires_credentials());
    assert!(matches!(
        DeepSeekKernel::new(
            "http://api.deepseek.com",
            "tenant",
            DeepSeekFamily::ModelCatalog
        ),
        Err(DeepSeekError::UnsafeOrigin)
    ));
    assert!(matches!(
        DeepSeekKernel::new(
            "https://evil.example",
            "tenant",
            DeepSeekFamily::ModelCatalog
        ),
        Err(DeepSeekError::UnsafeOrigin)
    ));
    assert!(matches!(
        DeepSeekKernel::new(
            "https://api.deepseek.com.evil.example",
            "tenant",
            DeepSeekFamily::ModelCatalog
        ),
        Err(DeepSeekError::UnsafeOrigin)
    ));
}

#[test]
fn provider_fixtures_match_go_oracle_semantics_and_projection() {
    let model = decode_oracle(DeepSeekFamily::ModelCatalog, MODEL_ORACLE);
    let balance = decode_oracle(DeepSeekFamily::AccountBalances, BALANCE_ORACLE);
    let records = vec![balance.clone(), model.clone()];
    let projection = project_deepseek_records(&records);
    let oracle: ProjectionOracle =
        serde_json::from_slice(PROJECTION_ORACLE).expect("projection oracle");
    assert_eq!(
        projection.entities,
        oracle
            .entities
            .into_iter()
            .map(|entity| DeepSeekEntityFact {
                urn: entity.urn,
                entity_type: entity.entity_type,
                label: entity.label,
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        projection.relations,
        oracle
            .relations
            .into_iter()
            .map(|relation| DeepSeekRelationFact {
                from_urn: relation.from_urn,
                relation: relation.relation,
                to_urn: relation.to_urn,
            })
            .collect::<Vec<_>>()
    );
}

#[test]
fn terminal_cursor_checkpoint_and_restart_are_deterministic() {
    let kernel = kernel("tenant-a", DeepSeekFamily::ModelCatalog);
    assert_eq!(
        kernel.plan(Some("cursor")),
        Err(DeepSeekError::InvalidCursor)
    );
    let request = kernel.plan(None).unwrap();
    let body = br#"{"data":[{"id":"deepseek-chat","updated_at":"2026-08-22T00:00:00Z"}]}"#;
    let page = kernel.decode(&request, body, OBSERVED_AT).unwrap();
    assert_eq!(page.next_cursor, None);
    let checkpoint = kernel
        .checkpoint_candidate(&request, &page, Some("2026-08-21T00:00:00Z"))
        .unwrap();
    assert_eq!(checkpoint.cursor, None);
    assert_eq!(
        checkpoint.watermark.as_deref(),
        Some("2026-08-22T00:00:00Z")
    );
    let replayed = kernel
        .decode(
            &kernel.plan(checkpoint.cursor.as_deref()).unwrap(),
            body,
            OBSERVED_AT,
        )
        .unwrap();
    assert_eq!(page.records[0].event_id, replayed.records[0].event_id);
    assert_eq!(page.records[0].attributes, replayed.records[0].attributes);
}

#[test]
fn identities_are_tenant_scoped_and_conflicting_duplicates_fail_closed() {
    let body = br#"{"data":[{"id":"deepseek-chat","name":"Chat"}]}"#;
    let record = |tenant: &str| {
        let kernel = kernel(tenant, DeepSeekFamily::ModelCatalog);
        kernel
            .decode(&kernel.plan(None).unwrap(), body, OBSERVED_AT)
            .unwrap()
            .records
            .remove(0)
    };
    let first = record("tenant-a");
    let repeated = record("tenant-a");
    let other = record("tenant-b");
    assert_eq!(first.event_id, repeated.event_id);
    assert_ne!(first.event_id, other.event_id);
    assert_ne!(
        first.attributes["resource_urn"],
        other.attributes["resource_urn"]
    );

    let kernel = kernel("tenant-a", DeepSeekFamily::ModelCatalog);
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode(
            &request,
            br#"{"data":[{"id":"same","name":"One"},{"id":"same","name":"Two"}]}"#,
            OBSERVED_AT
        ),
        Err(DeepSeekError::ConflictingDuplicate)
    );
    assert_eq!(
        kernel
            .decode(
                &request,
                br#"{"data":[{"id":"same","name":"One"},{"id":"same","name":"One"}]}"#,
                OBSERVED_AT
            )
            .unwrap()
            .records
            .len(),
        1
    );
}

#[test]
fn secrets_tenants_limits_and_provider_failures_stay_typed_and_bounded() {
    let kernel = kernel("trusted", DeepSeekFamily::ModelCatalog);
    let request = kernel.plan(None).unwrap();
    for (body, error) in [
        (
            br#"{"data":[{"id":"model","tenant_id":"attacker"}]}"#.as_slice(),
            DeepSeekError::TenantMismatch,
        ),
        (
            br#"{"data":[{"id":"model","tenant-id":"attacker"}]}"#.as_slice(),
            DeepSeekError::TenantMismatch,
        ),
        (
            br#"{"data":[{"id":"model","metadata":{"api_key":"secret-sentinel"}}]}"#.as_slice(),
            DeepSeekError::CredentialMaterial,
        ),
        (
            br#"{"data":[{"id":"model","metadata":{"api-key":"secret-sentinel"}}]}"#.as_slice(),
            DeepSeekError::CredentialMaterial,
        ),
    ] {
        let actual = kernel.decode(&request, body, OBSERVED_AT);
        assert_eq!(actual, Err(error));
        assert!(!format!("{actual:?}").contains("secret-sentinel"));
    }
    for (status, error) in [
        (401, DeepSeekError::AuthenticationRejected),
        (402, DeepSeekError::InsufficientBalance),
        (403, DeepSeekError::RequiredScopeMissing),
        (
            429,
            DeepSeekError::RateLimited {
                retry_after_seconds: Some(30),
            },
        ),
        (503, DeepSeekError::ProviderUnavailable { status: 503 }),
        (418, DeepSeekError::UnexpectedStatus { status: 418 }),
    ] {
        assert_eq!(
            kernel.decode_http(&request, status, Some(30), b"{}", OBSERVED_AT),
            Err(error)
        );
    }
    let oversized = vec![b' '; request.max_response_bytes() + 1];
    assert_eq!(
        kernel.decode(&request, &oversized, OBSERVED_AT),
        Err(DeepSeekError::ResponseTooLarge)
    );
    assert_eq!(
        kernel.decode(&request, br#"{"data":[{"object":"model"}]}"#, OBSERVED_AT),
        Err(DeepSeekError::MissingStableIdentity)
    );
}

fn decode_oracle(family: DeepSeekFamily, oracle_bytes: &[u8]) -> DeepSeekRecord {
    let oracle: Vec<Value> = serde_json::from_slice(oracle_bytes).expect("Go oracle JSON");
    let expected = oracle.first().expect("one oracle event");
    let mut provider = expected["payload"]
        .as_object()
        .expect("oracle payload object")
        .clone();
    for key in [
        "api_method",
        "api_path",
        "event_id",
        "family",
        "observed_at",
        "record_class",
        "record_selector",
        "resource_id",
        "resource_type",
        "resource_urn",
        "schema_ref",
        "source_id",
        "tenant_id",
    ] {
        provider.remove(key);
    }
    let response = json!({family.list_key(): [Value::Object(provider)]});
    let kernel = kernel("tenant", family);
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            &serde_json::to_vec(&response).unwrap(),
            OBSERVED_AT,
        )
        .expect("decode provider fixture");
    assert_eq!(page.records.len(), 1);
    let record = page.records.into_iter().next().unwrap();
    assert_eq!(record.tenant_id, expected["tenant_id"]);
    assert_eq!(record.kind, expected["kind"]);
    assert_eq!(record.schema_ref, expected["schema_ref"]);
    assert_eq!(record.occurred_at, expected["occurred_at"]);
    assert_eq!(record.attributes, string_map(&expected["attributes"]));
    assert_eq!(record.payload, expected["payload"]);
    record
}

fn string_map(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .expect("string map")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value.as_str().expect("string attribute").to_owned(),
            )
        })
        .collect()
}
