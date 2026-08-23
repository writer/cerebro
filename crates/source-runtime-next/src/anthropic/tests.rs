use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use cerebro_source_catalog::{AuthModel, HttpMethod, Pagination, SourceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{
    AnthropicAuthentication, AnthropicError, AnthropicFamily, AnthropicKernel, AnthropicScope,
};

const BASE_URL: &str = "https://api.anthropic.com/v1";
const OBSERVED_AT: &str = "2026-06-01T00:00:00Z";
const SOURCE_CATALOG: &[u8] = include_bytes!("../../../../sources/anthropic/catalog.yaml");
const CONNECTOR_CATALOG: &[u8] =
    include_bytes!("../../../../internal/connectorcatalog/catalog/ai-governance/anthropic.yaml");

#[derive(Deserialize)]
struct CatalogWire {
    runtime_families: Vec<String>,
    provider_api: ProviderApiWire,
    event_contracts: Vec<EventContractWire>,
}

#[derive(Deserialize)]
struct ProviderApiWire {
    families: Vec<ProviderFamilyWire>,
}

#[derive(Deserialize)]
struct ProviderFamilyWire {
    id: String,
    method: String,
    path: String,
}

#[derive(Deserialize)]
struct EventContractWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    #[serde(default)]
    required_payload_fields: Vec<String>,
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
    auth: ConnectorAuthWire,
    resource_families: Vec<ConnectorFamilyWire>,
}

#[derive(Deserialize)]
struct ConnectorAuthWire {
    model: String,
    configurable_models: Vec<String>,
    model_config_key: String,
    requires_references: bool,
    token_header: String,
}

#[derive(Deserialize)]
struct ConnectorFamilyWire {
    id: String,
    id_field: String,
    method: String,
    path: String,
    event: ConnectorEventWire,
    pagination: ConnectorPaginationWire,
    #[serde(default)]
    config: ConnectorFamilyConfigWire,
    coverage: Vec<ConnectorCoverageWire>,
}

#[derive(Deserialize)]
struct ConnectorEventWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    #[serde(default)]
    required_payload_fields: Vec<String>,
    exact_attributes: bool,
}

#[derive(Deserialize)]
struct ConnectorPaginationWire {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    cursor_param: String,
    #[serde(default)]
    cursor_json_path: String,
    #[serde(default)]
    has_more_key: String,
    #[serde(default)]
    page_size_param: String,
    #[serde(default)]
    page_size: usize,
    #[serde(default)]
    disable_page_size: bool,
}

#[derive(Default, Deserialize)]
struct ConnectorFamilyConfigWire {
    #[serde(default)]
    auth_model: String,
}

#[derive(Deserialize)]
struct ConnectorCoverageWire {
    notes: Vec<String>,
}

#[test]
fn public_connector_matches_the_closed_legacy_family_surface() {
    let source: CatalogWire =
        serde_saphyr::from_slice(SOURCE_CATALOG).expect("Anthropic source catalog YAML");
    let connector: ConnectorCatalogWire =
        serde_saphyr::from_slice(CONNECTOR_CATALOG).expect("Anthropic connector catalog YAML");
    let connector = connector
        .entries
        .into_iter()
        .find(|entry| entry.definition.source_id == "anthropic")
        .expect("Anthropic connector definition")
        .definition;

    let closed = AnthropicFamily::ALL
        .into_iter()
        .map(AnthropicFamily::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        source
            .runtime_families
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        closed
    );
    assert_eq!(
        connector
            .resource_families
            .iter()
            .map(|family| family.id.as_str())
            .collect::<BTreeSet<_>>(),
        closed
    );
    assert_eq!(connector.auth.model, "api_key");
    assert_eq!(
        connector.auth.configurable_models,
        ["api_key", "bearer_token"]
    );
    assert_eq!(connector.auth.model_config_key, "auth_model");
    assert!(connector.auth.requires_references);
    assert_eq!(connector.auth.token_header, "x-api-key");

    for family in AnthropicFamily::ALL {
        let public = connector
            .resource_families
            .iter()
            .find(|candidate| candidate.id == family.as_str())
            .expect("public family");
        let provider = source
            .provider_api
            .families
            .iter()
            .find(|candidate| candidate.id == family.as_str())
            .expect("provider proof family");
        let contract = source
            .event_contracts
            .iter()
            .find(|contract| contract.kind == family.provider_kind())
            .expect("source event contract");

        assert_eq!(public.method, "GET", "{} method", family.as_str());
        assert_eq!(provider.method, "GET", "{} proof method", family.as_str());
        assert_eq!(
            canonical_path(&public.path),
            canonical_path(provider.path.strip_prefix("/v1").unwrap_or(&provider.path)),
            "{} provider path",
            family.as_str()
        );
        assert_eq!(
            canonical_path(&public.path),
            canonical_path(family.path()),
            "{} kernel path",
            family.as_str()
        );
        assert_eq!(public.event.kind, family.provider_kind());
        assert_eq!(public.event.schema_ref, family.schema_ref());
        assert_eq!(contract.schema_ref, family.schema_ref());
        assert_eq!(
            public
                .event
                .required_attributes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            family.required_attributes()
        );
        assert_eq!(
            contract
                .required_attributes
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            family.required_attributes()
        );
        let public_required_payload = if family.required_payload_fields().is_empty() {
            vec![public.id_field.as_str()]
        } else {
            family.required_payload_fields().to_vec()
        };
        assert_eq!(
            public
                .event
                .required_payload_fields
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            public_required_payload
        );
        assert_eq!(
            contract
                .required_payload_fields
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            family.required_payload_fields()
        );
        assert!(public.event.exact_attributes);

        let (auth_model, permission) = match family.authentication() {
            AnthropicAuthentication::AdminKeyOrOrgAdminBearer => {
                ("", "Anthropic Admin API key or OAuth bearer with org:admin")
            }
            AnthropicAuthentication::OrgAdminBearer => {
                ("bearer_token", "OAuth bearer with org:admin")
            }
            AnthropicAuthentication::ComplianceAccessKey => {
                ("api_key", "Anthropic Compliance Access Key")
            }
        };
        assert_eq!(
            public.config.auth_model,
            auth_model,
            "{} auth",
            family.as_str()
        );
        assert_eq!(
            public.coverage[0].notes,
            [format!("Authentication requirement: {permission}")],
            "{} permission",
            family.as_str()
        );

        match family.pagination() {
            super::family::PaginationKind::None => {
                assert_eq!(public.pagination.kind, "none");
                assert!(public.pagination.disable_page_size);
                assert_eq!(public.pagination.page_size, 0);
            }
            super::family::PaginationKind::AfterId => {
                assert_eq!(public.pagination.kind, "cursor");
                assert_eq!(public.pagination.cursor_param, "after_id");
                assert_eq!(public.pagination.cursor_json_path, "$.last_id");
                assert_eq!(public.pagination.has_more_key, "has_more");
                assert_eq!(public.pagination.page_size_param, "limit");
                assert_eq!(public.pagination.page_size, 100);
            }
            super::family::PaginationKind::Page => {
                assert_eq!(public.pagination.kind, "cursor");
                assert_eq!(public.pagination.cursor_param, "page");
                assert_eq!(public.pagination.cursor_json_path, "$.next_page");
                assert!(public.pagination.has_more_key.is_empty());
                assert_eq!(public.pagination.page_size_param, "limit");
                assert_eq!(public.pagination.page_size, 100);
            }
        }
    }
}

#[test]
fn public_connector_compiles_as_the_same_credential_free_plan_set() {
    let root = repository_root();
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("compile source catalog");
    let source = catalog.get("anthropic").expect("compiled Anthropic source");
    assert_eq!(source.auth(), &AuthModel::ApiKey);
    assert_eq!(
        source.configurable_auth_models(),
        &[AuthModel::ApiKey, AuthModel::BearerToken]
    );
    assert_eq!(source.token_header(), "x-api-key");
    assert_eq!(
        source
            .families()
            .iter()
            .map(|family| family.id())
            .collect::<BTreeSet<_>>(),
        AnthropicFamily::ALL
            .into_iter()
            .map(AnthropicFamily::as_str)
            .collect::<BTreeSet<_>>()
    );
    for family in source.families() {
        assert_eq!(family.method(), HttpMethod::Get);
        assert!(
            family.exact_event_attributes(),
            "{} attributes",
            family.id()
        );
        assert_eq!(
            family
                .event_static_attributes()
                .get("source_product")
                .map(String::as_str),
            Some("anthropic")
        );
        let closed = family
            .id()
            .parse::<AnthropicFamily>()
            .expect("closed family");
        match closed.pagination() {
            super::family::PaginationKind::None => {
                assert_eq!(family.pagination(), &Pagination::None)
            }
            super::family::PaginationKind::AfterId => assert!(matches!(
                family.pagination(),
                Pagination::Cursor { parameter, response_path, page_size_parameter, page_size }
                    if parameter == "after_id"
                        && response_path == "$.last_id"
                        && page_size_parameter.as_deref() == Some("limit")
                        && *page_size == 100
            )),
            super::family::PaginationKind::Page => assert!(matches!(
                family.pagination(),
                Pagination::Cursor { parameter, response_path, page_size_parameter, page_size }
                    if parameter == "page"
                        && response_path == "$.next_page"
                        && page_size_parameter.as_deref() == Some("limit")
                        && *page_size == 100
            )),
        }
    }
}

fn canonical_path(path: &str) -> String {
    path.strip_prefix("/v1")
        .unwrap_or(path)
        .split('/')
        .map(|segment| {
            if (segment.starts_with("${config.") && segment.ends_with('}'))
                || (segment.starts_with('{') && segment.ends_with('}'))
            {
                "{}"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn all_go_oracle_fixtures_have_semantic_event_parity() {
    assert_eq!(AnthropicFamily::ALL.len(), 28);
    for family in AnthropicFamily::ALL {
        let expected = fixture(family);
        let event = expected
            .as_array()
            .and_then(|events| events.first())
            .expect("one Go oracle event");
        let payload = event.get("payload").cloned().expect("fixture payload");
        let attributes = event
            .get("attributes")
            .and_then(Value::as_object)
            .expect("fixture attributes");
        let scope = scope_from_fixture(family, attributes);
        let kernel = AnthropicKernel::new(BASE_URL, "tenant", family, scope, None).unwrap();
        let request = kernel.plan(None).unwrap();
        let response = if family.singleton() {
            payload.clone()
        } else if family.list_keys().contains(&"settings") {
            json!({"settings": [payload.clone()]})
        } else {
            json!({"data": [payload.clone()], "has_more": false})
        };
        let page = kernel
            .decode(
                &request,
                &serde_json::to_vec(&response).unwrap(),
                event.get("occurred_at").and_then(Value::as_str).unwrap(),
            )
            .unwrap_or_else(|error| panic!("{} fixture failed: {error}", family.as_str()));
        assert_eq!(page.records.len(), 1, "{} count", family.as_str());
        let actual = &page.records[0];
        assert_eq!(actual.tenant_id, "tenant", "{} tenant", family.as_str());
        assert_eq!(actual.payload, payload, "{} payload", family.as_str());
        assert_eq!(
            actual.provider_kind,
            event.get("kind").and_then(Value::as_str).unwrap(),
            "{} kind",
            family.as_str()
        );
        assert_eq!(
            actual.schema_ref,
            event.get("schema_ref").and_then(Value::as_str).unwrap(),
            "{} schema",
            family.as_str()
        );
        let expected_timestamp = family
            .timestamp_paths()
            .iter()
            .find_map(|path| value_at(&payload, path).and_then(Value::as_str))
            .unwrap_or_else(|| event.get("occurred_at").and_then(Value::as_str).unwrap());
        assert_eq!(
            actual.occurred_at,
            expected_timestamp,
            "{} timestamp",
            family.as_str()
        );
        for (key, value) in attributes {
            assert_eq!(
                actual.fields.get(key).map(String::as_str),
                value.as_str(),
                "{} attribute {key}",
                family.as_str()
            );
        }
        assert_eq!(
            page.checkpoint_cursor.as_deref(),
            Some(actual.provider_id.as_str()),
            "{} checkpoint",
            family.as_str()
        );
        assert_eq!(page.watermark.as_deref(), Some(actual.occurred_at.as_str()));
    }
}

#[test]
fn every_family_is_in_the_go_catalog_oracle() {
    let root = repository_root();
    let catalog = fs::read_to_string(root.join("sources/anthropic/catalog.yaml")).unwrap();
    for family in AnthropicFamily::ALL {
        assert!(
            catalog.contains(&format!("kind: anthropic.{}", family.as_str())),
            "missing catalog event {}",
            family.as_str()
        );
    }
}

#[test]
fn requests_are_bounded_origin_restricted_and_credential_free() {
    for family in AnthropicFamily::ALL {
        let scope = family
            .path_parameters()
            .iter()
            .map(|key| ((*key).to_owned(), "scope_123".to_owned()))
            .collect();
        let kernel = AnthropicKernel::new(
            BASE_URL,
            "tenant-a",
            family,
            AnthropicScope {
                path_parameters: scope,
                query_parameters: BTreeMap::new(),
            },
            Some(100),
        )
        .unwrap();
        let request = kernel.plan(None).unwrap();
        assert_eq!(request.method(), "GET");
        assert_eq!(
            request.url().origin(),
            reqwest::Url::parse(BASE_URL).unwrap().origin()
        );
        assert!(request.url().path().starts_with("/v1/"));
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), 8 * 1024 * 1024);
        assert_eq!(
            request.api_version_header(),
            ("anthropic-version", "2023-06-01")
        );
        assert_eq!(request.authentication(), family.authentication());
        assert!(!format!("{request:?}").contains("test-secret-value"));
    }
    assert_eq!(
        AnthropicFamily::ServiceAccount.authentication(),
        AnthropicAuthentication::OrgAdminBearer
    );
    assert_eq!(
        AnthropicFamily::ComplianceActivity.authentication(),
        AnthropicAuthentication::ComplianceAccessKey
    );

    let encoded = AnthropicKernel::new(
        BASE_URL,
        "tenant",
        AnthropicFamily::ComplianceGroupMember,
        AnthropicScope {
            path_parameters: BTreeMap::from([("group_id".to_owned(), "group/../other".to_owned())]),
            query_parameters: BTreeMap::new(),
        },
        None,
    )
    .unwrap()
    .plan(None)
    .unwrap();
    assert!(encoded.url().as_str().contains("group%2F..%2Fother"));
    assert_eq!(
        encoded.url().origin(),
        reqwest::Url::parse(BASE_URL).unwrap().origin()
    );
}

#[test]
fn cursor_checkpoint_and_duplicate_rules_fail_closed() {
    let kernel = AnthropicKernel::new(
        BASE_URL,
        "tenant",
        AnthropicFamily::User,
        AnthropicScope::default(),
        Some(10),
    )
    .unwrap();
    let first = kernel.plan(None).unwrap();
    let payload = json!({"id":"user_1","name":"Ada","added_at":OBSERVED_AT});
    let page = kernel
        .decode(
            &first,
            &serde_json::to_vec(&json!({
                "data":[payload.clone(), payload.clone()],
                "has_more":true,
                "last_id":"user_1"
            }))
            .unwrap(),
            OBSERVED_AT,
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some("user_1"));
    assert_eq!(page.checkpoint_cursor.as_deref(), Some("user_1"));
    assert!(
        kernel
            .plan(page.next_cursor.as_deref())
            .unwrap()
            .url()
            .query()
            .unwrap()
            .contains("after_id=user_1")
    );

    let conflict = json!({"data":[payload, {"id":"user_1","name":"Grace"}]});
    assert_eq!(
        kernel.decode(&first, &serde_json::to_vec(&conflict).unwrap(), OBSERVED_AT),
        Err(AnthropicError::DuplicateConflict)
    );

    let page_kernel = AnthropicKernel::new(
        BASE_URL,
        "tenant",
        AnthropicFamily::CostReport,
        AnthropicScope::default(),
        Some(10),
    )
    .unwrap();
    let request = page_kernel.plan(None).unwrap();
    let response = json!({"data":[], "next_page":"https://api.anthropic.com/v1/organizations/cost_report?page=page-2"});
    let page = page_kernel
        .decode(
            &request,
            &serde_json::to_vec(&response).unwrap(),
            OBSERVED_AT,
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("page-2"));
    assert!(
        page_kernel
            .plan(page.next_cursor.as_deref())
            .unwrap()
            .url()
            .query()
            .unwrap()
            .contains("page=page-2")
    );
    assert_eq!(page.checkpoint_cursor, None);
    let escaped = json!({"data":[], "next_page":"https://example.com/?page=2"});
    assert_eq!(
        page_kernel.decode(
            &request,
            &serde_json::to_vec(&escaped).unwrap(),
            OBSERVED_AT
        ),
        Err(AnthropicError::InvalidCursor)
    );
}

#[test]
fn provider_failures_and_secret_or_tenant_payloads_stay_typed() {
    let kernel = AnthropicKernel::new(
        BASE_URL,
        "trusted-tenant",
        AnthropicFamily::User,
        AnthropicScope::default(),
        None,
    )
    .unwrap();
    let request = kernel.plan(None).unwrap();
    for (status, expected) in [
        (401, AnthropicError::AuthenticationRejected),
        (403, AnthropicError::RequiredProviderScopeMissing),
        (429, AnthropicError::ProviderRateLimit),
        (503, AnthropicError::ProviderUnavailable),
        (418, AnthropicError::UnexpectedProviderStatus),
    ] {
        assert_eq!(
            kernel.decode_http(&request, status, b"{}", OBSERVED_AT),
            Err(expected)
        );
    }
    for record in [
        json!({"id":"user_1","tenant_id":"attacker"}),
        json!({"id":"user_1","access_token":"test-secret-value"}),
    ] {
        let result = kernel.decode(
            &request,
            &serde_json::to_vec(&json!({"data":[record]})).unwrap(),
            OBSERVED_AT,
        );
        assert_eq!(result, Err(AnthropicError::InvalidRecord));
        assert!(!format!("{result:?}").contains("test-secret-value"));
    }
}

#[test]
fn identities_are_deterministic_and_tenant_scoped() {
    let body = serde_json::to_vec(&json!({
        "data":[{"id":"user_1","added_at":OBSERVED_AT}], "has_more":false
    }))
    .unwrap();
    let event_id = |tenant: &str| {
        let kernel = AnthropicKernel::new(
            BASE_URL,
            tenant,
            AnthropicFamily::User,
            AnthropicScope::default(),
            None,
        )
        .unwrap();
        let request = kernel.plan(None).unwrap();
        kernel.decode(&request, &body, OBSERVED_AT).unwrap().records[0]
            .event_id
            .clone()
    };
    assert_eq!(event_id("tenant-a"), event_id("tenant-a"));
    assert_ne!(event_id("tenant-a"), event_id("tenant-b"));
}

fn fixture(family: AnthropicFamily) -> Value {
    let path = repository_root().join(format!(
        "sources/anthropic/testdata/read_{}.json",
        family.as_str()
    ));
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn scope_from_fixture(
    family: AnthropicFamily,
    attributes: &serde_json::Map<String, Value>,
) -> AnthropicScope {
    let path_parameters = family
        .path_parameters()
        .iter()
        .map(|name| {
            (
                (*name).to_owned(),
                attributes
                    .get(*name)
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("fixture missing path parameter {name}"))
                    .to_owned(),
            )
        })
        .collect();
    AnthropicScope {
        path_parameters,
        query_parameters: BTreeMap::new(),
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn value_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut value = value;
    for part in path.split('.') {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}
