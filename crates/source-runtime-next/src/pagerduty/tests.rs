use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

use cerebro_source_catalog::{
    AuthModel, CollectionAuthority, Pagination, PathParameterBinding, SourceCatalog,
    UnsupportedReasonCode,
};
use serde::Deserialize;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::*;

const OBSERVED_AT: &str = "2026-06-01T00:00:00Z";
const SECRET_CANARY: &str = "pagerduty-secret-test-value";
const SOURCE_CATALOG: &[u8] = include_bytes!("../../../../sources/pagerduty/catalog.yaml");
const CONNECTOR_CATALOG: &[u8] = include_bytes!(
    "../../../../internal/connectorcatalog/catalog/observability-soar-threat-intel/pagerduty.yaml"
);

#[derive(Deserialize)]
struct SourceCatalogWire {
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
struct EventContractWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

#[derive(Deserialize)]
struct ConnectorCatalogWire {
    entries: Vec<ConnectorEntryWire>,
}

#[derive(Deserialize)]
struct ConnectorEntryWire {
    classifier_output: String,
    definition: ConnectorDefinitionWire,
}

#[derive(Deserialize)]
struct ConnectorDefinitionWire {
    source_id: String,
    auth: ConnectorAuthWire,
    resource_families: Vec<ConnectorFamilyWire>,
    scope_options: Vec<ScopeOptionWire>,
}

#[derive(Deserialize)]
struct ConnectorAuthWire {
    model: String,
    token_header: String,
    token_scheme: String,
}

#[derive(Deserialize)]
struct ConnectorFamilyWire {
    id: String,
    method: String,
    path: String,
    record_selector: String,
    id_field: String,
    event: ConnectorEventWire,
    pagination: ConnectorPaginationWire,
    #[serde(default)]
    read: Option<ConnectorReadWire>,
}

#[derive(Deserialize)]
struct ConnectorEventWire {
    kind: String,
    schema_ref: String,
    required_attributes: Vec<String>,
    required_payload_fields: Vec<String>,
}

#[derive(Deserialize)]
struct ConnectorPaginationWire {
    #[serde(rename = "type")]
    kind: String,
    offset_param: String,
    limit_param: String,
    has_more_key: String,
    page_size: usize,
}

#[derive(Deserialize)]
struct ConnectorReadWire {
    path_params: Vec<String>,
    path_param_fanout: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct ScopeOptionWire {
    id: String,
    families: Vec<String>,
}

#[test]
fn closed_definition_covers_exact_pagerduty_families() {
    let source: SourceCatalogWire =
        serde_saphyr::from_slice(SOURCE_CATALOG).expect("PagerDuty source catalog YAML");
    let connector: ConnectorCatalogWire =
        serde_saphyr::from_slice(CONNECTOR_CATALOG).expect("PagerDuty connector catalog YAML");
    let connector = connector
        .entries
        .into_iter()
        .next()
        .expect("PagerDuty entry");
    let got = PagerDutyFamily::ALL
        .into_iter()
        .map(|family| {
            let kernel = kernel(family, "writer", None);
            let plan = kernel.definition();
            assert_eq!(plan.source_id, "pagerduty");
            assert_eq!(plan.family_id, family.as_str());
            assert_eq!(plan.method, "GET");
            assert_eq!(plan.auth_header, "Authorization");
            assert_eq!(plan.auth_scheme, "Token token=");
            assert_eq!(plan.origin, "https://api.pagerduty.com");
            assert_eq!(plan.path_template, family.path_template());
            assert_eq!(
                plan.record_selector,
                format!("$.{}[*]", family.response_key())
            );
            assert_eq!(plan.id_field, "id");
            assert_eq!(plan.offset_param, "offset");
            assert_eq!(plan.page_size_param, "limit");
            assert_eq!(plan.has_more_key, "more");
            assert_eq!(
                plan.fanout_config_key,
                (family == PagerDutyFamily::Integration).then_some("service_ids")
            );
            assert_eq!(plan.event_kind, family.event_kind());
            assert_eq!(plan.schema_ref, family.schema_ref());
            assert_eq!(plan.required_payload_fields, ["id"]);
            assert!(
                plan.required_attributes
                    .contains(&family.identity_attribute())
            );
            family.as_str()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        got,
        [
            "user",
            "team",
            "service",
            "schedule",
            "escalation_policy",
            "integration",
            "vendor",
        ]
    );
    let expected = got.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(
        source
            .runtime_families
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        connector
            .definition
            .resource_families
            .iter()
            .map(|family| family.id.as_str())
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        connector
            .definition
            .scope_options
            .iter()
            .map(|scope| scope.id.as_str())
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert!(
        connector
            .definition
            .scope_options
            .iter()
            .all(|scope| scope.families.len() == 1 && scope.families[0] == scope.id)
    );
}

#[test]
fn public_connector_matches_go_contract_but_remains_non_authoritative() {
    let source: SourceCatalogWire =
        serde_saphyr::from_slice(SOURCE_CATALOG).expect("PagerDuty source catalog YAML");
    let connector: ConnectorCatalogWire =
        serde_saphyr::from_slice(CONNECTOR_CATALOG).expect("PagerDuty connector catalog YAML");
    let connector = connector
        .entries
        .into_iter()
        .next()
        .expect("PagerDuty entry");
    assert_eq!(connector.classifier_output, "bespoke_required");
    assert_eq!(connector.definition.source_id, "pagerduty");
    assert_eq!(connector.definition.auth.model, "api_key");
    assert_eq!(connector.definition.auth.token_header, "Authorization");
    assert_eq!(connector.definition.auth.token_scheme, "Token");
    assert_eq!(source.provider_api.auth, "pagerduty_api_token");
    assert_eq!(source.provider_api.base_url, "https://api.pagerduty.com");

    for family in PagerDutyFamily::ALL {
        let plan = kernel(family, "tenant", None).definition();
        let provider = source
            .provider_api
            .families
            .iter()
            .find(|candidate| candidate.id == family.as_str())
            .expect("provider proof family");
        let public = connector
            .definition
            .resource_families
            .iter()
            .find(|candidate| candidate.id == family.as_str())
            .expect("public connector family");
        let contract = source
            .event_contracts
            .iter()
            .find(|candidate| candidate.kind == family.event_kind())
            .expect("source event contract");
        assert_eq!(provider.method, plan.method);
        assert_eq!(provider.path, plan.path_template);
        assert_eq!(public.method, plan.method);
        assert_eq!(public.path, plan.path_template);
        assert_eq!(public.record_selector, plan.record_selector);
        assert_eq!(public.id_field, plan.id_field);
        assert_eq!(public.event.kind, plan.event_kind);
        assert_eq!(public.event.schema_ref, plan.schema_ref);
        assert_eq!(contract.schema_ref, plan.schema_ref);
        assert_eq!(
            public.event.required_attributes,
            contract.required_attributes
        );
        assert_eq!(
            public.event.required_payload_fields,
            contract.required_payload_fields
        );
        assert_eq!(public.pagination.kind, "offset");
        assert_eq!(public.pagination.offset_param, plan.offset_param);
        assert_eq!(public.pagination.limit_param, plan.page_size_param);
        assert_eq!(public.pagination.has_more_key, plan.has_more_key);
        assert_eq!(public.pagination.page_size, plan.max_records_per_page);
        if family == PagerDutyFamily::Integration {
            let read = public.read.as_ref().expect("integration fanout");
            assert_eq!(read.path_params, ["service_id"]);
            assert_eq!(
                read.path_param_fanout,
                BTreeMap::from([("service_id".to_owned(), "service_ids".to_owned())])
            );
        } else {
            assert!(public.read.is_none());
        }
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let compiled = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("compile source catalog");
    let pagerduty = compiled
        .get("pagerduty")
        .expect("compiled PagerDuty source");
    assert_eq!(pagerduty.authority(), CollectionAuthority::ShadowOnly);
    assert_eq!(pagerduty.auth(), &AuthModel::ApiKey);
    assert_eq!(pagerduty.token_header(), "Authorization");
    assert_eq!(pagerduty.token_scheme(), "Token");
    assert_eq!(pagerduty.families().len(), PagerDutyFamily::ALL.len());
    for family in pagerduty.families() {
        assert!(!family.is_authoritative(), "{}", family.id());
        assert!(family.is_projection_authoritative(), "{}", family.id());
        assert_eq!(
            family.unsupported_reasons(),
            [UnsupportedReasonCode::BespokeRuntime],
            "{}",
            family.id()
        );
        assert_eq!(
            family.pagination(),
            &Pagination::Offset {
                parameter: "offset".to_owned(),
                limit_parameter: "limit".to_owned(),
                page_size: 100,
            }
        );
    }
    let integration = pagerduty
        .families()
        .iter()
        .find(|family| family.id() == "integration")
        .expect("integration family");
    assert_eq!(
        integration.path_parameters().get("service_id"),
        Some(&PathParameterBinding::CsvFanout {
            field: "service_ids".to_owned(),
        })
    );
}

#[test]
fn requests_are_bounded_origin_locked_and_credential_free() {
    for family in PagerDutyFamily::ALL {
        let kernel = kernel(family, "writer", Some(25));
        assert!(!PagerDutyKernel::requires_credentials());
        let request = kernel.plan(None).unwrap();
        assert_eq!(
            request.url().origin().ascii_serialization(),
            "https://api.pagerduty.com"
        );
        assert_eq!(
            request
                .url()
                .query_pairs()
                .find(|(key, _)| key == "limit")
                .unwrap()
                .1,
            "25"
        );
        assert!(request.url().query_pairs().all(|(key, _)| key != "offset"));
        assert_eq!(request.authorization_scheme(), "Token token=");
        assert_eq!(request.authorization_header(), "Authorization");
        assert_eq!(request.method(), "GET");
        assert_eq!(request.accept(), "application/json");
        assert!(!request.contains_credentials());
        assert!(!request.allows_redirects());
        assert_eq!(request.max_response_bytes(), request::MAX_RESPONSE_BYTES);
        let debug = format!("{kernel:?}{request:?}");
        assert!(!debug.contains(SECRET_CANARY));
        assert!(!debug.contains("Authorization"));
    }
}

#[test]
fn go_fixture_semantic_parity_covers_all_families() {
    for family in PagerDutyFamily::ALL {
        let fixture = go_fixture(family);
        let expected = fixture.as_array().unwrap().first().unwrap();
        let payload = expected.get("payload").unwrap().clone();
        let body = serde_json::to_vec(&json!({family.response_key(): [payload]})).unwrap();
        let kernel = kernel(family, "tenant", None);
        let request = kernel.plan(None).unwrap();
        let page = kernel.decode(&request, 200, &body, observed_at()).unwrap();
        assert_eq!(page.records.len(), 1, "family={}", family.as_str());
        let record = &page.records[0];
        assert_eq!(record.event_kind, expected["kind"].as_str().unwrap());
        assert_eq!(record.schema_ref, expected["schema_ref"].as_str().unwrap());
        assert_eq!(record.payload, expected["payload"]);
        let expected_occurred_at = if family == PagerDutyFamily::Service {
            // The Go HTTP runtime declares created_at as the service TimestampKeys oracle.
            // Its replay fixture envelope has a later fixture-only observation timestamp.
            expected["payload"]["created_at"].as_str().unwrap()
        } else {
            expected["occurred_at"].as_str().unwrap()
        };
        assert_eq!(record.occurred_at, expected_occurred_at);
        let attributes: BTreeMap<String, String> =
            serde_json::from_value(expected["attributes"].clone()).unwrap();
        assert_eq!(record.attributes, attributes, "family={}", family.as_str());
        assert!(record.event_id.starts_with("pagerduty-tenant-"));
        assert_eq!(
            page.checkpoint_cursor.as_deref(),
            Some(record.provider_id.as_str())
        );
        assert!(page.next_cursor.is_none());
    }
}

#[test]
fn offset_pagination_round_trips_and_advances_checkpoint_after_decode_only() {
    let kernel = kernel(PagerDutyFamily::User, "writer", Some(2));
    let first_request = kernel.plan(None).unwrap();
    let first = kernel
        .decode(
            &first_request,
            200,
            &serde_json::to_vec(&json!({
                "users": [{"id":"PU1"},{"id":"PU2"}],
                "limit": 2,
                "offset": 0,
                "more": true
            }))
            .unwrap(),
            observed_at(),
        )
        .unwrap();
    assert_eq!(first.next_cursor.as_deref(), Some("2"));
    assert_eq!(first.checkpoint_cursor.as_deref(), Some("2"));
    let second_request = kernel.plan(first.next_cursor.as_deref()).unwrap();
    assert_eq!(
        second_request
            .url()
            .query_pairs()
            .find(|(key, _)| key == "offset")
            .unwrap()
            .1,
        "2"
    );
    let second = kernel
        .decode(
            &second_request,
            200,
            &serde_json::to_vec(&json!({
                "users": [{"id":"PU3"}],
                "limit": 2,
                "offset": 2,
                "more": false
            }))
            .unwrap(),
            observed_at(),
        )
        .unwrap();
    assert!(second.next_cursor.is_none());
    assert_eq!(second.checkpoint_cursor.as_deref(), Some("PU3"));
}

#[test]
fn empty_pages_can_continue_without_proposing_a_checkpoint() {
    let kernel = kernel(PagerDutyFamily::Team, "writer", Some(10));
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            200,
            br#"{"teams":[],"limit":10,"offset":0,"more":true}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("10"));
    assert!(page.checkpoint_cursor.is_none());
}

#[test]
fn integration_cursor_preserves_service_fanout_and_provider_offset() {
    let kernel = PagerDutyKernel::new(
        None,
        "writer",
        PagerDutyFamily::Integration,
        PagerDutyFilters {
            service_ids: vec!["PS1".to_owned(), "PS2".to_owned()],
        },
        Some(1),
    )
    .unwrap();
    let first_request = kernel.plan(None).unwrap();
    assert_eq!(first_request.url().path(), "/services/PS1/integrations");
    let first = decode_integration(&kernel, &first_request, "PI1", true, 0);
    let first_cursor = first.next_cursor.unwrap();
    assert_eq!(
        first_cursor,
        r#"{"version":1,"source":"pagerduty","mode":"fanout_path_param","token":"{\"index\":0,\"cursor\":\"1\"}"}"#
    );
    assert_eq!(first.checkpoint_cursor.as_deref(), Some("1"));

    let second_request = kernel.plan(Some(&first_cursor)).unwrap();
    assert_eq!(second_request.url().path(), "/services/PS1/integrations");
    assert_eq!(
        second_request
            .url()
            .query_pairs()
            .find(|(key, _)| key == "offset")
            .unwrap()
            .1,
        "1"
    );
    let second = decode_integration(&kernel, &second_request, "PI2", false, 1);
    let second_cursor = second.next_cursor.unwrap();
    assert_eq!(
        second_cursor,
        r#"{"version":1,"source":"pagerduty","mode":"fanout_path_param","token":"{\"index\":1}"}"#
    );
    assert_eq!(second.checkpoint_cursor.as_deref(), Some("PI2"));

    let third_request = kernel.plan(Some(&second_cursor)).unwrap();
    assert_eq!(third_request.url().path(), "/services/PS2/integrations");
    let third = decode_integration(&kernel, &third_request, "PI3", false, 0);
    assert!(third.next_cursor.is_none());
    assert_eq!(third.records[0].attributes["service_id"], "PS2");
}

#[test]
fn identity_is_tenant_scoped_and_duplicate_content_is_idempotent() {
    let body = br#"{"users":[{"id":"PU1","name":"Alice"},{"id":"PU1","name":"Alice"}]}"#;
    let writer = kernel(PagerDutyFamily::User, "writer", None);
    let other = kernel(PagerDutyFamily::User, "other", None);
    let writer_page = writer
        .decode(&writer.plan(None).unwrap(), 200, body, observed_at())
        .unwrap();
    let other_page = other
        .decode(&other.plan(None).unwrap(), 200, body, observed_at())
        .unwrap();
    assert_eq!(writer_page.records.len(), 1);
    assert_ne!(
        writer_page.records[0].event_id,
        other_page.records[0].event_id
    );
    assert_ne!(
        primary_urn(&writer_page.records),
        primary_urn(&other_page.records)
    );
}

#[test]
fn secret_shaped_provider_fields_do_not_reach_events_or_graph_facts() {
    let kernel = kernel(PagerDutyFamily::User, "writer", None);
    let body = serde_json::to_vec(&json!({
        "users": [{
            "id": "PU1",
            "name": "Alice",
            "api_key": SECRET_CANARY,
            "nested": {"password": SECRET_CANARY},
            "safe_metadata": "preserved"
        }]
    }))
    .unwrap();
    let page = kernel
        .decode(&kernel.plan(None).unwrap(), 200, &body, observed_at())
        .unwrap();
    let record = page.records.first().unwrap();
    assert_eq!(record.payload["safe_metadata"].as_str(), Some("preserved"));
    assert!(record.payload.get("api_key").is_none());
    assert!(record.payload["nested"].get("password").is_none());
    assert!(
        !serde_json::to_string(&record.payload)
            .unwrap()
            .contains(SECRET_CANARY)
    );
    assert!(!format!("{:?}", project_pagerduty_records(&page.records)).contains(SECRET_CANARY));
}

#[test]
fn responder_identity_and_escalation_coverage_projection_matches_go_semantics() {
    let mut records = Vec::new();
    for family in PagerDutyFamily::ALL {
        let fixture = go_fixture(family);
        let expected = fixture.as_array().unwrap().first().unwrap();
        let body = serde_json::to_vec(&json!({
            family.response_key(): [expected["payload"].clone()]
        }))
        .unwrap();
        let kernel = kernel(family, "tenant", None);
        records.extend(
            kernel
                .decode(&kernel.plan(None).unwrap(), 200, &body, observed_at())
                .unwrap()
                .records,
        );
    }
    let projection = project_pagerduty_records(&records);
    assert_entity(
        &projection,
        "urn:cerebro:tenant:pagerduty_user:PU1",
        "pagerduty.user",
    );
    assert_entity(
        &projection,
        "urn:cerebro:tenant:pagerduty_team:PT1",
        "pagerduty.team",
    );
    assert_entity(
        &projection,
        "urn:cerebro:tenant:pagerduty_service:PS1",
        "pagerduty.service",
    );
    assert_entity(
        &projection,
        "urn:cerebro:tenant:pagerduty_schedule:PSC1",
        "pagerduty.schedule",
    );
    assert_entity(
        &projection,
        "urn:cerebro:tenant:pagerduty_escalation_policy:PE1",
        "pagerduty.escalation_policy",
    );
    assert_entity(
        &projection,
        "urn:cerebro:tenant:pagerduty_integration:PI1",
        "pagerduty.integration",
    );
    assert_entity(
        &projection,
        "urn:cerebro:tenant:pagerduty_vendor:PV1",
        "pagerduty.vendor",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_service:PS1",
        "depends_on",
        "urn:cerebro:tenant:pagerduty_escalation_policy:PE1",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_escalation_policy:PE1",
        "belongs_to",
        "urn:cerebro:tenant:pagerduty_team:PT1",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_escalation_policy:PE1",
        "depends_on",
        "urn:cerebro:tenant:pagerduty_schedule:PSC1",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_escalation_policy:PE1",
        "depends_on",
        "urn:cerebro:tenant:pagerduty_user:PU1",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_integration:PI1",
        "belongs_to",
        "urn:cerebro:tenant:pagerduty_service:PS1",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_integration:PI1",
        "depends_on",
        "urn:cerebro:tenant:pagerduty_vendor:PV1",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_user:PU1",
        "has_identifier",
        "urn:cerebro:tenant:identifier:email:alice@example.test",
    );
    assert_relation(
        &projection,
        "urn:cerebro:tenant:pagerduty_user:PU1",
        "represents_identity",
        "urn:cerebro:tenant:identity:email:alice@example.test",
    );
}

#[test]
fn failures_are_distinct_and_fail_closed() {
    assert_eq!(
        PagerDutyKernel::new(
            Some("http://api.pagerduty.com"),
            "writer",
            PagerDutyFamily::User,
            PagerDutyFilters::default(),
            None
        )
        .unwrap_err(),
        PagerDutyError::InvalidBaseUrl
    );
    assert_eq!(
        PagerDutyKernel::new(
            None,
            "",
            PagerDutyFamily::User,
            PagerDutyFilters::default(),
            None
        )
        .unwrap_err(),
        PagerDutyError::MissingTenantId
    );
    assert_eq!(
        PagerDutyKernel::new(
            None,
            "writer",
            PagerDutyFamily::Integration,
            PagerDutyFilters::default(),
            None
        )
        .unwrap_err(),
        PagerDutyError::MissingServiceId
    );
    assert_eq!(
        PagerDutyKernel::new(
            None,
            "writer",
            PagerDutyFamily::User,
            PagerDutyFilters::default(),
            Some(101)
        )
        .unwrap_err(),
        PagerDutyError::InvalidPageSize
    );

    let kernel = kernel(PagerDutyFamily::User, "writer", None);
    for cursor in ["https://evil.test/next", "-1", "+1", "not-a-number"] {
        assert_eq!(
            kernel.plan(Some(cursor)).unwrap_err(),
            PagerDutyError::InvalidCursor
        );
    }
    for (status, expected) in [
        (401, PagerDutyError::AuthenticationRejected),
        (403, PagerDutyError::PermissionDenied),
        (429, PagerDutyError::RateLimited),
        (503, PagerDutyError::ProviderUnavailable),
        (418, PagerDutyError::UnexpectedProviderStatus),
    ] {
        assert_eq!(
            kernel
                .decode(&kernel.plan(None).unwrap(), status, b"{}", observed_at())
                .unwrap_err(),
            expected
        );
    }
    assert_eq!(
        kernel
            .decode(&kernel.plan(None).unwrap(), 200, b"{}", observed_at())
            .unwrap_err(),
        PagerDutyError::MalformedResponse
    );
    assert_eq!(
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                200,
                br#"{"users":[{}]}"#,
                observed_at()
            )
            .unwrap_err(),
        PagerDutyError::MissingProviderIdentity
    );
    assert_eq!(
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                200,
                br#"{"users":[{"id":"PU/1"}]}"#,
                observed_at()
            )
            .unwrap_err(),
        PagerDutyError::InvalidProviderIdentity
    );
    assert_eq!(
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                200,
                br#"{"users":[{"id":"PU1","name":"Alice"},{"id":"PU1","name":"Mallory"}]}"#,
                observed_at()
            )
            .unwrap_err(),
        PagerDutyError::ConflictingProviderIdentity
    );
    assert_eq!(
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                200,
                &vec![b' '; request::MAX_RESPONSE_BYTES + 1],
                observed_at()
            )
            .unwrap_err(),
        PagerDutyError::ResponseTooLarge
    );
    let too_many = (0..=request::MAX_RECORDS_PER_PAGE)
        .map(|index| json!({"id": format!("PU{index}")}))
        .collect::<Vec<_>>();
    assert_eq!(
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                200,
                &serde_json::to_vec(&json!({"users": too_many})).unwrap(),
                observed_at()
            )
            .unwrap_err(),
        PagerDutyError::TooManyRecords
    );
}

fn kernel(family: PagerDutyFamily, tenant: &str, page_size: Option<usize>) -> PagerDutyKernel {
    PagerDutyKernel::new(
        None,
        tenant,
        family,
        PagerDutyFilters {
            service_ids: if family == PagerDutyFamily::Integration {
                vec!["PS1".to_owned()]
            } else {
                Vec::new()
            },
        },
        page_size,
    )
    .unwrap()
}

fn decode_integration(
    kernel: &PagerDutyKernel,
    request: &PagerDutyRequest,
    id: &str,
    more: bool,
    offset: u64,
) -> PagerDutyPage {
    kernel
        .decode(
            request,
            200,
            &serde_json::to_vec(&json!({
                "integrations": [{"id": id}],
                "limit": 1,
                "offset": offset,
                "more": more
            }))
            .unwrap(),
            observed_at(),
        )
        .unwrap()
}

fn observed_at() -> OffsetDateTime {
    OffsetDateTime::parse(OBSERVED_AT, &Rfc3339).unwrap()
}

fn primary_urn(records: &[PagerDutyRecord]) -> String {
    let record = records.first().unwrap();
    project_pagerduty_records(records)
        .entities
        .into_iter()
        .find(|entity| entity.entity_type == record.event_kind)
        .unwrap()
        .urn
}

fn go_fixture(family: PagerDutyFamily) -> Value {
    serde_json::from_str(match family {
        PagerDutyFamily::User => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sources/pagerduty/testdata/read_user.json"
        )),
        PagerDutyFamily::Team => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sources/pagerduty/testdata/read_team.json"
        )),
        PagerDutyFamily::Service => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sources/pagerduty/testdata/read_service.json"
        )),
        PagerDutyFamily::Schedule => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sources/pagerduty/testdata/read_schedule.json"
        )),
        PagerDutyFamily::EscalationPolicy => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sources/pagerduty/testdata/read_escalation_policy.json"
        )),
        PagerDutyFamily::Integration => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sources/pagerduty/testdata/read_integration.json"
        )),
        PagerDutyFamily::Vendor => include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../sources/pagerduty/testdata/read_vendor.json"
        )),
    })
    .unwrap()
}

fn assert_entity(projection: &PagerDutyProjectionFacts, urn: &str, entity_type: &str) {
    let found: Option<&PagerDutyEntityFact> = projection
        .entities
        .iter()
        .find(|entity| entity.urn == urn && entity.entity_type == entity_type);
    assert!(found.is_some(), "missing entity {urn} ({entity_type})");
}

fn assert_relation(projection: &PagerDutyProjectionFacts, from: &str, relation: &str, to: &str) {
    let found: Option<&PagerDutyRelationFact> = projection
        .relations
        .iter()
        .find(|edge| edge.from_urn == from && edge.relation == relation && edge.to_urn == to);
    assert!(
        found.is_some(),
        "missing relation {from} -[{relation}]-> {to}"
    );
}
