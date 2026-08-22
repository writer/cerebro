use std::{collections::BTreeMap, fs, path::PathBuf};

use serde_json::{Value, json};

use super::{
    AnthropicAuthentication, AnthropicError, AnthropicFamily, AnthropicKernel, AnthropicScope,
};

const BASE_URL: &str = "https://api.anthropic.com/v1";
const OBSERVED_AT: &str = "2026-06-01T00:00:00Z";

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
