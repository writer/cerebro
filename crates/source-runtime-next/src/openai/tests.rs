use std::{collections::BTreeMap, fs, path::PathBuf};

use cerebro_source_catalog::{CollectionAuthority, SourceCatalog};
use serde_json::{Value, json};

use super::{OpenAiError, OpenAiFamily, OpenAiKernel, OpenAiRequestInput, family::Pagination};

const OBSERVED_AT_MILLIS: i64 = 1_780_272_000_000;

#[test]
fn closed_family_table_matches_the_go_catalog() {
    let expected = [
        "user",
        "project",
        "service_account",
        "api_key",
        "admin_api_key",
        "audit_log",
        "invite",
        "role",
        "user_role",
        "group",
        "group_user",
        "group_role",
        "data_retention",
        "spend_alert",
        "certificate",
        "usage_audio_speech",
        "usage_audio_transcription",
        "usage_code_interpreter_session",
        "usage_completion",
        "usage_embedding",
        "usage_image",
        "usage_moderation",
        "usage_vector_store",
        "usage_file_search_call",
        "usage_web_search_call",
        "cost",
        "project_user",
        "project_user_role",
        "project_service_account",
        "project_api_key",
        "project_rate_limit",
        "project_model_permission",
        "project_hosted_tool_permission",
        "project_group",
        "project_group_role",
        "project_role",
        "project_data_retention",
        "project_spend_alert",
        "project_certificate",
    ];
    let actual = OpenAiFamily::all()
        .map(OpenAiFamily::id)
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
    assert_eq!(OpenAiFamily::all().len(), 39);
    assert_eq!(
        OpenAiFamily::parse("model"),
        Err(OpenAiError::UnknownFamily)
    );
}

#[test]
fn connector_catalog_compiles_the_same_closed_authoritative_family_set() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = SourceCatalog::load(
        root.join("internal/connectorcatalog/catalog"),
        root.join("sources"),
    )
    .expect("compile source catalog");
    let source = catalog.get("openai").expect("compiled OpenAI source");
    assert_eq!(source.authority(), CollectionAuthority::Authoritative);
    let compiled = source
        .families()
        .iter()
        .map(|family| family.id())
        .collect::<std::collections::BTreeSet<_>>();
    let closed = OpenAiFamily::all()
        .map(OpenAiFamily::id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(compiled, closed);
    assert!(
        source
            .families()
            .iter()
            .all(|family| family.is_authoritative())
    );
}

#[test]
fn request_plan_is_credential_free_and_origin_restricted() {
    let kernel = kernel("audit_log", "tenant-a");
    let input = OpenAiRequestInput {
        query_parameters: BTreeMap::from([
            ("effective_at_gte".to_owned(), "1711471533".to_owned()),
            ("resource_ids".to_owned(), "proj_123".to_owned()),
        ]),
        page_size: Some(2),
        cursor: Some("cursor-2".to_owned()),
        ..OpenAiRequestInput::default()
    };
    let request = kernel.plan(&input).expect("plan request");
    assert_eq!(request.method, "GET");
    assert!(
        request
            .url
            .starts_with("https://api.openai.com/v1/organization/audit_logs?")
    );
    assert!(request.url.contains("effective_at%5Bgte%5D=1711471533"));
    assert!(request.url.contains("after=cursor-2"));
    assert!(request.url.contains("limit=2"));
    assert!(!request.allow_redirects);
    assert_eq!(request.max_response_bytes, 8 << 20);
    assert!(!OpenAiKernel::requires_credentials());

    let protocol = serde_json::to_string(&request).expect("serialize protocol");
    assert!(protocol.contains("openai.admin_api_key_bearer"));
    for forbidden in [
        "credential-material",
        "api_key\":",
        "token\":",
        "client_secret",
        "cookie\":",
    ] {
        assert!(!protocol.to_ascii_lowercase().contains(forbidden));
    }
}

#[test]
fn request_plan_percent_encodes_scope_and_rejects_secret_shaped_inputs() {
    let project_kernel = kernel("project_user", "tenant-a");
    let input = OpenAiRequestInput {
        path_parameters: BTreeMap::from([("project_id".to_owned(), "project/a b".to_owned())]),
        ..OpenAiRequestInput::default()
    };
    let request = project_kernel.plan(&input).expect("plan scoped request");
    assert!(request.url.contains("/projects/project%2Fa%20b/users"));

    let secret = OpenAiRequestInput {
        query_parameters: BTreeMap::from([("api_key".to_owned(), "redacted".to_owned())]),
        ..OpenAiRequestInput::default()
    };
    assert_eq!(
        kernel("user", "tenant-a").plan(&secret),
        Err(OpenAiError::CredentialMaterialRejected)
    );
}

#[test]
fn singleton_families_have_stable_semantic_identity_and_no_cursor() {
    let kernel = kernel("project_model_permission", "tenant-a");
    let input = OpenAiRequestInput {
        path_parameters: BTreeMap::from([("project_id".to_owned(), "proj_1".to_owned())]),
        ..OpenAiRequestInput::default()
    };
    let page = kernel
        .decode(
            &input,
            200,
            br#"{"object":"project.model_permissions","mode":"allow","model_ids":["gpt-4o"]}"#,
            OBSERVED_AT_MILLIS,
        )
        .expect("decode singleton");
    assert_eq!(page.records[0].provider_id, "proj_1:model_permissions");
    assert_eq!(page.records[0].attributes["project_id"], "proj_1");
    assert_eq!(page.records[0].attributes["model_ids"], r#"["gpt-4o"]"#);
    assert_eq!(page.next_cursor, None);

    let cursor_input = OpenAiRequestInput {
        path_parameters: input.path_parameters,
        cursor: Some("not-valid-for-singletons".to_owned()),
        ..OpenAiRequestInput::default()
    };
    assert_eq!(kernel.plan(&cursor_input), Err(OpenAiError::InvalidCursor));
}

#[test]
fn all_go_projection_fixtures_match_rust_semantics() {
    for family in OpenAiFamily::all() {
        let expected = read_fixture(family.id());
        let expected_event = expected
            .as_array()
            .and_then(|events| events.first())
            .expect("fixture event");
        let payload = expected_event["payload"].clone();
        let expected_attributes = expected_event["attributes"]
            .as_object()
            .expect("fixture attributes");
        let input = fixture_input(family, expected_attributes);
        let response = match family.spec().pagination {
            Pagination::None => payload,
            Pagination::Cursor => json!({"data": [payload], "has_more": false}),
            Pagination::Page => json!({"data": [payload]}),
        };
        let bytes = serde_json::to_vec(&response).expect("encode provider response");
        let page = kernel(family.id(), "tenant")
            .decode(&input, 200, &bytes, OBSERVED_AT_MILLIS)
            .unwrap_or_else(|error| panic!("{} fixture failed: {error}", family.id()));
        assert_eq!(page.records.len(), 1, "{} record count", family.id());
        let record = &page.records[0];
        assert_eq!(
            record.provider_kind,
            expected_event["kind"].as_str().unwrap()
        );
        assert_eq!(
            record.schema_ref,
            expected_event["schema_ref"].as_str().unwrap()
        );
        assert_eq!(
            record.source_id,
            expected_event["source_id"].as_str().unwrap()
        );
        assert_eq!(
            record.tenant_id,
            expected_event["tenant_id"].as_str().unwrap()
        );
        let mut expected_payload = expected_event["payload"].clone();
        for (parameter, value) in &input.path_parameters {
            expected_payload
                .as_object_mut()
                .expect("fixture payload object")
                .entry(parameter.clone())
                .or_insert_with(|| Value::String(value.clone()));
        }
        assert_eq!(record.payload, expected_payload);
        for (key, expected_value) in expected_attributes {
            assert_eq!(
                record.attributes.get(key).map(String::as_str),
                expected_value.as_str(),
                "{} attribute {key}",
                family.id()
            );
        }
    }
}

#[test]
fn cursor_and_checkpoint_are_bounded_proposals() {
    let input = OpenAiRequestInput::default();
    let page = kernel("user", "tenant-a")
        .decode(
            &input,
            200,
            br#"{"data":[{"id":"user_1","added_at":1711471533}],"has_more":true,"next":"cursor-2"}"#,
            OBSERVED_AT_MILLIS,
        )
        .expect("decode page");
    assert_eq!(
        page.records[0].event_id,
        "openai-tenant-a-0d8a96046d12-user-user_1"
    );
    assert_eq!(page.next_cursor.as_deref(), Some("cursor-2"));
    let checkpoint = page.proposed_checkpoint.expect("checkpoint proposal");
    assert_eq!(checkpoint.cursor_opaque.as_deref(), Some("cursor-2"));
    assert_eq!(checkpoint.last_provider_id.as_deref(), Some("user_1"));
    assert_eq!(checkpoint.watermark_unix_millis, 1_711_471_533_000);

    let invalid = kernel("user", "tenant-a").decode(
        &input,
        200,
        br#"{"data":[],"has_more":true}"#,
        OBSERVED_AT_MILLIS,
    );
    assert_eq!(invalid, Err(OpenAiError::InvalidCursor));
}

#[test]
fn interrupted_collection_resumes_without_identity_drift() {
    let kernel = kernel("user", "tenant-a");
    let first_input = OpenAiRequestInput::default();
    let first_body = br#"{"data":[{"id":"user_1"}],"has_more":true,"next":"cursor-2"}"#;
    let first = kernel
        .decode(&first_input, 200, first_body, OBSERVED_AT_MILLIS)
        .expect("first page");
    let resumed_input = OpenAiRequestInput {
        cursor: first.next_cursor.clone(),
        ..OpenAiRequestInput::default()
    };
    let resumed_request = kernel.plan(&resumed_input).expect("resume request");
    assert!(resumed_request.url.contains("after=cursor-2"));
    let second = kernel
        .decode(
            &resumed_input,
            200,
            br#"{"data":[{"id":"user_2"}],"has_more":false}"#,
            OBSERVED_AT_MILLIS + 1,
        )
        .expect("resumed page");
    assert_eq!(second.next_cursor, None);
    assert_eq!(
        second
            .proposed_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.cursor_opaque.as_deref()),
        None
    );
    let replayed = kernel
        .decode(&first_input, 200, first_body, OBSERVED_AT_MILLIS)
        .expect("replayed first page");
    assert_eq!(first.records[0].event_id, replayed.records[0].event_id);
    assert_ne!(first.records[0].event_id, second.records[0].event_id);
}

#[test]
fn duplicate_identity_is_idempotent_but_conflicting_content_fails_closed() {
    let input = OpenAiRequestInput::default();
    let duplicate = br#"{"data":[{"id":"user_1","role":"owner"},{"id":"user_1","role":"owner"}],"has_more":false}"#;
    let page = kernel("user", "tenant-a")
        .decode(&input, 200, duplicate, OBSERVED_AT_MILLIS)
        .expect("deduplicate equal records");
    assert_eq!(page.records.len(), 1);

    let conflict = br#"{"data":[{"id":"user_1","role":"owner"},{"id":"user_1","role":"member"}],"has_more":false}"#;
    assert_eq!(
        kernel("user", "tenant-a").decode(&input, 200, conflict, OBSERVED_AT_MILLIS),
        Err(OpenAiError::DuplicateConflict)
    );
}

#[test]
fn tenant_scope_is_trusted_and_changes_identity() {
    let input = OpenAiRequestInput {
        path_parameters: BTreeMap::from([("project_id".to_owned(), "proj_1".to_owned())]),
        ..OpenAiRequestInput::default()
    };
    let bytes = br#"{"data":[{"id":"user_1"}],"has_more":false}"#;
    let first = kernel("project_user", "tenant-a")
        .decode(&input, 200, bytes, OBSERVED_AT_MILLIS)
        .expect("tenant a");
    let second = kernel("project_user", "tenant-b")
        .decode(&input, 200, bytes, OBSERVED_AT_MILLIS)
        .expect("tenant b");
    assert_ne!(first.records[0].event_id, second.records[0].event_id);

    let contradiction = br#"{"data":[{"id":"user_1","project_id":"proj_other"}],"has_more":false}"#;
    assert_eq!(
        kernel("project_user", "tenant-a").decode(&input, 200, contradiction, OBSERVED_AT_MILLIS),
        Err(OpenAiError::TenantMismatch)
    );
}

#[test]
fn provider_payload_cannot_inject_tenant_or_credential_material() {
    let input = OpenAiRequestInput::default();
    let wrong_tenant = br#"{"data":[{"id":"user_1","tenant_id":"tenant-b"}],"has_more":false}"#;
    assert_eq!(
        kernel("user", "tenant-a").decode(&input, 200, wrong_tenant, OBSERVED_AT_MILLIS),
        Err(OpenAiError::TenantMismatch)
    );

    let credential =
        br#"{"data":[{"id":"user_1","token":"credential-material"}],"has_more":false}"#;
    let error = kernel("user", "tenant-a")
        .decode(&input, 200, credential, OBSERVED_AT_MILLIS)
        .expect_err("credential-shaped payload must fail closed");
    assert_eq!(error, OpenAiError::EventContractRejected);
    assert!(!error.to_string().contains("credential-material"));

    let key_value = br#"{"data":[{"id":"key_1","value":"credential-material"}],"has_more":false}"#;
    assert_eq!(
        kernel("api_key", "tenant-a").decode(&input, 200, key_value, OBSERVED_AT_MILLIS),
        Err(OpenAiError::EventContractRejected)
    );
}

#[test]
fn provider_statuses_remain_distinct_and_response_size_is_bounded() {
    let kernel = kernel("user", "tenant-a");
    let input = OpenAiRequestInput::default();
    for (status, expected) in [
        (401, OpenAiError::AuthenticationRejected),
        (403, OpenAiError::PermissionDenied),
        (429, OpenAiError::RateLimited),
        (503, OpenAiError::ProviderUnavailable(503)),
        (418, OpenAiError::UnexpectedStatus(418)),
    ] {
        assert_eq!(
            kernel.decode(&input, status, b"{}", OBSERVED_AT_MILLIS),
            Err(expected)
        );
    }
    let oversized = vec![b' '; (8 << 20) + 1];
    assert_eq!(
        kernel.decode(&input, 200, &oversized, OBSERVED_AT_MILLIS),
        Err(OpenAiError::ResponseTooLarge)
    );
}

fn kernel(family: &str, tenant_id: &str) -> OpenAiKernel {
    OpenAiKernel::new(
        OpenAiFamily::parse(family).expect("known family"),
        tenant_id,
    )
    .expect("valid tenant")
}

fn fixture_input(
    family: OpenAiFamily,
    attributes: &serde_json::Map<String, Value>,
) -> OpenAiRequestInput {
    let mut path_parameters = BTreeMap::new();
    for parameter in family.spec().path_parameters {
        let value = attributes
            .get(*parameter)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("{} fixture missing {parameter}", family.id()));
        path_parameters.insert((*parameter).to_owned(), value.to_owned());
    }
    OpenAiRequestInput {
        path_parameters,
        ..OpenAiRequestInput::default()
    }
}

fn read_fixture(family: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../sources/openai/testdata")
        .join(format!("read_{family}.json"));
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("decode {}: {error}", path.display()))
}
