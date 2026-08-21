use super::*;
use serde_json::json;

const DISCOVER_SERVICE_ACCOUNT_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/discover_service_account.json"
));
const READ_SERVICE_ACCOUNT_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/read_service_account.json"
));
const DISCOVER_SERVICE_ACCOUNT_KEY_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/discover_service_account_key.json"
));
const READ_SERVICE_ACCOUNT_KEY_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/gcp/testdata/read_service_account_key.json"
));
const SERVICE_ACCOUNT_EMAIL: &str = "sa@writer-prod.iam.gserviceaccount.com";
const TENANT_ID: &str = "writer-prod";
const OBSERVED_AT: &str = "2026-04-23T02:03:04.123456789+01:00";
const SERVICE_ACCOUNT_NAME: &str =
    "projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com";
const SERVICE_ACCOUNT_RESPONSE: &[u8] = br#"{
        "accounts":[{
            "name":"projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com",
            "email":"sa@writer-prod.iam.gserviceaccount.com",
            "uniqueId":"sa-1",
            "displayName":"Prod SA"
        }],
        "nextPageToken":"accounts-2"
    }"#;
const SERVICE_ACCOUNT_KEY_RESPONSE: &[u8] = br#"{
        "keys":[{
            "name":"projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys/key-1",
            "keyType":"USER_MANAGED",
            "validAfterTime":"2026-04-23T00:00:00Z"
        }],
        "nextPageToken":"keys-2"
    }"#;

fn observed_at() -> OffsetDateTime {
    OffsetDateTime::parse(OBSERVED_AT, &Rfc3339).unwrap()
}

fn account_kernel() -> GcpIamKernel {
    GcpIamKernel::new(
        "https://iam.googleapis.com",
        TENANT_ID,
        "writer-prod",
        GcpIamFamily::ServiceAccount,
        GcpIamFilters::default(),
        None,
    )
    .unwrap()
}

fn key_kernel() -> GcpIamKernel {
    GcpIamKernel::new(
        "https://iam.googleapis.com",
        TENANT_ID,
        "writer-prod",
        GcpIamFamily::ServiceAccountKey,
        GcpIamFilters {
            service_account_email: Some(SERVICE_ACCOUNT_EMAIL.to_owned()),
        },
        None,
    )
    .unwrap()
}

#[test]
fn iam_plans_exact_go_paths_auth_and_pagination() {
    let account_request = account_kernel().plan(Some("accounts-2")).unwrap();
    assert_eq!(
        account_request.url().as_str(),
        "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts?pageSize=10&pageToken=accounts-2"
    );
    assert_eq!(account_request.authorization_scheme(), "Bearer");
    assert_eq!(account_request.accept(), "application/json");
    assert!(!GcpIamKernel::requires_credentials());

    let key_request = key_kernel().plan(Some("keys-2")).unwrap();
    assert_eq!(
        key_request.url().as_str(),
        "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys?pageSize=10&pageToken=keys-2"
    );
}

#[test]
fn service_account_fields_and_identities_match_go_authority() {
    let kernel = account_kernel();
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            SERVICE_ACCOUNT_RESPONSE,
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("accounts-2"));
    let record = &page.records[0];
    assert_eq!(record.family, "service_account");
    assert_eq!(record.provider_kind, "gcp.service_account");
    assert_eq!(record.schema_ref, "gcp/service_account/v1");
    assert_eq!(record.tenant_id, TENANT_ID);
    assert_eq!(record.provider_id, SERVICE_ACCOUNT_EMAIL);
    assert_eq!(record.event_id, "gcp-service-account-sa-1");
    assert_eq!(record.occurred_at, "2026-04-23T01:03:04.123456789Z");
    assert_eq!(
        record.fields.get("domain").map(String::as_str),
        Some(TENANT_ID)
    );
    assert_eq!(
        record.fields.get("family").map(String::as_str),
        Some("service_account")
    );
    assert_eq!(
        record.fields.get("display_name").map(String::as_str),
        Some("Prod SA")
    );
    assert_eq!(
        record.fields.get("user_id").map(String::as_str),
        Some(SERVICE_ACCOUNT_EMAIL)
    );
    assert_eq!(
        record.payload["raw"].get("name").and_then(Value::as_str),
        Some(SERVICE_ACCOUNT_NAME)
    );
    assert_eq!(record.payload["project_id"], "writer-prod");
    assert_eq!(record.payload.as_object().unwrap().len(), 2);
}

#[test]
fn checked_in_service_account_fixtures_bind_kind_attributes_and_fallback_urn() {
    let expected: Value = serde_json::from_slice(READ_SERVICE_ACCOUNT_FIXTURE).unwrap();
    let expected_event = expected.as_array().unwrap().first().unwrap();
    let kernel = account_kernel();
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            SERVICE_ACCOUNT_RESPONSE,
            observed_at(),
        )
        .unwrap();
    let record = &page.records[0];
    assert_eq!(
        record.provider_kind,
        expected_event.get("kind").and_then(Value::as_str).unwrap()
    );
    let expected_attributes = expected_event.get("attributes").unwrap();
    for field in [
        "domain",
        "email",
        "family",
        "mfa_enrolled",
        "principal_type",
        "status",
        "unique_id",
        "user_id",
    ] {
        assert_eq!(
            record.fields.get(field).map(String::as_str),
            expected_attributes.get(field).and_then(Value::as_str),
            "field {field}"
        );
    }

    let fixture_urns: Vec<String> =
        serde_json::from_slice(DISCOVER_SERVICE_ACCOUNT_FIXTURE).unwrap();
    let fallback = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{"accounts":[{"uniqueId":"sa-1"}]}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(
        fixture_urns,
        vec![format!(
            "urn:cerebro:writer-prod:gcp_service_account:{}",
            fallback.records[0].provider_id
        )]
    );
}

#[test]
fn checked_in_key_fixtures_bind_identity_attributes_timestamp_and_raw_object() {
    let kernel = key_kernel();
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            SERVICE_ACCOUNT_KEY_RESPONSE,
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("keys-2"));
    let record = &page.records[0];
    let expected: Value = serde_json::from_slice(READ_SERVICE_ACCOUNT_KEY_FIXTURE).unwrap();
    let expected_event = expected.as_array().unwrap().first().unwrap();
    assert_eq!(
        record.provider_kind,
        expected_event.get("kind").and_then(Value::as_str).unwrap()
    );
    assert_eq!(record.schema_ref, "gcp/service_account_key/v1");
    assert_eq!(record.tenant_id, TENANT_ID);
    let expected_attributes = expected_event.get("attributes").unwrap();
    for field in [
        "credential_id",
        "credential_type",
        "domain",
        "event_type",
        "family",
        "resource_id",
        "resource_type",
        "status",
        "subject_email",
        "subject_id",
        "subject_type",
    ] {
        assert_eq!(
            record.fields.get(field).map(String::as_str),
            expected_attributes.get(field).and_then(Value::as_str),
            "field {field}"
        );
    }
    assert_eq!(record.occurred_at, "2026-04-23T00:00:00Z");
    assert_eq!(
        record.event_id,
        "gcp-service-account-key-projects-writer-prod-serviceAccounts-sa@writer-prod.iam.gserviceaccount.com-keys-key-1"
    );
    assert_eq!(
        record.payload["raw"].get("keyType").and_then(Value::as_str),
        Some("USER_MANAGED")
    );
    assert_eq!(record.payload["project_id"], "writer-prod");
    assert_eq!(
        record.payload["service_account_email"],
        SERVICE_ACCOUNT_EMAIL
    );
    assert_eq!(record.payload.as_object().unwrap().len(), 3);
    let fixture_urns: Vec<String> =
        serde_json::from_slice(DISCOVER_SERVICE_ACCOUNT_KEY_FIXTURE).unwrap();
    assert_eq!(
        fixture_urns,
        vec![format!(
            "urn:cerebro:writer-prod:gcp_service_account_key:{}",
            record.provider_id
        )]
    );
}

#[test]
fn service_account_key_is_config_scoped_to_one_parent_and_cursor() {
    let child_kernel = key_kernel();
    let child_page = child_kernel
        .decode(
            &child_kernel.plan(Some("keys-1")).unwrap(),
            SERVICE_ACCOUNT_KEY_RESPONSE,
            observed_at(),
        )
        .unwrap();
    assert_eq!(
        child_page.records[0].provider_id,
        format!("{SERVICE_ACCOUNT_NAME}/keys/key-1")
    );
    assert_eq!(child_page.next_cursor.as_deref(), Some("keys-2"));
    assert_eq!(
        child_kernel
            .plan(child_page.next_cursor.as_deref())
            .unwrap()
            .url()
            .as_str(),
        "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts/sa@writer-prod.iam.gserviceaccount.com/keys?pageSize=10&pageToken=keys-2"
    );
}

#[test]
fn iam_timestamp_identity_type_and_cursor_selectors_are_fail_closed() {
    let account_kernel = account_kernel();
    let account_request = account_kernel.plan(Some("  ")).unwrap();
    assert_eq!(
        account_request.url().as_str(),
        "https://iam.googleapis.com/v1/projects/writer-prod/serviceAccounts?pageSize=10"
    );
    let blank_next = account_kernel
            .decode(
                &account_request,
                br#"{"accounts":[{"email":"sa@writer-prod.iam.gserviceaccount.com"}],"nextPageToken":"  \t "}"#,
                observed_at(),
            )
            .unwrap();
    assert_eq!(blank_next.next_cursor, None);
    assert_eq!(
        blank_next.records[0].event_id,
        "gcp-service-account-sa@writer-prod.iam.gserviceaccount.com"
    );
    assert_eq!(
        account_kernel
            .decode(
                &account_kernel.plan(None).unwrap(),
                br#"{"accounts":[{"name":"projects/writer-prod/serviceAccounts/name-only"}]}"#,
                observed_at(),
            )
            .unwrap_err(),
        GcpIamError::MissingProviderIdentity
    );
    for body in [
        br#"{"accounts":[{"uniqueId":7}]}"#.as_slice(),
        br#"{"accounts":[{"email":true}]}"#.as_slice(),
        br#"{"accounts":[{"uniqueId":"sa-1","disabled":"false"}]}"#.as_slice(),
    ] {
        assert_eq!(
            account_kernel
                .decode(&account_kernel.plan(None).unwrap(), body, observed_at())
                .unwrap_err(),
            GcpIamError::InvalidResponse
        );
    }

    let key_kernel = key_kernel();
    let key_request = key_kernel.plan(None).unwrap();
    let parsed = key_kernel
            .decode(
                &key_request,
                br#"{"keys":[{"name":"key-1","validAfterTime":"2026-04-23T02:03:04.123456789+01:00"}]}"#,
                observed_at(),
            )
            .unwrap();
    assert_eq!(
        parsed.records[0].occurred_at,
        "2026-04-23T01:03:04.123456789Z"
    );
    for valid_after_time in ["", "not-rfc3339"] {
        let body = serde_json::to_vec(&json!({
            "keys": [{"name": "key-1", "validAfterTime": valid_after_time}]
        }))
        .unwrap();
        let fallback = key_kernel
            .decode(&key_request, &body, observed_at())
            .unwrap();
        assert_eq!(
            fallback.records[0].occurred_at,
            "2026-04-23T01:03:04.123456789Z"
        );
    }
    for body in [
        br#"{"keys":[{"name":false}]}"#.as_slice(),
        br#"{"keys":[{"name":"key-1","disabled":{}}]}"#.as_slice(),
    ] {
        assert_eq!(
            key_kernel
                .decode(&key_request, body, observed_at())
                .unwrap_err(),
            GcpIamError::InvalidResponse
        );
    }
}

#[test]
fn iam_fails_closed_for_config_scope_cursor_and_response_bounds() {
    assert_eq!(
        GcpIamFamily::from_str("unknown").unwrap_err(),
        GcpIamError::InvalidFamily
    );
    assert_eq!(
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            "  ",
            "writer-prod",
            GcpIamFamily::ServiceAccount,
            GcpIamFilters::default(),
            None,
        )
        .unwrap_err(),
        GcpIamError::MissingTenantId
    );
    assert_eq!(
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            TENANT_ID,
            "writer-prod",
            GcpIamFamily::ServiceAccountKey,
            GcpIamFilters::default(),
            None,
        )
        .unwrap_err(),
        GcpIamError::MissingServiceAccountEmail
    );
    assert_eq!(
        GcpIamKernel::new(
            "https://iam.googleapis.com",
            TENANT_ID,
            "writer-prod",
            GcpIamFamily::ServiceAccount,
            GcpIamFilters::default(),
            Some(201),
        )
        .unwrap_err(),
        GcpIamError::InvalidPageSize
    );
    let kernel = account_kernel();
    assert_eq!(
        kernel.plan(Some("bad\ncursor")).unwrap_err(),
        GcpIamError::InvalidCursor
    );
    assert_eq!(
        kernel
            .plan(Some(&"x".repeat(MAX_PROVIDER_CURSOR_BYTES + 1)))
            .unwrap_err(),
        GcpIamError::InvalidCursor
    );
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel
            .decode(&request, br#"[]"#, observed_at())
            .unwrap_err(),
        GcpIamError::InvalidResponse
    );
    assert_eq!(
        kernel
            .decode(&request, br#"{"accounts":[{}]}"#, observed_at())
            .unwrap_err(),
        GcpIamError::MissingProviderIdentity
    );
    assert_eq!(
        kernel
            .decode(
                &request,
                &vec![b' '; MAX_RESPONSE_BYTES.saturating_add(1)],
                observed_at(),
            )
            .unwrap_err(),
        GcpIamError::ResponseTooLarge
    );
    let too_many = serde_json::to_vec(&serde_json::json!({
        "accounts": (0..=MAX_RECORDS_PER_PAGE)
            .map(|index| serde_json::json!({"uniqueId": index.to_string()}))
            .collect::<Vec<_>>()
    }))
    .unwrap();
    assert_eq!(
        kernel
            .decode(&request, &too_many, observed_at())
            .unwrap_err(),
        GcpIamError::TooManyRecords
    );
    let key_request = key_kernel().plan(None).unwrap();
    assert_eq!(
        kernel
            .decode(&key_request, SERVICE_ACCOUNT_RESPONSE, observed_at())
            .unwrap_err(),
        GcpIamError::RequestScopeMismatch
    );
    for base_url in [
        "http://iam.googleapis.com",
        "https://user@iam.googleapis.com",
        "https://iam.googleapis.com/v1",
        "https://10.0.0.1",
    ] {
        assert_eq!(
            GcpIamKernel::new(
                base_url,
                TENANT_ID,
                "writer-prod",
                GcpIamFamily::ServiceAccount,
                GcpIamFilters::default(),
                None,
            )
            .unwrap_err(),
            GcpIamError::InvalidBaseUrl,
            "base URL {base_url}"
        );
    }
}
