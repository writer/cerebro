use super::*;

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
