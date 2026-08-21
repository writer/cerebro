use super::*;

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
