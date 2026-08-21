use super::*;

#[test]
fn checked_in_accounts_fixture_binds_catalog_fields_payload_identity_and_time() {
    let kernel = kernel(TwilioFamily::Accounts);
    let page = kernel
        .decode(&kernel.plan(None).unwrap(), ACCOUNTS_FIXTURE, observed_at())
        .unwrap();
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record.family, "accounts");
    assert_eq!(record.provider_kind, "twilio.accounts");
    assert_eq!(record.schema_ref, "twilio/accounts/v1");
    assert_eq!(record.tenant_id, TENANT_ID);
    assert_eq!(record.provider_id, "record-1");
    assert_eq!(
        record.event_id,
        "twilio-tenant-a92380b4993d-accounts-record-1"
    );
    assert_eq!(record.occurred_at, "2026-06-01T00:00:00Z");
    for (name, value) in [
        ("external_id", "record-1"),
        ("family", "accounts"),
        ("provider", "twilio"),
        ("record_class", "identity_user"),
        ("schema", "accounts"),
        ("source_event_id", "record-1"),
        ("source_system", "twilio"),
        ("tenant_id", TENANT_ID),
        ("user_id", "record-1"),
    ] {
        assert_eq!(record.fields.get(name).map(String::as_str), Some(value));
    }
    assert_eq!(record.fields["evidence_cas_digest"], "sha256:test");
    assert_eq!(record.payload["id"], "record-1");
    assert_eq!(record.payload["name"], "Record One");
    assert_eq!(record.payload.as_object().unwrap().len(), 8);
}

#[test]
fn accounts_follow_go_selector_and_nested_attribute_precedence() {
    let kernel = kernel(TwilioFamily::Accounts);
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{"accounts":[{
                "id":"record-2",
                "event_id":"provider-event-2",
                "email":"user@example.test",
                "user_id":"user-1",
                "uid":"user-1",
                "profile":{"display_name":"Profile Name","department":"Security"},
                "metadata":{"resource_id":"resource-1","resource_name":"Metadata Resource"}
            }]}"#,
            observed_at(),
        )
        .unwrap();
    let record = &page.records[0];
    assert_eq!(record.provider_id, "record-2");
    assert_eq!(record.fields["display_name"], "Profile Name");
    assert_eq!(record.fields["department"], "Security");
    assert_eq!(record.fields["resource_id"], "record-2");
    assert_eq!(record.fields["resource_name"], "Metadata Resource");
    assert_eq!(record.fields["source_event_id"], "provider-event-2");
    assert_eq!(record.fields["user_id"], "user-1");
}
