use super::*;

#[test]
fn keys_bind_config_parent_catalog_fields_scalar_values_and_raw_object() {
    let kernel = kernel(TwilioFamily::Keys);
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{
                "keys":[{
                    "id":"key-1",
                    "name":"Primary key",
                    "type":"api_key",
                    "status":"active",
                    "rotation_enabled":true,
                    "updated_at":"2026-06-01T01:02:03.123456789+01:00"
                }],
                "nextCursor":"keys-2"
            }"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("keys-2"));
    let record = &page.records[0];
    assert_eq!(record.provider_kind, "twilio.keys");
    assert_eq!(record.schema_ref, "twilio/keys/v1");
    assert_eq!(record.provider_id, "key-1");
    assert_eq!(record.event_id, "twilio-tenant-ada263abb3a3-keys-key-1");
    assert_eq!(record.occurred_at, "2026-06-01T00:02:03.123456789Z");
    for (name, value) in [
        ("record_class", "secret"),
        ("secret_id", "key-1"),
        ("secret_name", "Primary key"),
        ("secret_rotation_enabled", "true"),
        ("secret_status", "active"),
        ("secret_type", "api_key"),
        ("source_event_id", "key-1"),
        ("tenant_id", TENANT_ID),
    ] {
        assert_eq!(record.fields.get(name).map(String::as_str), Some(value));
    }
    assert_eq!(record.payload["rotation_enabled"], true);
}

#[test]
fn keys_reject_records_that_cannot_meet_catalog_secret_name() {
    let kernel = kernel(TwilioFamily::Keys);
    assert_eq!(
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                br#"{"keys":[{"id":"SK123"}]}"#,
                observed_at(),
            )
            .unwrap_err(),
        TwilioError::MissingRequiredAttribute("secret_name")
    );
}

#[test]
fn keys_match_go_hostname_and_distinct_type_kind_precedence() {
    let kernel = kernel(TwilioFamily::Keys);
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{"keys":[{
                "id":"key-2",
                "secret_name":"Key Two",
                "hostname":"keys.example.test",
                "type":"provider-type",
                "kind":"provider-kind"
            }]}"#,
            observed_at(),
        )
        .unwrap();
    let fields = &page.records[0].fields;
    assert_eq!(fields["resource_name"], "keys.example.test");
    assert_eq!(fields["resource_type"], "provider-type");
    assert_eq!(fields["secret_type"], "provider-type");
}
