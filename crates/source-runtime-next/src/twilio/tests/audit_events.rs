use super::*;

#[test]
fn audit_events_bind_nested_actor_resource_catalog_fields_and_timestamp() {
    let kernel = kernel(TwilioFamily::AuditEvents);
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{"audit_events":[{
                "id":"evt-1",
                "action":"user.login",
                "actor":{"id":"user-1","email":"user@example.test","name":"User One"},
                "target":{"id":"app-1","name":"Application One","type":"application"},
                "created_at":"2026-06-01T00:00:00Z"
            }]}"#,
            observed_at(),
        )
        .unwrap();
    let record = &page.records[0];
    assert_eq!(record.provider_kind, "twilio.audit_events");
    assert_eq!(record.schema_ref, "twilio/audit_events/v1");
    assert_eq!(record.provider_id, "evt-1");
    assert_eq!(
        record.event_id,
        "twilio-tenant-8a1703761e9e-audit_events-evt-1"
    );
    assert_eq!(record.occurred_at, "2026-06-01T00:00:00Z");
    for (name, value) in [
        ("actor_email", "user@example.test"),
        ("actor_id", "user-1"),
        ("actor_name", "User One"),
        ("event_type", "user.login"),
        ("record_class", "audit_event"),
        ("resource_id", "app-1"),
        ("resource_name", "Application One"),
        ("resource_type", "application"),
        ("source_event_id", "evt-1"),
        ("tenant_id", TENANT_ID),
    ] {
        assert_eq!(record.fields.get(name).map(String::as_str), Some(value));
    }
    assert_eq!(record.payload["actor"]["id"], "user-1");
}

#[test]
fn audit_events_fail_closed_without_catalog_actor_or_event_type() {
    let kernel = kernel(TwilioFamily::AuditEvents);
    for (body, error) in [
        (
            br#"{"audit_events":[{"id":"evt-1","action":"login"}]}"#.as_slice(),
            TwilioError::MissingRequiredAttribute("actor_id"),
        ),
        (
            br#"{"audit_events":[{"id":"evt-1","actor_id":"user-1"}]}"#.as_slice(),
            TwilioError::MissingRequiredAttribute("event_type"),
        ),
    ] {
        assert_eq!(
            kernel
                .decode(&kernel.plan(None).unwrap(), body, observed_at())
                .unwrap_err(),
            error
        );
    }
}
