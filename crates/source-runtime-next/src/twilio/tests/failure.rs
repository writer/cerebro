use std::str::FromStr;

use super::*;
use crate::twilio::response::{TEST_MAX_RECORDS_PER_PAGE, TEST_MAX_RESPONSE_BYTES};

#[test]
fn configuration_origin_cursor_and_request_scope_fail_closed() {
    assert_eq!(
        TwilioFamily::from_str("unknown").unwrap_err(),
        TwilioError::InvalidFamily
    );
    assert_eq!(
        TwilioKernel::new(
            None,
            "  ",
            TwilioFamily::Accounts,
            TwilioFilters::default(),
            None,
        )
        .unwrap_err(),
        TwilioError::MissingTenantId
    );
    assert_eq!(
        TwilioKernel::new(
            None,
            TENANT_ID,
            TwilioFamily::Keys,
            TwilioFilters::default(),
            None,
        )
        .unwrap_err(),
        TwilioError::MissingAccountSid
    );
    assert_eq!(
        TwilioKernel::new(
            None,
            TENANT_ID,
            TwilioFamily::Accounts,
            TwilioFilters::default(),
            Some(501),
        )
        .unwrap_err(),
        TwilioError::InvalidPageSize
    );
    for base_url in [
        "http://api.twilio.com",
        "https://user@api.twilio.com",
        "https://api.twilio.com/v1",
        "https://10.0.0.1",
    ] {
        assert_eq!(
            TwilioKernel::new(
                Some(base_url),
                TENANT_ID,
                TwilioFamily::Accounts,
                TwilioFilters::default(),
                None,
            )
            .unwrap_err(),
            TwilioError::InvalidBaseUrl,
            "base URL {base_url}"
        );
    }
    let accounts = kernel(TwilioFamily::Accounts);
    for cursor in ["bad\ncursor".to_owned(), "x".repeat(4_097)] {
        assert_eq!(
            accounts.plan(Some(&cursor)).unwrap_err(),
            TwilioError::InvalidCursor
        );
    }
    assert_eq!(
        accounts
            .plan(Some("https://api.twilio.com/next"))
            .unwrap_err(),
        TwilioError::InvalidCursor
    );
    let keys_request = kernel(TwilioFamily::Keys).plan(None).unwrap();
    assert_eq!(
        accounts
            .decode(&keys_request, ACCOUNTS_FIXTURE, observed_at())
            .unwrap_err(),
        TwilioError::RequestScopeMismatch
    );
}

#[test]
fn response_shape_wire_types_identity_cursor_and_bounds_fail_closed() {
    let accounts_kernel = kernel(TwilioFamily::Accounts);
    let request = accounts_kernel.plan(None).unwrap();
    for body in [
        br#"{}"#.as_slice(),
        br#"{"items":{}}"#.as_slice(),
        br#"{"items":[false]}"#.as_slice(),
        br#"{"items":[{"id":{"nested":true}}]}"#.as_slice(),
        br#"{"items":[{"id":"record-1"}],"next_cursor":{}}"#.as_slice(),
    ] {
        assert_eq!(
            accounts_kernel
                .decode(&request, body, observed_at())
                .unwrap_err(),
            TwilioError::InvalidResponse
        );
    }
    assert_eq!(
        accounts_kernel
            .decode(
                &request,
                br#"{"items":[{"name":"display-only"}]}"#,
                observed_at(),
            )
            .unwrap_err(),
        TwilioError::MissingRequiredPayloadField("id")
    );
    for (family, body) in [
        (
            TwilioFamily::Accounts,
            br#"{"items":[{"email":"user@example.test","uid":"user-1"}]}"#.as_slice(),
        ),
        (
            TwilioFamily::Keys,
            br#"{"items":[{"secret_id":"key-1","secret_name":"Key One"}]}"#.as_slice(),
        ),
        (
            TwilioFamily::AuditEvents,
            br#"{"items":[{"event_id":"event-1","event_type":"login","actor_id":"user-1"}]}"#
                .as_slice(),
        ),
    ] {
        let family_kernel = kernel(family);
        assert_eq!(
            family_kernel
                .decode(&family_kernel.plan(None).unwrap(), body, observed_at())
                .unwrap_err(),
            TwilioError::MissingRequiredPayloadField("id"),
            "family {family:?} must fail before catalog admission"
        );
    }
    assert_eq!(
        accounts_kernel
            .decode(
                &request,
                &vec![b' '; TEST_MAX_RESPONSE_BYTES + 1],
                observed_at(),
            )
            .unwrap_err(),
        TwilioError::ResponseTooLarge
    );
    let too_many = serde_json::to_vec(&json!({
        "items": (0..=TEST_MAX_RECORDS_PER_PAGE)
            .map(|index| json!({"id": index.to_string()}))
            .collect::<Vec<_>>()
    }))
    .unwrap();
    assert_eq!(
        accounts_kernel
            .decode(&request, &too_many, observed_at())
            .unwrap_err(),
        TwilioError::TooManyRecords
    );
}

#[test]
fn invalid_or_missing_provider_time_falls_back_to_observation_utc() {
    let kernel = kernel(TwilioFamily::Accounts);
    for updated_at in [Value::Null, json!("not-rfc3339"), json!(1e308)] {
        let body = serde_json::to_vec(&json!({
            "items": [{"id": "record-1", "updated_at": updated_at}]
        }))
        .unwrap();
        let page = kernel
            .decode(&kernel.plan(None).unwrap(), &body, observed_at())
            .unwrap();
        assert_eq!(
            page.records[0].occurred_at,
            "2026-06-02T02:04:05.123456789Z"
        );
    }

    for (field, value, expected) in [
        (
            "updatedAt",
            "2026-06-02T03:04:05.123+0100",
            "2026-06-02T02:04:05.123Z",
        ),
        ("timestamp", "2026-06-01", "2026-06-01T00:00:00Z"),
        ("lastCheckIn", "1760000000.25", "2025-10-09T08:53:20.25Z"),
    ] {
        let body = serde_json::to_vec(&json!({
            "items": [{"id": "record-1", (field): value}]
        }))
        .unwrap();
        let page = kernel
            .decode(&kernel.plan(None).unwrap(), &body, observed_at())
            .unwrap();
        assert_eq!(page.records[0].occurred_at, expected, "field {field}");
    }
}

#[test]
fn event_identity_aliases_and_discriminator_controls_fail_closed() {
    for tenant_id in [
        "tenant/id",
        "tenant:id",
        "tenant id",
        "tenant\tid",
        "tenant\nid",
        "tenant\0id",
        " tenant",
    ] {
        assert_eq!(
            TwilioKernel::new(
                None,
                tenant_id,
                TwilioFamily::Accounts,
                TwilioFilters::default(),
                None,
            )
            .unwrap_err(),
            TwilioError::InvalidEventIdentity,
            "tenant {tenant_id:?}"
        );
    }

    let accounts_kernel = kernel(TwilioFamily::Accounts);
    let request = accounts_kernel.plan(None).unwrap();
    for record_id in ["a/b", "a:b", "a b", "a\tb", "a\nb", "a\0b", " a-b"] {
        let body = serde_json::to_vec(&json!({"items": [{"id": record_id}]})).unwrap();
        assert_eq!(
            accounts_kernel
                .decode(&request, &body, observed_at())
                .unwrap_err(),
            TwilioError::InvalidEventIdentity,
            "record id {record_id:?}"
        );
    }
    let canonical = accounts_kernel
        .decode(&request, br#"{"items":[{"id":"a-b"}]}"#, observed_at())
        .unwrap();
    assert!(canonical.records[0].event_id.ends_with("-a-b"));

    for family in [
        TwilioFamily::Accounts,
        TwilioFamily::Keys,
        TwilioFamily::AuditEvents,
    ] {
        let family_kernel = kernel(family);
        assert_eq!(
            family_kernel
                .decode(
                    &family_kernel.plan(None).unwrap(),
                    br#"{"items":[{"id":"a/b"}]}"#,
                    observed_at(),
                )
                .unwrap_err(),
            TwilioError::InvalidEventIdentity,
            "family {family:?}"
        );
    }

    let collision_pair = br#"{"items":[
        {"id":"record-1","device_id":"alpha\u0000serial_number=beta"},
        {"id":"record-1","device_id":"alpha","serial_number":"beta"}
    ]}"#;
    assert_eq!(
        accounts_kernel
            .decode(&request, collision_pair, observed_at())
            .unwrap_err(),
        TwilioError::InvalidEventIdentity
    );
    for body in [
        br#"{"items":[{"id":"record-1","device":{"id":"bad\u0000id"}}]}"#.as_slice(),
        br#"{"items":[{"id":"record-1","agent":{"uuid":"bad\u001fuuid"}}]}"#.as_slice(),
    ] {
        assert_eq!(
            accounts_kernel
                .decode(&request, body, observed_at())
                .unwrap_err(),
            TwilioError::InvalidEventIdentity
        );
    }
}

#[test]
fn conflicting_duplicate_provider_identities_fail_closed() {
    let kernel = kernel(TwilioFamily::Accounts);
    assert_eq!(
        kernel
            .decode(
                &kernel.plan(None).unwrap(),
                br#"{"items":[
                    {"id":"record-1","name":"First"},
                    {"id":"record-1","name":"Different"}
                ]}"#,
                observed_at(),
            )
            .unwrap_err(),
        TwilioError::ConflictingProviderIdentity
    );
}

#[test]
fn go_identity_discriminators_prevent_version_aliases_before_dedupe() {
    let kernel = kernel(TwilioFamily::Accounts);
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{"items":[
                {"id":"record-1","version":"v1"},
                {"id":"record-1","version":"v2"},
                {"id":"record-1","version":"v1"},
                {"id":"record-1","device":{"id":"device-1"}}
            ]}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.records.len(), 3);
    assert_eq!(
        page.records
            .iter()
            .map(|record| record.provider_id.as_str())
            .collect::<Vec<_>>(),
        [
            "record-1-806dcf595db8eaaf80f8a39a",
            "record-1-60eacac4769c93003b2fdb27",
            "record-1-690d2beaf4627ca31ca6d500",
        ]
    );
    for record in &page.records {
        assert_eq!(record.fields["external_id"], "record-1");
        assert_eq!(record.fields["source_event_id"], "record-1");
        assert!(record.event_id.ends_with(&record.provider_id));
    }
}
