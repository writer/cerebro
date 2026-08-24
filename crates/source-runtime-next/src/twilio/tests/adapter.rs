use super::*;
use crate::twilio::adapter::{TwilioFamilyAdapter, TwilioFamilyAdapterError};

const SOURCE_WORKER_ACCOUNTS_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/twilio/testdata/source_worker_accounts_page.json"
));

#[test]
fn accounts_adapter_plans_credential_free_bounded_cursor_request() {
    let adapter = TwilioFamilyAdapter::new(
        TwilioFamilyAdapter::default_origin(),
        TENANT_ID,
        TwilioFamily::Accounts,
    )
    .expect("authenticated execution scope");
    let request = adapter.plan(Some("accounts-page-1")).unwrap();

    assert_eq!(TwilioFamilyAdapter::source_id(), "twilio");
    assert_eq!(adapter.family_id(), "accounts");
    assert_eq!(adapter.provider_kernel(), "twilio.accounts");
    assert_eq!(adapter.path(), "/2010-04-01/Accounts.json");
    assert_eq!(TwilioFamilyAdapter::max_response_bytes(), 8 << 20);
    assert_eq!(TwilioFamilyAdapter::credential_operation(), "twilio.basic");
    assert_eq!(TwilioFamilyAdapter::credential_scheme(), "Basic");
    assert_eq!(request.authorization_scheme(), "Basic");
    assert_eq!(request.accept(), "application/json");
    assert_eq!(
        request.url().as_str(),
        "https://api.twilio.com/2010-04-01/Accounts.json?limit=100&cursor=accounts-page-1"
    );
    assert!(!request.url().as_str().contains("credential"));
    assert!(!request.url().as_str().contains("token"));
    assert_eq!(
        adapter.plan(Some(" accounts-page-1")).unwrap_err(),
        TwilioFamilyAdapterError::Kernel(TwilioError::InvalidCursor)
    );
}

#[test]
fn accounts_adapter_decodes_fixture_with_stable_tenant_identity_dedupe_and_cursor() {
    let adapter = TwilioFamilyAdapter::new(
        TwilioFamilyAdapter::default_origin(),
        TENANT_ID,
        TwilioFamily::Accounts,
    )
    .expect("authenticated execution scope");
    let page = adapter
        .decode(
            Some("accounts-page-1"),
            200,
            SOURCE_WORKER_ACCOUNTS_FIXTURE,
            observed_at(),
        )
        .unwrap();

    assert_eq!(page.next_cursor.as_deref(), Some("accounts-page-2"));
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record.tenant_id, TENANT_ID);
    assert_eq!(record.provider_id, "record-1");
    assert_eq!(
        record.event_id,
        "twilio-tenant-a92380b4993d-accounts-record-1"
    );
    assert_eq!(record.occurred_at, "2026-06-01T00:00:00Z");
    assert_eq!(record.fields["tenant_id"], TENANT_ID);
    assert_eq!(record.fields["source_event_id"], "provider-event-1");
    assert_eq!(record.fields["user_id"], "record-1");
    assert_eq!(record.payload["id"], "record-1");
}

#[test]
fn accounts_adapter_never_derives_tenant_from_provider_payload() {
    let adapter = TwilioFamilyAdapter::new(
        TwilioFamilyAdapter::default_origin(),
        TENANT_ID,
        TwilioFamily::Accounts,
    )
    .expect("authenticated execution scope");
    let page = adapter
        .decode(
            None,
            200,
            br#"{"data":[{"id":"record-1","tenant_id":"provider-tenant","metadata":{"tenant_id":"provider-metadata-tenant"}}]}"#,
            observed_at(),
        )
        .unwrap();
    let record = &page.records[0];

    assert_eq!(record.tenant_id, TENANT_ID);
    assert_eq!(record.fields["tenant_id"], TENANT_ID);
    assert_eq!(
        record.event_id,
        "twilio-tenant-a92380b4993d-accounts-record-1"
    );
    assert_eq!(record.payload["tenant_id"], "provider-tenant");
}

#[test]
fn accounts_adapter_maps_provider_statuses_without_response_data() {
    let adapter = TwilioFamilyAdapter::new(
        TwilioFamilyAdapter::default_origin(),
        TENANT_ID,
        TwilioFamily::Accounts,
    )
    .expect("authenticated execution scope");
    for (status, expected, retryable, action) in [
        (
            401,
            TwilioFamilyAdapterError::AuthenticationRejected,
            false,
            "repair credential binding",
        ),
        (
            403,
            TwilioFamilyAdapterError::RequiredScopeMissing,
            false,
            "grant required provider scope",
        ),
        (
            408,
            TwilioFamilyAdapterError::ProviderTimeout,
            true,
            "retry later",
        ),
        (
            429,
            TwilioFamilyAdapterError::RateLimited,
            true,
            "retry later",
        ),
        (
            503,
            TwilioFamilyAdapterError::ProviderUnavailable,
            true,
            "retry later",
        ),
        (
            418,
            TwilioFamilyAdapterError::UnexpectedStatus(418),
            false,
            "inspect provider status",
        ),
    ] {
        let error = adapter
            .decode(
                None,
                status,
                b"provider body must not enter the error",
                observed_at(),
            )
            .unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(error.retryable(), retryable);
        assert_eq!(error.operator_action(), action);
        assert!(!error.to_string().contains("provider body"));
    }
}
