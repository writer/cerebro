use super::*;

#[test]
fn plans_exact_go_paths_pagination_and_credential_free_basic_auth() {
    let accounts = kernel(TwilioFamily::Accounts);
    let request = accounts.plan(Some("accounts-2")).unwrap();
    assert_eq!(
        request.url().as_str(),
        "https://api.twilio.com/2010-04-01/Accounts.json?limit=100&cursor=accounts-2"
    );
    assert_eq!(request.authorization_scheme(), "Basic");
    assert_eq!(request.accept(), "application/json");
    assert!(!TwilioKernel::requires_credentials());

    let keys = kernel(TwilioFamily::Keys).plan(Some("keys-2")).unwrap();
    assert_eq!(
        keys.url().as_str(),
        "https://api.twilio.com/2010-04-01/Accounts/AC123/Keys.json?limit=100&cursor=keys-2"
    );
    let events = kernel(TwilioFamily::AuditEvents)
        .plan(Some("events-2"))
        .unwrap();
    assert_eq!(
        events.url().as_str(),
        "https://api.twilio.com/v1/Events?limit=100&cursor=events-2"
    );
    assert_eq!(
        accounts.plan(Some(" \t ")).unwrap().url().as_str(),
        "https://api.twilio.com/2010-04-01/Accounts.json?limit=100"
    );
}

#[test]
fn decodes_bounded_provider_cursor_and_deduplicates_in_provider_order() {
    let kernel = kernel(TwilioFamily::Accounts);
    let page = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{
                "data":[
                    {"id":"record-1","name":"First","updated_at":"2026-06-01T00:00:00Z"},
                    {"id":"record-1","name":"Duplicate","updated_at":"2026-06-01T00:00:00Z"}
                ],
                "pagination":{"next_cursor":"accounts-2"}
            }"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.records[0].fields["display_name"], "First");
    assert_eq!(page.next_cursor.as_deref(), Some("accounts-2"));

    let later_cursor = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{"items":[{"id":"record-2"}],"next_cursor":"  ","cursor":"accounts-3"}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(later_cursor.next_cursor.as_deref(), Some("accounts-3"));

    let relative_cursor = kernel
        .decode(
            &kernel.plan(None).unwrap(),
            br#"{"items":[{"id":"record-3"}],"next":"/v1/Events?cursor=accounts-4&limit=100"}"#,
            observed_at(),
        )
        .unwrap();
    assert_eq!(relative_cursor.next_cursor.as_deref(), Some("accounts-4"));
}
