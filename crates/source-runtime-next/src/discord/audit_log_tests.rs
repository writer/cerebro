use super::wire::MAX_RESPONSE_BYTES;
use super::*;

const TENANT_ID: &str = "tenant";
const GUILD_ID: &str = "100000000000000000";
const AUDIT_DUPLICATE_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/discord/testdata/read_audit_log_duplicates.json"
));

fn audit_kernel(tenant_id: &str, page_size: usize) -> DiscordKernel {
    DiscordKernel::new(
        "https://discord.com/api/v10",
        tenant_id,
        GUILD_ID,
        None,
        DiscordFamily::AuditLog,
        Some(page_size),
    )
    .unwrap()
}

#[test]
fn request_plan_is_credential_free_origin_bound_and_round_trippable() {
    let kernel = audit_kernel(TENANT_ID, 2);
    let first = kernel.plan(None).unwrap();
    assert_eq!(
        first.url().as_str(),
        "https://discord.com/api/v10/guilds/100000000000000000/audit-logs?after=0&limit=2"
    );
    assert_eq!(first.method(), "GET");
    assert_eq!(first.authorization_header(), "Authorization");
    assert_eq!(first.authorization_scheme(), "Bot");
    assert_eq!(first.required_permission(), Some("VIEW_AUDIT_LOG"));
    assert_eq!(first.accept(), "application/json");
    assert_eq!(first.max_response_bytes(), MAX_RESPONSE_BYTES);
    assert!(!first.contains_credentials());
    assert!(!first.allows_redirects());

    let resumed = kernel.plan(Some("100000000000000002")).unwrap();
    assert_eq!(
        resumed.url().query(),
        Some("after=100000000000000002&limit=2")
    );
    assert_eq!(kernel.plan(Some("0")), Err(DiscordError::InvalidCursor));
}

#[test]
fn normalized_identity_timestamp_and_tenant_match_go_contract() {
    let kernel = audit_kernel(TENANT_ID, 2);
    let request = kernel.plan(None).unwrap();
    let page = kernel
        .decode(
            &request,
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../sources/discord/testdata/read_audit_log.json"
            )),
        )
        .unwrap();
    let first = &page.records[0];
    assert_eq!(first.tenant_id, TENANT_ID);
    assert_eq!(
        first.event_id,
        "discord-tenant-f8ac972d2bb0-audit_log-100000000000000001"
    );
    assert_eq!(first.occurred_at_unix_millis, 1_443_912_257_910);
    assert_eq!(first.source_id, "discord");
    assert_eq!(first.provider_kind, "discord.audit_log");
    assert_eq!(first.schema_ref, "discord/audit_log/v1");
    assert_eq!(first.fields["external_id"], first.provider_id);
    assert_eq!(first.fields["guild_id"], GUILD_ID);
    assert_eq!(first.fields["record_class"], "audit_event");
    assert_eq!(first.fields["schema"], "audit_log");
    assert_eq!(first.fields["source_system"], "discord");
    assert!(!first.fields.contains_key("tenant_id"));
    assert!(!first.fields.contains_key("event_id"));
    assert!(!first.fields.contains_key("reason"));
    assert_eq!(page.next_cursor.as_deref(), Some("100000000000000002"));

    let other_kernel = audit_kernel("tenant-b", 2);
    assert_eq!(
        other_kernel.decode(&request, b"{}"),
        Err(DiscordError::RequestScopeMismatch)
    );
    let other_tenant = other_kernel
        .decode(
            &other_kernel.plan(None).unwrap(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../sources/discord/testdata/read_audit_log.json"
            )),
        )
        .unwrap();
    assert_ne!(first.event_id, other_tenant.records[0].event_id);
}

#[test]
fn identical_duplicates_collapse_without_losing_full_page_cursor() {
    let kernel = audit_kernel(TENANT_ID, 3);
    let request = kernel.plan(None).unwrap();
    let page = kernel.decode(&request, AUDIT_DUPLICATE_FIXTURE).unwrap();
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.next_cursor.as_deref(), Some("100000000000000002"));
}

#[test]
fn conflicting_duplicates_fail_closed() {
    let kernel = audit_kernel(TENANT_ID, 2);
    let request = kernel.plan(None).unwrap();
    let body = br#"{"audit_log_entries":[
        {"id":"100000000000000001","user_id":null,"action_type":10,"target_id":null},
        {"id":"100000000000000001","user_id":null,"action_type":20,"target_id":null}
    ]}"#;
    assert_eq!(
        kernel.decode(&request, body),
        Err(DiscordError::ConflictingDuplicate)
    );
}

#[test]
fn provider_payload_cannot_override_authenticated_tenant() {
    let kernel = audit_kernel(TENANT_ID, 1);
    let request = kernel.plan(None).unwrap();
    let body = br#"{"audit_log_entries":[
        {"id":"100000000000000001","user_id":null,"action_type":10,"target_id":null,"tenant_id":"attacker"}
    ]}"#;
    assert_eq!(
        kernel.decode(&request, body),
        Err(DiscordError::InvalidRecord)
    );
}

#[test]
fn provider_statuses_are_typed_and_retry_after_is_bounded() {
    let kernel = audit_kernel(TENANT_ID, 2);
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode_http(&request, 401, None, b"ignored"),
        Err(DiscordError::AuthenticationRejected)
    );
    assert_eq!(
        kernel.decode_http(&request, 403, None, b"ignored"),
        Err(DiscordError::RequiredScopeMissing)
    );
    assert_eq!(
        kernel.decode_http(&request, 429, Some(30), b"ignored"),
        Err(DiscordError::RateLimited {
            retry_after_seconds: Some(30)
        })
    );
    assert_eq!(
        kernel.decode_http(&request, 429, Some(3_601), b"ignored"),
        Err(DiscordError::InvalidRetryAfter)
    );
    assert_eq!(
        kernel.decode_http(&request, 503, None, b"ignored"),
        Err(DiscordError::ProviderUnavailable { status: 503 })
    );
    assert_eq!(
        kernel.decode_http(&request, 302, None, b"ignored"),
        Err(DiscordError::UnexpectedStatus { status: 302 })
    );
}

#[test]
fn unsafe_origins_and_tenants_are_rejected_before_planning() {
    for base_url in [
        "https://localhost/api/v10",
        "https://discord.com:444/api/v10",
        "https://192.0.2.1/api/v10",
        "https://[2001:db8::1]/api/v10",
    ] {
        assert!(
            DiscordKernel::new(
                base_url,
                TENANT_ID,
                GUILD_ID,
                None,
                DiscordFamily::AuditLog,
                Some(2),
            )
            .is_err()
        );
    }
    assert!(matches!(
        DiscordKernel::new(
            "https://discord.com/api/v10",
            "\n",
            GUILD_ID,
            None,
            DiscordFamily::AuditLog,
            Some(2),
        ),
        Err(DiscordError::InvalidTenantId)
    ));
}
