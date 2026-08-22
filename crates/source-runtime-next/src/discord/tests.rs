use super::*;
use super::{
    normalize::{MAX_COMMAND_PERMISSION_ENTRIES, MAX_MEMBER_ROLES},
    wire::{MAX_NONPAGED_RECORDS, MAX_RESPONSE_BYTES},
};
use serde_json::Value;

const AUDIT_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/discord/testdata/read_audit_log.json"
));
const MEMBER_FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../sources/discord/testdata/read_member.json"
));
const GUILD_ID: &str = "100000000000000000";
const APPLICATION_ID: &str = "200000000000000000";
const TENANT_ID: &str = "tenant";

fn kernel(family: DiscordFamily, page_size: Option<usize>) -> DiscordKernel {
    DiscordKernel::new(
        "https://discord.com/api/v10",
        TENANT_ID,
        GUILD_ID,
        Some(APPLICATION_ID),
        family,
        page_size,
    )
    .unwrap()
}

#[test]
fn families_plan_exact_paths_and_bot_auth_contract() {
    let cases = [
        (
            DiscordFamily::AuditLog,
            "/api/v10/guilds/100000000000000000/audit-logs",
            Some(2),
        ),
        (
            DiscordFamily::Member,
            "/api/v10/guilds/100000000000000000/members",
            Some(2),
        ),
        (
            DiscordFamily::Role,
            "/api/v10/guilds/100000000000000000/roles",
            None,
        ),
        (
            DiscordFamily::Permission,
            "/api/v10/applications/200000000000000000/guilds/100000000000000000/commands/permissions",
            None,
        ),
    ];
    for (family, path, page_size) in cases {
        let request = kernel(family, page_size).plan(None).unwrap();
        assert_eq!(request.url().path(), path);
        assert_eq!(request.authorization_scheme(), "Bot");
        assert_eq!(request.accept(), "application/json");
        assert_eq!(
            family.provider_kind(),
            format!("discord.{}", family.as_str())
        );
        if page_size.is_some() {
            assert_eq!(request.url().query(), Some("after=0&limit=2"));
        } else {
            assert_eq!(request.url().query(), None);
        }
    }
}

#[test]
fn normalized_audit_fixture_decodes_envelope_fields_and_cursor() {
    let kernel = kernel(DiscordFamily::AuditLog, Some(2));
    let request = kernel.plan(None).unwrap();
    let page = kernel.decode(&request, AUDIT_FIXTURE).unwrap();
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].provider_kind, "discord.audit_log");
    assert_eq!(page.records[0].fields["event_type"], "10");
    assert_eq!(page.records[0].fields["actor_id"], "400000000000000001");
    assert_eq!(page.records[0].fields["resource_id"], "300000000000000001");
    assert_eq!(page.next_cursor.as_deref(), Some("100000000000000002"));
}

#[test]
fn normalized_member_fixture_decodes_raw_array_and_nested_user_cursor() {
    let kernel = kernel(DiscordFamily::Member, Some(2));
    let request = kernel.plan(None).unwrap();
    let page = kernel.decode(&request, MEMBER_FIXTURE).unwrap();
    assert_eq!(page.records.len(), 2);
    assert_eq!(page.records[0].provider_kind, "discord.member");
    assert_eq!(page.records[0].fields["user_id"], "100000000000000001");
    assert_eq!(page.records[0].fields["display_name"], "Member One");
    assert_eq!(page.records[0].fields["avatar"], "normalized-avatar-one");
    assert_eq!(page.records[0].fields["roles"], "500000000000000001");
    assert_eq!(page.records[0].fields["deaf"], "false");
    assert_eq!(page.records[1].fields["login"], "member-two");
    assert_eq!(page.next_cursor.as_deref(), Some("100000000000000002"));
}

#[test]
fn partial_pages_are_terminal_and_resume_after_highest_id() {
    let kernel = kernel(DiscordFamily::Member, Some(2));
    let request = kernel.plan(Some("100000000000000002")).unwrap();
    assert_eq!(
        request.url().query(),
        Some("after=100000000000000002&limit=2")
    );
    let page = kernel
            .decode(
                &request,
                br#"[{"user":{"id":"100000000000000003","username":"member-three"},"joined_at":"2026-06-03T00:00:00Z","deaf":false,"mute":false,"roles":[]}]"#,
            )
            .unwrap();
    assert_eq!(page.records.len(), 1);
    assert_eq!(page.next_cursor, None);
}

#[test]
fn nonpaged_envelopes_normalize_roles_and_permissions() {
    let role_kernel = kernel(DiscordFamily::Role, None);
    let role_request = role_kernel.plan(None).unwrap();
    let roles = role_kernel
        .decode(
            &role_request,
            br#"[{"id":"500000000000000001","name":"operator","permissions":"8"}]"#,
        )
        .unwrap();
    assert_eq!(roles.records[0].fields["group_name"], "operator");
    assert_eq!(roles.next_cursor, None);

    let permission_kernel = kernel(DiscordFamily::Permission, None);
    let permission_request = permission_kernel.plan(None).unwrap();
    let permissions = permission_kernel
            .decode(
                &permission_request,
                br#"[{"id":"600000000000000001","application_id":"200000000000000000","guild_id":"100000000000000000","permissions":[]}]"#,
            )
            .unwrap();
    assert_eq!(permissions.records[0].fields["resource_type"], "permission");
    assert_eq!(
        permissions.records[0].fields["resource_name"],
        APPLICATION_ID
    );
    let mismatched_scope = br#"[{"id":"600000000000000001","application_id":"200000000000000009","guild_id":"100000000000000000","permissions":[]}]"#;
    assert_eq!(
        permission_kernel.decode(&permission_request, mismatched_scope),
        Err(DiscordError::RequestScopeMismatch)
    );
}

#[test]
fn kernel_rejects_unsafe_scope_invalid_bounds_and_wrong_envelopes() {
    assert!(matches!(
        DiscordKernel::new(
            "http://discord.com/api/v10",
            TENANT_ID,
            GUILD_ID,
            None,
            DiscordFamily::Member,
            Some(2)
        ),
        Err(DiscordError::InvalidBaseUrl)
    ));
    assert!(matches!(
        DiscordKernel::new(
            "https://127.0.0.1",
            TENANT_ID,
            GUILD_ID,
            None,
            DiscordFamily::Member,
            Some(2)
        ),
        Err(DiscordError::UnsafeOrigin)
    ));
    assert!(matches!(
        DiscordKernel::new(
            "https://discord.com/api/v10",
            TENANT_ID,
            "guild",
            None,
            DiscordFamily::Member,
            Some(2)
        ),
        Err(DiscordError::InvalidGuildId)
    ));
    assert!(matches!(
        DiscordKernel::new(
            "https://discord.com/api/v10",
            TENANT_ID,
            GUILD_ID,
            None,
            DiscordFamily::Permission,
            None
        ),
        Err(DiscordError::MissingApplicationId)
    ));
    assert!(matches!(
        DiscordKernel::new(
            "https://discord.com/api/v10",
            TENANT_ID,
            GUILD_ID,
            None,
            DiscordFamily::AuditLog,
            Some(101)
        ),
        Err(DiscordError::InvalidPageSize)
    ));
    assert_eq!(
        kernel(DiscordFamily::Role, None).plan(Some("1")),
        Err(DiscordError::UnsupportedCursor)
    );
    assert_eq!(
        kernel(DiscordFamily::Member, Some(2)).plan(Some("not-a-snowflake")),
        Err(DiscordError::InvalidCursor)
    );
    let audit_kernel = kernel(DiscordFamily::AuditLog, Some(2));
    let audit_request = audit_kernel.plan(None).unwrap();
    assert_eq!(
        audit_kernel.decode(&audit_request, br#"[{"id":"100000000000000001"}]"#),
        Err(DiscordError::InvalidResponse)
    );
    assert_eq!(
        audit_kernel.decode(&audit_request, br#"{"items":[]}"#),
        Err(DiscordError::InvalidResponse)
    );
    for family in [
        DiscordFamily::Member,
        DiscordFamily::Role,
        DiscordFamily::Permission,
    ] {
        let kernel = kernel(family, matches!(family, DiscordFamily::Member).then_some(2));
        let request = kernel.plan(None).unwrap();
        assert_eq!(
            kernel.decode(&request, br#"{"items":[]}"#),
            Err(DiscordError::InvalidResponse)
        );
    }
    assert_eq!(
        kernel(DiscordFamily::Member, Some(2)).decode(&audit_request, MEMBER_FIXTURE),
        Err(DiscordError::RequestScopeMismatch)
    );
}

#[test]
fn paged_contract_rejects_missing_ids_and_wrong_scalar_types() {
    let kernel = kernel(DiscordFamily::Member, Some(2));
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode(&request, br#"[{"user":{"username":"missing-id"}}]"#),
        Err(DiscordError::InvalidRecord)
    );
    assert_eq!(
            kernel.decode(
                &request,
                br#"[{"user":{"id":100000000000000001,"username":"number-id"},"joined_at":"2026-06-01T00:00:00Z","deaf":false,"mute":false,"roles":[]}]"#,
            ),
            Err(DiscordError::InvalidRecord)
        );
    assert_eq!(
            kernel.decode(
                &request,
                br#"[{"user":{"id":"100000000000000001","username":"leak"},"joined_at":"2026-06-01T00:00:00Z","deaf":false,"mute":false,"roles":[],"access_token":"redacted-fixture-value"}]"#,
            ),
            Err(DiscordError::CredentialMaterial)
        );
}

#[test]
fn member_full_page_uses_numeric_maximum_without_order_assumption() {
    let kernel = kernel(DiscordFamily::Member, Some(2));
    let request = kernel.plan(None).unwrap();
    let page = kernel
            .decode(
                &request,
                br#"[
                    {"user":{"id":"100000000000000009","username":"later"},"joined_at":"2026-06-09T00:00:00Z","deaf":false,"mute":false,"roles":[]},
                    {"user":{"id":"100000000000000003","username":"earlier"},"joined_at":"2026-06-03T00:00:00Z","deaf":false,"mute":false,"roles":[]}
                ]"#,
            )
            .unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("100000000000000009"));
}

#[test]
fn audit_after_page_requires_strictly_ascending_entry_ids() {
    let kernel = kernel(DiscordFamily::AuditLog, Some(2));
    let request = kernel.plan(None).unwrap();
    assert_eq!(
        kernel.decode(
            &request,
            br#"{"audit_log_entries":[
                    {"id":"100000000000000002","user_id":null,"action_type":10,"target_id":null},
                    {"id":"100000000000000001","user_id":null,"action_type":10,"target_id":null}
                ]}"#,
        ),
        Err(DiscordError::InvalidPageOrder)
    );
}

#[test]
fn audit_contract_rejects_field_specific_scalar_mismatches() {
    let kernel = kernel(DiscordFamily::AuditLog, Some(2));
    let request = kernel.plan(None).unwrap();
    let invalid_records = [
        serde_json::json!({"id":1,"user_id":null,"action_type":10,"target_id":null}),
        serde_json::json!({"id":"100000000000000001","user_id":1,"action_type":10,"target_id":null}),
        serde_json::json!({"id":"100000000000000001","user_id":null,"action_type":"10","target_id":null}),
        serde_json::json!({"id":"100000000000000001","user_id":null,"action_type":10,"target_id":1}),
    ];
    for record in invalid_records {
        let body = serde_json::to_vec(&serde_json::json!({
            "audit_log_entries":[record]
        }))
        .unwrap();
        assert_eq!(
            kernel.decode(&request, &body),
            Err(DiscordError::InvalidRecord)
        );
    }
}

#[test]
fn top_level_and_nested_record_counts_are_bounded() {
    let roles = vec![
        serde_json::json!({"id":"500000000000000001","name":"role","permissions":"0"});
        MAX_NONPAGED_RECORDS + 1
    ];
    let role_kernel = kernel(DiscordFamily::Role, None);
    let role_request = role_kernel.plan(None).unwrap();
    assert_eq!(
        role_kernel.decode(&role_request, &serde_json::to_vec(&roles).unwrap()),
        Err(DiscordError::TooManyRecords)
    );

    let permission_kernel = kernel(DiscordFamily::Permission, None);
    let permission_request = permission_kernel.plan(None).unwrap();
    let permission_records = vec![
        serde_json::json!({
            "id":"600000000000000001",
            "application_id":APPLICATION_ID,
            "guild_id":GUILD_ID,
            "permissions":[]
        });
        MAX_NONPAGED_RECORDS + 1
    ];
    assert_eq!(
        permission_kernel.decode(
            &permission_request,
            &serde_json::to_vec(&permission_records).unwrap()
        ),
        Err(DiscordError::TooManyRecords)
    );

    let permissions = vec![
        serde_json::json!({
            "id":"700000000000000001","type":1,"permission":true
        });
        MAX_COMMAND_PERMISSION_ENTRIES + 1
    ];
    let permission_body = serde_json::to_vec(&vec![serde_json::json!({
        "id":"600000000000000001",
        "application_id":APPLICATION_ID,
        "guild_id":GUILD_ID,
        "permissions":permissions
    })])
    .unwrap();
    assert_eq!(
        permission_kernel.decode(&permission_request, &permission_body),
        Err(DiscordError::TooManyNestedRecords)
    );

    let member_roles = vec![Value::String("500000000000000001".to_owned()); MAX_MEMBER_ROLES + 1];
    let member_body = serde_json::to_vec(&vec![serde_json::json!({
        "user":{"id":"100000000000000001","username":"member"},
        "joined_at":"2026-06-01T00:00:00Z",
        "deaf":false,
        "mute":false,
        "roles":member_roles
    })])
    .unwrap();
    let member_kernel = kernel(DiscordFamily::Member, Some(2));
    let member_request = member_kernel.plan(None).unwrap();
    assert_eq!(
        member_kernel.decode(&member_request, &member_body),
        Err(DiscordError::TooManyNestedRecords)
    );
}

#[test]
fn response_byte_count_is_bounded_before_json_decode() {
    let role_kernel = kernel(DiscordFamily::Role, None);
    let request = role_kernel.plan(None).unwrap();
    let body = vec![b' '; MAX_RESPONSE_BYTES + 1];
    assert_eq!(
        role_kernel.decode(&request, &body),
        Err(DiscordError::ResponseTooLarge)
    );
}
