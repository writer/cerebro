use super::{AzureAuthenticationMethodsPolicyError, AzureAuthenticationMethodsPolicyKernel};

const PROVIDER_RESPONSE: &[u8] = br#"{
    "id":"authorizationPolicy",
    "allowInvitesFrom":"adminsAndGuestInviters",
    "allowedToSignUpEmailBasedSubscriptions":false,
    "allowedToUseSSPR":true,
    "blockMsolPowerShell":true,
    "defaultUserRolePermissions":{
        "allowedToCreateApps":false,
        "allowedToCreateSecurityGroups":false,
        "allowedToReadBitlockerKeysForOwnedDevice":true,
        "permissionGrantPoliciesAssigned":[
            "ManagePermissionGrantsForSelf.microsoft-user-default-low"
        ]
    }
}"#;

fn kernel() -> AzureAuthenticationMethodsPolicyKernel {
    AzureAuthenticationMethodsPolicyKernel::new("https://graph.microsoft.com").unwrap()
}

#[test]
fn plans_exact_path_and_credential_free_auth_contract() {
    let request = kernel().plan_authorization_policy().unwrap();
    assert_eq!(
        request.url().as_str(),
        "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
    );
    assert_eq!(request.url().query(), None);
    assert_eq!(request.authorization_scheme(), "Bearer");
    assert_eq!(request.accept(), "application/json");
}

#[test]
fn decodes_fields_from_the_exact_go_test_response() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    let page = kernel
        .decode_authorization_policy(&request, PROVIDER_RESPONSE)
        .unwrap();
    assert_eq!(page.next_cursor, None);
    assert_eq!(page.records.len(), 1);
    let record = &page.records[0];
    assert_eq!(record.family, "authorization_policy");
    assert_eq!(record.provider_kind, "azure.authorization_policy");
    assert_eq!(record.provider_id, "authorizationPolicy");
    for (name, value) in [
        ("allow_email_verified_users_to_join", "false"),
        ("allow_invites_from", "adminsAndGuestInviters"),
        ("allowed_to_sign_up_email", "false"),
        ("allowed_to_use_sspr", "true"),
        ("block_msol_powershell", "true"),
        ("default_user_can_create_apps", "false"),
        ("default_user_can_create_groups", "false"),
        ("default_user_can_read_bitlocker", "true"),
        ("resource_name", "authorizationPolicy"),
        ("resource_provider", "azure"),
        ("resource_type", "authorization_policy"),
    ] {
        assert_eq!(
            record.fields.get(name).map(String::as_str),
            Some(value),
            "field {name}"
        );
    }
    assert_eq!(record.fields.get("guest_user_role_id"), None);
    assert_eq!(
        record
            .payload
            .pointer("/defaultUserRolePermissions/permissionGrantPoliciesAssigned/0")
            .and_then(serde_json::Value::as_str),
        Some("ManagePermissionGrantsForSelf.microsoft-user-default-low")
    );
}

#[test]
fn uses_the_go_singleton_fallback_and_trims_scalars() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    let page = kernel
        .decode_authorization_policy(&request, br#"{"id":"  ","allowInvitesFrom":"  none  "}"#)
        .unwrap();
    let record = &page.records[0];
    assert_eq!(record.provider_id, "authorizationPolicy");
    assert_eq!(
        record.payload.get("id").and_then(serde_json::Value::as_str),
        Some("authorizationPolicy")
    );
    assert_eq!(
        record.fields.get("allow_invites_from").map(String::as_str),
        Some("none")
    );
    assert_eq!(
        record
            .fields
            .get("allow_email_verified_users_to_join")
            .map(String::as_str),
        Some("false")
    );
}

#[test]
fn payload_matches_the_go_typed_remarshal_shape() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    let page = kernel
        .decode_authorization_policy(
            &request,
            br#"{"id":"authorizationPolicy","allowInvitesFrom":null,"unknown":"discarded"}"#,
        )
        .unwrap();
    let payload = &page.records[0].payload;
    assert_eq!(payload.get("allowInvitesFrom").and_then(serde_json::Value::as_str), Some(""));
    assert_eq!(payload.get("allowedToUseSSPR"), Some(&serde_json::Value::Null));
    assert_eq!(payload.get("defaultUserRolePermissions"), Some(&serde_json::Value::Null));
    assert_eq!(payload.get("unknown"), None);
}

#[test]
fn rejects_wrong_string_field_shapes() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    for field in ["id", "allowInvitesFrom", "guestUserRoleId"] {
        for invalid in ["1", "true", "{}"] {
            let body = format!(r#"{{"{field}":{invalid}}}"#);
            assert_eq!(
                kernel.decode_authorization_policy(&request, body.as_bytes()),
                Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse),
                "field {field} accepted {invalid}"
            );
        }
    }
}

#[test]
fn rejects_wrong_boolean_field_shapes() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    for field in [
        "allowEmailVerifiedUsersToJoinOrganization",
        "allowedToSignUpEmailBasedSubscriptions",
        "allowedToUseSSPR",
        "blockMsolPowerShell",
    ] {
        for invalid in [r#""false""#, "1", "{}"] {
            let body = format!(r#"{{"{field}":{invalid}}}"#);
            assert_eq!(
                kernel.decode_authorization_policy(&request, body.as_bytes()),
                Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse),
                "field {field} accepted {invalid}"
            );
        }
    }
}

#[test]
fn rejects_wrong_permissions_shapes() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    for invalid in [r#""permissions""#, "1", "false", "[]"] {
        let body = format!(r#"{{"defaultUserRolePermissions":{invalid}}}"#);
        assert_eq!(
            kernel.decode_authorization_policy(&request, body.as_bytes()),
            Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse),
            "defaultUserRolePermissions accepted {invalid}"
        );
    }
}

#[test]
fn accepts_null_optional_shapes() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    let page = kernel
        .decode_authorization_policy(
            &request,
            br#"{
                "id":null,
                "allowInvitesFrom":null,
                "guestUserRoleId":null,
                "allowEmailVerifiedUsersToJoinOrganization":null,
                "allowedToSignUpEmailBasedSubscriptions":null,
                "allowedToUseSSPR":null,
                "blockMsolPowerShell":null,
                "defaultUserRolePermissions":null
            }"#,
        )
        .unwrap();
    let record = &page.records[0];
    assert_eq!(record.provider_id, "authorizationPolicy");
    assert_eq!(
        record
            .fields
            .get("allow_email_verified_users_to_join")
            .map(String::as_str),
        Some("false")
    );
}

#[test]
fn rejects_non_objects_and_cross_origin_requests() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    assert_eq!(
        kernel.decode_authorization_policy(&request, br#"[]"#),
        Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse)
    );

    let other = AzureAuthenticationMethodsPolicyKernel::new("https://graph.example.test")
        .unwrap()
        .plan_authorization_policy()
        .unwrap();
    assert_eq!(
        kernel.decode_authorization_policy(&other, PROVIDER_RESPONSE),
        Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyRequestScopeMismatch)
    );
}

#[test]
fn failures_have_authorization_specific_classification() {
    let kernel = kernel();
    let request = kernel.plan_authorization_policy().unwrap();
    let invalid_response = kernel
        .decode_authorization_policy(&request, br#"[]"#)
        .unwrap_err();
    assert_eq!(
        invalid_response,
        AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse
    );
    assert_eq!(
        invalid_response.to_string(),
        "azure authorization policy response must be a JSON object"
    );

    let authentication_request = kernel.plan().unwrap();
    let scope_mismatch = kernel
        .decode_authorization_policy(&authentication_request, PROVIDER_RESPONSE)
        .unwrap_err();
    assert_eq!(
        scope_mismatch,
        AzureAuthenticationMethodsPolicyError::AuthorizationPolicyRequestScopeMismatch
    );
    assert_eq!(
        scope_mismatch.to_string(),
        "azure authorization policy request does not match the kernel"
    );
}
