use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    AzureAuthenticationMethodsPolicyError, AzureAuthenticationMethodsPolicyKernel,
    AzureAuthenticationMethodsPolicyPage, AzureAuthenticationMethodsPolicyRecord,
    AzureAuthenticationMethodsPolicyRequest, AzurePolicyFamily, insert_field, nonblank_string,
    scalar_at, scalar_string,
};

const PATH: &str = "/v1.0/policies/authorizationPolicy";
const FAMILY: &str = "authorization_policy";
const PROVIDER_KIND: &str = "azure.authorization_policy";

impl AzureAuthenticationMethodsPolicyKernel {
    /// Plan the singleton Microsoft Graph authorization policy request.
    pub fn plan_authorization_policy(
        &self,
    ) -> Result<AzureAuthenticationMethodsPolicyRequest, AzureAuthenticationMethodsPolicyError>
    {
        let url = self
            .graph_base_url
            .join(PATH)
            .map_err(|_| AzureAuthenticationMethodsPolicyError::InvalidBaseUrl)?;
        Ok(AzureAuthenticationMethodsPolicyRequest {
            url,
            family: AzurePolicyFamily::Authorization,
        })
    }

    /// Decode one authorization policy response for a request produced by this kernel.
    pub fn decode_authorization_policy(
        &self,
        request: &AzureAuthenticationMethodsPolicyRequest,
        body: &[u8],
    ) -> Result<AzureAuthenticationMethodsPolicyPage, AzureAuthenticationMethodsPolicyError> {
        self.validate_authorization_policy_request(request)?;
        let payload: Value = serde_json::from_slice(body).map_err(|_| {
            AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse
        })?;
        if !payload.is_object() {
            return Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse);
        }
        validate_payload(&payload)?;
        let provider_id =
            nonblank_string(payload.get("id")).unwrap_or_else(|| "authorizationPolicy".to_owned());
        let fields = normalize_fields(&payload);
        Ok(AzureAuthenticationMethodsPolicyPage {
            records: vec![AzureAuthenticationMethodsPolicyRecord {
                family: FAMILY.to_owned(),
                provider_kind: PROVIDER_KIND.to_owned(),
                provider_id,
                fields,
                payload,
            }],
            next_cursor: None,
        })
    }

    fn validate_authorization_policy_request(
        &self,
        request: &AzureAuthenticationMethodsPolicyRequest,
    ) -> Result<(), AzureAuthenticationMethodsPolicyError> {
        if request.family != AzurePolicyFamily::Authorization
            || request.url.origin() != self.graph_base_url.origin()
            || request.url.path() != PATH
            || request.url.query().is_some()
            || request.url.fragment().is_some()
        {
            return Err(
                AzureAuthenticationMethodsPolicyError::AuthorizationPolicyRequestScopeMismatch,
            );
        }
        Ok(())
    }
}

fn normalize_fields(payload: &Value) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    insert_field(
        &mut fields,
        "allow_email_verified_users_to_join",
        boolean_string(payload.get("allowEmailVerifiedUsersToJoinOrganization")),
    );
    insert_field(
        &mut fields,
        "allow_invites_from",
        scalar_string(payload.get("allowInvitesFrom")),
    );
    insert_field(
        &mut fields,
        "allowed_to_sign_up_email",
        boolean_string(payload.get("allowedToSignUpEmailBasedSubscriptions")),
    );
    insert_field(
        &mut fields,
        "allowed_to_use_sspr",
        boolean_string(payload.get("allowedToUseSSPR")),
    );
    insert_field(
        &mut fields,
        "block_msol_powershell",
        boolean_string(payload.get("blockMsolPowerShell")),
    );
    insert_field(
        &mut fields,
        "default_user_can_create_apps",
        scalar_at(
            payload,
            &["defaultUserRolePermissions", "allowedToCreateApps"],
        ),
    );
    insert_field(
        &mut fields,
        "default_user_can_create_groups",
        scalar_at(
            payload,
            &[
                "defaultUserRolePermissions",
                "allowedToCreateSecurityGroups",
            ],
        ),
    );
    insert_field(
        &mut fields,
        "default_user_can_read_bitlocker",
        scalar_at(
            payload,
            &[
                "defaultUserRolePermissions",
                "allowedToReadBitlockerKeysForOwnedDevice",
            ],
        ),
    );
    insert_field(
        &mut fields,
        "guest_user_role_id",
        scalar_string(payload.get("guestUserRoleId")),
    );
    insert_field(
        &mut fields,
        "resource_name",
        "authorizationPolicy".to_owned(),
    );
    insert_field(&mut fields, "resource_provider", "azure".to_owned());
    insert_field(&mut fields, "resource_type", FAMILY.to_owned());
    fields
}

fn validate_payload(payload: &Value) -> Result<(), AzureAuthenticationMethodsPolicyError> {
    for name in ["id", "allowInvitesFrom", "guestUserRoleId"] {
        if payload
            .get(name)
            .is_some_and(|value| !value.is_null() && !value.is_string())
        {
            return Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse);
        }
    }
    for name in [
        "allowEmailVerifiedUsersToJoinOrganization",
        "allowedToSignUpEmailBasedSubscriptions",
        "allowedToUseSSPR",
        "blockMsolPowerShell",
    ] {
        if payload
            .get(name)
            .is_some_and(|value| !value.is_null() && !value.is_boolean())
        {
            return Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse);
        }
    }
    if payload
        .get("defaultUserRolePermissions")
        .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        return Err(AzureAuthenticationMethodsPolicyError::AuthorizationPolicyInvalidResponse);
    }
    Ok(())
}

fn boolean_string(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_bool)
        .unwrap_or_default()
        .to_string()
}
