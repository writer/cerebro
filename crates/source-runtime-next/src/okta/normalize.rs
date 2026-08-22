//! Go-compatible Okta record normalization helpers.

use std::collections::BTreeMap;

use reqwest::Url;
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{OktaError, OktaFamily, OktaKernel, OktaRecord, OktaRequest};

pub(super) fn normalize_record(
    kernel: &OktaKernel,
    request: &OktaRequest,
    mut payload: Value,
    observed_at: OffsetDateTime,
) -> Result<OktaRecord, OktaError> {
    let object = payload.as_object().ok_or(OktaError::InvalidResponse)?;
    if object.contains_key("tenant_id") {
        return Err(OktaError::InvalidResponse);
    }
    let provider_id = provider_id(kernel.family, object, &kernel.tenant_id)?;
    require_identity_component(&provider_id)?;
    let occurred_at = occurred_at(kernel.family, object, observed_at)?;
    let fields = normalized_fields(kernel, request, object, &provider_id)?;
    if fields
        .get("family")
        .is_none_or(|value| value != kernel.family.as_str())
    {
        return Err(OktaError::EventContractRejected("attributes.family"));
    }
    scrub_sensitive_values(&mut payload);
    let event_id = event_id(&kernel.tenant_id, kernel.family, &provider_id, &occurred_at);
    Ok(OktaRecord {
        family: kernel.family.as_str().to_owned(),
        provider_kind: kernel.family.provider_kind(),
        schema_ref: kernel.family.schema_ref(),
        tenant_id: kernel.tenant_id.clone(),
        provider_id,
        event_id,
        fields,
        occurred_at,
        payload,
    })
}

pub(super) fn require_identity_component(value: &str) -> Result<(), OktaError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 512
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '/' | '\\' | '?' | '#'))
    {
        return Err(OktaError::InvalidEventIdentity);
    }
    Ok(())
}

fn provider_id(
    family: OktaFamily,
    object: &serde_json::Map<String, Value>,
    tenant_id: &str,
) -> Result<String, OktaError> {
    let value = match family {
        OktaFamily::Audit => text(object.get("uuid")),
        OktaFamily::ThreatInsight => first([text(object.get("id")), tenant_id.to_owned()]),
        _ => text(object.get("id")),
    };
    if value.is_empty() {
        return Err(OktaError::MissingProviderIdentity);
    }
    Ok(value)
}

fn normalized_fields(
    kernel: &OktaKernel,
    request: &OktaRequest,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) -> Result<BTreeMap<String, String>, OktaError> {
    let mut fields = BTreeMap::from([
        ("domain".to_owned(), kernel.tenant_id.clone()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
    ]);
    match kernel.family {
        OktaFamily::Audit => audit_fields(&mut fields, object, &kernel.tenant_id),
        OktaFamily::User => user_fields(&mut fields, object, provider_id),
        OktaFamily::Group => group_fields(&mut fields, object, provider_id),
        OktaFamily::GroupMembership => {
            let group_id = required_filter(&kernel.filters.group_id, "group_id")?;
            user_fields(&mut fields, object, provider_id);
            insert(&mut fields, "group_id", group_id);
            insert(&mut fields, "member_id", provider_id);
            insert(&mut fields, "member_user_id", provider_id);
            insert(&mut fields, "member_type", "user");
            if let Some(profile) = nested(object, "profile") {
                insert(
                    &mut fields,
                    "member_email",
                    first([path_text(profile, "email"), path_text(profile, "login")]),
                );
                insert(&mut fields, "member_name", display_name(profile));
                insert(&mut fields, "member_status", text(object.get("status")));
            }
        }
        OktaFamily::Application => application_fields(&mut fields, object, provider_id),
        OktaFamily::AppAssignment => {
            assignment_fields(kernel, request, &mut fields, object, provider_id)?
        }
        OktaFamily::AdminRole => admin_role_fields(kernel, &mut fields, object, provider_id)?,
        OktaFamily::PolicyRule => policy_rule_fields(kernel, &mut fields, object, provider_id)?,
        family => asset_fields(family, &mut fields, object, provider_id),
    }
    Ok(fields)
}

fn audit_fields(
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    tenant_id: &str,
) {
    let event_type = text(object.get("eventType"));
    insert(fields, "event_type", event_type.clone());
    insert(fields, "severity", text(object.get("severity")));
    if let Some(actor) = nested(object, "actor") {
        insert(fields, "actor_id", path_text(actor, "id"));
        insert(fields, "actor_type", path_text(actor, "type"));
        insert(fields, "actor_email", path_text(actor, "alternateId"));
        insert(
            fields,
            "actor_display_name",
            path_text(actor, "displayName"),
        );
    }
    let target = object
        .get("target")
        .and_then(Value::as_array)
        .and_then(|targets| targets.first())
        .and_then(Value::as_object);
    let actor = nested(object, "actor");
    let resource_id = target
        .map(|value| {
            first([
                path_text(value, "id"),
                path_text(value, "alternateId"),
                path_text(value, "displayName"),
            ])
        })
        .filter(|value| !value.is_empty())
        .or_else(|| {
            actor.map(|value| first([path_text(value, "alternateId"), path_text(value, "id")]))
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| tenant_id.to_owned());
    let resource_type = target
        .map(|value| path_text(value, "type"))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| event_type.split('.').next().unwrap_or("audit").to_owned());
    insert(fields, "resource_id", resource_id);
    insert(fields, "resource_type", resource_type);
}

fn user_fields(
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) {
    insert(fields, "user_id", provider_id);
    insert(fields, "status", text(object.get("status")));
    insert(fields, "realm_id", text(object.get("realmId")));
    if let Some(profile) = nested(object, "profile") {
        for (target, source) in [
            ("email", "email"),
            ("login", "login"),
            ("department", "department"),
            ("job_title", "title"),
            ("title", "title"),
            ("organization", "organization"),
            ("manager", "manager"),
            ("manager_id", "managerId"),
            ("employee_number", "employeeNumber"),
            ("user_type", "userType"),
        ] {
            insert(fields, target, path_text(profile, source));
        }
    }
    if let Some(kind) = nested(object, "type") {
        insert(fields, "type_id", path_text(kind, "id"));
        insert(fields, "type_name", path_text(kind, "name"));
    }
    if let Some(factors) = object.get("factors").and_then(Value::as_array) {
        let mut kinds: Vec<_> = factors
            .iter()
            .filter(|factor| factor.get("status").and_then(Value::as_str) == Some("ACTIVE"))
            .filter_map(|factor| factor.get("factorType").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        kinds.sort();
        kinds.dedup();
        insert(fields, "mfa_enrolled", (!kinds.is_empty()).to_string());
        insert(fields, "mfa_factor_count", kinds.len().to_string());
        insert(fields, "mfa_factor_types", kinds.join(","));
        let resistant = kinds
            .iter()
            .any(|kind| matches!(kind.as_str(), "signed_nonce" | "u2f" | "webauthn"));
        insert(fields, "mfa_phishing_resistant", resistant.to_string());
    }
}

fn group_fields(
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) {
    insert(fields, "group_id", provider_id);
    insert(fields, "type", text(object.get("type")));
    if let Some(profile) = nested(object, "profile") {
        let name = path_text(profile, "name");
        insert(fields, "group_name", name.clone());
        insert(fields, "name", name);
        insert(fields, "description", path_text(profile, "description"));
        insert(
            fields,
            "group_email",
            first([path_text(profile, "email"), path_text(profile, "login")]),
        );
    }
}

fn application_fields(
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) {
    insert(fields, "app_id", provider_id);
    insert(fields, "app_label", text(object.get("label")));
    insert(
        fields,
        "app_name",
        first([text(object.get("label")), text(object.get("name"))]),
    );
    insert(fields, "name", text(object.get("name")));
    insert(fields, "status", text(object.get("status")));
    let sign_on_mode = text(object.get("signOnMode"));
    insert(fields, "sign_on_mode", sign_on_mode.clone());
    let oauth = nested(object, "settings").and_then(|value| nested(value, "oauthClient"));
    let credentials = nested(object, "credentials").and_then(|value| nested(value, "oauthClient"));
    let application_type = oauth
        .map(|value| path_text(value, "application_type"))
        .unwrap_or_default();
    let auth_method = credentials
        .map(|value| path_text(value, "token_endpoint_auth_method"))
        .unwrap_or_default();
    let grants = oauth
        .map(|value| string_list(value.get("grant_types")))
        .unwrap_or_default();
    let responses = oauth
        .map(|value| string_list(value.get("response_types")))
        .unwrap_or_default();
    insert(fields, "application_type", application_type.clone());
    insert(fields, "token_endpoint_auth_method", auth_method.clone());
    insert(
        fields,
        "client_id",
        credentials
            .map(|value| path_text(value, "client_id"))
            .unwrap_or_default(),
    );
    insert(fields, "grant_types", grants.join(","));
    insert(fields, "response_types", responses.join(","));
    let public = matches!(
        application_type.to_ascii_lowercase().as_str(),
        "browser" | "native" | "spa"
    ) || auth_method.eq_ignore_ascii_case("none");
    insert(fields, "oauth_public_client", public.to_string());
    let mode = format!("{} {}", text(object.get("name")), sign_on_mode).to_ascii_lowercase();
    insert(
        fields,
        "oauth2",
        (mode.contains("oidc")
            || mode.contains("oauth")
            || !grants.is_empty()
            || !responses.is_empty()
            || !application_type.is_empty())
        .to_string(),
    );
    insert(fields, "saml", mode.contains("saml").to_string());
}

fn assignment_fields(
    kernel: &OktaKernel,
    request: &OktaRequest,
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) -> Result<(), OktaError> {
    let app_id = required_filter(&kernel.filters.app_id, "app_id")?;
    let subject_type = request
        .assignment_phase
        .as_deref()
        .unwrap_or("users")
        .trim_end_matches('s');
    insert(fields, "app_id", app_id);
    for name in ["assignee_id", "subject_id"] {
        insert(fields, name, provider_id);
    }
    for name in ["assignee_type", "principal_type", "subject_type"] {
        insert(fields, name, subject_type);
    }
    insert(fields, "status", text(object.get("status")));
    insert(fields, "scope", text(object.get("scope")));
    if let Some(profile) = nested(object, "profile") {
        let email = first([
            path_text(profile, "email"),
            path_text(profile, "login"),
            path_text(profile, "userName"),
        ]);
        insert(fields, "subject_email", email.clone());
        insert(fields, "email", email.clone());
        insert(
            fields,
            "subject_name",
            first([
                path_text(profile, "displayName"),
                path_text(profile, "name"),
                email,
                provider_id.to_owned(),
            ]),
        );
    }
    if subject_type == "group" {
        insert(fields, "group_id", provider_id);
    }
    Ok(())
}

fn admin_role_fields(
    kernel: &OktaKernel,
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) -> Result<(), OktaError> {
    let user_id = required_filter(&kernel.filters.user_id, "user_id")?;
    insert(fields, "role_id", provider_id);
    insert(
        fields,
        "role_name",
        first([
            text(object.get("label")),
            text(object.get("type")),
            provider_id.to_owned(),
        ]),
    );
    insert(fields, "role_type", text(object.get("type")));
    insert(fields, "subject_id", user_id);
    insert(fields, "subject_type", "user");
    insert(fields, "event_type", "admin.role.assignment");
    insert(fields, "action", "admin.role.assignment");
    insert(fields, "is_admin", "true");
    insert(fields, "actor_privileged", "true");
    insert(fields, "assigned_to", user_id);
    insert(fields, "status", text(object.get("status")));
    insert(
        fields,
        "assignment_type",
        text(object.get("assignmentType")),
    );
    if let Some(email) = kernel.filters.user_email.as_deref() {
        insert(fields, "subject_email", email);
    }
    Ok(())
}

fn policy_rule_fields(
    kernel: &OktaKernel,
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) -> Result<(), OktaError> {
    let policy_id = required_filter(&kernel.filters.policy_id, "policy_id")?;
    insert(fields, "policy_id", policy_id);
    insert(fields, "policy_rule_id", provider_id);
    insert(fields, "resource_id", provider_id);
    insert(fields, "resource_type", "PolicyRule");
    insert(fields, "name", text(object.get("name")));
    insert(fields, "status", text(object.get("status")));
    insert(fields, "policy_rule_status", text(object.get("status")));
    insert(fields, "priority", text(object.get("priority")));
    insert(fields, "system", text(object.get("system")));
    if let Some(signon) = nested(object, "actions").and_then(|value| nested(value, "signon")) {
        insert(
            fields,
            "access",
            path_text(signon, "access").to_ascii_uppercase(),
        );
        insert(fields, "requires_mfa", text(signon.get("requireFactor")));
        if let Some(session) = nested(signon, "session") {
            insert(
                fields,
                "session_idle_minutes",
                text(session.get("maxSessionIdleMinutes")),
            );
            insert(
                fields,
                "session_persistent",
                text(session.get("usePersistentCookie")),
            );
        }
    }
    Ok(())
}

fn asset_fields(
    family: OktaFamily,
    fields: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    provider_id: &str,
) {
    insert(fields, "resource_id", provider_id);
    insert(fields, "resource_type", title_family(family.as_str()));
    let id_name = format!("{}_id", family.as_str());
    insert(fields, &id_name, provider_id);
    for key in [
        "name",
        "status",
        "type",
        "key",
        "origin",
        "usage",
        "system",
        "createdBy",
        "lastUpdatedBy",
    ] {
        insert(fields, snake_case(key), text(object.get(key)));
    }
    if family == OktaFamily::NetworkZone {
        insert(fields, "zone_id", provider_id);
        insert(fields, "zone_type", text(object.get("type")));
    }
    if family == OktaFamily::TrustedOrigin {
        if let Some(origin) = object.get("origin").and_then(Value::as_str) {
            insert(
                fields,
                "origin_host",
                Url::parse(origin)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .unwrap_or_default(),
            );
            insert(fields, "wildcard_origin", origin.contains('*').to_string());
        }
        let scopes = object
            .get("scopes")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut types: Vec<_> = scopes
            .iter()
            .filter_map(|value| value.get("type").and_then(Value::as_str))
            .map(str::to_owned)
            .collect();
        types.sort();
        insert(fields, "scope_count", types.len().to_string());
        insert(fields, "scope_types", types.join(","));
        insert(
            fields,
            "cors",
            types.iter().any(|value| value == "CORS").to_string(),
        );
        insert(
            fields,
            "redirect",
            types.iter().any(|value| value == "REDIRECT").to_string(),
        );
    }
    for (container, uri_key, field_name) in [
        ("channel", "uri", "uri_host"),
        ("settings", "issuer", "issuer_host"),
    ] {
        if let Some(uri) = nested(object, container)
            .map(|value| path_text(value, uri_key))
            .filter(|value| !value.is_empty())
        {
            insert(
                fields,
                field_name,
                Url::parse(&uri)
                    .ok()
                    .and_then(|url| url.host_str().map(str::to_owned))
                    .unwrap_or_default(),
            );
        }
    }
}

fn occurred_at(
    family: OktaFamily,
    object: &serde_json::Map<String, Value>,
    observed_at: OffsetDateTime,
) -> Result<String, OktaError> {
    let keys: &[&str] = if family == OktaFamily::Audit {
        &["published"]
    } else {
        &[
            "lastUpdated",
            "created",
            "statusChanged",
            "lastLogin",
            "passwordChanged",
        ]
    };
    for key in keys {
        let raw = text(object.get(*key));
        if raw.is_empty() {
            continue;
        }
        let parsed =
            OffsetDateTime::parse(&raw, &Rfc3339).map_err(|_| OktaError::InvalidResponse)?;
        if parsed.unix_timestamp_nanos() <= 0 {
            return Err(OktaError::InvalidResponse);
        }
        return parsed
            .to_offset(UtcOffset::UTC)
            .format(&Rfc3339)
            .map_err(|_| OktaError::InvalidResponse);
    }
    if family == OktaFamily::Audit || observed_at.unix_timestamp_nanos() <= 0 {
        return Err(OktaError::InvalidResponse);
    }
    observed_at
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .map_err(|_| OktaError::InvalidResponse)
}

fn event_id(tenant_id: &str, family: OktaFamily, provider_id: &str, occurred_at: &str) -> String {
    let digest = Sha256::digest(
        format!(
            "cerebro.okta.event.v1\0{tenant_id}\0{}\0{provider_id}\0{occurred_at}",
            family.as_str()
        )
        .as_bytes(),
    );
    let encoded = digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
            output
        });
    format!("okta-{}-{encoded}", family.as_str().replace('_', "-"))
}

fn scrub_sensitive_values(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(scrub_sensitive_values),
        Value::Object(values) => {
            values.retain(|key, _| {
                !matches!(
                    key.to_ascii_lowercase().as_str(),
                    "token"
                        | "apitoken"
                        | "api_token"
                        | "access_token"
                        | "refreshtoken"
                        | "refresh_token"
                        | "sessiontoken"
                        | "session_token"
                        | "clientsecret"
                        | "client_secret"
                        | "privatekey"
                        | "private_key"
                        | "password"
                        | "passcode"
                        | "authorization"
                        | "cookie"
                )
            });
            values.values_mut().for_each(scrub_sensitive_values);
        }
        _ => {}
    }
}

fn required_filter<'a>(
    value: &'a Option<String>,
    name: &'static str,
) -> Result<&'a str, OktaError> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(OktaError::MissingScope(name))
}

fn nested<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a serde_json::Map<String, Value>> {
    object.get(key).and_then(Value::as_object)
}

fn path_text(object: &serde_json::Map<String, Value>, key: &str) -> String {
    text(object.get(key))
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn first<const N: usize>(values: [String; N]) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

fn insert(fields: &mut BTreeMap<String, String>, name: impl AsRef<str>, value: impl AsRef<str>) {
    let value = value.as_ref().trim();
    if !value.is_empty() {
        fields.insert(name.as_ref().to_owned(), value.to_owned());
    }
}

fn display_name(profile: &serde_json::Map<String, Value>) -> String {
    first([
        path_text(profile, "displayName"),
        format!(
            "{} {}",
            path_text(profile, "firstName"),
            path_text(profile, "lastName")
        )
        .trim()
        .to_owned(),
        path_text(profile, "login"),
    ])
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    let mut values: Vec<_> = value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    values.sort();
    values
}

fn snake_case(value: &str) -> String {
    value.chars().fold(String::new(), |mut output, character| {
        if character.is_ascii_uppercase() {
            output.push('_');
            output.push(character.to_ascii_lowercase());
        } else {
            output.push(character);
        }
        output
    })
}

fn title_family(value: &str) -> String {
    value
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<String>()
}
