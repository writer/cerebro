use std::collections::BTreeMap;

use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    JumpCloudError, JumpCloudFamily, JumpCloudKernel, JumpCloudRecord, JumpCloudRequest,
    JumpCloudRuntimeDefinition, identity,
};

pub(super) fn normalize(
    kernel: &JumpCloudKernel,
    request: &JumpCloudRequest,
    raw: Value,
    raw_bytes: Option<&[u8]>,
) -> Result<JumpCloudRecord, JumpCloudError> {
    reject_untrusted(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(JumpCloudError::InvalidProviderRecord)?;
    let identity = identity::material(kernel, request, values, raw_bytes)?;
    let occurred_at = occurred_at(kernel.family, values, &kernel.observed_at)?;
    let (attributes, payload) =
        family_values(kernel, request.group_id(), values, &identity.external_id)?;
    validate_contract(kernel.family, &attributes, &payload)?;
    Ok(JumpCloudRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: identity.event_id,
        provider_id: identity.provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    })
}

fn family_values(
    kernel: &JumpCloudKernel,
    request_group_id: Option<&str>,
    values: &Map<String, Value>,
    external_id: &str,
) -> Result<(BTreeMap<String, String>, Value), JumpCloudError> {
    let (record_class, schema, resource_type) = match kernel.family {
        JumpCloudFamily::Users => ("identity_user", "users", "identity_user"),
        JumpCloudFamily::Groups => ("identity_group", "groups", "user_group"),
        JumpCloudFamily::Systems => ("asset", "systems", "system"),
        JumpCloudFamily::Applications => ("identity_application", "applications", "application"),
        JumpCloudFamily::SystemGroups => ("identity_group", "system_groups", "system_group"),
        JumpCloudFamily::GroupMembers => (
            "identity_group_membership",
            "group_members",
            "identity_membership",
        ),
        JumpCloudFamily::AuditEvents => ("audit_event", "audit_events", "audit_event"),
    };
    let mut attributes = BTreeMap::from([
        ("external_id".to_owned(), external_id.to_owned()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("provider".to_owned(), "jumpcloud".to_owned()),
        ("record_class".to_owned(), record_class.to_owned()),
        ("schema".to_owned(), schema.to_owned()),
        ("source_event_id".to_owned(), external_id.to_owned()),
        ("source_provider".to_owned(), "jumpcloud".to_owned()),
        ("source_system".to_owned(), "jumpcloud".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    let mut payload = values.clone();
    match kernel.family {
        JumpCloudFamily::Users => {
            copy(&mut attributes, values, &["_id", "id"], "user_id");
            copy(&mut attributes, values, &["email"], "email");
            copy(&mut attributes, values, &["email"], "primary_email");
            copy(&mut attributes, values, &["username", "email"], "login");
            copy(
                &mut attributes,
                values,
                &["displayname", "displayName", "username", "email"],
                "display_name",
            );
            copy(
                &mut attributes,
                values,
                &["firstname", "firstName"],
                "first_name",
            );
            copy(
                &mut attributes,
                values,
                &["lastname", "lastName"],
                "last_name",
            );
            copy(&mut attributes, values, &["department"], "department");
            copy(
                &mut attributes,
                values,
                &["jobTitle", "job_title"],
                "job_title",
            );
            copy(
                &mut attributes,
                values,
                &["employeeIdentifier"],
                "employee_id",
            );
            copy(&mut attributes, values, &["state", "status"], "status");
            copy(&mut attributes, values, &["activated"], "activated");
            copy(&mut attributes, values, &["suspended"], "suspended");
            copy(
                &mut attributes,
                values,
                &[
                    "totp_enabled",
                    "enable_user_portal_multifactor",
                    "mfa.configured",
                ],
                "mfa_enabled",
            );
            copy(&mut attributes, values, &["_id", "id"], "resource_id");
            copy(
                &mut attributes,
                values,
                &["displayname", "username", "email"],
                "resource_name",
            );
            attributes.insert("resource_type".to_owned(), resource_type.to_owned());
            attributes.insert(
                "resource_urn".to_owned(),
                urn(&kernel.tenant_id, "jumpcloud_users", external_id),
            );
        }
        JumpCloudFamily::Groups => {
            copy(&mut attributes, values, &["id"], "group_id");
            copy(&mut attributes, values, &["name"], "group_name");
            copy(&mut attributes, values, &["type"], "group_type");
            copy(
                &mut attributes,
                values,
                &["attributes.description", "description"],
                "description",
            );
            copy(&mut attributes, values, &["id"], "resource_id");
            copy(&mut attributes, values, &["name"], "resource_name");
            attributes.insert("resource_type".to_owned(), resource_type.to_owned());
        }
        JumpCloudFamily::Systems => {
            copy(&mut attributes, values, &["_id", "id"], "system_id");
            copy(&mut attributes, values, &["_id", "id"], "resource_id");
            copy(
                &mut attributes,
                values,
                &["displayName", "hostname"],
                "resource_name",
            );
            attributes.insert("resource_type".to_owned(), resource_type.to_owned());
            for (paths, target) in [
                (&["hostname"][..], "hostname"),
                (&["os"][..], "os"),
                (&["version"][..], "os_version"),
                (&["arch"][..], "architecture"),
                (&["agentVersion"][..], "agent_version"),
                (&["active"][..], "active"),
                (&["lastContact"][..], "last_contact_at"),
                (&["remoteIP"][..], "remote_ip"),
            ] {
                copy(&mut attributes, values, paths, target);
            }
            attributes.insert(
                "resource_urn".to_owned(),
                urn(&kernel.tenant_id, "jumpcloud_systems", external_id),
            );
        }
        JumpCloudFamily::Applications => {
            copy(&mut attributes, values, &["_id", "id"], "app_id");
            copy(
                &mut attributes,
                values,
                &["displayName", "displayLabel", "name"],
                "app_name",
            );
            copy(&mut attributes, values, &["ssoUrl", "learnMore"], "app_url");
            copy(&mut attributes, values, &["_id", "id"], "resource_id");
            copy(
                &mut attributes,
                values,
                &["displayName", "displayLabel", "name"],
                "resource_name",
            );
            attributes.insert("resource_type".to_owned(), resource_type.to_owned());
            attributes.insert(
                "resource_urn".to_owned(),
                urn(&kernel.tenant_id, "jumpcloud_applications", external_id),
            );
        }
        JumpCloudFamily::SystemGroups => {
            copy(&mut attributes, values, &["id"], "group_id");
            copy(&mut attributes, values, &["name"], "group_name");
            copy(&mut attributes, values, &["type"], "group_type");
            copy(&mut attributes, values, &["id"], "resource_id");
            copy(&mut attributes, values, &["name"], "resource_name");
            attributes.insert("resource_type".to_owned(), resource_type.to_owned());
        }
        JumpCloudFamily::GroupMembers => {
            let group_id =
                request_group_id.ok_or(JumpCloudError::MissingConfiguration("group_id"))?;
            attributes.insert("group_id".to_owned(), group_id.to_owned());
            copy(&mut attributes, values, &["to.id", "id"], "member_id");
            copy(&mut attributes, values, &["to.id", "id"], "member_user_id");
            copy(&mut attributes, values, &["to.type", "type"], "member_type");
            copy(&mut attributes, values, &["to.id", "id"], "resource_id");
            copy(
                &mut attributes,
                values,
                &["to.type", "type"],
                "resource_type",
            );
            payload.insert("group_id".to_owned(), Value::String(group_id.to_owned()));
        }
        JumpCloudFamily::AuditEvents => {
            copy(
                &mut attributes,
                values,
                &["event_type", "type", "action"],
                "event_type",
            );
            copy(
                &mut attributes,
                values,
                &[
                    "initiated_by.id",
                    "actor.id",
                    "admin.id",
                    "user.id",
                    "user_id",
                    "resource.id",
                    "username",
                ],
                "actor_id",
            );
            copy(
                &mut attributes,
                values,
                &[
                    "initiated_by.email",
                    "actor.email",
                    "admin.email",
                    "user.email",
                    "resource.email",
                    "email",
                    "username",
                ],
                "actor_email",
            );
            copy(
                &mut attributes,
                values,
                &[
                    "initiated_by.name",
                    "actor.name",
                    "admin.name",
                    "user.name",
                    "username",
                ],
                "actor_name",
            );
            copy(
                &mut attributes,
                values,
                &[
                    "resource.id",
                    "target.id",
                    "object.id",
                    "application.id",
                    "system.id",
                ],
                "resource_id",
            );
            copy(
                &mut attributes,
                values,
                &["resource.type", "target.type", "object.type"],
                "resource_type",
            );
            copy(
                &mut attributes,
                values,
                &["resource.email", "target.email", "object.email"],
                "resource_email",
            );
            copy(
                &mut attributes,
                values,
                &[
                    "resource.name",
                    "target.name",
                    "object.name",
                    "application.name",
                    "system.hostname",
                ],
                "resource_name",
            );
            for (paths, target) in [
                (&["client_ip", "ip", "src_ip"][..], "client_ip"),
                (&["organization", "org_id"][..], "organization"),
            ] {
                copy(&mut attributes, values, paths, target);
            }
        }
    }
    Ok((attributes, Value::Object(payload)))
}

fn validate_contract(
    family: JumpCloudFamily,
    attributes: &BTreeMap<String, String>,
    payload: &Value,
) -> Result<(), JumpCloudError> {
    let definition = JumpCloudRuntimeDefinition::compile(family)?;
    let contract = definition.event_contract;
    if contract.kind != family.event_kind()
        || contract.schema_ref != family.schema_ref()
        || contract.required_attributes.iter().any(|field| {
            attributes
                .get(*field)
                .is_none_or(|value| value.trim().is_empty())
        })
        || contract.required_payload_fields.iter().any(|path| {
            value_at(payload, path).is_none_or(|value| {
                value.is_null() || value.as_str().is_some_and(|text| text.trim().is_empty())
            })
        })
    {
        return Err(JumpCloudError::EventContractRejection);
    }
    Ok(())
}

fn occurred_at(
    family: JumpCloudFamily,
    values: &Map<String, Value>,
    observed_at: &str,
) -> Result<String, JumpCloudError> {
    let paths: &[&str] = match family {
        JumpCloudFamily::Users => &["updated", "created", "lastLogin"],
        JumpCloudFamily::Groups | JumpCloudFamily::SystemGroups => &["updated", "created"],
        JumpCloudFamily::Systems => &["lastContact", "updated", "created"],
        JumpCloudFamily::Applications => &["updated", "created"],
        JumpCloudFamily::GroupMembers => &[],
        JumpCloudFamily::AuditEvents => &[
            "timestamp",
            "date",
            "observed_at",
            "updated_at",
            "created_at",
        ],
    };
    let candidate = string_first(values, paths).unwrap_or_else(|| observed_at.to_owned());
    OffsetDateTime::parse(&candidate, &Rfc3339)
        .map(|time| time.format(&Rfc3339).unwrap_or(candidate))
        .map_err(|_| JumpCloudError::InvalidProviderRecord)
}

fn copy(
    target: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    paths: &[&str],
    key: &str,
) {
    if let Some(value) = string_first(values, paths) {
        target.insert(key.to_owned(), value);
    }
}

fn string_first(values: &Map<String, Value>, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        let mut segments = path.split('.');
        let mut value = values.get(segments.next()?)?;
        for segment in segments {
            value = value.get(segment)?;
        }
        match value {
            Value::String(value) => (!value.trim().is_empty()).then(|| value.trim().to_owned()),
            Value::Number(value) => Some(value.to_string()),
            Value::Bool(value) => Some(value.to_string()),
            _ => None,
        }
    })
}

fn value_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(value, |value, segment| value.get(segment))
}

fn reject_untrusted(value: &Value, depth: usize) -> Result<(), JumpCloudError> {
    if depth > 32 {
        return Err(JumpCloudError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let key = key.to_ascii_lowercase();
                if key == "tenant_id" {
                    return Err(JumpCloudError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "api_key"
                        | "x-api-key"
                        | "access_token"
                        | "refresh_token"
                        | "client_secret"
                        | "password"
                        | "private_key"
                        | "authorization"
                ) {
                    return Err(JumpCloudError::CredentialMaterial);
                }
                reject_untrusted(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_untrusted(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn urn(tenant: &str, kind: &str, provider_id: &str) -> String {
    format!("urn:cerebro:{tenant}:{kind}:{provider_id}")
}
