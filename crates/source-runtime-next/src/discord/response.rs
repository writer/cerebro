use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::{
    DiscordError, DiscordFamily, DiscordKernel, DiscordPage, DiscordRecord, DiscordRequest,
    cursor::{highest_provider_id, validate_ascending_page},
    request::snowflake,
};

// Provider-local defense-in-depth bounds. The HTTP host must independently
// enforce a response byte limit before handing a body to this kernel.
pub(super) const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_NONPAGED_RECORDS: usize = 1_000;
pub(super) const MAX_MEMBER_ROLES: usize = 250;
pub(super) const MAX_COMMAND_PERMISSION_ENTRIES: usize = 100;

impl DiscordKernel {
    /// Decode and normalize a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &DiscordRequest,
        body: &[u8],
    ) -> Result<DiscordPage, DiscordError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DiscordError::ResponseTooLarge);
        }
        if request.family != self.family || request != &self.plan(request.cursor.as_deref())? {
            return Err(DiscordError::RequestScopeMismatch);
        }
        let payloads = decode_records(self.family, body)?;
        let record_limit = self.page_size.unwrap_or(MAX_NONPAGED_RECORDS);
        if payloads.len() > record_limit {
            return Err(DiscordError::TooManyRecords);
        }
        let records = payloads
            .into_iter()
            .map(|payload| normalize_record(self.family, payload))
            .collect::<Result<Vec<_>, _>>()?;
        if self.family == DiscordFamily::Permission {
            validate_permission_scope(self, &records)?;
        }
        validate_ascending_page(self.family, &records)?;
        let next_cursor = if self.page_size.is_some_and(|limit| records.len() == limit) {
            match self.family {
                DiscordFamily::AuditLog => records.last().map(|record| record.provider_id.clone()),
                DiscordFamily::Member => highest_provider_id(&records)?,
                DiscordFamily::Role | DiscordFamily::Permission => None,
            }
        } else {
            None
        };
        Ok(DiscordPage {
            records,
            next_cursor,
        })
    }
}

fn validate_permission_scope(
    kernel: &DiscordKernel,
    records: &[DiscordRecord],
) -> Result<(), DiscordError> {
    for record in records {
        let values = record
            .payload
            .as_object()
            .ok_or(DiscordError::InvalidRecord)?;
        if strict_string_at(values, "application_id").as_deref() != kernel.application_id.as_deref()
            || strict_string_at(values, "guild_id").as_deref() != Some(kernel.guild_id.as_str())
        {
            return Err(DiscordError::RequestScopeMismatch);
        }
    }
    Ok(())
}

fn decode_records(family: DiscordFamily, body: &[u8]) -> Result<Vec<Value>, DiscordError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| DiscordError::InvalidResponse)?;
    let records = match family {
        DiscordFamily::AuditLog => root
            .as_object()
            .and_then(|object| object.get("audit_log_entries"))
            .and_then(Value::as_array)
            .cloned()
            .ok_or(DiscordError::InvalidResponse),
        DiscordFamily::Member | DiscordFamily::Role | DiscordFamily::Permission => root
            .as_array()
            .cloned()
            .ok_or(DiscordError::InvalidResponse),
    }?;
    if records.iter().any(contains_credential_material) {
        return Err(DiscordError::CredentialMaterial);
    }
    Ok(records)
}

fn normalize_record(family: DiscordFamily, payload: Value) -> Result<DiscordRecord, DiscordError> {
    let values = payload.as_object().ok_or(DiscordError::InvalidResponse)?;
    validate_record_shape(family, values)?;
    let provider_id = match family {
        DiscordFamily::Member => strict_string_at(values, "user.id"),
        DiscordFamily::AuditLog | DiscordFamily::Role | DiscordFamily::Permission => {
            strict_string_at(values, "id")
        }
    }
    .ok_or(DiscordError::MissingProviderId)
    .and_then(|value| snowflake(&value, DiscordError::MissingProviderId))?;
    let mut fields = BTreeMap::from([
        ("family".to_owned(), family.as_str().to_owned()),
        ("provider".to_owned(), "discord".to_owned()),
        ("provider_id".to_owned(), provider_id.clone()),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("source_provider".to_owned(), "discord".to_owned()),
    ]);
    match family {
        DiscordFamily::AuditLog => {
            fields.insert("id".to_owned(), provider_id.clone());
            copy_first(&mut fields, values, "event_type", &["action_type"]);
            copy_first(&mut fields, values, "actor_id", &["user_id"]);
            copy_first(&mut fields, values, "resource_id", &["target_id"]);
            copy_first(&mut fields, values, "reason", &["reason"]);
        }
        DiscordFamily::Member => normalize_member(&mut fields, values, &provider_id),
        DiscordFamily::Role => {
            fields.insert("id".to_owned(), provider_id.clone());
            fields.insert("group_id".to_owned(), provider_id.clone());
            copy_first(&mut fields, values, "name", &["name"]);
            copy_first(&mut fields, values, "group_name", &["name"]);
            copy_first(&mut fields, values, "description", &["description"]);
            copy_first(&mut fields, values, "permissions", &["permissions"]);
        }
        DiscordFamily::Permission => {
            fields.insert("id".to_owned(), provider_id.clone());
            fields.insert("resource_id".to_owned(), provider_id.clone());
            fields.insert("resource_type".to_owned(), "permission".to_owned());
            copy_first(&mut fields, values, "application_id", &["application_id"]);
            copy_first(&mut fields, values, "resource_name", &["application_id"]);
        }
    }
    Ok(DiscordRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        fields,
        payload,
    })
}

fn normalize_member(
    fields: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) {
    fields.insert("id".to_owned(), provider_id.to_owned());
    fields.insert("user_id".to_owned(), provider_id.to_owned());
    fields.insert("resource_id".to_owned(), provider_id.to_owned());
    copy_first(
        fields,
        values,
        "name",
        &["nick", "user.global_name", "user.username"],
    );
    copy_first(
        fields,
        values,
        "display_name",
        &["nick", "user.global_name", "user.username"],
    );
    copy_first(fields, values, "login", &["user.username"]);
    copy_first(fields, values, "username", &["user.username"]);
    copy_first(fields, values, "global_name", &["user.global_name"]);
    copy_first(fields, values, "avatar", &["avatar", "user.avatar"]);
    copy_first(fields, values, "roles", &["roles"]);
    copy_first(fields, values, "joined_at", &["joined_at"]);
    copy_first(fields, values, "deaf", &["deaf"]);
    copy_first(fields, values, "mute", &["mute"]);
    copy_first(fields, values, "flags", &["flags"]);
    copy_first(fields, values, "pending", &["pending"]);
    copy_first(
        fields,
        values,
        "communication_disabled_until",
        &["communication_disabled_until"],
    );
}

fn value_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    let mut value = values.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        value = value.as_object()?.get(part)?;
    }
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Array(values) => values
            .iter()
            .map(|value| match value {
                Value::String(value) if !value.trim().is_empty() => Some(value.trim()),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()
            .map(|values| values.join(",")),
        _ => None,
    }
}

fn strict_string_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    let mut value = values.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        value = value.as_object()?.get(part)?;
    }
    match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_owned()),
        _ => None,
    }
}

fn validate_record_shape(
    family: DiscordFamily,
    values: &Map<String, Value>,
) -> Result<(), DiscordError> {
    match family {
        DiscordFamily::AuditLog => validate_audit(values),
        DiscordFamily::Member => validate_member(values),
        DiscordFamily::Role => validate_role(values),
        DiscordFamily::Permission => validate_permission(values),
    }
}

fn validate_audit(values: &Map<String, Value>) -> Result<(), DiscordError> {
    required_string(values.get("id"))?;
    required_nullable_snowflake(values.get("user_id"))?;
    required_unsigned_number(values.get("action_type"))?;
    required_nullable_snowflake(values.get("target_id"))?;
    nullable_string(values.get("reason"))
}

fn validate_member(values: &Map<String, Value>) -> Result<(), DiscordError> {
    let user = values
        .get("user")
        .and_then(Value::as_object)
        .ok_or(DiscordError::InvalidRecord)?;
    required_string(user.get("id"))?;
    required_string(user.get("username"))?;
    nullable_string(user.get("global_name"))?;
    nullable_string(user.get("avatar"))?;
    nullable_string(values.get("nick"))?;
    nullable_string(values.get("avatar"))?;
    required_string(values.get("joined_at"))?;
    required_bool(values.get("deaf"))?;
    required_bool(values.get("mute"))?;
    optional_unsigned_number(values.get("flags"))?;
    optional_bool(values.get("pending"))?;
    nullable_string(values.get("communication_disabled_until"))?;
    let roles = values
        .get("roles")
        .and_then(Value::as_array)
        .ok_or(DiscordError::InvalidRecord)?;
    if roles.len() > MAX_MEMBER_ROLES {
        return Err(DiscordError::TooManyNestedRecords);
    }
    for role in roles {
        let role = required_string(Some(role))?;
        snowflake(role, DiscordError::InvalidRecord)?;
    }
    Ok(())
}

fn validate_role(values: &Map<String, Value>) -> Result<(), DiscordError> {
    required_string(values.get("id"))?;
    required_string(values.get("name"))?;
    required_string(values.get("permissions"))?;
    nullable_string(values.get("description"))
}

fn validate_permission(values: &Map<String, Value>) -> Result<(), DiscordError> {
    required_string(values.get("id"))?;
    required_string(values.get("application_id"))?;
    required_string(values.get("guild_id"))?;
    let permissions = values
        .get("permissions")
        .and_then(Value::as_array)
        .ok_or(DiscordError::InvalidRecord)?;
    if permissions.len() > MAX_COMMAND_PERMISSION_ENTRIES {
        return Err(DiscordError::TooManyNestedRecords);
    }
    for permission in permissions {
        let permission = permission.as_object().ok_or(DiscordError::InvalidRecord)?;
        let id = required_string(permission.get("id"))?;
        snowflake(id, DiscordError::InvalidRecord)?;
        required_unsigned_number(permission.get("type"))?;
        required_bool(permission.get("permission"))?;
    }
    Ok(())
}

fn required_string(value: Option<&Value>) -> Result<&str, DiscordError> {
    match value {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.trim()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn nullable_string(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        None | Some(Value::Null) | Some(Value::String(_)) => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn required_nullable_snowflake(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(Value::String(value)) => {
            snowflake(value, DiscordError::InvalidRecord)?;
            Ok(())
        }
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn required_bool(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        Some(Value::Bool(_)) => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn optional_bool(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        None | Some(Value::Bool(_)) => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn required_unsigned_number(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        Some(Value::Number(value)) if value.as_u64().is_some() => Ok(()),
        _ => Err(DiscordError::InvalidRecord),
    }
}

fn optional_unsigned_number(value: Option<&Value>) -> Result<(), DiscordError> {
    match value {
        None => Ok(()),
        value => required_unsigned_number(value),
    }
}

fn contains_credential_material(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "authorization"
                    | "api_key"
                    | "api_token"
                    | "access_token"
                    | "refresh_token"
                    | "bot_token"
                    | "client_secret"
                    | "password"
                    | "secret"
                    | "token"
            ) || contains_credential_material(value)
        }),
        Value::Array(values) => values.iter().any(contains_credential_material),
        _ => false,
    }
}

fn copy_first(
    fields: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    output: &str,
    paths: &[&str],
) {
    if let Some(value) = paths.iter().find_map(|path| value_at(values, path)) {
        fields.insert(output.to_owned(), value);
    }
}
