use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{DiscordError, DiscordFamily, DiscordRecord, request::snowflake};

pub(super) const MAX_MEMBER_ROLES: usize = 250;
pub(super) const MAX_COMMAND_PERMISSION_ENTRIES: usize = 100;

pub(super) fn normalize_record(
    family: DiscordFamily,
    tenant_id: &str,
    base_url: &str,
    operation_path: &str,
    guild_id: &str,
    payload: Value,
) -> Result<DiscordRecord, DiscordError> {
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
    let occurred_at_unix_millis = snowflake_unix_millis(&provider_id)?;
    let event_id = event_id(tenant_id, base_url, operation_path, family, &provider_id);
    let mut fields = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), family.as_str().to_owned()),
        ("provider".to_owned(), "discord".to_owned()),
        ("provider_id".to_owned(), provider_id.clone()),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("source_provider".to_owned(), "discord".to_owned()),
    ]);
    match family {
        DiscordFamily::AuditLog => {
            fields.insert("id".to_owned(), provider_id.clone());
            fields.insert("guild_id".to_owned(), guild_id.to_owned());
            fields.insert("record_class".to_owned(), "audit_event".to_owned());
            fields.insert("schema".to_owned(), "audit_log".to_owned());
            fields.insert("source_system".to_owned(), "discord".to_owned());
            copy_first(&mut fields, values, "event_type", &["action_type"]);
            copy_first(&mut fields, values, "actor_id", &["user_id"]);
            copy_first(&mut fields, values, "resource_id", &["target_id"]);
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
        tenant_id: tenant_id.to_owned(),
        event_id,
        source_id: "discord".to_owned(),
        schema_ref: format!("discord/{}/v1", family.as_str()),
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        occurred_at_unix_millis,
        fields,
        payload,
    })
}

const DISCORD_EPOCH_MILLIS: u64 = 1_420_070_400_000;

fn snowflake_unix_millis(value: &str) -> Result<i64, DiscordError> {
    let snowflake = value
        .parse::<u64>()
        .map_err(|_| DiscordError::InvalidRecord)?;
    let milliseconds = (snowflake >> 22)
        .checked_add(DISCORD_EPOCH_MILLIS)
        .ok_or(DiscordError::InvalidRecord)?;
    i64::try_from(milliseconds).map_err(|_| DiscordError::InvalidRecord)
}

pub(super) fn event_id(
    tenant_id: &str,
    base_url: &str,
    operation_path: &str,
    family: DiscordFamily,
    provider_id: &str,
) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}",
        base_url.trim_end_matches('/'),
        operation_path
    ));
    let scope_prefix = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "discord-{}-{}-{}-{}",
        normalize_id(tenant_id),
        scope_prefix,
        normalize_id(family.as_str()),
        normalize_id(provider_id)
    )
}

fn normalize_id(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "unknown".to_owned();
    }
    value
        .chars()
        .map(|character| match character {
            ' ' | '/' | ':' | '\t' | '\n' => '-',
            other => other,
        })
        .collect()
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

pub(super) fn strict_string_at(values: &Map<String, Value>, path: &str) -> Option<String> {
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
    if values.contains_key("tenant_id") {
        return Err(DiscordError::InvalidRecord);
    }
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
