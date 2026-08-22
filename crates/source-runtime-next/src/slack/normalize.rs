use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{SlackError, SlackFamily, SlackKernel, SlackRecord, request::safe_component};

pub(super) fn normalize(kernel: &SlackKernel, value: &Value) -> Result<SlackRecord, SlackError> {
    if contains_credential_material(value) {
        return Err(SlackError::CredentialMaterial);
    }
    if contains_untrusted_tenant(value) {
        return Err(SlackError::TenantMismatch);
    }
    let (payload, provider_id, mut attributes) = match kernel.family {
        SlackFamily::Team => object_record(value, "id", "team_id")?,
        SlackFamily::User => object_record(value, "id", "user_id")?,
        SlackFamily::Channel => object_record(value, "id", "channel_id")?,
        SlackFamily::UserGroup => object_record(value, "id", "group_id")?,
        SlackFamily::AccessLog => access_log(value)?,
        SlackFamily::ChannelMember => membership(
            value,
            "channel_id",
            kernel.filters.channel_id.as_deref(),
            "channel",
        )?,
        SlackFamily::UserGroupMember => membership(
            value,
            "usergroup_id",
            kernel.filters.usergroup_id.as_deref(),
            "user_group",
        )?,
        SlackFamily::AuditLog => audit_log(value)?,
    };
    base_attributes(kernel.family, &provider_id, &mut attributes);
    if kernel.family == SlackFamily::AccessLog
        && let Some(user_id) = attributes.get("user_id").cloned()
    {
        attributes.insert("external_id".to_owned(), user_id);
    }
    family_attributes(kernel.family, &payload, &mut attributes);
    validate_contract(kernel.family, &attributes, &payload)?;
    let occurred_at_unix_millis =
        occurrence_time(kernel.family, &payload)?.unwrap_or(kernel.observed_at_unix_millis);
    let event_id = event_id(&kernel.tenant_id, kernel.family, &provider_id);
    Ok(SlackRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id,
        kind: kernel.family.event_kind(),
        schema_ref: kernel.family.schema_ref(),
        family: kernel.family.as_str().to_owned(),
        provider_id,
        occurred_at_unix_millis,
        attributes,
        payload,
    })
}

fn object_record(
    value: &Value,
    id_path: &str,
    identity_attribute: &str,
) -> Result<(Value, String, BTreeMap<String, String>), SlackError> {
    let object = value.as_object().ok_or(SlackError::InvalidRecord)?;
    let provider_id = required_string(object, id_path)?;
    let attributes = BTreeMap::from([(identity_attribute.to_owned(), provider_id.clone())]);
    Ok((value.clone(), provider_id, attributes))
}

fn membership(
    value: &Value,
    container_key: &str,
    container: Option<&str>,
    membership_type: &str,
) -> Result<(Value, String, BTreeMap<String, String>), SlackError> {
    let user_id = match value {
        Value::String(value) => bounded_identity(value)?,
        Value::Object(object) => required_string(object, "user_id")?,
        _ => return Err(SlackError::InvalidRecord),
    };
    let container = container
        .filter(|value| safe_component(value, 256))
        .ok_or(SlackError::MissingScope)?;
    let provider_id = format!("{container}-{user_id}");
    let payload = Value::Object(Map::from_iter([
        (
            container_key.to_owned(),
            Value::String(container.to_owned()),
        ),
        ("user_id".to_owned(), Value::String(user_id.clone())),
    ]));
    let attributes = BTreeMap::from([
        (container_key.to_owned(), container.to_owned()),
        ("membership_type".to_owned(), membership_type.to_owned()),
        ("user_id".to_owned(), user_id),
    ]);
    Ok((payload, provider_id, attributes))
}

fn access_log(value: &Value) -> Result<(Value, String, BTreeMap<String, String>), SlackError> {
    let object = value.as_object().ok_or(SlackError::InvalidRecord)?;
    let user_id = required_string(object, "user_id")?;
    let ip = required_string(object, "ip")?;
    let provider_id = stable_join(&[&user_id, &ip]);
    let attributes = BTreeMap::from([
        ("actor_id".to_owned(), user_id.clone()),
        ("event_type".to_owned(), "team_access".to_owned()),
        ("ip_address".to_owned(), ip),
        ("user_id".to_owned(), user_id),
    ]);
    Ok((value.clone(), provider_id, attributes))
}

fn audit_log(value: &Value) -> Result<(Value, String, BTreeMap<String, String>), SlackError> {
    let object = value.as_object().ok_or(SlackError::InvalidRecord)?;
    let provider_id = required_string(object, "id")?;
    let actor_id =
        first_text(value, &["actor.user.id", "actor.id"]).ok_or(SlackError::InvalidRecord)?;
    let event_type = text_at(value, "action").ok_or(SlackError::InvalidRecord)?;
    let attributes = BTreeMap::from([
        ("actor_id".to_owned(), actor_id),
        ("event_type".to_owned(), event_type),
    ]);
    Ok((value.clone(), provider_id, attributes))
}

fn base_attributes(
    family: SlackFamily,
    provider_id: &str,
    attributes: &mut BTreeMap<String, String>,
) {
    for (key, value) in [
        ("external_id", provider_id),
        ("family", family.as_str()),
        ("provider", "slack"),
        ("source_product", "slack"),
        ("source_provider", "slack"),
    ] {
        attributes.insert(key.to_owned(), value.to_owned());
    }
}

fn family_attributes(
    family: SlackFamily,
    payload: &Value,
    attributes: &mut BTreeMap<String, String>,
) {
    let mappings: &[(&str, &[&str])] = match family {
        SlackFamily::Team => &[("name", &["name"]), ("domain", &["domain"])],
        SlackFamily::User => &[
            ("team_id", &["team_id"]),
            ("email", &["profile.email", "email"]),
            ("real_name", &["real_name", "profile.real_name"]),
            ("name", &["name"]),
            ("deleted", &["deleted"]),
            ("is_admin", &["is_admin"]),
            ("is_owner", &["is_owner"]),
            ("is_primary_owner", &["is_primary_owner"]),
            ("is_bot", &["is_bot"]),
            ("is_restricted", &["is_restricted"]),
            ("is_ultra_restricted", &["is_ultra_restricted"]),
            ("has_2fa", &["has_2fa"]),
            ("has_mfa", &["has_2fa"]),
            ("two_factor_type", &["two_factor_type"]),
        ],
        SlackFamily::Channel => &[
            ("team_id", &["context_team_id"]),
            ("shared_team_ids", &["shared_team_ids", "internal_team_ids"]),
            ("name", &["name"]),
            ("is_private", &["is_private"]),
            ("is_archived", &["is_archived"]),
            ("creator", &["creator"]),
            ("num_members", &["num_members"]),
        ],
        SlackFamily::UserGroup => &[
            ("team_id", &["team_id"]),
            ("handle", &["handle"]),
            ("name", &["name"]),
            ("description", &["description"]),
            ("is_disabled", &["is_disabled"]),
        ],
        SlackFamily::AccessLog => &[
            ("actor_name", &["username"]),
            ("username", &["username"]),
            ("user_agent", &["user_agent"]),
            ("isp", &["isp"]),
            ("country", &["country"]),
            ("region", &["region"]),
            ("login_count", &["count"]),
        ],
        SlackFamily::AuditLog => &[
            ("actor_type", &["actor.type"]),
            ("actor_name", &["actor.user.name", "actor.name"]),
            ("actor_email", &["actor.user.email"]),
            ("resource_type", &["entity.type"]),
            (
                "resource_id",
                &[
                    "entity.user.id",
                    "entity.channel.id",
                    "entity.file.id",
                    "entity.id",
                ],
            ),
            (
                "resource_name",
                &[
                    "entity.user.name",
                    "entity.channel.name",
                    "entity.file.name",
                    "entity.name",
                ],
            ),
            (
                "team_id",
                &[
                    "actor.user.team",
                    "entity.user.team",
                    "entity.channel.team",
                    "context.team_id",
                ],
            ),
            ("ip_address", &["context.ip_address"]),
            ("user_agent", &["context.ua"]),
        ],
        SlackFamily::ChannelMember | SlackFamily::UserGroupMember => &[],
    };
    for (target, paths) in mappings {
        if let Some(value) = first_text(payload, paths) {
            attributes.insert((*target).to_owned(), value);
        }
    }
}

fn occurrence_time(family: SlackFamily, payload: &Value) -> Result<Option<i64>, SlackError> {
    let paths: &[&str] = match family {
        SlackFamily::Team | SlackFamily::ChannelMember | SlackFamily::UserGroupMember => &[],
        SlackFamily::User => &["updated"],
        SlackFamily::Channel => &["created", "updated"],
        SlackFamily::UserGroup => &["date_update", "date_create"],
        SlackFamily::AccessLog => &["date_last", "date_first"],
        SlackFamily::AuditLog => &["date_create"],
    };
    for path in paths {
        let Some(value) = value_at(payload, path) else {
            continue;
        };
        let seconds = match value {
            Value::Number(value) => value.as_i64(),
            Value::String(value) => value.parse::<i64>().ok(),
            _ => None,
        }
        .ok_or(SlackError::InvalidTimestamp)?;
        return seconds
            .checked_mul(1_000)
            .map(Some)
            .ok_or(SlackError::InvalidTimestamp);
    }
    Ok(None)
}

fn validate_contract(
    family: SlackFamily,
    attributes: &BTreeMap<String, String>,
    payload: &Value,
) -> Result<(), SlackError> {
    if family.required_attributes().iter().any(|field| {
        attributes
            .get(*field)
            .is_none_or(|value| value.trim().is_empty())
    }) || family
        .required_payload_fields()
        .iter()
        .any(|field| value_at(payload, field).is_none_or(Value::is_null))
    {
        return Err(SlackError::InvalidRecord);
    }
    Ok(())
}

fn required_string(object: &Map<String, Value>, key: &str) -> Result<String, SlackError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(bounded_identity)
        .transpose()?
        .ok_or(SlackError::MissingStableIdentity)
}

fn bounded_identity(value: &str) -> Result<String, SlackError> {
    let value = value.trim();
    if !safe_component(value, 512) {
        return Err(SlackError::MissingStableIdentity);
    }
    Ok(value.to_owned())
}

fn first_text(value: &Value, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| text_at(value, path))
}

fn text_at(value: &Value, path: &str) -> Option<String> {
    match value_at(value, path)? {
        Value::String(value) => (!value.trim().is_empty()).then(|| value.trim().to_owned()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Array(values) => {
            let values = values
                .iter()
                .filter_map(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>();
            (!values.is_empty()).then(|| values.join(","))
        }
        _ => None,
    }
}

fn value_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.as_object()?.get(part)?;
    }
    Some(current)
}

fn contains_credential_material(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "access_token"
                    | "api_token"
                    | "authorization"
                    | "client_secret"
                    | "cookie"
                    | "password"
                    | "refresh_token"
                    | "token"
            ) || contains_credential_material(value)
        }),
        Value::Array(values) => values.iter().any(contains_credential_material),
        _ => false,
    }
}

fn contains_untrusted_tenant(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("tenant_id") || contains_untrusted_tenant(value)
        }),
        Value::Array(values) => values.iter().any(contains_untrusted_tenant),
        _ => false,
    }
}

fn event_id(tenant_id: &str, family: SlackFamily, provider_id: &str) -> String {
    let digest = stable_digest(&[tenant_id, family.as_str(), provider_id]);
    format!("slack-{}-{digest}", family.as_str())
}

fn stable_join(values: &[&str]) -> String {
    stable_digest(values)
}

fn stable_digest(values: &[&str]) -> String {
    let mut digest = Sha256::new();
    for value in values {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
