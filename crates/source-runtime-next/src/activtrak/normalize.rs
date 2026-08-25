use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    ActivTrakError, ActivTrakFamily, ActivTrakKernel, ActivTrakRecord, ActivTrakRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &ActivTrakKernel,
    raw: Value,
) -> Result<ActivTrakRecord, ActivTrakError> {
    reject_protected(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(ActivTrakError::InvalidProviderRecord)?;
    let provider_id = scalar(values.get(kernel.family.id_field()))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(ActivTrakError::MissingStableIdentity)?;
    let attributes = attributes(kernel, values, &provider_id)?;
    let occurred_at = occurred_at(kernel, values)?;
    let record = ActivTrakRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload: raw,
    };
    admit(&record)?;
    Ok(record)
}

fn attributes(
    kernel: &ActivTrakKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<BTreeMap<String, String>, ActivTrakError> {
    let mut output = BTreeMap::from([
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_system".to_owned(), "activtrak".to_owned()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
    ]);
    match kernel.family {
        ActivTrakFamily::Users => {
            output.insert("record_class".to_owned(), "identity_user".to_owned());
            output.insert("user_id".to_owned(), provider_id.to_owned());
            copy(&mut output, values, "displayName", "display_name");
            nested_email(&mut output, values);
        }
        ActivTrakFamily::Consumers => {
            output.insert("record_class".to_owned(), "identity_user".to_owned());
            output.insert("user_id".to_owned(), provider_id.to_owned());
            let name = match (
                scalar(values.get("firstName")),
                scalar(values.get("lastName")),
            ) {
                (Some(first), Some(last)) => Some(format!("{first} {last}")),
                _ => scalar(values.get("username")),
            };
            if let Some(name) = name {
                output.insert("display_name".to_owned(), name);
            }
            copy(&mut output, values, "email", "email");
        }
        ActivTrakFamily::Clients | ActivTrakFamily::Groups => {
            let (resource_type, name_key) = match kernel.family {
                ActivTrakFamily::Clients => ("activtrak_client", "alias"),
                ActivTrakFamily::Groups => ("activtrak_group", "displayName"),
                _ => return Err(ActivTrakError::InternalRuntimeFailure),
            };
            let name = scalar(values.get(name_key)).unwrap_or_else(|| provider_id.to_owned());
            output.extend(BTreeMap::from([
                ("record_class".to_owned(), "asset".to_owned()),
                ("resource_id".to_owned(), provider_id.to_owned()),
                ("resource_name".to_owned(), name),
                ("resource_type".to_owned(), resource_type.to_owned()),
                (
                    "resource_urn".to_owned(),
                    format!(
                        "urn:cerebro:{}:runtime_{}:{}",
                        encode_segment(&kernel.tenant_id),
                        resource_type,
                        encode_segment(provider_id)
                    ),
                ),
            ]));
        }
        ActivTrakFamily::ActivityLog => {
            output.insert("record_class".to_owned(), "audit_event".to_owned());
            required_copy(&mut output, values, "description", "event_type")?;
            required_copy(&mut output, values, "user", "actor_id")?;
            copy(&mut output, values, "user", "actor_name");
            copy(&mut output, values, "computerId", "resource_id");
            output.insert("resource_type".to_owned(), "activity_log".to_owned());
        }
    }
    Ok(output)
}

fn occurred_at(
    kernel: &ActivTrakKernel,
    values: &Map<String, Value>,
) -> Result<String, ActivTrakError> {
    let value = if kernel.family == ActivTrakFamily::ActivityLog {
        scalar(values.get("time_utc")).unwrap_or_else(|| kernel.observed_at.clone())
    } else {
        kernel.observed_at.clone()
    };
    let time = OffsetDateTime::parse(&value, &Rfc3339)
        .map_err(|_| ActivTrakError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| ActivTrakError::InvalidProviderRecord)
}

fn admit(record: &ActivTrakRecord) -> Result<(), ActivTrakError> {
    let definition = ActivTrakRuntimeDefinition::compile(record.family)?;
    if record.kind != definition.event_contract.kind
        || record.schema_ref != definition.event_contract.schema_ref
        || definition
            .event_contract
            .required_attributes
            .iter()
            .any(|key| record.attributes.get(*key).is_none_or(String::is_empty))
        || definition
            .event_contract
            .required_payload_fields
            .iter()
            .any(|key| record.payload.get(*key).is_none_or(Value::is_null))
    {
        return Err(ActivTrakError::EventContractRejection);
    }
    Ok(())
}

pub(super) fn event_id(kernel: &ActivTrakKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}",
        kernel.base_url.as_str().trim_end_matches('/'),
        kernel.family.path()
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "activtrak-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn nested_email(output: &mut BTreeMap<String, String>, values: &Map<String, Value>) {
    let email = values
        .get("emails")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
        .and_then(|value| value.get("value"))
        .and_then(|value| scalar(Some(value)));
    if let Some(email) = email {
        output.insert("email".to_owned(), email);
    } else {
        copy(output, values, "userName", "email");
    }
}

fn required_copy(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    target: &str,
) -> Result<(), ActivTrakError> {
    let value = scalar(values.get(source)).filter(|value| !value.is_empty());
    output.insert(
        target.to_owned(),
        value.ok_or(ActivTrakError::InvalidProviderRecord)?,
    );
    Ok(())
}

fn copy(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    target: &str,
) {
    if let Some(value) = scalar(values.get(source)).filter(|value| !value.is_empty()) {
        output.insert(target.to_owned(), value);
    }
}

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn reject_protected(value: &Value, depth: usize) -> Result<(), ActivTrakError> {
    if depth > 32 {
        return Err(ActivTrakError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(ActivTrakError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.to_ascii_lowercase().replace(['-', '.'], "_");
                if ["tenant", "tenant_id", "runtime_id", "source_runtime_id"]
                    .contains(&key.as_str())
                {
                    return Err(ActivTrakError::TenantMismatch);
                }
                if [
                    "token",
                    "access_token",
                    "refresh_token",
                    "session_token",
                    "api_key",
                    "api_token",
                    "x_api_key",
                    "authorization",
                    "cookie",
                    "set_cookie",
                    "password",
                    "passcode",
                    "secret",
                    "client_secret",
                    "private_key",
                ]
                .contains(&key.as_str())
                {
                    return Err(ActivTrakError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 512 {
                return Err(ActivTrakError::InvalidProviderRecord);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        Value::String(value) if value.len() > 64 * 1024 => {
            return Err(ActivTrakError::InvalidProviderRecord);
        }
        _ => {}
    }
    Ok(())
}

fn normalize_id(value: &str) -> String {
    let normalized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    normalized.trim_matches('-').to_owned()
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.trim().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
