use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{AnthropicError, AnthropicFamily, AnthropicRecord};

pub(super) fn normalize_record(
    family: AnthropicFamily,
    tenant_id: &str,
    base_url: &str,
    operation_path: &str,
    path_parameters: &BTreeMap<String, String>,
    observed_at: &str,
    mut payload: Value,
) -> Result<AnthropicRecord, AnthropicError> {
    let object = payload.as_object().ok_or(AnthropicError::InvalidRecord)?;
    if contains_untrusted_tenant(object) || contains_secret_material(&payload) {
        return Err(AnthropicError::InvalidRecord);
    }
    let object = payload
        .as_object_mut()
        .ok_or(AnthropicError::InvalidRecord)?;
    for (key, value) in path_parameters {
        object
            .entry(key.clone())
            .or_insert_with(|| Value::String(value.clone()));
    }
    let object = payload.as_object().ok_or(AnthropicError::InvalidRecord)?;
    for field in family.required_payload_fields() {
        if value_at(object, field).is_none_or(Value::is_null) {
            return Err(AnthropicError::EventContractRejected);
        }
    }
    let provider_id = first_value(object, family.id_paths()).unwrap_or_else(|| {
        let digest = Sha256::digest(serde_json::to_vec(&payload).unwrap_or_default());
        digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    });
    if provider_id.trim().is_empty() || provider_id.len() > 4_096 {
        return Err(AnthropicError::MissingStableIdentity);
    }

    let mut fields = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), family.as_str().to_owned()),
        ("provider".to_owned(), "anthropic".to_owned()),
        ("source_product".to_owned(), "anthropic".to_owned()),
        ("source_provider".to_owned(), "anthropic".to_owned()),
    ]);
    for (key, value) in path_parameters {
        fields.insert(key.clone(), value.clone());
    }
    for binding in family.attributes() {
        if let Some(value) = first_value(object, binding.paths) {
            fields.insert(binding.name.to_owned(), value);
        }
    }
    if family.required_attributes().iter().any(|field| {
        fields
            .get(*field)
            .is_none_or(|value| value.trim().is_empty())
    }) {
        return Err(AnthropicError::EventContractRejected);
    }

    let occurred_at = first_value(object, family.timestamp_paths())
        .and_then(|value| canonical_timestamp(&value))
        .or_else(|| canonical_timestamp(observed_at))
        .ok_or(AnthropicError::InvalidObservedAt)?;
    let event_id = event_id(tenant_id, base_url, operation_path, family, &provider_id);
    Ok(AnthropicRecord {
        tenant_id: tenant_id.to_owned(),
        event_id,
        provider_id,
        provider_kind: family.provider_kind(),
        schema_ref: family.schema_ref(),
        fields,
        payload,
        occurred_at,
    })
}

fn first_value(object: &Map<String, Value>, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at(object, path).and_then(value_string))
}

fn value_at<'a>(object: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let mut value = object.get(parts.next()?)?;
    for part in parts {
        value = value.as_object()?.get(part)?;
    }
    Some(value)
}

fn value_string(value: &Value) -> Option<String> {
    let text = match value {
        Value::Null => return None,
        Value::String(value) => value.trim().to_owned(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Array(_) => serde_json::to_string(value).ok()?,
        Value::Object(_) => serde_json::to_string(value).ok()?,
    };
    (!text.is_empty()).then_some(text)
}

fn canonical_timestamp(value: &str) -> Option<String> {
    OffsetDateTime::parse(value.trim(), &Rfc3339)
        .ok()?
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .ok()
}

pub(super) fn event_id(
    tenant_id: &str,
    base_url: &str,
    operation_path: &str,
    family: AnthropicFamily,
    provider_id: &str,
) -> String {
    let scope = Sha256::digest(format!("{base_url}\0{operation_path}"));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "anthropic-{}-{scope}-{}-{}",
        normalize_id(tenant_id),
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

fn contains_untrusted_tenant(object: &Map<String, Value>) -> bool {
    ["tenant", "tenant_id", "tenantId"]
        .iter()
        .any(|key| object.contains_key(*key))
}

fn contains_secret_material(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "authorization"
                    | "access_token"
                    | "refresh_token"
                    | "api_key"
                    | "client_secret"
                    | "password"
                    | "private_key"
                    | "session_cookie"
            ) || contains_secret_material(value)
        }),
        Value::Array(values) => values.iter().any(contains_secret_material),
        _ => false,
    }
}
