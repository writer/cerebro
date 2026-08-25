use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source_execution::{SourceExecutionError, SourceWorkerRecordV1};

use super::catalog::{Family, Source};

const MAX_RECORDS: usize = 1_000;
const MAX_DEPTH: usize = 32;

pub(super) fn normalize_records(
    source: &Source,
    family: &Family,
    tenant_id: &str,
    body: &[u8],
    observed_at_unix_millis: i64,
    public_config: &HashMap<String, String>,
) -> Result<Vec<SourceWorkerRecordV1>, SourceExecutionError> {
    let document: Value =
        serde_json::from_slice(body).map_err(|_| SourceExecutionError::MalformedResponse)?;
    reject_untrusted(&document, 0)?;
    let selected = select_records(&document, &family.record_selector)?;
    if selected.len() > MAX_RECORDS {
        return Err(SourceExecutionError::ResponseTooLarge);
    }
    let observed_at =
        OffsetDateTime::from_unix_timestamp_nanos(i128::from(observed_at_unix_millis) * 1_000_000)
            .map_err(|_| SourceExecutionError::InvalidExecutionContext)?;
    selected
        .into_iter()
        .map(|raw| normalize_record(source, family, tenant_id, raw, observed_at, public_config))
        .collect()
}

pub(super) fn expected_event_id(
    tenant_id: &str,
    source_id: &str,
    family_id: &str,
    provider_id: &str,
) -> String {
    let digest = Sha256::digest(format!(
        "{tenant_id}\0{source_id}\0{family_id}\0{provider_id}"
    ));
    format!(
        "{source_id}-{family_id}-{}",
        digest[..12]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

pub(super) fn value_at<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let path = path
        .trim()
        .strip_prefix("$.")
        .or_else(|| path.trim().strip_prefix('$'))
        .unwrap_or(path.trim());
    if path.is_empty() {
        return Some(value);
    }
    path.split('.')
        .try_fold(value, |current, part| current.as_object()?.get(part))
}

pub(super) fn scalar_at(value: &Value, paths: &[String]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at(value, path).and_then(scalar))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty() && value.len() <= 4_096)
}

fn normalize_record(
    source: &Source,
    family: &Family,
    tenant_id: &str,
    raw: Value,
    observed_at: OffsetDateTime,
    public_config: &HashMap<String, String>,
) -> Result<SourceWorkerRecordV1, SourceExecutionError> {
    let values = raw
        .as_object()
        .ok_or(SourceExecutionError::InvalidProviderRecord)?;
    let external_id = scalar_at(&raw, &family.id_paths)
        .filter(|value| value.len() <= 1_024)
        .ok_or(SourceExecutionError::MissingStableIdentity)?;
    let provider_id = family
        .projection_fields
        .get("resource_id")
        .and_then(|paths| scalar_at(&raw, paths))
        .filter(|value| value.len() <= 1_024)
        .unwrap_or_else(|| external_id.clone());
    let occurred_at = observed_timestamp(&raw, values).unwrap_or(observed_at);
    let occurred_at_unix_millis = i64::try_from(occurred_at.unix_timestamp_nanos() / 1_000_000)
        .map_err(|_| SourceExecutionError::InvalidProviderRecord)?;
    let resource_urn = format!(
        "urn:cerebro:{}:{}:{}",
        urn_component(tenant_id)?,
        family.urn_kind,
        urn_component(&external_id)?
    );
    let resource_name = scalar_at(&raw, &family.name_paths).unwrap_or_else(|| provider_id.clone());
    let mut attributes = BTreeMap::from([
        ("external_id".to_owned(), external_id),
        ("family".to_owned(), family.id.clone()),
        ("provider".to_owned(), source.id.clone()),
        ("resource_id".to_owned(), provider_id.clone()),
        ("resource_name".to_owned(), resource_name),
        ("resource_type".to_owned(), family.id.clone()),
        ("resource_urn".to_owned(), resource_urn),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("source_product".to_owned(), source.id.clone()),
        ("source_provider".to_owned(), source.id.clone()),
        ("source_system".to_owned(), source.id.clone()),
        ("tenant_id".to_owned(), tenant_id.to_owned()),
    ]);
    for (attribute, value) in &family.static_attributes {
        if !protected_attribute(attribute) {
            attributes.insert(attribute.clone(), value.clone());
        }
    }
    for (attribute, config_key) in &family.config_attributes {
        if !protected_attribute(attribute)
            && let Some(value) = public_config
                .get(config_key)
                .map(String::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        {
            attributes.insert(attribute.clone(), value.to_owned());
        }
    }
    for (attribute, paths) in &family.projection_fields {
        if protected_attribute(attribute) {
            continue;
        }
        if let Some(value) = scalar_at(&raw, paths) {
            attributes.insert(attribute.clone(), value);
        }
    }
    for required in &family.required_attributes {
        if attributes.get(required).is_none_or(String::is_empty) {
            return Err(SourceExecutionError::EventContractRejected);
        }
    }
    for required in &family.required_payload_fields {
        if !required
            .split('|')
            .map(str::trim)
            .any(|path| value_at(&raw, path).is_some_and(|value| !value.is_null()))
        {
            return Err(SourceExecutionError::EventContractRejected);
        }
    }
    Ok(SourceWorkerRecordV1 {
        provider_id: provider_id.clone(),
        event_id: expected_event_id(tenant_id, &source.id, &family.id, &provider_id),
        occurred_at_unix_millis,
        attributes: attributes.into_iter().collect::<HashMap<_, _>>(),
        payload_json: serde_json::to_vec(&raw)
            .map_err(|_| SourceExecutionError::InternalRuntime)?,
    })
}

fn protected_attribute(attribute: &str) -> bool {
    matches!(
        attribute,
        "external_id"
            | "family"
            | "provider"
            | "resource_urn"
            | "source_event_id"
            | "source_product"
            | "source_provider"
            | "source_system"
            | "tenant_id"
    )
}

fn select_records(document: &Value, selector: &str) -> Result<Vec<Value>, SourceExecutionError> {
    let selector = selector.trim();
    if selector == "$" {
        return Ok(vec![document.clone()]);
    }
    let wildcard = selector.ends_with("[*]");
    let path = selector.trim_end_matches("[*]");
    let selected = value_at(document, path).ok_or(SourceExecutionError::MalformedResponse)?;
    if wildcard || selected.is_array() {
        return selected
            .as_array()
            .cloned()
            .ok_or(SourceExecutionError::MalformedResponse);
    }
    Ok(vec![selected.clone()])
}

fn observed_timestamp(raw: &Value, values: &Map<String, Value>) -> Option<OffsetDateTime> {
    let direct = [
        "observed_at",
        "updated_at",
        "updatedAt",
        "last_seen_at",
        "created_at",
        "createdAt",
        "timestamp",
    ]
    .iter()
    .find_map(|key| values.get(*key).and_then(scalar));
    direct
        .or_else(|| {
            scalar_at(
                raw,
                &[
                    "$.systemData.lastModifiedAt".to_owned(),
                    "$.systemData.createdAt".to_owned(),
                    "$.metadata.updated_at".to_owned(),
                    "$.metadata.created_at".to_owned(),
                ],
            )
        })
        .and_then(|value| OffsetDateTime::parse(value.trim(), &Rfc3339).ok())
}

fn scalar(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn urn_component(value: &str) -> Result<String, SourceExecutionError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 1_024 || value.chars().any(char::is_control) {
        return Err(SourceExecutionError::MissingStableIdentity);
    }
    Ok(value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                vec![char::from(byte)]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect())
}

fn reject_untrusted(value: &Value, depth: usize) -> Result<(), SourceExecutionError> {
    if depth > MAX_DEPTH {
        return Err(SourceExecutionError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let normalized = key
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if matches!(normalized.as_str(), "tenant" | "tenantid") {
                    return Err(SourceExecutionError::TenantMismatch);
                }
                if matches!(
                    normalized.as_str(),
                    "authorization"
                        | "accesstoken"
                        | "refreshtoken"
                        | "apikey"
                        | "clientsecret"
                        | "password"
                        | "privatekey"
                        | "sessioncookie"
                ) {
                    return Err(SourceExecutionError::InvalidProviderRecord);
                }
                reject_untrusted(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > MAX_RECORDS {
                return Err(SourceExecutionError::ResponseTooLarge);
            }
            for value in values {
                reject_untrusted(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
