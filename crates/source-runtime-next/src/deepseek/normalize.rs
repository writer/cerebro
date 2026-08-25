use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{
    DeepSeekError, DeepSeekKernel, DeepSeekRecord, DeepSeekRuntimeDefinition, request::bounded,
};

pub(super) fn normalize(
    kernel: &DeepSeekKernel,
    raw: Value,
    observed_at: &str,
) -> Result<DeepSeekRecord, DeepSeekError> {
    reject_untrusted(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(DeepSeekError::InvalidProviderRecord)?;
    let provider_id = values
        .get(kernel.family.identity_field())
        .and_then(scalar_string)
        .and_then(|value| bounded(&value, 1_024))
        .ok_or(DeepSeekError::MissingStableIdentity)?;
    let occurred_at = timestamp(values, observed_at)?;
    let resource_type = kernel.family.as_str().to_owned();
    let resource_urn = format!(
        "urn:cerebro:{}:{}:{}",
        canonical_component(&kernel.tenant_id)?,
        kernel.family.urn_kind(),
        canonical_component(&provider_id)?
    );
    let resource_name = values
        .get("name")
        .and_then(scalar_string)
        .and_then(|value| bounded(&value, 1_024))
        .unwrap_or_else(|| provider_id.clone());

    let mut attributes = BTreeMap::from([
        ("api_method".to_owned(), "GET".to_owned()),
        ("api_path".to_owned(), kernel.family.path().to_owned()),
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("observed_at".to_owned(), occurred_at.clone()),
        ("provider".to_owned(), "deepseek".to_owned()),
        ("record_class".to_owned(), "asset".to_owned()),
        (
            "record_selector".to_owned(),
            kernel.family.record_selector().to_owned(),
        ),
        ("resource_id".to_owned(), provider_id.clone()),
        ("resource_name".to_owned(), resource_name),
        ("resource_type".to_owned(), resource_type.clone()),
        ("resource_urn".to_owned(), resource_urn.clone()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("source_provider".to_owned(), "deepseek".to_owned()),
        ("source_system".to_owned(), "deepseek".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    for (attribute, paths) in [
        (
            "evidence_cas_commit_id",
            &[
                "evidence_cas.commit_id",
                "evidence_cas_commit_id",
                "commit_id",
            ][..],
        ),
        (
            "evidence_cas_digest",
            &["evidence_cas.digest", "evidence_cas_digest", "digest"][..],
        ),
        (
            "evidence_cas_merkle_root",
            &[
                "evidence_cas.merkle_root",
                "evidence_cas_merkle_root",
                "merkle_root",
            ][..],
        ),
        (
            "evidence_cas_ref_type",
            &["evidence_cas.ref_type", "evidence_cas_ref_type", "ref_type"][..],
        ),
        (
            "evidence_cas_uri",
            &["evidence_cas.uri", "evidence_cas_uri", "uri"][..],
        ),
    ] {
        if let Some(value) = paths.iter().find_map(|path| value_at(values, path)) {
            attributes.insert(attribute.to_owned(), value);
        }
    }

    let definition = DeepSeekRuntimeDefinition::compile(kernel.family)?;
    if definition
        .event_contract
        .required_attributes
        .iter()
        .any(|field| attributes.get(*field).is_none_or(String::is_empty))
    {
        return Err(DeepSeekError::EventContractRejection);
    }

    let mut payload = values.clone();
    payload.insert("api_method".to_owned(), Value::from("GET"));
    payload.insert("api_path".to_owned(), Value::from(kernel.family.path()));
    payload.insert("event_id".to_owned(), Value::from(provider_id.clone()));
    payload.insert("family".to_owned(), Value::from(kernel.family.as_str()));
    payload.insert("observed_at".to_owned(), Value::from(occurred_at.clone()));
    payload.insert("record_class".to_owned(), Value::from("asset"));
    payload.insert(
        "record_selector".to_owned(),
        Value::from(kernel.family.record_selector()),
    );
    payload.insert("resource_id".to_owned(), Value::from(provider_id.clone()));
    payload.insert("resource_type".to_owned(), Value::from(resource_type));
    payload.insert("resource_urn".to_owned(), Value::from(resource_urn));
    payload.insert(
        "schema_ref".to_owned(),
        Value::from(kernel.family.schema_ref()),
    );
    payload.insert("source_id".to_owned(), Value::from("deepseek"));
    payload.insert(
        "tenant_id".to_owned(),
        Value::from(kernel.tenant_id.clone()),
    );
    let payload = Value::Object(payload);
    if definition
        .event_contract
        .required_payload_fields
        .iter()
        .any(|field| payload.get(*field).is_none_or(Value::is_null))
    {
        return Err(DeepSeekError::EventContractRejection);
    }

    Ok(DeepSeekRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(&kernel.tenant_id, kernel.family, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    })
}

pub(super) fn event_id(
    tenant_id: &str,
    family: super::DeepSeekFamily,
    provider_id: &str,
) -> String {
    let digest = Sha256::digest(format!("{tenant_id}\0{}\0{provider_id}", family.as_str()));
    let suffix = digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("deepseek-{}-{suffix}", family.as_str())
}

fn timestamp(values: &Map<String, Value>, observed_at: &str) -> Result<String, DeepSeekError> {
    ["observed_at", "updated_at", "last_seen_at", "created_at"]
        .iter()
        .find_map(|key| values.get(*key).and_then(scalar_string))
        .or_else(|| Some(observed_at.to_owned()))
        .and_then(|value| canonical_timestamp(&value))
        .ok_or(DeepSeekError::InvalidObservedAt)
}

fn canonical_timestamp(value: &str) -> Option<String> {
    OffsetDateTime::parse(value.trim(), &Rfc3339)
        .ok()?
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .ok()
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    let mut value = values.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        value = value.as_object()?.get(part)?;
    }
    scalar_string(value).and_then(|value| bounded(&value, 4_096))
}

fn canonical_component(value: &str) -> Result<String, DeepSeekError> {
    let value = bounded(value, 1_024).ok_or(DeepSeekError::MissingStableIdentity)?;
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

fn reject_untrusted(value: &Value, depth: usize) -> Result<(), DeepSeekError> {
    if depth > 32 {
        return Err(DeepSeekError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let key = key
                    .chars()
                    .filter(char::is_ascii_alphanumeric)
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                if matches!(key.as_str(), "tenant" | "tenantid") {
                    return Err(DeepSeekError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "authorization"
                        | "accesstoken"
                        | "refreshtoken"
                        | "apikey"
                        | "clientsecret"
                        | "password"
                        | "privatekey"
                        | "sessioncookie"
                ) {
                    return Err(DeepSeekError::CredentialMaterial);
                }
                reject_untrusted(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 4_096 {
                return Err(DeepSeekError::TooManyRecords);
            }
            for value in values {
                reject_untrusted(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
