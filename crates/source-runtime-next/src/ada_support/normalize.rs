use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AdaSupportError, AdaSupportFamily, AdaSupportKernel, AdaSupportRecord,
    AdaSupportRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &AdaSupportKernel,
    raw: Value,
) -> Result<AdaSupportRecord, AdaSupportError> {
    reject_protected(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(AdaSupportError::InvalidProviderRecord)?;
    let provider_id = required_scalar(values, kernel.family.id_field())
        .map_err(|_| AdaSupportError::MissingStableIdentity)?;
    let attributes = attributes(kernel, values, &provider_id)?;
    let payload = payload(kernel, values, &provider_id)?;
    let record = AdaSupportRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at: occurred_at(kernel, values)?,
        attributes,
        payload,
    };
    admit(&record)?;
    Ok(record)
}

fn attributes(
    kernel: &AdaSupportKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<BTreeMap<String, String>, AdaSupportError> {
    let resource_id = match kernel.family {
        AdaSupportFamily::AuditEvents => required_scalar(values, "entity_id")?,
        _ => provider_id.to_owned(),
    };
    let resource_urn = urn(&kernel.tenant_id, kernel.family, &resource_id);
    let mut output = BTreeMap::from([
        ("api_method".to_owned(), "GET".to_owned()),
        ("api_path".to_owned(), kernel.family.path().to_owned()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("provider".to_owned(), "ada_support".to_owned()),
        (
            "record_selector".to_owned(),
            kernel.family.record_selector().to_owned(),
        ),
        ("resource_urn".to_owned(), resource_urn),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_provider".to_owned(), "ada_support".to_owned()),
        ("source_system".to_owned(), "ada_support".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
        ("observed_at".to_owned(), kernel.observed_at.clone()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
    ]);
    match kernel.family {
        AdaSupportFamily::AuditEvents => {
            required_copy(&mut output, values, "actor_user_id", "actor_id")?;
            copy(&mut output, values, "actor_email", "actor_email");
            copy(&mut output, values, "actor_name", "actor_name");
            required_copy(&mut output, values, "activity", "event_type")?;
            output.insert("resource_id".to_owned(), resource_id);
            required_copy(&mut output, values, "entity_name", "resource_name")?;
            required_copy(&mut output, values, "entity_type", "resource_type")?;
        }
        AdaSupportFamily::Conversations => {
            output.insert("resource_id".to_owned(), provider_id.to_owned());
            output.insert("resource_type".to_owned(), "conversation".to_owned());
            required_copy(&mut output, values, "inquiry_summary", "resource_name")?;
        }
        AdaSupportFamily::EndUsers => {
            output.insert("user_id".to_owned(), provider_id.to_owned());
            let profile = values
                .get("profile")
                .and_then(Value::as_object)
                .ok_or(AdaSupportError::InvalidProviderRecord)?;
            required_copy(&mut output, profile, "display_name", "display_name")?;
            if let Some(email) = scalar(profile.get("email")) {
                output.insert("email".to_owned(), email.clone());
                output.insert("primary_email".to_owned(), email);
            }
        }
        AdaSupportFamily::KnowledgeArticles => {
            output.insert("policy_id".to_owned(), provider_id.to_owned());
            required_copy(&mut output, values, "name", "policy_name")?;
            required_copy(&mut output, values, "enabled", "policy_status")?;
            output.insert("policy_type".to_owned(), "knowledge_article".to_owned());
        }
        AdaSupportFamily::PlatformIntegrations => {
            output.insert("resource_id".to_owned(), provider_id.to_owned());
            required_copy(&mut output, values, "name", "resource_name")?;
            output.insert(
                "resource_type".to_owned(),
                "platform_integration".to_owned(),
            );
            copy(&mut output, values, "status", "status");
        }
    }
    Ok(output)
}

fn payload(
    kernel: &AdaSupportKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<Value, AdaSupportError> {
    let mut payload = values.clone();
    payload.insert("api_method".to_owned(), Value::String("GET".to_owned()));
    payload.insert(
        "api_path".to_owned(),
        Value::String(kernel.family.path().to_owned()),
    );
    payload.insert(
        "schema_ref".to_owned(),
        Value::String(kernel.family.schema_ref().to_owned()),
    );
    payload.insert(
        "source_id".to_owned(),
        Value::String("ada_support".to_owned()),
    );
    payload.insert(
        "tenant_id".to_owned(),
        Value::String(kernel.tenant_id.clone()),
    );
    payload.insert("event_id".to_owned(), Value::String(provider_id.to_owned()));
    match kernel.family {
        AdaSupportFamily::AuditEvents => {
            let resource_id = required_scalar(values, "entity_id")?;
            payload.insert("resource_id".to_owned(), Value::String(resource_id.clone()));
            payload.insert(
                "resource_urn".to_owned(),
                Value::String(urn(&kernel.tenant_id, kernel.family, &resource_id)),
            );
        }
        AdaSupportFamily::Conversations | AdaSupportFamily::PlatformIntegrations => {
            payload.insert(
                "resource_id".to_owned(),
                Value::String(provider_id.to_owned()),
            );
            payload.insert(
                "resource_urn".to_owned(),
                Value::String(urn(&kernel.tenant_id, kernel.family, provider_id)),
            );
        }
        AdaSupportFamily::EndUsers => {
            payload.insert("user_id".to_owned(), Value::String(provider_id.to_owned()));
        }
        AdaSupportFamily::KnowledgeArticles => {
            payload.insert(
                "policy_id".to_owned(),
                Value::String(provider_id.to_owned()),
            );
            payload.insert(
                "policy_name".to_owned(),
                Value::String(required_scalar(values, "name")?),
            );
        }
    }
    Ok(Value::Object(payload))
}

fn occurred_at(
    kernel: &AdaSupportKernel,
    values: &Map<String, Value>,
) -> Result<String, AdaSupportError> {
    let key = match kernel.family {
        AdaSupportFamily::AuditEvents => "timestamp",
        AdaSupportFamily::Conversations => "date_updated",
        AdaSupportFamily::EndUsers | AdaSupportFamily::KnowledgeArticles => "updated_at",
        AdaSupportFamily::PlatformIntegrations => "updated",
    };
    let value = scalar(values.get(key)).unwrap_or_else(|| kernel.observed_at.clone());
    let time = OffsetDateTime::parse(&value, &Rfc3339)
        .map_err(|_| AdaSupportError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AdaSupportError::InvalidProviderRecord)
}

fn admit(record: &AdaSupportRecord) -> Result<(), AdaSupportError> {
    let contract = AdaSupportRuntimeDefinition::compile(record.family)?.event_contract;
    if record.kind != contract.kind
        || record.schema_ref != contract.schema_ref
        || contract
            .required_attributes
            .iter()
            .any(|key| record.attributes.get(*key).is_none_or(String::is_empty))
        || contract
            .required_payload_fields
            .iter()
            .any(|key| record.payload.get(*key).is_none_or(Value::is_null))
    {
        return Err(AdaSupportError::EventContractRejection);
    }
    Ok(())
}

pub(super) fn event_id(kernel: &AdaSupportKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}",
        kernel.base_url.as_str(),
        kernel.family.path()
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "ada-support-{}-{scope}-{}-{}",
        event_segment(&kernel.tenant_id),
        event_segment(kernel.family.as_str()),
        event_segment(provider_id)
    )
}

fn urn(tenant: &str, family: AdaSupportFamily, id: &str) -> String {
    format!(
        "urn:cerebro:{}:ada_support_{}:{}",
        encode_segment(tenant),
        family.as_str(),
        encode_segment(id)
    )
}

fn required_scalar(values: &Map<String, Value>, key: &str) -> Result<String, AdaSupportError> {
    scalar(values.get(key))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(AdaSupportError::InvalidProviderRecord)
}

fn required_copy(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    target: &str,
) -> Result<(), AdaSupportError> {
    output.insert(target.to_owned(), required_scalar(values, source)?);
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

fn event_segment(value: &str) -> String {
    let value = value.trim();
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return value.to_owned();
    }
    let digest = Sha256::digest(value.as_bytes());
    format!(
        "sha256-{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn reject_protected(value: &Value, depth: usize) -> Result<(), AdaSupportError> {
    if depth > 16 {
        return Err(AdaSupportError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AdaSupportError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if matches!(
                    key.as_str(),
                    "tenant_id" | "runtime_id" | "source_runtime_id"
                ) {
                    return Err(AdaSupportError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "session_token"
                        | "api_key"
                        | "api_token"
                        | "x_api_key"
                        | "set_cookie"
                        | "password"
                        | "passcode"
                        | "secret"
                        | "private_key"
                        | "authorization"
                        | "client_secret"
                        | "cookie"
                ) {
                    return Err(AdaSupportError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(AdaSupportError::TooManyRecords);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
