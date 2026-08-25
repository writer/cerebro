use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AbnormalSecurityError, AbnormalSecurityFamily, AbnormalSecurityKernel, AbnormalSecurityRecord,
    AbnormalSecurityRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &AbnormalSecurityKernel,
    raw: Value,
) -> Result<AbnormalSecurityRecord, AbnormalSecurityError> {
    reject_protected(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(AbnormalSecurityError::InvalidProviderRecord)?;
    let provider_id = required_scalar(values, kernel.family.id_field())?;
    if provider_id.len() > 512 {
        return Err(AbnormalSecurityError::MissingStableIdentity);
    }
    let occurred_at = occurred_at(kernel, values)?;
    let record = AbnormalSecurityRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id: provider_id.clone(),
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        attributes: attributes(kernel, values, &provider_id, &occurred_at)?,
        occurred_at,
        payload: raw,
    };
    admit(&record)?;
    Ok(record)
}

fn attributes(
    kernel: &AbnormalSecurityKernel,
    values: &Map<String, Value>,
    provider_id: &str,
    occurred_at: &str,
) -> Result<BTreeMap<String, String>, AbnormalSecurityError> {
    let mut output = BTreeMap::from([
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_system".to_owned(), "abnormal_security".to_owned()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("observed_at".to_owned(), occurred_at.to_owned()),
    ]);
    match kernel.family {
        AbnormalSecurityFamily::Resources => {
            let name = required_scalar(values, "name")?;
            output.extend(BTreeMap::from([
                ("record_class".to_owned(), "asset".to_owned()),
                ("resource_id".to_owned(), provider_id.to_owned()),
                ("resource_name".to_owned(), name),
                ("resource_type".to_owned(), "resource".to_owned()),
                (
                    "resource_urn".to_owned(),
                    format!(
                        "urn:cerebro:{}:abnormal_security_resources:{}",
                        encode_segment(&kernel.tenant_id),
                        encode_segment(provider_id)
                    ),
                ),
            ]));
        }
        AbnormalSecurityFamily::Threats => {
            finding(&mut output, provider_id);
            output.insert("resource_type".to_owned(), "email_threat".to_owned());
            required_copy(&mut output, values, "severity", "severity")?;
            required_copy(&mut output, values, "status", "status")?;
            required_copy(&mut output, values, "title", "title")?;
        }
        AbnormalSecurityFamily::Cases => {
            finding(&mut output, provider_id);
            let employee = required_scalar(values, "affectedEmployee")?;
            output.extend(BTreeMap::from([
                ("resource_id".to_owned(), employee.clone()),
                ("resource_name".to_owned(), employee),
                ("resource_type".to_owned(), "abnormal_case".to_owned()),
            ]));
            required_copy(&mut output, values, "severity_level", "severity")?;
            required_copy(&mut output, values, "case_status", "status")?;
            required_copy(&mut output, values, "description", "title")?;
        }
        AbnormalSecurityFamily::PostureCatalog => {
            let name = required_scalar(values, "name")?;
            output.extend(BTreeMap::from([
                ("record_class".to_owned(), "policy".to_owned()),
                ("policy_id".to_owned(), provider_id.to_owned()),
                ("policy_name".to_owned(), name),
                ("policy_type".to_owned(), "posture_catalog".to_owned()),
            ]));
            required_copy(&mut output, values, "description", "policy_description")?;
            required_copy(&mut output, values, "risk_level", "policy_severity")?;
        }
        AbnormalSecurityFamily::AuditEvents => {
            output.insert("record_class".to_owned(), "audit_event".to_owned());
            required_copy(&mut output, values, "action", "event_type")?;
            required_nested(&mut output, values, &["user", "email"], "actor_id")?;
            required_nested(&mut output, values, &["user", "email"], "actor_email")?;
            nested(
                &mut output,
                values,
                &["actionDetails", "message_id"],
                "resource_id",
            );
            nested(
                &mut output,
                values,
                &["actionDetails", "request_url"],
                "resource_name",
            );
            copy(&mut output, values, "category", "resource_type");
        }
    }
    Ok(output)
}

fn finding(output: &mut BTreeMap<String, String>, provider_id: &str) {
    output.insert("record_class".to_owned(), "finding".to_owned());
    output.insert("finding_id".to_owned(), provider_id.to_owned());
}

fn occurred_at(
    kernel: &AbnormalSecurityKernel,
    values: &Map<String, Value>,
) -> Result<String, AbnormalSecurityError> {
    let key = match kernel.family {
        AbnormalSecurityFamily::Resources => "updated_at",
        AbnormalSecurityFamily::AuditEvents => "timestamp",
        AbnormalSecurityFamily::Cases => "last_modified",
        AbnormalSecurityFamily::PostureCatalog => "updated_at",
        AbnormalSecurityFamily::Threats => "receivedTime",
    };
    let value = scalar(values.get(key)).unwrap_or_else(|| kernel.observed_at.clone());
    let time = OffsetDateTime::parse(&value, &Rfc3339)
        .map_err(|_| AbnormalSecurityError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AbnormalSecurityError::InvalidProviderRecord)
}

fn admit(record: &AbnormalSecurityRecord) -> Result<(), AbnormalSecurityError> {
    let contract = AbnormalSecurityRuntimeDefinition::compile(record.family)?.event_contract;
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
        return Err(AbnormalSecurityError::EventContractRejection);
    }
    Ok(())
}

pub(super) fn event_id(kernel: &AbnormalSecurityKernel, provider_id: &str) -> String {
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
        "abnormal-security-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn required_scalar(
    values: &Map<String, Value>,
    key: &str,
) -> Result<String, AbnormalSecurityError> {
    scalar(values.get(key))
        .filter(|value| !value.is_empty())
        .ok_or(AbnormalSecurityError::MissingStableIdentity)
}

fn required_copy(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    target: &str,
) -> Result<(), AbnormalSecurityError> {
    let value = scalar(values.get(source))
        .filter(|value| !value.is_empty())
        .ok_or(AbnormalSecurityError::InvalidProviderRecord)?;
    output.insert(target.to_owned(), value);
    Ok(())
}

fn required_nested(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    path: &[&str],
    target: &str,
) -> Result<(), AbnormalSecurityError> {
    let value = nested_scalar(values, path).ok_or(AbnormalSecurityError::InvalidProviderRecord)?;
    output.insert(target.to_owned(), value);
    Ok(())
}

fn nested(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    path: &[&str],
    target: &str,
) {
    if let Some(value) = nested_scalar(values, path) {
        output.insert(target.to_owned(), value);
    }
}

fn nested_scalar(values: &Map<String, Value>, path: &[&str]) -> Option<String> {
    let mut value = values.get(*path.first()?)?;
    for key in &path[1..] {
        value = value.get(*key)?;
    }
    scalar(Some(value)).filter(|value| !value.is_empty())
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

fn reject_protected(value: &Value, depth: usize) -> Result<(), AbnormalSecurityError> {
    if depth > 32 {
        return Err(AbnormalSecurityError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AbnormalSecurityError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.to_ascii_lowercase().replace(['-', '.'], "_");
                if ["tenant", "tenant_id", "runtime_id", "source_runtime_id"]
                    .contains(&key.as_str())
                {
                    return Err(AbnormalSecurityError::TenantMismatch);
                }
                if [
                    "token",
                    "access_token",
                    "refresh_token",
                    "session_token",
                    "api_key",
                    "api_token",
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
                    return Err(AbnormalSecurityError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 512 {
                return Err(AbnormalSecurityError::InvalidProviderRecord);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        Value::String(value) if value.len() > 64 * 1024 => {
            return Err(AbnormalSecurityError::InvalidProviderRecord);
        }
        _ => {}
    }
    Ok(())
}

fn normalize_id(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
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
