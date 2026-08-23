use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AddigyError, AddigyFamily, AddigyKernel, AddigyRecord, AddigyRuntimeDefinition};

pub(super) fn normalize(kernel: &AddigyKernel, raw: Value) -> Result<AddigyRecord, AddigyError> {
    reject_protected(&raw, 0)?;
    let values = raw.as_object().ok_or(AddigyError::InvalidProviderRecord)?;
    let provider_id = required_scalar(values, kernel.family.id_field())
        .map_err(|_| AddigyError::MissingStableIdentity)?;
    let organization_id = organization_id(kernel.family, values)?;
    if let Some(expected) = &kernel.organization_id
        && organization_id != *expected
    {
        return Err(AddigyError::OrganizationMismatch);
    }
    let record = AddigyRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id: provider_id.clone(),
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at: occurred_at(kernel, values)?,
        attributes: attributes(kernel, values, &provider_id, &organization_id)?,
        payload: raw,
    };
    admit(&record)?;
    Ok(record)
}

fn attributes(
    kernel: &AddigyKernel,
    values: &Map<String, Value>,
    provider_id: &str,
    organization_id: &str,
) -> Result<BTreeMap<String, String>, AddigyError> {
    let mut output = BTreeMap::from([
        ("external_id".to_owned(), provider_id.to_owned()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("observed_at".to_owned(), kernel.observed_at.clone()),
        ("organization_id".to_owned(), organization_id.to_owned()),
        ("provider".to_owned(), "addigy".to_owned()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_provider".to_owned(), "addigy".to_owned()),
        ("source_system".to_owned(), "addigy".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    match kernel.family {
        AddigyFamily::AuditEvents => audit_attributes(&mut output, values, provider_id)?,
        AddigyFamily::Devices => device_attributes(&mut output, values, provider_id, kernel)?,
        AddigyFamily::Groups => group_attributes(&mut output, values, provider_id)?,
        AddigyFamily::Policies => policy_attributes(&mut output, values, provider_id)?,
        AddigyFamily::Users => user_attributes(&mut output, values, provider_id)?,
    }
    Ok(output)
}

fn device_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
    kernel: &AddigyKernel,
) -> Result<(), AddigyError> {
    let name = nested_first(
        values,
        &[
            &["facts", "device_name", "value"],
            &["facts", "host_name", "value"],
            &["facts", "serial_number", "value"],
        ],
    )
    .unwrap_or_else(|| provider_id.to_owned());
    output.extend(BTreeMap::from([
        ("id".to_owned(), provider_id.to_owned()),
        ("record_class".to_owned(), "asset".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), "device".to_owned()),
        (
            "resource_urn".to_owned(),
            format!(
                "urn:cerebro:{}:addigy_devices:{}",
                encode_segment(&kernel.tenant_id),
                encode_segment(provider_id)
            ),
        ),
    ]));
    if let Some(serial) = nested_scalar(values, &["facts", "serial_number", "value"]) {
        output.insert("serial_number".to_owned(), serial);
    }
    Ok(())
}

fn user_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AddigyError> {
    let name = required_scalar(values, "name")?;
    output.extend(BTreeMap::from([
        ("display_name".to_owned(), name.clone()),
        ("email".to_owned(), provider_id.to_owned()),
        ("primary_email".to_owned(), provider_id.to_owned()),
        ("record_class".to_owned(), "identity_user".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), "user".to_owned()),
        ("user_id".to_owned(), provider_id.to_owned()),
    ]));
    copy(output, values, "addigy_role", "addigy_role");
    Ok(())
}

fn group_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AddigyError> {
    let external_id = scalar(values.get("external_id")).unwrap_or_else(|| provider_id.to_owned());
    let name = scalar(values.get("display_name"))
        .or_else(|| scalar(values.get("external_id")))
        .unwrap_or_else(|| provider_id.to_owned());
    output.extend(BTreeMap::from([
        ("external_id".to_owned(), external_id),
        ("group_id".to_owned(), provider_id.to_owned()),
        ("group_name".to_owned(), name.clone()),
        ("record_class".to_owned(), "identity_group".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), "group".to_owned()),
    ]));
    Ok(())
}

fn policy_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AddigyError> {
    let name = scalar(values.get("name")).unwrap_or_else(|| provider_id.to_owned());
    output.extend(BTreeMap::from([
        ("policy_id".to_owned(), provider_id.to_owned()),
        ("policy_name".to_owned(), name.clone()),
        ("policy_status".to_owned(), "configured".to_owned()),
        ("policy_type".to_owned(), "device_policy".to_owned()),
        ("record_class".to_owned(), "policy".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), "policy".to_owned()),
    ]));
    Ok(())
}

fn audit_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AddigyError> {
    output.extend(BTreeMap::from([
        ("id".to_owned(), provider_id.to_owned()),
        ("record_class".to_owned(), "audit_event".to_owned()),
    ]));
    required_nested(output, values, &["action", "name"], "event_type")?;
    if let Some(value) = nested_first(
        values,
        &[&["action_sender", "identifier"], &["action_sender", "name"]],
    ) {
        output.insert("actor_id".to_owned(), value);
    }
    nested_copy(output, values, &["action_sender", "name"], "actor_name");
    if let Some(value) = nested_first(
        values,
        &[
            &["action", "entity", "identifier"],
            &["action_receiver", "identifier"],
        ],
    ) {
        output.insert("resource_id".to_owned(), value);
    }
    if let Some(value) = nested_first(
        values,
        &[&["action", "entity", "name"], &["action_receiver", "name"]],
    ) {
        output.insert("resource_name".to_owned(), value);
    }
    if let Some(value) = nested_first(
        values,
        &[&["action", "entity", "type"], &["action_receiver", "type"]],
    ) {
        output.insert("resource_type".to_owned(), value);
    }
    nested_copy(output, values, &["result", "status"], "result");
    Ok(())
}

fn organization_id(
    family: AddigyFamily,
    values: &Map<String, Value>,
) -> Result<String, AddigyError> {
    let value = if family == AddigyFamily::Groups {
        nested_scalar(values, &["tenant", "value"])
    } else {
        scalar(values.get("orgid"))
    };
    value
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(AddigyError::InvalidProviderRecord)
}

fn occurred_at(kernel: &AddigyKernel, values: &Map<String, Value>) -> Result<String, AddigyError> {
    if kernel.family == AddigyFamily::Policies
        && let Some(seconds) = values.get("creation_time").and_then(Value::as_i64)
    {
        return OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(|_| AddigyError::InvalidProviderRecord)?
            .format(&Rfc3339)
            .map_err(|_| AddigyError::InvalidProviderRecord);
    }
    let key = match kernel.family {
        AddigyFamily::AuditEvents => Some("date"),
        AddigyFamily::Devices => Some("audit_date"),
        AddigyFamily::Groups | AddigyFamily::Policies | AddigyFamily::Users => None,
    };
    let value = key
        .and_then(|key| scalar(values.get(key)))
        .unwrap_or_else(|| kernel.observed_at.clone());
    let time =
        OffsetDateTime::parse(&value, &Rfc3339).map_err(|_| AddigyError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AddigyError::InvalidProviderRecord)
}

fn admit(record: &AddigyRecord) -> Result<(), AddigyError> {
    let contract = AddigyRuntimeDefinition::compile(record.family)?.event_contract;
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
        return Err(AddigyError::EventContractRejection);
    }
    Ok(())
}

fn event_id(kernel: &AddigyKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}\0{}",
        kernel.base_url.as_str(),
        kernel.family.as_str(),
        kernel.organization_id.as_deref().unwrap_or("")
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "addigy-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn required_scalar(values: &Map<String, Value>, key: &str) -> Result<String, AddigyError> {
    scalar(values.get(key))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(AddigyError::InvalidProviderRecord)
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

fn required_nested(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    path: &[&str],
    target: &str,
) -> Result<(), AddigyError> {
    let value = nested_scalar(values, path).ok_or(AddigyError::InvalidProviderRecord)?;
    output.insert(target.to_owned(), value);
    Ok(())
}

fn nested_copy(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    path: &[&str],
    target: &str,
) {
    if let Some(value) = nested_scalar(values, path) {
        output.insert(target.to_owned(), value);
    }
}

fn nested_first(values: &Map<String, Value>, paths: &[&[&str]]) -> Option<String> {
    paths.iter().find_map(|path| nested_scalar(values, path))
}

fn nested_scalar(values: &Map<String, Value>, path: &[&str]) -> Option<String> {
    let mut value = values.get(*path.first()?)?;
    for key in &path[1..] {
        value = value.get(*key)?;
    }
    scalar(Some(value)).filter(|value| !value.is_empty())
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

fn reject_protected(value: &Value, depth: usize) -> Result<(), AddigyError> {
    if depth > 16 {
        return Err(AddigyError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AddigyError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if key == "tenant_id" {
                    return Err(AddigyError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "api_key"
                        | "api_token"
                        | "x_api_key"
                        | "password"
                        | "private_key"
                        | "authorization"
                        | "client_secret"
                ) {
                    return Err(AddigyError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(AddigyError::TooManyRecords);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
