use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AcunetixError, AcunetixFamily, AcunetixKernel, AcunetixRecord, AcunetixRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &AcunetixKernel,
    raw: Value,
) -> Result<AcunetixRecord, AcunetixError> {
    reject_protected(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(AcunetixError::InvalidProviderRecord)?;
    let provider_id = scalar(values.get(kernel.family.id_field()))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(AcunetixError::MissingStableIdentity)?;
    let record = AcunetixRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id: provider_id.clone(),
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at: occurred_at(kernel, values)?,
        attributes: attributes(kernel, values, &provider_id)?,
        payload: raw,
    };
    admit(&record)?;
    Ok(record)
}

fn attributes(
    kernel: &AcunetixKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<BTreeMap<String, String>, AcunetixError> {
    let mut output = BTreeMap::from([
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_system".to_owned(), "acunetix".to_owned()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
    ]);
    match kernel.family {
        AcunetixFamily::Reports => {
            asset(
                &mut output,
                &kernel.tenant_id,
                provider_id,
                scalar(values.get("template_name")).unwrap_or_else(|| provider_id.to_owned()),
                "report",
                "acunetix_reports",
            );
            copy(&mut output, values, "report_id", "id");
            copy(&mut output, values, "template_name", "name");
            copy(&mut output, values, "status", "status");
        }
        AcunetixFamily::Targets => {
            asset(
                &mut output,
                &kernel.tenant_id,
                provider_id,
                scalar(values.get("address")).unwrap_or_else(|| provider_id.to_owned()),
                "target",
                "acunetix_targets",
            );
            copy(&mut output, values, "target_id", "id");
            copy(&mut output, values, "target_id", "target_id");
            copy(&mut output, values, "address", "name");
            copy(&mut output, values, "criticality", "criticality");
            copy(&mut output, values, "description", "description");
        }
        AcunetixFamily::ScanningProfiles => {
            let name = required_scalar(values, "name")?;
            output.extend(BTreeMap::from([
                ("record_class".to_owned(), "policy".to_owned()),
                ("policy_id".to_owned(), provider_id.to_owned()),
                ("policy_name".to_owned(), name.clone()),
                ("policy_description".to_owned(), name.clone()),
                ("policy_type".to_owned(), "scanning_profile".to_owned()),
                ("resource_id".to_owned(), provider_id.to_owned()),
                ("resource_name".to_owned(), name),
                ("resource_type".to_owned(), "scanning_profile".to_owned()),
            ]));
            copy(&mut output, values, "sort_order", "policy_severity");
        }
        AcunetixFamily::Scans => {
            finding_base(&mut output, &kernel.tenant_id, values, provider_id)?;
            let title = required_scalar(values, "profile_name")?;
            output.insert("scan_id".to_owned(), provider_id.to_owned());
            output.insert("title".to_owned(), title.clone());
            output.insert("description".to_owned(), title);
            required_nested(
                &mut output,
                values,
                &["current_session", "status"],
                "status",
            )?;
            nested(&mut output, values, &["target", "address"], "resource_name");
        }
        AcunetixFamily::Vulnerabilities => {
            finding_base(&mut output, &kernel.tenant_id, values, provider_id)?;
            let title = required_scalar(values, "vt_name")?;
            output.insert("title".to_owned(), title.clone());
            output.insert("description".to_owned(), title);
            required_copy(&mut output, values, "severity", "severity")?;
            required_copy(&mut output, values, "status", "status")?;
            copy(&mut output, values, "affects_url", "affects_url");
            copy(&mut output, values, "affects_url", "resource_name");
        }
    }
    Ok(output)
}

fn asset(
    output: &mut BTreeMap<String, String>,
    tenant: &str,
    id: &str,
    name: String,
    resource_type: &str,
    urn_kind: &str,
) {
    output.extend(BTreeMap::from([
        ("record_class".to_owned(), "asset".to_owned()),
        ("resource_id".to_owned(), id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), resource_type.to_owned()),
        (
            "resource_urn".to_owned(),
            format!(
                "urn:cerebro:{}:{}:{}",
                encode_segment(tenant),
                urn_kind,
                encode_segment(id)
            ),
        ),
    ]));
}

fn finding_base(
    output: &mut BTreeMap<String, String>,
    tenant: &str,
    values: &Map<String, Value>,
    id: &str,
) -> Result<(), AcunetixError> {
    let target_id = required_scalar(values, "target_id")?;
    output.extend(BTreeMap::from([
        ("record_class".to_owned(), "finding".to_owned()),
        ("finding_id".to_owned(), id.to_owned()),
        ("resource_id".to_owned(), target_id.clone()),
        ("resource_type".to_owned(), "target".to_owned()),
        (
            "resource_urn".to_owned(),
            format!(
                "urn:cerebro:{}:acunetix_targets:{}",
                encode_segment(tenant),
                encode_segment(&target_id)
            ),
        ),
    ]));
    Ok(())
}

fn occurred_at(
    kernel: &AcunetixKernel,
    values: &Map<String, Value>,
) -> Result<String, AcunetixError> {
    let value = scalar(values.get("generation_date")).unwrap_or_else(|| kernel.observed_at.clone());
    let time = OffsetDateTime::parse(&value, &Rfc3339)
        .map_err(|_| AcunetixError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AcunetixError::InvalidProviderRecord)
}

fn admit(record: &AcunetixRecord) -> Result<(), AcunetixError> {
    let contract = AcunetixRuntimeDefinition::compile(record.family)?.event_contract;
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
        return Err(AcunetixError::EventContractRejection);
    }
    Ok(())
}

fn event_id(kernel: &AcunetixKernel, provider_id: &str) -> String {
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
        "acunetix-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn required_scalar(values: &Map<String, Value>, key: &str) -> Result<String, AcunetixError> {
    scalar(values.get(key))
        .filter(|value| !value.is_empty())
        .ok_or(AcunetixError::InvalidProviderRecord)
}

fn required_copy(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    target: &str,
) -> Result<(), AcunetixError> {
    output.insert(target.to_owned(), required_scalar(values, source)?);
    Ok(())
}

fn required_nested(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    path: &[&str],
    target: &str,
) -> Result<(), AcunetixError> {
    let value = nested_scalar(values, path).ok_or(AcunetixError::InvalidProviderRecord)?;
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

fn reject_protected(value: &Value, depth: usize) -> Result<(), AcunetixError> {
    if depth > 32 {
        return Err(AcunetixError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AcunetixError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.to_ascii_lowercase().replace(['-', '.'], "_");
                if key == "tenant_id" {
                    return Err(AcunetixError::TenantMismatch);
                }
                if [
                    "x_auth",
                    "api_key",
                    "token",
                    "authorization",
                    "password",
                    "private_key",
                ]
                .contains(&key.as_str())
                {
                    return Err(AcunetixError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 512 {
                return Err(AcunetixError::InvalidProviderRecord);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        Value::String(value) if value.len() > 64 * 1024 => {
            return Err(AcunetixError::InvalidProviderRecord);
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
