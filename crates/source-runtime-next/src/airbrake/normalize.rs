use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AirbrakeError, AirbrakeFamily, AirbrakeKernel, AirbrakeRecord, AirbrakeRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &AirbrakeKernel,
    raw: Value,
) -> Result<AirbrakeRecord, AirbrakeError> {
    reject_protected(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(AirbrakeError::InvalidProviderRecord)?;
    let provider_id = required_scalar(values, kernel.family.id_field())
        .map_err(|_| AirbrakeError::MissingStableIdentity)?;
    validate_project_scope(kernel, values)?;

    let payload = inject_contract_fields(kernel, values.clone());
    let record = AirbrakeRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id: provider_id.clone(),
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at: occurred_at(kernel, values)?,
        attributes: attributes(kernel, values, &provider_id)?,
        payload,
    };
    admit(&record)?;
    Ok(record)
}

fn validate_project_scope(
    kernel: &AirbrakeKernel,
    values: &Map<String, Value>,
) -> Result<(), AirbrakeError> {
    let Some(configured) = kernel.project_id.as_deref() else {
        return Ok(());
    };
    if let Some(provider_project) = scalar(values.get("projectId"))
        && provider_project != configured
    {
        return Err(AirbrakeError::ProjectMismatch);
    }
    Ok(())
}

fn inject_contract_fields(kernel: &AirbrakeKernel, mut values: Map<String, Value>) -> Value {
    values.insert("source_id".to_owned(), Value::String("airbrake".to_owned()));
    values.insert(
        "tenant_id".to_owned(),
        Value::String(kernel.tenant_id.clone()),
    );
    values.insert(
        "schema_ref".to_owned(),
        Value::String(kernel.family.schema_ref().to_owned()),
    );
    Value::Object(values)
}

fn attributes(
    kernel: &AirbrakeKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<BTreeMap<String, String>, AirbrakeError> {
    let mut output = BTreeMap::from([
        ("provider".to_owned(), "airbrake".to_owned()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_system".to_owned(), "airbrake".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    match kernel.family {
        AirbrakeFamily::Deploys => asset_attributes(
            &mut output,
            kernel,
            values,
            provider_id,
            "airbrake_deploys",
            "airbrake_deploy",
            "version",
        )?,
        AirbrakeFamily::Projects => asset_attributes(
            &mut output,
            kernel,
            values,
            provider_id,
            "airbrake_projects",
            "airbrake_project",
            "name",
        )?,
        AirbrakeFamily::SourceMaps => asset_attributes(
            &mut output,
            kernel,
            values,
            provider_id,
            "airbrake_source_maps",
            "airbrake_source_map",
            "name",
        )?,
        AirbrakeFamily::Groups => group_attributes(&mut output, kernel, values, provider_id)?,
        AirbrakeFamily::ProjectActivities => activity_attributes(&mut output, values)?,
    }
    Ok(output)
}

fn asset_attributes(
    output: &mut BTreeMap<String, String>,
    kernel: &AirbrakeKernel,
    values: &Map<String, Value>,
    provider_id: &str,
    urn_kind: &str,
    resource_type: &str,
    name_field: &str,
) -> Result<(), AirbrakeError> {
    let name = required_scalar(values, name_field)?;
    let urn_id = if kernel.family == AirbrakeFamily::SourceMaps {
        provider_id.replacen("source-maps", "source_maps", 1)
    } else {
        provider_id.to_owned()
    };
    output.extend(BTreeMap::from([
        ("record_class".to_owned(), "asset".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), resource_type.to_owned()),
        (
            "resource_urn".to_owned(),
            format!(
                "urn:cerebro:{}:{urn_kind}:{}",
                encode_segment(&kernel.tenant_id),
                encode_segment(&urn_id)
            ),
        ),
    ]));
    Ok(())
}

fn group_attributes(
    output: &mut BTreeMap<String, String>,
    kernel: &AirbrakeKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AirbrakeError> {
    let project_id = required_scalar(values, "projectId")?;
    let title = values
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|errors| errors.first())
        .and_then(Value::as_object)
        .and_then(|error| scalar(error.get("type")))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(AirbrakeError::InvalidProviderRecord)?;
    let severity = nested_scalar(values, &["context", "severity"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "error".to_owned());
    let status = if scalar(values.get("resolved")).as_deref() == Some("true") {
        "resolved"
    } else {
        "open"
    };
    output.extend(BTreeMap::from([
        ("finding_id".to_owned(), provider_id.to_owned()),
        ("record_class".to_owned(), "finding".to_owned()),
        ("resource_id".to_owned(), project_id.clone()),
        ("resource_type".to_owned(), "airbrake_project".to_owned()),
        (
            "resource_urn".to_owned(),
            format!(
                "urn:cerebro:{}:airbrake_projects:source-airbrake-projects-{}",
                encode_segment(&kernel.tenant_id),
                encode_segment(&project_id)
            ),
        ),
        ("severity".to_owned(), severity),
        ("status".to_owned(), status.to_owned()),
        ("title".to_owned(), title),
    ]));
    Ok(())
}

fn activity_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
) -> Result<(), AirbrakeError> {
    let actor_id = required_scalar(values, "userId")?;
    let event_type = required_scalar(values, "activity")?;
    let resource_id = required_scalar(values, "trackableId")?;
    let resource_type = required_scalar(values, "trackableType")?;
    output.extend(BTreeMap::from([
        ("actor_id".to_owned(), actor_id),
        ("event_type".to_owned(), event_type),
        ("record_class".to_owned(), "audit_event".to_owned()),
        ("resource_id".to_owned(), resource_id),
        ("resource_name".to_owned(), resource_type.clone()),
        ("resource_type".to_owned(), resource_type),
    ]));
    if let Some(actor_name) = scalar(values.get("userName")).filter(|value| !value.is_empty()) {
        output.insert("actor_name".to_owned(), actor_name);
    }
    Ok(())
}

fn occurred_at(
    kernel: &AirbrakeKernel,
    values: &Map<String, Value>,
) -> Result<String, AirbrakeError> {
    let field = match kernel.family {
        AirbrakeFamily::Groups => Some("lastNoticeAt"),
        AirbrakeFamily::ProjectActivities => Some("createdAt"),
        AirbrakeFamily::Projects => Some("deployAt"),
        AirbrakeFamily::SourceMaps => Some("usedAt"),
        AirbrakeFamily::Deploys => None,
    };
    if let Some(value) = field
        .and_then(|field| scalar(values.get(field)))
        .filter(|value| !value.is_empty())
    {
        return valid_time(&value);
    }
    Ok(kernel.observed_at.clone())
}

fn valid_time(value: &str) -> Result<String, AirbrakeError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AirbrakeError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AirbrakeError::InvalidProviderRecord)
}

fn admit(record: &AirbrakeRecord) -> Result<(), AirbrakeError> {
    let contract = AirbrakeRuntimeDefinition::compile(record.family)?.event_contract;
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
        return Err(AirbrakeError::EventContractRejection);
    }
    Ok(())
}

fn event_id(kernel: &AirbrakeKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}\0{}",
        kernel.base_url.as_str(),
        kernel.family.as_str(),
        kernel.project_id.as_deref().unwrap_or("")
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "airbrake-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn required_scalar(values: &Map<String, Value>, key: &str) -> Result<String, AirbrakeError> {
    scalar(values.get(key))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(AirbrakeError::InvalidProviderRecord)
}

fn nested_scalar(values: &Map<String, Value>, path: &[&str]) -> Option<String> {
    let mut value = values.get(*path.first()?)?;
    for key in &path[1..] {
        value = value.as_object()?.get(*key)?;
    }
    scalar(Some(value)).filter(|value| !value.is_empty() && value.len() <= 512)
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

fn reject_protected(value: &Value, depth: usize) -> Result<(), AirbrakeError> {
    if depth > 16 {
        return Err(AirbrakeError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AirbrakeError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if key == "tenant_id" {
                    return Err(AirbrakeError::TenantMismatch);
                }
                if matches!(key.as_str(), "source_id" | "schema_ref") {
                    return Err(AirbrakeError::ProtectedContractField);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "api_key"
                        | "api_token"
                        | "password"
                        | "private_key"
                        | "authorization"
                        | "client_secret"
                        | "cookie"
                ) {
                    return Err(AirbrakeError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(AirbrakeError::TooManyRecords);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
