use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AhaError, AhaFamily, AhaKernel, AhaRecord, AhaRuntimeDefinition};

pub(super) fn normalize(kernel: &AhaKernel, raw: Value) -> Result<AhaRecord, AhaError> {
    reject_protected(&raw, 0)?;
    let values = raw.as_object().ok_or(AhaError::InvalidProviderRecord)?;
    let provider_id = required_scalar(values, kernel.family.id_field())
        .map_err(|_| AhaError::MissingStableIdentity)?;
    if kernel.family == AhaFamily::Releases {
        let product_id =
            nested_scalar(values, &["product", "id"]).ok_or(AhaError::InvalidProviderRecord)?;
        if Some(product_id.as_str()) != kernel.product_id.as_deref() {
            return Err(AhaError::ProductMismatch);
        }
    }
    let occurred_at = occurred_at(kernel, values)?;
    let record = AhaRecord {
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
    kernel: &AhaKernel,
    values: &Map<String, Value>,
    provider_id: &str,
    occurred_at: &str,
) -> Result<BTreeMap<String, String>, AhaError> {
    let mut output = BTreeMap::from([
        ("external_id".to_owned(), provider_id.to_owned()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("observed_at".to_owned(), occurred_at.to_owned()),
        ("provider".to_owned(), "aha".to_owned()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_provider".to_owned(), "aha".to_owned()),
        ("source_system".to_owned(), "aha".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    match kernel.family {
        AhaFamily::AuditEvents => audit_attributes(&mut output, values, provider_id)?,
        AhaFamily::Features => feature_attributes(&mut output, values, provider_id)?,
        AhaFamily::Products => product_attributes(&mut output, values, provider_id)?,
        AhaFamily::Releases => release_attributes(&mut output, values, provider_id)?,
        AhaFamily::Users => user_attributes(&mut output, values, provider_id)?,
    }
    Ok(output)
}

fn user_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AhaError> {
    let name = required_scalar(values, "name")?;
    output.extend(BTreeMap::from([
        ("display_name".to_owned(), name.clone()),
        ("record_class".to_owned(), "identity_user".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), "user".to_owned()),
        ("user_id".to_owned(), provider_id.to_owned()),
    ]));
    if let Some(email) = scalar(values.get("email")).filter(|value| !value.is_empty()) {
        output.insert("email".to_owned(), email.clone());
        output.insert("primary_email".to_owned(), email);
    }
    Ok(())
}

fn product_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AhaError> {
    let name = required_scalar(values, "name")?;
    let tenant = output
        .get("tenant_id")
        .cloned()
        .ok_or(AhaError::InternalRuntimeFailure)?;
    common_resource_for_tenant(output, &tenant, "products", provider_id, name, "product");
    output.insert("product_id".to_owned(), provider_id.to_owned());
    copy(output, values, "reference_prefix", "product_key");
    Ok(())
}

fn feature_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AhaError> {
    let name = required_scalar(values, "name")?;
    let tenant = output
        .get("tenant_id")
        .cloned()
        .ok_or(AhaError::InternalRuntimeFailure)?;
    common_resource_for_tenant(output, &tenant, "features", provider_id, name, "feature");
    output.insert("feature_id".to_owned(), provider_id.to_owned());
    copy(output, values, "reference_num", "reference_num");
    nested_copy(output, values, &["product", "id"], "product_id");
    nested_copy(output, values, &["release", "id"], "release_id");
    Ok(())
}

fn release_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AhaError> {
    let name = required_scalar(values, "name")?;
    let tenant = output
        .get("tenant_id")
        .cloned()
        .ok_or(AhaError::InternalRuntimeFailure)?;
    common_resource_for_tenant(output, &tenant, "releases", provider_id, name, "release");
    output.insert("release_id".to_owned(), provider_id.to_owned());
    copy(output, values, "reference_num", "reference_num");
    copy(output, values, "release_date", "release_date");
    nested_copy(output, values, &["product", "id"], "product_id");
    Ok(())
}

fn audit_attributes(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(), AhaError> {
    let actor_id = nested_scalar(values, &["user", "id"]).ok_or(AhaError::InvalidProviderRecord)?;
    let action = required_scalar(values, "action")?;
    let resource_id = required_scalar(values, "auditable_id")?;
    let resource_type = required_scalar(values, "auditable_type")?;
    let tenant = output
        .get("tenant_id")
        .cloned()
        .ok_or(AhaError::InternalRuntimeFailure)?;
    let resource_urn = format!(
        "urn:cerebro:{}:aha_audit_events:{}",
        encode_segment(&tenant),
        encode_segment(provider_id)
    );
    output.extend(BTreeMap::from([
        ("actor_id".to_owned(), actor_id),
        ("event_type".to_owned(), action),
        ("record_class".to_owned(), "audit_event".to_owned()),
        ("resource_id".to_owned(), resource_id),
        ("resource_name".to_owned(), provider_id.to_owned()),
        ("resource_type".to_owned(), resource_type),
        ("resource_urn".to_owned(), resource_urn),
    ]));
    nested_copy(output, values, &["user", "name"], "actor_name");
    nested_copy(output, values, &["user", "email"], "actor_email");
    Ok(())
}

fn common_resource_for_tenant(
    output: &mut BTreeMap<String, String>,
    tenant: &str,
    family: &str,
    provider_id: &str,
    name: String,
    resource_type: &str,
) {
    output.extend(BTreeMap::from([
        ("record_class".to_owned(), "asset".to_owned()),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), resource_type.to_owned()),
        (
            "resource_urn".to_owned(),
            format!(
                "urn:cerebro:{}:aha_{}:{}",
                encode_segment(tenant),
                family,
                encode_segment(provider_id)
            ),
        ),
    ]));
}

fn occurred_at(kernel: &AhaKernel, values: &Map<String, Value>) -> Result<String, AhaError> {
    for key in ["updated_at", "created_at"] {
        if let Some(value) = scalar(values.get(key)).filter(|value| !value.is_empty()) {
            return valid_time(&value);
        }
    }
    Ok(kernel.observed_at.clone())
}

fn valid_time(value: &str) -> Result<String, AhaError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AhaError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AhaError::InvalidProviderRecord)
}

fn admit(record: &AhaRecord) -> Result<(), AhaError> {
    let contract = AhaRuntimeDefinition::compile(record.family)?.event_contract;
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
        return Err(AhaError::EventContractRejection);
    }
    Ok(())
}

fn event_id(kernel: &AhaKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}\0{}",
        kernel.base_url.as_str(),
        kernel.family.as_str(),
        kernel.product_id.as_deref().unwrap_or("")
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "aha-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn required_scalar(values: &Map<String, Value>, key: &str) -> Result<String, AhaError> {
    scalar(values.get(key))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(AhaError::InvalidProviderRecord)
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

fn reject_protected(value: &Value, depth: usize) -> Result<(), AhaError> {
    if depth > 16 {
        return Err(AhaError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AhaError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if key == "tenant_id" {
                    return Err(AhaError::TenantMismatch);
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
                    return Err(AhaError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(AhaError::TooManyRecords);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
