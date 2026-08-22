use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AkeneoError, AkeneoFamily, AkeneoKernel, AkeneoRecord, AkeneoRuntimeDefinition};

pub(super) fn normalize(kernel: &AkeneoKernel, raw: Value) -> Result<AkeneoRecord, AkeneoError> {
    reject_protected(&raw, 0)?;
    let values = raw.as_object().ok_or(AkeneoError::InvalidProviderRecord)?;
    let provider_id = stable_identity(values).ok_or(AkeneoError::MissingStableIdentity)?;
    let payload = inject_contract_fields(kernel, values.clone(), &provider_id);
    let record = AkeneoRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id: provider_id.clone(),
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at: occurred_at(kernel, values)?,
        attributes: attributes(kernel, values, &provider_id),
        payload,
    };
    admit(&record)?;
    Ok(record)
}

fn inject_contract_fields(
    kernel: &AkeneoKernel,
    mut values: Map<String, Value>,
    provider_id: &str,
) -> Value {
    for field in kernel.family.required_payload_fields() {
        values
            .entry((*field).to_owned())
            .or_insert_with(|| Value::String(provider_id.to_owned()));
    }
    values.insert("source_id".to_owned(), Value::String("akeneo".to_owned()));
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
    kernel: &AkeneoKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> BTreeMap<String, String> {
    let name = scalar(values.get("name"))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| provider_id.to_owned());
    let mut output = BTreeMap::from([
        ("api_method".to_owned(), "GET".to_owned()),
        (
            "api_path".to_owned(),
            kernel.family.path_template().to_owned(),
        ),
        ("external_id".to_owned(), provider_id.to_owned()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("id".to_owned(), provider_id.to_owned()),
        ("observed_at".to_owned(), kernel.observed_at.clone()),
        ("provider".to_owned(), "akeneo".to_owned()),
        (
            "record_class".to_owned(),
            if kernel.family == AkeneoFamily::AttributeGroup {
                "identity_group"
            } else {
                "asset"
            }
            .to_owned(),
        ),
        (
            "record_selector".to_owned(),
            kernel.family.record_selector().to_owned(),
        ),
        ("resource_id".to_owned(), provider_id.to_owned()),
        ("resource_name".to_owned(), name.clone()),
        (
            "resource_type".to_owned(),
            kernel.family.resource_type().to_owned(),
        ),
        (
            "resource_urn".to_owned(),
            format!(
                "urn:cerebro:{}:akeneo_{}:{}",
                encode_segment(&kernel.tenant_id),
                kernel.family.as_str(),
                encode_segment(provider_id)
            ),
        ),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_provider".to_owned(), "akeneo".to_owned()),
        ("source_system".to_owned(), "akeneo".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    if kernel.family.copies_name_attribute() {
        output.insert("name".to_owned(), name.clone());
    }
    copy_evidence(&mut output, values);
    if kernel.family == AkeneoFamily::AttributeGroup {
        output.extend(BTreeMap::from([
            (
                "description".to_owned(),
                scalar(values.get("description"))
                    .unwrap_or_else(|| format!("{name} identity_group")),
            ),
            (
                "domain".to_owned(),
                scalar(values.get("domain")).unwrap_or_else(|| format!("domain-{provider_id}")),
            ),
            (
                "group_email".to_owned(),
                scalar(values.get("group_email"))
                    .unwrap_or_else(|| "group@akeneo.example.test".to_owned()),
            ),
            ("group_id".to_owned(), provider_id.to_owned()),
            ("group_name".to_owned(), name),
            (
                "provider_id".to_owned(),
                format!("provider-id-{provider_id}"),
            ),
        ]));
    }
    output
}

fn copy_evidence(output: &mut BTreeMap<String, String>, values: &Map<String, Value>) {
    let Some(evidence) = values.get("evidence_cas").and_then(Value::as_object) else {
        return;
    };
    for (source, target) in [
        ("commit_id", "evidence_cas_commit_id"),
        ("digest", "evidence_cas_digest"),
        ("merkle_root", "evidence_cas_merkle_root"),
        ("ref_type", "evidence_cas_ref_type"),
        ("uri", "evidence_cas_uri"),
    ] {
        if let Some(value) = scalar(evidence.get(source)).filter(|value| !value.is_empty()) {
            output.insert(target.to_owned(), value);
        }
    }
}

fn occurred_at(kernel: &AkeneoKernel, values: &Map<String, Value>) -> Result<String, AkeneoError> {
    for field in ["updated_at", "updated", "created_at", "created"] {
        if let Some(value) = scalar(values.get(field)).filter(|value| !value.is_empty()) {
            return valid_time(&value);
        }
    }
    Ok(kernel.observed_at.clone())
}

fn valid_time(value: &str) -> Result<String, AkeneoError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AkeneoError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AkeneoError::InvalidProviderRecord)
}

fn admit(record: &AkeneoRecord) -> Result<(), AkeneoError> {
    let contract = AkeneoRuntimeDefinition::compile(record.family)?.event_contract;
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
        return Err(AkeneoError::EventContractRejection);
    }
    Ok(())
}

fn stable_identity(values: &Map<String, Value>) -> Option<String> {
    [
        "id",
        "code",
        "uuid",
        "identifier",
        "allowed_extensions",
        "assign_assets_to",
    ]
    .into_iter()
    .find_map(|field| scalar(values.get(field)))
    .filter(|value| !value.is_empty() && value.len() <= 512)
}

fn event_id(kernel: &AkeneoKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}\0{}",
        kernel.base_url.as_str(),
        kernel.family.as_str(),
        kernel.scope.identity_scope()
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "akeneo-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
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

fn reject_protected(value: &Value, depth: usize) -> Result<(), AkeneoError> {
    if depth > 16 {
        return Err(AkeneoError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AkeneoError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if key == "tenant_id" {
                    return Err(AkeneoError::TenantMismatch);
                }
                if matches!(key.as_str(), "source_id" | "schema_ref") {
                    return Err(AkeneoError::ProtectedContractField);
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
                    return Err(AkeneoError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(AkeneoError::TooManyRecords);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
