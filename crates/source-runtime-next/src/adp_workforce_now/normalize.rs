use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::{
    Date, OffsetDateTime, PrimitiveDateTime, Time, format_description,
    format_description::well_known::Rfc3339,
};

use super::{AdpError, AdpFamily, AdpKernel, AdpRecord, AdpRuntimeDefinition};

pub(super) fn normalize(kernel: &AdpKernel, raw: Value) -> Result<AdpRecord, AdpError> {
    reject_protected(&raw, 0)?;
    let values = raw.as_object().ok_or(AdpError::InvalidProviderRecord)?;
    let provider_id = required_scalar(values, kernel.family.id_field())
        .map_err(|_| AdpError::MissingStableIdentity)?;
    let occurred_at = occurred_at(kernel, values)?;
    let observed_at = provider_observed_at(kernel, values);
    let attributes = attributes(kernel, values, &provider_id, &observed_at)?;
    let payload = payload(kernel, values)?;
    let record = AdpRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    };
    admit(&record)?;
    Ok(record)
}

fn attributes(
    kernel: &AdpKernel,
    values: &Map<String, Value>,
    provider_id: &str,
    observed_at: &str,
) -> Result<BTreeMap<String, String>, AdpError> {
    let mut output = BTreeMap::from([
        ("api_method".to_owned(), "GET".to_owned()),
        ("api_path".to_owned(), kernel.family.path().to_owned()),
        ("external_id".to_owned(), provider_id.to_owned()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("observed_at".to_owned(), observed_at.to_owned()),
        ("provider".to_owned(), "adp_workforce_now".to_owned()),
        (
            "record_selector".to_owned(),
            match kernel.family {
                AdpFamily::EventNotifications => "$.events[*]",
                AdpFamily::Users => "$.workers[*]",
            }
            .to_owned(),
        ),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_provider".to_owned(), "adp_workforce_now".to_owned()),
        ("source_system".to_owned(), "adp_workforce_now".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    match kernel.family {
        AdpFamily::EventNotifications => {
            output.insert("id".to_owned(), provider_id.to_owned());
            output.insert("record_class".to_owned(), "audit_event".to_owned());
            output.insert(
                "resource_urn".to_owned(),
                urn(&kernel.tenant_id, kernel.family, provider_id),
            );
            required_nested(
                &mut output,
                values,
                &["eventNameCode", "codeValue"],
                "event_type",
            )?;
            nested_copy(
                &mut output,
                values,
                &["originator", "associateOID"],
                "actor_id",
            );
            nested_copy(
                &mut output,
                values,
                &["data", "eventContext", "worker", "associateOID"],
                "resource_id",
            );
            output.insert("resource_type".to_owned(), "worker".to_owned());
        }
        AdpFamily::Users => {
            let name = required_nested_scalar(values, &["person", "legalName", "formattedName"])?;
            output.extend(BTreeMap::from([
                ("display_name".to_owned(), name.clone()),
                ("record_class".to_owned(), "identity_user".to_owned()),
                ("resource_id".to_owned(), provider_id.to_owned()),
                ("resource_name".to_owned(), name),
                ("resource_type".to_owned(), "worker".to_owned()),
                (
                    "resource_urn".to_owned(),
                    urn(&kernel.tenant_id, kernel.family, provider_id),
                ),
                ("user_id".to_owned(), provider_id.to_owned()),
            ]));
            if let Some(email) = nested_scalar(
                values,
                &["businessCommunication", "emails", "0", "emailUri"],
            ) {
                for key in ["domain", "email", "login", "primary_email"] {
                    output.insert(key.to_owned(), email.clone());
                }
            }
            nested_copy(
                &mut output,
                values,
                &[
                    "workAssignments",
                    "0",
                    "homeOrganizationalUnits",
                    "0",
                    "nameCode",
                    "shortName",
                ],
                "department",
            );
            nested_copy(
                &mut output,
                values,
                &["workAssignments", "0", "jobTitle"],
                "job_title",
            );
            nested_copy(
                &mut output,
                values,
                &["workAssignments", "0", "reportsTo", "0", "associateOID"],
                "manager",
            );
            nested_copy(
                &mut output,
                values,
                &["workerStatus", "statusCode", "codeValue"],
                "status",
            );
            nested_copy(
                &mut output,
                values,
                &["workerDates", "originalHireDate"],
                "created_at",
            );
        }
    }
    Ok(output)
}

fn payload(kernel: &AdpKernel, values: &Map<String, Value>) -> Result<Value, AdpError> {
    let mut output = values.clone();
    output.insert(
        "schema_ref".to_owned(),
        Value::String(kernel.family.schema_ref().to_owned()),
    );
    output.insert(
        "source_id".to_owned(),
        Value::String("adp_workforce_now".to_owned()),
    );
    output.insert(
        "tenant_id".to_owned(),
        Value::String(kernel.tenant_id.clone()),
    );
    if kernel.family == AdpFamily::EventNotifications {
        let actor = required_nested_scalar(values, &["originator", "associateOID"])?;
        output.insert("actor".to_owned(), json!({"associateOID": actor}));
    }
    Ok(Value::Object(output))
}

fn provider_observed_at(kernel: &AdpKernel, values: &Map<String, Value>) -> String {
    match kernel.family {
        AdpFamily::EventNotifications => {
            nested_scalar(values, &["eventStatusCode", "effectiveDateTime"])
        }
        AdpFamily::Users => nested_scalar(values, &["workerDates", "originalHireDate"]),
    }
    .unwrap_or_else(|| kernel.observed_at.clone())
}

fn occurred_at(kernel: &AdpKernel, values: &Map<String, Value>) -> Result<String, AdpError> {
    let value = provider_observed_at(kernel, values);
    if let Ok(time) = OffsetDateTime::parse(&value, &Rfc3339) {
        return time
            .format(&Rfc3339)
            .map_err(|_| AdpError::InvalidProviderRecord);
    }
    let date_format = format_description::parse_borrowed::<2>("[year]-[month]-[day]")
        .map_err(|_| AdpError::InternalRuntimeFailure)?;
    let date = Date::parse(&value, &date_format).map_err(|_| AdpError::InvalidProviderRecord)?;
    PrimitiveDateTime::new(date, Time::MIDNIGHT)
        .assume_utc()
        .format(&Rfc3339)
        .map_err(|_| AdpError::InvalidProviderRecord)
}

fn admit(record: &AdpRecord) -> Result<(), AdpError> {
    let contract = AdpRuntimeDefinition::compile(record.family)?.event_contract;
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
        return Err(AdpError::EventContractRejection);
    }
    Ok(())
}

fn event_id(kernel: &AdpKernel, provider_id: &str) -> String {
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
        "adp-workforce-now-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn urn(tenant: &str, family: AdpFamily, id: &str) -> String {
    format!(
        "urn:cerebro:{}:adp_workforce_now_{}:{}",
        encode_segment(tenant),
        family.as_str(),
        encode_segment(id)
    )
}

fn required_scalar(values: &Map<String, Value>, key: &str) -> Result<String, AdpError> {
    scalar(values.get(key))
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or(AdpError::InvalidProviderRecord)
}

fn required_nested(
    output: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    path: &[&str],
    target: &str,
) -> Result<(), AdpError> {
    output.insert(target.to_owned(), required_nested_scalar(values, path)?);
    Ok(())
}

fn required_nested_scalar(values: &Map<String, Value>, path: &[&str]) -> Result<String, AdpError> {
    nested_scalar(values, path).ok_or(AdpError::InvalidProviderRecord)
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
        value = match value {
            Value::Array(items) => items.get(key.parse::<usize>().ok()?)?,
            Value::Object(fields) => fields.get(*key)?,
            _ => return None,
        };
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

fn reject_protected(value: &Value, depth: usize) -> Result<(), AdpError> {
    if depth > 16 {
        return Err(AdpError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AdpError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if key == "tenant_id" {
                    return Err(AdpError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "api_key"
                        | "password"
                        | "private_key"
                        | "authorization"
                        | "client_secret"
                        | "client_certificate"
                        | "client_key"
                ) {
                    return Err(AdpError::CredentialMaterial);
                }
                reject_protected(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(AdpError::TooManyRecords);
            }
            for value in values {
                reject_protected(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
