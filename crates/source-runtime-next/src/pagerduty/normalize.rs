//! Deterministic Go-compatible PagerDuty record normalization.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{PagerDutyError, PagerDutyFamily, PagerDutyRecord};

pub(super) fn require_tenant(value: &str) -> Result<String, PagerDutyError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(char::is_control)
        || value.contains('/')
        || value.contains(':')
    {
        return Err(PagerDutyError::MissingTenantId);
    }
    Ok(value.to_owned())
}

pub(super) fn require_safe_identity(value: &str) -> Result<(), PagerDutyError> {
    if value.is_empty()
        || value.len() > 512
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(PagerDutyError::InvalidProviderIdentity);
    }
    Ok(())
}

pub(super) fn normalize_record(
    family: PagerDutyFamily,
    tenant_id: &str,
    origin: &str,
    path: &str,
    configured_service_id: Option<&str>,
    payload: Value,
    observed_at: OffsetDateTime,
) -> Result<PagerDutyRecord, PagerDutyError> {
    let object = payload
        .as_object()
        .ok_or(PagerDutyError::MalformedResponse)?;
    let provider_id = scalar(object.get("id")).ok_or(PagerDutyError::MissingProviderIdentity)?;
    require_safe_identity(&provider_id)?;

    let mut attributes = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), family.as_str().to_owned()),
        ("provider".to_owned(), "pagerduty".to_owned()),
        ("source_product".to_owned(), "pagerduty".to_owned()),
        ("source_provider".to_owned(), "pagerduty".to_owned()),
        (family.identity_attribute().to_owned(), provider_id.clone()),
    ]);

    match family {
        PagerDutyFamily::User => insert_fields(
            &mut attributes,
            object,
            &[
                ("name", &["name"]),
                ("email", &["email"]),
                ("role", &["role"]),
                ("time_zone", &["time_zone"]),
                ("job_title", &["job_title"]),
            ],
        ),
        PagerDutyFamily::Team => insert_fields(
            &mut attributes,
            object,
            &[("name", &["name"]), ("description", &["description"])],
        ),
        PagerDutyFamily::Service => insert_fields(
            &mut attributes,
            object,
            &[
                ("name", &["name"]),
                ("summary", &["summary"]),
                ("status", &["status"]),
                ("html_url", &["html_url"]),
                ("escalation_policy_id", &["escalation_policy.id"]),
                (
                    "escalation_policy_name",
                    &["escalation_policy.summary", "escalation_policy.name"],
                ),
            ],
        ),
        PagerDutyFamily::Schedule => insert_fields(
            &mut attributes,
            object,
            &[
                ("name", &["name"]),
                ("summary", &["summary"]),
                ("time_zone", &["time_zone"]),
                ("html_url", &["html_url"]),
            ],
        ),
        PagerDutyFamily::EscalationPolicy => insert_fields(
            &mut attributes,
            object,
            &[
                ("name", &["name"]),
                ("summary", &["summary"]),
                ("num_loops", &["num_loops"]),
                ("html_url", &["html_url"]),
            ],
        ),
        PagerDutyFamily::Integration => {
            let service_id = configured_service_id.ok_or(PagerDutyError::MissingServiceId)?;
            require_safe_identity(service_id).map_err(|_| PagerDutyError::InvalidServiceId)?;
            attributes.insert("service_id".to_owned(), service_id.to_owned());
            insert_fields(
                &mut attributes,
                object,
                &[
                    ("name", &["name"]),
                    ("summary", &["summary"]),
                    ("service_name", &["service.summary", "service.name"]),
                    ("vendor_id", &["vendor.id"]),
                    ("vendor_name", &["vendor.summary", "vendor.name"]),
                ],
            );
        }
        PagerDutyFamily::Vendor => insert_fields(
            &mut attributes,
            object,
            &[
                ("name", &["name"]),
                ("summary", &["summary"]),
                ("website_url", &["website_url"]),
            ],
        ),
    }

    validate_event_contract(family, &attributes, object)?;
    let occurred_at = provider_time(family, object)
        .unwrap_or(observed_at)
        .format(&Rfc3339)
        .map_err(|_| PagerDutyError::EventContractRejected)?;
    let payload = sanitize_payload(payload);
    Ok(PagerDutyRecord {
        family,
        tenant_id: tenant_id.to_owned(),
        provider_id: provider_id.clone(),
        event_id: event_id(tenant_id, origin, path, family, &provider_id),
        event_kind: family.event_kind().to_owned(),
        schema_ref: family.schema_ref().to_owned(),
        attributes,
        occurred_at,
        payload,
    })
}

fn sanitize_payload(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| !secret_field(key))
                .map(|(key, value)| (key, sanitize_payload(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(sanitize_payload).collect()),
        other => other,
    }
}

fn secret_field(key: &str) -> bool {
    let key = key.trim().to_ascii_lowercase().replace('-', "_");
    matches!(
        key.as_str(),
        "token"
            | "access_token"
            | "api_token"
            | "api_key"
            | "integration_key"
            | "routing_key"
            | "password"
            | "secret"
            | "client_secret"
            | "private_key"
            | "authorization"
            | "cookie"
            | "set_cookie"
            | "session_cookie"
    ) || key.ends_with("_token")
        || key.ends_with("_password")
        || key.ends_with("_secret")
        || key.ends_with("_api_key")
        || key.ends_with("_private_key")
        || key.ends_with("_cookie")
}

fn insert_fields(
    attributes: &mut BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
    mappings: &[(&str, &[&str])],
) {
    for (attribute, paths) in mappings {
        if let Some(value) = first_path(object, paths) {
            attributes.insert((*attribute).to_owned(), value);
        }
    }
}

fn first_path(object: &serde_json::Map<String, Value>, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| value_at(object, path))
}

fn value_at(object: &serde_json::Map<String, Value>, path: &str) -> Option<String> {
    let mut value = object.get(path.split('.').next()?)?;
    for part in path.split('.').skip(1) {
        value = value.as_object()?.get(part)?;
    }
    scalar(Some(value))
}

fn scalar(value: Option<&Value>) -> Option<String> {
    let value = match value? {
        Value::String(value) => value.trim().to_owned(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        _ => return None,
    };
    (!value.is_empty()).then_some(value)
}

fn validate_event_contract(
    family: PagerDutyFamily,
    attributes: &BTreeMap<String, String>,
    object: &serde_json::Map<String, Value>,
) -> Result<(), PagerDutyError> {
    for key in [
        "external_id",
        "family",
        "source_provider",
        "source_product",
        family.identity_attribute(),
    ] {
        if attributes.get(key).is_none_or(String::is_empty) {
            return Err(PagerDutyError::EventContractRejected);
        }
    }
    if scalar(object.get("id")).is_none() {
        return Err(PagerDutyError::EventContractRejected);
    }
    if family == PagerDutyFamily::Integration
        && attributes.get("service_id").is_none_or(String::is_empty)
    {
        return Err(PagerDutyError::EventContractRejected);
    }
    Ok(())
}

fn provider_time(
    family: PagerDutyFamily,
    object: &serde_json::Map<String, Value>,
) -> Option<OffsetDateTime> {
    let keys: &[&str] = if family == PagerDutyFamily::Service {
        &["created_at", "updated_at", "timestamp"]
    } else {
        &["updated_at", "created_at", "timestamp"]
    };
    keys.iter().find_map(|key| {
        scalar(object.get(*key)).and_then(|value| OffsetDateTime::parse(&value, &Rfc3339).ok())
    })
}

pub(super) fn event_id(
    tenant_id: &str,
    origin: &str,
    path: &str,
    family: PagerDutyFamily,
    provider_id: &str,
) -> String {
    let scope = Sha256::digest([origin.as_bytes(), b"\0", path.as_bytes()].concat());
    format!(
        "pagerduty-{}-{}-{}-{}",
        normalize_id(tenant_id),
        hex_prefix(&scope, 12),
        normalize_id(family.as_str()),
        normalize_id(provider_id)
    )
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

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output.truncate(length);
    output
}
