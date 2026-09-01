use std::{collections::BTreeMap, fmt::Write as _};

use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    error::DopplerError,
    family::DopplerFamily,
    origin,
    types::{DopplerKernel, DopplerRecord},
};

pub(super) fn normalize_record(
    kernel: &DopplerKernel,
    value: &Value,
) -> Result<DopplerRecord, DopplerError> {
    reject_tenant_override(value)?;
    let object = value
        .as_object()
        .ok_or(DopplerError::InvalidProviderRecord)?;
    let raw_id = object
        .get("id")
        .ok_or(DopplerError::MissingStableIdentity)?;
    let provider_id =
        origin::provider_id(&scalar_string(raw_id).ok_or(DopplerError::MissingStableIdentity)?)?;
    let occurred_at_unix_millis = occurred_at(object, kernel.observed_at_unix_millis);
    let mut attributes = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("provider".to_owned(), "doppler".to_owned()),
        (
            "record_class".to_owned(),
            kernel.family.record_class().to_owned(),
        ),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("source_provider".to_owned(), "doppler".to_owned()),
        ("source_system".to_owned(), "doppler".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    let mut payload = Map::from_iter([("id".to_owned(), raw_id.clone())]);

    match kernel.family {
        DopplerFamily::Secrets => {
            normalize_secret(kernel, object, &provider_id, &mut attributes, &mut payload)?
        }
        DopplerFamily::Projects => {
            normalize_project(kernel, object, &provider_id, &mut attributes, &mut payload)
        }
        DopplerFamily::AuditEvents => {
            normalize_audit_event(kernel, object, &provider_id, &mut attributes, &mut payload)?
        }
    }

    if kernel.family.required_attributes().iter().any(|key| {
        attributes
            .get(*key)
            .is_none_or(|value| value.trim().is_empty())
    }) {
        return Err(DopplerError::EventContractRejection);
    }
    Ok(DopplerRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(
            kernel.base_url.as_str().trim_end_matches('/'),
            &kernel.tenant_id,
            kernel.family,
            &provider_id,
        ),
        provider_id,
        family: kernel.family,
        event_kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at_unix_millis,
        attributes,
        payload: Value::Object(payload),
    })
}

fn normalize_secret(
    kernel: &DopplerKernel,
    object: &Map<String, Value>,
    provider_id: &str,
    attributes: &mut BTreeMap<String, String>,
    payload: &mut Map<String, Value>,
) -> Result<(), DopplerError> {
    let secret_id = first(object, &["secret_id", "id", "key", "sid", "name"])
        .ok_or(DopplerError::MissingStableIdentity)?;
    let secret_name = first(
        object,
        &["secret_name", "name", "display_name", "label", "title"],
    )
    .ok_or(DopplerError::EventContractRejection)?;
    let resource_id = first(object, &["resource_id", "id", "metadata.resource_id"])
        .unwrap_or_else(|| provider_id.to_owned());
    attributes.insert("secret_id".to_owned(), secret_id.clone());
    attributes.insert("secret_name".to_owned(), secret_name.clone());
    attributes.insert("resource_id".to_owned(), resource_id.clone());
    attributes.insert("resource_name".to_owned(), secret_name.clone());
    attributes.insert(
        "resource_type".to_owned(),
        first(object, &["resource_type", "type", "metadata.resource_type"])
            .unwrap_or_else(|| "secret".to_owned()),
    );
    attributes.insert(
        "resource_urn".to_owned(),
        resource_urn(kernel, &resource_id),
    );
    copy_attribute(
        object,
        attributes,
        "project_id",
        &["project.id", "project_id", "project"],
    );
    for (attribute, paths) in [
        (
            "secret_created_at",
            &["created_at", "created", "date_created"][..],
        ),
        (
            "secret_last_rotated_at",
            &[
                "secret_last_rotated_at",
                "last_rotated_at",
                "last_rotated",
                "rotated_at",
            ][..],
        ),
        (
            "secret_rotation_enabled",
            &["secret_rotation_enabled", "rotation_enabled", "auto_rotate"][..],
        ),
        ("secret_status", &["secret_status", "status", "state"][..]),
        ("secret_type", &["secret_type", "type", "kind"][..]),
        (
            "observed_at",
            &["observed_at", "updated_at", "last_seen_at"][..],
        ),
    ] {
        copy_attribute(object, attributes, attribute, paths);
    }

    payload.insert("name".to_owned(), Value::String(secret_name));
    payload.insert("secret_id".to_owned(), Value::String(secret_id));
    copy_payload(object, payload, "project_id", &["project.id", "project_id"]);
    copy_payload(
        object,
        payload,
        "status",
        &["secret_status", "status", "state"],
    );
    copy_payload(object, payload, "type", &["secret_type", "type", "kind"]);
    copy_payload(
        object,
        payload,
        "rotation_enabled",
        &["secret_rotation_enabled", "rotation_enabled", "auto_rotate"],
    );
    copy_payload(object, payload, "created_at", &["created_at", "created"]);
    copy_payload(
        object,
        payload,
        "updated_at",
        &["updated_at", "last_seen_at"],
    );
    Ok(())
}

fn normalize_project(
    kernel: &DopplerKernel,
    object: &Map<String, Value>,
    provider_id: &str,
    attributes: &mut BTreeMap<String, String>,
    payload: &mut Map<String, Value>,
) {
    let resource_id = first(object, &["resource_id", "id", "metadata.resource_id"])
        .unwrap_or_else(|| provider_id.to_owned());
    let resource_name = first(
        object,
        &["name", "display_name", "hostname", "metadata.resource_name"],
    )
    .unwrap_or_else(|| resource_id.clone());
    attributes.insert("resource_id".to_owned(), resource_id.clone());
    attributes.insert("resource_name".to_owned(), resource_name.clone());
    attributes.insert(
        "resource_type".to_owned(),
        first(object, &["resource_type", "type", "metadata.resource_type"])
            .unwrap_or_else(|| "project".to_owned()),
    );
    attributes.insert(
        "resource_urn".to_owned(),
        resource_urn(kernel, &resource_id),
    );
    copy_attribute(
        object,
        attributes,
        "observed_at",
        &["observed_at", "updated_at", "last_seen_at"],
    );
    payload.insert("name".to_owned(), Value::String(resource_name));
    copy_payload(object, payload, "type", &["resource_type", "type"]);
    copy_payload(object, payload, "created_at", &["created_at", "created"]);
    copy_payload(
        object,
        payload,
        "updated_at",
        &["updated_at", "last_seen_at"],
    );
}

fn normalize_audit_event(
    kernel: &DopplerKernel,
    object: &Map<String, Value>,
    provider_id: &str,
    attributes: &mut BTreeMap<String, String>,
    payload: &mut Map<String, Value>,
) -> Result<(), DopplerError> {
    let event_type = first(object, &["event_type", "event_name", "action", "type"])
        .ok_or(DopplerError::EventContractRejection)?;
    let actor_id = first(
        object,
        &["actor_id", "actor.id", "actorId", "user_id", "user.id"],
    )
    .ok_or(DopplerError::EventContractRejection)?;
    attributes.insert("event_type".to_owned(), event_type.clone());
    attributes.insert("actor_id".to_owned(), actor_id.clone());
    for (attribute, paths) in [
        (
            "actor_email",
            &["actor_email", "actor.email", "email", "user.email"][..],
        ),
        ("actor_name", &["actor_name", "actor.name", "user.name"][..]),
        (
            "resource_email",
            &["resource_email", "target_email", "target.email"][..],
        ),
        (
            "resource_id",
            &[
                "resource_id",
                "target_id",
                "target.id",
                "resource.id",
                "object_id",
            ][..],
        ),
        (
            "resource_name",
            &[
                "resource_name",
                "target_name",
                "target.name",
                "resource.name",
                "object_name",
            ][..],
        ),
        (
            "resource_type",
            &["resource_type", "target_type", "target.type", "object_type"][..],
        ),
        (
            "observed_at",
            &["observed_at", "updated_at", "last_seen_at"][..],
        ),
    ] {
        copy_attribute(object, attributes, attribute, paths);
    }
    attributes.insert("resource_urn".to_owned(), resource_urn(kernel, provider_id));

    payload.insert("event_type".to_owned(), Value::String(event_type));
    let mut actor = Map::from_iter([("id".to_owned(), Value::String(actor_id))]);
    copy_payload(object, &mut actor, "email", &["actor_email", "actor.email"]);
    copy_payload(object, &mut actor, "name", &["actor_name", "actor.name"]);
    payload.insert("actor".to_owned(), Value::Object(actor));
    let mut resource = Map::new();
    copy_payload(
        object,
        &mut resource,
        "id",
        &["resource_id", "target_id", "target.id", "resource.id"],
    );
    copy_payload(
        object,
        &mut resource,
        "name",
        &[
            "resource_name",
            "target_name",
            "target.name",
            "resource.name",
        ],
    );
    copy_payload(
        object,
        &mut resource,
        "type",
        &["resource_type", "target_type", "target.type"],
    );
    if !resource.is_empty() {
        payload.insert("resource".to_owned(), Value::Object(resource));
    }
    copy_payload(
        object,
        payload,
        "created_at",
        &["created_at", "observed_at"],
    );
    Ok(())
}

fn copy_attribute(
    object: &Map<String, Value>,
    attributes: &mut BTreeMap<String, String>,
    name: &str,
    paths: &[&str],
) {
    if let Some(value) = first(object, paths) {
        attributes.insert(name.to_owned(), value);
    }
}

fn copy_payload(
    object: &Map<String, Value>,
    payload: &mut Map<String, Value>,
    name: &str,
    paths: &[&str],
) {
    if let Some(value) = first_value(object, paths).and_then(safe_scalar) {
        payload.insert(name.to_owned(), value);
    }
}

fn first(object: &Map<String, Value>, paths: &[&str]) -> Option<String> {
    first_value(object, paths).and_then(scalar_string)
}

fn first_value<'a>(object: &'a Map<String, Value>, paths: &[&str]) -> Option<&'a Value> {
    paths.iter().find_map(|path| value_at(object, path))
}

fn value_at<'a>(object: &'a Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut segments = path.split('.');
    let mut value = object.get(segments.next()?)?;
    for segment in segments {
        value = value.as_object()?.get(segment)?;
    }
    Some(value)
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => nonempty(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn safe_scalar(value: &Value) -> Option<Value> {
    match value {
        Value::String(value) => nonempty(value).map(Value::String),
        Value::Number(value) => Some(Value::Number(value.clone())),
        Value::Bool(value) => Some(Value::Bool(*value)),
        _ => None,
    }
}

fn nonempty(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 4096 && !value.chars().any(char::is_control))
        .then(|| value.to_owned())
}

fn occurred_at(object: &Map<String, Value>, fallback: i64) -> i64 {
    ["observed_at", "updated_at", "last_seen_at", "created_at"]
        .iter()
        .filter_map(|path| value_at(object, path))
        .find_map(timestamp_millis)
        .unwrap_or(fallback)
}

fn timestamp_millis(value: &Value) -> Option<i64> {
    match value {
        Value::Number(value) => number_millis(value),
        Value::String(value) => {
            let value = value.trim();
            if let Ok(number) = value.parse::<i64>() {
                return positive_epoch_millis(number);
            }
            let nanos = OffsetDateTime::parse(value, &Rfc3339)
                .ok()?
                .unix_timestamp_nanos();
            i64::try_from(nanos / 1_000_000)
                .ok()
                .filter(|value| *value > 0)
        }
        _ => None,
    }
}

fn number_millis(value: &Number) -> Option<i64> {
    value.as_i64().and_then(positive_epoch_millis)
}

fn positive_epoch_millis(value: i64) -> Option<i64> {
    if value <= 0 {
        return None;
    }
    if value >= 1_000_000_000_000 {
        Some(value)
    } else {
        value.checked_mul(1_000)
    }
}

fn resource_urn(kernel: &DopplerKernel, provider_id: &str) -> String {
    format!(
        "urn:cerebro:{}:{}:{provider_id}",
        kernel.tenant_id,
        kernel.family.urn_kind()
    )
}

pub(super) fn event_id(
    base_url: &str,
    tenant_id: &str,
    family: DopplerFamily,
    provider_id: &str,
) -> String {
    let scope = Sha256::digest(format!("{base_url}\0{}", family.path()).as_bytes());
    let mut scope_prefix = String::with_capacity(12);
    for byte in &scope[..6] {
        write!(&mut scope_prefix, "{byte:02x}").expect("writing to a String cannot fail");
    }
    format!(
        "doppler-{}-{scope_prefix}-{}-{}",
        normalize_id(tenant_id),
        family.as_str(),
        normalize_id(provider_id)
    )
}

fn normalize_id(value: &str) -> String {
    value
        .trim()
        .chars()
        .map(|character| match character {
            ' ' | '/' | ':' | '\t' | '\n' => '-',
            other => other,
        })
        .collect()
}

fn reject_tenant_override(value: &Value) -> Result<(), DopplerError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let key = key.to_ascii_lowercase().replace('-', "_");
                if matches!(key.as_str(), "tenant_id" | "tenantid") {
                    return Err(DopplerError::TenantMismatch);
                }
                reject_tenant_override(nested)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_tenant_override(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}
