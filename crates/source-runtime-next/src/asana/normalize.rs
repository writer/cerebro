use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{AsanaError, AsanaFamily, AsanaKernel, AsanaRecord};

pub(super) fn normalize(
    kernel: &AsanaKernel,
    raw: Value,
    observed_at: &str,
) -> Result<AsanaRecord, AsanaError> {
    reject_untrusted(&raw, 0)?;
    let values = raw.as_object().ok_or(AsanaError::InvalidProviderRecord)?;
    let provider_id = provider_component(
        &string_first(values, &["gid", "id"]).ok_or(AsanaError::MissingStableIdentity)?,
    )?;
    let occurred_at = occurred_at(kernel.family, values, observed_at)?;
    let (attributes, payload) = match kernel.family {
        AsanaFamily::Users => normalize_user(kernel, values)?,
        AsanaFamily::Projects => normalize_project(kernel, values)?,
        AsanaFamily::AuditEvents => normalize_audit(kernel, values)?,
    };
    let definition = super::AsanaRuntimeDefinition::compile(kernel.family)?;
    let contract = definition.event_contract;
    if contract.kind != kernel.family.event_kind()
        || contract.schema_ref != kernel.family.schema_ref()
        || contract.required_attributes.iter().any(|field| {
            attributes
                .get(*field)
                .is_none_or(|value| value.trim().is_empty())
        })
        || contract.required_payload_fields.iter().any(|field| {
            payload
                .get(*field)
                .is_none_or(|value| value.is_null() || value.as_str().is_some_and(str::is_empty))
        })
    {
        return Err(AsanaError::EventContractRejection);
    }
    Ok(AsanaRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(&kernel.tenant_id, kernel.family, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    })
}

pub(super) fn event_id(tenant_id: &str, family: AsanaFamily, provider_id: &str) -> String {
    let digest = Sha256::digest(format!("{tenant_id}\0{}\0{provider_id}", family.as_str()));
    let suffix = digest[..10]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("asana-{}-{suffix}", family.as_str())
}

fn normalize_user(
    kernel: &AsanaKernel,
    values: &Map<String, Value>,
) -> Result<(BTreeMap<String, String>, Value), AsanaError> {
    let id = provider_component(&required(values, "gid")?)?;
    let name = string_first(values, &["name", "display_name"]).unwrap_or_else(|| id.clone());
    let email = string_first(values, &["email", "primary_email"]).unwrap_or_default();
    let resource_urn = urn(&kernel.tenant_id, "runtime_users", &id);
    let status = string_first(values, &["status"]).unwrap_or_else(|| {
        if values.get("enabled").and_then(Value::as_bool) == Some(false) {
            "inactive".to_owned()
        } else {
            "active".to_owned()
        }
    });
    let mut attributes = BTreeMap::from([
        ("display_name".to_owned(), name.clone()),
        ("resource_id".to_owned(), id.clone()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), "identity_user".to_owned()),
        ("resource_urn".to_owned(), resource_urn.clone()),
        ("source_event_id".to_owned(), id.clone()),
        ("status".to_owned(), status),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
        ("user_id".to_owned(), id),
    ]);
    if !email.is_empty() {
        attributes.insert("email".to_owned(), email);
    }
    let mut payload = values.clone();
    payload.insert("resource_urn".to_owned(), Value::from(resource_urn));
    Ok((attributes, Value::Object(payload)))
}

fn normalize_project(
    kernel: &AsanaKernel,
    values: &Map<String, Value>,
) -> Result<(BTreeMap<String, String>, Value), AsanaError> {
    let id = provider_component(&required(values, "gid")?)?;
    let name = string_first(values, &["name"]).unwrap_or_else(|| id.clone());
    let resource_urn = urn(&kernel.tenant_id, "runtime_projects", &id);
    let mut attributes = BTreeMap::from([
        ("resource_id".to_owned(), id.clone()),
        ("resource_name".to_owned(), name),
        ("resource_type".to_owned(), "project".to_owned()),
        ("resource_urn".to_owned(), resource_urn),
        ("source_event_id".to_owned(), id),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    copy(
        &mut attributes,
        values,
        "evidence_cas.digest",
        "evidence_cas_digest",
    );
    copy(
        &mut attributes,
        values,
        "evidence_cas.uri",
        "evidence_cas_uri",
    );
    let mut payload = values.clone();
    payload.remove("evidence_cas");
    Ok((attributes, Value::Object(payload)))
}

fn normalize_audit(
    kernel: &AsanaKernel,
    values: &Map<String, Value>,
) -> Result<(BTreeMap<String, String>, Value), AsanaError> {
    let id = provider_component(&required(values, "gid")?)?;
    let actor_id = provider_component(
        &string_first(values, &["actor.gid", "actor.id"])
            .ok_or(AsanaError::InvalidProviderRecord)?,
    )?;
    let event_type = string_first(values, &["event_type", "event_name", "action", "type"])
        .ok_or(AsanaError::InvalidProviderRecord)?;
    let mut attributes = BTreeMap::from([
        ("actor_id".to_owned(), actor_id),
        ("event_type".to_owned(), event_type),
        ("source_event_id".to_owned(), id),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    for (source, target) in [
        ("actor.email", "actor_email"),
        ("actor.name", "actor_name"),
        ("created_at", "created_at"),
        ("created_at", "observed_at"),
        ("resource.gid", "resource_id"),
        ("resource.name", "resource_name"),
        ("resource.resource_type", "resource_type"),
        ("resource_urn", "resource_urn"),
    ] {
        copy(&mut attributes, values, source, target);
    }
    if !attributes.contains_key("resource_id") {
        copy(&mut attributes, values, "target.gid", "resource_id");
    }
    if let Some(resource_id) = attributes.get("resource_id").cloned() {
        attributes.insert("resource_id".to_owned(), provider_component(&resource_id)?);
    }
    if let Some(resource_urn) = attributes.get("resource_urn") {
        let prefix = format!("urn:cerebro:{}:", kernel.tenant_id);
        if !resource_urn.starts_with(&prefix) {
            return Err(AsanaError::TenantMismatch);
        }
    }
    Ok((attributes, Value::Object(values.clone())))
}

fn occurred_at(
    family: AsanaFamily,
    values: &Map<String, Value>,
    observed_at: &str,
) -> Result<String, AsanaError> {
    let candidate = match family {
        AsanaFamily::Users => string_first(values, &["observed_at", "updated_at", "last_seen_at"])
            .unwrap_or_else(|| observed_at.to_owned()),
        AsanaFamily::Projects => string_first(
            values,
            &["observed_at", "modified_at", "updated_at", "created_at"],
        )
        .unwrap_or_else(|| observed_at.to_owned()),
        AsanaFamily::AuditEvents => {
            string_first(values, &["observed_at", "created_at", "updated_at"])
                .unwrap_or_else(|| observed_at.to_owned())
        }
    };
    OffsetDateTime::parse(&candidate, &Rfc3339)
        .map(|value| value.format(&Rfc3339).unwrap_or(candidate))
        .map_err(|_| AsanaError::InvalidProviderRecord)
}

fn required(values: &Map<String, Value>, path: &str) -> Result<String, AsanaError> {
    string_at(values, path).ok_or(AsanaError::MissingStableIdentity)
}

fn provider_component(value: &str) -> Result<String, AsanaError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 512
        || value.chars().any(char::is_control)
        || value.contains([':', '/', '\\'])
    {
        return Err(AsanaError::MissingStableIdentity);
    }
    Ok(value.to_owned())
}

fn string_first(values: &Map<String, Value>, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| string_at(values, path))
}

fn string_at(values: &Map<String, Value>, path: &str) -> Option<String> {
    let mut value = values.get(path.split('.').next()?)?;
    for segment in path.split('.').skip(1) {
        value = value.get(segment)?;
    }
    match value {
        Value::String(value) => (!value.trim().is_empty()).then(|| value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn copy(
    target: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    key: &str,
) {
    if let Some(value) = string_at(values, source) {
        target.insert(key.to_owned(), value);
    }
}

fn reject_untrusted(value: &Value, depth: usize) -> Result<(), AsanaError> {
    if depth > 32 {
        return Err(AsanaError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let key = key.to_ascii_lowercase();
                if key == "tenant_id" {
                    return Err(AsanaError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "client_secret"
                        | "password"
                        | "private_key"
                        | "authorization"
                ) {
                    return Err(AsanaError::CredentialMaterial);
                }
                reject_untrusted(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_untrusted(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn urn(tenant: &str, kind: &str, provider_id: &str) -> String {
    format!("urn:cerebro:{tenant}:{kind}:{provider_id}")
}
