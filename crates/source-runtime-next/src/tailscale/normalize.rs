use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{TailscaleError, TailscaleFamily, TailscaleKernel, TailscaleRecord};

pub(super) fn records(
    family: TailscaleFamily,
    root: &Value,
    tailnet: &str,
) -> Result<Vec<Value>, TailscaleError> {
    match family {
        TailscaleFamily::Tailnet => {
            let mut object = root
                .as_object()
                .cloned()
                .ok_or(TailscaleError::MalformedResponse)?;
            object
                .entry("id".to_owned())
                .or_insert_with(|| Value::String(tailnet.to_owned()));
            object
                .entry("tailnet".to_owned())
                .or_insert_with(|| Value::String(tailnet.to_owned()));
            Ok(vec![Value::Object(object)])
        }
        TailscaleFamily::User => list(root, &["users", "data", "items", "results"]),
        TailscaleFamily::Device => list(root, &["devices", "data", "items", "results"]),
        TailscaleFamily::Service => list(
            root,
            &["vipServices", "services", "data", "items", "results"],
        ),
        TailscaleFamily::Grant => list(root, &["grants", "data", "items", "results"]),
        TailscaleFamily::Group => object_map(root, "groups", "members"),
        TailscaleFamily::Tag => object_map(root, "tagOwners", "owners"),
    }
}

pub(super) fn normalize(
    kernel: &TailscaleKernel,
    mut payload: Value,
) -> Result<TailscaleRecord, TailscaleError> {
    reject_untrusted_material(&payload, 0)?;
    let provider_id = provider_id(
        kernel.family,
        payload
            .as_object()
            .ok_or(TailscaleError::InvalidProviderRecord)?,
        &payload,
    )?;
    if kernel.family == TailscaleFamily::Tailnet {
        let object = payload
            .as_object_mut()
            .ok_or(TailscaleError::InvalidProviderRecord)?;
        object.insert("id".to_owned(), Value::String(kernel.tailnet.clone()));
        object.insert("tailnet".to_owned(), Value::String(kernel.tailnet.clone()));
    }
    let object = payload
        .as_object()
        .ok_or(TailscaleError::InvalidProviderRecord)?;
    let mut attributes = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("provider".to_owned(), "tailscale".to_owned()),
        ("source_product".to_owned(), "tailscale".to_owned()),
        ("source_provider".to_owned(), "tailscale".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    for (name, paths) in mappings(kernel.family) {
        if let Some(value) = first_value(object, paths) {
            attributes.insert((*name).to_owned(), value);
        }
    }
    if kernel.family == TailscaleFamily::Tailnet {
        attributes.insert("tailnet".to_owned(), kernel.tailnet.clone());
    }
    attributes.insert("resource_id".to_owned(), provider_id.clone());
    attributes.insert(
        "resource_type".to_owned(),
        kernel.family.as_str().to_owned(),
    );
    attributes.insert(
        "resource_name".to_owned(),
        resource_name(kernel.family, object, &provider_id),
    );
    attributes.insert(
        "resource_urn".to_owned(),
        format!(
            "urn:cerebro:{}:{}:{}",
            kernel.tenant_id,
            kernel.family.urn_kind(),
            provider_id
        ),
    );
    validate_contract(kernel.family, &attributes, &payload)?;
    let occurred_at = occurred_at(kernel, object)?;
    let event_id = event_id(kernel, &provider_id);
    Ok(TailscaleRecord {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        event_id,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    })
}

pub(super) fn canonical_bytes(value: &Value) -> Result<Vec<u8>, TailscaleError> {
    serde_json::to_vec(&canonical(value)).map_err(|_| TailscaleError::InternalRuntimeFailure)
}

fn list(root: &Value, keys: &[&str]) -> Result<Vec<Value>, TailscaleError> {
    if let Some(values) = root.as_array() {
        return Ok(values.clone());
    }
    let object = root.as_object().ok_or(TailscaleError::MalformedResponse)?;
    keys.iter()
        .find_map(|key| object.get(*key).and_then(Value::as_array))
        .cloned()
        .ok_or(TailscaleError::MalformedResponse)
}

fn object_map(root: &Value, key: &str, value_key: &str) -> Result<Vec<Value>, TailscaleError> {
    let values = root
        .get(key)
        .and_then(Value::as_object)
        .ok_or(TailscaleError::MalformedResponse)?;
    let mut keys = values.keys().collect::<Vec<_>>();
    keys.sort_unstable();
    Ok(keys
        .into_iter()
        .map(|id| {
            Value::Object(Map::from_iter([
                ("id".to_owned(), Value::String(id.clone())),
                ("name".to_owned(), Value::String(id.clone())),
                (value_key.to_owned(), values[id].clone()),
            ]))
        })
        .collect())
}

fn provider_id(
    family: TailscaleFamily,
    object: &Map<String, Value>,
    payload: &Value,
) -> Result<String, TailscaleError> {
    let keys: &[&str] = match family {
        TailscaleFamily::Tailnet => &["id", "tailnet", "organization"],
        TailscaleFamily::User => &["id", "user_id", "loginName"],
        TailscaleFamily::Device => &["id", "nodeId", "device_id"],
        TailscaleFamily::Group | TailscaleFamily::Tag => &["id", "name"],
        TailscaleFamily::Service => &["id", "service_id", "name"],
        TailscaleFamily::Grant => &["id", "grant_id"],
    };
    if let Some(id) = first_value(object, keys) {
        return Ok(id);
    }
    if family == TailscaleFamily::Grant {
        let digest = Sha256::digest(canonical_bytes(payload)?);
        return Ok(hex_prefix(&digest, 24));
    }
    Err(TailscaleError::MissingStableIdentity)
}

fn mappings(family: TailscaleFamily) -> &'static [(&'static str, &'static [&'static str])] {
    match family {
        TailscaleFamily::Tailnet => &[
            ("tailnet", &["id", "tailnet", "organization"]),
            ("devices_approval_on", &["devicesApprovalOn"]),
            ("users_approval_on", &["usersApprovalOn"]),
            ("network_flow_logging_on", &["networkFlowLoggingOn"]),
            ("regional_routing_on", &["regionalRoutingOn"]),
            ("max_key_duration_days", &["maxKeyDurationDays"]),
        ],
        TailscaleFamily::User => &[
            ("user_id", &["id", "user_id"]),
            ("login_name", &["loginName", "login_name", "email"]),
            ("email", &["email", "loginName"]),
            ("display_name", &["displayName", "display_name"]),
            ("role", &["role"]),
            ("status", &["status"]),
            ("type", &["type"]),
            ("last_seen_at", &["lastSeen", "last_seen"]),
        ],
        TailscaleFamily::Device => &[
            ("device_id", &["id", "nodeId", "device_id"]),
            ("node_id", &["nodeId", "id"]),
            ("name", &["name"]),
            ("hostname", &["hostname"]),
            ("os", &["os"]),
            ("user_id", &["user"]),
            ("owner_email", &["user"]),
            ("authorized", &["authorized"]),
            ("is_external", &["isExternal", "is_external"]),
            (
                "key_expiry_disabled",
                &["keyExpiryDisabled", "key_expiry_disabled"],
            ),
            ("update_available", &["updateAvailable", "update_available"]),
            (
                "blocks_incoming_connections",
                &["blocksIncomingConnections", "blocks_incoming_connections"],
            ),
            ("tags", &["tags"]),
            ("last_seen_at", &["lastSeen", "last_seen"]),
            ("client_version", &["clientVersion", "client_version"]),
        ],
        TailscaleFamily::Group => &[
            ("group_id", &["id", "name"]),
            ("name", &["name"]),
            ("members", &["members"]),
        ],
        TailscaleFamily::Tag => &[
            ("tag_id", &["id", "name"]),
            ("name", &["name"]),
            ("owners", &["owners"]),
        ],
        TailscaleFamily::Service => &[
            ("service_id", &["id", "service_id", "name"]),
            ("name", &["name"]),
            ("addresses", &["addrs", "addresses"]),
            ("ports", &["ports"]),
            ("tags", &["tags"]),
            ("comment", &["comment"]),
        ],
        TailscaleFamily::Grant => &[
            ("grant_id", &["id", "grant_id"]),
            ("sources", &["src", "sources"]),
            ("destinations", &["dst", "destinations"]),
            ("via", &["via"]),
            ("ip", &["ip"]),
            ("app", &["app"]),
            ("disabled", &["disabled"]),
        ],
    }
}

fn first_value(object: &Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(value_string))
}

fn value_string(value: &Value) -> Option<String> {
    let value = match value {
        Value::Null => return None,
        Value::String(value) => value.trim().to_owned(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::Array(values) => values
            .iter()
            .filter_map(value_string)
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => serde_json::to_string(value).ok()?,
    };
    (!value.is_empty()).then_some(value)
}

fn occurred_at(
    kernel: &TailscaleKernel,
    object: &Map<String, Value>,
) -> Result<String, TailscaleError> {
    let preferred: &[&str] = match kernel.family {
        TailscaleFamily::User => &["created", "lastSeen"],
        TailscaleFamily::Device => &["lastSeen", "created"],
        _ => &[],
    };
    for key in preferred.iter().chain(
        [
            "updated_at",
            "updatedAt",
            "last_seen_at",
            "lastSeenAt",
            "created_at",
            "createdAt",
            "timestamp",
        ]
        .iter(),
    ) {
        if let Some(value) = object.get(*key).and_then(value_string)
            && let Ok(parsed) = OffsetDateTime::parse(&value, &Rfc3339)
        {
            return parsed
                .format(&Rfc3339)
                .map_err(|_| TailscaleError::InvalidProviderRecord);
        }
    }
    Ok(kernel.observed_at.clone())
}

fn event_id(kernel: &TailscaleKernel, provider_id: &str) -> String {
    let mut scope = Sha256::new();
    scope.update(kernel.base_url.as_str().as_bytes());
    scope.update([0]);
    scope.update(kernel.family.path().as_bytes());
    let scope = scope.finalize();
    format!(
        "tailscale-{}-{}-{}-{}",
        normalize_id(&kernel.tenant_id),
        hex_prefix(&scope, 12),
        normalize_id(kernel.family.as_str()),
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

fn resource_name(family: TailscaleFamily, object: &Map<String, Value>, fallback: &str) -> String {
    if family == TailscaleFamily::Grant {
        let sources = first_value(object, &["src", "sources"]);
        let destinations = first_value(object, &["dst", "destinations"]);
        if let (Some(sources), Some(destinations)) = (sources, destinations) {
            return format!("{sources} to {destinations}");
        }
    }
    let keys: &[&str] = match family {
        TailscaleFamily::User => &["displayName", "loginName", "email"],
        TailscaleFamily::Device | TailscaleFamily::Service => &["name", "hostname"],
        TailscaleFamily::Group | TailscaleFamily::Tag => &["name"],
        TailscaleFamily::Grant => &["name"],
        TailscaleFamily::Tailnet => &["tailnet", "organization", "id"],
    };
    first_value(object, keys).unwrap_or_else(|| fallback.to_owned())
}

fn validate_contract(
    family: TailscaleFamily,
    attributes: &BTreeMap<String, String>,
    payload: &Value,
) -> Result<(), TailscaleError> {
    if family.required_attributes().iter().any(|key| {
        attributes
            .get(*key)
            .is_none_or(|value| value.trim().is_empty())
    }) || payload.as_object().is_none_or(|payload| {
        family
            .required_payload_fields()
            .iter()
            .any(|field| payload.get(*field).is_none_or(Value::is_null))
    }) {
        return Err(TailscaleError::EventContractRejected);
    }
    Ok(())
}

fn reject_untrusted_material(value: &Value, depth: usize) -> Result<(), TailscaleError> {
    if depth > 16 {
        return Err(TailscaleError::InvalidProviderRecord);
    }
    match value {
        Value::Object(object) => {
            if object.len() > 512 {
                return Err(TailscaleError::InvalidProviderRecord);
            }
            for (key, value) in object {
                let normalized = key.trim().to_ascii_lowercase().replace('-', "_");
                if normalized == "tenant_id" || normalized == "tenant" {
                    return Err(TailscaleError::TenantMismatch);
                }
                if matches!(
                    normalized.as_str(),
                    "token"
                        | "access_token"
                        | "api_key"
                        | "client_secret"
                        | "clientsecret"
                        | "password"
                        | "private_key"
                        | "authorization"
                        | "cookie"
                ) {
                    return Err(TailscaleError::CredentialMaterial);
                }
                reject_untrusted_material(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(TailscaleError::InvalidProviderRecord);
            }
            for value in values {
                reject_untrusted_material(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by(|left, right| left.0.cmp(right.0));
            Value::Object(Map::from_iter(
                entries
                    .into_iter()
                    .map(|(key, value)| (key.clone(), canonical(value))),
            ))
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    bytes
        .iter()
        .flat_map(|byte| {
            [
                char::from_digit((byte >> 4) as u32, 16),
                char::from_digit((byte & 15) as u32, 16),
            ]
        })
        .flatten()
        .take(length)
        .collect()
}
