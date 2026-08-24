//! Shared SentinelOne normalization helpers and the agent event contract.

use std::collections::BTreeMap;

use serde_json::{Map, Value};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::source_execution::{SourceWorkerExecutionContextV1, SourceWorkerRecordV1};

use super::{FAMILY_ID, agent_event_id, error::SentinelOneAgentAdapterError};
use crate::sentinelone::SentinelOneRecord;

#[path = "normalization/direct.rs"]
mod direct;
pub(super) use direct::normalize_direct_record;

pub(super) fn normalize_agent_record(
    record: SentinelOneRecord,
    context: &SourceWorkerExecutionContextV1,
) -> Result<SourceWorkerRecordV1, SentinelOneAgentAdapterError> {
    let provider_id = record.provider_id.trim();
    if provider_id.is_empty() {
        return Err(SentinelOneAgentAdapterError::MissingProviderIdentity);
    }

    let occurred_at_unix_millis =
        provider_occurred_at_millis(&record.payload).unwrap_or(context.observed_at_unix_millis);
    let event_id = agent_event_id(&context.tenant_id, provider_id)?;

    let attributes = agent_attributes(&record.payload, &context.tenant_id, provider_id);
    let payload = agent_payload(&record.payload, &context.tenant_id, provider_id);
    Ok(SourceWorkerRecordV1 {
        provider_id: provider_id.to_owned(),
        event_id,
        occurred_at_unix_millis,
        attributes: attributes.into_iter().collect(),
        payload_json: serde_json::to_vec(&payload)
            .map_err(|_| SentinelOneAgentAdapterError::InvalidProviderResponse)?,
    })
}

fn agent_attributes(raw: &Value, tenant_id: &str, provider_id: &str) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::new();
    for (name, value) in [
        ("family", FAMILY_ID.to_owned()),
        ("agent_id", provider_id.to_owned()),
        ("tenant_host", tenant_id.to_owned()),
        ("is_active", bool_text(raw, "isActive")),
        ("is_decommissioned", bool_text(raw, "isDecommissioned")),
        ("is_uninstalled", bool_text(raw, "isUninstalled")),
        ("is_pending_uninstall", bool_text(raw, "isPendingUninstall")),
        ("is_up_to_date", bool_text(raw, "isUpToDate")),
        ("infected", bool_text(raw, "infected")),
        ("active_threats", integer_text(raw, "activeThreats")),
    ] {
        insert_nonblank(&mut attributes, name, value);
    }

    for (name, provider_name) in [
        ("computer_name", "computerName"),
        ("hostname", "computerName"),
        ("uuid", "uuid"),
        ("os_name", "osName"),
        ("os_type", "osType"),
        ("os_arch", "osArch"),
        ("os_revision", "osRevision"),
        ("agent_version", "agentVersion"),
        ("last_active_date", "lastActiveDate"),
        ("registered_at", "registeredAt"),
        ("domain", "domain"),
        ("external_ip", "externalIp"),
        ("group_ip", "groupIp"),
        ("last_ip_to_mgmt", "lastIpToMgmt"),
        ("site_id", "siteId"),
        ("site_name", "siteName"),
        ("group_id", "groupId"),
        ("group_name", "groupName"),
        ("account_id", "accountId"),
        ("account_name", "accountName"),
        ("machine_type", "machineType"),
        ("model_name", "modelName"),
        ("serial_number", "serialNumber"),
        ("operational_state", "operationalState"),
        ("network_status", "networkStatus"),
        ("mitigation_mode", "mitigationMode"),
    ] {
        insert_nonblank(&mut attributes, name, string_at(raw, provider_name));
    }

    if let Some(value) = flexible_bool_text(raw.get("firewallEnabled")) {
        attributes.insert("firewall_enabled".to_owned(), value);
    }
    let ip_values = [
        string_at(raw, "externalIp"),
        string_at(raw, "lastIpToMgmt"),
        string_at(raw, "groupIp"),
    ];
    if let Some(ip) = ip_values.iter().find(|value| !value.is_empty()) {
        attributes.insert("ip".to_owned(), ip.clone());
    }
    insert_nonblank(&mut attributes, "ip_addresses", distinct_join(&ip_values));

    let user_name = [
        string_at(raw, "lastLoggedInUserName"),
        string_at(raw, "osUsername"),
    ]
    .into_iter()
    .find(|value| !value.is_empty())
    .unwrap_or_default();
    insert_nonblank(&mut attributes, "user_name", user_name.clone());
    if email_like(&user_name) {
        attributes.insert("user_email".to_owned(), user_name.to_ascii_lowercase());
    }
    if let Some(actions) = raw.get("userActionsNeeded").and_then(Value::as_array) {
        let actions = actions
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
            .join(",");
        insert_nonblank(&mut attributes, "user_actions_needed", actions);
    }
    attributes
}

fn agent_payload(raw: &Value, tenant_id: &str, provider_id: &str) -> Value {
    let mut payload = Map::new();
    payload.insert("id".to_owned(), Value::String(provider_id.to_owned()));
    for (name, provider_name) in [
        ("computer_name", "computerName"),
        ("hostname", "computerName"),
        ("uuid", "uuid"),
        ("account_id", "accountId"),
        ("account_name", "accountName"),
        ("model_name", "modelName"),
        ("serial_number", "serialNumber"),
        ("machine_type", "machineType"),
        ("os_name", "osName"),
        ("os_type", "osType"),
        ("os_arch", "osArch"),
        ("os_revision", "osRevision"),
        ("agent_version", "agentVersion"),
        ("last_active_date", "lastActiveDate"),
        ("last_successful_scan_at", "lastSuccessfulScanDate"),
        ("registered_at", "registeredAt"),
        ("created_at", "createdAt"),
        ("updated_at", "updatedAt"),
        ("network_status", "networkStatus"),
        ("operational_state", "operationalState"),
        ("mitigation_mode", "mitigationMode"),
        ("domain", "domain"),
        ("external_ip", "externalIp"),
        ("group_ip", "groupIp"),
        ("last_ip_to_mgmt", "lastIpToMgmt"),
        ("group_id", "groupId"),
        ("group_name", "groupName"),
        ("site_id", "siteId"),
        ("site_name", "siteName"),
    ] {
        insert_json_string(&mut payload, name, string_at(raw, provider_name));
    }

    for (name, provider_name) in [
        ("is_active", "isActive"),
        ("is_decommissioned", "isDecommissioned"),
        ("is_up_to_date", "isUpToDate"),
        ("is_uninstalled", "isUninstalled"),
        ("is_pending_uninstall", "isPendingUninstall"),
        ("is_infected", "infected"),
    ] {
        payload.insert(
            name.to_owned(),
            Value::Bool(
                raw.get(provider_name)
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        );
    }
    payload.insert(
        "active_threats".to_owned(),
        Value::Number(
            raw.get("activeThreats")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .into(),
        ),
    );

    let ip_values = [
        string_at(raw, "externalIp"),
        string_at(raw, "lastIpToMgmt"),
        string_at(raw, "groupIp"),
    ];
    if let Some(ip) = ip_values.iter().find(|value| !value.is_empty()) {
        payload.insert("ip".to_owned(), Value::String(ip.clone()));
    }
    insert_json_string(&mut payload, "ip_addresses", distinct_join(&ip_values));
    let user_name = [
        string_at(raw, "lastLoggedInUserName"),
        string_at(raw, "osUsername"),
    ]
    .into_iter()
    .find(|value| !value.is_empty())
    .unwrap_or_default();
    insert_json_string(&mut payload, "user_name", user_name);

    if let Some(actions) = raw.get("userActionsNeeded").and_then(Value::as_array)
        && !actions.is_empty()
    {
        payload.insert(
            "user_actions_needed".to_owned(),
            Value::Array(actions.clone()),
        );
    }
    if let Some(tags) = raw.get("tags").and_then(Value::as_object)
        && !tags.is_empty()
    {
        payload.insert("tags".to_owned(), Value::Object(tags.clone()));
    }
    payload.insert(
        "tenant_host".to_owned(),
        Value::String(tenant_id.to_owned()),
    );

    let mut raw = raw.clone();
    remove_untrusted_tenant_fields(&mut raw);
    payload.insert("raw".to_owned(), raw);
    Value::Object(payload)
}

pub(super) fn remove_untrusted_tenant_fields(value: &mut Value) {
    match value {
        Value::Object(object) => {
            object.retain(|name, _| {
                !matches!(
                    name.as_str(),
                    "Authorization"
                        | "authorization"
                        | "apiToken"
                        | "api_token"
                        | "clientSecret"
                        | "client_secret"
                        | "licenseKey"
                        | "password"
                        | "privateKey"
                        | "private_key"
                        | "registrationToken"
                        | "secret"
                        | "sessionCookie"
                        | "session_cookie"
                        | "tenantId"
                        | "tenant_id"
                        | "tenantHost"
                        | "tenant_host"
                        | "token"
                )
            });
            for value in object.values_mut() {
                remove_untrusted_tenant_fields(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                remove_untrusted_tenant_fields(value);
            }
        }
        _ => {}
    }
}

fn provider_occurred_at_millis(raw: &Value) -> Option<i64> {
    provider_occurred_at_millis_for(
        raw,
        &["updatedAt", "lastActiveDate", "createdAt", "registeredAt"],
    )
}

pub(super) fn provider_occurred_at_millis_for(raw: &Value, fields: &[&str]) -> Option<i64> {
    for field in fields {
        let value = string_at(raw, field);
        if value.is_empty() {
            continue;
        }
        if let Ok(parsed) = OffsetDateTime::parse(&value, &Rfc3339) {
            return i64::try_from(parsed.unix_timestamp_nanos() / 1_000_000).ok();
        }
    }
    None
}

pub(super) fn string_at(raw: &Value, name: &str) -> String {
    raw.get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

pub(super) fn bool_text(raw: &Value, name: &str) -> String {
    raw.get(name)
        .and_then(Value::as_bool)
        .unwrap_or(false)
        .to_string()
}

pub(super) fn integer_text(raw: &Value, name: &str) -> String {
    raw.get(name)
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .to_string()
}

fn flexible_bool_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Bool(value) => Some(value.to_string()),
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some("true".to_owned()),
            "false" | "0" | "no" => Some("false".to_owned()),
            _ => None,
        },
        _ => None,
    }
}

pub(super) fn flexible_bool(value: Option<&Value>) -> bool {
    match value {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "y" | "yes"
            )
        }
        _ => false,
    }
}

pub(super) fn flexible_string(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_owned(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Array(_) | Value::Object(_)) => {
            serde_json::to_string(value.unwrap_or(&Value::Null)).unwrap_or_default()
        }
        Some(Value::Null) | None => String::new(),
    }
}

pub(super) fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    let values = value?.as_array()?;
    Some(
        values
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

pub(super) fn insert_nonblank(fields: &mut BTreeMap<String, String>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(name.to_owned(), value.to_owned());
    }
}

pub(super) fn insert_json_string(object: &mut Map<String, Value>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        object.insert(name.to_owned(), Value::String(value.to_owned()));
    }
}

pub(super) fn insert_json_true(
    object: &mut Map<String, Value>,
    name: &str,
    raw: &Value,
    provider_name: &str,
) {
    if raw
        .get(provider_name)
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        object.insert(name.to_owned(), Value::Bool(true));
    }
}

pub(super) fn insert_json_integer(
    object: &mut Map<String, Value>,
    name: &str,
    raw: &Value,
    provider_name: &str,
) {
    if let Some(value) = raw.get(provider_name).and_then(Value::as_i64)
        && value != 0
    {
        object.insert(name.to_owned(), Value::Number(value.into()));
    }
}

pub(super) fn insert_json_object(
    object: &mut Map<String, Value>,
    name: &str,
    value: Option<&Value>,
) {
    if let Some(value @ Value::Object(fields)) = value
        && !fields.is_empty()
    {
        object.insert(name.to_owned(), value.clone());
    }
}

fn distinct_join(values: &[String]) -> String {
    let mut output = Vec::new();
    for value in values {
        let value = value.trim();
        if !value.is_empty() && !output.contains(&value) {
            output.push(value);
        }
    }
    output.join(",")
}

fn email_like(value: &str) -> bool {
    let value = value.trim();
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain
            .rsplit_once('.')
            .is_some_and(|(name, suffix)| !name.is_empty() && suffix.len() >= 2)
}
