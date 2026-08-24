//! Canonical SentinelOne application-inventory event normalization.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::sentinelone::SentinelOneRecord;
use crate::source_execution::{SourceWorkerExecutionContextV1, SourceWorkerRecordV1};

use super::super::error::SentinelOneAgentAdapterError;
use super::{
    insert_json_integer, insert_json_string, insert_nonblank, provider_occurred_at_millis_for,
    remove_untrusted_tenant_fields, string_at,
};

pub(crate) fn normalize_application_record(
    record: SentinelOneRecord,
    context: &SourceWorkerExecutionContextV1,
) -> Result<SourceWorkerRecordV1, SentinelOneAgentAdapterError> {
    let provider_id = record.provider_id.trim();
    let agent_id = record
        .fields
        .get("agent_id")
        .map(String::as_str)
        .map(str::trim)
        .unwrap_or_default();
    let application_id = record
        .fields
        .get("application_id")
        .map(String::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if provider_id.is_empty()
        || agent_id.is_empty()
        || application_id.is_empty()
        || provider_id != format!("{agent_id}::{application_id}")
    {
        return Err(SentinelOneAgentAdapterError::MissingProviderIdentity);
    }
    let occurred_at_unix_millis =
        provider_occurred_at_millis_for(&record.payload, &["installedDate"])
            .unwrap_or(context.observed_at_unix_millis);

    let mut attributes = BTreeMap::from([
        ("family".to_owned(), "application".to_owned()),
        ("agent_id".to_owned(), agent_id.to_owned()),
        ("tenant_host".to_owned(), context.tenant_id.clone()),
    ]);
    for (name, provider_name) in [
        ("application_name", "name"),
        ("publisher", "publisher"),
        ("version", "version"),
        ("installed_date", "installedDate"),
    ] {
        insert_nonblank(
            &mut attributes,
            name,
            string_at(&record.payload, provider_name),
        );
    }

    let mut payload = Map::new();
    payload.insert("agent_id".to_owned(), Value::String(agent_id.to_owned()));
    payload.insert(
        "tenant_host".to_owned(),
        Value::String(context.tenant_id.clone()),
    );
    for (name, provider_name) in [
        ("name", "name"),
        ("publisher", "publisher"),
        ("version", "version"),
        ("installed_date", "installedDate"),
    ] {
        insert_json_string(
            &mut payload,
            name,
            string_at(&record.payload, provider_name),
        );
    }
    insert_json_integer(&mut payload, "size_bytes", &record.payload, "size");
    let mut raw = record.payload;
    remove_untrusted_tenant_fields(&mut raw);
    payload.insert("raw".to_owned(), raw);

    Ok(SourceWorkerRecordV1 {
        provider_id: provider_id.to_owned(),
        event_id: application_event_id(&context.tenant_id, agent_id, application_id)?,
        occurred_at_unix_millis,
        attributes: attributes.into_iter().collect(),
        payload_json: serde_json::to_vec(&Value::Object(payload))
            .map_err(|_| SentinelOneAgentAdapterError::InvalidProviderResponse)?,
    })
}

pub(crate) fn application_event_id(
    tenant_id: &str,
    agent_id: &str,
    application_id: &str,
) -> Result<String, SentinelOneAgentAdapterError> {
    let event_id = format!(
        "sentinelone-application-{}-{}-{}",
        tenant_id.trim(),
        agent_id.trim(),
        application_id.trim()
    );
    if tenant_id.trim().is_empty()
        || agent_id.trim().is_empty()
        || application_id.trim().is_empty()
        || event_id.len() > 256
        || event_id != event_id.trim()
        || event_id.chars().any(char::is_control)
    {
        return Err(SentinelOneAgentAdapterError::InvalidEventIdentity);
    }
    Ok(event_id)
}
