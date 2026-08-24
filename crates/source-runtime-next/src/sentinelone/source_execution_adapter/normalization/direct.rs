//! Canonical event normalization for directly paginated SentinelOne families.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::sentinelone::{SentinelOneFamily, SentinelOneRecord};
use crate::source_execution::{SourceWorkerExecutionContextV1, SourceWorkerRecordV1};

use super::super::{direct::direct_event_id, error::SentinelOneAgentAdapterError};
use super::{
    bool_text, flexible_bool, flexible_string, insert_json_integer, insert_json_object,
    insert_json_string, insert_json_true, insert_nonblank, integer_text,
    provider_occurred_at_millis_for, remove_untrusted_tenant_fields, string_array, string_at,
};

pub(crate) fn normalize_direct_record(
    record: SentinelOneRecord,
    context: &SourceWorkerExecutionContextV1,
    family: SentinelOneFamily,
) -> Result<SourceWorkerRecordV1, SentinelOneAgentAdapterError> {
    if record.family != family.as_str() || record.provider_kind != family.provider_kind() {
        return Err(SentinelOneAgentAdapterError::InvalidProviderResponse);
    }
    let provider_id = record.provider_id.trim();
    if provider_id.is_empty() {
        return Err(SentinelOneAgentAdapterError::MissingProviderIdentity);
    }
    let (attributes, payload, occurred_at_unix_millis) = match family {
        SentinelOneFamily::Activity => (
            activity_attributes(&record.payload, &context.tenant_id, provider_id),
            activity_payload(&record.payload, &context.tenant_id, provider_id),
            provider_occurred_at_millis_for(&record.payload, &["createdAt", "updatedAt"]),
        ),
        SentinelOneFamily::Exclusion => (
            exclusion_attributes(&record.payload, &context.tenant_id, provider_id),
            exclusion_payload(&record.payload, &context.tenant_id, provider_id),
            provider_occurred_at_millis_for(&record.payload, &["updatedAt", "createdAt"]),
        ),
        SentinelOneFamily::Group => (
            group_attributes(&record.payload, &context.tenant_id, provider_id),
            group_payload(&record.payload, &context.tenant_id, provider_id),
            provider_occurred_at_millis_for(&record.payload, &["updatedAt", "createdAt"]),
        ),
        SentinelOneFamily::Site => (
            site_attributes(&record.payload, &context.tenant_id, provider_id),
            site_payload(&record.payload, &context.tenant_id, provider_id),
            provider_occurred_at_millis_for(&record.payload, &["updatedAt", "createdAt"]),
        ),
        SentinelOneFamily::Agent | SentinelOneFamily::Application | SentinelOneFamily::Threat => {
            return Err(SentinelOneAgentAdapterError::InvalidPlan);
        }
    };
    Ok(SourceWorkerRecordV1 {
        provider_id: provider_id.to_owned(),
        event_id: direct_event_id(family, &context.tenant_id, provider_id)?,
        occurred_at_unix_millis: occurred_at_unix_millis.unwrap_or(context.observed_at_unix_millis),
        attributes: attributes.into_iter().collect(),
        payload_json: serde_json::to_vec(&payload)
            .map_err(|_| SentinelOneAgentAdapterError::InvalidProviderResponse)?,
    })
}

fn base_attributes(
    family: SentinelOneFamily,
    tenant_id: &str,
    identity_name: &str,
    provider_id: &str,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("family".to_owned(), family.as_str().to_owned()),
        (identity_name.to_owned(), provider_id.to_owned()),
        ("tenant_host".to_owned(), tenant_id.to_owned()),
    ])
}

fn base_payload(raw: &Value, tenant_id: &str, provider_id: &str) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert("id".to_owned(), Value::String(provider_id.to_owned()));
    payload.insert(
        "tenant_host".to_owned(),
        Value::String(tenant_id.to_owned()),
    );
    let mut sanitized_raw = raw.clone();
    remove_untrusted_tenant_fields(&mut sanitized_raw);
    payload.insert("raw".to_owned(), sanitized_raw);
    payload
}

fn activity_attributes(
    raw: &Value,
    tenant_id: &str,
    provider_id: &str,
) -> BTreeMap<String, String> {
    let mut attributes = base_attributes(
        SentinelOneFamily::Activity,
        tenant_id,
        "activity_id",
        provider_id,
    );
    attributes.insert(
        "activity_type".to_owned(),
        integer_text(raw, "activityType"),
    );
    for (name, provider_name) in [
        ("activity_uuid", "activityUuid"),
        ("agent_id", "agentId"),
        ("site_id", "siteId"),
        ("group_id", "groupId"),
        ("threat_id", "threatId"),
        ("user_id", "userId"),
        ("primary_description", "primaryDescription"),
        ("os_family", "osFamily"),
    ] {
        insert_nonblank(&mut attributes, name, string_at(raw, provider_name));
    }
    attributes
}

fn activity_payload(raw: &Value, tenant_id: &str, provider_id: &str) -> Value {
    let mut payload = base_payload(raw, tenant_id, provider_id);
    insert_json_integer(&mut payload, "activity_type", raw, "activityType");
    for (name, provider_name) in [
        ("activity_uuid", "activityUuid"),
        ("agent_id", "agentId"),
        ("agent_updated_version", "agentUpdatedVersion"),
        ("created_at", "createdAt"),
        ("updated_at", "updatedAt"),
        ("description", "description"),
        ("primary_description", "primaryDescription"),
        ("secondary_description", "secondaryDescription"),
        ("comments", "comments"),
        ("group_id", "groupId"),
        ("group_name", "groupName"),
        ("os_family", "osFamily"),
        ("site_id", "siteId"),
        ("site_name", "siteName"),
        ("account_id", "accountId"),
        ("account_name", "accountName"),
        ("threat_id", "threatId"),
        ("user_id", "userId"),
        ("hash", "hash"),
    ] {
        insert_json_string(&mut payload, name, string_at(raw, provider_name));
    }
    insert_json_object(&mut payload, "data", raw.get("data"));
    Value::Object(payload)
}

fn site_attributes(raw: &Value, tenant_id: &str, provider_id: &str) -> BTreeMap<String, String> {
    let mut attributes =
        base_attributes(SentinelOneFamily::Site, tenant_id, "site_id", provider_id);
    for (name, provider_name) in [
        ("site_name", "name"),
        ("state", "state"),
        ("site_type", "siteType"),
        ("account_id", "accountId"),
        ("account_name", "accountName"),
    ] {
        insert_nonblank(&mut attributes, name, string_at(raw, provider_name));
    }
    attributes.insert("is_default".to_owned(), bool_text(raw, "isDefault"));
    attributes
}

fn site_payload(raw: &Value, tenant_id: &str, provider_id: &str) -> Value {
    let mut payload = base_payload(raw, tenant_id, provider_id);
    for (name, provider_name) in [
        ("name", "name"),
        ("state", "state"),
        ("site_type", "siteType"),
        ("description", "description"),
        ("expiration", "expiration"),
        ("account_id", "accountId"),
        ("account_name", "accountName"),
        ("created_at", "createdAt"),
        ("updated_at", "updatedAt"),
    ] {
        insert_json_string(&mut payload, name, string_at(raw, provider_name));
    }
    insert_json_true(&mut payload, "is_default", raw, "isDefault");
    insert_json_true(&mut payload, "health_status", raw, "healthStatus");
    insert_json_integer(&mut payload, "total_licenses", raw, "totalLicenses");
    insert_json_integer(&mut payload, "used_licenses", raw, "activeLicenses");
    Value::Object(payload)
}

fn group_attributes(raw: &Value, tenant_id: &str, provider_id: &str) -> BTreeMap<String, String> {
    let mut attributes =
        base_attributes(SentinelOneFamily::Group, tenant_id, "group_id", provider_id);
    for (name, provider_name) in [
        ("group_name", "name"),
        ("site_id", "siteId"),
        ("type", "type"),
    ] {
        insert_nonblank(&mut attributes, name, string_at(raw, provider_name));
    }
    attributes.insert("is_default".to_owned(), bool_text(raw, "isDefault"));
    attributes.insert("total_agents".to_owned(), integer_text(raw, "totalAgents"));
    attributes
}

fn group_payload(raw: &Value, tenant_id: &str, provider_id: &str) -> Value {
    let mut payload = base_payload(raw, tenant_id, provider_id);
    for (name, provider_name) in [
        ("name", "name"),
        ("type", "type"),
        ("description", "description"),
        ("site_id", "siteId"),
        ("filter_id", "filterId"),
        ("filter_name", "filterName"),
        ("creator", "creator"),
        ("creator_id", "creatorId"),
        ("created_at", "createdAt"),
        ("updated_at", "updatedAt"),
    ] {
        insert_json_string(&mut payload, name, string_at(raw, provider_name));
    }
    insert_json_true(&mut payload, "is_default", raw, "isDefault");
    insert_json_true(&mut payload, "inherits", raw, "inherits");
    insert_json_integer(&mut payload, "rank", raw, "rank");
    insert_json_integer(&mut payload, "total_agents", raw, "totalAgents");
    if !string_at(raw, "registrationToken").is_empty() {
        payload.insert("has_registration_token".to_owned(), Value::Bool(true));
    }
    Value::Object(payload)
}

fn exclusion_attributes(
    raw: &Value,
    tenant_id: &str,
    provider_id: &str,
) -> BTreeMap<String, String> {
    let mut attributes = base_attributes(
        SentinelOneFamily::Exclusion,
        tenant_id,
        "exclusion_id",
        provider_id,
    );
    for (name, provider_name) in [
        ("exclusion_type", "type"),
        ("mode", "mode"),
        ("source", "source"),
        ("os_type", "osType"),
        ("path_exclusion_type", "pathExclusionType"),
        ("scope", "scope"),
        ("scope_name", "scopeName"),
        ("scope_path", "scopePath"),
        ("value", "value"),
    ] {
        insert_nonblank(
            &mut attributes,
            name,
            flexible_string(raw.get(provider_name)),
        );
    }
    for (name, provider_name) in [
        ("not_recommended", "notRecommended"),
        ("include_children", "includeChildren"),
        ("include_parents", "includeParents"),
        ("imported", "imported"),
    ] {
        attributes.insert(
            name.to_owned(),
            flexible_bool(raw.get(provider_name)).to_string(),
        );
    }
    if let Some(actions) = string_array(raw.get("actions")) {
        insert_nonblank(&mut attributes, "actions", actions.join(","));
    }
    attributes
}

fn exclusion_payload(raw: &Value, tenant_id: &str, provider_id: &str) -> Value {
    let mut payload = base_payload(raw, tenant_id, provider_id);
    for (name, provider_name) in [
        ("type", "type"),
        ("mode", "mode"),
        ("source", "source"),
        ("os_type", "osType"),
        ("path_exclusion_type", "pathExclusionType"),
        ("description", "description"),
        ("application_name", "applicationName"),
        ("user_id", "userId"),
        ("user_name", "userName"),
        ("scope", "scope"),
        ("scope_name", "scopeName"),
        ("scope_path", "scopePath"),
        ("value", "value"),
        ("created_at", "createdAt"),
        ("updated_at", "updatedAt"),
    ] {
        insert_json_string(&mut payload, name, flexible_string(raw.get(provider_name)));
    }
    for (name, provider_name) in [
        ("include_children", "includeChildren"),
        ("include_parents", "includeParents"),
        ("imported", "imported"),
        ("not_recommended", "notRecommended"),
    ] {
        if flexible_bool(raw.get(provider_name)) {
            payload.insert(name.to_owned(), Value::Bool(true));
        }
    }
    if let Some(actions) = raw.get("actions").and_then(Value::as_array)
        && !actions.is_empty()
    {
        payload.insert("actions".to_owned(), Value::Array(actions.clone()));
    }
    Value::Object(payload)
}
