//! Canonical SentinelOne threat event normalization.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::sentinelone::SentinelOneRecord;
use crate::source_execution::{SourceWorkerExecutionContextV1, SourceWorkerRecordV1};

use super::super::{direct::direct_event_id, error::SentinelOneAgentAdapterError};
use super::{
    bool_text, insert_json_integer, insert_json_string, insert_nonblank,
    provider_occurred_at_millis_for, remove_untrusted_tenant_fields, string_at,
};
use crate::sentinelone::SentinelOneFamily;

pub(crate) fn normalize_threat_record(
    record: SentinelOneRecord,
    context: &SourceWorkerExecutionContextV1,
) -> Result<SourceWorkerRecordV1, SentinelOneAgentAdapterError> {
    let provider_id = record.provider_id.trim();
    if provider_id.is_empty() {
        return Err(SentinelOneAgentAdapterError::MissingProviderIdentity);
    }
    let threat_info = object_at(&record.payload, "threatInfo");
    let detection = object_at(&record.payload, "agentDetectionInfo");
    let realtime = object_at(&record.payload, "agentRealtimeInfo");
    let indicators = indicator_summary(&record.payload);
    let occurred_at_unix_millis =
        provider_occurred_at_millis_for(threat_info, &["updatedAt", "identifiedAt", "createdAt"])
            .unwrap_or(context.observed_at_unix_millis);
    let attributes = threat_attributes(
        threat_info,
        detection,
        realtime,
        &indicators,
        &context.tenant_id,
        provider_id,
    );
    let payload = threat_payload(
        &record.payload,
        threat_info,
        detection,
        realtime,
        indicators,
        &context.tenant_id,
        provider_id,
    );
    Ok(SourceWorkerRecordV1 {
        provider_id: provider_id.to_owned(),
        event_id: direct_event_id(SentinelOneFamily::Threat, &context.tenant_id, provider_id)?,
        occurred_at_unix_millis,
        attributes: attributes.into_iter().collect(),
        payload_json: serde_json::to_vec(&payload)
            .map_err(|_| SentinelOneAgentAdapterError::InvalidProviderResponse)?,
    })
}

#[derive(Default)]
struct IndicatorSummary {
    categories: Vec<String>,
    tactics: Vec<String>,
    techniques: Vec<String>,
    descriptions: Vec<String>,
}

fn threat_attributes(
    threat_info: &Value,
    detection: &Value,
    realtime: &Value,
    indicators: &IndicatorSummary,
    tenant_id: &str,
    provider_id: &str,
) -> BTreeMap<String, String> {
    let mut attributes = BTreeMap::from([
        ("family".to_owned(), "threat".to_owned()),
        ("threat_id".to_owned(), provider_id.to_owned()),
        ("tenant_host".to_owned(), tenant_id.to_owned()),
        ("is_active".to_owned(), bool_text(realtime, "agentIsActive")),
        (
            "is_decommissioned".to_owned(),
            bool_text(realtime, "agentIsDecommissioned"),
        ),
        (
            "is_infected".to_owned(),
            bool_text(realtime, "agentInfected"),
        ),
        (
            "is_fileless".to_owned(),
            bool_text(threat_info, "isFileless"),
        ),
        (
            "automatically_resolved".to_owned(),
            bool_text(threat_info, "automaticallyResolved"),
        ),
    ]);
    for (name, value) in [
        ("classification", string_at(threat_info, "classification")),
        (
            "classification_source",
            string_at(threat_info, "classificationSource"),
        ),
        ("analyst_verdict", string_at(threat_info, "analystVerdict")),
        ("incident_status", string_at(threat_info, "incidentStatus")),
        (
            "confidence_level",
            string_at(threat_info, "confidenceLevel"),
        ),
        (
            "mitigation_status",
            string_at(threat_info, "mitigationStatus"),
        ),
        ("detection_type", string_at(threat_info, "detectionType")),
        ("threat_name", string_at(threat_info, "threatName")),
        ("file_path", string_at(threat_info, "filePath")),
        ("sha256", string_at(threat_info, "sha256")),
        (
            "agent_id",
            first_nonempty(&[
                string_at(realtime, "agentId"),
                string_at(detection, "agentUuid"),
            ]),
        ),
        ("agent_uuid", string_at(detection, "agentUuid")),
        ("agent_name", string_at(realtime, "agentComputerName")),
        ("computer_name", string_at(realtime, "agentComputerName")),
        ("hostname", string_at(realtime, "agentComputerName")),
        (
            "site_id",
            first_nonempty(&[
                string_at(detection, "siteId"),
                string_at(realtime, "siteId"),
            ]),
        ),
        (
            "group_id",
            first_nonempty(&[
                string_at(detection, "groupId"),
                string_at(realtime, "groupId"),
            ]),
        ),
        (
            "site_name",
            first_nonempty(&[
                string_at(detection, "siteName"),
                string_at(realtime, "siteName"),
            ]),
        ),
        (
            "group_name",
            first_nonempty(&[
                string_at(detection, "groupName"),
                string_at(realtime, "groupName"),
            ]),
        ),
        (
            "account_id",
            first_nonempty(&[
                string_at(detection, "accountId"),
                string_at(realtime, "accountId"),
            ]),
        ),
        (
            "account_name",
            first_nonempty(&[
                string_at(detection, "accountName"),
                string_at(realtime, "accountName"),
            ]),
        ),
        (
            "agent_os_name",
            first_nonempty(&[
                string_at(detection, "agentOsName"),
                string_at(realtime, "agentOsName"),
            ]),
        ),
        ("agent_os_type", string_at(realtime, "agentOsType")),
        ("agent_ip_v4", string_at(detection, "agentIpV4")),
        ("agent_ip_v6", string_at(detection, "agentIpV6")),
        ("external_ip", string_at(detection, "externalIp")),
        (
            "ip",
            first_nonempty(&[
                string_at(detection, "agentIpV4"),
                string_at(detection, "externalIp"),
                string_at(detection, "agentIpV6"),
            ]),
        ),
        (
            "ip_addresses",
            distinct_join(&[
                string_at(detection, "agentIpV4"),
                string_at(detection, "agentIpV6"),
                string_at(detection, "externalIp"),
            ]),
        ),
        (
            "user_mail",
            string_at(detection, "agentLastLoggedInUserMail"),
        ),
        (
            "user_name",
            string_at(detection, "agentLastLoggedInUserName"),
        ),
    ] {
        insert_nonblank(&mut attributes, name, value);
    }
    for (name, provider_name) in [
        ("classification_norm", "classification"),
        ("analyst_verdict_norm", "analystVerdict"),
        ("incident_status_norm", "incidentStatus"),
        ("mitigation_status_norm", "mitigationStatus"),
    ] {
        insert_nonblank(
            &mut attributes,
            name,
            normalize_posture(&string_at(threat_info, provider_name)),
        );
    }
    for (name, values) in [
        ("mitre_tactics", &indicators.tactics),
        ("mitre_techniques", &indicators.techniques),
        ("indicator_categories", &indicators.categories),
    ] {
        if !values.is_empty() {
            attributes.insert(name.to_owned(), values.join(","));
        }
    }
    attributes
}

fn threat_payload(
    raw: &Value,
    threat_info: &Value,
    detection: &Value,
    realtime: &Value,
    indicators: IndicatorSummary,
    tenant_id: &str,
    provider_id: &str,
) -> Value {
    let mut payload = Map::new();
    payload.insert("id".to_owned(), Value::String(provider_id.to_owned()));
    payload.insert(
        "tenant_host".to_owned(),
        Value::String(tenant_id.to_owned()),
    );
    payload.insert("threat_info".to_owned(), threat_info_payload(threat_info));
    payload.insert("agent_detection".to_owned(), detection_payload(detection));
    payload.insert("agent_realtime".to_owned(), realtime_payload(realtime));
    payload.insert("indicators".to_owned(), indicators_payload(indicators));
    if let Some(actions) = mitigation_payload(raw) {
        payload.insert("mitigation_actions".to_owned(), actions);
    }
    if let Some(values) = nonempty_array(raw.get("whiteningOptions")) {
        payload.insert("whitening_options".to_owned(), values);
    }
    let mut sanitized_raw = raw.clone();
    remove_untrusted_tenant_fields(&mut sanitized_raw);
    payload.insert("raw".to_owned(), sanitized_raw);
    Value::Object(payload)
}

fn threat_info_payload(raw: &Value) -> Value {
    let mut output = Map::new();
    for (name, provider_name) in [
        ("analyst_verdict", "analystVerdict"),
        ("classification", "classification"),
        ("classification_source", "classificationSource"),
        ("confidence_level", "confidenceLevel"),
        ("incident_status", "incidentStatus"),
        ("mitigation_status", "mitigationStatus"),
        ("threat_name", "threatName"),
        ("detection_type", "detectionType"),
        ("created_at", "createdAt"),
        ("identified_at", "identifiedAt"),
        ("updated_at", "updatedAt"),
        ("initiated_by", "initiatedBy"),
        ("initiated_by_description", "initiatedByDescription"),
        ("initiating_user_id", "initiatingUserId"),
        ("initiating_username", "initiatingUsername"),
        ("originator_process", "originatorProcess"),
        ("storyline_id", "storyline"),
        ("external_ticket_id", "externalTicketId"),
        ("file_path", "filePath"),
        ("file_extension", "fileExtension"),
        ("file_extension_type", "fileExtensionType"),
        ("sha1", "sha1"),
        ("sha256", "sha256"),
        ("md5", "md5"),
    ] {
        insert_json_string(&mut output, name, string_at(raw, provider_name));
    }
    insert_json_integer(&mut output, "file_size", raw, "fileSize");
    for (name, provider_name) in [
        ("is_fileless", "isFileless"),
        ("automatically_resolved", "automaticallyResolved"),
    ] {
        if raw.get(provider_name).and_then(Value::as_bool) == Some(true) {
            output.insert(name.to_owned(), Value::Bool(true));
        }
    }
    Value::Object(output)
}

fn detection_payload(raw: &Value) -> Value {
    let mut output = Map::new();
    for (name, provider_name) in [
        ("account_id", "accountId"),
        ("account_name", "accountName"),
        ("domain", "agentDomain"),
        ("ip_v4", "agentIpV4"),
        ("ip_v6", "agentIpV6"),
        ("os_name", "agentOsName"),
        ("os_revision", "agentOsRevision"),
        ("registered_at", "agentRegisteredAt"),
        ("uuid", "agentUuid"),
        ("version", "agentVersion"),
        ("external_ip", "externalIp"),
        ("group_id", "groupId"),
        ("group_name", "groupName"),
        ("site_id", "siteId"),
        ("site_name", "siteName"),
        ("user_mail", "agentLastLoggedInUserMail"),
        ("user_name", "agentLastLoggedInUserName"),
    ] {
        insert_json_string(&mut output, name, string_at(raw, provider_name));
    }
    insert_json_string(
        &mut output,
        "ip_addresses",
        distinct_join(&[
            string_at(raw, "agentIpV4"),
            string_at(raw, "agentIpV6"),
            string_at(raw, "externalIp"),
        ]),
    );
    Value::Object(output)
}

fn realtime_payload(raw: &Value) -> Value {
    let mut output = Map::new();
    for (name, provider_name) in [
        ("agent_id", "agentId"),
        ("computer_name", "agentComputerName"),
        ("hostname", "agentComputerName"),
        ("os_name", "agentOsName"),
        ("os_type", "agentOsType"),
        ("os_revision", "agentOsRevision"),
        ("network_status", "agentNetworkStatus"),
        ("operational_state", "operationalState"),
        ("scan_status", "scanStatus"),
        ("mitigation_mode", "agentMitigationMode"),
        ("uuid", "agentUuid"),
        ("version", "agentVersion"),
        ("group_id", "groupId"),
        ("group_name", "groupName"),
        ("site_id", "siteId"),
        ("site_name", "siteName"),
    ] {
        insert_json_string(&mut output, name, string_at(raw, provider_name));
    }
    for (name, provider_name) in [
        ("is_active", "agentIsActive"),
        ("is_decommissioned", "agentIsDecommissioned"),
        ("is_infected", "agentInfected"),
    ] {
        output.insert(
            name.to_owned(),
            Value::Bool(
                raw.get(provider_name)
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            ),
        );
    }
    output.insert(
        "active_threats".to_owned(),
        Value::Number(
            raw.get("activeThreats")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                .into(),
        ),
    );
    for (name, provider_name) in [("reboot_required", "rebootRequired")] {
        if raw.get(provider_name).and_then(Value::as_bool) == Some(true) {
            output.insert(name.to_owned(), Value::Bool(true));
        }
    }
    Value::Object(output)
}

fn indicator_summary(raw: &Value) -> IndicatorSummary {
    let mut categories = BTreeSet::new();
    let mut tactics = BTreeSet::new();
    let mut techniques = BTreeSet::new();
    let mut descriptions = BTreeSet::new();
    for indicator in raw
        .get("indicators")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        insert_set(&mut categories, string_at(indicator, "category"));
        for value in indicator
            .get("categories")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(value) = value.as_str() {
                insert_set(&mut categories, value.to_owned());
            }
        }
        insert_set(&mut descriptions, string_at(indicator, "description"));
        for tactic in indicator
            .get("tactics")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            insert_set(&mut tactics, string_at(tactic, "name"));
            for technique in tactic
                .get("techniques")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                insert_set(&mut techniques, string_at(technique, "name"));
            }
        }
    }
    IndicatorSummary {
        categories: categories.into_iter().collect(),
        tactics: tactics.into_iter().collect(),
        techniques: techniques.into_iter().collect(),
        descriptions: descriptions.into_iter().collect(),
    }
}

fn indicators_payload(summary: IndicatorSummary) -> Value {
    let mut output = Map::new();
    for (name, values) in [
        ("categories", summary.categories),
        ("mitre_tactics", summary.tactics),
        ("mitre_techniques", summary.techniques),
        ("descriptions", summary.descriptions),
    ] {
        if !values.is_empty() {
            output.insert(
                name.to_owned(),
                Value::Array(values.into_iter().map(Value::String).collect()),
            );
        }
    }
    Value::Object(output)
}

fn mitigation_payload(raw: &Value) -> Option<Value> {
    let actions = raw.get("mitigationStatus")?.as_array()?;
    if actions.is_empty() {
        return None;
    }
    let values = actions
        .iter()
        .map(|action| {
            let mut output = Map::new();
            output.insert(
                "action".to_owned(),
                Value::String(string_at(action, "action")),
            );
            for (name, provider_name) in [
                ("status", "status"),
                ("started_at", "mitigationStartedAt"),
                ("ended_at", "mitigationEndedAt"),
                ("last_update", "lastUpdate"),
                ("report_id", "reportId"),
            ] {
                insert_json_string(&mut output, name, string_at(action, provider_name));
            }
            Value::Object(output)
        })
        .collect();
    Some(Value::Array(values))
}

fn object_at<'a>(raw: &'a Value, name: &str) -> &'a Value {
    raw.get(name)
        .filter(|value| value.is_object())
        .unwrap_or(&Value::Null)
}

fn nonempty_array(value: Option<&Value>) -> Option<Value> {
    let values = value?.as_array()?;
    (!values.is_empty()).then(|| Value::Array(values.clone()))
}

fn insert_set(values: &mut BTreeSet<String>, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        values.insert(value.to_owned());
    }
}

fn first_nonempty(values: &[String]) -> String {
    values
        .iter()
        .find(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_default()
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

fn normalize_posture(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}
