use std::collections::BTreeMap;

use serde_json::{Map, Value};

use super::cursor::bounded_provider_cursor;
use super::model::{SentinelOneError, SentinelOneFamily, SentinelOneRecord};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 << 20;

pub(super) struct DecodedList {
    pub(super) records: Vec<Value>,
    pub(super) next_cursor: String,
}

pub(super) fn decode_list(
    family: SentinelOneFamily,
    body: &[u8],
) -> Result<DecodedList, SentinelOneError> {
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(SentinelOneError::InvalidResponse);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| SentinelOneError::InvalidResponse)?;
    let object = root.as_object().ok_or(SentinelOneError::InvalidResponse)?;
    let data = object.get("data").unwrap_or(&Value::Null);
    let (records, nested_cursor) = records_from_data(data)?;
    let next_cursor = match nested_cursor {
        Some(cursor) => Some(cursor),
        None => cursor_from_object(object)?,
    }
    .unwrap_or_default();
    validate_records(family, &records)?;
    Ok(DecodedList {
        records,
        next_cursor,
    })
}

#[derive(Clone, Copy)]
enum WireType {
    String,
    Bool,
    Integer,
    Object,
    StringArray,
    FlexibleBool,
}

fn validate_records(family: SentinelOneFamily, records: &[Value]) -> Result<(), SentinelOneError> {
    for record in records {
        let object = record
            .as_object()
            .ok_or(SentinelOneError::InvalidResponse)?;
        validate_fields(object, &["id"], WireType::String)?;
        match family {
            SentinelOneFamily::Activity => validate_activity(object)?,
            SentinelOneFamily::Agent => validate_agent(object)?,
            SentinelOneFamily::Application => validate_application(object)?,
            SentinelOneFamily::Exclusion => validate_exclusion(object)?,
            SentinelOneFamily::Group => validate_group(object)?,
            SentinelOneFamily::Site => validate_site(object)?,
            SentinelOneFamily::Threat => validate_threat(object)?,
        }
    }
    Ok(())
}

fn validate_activity(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(
        object,
        &[
            "accountId",
            "accountName",
            "activityUuid",
            "agentId",
            "agentUpdatedVersion",
            "comments",
            "createdAt",
            "description",
            "groupId",
            "groupName",
            "hash",
            "osFamily",
            "primaryDescription",
            "secondaryDescription",
            "siteId",
            "siteName",
            "threatId",
            "updatedAt",
            "userId",
        ],
        WireType::String,
    )?;
    validate_fields(object, &["activityType"], WireType::Integer)?;
    validate_fields(object, &["data"], WireType::Object)
}

fn validate_agent(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(
        object,
        &[
            "accountId",
            "accountName",
            "agentVersion",
            "appsVulnerabilityStatus",
            "computerName",
            "createdAt",
            "detectionState",
            "domain",
            "externalId",
            "externalIp",
            "groupId",
            "groupIp",
            "groupName",
            "installerType",
            "lastActiveDate",
            "lastIpToMgmt",
            "lastLoggedInUserName",
            "lastSuccessfulScanDate",
            "licenseKey",
            "machineType",
            "mitigationMode",
            "mitigationModeSuspicious",
            "modelName",
            "networkStatus",
            "operationalState",
            "osArch",
            "osName",
            "osRevision",
            "osType",
            "osUsername",
            "registeredAt",
            "scanStatus",
            "serialNumber",
            "siteId",
            "siteName",
            "storageName",
            "storageType",
            "updatedAt",
            "uuid",
        ],
        WireType::String,
    )?;
    validate_fields(
        object,
        &[
            "inRemoteShellSession",
            "infected",
            "isActive",
            "isDecommissioned",
            "isPendingUninstall",
            "isUninstalled",
            "isUpToDate",
            "rebootRequired",
            "showAlertIcon",
        ],
        WireType::Bool,
    )?;
    validate_fields(
        object,
        &["activeThreats", "coreCount", "cpuCount", "totalMemory"],
        WireType::Integer,
    )?;
    validate_fields(object, &["firewallEnabled"], WireType::FlexibleBool)?;
    validate_fields(object, &["tags"], WireType::Object)?;
    validate_fields(object, &["userActionsNeeded"], WireType::StringArray)
}

fn validate_application(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(
        object,
        &["installedDate", "name", "publisher", "version"],
        WireType::String,
    )?;
    validate_fields(object, &["size"], WireType::Integer)
}

fn validate_exclusion(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(
        object,
        &[
            "applicationName",
            "createdAt",
            "description",
            "mode",
            "osType",
            "pathExclusionType",
            "source",
            "type",
            "updatedAt",
            "userId",
            "userName",
        ],
        WireType::String,
    )?;
    validate_fields(
        object,
        &[
            "imported",
            "includeChildren",
            "includeParents",
            "notRecommended",
        ],
        WireType::FlexibleBool,
    )?;
    validate_fields(object, &["actions"], WireType::StringArray)
}

fn validate_group(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(
        object,
        &[
            "createdAt",
            "creator",
            "creatorId",
            "description",
            "filterId",
            "filterName",
            "name",
            "registrationToken",
            "siteId",
            "type",
            "updatedAt",
        ],
        WireType::String,
    )?;
    validate_fields(object, &["inherits", "isDefault"], WireType::Bool)?;
    validate_fields(object, &["rank", "totalAgents"], WireType::Integer)
}

fn validate_site(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(
        object,
        &[
            "accountId",
            "accountName",
            "createdAt",
            "description",
            "expiration",
            "name",
            "siteType",
            "state",
            "updatedAt",
        ],
        WireType::String,
    )?;
    validate_fields(object, &["healthStatus", "isDefault"], WireType::Bool)?;
    validate_fields(
        object,
        &["activeLicenses", "totalLicenses"],
        WireType::Integer,
    )
}

fn validate_threat(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_nested_object(object, "threatInfo", |info| {
        validate_fields(
            info,
            &[
                "analystVerdict",
                "classification",
                "classificationSource",
                "confidenceLevel",
                "createdAt",
                "detectionType",
                "externalTicketId",
                "fileExtension",
                "fileExtensionType",
                "filePath",
                "identifiedAt",
                "incidentStatus",
                "initiatedBy",
                "initiatedByDescription",
                "initiatingUserId",
                "initiatingUsername",
                "md5",
                "mitigationStatus",
                "originatorProcess",
                "sha1",
                "sha256",
                "storyline",
                "threatName",
                "updatedAt",
            ],
            WireType::String,
        )?;
        validate_fields(
            info,
            &["automaticallyResolved", "isFileless"],
            WireType::Bool,
        )?;
        validate_fields(info, &["fileSize"], WireType::Integer)
    })?;
    validate_nested_object(object, "agentDetectionInfo", |info| {
        validate_fields(
            info,
            &[
                "accountId",
                "accountName",
                "agentDetectionState",
                "agentDomain",
                "agentIpV4",
                "agentIpV6",
                "agentLastLoggedInUserMail",
                "agentLastLoggedInUserName",
                "agentMitigationMode",
                "agentOsName",
                "agentOsRevision",
                "agentRegisteredAt",
                "agentUuid",
                "agentVersion",
                "externalIp",
                "groupId",
                "groupName",
                "siteId",
                "siteName",
            ],
            WireType::String,
        )
    })?;
    validate_nested_object(object, "agentRealtimeInfo", |info| {
        validate_fields(
            info,
            &[
                "accountId",
                "accountName",
                "agentComputerName",
                "agentDomain",
                "agentId",
                "agentMachineType",
                "agentMitigationMode",
                "agentNetworkStatus",
                "agentOsName",
                "agentOsRevision",
                "agentOsType",
                "agentUuid",
                "agentVersion",
                "groupId",
                "groupName",
                "operationalState",
                "scanStatus",
                "siteId",
                "siteName",
                "storageName",
            ],
            WireType::String,
        )?;
        validate_fields(
            info,
            &[
                "agentInfected",
                "agentIsActive",
                "agentIsDecommissioned",
                "rebootRequired",
            ],
            WireType::Bool,
        )?;
        validate_fields(info, &["activeThreats"], WireType::Integer)
    })?;
    validate_object_array(object, "indicators", validate_indicator)?;
    validate_object_array(object, "mitigationStatus", validate_mitigation)?;
    validate_fields(object, &["whiteningOptions"], WireType::StringArray)
}

fn validate_indicator(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(object, &["category", "description"], WireType::String)?;
    validate_fields(object, &["categories"], WireType::StringArray)?;
    validate_integer_array(object, "ids")?;
    validate_object_array(object, "tactics", |tactic| {
        validate_fields(tactic, &["name", "source"], WireType::String)?;
        validate_object_array(tactic, "techniques", |technique| {
            validate_fields(technique, &["link", "name"], WireType::String)
        })
    })
}

fn validate_mitigation(object: &Map<String, Value>) -> Result<(), SentinelOneError> {
    validate_fields(
        object,
        &[
            "action",
            "lastUpdate",
            "mitigationEndedAt",
            "mitigationStartedAt",
            "reportId",
            "status",
        ],
        WireType::String,
    )?;
    let Some(value) = object.get("actionsCounters") else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let counters = value.as_object().ok_or(SentinelOneError::InvalidResponse)?;
    if counters.values().all(is_integer) {
        Ok(())
    } else {
        Err(SentinelOneError::InvalidResponse)
    }
}

fn validate_fields(
    object: &Map<String, Value>,
    fields: &[&str],
    expected: WireType,
) -> Result<(), SentinelOneError> {
    for field in fields {
        if let Some(value) = object.get(*field)
            && !value.is_null()
            && !matches_wire_type(value, expected)
        {
            return Err(SentinelOneError::InvalidResponse);
        }
    }
    Ok(())
}

fn matches_wire_type(value: &Value, expected: WireType) -> bool {
    match expected {
        WireType::String => value.is_string(),
        WireType::Bool => value.is_boolean(),
        WireType::Integer => is_integer(value),
        WireType::Object => value.is_object(),
        WireType::StringArray => value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string)),
        WireType::FlexibleBool => value.is_boolean() || value.is_string(),
    }
}

fn is_integer(value: &Value) -> bool {
    value.as_i64().is_some()
}

fn validate_nested_object(
    object: &Map<String, Value>,
    field: &str,
    validate: impl FnOnce(&Map<String, Value>) -> Result<(), SentinelOneError>,
) -> Result<(), SentinelOneError> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    validate(value.as_object().ok_or(SentinelOneError::InvalidResponse)?)
}

fn validate_object_array(
    object: &Map<String, Value>,
    field: &str,
    validate: impl Fn(&Map<String, Value>) -> Result<(), SentinelOneError>,
) -> Result<(), SentinelOneError> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    for item in value.as_array().ok_or(SentinelOneError::InvalidResponse)? {
        validate(item.as_object().ok_or(SentinelOneError::InvalidResponse)?)?;
    }
    Ok(())
}

fn validate_integer_array(
    object: &Map<String, Value>,
    field: &str,
) -> Result<(), SentinelOneError> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    if value
        .as_array()
        .is_some_and(|values| values.iter().all(is_integer))
    {
        Ok(())
    } else {
        Err(SentinelOneError::InvalidResponse)
    }
}

fn records_from_data(data: &Value) -> Result<(Vec<Value>, Option<String>), SentinelOneError> {
    match data {
        Value::Null => Ok((Vec::new(), None)),
        Value::Array(records) => Ok((records.clone(), None)),
        Value::Object(object) => {
            let cursor = cursor_from_object(object)?;
            for key in [
                "activities",
                "agents",
                "applications",
                "exclusions",
                "groups",
                "sites",
                "threats",
                "items",
                "records",
                "data",
            ] {
                if let Some(Value::Array(records)) = object.get(key) {
                    return Ok((records.clone(), cursor));
                }
            }
            Err(SentinelOneError::InvalidResponse)
        }
        _ => Err(SentinelOneError::InvalidResponse),
    }
}

fn cursor_from_object(object: &Map<String, Value>) -> Result<Option<String>, SentinelOneError> {
    let value = object
        .get("pagination")
        .and_then(Value::as_object)
        .and_then(|pagination| pagination.get("nextCursor"))
        .or_else(|| object.get("nextCursor"));
    match value {
        Some(Value::String(value)) => bounded_provider_cursor(Some(value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(SentinelOneError::InvalidResponse),
    }
}

pub(super) fn normalize_record(
    family: SentinelOneFamily,
    provider_id: String,
    payload: Value,
    agent_id: Option<&str>,
) -> SentinelOneRecord {
    let mut fields = BTreeMap::new();
    flatten_scalars(None, &payload, &mut fields);
    if let Some(agent_id) = agent_id {
        fields.insert("agent_id".to_owned(), agent_id.to_owned());
        fields.insert("application_id".to_owned(), application_identity(&payload));
    }
    SentinelOneRecord {
        family: family.as_str().to_owned(),
        provider_kind: family.provider_kind().to_owned(),
        provider_id,
        fields,
        payload,
    }
}

fn flatten_scalars(prefix: Option<&str>, value: &Value, fields: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let path = prefix.map_or_else(|| key.clone(), |prefix| format!("{prefix}.{key}"));
                flatten_scalars(Some(&path), value, fields);
            }
        }
        Value::Array(_) | Value::Null => {}
        Value::Bool(value) => {
            if let Some(prefix) = prefix {
                fields.insert(prefix.to_owned(), value.to_string());
            }
        }
        Value::Number(value) => {
            if let Some(prefix) = prefix {
                fields.insert(prefix.to_owned(), value.to_string());
            }
        }
        Value::String(value) => {
            if let Some(prefix) = prefix {
                fields.insert(prefix.to_owned(), value.clone());
            }
        }
    }
}

pub(super) fn scalar_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => Some(value.trim().to_owned()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

pub(super) fn application_identity(payload: &Value) -> String {
    let parts = ["publisher", "name", "version"]
        .into_iter()
        .filter_map(|field| scalar_string(payload.get(field)))
        .map(|value| value.trim().replace(' ', "_"))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "unknown".to_owned()
    } else {
        parts.join("::")
    }
}

pub(super) fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_owned())
}
