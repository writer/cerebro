use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Map, Value};

use super::cursor::bounded_provider_cursor;
use super::model::{SentinelOneError, SentinelOneFamily, SentinelOneRecord};

pub(super) struct DecodedList {
    pub(super) records: Vec<Value>,
    pub(super) next_cursor: String,
}

pub(super) fn decode_list(body: &[u8]) -> Result<DecodedList, SentinelOneError> {
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
    Ok(DecodedList {
        records,
        next_cursor,
    })
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
    let encoded = |field| {
        URL_SAFE_NO_PAD.encode(
            scalar_string(payload.get(field))
                .unwrap_or_default()
                .as_bytes(),
        )
    };
    format!(
        "p.{}.n.{}.v.{}",
        encoded("publisher"),
        encoded("name"),
        encoded("version")
    )
}

pub(super) fn nonempty(value: String) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.trim().to_owned())
}
