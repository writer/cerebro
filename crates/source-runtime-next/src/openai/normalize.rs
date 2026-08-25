//! Strict OpenAI response decoding and event-contract admission.

use std::collections::{BTreeMap, btree_map::Entry};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{
    OpenAiCheckpoint, OpenAiError, OpenAiKernel, OpenAiPage, OpenAiRecord, OpenAiRequestInput,
    family::{BASE_PATH, MAX_RECORDS_PER_PAGE, MAX_RESPONSE_BYTES, ORIGIN, Pagination, SOURCE_ID},
};

pub(super) fn decode_page(
    kernel: &OpenAiKernel,
    input: &OpenAiRequestInput,
    status_code: u16,
    response_body: &[u8],
    observed_at_unix_millis: i64,
) -> Result<OpenAiPage, OpenAiError> {
    classify_status(status_code)?;
    if response_body.len() > MAX_RESPONSE_BYTES {
        return Err(OpenAiError::ResponseTooLarge);
    }
    if observed_at_unix_millis <= 0 {
        return Err(OpenAiError::MalformedResponse);
    }
    // Re-plan so decoding is bound to the same validated public scope and cursor.
    let planned = kernel.plan(input)?;
    let root: Value =
        serde_json::from_slice(response_body).map_err(|_| OpenAiError::MalformedResponse)?;
    let spec = kernel.family().spec();
    let (provider_records, next_cursor) = match spec.pagination {
        Pagination::None => (vec![singleton_record(root)?], None),
        Pagination::Cursor => {
            let records = root
                .get("data")
                .and_then(Value::as_array)
                .cloned()
                .ok_or(OpenAiError::MalformedResponse)?;
            let has_more = root
                .get("has_more")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let next = first_string(&root, &["next", "last_id"]);
            if has_more && next.is_none() {
                return Err(OpenAiError::InvalidCursor);
            }
            (records, next)
        }
        Pagination::Page => {
            let records = root
                .get("data")
                .and_then(Value::as_array)
                .cloned()
                .ok_or(OpenAiError::MalformedResponse)?;
            (records, first_string(&root, &["next_page"]))
        }
    };
    if provider_records.len() > MAX_RECORDS_PER_PAGE {
        return Err(OpenAiError::ResponseTooLarge);
    }
    if next_cursor.as_deref().is_some_and(|cursor| {
        cursor.is_empty()
            || cursor.len() > 4 << 10
            || cursor.trim() != cursor
            || cursor.chars().any(char::is_control)
    }) {
        return Err(OpenAiError::InvalidCursor);
    }

    let request_path = planned
        .url
        .strip_prefix(&format!("{ORIGIN}{BASE_PATH}"))
        .and_then(|value| value.split('?').next())
        .ok_or(OpenAiError::MalformedResponse)?;
    let mut deduped = BTreeMap::<String, (String, OpenAiRecord)>::new();
    for provider_record in provider_records {
        let record = normalize_record(
            kernel,
            input,
            request_path,
            provider_record,
            observed_at_unix_millis,
        )?;
        let digest = canonical_record_digest(&record)?;
        match deduped.entry(record.event_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert((digest, record));
            }
            Entry::Occupied(entry) if entry.get().0 == digest => {}
            Entry::Occupied(_) => return Err(OpenAiError::DuplicateConflict),
        }
    }
    let records = deduped
        .into_values()
        .map(|(_, record)| record)
        .collect::<Vec<_>>();
    let proposed_checkpoint =
        (!records.is_empty() || next_cursor.is_some()).then(|| OpenAiCheckpoint {
            cursor_opaque: next_cursor.clone(),
            last_provider_id: records.last().map(|record| record.provider_id.clone()),
            watermark_unix_millis: records.last().map_or(observed_at_unix_millis, |record| {
                record.occurred_at_unix_millis
            }),
        });
    Ok(OpenAiPage {
        records,
        next_cursor,
        proposed_checkpoint,
    })
}

fn normalize_record(
    kernel: &OpenAiKernel,
    input: &OpenAiRequestInput,
    request_path: &str,
    mut payload: Value,
    observed_at_unix_millis: i64,
) -> Result<OpenAiRecord, OpenAiError> {
    let spec = kernel.family().spec();
    reject_credential_material(&payload)?;
    if matches!(spec.id, "api_key" | "admin_api_key" | "project_api_key")
        && payload.get("value").is_some()
    {
        return Err(OpenAiError::EventContractRejected);
    }
    let object = payload
        .as_object_mut()
        .ok_or(OpenAiError::MalformedResponse)?;
    if let Some(provider_tenant) = object.get("tenant_id")
        && provider_tenant.as_str() != Some(kernel.tenant_id())
    {
        return Err(OpenAiError::TenantMismatch);
    }
    object.remove("tenant_id");
    for (parameter, expected) in &input.path_parameters {
        if let Some(actual) = object.get(parameter).and_then(scalar_string)
            && actual != *expected
        {
            return Err(OpenAiError::TenantMismatch);
        }
        object
            .entry(parameter.clone())
            .or_insert_with(|| Value::String(expected.clone()));
    }
    let provider_id = if let Some(identity_template) = spec.singleton_identity {
        render_singleton_identity(identity_template, &input.path_parameters)?
    } else {
        first_expression(&payload, spec.id_paths)
            .filter(|value| safe_identity(value))
            .ok_or(OpenAiError::MissingStableIdentity)?
    };
    if !safe_identity(&provider_id) {
        return Err(OpenAiError::MissingStableIdentity);
    }
    for field in spec.required_payload_fields {
        if first_expression(&payload, &[*field]).is_none() {
            return Err(OpenAiError::EventContractRejected);
        }
    }
    let mut attributes = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), spec.id.to_owned()),
        ("provider".to_owned(), SOURCE_ID.to_owned()),
        ("source_product".to_owned(), SOURCE_ID.to_owned()),
        ("source_provider".to_owned(), SOURCE_ID.to_owned()),
    ]);
    for (key, value) in &input.path_parameters {
        attributes.insert(key.clone(), value.clone());
    }
    for (attribute, expression) in spec.attributes {
        if let Some(value) = first_expression(&payload, &[*expression]) {
            attributes.insert((*attribute).to_owned(), value);
        }
    }
    if spec.id == "admin_api_key" {
        attributes.insert("key_class".to_owned(), "admin".to_owned());
        attributes.insert("privileged".to_owned(), "true".to_owned());
    }
    for required in spec.required_attributes {
        if attributes
            .get(*required)
            .is_none_or(|value| value.is_empty())
        {
            return Err(OpenAiError::EventContractRejected);
        }
    }
    let occurred_at_unix_millis = spec
        .timestamp_paths
        .iter()
        .find_map(|path| value_at_path(&payload, path).and_then(timestamp_millis))
        .unwrap_or(observed_at_unix_millis);
    let event_id = go_event_id(kernel.tenant_id(), request_path, spec.id, &provider_id);
    Ok(OpenAiRecord {
        event_id,
        tenant_id: kernel.tenant_id().to_owned(),
        source_id: SOURCE_ID.to_owned(),
        family: spec.id.to_owned(),
        provider_kind: kernel.family().event_kind(),
        schema_ref: kernel.family().schema_ref(),
        provider_id,
        occurred_at_unix_millis,
        attributes,
        payload,
    })
}

fn reject_credential_material(value: &Value) -> Result<(), OpenAiError> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let key = key.to_ascii_lowercase().replace('-', "_");
                if matches!(
                    key.as_str(),
                    "api_key"
                        | "access_token"
                        | "refresh_token"
                        | "authorization"
                        | "client_secret"
                        | "cookie"
                        | "password"
                        | "private_key"
                        | "secret"
                        | "token"
                ) {
                    return Err(OpenAiError::EventContractRejected);
                }
                reject_credential_material(value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_credential_material(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn render_singleton_identity(
    template: &str,
    path_parameters: &BTreeMap<String, String>,
) -> Result<String, OpenAiError> {
    let mut identity = template.to_owned();
    for (parameter, value) in path_parameters {
        identity = identity.replace(&format!("{{{parameter}}}"), value);
    }
    if identity.contains('{') || identity.contains('}') {
        return Err(OpenAiError::MissingStableIdentity);
    }
    Ok(identity)
}

fn singleton_record(root: Value) -> Result<Value, OpenAiError> {
    let Some(object) = root.as_object() else {
        return Err(OpenAiError::MalformedResponse);
    };
    if object.len() == 1
        && let Some(data) = object.get("data")
        && data.is_object()
    {
        return Ok(data.clone());
    }
    Ok(root)
}

fn classify_status(status: u16) -> Result<(), OpenAiError> {
    match status {
        200..=299 => Ok(()),
        401 => Err(OpenAiError::AuthenticationRejected),
        403 => Err(OpenAiError::PermissionDenied),
        429 => Err(OpenAiError::RateLimited),
        408 | 425 | 500..=599 => Err(OpenAiError::ProviderUnavailable(status)),
        _ => Err(OpenAiError::UnexpectedStatus(status)),
    }
}

fn first_string(root: &Value, paths: &[&str]) -> Option<String> {
    paths
        .iter()
        .find_map(|path| value_at_path(root, path).and_then(scalar_string))
        .filter(|value| !value.is_empty())
}

fn first_expression(root: &Value, expressions: &[&str]) -> Option<String> {
    expressions.iter().find_map(|expression| {
        expression
            .split('|')
            .find_map(|path| expression_value(root, path))
    })
}

fn expression_value(root: &Value, path: &str) -> Option<String> {
    if let Some(prefix) = path.strip_suffix(".__count") {
        return value_at_path(root, prefix)
            .and_then(Value::as_array)
            .map(|values| values.len().to_string());
    }
    if let Some(prefix) = path.strip_suffix(".__sum") {
        let (array_path, value_path) = prefix.rsplit_once('.')?;
        let sum = value_at_path(root, array_path)?
            .as_array()?
            .iter()
            .filter_map(|value| value_at_path(value, value_path))
            .filter_map(number_as_i128)
            .sum::<i128>();
        return Some(sum.to_string());
    }
    let value = value_at_path(root, path)?;
    scalar_string(value).or_else(|| serde_json::to_string(value).ok())
}

fn value_at_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let parts = path.trim_start_matches("$.").split('.').collect::<Vec<_>>();
    value_at_parts(root, &parts)
}

fn value_at_parts<'a>(current: &'a Value, parts: &[&str]) -> Option<&'a Value> {
    if parts.is_empty() {
        return Some(current);
    }
    let object = current.as_object()?;
    for end in 1..=parts.len() {
        let key = parts[..end].join(".");
        if let Some(next) = object.get(&key)
            && let Some(value) = value_at_parts(next, &parts[end..])
        {
            return Some(value);
        }
    }
    None
}

fn scalar_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn number_as_i128(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn timestamp_millis(value: &Value) -> Option<i64> {
    if let Some(seconds) = value.as_i64() {
        return Some(if seconds > 1_000_000_000_000 {
            seconds
        } else {
            seconds.saturating_mul(1_000)
        });
    }
    let raw = value.as_str()?;
    if let Ok(seconds) = raw.parse::<i64>() {
        return Some(if seconds > 1_000_000_000_000 {
            seconds
        } else {
            seconds.saturating_mul(1_000)
        });
    }
    time::OffsetDateTime::parse(raw, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|time| time.unix_timestamp_nanos().div_euclid(1_000_000) as i64)
}

fn safe_identity(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && value.len() <= 1 << 10
        && !value.chars().any(char::is_control)
}

pub(super) fn go_event_id(tenant_id: &str, path: &str, family: &str, provider_id: &str) -> String {
    let scope = Sha256::digest(format!("{ORIGIN}{BASE_PATH}\0{path}").as_bytes());
    format!(
        "{SOURCE_ID}-{}-{}-{}-{}",
        normalize_id(tenant_id),
        hex_bytes(&scope[..6]),
        normalize_id(family),
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

fn canonical_record_digest(record: &OpenAiRecord) -> Result<String, OpenAiError> {
    let bytes = serde_json::to_vec(record).map_err(|_| OpenAiError::MalformedResponse)?;
    Ok(hex_bytes(&Sha256::digest(bytes)))
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
            output
        },
    )
}
