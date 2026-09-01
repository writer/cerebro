use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    error::DopplerError,
    normalize::normalize_record,
    request::{PAGE_SIZE, validate_cursor, validate_request},
    types::{DopplerKernel, DopplerPage, DopplerRecord, DopplerRequest},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 << 20;

pub(super) fn decode(
    kernel: &DopplerKernel,
    request: &DopplerRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<DopplerPage, DopplerError> {
    validate_request(kernel, request)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(DopplerError::ResponseTooLarge);
    }
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(DopplerError::UnexpectedStatus);
    }
    match status {
        200 => {}
        401 => return Err(DopplerError::AuthenticationRejected),
        403 => return Err(DopplerError::RequiredScopeMissing),
        408 | 504 => return Err(DopplerError::ProviderTimeout),
        429 => return Err(DopplerError::RateLimited),
        500..=599 => return Err(DopplerError::ProviderUnavailable),
        _ => return Err(DopplerError::UnexpectedStatus),
    }

    let root: Value = serde_json::from_slice(body).map_err(|_| DopplerError::MalformedResponse)?;
    let object = root.as_object().ok_or(DopplerError::MalformedResponse)?;
    let values = object
        .get("data")
        .and_then(Value::as_array)
        .ok_or(DopplerError::MalformedResponse)?;
    if values.len() > PAGE_SIZE {
        return Err(DopplerError::TooManyRecords);
    }

    let mut records = Vec::<DopplerRecord>::with_capacity(values.len());
    let mut first_by_id = BTreeMap::<String, usize>::new();
    for value in values {
        let record = normalize_record(kernel, value)?;
        if let Some(index) = first_by_id.get(&record.provider_id).copied() {
            if records.get(index) != Some(&record) {
                return Err(DopplerError::ConflictingDuplicate);
            }
            continue;
        }
        first_by_id.insert(record.provider_id.clone(), records.len());
        records.push(record);
    }

    let next_cursor = match object.get("next_cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.trim().is_empty() => None,
        Some(Value::String(value)) => Some(validate_cursor(value)?),
        Some(_) => return Err(DopplerError::InvalidCursor),
    };
    if next_cursor.as_deref() == request.cursor.as_deref() && next_cursor.is_some() {
        return Err(DopplerError::InvalidCursor);
    }
    Ok(DopplerPage {
        records,
        next_cursor,
    })
}
