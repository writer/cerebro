use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AirbrakeCheckpointCandidate, AirbrakeError, AirbrakeKernel, AirbrakePage, AirbrakeRequest,
    normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AirbrakeKernel,
    request: &AirbrakeRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AirbrakePage, AirbrakeError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AirbrakeError::ResponseTooLarge);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| AirbrakeError::MalformedResponse)?;
    let root = root.as_object().ok_or(AirbrakeError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .and_then(Value::as_array)
        .ok_or(AirbrakeError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(AirbrakeError::TooManyRecords);
    }

    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| AirbrakeError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AirbrakeError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }

    let next_cursor = if kernel.family.cursor_paginated() {
        root.get("end")
            .and_then(cursor_scalar)
            .filter(|cursor| request.cursor.as_deref() != Some(cursor.as_str()))
            .map(|cursor| validate_cursor(&cursor))
            .transpose()?
    } else {
        None
    };
    Ok(AirbrakePage {
        records,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &AirbrakeKernel,
    request: &AirbrakeRequest,
    page: &AirbrakePage,
    prior_watermark: Option<&str>,
) -> Result<AirbrakeCheckpointCandidate, AirbrakeError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AirbrakeError::TenantMismatch);
    }
    if let Some(cursor) = &page.next_cursor {
        kernel.plan(Some(cursor))?;
    }
    let mut watermark = valid_time(prior_watermark.unwrap_or(&kernel.observed_at))?;
    for record in &page.records {
        let occurred_at = valid_time(&record.occurred_at)?;
        if occurred_at > watermark {
            watermark = occurred_at;
        }
    }
    Ok(AirbrakeCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn cursor_scalar(value: &Value) -> Option<String> {
    let cursor = match value {
        Value::String(value) => value.trim().to_owned(),
        Value::Number(value) => value.to_string(),
        _ => return None,
    };
    (!cursor.is_empty()).then_some(cursor)
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), AirbrakeError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(AirbrakeError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AirbrakeError::AuthenticationRejected),
        403 => Err(AirbrakeError::RequiredScopeMissing),
        404 => Err(AirbrakeError::ProviderResourceNotFound),
        429 => Err(AirbrakeError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(AirbrakeError::ProviderUnavailable { status }),
        _ => Err(AirbrakeError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AirbrakeError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AirbrakeError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AirbrakeError::InvalidProviderRecord)
}
