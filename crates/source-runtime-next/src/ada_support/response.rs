use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AdaSupportCheckpointCandidate, AdaSupportError, AdaSupportKernel, AdaSupportPage,
    AdaSupportRequest, normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AdaSupportKernel,
    request: &AdaSupportRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AdaSupportPage, AdaSupportError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AdaSupportError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| AdaSupportError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .and_then(Value::as_array)
        .ok_or(AdaSupportError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(AdaSupportError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| AdaSupportError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AdaSupportError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    let next_cursor = root
        .get("meta")
        .and_then(|meta| meta.get(kernel.family.next_page_key()))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|cursor| validate_cursor(kernel, cursor).map(str::to_owned))
        .transpose()?;
    if next_cursor.is_some() && next_cursor == request.cursor {
        return Err(AdaSupportError::InvalidCursor);
    }
    Ok(AdaSupportPage {
        records,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &AdaSupportKernel,
    request: &AdaSupportRequest,
    page: &AdaSupportPage,
    prior_watermark: Option<&str>,
) -> Result<AdaSupportCheckpointCandidate, AdaSupportError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AdaSupportError::TenantMismatch);
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
    Ok(AdaSupportCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), AdaSupportError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(AdaSupportError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AdaSupportError::AuthenticationRejected),
        403 => Err(AdaSupportError::RequiredScopeMissing),
        404 => Err(AdaSupportError::ProviderResourceNotFound),
        429 => Err(AdaSupportError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(AdaSupportError::ProviderUnavailable { status }),
        _ => Err(AdaSupportError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AdaSupportError> {
    let time = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| AdaSupportError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AdaSupportError::InvalidProviderRecord)
}
