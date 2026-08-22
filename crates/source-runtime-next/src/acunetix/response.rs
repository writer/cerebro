use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AcunetixCheckpointCandidate, AcunetixError, AcunetixKernel, AcunetixPage, AcunetixRequest,
    normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AcunetixKernel,
    request: &AcunetixRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AcunetixPage, AcunetixError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AcunetixError::ResponseTooLarge);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| AcunetixError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .and_then(Value::as_array)
        .ok_or(AcunetixError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(AcunetixError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| AcunetixError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AcunetixError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    let next_cursor = match root.pointer("/pagination/next_cursor") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.is_empty() => None,
        Some(Value::String(value)) => Some(validate_cursor(value)?.to_owned()),
        Some(_) => return Err(AcunetixError::InvalidCursor),
    };
    if next_cursor.is_some() && next_cursor == request.cursor {
        return Err(AcunetixError::InvalidCursor);
    }
    Ok(AcunetixPage {
        records,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &AcunetixKernel,
    request: &AcunetixRequest,
    page: &AcunetixPage,
    prior_watermark: Option<&str>,
) -> Result<AcunetixCheckpointCandidate, AcunetixError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AcunetixError::TenantMismatch);
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
    Ok(AcunetixCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(status: u16, retry: Option<u64>) -> Result<(), AcunetixError> {
    if retry.is_some_and(|seconds| seconds > 3_600) {
        return Err(AcunetixError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AcunetixError::AuthenticationRejected),
        403 => Err(AcunetixError::RequiredScopeMissing),
        404 => Err(AcunetixError::ProviderResourceNotFound),
        429 => Err(AcunetixError::RateLimited {
            retry_after_seconds: retry,
        }),
        500..=599 => Err(AcunetixError::ProviderUnavailable { status }),
        _ => Err(AcunetixError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AcunetixError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AcunetixError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AcunetixError::InvalidProviderRecord)
}
