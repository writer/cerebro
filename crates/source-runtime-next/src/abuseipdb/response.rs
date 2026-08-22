use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AbuseIpDbCheckpointCandidate, AbuseIpDbError, AbuseIpDbFamily, AbuseIpDbKernel, AbuseIpDbPage,
    AbuseIpDbRequest, normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AbuseIpDbKernel,
    request: &AbuseIpDbRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AbuseIpDbPage, AbuseIpDbError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AbuseIpDbError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| AbuseIpDbError::MalformedResponse)?;
    let items = records(kernel.family, &root)?;
    if items.len() > request.record_limit {
        return Err(AbuseIpDbError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut normalized = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| AbuseIpDbError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AbuseIpDbError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                normalized.push(record);
            }
        }
    }
    Ok(AbuseIpDbPage {
        records: normalized,
        next_cursor: next_cursor(kernel.family, request, &root, items.len())?,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &AbuseIpDbKernel,
    request: &AbuseIpDbRequest,
    page: &AbuseIpDbPage,
    prior_watermark: Option<&str>,
) -> Result<AbuseIpDbCheckpointCandidate, AbuseIpDbError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AbuseIpDbError::TenantMismatch);
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
    Ok(AbuseIpDbCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn records(family: AbuseIpDbFamily, root: &Value) -> Result<&[Value], AbuseIpDbError> {
    match family {
        AbuseIpDbFamily::Reports => root
            .get("data")
            .and_then(|value| value.get("results"))
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or(AbuseIpDbError::MalformedResponse),
        AbuseIpDbFamily::IpAddresses => root
            .get("data")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or(AbuseIpDbError::MalformedResponse),
    }
}

fn next_cursor(
    family: AbuseIpDbFamily,
    request: &AbuseIpDbRequest,
    root: &Value,
    raw_count: usize,
) -> Result<Option<String>, AbuseIpDbError> {
    if family == AbuseIpDbFamily::IpAddresses {
        return Ok(None);
    }
    let data = root.get("data").ok_or(AbuseIpDbError::MalformedResponse)?;
    if let Some(page) = data.get("page").and_then(Value::as_u64)
        && usize::try_from(page).ok() != Some(request.page)
    {
        return Err(AbuseIpDbError::InvalidCursor);
    }
    if let Some(per_page) = data.get("perPage").and_then(Value::as_u64)
        && usize::try_from(per_page).ok() != Some(request.record_limit)
    {
        return Err(AbuseIpDbError::MalformedResponse);
    }
    let has_more = match data.get("lastPage").and_then(Value::as_u64) {
        Some(last) => usize::try_from(last)
            .ok()
            .is_some_and(|last| request.page < last),
        None => raw_count == request.record_limit,
    };
    if !has_more || raw_count == 0 {
        return Ok(None);
    }
    let next = request
        .page
        .checked_add(1)
        .ok_or(AbuseIpDbError::InvalidCursor)?
        .to_string();
    validate_cursor(&next)?;
    if request.cursor.as_deref() == Some(next.as_str()) {
        return Err(AbuseIpDbError::InvalidCursor);
    }
    Ok(Some(next))
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), AbuseIpDbError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(AbuseIpDbError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AbuseIpDbError::AuthenticationRejected),
        403 => Err(AbuseIpDbError::RequiredScopeMissing),
        404 => Err(AbuseIpDbError::ProviderResourceNotFound),
        429 => Err(AbuseIpDbError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(AbuseIpDbError::ProviderUnavailable { status }),
        _ => Err(AbuseIpDbError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AbuseIpDbError> {
    let time = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| AbuseIpDbError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AbuseIpDbError::InvalidProviderRecord)
}
