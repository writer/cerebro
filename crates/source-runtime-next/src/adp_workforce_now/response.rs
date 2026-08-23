use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AdpCheckpointCandidate, AdpError, AdpFamily, AdpKernel, AdpPage, AdpRequest, normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AdpKernel,
    request: &AdpRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AdpPage, AdpError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AdpError::ResponseTooLarge);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| AdpError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .and_then(Value::as_array)
        .ok_or(AdpError::MalformedResponse)?;
    if items.len() > request.record_limit {
        return Err(AdpError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical =
            serde_json::to_vec(&record.payload).map_err(|_| AdpError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AdpError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    let next_cursor = if kernel.family == AdpFamily::Users && items.len() == request.record_limit {
        let next = request
            .offset
            .checked_add(items.len())
            .ok_or(AdpError::InvalidCursor)?
            .to_string();
        validate_cursor(&next)?;
        Some(next)
    } else {
        None
    };
    Ok(AdpPage {
        records,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &AdpKernel,
    request: &AdpRequest,
    page: &AdpPage,
    prior_watermark: Option<&str>,
) -> Result<AdpCheckpointCandidate, AdpError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AdpError::TenantMismatch);
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
    Ok(AdpCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), AdpError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(AdpError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AdpError::AuthenticationRejected),
        403 => Err(AdpError::RequiredScopeMissing),
        404 => Err(AdpError::ProviderResourceNotFound),
        429 => Err(AdpError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(AdpError::ProviderUnavailable { status }),
        _ => Err(AdpError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AdpError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AdpError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AdpError::InvalidProviderRecord)
}
