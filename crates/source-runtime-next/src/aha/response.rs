use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AhaCheckpointCandidate, AhaError, AhaKernel, AhaPage, AhaRequest, normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AhaKernel,
    request: &AhaRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AhaPage, AhaError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AhaError::ResponseTooLarge);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| AhaError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .and_then(Value::as_array)
        .ok_or(AhaError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(AhaError::TooManyRecords);
    }

    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical =
            serde_json::to_vec(&record.payload).map_err(|_| AhaError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AhaError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }

    let next_cursor = if items.len() == request.page_size {
        let next = request
            .page
            .checked_add(1)
            .ok_or(AhaError::InvalidCursor)?
            .to_string();
        validate_cursor(&next)?;
        Some(next)
    } else {
        None
    };
    Ok(AhaPage {
        records,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &AhaKernel,
    request: &AhaRequest,
    page: &AhaPage,
    prior_watermark: Option<&str>,
) -> Result<AhaCheckpointCandidate, AhaError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AhaError::TenantMismatch);
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
    Ok(AhaCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), AhaError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(AhaError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AhaError::AuthenticationRejected),
        403 => Err(AhaError::RequiredScopeMissing),
        404 => Err(AhaError::ProviderResourceNotFound),
        429 => Err(AhaError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(AhaError::ProviderUnavailable { status }),
        _ => Err(AhaError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AhaError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AhaError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AhaError::InvalidProviderRecord)
}
