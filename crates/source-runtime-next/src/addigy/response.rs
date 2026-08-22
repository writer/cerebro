use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AddigyCheckpointCandidate, AddigyError, AddigyKernel, AddigyPage, AddigyRequest, normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AddigyKernel,
    request: &AddigyRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AddigyPage, AddigyError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AddigyError::ResponseTooLarge);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| AddigyError::MalformedResponse)?;
    let items = if kernel.family.root_array() {
        root.as_array().ok_or(AddigyError::MalformedResponse)?
    } else {
        root.get("items")
            .and_then(Value::as_array)
            .ok_or(AddigyError::MalformedResponse)?
    };
    if items.len() > request.page_size {
        return Err(AddigyError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical =
            serde_json::to_vec(&record.payload).map_err(|_| AddigyError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AddigyError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    let next_cursor = if kernel.family.paginated() && items.len() == request.page_size {
        let reported_page = root
            .get("metadata")
            .and_then(|metadata| metadata.get("page"))
            .and_then(integer)
            .ok_or(AddigyError::InvalidCursor)?;
        if reported_page != u64::from(request.page) {
            return Err(AddigyError::InvalidCursor);
        }
        let next = request
            .page
            .checked_add(1)
            .ok_or(AddigyError::InvalidCursor)?
            .to_string();
        validate_cursor(&next)?;
        Some(next)
    } else {
        None
    };
    Ok(AddigyPage {
        records,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &AddigyKernel,
    request: &AddigyRequest,
    page: &AddigyPage,
    prior_watermark: Option<&str>,
) -> Result<AddigyCheckpointCandidate, AddigyError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AddigyError::TenantMismatch);
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
    Ok(AddigyCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), AddigyError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(AddigyError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AddigyError::AuthenticationRejected),
        403 => Err(AddigyError::RequiredScopeMissing),
        404 => Err(AddigyError::ProviderResourceNotFound),
        429 => Err(AddigyError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(AddigyError::ProviderUnavailable { status }),
        _ => Err(AddigyError::UnexpectedStatus { status }),
    }
}

fn integer(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
}

fn valid_time(value: &str) -> Result<String, AddigyError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AddigyError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AddigyError::InvalidProviderRecord)
}
