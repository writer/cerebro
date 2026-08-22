use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    ActiveCampaignCheckpointCandidate, ActiveCampaignError, ActiveCampaignKernel,
    ActiveCampaignPage, ActiveCampaignRequest, normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &ActiveCampaignKernel,
    request: &ActiveCampaignRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<ActiveCampaignPage, ActiveCampaignError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ActiveCampaignError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| ActiveCampaignError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .and_then(Value::as_array)
        .ok_or(ActiveCampaignError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(ActiveCampaignError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut normalized = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| ActiveCampaignError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(ActiveCampaignError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                normalized.push(record);
            }
        }
    }
    let candidate = request
        .offset
        .checked_add(items.len())
        .ok_or(ActiveCampaignError::InvalidCursor)?;
    let total = root
        .get("meta")
        .and_then(|value| value.get("total"))
        .and_then(integer)
        .and_then(|value| usize::try_from(value).ok());
    let has_more = total.map_or(items.len() == request.page_size, |total| candidate < total);
    let next_cursor = (has_more && !items.is_empty()).then(|| candidate.to_string());
    if let Some(cursor) = &next_cursor {
        validate_cursor(cursor)?;
    }
    if next_cursor.is_some() && next_cursor == request.cursor {
        return Err(ActiveCampaignError::InvalidCursor);
    }
    Ok(ActiveCampaignPage {
        records: normalized,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &ActiveCampaignKernel,
    request: &ActiveCampaignRequest,
    page: &ActiveCampaignPage,
    prior_watermark: Option<&str>,
) -> Result<ActiveCampaignCheckpointCandidate, ActiveCampaignError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(ActiveCampaignError::TenantMismatch);
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
    Ok(ActiveCampaignCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(
    status: u16,
    retry_after_seconds: Option<u64>,
) -> Result<(), ActiveCampaignError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(ActiveCampaignError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(ActiveCampaignError::AuthenticationRejected),
        403 => Err(ActiveCampaignError::RequiredScopeMissing),
        404 => Err(ActiveCampaignError::ProviderResourceNotFound),
        429 => Err(ActiveCampaignError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(ActiveCampaignError::ProviderUnavailable { status }),
        _ => Err(ActiveCampaignError::UnexpectedStatus { status }),
    }
}

fn integer(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
}

fn valid_time(value: &str) -> Result<String, ActiveCampaignError> {
    let time = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ActiveCampaignError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| ActiveCampaignError::InvalidProviderRecord)
}
