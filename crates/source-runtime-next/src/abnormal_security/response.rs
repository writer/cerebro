use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AbnormalSecurityCheckpointCandidate, AbnormalSecurityError, AbnormalSecurityFamily,
    AbnormalSecurityKernel, AbnormalSecurityPage, AbnormalSecurityRequest, normalize,
    request::{validate_cursor, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AbnormalSecurityKernel,
    request: &AbnormalSecurityRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AbnormalSecurityPage, AbnormalSecurityError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AbnormalSecurityError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| AbnormalSecurityError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .and_then(Value::as_array)
        .ok_or(AbnormalSecurityError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(AbnormalSecurityError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| AbnormalSecurityError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AbnormalSecurityError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    let cursor_value = if kernel.family == AbnormalSecurityFamily::PostureCatalog {
        root.pointer("/metadata/next_page")
    } else {
        root.get("nextPageNumber")
    };
    let next_cursor = match cursor_value {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) if value.is_empty() => None,
        Some(value) => value_as_cursor(value)?,
    };
    if next_cursor.is_some() && next_cursor == request.cursor {
        return Err(AbnormalSecurityError::InvalidCursor);
    }
    Ok(AbnormalSecurityPage {
        records,
        next_cursor,
    })
}

fn value_as_cursor(value: &Value) -> Result<Option<String>, AbnormalSecurityError> {
    let cursor = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        _ => return Err(AbnormalSecurityError::InvalidCursor),
    };
    validate_cursor(&cursor)?;
    Ok(Some(cursor))
}

pub(super) fn checkpoint_candidate(
    kernel: &AbnormalSecurityKernel,
    request: &AbnormalSecurityRequest,
    page: &AbnormalSecurityPage,
    prior_watermark: Option<&str>,
) -> Result<AbnormalSecurityCheckpointCandidate, AbnormalSecurityError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AbnormalSecurityError::TenantMismatch);
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
    Ok(AbnormalSecurityCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(status: u16, retry: Option<u64>) -> Result<(), AbnormalSecurityError> {
    if retry.is_some_and(|seconds| seconds > 3_600) {
        return Err(AbnormalSecurityError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AbnormalSecurityError::AuthenticationRejected),
        403 => Err(AbnormalSecurityError::RequiredScopeMissing),
        404 => Err(AbnormalSecurityError::ProviderResourceNotFound),
        429 => Err(AbnormalSecurityError::RateLimited {
            retry_after_seconds: retry,
        }),
        500..=599 => Err(AbnormalSecurityError::ProviderUnavailable { status }),
        _ => Err(AbnormalSecurityError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AbnormalSecurityError> {
    let time = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| AbnormalSecurityError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AbnormalSecurityError::InvalidProviderRecord)
}
