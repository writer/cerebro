use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    ActivTrakCheckpointCandidate, ActivTrakError, ActivTrakFamily, ActivTrakKernel, ActivTrakPage,
    ActivTrakRequest, normalize,
    request::{validate_offset, validate_opaque, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &ActivTrakKernel,
    request: &ActivTrakRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<ActivTrakPage, ActivTrakError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(ActivTrakError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| ActivTrakError::MalformedResponse)?;
    let items = root
        .get(kernel.family.response_key())
        .or_else(|| {
            matches!(
                kernel.family,
                ActivTrakFamily::Groups | ActivTrakFamily::Users
            )
            .then(|| root.get("Resources"))
            .flatten()
        })
        .and_then(Value::as_array)
        .ok_or(ActivTrakError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(ActivTrakError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| ActivTrakError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(ActivTrakError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    let next_cursor = next_cursor(kernel.family, request, &root, items.len())?;
    if next_cursor.is_some() && next_cursor == request.cursor {
        return Err(ActivTrakError::InvalidCursor);
    }
    Ok(ActivTrakPage {
        records,
        next_cursor,
    })
}

fn next_cursor(
    family: ActivTrakFamily,
    request: &ActivTrakRequest,
    root: &Value,
    count: usize,
) -> Result<Option<String>, ActivTrakError> {
    match family {
        ActivTrakFamily::Groups | ActivTrakFamily::Users => {
            if count < request.page_size {
                return Ok(None);
            }
            let next = request
                .offset
                .and_then(|offset| offset.checked_add(count))
                .ok_or(ActivTrakError::InvalidCursor)?;
            validate_offset(&next.to_string())?;
            Ok(Some(next.to_string()))
        }
        ActivTrakFamily::ActivityLog => match root.get("cursor") {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) if value.is_empty() => Ok(None),
            Some(Value::String(value)) => Ok(Some(validate_opaque(value)?.to_owned())),
            Some(_) => Err(ActivTrakError::InvalidCursor),
        },
        ActivTrakFamily::Clients | ActivTrakFamily::Consumers => Ok(None),
    }
}

pub(super) fn checkpoint_candidate(
    kernel: &ActivTrakKernel,
    request: &ActivTrakRequest,
    page: &ActivTrakPage,
    prior_watermark: Option<&str>,
) -> Result<ActivTrakCheckpointCandidate, ActivTrakError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(ActivTrakError::TenantMismatch);
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
    Ok(ActivTrakCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn classify_status(status: u16, retry: Option<u64>) -> Result<(), ActivTrakError> {
    if retry.is_some_and(|seconds| seconds > 3_600) {
        return Err(ActivTrakError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(ActivTrakError::AuthenticationRejected),
        403 => Err(ActivTrakError::RequiredScopeMissing),
        404 => Err(ActivTrakError::ProviderResourceNotFound),
        429 => Err(ActivTrakError::RateLimited {
            retry_after_seconds: retry,
        }),
        500..=599 => Err(ActivTrakError::ProviderUnavailable { status }),
        _ => Err(ActivTrakError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, ActivTrakError> {
    let time = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| ActivTrakError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| ActivTrakError::InvalidProviderRecord)
}
