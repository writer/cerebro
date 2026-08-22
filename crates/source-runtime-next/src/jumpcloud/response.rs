use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    JumpCloudCheckpointCandidate, JumpCloudError, JumpCloudFamily, JumpCloudKernel, JumpCloudPage,
    JumpCloudRequest, JumpCloudResponseMetadata, normalize,
    request::{validate_audit_cursor, validate_offset, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &JumpCloudKernel,
    request: &JumpCloudRequest,
    status: u16,
    metadata: &JumpCloudResponseMetadata,
    body: &[u8],
) -> Result<JumpCloudPage, JumpCloudError> {
    validate_request(kernel, request)?;
    classify_status(status, metadata.retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(JumpCloudError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| JumpCloudError::MalformedResponse)?;
    let items = records(kernel.family, &root)?;
    if items.len() > request.page_size {
        return Err(JumpCloudError::TooManyRecords);
    }
    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut normalized = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical = serde_json::to_vec(&record.payload)
            .map_err(|_| JumpCloudError::InvalidProviderRecord)?;
        match seen.get(&record.event_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(JumpCloudError::ConflictingDuplicate),
            None => {
                seen.insert(record.event_id.clone(), canonical);
                normalized.push(record);
            }
        }
    }
    let next_cursor = next_cursor(kernel.family, request, metadata, &root, items.len())?;
    Ok(JumpCloudPage {
        records: normalized,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &JumpCloudKernel,
    request: &JumpCloudRequest,
    page: &JumpCloudPage,
    prior_watermark: Option<&str>,
) -> Result<JumpCloudCheckpointCandidate, JumpCloudError> {
    validate_request(kernel, request)?;
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(JumpCloudError::TenantMismatch);
    }
    if let Some(cursor) = &page.next_cursor {
        kernel.plan(Some(cursor))?;
    }
    let prior = prior_watermark.map(valid_time).transpose()?;
    let watermark = page
        .records
        .iter()
        .map(|record| record.occurred_at.clone())
        .chain(prior)
        .max();
    Ok(JumpCloudCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark,
    })
}

fn records(family: JumpCloudFamily, root: &Value) -> Result<&[Value], JumpCloudError> {
    match family {
        JumpCloudFamily::Users | JumpCloudFamily::Systems | JumpCloudFamily::Applications => root
            .get("results")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .ok_or(JumpCloudError::MalformedResponse),
        JumpCloudFamily::Groups
        | JumpCloudFamily::SystemGroups
        | JumpCloudFamily::GroupMembers
        | JumpCloudFamily::AuditEvents => root
            .as_array()
            .map(Vec::as_slice)
            .ok_or(JumpCloudError::MalformedResponse),
    }
}

fn next_cursor(
    family: JumpCloudFamily,
    request: &JumpCloudRequest,
    metadata: &JumpCloudResponseMetadata,
    root: &Value,
    raw_count: usize,
) -> Result<Option<String>, JumpCloudError> {
    let next = if family == JumpCloudFamily::AuditEvents {
        let limit = metadata.limit.unwrap_or(request.page_size);
        match (metadata.result_count, metadata.search_after.as_deref()) {
            (Some(count), Some(cursor)) if limit > 0 && count >= limit => {
                Some(validate_audit_cursor(cursor)?)
            }
            _ => None,
        }
    } else {
        let offset = request
            .cursor
            .as_deref()
            .map(validate_offset)
            .transpose()?
            .unwrap_or(0);
        let candidate = offset
            .checked_add(raw_count)
            .ok_or(JumpCloudError::InvalidCursor)?;
        let total = root
            .get("totalCount")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok());
        let more = total.map_or(raw_count == request.page_size, |total| candidate < total);
        (more && raw_count > 0).then(|| candidate.to_string())
    };
    if next.is_some() && next == request.cursor {
        return Err(JumpCloudError::InvalidCursor);
    }
    Ok(next)
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), JumpCloudError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(JumpCloudError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(JumpCloudError::AuthenticationRejected),
        403 => Err(JumpCloudError::RequiredScopeMissing),
        429 => Err(JumpCloudError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(JumpCloudError::ProviderUnavailable { status }),
        _ => Err(JumpCloudError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, JumpCloudError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|time| time.format(&Rfc3339).unwrap_or_else(|_| value.to_owned()))
        .map_err(|_| JumpCloudError::InvalidProviderRecord)
}
