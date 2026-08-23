use std::collections::BTreeMap;

use serde_json::Value;

use super::{
    DigitalOceanCheckpointCandidate, DigitalOceanError, DigitalOceanKernel, DigitalOceanOperation,
    DigitalOceanPage, DigitalOceanRecord, DigitalOceanRequest,
    normalize::normalize_record,
    request::{next_page, validate_request},
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &DigitalOceanKernel,
    request: &DigitalOceanRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<DigitalOceanPage, DigitalOceanError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(DigitalOceanError::ResponseTooLarge);
    }
    let root: Value =
        serde_json::from_slice(body).map_err(|_| DigitalOceanError::MalformedResponse)?;
    let object = root
        .as_object()
        .ok_or(DigitalOceanError::MalformedResponse)?;
    let items = object
        .get(kernel.family.as_str())
        .and_then(Value::as_array)
        .ok_or(DigitalOceanError::MalformedResponse)?;
    if items.len() > request.page_size {
        return Err(DigitalOceanError::TooManyRecords);
    }
    let mut records = Vec::<DigitalOceanRecord>::with_capacity(items.len());
    let mut seen = BTreeMap::<String, usize>::new();
    for value in items {
        let record = normalize_record(kernel, value)?;
        if let Some(index) = seen.get(&record.provider_id).copied() {
            if records.get(index) != Some(&record) {
                return Err(DigitalOceanError::ConflictingDuplicate);
            }
            continue;
        }
        seen.insert(record.provider_id.clone(), records.len());
        records.push(record);
    }
    let next_cursor = if has_next_link(object)? {
        Some(next_page(request.page)?)
    } else {
        None
    };
    Ok(DigitalOceanPage {
        records,
        next_cursor,
    })
}

pub(super) fn checkpoint_candidate(
    kernel: &DigitalOceanKernel,
    request: &DigitalOceanRequest,
    page: &DigitalOceanPage,
    prior_watermark: Option<&str>,
) -> Result<DigitalOceanCheckpointCandidate, DigitalOceanError> {
    validate_request(kernel, request)?;
    if request.operation != DigitalOceanOperation::Read {
        return Err(DigitalOceanError::RequestScopeMismatch);
    }
    if let Some(cursor) = page.next_cursor.as_deref() {
        super::request::validate_cursor(cursor)?;
    }
    let watermark = if page.records.is_empty() {
        prior_watermark.unwrap_or(&kernel.observed_at)
    } else {
        &kernel.observed_at
    };
    Ok(DigitalOceanCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: page.next_cursor.clone(),
        watermark: watermark.to_owned(),
    })
}

fn has_next_link(object: &serde_json::Map<String, Value>) -> Result<bool, DigitalOceanError> {
    let Some(links) = object.get("links") else {
        return Ok(false);
    };
    let links = links
        .as_object()
        .ok_or(DigitalOceanError::MalformedResponse)?;
    let Some(pages) = links.get("pages") else {
        return Ok(false);
    };
    let pages = pages
        .as_object()
        .ok_or(DigitalOceanError::MalformedResponse)?;
    let Some(next) = pages.get("next") else {
        return Ok(false);
    };
    next.as_str()
        .map(|value| !value.is_empty())
        .ok_or(DigitalOceanError::MalformedResponse)
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), DigitalOceanError> {
    match status {
        200 => Ok(()),
        401 => Err(DigitalOceanError::AuthenticationRejected),
        403 => Err(DigitalOceanError::RequiredScopeMissing),
        429 => Err(DigitalOceanError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(DigitalOceanError::ProviderUnavailable { status }),
        _ => Err(DigitalOceanError::UnexpectedStatus { status }),
    }
}
