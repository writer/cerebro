use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AkeneoCheckpointCandidate, AkeneoError, AkeneoKernel, AkeneoPage, AkeneoRequest, normalize,
    request::validate_request,
};

pub(super) const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn decode(
    kernel: &AkeneoKernel,
    request: &AkeneoRequest,
    status: u16,
    retry_after_seconds: Option<u64>,
    body: &[u8],
) -> Result<AkeneoPage, AkeneoError> {
    validate_request(kernel, request)?;
    classify_status(status, retry_after_seconds)?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(AkeneoError::ResponseTooLarge);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| AkeneoError::MalformedResponse)?;
    let items = records(kernel, &root)?;
    if items.len() > request.record_limit {
        return Err(AkeneoError::TooManyRecords);
    }

    let mut seen = BTreeMap::<String, Vec<u8>>::new();
    let mut records = Vec::with_capacity(items.len());
    for raw in items {
        let record = normalize::normalize(kernel, raw.clone())?;
        let canonical =
            serde_json::to_vec(&record.payload).map_err(|_| AkeneoError::InvalidProviderRecord)?;
        match seen.get(&record.provider_id) {
            Some(previous) if previous == &canonical => continue,
            Some(_) => return Err(AkeneoError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), canonical);
                records.push(record);
            }
        }
    }
    Ok(AkeneoPage {
        records,
        next_cursor: None,
    })
}

fn records<'a>(kernel: &AkeneoKernel, root: &'a Value) -> Result<Vec<&'a Value>, AkeneoError> {
    if !kernel.family.collection() {
        return root
            .as_object()
            .map(|_| vec![root])
            .ok_or(AkeneoError::MalformedResponse);
    }
    let items = root.as_array().or_else(|| {
        root.get("_embedded")
            .and_then(|embedded| embedded.get("items"))
            .and_then(Value::as_array)
    });
    items
        .map(|items| items.iter().collect())
        .ok_or(AkeneoError::MalformedResponse)
}

pub(super) fn checkpoint_candidate(
    kernel: &AkeneoKernel,
    request: &AkeneoRequest,
    page: &AkeneoPage,
    prior_watermark: Option<&str>,
) -> Result<AkeneoCheckpointCandidate, AkeneoError> {
    validate_request(kernel, request)?;
    if page.next_cursor.is_some() {
        return Err(AkeneoError::InvalidCursor);
    }
    if page
        .records
        .iter()
        .any(|record| record.tenant_id != kernel.tenant_id || record.family != kernel.family)
    {
        return Err(AkeneoError::TenantMismatch);
    }
    let mut watermark = valid_time(prior_watermark.unwrap_or(&kernel.observed_at))?;
    for record in &page.records {
        let occurred_at = valid_time(&record.occurred_at)?;
        if occurred_at > watermark {
            watermark = occurred_at;
        }
    }
    Ok(AkeneoCheckpointCandidate {
        tenant_id: kernel.tenant_id.clone(),
        family: kernel.family,
        cursor: None,
        watermark,
    })
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), AkeneoError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(AkeneoError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(AkeneoError::AuthenticationRejected),
        403 => Err(AkeneoError::RequiredScopeMissing),
        404 => Err(AkeneoError::ProviderResourceNotFound),
        429 => Err(AkeneoError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(AkeneoError::ProviderUnavailable { status }),
        _ => Err(AkeneoError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, AkeneoError> {
    let time =
        OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AkeneoError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AkeneoError::InvalidProviderRecord)
}
