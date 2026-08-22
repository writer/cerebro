//! Bounded PagerDuty response decoding and progress calculation.

use std::collections::HashMap;

use serde_json::Value;
use time::OffsetDateTime;

use super::{
    PagerDutyError, PagerDutyFamily, PagerDutyKernel, PagerDutyPage, PagerDutyRequest,
    cursor::encode_fanout_cursor,
    normalize::normalize_record,
    request::{MAX_RECORDS_PER_PAGE, MAX_RESPONSE_BYTES},
};

impl PagerDutyKernel {
    /// Decode one trusted-host response and return normalized records plus proposed progress.
    pub fn decode(
        &self,
        request: &PagerDutyRequest,
        status_code: u16,
        body: &[u8],
        observed_at: OffsetDateTime,
    ) -> Result<PagerDutyPage, PagerDutyError> {
        self.validate_request(request)?;
        classify_status(status_code)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(PagerDutyError::ResponseTooLarge);
        }
        let envelope: Value =
            serde_json::from_slice(body).map_err(|_| PagerDutyError::MalformedResponse)?;
        let object = envelope
            .as_object()
            .ok_or(PagerDutyError::MalformedResponse)?;
        let raw_records = object
            .get(self.family.response_key())
            .and_then(Value::as_array)
            .ok_or(PagerDutyError::MalformedResponse)?;
        if raw_records.len() > MAX_RECORDS_PER_PAGE || raw_records.len() > self.page_size {
            return Err(PagerDutyError::TooManyRecords);
        }
        let mut seen = HashMap::<String, usize>::new();
        let mut records: Vec<super::PagerDutyRecord> = Vec::with_capacity(raw_records.len());
        for payload in raw_records {
            let record = normalize_record(
                self.family,
                &self.tenant_id,
                &self.origin,
                request.url.path(),
                request.service_id.as_deref(),
                payload.clone(),
                observed_at,
            )?;
            if let Some(index) = seen.get(&record.provider_id).copied() {
                if records.get(index) != Some(&record) {
                    return Err(PagerDutyError::ConflictingProviderIdentity);
                }
                continue;
            }
            seen.insert(record.provider_id.clone(), records.len());
            records.push(record);
        }
        let provider_next = provider_next_offset(object, request)?;
        let next_cursor = self.next_cursor(request, provider_next)?;
        let checkpoint_cursor = if records.is_empty() {
            None
        } else {
            provider_next
                .map(|offset| offset.to_string())
                .or_else(|| records.last().map(|record| record.provider_id.clone()))
        };
        Ok(PagerDutyPage {
            records,
            next_cursor,
            checkpoint_cursor,
        })
    }

    fn next_cursor(
        &self,
        request: &PagerDutyRequest,
        provider_next: Option<u64>,
    ) -> Result<Option<String>, PagerDutyError> {
        if self.family != PagerDutyFamily::Integration {
            return Ok(provider_next.map(|offset| offset.to_string()));
        }
        if let Some(offset) = provider_next {
            return encode_fanout_cursor(request.cursor.service_index, Some(offset)).map(Some);
        }
        let next_index = request.cursor.service_index + 1;
        if next_index < self.service_ids.len() {
            return encode_fanout_cursor(next_index, None).map(Some);
        }
        Ok(None)
    }
}

fn provider_next_offset(
    object: &serde_json::Map<String, Value>,
    request: &PagerDutyRequest,
) -> Result<Option<u64>, PagerDutyError> {
    let more = match object.get("more") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(value)) => value.as_u64() == Some(1),
        Some(Value::String(value)) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes"
        ),
        _ => return Err(PagerDutyError::MalformedResponse),
    };
    if !more {
        return Ok(None);
    }
    let offset = unsigned(object.get("offset")).ok_or(PagerDutyError::MalformedResponse)?;
    let limit = unsigned(object.get("limit")).ok_or(PagerDutyError::MalformedResponse)?;
    if limit == 0 || limit > MAX_RECORDS_PER_PAGE as u64 {
        return Err(PagerDutyError::MalformedResponse);
    }
    if request.cursor.offset.unwrap_or(0) != offset {
        return Err(PagerDutyError::InvalidCursor);
    }
    offset
        .checked_add(limit)
        .map(Some)
        .ok_or(PagerDutyError::InvalidCursor)
}

fn unsigned(value: Option<&Value>) -> Option<u64> {
    match value? {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.trim().parse().ok(),
        _ => None,
    }
}

fn classify_status(status: u16) -> Result<(), PagerDutyError> {
    match status {
        200 => Ok(()),
        401 => Err(PagerDutyError::AuthenticationRejected),
        403 => Err(PagerDutyError::PermissionDenied),
        429 => Err(PagerDutyError::RateLimited),
        500..=599 => Err(PagerDutyError::ProviderUnavailable),
        _ => Err(PagerDutyError::UnexpectedProviderStatus),
    }
}
