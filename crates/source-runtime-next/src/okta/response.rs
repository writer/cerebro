//! Bounded Okta response decoding and family dispatch.

use std::collections::HashMap;

use serde_json::Value;
use time::OffsetDateTime;

use super::{
    OktaError, OktaKernel, OktaPage, OktaRequest, OktaResponse, cursor::next_cursor,
    normalize::normalize_record,
};

const MAX_RESPONSE_BYTES: usize = 4 << 20;

impl OktaKernel {
    /// Decode one provider response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &OktaRequest,
        response: OktaResponse<'_>,
        observed_at: OffsetDateTime,
    ) -> Result<OktaPage, OktaError> {
        self.validate_request(request)?;
        classify_status(response.status)?;
        if response.body.len() > MAX_RESPONSE_BYTES {
            return Err(OktaError::ResponseTooLarge);
        }
        let payload: Value =
            serde_json::from_slice(response.body).map_err(|_| OktaError::InvalidResponse)?;
        let raw_records = if self.family.singleton() {
            if !payload.is_object() {
                return Err(OktaError::InvalidResponse);
            }
            vec![payload]
        } else {
            records(payload)?
        };
        if raw_records.len() > self.page_size {
            return Err(OktaError::TooManyRecords);
        }
        let mut seen = HashMap::<String, usize>::new();
        let mut normalized = Vec::with_capacity(raw_records.len());
        for payload in raw_records {
            let record = normalize_record(self, request, payload, observed_at)?;
            if let Some(index) = seen.get(&record.provider_id).copied() {
                if normalized.get(index) != Some(&record) {
                    return Err(OktaError::ConflictingProviderIdentity);
                }
                continue;
            }
            seen.insert(record.provider_id.clone(), normalized.len());
            normalized.push(record);
        }
        let next_cursor = next_cursor(request, &self.base_origin, response.link_header)?;
        let input_after = request
            .url
            .query_pairs()
            .find_map(|(name, value)| (name == "after").then(|| value.into_owned()));
        let input_cursor = input_after.map(|cursor| {
            if request.family == super::OktaFamily::AppAssignment {
                format!(
                    "{}:{cursor}",
                    request.assignment_phase.as_deref().unwrap_or("users")
                )
            } else {
                cursor
            }
        });
        if next_cursor.is_some() && next_cursor == input_cursor {
            return Err(OktaError::InvalidCursor);
        }
        let proposed_checkpoint = normalized.last().map(|record| record.occurred_at.clone());
        Ok(OktaPage {
            records: normalized,
            next_cursor,
            proposed_checkpoint,
        })
    }
}

fn classify_status(status: u16) -> Result<(), OktaError> {
    match status {
        200..=299 => Ok(()),
        401 => Err(OktaError::AuthenticationRejected),
        403 => Err(OktaError::PermissionDenied),
        429 => Err(OktaError::RateLimited),
        500..=599 => Err(OktaError::ProviderUnavailable),
        _ => Err(OktaError::UnexpectedProviderStatus),
    }
}

fn records(payload: Value) -> Result<Vec<Value>, OktaError> {
    match payload {
        Value::Array(records) => Ok(records),
        Value::Object(mut object) => {
            for key in ["data", "items", "results", "records"] {
                if let Some(value) = object.remove(key) {
                    return value.as_array().cloned().ok_or(OktaError::InvalidResponse);
                }
            }
            Err(OktaError::InvalidResponse)
        }
        _ => Err(OktaError::InvalidResponse),
    }
}

#[cfg(test)]
pub(super) const TEST_MAX_RESPONSE_BYTES: usize = MAX_RESPONSE_BYTES;
