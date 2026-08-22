use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AsanaCheckpointCandidate, AsanaError, AsanaKernel, AsanaPage, AsanaRequest,
    normalize::normalize,
    request::{MAX_RESPONSE_BYTES, validate_cursor},
};

impl AsanaKernel {
    /// Classify status and normalize one provider page.
    pub fn decode_http(
        &self,
        request: &AsanaRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
        observed_at: &str,
    ) -> Result<AsanaPage, AsanaError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(AsanaError::ResponseTooLarge);
        }
        if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
            return Err(AsanaError::InvalidRetryAfter);
        }
        match status {
            200 => {}
            401 => return Err(AsanaError::AuthenticationRejected),
            403 => return Err(AsanaError::RequiredScopeMissing),
            429 => {
                return Err(AsanaError::RateLimited {
                    retry_after_seconds,
                });
            }
            500..=599 => return Err(AsanaError::ProviderUnavailable { status }),
            _ => return Err(AsanaError::UnexpectedStatus { status }),
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| AsanaError::MalformedResponse)?;
        let envelope = value.as_object().ok_or(AsanaError::MalformedResponse)?;
        let records = envelope
            .get("data")
            .and_then(Value::as_array)
            .ok_or(AsanaError::MalformedResponse)?;
        if records.len() > self.page_size {
            return Err(AsanaError::TooManyRecords);
        }
        let mut seen = BTreeMap::<String, Value>::new();
        let mut normalized = Vec::with_capacity(records.len());
        for raw in records {
            let record = normalize(self, raw.clone(), observed_at)?;
            match seen.get(&record.provider_id) {
                Some(previous) if previous == raw => continue,
                Some(_) => return Err(AsanaError::ConflictingDuplicate),
                None => {
                    seen.insert(record.provider_id.clone(), raw.clone());
                    normalized.push(record);
                }
            }
        }
        let next_cursor = match envelope.get("next_page") {
            None | Some(Value::Null) => None,
            Some(Value::Object(page)) => Some(
                page.get("offset")
                    .and_then(Value::as_str)
                    .ok_or(AsanaError::InvalidCursor)
                    .and_then(validate_cursor)?,
            ),
            Some(_) => return Err(AsanaError::InvalidCursor),
        };
        if next_cursor.is_some() && next_cursor == request.cursor {
            return Err(AsanaError::InvalidCursor);
        }
        Ok(AsanaPage {
            records: normalized,
            next_cursor,
        })
    }

    /// Decode a normal HTTP 200 response.
    pub fn decode(
        &self,
        request: &AsanaRequest,
        body: &[u8],
        observed_at: &str,
    ) -> Result<AsanaPage, AsanaError> {
        self.decode_http(request, 200, None, body, observed_at)
    }

    /// Validate a checkpoint candidate for post-append/project persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &AsanaRequest,
        page: &AsanaPage,
        prior_watermark: Option<&str>,
    ) -> Result<AsanaCheckpointCandidate, AsanaError> {
        self.validate_request(request)?;
        if page
            .records
            .iter()
            .any(|record| record.tenant_id != self.tenant_id || record.family != self.family)
        {
            return Err(AsanaError::TenantMismatch);
        }
        if let Some(cursor) = &page.next_cursor {
            self.plan(Some(cursor))?;
        }
        let prior = prior_watermark.map(valid_time).transpose()?;
        let watermark = page
            .records
            .iter()
            .map(|record| record.occurred_at.clone())
            .chain(prior)
            .max();
        Ok(AsanaCheckpointCandidate {
            tenant_id: self.tenant_id.clone(),
            family: self.family,
            cursor: page.next_cursor.clone(),
            watermark,
        })
    }
}

fn valid_time(value: &str) -> Result<String, AsanaError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|time| time.format(&Rfc3339).unwrap_or_else(|_| value.to_owned()))
        .map_err(|_| AsanaError::InvalidProviderRecord)
}
