use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    DeepSeekCheckpointCandidate, DeepSeekError, DeepSeekKernel, DeepSeekPage, DeepSeekRequest,
    normalize::normalize, request::MAX_RESPONSE_BYTES,
};

const MAX_RECORDS: usize = 1_000;

impl DeepSeekKernel {
    /// Classify status and normalize one provider response.
    pub fn decode_http(
        &self,
        request: &DeepSeekRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
        observed_at: &str,
    ) -> Result<DeepSeekPage, DeepSeekError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DeepSeekError::ResponseTooLarge);
        }
        if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
            return Err(DeepSeekError::InvalidRetryAfter);
        }
        match status {
            200 => {}
            401 => return Err(DeepSeekError::AuthenticationRejected),
            402 => return Err(DeepSeekError::InsufficientBalance),
            403 => return Err(DeepSeekError::RequiredScopeMissing),
            429 => {
                return Err(DeepSeekError::RateLimited {
                    retry_after_seconds,
                });
            }
            500..=599 => return Err(DeepSeekError::ProviderUnavailable { status }),
            _ => return Err(DeepSeekError::UnexpectedStatus { status }),
        }
        let value: Value =
            serde_json::from_slice(body).map_err(|_| DeepSeekError::MalformedResponse)?;
        let records = value
            .as_object()
            .and_then(|object| object.get(self.family.list_key()))
            .and_then(Value::as_array)
            .ok_or(DeepSeekError::MalformedResponse)?;
        if records.len() > MAX_RECORDS {
            return Err(DeepSeekError::TooManyRecords);
        }
        let mut seen = BTreeMap::<String, Value>::new();
        let mut normalized = Vec::with_capacity(records.len());
        for raw in records {
            let record = normalize(self, raw.clone(), observed_at)?;
            match seen.get(&record.provider_id) {
                Some(previous) if previous == raw => continue,
                Some(_) => return Err(DeepSeekError::ConflictingDuplicate),
                None => {
                    seen.insert(record.provider_id.clone(), raw.clone());
                    normalized.push(record);
                }
            }
        }
        Ok(DeepSeekPage {
            records: normalized,
            next_cursor: None,
        })
    }

    /// Decode a normal HTTP 200 response.
    pub fn decode(
        &self,
        request: &DeepSeekRequest,
        body: &[u8],
        observed_at: &str,
    ) -> Result<DeepSeekPage, DeepSeekError> {
        self.decode_http(request, 200, None, body, observed_at)
    }

    /// Validate a terminal checkpoint candidate for post-projection persistence.
    pub fn checkpoint_candidate(
        &self,
        request: &DeepSeekRequest,
        page: &DeepSeekPage,
        prior_watermark: Option<&str>,
    ) -> Result<DeepSeekCheckpointCandidate, DeepSeekError> {
        self.validate_request(request)?;
        if page.next_cursor.is_some() {
            return Err(DeepSeekError::InvalidCursor);
        }
        if page
            .records
            .iter()
            .any(|record| record.tenant_id != self.tenant_id || record.family != self.family)
        {
            return Err(DeepSeekError::TenantMismatch);
        }
        let prior = prior_watermark.map(valid_time).transpose()?;
        let watermark = page
            .records
            .iter()
            .map(|record| record.occurred_at.clone())
            .chain(prior)
            .max();
        Ok(DeepSeekCheckpointCandidate {
            tenant_id: self.tenant_id.clone(),
            family: self.family,
            cursor: None,
            watermark,
        })
    }
}

fn valid_time(value: &str) -> Result<String, DeepSeekError> {
    OffsetDateTime::parse(value, &Rfc3339)
        .map(|time| time.format(&Rfc3339).unwrap_or_else(|_| value.to_owned()))
        .map_err(|_| DeepSeekError::InvalidObservedAt)
}
