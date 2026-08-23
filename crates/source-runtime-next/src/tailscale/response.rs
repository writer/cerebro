use std::collections::BTreeMap;

use serde_json::Value;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    TailscaleCheckpointCandidate, TailscaleError, TailscaleKernel, TailscalePage, TailscaleRequest,
    TailscaleResponseMetadata,
    normalize::{canonical_bytes, normalize, records},
    request::{MAX_RESPONSE_BYTES, validate_cursor},
};

impl TailscaleKernel {
    /// Classify one status and normalize a bounded provider response.
    pub fn decode_http(
        &self,
        request: &TailscaleRequest,
        status: u16,
        metadata: &TailscaleResponseMetadata,
        body: &[u8],
    ) -> Result<TailscalePage, TailscaleError> {
        self.validate_request(request)?;
        classify_status(status, metadata.retry_after_seconds)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TailscaleError::ResponseTooLarge);
        }
        let root: Value =
            serde_json::from_slice(body).map_err(|_| TailscaleError::MalformedResponse)?;
        let raw_records = records(self.family, &root, &self.tailnet)?;
        if raw_records.len() > request.page_size {
            return Err(TailscaleError::TooManyRecords);
        }
        let mut seen = BTreeMap::<String, Vec<u8>>::new();
        let mut normalized = Vec::with_capacity(raw_records.len());
        for raw in raw_records {
            let record = normalize(self, raw)?;
            let canonical = canonical_bytes(&record.payload)?;
            match seen.get(&record.event_id) {
                Some(previous) if previous == &canonical => continue,
                Some(_) => return Err(TailscaleError::ConflictingDuplicate),
                None => {
                    seen.insert(record.event_id.clone(), canonical);
                    normalized.push(record);
                }
            }
        }
        let next_cursor = next_cursor(request, metadata, &root)?;
        Ok(TailscalePage {
            records: normalized,
            next_cursor,
        })
    }

    /// Validate a checkpoint proposal for persistence after append and projection.
    pub fn checkpoint_candidate(
        &self,
        request: &TailscaleRequest,
        page: &TailscalePage,
        prior_watermark: Option<&str>,
    ) -> Result<TailscaleCheckpointCandidate, TailscaleError> {
        self.validate_request(request)?;
        if page
            .records
            .iter()
            .any(|record| record.tenant_id != self.tenant_id || record.family != self.family)
        {
            return Err(TailscaleError::TenantMismatch);
        }
        let cursor = page
            .next_cursor
            .clone()
            .or_else(|| {
                page.records
                    .last()
                    .and_then(|record| record.attributes.get("external_id"))
                    .cloned()
            })
            .map(|cursor| validate_cursor(&cursor))
            .transpose()?;
        if let Some(cursor) = &cursor {
            self.plan(Some(cursor))?;
        }
        let prior = prior_watermark.map(valid_time).transpose()?;
        let watermark = page
            .records
            .last()
            .map(|record| record.occurred_at.clone())
            .or(prior);
        Ok(TailscaleCheckpointCandidate {
            tenant_id: self.tenant_id.clone(),
            family: self.family,
            cursor,
            watermark,
        })
    }
}

fn next_cursor(
    request: &TailscaleRequest,
    metadata: &TailscaleResponseMetadata,
    root: &Value,
) -> Result<Option<String>, TailscaleError> {
    let body_cursor = ["nextCursor", "next_cursor", "cursor", "next"]
        .into_iter()
        .find_map(|key| root.get(key).and_then(Value::as_str));
    let next = metadata
        .next_cursor
        .as_deref()
        .or(body_cursor)
        .map(validate_cursor)
        .transpose()?;
    if next.is_some() && next == request.cursor {
        return Err(TailscaleError::InvalidCursor);
    }
    Ok(next)
}

fn classify_status(status: u16, retry_after_seconds: Option<u64>) -> Result<(), TailscaleError> {
    if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
        return Err(TailscaleError::InvalidRetryAfter);
    }
    match status {
        200..=299 => Ok(()),
        401 => Err(TailscaleError::AuthenticationRejected),
        403 => Err(TailscaleError::RequiredScopeMissing),
        429 => Err(TailscaleError::RateLimited {
            retry_after_seconds,
        }),
        500..=599 => Err(TailscaleError::ProviderUnavailable { status }),
        _ => Err(TailscaleError::UnexpectedStatus { status }),
    }
}

fn valid_time(value: &str) -> Result<String, TailscaleError> {
    let time = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| TailscaleError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| TailscaleError::InvalidProviderRecord)
}
