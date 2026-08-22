//! Bounded Linode managed-issue response decoding.

use std::collections::HashMap;

use time::OffsetDateTime;

use super::{
    LinodeError, LinodeKernel, LinodePage, LinodeRecord, LinodeRequest, cursor::next_cursor,
    normalize::normalize_issue, wire::IssuePageWire,
};

const MAX_RESPONSE_BYTES: usize = 8 << 20;
const MAX_RECORDS_PER_PAGE: usize = 500;

impl LinodeKernel {
    /// Decode one provider response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &LinodeRequest,
        body: &[u8],
        observed_at: OffsetDateTime,
    ) -> Result<LinodePage, LinodeError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(LinodeError::ResponseTooLarge);
        }
        let response: IssuePageWire =
            serde_json::from_slice(body).map_err(|_| LinodeError::InvalidResponse)?;
        if response.page != request.page {
            return Err(LinodeError::ResponsePageMismatch);
        }
        if response.data.len() > MAX_RECORDS_PER_PAGE || response.data.len() > self.page_size {
            return Err(LinodeError::TooManyRecords);
        }
        if response.results < response.data.len() as u64 {
            return Err(LinodeError::InvalidResponse);
        }
        let continuation = next_cursor(response.page, response.pages)?;
        let mut seen = HashMap::new();
        let mut records: Vec<LinodeRecord> = Vec::with_capacity(response.data.len());
        for payload in response.data {
            if !payload.is_object() {
                return Err(LinodeError::InvalidResponse);
            }
            let record = normalize_issue(payload, &self.tenant_id, &self.scope_base, observed_at)?;
            if let Some(index) = seen.get(&record.provider_id).copied() {
                if records.get(index) != Some(&record) {
                    return Err(LinodeError::ConflictingProviderIdentity);
                }
                continue;
            }
            seen.insert(record.provider_id.clone(), records.len());
            records.push(record);
        }
        Ok(LinodePage {
            records,
            next_cursor: continuation,
            total_results: response.results,
        })
    }
}
