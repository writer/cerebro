//! Bounded Twilio response decoding and family dispatch.

use std::collections::HashSet;

use serde_json::Value;
use time::OffsetDateTime;

use super::{
    TwilioError, TwilioFamily, TwilioKernel, TwilioPage, TwilioRecord, TwilioRequest,
    cursor::{bounded_cursor, response_cursor},
    family::{accounts, audit_events, keys},
};

const MAX_RESPONSE_BYTES: usize = 8 << 20;
const MAX_RECORDS_PER_PAGE: usize = 500;

impl TwilioKernel {
    /// Decode one provider response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &TwilioRequest,
        body: &[u8],
        observed_at: OffsetDateTime,
    ) -> Result<TwilioPage, TwilioError> {
        self.validate_request(request)?;
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(TwilioError::ResponseTooLarge);
        }
        let payload: Value =
            serde_json::from_slice(body).map_err(|_| TwilioError::InvalidResponse)?;
        let (raw_records, next_cursor) = match payload {
            Value::Array(records) => (records, None),
            Value::Object(object) => {
                let records = self.records_from_object(&object)?;
                let cursor = response_cursor(&object)?;
                (records, cursor)
            }
            _ => return Err(TwilioError::InvalidResponse),
        };
        if raw_records.len() > MAX_RECORDS_PER_PAGE {
            return Err(TwilioError::TooManyRecords);
        }
        let path = request.url.path();
        let mut seen = HashSet::new();
        let mut records = Vec::with_capacity(raw_records.len());
        for payload in raw_records {
            if !payload.is_object() {
                return Err(TwilioError::InvalidResponse);
            }
            let record = self.normalize_record(payload, path, observed_at)?;
            if seen.insert(record.provider_id.clone()) {
                records.push(record);
            }
        }
        Ok(TwilioPage {
            records,
            next_cursor: bounded_cursor(next_cursor.as_deref())?,
        })
    }

    fn records_from_object(
        &self,
        object: &serde_json::Map<String, Value>,
    ) -> Result<Vec<Value>, TwilioError> {
        for key in self.family.response_keys() {
            let Some(value) = object.get(*key) else {
                continue;
            };
            return match value {
                Value::Array(records) => Ok(records.clone()),
                _ => Err(TwilioError::InvalidResponse),
            };
        }
        Err(TwilioError::InvalidResponse)
    }

    fn normalize_record(
        &self,
        payload: Value,
        path: &str,
        observed_at: OffsetDateTime,
    ) -> Result<TwilioRecord, TwilioError> {
        match self.family {
            TwilioFamily::Accounts => accounts::normalize(
                payload,
                &self.tenant_id,
                &self.base_origin,
                path,
                observed_at,
            ),
            TwilioFamily::Keys => keys::normalize(
                payload,
                &self.tenant_id,
                &self.base_origin,
                path,
                observed_at,
            ),
            TwilioFamily::AuditEvents => audit_events::normalize(
                payload,
                &self.tenant_id,
                &self.base_origin,
                path,
                observed_at,
            ),
        }
    }
}

#[cfg(test)]
pub(super) const TEST_MAX_RESPONSE_BYTES: usize = MAX_RESPONSE_BYTES;

#[cfg(test)]
pub(super) const TEST_MAX_RECORDS_PER_PAGE: usize = MAX_RECORDS_PER_PAGE;
