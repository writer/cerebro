use std::collections::BTreeMap;

use super::{
    DiscordError, DiscordFamily, DiscordKernel, DiscordPage, DiscordRecord, DiscordRequest,
    cursor::{highest_provider_id, validate_ascending_page},
    normalize::{normalize_record, strict_string_at},
    wire::{MAX_NONPAGED_RECORDS, MAX_RESPONSE_BYTES, decode_records},
};

impl DiscordKernel {
    /// Classify the provider status and decode a bounded response body.
    ///
    /// The trusted host owns network I/O, credentials, redirects, deadlines,
    /// DNS/egress checks, and response buffering. It passes only the status,
    /// bounded Retry-After value, and bounded body to this portable kernel.
    pub fn decode_http(
        &self,
        request: &DiscordRequest,
        status: u16,
        retry_after_seconds: Option<u64>,
        body: &[u8],
    ) -> Result<DiscordPage, DiscordError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DiscordError::ResponseTooLarge);
        }
        if request.family != self.family || request != &self.plan(request.cursor.as_deref())? {
            return Err(DiscordError::RequestScopeMismatch);
        }
        if retry_after_seconds.is_some_and(|seconds| seconds > 3_600) {
            return Err(DiscordError::InvalidRetryAfter);
        }
        match status {
            200 => self.decode_success(request, body),
            401 => Err(DiscordError::AuthenticationRejected),
            403 if self.family == DiscordFamily::AuditLog => {
                Err(DiscordError::RequiredScopeMissing)
            }
            403 => Err(DiscordError::UnexpectedStatus { status }),
            429 => Err(DiscordError::RateLimited {
                retry_after_seconds,
            }),
            500..=599 => Err(DiscordError::ProviderUnavailable { status }),
            _ => Err(DiscordError::UnexpectedStatus { status }),
        }
    }

    /// Decode and normalize a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &DiscordRequest,
        body: &[u8],
    ) -> Result<DiscordPage, DiscordError> {
        self.decode_http(request, 200, None, body)
    }

    fn decode_success(
        &self,
        request: &DiscordRequest,
        body: &[u8],
    ) -> Result<DiscordPage, DiscordError> {
        let payloads = decode_records(self.family, body)?;
        let record_limit = self.page_size.unwrap_or(MAX_NONPAGED_RECORDS);
        if payloads.len() > record_limit {
            return Err(DiscordError::TooManyRecords);
        }
        let scanned_count = payloads.len();
        let records = payloads
            .into_iter()
            .map(|payload| {
                normalize_record(
                    self.family,
                    &self.tenant_id,
                    self.base_url.as_str(),
                    &request.operation_path,
                    &self.guild_id,
                    payload,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        let records = dedupe_audit_records(self.family, records)?;
        if self.family == DiscordFamily::Permission {
            validate_permission_scope(self, &records)?;
        }
        validate_ascending_page(self.family, &records)?;
        let next_cursor = if self.page_size.is_some_and(|limit| scanned_count == limit) {
            match self.family {
                DiscordFamily::AuditLog => records.last().map(|record| record.provider_id.clone()),
                DiscordFamily::Member => highest_provider_id(&records)?,
                DiscordFamily::Role | DiscordFamily::Permission => None,
            }
        } else {
            None
        };
        Ok(DiscordPage {
            records,
            next_cursor,
        })
    }
}

fn dedupe_audit_records(
    family: DiscordFamily,
    records: Vec<DiscordRecord>,
) -> Result<Vec<DiscordRecord>, DiscordError> {
    if family != DiscordFamily::AuditLog {
        return Ok(records);
    }
    let mut previous = None;
    let mut seen = BTreeMap::<String, serde_json::Value>::new();
    let mut unique = Vec::with_capacity(records.len());
    for record in records {
        let current = record
            .provider_id
            .parse::<u64>()
            .map_err(|_| DiscordError::InvalidPageOrder)?;
        if previous.is_some_and(|value| current < value) {
            return Err(DiscordError::InvalidPageOrder);
        }
        previous = Some(current);
        match seen.get(&record.provider_id) {
            Some(payload) if payload == &record.payload => continue,
            Some(_) => return Err(DiscordError::ConflictingDuplicate),
            None => {
                seen.insert(record.provider_id.clone(), record.payload.clone());
                unique.push(record);
            }
        }
    }
    Ok(unique)
}

fn validate_permission_scope(
    kernel: &DiscordKernel,
    records: &[DiscordRecord],
) -> Result<(), DiscordError> {
    for record in records {
        let values = record
            .payload
            .as_object()
            .ok_or(DiscordError::InvalidRecord)?;
        if strict_string_at(values, "application_id").as_deref() != kernel.application_id.as_deref()
            || strict_string_at(values, "guild_id").as_deref() != Some(kernel.guild_id.as_str())
        {
            return Err(DiscordError::RequestScopeMismatch);
        }
    }
    Ok(())
}
