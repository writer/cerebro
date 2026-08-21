use super::{
    DiscordError, DiscordFamily, DiscordKernel, DiscordPage, DiscordRecord, DiscordRequest,
    cursor::{highest_provider_id, validate_ascending_page},
    normalize::{normalize_record, strict_string_at},
    wire::{MAX_NONPAGED_RECORDS, MAX_RESPONSE_BYTES, decode_records},
};

impl DiscordKernel {
    /// Decode and normalize a response for a request produced by this kernel.
    pub fn decode(
        &self,
        request: &DiscordRequest,
        body: &[u8],
    ) -> Result<DiscordPage, DiscordError> {
        if body.len() > MAX_RESPONSE_BYTES {
            return Err(DiscordError::ResponseTooLarge);
        }
        if request.family != self.family || request != &self.plan(request.cursor.as_deref())? {
            return Err(DiscordError::RequestScopeMismatch);
        }
        let payloads = decode_records(self.family, body)?;
        let record_limit = self.page_size.unwrap_or(MAX_NONPAGED_RECORDS);
        if payloads.len() > record_limit {
            return Err(DiscordError::TooManyRecords);
        }
        let records = payloads
            .into_iter()
            .map(|payload| normalize_record(self.family, payload))
            .collect::<Result<Vec<_>, _>>()?;
        if self.family == DiscordFamily::Permission {
            validate_permission_scope(self, &records)?;
        }
        validate_ascending_page(self.family, &records)?;
        let next_cursor = if self.page_size.is_some_and(|limit| records.len() == limit) {
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
