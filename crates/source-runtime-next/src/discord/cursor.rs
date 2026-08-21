use super::{DiscordError, DiscordFamily, DiscordRecord};

pub(super) fn validate_ascending_page(
    family: DiscordFamily,
    records: &[DiscordRecord],
) -> Result<(), DiscordError> {
    if family != DiscordFamily::AuditLog {
        return Ok(());
    }
    let mut previous = None;
    for record in records {
        let current = record
            .provider_id
            .parse::<u64>()
            .map_err(|_| DiscordError::InvalidPageOrder)?;
        if previous.is_some_and(|value| current <= value) {
            return Err(DiscordError::InvalidPageOrder);
        }
        previous = Some(current);
    }
    Ok(())
}

pub(super) fn highest_provider_id(
    records: &[DiscordRecord],
) -> Result<Option<String>, DiscordError> {
    let mut highest = None;
    for record in records {
        let number = record
            .provider_id
            .parse::<u64>()
            .map_err(|_| DiscordError::InvalidRecord)?;
        if highest
            .as_ref()
            .is_none_or(|(current, _): &(u64, String)| number > *current)
        {
            highest = Some((number, record.provider_id.clone()));
        }
    }
    Ok(highest.map(|(_, id)| id))
}
