//! Shared Go-compatible Twilio normalization helpers.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use time::{Date, Duration, OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::{
    TwilioError, TwilioFamily,
    family::wire::{IdentityDiscriminatorsWire, WireScalar},
};

pub(super) fn insert(fields: &mut BTreeMap<String, String>, name: &str, value: String) {
    let value = value.trim();
    if !value.is_empty() {
        fields.insert(name.to_owned(), value.to_owned());
    }
}

pub(super) fn first<const N: usize>(values: [String; N]) -> String {
    values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default()
}

pub(super) fn scalar(value: &Option<WireScalar>) -> String {
    value.as_ref().map(WireScalar::text).unwrap_or_default()
}

pub(super) fn provider_identity<const N: usize>(
    values: [String; N],
) -> Result<String, TwilioError> {
    let value = first(values);
    if value.is_empty() {
        Err(TwilioError::MissingProviderIdentity)
    } else {
        Ok(value)
    }
}

pub(super) fn require_payload_id(value: &Option<WireScalar>) -> Result<(), TwilioError> {
    if scalar(value).is_empty() {
        Err(TwilioError::MissingRequiredPayloadField("id"))
    } else {
        Ok(())
    }
}

pub(super) fn record_identity(record_id: &str, identity: &IdentityDiscriminatorsWire) -> String {
    let device = identity.device.as_ref();
    let agent = identity.agent.as_ref();
    let mut parts = vec![record_id.trim().to_owned()];
    for (key, value) in [
        ("device_id", scalar(&identity.device_id)),
        (
            "device.id",
            scalar(&device.and_then(|value| value.id.clone())),
        ),
        ("serial_number", scalar(&identity.serial_number)),
        ("agent_id", scalar(&identity.agent_id)),
        (
            "agent.uuid",
            scalar(&agent.and_then(|value| value.uuid.clone())),
        ),
        ("device_uuid", scalar(&identity.device_uuid)),
        ("installed_version", scalar(&identity.installed_version)),
        ("version", scalar(&identity.version)),
    ] {
        if !value.is_empty() {
            parts.push(format!("{key}={value}"));
        }
    }
    if parts.len() == 1 {
        return parts.remove(0);
    }
    let material = parts.join("\0");
    format!(
        "{}-{}",
        record_id.trim(),
        hex_prefix(&Sha256::digest(material.as_bytes()), 24)
    )
}

pub(super) fn require_field(
    fields: &BTreeMap<String, String>,
    name: &'static str,
) -> Result<(), TwilioError> {
    fields
        .get(name)
        .filter(|value| !value.trim().is_empty())
        .map(|_| ())
        .ok_or(TwilioError::MissingRequiredAttribute(name))
}

pub(super) fn base_fields(
    family: TwilioFamily,
    tenant_id: &str,
    record_id: &str,
    record_class: &str,
) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for (name, value) in [
        ("external_id", record_id),
        ("family", family.as_str()),
        ("provider", "twilio"),
        ("record_class", record_class),
        ("schema", family.as_str()),
        ("source_provider", "twilio"),
        ("source_system", "twilio"),
        ("tenant_id", tenant_id),
    ] {
        insert(&mut fields, name, value.to_owned());
    }
    fields
}

pub(super) fn event_id(
    tenant_id: &str,
    base_origin: &str,
    path: &str,
    family: TwilioFamily,
    provider_id: &str,
) -> String {
    let scope = Sha256::digest(format!("{base_origin}\0{path}").as_bytes());
    format!(
        "twilio-{}-{}-{}-{}",
        normalize_id(tenant_id),
        hex_prefix(&scope, 12),
        normalize_id(family.as_str()),
        normalize_id(provider_id)
    )
}

pub(super) fn occurred_at<const N: usize>(
    values: [String; N],
    observed_at: OffsetDateTime,
) -> String {
    values
        .iter()
        .find_map(|value| normalized_time(value))
        .unwrap_or_else(|| normalized_observed_at(observed_at))
}

fn normalized_time(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(parsed) = parse_provider_time(value) {
        return parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok();
    }
    let numeric = value.parse::<f64>().ok()?;
    if !numeric.is_finite() || numeric <= 0.0 {
        return None;
    }
    let parsed = if numeric > 1_000_000_000_000.0 {
        OffsetDateTime::from_unix_timestamp_nanos((numeric.trunc() as i128) * 1_000_000).ok()?
    } else {
        let whole = numeric.trunc();
        let fraction = numeric - whole;
        OffsetDateTime::from_unix_timestamp(whole as i64)
            .ok()?
            .checked_add(Duration::nanoseconds((fraction * 1_000_000_000.0) as i64))?
    };
    parsed.to_offset(UtcOffset::UTC).format(&Rfc3339).ok()
}

fn parse_provider_time(value: &str) -> Option<OffsetDateTime> {
    if let Ok(parsed) = OffsetDateTime::parse(value, &Rfc3339) {
        return Some(parsed);
    }
    if let Some(normalized) = compact_offset_time(value)
        && let Ok(parsed) = OffsetDateTime::parse(&normalized, &Rfc3339)
    {
        return Some(parsed);
    }
    let date_format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]").ok()?;
    Date::parse(value, &date_format)
        .ok()
        .map(|date| date.midnight().assume_utc())
}

fn compact_offset_time(value: &str) -> Option<String> {
    let split = value.len().checked_sub(5)?;
    let bytes = value.as_bytes();
    if !matches!(bytes.get(split), Some(b'+' | b'-'))
        || !bytes.get(split + 1..)?.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    let mut normalized = String::with_capacity(value.len() + 1);
    normalized.push_str(value.get(..split + 3)?);
    normalized.push(':');
    normalized.push_str(value.get(split + 3..)?);
    Some(normalized)
}

fn normalized_observed_at(value: OffsetDateTime) -> String {
    value
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)
        .expect("RFC3339 formats OffsetDateTime")
}

fn normalize_id(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "unknown".to_owned();
    }
    value.replace([' ', '/', ':', '\t', '\n'], "-")
}

fn hex_prefix(bytes: &[u8], length: usize) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(length);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        if encoded.len() == length {
            break;
        }
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
        if encoded.len() == length {
            break;
        }
    }
    encoded
}
