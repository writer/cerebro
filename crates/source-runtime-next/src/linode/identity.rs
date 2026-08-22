//! Collision-safe Go-compatible Linode identities.

use sha2::{Digest, Sha256};

use super::{LinodeError, wire::IdentityDiscriminatorsWire};

pub(super) fn require_event_identity(value: &str) -> Result<(), LinodeError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || trimmed.chars().any(char::is_control)
        || normalize_id(trimmed) != trimmed
    {
        return Err(LinodeError::InvalidEventIdentity);
    }
    Ok(())
}

pub(super) fn provider_identity<const N: usize>(
    values: [String; N],
) -> Result<String, LinodeError> {
    let value = values
        .into_iter()
        .find(|value| !value.trim().is_empty())
        .unwrap_or_default();
    if value.is_empty() {
        Err(LinodeError::MissingProviderIdentity)
    } else {
        Ok(value)
    }
}

pub(super) fn record_identity(
    record_id: &str,
    identity: &IdentityDiscriminatorsWire,
) -> Result<String, LinodeError> {
    require_event_identity(record_id)?;
    let device = identity.device.as_ref();
    let agent = identity.agent.as_ref();
    let values = [
        ("device_id", identity.device_id.as_ref()),
        ("device.id", device.and_then(|value| value.id.as_ref())),
        ("serial_number", identity.serial_number.as_ref()),
        ("agent_id", identity.agent_id.as_ref()),
        ("agent.uuid", agent.and_then(|value| value.uuid.as_ref())),
        ("device_uuid", identity.device_uuid.as_ref()),
        ("installed_version", identity.installed_version.as_ref()),
        ("version", identity.version.as_ref()),
    ];
    let mut parts = vec![record_id.to_owned()];
    for (name, value) in values {
        let Some(value) = value else {
            continue;
        };
        if !value.canonical_identity() {
            return Err(LinodeError::InvalidEventIdentity);
        }
        let value = value.text();
        if !value.is_empty() {
            parts.push(format!("{name}={value}"));
        }
    }
    if parts.len() == 1 {
        return Ok(record_id.to_owned());
    }
    let material = parts.join("\0");
    Ok(format!(
        "{}-{}",
        record_id,
        hex_prefix(&Sha256::digest(material.as_bytes()), 24)
    ))
}

pub(super) fn event_id(tenant_id: &str, base_url: &str, path: &str, provider_id: &str) -> String {
    let scope = Sha256::digest(format!("{base_url}\0{path}").as_bytes());
    format!(
        "linode-{}-{}-issue-{}",
        normalize_id(tenant_id),
        hex_prefix(&scope, 12),
        normalize_id(provider_id)
    )
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
