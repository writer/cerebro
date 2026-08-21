use serde_json::Value;

use super::{DiscordError, DiscordFamily};

// Provider-local defense-in-depth bounds. The HTTP host must independently
// enforce a response byte limit before handing a body to this kernel.
pub(super) const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub(super) const MAX_NONPAGED_RECORDS: usize = 1_000;

pub(super) fn decode_records(
    family: DiscordFamily,
    body: &[u8],
) -> Result<Vec<Value>, DiscordError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| DiscordError::InvalidResponse)?;
    let records = match family {
        DiscordFamily::AuditLog => root
            .as_object()
            .and_then(|object| object.get("audit_log_entries"))
            .and_then(Value::as_array)
            .cloned()
            .ok_or(DiscordError::InvalidResponse),
        DiscordFamily::Member | DiscordFamily::Role | DiscordFamily::Permission => root
            .as_array()
            .cloned()
            .ok_or(DiscordError::InvalidResponse),
    }?;
    if records.iter().any(contains_credential_material) {
        return Err(DiscordError::CredentialMaterial);
    }
    Ok(records)
}

fn contains_credential_material(value: &Value) -> bool {
    match value {
        Value::Object(values) => values.iter().any(|(key, value)| {
            matches!(
                key.to_ascii_lowercase().as_str(),
                "authorization"
                    | "api_key"
                    | "api_token"
                    | "access_token"
                    | "refresh_token"
                    | "bot_token"
                    | "client_secret"
                    | "password"
                    | "secret"
                    | "token"
            ) || contains_credential_material(value)
        }),
        Value::Array(values) => values.iter().any(contains_credential_material),
        _ => false,
    }
}
