use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{JumpCloudError, JumpCloudFamily, JumpCloudKernel, JumpCloudRequest};

pub(super) struct Identity {
    pub(super) external_id: String,
    pub(super) provider_id: String,
    pub(super) event_id: String,
}

pub(super) fn material(
    kernel: &JumpCloudKernel,
    request: &JumpCloudRequest,
    values: &Map<String, Value>,
    raw_bytes: Option<&[u8]>,
) -> Result<Identity, JumpCloudError> {
    let external_id = external_id(kernel.family, values, raw_bytes)?;
    let provider_id = if kernel.family == JumpCloudFamily::AuditEvents {
        external_id.clone()
    } else {
        record_identity(kernel, request, values, &external_id)
    };
    let event_id = if kernel.family == JumpCloudFamily::AuditEvents {
        sourcecdk_event_id(&[
            "jumpcloud",
            &kernel.tenant_id,
            kernel.insights_origin.as_str().trim_end_matches('/'),
            kernel.family.as_str(),
            &provider_id,
        ])
    } else {
        let path = resolved_path(kernel, request)?;
        jsonapi_event_id(
            &kernel.tenant_id,
            kernel.directory_origin.as_str().trim_end_matches('/'),
            &path,
            kernel.family.as_str(),
            &provider_id,
        )
    };
    Ok(Identity {
        external_id,
        provider_id,
        event_id,
    })
}

fn external_id(
    family: JumpCloudFamily,
    values: &Map<String, Value>,
    raw_bytes: Option<&[u8]>,
) -> Result<String, JumpCloudError> {
    let paths: &[&str] = match family {
        JumpCloudFamily::Users => &["_id", "id", "email", "username"],
        JumpCloudFamily::Groups | JumpCloudFamily::SystemGroups => &["id", "name"],
        JumpCloudFamily::Systems => &["_id", "id", "displayName", "hostname"],
        JumpCloudFamily::Applications => &["_id", "id", "displayName", "name"],
        JumpCloudFamily::GroupMembers => &["to.id", "id"],
        JumpCloudFamily::AuditEvents => &["id", "event_id", "uuid", "request_id"],
    };
    match string_first(values, paths) {
        Some(value) => bounded_provider_id(&value),
        None if family == JumpCloudFamily::AuditEvents => {
            let raw = raw_bytes.ok_or(JumpCloudError::InvalidProviderRecord)?;
            let raw =
                std::str::from_utf8(raw).map_err(|_| JumpCloudError::InvalidProviderRecord)?;
            Ok(sourcecdk_event_id(&[raw]))
        }
        None => Err(JumpCloudError::MissingStableIdentity),
    }
}

fn record_identity(
    kernel: &JumpCloudKernel,
    request: &JumpCloudRequest,
    values: &Map<String, Value>,
    external_id: &str,
) -> String {
    let mut parts = vec![external_id.to_owned()];
    let identity_keys: &[&str] = if kernel.family == JumpCloudFamily::GroupMembers {
        &["group_id"]
    } else {
        &[]
    };
    for key in identity_keys.iter().copied().chain([
        "device_id",
        "device.id",
        "serial_number",
        "agent_id",
        "agent.uuid",
        "device_uuid",
        "installed_version",
        "version",
    ]) {
        let value = if key == "group_id" {
            request.group_id.clone()
        } else {
            string_first(values, &[key])
        };
        if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
            parts.push(format!("{key}={}", value.trim()));
        }
    }
    if parts.len() == 1 {
        return parts.remove(0);
    }
    let digest = Sha256::digest(parts.join("\0"));
    format!("{}-{}", parts[0], hex_prefix(&digest, 12))
}

fn resolved_path(
    kernel: &JumpCloudKernel,
    request: &JumpCloudRequest,
) -> Result<String, JumpCloudError> {
    if kernel.family != JumpCloudFamily::GroupMembers {
        return Ok(kernel.family.path().to_owned());
    }
    let base_path = kernel.directory_origin.path().trim_end_matches('/');
    request
        .url
        .path()
        .strip_prefix(base_path)
        .map(str::to_owned)
        .filter(|path| path.starts_with('/'))
        .ok_or(JumpCloudError::RequestScopeMismatch)
}

fn jsonapi_event_id(
    tenant_id: &str,
    base_url: &str,
    path: &str,
    family: &str,
    record_id: &str,
) -> String {
    let scope = Sha256::digest(format!("{base_url}\0{path}"));
    [
        "jumpcloud".to_owned(),
        normalize_id(tenant_id),
        hex_prefix(&scope, 6),
        normalize_id(family),
        normalize_id(record_id),
    ]
    .join("-")
}

fn sourcecdk_event_id(parts: &[&str]) -> String {
    let normalized = parts
        .iter()
        .map(|part| part.trim())
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return "id-missing".to_owned();
    }
    let digest = Sha256::digest(normalized.join("\0"));
    format!("id-{}", hex_prefix(&digest, 16))
}

fn string_first(values: &Map<String, Value>, paths: &[&str]) -> Option<String> {
    paths.iter().find_map(|path| {
        let mut segments = path.split('.');
        let mut value = values.get(segments.next()?)?;
        for segment in segments {
            value = value.get(segment)?;
        }
        match value {
            Value::String(value) => (!value.trim().is_empty()).then(|| value.trim().to_owned()),
            Value::Number(value) => Some(value.to_string()),
            Value::Bool(value) => Some(value.to_string()),
            _ => None,
        }
    })
}

fn bounded_provider_id(value: &str) -> Result<String, JumpCloudError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 512 {
        return Err(JumpCloudError::MissingStableIdentity);
    }
    Ok(value.to_owned())
}

fn normalize_id(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "unknown".to_owned();
    }
    value.replace([' ', '/', ':', '\t', '\n'], "-")
}

fn hex_prefix(digest: &[u8], bytes: usize) -> String {
    digest[..bytes]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
