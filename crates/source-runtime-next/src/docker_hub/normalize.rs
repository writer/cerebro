use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    DockerHubError, DockerHubKernel, DockerHubRecord, DockerHubRequest, DockerHubRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &DockerHubKernel,
    request: &DockerHubRequest,
    raw: Value,
    observed_at: &str,
) -> Result<DockerHubRecord, DockerHubError> {
    reject_untrusted(&raw, 0)?;
    let values = raw.as_object().ok_or(DockerHubError::MalformedResponse)?;
    let namespace = required_component(values, "namespace")?;
    let name = required_component(values, "name")?;
    if namespace != kernel.namespace || name != kernel.repository {
        return Err(DockerHubError::ProviderIdentityMismatch);
    }
    let provider_id = format!("{namespace}/{name}");
    let resource_urn = format!(
        "urn:cerebro:{}:docker_hub_repositories:{}",
        kernel.tenant_id,
        encode_urn_segment(&provider_id)
    );
    let occurred_at = occurred_at(values, observed_at)?;
    let attributes = BTreeMap::from([
        ("external_id".to_owned(), provider_id.clone()),
        ("family".to_owned(), "repositories".to_owned()),
        ("provider".to_owned(), "docker_hub".to_owned()),
        ("record_class".to_owned(), "asset".to_owned()),
        ("resource_id".to_owned(), provider_id.clone()),
        ("resource_name".to_owned(), name),
        (
            "resource_type".to_owned(),
            "container_repository".to_owned(),
        ),
        ("resource_urn".to_owned(), resource_urn),
        ("schema".to_owned(), "repositories".to_owned()),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("source_provider".to_owned(), "docker_hub".to_owned()),
        ("source_system".to_owned(), "docker_hub".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    let event_id = go_compatible_event_id(kernel, request, &provider_id);
    let mut payload = raw;
    payload
        .as_object_mut()
        .ok_or(DockerHubError::MalformedResponse)?
        .entry("id")
        .or_insert_with(|| Value::from("repositories"));
    let record = DockerHubRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id,
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    };
    validate_event_contract(&record)?;
    Ok(record)
}

fn validate_event_contract(record: &DockerHubRecord) -> Result<(), DockerHubError> {
    let contract = DockerHubRuntimeDefinition::compile(record.family)?.event_contract;
    if record.kind != contract.kind || record.schema_ref != contract.schema_ref {
        return Err(DockerHubError::EventContractRejection);
    }
    if contract.required_attributes.iter().any(|key| {
        record
            .attributes
            .get(*key)
            .is_none_or(|value| value.trim().is_empty())
    }) || contract.required_payload_fields.iter().any(|key| {
        record
            .payload
            .get(*key)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
    }) {
        return Err(DockerHubError::EventContractRejection);
    }
    Ok(())
}

fn required_component(values: &Map<String, Value>, key: &str) -> Result<String, DockerHubError> {
    let value = values
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 255
                && !value.chars().any(char::is_control)
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
        .ok_or(DockerHubError::MissingStableIdentity)?;
    Ok(value.to_owned())
}

fn occurred_at(values: &Map<String, Value>, observed_at: &str) -> Result<String, DockerHubError> {
    let candidate = ["last_updated", "last_modified"]
        .into_iter()
        .find_map(|key| values.get(key).and_then(Value::as_str))
        .unwrap_or(observed_at);
    let parsed = OffsetDateTime::parse(candidate.trim(), &Rfc3339)
        .map_err(|_| DockerHubError::InvalidProviderRecord)?;
    parsed
        .replace_nanosecond(0)
        .map_err(|_| DockerHubError::InvalidProviderRecord)?
        .format(&Rfc3339)
        .map_err(|_| DockerHubError::InvalidProviderRecord)
}

fn go_compatible_event_id(
    kernel: &DockerHubKernel,
    request: &DockerHubRequest,
    provider_id: &str,
) -> String {
    let base_url = kernel.base_url.as_str().trim_end_matches('/');
    let scope = Sha256::digest(format!("{base_url}\0{}", request.url.path()));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "docker_hub-{}-{scope}-repositories-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(provider_id)
    )
}

fn normalize_id(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        return "unknown".to_owned();
    }
    value
        .chars()
        .map(|character| match character {
            ' ' | '/' | ':' | '\t' | '\n' => '-',
            other => other,
        })
        .collect()
}

fn encode_urn_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn reject_untrusted(value: &Value, depth: usize) -> Result<(), DockerHubError> {
    if depth > 32 {
        return Err(DockerHubError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            for (key, value) in values {
                let key = key.to_ascii_lowercase();
                if key == "tenant_id" {
                    return Err(DockerHubError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "client_secret"
                        | "password"
                        | "private_key"
                        | "authorization"
                ) {
                    return Err(DockerHubError::CredentialMaterial);
                }
                reject_untrusted(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_untrusted(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
