use std::collections::BTreeMap;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use super::{
    ActiveCampaignError, ActiveCampaignFamily, ActiveCampaignKernel, ActiveCampaignRecord,
    ActiveCampaignRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &ActiveCampaignKernel,
    raw: Value,
) -> Result<ActiveCampaignRecord, ActiveCampaignError> {
    reject_untrusted(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(ActiveCampaignError::InvalidProviderRecord)?;
    let provider_id = required_scalar(values, "id")?;
    let (attributes, payload) = family_values(kernel, values, &provider_id)?;
    validate_contract(kernel.family, &attributes, &payload)?;
    Ok(ActiveCampaignRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at: kernel.observed_at.clone(),
        attributes,
        payload,
    })
}

fn family_values(
    kernel: &ActiveCampaignKernel,
    values: &Map<String, Value>,
    provider_id: &str,
) -> Result<(BTreeMap<String, String>, Value), ActiveCampaignError> {
    let record_class = if kernel.family == ActiveCampaignFamily::Users {
        "identity_user"
    } else {
        "asset"
    };
    let mut attributes = BTreeMap::from([
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("record_class".to_owned(), record_class.to_owned()),
        ("schema".to_owned(), kernel.family.as_str().to_owned()),
        ("source_system".to_owned(), "activecampaign".to_owned()),
    ]);
    match kernel.family {
        ActiveCampaignFamily::Users => {
            attributes.insert("user_id".to_owned(), provider_id.to_owned());
            copy(&mut attributes, values, "username", "display_name");
            copy(&mut attributes, values, "email", "email");
            copy(&mut attributes, values, "username", "login");
            copy(&mut attributes, values, "status", "status");
        }
        family @ (ActiveCampaignFamily::Accounts
        | ActiveCampaignFamily::Automations
        | ActiveCampaignFamily::Campaigns
        | ActiveCampaignFamily::Contacts) => {
            let resource_type = match kernel.family {
                ActiveCampaignFamily::Accounts => "activecampaign_account",
                ActiveCampaignFamily::Automations => "activecampaign_automation",
                ActiveCampaignFamily::Campaigns => "activecampaign_campaign",
                ActiveCampaignFamily::Contacts => "activecampaign_contact",
                ActiveCampaignFamily::Users => {
                    return Err(ActiveCampaignError::InternalRuntimeFailure);
                }
            };
            let resource_name_key = if family == ActiveCampaignFamily::Contacts {
                "email"
            } else {
                "name"
            };
            let resource_name =
                scalar(values.get(resource_name_key)).unwrap_or_else(|| provider_id.to_owned());
            attributes.extend(BTreeMap::from([
                ("resource_id".to_owned(), provider_id.to_owned()),
                ("resource_name".to_owned(), resource_name),
                ("resource_type".to_owned(), resource_type.to_owned()),
                (
                    "resource_urn".to_owned(),
                    format!(
                        "urn:cerebro:{}:runtime_{}:{}",
                        encode_segment(&kernel.tenant_id),
                        resource_type,
                        encode_segment(provider_id)
                    ),
                ),
            ]));
            if matches!(
                family,
                ActiveCampaignFamily::Automations | ActiveCampaignFamily::Campaigns
            ) {
                copy(&mut attributes, values, "status", "status");
            }
            if family == ActiveCampaignFamily::Contacts {
                copy(&mut attributes, values, "email", "email");
            }
        }
    }
    let mut payload = values.clone();
    payload.insert(
        "schema_ref".to_owned(),
        Value::String(kernel.family.schema_ref().to_owned()),
    );
    Ok((attributes, Value::Object(payload)))
}

fn validate_contract(
    family: ActiveCampaignFamily,
    attributes: &BTreeMap<String, String>,
    payload: &Value,
) -> Result<(), ActiveCampaignError> {
    let definition = ActiveCampaignRuntimeDefinition::compile(family)?;
    if definition.event_contract.kind != family.event_kind()
        || definition.event_contract.schema_ref != family.schema_ref()
        || definition
            .event_contract
            .required_attributes
            .iter()
            .any(|key| {
                attributes
                    .get(*key)
                    .is_none_or(|value| value.trim().is_empty())
            })
        || definition
            .event_contract
            .required_payload_fields
            .iter()
            .any(|key| payload.get(*key).is_none_or(Value::is_null))
    {
        return Err(ActiveCampaignError::EventContractRejection);
    }
    Ok(())
}

fn event_id(kernel: &ActiveCampaignKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}",
        kernel.base_url.as_str().trim_end_matches('/'),
        kernel.family.path()
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "activecampaign-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn required_scalar(
    values: &Map<String, Value>,
    key: &'static str,
) -> Result<String, ActiveCampaignError> {
    scalar(values.get(key)).ok_or(ActiveCampaignError::MissingStableIdentity)
}

fn scalar(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(value) => {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_owned())
        }
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn copy(
    attributes: &mut BTreeMap<String, String>,
    values: &Map<String, Value>,
    source: &str,
    target: &str,
) {
    if let Some(value) = scalar(values.get(source)) {
        attributes.insert(target.to_owned(), value);
    }
}

fn encode_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.trim().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
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

fn reject_untrusted(value: &Value, depth: usize) -> Result<(), ActiveCampaignError> {
    if depth > 16 {
        return Err(ActiveCampaignError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(ActiveCampaignError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if key == "tenant_id" {
                    return Err(ActiveCampaignError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "api_key"
                        | "api_token"
                        | "password"
                        | "private_key"
                        | "authorization"
                        | "client_secret"
                ) {
                    return Err(ActiveCampaignError::CredentialMaterial);
                }
                reject_untrusted(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(ActiveCampaignError::TooManyRecords);
            }
            for value in values {
                reject_untrusted(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
