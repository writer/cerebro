use std::{collections::BTreeMap, net::IpAddr};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    AbuseIpDbError, AbuseIpDbFamily, AbuseIpDbKernel, AbuseIpDbRecord, AbuseIpDbRuntimeDefinition,
};

pub(super) fn normalize(
    kernel: &AbuseIpDbKernel,
    raw: Value,
) -> Result<AbuseIpDbRecord, AbuseIpDbError> {
    reject_untrusted(&raw, 0)?;
    let values = raw
        .as_object()
        .ok_or(AbuseIpDbError::InvalidProviderRecord)?;
    let (provider_id, occurred_at, attributes, payload) = match kernel.family {
        AbuseIpDbFamily::Reports => normalize_report(kernel, values)?,
        AbuseIpDbFamily::IpAddresses => normalize_ip_address(kernel, values)?,
    };
    validate_contract(kernel.family, &attributes, &payload)?;
    Ok(AbuseIpDbRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(kernel, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    })
}

fn normalize_report(
    kernel: &AbuseIpDbKernel,
    values: &Map<String, Value>,
) -> Result<(String, String, BTreeMap<String, String>, Value), AbuseIpDbError> {
    let reported_at = required_time(values, "reportedAt")?;
    let reporter_id = positive_integer(values.get("reporterId"))?;
    let provider_id = format!("{reported_at}:{reporter_id}");
    let configured_ip = kernel
        .filters
        .ip_address
        .as_deref()
        .ok_or(AbuseIpDbError::MissingConfiguration("ip_address"))?;
    if let Some(provider_ip) = values.get("ipAddress").and_then(Value::as_str) {
        let provider_ip = provider_ip
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| AbuseIpDbError::InvalidProviderRecord)?
            .to_string();
        if provider_ip != configured_ip {
            return Err(AbuseIpDbError::ProviderIdentityMismatch);
        }
    }
    let resource_urn = resource_urn(&kernel.tenant_id, configured_ip);
    let mut attributes = common_attributes(kernel, &provider_id, "finding", "reports");
    attributes.extend(BTreeMap::from([
        ("finding_id".to_owned(), provider_id.clone()),
        ("resource_id".to_owned(), configured_ip.to_owned()),
        ("resource_name".to_owned(), configured_ip.to_owned()),
        ("resource_type".to_owned(), "abuseipdb_report".to_owned()),
        ("resource_urn".to_owned(), resource_urn.clone()),
        ("severity".to_owned(), "reported".to_owned()),
        ("status".to_owned(), "observed".to_owned()),
    ]));
    if let Some(comment) = nonempty_string(values.get("comment")) {
        attributes.insert("description".to_owned(), comment.to_owned());
        attributes.insert("title".to_owned(), comment.to_owned());
    }
    let mut payload = values.clone();
    payload.insert(
        "ipAddress".to_owned(),
        Value::String(configured_ip.to_owned()),
    );
    add_payload_metadata(
        kernel,
        &mut payload,
        &provider_id,
        "finding",
        configured_ip,
        "abuseipdb_report",
        &resource_urn,
    );
    Ok((provider_id, reported_at, attributes, Value::Object(payload)))
}

fn normalize_ip_address(
    kernel: &AbuseIpDbKernel,
    values: &Map<String, Value>,
) -> Result<(String, String, BTreeMap<String, String>, Value), AbuseIpDbError> {
    let ip = values
        .get("ipAddress")
        .and_then(Value::as_str)
        .ok_or(AbuseIpDbError::MissingStableIdentity)?
        .trim()
        .parse::<IpAddr>()
        .map_err(|_| AbuseIpDbError::InvalidProviderRecord)?
        .to_string();
    let occurred_at = values
        .get("lastReportedAt")
        .and_then(Value::as_str)
        .map(normalized_time)
        .transpose()?
        .unwrap_or_else(|| kernel.observed_at.clone());
    let resource_urn = resource_urn(&kernel.tenant_id, &ip);
    let mut attributes = common_attributes(kernel, &ip, "asset", "ip_addresses");
    attributes.extend(BTreeMap::from([
        ("resource_id".to_owned(), ip.clone()),
        ("resource_name".to_owned(), ip.clone()),
        ("resource_type".to_owned(), "ip_address".to_owned()),
        ("resource_urn".to_owned(), resource_urn.clone()),
    ]));
    if let Some(score) = scalar(values.get("abuseConfidenceScore")) {
        attributes.insert("abuse_confidence_score".to_owned(), score);
    }
    if let Some(country) = scalar(values.get("countryCode")) {
        attributes.insert("country_code".to_owned(), country);
    }
    let mut payload = values.clone();
    payload.insert("ipAddress".to_owned(), Value::String(ip.clone()));
    add_payload_metadata(
        kernel,
        &mut payload,
        &ip,
        "asset",
        &ip,
        "ip_address",
        &resource_urn,
    );
    Ok((ip, occurred_at, attributes, Value::Object(payload)))
}

fn common_attributes(
    kernel: &AbuseIpDbKernel,
    provider_id: &str,
    record_class: &str,
    schema: &str,
) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("api_method".to_owned(), "GET".to_owned()),
        ("api_path".to_owned(), kernel.family.path().to_owned()),
        ("external_id".to_owned(), provider_id.to_owned()),
        ("family".to_owned(), kernel.family.as_str().to_owned()),
        ("observed_at".to_owned(), kernel.observed_at.clone()),
        ("provider".to_owned(), "abuseipdb".to_owned()),
        ("record_class".to_owned(), record_class.to_owned()),
        (
            "record_selector".to_owned(),
            match kernel.family {
                AbuseIpDbFamily::Reports => "$.data.results[*]",
                AbuseIpDbFamily::IpAddresses => "$.data[*]",
            }
            .to_owned(),
        ),
        ("schema".to_owned(), schema.to_owned()),
        ("source_event_id".to_owned(), provider_id.to_owned()),
        ("source_provider".to_owned(), "abuseipdb".to_owned()),
        ("source_system".to_owned(), "abuseipdb".to_owned()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ])
}

fn add_payload_metadata(
    kernel: &AbuseIpDbKernel,
    payload: &mut Map<String, Value>,
    provider_id: &str,
    record_class: &str,
    resource_id: &str,
    resource_type: &str,
    resource_urn: &str,
) {
    for (key, value) in [
        ("api_method", "GET"),
        ("api_path", kernel.family.path()),
        ("event_id", provider_id),
        ("family", kernel.family.as_str()),
        ("record_class", record_class),
        (
            "record_selector",
            match kernel.family {
                AbuseIpDbFamily::Reports => "$.data.results[*]",
                AbuseIpDbFamily::IpAddresses => "$.data[*]",
            },
        ),
        ("resource_id", resource_id),
        ("resource_type", resource_type),
        ("resource_urn", resource_urn),
        ("schema_ref", kernel.family.schema_ref()),
        ("source_id", "abuseipdb"),
        ("tenant_id", &kernel.tenant_id),
    ] {
        payload.insert(key.to_owned(), Value::String(value.to_owned()));
    }
    if kernel.family == AbuseIpDbFamily::Reports {
        payload.insert("status".to_owned(), Value::String("observed".to_owned()));
    }
}

fn validate_contract(
    family: AbuseIpDbFamily,
    attributes: &BTreeMap<String, String>,
    payload: &Value,
) -> Result<(), AbuseIpDbError> {
    let definition = AbuseIpDbRuntimeDefinition::compile(family)?;
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
        return Err(AbuseIpDbError::EventContractRejection);
    }
    Ok(())
}

fn event_id(kernel: &AbuseIpDbKernel, provider_id: &str) -> String {
    let scope = Sha256::digest(format!(
        "{}\0{}",
        kernel.base_url.as_str(),
        kernel.family.path()
    ));
    let scope = scope[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!(
        "abuseipdb-{}-{scope}-{}-{}",
        normalize_id(&kernel.tenant_id),
        normalize_id(kernel.family.as_str()),
        normalize_id(provider_id)
    )
}

fn resource_urn(tenant: &str, ip: &str) -> String {
    format!(
        "urn:cerebro:{}:abuseipdb_ip_address:{}",
        encode_segment(tenant),
        encode_segment(ip)
    )
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

fn positive_integer(value: Option<&Value>) -> Result<String, AbuseIpDbError> {
    let value = value.ok_or(AbuseIpDbError::MissingStableIdentity)?;
    let parsed = value
        .as_u64()
        .or_else(|| value.as_str()?.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(AbuseIpDbError::MissingStableIdentity)?;
    Ok(parsed.to_string())
}

fn required_time(values: &Map<String, Value>, key: &'static str) -> Result<String, AbuseIpDbError> {
    let value = values
        .get(key)
        .and_then(Value::as_str)
        .ok_or(AbuseIpDbError::MissingStableIdentity)?;
    normalized_time(value)
}

fn normalized_time(value: &str) -> Result<String, AbuseIpDbError> {
    let time = OffsetDateTime::parse(value.trim(), &Rfc3339)
        .map_err(|_| AbuseIpDbError::InvalidProviderRecord)?;
    time.format(&Rfc3339)
        .map_err(|_| AbuseIpDbError::InvalidProviderRecord)
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

fn nonempty_string(value: Option<&Value>) -> Option<&str> {
    value?
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn reject_untrusted(value: &Value, depth: usize) -> Result<(), AbuseIpDbError> {
    if depth > 16 {
        return Err(AbuseIpDbError::InvalidProviderRecord);
    }
    match value {
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(AbuseIpDbError::InvalidProviderRecord);
            }
            for (key, value) in values {
                let key = key.trim().to_ascii_lowercase().replace('-', "_");
                if key == "tenant_id" {
                    return Err(AbuseIpDbError::TenantMismatch);
                }
                if matches!(
                    key.as_str(),
                    "token"
                        | "access_token"
                        | "refresh_token"
                        | "api_key"
                        | "key"
                        | "password"
                        | "private_key"
                        | "authorization"
                        | "client_secret"
                ) {
                    return Err(AbuseIpDbError::CredentialMaterial);
                }
                reject_untrusted(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            if values.len() > 10_000 {
                return Err(AbuseIpDbError::TooManyRecords);
            }
            for value in values {
                reject_untrusted(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
