use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use super::{
    DigitalOceanError, DigitalOceanFamily, DigitalOceanKernel, DigitalOceanRecord, origin,
};

pub(super) fn normalize_record(
    kernel: &DigitalOceanKernel,
    value: &Value,
) -> Result<DigitalOceanRecord, DigitalOceanError> {
    reject_untrusted_fields(value)?;
    let object = value
        .as_object()
        .ok_or(DigitalOceanError::InvalidProviderRecord)?;
    let provider_id = provider_id(kernel.family, object)?;
    let name = string(object, "name").unwrap_or_default();
    let created = string(object, "created_at").unwrap_or_default();
    let occurred_at = timestamp_or_epoch(&created)?;
    let resource_urn = format!(
        "urn:cerebro:{}:{}:{}",
        kernel.tenant_id,
        kernel.family.urn_kind(),
        provider_id
    );
    let mut attributes = BTreeMap::from([
        ("record_class".to_owned(), "asset".to_owned()),
        ("resource_id".to_owned(), provider_id.clone()),
        ("resource_name".to_owned(), name.clone()),
        (
            "resource_type".to_owned(),
            kernel.family.resource_type().to_owned(),
        ),
        ("resource_urn".to_owned(), resource_urn),
        ("source_event_id".to_owned(), provider_id.clone()),
        ("tenant_id".to_owned(), kernel.tenant_id.clone()),
    ]);
    let payload = match kernel.family {
        DigitalOceanFamily::Droplets => {
            let id = integer(object, "id")?;
            let status = string(object, "status").unwrap_or_default();
            let region = object
                .get("region")
                .and_then(Value::as_object)
                .and_then(|region| string(region, "slug"))
                .unwrap_or_default();
            let vpc_uuid = string(object, "vpc_uuid").unwrap_or_default();
            attributes.insert("region".to_owned(), region.clone());
            if !vpc_uuid.is_empty() {
                attributes.insert("vpc_uuid".to_owned(), vpc_uuid.clone());
            }
            json!({
                "id": id,
                "name": name,
                "status": status,
                "region": region,
                "vpc_uuid": vpc_uuid,
                "created_at": created,
            })
        }
        DigitalOceanFamily::Vpcs => {
            let ip_range = string(object, "ip_range").unwrap_or_default();
            let region = string(object, "region").unwrap_or_default();
            let default = object
                .get("default")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            attributes.insert("region".to_owned(), region.clone());
            json!({
                "id": provider_id,
                "name": name,
                "ip_range": ip_range,
                "region": region,
                "default": default,
                "created_at": occurred_at,
            })
        }
        DigitalOceanFamily::Firewalls => {
            let status = string(object, "status").unwrap_or_default();
            let droplet_ids = droplet_ids(object)?;
            let public = public_ingress(object)?;
            attributes.insert("public_ingress".to_owned(), public.to_string());
            if !droplet_ids.is_empty() {
                attributes.insert(
                    "droplet_ids".to_owned(),
                    droplet_ids
                        .iter()
                        .map(i64::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                );
            }
            json!({
                "id": provider_id,
                "name": name,
                "status": status,
                "droplet_ids": droplet_ids,
                "public": public,
                "created_at": created,
            })
        }
    };
    let record = DigitalOceanRecord {
        tenant_id: kernel.tenant_id.clone(),
        event_id: event_id(&kernel.tenant_id, kernel.family, &provider_id),
        provider_id,
        family: kernel.family,
        kind: kernel.family.event_kind().to_owned(),
        schema_ref: kernel.family.schema_ref().to_owned(),
        occurred_at,
        attributes,
        payload,
    };
    admit(&record)?;
    Ok(record)
}

fn provider_id(
    family: DigitalOceanFamily,
    object: &Map<String, Value>,
) -> Result<String, DigitalOceanError> {
    let value = match family {
        DigitalOceanFamily::Droplets => integer(object, "id")?.to_string(),
        DigitalOceanFamily::Vpcs | DigitalOceanFamily::Firewalls => {
            string(object, "id").ok_or(DigitalOceanError::MissingStableIdentity)?
        }
    };
    origin::provider_id(&value).ok_or(DigitalOceanError::MissingStableIdentity)
}

fn integer(object: &Map<String, Value>, key: &str) -> Result<i64, DigitalOceanError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .filter(|value| *value > 0)
        .ok_or(DigitalOceanError::MissingStableIdentity)
}

fn string(object: &Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn droplet_ids(object: &Map<String, Value>) -> Result<Vec<i64>, DigitalOceanError> {
    let Some(value) = object.get("droplet_ids") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or(DigitalOceanError::InvalidProviderRecord)?;
    values
        .iter()
        .map(|value| {
            value
                .as_i64()
                .filter(|id| *id > 0)
                .ok_or(DigitalOceanError::InvalidProviderRecord)
        })
        .collect()
}

fn public_ingress(object: &Map<String, Value>) -> Result<bool, DigitalOceanError> {
    let Some(value) = object.get("inbound_rules") else {
        return Ok(false);
    };
    let rules = value
        .as_array()
        .ok_or(DigitalOceanError::InvalidProviderRecord)?;
    for rule in rules {
        let Some(addresses) = rule
            .as_object()
            .and_then(|rule| rule.get("sources"))
            .and_then(Value::as_object)
            .and_then(|sources| sources.get("addresses"))
        else {
            continue;
        };
        let addresses = addresses
            .as_array()
            .ok_or(DigitalOceanError::InvalidProviderRecord)?;
        if addresses
            .iter()
            .any(|address| matches!(address.as_str().map(str::trim), Some("0.0.0.0/0" | "::/0")))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn timestamp_or_epoch(value: &str) -> Result<String, DigitalOceanError> {
    if value.is_empty() {
        return Ok("1970-01-01T00:00:00Z".to_owned());
    }
    OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| DigitalOceanError::InvalidProviderRecord)?
        .format(&Rfc3339)
        .map_err(|_| DigitalOceanError::InvalidProviderRecord)
}

fn event_id(tenant_id: &str, family: DigitalOceanFamily, provider_id: &str) -> String {
    let digest = Sha256::digest(
        format!(
            "digitalocean\0{tenant_id}\0{}\0{provider_id}",
            family.as_str()
        )
        .as_bytes(),
    );
    format!(
        "id-{}",
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn admit(record: &DigitalOceanRecord) -> Result<(), DigitalOceanError> {
    if record.kind != record.family.event_kind()
        || record.schema_ref != record.family.schema_ref()
        || [
            "tenant_id",
            "source_event_id",
            "resource_urn",
            "resource_type",
            "resource_id",
        ]
        .iter()
        .any(|key| record.attributes.get(*key).is_none_or(String::is_empty))
        || record.payload.get("id").is_none_or(Value::is_null)
    {
        return Err(DigitalOceanError::EventContractRejection);
    }
    Ok(())
}

fn reject_untrusted_fields(value: &Value) -> Result<(), DigitalOceanError> {
    match value {
        Value::Object(values) => {
            for (key, nested) in values {
                let normalized = key.to_ascii_lowercase().replace('-', "_");
                if matches!(normalized.as_str(), "tenant_id" | "tenantid") {
                    return Err(DigitalOceanError::TenantMismatch);
                }
                if matches!(
                    normalized.as_str(),
                    "authorization" | "access_token" | "token" | "password" | "private_key"
                ) {
                    return Err(DigitalOceanError::CredentialMaterial);
                }
                reject_untrusted_fields(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                reject_untrusted_fields(nested)?;
            }
        }
        _ => {}
    }
    Ok(())
}
