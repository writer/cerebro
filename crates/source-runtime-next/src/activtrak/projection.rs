use std::collections::BTreeMap;

use super::{ActivTrakFamily, ActivTrakRecord};

/// One deterministic tenant-scoped ActivTrak projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActivTrakEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActivTrakProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<ActivTrakEntityFact>,
}

/// Project normalized records into identity, asset, and audit entities.
pub fn project_activtrak_records(records: &[ActivTrakRecord]) -> ActivTrakProjectionFacts {
    let mut entities = BTreeMap::<String, ActivTrakEntityFact>::new();
    for record in records {
        let (urn, entity_type, label) = match record.family {
            ActivTrakFamily::Clients | ActivTrakFamily::Groups => {
                let (Some(urn), Some(resource_type)) = (
                    record.attributes.get("resource_urn"),
                    record.attributes.get("resource_type"),
                ) else {
                    continue;
                };
                (
                    urn.clone(),
                    format!("runtime.{}", resource_type.replace('_', ".")),
                    record
                        .attributes
                        .get("resource_name")
                        .cloned()
                        .unwrap_or_else(|| record.provider_id.clone()),
                )
            }
            family => (
                format!(
                    "urn:cerebro:{}:activtrak_{}:{}",
                    encode_segment(&record.tenant_id),
                    family.as_str(),
                    encode_segment(&record.provider_id)
                ),
                format!("activtrak.{}", family.as_str().replace('_', ".")),
                record
                    .attributes
                    .get("display_name")
                    .or_else(|| record.attributes.get("event_type"))
                    .cloned()
                    .unwrap_or_else(|| record.provider_id.clone()),
            ),
        };
        entities.insert(
            urn.clone(),
            ActivTrakEntityFact {
                urn,
                entity_type,
                label,
            },
        );
    }
    ActivTrakProjectionFacts {
        entities: entities.into_values().collect(),
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
