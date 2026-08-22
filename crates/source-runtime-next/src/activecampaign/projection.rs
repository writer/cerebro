use std::collections::BTreeMap;

use super::{ActiveCampaignFamily, ActiveCampaignRecord};

/// One deterministic tenant-scoped ActiveCampaign projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ActiveCampaignEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ActiveCampaignProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<ActiveCampaignEntityFact>,
}

/// Project normalized ActiveCampaign records into users and business assets.
pub fn project_activecampaign_records(
    records: &[ActiveCampaignRecord],
) -> ActiveCampaignProjectionFacts {
    let mut entities = BTreeMap::<String, ActiveCampaignEntityFact>::new();
    for record in records {
        let (urn, entity_type, label) = if record.family == ActiveCampaignFamily::Users {
            (
                format!(
                    "urn:cerebro:{}:activecampaign_user:{}",
                    encode_segment(&record.tenant_id),
                    encode_segment(&record.provider_id)
                ),
                "activecampaign.user".to_owned(),
                record
                    .attributes
                    .get("display_name")
                    .or_else(|| record.attributes.get("email"))
                    .cloned()
                    .unwrap_or_else(|| record.provider_id.clone()),
            )
        } else {
            let Some(urn) = record.attributes.get("resource_urn") else {
                continue;
            };
            let Some(resource_type) = record.attributes.get("resource_type") else {
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
        };
        entities.insert(
            urn.clone(),
            ActiveCampaignEntityFact {
                urn,
                entity_type,
                label,
            },
        );
    }
    ActiveCampaignProjectionFacts {
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
