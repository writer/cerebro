use std::collections::BTreeMap;

use super::AcunetixRecord;

/// One deterministic tenant-scoped Acunetix projection entity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AcunetixEntityFact {
    /// Canonical entity URN.
    pub urn: String,
    /// Closed entity type.
    pub entity_type: String,
    /// Human-readable label.
    pub label: String,
}

/// Provider-local projection facts used for Go/Rust parity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AcunetixProjectionFacts {
    /// Deduplicated entities in canonical order.
    pub entities: Vec<AcunetixEntityFact>,
}

/// Project normalized Acunetix records into catalog entities.
pub fn project_acunetix_records(records: &[AcunetixRecord]) -> AcunetixProjectionFacts {
    let mut entities = BTreeMap::<String, AcunetixEntityFact>::new();
    for record in records {
        let urn = format!(
            "urn:cerebro:{}:acunetix_{}:{}",
            encode_segment(&record.tenant_id),
            record.family.as_str(),
            encode_segment(&record.provider_id)
        );
        let label = record
            .attributes
            .get("resource_name")
            .or_else(|| record.attributes.get("policy_name"))
            .or_else(|| record.attributes.get("title"))
            .cloned()
            .unwrap_or_else(|| record.provider_id.clone());
        entities.insert(
            urn.clone(),
            AcunetixEntityFact {
                urn,
                entity_type: format!("acunetix.{}", record.family.as_str().replace('_', ".")),
                label,
            },
        );
    }
    AcunetixProjectionFacts {
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
